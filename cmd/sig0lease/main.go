// Package main implements the DNS proxy server.
package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/handlers"
	"github.com/NetworkCommons/sig0lease/logging"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
	"github.com/NetworkCommons/sig0lease/server"
)

func setUintEnv(dst map[string]any, envName string, field string) {
	if v := os.Getenv(envName); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err == nil {
			dst[field] = uint32(n)
		}
	}
}

func applyUpdateHandlerEnvOverrides(cfg map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range cfg {
		out[k] = v
	}

	if v := os.Getenv("UPSTREAM_ZONE"); v != "" {
		out["upstream_zone"] = v
	}
	if v := os.Getenv("KEYSTORE_DIR"); v != "" {
		out["keystore_dir"] = v
	}
	if v := os.Getenv("ALLOW_ONLINE_KEY_REGISTRATION"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			out["allow_online_key_registration"] = b
		}
	}

	rawPolicy, _ := out["lease_policy"].(map[string]any)
	if rawPolicy == nil {
		rawPolicy = make(map[string]any)
	}
	setUintEnv(rawPolicy, "POLICY_MIN_KEY_LEASE", "min_key_lease_sec")
	setUintEnv(rawPolicy, "POLICY_MAX_KEY_LEASE", "max_key_lease_sec")
	setUintEnv(rawPolicy, "POLICY_MIN_RR_LEASE", "min_rr_lease_sec")
	setUintEnv(rawPolicy, "POLICY_MAX_RR_LEASE", "max_rr_lease_sec")
	if len(rawPolicy) > 0 {
		out["lease_policy"] = rawPolicy
	}

	return out
}

// withBootstrapResolvers fills in "bootstrap_resolvers" for the update
// handler from the top-level "upstreams" config, unless the handler config
// already sets its own. Without this, the handler's own SOA-based zone-
// authority resolution (used to find where to forward signed UPDATEs, and
// to check for pre-existing records upstream) has no configured resolver of
// its own and falls back to a hardcoded default -- silently independent of
// whatever the operator configured under "upstreams" for generic traffic.
func withBootstrapResolvers(handlerCfg map[string]any, appCfg *config.Config) map[string]any {
	out := make(map[string]any, len(handlerCfg)+1)
	for k, v := range handlerCfg {
		out[k] = v
	}
	if _, explicit := out["bootstrap_resolvers"]; explicit {
		return out
	}
	addrs := make([]string, 0, len(appCfg.Upstreams))
	for _, u := range appCfg.Upstreams {
		if u.Address != "" {
			addrs = append(addrs, u.Address)
		}
	}
	if len(addrs) > 0 {
		out["bootstrap_resolvers"] = addrs
	}
	return out
}

// checkSeparateLeaseStores fails when update_handler and srp_handler are both enabled and
// their storage sections name the same snapshot file: the two handlers must never share a
// lease store. A file store loads its snapshot and writes it straight back while Setup builds
// it, so with one shared file the second handler would start from the first handler's tree,
// and from then on each would overwrite the other's saves. It runs before any Setup, so
// nothing has touched the file yet, and in dump mode too, where such a configuration would
// print one tree as both handlers'.
//
// An in-memory store (no storage section, or type memory) is never shared: each Setup builds
// its own.
func checkSeparateLeaseStores(cfg *config.Config) error {
	enabled := enabledModules(cfg)
	if !slices.Contains(enabled, "update_handler") || !slices.Contains(enabled, "srp_handler") {
		return nil
	}

	updatePath, err := handlers.LeaseSnapshotPath(cfg.Handlers["update"])
	if err != nil {
		return fmt.Errorf("handlers.update: %w", err)
	}
	srpPath, err := handlers.LeaseSnapshotPath(cfg.Handlers["srp_handler"])
	if err != nil {
		return fmt.Errorf("handlers.srp_handler: %w", err)
	}
	if updatePath == "" || srpPath == "" {
		return nil
	}
	same, err := sameFile(updatePath, srpPath)
	if err != nil {
		return err
	}
	if same {
		return fmt.Errorf("handlers.update.storage.path %q and handlers.srp_handler.storage.path %q are the same file: update_handler and srp_handler must each have their own lease store", updatePath, srpPath)
	}
	return nil
}

// sameFile reports whether paths a and b name the same file: the same absolute path or, when
// both files already exist, the same file reached another way -- a symlink, a hard link, or a
// different spelling on a case-insensitive file system.
func sameFile(a, b string) (bool, error) {
	absA, err := filepath.Abs(a)
	if err != nil {
		return false, err
	}
	absB, err := filepath.Abs(b)
	if err != nil {
		return false, err
	}
	if absA == absB {
		return true, nil
	}

	infoA, err := os.Stat(absA)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	infoB, err := os.Stat(absB)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(infoA, infoB), nil
}

// enabledModules returns the handler module names the opcode routing enables, each once,
// sorted.
func enabledModules(cfg *config.Config) []string {
	var names []string
	for _, moduleNames := range cfg.GetOpcodeMap() {
		names = append(names, moduleNames...)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// proxyHandler is a handler module as cmd/sig0lease uses it: served, and dumped by --dump.
type proxyHandler interface {
	handlers.Handler
	DumpLeasesLevel(level string) string
}

// newHandler returns the handler module moduleName names, with its logger set but not yet
// Setup, and the config its Setup takes: a copy of its section under handlers in config.yaml,
// with the environment overrides and bootstrap resolvers applied, which the caller may change.
// ok is false for a name that is no handler module.
func newHandler(moduleName string, cfg *config.Config, logger *logging.Logger) (h proxyHandler, handlerCfg map[string]any, ok bool) {
	switch moduleName {
	case "update_handler":
		uh := handlers.NewUpdateHandler()
		uh.SetLogger(logger)
		return uh, withBootstrapResolvers(applyUpdateHandlerEnvOverrides(cfg.Handlers["update"]), cfg), true
	case "srp_handler":
		sh := handlers.NewSRPHandler()
		sh.SetLogger(logger)
		return sh, withBootstrapResolvers(cfg.Handlers["srp_handler"], cfg), true
	default:
		return nil, nil, false
	}
}

// dumpLeases writes the lease store of every configured handler to w, at level ("info" for a
// summary, "debug" for everything). It writes nothing else anywhere: the file store Setup would
// build from a "storage" section creates the snapshot's directory, writes the snapshot straight
// back and keeps saving it, so each handler is Setup with its store read once instead
// (handlers.LeaseStoreFromConfig, read-only), passed as "lease_manager". A dump never changes
// the snapshot of a proxy running beside it. Setup's other effect is a reconciliation ticker
// whose first tick, 30s away, a dump never reaches.
func dumpLeases(w io.Writer, cfg *config.Config, level string, logger *logging.Logger) error {
	printed := false
	for _, moduleName := range enabledModules(cfg) {
		h, handlerCfg, ok := newHandler(moduleName, cfg, logger)
		if !ok {
			continue
		}
		store, err := handlers.LeaseStoreFromConfig(handlerCfg, logger, true)
		if err != nil {
			return fmt.Errorf("failed to read the lease store of %s: %w", moduleName, err)
		}
		delete(handlerCfg, "storage")
		handlerCfg["lease_manager"] = store
		if err := h.Setup(handlerCfg); err != nil {
			return fmt.Errorf("failed to setup %s: %w", moduleName, err)
		}
		// DumpLeasesLevel's returned string already starts with its own "=== ... ===" header
		// line.
		if _, err := io.WriteString(w, h.DumpLeasesLevel(level)); err != nil {
			return err
		}
		printed = true
	}
	if !printed {
		_, err := fmt.Fprintln(w, "(no dump-capable handlers configured)")
		return err
	}
	return nil
}

func main() {
	cfgPath := "config.yaml"
	dumpMode := false
	dumpLevel := "info" // default: INFO (summary)

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--dump":
			dumpMode = true
		case "--dump-debug":
			dumpMode = true
			dumpLevel = "debug"
		default:
			cfgPath = os.Args[i]
		}
	}

	// Create logger. Default to "info": per-packet/per-request tracing is
	// available via DEBUG_LEVEL=debug, but shouldn't be on by default.
	logLevel := os.Getenv("DEBUG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	// LOG_OUTPUT picks where log lines go: stdout (the default), syslog, or both.
	logOutput := os.Getenv("LOG_OUTPUT")
	if logOutput == "" {
		logOutput = logging.OutputStdout
	}
	logger, err := logging.NewLoggerWithOutput(logLevel, logOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up logging (LOG_OUTPUT=%s): %v\n", logOutput, err)
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		logger.Errorf("Error loading config: %v", err)
		os.Exit(1)
	}
	if err := updatecore.SetMaxInflightUpdates(cfg.Authoritative.MaxInflightUpdates); err != nil {
		logger.Errorf("Error applying authoritative.max_inflight_updates: %v", err)
		os.Exit(1)
	}
	if err := checkSeparateLeaseStores(cfg); err != nil {
		logger.Errorf("Error in lease storage configuration: %v", err)
		os.Exit(1)
	}

	if dumpMode {
		if err := dumpLeases(os.Stdout, cfg, dumpLevel, logger); err != nil {
			logger.Errorf("%v", err)
			os.Exit(1)
		}
		return
	}

	logger.Infof("Starting DNS Proxy")
	if n := cfg.Authoritative.MaxInflightUpdates; n > 0 {
		logger.Infof("At most %d UPDATE(s) in flight to each authoritative server (authoritative.max_inflight_updates)", n)
	} else {
		logger.Infof("No limit on UPDATEs in flight to authoritative servers (authoritative.max_inflight_updates: 0)")
	}

	if v := os.Getenv("SERVER_ADDRESS"); v != "" {
		cfg.Server.Address = v
	}

	// Create server
	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Errorf("Error creating server: %v", err)
		os.Exit(1)
	}

	// Register processing module handlers based on configuration (each opcode maps
	// to an ordered list of module names, tried in turn -- e.g. [srp_handler,
	// update_handler] for opcode 5). Each named handler is constructed and Setup at
	// most once even if it appears under multiple opcodes.
	// Prepare handler configuration with upstream resolver for SIG(0) signing
	opcodeMap := cfg.GetOpcodeMap()
	registered := make(map[string]bool)
	for opcode, moduleNames := range opcodeMap {
		for _, moduleName := range moduleNames {
			if registered[moduleName] {
				logger.Infof("Module %s already registered (reused for opcode %d)", moduleName, opcode)
				continue
			}

			h, handlerCfg, ok := newHandler(moduleName, cfg, logger)
			if !ok {
				logger.Warnf("Unknown handler module: %s", moduleName)
				continue
			}
			// Setup configures upstream coordination too: the coordinator resolves the
			// authoritative server from upstream_zone and sends UPDATEs to it directly.
			if err := h.Setup(handlerCfg); err != nil {
				logger.Errorf("Failed to setup %s: %v", moduleName, err)
				os.Exit(1)
			}
			logger.Infof("Upstream coordination configured for %s", moduleName)

			srv.RegisterHandler(h)
			registered[moduleName] = true
			logger.Infof("Registered %s for opcode %d (%s)",
				moduleName, opcode, dns.OpcodeToString[opcode])
		}
	}

	// Start server
	if err := srv.Serve(); err != nil {
		logger.Errorf("Server error: %v", err)
		os.Exit(1)
	}
}
