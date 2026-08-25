// Package main implements the DNS proxy server.
package main

import (
	"fmt"
	"os"
	"strconv"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/handlers"
	"github.com/NetworkCommons/sig0lease/logging"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat"
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
// already sets its own. Without this, the handler's own SOA/NS zone-
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
	logger := logging.NewLogger(logLevel)

	// Load configuration
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		logger.Errorf("Error loading config: %v", err)
		os.Exit(1)
	}

	if dumpMode {
		// Dump mode: create handler, print lease state, exit.
		opcodeMap := cfg.GetOpcodeMap()
		for _, moduleName := range opcodeMap {
			if moduleName == "update_handler" {
				h := handlers.NewUpdateHandler()
				h.SetLogger(logger)

				handlerCfg := withBootstrapResolvers(applyUpdateHandlerEnvOverrides(cfg.Handlers["update"]), cfg)
				if handlerCfg != nil {
					if err := h.Setup(handlerCfg); err != nil {
						logger.Errorf("Failed to setup %s: %v", moduleName, err)
						os.Exit(1)
					}
				}

				// DumpLeasesLevel's returned string already starts with its
				// own "=== Lease Store Dump/Summary ===" header line; printing
				// it again here duplicated it, misplaced at the end instead
				// of the start.
				fmt.Print(h.DumpLeasesLevel(dumpLevel))
				return
			}
		}
		fmt.Println("(no update_handler configured)")
		return
	}

	logger.Infof("Starting DNS Proxy")

	if v := os.Getenv("SERVER_ADDRESS"); v != "" {
		cfg.Server.Address = v
	}

	// Create server
	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Errorf("Error creating server: %v", err)
		os.Exit(1)
	}

	// Register processing module handlers based on configuration
	// Prepare handler configuration with upstream resolver for SIG(0) signing
	opcodeMap := cfg.GetOpcodeMap()
	for opcode, moduleName := range opcodeMap {
		switch moduleName {
		case "update_handler":
			h := handlers.NewUpdateHandler()
			h.SetLogger(logger)

			// Setup handler with configuration for upstream coordination.
			// Coordinator resolves authoritative NS from upstream_zone and sends UPDATE directly.
			handlerCfg := withBootstrapResolvers(applyUpdateHandlerEnvOverrides(cfg.Handlers["update"]), cfg)
			if handlerCfg != nil {
				if err := h.Setup(handlerCfg); err != nil {
					logger.Errorf("Failed to setup %s: %v", moduleName, err)
					os.Exit(1)
				}
				logger.Infof("Upstream coordination configured for %s", moduleName)
			}

			srv.RegisterHandler(h)
			logger.Infof("Registered %s for opcode %d (%s)",
				moduleName, opcode, dns.OpcodeToString[opcode])

		default:
			logger.Warnf("Unknown handler module: %s", moduleName)
		}
	}

	// Start server
	if err := srv.Serve(); err != nil {
		logger.Errorf("Server error: %v", err)
		os.Exit(1)
	}
}
