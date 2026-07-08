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

	rawPolicy, _ := out["ttl_policy"].(map[string]any)
	if rawPolicy == nil {
		rawPolicy = make(map[string]any)
	}
	setUintEnv(rawPolicy, "TTL_POLICY_MIN_KEY_TTL", "min_key_ttl")
	setUintEnv(rawPolicy, "TTL_POLICY_MAX_KEY_TTL", "max_key_ttl")
	setUintEnv(rawPolicy, "TTL_POLICY_MIN_RR_TTL", "min_rr_ttl")
	setUintEnv(rawPolicy, "TTL_POLICY_MAX_RR_TTL", "max_rr_ttl")
	if len(rawPolicy) > 0 {
		out["ttl_policy"] = rawPolicy
	}

	return out
}

func main() {
	cfgPath := "config.yaml"

	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	// Load configuration
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Create logger
	logLevel := os.Getenv("DEBUG_LEVEL")
	if logLevel == "" {
		logLevel = "debug"
	}
	logger := logging.NewLogger(logLevel, "text")
	logger.Infof("Starting DNS Proxy")

	if v := os.Getenv("SERVER_ADDRESS"); v != "" {
		cfg.Server.Address = v
	}

	// Create server
	srv, err := server.New(cfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating server: %v\n", err)
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
			handlerCfg := applyUpdateHandlerEnvOverrides(cfg.Handlers["update"])
			if handlerCfg != nil {
				if err := h.Setup(handlerCfg); err != nil {
					logger.Warnf("Failed to setup %s: %v", moduleName, err)
				} else {
					logger.Infof("Upstream coordination configured for %s", moduleName)
				}
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
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
