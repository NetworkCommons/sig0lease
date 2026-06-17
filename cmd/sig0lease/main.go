// Package main implements the DNS proxy server.
package main

import (
	"fmt"
	"os"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/handlers"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/server"
)

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
	logger := logging.NewLogger("info", "text")
	logger.Infof("Starting DNS Proxy")

	// Create server
	srv, err := server.New(cfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating server: %v\n", err)
		os.Exit(1)
	}

	// Register processing module handlers based on configuration
	opcodeMap := cfg.GetOpcodeMap()
	for opcode, moduleName := range opcodeMap {
		switch moduleName {
		case "status_handler":
			h := handlers.NewStatusHandler()
			h.SetLogger(logger)
			srv.RegisterHandler(h)
			logger.Infof("Registered %s for opcode %d (%s)",
				moduleName, opcode, dns.OpcodeToString[opcode])
		case "update_handler":
			h := handlers.NewUpdateHandler()
			h.SetLogger(logger)
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
