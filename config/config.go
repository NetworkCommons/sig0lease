// Package config provides configuration for the DNS proxy.
package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ProcessingConfig holds opcode-specific processing configuration.
type ProcessingConfig struct {
	// Opcode is the DNS opcode to match (0=QUERY, 1=IQUERY, 2=STATUS, etc.)
	Opcode uint8 `yaml:"opcode"`
	// Modules is the ordered list of processing module names to try for this opcode:
	// the router calls each in turn until one returns Processed or Error; if every one
	// declines (NotRelevant), the opcode falls through to plain upstream forwarding. A
	// single-module list (the common case today, e.g. just "update_handler") behaves
	// exactly as the old single-"module" field did.
	Modules []string `yaml:"modules"`
}

// UpstreamConfig holds upstream resolver configuration.
type UpstreamConfig struct {
	// Address is the upstream DNS server address (e.g., "8.8.8.8:53")
	Address string `yaml:"address"`
	// Protocol is the protocol to use ("udp", "tcp", "tls", "https")
	Protocol string `yaml:"protocol"`
	// Timeout for upstream queries
	Timeout time.Duration `yaml:"timeout"`
}

// ServerConfig holds server listening configuration.
type ServerConfig struct {
	// Address is the address to listen on (e.g., ":53")
	Address string `yaml:"address"`
	// Networks are the network protocols to enable ("udp", "tcp", "tls")
	Networks []string `yaml:"networks"`
	// TLS configures the "tls" network (DNS-over-TLS, RFC 7858):
	// opportunistic only, no client-certificate/key-pinning auth -- transport-level, so it
	// benefits every handler (base RFC 9664, SRP, plain forwarding alike), not just one
	// protocol. Required when "tls" appears in Networks; ignored otherwise.
	TLS *TLSConfig `yaml:"tls,omitempty"`
}

// TLSConfig holds the DNS-over-TLS listener's own address and certificate. A separate
// Address (rather than reusing ServerConfig.Address) because DoT conventionally listens on
// its own port (853, RFC 7858) alongside plain DNS on 53 -- binding both to one address
// would collide, since they're two independent net.Listeners either way.
type TLSConfig struct {
	// Address is the DoT listener's own address (e.g., ":853").
	Address string `yaml:"address"`
	// Cert is the path to a PEM-encoded certificate (or certificate chain).
	Cert string `yaml:"cert"`
	// Key is the path to the PEM-encoded private key matching Cert.
	Key string `yaml:"key"`
}

// Config is the top-level configuration structure.
type Config struct {
	// Downstream server settings
	Server ServerConfig `yaml:"server"`

	// Upstream resolver settings
	Upstreams []UpstreamConfig `yaml:"upstreams"`

	// Opcode processing rules - opcodes listed here are processed by modules
	ProcessingRules []ProcessingConfig `yaml:"processing_rules"`

	// Handler-specific configuration (e.g., for update handler)
	Handlers map[string]map[string]interface{} `yaml:"handlers"`
}

// NewDefaultConfig returns a configuration with sensible defaults.
func NewDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Address:  ":8053", // Use non-privileged port by default
			Networks: []string{"udp", "tcp"},
		},
		ProcessingRules: []ProcessingConfig{},
		Upstreams: []UpstreamConfig{
			{
				Address:  "8.8.8.8:53",
				Protocol: "udp",
				Timeout:  5 * time.Second,
			},
			{
				Address:  "1.1.1.1:53",
				Protocol: "udp",
				Timeout:  5 * time.Second,
			},
		},
		Handlers: make(map[string]map[string]interface{}),
	}
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.Server.Address == "" {
		return fmt.Errorf("server address cannot be empty")
	}
	if _, _, err := net.SplitHostPort(c.Server.Address); err != nil {
		return fmt.Errorf("invalid server address %q: %w", c.Server.Address, err)
	}

	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream must be configured")
	}

	for _, network := range c.Server.Networks {
		if network != "tls" {
			continue
		}
		if c.Server.TLS == nil {
			return fmt.Errorf(`server.networks includes "tls" but server.tls is not configured`)
		}
		if c.Server.TLS.Address == "" {
			return fmt.Errorf("server.tls.address cannot be empty")
		}
		if _, _, err := net.SplitHostPort(c.Server.TLS.Address); err != nil {
			return fmt.Errorf("invalid server.tls.address %q: %w", c.Server.TLS.Address, err)
		}
		if c.Server.TLS.Cert == "" || c.Server.TLS.Key == "" {
			return fmt.Errorf("server.tls.cert and server.tls.key are both required")
		}
		break
	}

	for i, rule := range c.ProcessingRules {
		if rule.Opcode > 15 {
			return fmt.Errorf("processing_rule %d: opcode must be between 0-15", i)
		}
		if len(rule.Modules) == 0 {
			return fmt.Errorf("processing_rule %d: modules list cannot be empty", i)
		}
		for j, name := range rule.Modules {
			if name == "" {
				return fmt.Errorf("processing_rule %d: modules[%d] name cannot be empty", i, j)
			}
		}
	}

	for i, upstream := range c.Upstreams {
		if upstream.Address == "" {
			return fmt.Errorf("upstream %d: address cannot be empty", i)
		}
		if upstream.Timeout <= 0 {
			c.Upstreams[i].Timeout = 5 * time.Second
		}
	}

	return nil
}

// LoadConfig reads configuration from a file.
func LoadConfig(path string) (*Config, error) {
	cfg := NewDefaultConfig()

	// Check if config file exists
	if _, err := os.Stat(path); err != nil {
		// File doesn't exist - use defaults
		return cfg, cfg.Validate()
	}

	// Read and parse the YAML config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, cfg.Validate()
}

// GetOpcodeMap creates a map from opcode to its ordered module list for fast lookup.
func (c *Config) GetOpcodeMap() map[uint8][]string {
	opcodeMap := make(map[uint8][]string)
	for _, rule := range c.ProcessingRules {
		opcodeMap[rule.Opcode] = rule.Modules
	}
	return opcodeMap
}

// GetKeystoreDir returns the keystore directory from handler configuration.
// Returns empty string if not configured.
func (c *Config) GetKeystoreDir() string {
	if c.Handlers != nil {
		if updateHandlerCfg, ok := c.Handlers["update"]; ok {
			if dir, ok := updateHandlerCfg["keystore_dir"].(string); ok && dir != "" {
				return dir
			}
		}
	}
	return ""
}

// Use4ByteVariant returns true if 4-byte variant is explicitly enabled via config.
// Returns false by default (8-byte variant is the default for all lease requests).
func (c *Config) Use4ByteVariant() bool {
	if c.Handlers != nil {
		if updateHandlerCfg, ok := c.Handlers["update"]; ok {
			if prefer, ok := updateHandlerCfg["prefer_4byte_variant"].(bool); ok {
				return prefer
			}
		}
	}
	return false
}
