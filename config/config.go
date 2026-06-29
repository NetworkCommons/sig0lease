// Package config provides configuration for the DNS proxy.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ProcessingConfig holds opcode-specific processing configuration.
type ProcessingConfig struct {
	// Opcode is the DNS opcode to match (0=QUERY, 1=IQUERY, 2=STATUS, etc.)
	Opcode uint8 `yaml:"opcode"`
	// Module is the name of the processing module to handle this opcode
	Module string `yaml:"module"`
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
	// Networks are the network protocols to enable ("udp", "tcp")
	Networks []string `yaml:"networks"`
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

	// DefaultForward is the upstream to use for opcodes not in ProcessingRules
	DefaultForward string `yaml:"default_forward"`
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
		Handlers:       make(map[string]map[string]interface{}),
		DefaultForward: "8.8.8.8:53",
	}
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.Server.Address == "" {
		return fmt.Errorf("server address cannot be empty")
	}

	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream must be configured")
	}

	for i, rule := range c.ProcessingRules {
		if rule.Opcode > 15 {
			return fmt.Errorf("processing_rule %d: opcode must be between 0-15", i)
		}
		if rule.Module == "" {
			return fmt.Errorf("processing_rule %d: module name cannot be empty", i)
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

	// Parse default forward as address for validation
	if c.DefaultForward == "" {
		if len(c.Upstreams) > 0 {
			c.DefaultForward = c.Upstreams[0].Address
		} else {
			c.DefaultForward = "8.8.8.8:53"
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

// GetOpcodeMap creates a map from opcode to module name for fast lookup.
func (c *Config) GetOpcodeMap() map[uint8]string {
	opcodeMap := make(map[uint8]string)
	for _, rule := range c.ProcessingRules {
		opcodeMap[rule.Opcode] = rule.Module
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
