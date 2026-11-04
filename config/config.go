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
	// Protocol is the protocol to use ("udp" or "tcp")
	Protocol string `yaml:"protocol"`
	// Timeout for upstream queries
	Timeout time.Duration `yaml:"timeout"`
}

// ServerConfig holds server listening configuration.
type ServerConfig struct {
	// Address is the address to listen on (e.g., ":53")
	Address string `yaml:"address"`
	// Networks are the network protocols to enable ("udp", "tcp", "tls", "doh")
	Networks []string `yaml:"networks"`
	// TLS configures the "tls" network (DNS-over-TLS, RFC 7858):
	// opportunistic only, no client-certificate/key-pinning auth -- transport-level, so it
	// benefits every handler (base RFC 9664, SRP, plain forwarding alike), not just one
	// protocol. Required when "tls" appears in Networks; ignored otherwise.
	TLS *TLSConfig `yaml:"tls,omitempty"`
	// DoH configures the "doh" network (DNS-over-HTTPS, RFC 8484), the one DNS transport a
	// web browser has. Transport-level, like TLS. Its certificate is optional: without one
	// it serves plain HTTP, which a page on a plain-HTTP origin (a laptop on the LAN) can
	// reach, as browsers refuse a self-signed certificate. Required when "doh" appears in
	// Networks; ignored otherwise.
	DoH *TLSConfig `yaml:"doh,omitempty"`
	// RequestTimeout bounds how long the handlers may work on one request, including any
	// wait for a lease-store node another request holds (docs/siglease_rfc9664.md, "Node
	// Locks"). Must be positive: without a bound, a waiter could wait forever.
	RequestTimeout time.Duration `yaml:"request_timeout"`
	// Diagnostics lets clients see the proxy's internals, for testing and debugging: the
	// reason text in the Extended DNS Error (RFC 8914) of each error reply, and the lease-store
	// dump query (__dump.sig0lease.internal[.debug]. TXT). Off by default, as it should be in
	// production: error replies then carry only the Extended DNS Error's code, and the dump
	// query is answered REFUSED with code 18 (Prohibited).
	Diagnostics bool `yaml:"diagnostics"`
}

// TLSConfig holds a listener's own address and certificate: the DNS-over-TLS listener's,
// and the DNS-over-HTTPS one's. A separate Address (rather than reusing
// ServerConfig.Address) because DoT conventionally listens on its own port (853, RFC 7858)
// alongside plain DNS on 53, and DoH on an HTTP port -- binding both to one address would
// collide, since they're independent net.Listeners either way.
type TLSConfig struct {
	// Address is the listener's own address (e.g., ":853" for DoT, ":8443" for DoH).
	Address string `yaml:"address"`
	// Cert is the path to a PEM-encoded certificate (or certificate chain).
	Cert string `yaml:"cert"`
	// Key is the path to the PEM-encoded private key matching Cert.
	Key string `yaml:"key"`
}

// validate checks the server.<network> block of a network that is enabled: it must be
// there, with an address; certRequired says whether it needs a certificate, which comes
// with its key either way.
func (t *TLSConfig) validate(network string, certRequired bool) error {
	if t == nil {
		return fmt.Errorf(`server.networks includes %q but server.%s is not configured`, network, network)
	}
	if t.Address == "" {
		return fmt.Errorf("server.%s.address cannot be empty", network)
	}
	if _, _, err := net.SplitHostPort(t.Address); err != nil {
		return fmt.Errorf("invalid server.%s.address %q: %w", network, t.Address, err)
	}
	if (t.Cert == "") != (t.Key == "") || (certRequired && t.Cert == "") {
		return fmt.Errorf("server.%s.cert and server.%s.key are both required", network, network)
	}
	return nil
}

// AuthoritativeConfig holds limits on the UPDATEs this proxy sends to authoritative servers.
type AuthoritativeConfig struct {
	// MaxInflightUpdates caps how many UPDATEs the proxy has in flight to one authoritative
	// server at a time; 0 means no limit. Every UPDATE it sends is SIG(0)-signed, and BIND 9.20
	// answers REFUSED to a SIG(0) request beyond its sig0checks-quota (default 1) instead of
	// queueing it, so set this to the upstream server's sig0checks-quota.
	MaxInflightUpdates int `yaml:"max_inflight_updates"`
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

	// Limits on the UPDATEs sent to authoritative servers, shared by every handler
	Authoritative AuthoritativeConfig `yaml:"authoritative"`
}

// NewDefaultConfig returns the defaults of the optional settings, which LoadConfig reads the
// config file over. The rest -- the server's address and networks, and the upstreams -- the
// file gives.
func NewDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			// Above the worst case of one authoritative UPDATE: a UDP attempt, then a TCP
			// fallback, at the dns library's default timeouts (about 11s).
			RequestTimeout: 15 * time.Second,
		},
		ProcessingRules: []ProcessingConfig{},
		Handlers:        make(map[string]map[string]interface{}),
		// BIND 9.20's default sig0checks-quota.
		Authoritative: AuthoritativeConfig{MaxInflightUpdates: 1},
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

	if len(c.Server.Networks) == 0 {
		return fmt.Errorf("server.networks must list at least one network")
	}

	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream must be configured")
	}

	if c.Server.RequestTimeout <= 0 {
		return fmt.Errorf("server.request_timeout must be positive, got %s", c.Server.RequestTimeout)
	}

	for _, network := range c.Server.Networks {
		switch network {
		case "tls":
			if err := c.Server.TLS.validate("tls", true); err != nil {
				return err
			}
		case "doh":
			if err := c.Server.DoH.validate("doh", false); err != nil {
				return err
			}
		}
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
		if _, _, err := net.SplitHostPort(upstream.Address); err != nil {
			return fmt.Errorf("upstream %d: invalid address %q: %w", i, upstream.Address, err)
		}
		if upstream.Protocol != "udp" && upstream.Protocol != "tcp" {
			return fmt.Errorf("upstream %d: protocol must be udp or tcp, got %q", i, upstream.Protocol)
		}
		if upstream.Timeout <= 0 {
			return fmt.Errorf("upstream %d: timeout must be positive, got %s", i, upstream.Timeout)
		}
	}

	if c.Authoritative.MaxInflightUpdates < 0 {
		return fmt.Errorf("authoritative.max_inflight_updates must be 0 (no limit) or more, got %d", c.Authoritative.MaxInflightUpdates)
	}

	return nil
}

// LoadConfig reads the configuration from the file at path, which must exist.
func LoadConfig(path string) (*Config, error) {
	cfg := NewDefaultConfig()

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
