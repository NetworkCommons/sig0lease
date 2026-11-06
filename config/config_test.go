package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// minimalYAML is a config file with only what the file must give, its server block last.
const minimalYAML = `upstreams:
  - address: "8.8.8.8:53"
    protocol: "udp"
    timeout: "5s"
server:
  address: ":8053"
  networks: [udp, tcp]
`

func baseValidConfig() *Config {
	return &Config{
		Server:    ServerConfig{Address: ":8053", Networks: []string{"udp", "tcp"}, RequestTimeout: 15 * time.Second},
		Upstreams: []UpstreamConfig{{Address: "8.8.8.8:53", Protocol: "udp", Timeout: 5}},
	}
}

func TestValidate_TLSNetworkWithoutServerTLS_Rejected(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Server.Networks = append(cfg.Server.Networks, "tls")
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error: \"tls\" in networks with no server.tls block")
	}
}

func TestValidate_TLSNetworkMissingFields_Rejected(t *testing.T) {
	cases := []struct {
		name string
		tls  *TLSConfig
	}{
		{"empty address", &TLSConfig{Address: "", Cert: "c.pem", Key: "k.pem"}},
		{"invalid address (no port)", &TLSConfig{Address: "127.0.0.1", Cert: "c.pem", Key: "k.pem"}},
		{"missing cert", &TLSConfig{Address: ":853", Cert: "", Key: "k.pem"}},
		{"missing key", &TLSConfig{Address: ":853", Cert: "c.pem", Key: ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := baseValidConfig()
			cfg.Server.Networks = append(cfg.Server.Networks, "tls")
			cfg.Server.TLS = c.tls
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected an error for %s", c.name)
			}
		})
	}
}

func TestValidate_TLSNetworkFullyConfigured_Accepted(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Server.Networks = append(cfg.Server.Networks, "tls")
	cfg.Server.TLS = &TLSConfig{Address: ":853", Cert: "c.pem", Key: "k.pem"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected a fully-configured server.tls block to validate, got: %v", err)
	}
}

func TestValidate_NoTLSNetwork_ServerTLSIgnoredIfAbsent(t *testing.T) {
	cfg := baseValidConfig() // no "tls" in Networks, no Server.TLS set
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected a plain udp/tcp config with no server.tls to validate, got: %v", err)
	}
}

// The "doh" network needs its server.doh block and an address; a certificate is optional
// (plain HTTP without one) but comes with its key.
func TestValidate_DoHNetwork(t *testing.T) {
	cases := []struct {
		name string
		doh  *TLSConfig
		good bool
	}{
		{"no server.doh block", nil, false},
		{"empty address", &TLSConfig{Address: ""}, false},
		{"invalid address (no port)", &TLSConfig{Address: "127.0.0.1"}, false},
		{"cert without key", &TLSConfig{Address: ":8443", Cert: "c.pem"}, false},
		{"key without cert", &TLSConfig{Address: ":8443", Key: "k.pem"}, false},
		{"plain HTTP", &TLSConfig{Address: ":8080"}, true},
		{"HTTPS", &TLSConfig{Address: ":8443", Cert: "c.pem", Key: "k.pem"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := baseValidConfig()
			cfg.Server.Networks = append(cfg.Server.Networks, "doh")
			cfg.Server.DoH = c.doh
			if err := cfg.Validate(); (err == nil) != c.good {
				t.Fatalf("Validate() = %v, want good=%v", err, c.good)
			}
		})
	}
}

func TestAuthoritativeMaxInflightUpdates_DefaultsToOneAndRejectsNegative(t *testing.T) {
	if got := NewDefaultConfig().Authoritative.MaxInflightUpdates; got != 1 {
		t.Fatalf("expected the default to match BIND's default sig0checks-quota (1), got %d", got)
	}
	cfg := baseValidConfig()
	cfg.Authoritative.MaxInflightUpdates = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected 0 (no limit) to be accepted, got %v", err)
	}
	cfg.Authoritative.MaxInflightUpdates = -1
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected a negative limit to be rejected")
	}
}

func TestServerRequestTimeout_DefaultsAndRejectsNonPositive(t *testing.T) {
	if got := NewDefaultConfig().Server.RequestTimeout; got != 15*time.Second {
		t.Fatalf("expected a 15s default, got %s", got)
	}
	cfg := baseValidConfig()
	for _, d := range []time.Duration{0, -time.Second} {
		cfg.Server.RequestTimeout = d
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected request_timeout %s to be rejected", d)
		}
	}
}

func TestServerRequestTimeout_ReadFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML+"  request_timeout: \"20s\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.RequestTimeout != 20*time.Second {
		t.Fatalf("expected request_timeout 20s from YAML, got %s", cfg.Server.RequestTimeout)
	}
}

// server.forward is off unless the file turns it on.
func TestServerForward_OffByDefaultAndReadFromYAML(t *testing.T) {
	if NewDefaultConfig().Server.Forward {
		t.Fatal("expected server.forward off by default")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML+"  forward: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.Server.Forward {
		t.Fatal("expected server.forward on from YAML")
	}
}

// The config file is mandatory: a missing one is an error, not built-in defaults.
func TestLoadConfig_MissingFileRejected(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "config.yaml")); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

// What the file must give has no default: leaving any of it out is an error.
func TestLoadConfig_RequiredSettingsRejectedWhenMissing(t *testing.T) {
	cases := map[string]string{
		"no server address": "upstreams:\n  - {address: \"8.8.8.8:53\", protocol: udp, timeout: 5s}\nserver:\n  networks: [udp]\n",
		"no networks":       "upstreams:\n  - {address: \"8.8.8.8:53\", protocol: udp, timeout: 5s}\nserver:\n  address: \":8053\"\n",
		"no upstreams":      "server:\n  address: \":8053\"\n  networks: [udp]\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatalf("expected an error for a config file with %s", name)
			}
		})
	}
}

func TestValidate_Upstream(t *testing.T) {
	cases := []struct {
		name     string
		upstream UpstreamConfig
		good     bool
	}{
		{"udp", UpstreamConfig{Address: "8.8.8.8:53", Protocol: "udp", Timeout: time.Second}, true},
		{"tcp", UpstreamConfig{Address: "8.8.8.8:53", Protocol: "tcp", Timeout: time.Second}, true},
		{"no address", UpstreamConfig{Protocol: "udp", Timeout: time.Second}, false},
		{"address without port", UpstreamConfig{Address: "8.8.8.8", Protocol: "udp", Timeout: time.Second}, false},
		{"no protocol", UpstreamConfig{Address: "8.8.8.8:53", Timeout: time.Second}, false},
		{"unsupported protocol", UpstreamConfig{Address: "8.8.8.8:53", Protocol: "https", Timeout: time.Second}, false},
		{"no timeout", UpstreamConfig{Address: "8.8.8.8:53", Protocol: "udp"}, false},
		{"negative timeout", UpstreamConfig{Address: "8.8.8.8:53", Protocol: "udp", Timeout: -time.Second}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := baseValidConfig()
			cfg.Upstreams = []UpstreamConfig{c.upstream}
			if err := cfg.Validate(); (err == nil) != c.good {
				t.Fatalf("Validate() = %v, want good=%v", err, c.good)
			}
		})
	}
}
