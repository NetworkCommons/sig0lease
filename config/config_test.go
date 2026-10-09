package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

func TestAuthoritativeMaxInflightUpdates_DefaultsToOneAndRejectsNegative(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg.Authoritative.MaxInflightUpdates != 1 {
		t.Fatalf("expected the default to match BIND's default sig0checks-quota (1), got %d", cfg.Authoritative.MaxInflightUpdates)
	}
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
	cfg := NewDefaultConfig()
	if cfg.Server.RequestTimeout != 15*time.Second {
		t.Fatalf("expected a 15s default, got %s", cfg.Server.RequestTimeout)
	}
	for _, d := range []time.Duration{0, -time.Second} {
		cfg.Server.RequestTimeout = d
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected request_timeout %s to be rejected", d)
		}
	}
}

func TestServerRequestTimeout_ReadFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  address: \":8053\"\n  request_timeout: \"20s\"\n"), 0o600); err != nil {
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
