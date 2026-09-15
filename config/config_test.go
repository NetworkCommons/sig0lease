package config

import "testing"

func baseValidConfig() *Config {
	return &Config{
		Server:    ServerConfig{Address: ":8053", Networks: []string{"udp", "tcp"}},
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
