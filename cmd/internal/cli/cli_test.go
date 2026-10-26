package cli

import (
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/NetworkCommons/sig0lease/client"
)

// The shared flags parse with their defaults, -transport through client.Network.
func TestRequest_Define(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var r Request
	r.Define(fs, "server")
	if err := fs.Parse([]string{"-server", "127.0.0.1:8053", "-transport", "tls", "-key-lease", "60"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.Server != "127.0.0.1:8053" || r.Transport != client.NetworkTLS || r.Lease != 3600 || r.KeyLease != 60 || r.TTL != 300 {
		t.Fatalf("parsed %+v", r)
	}
	if err := fs.Parse([]string{"-transport", "quic"}); err == nil {
		t.Fatalf("-transport quic parsed")
	}
}

func TestChecks(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"lease too long", (&Request{Lease: 1 << 32, TTL: 1}).Check(), "32 bits"},
		{"no TTL", (&Request{}).Check(), "-ttl"},
		{"algorithm", (&Request{TTL: 1, KeyAlg: 256}).Check(), "-k"},
		{"no server", (&Endpoint{}).RequireServer(), "-server is required"},
		{"once and deregister", (&Modes{Once: true, Deregister: true}).Check(), "give one"},
		{"keep-names alone", (&Modes{KeepNames: true}).Check(), "-keep-names is for -deregister"},
		{"fine", (&Modes{Deregister: true, KeepNames: true}).Check(), ""},
	} {
		if tc.want == "" && tc.err != nil || tc.want != "" && (tc.err == nil || !strings.Contains(tc.err.Error(), tc.want)) {
			t.Errorf("%s: error %v, want one containing %q", tc.name, tc.err, tc.want)
		}
	}
}
