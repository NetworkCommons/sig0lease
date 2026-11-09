package client

import "testing"

// A Network reads back from its String, as text in a JSON document, and nothing else parses.
func TestNetwork_Text(t *testing.T) {
	for _, n := range networks {
		b, err := n.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var got Network
		if err := got.UnmarshalText(b); err != nil || got != n {
			t.Errorf("%s read back as %s, %v", n, got, err)
		}
	}
	if _, err := ParseNetwork("quic"); err == nil || err.Error() != `"quic": want tcp, udp, tls or doh` {
		t.Errorf("ParseNetwork(quic) = %v, want it refused", err)
	}
}

// A DoH registrar is a URL with no path; every other one is host:port.
func TestNetwork_CheckServer(t *testing.T) {
	cases := []struct {
		n    Network
		s    string
		good bool
	}{
		{NetworkTCP, "127.0.0.1:8053", true},
		{NetworkTLS, "[::1]:853", true},
		{NetworkUDP, "127.0.0.1", false},
		{NetworkTCP, "host:port", false},
		{NetworkTCP, "http://127.0.0.1:8053", false},
		{NetworkDoH, "https://proxy.example:8443", true},
		{NetworkDoH, "http://127.0.0.1:8080/", true},
		{NetworkDoH, "127.0.0.1:8080", false},
		{NetworkDoH, "ftp://proxy.example", false},
		{NetworkDoH, "https://proxy.example/dns-query", false},
		{NetworkDoH, "https://proxy.example/?dns=x", false},
		{NetworkDoH, "https://", false},
	}
	for _, c := range cases {
		if err := c.n.CheckServer(c.s); (err == nil) != c.good {
			t.Errorf("%s CheckServer(%q) = %v, want good=%v", c.n, c.s, err, c.good)
		}
	}
}
