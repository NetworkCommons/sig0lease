package client

import "testing"

// A Network reads back from its String, as text in a JSON document, and nothing else parses.
func TestNetwork_Text(t *testing.T) {
	for _, n := range []Network{NetworkTCP, NetworkUDP, NetworkTLS} {
		b, err := n.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var got Network
		if err := got.UnmarshalText(b); err != nil || got != n {
			t.Errorf("%s read back as %s, %v", n, got, err)
		}
	}
	if _, err := ParseNetwork("quic"); err == nil || err.Error() != `"quic": want tcp, udp or tls` {
		t.Errorf("ParseNetwork(quic) = %v, want it refused", err)
	}
}
