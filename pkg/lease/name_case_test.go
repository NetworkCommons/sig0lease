package lease

import (
	"testing"

	"codeberg.org/miekg/dns"
)

// TestRecordKey_NameCase pins RecordKey to the RFC 2136 S1.1 equality BIND applies: names
// compare case-insensitively for US-ASCII letters only (S1.1.2 -> RFC 1035 S2.3.3), and that
// includes names embedded in RDATA of the RFC 4034 S6.2 types (PTR, SRV, MX, ...), while
// TXT character-strings stay case-sensitive.
func TestRecordKey_NameCase(t *testing.T) {
	ptr := func(owner, target string) dns.RR {
		p := &dns.PTR{Hdr: dns.Header{Name: owner, Class: dns.ClassINET, TTL: 30}}
		p.Ptr = target
		return p
	}
	rr := func(s string) dns.RR {
		r, err := dns.New(s)
		if err != nil {
			t.Fatalf("dns.New(%q): %v", s, err)
		}
		return r
	}

	cases := []struct {
		desc string
		a, b dns.RR
		same bool
	}{
		{"owner name, ASCII case only", rr("DemoScene.example. 30 IN A 192.0.2.1"), rr("demoscene.example. 30 IN A 192.0.2.1"), true},
		{"PTR target, ASCII case only", ptr("_http._tcp.example.", "DemoScene._http._tcp.example."), ptr("_http._tcp.example.", "demoscene._http._tcp.example."), true},
		{"SRV target, ASCII case only", rr("i._http._tcp.example. 30 IN SRV 0 0 668 Demo.example."), rr("i._http._tcp.example. 30 IN SRV 0 0 668 demo.example."), true},
		{"MX exchange, ASCII case only", rr("example. 30 IN MX 10 Mail.example."), rr("example. 30 IN MX 10 mail.example."), true},
		{"TXT data is not a name", rr(`i.example. 30 IN TXT "Path=/"`), rr(`i.example. 30 IN TXT "path=/"`), false},
		{"PTR target, non-ASCII letters", ptr("_http._tcp.example.", "CAFÉ._http._tcp.example."), ptr("_http._tcp.example.", "CAFé._http._tcp.example."), false},
		{"owner name, non-ASCII letters", ptr("CAFÉ.example.", "x.example."), ptr("CAFé.example.", "x.example."), false},
		{"owner name, KELVIN SIGN vs k", ptr("Kitchen.example.", "x.example."), ptr("kitchen.example.", "x.example."), false},
	}
	for _, c := range cases {
		ka, kb := RecordKey(c.a), RecordKey(c.b)
		if (ka == kb) != c.same {
			t.Errorf("%s: RecordKey equal = %v, want %v\n  a: %q\n  b: %q", c.desc, ka == kb, c.same, ka, kb)
		}
	}
}

func TestNodeKey_FoldsOnlyASCII(t *testing.T) {
	if NodeKey(testKeyRR("DemoScene.example.", "AAAA=")) != NodeKey(testKeyRR("demoscene.example.", "AAAA=")) {
		t.Error("names differing only in ASCII case must share a node key")
	}
	if NodeKey(testKeyRR("Kitchen.example.", "AAAA=")) == NodeKey(testKeyRR("kitchen.example.", "AAAA=")) {
		t.Error("KELVIN SIGN and ASCII 'k' are different DNS names and must not share a node key")
	}
	if NodeKey(testKeyRR("CAFÉ.example.", "AAAA=")) == NodeKey(testKeyRR("café.example.", "AAAA=")) {
		t.Error("'É' and 'é' are different DNS octets and must not share a node key")
	}
}
