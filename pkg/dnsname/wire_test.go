package dnsname

import (
	"bytes"
	"testing"

	"codeberg.org/miekg/dns"
)

// packedUpdate packs an UPDATE for zone carrying rrs, as a client would send it.
func packedUpdate(t *testing.T, zone string, rrs ...string) []byte {
	t.Helper()
	m := dns.NewMsg(zone, dns.TypeSOA)
	m.Opcode = dns.OpcodeUpdate
	for _, s := range rrs {
		rr, err := dns.New(s)
		if err != nil {
			t.Fatalf("dns.New(%q): %v", s, err)
		}
		m.Ns = append(m.Ns, rr)
	}
	if err := m.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return m.Data
}

// withDot turns the wire label from, which must occur in msg, into to, which has the same
// length and holds a ".": what a client sends for a label with a dot in it, which the library
// cannot produce itself. Same length, so compression pointers into it stay valid.
func withDot(t *testing.T, msg []byte, from, to string) []byte {
	t.Helper()
	f, r := wireLabels(from), wireLabels(to)
	if !bytes.Contains(msg, f) {
		t.Fatalf("wire message has no %q label", from)
	}
	return bytes.ReplaceAll(msg, f, r)
}

func TestDottedWireLabel(t *testing.T) {
	const zone = "example."
	srp := []string{
		"host.example. 3600 IN A 192.0.2.1",
		"printerv2x1._ipp._tcp.example. 3600 IN SRV 0 0 631 host.example.",
		`printerv2x1._ipp._tcp.example. 3600 IN TXT "txtvers=1"`,
		"_ipp._tcp.example. 3600 IN PTR printerv2x1._ipp._tcp.example.",
	}

	cases := []struct {
		name      string
		msg       []byte
		wantLabel string
	}{
		{"no dotted label", packedUpdate(t, zone, srp...), ""},
		{"dotted instance label", withDot(t, packedUpdate(t, zone, srp...), "printerv2x1", "printerv2.1"), "printerv2.1"},
		{"dotted host label, also the SRV target", withDot(t, packedUpdate(t, zone, srp...), "host", "ho.t"), "ho.t"},
		{"dotted label only in a PTR target", withDot(t, packedUpdate(t, zone, "_ipp._tcp.example. 3600 IN PTR ab.x._ipp._tcp.example."), "ab", "a."), "a."},
		{"dotted label only in an SRV target", withDot(t, packedUpdate(t, zone, "x._ipp._tcp.example. 3600 IN SRV 0 0 631 hostx.other."), "hostx", "host."), "host."},
		{"dotted label only in an HTTPS target", withDot(t, packedUpdate(t, zone, "example. 3600 IN HTTPS 1 svcx.cdn. alpn=h2"), "svcx", "sv.x"), "sv.x"},
		{"dotted zone name", withDot(t, packedUpdate(t, "zonex.", "a.zonex. 3600 IN A 192.0.2.1"), "zonex", "zon.x"), "zon.x"},
		// A dot in a mailbox's first label is ordinary, and the library escapes it there.
		{"dotted SOA mailbox", packedUpdate(t, zone, `example. 3600 IN SOA ns.example. john\.doe.example. 1 2 3 4 5`), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			label, found, err := DottedWireLabel(c.msg)
			if err != nil {
				t.Fatalf("DottedWireLabel: %v", err)
			}
			if found != (c.wantLabel != "") || label != c.wantLabel {
				t.Fatalf("DottedWireLabel = (%q, %v), want %q", label, found, c.wantLabel)
			}
		})
	}

	// The SOA case must really carry "john.doe" as one wire label, or it proves nothing.
	if soa := packedUpdate(t, zone, `example. 3600 IN SOA ns.example. john\.doe.example. 1 2 3 4 5`); !bytes.Contains(soa, wireLabels("john.doe")) {
		t.Fatalf("SOA mailbox was not packed as the single label \"john.doe\": %q", soa)
	}
}

func TestDottedWireLabel_Malformed(t *testing.T) {
	good := packedUpdate(t, "example.", "host.example. 3600 IN A 192.0.2.1")
	header := func(qdcount byte) []byte { return []byte{0, 0, 0x28, 0, 0, qdcount, 0, 0, 0, 0, 0, 0} }
	cases := []struct {
		name string
		msg  []byte
	}{
		{"shorter than a header", good[:11]},
		{"truncated record", good[:len(good)-2]},
		{"pointer to itself", append(header(1), 0xC0, 12, 0, 6, 0, 1)},
		{"pointer loop", append(header(1), 1, 'a', 0xC0, 12, 0, 6, 0, 1)},
		{"reserved label type", append(header(1), 0x40, 0, 0, 6, 0, 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := DottedWireLabel(c.msg); err == nil {
				t.Fatalf("DottedWireLabel(%q) = nil error, want one", c.msg)
			}
		})
	}
}
