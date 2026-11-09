package dnsmsg

import (
	"bytes"
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
)

// allOctets is every octet, as one string.
func allOctets() string {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return string(b)
}

// TestEscapeTXT_IsTheLibrarysForm: a TXT string made with EscapeTXT packs to the raw octets,
// and the library unpacks them into the same string.
func TestEscapeTXT_IsTheLibrarysForm(t *testing.T) {
	all := allOctets()
	for _, raw := range []string{"", "plain", "a\\b\x00\xff\"q", "café ☕", all[:128], all[128:]} {
		txt := &dns.TXT{Hdr: dns.Header{Name: "x.", Class: dns.ClassINET}}
		txt.TXT.Txt = []string{EscapeTXT(raw)}
		m := &dns.Msg{Answer: []dns.RR{txt}}
		if err := m.Pack(); err != nil {
			t.Fatal(err)
		}
		if want := append([]byte{byte(len(raw))}, raw...); !bytes.HasSuffix(m.Data, want) {
			t.Errorf("%q: packed TXT ends % x, want % x", raw, m.Data[len(m.Data)-len(want):], want)
		}
		back := &dns.Msg{Data: m.Data}
		if err := back.Unpack(); err != nil {
			t.Fatal(err)
		}
		if got := back.Answer[0].(*dns.TXT).Txt[0]; got != txt.Txt[0] {
			t.Errorf("%q: unpacked %q, EscapeTXT %q", raw, got, txt.Txt[0])
		}
	}
}

func TestUnescapeTXT(t *testing.T) {
	all := allOctets()
	if got := UnescapeTXT(EscapeTXT(all)); got != all {
		t.Fatalf("UnescapeTXT(EscapeTXT(every octet)) = %q", got)
	}
	for s, want := range map[string]string{
		`caf\195\169`: "café",
		`\"hi\"`:      `"hi"`,
		`\o/`:         "o/",
		`a\12`:        "a12",
		`end\`:        "end",
		`\\032`:       `\032`,
	} {
		if got := UnescapeTXT(s); got != want {
			t.Errorf("UnescapeTXT(%q) = %q, want %q", s, got, want)
		}
	}
}

// TestTXTStrings: each string's octets, in order; an empty list, not nil, for none.
func TestTXTStrings(t *testing.T) {
	rr, err := dns.New(`x. TXT "caf\195\169" "\"hi\"" ""`)
	if err != nil {
		t.Fatal(err)
	}
	got := TXTStrings(rr.(*dns.TXT))
	if want := []string{"café", `"hi"`, ""}; !slices.Equal(got, want) {
		t.Fatalf("TXTStrings = %q, want %q", got, want)
	}
	if got := TXTStrings(&dns.TXT{}); got == nil || len(got) != 0 {
		t.Fatalf("TXTStrings of no strings = %#v, want empty, not nil", got)
	}
}
