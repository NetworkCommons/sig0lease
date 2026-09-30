package dnsname

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestLabels(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"widget._http._tcp.example.com.", []string{"widget", "_http", "_tcp", "example", "com", ""}},
		{"_http._tcp", []string{"_http", "_tcp"}},
		{"My Printer._ipp._tcp.example.", []string{"My Printer", "_ipp", "_tcp", "example", ""}},
		{".", []string{"", ""}},
		{"", nil},
	}
	for _, c := range cases {
		if got := Labels(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Labels(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCutFirstLabel(t *testing.T) {
	cases := []struct {
		in, first, rest string
		ok              bool
	}{
		{"Widget._http._tcp.example.com.", "Widget", "_http._tcp.example.com.", true},
		{"My Printer._ipp._tcp.example.", "My Printer", "_ipp._tcp.example.", true},
		{"example.com", "example", "com", true},
		{"com.", "com", "", true},
		{"com", "com", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		first, rest, ok := CutFirstLabel(c.in)
		if first != c.first || rest != c.rest || ok != c.ok {
			t.Errorf("CutFirstLabel(%q) = (%q, %q, %v), want (%q, %q, %v)", c.in, first, rest, ok, c.first, c.rest, c.ok)
		}
	}
}

func TestCheckLabel(t *testing.T) {
	for _, ok := range []string{"MyPrinter", "My Printer", "Café Printer", "_universal", strings.Repeat("a", 63)} {
		if err := CheckLabel(ok); err != nil {
			t.Errorf("CheckLabel(%q) = %v, want nil", ok, err)
		}
	}
	cases := []struct {
		label, wantErr string
	}{
		{"", "empty"},
		{strings.Repeat("a", 64), "at most 63"},
		{"Printer v2.1", "label boundary"},
		{"example.com.", "label boundary"},
	}
	for _, c := range cases {
		if err := CheckLabel(c.label); err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("CheckLabel(%q) = %v, want an error containing %q", c.label, err, c.wantErr)
		}
	}
}

// wireLabels encodes labels in wire format, each preceded by its length octet.
func wireLabels(labels ...string) []byte {
	var b []byte
	for _, l := range labels {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return b
}

// wireName encodes labels as an uncompressed wire-format name, root label included.
func wireName(labels ...string) []byte {
	return append(wireLabels(labels...), 0)
}

// libraryChanged ends every failure of TestLibraryReadsEveryDotAsLabelBoundary's checks on the
// library, since whoever sees one needs to know what it means before anything else.
const libraryChanged = "\n\ncodeberg.org/miekg/dns now escapes dots inside labels. Before changing anything, follow the ordered steps in docs/siglease_rfc9664.md, section \"When the library starts escaping dots\": two name checks in handlers/ must become label-aware before the dotted-label refusal is removed."

// TestLibraryReadsEveryDotAsLabelBoundary pins the codeberg.org/miekg/dns behavior labels.go
// is built on. If it fails, the library has started escaping dots inside labels: see
// libraryChanged for what to do.
func TestLibraryReadsEveryDotAsLabelBoundary(t *testing.T) {
	instance := wireName("Printer v2.1", "_ipp", "_tcp", "example")

	// A response with one PTR answer: _ipp._tcp.example. PTR <instance>.
	data := []byte{0x12, 0x34, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0}
	data = append(data, wireName("_ipp", "_tcp", "example")...)
	data = append(data, 0, byte(dns.TypePTR), 0, byte(dns.ClassINET), 0, 0, 0x0e, 0x10, 0, byte(len(instance)))
	data = append(data, instance...)

	m := &dns.Msg{Data: data}
	if err := m.Unpack(); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	ptr := m.Answer[0].(*dns.PTR)

	// Unpacking leaves the label's own dot unescaped...
	if want := "Printer v2.1._ipp._tcp.example."; ptr.Ptr != want {
		t.Fatalf("unpacked PTR target = %q, want %q%s", ptr.Ptr, want, libraryChanged)
	}
	if first, _, _ := CutFirstLabel(ptr.Ptr); first != "Printer v2" {
		t.Errorf("CutFirstLabel(%q) first label = %q, want %q%s", ptr.Ptr, first, "Printer v2", libraryChanged)
	}

	// ...packing splits at it (compression may point the rest of the name elsewhere, so only
	// the split labels are looked for)...
	out := dns.NewMsg("example.", dns.TypeSOA)
	out.Answer = []dns.RR{ptr}
	if err := out.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if split := wireLabels("Printer v2", "1"); !bytes.Contains(out.Data, split) {
		t.Errorf("packed %q did not split at the dot: want wire labels %q in %q%s", ptr.Ptr, split, out.Data, libraryChanged)
	}

	// ...and so does a backslash-escaped dot, keeping the backslash as a literal octet.
	esc := &dns.PTR{Hdr: dns.Header{Name: "_ipp._tcp.example.", Class: dns.ClassINET}}
	esc.Ptr = `Printer v2\.1._ipp._tcp.example.`
	out = dns.NewMsg("example.", dns.TypeSOA)
	out.Answer = []dns.RR{esc}
	if err := out.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if split := wireLabels(`Printer v2\`, "1"); !bytes.Contains(out.Data, split) {
		t.Errorf(`packed %q did not split at "\.": want wire labels %q in %q%s`, esc.Ptr, split, out.Data, libraryChanged)
	}
}
