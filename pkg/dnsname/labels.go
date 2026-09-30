package dnsname

import (
	"fmt"
	"strings"
)

// This file is the one place the module splits a name into labels, or checks that a string
// can be sent as one label. A name here is a codeberg.org/miekg/dns name string, and in that
// form "." always ends a label. When the library unpacks a name it copies each label's bytes
// into the string as they are, so a label's own "." bytes land there unescaped. When it packs
// a name it splits at every ".", even one after a backslash: "\." is not an escape either
// (the library honors it only in the mailbox fields of SOA, RP, MINFO, MB, MG and MR). A
// label containing a "." byte therefore cannot be carried in a name string at all: an
// RFC 6763 S4.3 Instance label such as "Printer v2.1" unpacks to
// "Printer v2.1._ipp._tcp.example.com.", which reads -- and would pack again -- as the two
// labels "Printer v2" and "1".
//
// Splitting at "." is exact for every name the library can represent. Keeping it here, rather
// than in each caller, means that supporting such labels, if the library ever does, changes this
// file rather than every caller. docs/miekg-dns-escaped-names.patch proposes that library
// change; docs/siglease_rfc9664.md ("miekg/dns Shortcomings") lists what else would follow.

// maxLabelLength is the most octets one DNS label can hold (RFC 1035 S2.3.4).
const maxLabelLength = 63

// Labels splits name into its labels. A fully-qualified name's last element is the empty root
// label -- "widget._http._tcp.example.com." -> ["widget","_http","_tcp","example","com",""]
// -- so a caller can tell it from a relative name. Returns nil for "".
func Labels(name string) []string {
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// CutFirstLabel splits name after its first label, returning that label and the name that
// follows it: "Widget._http._tcp.example.com." -> ("Widget", "_http._tcp.example.com.", true).
// This is how a Service Instance Name divides into <Instance> and <Service>.<Domain>, since
// RFC 6763 S4.1 makes <Instance> exactly one label however many <Domain> has. ok is false if
// name is a single label with nothing after it, in which case first is name and rest is "".
func CutFirstLabel(name string) (first, rest string, ok bool) {
	return strings.Cut(name, ".")
}

// CheckLabel returns an error unless label can be sent as exactly one DNS label: 1 to 63
// octets, with no "." (which the library would send as a label boundary -- see above). RFC
// 6763 S4.3 requires software that joins an Instance label onto <Service>.<Domain> to keep
// that label boundary intact; with this library, refusing such a label is the only way to.
// Every other octet is allowed: S4.1.1 makes Instance labels arbitrary UTF-8 text, spaces
// included.
func CheckLabel(label string) error {
	switch {
	case label == "":
		return fmt.Errorf("label is empty")
	case len(label) > maxLabelLength:
		return fmt.Errorf("label %q is %d octets, but a DNS label holds at most %d (RFC 1035 S2.3.4)", label, len(label), maxLabelLength)
	case strings.Contains(label, "."):
		return fmt.Errorf("label %q contains \".\", which would be sent as a label boundary, splitting it into several labels (RFC 6763 S4.3 requires the boundary be kept)", label)
	}
	return nil
}
