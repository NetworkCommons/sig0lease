// Package dnsname implements DNS name case-insensitivity exactly as the DNS defines it:
// only the US-ASCII letters A-Z and a-z match each other; every other octet must match
// exactly (RFC 1035 S2.3.3, RFC 4343 S3). It is the one place the rest of the proxy should
// fold names for comparison or map keying.
//
// Go's strings.ToLower/strings.EqualFold are not a substitute: they fold Unicode, so they
// treat names BIND considers different as equal ("CAFÉ" vs "CAFé"; U+212A KELVIN SIGN vs
// ASCII "k"), and ToLower rewrites bytes that aren't valid UTF-8 to U+FFFD, changing the
// name's length. codeberg.org/miekg/dns keeps name labels as raw bytes (no \DDD escaping),
// so those bytes do reach the proxy -- DNS-SD instance names in particular are UTF-8 text
// (RFC 6763 S4.1.1). The library's own dnsutil.Canonical folds ASCII only but goes through
// strings.Map, which has the same U+FFFD rewrite, so it is not used either.
//
// It is likewise the one place the module splits a name into labels or checks that a string
// can be sent as one label (labels.go, whose opening comment explains why splitting at "."
// is exact for this library's name strings), and finds, in a wire-format message, the labels
// the library cannot carry (wire.go).
//
// Fold keeps a name's trailing dot, for code that works on fully-qualified names (pkg/srp,
// pkg/dnssd split them into labels ending in the empty root label); Normalize drops it, for
// the lease store, the handlers and pkg/updatecore, which key and compare names without it.
//
// This package depends only on the standard library, so any package in the module can
// import it.
package dnsname

import "strings"

// Normalize returns the form the lease store, the handlers and pkg/updatecore compare and
// key names by: surrounding whitespace trimmed (zone names also arrive from configuration),
// ASCII case folded (see Fold), and the trailing dot removed, so "Demo.Example.",
// "demo.example" and " demo.example. " all normalize to "demo.example".
func Normalize(name string) string {
	return strings.TrimSuffix(Fold(strings.TrimSpace(name)), ".")
}

// Fold returns name with the US-ASCII letters A-Z replaced by a-z and every other byte
// unchanged. The result always has the same length as name.
func Fold(name string) string {
	for i := 0; i < len(name); i++ {
		if isUpper(name[i]) {
			b := []byte(name)
			for j := i; j < len(b); j++ {
				if isUpper(b[j]) {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return name
}

// EqualFold reports whether a and b are equal under Fold, without allocating.
func EqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if fold(a[i]) != fold(b[i]) {
			return false
		}
	}
	return true
}

func isUpper(c byte) bool { return 'A' <= c && c <= 'Z' }

func fold(c byte) byte {
	if isUpper(c) {
		return c + 'a' - 'A'
	}
	return c
}
