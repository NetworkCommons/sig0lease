package srp

import "strings"

// canonicalName lower-cases a DNS name for comparison/map-keying purposes, leaving the
// trailing dot intact (unlike handlers.canonicalName in the base RFC 9664 handler, which
// strips it) -- this package works entirely with fully-qualified, dot-terminated names, so
// keeping the dot avoids an extra normalization step at every call site that reconstructs
// or compares against a wire-derived name.
func canonicalName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// isSubtypePTROwner reports whether owner (a PTR RR's owner name) has the DNS-SD subtype
// shape "<sub>._sub.<Service>.<Domain>" (RFC 6763 S7.1) -- i.e. its second label is
// literally "_sub" -- and if so returns the base service type name ("<Service>.<Domain>",
// everything from the third label on). ok is false for a non-subtype (base-type) PTR
// owner name, in which case baseType is empty.
func isSubtypePTROwner(owner string) (baseType string, ok bool) {
	labels := splitLabels(canonicalName(owner))
	// Need at least: <sub> _sub <one-or-more base-type labels> root
	// i.e. len(labels) >= 4 including the trailing empty root label from the split.
	if len(labels) < 4 {
		return "", false
	}
	if labels[1] != "_sub" {
		return "", false
	}
	return strings.Join(labels[2:], "."), true
}

// splitLabels splits a canonical (already-lowercased, dot-terminated) DNS name into its
// labels, including a trailing empty string for the root label -- e.g.
// "_print._sub._ipps._tcp.example.com." -> ["_print","_sub","_ipps","_tcp","example","com",""].
// This is a presentation-format split (on literal "."), not wire-aware, which is fine here
// since every name this package handles has already round-tripped through the dns
// library's own name decompression into presentation form.
func splitLabels(name string) []string {
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}
