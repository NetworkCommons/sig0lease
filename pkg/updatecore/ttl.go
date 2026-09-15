// Package updatecore holds forwarding plumbing shared by the RFC 9664 update-lease
// handler and the RFC 9665 SRP handler (see main/docs/rfc9665-srp-implementation-plan.md
// S4.1, D1/D8). It is a public package, not internal/, matching this repo's convention.
package updatecore

import (
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
)

// rrsetKey identifies an RRset for TTL-consistency purposes: RFC 2181 S5.2 defines an
// RRset as all RRs of a given type at a given owner name (class is implicitly IN
// throughout this proxy, but included here for correctness since a delete-all-RRset
// instruction and an add can legitimately carry different classes -- ANY/NONE vs IN --
// for what is otherwise the same name+type, and those are never the same RRset on the
// wire, so must never be merged into one TTL-consistency group).
type rrsetKey struct {
	name  string // canonical: lower-cased, trailing dot stripped
	class uint16
	rtype uint16
}

func canonicalOwnerName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func keyFor(rr dns.RR) rrsetKey {
	hdr := rr.Header()
	return rrsetKey{name: canonicalOwnerName(hdr.Name), class: hdr.Class, rtype: dns.RRToType(rr)}
}

// groupRRsets buckets records by rrsetKey, preserving each group's original relative
// order (not that order is meaningful here, but stable output makes tests and logs
// deterministic).
func groupRRsets(records []dns.RR) map[rrsetKey][]dns.RR {
	groups := make(map[rrsetKey][]dns.RR, len(records))
	for _, rr := range records {
		if rr == nil || rr.Header() == nil {
			continue
		}
		k := keyFor(rr)
		groups[k] = append(groups[k], rr)
	}
	return groups
}

// CheckConsistentTTLs implements the RFC 9665 S4 MUST for the SRP path: every RRset in
// an update must carry one TTL across all its RRs. Unlike NormalizeTTLs, this never
// rewrites anything -- SRP requires rejecting a violation outright (REFUSED), not
// silently correcting it. Returns the first inconsistency found, naming the owner,
// type, and the conflicting TTL values, or nil if every RRset present is consistent.
// Single-RR RRsets (the common case) are trivially consistent and never inspected
// beyond membership.
func CheckConsistentTTLs(records []dns.RR) error {
	for k, group := range groupRRsets(records) {
		if len(group) < 2 {
			continue
		}
		first := group[0].Header().TTL
		for _, rr := range group[1:] {
			if rr.Header().TTL != first {
				return fmt.Errorf("inconsistent TTLs in RRset %s %s %s: %d != %d",
					k.name, dns.ClassToString[k.class], dns.TypeToString[k.rtype], first, rr.Header().TTL)
			}
		}
	}
	return nil
}

// NormalizeTTLs implements the RFC 2181 S5.2 (erratum-corrected) guidance for the base
// RFC 9664 handler: a resolver encountering an RRset with differing TTLs should treat
// the lowest TTL as authoritative for the whole set. Unlike CheckConsistentTTLs, this
// mutates each affected RR's Hdr.TTL in place to its RRset's minimum, rather than
// rejecting the update -- the base handler's policy is "normalize", not "refuse". Must
// run before LeasePolicy clamping (S6) so clamping sees the already-uniform value.
// Returns the number of distinct RRsets that needed rewriting, for caller logging; 0
// means every RRset present was already consistent and nothing was touched.
func NormalizeTTLs(records []dns.RR) int {
	changed := 0
	for _, group := range groupRRsets(records) {
		if len(group) < 2 {
			continue
		}
		min := group[0].Header().TTL
		for _, rr := range group[1:] {
			if ttl := rr.Header().TTL; ttl < min {
				min = ttl
			}
		}
		groupChanged := false
		for _, rr := range group {
			if rr.Header().TTL != min {
				rr.Header().TTL = min
				groupChanged = true
			}
		}
		if groupChanged {
			changed++
		}
	}
	return changed
}
