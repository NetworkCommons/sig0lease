// Package updatecore holds forwarding plumbing shared by the RFC 9664 update-lease
// handler and the RFC 9665 SRP handler (see docs/siglease_rfc9665.md's upstream forward
// section). It is a public package, not internal/, matching this repo's convention.
package updatecore

import (
	"fmt"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
)

// rrsetKey identifies an RRset for TTL-consistency purposes: RFC 2181 S5.2 defines an
// RRset as all RRs of a given type at a given owner name (class is implicitly IN
// throughout this proxy, but included here for correctness since a delete-all-RRset
// instruction and an add can legitimately carry different classes -- ANY/NONE vs IN --
// for what is otherwise the same name+type, and those are never the same RRset on the
// wire, so must never be merged into one TTL-consistency group).
type rrsetKey struct {
	name  string // dnsname.Normalize form
	class uint16
	rtype uint16
}

func keyFor(rr dns.RR) rrsetKey {
	hdr := rr.Header()
	return rrsetKey{name: dnsname.Normalize(hdr.Name), class: hdr.Class, rtype: dns.RRToType(rr)}
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
// an update must carry one TTL across all its RRs. It never rewrites anything -- SRP
// requires rejecting a violation outright (REFUSED), not silently correcting it. Returns the first inconsistency found, naming the owner,
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
