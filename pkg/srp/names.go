package srp

import (
	"strings"

	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
)

// isSubtypePTROwner reports whether owner (a PTR RR's owner name) has the DNS-SD subtype
// shape "<sub>._sub.<Service>.<Domain>" (RFC 6763 S7.1) -- i.e. its second label is
// literally "_sub" -- and if so returns the base service type name ("<Service>.<Domain>",
// everything from the third label on). ok is false for a non-subtype (base-type) PTR
// owner name, in which case baseType is empty.
func isSubtypePTROwner(owner string) (baseType string, ok bool) {
	labels := dnsname.Labels(dnsname.Fold(owner))
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
