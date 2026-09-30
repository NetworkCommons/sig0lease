package dnssd

import (
	"fmt"
	"strings"

	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
)

// ServiceTypeFromServiceName returns the two-label DNS-SD service type (e.g. "_http._tcp")
// of a name shaped "<Service>.<Domain>." -- a base-type browse name such as
// "_http._tcp.example.com.". RFC 6763 S7 fixes <Service> at exactly two labels: an
// underscore-prefixed Service Name, then "_tcp" or "_udp". ok is false for any other shape,
// e.g. "_vpnserver._wg._udp.example.com.", whose second label is "_wg".
//
// This is the registrar-side structural check: it doesn't hold the Service Name to RFC
// 6335's syntax rules (see ValidateServiceType for that), so a registrar keeps accepting
// types a sloppy but otherwise working requester sends.
func ServiceTypeFromServiceName(name string) (svcType string, ok bool) {
	labels := dnsname.Labels(dnsname.Fold(name))
	// service, proto, and at least the trailing empty root label from the split.
	if len(labels) < 3 || !isServiceLabel(labels[0]) || !isProtoLabel(labels[1]) {
		return "", false
	}
	return labels[0] + "." + labels[1], true
}

// ServiceTypeFromInstanceName extracts the two-label DNS-SD service type (e.g. "_http._tcp")
// from a Service Instance Name shaped "<Instance>.<Service>.<Domain>." -- RFC 6763 S4.1 is
// explicit that the Instance portion always occupies exactly one label, so <Service> always
// starts at the second label regardless of how many labels <Domain> itself has. ok is false
// if what follows the Instance label isn't a service name (ServiceTypeFromServiceName).
func ServiceTypeFromInstanceName(name string) (svcType string, ok bool) {
	_, service, found := dnsname.CutFirstLabel(name)
	if !found {
		return "", false
	}
	return ServiceTypeFromServiceName(service)
}

// ValidateServiceType checks svcType, a bare service type with no domain (e.g.
// "_http._tcp"), against RFC 6763 S7: exactly two labels, the first an underscore plus a
// Service Name valid per RFC 6335 S5.1, the second "_tcp" or "_udp". It is the requester's
// check -- stricter than ServiceTypeFromServiceName, since a requester should only ever send
// well-formed types.
func ValidateServiceType(svcType string) error {
	labels := dnsname.Labels(svcType)
	if len(labels) != 2 {
		return fmt.Errorf("service type %q must be exactly two labels, \"_<service>._tcp\" or \"_<service>._udp\" (RFC 6763 S7) -- to narrow a type further, register a subtype of it (RFC 6763 S7.1)", svcType)
	}
	service, proto := labels[0], labels[1]
	if !isProtoLabel(dnsname.Fold(proto)) {
		return fmt.Errorf("service type %q: second label must be _tcp or _udp, got %q (RFC 6763 S7)", svcType, proto)
	}
	if !strings.HasPrefix(service, "_") {
		return fmt.Errorf("service type %q: first label must be an underscore followed by the Service Name (RFC 6763 S7)", svcType)
	}
	if err := validateServiceNameSyntax(service[1:]); err != nil {
		return fmt.Errorf("service type %q: %w", svcType, err)
	}
	return nil
}

// validateServiceNameSyntax applies RFC 6335 S5.1's Service Name syntax: 1-15 characters,
// only US-ASCII letters, digits and hyphens, at least one letter, no leading or trailing
// hyphen, no two adjacent hyphens.
func validateServiceNameSyntax(name string) error {
	if len(name) < 1 || len(name) > 15 {
		return fmt.Errorf("Service Name %q must be 1-15 characters (RFC 6335 S5.1)", name)
	}
	hasLetter := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
			hasLetter = true
		case '0' <= c && c <= '9':
		case c == '-':
			if i == 0 || i == len(name)-1 || name[i-1] == '-' {
				return fmt.Errorf("Service Name %q must not begin or end with a hyphen or contain adjacent hyphens (RFC 6335 S5.1)", name)
			}
		default:
			return fmt.Errorf("Service Name %q may contain only letters, digits and hyphens (RFC 6335 S5.1)", name)
		}
	}
	if !hasLetter {
		return fmt.Errorf("Service Name %q must contain at least one letter (RFC 6335 S5.1)", name)
	}
	return nil
}

// isServiceLabel reports whether label is an underscore-prefixed Service Name label.
func isServiceLabel(label string) bool {
	return len(label) > 1 && label[0] == '_'
}

// isProtoLabel reports whether label (already case-folded) is one of RFC 6763 S7's two
// protocol labels.
func isProtoLabel(label string) bool {
	return label == "_tcp" || label == "_udp"
}
