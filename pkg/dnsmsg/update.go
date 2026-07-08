package dnsmsg

import (
	"fmt"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/lease"
)

// NewRegistrationUpdate builds a DNS UPDATE registration message with
// one KEY RR, optional additional RRs, and an 8-byte UPDATE-LEASE option.
func NewRegistrationUpdate(zone string, keyRR *dns.KEY, additional []dns.RR, leaseDuration, keyLeaseDuration uint32) (*dns.Msg, error) {
	if strings.TrimSpace(zone) == "" {
		return nil, fmt.Errorf("zone cannot be empty")
	}
	if keyRR == nil {
		return nil, fmt.Errorf("key RR cannot be nil")
	}

	msg := dns.NewMsg(zone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}
	msg.Opcode = dns.OpcodeUpdate
	msg.Ns = append(msg.Ns, keyRR)
	msg.Ns = append(msg.Ns, additional...)

	leaseOpt := lease.Encode8Byte(leaseDuration, keyLeaseDuration)
	if err := leaseOpt.Validate(); err != nil {
		return nil, err
	}
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	if err := leaseOpt.Encode(opt); err != nil {
		return nil, fmt.Errorf("failed to encode lease option: %w", err)
	}
	msg.Extra = append(msg.Extra, opt)
	return msg, nil
}

// NewRefreshUpdate builds a DNS UPDATE refresh message with one KEY RR and
// a lease option. By default callers should use 8-byte variant; 4-byte is for compatibility testing.
func NewRefreshUpdate(zone string, keyRR *dns.KEY, leaseDuration, keyLeaseDuration uint32, use4Byte bool) (*dns.Msg, error) {
	if strings.TrimSpace(zone) == "" {
		return nil, fmt.Errorf("zone cannot be empty")
	}
	if keyRR == nil {
		return nil, fmt.Errorf("key RR cannot be nil")
	}

	msg := dns.NewMsg(zone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}
	msg.Opcode = dns.OpcodeUpdate
	msg.Ns = append(msg.Ns, keyRR)

	var leaseOpt *lease.LeaseOption
	if use4Byte {
		leaseOpt = lease.Encode4Byte(leaseDuration)
	} else {
		leaseOpt = lease.Encode8Byte(leaseDuration, keyLeaseDuration)
	}
	if err := leaseOpt.Validate(); err != nil {
		return nil, err
	}
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	if err := leaseOpt.Encode(opt); err != nil {
		return nil, fmt.Errorf("failed to encode lease option: %w", err)
	}
	msg.Extra = append(msg.Extra, opt)
	return msg, nil
}

// EnsureFQDN returns name with a trailing dot if missing.
func EnsureFQDN(name string) string {
	if name == "" {
		return name
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func isLikelyDNSName(s string) bool {
	s = strings.TrimSpace(strings.TrimSuffix(s, "."))
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' {
			continue
		}
		return false
	}
	return strings.Contains(s, ".") || strings.HasPrefix(s, "@") || strings.HasPrefix(s, "*")
}

// ParseAdditionalRRSpec parses rr-spec values accepted by sig0lease-client register command:
// txt:<text>, txt:<name>:<text>, a:<ipv4>, a:<name>:<ipv4>, aaaa:<ipv6>, aaaa:<name>:<ipv6>.
func ParseAdditionalRRSpec(spec string, fallbackName string, ttl uint32) (dns.RR, error) {
	kv := strings.SplitN(spec, ":", 2)
	if len(kv) != 2 {
		return nil, fmt.Errorf("expected kind:value or kind:name:value")
	}

	kind := strings.ToLower(strings.TrimSpace(kv[0]))
	rest := strings.TrimSpace(kv[1])
	if rest == "" {
		return nil, fmt.Errorf("record value cannot be empty")
	}

	switch kind {
	case "txt":
		name := EnsureFQDN(fallbackName)
		value := rest
		if idx := strings.Index(rest, ":"); idx > 0 {
			candidateName := strings.TrimSpace(rest[:idx])
			candidateValue := strings.TrimSpace(rest[idx+1:])
			if candidateValue != "" && isLikelyDNSName(candidateName) {
				name = EnsureFQDN(candidateName)
				value = candidateValue
			}
		}
		rr := &dns.TXT{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}}
		rr.TXT.Txt = []string{value}
		return rr, nil
	case "a":
		name := EnsureFQDN(fallbackName)
		addrText := rest
		if addr, err := netip.ParseAddr(rest); err == nil && addr.Is4() {
			rr := &dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}}
			rr.A.Addr = addr
			return rr, nil
		}
		if idx := strings.Index(rest, ":"); idx > 0 {
			name = EnsureFQDN(strings.TrimSpace(rest[:idx]))
			addrText = strings.TrimSpace(rest[idx+1:])
		}
		addr, err := netip.ParseAddr(addrText)
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("invalid IPv4 address %q", addrText)
		}
		rr := &dns.A{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}}
		rr.A.Addr = addr
		return rr, nil
	case "aaaa":
		name := EnsureFQDN(fallbackName)
		addrText := rest
		if addr, err := netip.ParseAddr(rest); err == nil && addr.Is6() && !addr.Is4In6() {
			rr := &dns.AAAA{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}}
			rr.AAAA.Addr = addr
			return rr, nil
		}
		if idx := strings.Index(rest, ":"); idx > 0 {
			name = EnsureFQDN(strings.TrimSpace(rest[:idx]))
			addrText = strings.TrimSpace(rest[idx+1:])
		}
		addr, err := netip.ParseAddr(addrText)
		if err != nil || !addr.Is6() || addr.Is4In6() {
			return nil, fmt.Errorf("invalid IPv6 address %q", addrText)
		}
		rr := &dns.AAAA{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}}
		rr.AAAA.Addr = addr
		return rr, nil
	default:
		return nil, fmt.Errorf("unsupported rr kind %q (supported: txt,a,aaaa)", kind)
	}
}
