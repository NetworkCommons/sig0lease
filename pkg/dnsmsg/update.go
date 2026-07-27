package dnsmsg

import (
	"fmt"
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

// ParseAdditionalRRSpec parses a DNS RR in standard presentation format.
//
// Required form:
//
//	owner ttl class type rdata...
func ParseAdditionalRRSpec(spec string, fallbackName string, ttl uint32) (dns.RR, error) {
	_ = fallbackName
	_ = ttl

	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("rr spec cannot be empty")
	}

	rr, err := dns.New(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid rr spec %q: expected full RR presentation (owner ttl class type rdata): %w", spec, err)
	}
	if rr == nil {
		return nil, fmt.Errorf("invalid rr spec %q: parser returned nil RR", spec)
	}

	return rr, nil
}

// NewDataOnlyUpdate builds a DNS UPDATE message with only data RRs (no KEY RR) and
// an 8-byte UPDATE-LEASE EDNS option with KEY-LEASE = 0.
// Per RFC 9664 §4, KEY-LEASE == 0 means "no KEY RRs are being registered".
// This is used for data-only operations where the client's key is resolved
// from the lease store or DNS server on the proxy side.
func NewDataOnlyUpdate(zone string, additional []dns.RR, leaseDuration uint32) (*dns.Msg, error) {
	if strings.TrimSpace(zone) == "" {
		return nil, fmt.Errorf("zone cannot be empty")
	}
	// Additional RRs are optional — a refresh with KEY-LEASE == 0 may not
	// include any data RRs; the proxy resolves them from the lease store.

	msg := dns.NewMsg(zone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}
	msg.Opcode = dns.OpcodeUpdate

	// Only data RRs in the authority section — no KEY RR.
	msg.Ns = append(msg.Ns, additional...)

	// 8-byte UPDATE-LEASE with KEY-LEASE = 0 (no KEY RRs being registered).
	leaseOpt := lease.Encode8Byte(leaseDuration, 0)
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
