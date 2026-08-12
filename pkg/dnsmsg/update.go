package dnsmsg

import (
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/lease"
)

// NewLeaseUpdate builds a DNS UPDATE registration message with
// one optional KEY RR, optional additional RRs, and an 8-byte UPDATE-LEASE option.
func NewLeaseUpdate(zone string, keyRRs []*dns.KEY, additional []dns.RR, leaseDuration, keyLeaseDuration uint32) (*dns.Msg, error) {
	if strings.TrimSpace(zone) == "" {
		return nil, fmt.Errorf("zone cannot be empty")
	}
	msg := dns.NewMsg(zone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}
	msg.Opcode = dns.OpcodeUpdate

	if len(keyRRs) > 0 {
		for _, keyRR := range keyRRs {
			msg.Ns = append(msg.Ns, keyRR)
		}
	} else {
		if keyLeaseDuration != 0 {
			return nil, fmt.Errorf("keyRRs not present but keyLeaseDuration != 0")
		}
	}

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

// ParseAdditionalRRSpec parses a DNS RR in standard presentation format.
//
// Required form:
//
//	owner ttl class type rdata...
func ParseAdditionalRRSpec(spec string) (dns.RR, error) {

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
