package updatecore

import (
	"fmt"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

// BuildAndSign constructs a new UPDATE message for upstreamZone containing prereqs (in the
// given order) as the Prerequisite section and records (in the given order) as the Update
// section, and signs it with signingKey. prereqs may be nil/empty -- most callers have none.
// Every UPDATE both handlers send is built here (handlers' upstreamTarget.send); it does no
// per-record-type branching, the callers assemble the records. The registrar's own TTLs are
// set earlier, against the classified instructions (handlers.applyRecordTTL), not here.
func BuildAndSign(upstreamZone string, prereqs, records []dns.RR, signingKey *keyrec.LoadedKey) (*dns.Msg, error) {
	if signingKey == nil || signingKey.PublicKey == nil || signingKey.PrivateKey == nil {
		return nil, fmt.Errorf("updatecore: signing key is not configured")
	}

	msg := dns.NewMsg(upstreamZone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("updatecore: failed to create upstream UPDATE message")
	}
	msg.Opcode = dns.OpcodeUpdate

	for _, rr := range prereqs {
		if rr == nil || rr.Header() == nil {
			continue
		}
		msg.Answer = append(msg.Answer, rr.Clone())
	}

	for _, rr := range records {
		if rr == nil || rr.Header() == nil {
			continue
		}
		msg.Ns = append(msg.Ns, rr.Clone())
	}

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	msg.Extra = append(msg.Extra, opt)

	signed, err := sig0.SignMessage(msg, signingKey.PublicKey, signingKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("updatecore: failed to sign upstream UPDATE: %w", err)
	}
	return signed, nil
}

// AsDelete returns a copy of rr rewritten as an RFC 2136 S2.5.4 "Delete An RR From An
// RRSet" instruction: class NONE, TTL 0, RDATA unchanged (which RR the delete targets is
// carried by NAME+TYPE+RDATA, same as any other RR identity in this codebase --
// pkg/lease.RecordKey uses the identical convention).
func AsDelete(rr dns.RR) dns.RR {
	cpy := rr.Clone()
	hdr := cpy.Header()
	hdr.Class = dns.ClassNONE
	hdr.TTL = 0
	return cpy
}
