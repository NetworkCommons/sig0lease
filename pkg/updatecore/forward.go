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
//
// Unlike the base RFC 9664 handler's constructUpstreamUpdate (handlers/
// opcode5_update_helpers.go), this does no per-record-type branching or TTL clamping --
// S4.3 step 7's SRP forward is simpler by construction: it's exactly "the same
// adds/deletes [the requester sent], re-signed with proxy key" (plus, for a Service
// Description, the pkg/srp-computed PTR-delete diff appended by the caller before this is
// called -- see the plan's S4.4/S4.5). Any clamping SRP wants happens earlier, against the
// classified instructions, not here.
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
