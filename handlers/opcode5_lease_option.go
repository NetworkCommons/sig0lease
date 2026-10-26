package handlers

import (
	"fmt"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

func (h *UpdateHandler) hasUpdateLeaseOption(msg *dns.Msg) bool {
	// RFC 9664 Section 4: UPDATE-LEASE is EDNS(0) option code 2
	h.logger.Debugf("hasUpdateLeaseOption: checking message with %d Pseudo and %d Extra records", len(msg.Pseudo), len(msg.Extra))
	_, found := leasepkg.FindOption(msg)
	if found {
		h.logger.Debugf("  Found UPDATE-LEASE option")
		return true
	}
	h.logger.Debugf("  No UPDATE-LEASE option found")
	return false
}

// decodeLease reads the request's Update Lease option (RFC 9664 S4) and applies this handler's
// variant policy: the 4-byte variant only with prefer_4byte_variant. On failure it also returns
// the RCODE to answer with -- FORMERR for an option RFC 9664 does not allow (a length other
// than 4 or 8, LEASE above KEY-LEASE), REFUSED for a 4-byte one this handler does not take,
// SERVFAIL for a request Handle should not have reached without one. Each fits the header's
// four RCODE bits: an extended RCODE (16 and up, its high bits in the OPT RR) reads as NOERROR
// to a requester that looks only at the header, as mDNSResponder does (mDNSCore/uDNS.c).
// REFUSED, not FORMERR, for the 4-byte variant also because mDNSResponder, sending to port 53,
// answers FORMERR by sending the update again without the option, which this proxy forwards
// upstream (hndlRecordUpdateReply in mDNSCore/uDNS.c).
func (h *UpdateHandler) decodeLease(msg *dns.Msg) (*leasepkg.LeaseOption, uint16, error) {
	erfc, found := leasepkg.FindOption(msg)
	if !found {
		// Handle takes only requests in which hasUpdateLeaseOption found the option.
		return nil, dns.RcodeServerFailure, fmt.Errorf("no Update Lease EDNS option found")
	}
	lo, err := leasepkg.DecodeOption(erfc)
	if err != nil {
		return nil, dns.RcodeFormatError, fmt.Errorf("invalid lease option: %w", err)
	}
	if lo.KeyLease == nil && !h.prefer4ByteVariant {
		return nil, dns.RcodeRefused, fmt.Errorf("4-byte variant not accepted: prefer_4byte_variant is off")
	}
	return lo, dns.RcodeSuccess, nil
}

// requestedLeases is the LEASE and KEY-LEASE that lo asks for, as this handler's case matrix
// reads them. The 8-byte variant carries both. The 4-byte variant carries one value for every
// record in the Update section (RFC 9664 S4: the KEYs and the other records expire together),
// so it is the KEY-LEASE when the section has KEY RRs and the LEASE when it has other records,
// and 0 for the kind it has none of: Case A with both kinds, B with non-KEY records only, D
// with KEYs only, and C for a value of 0. A section with no records at all keeps it as the
// LEASE, so it is refused as Case B refuses one.
func requestedLeases(lo *leasepkg.LeaseOption, hasKeyRRs, hasOtherRRs bool) (lease, keyLease uint32) {
	if lo.KeyLease != nil {
		return lo.Lease, *lo.KeyLease
	}
	if hasKeyRRs {
		keyLease = lo.Lease
	}
	if hasOtherRRs || !hasKeyRRs {
		lease = lo.Lease
	}
	return lease, keyLease
}

// grantedLeaseOption is the Update Lease option of the success reply: the granted LEASE and
// KEY-LEASE in the variant the request used (RFC 9664 S4). For a 4-byte request its one value
// is whichever of the two is set -- Handle makes them equal when both are -- or 0 for a delete.
func grantedLeaseOption(requested *leasepkg.LeaseOption, lease, keyLease uint32) *leasepkg.LeaseOption {
	if requested.KeyLease == nil {
		return leasepkg.Encode4Byte(max(lease, keyLease))
	}
	return leasepkg.Encode8Byte(lease, keyLease)
}
