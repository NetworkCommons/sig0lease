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

// parseLease extracts UPDATE-LEASE EDNS(0) data.
// Returns LEASE and KEY-LEASE values, and error if invalid.
// The decision between refresh and registration is NOT made here —
// it is determined by the caller based on lease existence (Lookup).
func (h *UpdateHandler) parseLease(msg *dns.Msg) (uint32, uint32, error) {
	// Minimums come from the configured lease_policy (min_rr_lease_sec /
	// min_key_lease_sec), matching clampTTL's convention elsewhere in this
	// handler: 0 means "no minimum enforced", not "use some hardcoded RFC
	// 9664 default". A proxy launched with a different policy (e.g. a lower
	// floor for testing) must actually enforce that policy here, at parse
	// time, since this check runs before any clamping does.
	minRRLease := h.LeasePolicy.MinRRLease
	minKeyLease := h.LeasePolicy.MinKeyLease

	erfc, found := leasepkg.FindOption(msg)
	if !found {
		return 0, 0, fmt.Errorf("no Update Lease EDNS option found")
	}
	lo, err := leasepkg.DecodeOption(erfc)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid lease option: %w", err)
	}

	if lo.KeyLease == nil {
		// 4-byte variant: only permitted when prefer_4byte_variant is configured.
		if minRRLease > 0 && lo.Lease < minRRLease {
			return 0, 0, fmt.Errorf("lease duration %d below minimum %d", lo.Lease, minRRLease)
		}
		if !h.prefer4ByteVariant {
			return 0, 0, fmt.Errorf("4-byte variant not permitted; prefer 8-byte variant")
		}
		return lo.Lease, 0, nil
	}

	// 8-byte variant: always valid (default mode).
	lease := lo.Lease
	keyLease := *lo.KeyLease

	// LEASE==0 is accepted for explicit delete semantics.
	if lease == 0 {
		if keyLease != 0 && minKeyLease > 0 && keyLease < minKeyLease {
			return 0, 0, fmt.Errorf("key-lease duration %d below minimum %d", keyLease, minKeyLease)
		}
		return lease, keyLease, nil
	}

	if minRRLease > 0 && lease < minRRLease {
		return 0, 0, fmt.Errorf("lease duration %d below minimum %d", lease, minRRLease)
	}

	// KEY-LEASE == 0 means no KEY RR lease operation.
	if keyLease != 0 {
		if minKeyLease > 0 && keyLease < minKeyLease {
			return 0, 0, fmt.Errorf("key-lease duration %d below minimum %d", keyLease, minKeyLease)
		}
		if lease > keyLease {
			return 0, 0, fmt.Errorf("lease duration %d cannot exceed key-lease duration %d", lease, keyLease)
		}
	}

	return lease, keyLease, nil
}
