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
	const MinLeaseDuration = 30 // RFC 9664 minimum

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
		if lo.Lease < MinLeaseDuration {
			return 0, 0, fmt.Errorf("lease duration %d below minimum %d", lo.Lease, MinLeaseDuration)
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
		if keyLease != 0 && keyLease < MinLeaseDuration {
			return 0, 0, fmt.Errorf("key-lease duration %d below minimum %d", keyLease, MinLeaseDuration)
		}
		return lease, keyLease, nil
	}

	if lease < MinLeaseDuration {
		return 0, 0, fmt.Errorf("lease duration %d below minimum %d", lease, MinLeaseDuration)
	}

	// KEY-LEASE == 0 means no KEY RR lease operation.
	if keyLease != 0 {
		if keyLease < MinLeaseDuration {
			return 0, 0, fmt.Errorf("key-lease duration %d below minimum %d", keyLease, MinLeaseDuration)
		}
		if lease > keyLease {
			return 0, 0, fmt.Errorf("lease duration %d cannot exceed key-lease duration %d", lease, keyLease)
		}
	}

	return lease, keyLease, nil
}
