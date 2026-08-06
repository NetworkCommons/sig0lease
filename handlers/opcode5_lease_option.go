package handlers

import (
	"encoding/hex"
	"fmt"

	"codeberg.org/miekg/dns"
)

func eachUpdateLeaseOption(msg *dns.Msg, visit func(*dns.ERFC3597) bool) bool {
	if msg == nil {
		return false
	}

	iter := func(rrs []dns.RR) bool {
		for _, rr := range rrs {
			erfc, ok := rr.(*dns.ERFC3597)
			if ok {
				if erfc.EDNS0Code == 2 && visit(erfc) {
					return true
				}
				continue
			}

			opt, ok := rr.(*dns.OPT)
			if !ok {
				continue
			}
			for _, option := range opt.Options {
				erfc, ok := option.(*dns.ERFC3597)
				if !ok || erfc.EDNS0Code != 2 {
					continue
				}
				if visit(erfc) {
					return true
				}
			}
		}
		return false
	}

	if iter(msg.Pseudo) {
		return true
	}

	return iter(msg.Extra)
}

func (h *UpdateHandler) hasUpdateLeaseOption(msg *dns.Msg) bool {
	// RFC 9664 Section 4: UPDATE-LEASE is EDNS(0) option code 2
	h.logger.Debugf("hasUpdateLeaseOption: checking message with %d Pseudo and %d Extra records", len(msg.Pseudo), len(msg.Extra))
	found := eachUpdateLeaseOption(msg, func(_ *dns.ERFC3597) bool { return true })
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
	parseERFC := func(erfc *dns.ERFC3597) (uint32, uint32, error) {
		data := erfc.Code
		if data == "" {
			return 0, 0, fmt.Errorf("empty lease option data")
		}

		// Decode hex string to binary
		binary, err := hex.DecodeString(data)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid hex in lease option: %w", err)
		}
		if len(binary) != 4 && len(binary) != 8 {
			return 0, 0, fmt.Errorf("invalid lease option length: %d bytes", len(binary))
		}

		// Parse 4-byte big-endian LEASE value
		lease := uint32(binary[0])<<24 | uint32(binary[1])<<16 | uint32(binary[2])<<8 | uint32(binary[3])

		// 4-byte variant: only permitted when prefer_4byte_variant is configured.
		if len(binary) == 4 {
			if lease < MinLeaseDuration {
				return 0, 0, fmt.Errorf("lease duration %d below minimum %d", lease, MinLeaseDuration)
			}
			if !h.prefer4ByteVariant {
				return 0, 0, fmt.Errorf("4-byte variant not permitted; prefer 8-byte variant")
			}
			return lease, 0, nil
		}

		// 8-byte variant: always valid (default mode).
		keyLease := uint32(binary[4])<<24 | uint32(binary[5])<<16 | uint32(binary[6])<<8 | uint32(binary[7])

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

	var (
		lease    uint32
		keyLease uint32
		found    bool
		parseErr error
	)
	eachUpdateLeaseOption(msg, func(erfc *dns.ERFC3597) bool {
		lease, keyLease, parseErr = parseERFC(erfc)
		found = true
		return true
	})
	if found {
		return lease, keyLease, parseErr
	}

	// No lease option found
	return 0, 0, fmt.Errorf("no Update Lease EDNS option found")
}
