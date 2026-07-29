package client

import (
	"encoding/hex"
	"time"

	"codeberg.org/miekg/dns"
)

func decodeLeaseFromERFC(erfc *dns.ERFC3597) (uint32, bool) {
	if erfc == nil || erfc.EDNS0Code != 2 || erfc.Code == "" {
		return 0, false
	}
	binary, err := hex.DecodeString(erfc.Code)
	if err != nil {
		return 0, false
	}
	if len(binary) != 4 && len(binary) != 8 {
		return 0, false
	}
	lease := uint32(binary[0])<<24 | uint32(binary[1])<<16 | uint32(binary[2])<<8 | uint32(binary[3])
	return lease, true
}

// EffectiveLeaseDuration returns the lease duration that should be used by the
// client for expiry calculations. If the server response contains an
// UPDATE-LEASE option, that LEASE value is authoritative. Otherwise requested is used.
func EffectiveLeaseDuration(resp *dns.Msg, requested uint32) uint32 {
	if resp == nil {
		return requested
	}

	scan := func(rrs []dns.RR) (uint32, bool) {
		for _, rr := range rrs {
			if erfc, ok := rr.(*dns.ERFC3597); ok {
				if lease, ok := decodeLeaseFromERFC(erfc); ok {
					return lease, true
				}
			}
			if opt, ok := rr.(*dns.OPT); ok {
				for _, option := range opt.Options {
					if erfc, ok := option.(*dns.ERFC3597); ok {
						if lease, ok := decodeLeaseFromERFC(erfc); ok {
							return lease, true
						}
					}
				}
			}
		}
		return 0, false
	}

	if lease, ok := scan(resp.Pseudo); ok {
		return lease
	}
	if lease, ok := scan(resp.Extra); ok {
		return lease
	}
	return requested
}

// ExpiryFromResponse computes expiration time using server-granted lease when present.
func ExpiryFromResponse(now time.Time, requested uint32, resp *dns.Msg) time.Time {
	lease := EffectiveLeaseDuration(resp, requested)
	return now.Add(time.Duration(lease) * time.Second)
}
