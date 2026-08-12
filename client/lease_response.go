package client

import (
	"time"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// EffectiveLeaseDuration returns the LEASE and KEY-LEASE durations the
// client should use for expiry calculations. If the server response
// contains an UPDATE-LEASE option, those (possibly clamped) values are
// authoritative — the proxy applies its own LeasePolicy bounds and may
// grant less than what was requested for either value independently.
// Otherwise the originally-requested values are used. For the 4-byte
// variant (a single shared value), that value is used for both.
func EffectiveLeaseDuration(resp *dns.Msg, requestedLease, requestedKeyLease uint32) (lease uint32, keyLease uint32) {
	lo, err := leasepkg.FindAndDecode(resp)
	if err != nil {
		return requestedLease, requestedKeyLease
	}
	lease = lo.Lease
	if lo.KeyLease != nil {
		keyLease = *lo.KeyLease
	} else {
		keyLease = lo.Lease
	}
	return lease, keyLease
}

// ExpiryFromResponse computes the data-record and KEY expiration times using
// the server-granted LEASE and KEY-LEASE when present in the response.
func ExpiryFromResponse(now time.Time, requestedLease, requestedKeyLease uint32, resp *dns.Msg) (dataExpiry, keyExpiry time.Time) {
	lease, keyLease := EffectiveLeaseDuration(resp, requestedLease, requestedKeyLease)
	return now.Add(time.Duration(lease) * time.Second), now.Add(time.Duration(keyLease) * time.Second)
}
