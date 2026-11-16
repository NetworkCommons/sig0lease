package client

import (
	"fmt"
	"time"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// Outcome classifies a registrar's response to an UPDATE, from the requester's side: an SRP
// registrar's (client/srp, RFC 9665) or this proxy's RFC 9664 handler's (client/rfc9664).
type Outcome int

const (
	// OutcomeSuccess: NOERROR. The registration was accepted; GrantedLease reads the
	// granted LEASE/KEY-LEASE off the same response.
	OutcomeSuccess Outcome = iota
	// OutcomeConflict: YXDOMAIN, a First-Come First-Served conflict (RFC 9665 S3.3.3, and
	// the RFC 9664 handler's fcfs_naming): a different key already holds one of the names in
	// the update. An SRP requester renames and retries (client/srp); an RFC 9664 one, whose
	// names are typed and linked, waits for the name to be freed (client/rfc9664).
	OutcomeConflict
	// OutcomeRefused: REFUSED. Covers every registrar-side rejection that isn't a naming
	// conflict -- SIG(0) failure, foreign non-SRP data present (refuse_on_foreign_data),
	// malformed update, TCP-required-but-got-UDP, and so on. The RCODE alone doesn't tell
	// the requester which; retrying the identical request is unlikely to help.
	OutcomeRefused
	// OutcomeServerFailure: SERVFAIL, or no response at all (nil resp).
	OutcomeServerFailure
	// OutcomeOther: any other RCODE.
	OutcomeOther
)

func (o Outcome) String() string {
	switch o {
	case OutcomeSuccess:
		return "success"
	case OutcomeConflict:
		return "conflict"
	case OutcomeRefused:
		return "refused"
	case OutcomeServerFailure:
		return "server-failure"
	default:
		return fmt.Sprintf("Outcome(%d)", int(o))
	}
}

// InterpretResponse classifies resp's RCODE for a requester. A nil resp (e.g. a transport
// error before any response arrived) is treated as OutcomeServerFailure.
func InterpretResponse(resp *dns.Msg) Outcome {
	if resp == nil {
		return OutcomeServerFailure
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return OutcomeSuccess
	case dns.RcodeYXDomain:
		return OutcomeConflict
	case dns.RcodeRefused:
		return OutcomeRefused
	case dns.RcodeServerFailure:
		return OutcomeServerFailure
	default:
		return OutcomeOther
	}
}

// GrantedLease reads the LEASE/KEY-LEASE the registrar actually granted off a successful
// response's echoed Update-Lease option -- which may differ from what was requested (the
// registrar's own LeasePolicy can clamp either value independently). For the 4-byte variant
// (a single shared value), that value is both. ok is false if resp carries no (decodable)
// Update-Lease option, in which case the requester should fall back to what it requested.
func GrantedLease(resp *dns.Msg) (lease, keyLease uint32, ok bool) {
	lo, err := leasepkg.FindAndDecode(resp)
	if err != nil {
		return 0, 0, false
	}
	lease = lo.Lease
	if lo.KeyLease != nil {
		keyLease = *lo.KeyLease
	} else {
		keyLease = lo.Lease
	}
	return lease, keyLease, true
}

// EffectiveLeaseDuration returns the LEASE and KEY-LEASE durations the client should use for
// expiry calculations: what resp grants (GrantedLease), or, if it carries no Update-Lease
// option, what was requested.
func EffectiveLeaseDuration(resp *dns.Msg, requestedLease, requestedKeyLease uint32) (lease uint32, keyLease uint32) {
	if lease, keyLease, ok := GrantedLease(resp); ok {
		return lease, keyLease
	}
	return requestedLease, requestedKeyLease
}

// ExpiryFromResponse computes the data-record and KEY expiration times using
// the server-granted LEASE and KEY-LEASE when present in the response.
func ExpiryFromResponse(now time.Time, requestedLease, requestedKeyLease uint32, resp *dns.Msg) (dataExpiry, keyExpiry time.Time) {
	lease, keyLease := EffectiveLeaseDuration(resp, requestedLease, requestedKeyLease)
	return now.Add(time.Duration(lease) * time.Second), now.Add(time.Duration(keyLease) * time.Second)
}
