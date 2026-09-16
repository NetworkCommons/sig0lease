package srp

import (
	"fmt"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// Outcome classifies a registrar's response to an SRP UPDATE, from the requester's side --
// the counterpart to the RCODEs handlers/srp_handler.go's Handle() produces.
type Outcome int

const (
	// OutcomeSuccess: NOERROR. The registration was accepted; GrantedLease reads the
	// granted LEASE/KEY-LEASE off the same response.
	OutcomeSuccess Outcome = iota
	// OutcomeConflict: YXDOMAIN (S3.3.3's FCFS conflict). A different key already holds
	// one of the names in this update. This is "rename and retry,"
	// not a hard failure -- see client/srp's rename-retry loop.
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
// response's echoed Update-Lease option -- which may differ from what
// was requested (the registrar's own LeasePolicy can clamp either value independently).
// ok is false if resp carries no (decodable) Update-Lease option, in which case the
// requester should fall back to what it originally requested.
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
