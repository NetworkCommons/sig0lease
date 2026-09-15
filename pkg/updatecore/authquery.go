package updatecore

import (
	"context"

	"codeberg.org/miekg/dns"
)

// AuthoritativeKeyState is the tri-state result of a live KEY-at-name query against the
// authoritative server, consumed by pkg/srp.Evaluate (S3.3.3 FCFS) when the lease store
// has no local record for a name. This is the RCODE-aware distinction the base RFC 9664
// handler's queryAuthoritativeRRs discards -- keeping it is what makes the
// NXDOMAIN/NODATA/KEY-present cases distinguishable at all.
//
// Defined here rather than in pkg/srp (which consumes it) because Coordinator, the real
// implementation, lives here and needs actual network I/O -- pkg/srp stays pure logic
// with no network I/O of its own and imports this type rather than the reverse, which
// would create an import cycle (pkg/srp already imports this package for
// CheckConsistentTTLs).
type AuthoritativeKeyState int

const (
	// AuthNXDomain: the name does not exist. First come -- proceed.
	AuthNXDomain AuthoritativeKeyState = iota
	// AuthNoKey: the name exists (NOERROR) but has no KEY RRset -- foreign or orphaned
	// data. Handled per srp.refuse_on_foreign_data (see pkg/srp.Evaluate's doc comment).
	AuthNoKey
	// AuthKeyPresent: the name exists and a KEY RRset was found; the keys are returned
	// alongside this state.
	AuthKeyPresent
)

// AuthoritativeKeyQuery performs one live KEY-at-name query against the authoritative
// server for name (scoped by zoneHint) and reports its tri-state result plus, for
// AuthKeyPresent, the KEY RR(s) found. Coordinator.QueryKeyAtName is the real
// implementation; pkg/srp.Evaluate takes this as an injected function type so tests can
// supply a canned response instead of a live server.
type AuthoritativeKeyQuery func(ctx context.Context, zoneHint, name string) (AuthoritativeKeyState, []*dns.KEY, error)
