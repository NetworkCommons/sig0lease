package srp

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
)

// AuthoritativeKeyState and AuthoritativeKeyQuery are defined in pkg/updatecore, not
// here, even though this file is where they're consumed -- pkg/updatecore.Coordinator is
// the real implementation (needs network I/O), and this package already imports
// pkg/updatecore for CheckConsistentTTLs, so defining them here instead would create an
// import cycle. See pkg/updatecore/authquery.go's doc comment for the full reasoning.
type (
	AuthoritativeKeyState = updatecore.AuthoritativeKeyState
	AuthoritativeKeyQuery = updatecore.AuthoritativeKeyQuery
)

const (
	AuthNXDomain   = updatecore.AuthNXDomain
	AuthNoKey      = updatecore.AuthNoKey
	AuthKeyPresent = updatecore.AuthKeyPresent
)

// StoreView is the minimal read-only view into the lease store Evaluate needs. A thin,
// intentionally narrow adapter over pkg/lease.LeaseStorage.FindByName -- narrow so this
// package depends on a two-line interface it can trivially fake in tests, not on the
// store's full read/write surface.
type StoreView interface {
	// KeyAtName returns the live (non-expired) KEY record the lease store currently
	// manages at name, and whether one was found. A name the store has never seen, or
	// whose only record there has expired, reports ok=false -- Evaluate then falls back
	// to a live authoritative query, exactly as S3.3.3 describes.
	KeyAtName(name string) (key *dns.KEY, ok bool)
}

// FCFSResult is the outcome of evaluating one name under S3.3.3's First-Come-First-Served
// rule.
type FCFSResult int

const (
	// FCFSProceed: first-come (name doesn't exist anywhere we can tell), or the update's
	// key already owns this name (a refresh).
	FCFSProceed FCFSResult = iota
	// FCFSConflict: a different key holds this name -- the response RCODE is YXDOMAIN.
	FCFSConflict
	// FCFSForeignData: the name exists with data but no KEY, and
	// srp.refuse_on_foreign_data is true (the default) -- REFUSED.
	FCFSForeignData
)

func (r FCFSResult) String() string {
	switch r {
	case FCFSProceed:
		return "proceed"
	case FCFSConflict:
		return "conflict"
	case FCFSForeignData:
		return "foreign-data"
	default:
		return fmt.Sprintf("FCFSResult(%d)", int(r))
	}
}

// Evaluate implements RFC 9665 S3.3.3 FCFS for a single name -- the Host Description name,
// or one Service Description name -- against updateKey, the KEY that governs it (the Host
// Description's KEY, or a Service Description's own explicit KEY when it has one; per
// S3.2.5.1 every KEY in a valid update is identical anyway, so callers may simply pass
// ClassifiedUpdate.Host.Key for every name -- see the package-level Names helper).
//
// Per RFC 9665 S3.3.3's FCFS table:
//
//	lease store has a KEY at name, matches updateKey        -> FCFSProceed  (refresh)
//	lease store has a KEY at name, does NOT match           -> FCFSConflict (YXDOMAIN)
//	no local record; live query: NXDOMAIN                   -> FCFSProceed  (first come)
//	no local record; live query: NOERROR, no KEY             -> refuseOnForeignData ? FCFSForeignData : FCFSProceed
//	no local record; live query: NOERROR, KEY matches        -> FCFSProceed
//	no local record; live query: NOERROR, KEY doesn't match  -> FCFSConflict (YXDOMAIN)
//
// The lease store is checked first and trusted over a live query when both are available:
// it is the source of truth for what this proxy already manages (see
// handlers.filterDuplicateRegistrations's doc comment for the base handler's identical
// reasoning) -- a live query only runs for a name the store has no opinion on.
//
// The second return value is an RFC 2136 prerequisite RR the caller should attach to the
// upstream UPDATE it forwards for an FCFSProceed name (nil for a Conflict/ForeignData
// result, and also nil for a store-trusted refresh -- see below), or nil if none is needed.
// This closes the gap between this function's own check and the caller's later, separate
// upstream write: without it, two concurrent first-time registrations of the same
// never-before-seen name can both observe AuthNXDomain here (neither has forwarded its own
// UPDATE yet) and both go on to be accepted upstream, breaking the FCFS guarantee this
// function exists to provide. Attaching a "Name is not in use" prerequisite (RFC 2136
// S2.4.4) to the forwarded UPDATE makes the authoritative server itself re-check, and
// enforce, the same condition atomically at write time -- which a second, separate
// pre-forward query from this function can never fully guarantee no matter how recently it
// ran. Deliberately narrow in scope: only the AuthNXDomain case gets a prerequisite (the
// one the concurrent-first-registration race above actually needs); a store-trusted
// "already ours" refresh gets none, preserving this store's pre-existing behavior of
// silently re-establishing a record that disappeared from authoritative DNS while still
// locally unexpired.
func Evaluate(ctx context.Context, view StoreView, query AuthoritativeKeyQuery, zoneHint, name string, updateKey *dns.KEY, refuseOnForeignData bool) (FCFSResult, dns.RR, error) {
	if view == nil {
		return 0, nil, fmt.Errorf("srp: FCFS Evaluate called with a nil StoreView")
	}
	if updateKey == nil {
		return 0, nil, fmt.Errorf("srp: FCFS Evaluate called with a nil updateKey")
	}

	if key, ok := view.KeyAtName(name); ok {
		if keysIdentical(key, updateKey) {
			return FCFSProceed, nil, nil
		}
		return FCFSConflict, nil, nil
	}

	if query == nil {
		return 0, nil, fmt.Errorf("srp: FCFS Evaluate: no local record for %s and no AuthoritativeKeyQuery provided", name)
	}
	state, keys, err := query(ctx, zoneHint, name)
	if err != nil {
		return 0, nil, fmt.Errorf("srp: FCFS authoritative query for %s: %w", name, err)
	}

	switch state {
	case AuthNXDomain:
		return FCFSProceed, nameNotInUsePrerequisite(name), nil

	case AuthNoKey:
		if refuseOnForeignData {
			return FCFSForeignData, nil, nil
		}
		return FCFSProceed, nil, nil

	case AuthKeyPresent:
		for _, k := range keys {
			if keysIdentical(k, updateKey) {
				return FCFSProceed, nil, nil
			}
		}
		return FCFSConflict, nil, nil

	default:
		return 0, nil, fmt.Errorf("srp: FCFS authoritative query for %s returned unknown state %d", name, state)
	}
}

// nameNotInUsePrerequisite builds an RFC 2136 S2.4.4 "Name is not in use" prerequisite RR
// for name: TYPE=ANY, CLASS=NONE, RDLENGTH=0. dns.ANY carries no RDATA fields of its own
// (unlike, say, dns.KEY, which always wire-encodes its flags/protocol/algorithm/public-key
// fields even when zero-valued), so this is the one prerequisite shape this package can
// build with confidence that it reliably wire-encodes with an empty RDATA section as RFC
// 2136 requires -- see Evaluate's doc comment for why only the AuthNXDomain case gets one.
func nameNotInUsePrerequisite(name string) dns.RR {
	return &dns.ANY{Hdr: dns.Header{Name: name, Class: dns.ClassNONE, TTL: 0}}
}

// Names returns every name Evaluate must be called for to authorize cu (S3.3's "the
// checked names are the Host Description name and each Service Description name --
// nothing else"): the host, plus each service instance's own name. SRV/TXT/PTR owner
// names are deliberately never included -- they have no independent identity to check
// (S4.4/S4.5's "nothing walks up from the SRV node" reasoning), and per S3.3.1.1 every
// Service Discovery instruction is authorized transitively through its target instance's
// own check.
func Names(cu *ClassifiedUpdate) []string {
	names := make([]string, 0, 1+len(cu.Instances))
	names = append(names, cu.Host.Name)
	for _, inst := range cu.Instances {
		names = append(names, inst.Name)
	}
	return names
}

// KeyFor returns the KEY that governs name: an instance's own explicit KEY if it has
// one, otherwise a copy of the Host Description's KEY with its owner name rewritten to
// name (S3.2.5.1: "the SRP registrar MUST behave AS IF the same KEY record that is given
// for the Host Description is also given for each Service Description for which no KEY
// record is provided" -- "as if... given for" that name, not the literal host-owned RR
// object). Returning cu.Host.Key verbatim here was a real bug caught by a live end-to-end
// test: callers that derive a lease-store node identity from the
// result (pkg/lease.NodeKey is name-scoped) would silently collide the instance's node
// with the host's, since both would carry the host's own owner name.
//
// name must be cu.Host.Name or one of cu.Instances' names -- anything else is a caller
// bug, not a data problem, so KeyFor panics rather than returning a zero value a caller
// could silently misuse.
func KeyFor(cu *ClassifiedUpdate, name string) *dns.KEY {
	if name == cu.Host.Name {
		return cu.Host.Key
	}
	for _, inst := range cu.Instances {
		if inst.Name == name {
			if inst.Key != nil {
				return inst.Key
			}
			return keyAtName(cu.Host.Key, inst.Name)
		}
	}
	panic(fmt.Sprintf("srp: KeyFor called with %q, which is neither the host nor a service instance in this update", name))
}

// keyAtName returns a copy of key with its owner name rewritten to name -- the same
// algorithm/protocol/flags/public-key, "as if" registered there (S3.2.5.1). Never mutates
// key itself.
func keyAtName(key *dns.KEY, name string) *dns.KEY {
	cpy := *key
	cpy.Hdr.Name = name
	return &cpy
}
