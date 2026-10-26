// Package handlers provides opcode-specific processing modules.
package handlers

import (
	"context"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/srp"
)

// LeaseRecord is the shared lease state record used by handlers.
type LeaseRecord = leasepkg.Record

// NonKEYLeaseRecord is the non-KEY equivalent of LeaseRecord: an alias
// straight onto pkg/lease's own type, rather than a second, hand-maintained
// copy of the same shape. leaseManager.GetNonKEYRecordSet already returns
// cloned data, so there is nothing left for a handlers-local wrapper type to
// add. Its Records map's value type (*leasepkg.NonKEYRecord) is used
// directly wherever a single entry is needed, rather than a second alias.
type NonKEYLeaseRecord = leasepkg.NonKEYRecordSet

// LeaseManager is the shared lease manager abstraction.
type LeaseManager = leasepkg.LeaseStorage

// InMemoryLeaseManager is a reusable in-memory lease manager implementation.
type InMemoryLeaseManager = leasepkg.InMemoryLeaseStore

// NewInMemoryLeaseManager creates a new in-memory lease manager.
func NewInMemoryLeaseManager() *InMemoryLeaseManager {
	return leasepkg.NewInMemoryManager()
}

// UpstreamCoordinator handles communication with the upstream authoritative server.
// pkg/updatecore.Coordinator is the production implementation, constructed in Setup via
// buildCoordinatorFromConfig -- this interface exists so tests can set a stub in its place
// (see handlers/opcode5_sig0_validation_test.go's stubUpstreamCoordinator). It covers
// everything the handler asks of the upstream side, so a stub is used the same way as the
// production implementation, never bypassed.
type UpstreamCoordinator interface {
	// updateSender sends a DNS UPDATE to the upstream authoritative server; the handler sends
	// every UPDATE through upstreamTarget.send.
	updateSender
	// ResolveAuthoritativeZone returns the apex of the zone holding zone: the zone an UPDATE
	// for names under zone must name.
	ResolveAuthoritativeZone(ctx context.Context, zone string) (string, error)
	// QueryRRs returns the rrType records at name from zoneHint's authoritative server --
	// none for NXDOMAIN -- for the handler's checks of what is already published.
	QueryRRs(ctx context.Context, zoneHint, name string, rrType uint16) ([]dns.RR, error)
	// QueryKeyAtName reports the KEYs at name, telling NXDOMAIN from a name without one:
	// fcfs_naming's live check (srp.Evaluate), as for the SRP handler.
	QueryKeyAtName(ctx context.Context, zoneHint, name string) (srp.AuthoritativeKeyState, []*dns.KEY, error)
}

// UpdateHandler handles DNS opcode 5 (UPDATE queries).
//
// This implementation supports the following features:
//   - Basic key registration with 8-byte lease EDNS(0) option (RFC 9664)
//   - SIG(0) client authentication (RFC 2931)
//   - Lease tracking in a memory or file lease store
//   - Future SRP support
type UpdateHandler struct {
	leaseHandler[UpstreamCoordinator]
	prefer4ByteVariant bool // prefer_4byte_variant: accept 4-byte Update Lease requests (answered in kind); default false refuses them.
	// AllowOnlineKeyRegistration controls whether a signer resolved only via
	// authoritative DNS (not in the lease store, not present anywhere in the
	// request) may authorize registration of new KEY RRs. Such a signer can
	// always be used for SIG(0) verification and for deletes; this flag only
	// gates whether it may also be used to create new managed state. Default
	// false (fail closed).
	AllowOnlineKeyRegistration bool
	// fcfsNaming (fcfs_naming) refuses a new KEY at a name another key holds: its own name or
	// one above it (fcfsNewKey). Default false: any new key may register next to another.
	fcfsNaming       bool
	blacklistedTypes map[uint16]struct{} // RR types blocked from registration (type code -> empty)
}

// NewUpdateHandler creates a new handler for opcode 5 (UPDATE) queries.
func NewUpdateHandler() *UpdateHandler {
	h := &UpdateHandler{}
	// A node's lock ids are its NodeKey and those of its subtree. A lease event is the shared
	// engine alone: RFC 9664 adds nothing to it, and its reconciliation pass has nothing to
	// add either.
	h.leaseHandler = newLeaseHandler[UpstreamCoordinator]("update_handler",
		func(nodeKey string) []string {
			return append([]string{nodeKey}, h.leaseManager.ListSubtreeKeys(nodeKey)...)
		},
		func(ctx context.Context, nodeKey string) { h.expirer().run(ctx, nodeKey) }, nil)
	return h
}

func keyRREqual(a, b *dns.KEY) bool {
	if a == nil || b == nil {
		return false
	}
	if !dnsname.EqualFold(a.Hdr.Name, b.Hdr.Name) {
		return false
	}
	return a.Flags == b.Flags &&
		a.Protocol == b.Protocol &&
		a.Algorithm == b.Algorithm &&
		a.PublicKey == b.PublicKey
}

func copyRR(rr dns.RR) dns.RR {
	if rr == nil {
		return nil
	}
	return rr.Clone()
}

func clampLease(lease, min, max uint32) uint32 {
	if min > 0 && lease < min {
		lease = min
	}
	if max > 0 && lease > max {
		lease = max
	}
	return lease
}
