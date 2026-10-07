// Package handlers provides opcode-specific processing modules.
package handlers

import (
	"context"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
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
// pkg/updatecore.Coordinator is the production implementation, constructed directly in
// Setup (below) via updatecore.NewCoordinator -- this interface exists so tests and
// operators can substitute their own (config's "upstream_coordinator" option, or a test
// stub; see handlers/opcode5_sig0_validation_test.go's stubUpstreamCoordinator). It covers
// everything the handler asks of the upstream side, so a substitute is used the same way as
// the production implementation, never bypassed.
type UpstreamCoordinator interface {
	// SendUpdate sends a DNS UPDATE message to the upstream authoritative server.
	// Returns the response message or an error.
	SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error)
	// ResolveAuthoritativeZone returns the zone cut (the name that has NS records) for zone
	// or one of its parents: the zone an UPDATE for names under zone must name.
	ResolveAuthoritativeZone(ctx context.Context, zone string) (string, error)
	// QueryRRs returns the rrType records at name from zoneHint's authoritative server --
	// none for NXDOMAIN -- for the handler's checks of what is already published.
	QueryRRs(ctx context.Context, zoneHint, name string, rrType uint16) ([]dns.RR, error)
}

// UpdateHandler handles DNS opcode 5 (UPDATE queries).
//
// This implementation supports the following features:
//   - Basic key registration with 8-byte lease EDNS(0) option (RFC 9664)
//   - SIG(0) client authentication (RFC 2931)
//   - In-memory lease tracking with configurable persistence hooks
//   - Future SRP support
type UpdateHandler struct {
	BaseHandler
	upstreamZone        string            // Upstream authoritative zone (e.g., "dev.zenr.io.")
	upstreamKeyRecord   *keyrec.LoadedKey // Key for signing upstream UPDATE (Upstream key)
	leaseManager        LeaseManager
	upstreamCoordinator UpstreamCoordinator
	keystoreDir         string
	LeasePolicy         LeasePolicy
	prefer4ByteVariant  bool // When true, use 4-byte variant (legacy); default false uses 8-byte always.
	// AllowOnlineKeyRegistration controls whether a signer resolved only via
	// authoritative DNS (not in the lease store, not present anywhere in the
	// request) may authorize registration of new KEY RRs. Such a signer can
	// always be used for SIG(0) verification and for deletes; this flag only
	// gates whether it may also be used to create new managed state. Default
	// false (fail closed).
	AllowOnlineKeyRegistration bool
	timers                     *expiryTimers
	blacklistedTypes           map[uint16]struct{} // RR types blocked from registration (type code -> empty)
	reconcileTicker            *time.Ticker
}

// NewUpdateHandler creates a new handler for opcode 5 (UPDATE) queries.
func NewUpdateHandler() *UpdateHandler {
	return &UpdateHandler{
		BaseHandler: BaseHandler{
			name:    "update_handler",
			opcodes: []uint8{dns.OpcodeUpdate},
		},
		leaseManager:        NewInMemoryLeaseManager(),
		upstreamCoordinator: nil, // Must be configured via Setup()
		timers:              newExpiryTimers(),
	}
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

func clampTTL(ttl, min, max uint32) uint32 {
	if min > 0 && ttl < min {
		ttl = min
	}
	if max > 0 && ttl > max {
		ttl = max
	}
	return ttl
}
