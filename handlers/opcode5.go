// Package handlers provides opcode-specific processing modules.
package handlers

import (
	"context"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
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

// LeasePolicy controls clamping for lease durations and forwarded RR TTLs.
type LeasePolicy struct {
	MinKeyLease uint32
	MaxKeyLease uint32
	MinRRLease  uint32
	MaxRRLease  uint32
}

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
// stub; see handlers/opcode5_sig0_validation_test.go's stubUpstreamCoordinator).
type UpstreamCoordinator interface {
	// SendUpdate sends a DNS UPDATE message to the upstream authoritative server.
	// Returns the response message or an error.
	SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error)
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
	upstreamZone      string            // Upstream authoritative zone (e.g., "dev.zenr.io.")
	upstreamKeyRecord *keyrec.LoadedKey // Key for signing upstream UPDATE (Upstream key)
	// upstreamKeyZone is the zone upstreamKeyRecord was actually found at (upstreamZone
	// itself, or a parent of it -- FindAuthorizedProxyKey walks up). Cached alongside
	// upstreamKeyRecord purely for the debug log resolveUpstreamSigningContext used to
	// emit on every call before the key itself was cached at Setup() and reused for the
	// life of the handler instead of being re-read from disk on every request/expiry.
	upstreamKeyZone     string
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
	leaseTimersMu              sync.Mutex
	leaseTimers                map[string]*time.Timer
	blacklistedTypes           map[uint16]struct{} // RR types blocked from registration (type code -> empty)
	authoritativeLookup        func(ctx context.Context, zoneHint string, fqdn string, rrType uint16) ([]dns.RR, error)
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
		leaseTimers:         make(map[string]*time.Timer),
	}
}

func keyRREqual(a, b *dns.KEY) bool {
	if a == nil || b == nil {
		return false
	}
	if !strings.EqualFold(a.Hdr.Name, b.Hdr.Name) {
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
