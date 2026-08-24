// Package handlers provides opcode-specific processing modules.
package handlers

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// LeaseRecord is the shared lease state record used by handlers.
type LeaseRecord = leasepkg.Record

// NonKEYLeaseRecord tracks non-KEY RR lease state linked to a key registration.
// Records are tracked individually by their RFC 2136 key (rfc2136 - 1.1 -
// Comparison Rules), so each record can have its own lease duration and
// expiry time. The key excludes TTL and applies special rules for SOA,
// CNAME, and WKS record types. A deleted or expired record is removed from
// Records outright, never flagged in place.
type NonKEYLeaseRecord struct {
	Records       map[string]*nonKeyRecordEntry // key = RFC 2136 RR key (excludes TTL)
	ExpiresAt     time.Time
	UpstreamZone  string
	LeaseDuration uint32
}

// nonKeyRecordEntry holds a single non-KEY record with its own lease metadata.
type nonKeyRecordEntry struct {
	RR            dns.RR
	ExpiresAt     time.Time
	LeaseDuration uint32
}

// recordKey returns an RFC 2136-compliant key for a DNS RR.
// Per rfc2136 - 1.1 - Comparison Rules, two RRs are equal if their NAME,
// CLASS, TYPE, RDLENGTH, and RDATA fields are equal. The TTL field is
// explicitly excluded from the comparison.
//
// Special RR types (rfc2136 - 1.1 - Comparison Rules):
//
//	SOA:  compare only NAME, CLASS, TYPE (only one SOA per zone)
//	WKS:  compare only NAME, CLASS, TYPE, ADDRESS, PROTOCOL (services mask excluded)
func recordKey(rr dns.RR) string {
	if rr == nil {
		return ""
	}
	hdr := rr.Header()
	name := hdr.Name
	class := hdr.Class
	typ := dns.RRToType(rr)

	switch typ {
	case dns.TypeSOA:
		// rfc2136 - 1.1 - Comparison Rules: SOA compare only NAME, CLASS and TYPE
		return name + " " + fmt.Sprint(class) + " " + fmt.Sprint(typ)
	case dns.TypeCNAME:
		// rfc2136 - 1.1 - Comparison Rules: CNAME compare only NAME, CLASS, and TYPE
		return name + " " + fmt.Sprint(class) + " " + fmt.Sprint(typ)
	case uint16(4): // WKS type code (not exported by the dns library)
		// rfc2136 - 1.1 - Comparison Rules: WKS compare only NAME, CLASS, TYPE, ADDRESS, and PROTOCOL
		// (services mask excluded). The dns library does not provide support for WKS RRs
		// (no dns.WK type, no TypeWKS constant), so we have no proper parser for the RDATA.
		// We fall back to comparing the full data string, which may include the services mask;
		// this is not fully RFC 2136 compliant for WKS, but there is no better option available.
		return name + " " + fmt.Sprint(class) + " " + fmt.Sprint(typ) + " " + rr.Data().String()
	default:
		// rfc2136 - 1.1 - Comparison Rules: two RRs are equal if their NAME,
		// CLASS, TYPE, RDLENGTH and RDATA fields are equal (TTL excluded).
		return name + " " + fmt.Sprint(class) + " " + fmt.Sprint(typ) + " " + fmt.Sprint(rr.Data().Len()) + " " + rr.Data().String()
	}
}

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
type UpstreamCoordinator interface {
	// SendUpdate sends a DNS UPDATE message to the upstream authoritative server.
	// Returns the response message or an error.
	SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error)
}

// DefaultUpstreamCoordinator resolves authoritative NS for a zone
// and sends UPDATE messages directly to that authoritative server.
type DefaultUpstreamCoordinator struct {
	logger *logging.Logger
}

func (u *DefaultUpstreamCoordinator) resolveSOAMasterServer(ctx context.Context, zone string) (string, string, error) {
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return "", "", fmt.Errorf("upstream zone is empty")
	}

	for candidate := zone; candidate != ""; candidate = parentZone(candidate) {
		candidateFQDN := candidate + "."
		req := dns.NewMsg(candidateFQDN, dns.TypeSOA)
		if req == nil {
			continue
		}

		resp, err := dns.Exchange(ctx, req, "udp", "8.8.4.4:53")
		if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
			continue
		}

		for _, rr := range resp.Answer {
			soa, ok := rr.(*dns.SOA)
			if !ok {
				continue
			}
			mname := strings.TrimSuffix(soa.Ns, ".")
			if mname == "" {
				break
			}
			u.logger.Debugf("Selected SOA MNAME %s for effective zone %s", mname, candidateFQDN)
			return net.JoinHostPort(mname, "53"), candidateFQDN, nil
		}
	}

	return "", "", fmt.Errorf("no SOA master server found for %q", zone)
}

func (u *DefaultUpstreamCoordinator) resolveAuthoritativeZone(ctx context.Context, zone string) (string, error) {
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return "", fmt.Errorf("upstream zone is empty")
	}

	for candidate := zone; candidate != ""; candidate = parentZone(candidate) {
		nsRecords, err := net.DefaultResolver.LookupNS(ctx, candidate)
		if err != nil || len(nsRecords) == 0 {
			continue
		}
		return candidate + ".", nil
	}

	return "", fmt.Errorf("no authoritative zone with NS records found for %q", zone)
}

func parentZone(zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return ""
	}
	idx := strings.Index(zone, ".")
	if idx < 0 {
		return ""
	}
	return zone[idx+1:]
}

func (h *UpdateHandler) findAuthorizedProxyKeyForZone(zone string) (*keyrec.LoadedKey, string, error) {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	if zone == "" {
		return nil, "", fmt.Errorf("zone is empty")
	}

	for candidate := zone; candidate != ""; candidate = parentZone(candidate) {
		keyNames, err := keyrec.FindKeysByZone(h.keystoreDir, candidate+".", h.logger)
		if len(keyNames) == 0 {
			continue
		}
		if len(keyNames) > 1 {
			return nil, "", fmt.Errorf("More than one proxy authorization key found for zone %s", candidate)
		}

		k, err := keyrec.LoadKeyFromFile(h.keystoreDir, keyNames[0])
		if err != nil {
			return nil, "", fmt.Errorf("error loading proxy authorization key %s", keyNames[0])
		}
		return k, candidate + ".", nil
	}

	return nil, "", fmt.Errorf("no proxy authorization key found for zone %q or any parent", zone+".")
}

// NewDefaultUpstreamCoordinator creates a new upstream coordinator.
func NewDefaultUpstreamCoordinator(logger *logging.Logger) *DefaultUpstreamCoordinator {
	return &DefaultUpstreamCoordinator{
		logger: logger,
	}
}

// SendUpdate sends an UPDATE message to the upstream server.
func (u *DefaultUpstreamCoordinator) SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error) {
	if upstreamZone == "" {
		return nil, fmt.Errorf("upstream zone is required")
	}
	if updateMsg == nil {
		return nil, fmt.Errorf("update message is nil")
	}
	if len(updateMsg.Question) != 1 {
		return nil, fmt.Errorf("update message must contain exactly one question")
	}
	msgZone := updateMsg.Question[0].Header().Name
	u.logger.Debugf("Message zone: %s", msgZone)
	// Compare canonically (case-insensitive, trailing-dot-insensitive):
	// callers pass zone strings from several sources (config, resolved via
	// live NS lookup with a trailing dot, or normalizeZone()'d lease-store
	// values without one) that are the same zone but not byte-identical. A
	// raw string comparison here rejects valid same-zone deletes whenever
	// the caller couldn't re-resolve the FQDN form (e.g. resolveAuthoritativeZone
	// failing/timing out), which silently orphans records at authoritative DNS.
	if canonicalName(msgZone) != canonicalName(upstreamZone) {
		return nil, fmt.Errorf("update zone mismatch: message zone %q, expected upstream zone %q", msgZone, upstreamZone)
	}

	// Resolve SOA MNAME for effective zone and send UPDATE only to that server.
	soaServer, authZone, err := u.resolveSOAMasterServer(ctx, upstreamZone)
	if err != nil {
		return nil, fmt.Errorf("SOA master resolution failed for zone %q: %w", upstreamZone, err)
	}
	u.logger.Debugf("Resolved SOA master for zone %s (effective zone %s): %s", upstreamZone, authZone, soaServer)

	resp, udpErr := dns.Exchange(ctx, updateMsg, "udp", soaServer)
	if udpErr == nil {
		u.logger.Debugf("Authoritative UPDATE over UDP succeeded: server=%s rcode=%d", soaServer, resp.Rcode)
		return resp, nil
	}

	u.logger.Debugf("Authoritative UPDATE over UDP failed: server=%s err=%v; retrying TCP", soaServer, udpErr)
	resp, tcpErr := dns.Exchange(ctx, updateMsg, "tcp", soaServer)
	if tcpErr == nil {
		u.logger.Debugf("Authoritative UPDATE over TCP succeeded: server=%s rcode=%d", soaServer, resp.Rcode)
		return resp, nil
	}

	return nil, fmt.Errorf("authoritative update failed to SOA master %s (udp: %v, tcp: %v)", soaServer, udpErr, tcpErr)
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
