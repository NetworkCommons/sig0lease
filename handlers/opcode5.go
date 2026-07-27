// Package handlers provides opcode-specific processing modules.
package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

// LeaseRecord is the shared lease state record used by handlers.
type LeaseRecord = leasepkg.Record

// DataLeaseRecord tracks non-KEY RR lease state linked to a key registration.
// Records are tracked individually by their full RDATA, so each record
// can have its own lease duration and expiry time.
type DataLeaseRecord struct {
	Records       map[string]*dataRecordEntry // key = wire-serialized RDATA
	ExpiresAt     time.Time
	UpstreamZone  string
	LeaseDuration uint32
	Deleted       bool
}

// dataRecordEntry holds a single data record with its own lease metadata.
type dataRecordEntry struct {
	RR            dns.RR
	ExpiresAt     time.Time
	LeaseDuration uint32
	Deleted       bool
}

// recordKey returns a unique key for a DNS RR based on its full string
// representation: "name TTL class type rdata". The TTL is included because
// it is lease metadata — records with different TTLs are treated as distinct
// data records, and the lease system handles TTL clamping by expiring the
// old entry and creating a new one when a lease expires without renewal.
//
// This correctly distinguishes multiple records of the same name+type
// (e.g., multiple MX records with different priorities) as well as records
// of the same name+type+rdata but with different TTLs.
func recordKey(rr dns.RR) string {
	if rr == nil {
		return ""
	}
	return rr.String()
}

// LeasePolicy controls rewrite clamping for upstream forwarded RRs.
type LeasePolicy struct {
	MinKeyLease uint32
	MaxKeyLease uint32
	MinRRLease  uint32
	MaxRRLease  uint32
}

// LeaseManager is the shared lease manager abstraction.
type LeaseManager = leasepkg.Manager

// InMemoryLeaseManager is a reusable in-memory lease manager implementation.
type InMemoryLeaseManager = leasepkg.InMemoryManager

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
		keyName, err := keyrec.FindKeyByZone(h.keystoreDir, candidate+".")
		if err != nil {
			continue
		}
		k, err := keyrec.LoadKeyFromFiles(h.keystoreDir, keyName)
		if err != nil {
			continue
		}
		return k, candidate + ".", nil
	}

	return nil, "", fmt.Errorf("no proxy authorization key found for zone %q or any parent", zone+".")
}

// resolveKeyForValidation retrieves the KEY RR needed to validate a client's SIG(0)
// signature when the request does not include a KEY RR in its update records.
//
// The behavior depends on the configured keyRetrievalMode:
//   - KeyRetrievalLeaseStoreOnly: Looks up the key in the lease store. Rejects if not found.
//   - KeyRetrievalDNSServerOnly: Queries the DNS server for the KEY RR at targetName
//     (and parent zones). Rejects if not found on DNS.
//   - KeyRetrievalLeaseStoreWithFallback: Looks up in lease store first. If not found,
//     queries DNS server. If DNS returns a key, caches it in the lease store and uses it.
//     Rejects if neither source has the key.
func (h *UpdateHandler) resolveKeyForValidation(ctx context.Context, targetName string) (*dns.KEY, error) {
	targetName = strings.TrimSuffix(strings.ToLower(targetName), ".")
	if targetName == "" {
		return nil, fmt.Errorf("target name is empty")
	}

	// Always check the lease store first (works for all modes).
	// Use normalized name for lookup to match how names are stored in the lease store.
	stored := h.leaseManager.Get(targetName)
	if stored != nil && stored.KeyRR != nil {
		h.logger.Debugf("Key found in lease store for %s", targetName)
		return stored.KeyRR, nil
	}

	// Lease store miss — behavior depends on mode.
	switch h.keyRetrievalMode {
	case KeyRetrievalLeaseStoreOnly, "":
		// Default to lease_store_only: no DNS query, reject if not in store.
		return nil, fmt.Errorf("no KEY RR found in lease store for %s (mode: lease_store_only)", targetName)

	case KeyRetrievalDNSServerOnly:
		// Query DNS server directly, do not cache.
		keyRR, err := h.queryDNSForKeyRR(ctx, targetName)
		if err != nil {
			return nil, fmt.Errorf("DNS server lookup failed for %s: %w", targetName, err)
		}
		return keyRR, nil

	case KeyRetrievalLeaseStoreWithFallback:
		// Query DNS server; if found, cache in lease store.
		keyRR, err := h.queryDNSForKeyRR(ctx, targetName)
		if err != nil {
			return nil, fmt.Errorf("DNS server lookup failed for %s: %w", targetName, err)
		}
		// Cache the retrieved key in the lease store for future requests.
		// Use a placeholder lease duration (3600s) since this is a cache fill.
		_ = h.leaseManager.Register(ctx, targetName, keyRR, 3600, 3600, h.upstreamZone)
		h.logger.Debugf("Cached DNS-retrieved key for %s in lease store", targetName)
		return keyRR, nil

	default:
		return nil, fmt.Errorf("unknown key retrieval mode: %q", h.keyRetrievalMode)
	}
}

// queryDNSForKeyRR queries the DNS server for a KEY RR at the given name,
// searching the name and its parent zones (similar to findAuthorizedProxyKeyForZone
// but queries live DNS instead of the local keystore).
func (h *UpdateHandler) queryDNSForKeyRR(ctx context.Context, name string) (*dns.KEY, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return nil, fmt.Errorf("name is empty")
	}

	for candidate := name; candidate != ""; candidate = parentZone(candidate) {
		candidateFQDN := candidate + "."

		req := dns.NewMsg(candidateFQDN, dns.TypeKEY)
		if req == nil {
			continue
		}
		req.RecursionDesired = false

		resp, err := dns.Exchange(ctx, req, "udp", "8.8.4.4:53")
		if err != nil {
			h.logger.Debugf("DNS query for KEY %s failed: %v", candidateFQDN, err)
			continue
		}

		for _, rr := range resp.Answer {
			if key, ok := rr.(*dns.KEY); ok {
				h.logger.Debugf("Found KEY RR for %s via DNS (zone=%s)", candidateFQDN, candidateFQDN)
				return key, nil
			}
		}
	}

	return nil, fmt.Errorf("no KEY RR found via DNS for %s or any parent zone", name)
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
	if msgZone != upstreamZone {
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

// KeyRetrievalMode controls how the proxy retrieves the registered KEY RR
// when a request does not include a KEY RR in its update records.
type KeyRetrievalMode string

const (
	// KeyRetrievalLeaseStoreOnly retrieves the key exclusively from the lease store.
	// Fastest path, but requires the key was previously registered through this proxy.
	KeyRetrievalLeaseStoreOnly KeyRetrievalMode = "lease_store_only"

	// KeyRetrievalDNSServerOnly retrieves the key by querying the DNS server
	// for the KEY RR at the target name (and parent zones). Authoritative but
	// incurs network latency.
	KeyRetrievalDNSServerOnly KeyRetrievalMode = "dns_server_only"

	// KeyRetrievalLeaseStoreWithFallback first checks the lease store; if the
	// key is not found, queries the DNS server and caches the result in the
	// lease store for subsequent requests.
	KeyRetrievalLeaseStoreWithFallback KeyRetrievalMode = "lease_store_with_dns_fallback"
)

// UpdateHandler handles DNS opcode 5 (UPDATE queries).
//
// This implementation supports the following features:
//   - Basic key registration with 8-byte lease EDNS(0) option (RFC 9664)
//   - SIG(0) client authentication (RFC 2931)
//   - Upstream UPDATE coordination
//   - In-memory lease tracking with configurable persistence hooks
//   - Configurable key retrieval strategy for data-only operations
//   - Future SRP support
type UpdateHandler struct {
	BaseHandler
	upstreamZone        string            // Upstream authoritative zone (e.g., "dev.zenr.io.")
	upstreamKeyRecord   *keyrec.LoadedKey // Key for signing upstream UPDATE (Upstream key)
	leaseManager        LeaseManager
	upstreamCoordinator UpstreamCoordinator
	keystoreDir         string
	LeasePolicy         LeasePolicy
	prefer4ByteVariant  bool              // When true, use 4-byte variant (legacy); default false uses 8-byte always.
	keyRetrievalMode    KeyRetrievalMode  // How to retrieve KEY RR when not present in request.
	leaseTimersMu       sync.Mutex
	leaseTimers         map[string]*time.Timer
	dataLeasesMu        sync.RWMutex
	dataLeases          map[string]*DataLeaseRecord
	blacklistedTypes    map[uint16]struct{} // RR types blocked from registration (type code -> empty)
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
		dataLeases:          make(map[string]*DataLeaseRecord),
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

func (h *UpdateHandler) applyLeasePolicy(keyRR *dns.KEY, other []dns.RR) (*dns.KEY, []dns.RR) {
	newKey := copyRR(keyRR).(*dns.KEY)
	newKey.Hdr.TTL = clampTTL(newKey.Hdr.TTL, h.LeasePolicy.MinKeyLease, h.LeasePolicy.MaxKeyLease)

	newOther := make([]dns.RR, 0, len(other))
	for _, rr := range other {
		cpy := copyRR(rr)
		hdr := cpy.Header()
		hdr.TTL = clampTTL(hdr.TTL, h.LeasePolicy.MinRRLease, h.LeasePolicy.MaxRRLease)
		newOther = append(newOther, cpy)
	}

	return newKey, newOther
}

func (h *UpdateHandler) validateRefreshOwnership(clientKeyRR *dns.KEY) error {
	if clientKeyRR == nil {
		return fmt.Errorf("refresh rejected: missing key")
	}

	clientKeyName := clientKeyRR.Hdr.Name
	existing := h.leaseManager.Lookup(clientKeyName)
	if existing == nil {
		return fmt.Errorf("refresh rejected: lease does not exist")
	}
	if !keyRREqual(existing.KeyRR, clientKeyRR) {
		return fmt.Errorf("refresh rejected: key mismatch")
	}

	return nil
}

func (h *UpdateHandler) setDataLease(keyName string, records []dns.RR, leaseDuration uint32, upstreamZone string) {
	h.dataLeasesMu.Lock()
	defer h.dataLeasesMu.Unlock()

	rec, ok := h.dataLeases[keyName]
	if !ok {
		rec = &DataLeaseRecord{Records: make(map[string]*dataRecordEntry)}
		h.dataLeases[keyName] = rec
	}

	// Merge: update or append each record by its full RDATA key.
	for _, newRR := range records {
		if newRR == nil || newRR.Header() == nil {
			continue
		}
		key := recordKey(newRR)
		if key == "" {
			continue
		}
		if existing, exists := rec.Records[key]; exists {
			// Update existing record: replace RDATA, update lease.
			existing.RR = newRR
			existing.LeaseDuration = leaseDuration
			existing.ExpiresAt = time.Now().Add(time.Duration(leaseDuration) * time.Second)
			existing.Deleted = false
		} else {
			// New record: append.
			rec.Records[key] = &dataRecordEntry{
				RR:            newRR,
				ExpiresAt:     time.Now().Add(time.Duration(leaseDuration) * time.Second),
				LeaseDuration: leaseDuration,
				Deleted:       false,
			}
		}
	}

	rec.UpstreamZone = upstreamZone
	rec.Deleted = false
}

func (h *UpdateHandler) refreshDataLease(keyName string, leaseDuration uint32) error {
	h.dataLeasesMu.Lock()
	defer h.dataLeasesMu.Unlock()

	rec, ok := h.dataLeases[keyName]
	if !ok {
		return fmt.Errorf("refresh rejected: lease does not exist")
	}

	// Refresh all individual records.
	for _, entry := range rec.Records {
		if !entry.Deleted {
			entry.LeaseDuration = leaseDuration
			entry.ExpiresAt = time.Now().Add(time.Duration(leaseDuration) * time.Second)
		}
	}
	rec.Deleted = false
	return nil
}

func (h *UpdateHandler) deleteDataLease(keyName string) {
	h.dataLeasesMu.Lock()
	defer h.dataLeasesMu.Unlock()
	rec, ok := h.dataLeases[keyName]
	if !ok {
		return
	}
	// Mark all records as deleted (but keep the entry for expiry tracking).
	for _, entry := range rec.Records {
		entry.Deleted = true
	}
}

func (h *UpdateHandler) getDataLease(keyName string) *DataLeaseRecord {
	h.dataLeasesMu.RLock()
	defer h.dataLeasesMu.RUnlock()
	rec, ok := h.dataLeases[keyName]
	if !ok {
		return nil
	}
	// Return a shallow copy of the entry map (pointers preserved).
	return &DataLeaseRecord{
		Records:     rec.Records,
		ExpiresAt:   rec.ExpiresAt,
		UpstreamZone: rec.UpstreamZone,
		LeaseDuration: rec.LeaseDuration,
		Deleted:     rec.Deleted,
	}
}

func (h *UpdateHandler) markDataLeaseDeleted(keyName string) {
	h.dataLeasesMu.Lock()
	defer h.dataLeasesMu.Unlock()
	if rec, ok := h.dataLeases[keyName]; ok {
		rec.Deleted = true
	}
}

func (h *UpdateHandler) nextLeaseEventAfter(keyName string) (time.Duration, bool) {
	var next *time.Time

	if keyRec := h.leaseManager.Get(keyName); keyRec != nil {
		t := keyRec.ExpiresAt
		next = &t
	}

	if dataRec := h.getDataLease(keyName); dataRec != nil {
		for _, entry := range dataRec.Records {
			if !entry.Deleted {
				t := entry.ExpiresAt
				if next == nil || t.Before(*next) {
					next = &t
				}
			}
		}
	}

	if next == nil {
		return 0, false
	}

	d := time.Until(*next)
	if d < 0 {
		d = 0
	}
	if d < 100*time.Millisecond {
		d = 100 * time.Millisecond
	}

	return d, true
}

func (h *UpdateHandler) clearLeaseTimer(keyName string) {
	h.leaseTimersMu.Lock()
	defer h.leaseTimersMu.Unlock()

	if t, ok := h.leaseTimers[keyName]; ok {
		t.Stop()
		delete(h.leaseTimers, keyName)
	}
}

func (h *UpdateHandler) scheduleLeaseExpiry(keyName string) {
	h.clearLeaseTimer(keyName)

	d, ok := h.nextLeaseEventAfter(keyName)
	if !ok {
		return
	}

	t := time.AfterFunc(d, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		h.processExpiredLease(ctx, keyName)
	})

	h.leaseTimersMu.Lock()
	h.leaseTimers[keyName] = t
	h.leaseTimersMu.Unlock()
}

// DumpLeasesLevel returns lease state dump at the specified log level.
// Supported levels: "debug" (full dump), "info" (summary), anything else = "info".
//
// DEBUG format (full dump):
//
//	=== Lease Store Dump ===
//	KEY lease: <keyName>
//	  KeyRR: <dns.KEY string>
//	  ExpiresAt: <time>
//	  LeaseDuration: <seconds>s
//	  KeyLeaseDuration: <seconds>s
//	  UpstreamZone: <zone>
//	  RegisteredAt: <time>
//	Data lease: <keyName>
//	  Records:
//	    <recordKey>
//	      RR: <dns.RR string>
//	      ExpiresAt: <time>
//	      LeaseDuration: <seconds>s
//	      Deleted: <bool>
//	  ExpiresAt: <time>
//	  LeaseDuration: <seconds>s
//	  UpstreamZone: <zone>
//	  Deleted: <bool>
//
// INFO format (summary):
//
//	=== Lease Store Summary ===
//	Key: <keyName>  KEY=<active|expired|absent>  Data=<count>  Status=<active|expired|deleted>
//
// Keys that appear only in the KEY lease (no data lease) represent KEY-only registrations.
// Keys that appear only in the data lease (no KEY lease) represent data-only refreshes.
// Keys that appear in both have an active KEY + data RR lease.
func (h *UpdateHandler) DumpLeasesLevel(level string) string {
	// Normalize level.
	lower := strings.ToLower(strings.TrimSpace(level))
	isDebug := lower == "debug"

	// Lock timers to prevent schedule/expire during dump.
	h.leaseTimersMu.Lock()
	defer h.leaseTimersMu.Unlock()

	// Lock data leases for consistent snapshot.
	h.dataLeasesMu.RLock()
	defer h.dataLeasesMu.RUnlock()

	var sb strings.Builder

	// Collect all key names from both stores.
	keyNames := make(map[string]bool)
	for _, rec := range h.leaseManager.ListAll() {
		keyNames[rec.KeyRR.Hdr.Name] = true
	}
	for name := range h.dataLeases {
		keyNames[name] = true
	}

	if isDebug {
		sb.WriteString("=== Lease Store Dump ===\n")
		if len(keyNames) == 0 {
			sb.WriteString("(empty)\n")
			return sb.String()
		}

		// Sort key names for deterministic output.
		sortedNames := make([]string, 0, len(keyNames))
		for name := range keyNames {
			sortedNames = append(sortedNames, name)
		}
		// Simple insertion sort (small N).
		for i := 1; i < len(sortedNames); i++ {
			for j := i; j > 0 && sortedNames[j] < sortedNames[j-1]; j-- {
				sortedNames[j], sortedNames[j-1] = sortedNames[j-1], sortedNames[j]
			}
		}

		for _, name := range sortedNames {
			keyRec := h.leaseManager.Get(name)
			dataRec := h.getDataLease(name)

			hasKey := keyRec != nil
			hasData := dataRec != nil

			// Only print a section if it has live data (not expired/deleted away).
			if hasKey || hasData {
				sb.WriteString(fmt.Sprintf("Key: %s\n", name))
			}

			if hasKey {
				sb.WriteString("  KEY lease:\n")
				sb.WriteString(fmt.Sprintf("    KeyRR: %s\n", keyRec.KeyRR.String()))
				sb.WriteString(fmt.Sprintf("    ExpiresAt: %s\n", keyRec.ExpiresAt.Format(time.RFC3339)))
				sb.WriteString(fmt.Sprintf("    LeaseDuration: %ds\n", keyRec.LeaseDuration))
				sb.WriteString(fmt.Sprintf("    KeyLeaseDuration: %ds\n", keyRec.KeyLeaseDuration))
				sb.WriteString(fmt.Sprintf("    UpstreamZone: %s\n", keyRec.UpstreamZone))
				sb.WriteString(fmt.Sprintf("    RegisteredAt: %s\n", keyRec.RegisteredAt.Format(time.RFC3339)))
				sb.WriteString(fmt.Sprintf("    IsExpired: %v\n", keyRec.IsExpired()))
			}

			if hasData {
				sb.WriteString("  Data lease:\n")
				if len(dataRec.Records) > 0 {
					sb.WriteString("    Records:\n")
					// Sort record keys for deterministic output.
					recordKeys := make([]string, 0, len(dataRec.Records))
					for rk := range dataRec.Records {
						recordKeys = append(recordKeys, rk)
					}
					for i := 1; i < len(recordKeys); i++ {
						for j := i; j > 0 && recordKeys[j] < recordKeys[j-1]; j-- {
							recordKeys[j], recordKeys[j-1] = recordKeys[j-1], recordKeys[j]
						}
					}
					for _, rk := range recordKeys {
						entry := dataRec.Records[rk]
						sb.WriteString(fmt.Sprintf("      %s\n", rk))
						sb.WriteString(fmt.Sprintf("        RR: %s\n", entry.RR.String()))
						sb.WriteString(fmt.Sprintf("        ExpiresAt: %s\n", entry.ExpiresAt.Format(time.RFC3339)))
						sb.WriteString(fmt.Sprintf("        LeaseDuration: %ds\n", entry.LeaseDuration))
						sb.WriteString(fmt.Sprintf("        Deleted: %v\n", entry.Deleted))
					}
				} else {
					sb.WriteString("    Records: (none)\n")
				}
				sb.WriteString(fmt.Sprintf("    ExpiresAt: %s\n", dataRec.ExpiresAt.Format(time.RFC3339)))
				sb.WriteString(fmt.Sprintf("    LeaseDuration: %ds\n", dataRec.LeaseDuration))
				sb.WriteString(fmt.Sprintf("    UpstreamZone: %s\n", dataRec.UpstreamZone))
				sb.WriteString(fmt.Sprintf("    Deleted: %v\n", dataRec.Deleted))
			}

			sb.WriteString("\n")
		}

		return sb.String()
	}

	// INFO level: summary output.
	sb.WriteString("=== Lease Store Summary ===\n")
	if len(keyNames) == 0 {
		sb.WriteString("(empty)\n")
		return sb.String()
	}

	// Sort key names for deterministic output.
	sortedNames := make([]string, 0, len(keyNames))
	for name := range keyNames {
		sortedNames = append(sortedNames, name)
	}
	// Simple insertion sort (small N).
	for i := 1; i < len(sortedNames); i++ {
		for j := i; j > 0 && sortedNames[j] < sortedNames[j-1]; j-- {
			sortedNames[j], sortedNames[j-1] = sortedNames[j-1], sortedNames[j]
		}
	}

	for _, name := range sortedNames {
		keyRec := h.leaseManager.Get(name)
		dataRec := h.getDataLease(name)

		// Determine key status.
		keyStatus := "absent"
		if keyRec != nil {
			if keyRec.IsExpired() {
				keyStatus = "expired"
			} else {
				keyStatus = "active"
			}
		}

		// Count live data records.
		dataCount := 0
		dataStatus := "absent"
		if dataRec != nil {
			dataStatus = "active"
			if dataRec.Deleted {
				dataStatus = "deleted"
			}
			for _, entry := range dataRec.Records {
				if !entry.Deleted {
					dataCount++
				}
			}
			if dataCount == 0 && !dataRec.Deleted {
				dataStatus = "empty"
			}
		}

		sb.WriteString(fmt.Sprintf("Key: %-40s KEY=%-8s Data=%d  Status=%s\n",
			name, keyStatus, dataCount, dataStatus))
	}

	return sb.String()
}

// DumpLeases is a convenience method that returns the full DEBUG-level dump.
// Deprecated: use DumpLeasesLevel("debug") instead.
func (h *UpdateHandler) DumpLeases() string {
	return h.DumpLeasesLevel("debug")
}

func (h *UpdateHandler) constructUpstreamDelete(clientKeyRR *dns.KEY, upstreamZone string) (*dns.Msg, error) {
	msg := dns.NewMsg(upstreamZone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS delete message")
	}

	msg.Opcode = dns.OpcodeUpdate
	msg.RecursionDesired = false
	msg.Answer = nil
	msg.Ns = nil

	deleteRR := *clientKeyRR
	deleteRR.Hdr.Class = dns.ClassNONE
	deleteRR.Hdr.TTL = 0
	msg.Ns = append(msg.Ns, &deleteRR)

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	msg.Extra = append(msg.Extra, opt)

	if h.upstreamKeyRecord == nil || h.upstreamKeyRecord.PrivateKey == nil || h.upstreamKeyRecord.PublicKey == nil {
		return nil, fmt.Errorf("upstream SIG(0) key is not configured")
	}

	signedMsg, err := sig0.SignMessage(msg, h.upstreamKeyRecord.PublicKey, h.upstreamKeyRecord.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign upstream DELETE with SIG(0): %w", err)
	}

	return signedMsg, nil
}

func (h *UpdateHandler) constructUpstreamDeleteForRecords(records []dns.RR, upstreamZone string) (*dns.Msg, error) {
	msg := dns.NewMsg(upstreamZone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS delete message")
	}

	msg.Opcode = dns.OpcodeUpdate
	msg.RecursionDesired = false
	msg.Answer = nil
	msg.Ns = nil

	for _, rr := range records {
		if rr == nil {
			continue
		}
		hdr := rr.Header()
		if hdr == nil {
			continue
		}

		// RFC 2136 delete: class NONE + TTL 0 with full RDATA for RR delete.
		cpy := copyRR(rr)
		cpyHdr := cpy.Header()
		cpyHdr.Class = dns.ClassNONE
		cpyHdr.TTL = 0
		msg.Ns = append(msg.Ns, cpy)
	}

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	msg.Extra = append(msg.Extra, opt)

	if h.upstreamKeyRecord == nil || h.upstreamKeyRecord.PrivateKey == nil || h.upstreamKeyRecord.PublicKey == nil {
		return nil, fmt.Errorf("upstream SIG(0) key is not configured")
	}

	signedMsg, err := sig0.SignMessage(msg, h.upstreamKeyRecord.PublicKey, h.upstreamKeyRecord.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign upstream DELETE with SIG(0): %w", err)
	}

	return signedMsg, nil
}

func extractUpdateRecords(msg *dns.Msg, blacklistedTypes map[uint16]struct{}) (*dns.KEY, []dns.RR, error) {
	var keyRR *dns.KEY
	other := make([]dns.RR, 0, len(msg.Ns))

	for _, rr := range msg.Ns {
		if rr == nil || rr.Header() == nil {
			return nil, nil, fmt.Errorf("nil RR encountered in UPDATE section")
		}
		switch v := rr.(type) {
		case *dns.KEY:
			if keyRR != nil {
				return nil, nil, fmt.Errorf("multiple KEY RRs are not supported")
			}
			keyRR = v
		default:
			// Check blacklist: reject blacklisted RR types.
			if blacklistedTypes != nil {
				if _, blacklisted := blacklistedTypes[dns.RRToType(rr)]; blacklisted {
					return nil, nil, fmt.Errorf("RR type %s (code %d) is blacklisted for registration",
						dns.TypeToString[dns.RRToType(rr)], dns.RRToType(rr))
				}
			}
			other = append(other, rr)
		}
	}

	if keyRR == nil {
		return nil, nil, fmt.Errorf("no KEY RR found in update records")
	}
	if keyRR.Algorithm == 0 || keyRR.Protocol == 0 || strings.TrimSpace(keyRR.PublicKey) == "" {
		return nil, nil, fmt.Errorf("incomplete KEY RR in update records: full KEY RDATA is required")
	}

	return keyRR, other, nil
}

func (h *UpdateHandler) processExpiredLease(ctx context.Context, keyName string) {
	defer h.scheduleLeaseExpiry(keyName)

	record := h.leaseManager.Get(keyName)
	dataLease := h.getDataLease(keyName)
	if record == nil && (dataLease == nil || len(dataLease.Records) == 0) {
		h.clearLeaseTimer(keyName)
		return
	}

	now := time.Now()

	// Per-record expiry: expire each expired data record individually.
	if dataLease != nil {
		effectiveZone := dataLease.UpstreamZone
		if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
			resolvedZone, err := dc.resolveAuthoritativeZone(ctx, dataLease.UpstreamZone)
			if err == nil {
				effectiveZone = resolvedZone
			}
		}

		for key, entry := range dataLease.Records {
			if !entry.Deleted && !now.Before(entry.ExpiresAt) {
				if h.upstreamCoordinator != nil {
					deleteMsg, err := h.constructUpstreamDeleteForRecords([]dns.RR{entry.RR}, effectiveZone)
					if err != nil {
						h.logger.Debugf("Failed to construct upstream data lease-expiry delete for %s record %s: %v", keyName, key, err)
					} else if _, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveZone, deleteMsg); err != nil {
						h.logger.Debugf("Upstream data lease-expiry delete failed for %s record %s: %v", keyName, key, err)
					}
				}
				entry.Deleted = true
			}
		}
	}

	if record == nil || now.Before(record.ExpiresAt) {
		return
	}

	effectiveUpstreamZone := record.UpstreamZone
	if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
		resolvedZone, err := dc.resolveAuthoritativeZone(ctx, record.UpstreamZone)
		if err == nil {
			effectiveUpstreamZone = resolvedZone
		}
	}

	if h.upstreamCoordinator != nil && record.KeyRR != nil {
		deleteMsg, err := h.constructUpstreamDelete(record.KeyRR, effectiveUpstreamZone)
		if err != nil {
			h.logger.Debugf("Failed to construct upstream lease-expiry delete for %s: %v", keyName, err)
		} else {
			if _, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveUpstreamZone, deleteMsg); err != nil {
				h.logger.Debugf("Upstream lease-expiry delete failed for %s: %v", keyName, err)
			}
		}
	}

	if err := h.leaseManager.Delete(keyName); err != nil {
		h.logger.Debugf("Failed to delete expired local lease for %s: %v", keyName, err)
	}
	h.deleteDataLease(keyName)
	h.clearLeaseTimer(keyName)
}

// Handle processes an UPDATE query and returns a HandlerResult.
//
// Sig0lease packet detection (RFC 9664 Section 4):
//   - Opcode must be UPDATE (5) - handled by router
//   - Must contain EDNS(0) OPT RR with OPTION_CODE 2 (UPDATE-LEASE)
//   - If UPDATE-LEASE is absent, packet is not sig0lease relevant → StatusNotRelevant
//
// Registration Flow (if UPDATE-LEASE present):
//  1. Validate message structure (single question for downstream zone)
//  2. Parse 8-byte lease EDNS(0) option (RFC 9664)
//  3. Extract and validate client SIG(0) signature (RFC 2931)
//  4. Extract KEY RR from update records
//  5. Register lease in-memory with persistence hook
//  6. Construct UPDATE for upstream zone
//  7. Sign UPDATE with upstream key
//  8. Send to upstream authoritative server
//  9. Return response to client
//
// The DNS UPDATE message format:
//   - Question section: Downstream zone name and class (typically ClassINET)
//   - Answer section: Prerequisite records (unused in this implementation)
//   - Authority section: Update records (typically KEY RRs being registered)
//   - Additional section: EDNS options (including 8-byte Update Lease and SIG(0))
func (h *UpdateHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult {
	h.logger.Debugf("UPDATE handler: Processing message from %s", w.RemoteAddr().String())

	// Validate message structure
	if r == nil {
		return NewErrorResult(nil, "nil message received", fmt.Errorf("nil message"))
	}

	// CHECK 1: Verify UPDATE-LEASE EDNS option is present
	// If missing, this is a regular UPDATE not relevant to sig0lease
	if !h.hasUpdateLeaseOption(r) {
		h.logger.Debugf("UPDATE packet lacks UPDATE-LEASE EDNS option, not sig0lease relevant")
		return NewNotRelevantResult("UPDATE without UPDATE-LEASE EDNS option - not sig0lease")
	}

	h.logger.Debugf("UPDATE-LEASE EDNS option present, processing as sig0lease packet")

	if len(r.Question) != 1 {
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, "exactly one question required")
		return NewErrorResult(msg, "invalid question count", fmt.Errorf("multiple questions"))
	}

	// Extract zone and class from question
	qHeader := r.Question[0].Header()
	zone := qHeader.Name
	class := qHeader.Class

	h.logger.Debugf("UPDATE for zone: %s (class: %d)", zone, class)

	leaseDuration, keyLeaseDuration, err := h.parseLease(r)
	if err != nil {
		h.logger.Debugf("Lease parsing failed: %v", err)
		msg := h.makeErrorResponse(r, uint16(16), fmt.Sprintf("invalid lease: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("lease parsing failed: %v", err), err)
	}

	h.logger.Debugf("Parsed lease duration: %d seconds key-lease=%d", leaseDuration, keyLeaseDuration)

	clientKeyRR, otherRecords, err := extractUpdateRecords(r, h.blacklistedTypes)
	if err != nil {
		h.logger.Debugf("Invalid update records: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	clientKeyName := clientKeyRR.Hdr.Name

	// Determine refresh vs registration based on lease existence, not keyLease value.
	existingLease := h.leaseManager.Lookup(clientKeyName)
	isRefresh := existingLease != nil

	// Extract and validate client SIG(0) against the KEY RR carried in the request.
	sigRR, _, err := h.extractAndValidateSig0(r, zone, clientKeyRR)
	if err != nil {
		h.logger.Debugf("SIG(0) validation failed: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("SIG(0) validation failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("SIG(0) validation failed: %v", err), err)
	}

	h.logger.Debugf("SIG(0) validated: Algorithm=%d, KeyTag=%d, Signer=%s",
		sigRR.Algorithm, sigRR.KeyTag, sigRR.SignerName)
	if sigRR.Algorithm != 15 {
		h.logger.Warnf("Non-default DNSSEC algorithm used in request signer: %d", sigRR.Algorithm)
	}

	h.logger.Debugf("Extracted client KEY RR: %s", clientKeyRR.String())

	// Case 2 / Case 4: KEY-LEASE == 0, LEASE == 0.
	if keyLeaseDuration == 0 && leaseDuration == 0 {
		if err := h.leaseManager.Delete(clientKeyName); err != nil {
			h.logger.Debugf("Failed to delete key lease for %s: %v", clientKeyName, err)
		}
		h.clearLeaseTimer(clientKeyName)

		if len(otherRecords) > 0 {
			h.deleteDataLease(clientKeyName)
			h.logger.Debugf("Deleted key and non-key records for %s (KEY-LEASE=0, LEASE=0)", clientKeyName)
		} else {
			h.logger.Debugf("Deleted key for %s (KEY-LEASE=0, LEASE=0)", clientKeyName)
		}

		resp := &dns.Msg{MsgHeader: r.MsgHeader, Question: r.Question}
		resp.Response = true
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess
		opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
		opt.SetUDPSize(uint16(dns.DefaultMsgSize))
		resp.Extra = append(resp.Extra, opt)
		return NewProcessedResult(resp)
	}

	// Case 3: KEY-LEASE == 0, LEASE != 0, no other RRs.
	if keyLeaseDuration == 0 && leaseDuration != 0 && len(otherRecords) == 0 {
		msg := h.makeErrorResponse(r, dns.RcodeRefused,
			"KEY-LEASE=0 and LEASE!=0 requires at least one non-KEY RR")
		return NewErrorResult(msg, "invalid data-only lease request", fmt.Errorf("no non-KEY RR present"))
	}

	// Case 1: KEY-LEASE == 0, LEASE != 0, other RRs present.
	if keyLeaseDuration == 0 && leaseDuration != 0 && len(otherRecords) > 0 {
		existingKey := h.leaseManager.Lookup(clientKeyName)
		if existingKey == nil {
			msg := h.makeErrorResponse(r, dns.RcodeRefused,
				"KEY-LEASE=0 requires existing KEY at FQDN; cannot register KEY with zero key-lease")
			return NewErrorResult(msg, "key missing for KEY-LEASE=0 data update", fmt.Errorf("missing existing key at FQDN"))
		}

		h.setDataLease(clientKeyName, otherRecords, leaseDuration, h.upstreamZone)
		h.scheduleLeaseExpiry(clientKeyName)

		resp := &dns.Msg{MsgHeader: r.MsgHeader, Question: r.Question}
		resp.Response = true
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess
		opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
		opt.SetUDPSize(uint16(dns.DefaultMsgSize))
		resp.Extra = append(resp.Extra, opt)
		return NewProcessedResult(resp)
	}

	// Case 5: KEY-LEASE != 0, LEASE == 0, other RRs present.
	if keyLeaseDuration != 0 && leaseDuration == 0 && len(otherRecords) > 0 {
		if err := h.leaseManager.Register(ctx, clientKeyName, clientKeyRR, keyLeaseDuration, keyLeaseDuration, h.upstreamZone); err != nil {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("key registration failed: %v", err))
			return NewErrorResult(msg, fmt.Sprintf("key registration failed: %v", err), err)
		}
		h.deleteDataLease(clientKeyName)
		h.scheduleLeaseExpiry(clientKeyName)

		resp := &dns.Msg{MsgHeader: r.MsgHeader, Question: r.Question}
		resp.Response = true
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = append(resp.Answer, clientKeyRR)
		opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
		opt.SetUDPSize(uint16(dns.DefaultMsgSize))
		resp.Extra = append(resp.Extra, opt)
		return NewProcessedResult(resp)
	}

	if keyLeaseDuration != 0 && leaseDuration == 0 && len(otherRecords) == 0 {
		msg := h.makeErrorResponse(r, dns.RcodeFormatError,
			"KEY-LEASE!=0 with LEASE=0 requires non-KEY RRs to delete")
		return NewErrorResult(msg, "invalid KEY-LEASE/LEASE combination", fmt.Errorf("missing non-KEY RRs for delete"))
	}

	if isRefresh {
		// Normal refresh: validate ownership and refresh key/data lease.
		if err := h.validateRefreshOwnership(clientKeyRR); err != nil {
			// Ownership check failed (key mismatch). Promote to full registration
			// if the key does not exist at the FQDN — the client is re-registering
			// (they have valid lease-times from before and lost the key at the DNS).
			existingKey := h.leaseManager.Lookup(clientKeyName)
			if existingKey == nil {
				// Key not at FQDN: promote to full registration (both key and data RRs).
				if err := h.leaseManager.Register(ctx, clientKeyName, clientKeyRR, leaseDuration, keyLeaseDuration, h.upstreamZone); err != nil {
					msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("lease registration failed: %v", err))
					return NewErrorResult(msg, fmt.Sprintf("lease registration failed: %v", err), err)
				}
				h.setDataLease(clientKeyName, otherRecords, leaseDuration, h.upstreamZone)
				h.scheduleLeaseExpiry(clientKeyName)
				h.logger.Debugf("Lease re-registered for %s (KEY-LEASE != 0, key not at FQDN, promoted from refresh)", clientKeyName)

				resp := &dns.Msg{
					MsgHeader: r.MsgHeader,
					Question:  r.Question,
				}
				resp.Response = true
				resp.Authoritative = true
				resp.Rcode = dns.RcodeSuccess
				resp.Answer = append(resp.Answer, clientKeyRR)
				opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
				opt.SetUDPSize(uint16(dns.DefaultMsgSize))
				resp.Extra = append(resp.Extra, opt)

				return NewProcessedResult(resp)
			}
			// Key exists at FQDN: return ownership error (existing behavior).
			msg := h.makeErrorResponse(r, dns.RcodeRefused, err.Error())
			return NewErrorResult(msg, err.Error(), err)
		}
		if err := h.refreshDataLease(clientKeyName, leaseDuration); err != nil {
			msg := h.makeErrorResponse(r, dns.RcodeRefused, err.Error())
			return NewErrorResult(msg, err.Error(), err)
		}
		h.scheduleLeaseExpiry(clientKeyName)

		h.logger.Debugf("Lease refreshed for %s (data lease=%d seconds)", clientKeyName, leaseDuration)

		resp := &dns.Msg{
			MsgHeader: r.MsgHeader,
			Question:  r.Question,
		}

		resp.Response = true
		resp.Authoritative = true
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = append(resp.Answer, clientKeyRR)
		opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
		opt.SetUDPSize(uint16(dns.DefaultMsgSize))
		resp.Extra = append(resp.Extra, opt)

		return NewProcessedResult(resp)
	}

	// Normal path: KEY-LEASE != 0, register KEY RR and forward upstream.
	if err := h.leaseManager.Register(ctx, clientKeyName, clientKeyRR, leaseDuration, keyLeaseDuration, h.upstreamZone); err != nil {
		h.logger.Debugf("Failed to register lease: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("lease registration failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("lease registration failed: %v", err), err)
	}
	h.setDataLease(clientKeyName, otherRecords, leaseDuration, h.upstreamZone)

	h.scheduleLeaseExpiry(clientKeyName)

	h.logger.Debugf("Lease registered for %s (lease=%d seconds, key-lease=%d seconds)", clientKeyName, leaseDuration, keyLeaseDuration)

	effectiveUpstreamZone := h.upstreamZone
	if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
		resolvedZone, err := dc.resolveAuthoritativeZone(ctx, h.upstreamZone)
		if err != nil {
			h.logger.Debugf("Failed to resolve effective upstream zone from %s: %v", h.upstreamZone, err)
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream zone resolution failed: %v", err))
			return NewErrorResult(msg, fmt.Sprintf("upstream zone resolution failed: %v", err), err)
		}
		effectiveUpstreamZone = resolvedZone
		h.logger.Debugf("Resolved effective upstream zone: configured=%s effective=%s", h.upstreamZone, effectiveUpstreamZone)
	}

	// Construct UPDATE message for effective upstream zone
	upstreamUpdate, err := h.constructUpstreamUpdate(clientKeyRR, otherRecords, effectiveUpstreamZone)
	if err != nil {
		h.logger.Debugf("Failed to construct upstream UPDATE: %v", err)
		h.deleteDataLease(clientKeyName)
		_ = h.leaseManager.Delete(clientKeyName)
		h.clearLeaseTimer(clientKeyName)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream construction failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("upstream construction failed: %v", err), err)
	}

	// Send UPDATE to upstream and fail-closed if upstream does not accept it.
	if h.upstreamCoordinator == nil {
		_ = h.leaseManager.Delete(clientKeyName)
		h.deleteDataLease(clientKeyName)
		h.clearLeaseTimer(clientKeyName)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "upstream coordinator not configured")
		return NewErrorResult(msg, "upstream coordinator not configured", fmt.Errorf("upstream coordinator is nil"))
	}

	h.logger.Debugf("Sending UPDATE to upstream zone=%s (configured=%s), key=%s", effectiveUpstreamZone, h.upstreamZone, clientKeyName)
	upstreamResp, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveUpstreamZone, upstreamUpdate)
	if err != nil {
		h.logger.Debugf("Upstream UPDATE transport/processing error for zone=%s key=%s: %v", h.upstreamZone, clientKeyName, err)
		_ = h.leaseManager.Delete(clientKeyName)
		h.deleteDataLease(clientKeyName)
		h.clearLeaseTimer(clientKeyName)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream update failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("upstream update failed: %v", err), err)
	}
	if upstreamResp == nil {
		h.logger.Debugf("Upstream UPDATE returned nil response for zone=%s key=%s", h.upstreamZone, clientKeyName)
		_ = h.leaseManager.Delete(clientKeyName)
		h.deleteDataLease(clientKeyName)
		h.clearLeaseTimer(clientKeyName)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "upstream update returned nil response")
		return NewErrorResult(msg, "upstream update returned nil response", fmt.Errorf("nil upstream response"))
	}

	h.logger.Debugf("Upstream UPDATE response: Rcode=%d (%s), Answers=%d, Ns=%d, Extra=%d",
		upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode], len(upstreamResp.Answer), len(upstreamResp.Ns), len(upstreamResp.Extra))
	if upstreamResp.Rcode != dns.RcodeSuccess {
		_ = h.leaseManager.Delete(clientKeyName)
		h.deleteDataLease(clientKeyName)
		h.clearLeaseTimer(clientKeyName)
		msg := h.makeErrorResponse(r, uint16(upstreamResp.Rcode),
			fmt.Sprintf("upstream rejected update: rcode=%d (%s)", upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode]))
		return NewErrorResult(msg,
			fmt.Sprintf("upstream rejected update: rcode=%d (%s)", upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode]), nil)
	}

	// Create response to client
	resp := &dns.Msg{
		MsgHeader: r.MsgHeader,
		Question:  r.Question,
	}

	resp.Response = true
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess

	// Echo back the KEY RR in response to confirm registration
	resp.Answer = append(resp.Answer, clientKeyRR)

	// Add OPT with response lease option
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	resp.Extra = append(resp.Extra, opt)

	h.logger.Debugf("Sending success response for %s (lease: %d seconds)", clientKeyName, leaseDuration)

	return NewProcessedResult(resp)
}

// parseLease extracts the 8-byte lease EDNS(0) option from the message.
// Returns the lease duration in seconds, or an error if the option is invalid.
func (h *UpdateHandler) hasUpdateLeaseOption(msg *dns.Msg) bool {
	// RFC 9664 Section 4: UPDATE-LEASE is EDNS(0) option code 2
	h.logger.Debugf("hasUpdateLeaseOption: checking message with %d Pseudo and %d Extra records", len(msg.Pseudo), len(msg.Extra))
	for i, rr := range msg.Pseudo {
		h.logger.Debugf("  Pseudo[%d]: %T = %v", i, rr, rr)
		if erfc, ok := rr.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
			h.logger.Debugf("      Found UPDATE-LEASE option!")
			return true
		}
		if opt, ok := rr.(*dns.OPT); ok {
			h.logger.Debugf("    Found OPT RR with %d options", len(opt.Options))
			for j, option := range opt.Options {
				h.logger.Debugf("      Option[%d]: %T = %v", j, option, option)
				if erfc, ok := option.(*dns.ERFC3597); ok {
					h.logger.Debugf("        ERFC3597 with code %d (looking for 2)", erfc.EDNS0Code)
					if erfc.EDNS0Code == 2 {
						h.logger.Debugf("      Found UPDATE-LEASE option!")
						return true
					}
				}
			}
		}
	}

	for i, rr := range msg.Extra {
		h.logger.Debugf("  Extra[%d]: %T = %v", i, rr, rr)
		if erfc, ok := rr.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
			h.logger.Debugf("      Found UPDATE-LEASE option!")
			return true
		}
		if opt, ok := rr.(*dns.OPT); ok {
			h.logger.Debugf("    Found OPT RR with %d options", len(opt.Options))
			for j, option := range opt.Options {
				h.logger.Debugf("      Option[%d]: %T = %v", j, option, option)
				if erfc, ok := option.(*dns.ERFC3597); ok {
					h.logger.Debugf("        ERFC3597 with code %d (looking for 2)", erfc.EDNS0Code)
					if erfc.EDNS0Code == 2 {
						h.logger.Debugf("      Found UPDATE-LEASE option!")
						return true
					}
				}
			}
		}
	}
	h.logger.Debugf("  No UPDATE-LEASE option found")
	return false
}

// parseLease extracts UPDATE-LEASE EDNS(0) data.
// Returns LEASE and KEY-LEASE values, and error if invalid.
// The decision between refresh and registration is NOT made here —
// it is determined by the caller based on lease existence (Lookup).
func (h *UpdateHandler) parseLease(msg *dns.Msg) (uint32, uint32, error) {
	const MinLeaseDuration = 30 // RFC 9664 minimum
	parseERFC := func(erfc *dns.ERFC3597) (uint32, uint32, bool, error) {
		if erfc.EDNS0Code != 2 {
			return 0, 0, false, nil
		}

		data := erfc.Code
		if data == "" {
			return 0, 0, true, fmt.Errorf("empty lease option data")
		}

		// Decode hex string to binary
		binary, err := hex.DecodeString(data)
		if err != nil {
			return 0, 0, true, fmt.Errorf("invalid hex in lease option: %w", err)
		}
		if len(binary) != 4 && len(binary) != 8 {
			return 0, 0, true, fmt.Errorf("invalid lease option length: %d bytes", len(binary))
		}

		// Parse 4-byte big-endian LEASE value
		lease := uint32(binary[0])<<24 | uint32(binary[1])<<16 | uint32(binary[2])<<8 | uint32(binary[3])

		// 4-byte variant: only permitted when prefer_4byte_variant is configured.
		if len(binary) == 4 {
			if lease < MinLeaseDuration {
				return 0, 0, true, fmt.Errorf("lease duration %d below minimum %d", lease, MinLeaseDuration)
			}
			if !h.prefer4ByteVariant {
				return 0, 0, true, fmt.Errorf("4-byte variant not permitted; prefer 8-byte variant")
			}
			return lease, 0, true, nil
		}

		// 8-byte variant: always valid (default mode).
		keyLease := uint32(binary[4])<<24 | uint32(binary[5])<<16 | uint32(binary[6])<<8 | uint32(binary[7])

		// LEASE==0 is accepted for explicit delete semantics.
		if lease == 0 {
			if keyLease != 0 && keyLease < MinLeaseDuration {
				return 0, 0, true, fmt.Errorf("key-lease duration %d below minimum %d", keyLease, MinLeaseDuration)
			}
			return lease, keyLease, true, nil
		}

		if lease < MinLeaseDuration {
			return 0, 0, true, fmt.Errorf("lease duration %d below minimum %d", lease, MinLeaseDuration)
		}

		// KEY-LEASE == 0 means no KEY RR lease operation.
		if keyLease != 0 {
			if keyLease < MinLeaseDuration {
				return 0, 0, true, fmt.Errorf("key-lease duration %d below minimum %d", keyLease, MinLeaseDuration)
			}
			if lease > keyLease {
				return 0, 0, true, fmt.Errorf("lease duration %d cannot exceed key-lease duration %d", lease, keyLease)
			}
		}

		return lease, keyLease, true, nil
	}

	for _, rr := range msg.Pseudo {
		if erfc, ok := rr.(*dns.ERFC3597); ok {
			if lease, keyLease, matched, err := parseERFC(erfc); matched {
				return lease, keyLease, err
			}
		}
		if opt, ok := rr.(*dns.OPT); ok {
			for _, option := range opt.Options {
				if erfc, ok := option.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
					if lease, keyLease, matched, err := parseERFC(erfc); matched {
						return lease, keyLease, err
					}
				}
			}
		}
	}

	for _, rr := range msg.Extra {
		if erfc, ok := rr.(*dns.ERFC3597); ok {
			if lease, keyLease, matched, err := parseERFC(erfc); matched {
				return lease, keyLease, err
			}
		}
		if opt, ok := rr.(*dns.OPT); ok {
			for _, option := range opt.Options {
				if erfc, ok := option.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
					if lease, keyLease, matched, err := parseERFC(erfc); matched {
						return lease, keyLease, err
					}
				}
			}
		}
	}

	// No lease option found
	return 0, 0, fmt.Errorf("no Update Lease EDNS option found")
}

// extractAndValidateSig0 extracts and validates SIG(0) from the message.
// expectedKey must be the single validated KEY RR extracted from update records.
func (h *UpdateHandler) extractAndValidateSig0(msg *dns.Msg, downstreamZone string, expectedKey *dns.KEY) (*dns.SIG, *dns.KEY, error) {
	var sigRR *dns.SIG
	dnskey := expectedKey

	// Look for SIG in Pseudo section first (RFC 2535 SIG(0))
	for _, rr := range msg.Pseudo {
		if sig, ok := rr.(*dns.SIG); ok && sigRR == nil {
			sigRR = sig
		}
	}

	// If not found in Pseudo, look in Extra (shouldn't be there but check anyway)
	if sigRR == nil {
		for _, rr := range msg.Extra {
			if sig, ok := rr.(*dns.SIG); ok && sigRR == nil {
				sigRR = sig
			}
		}
	}

	if sigRR == nil {
		return nil, nil, fmt.Errorf("no SIG(0) in message")
	}

	if dnskey == nil {
		return nil, nil, fmt.Errorf("no KEY RR provided for validation")
	}
	if downstreamZone == "" {
		return nil, nil, fmt.Errorf("downstream zone is empty")
	}

	// SIG(0) must be produced by the same key being registered in this request.
	if sigRR.KeyTag != dnskey.KeyTag() {
		return nil, nil, fmt.Errorf("SIG(0) key tag %d does not match payload KEY key tag %d",
			sigRR.KeyTag, dnskey.KeyTag())
	}
	if sigRR.Algorithm != dnskey.Algorithm {
		return nil, nil, fmt.Errorf("SIG(0) algorithm %d does not match payload KEY algorithm %d",
			sigRR.Algorithm, dnskey.Algorithm)
	}
	if !strings.EqualFold(strings.TrimSuffix(sigRR.SignerName, "."), strings.TrimSuffix(dnskey.Hdr.Name, ".")) {
		return nil, nil, fmt.Errorf("SIG(0) signer %q does not match payload KEY owner name %q",
			sigRR.SignerName, dnskey.Hdr.Name)
	}

	// Client key must match the requested downstream zone exactly.
	zoneCanon := strings.TrimSuffix(strings.ToLower(downstreamZone), ".")
	keyCanon := strings.TrimSuffix(strings.ToLower(dnskey.Hdr.Name), ".")
	if keyCanon != zoneCanon {
		return nil, nil, fmt.Errorf("payload KEY %q must match requested downstream zone %q", dnskey.Hdr.Name, downstreamZone)
	}

	// Proxy authorization is independent from client key: proxy may authorize via
	// requested zone or any parent zone key it controls.
	proxyAuthKey, proxyAuthZone, err := h.findAuthorizedProxyKeyForZone(downstreamZone)
	if err != nil {
		return nil, nil, err
	}

	// Cryptographically verify that the message was signed by the private key
	// corresponding to the public key carried in the payload KEY RR.
	if err := sig0.VerifySignature(msg, dnskey); err != nil {
		return nil, nil, fmt.Errorf("SIG(0) cryptographic verification failed: %w", err)
	}
	h.logger.Debugf("Proxy authorization key matched zone %s: %s", proxyAuthZone, proxyAuthKey.Name)
	h.logger.Debugf("SIG(0) cryptographic verification passed for %s", dnskey.Hdr.Name)

	return sigRR, dnskey, nil
}

// constructUpstreamUpdate builds an UPDATE message for the upstream zone.
// This UPDATE will be sent to the authoritative server for the upstream zone.
// If upstream key is loaded, it will be signed with SIG(0).
func (h *UpdateHandler) constructUpstreamUpdate(clientKeyRR *dns.KEY, otherRecords []dns.RR, upstreamZone string) (*dns.Msg, error) {
	// Create UPDATE message for upstream zone using dns.NewMsg
	msg := dns.NewMsg(upstreamZone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}

	msg.Opcode = dns.OpcodeUpdate
	msg.RecursionDesired = false

	// Clear any default sections
	msg.Answer = nil
	msg.Ns = nil

	policyKey, policyOther := h.applyLeasePolicy(clientKeyRR, otherRecords)

	// Update section: KEY plus supported non-KEY records.
	msg.Ns = append(msg.Ns, policyKey)
	msg.Ns = append(msg.Ns, policyOther...)

	// Add OPT for EDNS support
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	msg.Extra = append(msg.Extra, opt)

	if h.upstreamKeyRecord == nil || h.upstreamKeyRecord.PrivateKey == nil || h.upstreamKeyRecord.PublicKey == nil {
		return nil, fmt.Errorf("upstream SIG(0) key is not configured")
	}

	signedMsg, err := sig0.SignMessage(msg, h.upstreamKeyRecord.PublicKey, h.upstreamKeyRecord.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign upstream UPDATE with SIG(0): %w", err)
	}
	msg = signedMsg
	h.logger.Debugf("Signed upstream UPDATE with key: %s", h.upstreamKeyRecord)

	return msg, nil
}

// makeErrorResponse creates a properly formatted error response.
func (h *UpdateHandler) makeErrorResponse(req *dns.Msg, rcode uint16, msg string) *dns.Msg {
	resp := &dns.Msg{
		MsgHeader: req.MsgHeader,
		Question:  req.Question,
	}

	resp.Response = true
	resp.Rcode = rcode

	// Note: we don't include detailed error messages in the response.
	// Errors are logged locally but responses use standard DNS rcodes.
	// In future versions, we can add extended error EDNS options.

	return resp
}

func toUint32(v any) (uint32, bool) {
	switch n := v.(type) {
	case int:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	case int64:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	case float64:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	case uint32:
		return n, true
	case uint64:
		return uint32(n), true
	default:
		return 0, false
	}
}

// Setup initializes the handler configuration.
//
// Configuration options:
//   - "upstream_zone": Authoritative zone (e.g., "dev.zenr.io.") [REQUIRED]
//   - "upstream_key": Path to upstream private key file [OPTIONAL, needed for upstream UPDATE signing]
//   - "upstream_coordinator": Custom UpstreamCoordinator implementation [OPTIONAL]
//   - "lease_manager": Custom LeaseManager implementation [OPTIONAL, defaults to InMemoryLeaseManager]
//   - "persistence_hook": Persistence function for leases [OPTIONAL]
//   - "lease_policy": Rewrite TTL bounds applied before upstream forwarding [OPTIONAL]
//   - "key_retrieval_mode": How to retrieve KEY RR when not in request: "lease_store_only",
//     "dns_server_only", or "lease_store_with_dns_fallback" [OPTIONAL, defaults to lease_store_with_dns_fallback]
//   - "prefer_4byte_variant": Enable 4-byte variant for backward compatibility [OPTIONAL, defaults to false]
func (h *UpdateHandler) Setup(cfg map[string]any) error {
	// Extract upstream zone
	if zone, ok := cfg["upstream_zone"].(string); ok && zone != "" {
		h.upstreamZone = zone
		h.logger.Debugf("UpdateHandler upstream zone: %s", zone)
	} else {
		return fmt.Errorf("upstream_zone is required in config")
	}

	// Keystore directory - required for loading keys
	keystoreDir, ok := cfg["keystore_dir"].(string)
	if !ok || keystoreDir == "" {
		return fmt.Errorf("keystore_dir is required in config handlers.update section")
	}
	h.keystoreDir = keystoreDir
	h.logger.Debugf("Using keystore directory: %s", keystoreDir)

	// Load Upstream key for signing UPDATE messages to authoritative server (required).
	upstreamKeyName, err := keyrec.FindKeyByZone(keystoreDir, h.upstreamZone)
	if err != nil {
		return fmt.Errorf("could not find upstream key for %s: %w", h.upstreamZone, err)
	}
	upstreamKey, err := keyrec.LoadKeyFromFiles(keystoreDir, upstreamKeyName)
	if err != nil {
		return fmt.Errorf("failed to load upstream key %s: %w", upstreamKeyName, err)
	}
	h.upstreamKeyRecord = upstreamKey
	h.logger.Debugf("Loaded upstream key: %s", upstreamKey)

	// Optional: Custom lease manager
	if lm, ok := cfg["lease_manager"].(LeaseManager); ok && lm != nil {
		h.leaseManager = lm
		h.logger.Debugf("Custom lease manager configured")
	}

	// Optional: Persistence hook for leases
	if hook, ok := cfg["persistence_hook"].(func(context.Context, string, *LeaseRecord) error); ok {
		h.leaseManager.SetPersistenceHook(hook)
		h.logger.Debugf("Persistence hook configured for leases")
	}

	// Optional: TTL rewrite policy hook
	if raw, ok := cfg["lease_policy"]; ok {
		policy, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("lease_policy must be a map")
		}
		if v, ok := toUint32(policy["min_key_lease_sec"]); ok {
			h.LeasePolicy.MinKeyLease = v
		}
		if v, ok := toUint32(policy["max_key_lease_sec"]); ok {
			h.LeasePolicy.MaxKeyLease = v
		}
		if v, ok := toUint32(policy["min_rr_lease_sec"]); ok {
			h.LeasePolicy.MinRRLease = v
		}
		if v, ok := toUint32(policy["max_rr_lease_sec"]); ok {
			h.LeasePolicy.MaxRRLease = v
		}

		if h.LeasePolicy.MaxKeyLease > 0 && h.LeasePolicy.MinKeyLease > 0 && h.LeasePolicy.MinKeyLease > h.LeasePolicy.MaxKeyLease {
			return fmt.Errorf("lease_policy min_key_lease_sec cannot be greater than max_key_lease_sec")
		}
		if h.LeasePolicy.MaxRRLease > 0 && h.LeasePolicy.MinRRLease > 0 && h.LeasePolicy.MinRRLease > h.LeasePolicy.MaxRRLease {
			return fmt.Errorf("lease_policy min_rr_lease_sec cannot be greater than max_rr_lease_sec")
		}

		h.logger.Debugf("TTL policy configured: key[min=%d,max=%d] rr[min=%d,max=%d]",
			h.LeasePolicy.MinKeyLease, h.LeasePolicy.MaxKeyLease, h.LeasePolicy.MinRRLease, h.LeasePolicy.MaxRRLease)
	}

	// Optional: Custom upstream coordinator
	if coordinator, ok := cfg["upstream_coordinator"].(UpstreamCoordinator); ok && coordinator != nil {
		h.upstreamCoordinator = coordinator
		h.logger.Debugf("Custom upstream coordinator configured")
	} else {
		h.upstreamCoordinator = NewDefaultUpstreamCoordinator(h.logger)
		h.logger.Debugf("Default upstream coordinator configured")
	}

	// Check if 4-byte variant is explicitly enabled via config for backward compatibility.
	// Default: false (always use 8-byte variant for all lease requests).
	if prefer, ok := cfg["prefer_4byte_variant"].(bool); ok {
		h.prefer4ByteVariant = prefer
	}

	// Parse key retrieval mode from config.
	if mode, ok := cfg["key_retrieval_mode"].(string); ok && mode != "" {
		switch KeyRetrievalMode(mode) {
		case KeyRetrievalLeaseStoreOnly, KeyRetrievalDNSServerOnly, KeyRetrievalLeaseStoreWithFallback:
			h.keyRetrievalMode = KeyRetrievalMode(mode)
			h.logger.Debugf("Key retrieval mode configured: %s", h.keyRetrievalMode)
		default:
			return fmt.Errorf("invalid key_retrieval_mode %q, must be one of: %s, %s, %s",
				mode, KeyRetrievalLeaseStoreOnly, KeyRetrievalDNSServerOnly, KeyRetrievalLeaseStoreWithFallback)
		}
	} else {
		// Default: lease_store_with_dns_fallback
		h.keyRetrievalMode = KeyRetrievalLeaseStoreWithFallback
		h.logger.Debugf("Key retrieval mode not specified, using default: %s", h.keyRetrievalMode)
	}

	// Parse blacklisted RR types from config.
	if raw, ok := cfg["blacklisted_types"]; ok {
		h.blacklistedTypes = make(map[uint16]struct{})
		switch v := raw.(type) {
		case []string:
			for _, typeName := range v {
				typeName = strings.TrimSpace(strings.ToUpper(typeName))
				if typeCode, ok := dns.StringToType[typeName]; ok {
					h.blacklistedTypes[typeCode] = struct{}{}
					h.logger.Debugf("Blacklisted RR type: %s (code %d)", typeName, typeCode)
				} else {
					h.logger.Warnf("Unknown RR type name %q in blacklisted_types, skipping", typeName)
				}
			}
		case []interface{}:
			for _, item := range v {
				if typeName, ok := item.(string); ok {
					typeName = strings.TrimSpace(strings.ToUpper(typeName))
					if typeCode, ok := dns.StringToType[typeName]; ok {
						h.blacklistedTypes[typeCode] = struct{}{}
						h.logger.Debugf("Blacklisted RR type: %s (code %d)", typeName, typeCode)
					} else {
						h.logger.Warnf("Unknown RR type name %q in blacklisted_types, skipping", typeName)
					}
				}
			}
		default:
			h.logger.Warnf("blacklisted_types has unexpected type %T, expected []string", raw)
		}
		if len(h.blacklistedTypes) > 0 {
			h.logger.Debugf("Blacklisted RR types: %d entries", len(h.blacklistedTypes))
		}
	}

	return nil
}
