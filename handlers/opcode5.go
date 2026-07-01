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
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

// LeaseRecord represents an active lease for a client key.
type LeaseRecord struct {
	// Client's public key (KEY RR)
	KeyRR *dns.KEY

	// Lease expiration time
	ExpiresAt time.Time

	// Original lease duration requested (in seconds)
	LeaseDuration uint32

	// Upstream zone where the key is registered
	UpstreamZone string

	// When the lease was registered
	RegisteredAt time.Time
}

// IsExpired returns true if the lease has expired.
func (lr *LeaseRecord) IsExpired() bool {
	return time.Now().After(lr.ExpiresAt)
}

// TimeRemaining returns the time until lease expiration.
func (lr *LeaseRecord) TimeRemaining() time.Duration {
	remaining := time.Until(lr.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// LeaseManager manages the lifecycle of client leases.
// Implementations must be thread-safe.
type LeaseManager interface {
	// Register creates or updates a lease for a key.
	// keyName is the FQDN of the key (e.g., "client.example.com.")
	// Returns error if registration fails.
	Register(ctx context.Context, keyName string, keyRR *dns.KEY, leaseDuration uint32, upstreamZone string) error

	// Lookup retrieves an active lease for a key name.
	// Returns nil if not found or expired.
	Lookup(keyName string) *LeaseRecord

	// Get retrieves a lease record regardless of expiry state.
	// Returns nil if not found.
	Get(keyName string) *LeaseRecord

	// Delete removes a lease.
	Delete(keyName string) error

	// ListExpiring returns leases expiring within the next duration.
	// Used for maintenance and refresh handling.
	ListExpiring(within time.Duration) []*LeaseRecord

	// PersistenceHook is called when a lease is registered or updated.
	// Allows plugging in persistence backends (file, database, etc.).
	// Implementation can be async if needed.
	SetPersistenceHook(hook func(ctx context.Context, op string, record *LeaseRecord) error)
}

// InMemoryLeaseManager is a simple in-memory implementation of LeaseManager.
type InMemoryLeaseManager struct {
	mu              sync.RWMutex
	leases          map[string]*LeaseRecord
	persistenceHook func(ctx context.Context, op string, record *LeaseRecord) error
	cleanupTicker   *time.Ticker
	cleanupDone     chan struct{}
}

// NewInMemoryLeaseManager creates a new in-memory lease manager.
func NewInMemoryLeaseManager() *InMemoryLeaseManager {
	m := &InMemoryLeaseManager{
		leases:      make(map[string]*LeaseRecord),
		cleanupDone: make(chan struct{}),
	}

	// Start cleanup goroutine to remove expired leases periodically
	m.cleanupTicker = time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-m.cleanupTicker.C:
				m.cleanupExpired()
			case <-m.cleanupDone:
				return
			}
		}
	}()

	return m
}

// Register creates or updates a lease.
func (m *InMemoryLeaseManager) Register(ctx context.Context, keyName string, keyRR *dns.KEY, leaseDuration uint32, upstreamZone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	record := &LeaseRecord{
		KeyRR:         keyRR,
		ExpiresAt:     time.Now().Add(time.Duration(leaseDuration) * time.Second),
		LeaseDuration: leaseDuration,
		UpstreamZone:  upstreamZone,
		RegisteredAt:  time.Now(),
	}

	m.leases[keyName] = record

	// Call persistence hook if configured
	if m.persistenceHook != nil {
		if err := m.persistenceHook(ctx, "register", record); err != nil {
			// Log but don't fail - lease is still tracked in memory
			// Caller should decide whether to propagate error
		}
	}

	return nil
}

// Lookup retrieves an active lease.
func (m *InMemoryLeaseManager) Lookup(keyName string) *LeaseRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	record, exists := m.leases[keyName]
	if !exists {
		return nil
	}

	if record.IsExpired() {
		return nil
	}

	return record
}

// Get retrieves a lease record regardless of expiry state.
func (m *InMemoryLeaseManager) Get(keyName string) *LeaseRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	record, exists := m.leases[keyName]
	if !exists {
		return nil
	}

	return record
}

// Delete removes a lease.
func (m *InMemoryLeaseManager) Delete(keyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.leases, keyName)
	return nil
}

// ListExpiring returns leases expiring within the specified duration.
func (m *InMemoryLeaseManager) ListExpiring(within time.Duration) []*LeaseRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var expiring []*LeaseRecord
	cutoff := time.Now().Add(within)

	for _, record := range m.leases {
		if !record.IsExpired() && record.ExpiresAt.Before(cutoff) {
			expiring = append(expiring, record)
		}
	}

	return expiring
}

// SetPersistenceHook sets a hook for persistence operations.
func (m *InMemoryLeaseManager) SetPersistenceHook(hook func(ctx context.Context, op string, record *LeaseRecord) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.persistenceHook = hook
}

// cleanupExpired removes all expired leases.
func (m *InMemoryLeaseManager) cleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for keyName, record := range m.leases {
		if record.IsExpired() {
			delete(m.leases, keyName)
		}
	}
}

// Stop terminates the cleanup goroutine.
func (m *InMemoryLeaseManager) Stop() {
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
		close(m.cleanupDone)
	}
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
	logger Logger
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

// NewDefaultUpstreamCoordinator creates a new upstream coordinator.
func NewDefaultUpstreamCoordinator(logger Logger) *DefaultUpstreamCoordinator {
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

// UpdateHandler handles DNS opcode 5 (UPDATE queries).
//
// This is a Phase 1 implementation supporting:
//   - Basic key registration with 8-byte lease EDNS(0) option (RFC 9664)
//   - SIG(0) client authentication (RFC 2931)
//   - Upstream UPDATE coordination
//   - In-memory lease tracking with configurable persistence hooks
//   - Future SRP support (Phase 2+)
type UpdateHandler struct {
	BaseHandler
	upstreamZone        string            // Upstream authoritative zone (e.g., "dev.zenr.io.")
	upstreamKeyRecord   *keyrec.LoadedKey // Key for signing upstream UPDATE (Upstream key)
	leaseManager        LeaseManager
	upstreamCoordinator UpstreamCoordinator
	keystoreDir         string
	leaseTimersMu       sync.Mutex
	leaseTimers         map[string]*time.Timer
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

func (h *UpdateHandler) clearLeaseTimer(keyName string) {
	h.leaseTimersMu.Lock()
	defer h.leaseTimersMu.Unlock()

	if t, ok := h.leaseTimers[keyName]; ok {
		t.Stop()
		delete(h.leaseTimers, keyName)
	}
}

func (h *UpdateHandler) scheduleLeaseExpiry(keyName string, leaseDuration uint32) {
	h.clearLeaseTimer(keyName)

	d := time.Duration(leaseDuration) * time.Second
	t := time.AfterFunc(d, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		h.processExpiredLease(ctx, keyName)
	})

	h.leaseTimersMu.Lock()
	h.leaseTimers[keyName] = t
	h.leaseTimersMu.Unlock()
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

func (h *UpdateHandler) processExpiredLease(ctx context.Context, keyName string) {
	defer h.clearLeaseTimer(keyName)

	record := h.leaseManager.Get(keyName)
	if record == nil {
		return
	}
	if !record.IsExpired() {
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
			h.Debugf("Failed to construct upstream lease-expiry delete for %s: %v", keyName, err)
		} else {
			if _, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveUpstreamZone, deleteMsg); err != nil {
				h.Debugf("Upstream lease-expiry delete failed for %s: %v", keyName, err)
			}
		}
	}

	if err := h.leaseManager.Delete(keyName); err != nil {
		h.Debugf("Failed to delete expired local lease for %s: %v", keyName, err)
	}
}

// Handle processes an UPDATE query and returns a HandlerResult.
//
// Sig0lease packet detection (RFC 9664 Section 4):
//   - Opcode must be UPDATE (5) - handled by router
//   - Must contain EDNS(0) OPT RR with OPTION_CODE 2 (UPDATE-LEASE)
//   - If UPDATE-LEASE is absent, packet is not sig0lease relevant → StatusNotRelevant
//
// Phase 1 Registration Flow (if UPDATE-LEASE present):
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
//   - Answer section: Prerequisite records (unused in Phase 1)
//   - Authority section: Update records (typically KEY RRs being registered)
//   - Additional section: EDNS options (including 8-byte Update Lease and SIG(0))
func (h *UpdateHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult {
	h.Debugf("Phase 1 UPDATE handler: Processing message from %s", w.RemoteAddr().String())

	// Validate message structure
	if r == nil {
		return NewErrorResult(nil, "nil message received", fmt.Errorf("nil message"))
	}

	// CHECK 1: Verify UPDATE-LEASE EDNS option is present
	// If missing, this is a regular UPDATE not relevant to sig0lease
	if !h.hasUpdateLeaseOption(r) {
		h.Debugf("UPDATE packet lacks UPDATE-LEASE EDNS option, not sig0lease relevant")
		return NewNotRelevantResult("UPDATE without UPDATE-LEASE EDNS option - not sig0lease")
	}

	h.Debugf("UPDATE-LEASE EDNS option present, processing as sig0lease packet")

	if len(r.Question) != 1 {
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, "exactly one question required")
		return NewErrorResult(msg, "invalid question count", fmt.Errorf("multiple questions"))
	}

	// Extract zone and class from question
	qHeader := r.Question[0].Header()
	zone := qHeader.Name
	class := qHeader.Class

	h.Debugf("UPDATE for zone: %s (class: %d)", zone, class)

	leaseDuration, isRefresh, err := h.parseLease(r)
	if err != nil {
		h.Debugf("Lease parsing failed: %v", err)
		msg := h.makeErrorResponse(r, uint16(16), fmt.Sprintf("invalid lease: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("lease parsing failed: %v", err), err)
	}

	h.Debugf("Parsed lease duration: %d seconds (refresh=%v)", leaseDuration, isRefresh)

	// Extract and validate client SIG(0) against dynamic downstream zone key.
	// The request zone itself is treated as downstream zone asserted by client.
	sigRR, _, err := h.extractAndValidateSig0(r, zone)
	if err != nil {
		h.Debugf("SIG(0) validation failed: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("SIG(0) validation failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("SIG(0) validation failed: %v", err), err)
	}

	h.Debugf("SIG(0) validated: Algorithm=%d, KeyTag=%d, Signer=%s",
		sigRR.Algorithm, sigRR.KeyTag, sigRR.SignerName)

	// Extract client's KEY RR from update records (Authority section)
	// For Phase 1, we expect exactly one KEY RR
	var clientKeyRR *dns.KEY
	for _, rr := range r.Ns {
		if key, ok := rr.(*dns.KEY); ok {
			clientKeyRR = key
			h.Debugf("Extracted client KEY RR: %s", key.String())
			break
		}
	}

	if clientKeyRR == nil {
		h.Debugf("No KEY RR found in update records")
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, "no KEY RR in update")
		return NewErrorResult(msg, "no KEY RR found in update records", nil)
	}

	// Refresh requests must target an existing lease and present the same key material.
	clientKeyName := clientKeyRR.Hdr.Name
	if isRefresh {
		if err := h.validateRefreshOwnership(clientKeyRR); err != nil {
			msg := h.makeErrorResponse(r, dns.RcodeRefused, err.Error())
			return NewErrorResult(msg, err.Error(), err)
		}
	}

	// Register lease in in-memory storage (for refresh this extends expiry).
	if err := h.leaseManager.Register(ctx, clientKeyName, clientKeyRR, leaseDuration, h.upstreamZone); err != nil {
		h.Debugf("Failed to register lease: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("lease registration failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("lease registration failed: %v", err), err)
	}

	h.scheduleLeaseExpiry(clientKeyName, leaseDuration)

	h.Debugf("Lease registered/refreshed for %s (duration: %d seconds, refresh=%v)", clientKeyName, leaseDuration, isRefresh)

	if isRefresh {
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

	effectiveUpstreamZone := h.upstreamZone
	if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
		resolvedZone, err := dc.resolveAuthoritativeZone(ctx, h.upstreamZone)
		if err != nil {
			h.Debugf("Failed to resolve effective upstream zone from %s: %v", h.upstreamZone, err)
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream zone resolution failed: %v", err))
			return NewErrorResult(msg, fmt.Sprintf("upstream zone resolution failed: %v", err), err)
		}
		effectiveUpstreamZone = resolvedZone
		h.Debugf("Resolved effective upstream zone: configured=%s effective=%s", h.upstreamZone, effectiveUpstreamZone)
	}

	// Construct UPDATE message for effective upstream zone
	upstreamUpdate, err := h.constructUpstreamUpdate(clientKeyName, clientKeyRR, effectiveUpstreamZone)
	if err != nil {
		h.Debugf("Failed to construct upstream UPDATE: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream construction failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("upstream construction failed: %v", err), err)
	}

	// Send UPDATE to upstream and fail-closed if upstream does not accept it.
	if h.upstreamCoordinator == nil {
		_ = h.leaseManager.Delete(clientKeyName)
		h.clearLeaseTimer(clientKeyName)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "upstream coordinator not configured")
		return NewErrorResult(msg, "upstream coordinator not configured", fmt.Errorf("upstream coordinator is nil"))
	}

	h.Debugf("Sending UPDATE to upstream zone=%s (configured=%s), key=%s", effectiveUpstreamZone, h.upstreamZone, clientKeyName)
	upstreamResp, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveUpstreamZone, upstreamUpdate)
	if err != nil {
		h.Debugf("Upstream UPDATE transport/processing error for zone=%s key=%s: %v", h.upstreamZone, clientKeyName, err)
		_ = h.leaseManager.Delete(clientKeyName)
		h.clearLeaseTimer(clientKeyName)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream update failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("upstream update failed: %v", err), err)
	}
	if upstreamResp == nil {
		h.Debugf("Upstream UPDATE returned nil response for zone=%s key=%s", h.upstreamZone, clientKeyName)
		_ = h.leaseManager.Delete(clientKeyName)
		h.clearLeaseTimer(clientKeyName)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "upstream update returned nil response")
		return NewErrorResult(msg, "upstream update returned nil response", fmt.Errorf("nil upstream response"))
	}

	h.Debugf("Upstream UPDATE response: Rcode=%d (%s), Answers=%d, Ns=%d, Extra=%d",
		upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode], len(upstreamResp.Answer), len(upstreamResp.Ns), len(upstreamResp.Extra))
	if upstreamResp.Rcode != dns.RcodeSuccess {
		_ = h.leaseManager.Delete(clientKeyName)
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

	h.Debugf("Sending success response for %s (lease: %d seconds)", clientKeyName, leaseDuration)

	return NewProcessedResult(resp)
}

// parseLease extracts the 8-byte lease EDNS(0) option from the message.
// Returns the lease duration in seconds, or an error if the option is invalid.
func (h *UpdateHandler) hasUpdateLeaseOption(msg *dns.Msg) bool {
	// RFC 9664 Section 4: UPDATE-LEASE is EDNS(0) option code 2
	h.Debugf("hasUpdateLeaseOption: checking message with %d Pseudo and %d Extra records", len(msg.Pseudo), len(msg.Extra))
	for i, rr := range msg.Pseudo {
		h.Debugf("  Pseudo[%d]: %T = %v", i, rr, rr)
		if erfc, ok := rr.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
			h.Debugf("      Found UPDATE-LEASE option!")
			return true
		}
		if opt, ok := rr.(*dns.OPT); ok {
			h.Debugf("    Found OPT RR with %d options", len(opt.Options))
			for j, option := range opt.Options {
				h.Debugf("      Option[%d]: %T = %v", j, option, option)
				if erfc, ok := option.(*dns.ERFC3597); ok {
					h.Debugf("        ERFC3597 with code %d (looking for 2)", erfc.EDNS0Code)
					if erfc.EDNS0Code == 2 {
						h.Debugf("      Found UPDATE-LEASE option!")
						return true
					}
				}
			}
		}
	}

	for i, rr := range msg.Extra {
		h.Debugf("  Extra[%d]: %T = %v", i, rr, rr)
		if erfc, ok := rr.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
			h.Debugf("      Found UPDATE-LEASE option!")
			return true
		}
		if opt, ok := rr.(*dns.OPT); ok {
			h.Debugf("    Found OPT RR with %d options", len(opt.Options))
			for j, option := range opt.Options {
				h.Debugf("      Option[%d]: %T = %v", j, option, option)
				if erfc, ok := option.(*dns.ERFC3597); ok {
					h.Debugf("        ERFC3597 with code %d (looking for 2)", erfc.EDNS0Code)
					if erfc.EDNS0Code == 2 {
						h.Debugf("      Found UPDATE-LEASE option!")
						return true
					}
				}
			}
		}
	}
	h.Debugf("  No UPDATE-LEASE option found")
	return false
}

// parseLease extracts the 8-byte lease EDNS(0) option from the message.
// Returns the lease duration in seconds, or an error if the option is invalid.
func (h *UpdateHandler) parseLease(msg *dns.Msg) (uint32, bool, error) {
	const MinLeaseDuration = 30 // RFC 9664 minimum
	parseERFC := func(erfc *dns.ERFC3597) (uint32, bool, bool, error) {
		if erfc.EDNS0Code != 2 {
			return 0, false, false, nil
		}

		data := erfc.Code
		if data == "" {
			return 0, false, true, fmt.Errorf("empty lease option data")
		}

		// Decode hex string to binary
		binary, err := hex.DecodeString(data)
		if err != nil {
			return 0, false, true, fmt.Errorf("invalid hex in lease option: %w", err)
		}
		if len(binary) != 4 && len(binary) != 8 {
			return 0, false, true, fmt.Errorf("invalid lease option length: %d bytes", len(binary))
		}

		// Parse 4-byte big-endian LEASE value
		lease := uint32(binary[0])<<24 | uint32(binary[1])<<16 | uint32(binary[2])<<8 | uint32(binary[3])

		if lease < MinLeaseDuration {
			return 0, false, true, fmt.Errorf("lease duration %d below minimum %d", lease, MinLeaseDuration)
		}

		// Refresh requests use 4-byte LEASE variant.
		isRefresh := len(binary) == 4

		return lease, isRefresh, true, nil
	}

	for _, rr := range msg.Pseudo {
		if erfc, ok := rr.(*dns.ERFC3597); ok {
			if lease, isRefresh, matched, err := parseERFC(erfc); matched {
				return lease, isRefresh, err
			}
		}
		if opt, ok := rr.(*dns.OPT); ok {
			for _, option := range opt.Options {
				if erfc, ok := option.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
					if lease, isRefresh, matched, err := parseERFC(erfc); matched {
						return lease, isRefresh, err
					}
				}
			}
		}
	}

	for _, rr := range msg.Extra {
		if erfc, ok := rr.(*dns.ERFC3597); ok {
			if lease, isRefresh, matched, err := parseERFC(erfc); matched {
				return lease, isRefresh, err
			}
		}
		if opt, ok := rr.(*dns.OPT); ok {
			for _, option := range opt.Options {
				if erfc, ok := option.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
					if lease, isRefresh, matched, err := parseERFC(erfc); matched {
						return lease, isRefresh, err
					}
				}
			}
		}
	}

	// No lease option found - Phase 1 requires it
	return 0, false, fmt.Errorf("no Update Lease EDNS option found")
}

// extractAndValidateSig0 extracts and validates SIG(0) from the message.
// Returns the SIG RR, KEY RR, and error (if validation failed).
func (h *UpdateHandler) extractAndValidateSig0(msg *dns.Msg, downstreamZone string) (*dns.SIG, *dns.KEY, error) {
	var sigRR *dns.SIG
	var dnskey *dns.KEY

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

	// Look for KEY in Ns section (Authority - where UPDATE sends it)
	for _, rr := range msg.Ns {
		if key, ok := rr.(*dns.KEY); ok && dnskey == nil {
			dnskey = key
		}
	}

	// Also look in Extra if not found in Ns
	if dnskey == nil {
		for _, rr := range msg.Extra {
			if key, ok := rr.(*dns.KEY); ok && dnskey == nil {
				dnskey = key
			}
		}
	}

	if sigRR == nil {
		return nil, nil, fmt.Errorf("no SIG(0) in message")
	}

	if dnskey == nil {
		return nil, nil, fmt.Errorf("no KEY RR in message payload")
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
	h.Debugf("Proxy authorization key matched zone %s: %s", proxyAuthZone, proxyAuthKey.Name)
	h.Debugf("SIG(0) cryptographic verification passed for %s", dnskey.Hdr.Name)

	return sigRR, dnskey, nil
}

// constructUpstreamUpdate builds an UPDATE message for the upstream zone.
// This UPDATE will be sent to the authoritative server for the upstream zone.
// If upstream key is loaded, it will be signed with SIG(0).
func (h *UpdateHandler) constructUpstreamUpdate(clientKeyName string, clientKeyRR *dns.KEY, upstreamZone string) (*dns.Msg, error) {
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

	// Update section: Add the client's KEY RR to upstream zone
	// For Phase 1, we just use the original KEY RR from the client
	// In future phases, we may need to modify it (e.g., adjust TTL or name)
	msg.Ns = append(msg.Ns, clientKeyRR)

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
	h.Debugf("Signed upstream UPDATE with key: %s", h.upstreamKeyRecord)

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

	// Note: In Phase 1, we don't include detailed error messages in the response.
	// Errors are logged locally but responses use standard DNS rcodes.
	// In future versions, we can add extended error EDNS options.

	return resp
}

// Setup initializes the handler configuration.
//
// Configuration options:
//   - "upstream_zone": Authoritative zone (e.g., "dev.zenr.io.") [REQUIRED]
//   - "downstream_key": Path to downstream private key file [OPTIONAL, Phase 1 doesn't sign responses]
//   - "upstream_key": Path to upstream private key file [OPTIONAL, needed for upstream UPDATE signing]
//   - "upstream_coordinator": Custom UpstreamCoordinator implementation [OPTIONAL]
//   - "lease_manager": Custom LeaseManager implementation [OPTIONAL, defaults to InMemoryLeaseManager]
//   - "persistence_hook": Persistence function for leases [OPTIONAL]
func (h *UpdateHandler) Setup(cfg map[string]any) error {
	// Extract upstream zone
	if zone, ok := cfg["upstream_zone"].(string); ok && zone != "" {
		h.upstreamZone = zone
		h.Debugf("UpdateHandler upstream zone: %s", zone)
	} else {
		return fmt.Errorf("upstream_zone is required in config")
	}

	// Keystore directory - required for loading keys
	keystoreDir, ok := cfg["keystore_dir"].(string)
	if !ok || keystoreDir == "" {
		return fmt.Errorf("keystore_dir is required in config handlers.update section")
	}
	h.keystoreDir = keystoreDir
	h.Debugf("Using keystore directory: %s", keystoreDir)

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
	h.Debugf("Loaded upstream key: %s", upstreamKey)

	// Optional: Custom lease manager
	if lm, ok := cfg["lease_manager"].(LeaseManager); ok && lm != nil {
		h.leaseManager = lm
		h.Debugf("Custom lease manager configured")
	}

	// Optional: Persistence hook for leases
	if hook, ok := cfg["persistence_hook"].(func(context.Context, string, *LeaseRecord) error); ok {
		h.leaseManager.SetPersistenceHook(hook)
		h.Debugf("Persistence hook configured for leases")
	}

	// Optional: Custom upstream coordinator
	if coordinator, ok := cfg["upstream_coordinator"].(UpstreamCoordinator); ok && coordinator != nil {
		h.upstreamCoordinator = coordinator
		h.Debugf("Custom upstream coordinator configured")
	} else {
		h.upstreamCoordinator = NewDefaultUpstreamCoordinator(h.logger)
		h.Debugf("Default upstream coordinator configured")
	}

	return nil
}
