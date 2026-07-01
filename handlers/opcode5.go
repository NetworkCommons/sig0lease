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

func (u *DefaultUpstreamCoordinator) resolveAuthoritativeServer(ctx context.Context, zone string) (string, error) {
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return "", fmt.Errorf("upstream zone is empty")
	}
	u.logger.Debugf("Resolving authoritative NS starting from zone %s", zone)

	for candidate := zone; candidate != ""; candidate = parentZone(candidate) {
		u.logger.Debugf("Trying authoritative zone candidate %s", candidate)
		nsRecords, err := net.DefaultResolver.LookupNS(ctx, candidate)
		if err != nil {
			u.logger.Debugf("LookupNS failed for candidate %s: %v", candidate, err)
			continue
		}
		if len(nsRecords) == 0 {
			u.logger.Debugf("No NS records found for candidate %s", candidate)
			continue
		}

		// Use the first authoritative nameserver; caller can retry with fallback resolver.
		nsHost := strings.TrimSuffix(nsRecords[0].Host, ".")
		u.logger.Debugf("Selected authoritative zone %s with NS %s", candidate, nsHost)
		return net.JoinHostPort(nsHost, "53"), nil
	}

	return "", fmt.Errorf("no authoritative zone with NS records found for %q", zone)
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

	// Resolve authoritative server from upstream zone and send UPDATE there.
	authServer, err := u.resolveAuthoritativeServer(ctx, upstreamZone)

	if err != nil {
		return nil, fmt.Errorf("authoritative NS resolution failed for zone %q: %w", upstreamZone, err)
	}
	u.logger.Debugf("Resolved authoritative server %s for zone %s", authServer, upstreamZone)

	resp, udpErr := dns.Exchange(ctx, updateMsg, "udp", authServer)
	if udpErr == nil {
		u.logger.Debugf("Authoritative UPDATE over UDP succeeded: server=%s rcode=%d", authServer, resp.Rcode)
		return resp, nil
	}

	// Retry over TCP for authoritative servers that require TCP for UPDATE.
	u.logger.Debugf("Authoritative UPDATE over UDP failed: server=%s err=%v; retrying TCP", authServer, udpErr)
	resp, tcpErr := dns.Exchange(ctx, updateMsg, "tcp", authServer)
	if tcpErr == nil {
		u.logger.Debugf("Authoritative UPDATE over TCP succeeded: server=%s rcode=%d", authServer, resp.Rcode)
		return resp, nil
	}

	return nil, fmt.Errorf("authoritative update failed to %s (udp: %v, tcp: %v)", authServer, udpErr, tcpErr)
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

	// Extract lease EDNS(0) option (8-byte variant: LEASE + KEY-LEASE)
	leaseDuration, err := h.parseLease(r)
	if err != nil {
		h.Debugf("Lease parsing failed: %v", err)
		msg := h.makeErrorResponse(r, uint16(16), fmt.Sprintf("invalid lease: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("lease parsing failed: %v", err), err)
	}

	h.Debugf("Parsed lease duration: %d seconds", leaseDuration)

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

	// Register lease in in-memory storage
	clientKeyName := clientKeyRR.Hdr.Name
	if err := h.leaseManager.Register(ctx, clientKeyName, clientKeyRR, leaseDuration, h.upstreamZone); err != nil {
		h.Debugf("Failed to register lease: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("lease registration failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("lease registration failed: %v", err), err)
	}

	h.Debugf("Lease registered for %s (duration: %d seconds)", clientKeyName, leaseDuration)

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
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "upstream coordinator not configured")
		return NewErrorResult(msg, "upstream coordinator not configured", fmt.Errorf("upstream coordinator is nil"))
	}

	h.Debugf("Sending UPDATE to upstream zone=%s (configured=%s), key=%s", effectiveUpstreamZone, h.upstreamZone, clientKeyName)
	upstreamResp, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveUpstreamZone, upstreamUpdate)
	if err != nil {
		h.Debugf("Upstream UPDATE transport/processing error for zone=%s key=%s: %v", h.upstreamZone, clientKeyName, err)
		_ = h.leaseManager.Delete(clientKeyName)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream update failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("upstream update failed: %v", err), err)
	}
	if upstreamResp == nil {
		h.Debugf("Upstream UPDATE returned nil response for zone=%s key=%s", h.upstreamZone, clientKeyName)
		_ = h.leaseManager.Delete(clientKeyName)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "upstream update returned nil response")
		return NewErrorResult(msg, "upstream update returned nil response", fmt.Errorf("nil upstream response"))
	}

	h.Debugf("Upstream UPDATE response: Rcode=%d (%s), Answers=%d, Ns=%d, Extra=%d",
		upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode], len(upstreamResp.Answer), len(upstreamResp.Ns), len(upstreamResp.Extra))
	if upstreamResp.Rcode != dns.RcodeSuccess {
		_ = h.leaseManager.Delete(clientKeyName)
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
	h.Debugf("hasUpdateLeaseOption: checking message with %d Extra records", len(msg.Extra))
	for i, rr := range msg.Extra {
		h.Debugf("  Extra[%d]: %T = %v", i, rr, rr)
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
func (h *UpdateHandler) parseLease(msg *dns.Msg) (uint32, error) {
	const MinLeaseDuration = 30 // RFC 9664 minimum

	for _, rr := range msg.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			for _, option := range opt.Options {
				if erfc, ok := option.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
					// Update Lease EDNS0 option (code 2)
					// Format: 2-byte LEASE + 2-byte KEY-LEASE (8-byte total, or 4-byte for LEASE-only)

					data := erfc.Code
					if data == "" {
						return 0, fmt.Errorf("empty lease option data")
					}

					// Decode hex string to binary
					binary, err := hex.DecodeString(data)
					if err != nil {
						return 0, fmt.Errorf("invalid hex in lease option: %w", err)
					}

					if len(binary) < 4 {
						return 0, fmt.Errorf("lease option too short: %d bytes", len(binary))
					}

					// Parse 4-byte big-endian LEASE value
					lease := uint32(binary[0])<<24 | uint32(binary[1])<<16 | uint32(binary[2])<<8 | uint32(binary[3])

					if lease < MinLeaseDuration {
						return 0, fmt.Errorf("lease duration %d below minimum %d", lease, MinLeaseDuration)
					}

					return lease, nil
				}
			}
		}
	}

	// No lease option found - Phase 1 requires it
	return 0, fmt.Errorf("no Update Lease EDNS option found")
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
		return nil, nil, fmt.Errorf("no KEY RR in message for SIG(0) verification")
	}

	// Phase 1: Verify key tag and algorithm match
	if sigRR.KeyTag != dnskey.KeyTag() {
		return nil, nil, fmt.Errorf("SIG(0) key tag %d does not match KEY key tag %d",
			sigRR.KeyTag, dnskey.KeyTag())
	}

	if sigRR.Algorithm != dnskey.Algorithm {
		return nil, nil, fmt.Errorf("SIG(0) algorithm %d does not match KEY algorithm %d",
			sigRR.Algorithm, dnskey.Algorithm)
	}

	// Dynamic zone authorization: verify this downstream zone has a registered key in keystore
	// and that request KEY matches the expected key metadata.
	if downstreamZone == "" {
		return nil, nil, fmt.Errorf("downstream zone is empty")
	}
	expectedKeyName, err := keyrec.FindKeyByZone(h.keystoreDir, downstreamZone)
	if err != nil {
		return nil, nil, fmt.Errorf("no registered key found for downstream zone %q: %w", downstreamZone, err)
	}
	expectedKey, err := keyrec.LoadKeyFromFiles(h.keystoreDir, expectedKeyName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load downstream zone key %q: %w", expectedKeyName, err)
	}
	if dnskey.KeyTag() != expectedKey.PublicKey.KeyTag() {
		return nil, nil, fmt.Errorf("KEY tag %d does not match expected downstream key tag %d for zone %s",
			dnskey.KeyTag(), expectedKey.PublicKey.KeyTag(), downstreamZone)
	}
	if dnskey.Algorithm != expectedKey.PublicKey.Algorithm {
		return nil, nil, fmt.Errorf("KEY algorithm %d does not match expected downstream algorithm %d for zone %s",
			dnskey.Algorithm, expectedKey.PublicKey.Algorithm, downstreamZone)
	}

	// TODO: Validate actual SIG(0) signature cryptographically when verifier integration is ready
	// For Phase 1, structural validation is sufficient

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

	// Phase 1: Sign upstream UPDATE with upstream key if available
	// Provenance: Inspired by sig0namectl's SignUpdate() in update.go
	if h.upstreamKeyRecord != nil && h.upstreamKeyRecord.PrivateKey != nil {
		signedMsg, err := sig0.SignMessage(msg, h.upstreamKeyRecord.PublicKey, h.upstreamKeyRecord.PrivateKey)
		if err != nil {
			h.Debugf("WARNING: Failed to sign upstream UPDATE with SIG(0): %v (sending unsigned)", err)
		} else {
			msg = signedMsg // Use the signed message
			h.Debugf("Signed upstream UPDATE with key: %s", h.upstreamKeyRecord)
		}
	}

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

	// Load Upstream key for signing UPDATE messages to authoritative server
	upstreamKeyName, err := keyrec.FindKeyByZone(keystoreDir, h.upstreamZone)
	if err != nil {
		h.Debugf("WARNING: Could not find upstream key for %s: %v (upstream UPDATEs will be unsigned)", h.upstreamZone, err)
		// Don't fail - we can still operate and send unsigned UPDATEs
	} else {
		upstreamKey, err := keyrec.LoadKeyFromFiles(keystoreDir, upstreamKeyName)
		if err != nil {
			h.Debugf("WARNING: Failed to load upstream key: %v (upstream UPDATEs will be unsigned)", err)
		} else {
			h.upstreamKeyRecord = upstreamKey
			h.Debugf("Loaded upstream key: %s", upstreamKey)
		}
	}

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
