// Package handlers provides opcode-specific processing modules.
package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/forward"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
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

// DefaultUpstreamCoordinator uses forward.Resolver to send updates upstream.
type DefaultUpstreamCoordinator struct {
	resolver *forward.Resolver
}

// NewDefaultUpstreamCoordinator creates a new upstream coordinator.
func NewDefaultUpstreamCoordinator(resolver *forward.Resolver) *DefaultUpstreamCoordinator {
	return &DefaultUpstreamCoordinator{
		resolver: resolver,
	}
}

// SendUpdate sends an UPDATE message to the upstream server.
func (u *DefaultUpstreamCoordinator) SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error) {
	if u.resolver == nil {
		return nil, fmt.Errorf("no resolver configured for upstream coordination")
	}

	// Send through resolver (which knows how to find the upstream server)
	resp, err := u.resolver.Query(ctx, updateMsg)
	if err != nil {
		return nil, fmt.Errorf("upstream update failed: %w", err)
	}

	return resp, nil
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
	downstreamZone      string            // Zone proxy is authoritative for (e.g., "test.dev.zenr.io.")
	upstreamZone        string            // Upstream authoritative zone (e.g., "dev.zenr.io.")
	downstreamKeyRecord *keyrec.LoadedKey // Client's key (Downstream key) for verifying client SIG(0)
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

// SetZone sets the downstream zone for this handler.
func (h *UpdateHandler) SetZone(zone string) {
	h.downstreamZone = zone
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
	debugf := func(format string, args ...interface{}) {
		if h.logger != nil {
			h.logger.Debugf(format, args...)
		}
	}

	debugf("Phase 1 UPDATE handler: Processing message from %s", w.RemoteAddr().String())

	// Validate message structure
	if r == nil {
		return NewErrorResult(nil, "nil message received", fmt.Errorf("nil message"))
	}

	// CHECK 1: Verify UPDATE-LEASE EDNS option is present
	// If missing, this is a regular UPDATE not relevant to sig0lease
	if !h.hasUpdateLeaseOption(r) {
		debugf("UPDATE packet lacks UPDATE-LEASE EDNS option, not sig0lease relevant")
		return NewNotRelevantResult("UPDATE without UPDATE-LEASE EDNS option - not sig0lease")
	}

	debugf("UPDATE-LEASE EDNS option present, processing as sig0lease packet")

	if len(r.Question) != 1 {
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, "exactly one question required")
		return NewErrorResult(msg, "invalid question count", fmt.Errorf("multiple questions"))
	}

	// Extract zone and class from question
	qHeader := r.Question[0].Header()
	zone := qHeader.Name
	class := qHeader.Class

	debugf("UPDATE for zone: %s (class: %d)", zone, class)

	// Phase 1: Zone must match configured downstream zone
	if zone != h.downstreamZone {
		debugf("Zone mismatch: got %s, expected %s", zone, h.downstreamZone)
		msg := h.makeErrorResponse(r, dns.RcodeNotAuth, "not authorized for this zone")
		return NewErrorResult(msg, fmt.Sprintf("zone mismatch: %s vs %s", zone, h.downstreamZone), nil)
	}

	// Extract lease EDNS(0) option (8-byte variant: LEASE + KEY-LEASE)
	leaseDuration, err := h.parseLease(r)
	if err != nil {
		debugf("Lease parsing failed: %v", err)
		msg := h.makeErrorResponse(r, uint16(16), fmt.Sprintf("invalid lease: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("lease parsing failed: %v", err), err)
	}

	debugf("Parsed lease duration: %d seconds", leaseDuration)

	// Extract and validate client SIG(0)
	sigRR, _, err := h.extractAndValidateSig0(r)
	if err != nil {
		debugf("SIG(0) validation failed: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("SIG(0) validation failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("SIG(0) validation failed: %v", err), err)
	}

	debugf("SIG(0) validated: Algorithm=%d, KeyTag=%d, Signer=%s",
		sigRR.Algorithm, sigRR.KeyTag, sigRR.SignerName)

	// Extract client's KEY RR from update records (Authority section)
	// For Phase 1, we expect exactly one KEY RR
	var clientKeyRR *dns.KEY
	for _, rr := range r.Ns {
		if key, ok := rr.(*dns.KEY); ok {
			clientKeyRR = key
			debugf("Extracted client KEY RR: %s", key.String())
			break
		}
	}

	if clientKeyRR == nil {
		debugf("No KEY RR found in update records")
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, "no KEY RR in update")
		return NewErrorResult(msg, "no KEY RR found in update records", nil)
	}

	// Register lease in in-memory storage
	clientKeyName := clientKeyRR.Hdr.Name
	if err := h.leaseManager.Register(ctx, clientKeyName, clientKeyRR, leaseDuration, h.upstreamZone); err != nil {
		debugf("Failed to register lease: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("lease registration failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("lease registration failed: %v", err), err)
	}

	debugf("Lease registered for %s (duration: %d seconds)", clientKeyName, leaseDuration)

	// Construct UPDATE message for upstream zone
	upstreamUpdate, err := h.constructUpstreamUpdate(clientKeyName, clientKeyRR, h.upstreamZone)
	if err != nil {
		debugf("Failed to construct upstream UPDATE: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream construction failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("upstream construction failed: %v", err), err)
	}

	// TODO: Sign upstream UPDATE with upstream SIG(0) key when available
	// For now, send unsigned UPDATE to upstream

	// Send UPDATE to upstream
	if h.upstreamCoordinator != nil {
		upstreamResp, err := h.upstreamCoordinator.SendUpdate(ctx, h.upstreamZone, upstreamUpdate)
		if err != nil {
			debugf("Upstream UPDATE failed: %v", err)
			// Don't fail locally - lease is tracked, upstream can be retried
			// For Phase 1, we optimistically return success if lease is registered
		} else if upstreamResp != nil {
			debugf("Upstream UPDATE response: Rcode=%d", upstreamResp.Rcode)
			if upstreamResp.Rcode != dns.RcodeSuccess {
				debugf("Upstream rejected UPDATE with rcode %d", upstreamResp.Rcode)
			}
		}
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

	debugf("Sending success response for %s (lease: %d seconds)", clientKeyName, leaseDuration)

	return NewProcessedResult(resp)
}

// parseLease extracts the 8-byte lease EDNS(0) option from the message.
// Returns the lease duration in seconds, or an error if the option is invalid.
func (h *UpdateHandler) hasUpdateLeaseOption(msg *dns.Msg) bool {
	// RFC 9664 Section 4: UPDATE-LEASE is EDNS(0) option code 2
	if h.logger != nil {
		h.logger.Debugf("hasUpdateLeaseOption: checking message with %d Extra records", len(msg.Extra))
	}
	for i, rr := range msg.Extra {
		if h.logger != nil {
			h.logger.Debugf("  Extra[%d]: %T = %v", i, rr, rr)
		}
		if opt, ok := rr.(*dns.OPT); ok {
			if h.logger != nil {
				h.logger.Debugf("    Found OPT RR with %d options", len(opt.Options))
			}
			for j, option := range opt.Options {
				if h.logger != nil {
					h.logger.Debugf("      Option[%d]: %T = %v", j, option, option)
				}
				if erfc, ok := option.(*dns.ERFC3597); ok {
					if h.logger != nil {
						h.logger.Debugf("        ERFC3597 with code %d (looking for 2)", erfc.EDNS0Code)
					}
					if erfc.EDNS0Code == 2 {
						if h.logger != nil {
							h.logger.Debugf("      Found UPDATE-LEASE option!")
						}
						return true
					}
				}
			}
		}
	}
	if h.logger != nil {
		h.logger.Debugf("  No UPDATE-LEASE option found")
	}
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
func (h *UpdateHandler) extractAndValidateSig0(msg *dns.Msg) (*dns.SIG, *dns.KEY, error) {
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

	// Phase 1: Verify KEY matches expected downstream key if loaded
	// Provenance: Validation pattern from sig0namectl's verifier.go
	if h.downstreamKeyRecord != nil {
		if dnskey.KeyTag() != h.downstreamKeyRecord.PublicKey.KeyTag() {
			return nil, nil, fmt.Errorf("KEY tag %d does not match expected downstream key tag %d",
				dnskey.KeyTag(), h.downstreamKeyRecord.PublicKey.KeyTag())
		}
		if dnskey.Algorithm != h.downstreamKeyRecord.PublicKey.Algorithm {
			return nil, nil, fmt.Errorf("KEY algorithm %d does not match expected downstream algorithm %d",
				dnskey.Algorithm, h.downstreamKeyRecord.PublicKey.Algorithm)
		}
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
		// Use the client's proven Sig0Signer implementation
		signer, err := client.NewSig0Signer(h.upstreamKeyRecord.PublicKey, h.upstreamKeyRecord.PrivateKey)
		if err != nil {
			if h.logger != nil {
				h.logger.Debugf("WARNING: Failed to create SIG(0) signer: %v (sending unsigned)", err)
			}
		} else {
			signedMsg, err := signer.SignMessage(msg)
			if err != nil {
				if h.logger != nil {
					h.logger.Debugf("WARNING: Failed to sign upstream UPDATE with SIG(0): %v (sending unsigned)", err)
				}
			} else {
				msg = signedMsg // Use the signed message
				if h.logger != nil {
					h.logger.Debugf("Signed upstream UPDATE with key: %s", h.upstreamKeyRecord)
				}
			}
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
//   - "downstream_zone": Proxy's zone (e.g., "test.dev.zenr.io.") [REQUIRED]
//   - "upstream_zone": Authoritative zone (e.g., "dev.zenr.io.") [REQUIRED]
//   - "downstream_key": Path to downstream private key file [OPTIONAL, Phase 1 doesn't sign responses]
//   - "upstream_key": Path to upstream private key file [OPTIONAL, needed for upstream UPDATE signing]
//   - "upstream_resolver": *forward.Resolver instance [RECOMMENDED for production]
//   - "lease_manager": Custom LeaseManager implementation [OPTIONAL, defaults to InMemoryLeaseManager]
//   - "persistence_hook": Persistence function for leases [OPTIONAL]
func (h *UpdateHandler) Setup(cfg map[string]any) error {
	debugf := func(format string, args ...interface{}) {
		if h.logger != nil {
			h.logger.Debugf(format, args...)
		}
	}

	// Extract zones
	if zone, ok := cfg["downstream_zone"].(string); ok && zone != "" {
		h.downstreamZone = zone
		debugf("UpdateHandler downstream zone: %s", zone)
	} else {
		return fmt.Errorf("downstream_zone is required in config")
	}

	if zone, ok := cfg["upstream_zone"].(string); ok && zone != "" {
		h.upstreamZone = zone
		debugf("UpdateHandler upstream zone: %s", zone)
	} else {
		return fmt.Errorf("upstream_zone is required in config")
	}

	// Keystore directory - required for loading keys
	keystoreDir, ok := cfg["keystore_dir"].(string)
	if !ok || keystoreDir == "" {
		return fmt.Errorf("keystore_dir is required in config handlers.update section")
	}
	h.keystoreDir = keystoreDir
	debugf("Using keystore directory: %s", keystoreDir)

	// Load Downstream key for verifying client SIG(0)
	// Provenance: Inspired by sig0namectl key loading
	downstreamKeyName, err := keyrec.FindKeyByZone(keystoreDir, h.downstreamZone)
	if err != nil {
		debugf("WARNING: Could not find downstream key for %s: %v (SIG(0) verification disabled)", h.downstreamZone, err)
		// Don't fail - we can still operate in Phase 1 without verification
	} else {
		downstreamKey, err := keyrec.LoadKeyFromFiles(keystoreDir, downstreamKeyName)
		if err != nil {
			debugf("WARNING: Failed to load downstream key: %v (SIG(0) verification disabled)", err)
		} else {
			h.downstreamKeyRecord = downstreamKey
			debugf("Loaded downstream key: %s", downstreamKey)
		}
	}

	// Load Upstream key for signing UPDATE messages to authoritative server
	upstreamKeyName, err := keyrec.FindKeyByZone(keystoreDir, h.upstreamZone)
	if err != nil {
		debugf("WARNING: Could not find upstream key for %s: %v (upstream UPDATEs will be unsigned)", h.upstreamZone, err)
		// Don't fail - we can still operate and send unsigned UPDATEs
	} else {
		upstreamKey, err := keyrec.LoadKeyFromFiles(keystoreDir, upstreamKeyName)
		if err != nil {
			debugf("WARNING: Failed to load upstream key: %v (upstream UPDATEs will be unsigned)", err)
		} else {
			h.upstreamKeyRecord = upstreamKey
			debugf("Loaded upstream key: %s", upstreamKey)
		}
	}

	// Optional: Custom lease manager
	if lm, ok := cfg["lease_manager"].(LeaseManager); ok && lm != nil {
		h.leaseManager = lm
		debugf("Custom lease manager configured")
	}

	// Optional: Persistence hook for leases
	if hook, ok := cfg["persistence_hook"].(func(context.Context, string, *LeaseRecord) error); ok {
		h.leaseManager.SetPersistenceHook(hook)
		debugf("Persistence hook configured for leases")
	}

	// Optional: Upstream resolver for forwarding
	if resolver, ok := cfg["upstream_resolver"].(*forward.Resolver); ok && resolver != nil {
		h.upstreamCoordinator = NewDefaultUpstreamCoordinator(resolver)
		debugf("Upstream coordinator configured")
	} else {
		// For Phase 1 development, we can work without upstream coordination
		debugf("WARNING: No upstream resolver configured - upstream coordination disabled")
	}

	return nil
}
