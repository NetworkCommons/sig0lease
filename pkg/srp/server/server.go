// Package server implements the SRP (Service Registration Protocol) server.
//
// SRP servers process DNS UPDATE messages containing SRP Instructions and
// manage the registration, update, and deletion of services.
package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/srp/instruction"
)

// Server manages SRP service registrations.
type Server struct {
	zone     string
	keyStore KeyStore // Interface for key management
}

// KeyStore is an interface for managing keys.
type KeyStore interface {
	// AddKey adds a key to the store
	AddKey(key *dns.DNSKEY)
	// GetKey retrieves the DNSKEY by name
	GetKey(name string) (*dns.DNSKEY, error)
	// GetKeysByZone retrieves all keys for a zone
	GetKeysByZone(zone string) ([]*dns.DNSKEY, error)
	// VerifySignature verifies a SIG(0) signature
	VerifySignature(msg *dns.Msg, key *dns.DNSKEY) error
}

// DefaultKeyStore is a simple in-memory key store for testing.
type DefaultKeyStore struct {
	keys map[string]*dns.DNSKEY
}

// NewDefaultKeyStore creates a new default key store.
func NewDefaultKeyStore() *DefaultKeyStore {
	return &DefaultKeyStore{
		keys: make(map[string]*dns.DNSKEY),
	}
}

// AddKey adds a key to the store.
func (s *DefaultKeyStore) AddKey(key *dns.DNSKEY) {
	s.keys[key.Hdr.Name] = key
}

// GetKey retrieves a key by name.
func (s *DefaultKeyStore) GetKey(name string) (*dns.DNSKEY, error) {
	key, exists := s.keys[name]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", name)
	}
	return key, nil
}

// GetKeysByZone retrieves keys by zone.
func (s *DefaultKeyStore) GetKeysByZone(zone string) ([]*dns.DNSKEY, error) {
	var keys []*dns.DNSKEY
	for name, key := range s.keys {
		if strings.HasSuffix(name, "."+zone) || name == zone {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found for zone: %s", zone)
	}
	return keys, nil
}

// VerifySignature verifies a SIG(0) signature.
func (s *DefaultKeyStore) VerifySignature(msg *dns.Msg, key *dns.DNSKEY) error {
	// Placeholder for signature verification
	return nil // In real implementation, verify the signature
}

// New creates a new SRP server.
func New(zone string) *Server {
	return &Server{
		zone:     zone,
		keyStore: NewDefaultKeyStore(),
	}
}

// NewWithKeyStore creates a new SRP server with a custom key store.
func NewWithKeyStore(zone string, ks KeyStore) *Server {
	return &Server{
		zone:     zone,
		keyStore: ks,
	}
}

// Process processes a DNS UPDATE message containing SRP Instructions.
func (s *Server) Process(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// Validate the message
	if err := s.validateMessage(msg); err != nil {
		return s.errorResponse(msg, dns.RcodeFormatError, err.Error()), nil
	}

	// Verify SIG(0) if present
	if err := s.verifySIG0(msg); err != nil {
		return s.errorResponse(msg, dns.RcodeNotAuth, err.Error()), nil
	}

	// Process prerequisites
	if err := s.processPrerequisites(msg); err != nil {
		return s.errorResponse(msg, dns.RcodeYXDomain, err.Error()), nil
	}

	// Process SRP Instructions from the Additional section
	results := s.processInstructions(msg)

	// Check if any instruction failed to parse
	for _, result := range results {
		if result.Action == "parse_error" {
			return s.errorResponse(msg, dns.RcodeFormatError, result.Error.Error()), nil
		}
	}

	// Build response
	resp := s.buildResponse(msg, results)
	return resp, nil
}

// validateMessage validates the incoming DNS UPDATE message.
func (s *Server) validateMessage(msg *dns.Msg) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}

	if msg.Response || msg.Opcode != dns.OpcodeUpdate {
		return fmt.Errorf("not an UPDATE message")
	}

	if len(msg.Question) != 1 {
		return fmt.Errorf("UPDATE messages must have exactly one question")
	}

	q := msg.Question[0]
	if q.Header().Class != dns.ClassANY {
		return fmt.Errorf("UPDATE messages must have Qclass=ANY")
	}

	if dns.RRToType(q) != dns.TypeSOA {
		return fmt.Errorf("UPDATE messages must have Qtype=SOA")
	}

	zoneName := ensureFQDN(s.zone)
	qName := ensureFQDN(q.Header().Name)

	// The question zone must exactly match the server's zone
	if qName != zoneName {
		return fmt.Errorf("zone mismatch: got %s, expected %s", qName, zoneName)
	}

	// Check for nil RRs in Extra section
	for _, rr := range msg.Extra {
		if rr == nil {
			return fmt.Errorf("nil RR in Additional section")
		}
	}

	return nil
}

// verifySIG0 verifies the SIG(0) signature if present in the message.
func (s *Server) verifySIG0(msg *dns.Msg) error {
	// Find SIG(0) record
	sigRR := s.findSIG0(msg)
	if sigRR == nil {
		return nil // No SIG(0) is allowed for testing
	}

	// Find DNSKEY record
	dnskey := s.findDNSKEY(msg)
	if dnskey == nil {
		return fmt.Errorf("DNSKEY not found for SIG(0) verification")
	}

	// Verify key tag matches
	if sigRR.KeyTag != dnskey.KeyTag() {
		return fmt.Errorf("SIG(0) key tag %d does not match DNSKEY key tag %d",
			sigRR.KeyTag, dnskey.KeyTag())
	}

	// Verify algorithm matches
	if sigRR.Algorithm != dnskey.Algorithm {
		return fmt.Errorf("SIG(0) algorithm %d does not match DNSKEY algorithm %d",
			sigRR.Algorithm, dnskey.Algorithm)
	}

	// In a real implementation, verify the signature
	if s.keyStore != nil {
		if err := s.keyStore.VerifySignature(msg, dnskey); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	return nil
}

// findSIG0 finds the SIG(0) record in the message.
func (s *Server) findSIG0(msg *dns.Msg) *dns.SIG {
	for _, rr := range msg.Extra {
		if sig, ok := rr.(*dns.SIG); ok {
			return sig
		}
	}
	for _, rr := range msg.Answer {
		if sig, ok := rr.(*dns.SIG); ok {
			return sig
		}
	}
	return nil
}

// findDNSKEY finds the DNSKEY record in the message.
func (s *Server) findDNSKEY(msg *dns.Msg) *dns.DNSKEY {
	for _, rr := range msg.Extra {
		if key, ok := rr.(*dns.DNSKEY); ok {
			return key
		}
	}
	for _, rr := range msg.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			return key
		}
	}
	return nil
}

// processPrerequisites checks prerequisite records.
func (s *Server) processPrerequisites(msg *dns.Msg) error {
	for _, rr := range msg.Extra {
		switch rr.(type) {
		case *dns.SOA:
			// SOA prerequisites check if the zone exists
			// This is a basic implementation; real servers would check actual zone state
		case *dns.A, *dns.AAAA, *dns.TXT:
			// Other prerequisite types could be checked here
		default:
			// Unknown record type - skip or log warning
		}
	}
	return nil
}

// InstructionResult holds the result of processing a single instruction.
type InstructionResult struct {
	Name        string
	Instruction *instruction.Instruction
	Action      string // "register", "update", or "delete"
	Success     bool
	Error       error
}

// processInstructions processes all SRP Instructions in the message.
func (s *Server) processInstructions(msg *dns.Msg) []InstructionResult {
	var results []InstructionResult

	if msg == nil || msg.Extra == nil {
		return results
	}

	for _, rr := range msg.Extra {
		if rr == nil {
			continue
		}

		inst, err := s.parseInstruction(rr)
		if err != nil {
			hdr := rr.Header()
			if hdr == nil {
				continue
			}
			results = append(results, InstructionResult{
				Name:    hdr.Name,
				Action:  "parse_error",
				Success: false,
				Error:   err,
			})
			continue
		}

		if inst == nil {
			continue
		}

		var action string
		if inst.IsServiceDelete() {
			action = "delete"
			// Delete service
		} else {
			action = "register"
			// Register/update service
		}

		results = append(results, InstructionResult{
			Name:        inst.Name,
			Instruction: inst,
			Action:      action,
			Success:     true,
		})
	}

	return results
}

// parseInstruction parses a DNS RR into an Instruction.
func (s *Server) parseInstruction(rr dns.RR) (*instruction.Instruction, error) {
	switch record := rr.(type) {
	case *dns.ERFC3597:
		if record.EDNS0Code != instruction.OPTION_CODE {
			return nil, fmt.Errorf("not an SRP instruction (opcode %d)", record.EDNS0Code)
		}

		data, err := hex.DecodeString(record.Code)
		if err != nil {
			return nil, fmt.Errorf("failed to decode instruction hex payload: %w", err)
		}

		inst := &instruction.Instruction{}
		if err := inst.Decode(data); err != nil {
			return nil, fmt.Errorf("decode instruction: %w", err)
		}
		return inst, nil
	default:
		return nil, fmt.Errorf("unsupported RR type for instruction: %T", rr)
	}
}

// buildResponse builds the response message.
func (s *Server) buildResponse(request *dns.Msg, results []InstructionResult) *dns.Msg {
	response := new(dns.Msg)
	response.ID = request.ID
	response.Response = true
	response.Opcode = request.Opcode
	if response.Opcode == dns.OpcodeQuery {
		response.RecursionDesired = request.RecursionDesired
	}
	response.Rcode = uint16(dns.RcodeSuccess)
	response.Question = request.Question

	// Add answer records (original zone state, if requested)
	for _, rr := range request.Answer {
		response.Answer = append(response.Answer, rr)
	}

	// Add authority records (SOA update would go here in a real implementation)
	response.Ns = append(response.Ns, s.createSOA())

	// Add results to extra section
	response.Extra = request.Extra

	return response
}

// createSOA creates a minimal SOA record for the zone.
func (s *Server) createSOA() *dns.SOA {
	soa := &dns.SOA{
		Hdr: dns.Header{
			Name:  s.zone,
			Class: dns.ClassINET,
			TTL:   3600,
		},
	}
	soa.Ns = "ns1." + s.zone
	soa.Mbox = "admin." + s.zone
	soa.Serial = 1
	soa.Refresh = 3600
	soa.Retry = 600
	soa.Expire = 604800
	soa.Minttl = 86400
	return soa
}

// errorResponse creates an error response.
func (s *Server) errorResponse(request *dns.Msg, rcode uint16, msg string) *dns.Msg {
	response := new(dns.Msg)
	response.ID = request.ID
	response.Response = true
	response.Opcode = request.Opcode
	if response.Opcode == dns.OpcodeQuery {
		response.RecursionDesired = request.RecursionDesired
	}
	response.Rcode = rcode

	// Add error message to extra section
	if msg != "" {
		txt := &dns.TXT{
			Hdr: dns.Header{Name: ".", Class: dns.ClassANY},
		}
		txt.TXT.Txt = []string{fmt.Sprintf("Error: %s", msg)}
		response.Extra = append(response.Extra, txt)
	}

	return response
}

// ProcessUpdateMessage is a wrapper for the common case.
func (s *Server) ProcessUpdateMessage(msg *dns.Msg) (*dns.Msg, error) {
	return s.Process(context.Background(), msg)
}

// GetZone returns the zone managed by this server.
func (s *Server) GetZone() string {
	return s.zone
}

// RegisterKey registers a key with the server.
func (s *Server) RegisterKey(key *dns.DNSKEY) error {
	s.keyStore.AddKey(key)
	return nil
}

// KeyStore returns the key store.
func (s *Server) KeyStore() KeyStore {
	return s.keyStore
}

// ensureFQDN ensures a domain name is fully qualified by appending a trailing dot if needed.
func ensureFQDN(name string) string {
	if name == "" {
		return name
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
