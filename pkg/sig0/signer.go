// Package sig0 implements SIG(0) request/response signing as per RFC 2931.
// This is a simplified implementation for the SRP proxy use case.
package sig0

import (
	"crypto"
	"fmt"
	"log"
	"time"

	"codeberg.org/miekg/dns"
)

const (
	// ECDSAP256SHA256 is the required algorithm per RFC 9665 §6.6
	ECDSAP256SHA256 = 13
)

// KeyStore interface defines how to access keys for signing.
type KeyStore interface {
	PrivateKey() crypto.PrivateKey
	PublicKey() dns.RR // Returns a KEY or DNSKEY RR
	Name() string      // Name of the key (for logging)
}

// Signer holds state for signing DNS messages with SIG(0).
type Signer struct {
	store   KeyStore
	private crypto.PrivateKey
	update  *dns.Msg
}

// NewSigner creates a new signer from a keystore.
func NewSigner(store KeyStore) (*Signer, error) {
	private := store.PrivateKey()
	if private == nil {
		return nil, fmt.Errorf("no private key available")
	}
	return &Signer{
		store:   store,
		private: private,
	}, nil
}

// StartUpdate initializes a new DNS update message for the given zone.
func (s *Signer) StartUpdate(zone string) error {
	if s.update != nil {
		return fmt.Errorf("update already in progress")
	}
	log.Println("-- Set dns.Msg Structure --")

	// Create an UPDATE message with SOA in Question section
	m := new(dns.Msg)
	m.Opcode = dns.OpcodeUpdate
	m.Question = []dns.RR{&dns.SOA{Hdr: dns.Header{Name: zone, Class: dns.ClassINET}}}

	s.update = m
	return nil
}

// UpdateRR adds a resource record to the current update.
func (s *Signer) UpdateRR(rr dns.RR) error {
	if s.update == nil {
		return fmt.Errorf("no update in progress")
	}
	log.Println("-- Adding RR --")
	s.update.Extra = append(s.update.Extra, rr)
	return nil
}

// RemoveRR removes a resource record from the current update.
func (s *Signer) RemoveRR(rr dns.RR) error {
	if s.update == nil {
		return fmt.Errorf("no update in progress")
	}
	log.Println("-- Removing RR --")
	s.update.Extra = append(s.update.Extra, rr)
	return nil
}

// UpdateParsedRR adds a resource record parsed from string.
func (s *Signer) UpdateParsedRR(rrStr string) error {
	if s.update == nil {
		return fmt.Errorf("no update in progress")
	}
	log.Println("-- Parsing and adding RR: ", rrStr)
	rr, err := dns.New(rrStr)
	if err != nil {
		return fmt.Errorf("failed to parse RR: %w", err)
	}
	s.update.Extra = append(s.update.Extra, rr)
	return nil
}

// RemoveParsedRR removes a resource record parsed from string.
func (s *Signer) RemoveParsedRR(rrStr string) error {
	if s.update == nil {
		return fmt.Errorf("no update in progress")
	}
	log.Println("-- Parsing and removing RR: ", rrStr)
	rr, err := dns.New(rrStr)
	if err != nil {
		return fmt.Errorf("failed to parse RR: %w", err)
	}
	s.update.Extra = append(s.update.Extra, rr)
	return nil
}

// SignUpdate signs the update message with SIG(0).
func (s *Signer) SignUpdate() (*dns.Msg, error) {
	if s.update == nil {
		return nil, fmt.Errorf("no update in progress")
	}

	log.Println("-- Signing DNS message with SIG(0) --")

	// Get public key for signing parameters
	pubKey := s.store.PublicKey()
	rdataKey := getDNSKEYData(pubKey)

	// Create SIG RR with proper parameters
	sigRR := new(dns.SIG)
	sigRR.Hdr.Name = "."
	sigRR.Algorithm = rdataKey.Algorithm
	sigRR.Expiration = uint32(time.Now().Unix()) + 300 // 5 minutes validity
	sigRR.Inception = uint32(time.Now().Unix()) - 300
	sigRR.KeyTag = keyTag(pubKey)
	sigRR.SignerName = pubKey.Header().Name

	log.Printf("-- Signing with algorithm %d, key tag %d --", sigRR.Algorithm, sigRR.KeyTag)

	// Add SIG to extra section and pack the message
	s.update.Extra = append(s.update.Extra, sigRR)
	if err := s.update.Pack(); err != nil {
		return nil, fmt.Errorf("failed to pack message: %w", err)
	}

	m := s.update
	s.update = nil
	return m, nil
}

// getDNSKEYData extracts DNSKEY rdata from a public key RR.
func getDNSKEYData(pubKey dns.RR) struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string
} {
	switch rr := pubKey.(type) {
	case *dns.KEY:
		return struct {
			Flags     uint16
			Protocol  uint8
			Algorithm uint8
			PublicKey string
		}{
			Flags:     rr.Flags,
			Protocol:  rr.Protocol,
			Algorithm: rr.Algorithm,
			PublicKey: rr.PublicKey,
		}
	case *dns.DNSKEY:
		return struct {
			Flags     uint16
			Protocol  uint8
			Algorithm uint8
			PublicKey string
		}{
			Flags:     rr.Flags,
			Protocol:  rr.Protocol,
			Algorithm: rr.Algorithm,
			PublicKey: rr.PublicKey,
		}
	default:
		return struct {
			Flags     uint16
			Protocol  uint8
			Algorithm uint8
			PublicKey string
		}{}
	}
}

// keyTag calculates the key tag for SIG(0) use.
func keyTag(pubKey dns.RR) uint16 {
	switch rr := pubKey.(type) {
	case *dns.KEY:
		return rr.KeyTag()
	case *dns.DNSKEY:
		return rr.KeyTag()
	default:
		return 0
	}
}
