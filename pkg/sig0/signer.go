// Package sig0 implements SIG(0) request/response signing as per RFC 2931.
// Uses codeberg.org/miekg/dns SIG(0) facilities for proper cryptographic signing.
// Provenance: RFC 2931 (Transaction Signatures with SIG(0))
package sig0

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

// Signer holds state for signing DNS messages with SIG(0).
// Implements RFC 2931 SIG(0) signing using the loaded KeyStore.
type Signer struct {
	keyRR   *dns.KEY          // The KEY RR for this signer (RFC 2539)
	private crypto.PrivateKey // Private key material for signing
	update  *dns.Msg          // Current UPDATE message being built
}

// sig0SignerImpl wraps CryptoSIG0 or provides custom implementation for algorithms
// that CryptoSIG0 doesn't support (like ED25519 in SIG(0) mode).
// Implements the full dns.SIG0Signer interface.
type sig0SignerImpl struct {
	base      dns.CryptoSIG0
	algorithm uint8 // Algorithm for special handling (0 means use base CryptoSIG0)
}

// Sign implements the full dns.SIG0Signer interface with SIG0Option parameter
// For ED25519, we bypass the hash function requirement that CryptoSIG0 needs
func (s sig0SignerImpl) Sign(sig *dns.SIG, p []byte, _ dns.SIG0Option) ([]byte, error) {
	// For ED25519, CryptoSIG0.Sign would fail because AlgorithmToHash doesn't have it
	// ED25519 does its own hashing, so we can't use CryptoSIG0.Sign directly
	if s.algorithm == 15 { // ED25519 (algorithm value)
		// Use the Ed25519 private key directly
		ed25519Key, ok := s.base.Signer().(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ED25519 signer is not an ed25519.PrivateKey")
		}

		// According to RFC 2931 and the dns library implementation,
		// we need to sign: SIG_RDATA || MSG_BODY
		// Where SIG_RDATA is the SIG record without the signature field
		// We use the same binary wire format the dns library does

		// Build SIG record data: TypeCovered(2) + Algorithm(1) + Labels(1) + OrigTTL(4) +
		//                         Expiration(4) + Inception(4) + KeyTag(2) + SignerName + Signature(0)
		sigData := make([]byte, 0, 100)

		// TypeCovered (for SIG(0), this is typically 0)
		sigData = append(sigData, 0, 0)

		// Algorithm
		sigData = append(sigData, sig.Algorithm)

		// Labels
		sigData = append(sigData, sig.Labels)

		// OrigTTL (use Hdr.TTL)
		sigData = append(sigData, byte(sig.OrigTTL>>24), byte(sig.OrigTTL>>16), byte(sig.OrigTTL>>8), byte(sig.OrigTTL))

		// Expiration
		sigData = append(sigData, byte(sig.Expiration>>24), byte(sig.Expiration>>16), byte(sig.Expiration>>8), byte(sig.Expiration))

		// Inception
		sigData = append(sigData, byte(sig.Inception>>24), byte(sig.Inception>>16), byte(sig.Inception>>8), byte(sig.Inception))

		// KeyTag
		sigData = append(sigData, byte(sig.KeyTag>>8), byte(sig.KeyTag))

		// SignerName (wire format)
		sigData = appendDomainName(sigData, sig.SignerName)

		// Combine SIG record data with message data
		toSign := append(sigData, p...)

		// ED25519 signature
		return ed25519Key.Sign(rand.Reader, toSign, crypto.Hash(0))
	}

	// For other algorithms, use the base CryptoSIG0 implementation
	return s.base.Sign(sig, p)
}

// Helper to append domain name in DNS wire format
func appendDomainName(buf []byte, name string) []byte {
	name = canonicalDomainName(name)
	if name == "." {
		return append(buf, 0)
	}
	name = name[:len(name)-1] // strip trailing dot; root terminator is appended below

	// Split the domain name into labels
	// This is a simple implementation for DNS names
	i := 0
	for i < len(name) {
		// Find the next label
		j := i
		for j < len(name) && name[j] != '.' {
			j++
		}

		label := name[i:j]
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)

		if j == len(name) {
			break
		}
		i = j + 1
	}

	// Always terminate with root label.
	buf = append(buf, 0)

	return buf
}

func canonicalDomainName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" || name == "." {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// Verify implements the full dns.SIG0Signer interface with SIG0Option parameter
func (s sig0SignerImpl) Verify(sig *dns.SIG, p []byte, _ dns.SIG0Option) error {
	// For ED25519, we need custom verification as well
	if s.algorithm == 15 { // ED25519
		// Verify using ED25519 key from the KEY record
		// The public key is stored as base64-encoded data in the KEY record
		pubKeyB64 := s.base.PublicKey.PublicKey

		// Decode base64 public key
		pubKeyBinary, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return fmt.Errorf("failed to decode base64 public key: %w", err)
		}

		if len(pubKeyBinary) != 32 {
			return fmt.Errorf("invalid ED25519 public key length after base64 decode: %d (expected 32)", len(pubKeyBinary))
		}

		ed25519Pub := ed25519.PublicKey(pubKeyBinary)

		// Build the data that was signed - same format as Sign method
		sigData := make([]byte, 0, 100)

		// TypeCovered
		sigData = append(sigData, 0, 0)

		// Algorithm
		sigData = append(sigData, sig.Algorithm)

		// Labels
		sigData = append(sigData, sig.Labels)

		// OrigTTL
		sigData = append(sigData, byte(sig.OrigTTL>>24), byte(sig.OrigTTL>>16), byte(sig.OrigTTL>>8), byte(sig.OrigTTL))

		// Expiration
		sigData = append(sigData, byte(sig.Expiration>>24), byte(sig.Expiration>>16), byte(sig.Expiration>>8), byte(sig.Expiration))

		// Inception
		sigData = append(sigData, byte(sig.Inception>>24), byte(sig.Inception>>16), byte(sig.Inception>>8), byte(sig.Inception))

		// KeyTag
		sigData = append(sigData, byte(sig.KeyTag>>8), byte(sig.KeyTag))

		// SignerName
		sigData = appendDomainName(sigData, sig.SignerName)

		toVerify := append(sigData, p...)

		// Decode base64 signature
		sig_bytes, err := base64.StdEncoding.DecodeString(sig.Signature)
		if err != nil {
			return fmt.Errorf("failed to decode signature: %w", err)
		}

		// Verify ED25519 signature
		if !ed25519.Verify(ed25519Pub, toVerify, sig_bytes) {
			return fmt.Errorf("ED25519 signature verification failed")
		}

		return nil
	}

	// For other algorithms, use the base CryptoSIG0 implementation
	return s.base.Verify(sig, p)
}

// Key returns the KEY RR
func (s sig0SignerImpl) Key() *dns.KEY {
	return s.base.Key()
}

// Signer returns the crypto signer
func (s sig0SignerImpl) Signer() crypto.Signer {
	return s.base.Signer()
}

// NewSigner creates a new SIG(0) signer from a KEY record and private key.
// Provenance: Uses dns.CryptoSIG0 pattern from codeberg/miekg/dns
func NewSigner(keyRR *dns.KEY, privateKey crypto.PrivateKey) (*Signer, error) {
	if keyRR == nil {
		return nil, fmt.Errorf("KEY RR cannot be nil")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if _, ok := privateKey.(crypto.Signer); !ok {
		return nil, fmt.Errorf("private key must implement crypto.Signer")
	}
	return &Signer{
		keyRR:   keyRR,
		private: privateKey,
	}, nil
}

// StartUpdate initializes a new DNS UPDATE message for the given zone.
// Provenance: RFC 2136 specifies UPDATE message format
func (s *Signer) StartUpdate(zone string) error {
	if s.update != nil {
		return fmt.Errorf("update already in progress")
	}
	log.Println("-- Creating DNS UPDATE message for zone:", zone)

	// Create a proper UPDATE message (RFC 2136)
	// - Opcode = UPDATE
	// - Question section contains the zone SOA
	// - Authority section contains RRs to be added/removed
	m := new(dns.Msg)
	m.Opcode = dns.OpcodeUpdate
	m.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{
			Name:  zone,
			Class: dns.ClassINET,
		},
	}}

	s.update = m
	return nil
}

// UpdateRR adds a resource record to the UPDATE message's Authority section.
// In DNS UPDATE (RFC 2136), RRs to be added/modified go in the Authority section.
func (s *Signer) UpdateRR(rr dns.RR) error {
	if s.update == nil {
		return fmt.Errorf("no update in progress")
	}
	log.Printf("-- Adding RR to update: %s", rr.String())
	s.update.Ns = append(s.update.Ns, rr)
	return nil
}

// RemoveRR marks a resource record for removal.
// RFC 2136 specifies removal with class = NONE, ttl = 0
func (s *Signer) RemoveRR(rr dns.RR) error {
	if s.update == nil {
		return fmt.Errorf("no update in progress")
	}
	log.Printf("-- Removing RR from update: %s", rr.String())
	// Clone the RR and set class to NONE to signal deletion
	h := rr.Header()
	h.Class = dns.ClassNONE
	h.TTL = 0
	s.update.Ns = append(s.update.Ns, rr)
	return nil
}

// UpdateParsedRR adds a resource record parsed from string.
func (s *Signer) UpdateParsedRR(rrStr string) error {
	if s.update == nil {
		return fmt.Errorf("no update in progress")
	}
	log.Println("-- Parsing and adding RR:", rrStr)
	rr, err := dns.New(rrStr)
	if err != nil {
		return fmt.Errorf("failed to parse RR: %w", err)
	}
	s.update.Ns = append(s.update.Ns, rr)
	return nil
}

// RemoveParsedRR removes a resource record parsed from string.
func (s *Signer) RemoveParsedRR(rrStr string) error {
	if s.update == nil {
		return fmt.Errorf("no update in progress")
	}
	log.Println("-- Parsing and removing RR:", rrStr)
	rr, err := dns.New(rrStr)
	if err != nil {
		return fmt.Errorf("failed to parse RR: %w", err)
	}
	// Mark for deletion by setting class to NONE and TTL to 0
	h := rr.Header()
	h.Class = dns.ClassNONE
	h.TTL = 0
	s.update.Ns = append(s.update.Ns, rr)
	return nil
}

// SignUpdate signs the current UPDATE message with SIG(0) and returns it.
// Provenance: RFC 2931 SIG(0) transaction signing + codeberg/miekg/dns SIG0Sign()
func (s *Signer) SignUpdate() (*dns.Msg, error) {
	if s.update == nil {
		return nil, fmt.Errorf("no update in progress")
	}

	log.Println("-- Signing DNS UPDATE message with SIG(0) --")

	msg, err := SignMessage(s.update, s.keyRR, s.private)
	if err != nil {
		return nil, fmt.Errorf("failed to sign update with SIG(0): %w", err)
	}

	log.Println("-- SIG(0) signing successful --")

	m := msg
	s.update = nil
	return m, nil
}

// SignMessage signs any DNS message with SIG(0) using shared logic for both client and server paths.
func SignMessage(msg *dns.Msg, keyRR *dns.KEY, privateKey crypto.PrivateKey) (*dns.Msg, error) {
	if msg == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}
	if keyRR == nil {
		return nil, fmt.Errorf("KEY RR cannot be nil")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	cryptoSigner, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer interface")
	}

	now := uint32(time.Now().Unix())
	sigRR := new(dns.SIG)
	sigRR.Hdr.Name = "."
	sigRR.Hdr.Class = dns.ClassANY
	sigRR.Hdr.TTL = 0
	sigRR.Algorithm = keyRR.Algorithm
	sigRR.Inception = now - 300
	sigRR.Expiration = now + 300
	sigRR.KeyTag = keyRR.KeyTag()
	sigRR.SignerName = keyRR.Hdr.Name

	msg.Pseudo = append(msg.Pseudo, sigRR)

	baseSigner := dns.CryptoSIG0{
		CryptoSigner: cryptoSigner,
		PublicKey:    keyRR,
	}
	wrappedSigner := sig0SignerImpl{
		base:      baseSigner,
		algorithm: keyRR.Algorithm,
	}

	options := dns.SIG0Option{}
	if err := dns.SIG0Sign(msg, wrappedSigner, &options); err != nil {
		return nil, err
	}

	return msg, nil
}

// VerifySignature verifies a SIG(0) signature on a message.
// This is useful for servers to verify client-signed requests.
// Provenance: RFC 2931 SIG(0) verification + codeberg/miekg/dns SIG0Verify()
func VerifySignature(msg *dns.Msg, keyRR *dns.KEY) error {
	if msg == nil {
		return fmt.Errorf("message cannot be nil")
	}
	if keyRR == nil {
		return fmt.Errorf("KEY RR cannot be nil")
	}

	log.Println("-- Verifying SIG(0) signature on message --")

	// Create CryptoSIG0 verifier (without private key for verification)
	baseVerifier := dns.CryptoSIG0{
		PublicKey: keyRR,
	}
	cryptoVerifier := sig0SignerImpl{
		base:      baseVerifier,
		algorithm: keyRR.Algorithm, // Pass algorithm for ED25519 support
	}

	// Verify the signature using SIG0Verify from codeberg/miekg/dns
	options := dns.SIG0Option{} // Empty options struct for SIG0Verify
	err := dns.SIG0Verify(msg, keyRR, cryptoVerifier, &options)
	if err != nil {
		return fmt.Errorf("SIG(0) verification failed: %w", err)
	}

	log.Println("-- SIG(0) signature verified --")
	return nil
}
