// File: client/sig0.go
// SIG(0) signing support for DNS requests
// Provenance: Inspired by sig0namectl's update.go SIG(0) signing mechanism

package client

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"codeberg.org/miekg/dns"
)

// Sig0Signer wraps a private key for signing DNS messages with SIG(0).
// Provenance: Inspired by sig0namectl's Signer structure
type Sig0Signer struct {
	// PublicKey is the KEY RR with public key material
	PublicKey *dns.KEY

	// PrivateKey is the private key for signing
	PrivateKey crypto.PrivateKey
}

// NewSig0Signer creates a new SIG(0) signer from a public and private key.
func NewSig0Signer(publicKey *dns.KEY, privateKey crypto.PrivateKey) (*Sig0Signer, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	return &Sig0Signer{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// SignMessage adds SIG(0) signature to a DNS message.
// Provenance: RFC 2931 SIG(0) using pkg/sig0 Signer
func (s *Sig0Signer) SignMessage(msg *dns.Msg) (*dns.Msg, error) {
	if msg == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}

	// Create a SIG record for SIG(0) signing
	now := uint32(time.Now().Unix())
	sigRR := new(dns.SIG)
	sigRR.Hdr.Name = "."
	sigRR.Hdr.Class = dns.ClassANY
	sigRR.Algorithm = s.PublicKey.Algorithm
	sigRR.Inception = now - 300  // 5 minutes before now (clock skew tolerance)
	sigRR.Expiration = now + 300 // 5 minutes after now (signature validity)
	sigRR.KeyTag = s.PublicKey.KeyTag()
	sigRR.SignerName = s.PublicKey.Hdr.Name

	// Add the SIG record to the Pseudo section
	msg.Pseudo = append(msg.Pseudo, sigRR)

	// Create wrapper signer that implements dns.SIG0Signer interface
	wrappedSigner := &sig0SignerImpl{
		publicKey:  s.PublicKey,
		privateKey: s.PrivateKey,
	}

	// Sign the message using dns.SIG0Sign
	options := dns.SIG0Option{}
	err := dns.SIG0Sign(msg, wrappedSigner, &options)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message with SIG(0): %w", err)
	}

	return msg, nil
}

// sig0SignerImpl wraps public and private keys to implement dns.SIG0Signer interface
type sig0SignerImpl struct {
	publicKey  *dns.KEY
	privateKey crypto.PrivateKey
}

// Sign implements the dns.SIG0Signer interface
func (s *sig0SignerImpl) Sign(sig *dns.SIG, p []byte, _ dns.SIG0Option) ([]byte, error) {
	// For ED25519, use direct signing
	if sig.Algorithm == 15 { // ED25519
		ed25519Key, ok := s.privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ED25519 private key type assertion failed")
		}

		// Build SIG_RDATA for signing
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

		// SignerName (wire format domain name)
		sigData = appendDomainName(sigData, sig.SignerName)

		// Combine with message body
		toSign := append(sigData, p...)

		// Sign with ED25519 - pass crypto.Hash(0) as opts
		signature, err := ed25519Key.Sign(rand.Reader, toSign, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("ED25519 signing failed: %w", err)
		}

		return signature, nil
	}

	// For other algorithms, use crypto.Signer interface
	signer, ok := s.privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	// Build SIG_RDATA for signing
	sigData := make([]byte, 0, 100)
	sigData = append(sigData, 0, 0) // TypeCovered
	sigData = append(sigData, sig.Algorithm)
	sigData = append(sigData, sig.Labels)
	sigData = append(sigData, byte(sig.OrigTTL>>24), byte(sig.OrigTTL>>16), byte(sig.OrigTTL>>8), byte(sig.OrigTTL))
	sigData = append(sigData, byte(sig.Expiration>>24), byte(sig.Expiration>>16), byte(sig.Expiration>>8), byte(sig.Expiration))
	sigData = append(sigData, byte(sig.Inception>>24), byte(sig.Inception>>16), byte(sig.Inception>>8), byte(sig.Inception))
	sigData = append(sigData, byte(sig.KeyTag>>8), byte(sig.KeyTag))
	sigData = appendDomainName(sigData, sig.SignerName)

	toSign := append(sigData, p...)

	// Sign using crypto.Signer interface with crypto.Hash(0)
	sig_data, err := signer.Sign(rand.Reader, toSign, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	return sig_data, nil
}

// Verify implements the dns.SIG0Signer interface (not used in signing, but required by interface)
func (s *sig0SignerImpl) Verify(sig *dns.SIG, p []byte, _ dns.SIG0Option) error {
	// This is not needed for signing, but required by interface
	return fmt.Errorf("verify not implemented for client signer")
}

// Key returns the KEY RR
func (s *sig0SignerImpl) Key() *dns.KEY {
	return s.publicKey
}

// Signer returns the crypto.Signer
func (s *sig0SignerImpl) Signer() crypto.Signer {
	signer, ok := s.privateKey.(crypto.Signer)
	if !ok {
		return nil
	}
	return signer
}

// appendDomainName appends a domain name in DNS wire format (labels with length prefix)
func appendDomainName(buf []byte, name string) []byte {
	if name == "." {
		return append(buf, 0)
	}

	i := 0
	for i < len(name) {
		// Find the next label separator (dot)
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

	// Add root label if not already present
	if len(name) == 0 || name[len(name)-1] != '.' {
		buf = append(buf, 0)
	}

	return buf
}

// MakeRegistrationRequest creates a Phase 1 registration request with 8-byte lease EDNS option.
// This sends a KEY RR to be registered under the downstream zone.
// Provenance: RFC 9664 Section 3 (Lease Option Format)
func MakeRegistrationRequest(downstreamZone string, keyRR *dns.KEY, leaseDuration uint32) (*dns.Msg, error) {
	if downstreamZone == "" {
		return nil, fmt.Errorf("downstream zone cannot be empty")
	}
	if keyRR == nil {
		return nil, fmt.Errorf("KEY RR cannot be nil")
	}
	if leaseDuration < 30 {
		return nil, fmt.Errorf("lease duration must be at least 30 seconds")
	}

	// Create UPDATE message for the downstream zone
	msg := dns.NewMsg(downstreamZone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}

	msg.Opcode = dns.OpcodeUpdate

	// Add KEY RR to the Authority section (records to be added)
	msg.Ns = append(msg.Ns, keyRR)

	// Add 8-byte lease EDNS(0) option (RFC 9664)
	// Format: 4-byte LEASE + 4-byte KEY-LEASE
	// For Phase 1, we only use LEASE (set KEY-LEASE to 0)
	opt := &dns.OPT{
		Hdr: dns.Header{
			Name: ".",
		},
	}

	// Create the lease data: 4-byte big-endian LEASE + 4-byte big-endian KEY-LEASE
	leaseData := make([]byte, 8)
	leaseData[0] = byte(leaseDuration >> 24)
	leaseData[1] = byte(leaseDuration >> 16)
	leaseData[2] = byte(leaseDuration >> 8)
	leaseData[3] = byte(leaseDuration)
	// leaseData[4:8] = 0 (KEY-LEASE defaults to 0)

	// Create ERFC3597 option with code 2 (Update Lease)
	// Provenance: RFC 9664 defines Update Lease as EDNS code 2
	leaseOption := &dns.ERFC3597{
		EDNS0Code: 2,
		Code:      fmt.Sprintf("%02x", leaseData), // Hex-encoded for DNS library
	}

	opt.Options = append(opt.Options, leaseOption)
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	msg.Extra = append(msg.Extra, opt)

	return msg, nil
}

// MakeRefreshRequest creates a Phase 2 refresh request to extend an existing lease.
// Provenance: RFC 9664 Section 3 - Refresh variant uses same EDNS structure
func MakeRefreshRequest(downstreamZone string, keyName string, newLeaseDuration uint32) (*dns.Msg, error) {
	if downstreamZone == "" {
		return nil, fmt.Errorf("downstream zone cannot be empty")
	}
	if keyName == "" {
		return nil, fmt.Errorf("key name cannot be empty")
	}
	if newLeaseDuration < 30 {
		return nil, fmt.Errorf("lease duration must be at least 30 seconds")
	}

	// Create UPDATE message
	msg := dns.NewMsg(downstreamZone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}

	msg.Opcode = dns.OpcodeUpdate

	// For refresh, we add an empty KEY RR with just the name (no RDATA)
	// This signals a refresh rather than a new registration
	emptyKeyRR := &dns.KEY{
		DNSKEY: dns.DNSKEY{
			Hdr: dns.Header{
				Name:  keyName,
				Class: dns.ClassINET,
				TTL:   0,
			},
		},
	}
	msg.Ns = append(msg.Ns, emptyKeyRR)

	// Add lease EDNS(0) option
	opt := &dns.OPT{
		Hdr: dns.Header{
			Name: ".",
		},
	}

	leaseData := make([]byte, 8)
	leaseData[0] = byte(newLeaseDuration >> 24)
	leaseData[1] = byte(newLeaseDuration >> 16)
	leaseData[2] = byte(newLeaseDuration >> 8)
	leaseData[3] = byte(newLeaseDuration)

	leaseOption := &dns.ERFC3597{
		EDNS0Code: 2,
		Code:      fmt.Sprintf("%02x", leaseData),
	}

	opt.Options = append(opt.Options, leaseOption)
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	msg.Extra = append(msg.Extra, opt)

	return msg, nil
}
