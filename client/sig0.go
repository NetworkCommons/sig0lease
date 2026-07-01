// File: client/sig0.go
// SIG(0) signing support for DNS requests
// Provenance: Inspired by sig0namectl's update.go SIG(0) signing mechanism

package client

import (
	"crypto"
	"fmt"

	"codeberg.org/miekg/dns"
	sharedsig0 "github.com/NetworkCommons/sig0lease/pkg/sig0"
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
	return sharedsig0.SignMessage(msg, s.PublicKey, s.PrivateKey)
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
