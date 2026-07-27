// File: client/sig0.go
// SIG(0) signing support for DNS requests
// Provenance: Inspired by sig0namectl's update.go SIG(0) signing mechanism

package client

import (
	"crypto"
	"fmt"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
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

// MakeRegistrationRequest creates a registration request with 8-byte lease EDNS option.
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

	return dnsmsg.NewRegistrationUpdate(downstreamZone, keyRR, nil, leaseDuration, leaseDuration)
}

// MakeRefreshRequest creates a refresh request to extend an existing lease.
// A full KEY RR must be provided; header-only or omitted KEY RRs are rejected.
func MakeRefreshRequest(downstreamZone string, keyRR *dns.KEY, leaseDuration, keyLeaseDuration uint32) (*dns.Msg, error) {
	if downstreamZone == "" {
		return nil, fmt.Errorf("downstream zone cannot be empty")
	}
	if keyRR == nil {
		return nil, fmt.Errorf("KEY RR cannot be nil")
	}
	if keyRR.Algorithm == 0 || keyRR.Protocol == 0 || keyRR.PublicKey == "" {
		return nil, fmt.Errorf("incomplete KEY RR: full RDATA is required")
	}
	if leaseDuration < 30 {
		return nil, fmt.Errorf("lease duration must be at least 30 seconds")
	}
	return dnsmsg.NewRefreshUpdate(downstreamZone, keyRR, leaseDuration, keyLeaseDuration, false)
}
