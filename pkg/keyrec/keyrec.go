// Package keyrec implements KEY record handling per RFC 2539 and RFC 4034.
package keyrec

import (
	"encoding/base64"
	"fmt"

	"codeberg.org/miekg/dns"
)

const (
	// KEY_SIZE is the size of a KEY record's fixed fields (before public key)
	KEY_SIZE = 4
)

// KeyRecord represents a DNSKEY or KEY record.
type KeyRecord struct {
	Flags      uint16
	Protocol   uint8
	Algorithm  uint8
	PublicKey  []byte
	keyTag     uint16 // cached key tag for performance
}

// Parse parses a KEY record from an RR.
func (k *KeyRecord) Parse(rr dns.RR) error {
	switch r := rr.(type) {
	case *dns.KEY:
		k, err := FromKEY(r)
		if err != nil {
			return err
		}
		*k = *k
		return nil
	default:
		return fmt.Errorf("unsupported record type: %T", rr)
	}
}

// FromKEY converts a dns.KEY record to KeyRecord.
func FromKEY(r *dns.KEY) (*KeyRecord, error) {
	if r == nil {
		return nil, fmt.Errorf("KEY record is nil")
	}

	// Parse the public key from base64-encoded string to raw bytes
	var publicKey []byte
	publicKeyStr := r.PublicKey
	if len(publicKeyStr) > 0 {
		var err error
		publicKey, err = base64.StdEncoding.DecodeString(publicKeyStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key from base64: %w", err)
		}
	}

	kr := &KeyRecord{
		Flags:     r.Flags,
		Protocol:  r.Protocol,
		Algorithm: r.Algorithm,
		PublicKey: publicKey,
	}

	// Calculate key tag
	kr.keyTag = calculateKeyTag(kr)

	return kr, nil
}

// ToKEY converts KeyRecord to dns.KEY record.
func (k *KeyRecord) ToKEY() (*dns.KEY, error) {
	if k == nil {
		return nil, fmt.Errorf("KeyRecord is nil")
	}

	// Convert public key bytes to base64-encoded string
	publicKeyStr := ""
	if len(k.PublicKey) > 0 {
		publicKeyStr = base64.StdEncoding.EncodeToString(k.PublicKey)
	}

	key := new(dns.KEY)

	// Set the header fields
	key.Hdr.Name = "."
	key.Hdr.Class = dns.ClassINET
	key.Hdr.TTL = 0

	// Set the KEY-specific fields
	key.Flags = k.Flags
	key.Protocol = k.Protocol
	key.Algorithm = k.Algorithm
	key.PublicKey = publicKeyStr

	return key, nil
}

// calculateKeyTag computes the Key Tag as per RFC 2535 Section 4.1.2.
func calculateKeyTag(k *KeyRecord) uint16 {
	if len(k.PublicKey) == 0 {
		return 0
	}

	digest := make([]byte, len(k.PublicKey)+4)
	copy(digest[0:], k.PublicKey)

	// If the public key has fewer than 256 bytes, prepend a zero byte
	if len(digest) < 272 {
		digest = append([]byte{0}, digest...)
	}

	// Calculate checksum
	var ac uint32
	for i := 0; i < len(digest); i += 2 {
		ac += uint32(digest[i]) << 8
		if i+1 < len(digest) {
			ac += uint32(digest[i+1])
		}
	}

	// Fold 32-bit sum to 16 bits
	for ac > 0xFFFF {
		ac = (ac >> 16) + (ac & 0xFFFF)
	}

	return uint16(ac)
}

// KeyTag returns the key tag.
func (k *KeyRecord) KeyTag() uint16 {
	if k.keyTag == 0 && len(k.PublicKey) > 0 {
		k.keyTag = calculateKeyTag(k)
	}
	return k.keyTag
}

// AlgorithmName returns a string representation of the algorithm.
func (k *KeyRecord) AlgorithmName() string {
	if name, ok := dns.AlgorithmToString[k.Algorithm]; ok {
		return name
	}
	return fmt.Sprintf("Algorithm%d", k.Algorithm)
}

// String returns a string representation of the KeyRecord.
func (k *KeyRecord) String() string {
	if k == nil {
		return "<nil>"
	}
	
	keyHex := ""
	if len(k.PublicKey) > 0 {
		if len(k.PublicKey) <= 16 {
			keyHex = fmt.Sprintf(" %x", k.PublicKey)
		} else {
			keyHex = fmt.Sprintf(" %x...%x", k.PublicKey[:8], k.PublicKey[len(k.PublicKey)-8:])
		}
	}
	
	return fmt.Sprintf("KeyRecord{Flags:0x%04x, Protocol:%d, Algorithm:%d (%s), KeyTag:%d%s}",
		k.Flags, k.Protocol, k.Algorithm, k.AlgorithmName(), k.KeyTag(), keyHex)
}

// KEY record constants from dns package
const (
	DSA     = uint8(3)
	ECDSA256 = uint8(13)
	ECDSA384 = uint8(14)
	ED25519  = uint8(15)
	RSASHA256 = uint8(10)
)
