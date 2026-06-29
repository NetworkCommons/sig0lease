// Package instruction implements SRP Instruction Records as per RFC 9665 Section 6.1.
//
// SRP Instructions are carried in the Additional section of DNS UPDATE messages
// using EDNS(0) option code 11 (INSTRUCTION).
package instruction

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"codeberg.org/miekg/dns"
)

const (
	// OPTION_CODE is the EDNS0 option code for SRP Instructions (RFC 9665 Section 7)
	OPTION_CODE = 11

	// Service and Priority constants
	DEFAULT_PRIORITY uint16 = 0
	DEFAULT_WEIGHT   uint16 = 0
	MIN_PORT         uint16 = 1
	MAX_PORT         uint16 = 65535

	// Flags
	SERVICE_DELETE_FLAG uint8 = 0x80 // Delete all services for this name
)

// Instruction represents an SRP Instruction Record.
//
// Per RFC 9665 Section 6.1, an Instruction contains:
//   - Name: The domain name being registered
//   - Service: Optional service description (priority, weight, port, host)
//   - TXT: Optional TXT records
//   - DNSKEY: Optional DNSKEY for authentication
type Instruction struct {
	Name    string      // Domain name being registered
	Service *Service    // Service pointer (optional)
	TXT     []string    // TXT records
	DNSKEY  *dns.DNSKEY // DNSKEY record (optional)
}

// Service represents the SRP Service data.
//
// Per RFC 9665 Section 6.1, the service structure contains:
//   - Priority: Priority for this target (0-65535, lower is preferred)
//   - Weight: Weight for this target (0-65535, higher is preferred)
//   - Port: Port number for the service
//   - Host: Target host providing this service
type Service struct {
	Priority uint16 // Priority (0-65535)
	Weight   uint16 // Weight (0-65535)
	Port     uint16 // Port number
	Host     string // Target host
}

// New creates a new Instruction.
func New(name string) *Instruction {
	return &Instruction{
		Name: name,
	}
}

// SetService sets the service record.
func (i *Instruction) SetService(priority, weight, port uint16, host string) {
	i.Service = &Service{
		Priority: priority,
		Weight:   weight,
		Port:     port,
		Host:     host,
	}
}

// SetTXT sets the TXT records.
func (i *Instruction) SetTXT(txt []string) {
	i.TXT = txt
}

// SetDNSKEY sets the DNSKEY record.
func (i *Instruction) SetDNSKEY(key *dns.DNSKEY) {
	i.DNSKEY = key
}

// IsServiceDelete returns true if this is a service delete instruction.
func (i *Instruction) IsServiceDelete() bool {
	return i.Service == nil
}

// ServiceDelete creates a service delete instruction (no service data).
func ServiceDelete(name string) *Instruction {
	return &Instruction{
		Name:    name,
		Service: nil,
	}
}

// NewService creates a new Service record.
func NewService(priority, weight, port uint16, host string) *Service {
	return &Service{
		Priority: priority,
		Weight:   weight,
		Port:     port,
		Host:     host,
	}
}

// Validate checks that the instruction values are valid.
func (i *Instruction) Validate() error {
	if i.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	if i.Service != nil {
		if err := i.Service.Validate(); err != nil {
			return fmt.Errorf("service: %w", err)
		}
	}

	if i.DNSKEY != nil {
		if err := validateDNSKEY(i.DNSKEY); err != nil {
			return fmt.Errorf("dnskey: %w", err)
		}
	}

	return nil
}

// Validate checks that the service values are valid.
func (s *Service) Validate() error {
	if s == nil {
		return nil
	}

	// Priority and Weight are 16-bit unsigned, so they're always valid
	if s.Port < MIN_PORT || s.Port > MAX_PORT {
		return fmt.Errorf("port %d is out of range [%d-%d]", s.Port, MIN_PORT, MAX_PORT)
	}

	if s.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	return nil
}

func validateDNSKEY(key *dns.DNSKEY) error {
	if key == nil {
		return fmt.Errorf("DNSKEY is nil")
	}

	// Validate algorithm
	switch key.Algorithm {
	case 0: // Reserved
		return fmt.Errorf("algorithm 0 is reserved")
	case 3, 5, 7, 8, 10: // RSA
	case 13, 14, 15: // ECDSA, Ed25519
	default:
		return fmt.Errorf("unsupported algorithm %d", key.Algorithm)
	}

	// Validate public key length based on algorithm
	if len(key.PublicKey) == 0 {
		return fmt.Errorf("public key cannot be empty")
	}

	return nil
}

// Encode encodes the Instruction into EDNS0 option data per RFC 9665.
func (i *Instruction) Encode() ([]byte, error) {
	if err := i.Validate(); err != nil {
		return nil, err
	}

	var data []byte

	// Encode name (as a null-terminated string)
	nameBytes := []byte(i.Name)
	data = append(data, byte(len(nameBytes)))
	data = append(data, nameBytes...)
	data = append(data, 0) // Null terminator

	// Encode flags and service length (4 bytes)
	flags := byte(0)
	if i.Service == nil {
		flags |= SERVICE_DELETE_FLAG
	}

	serviceLen := uint32(0)
	if i.Service != nil {
		hostLen := uint32(len(i.Service.Host))
		serviceLen = 7 + hostLen // Priority(2) + Weight(2) + Port(2) + HostLenByte(1) + Host(hostLen)
	}

	data = append(data, flags)
	data = append(data, 0) // Reserved byte
	data = append(data, byte(serviceLen>>8), byte(serviceLen))

	// Encode service if present
	if i.Service != nil {
		data = append(data, byte(i.Service.Priority>>8), byte(i.Service.Priority))
		data = append(data, byte(i.Service.Weight>>8), byte(i.Service.Weight))
		data = append(data, byte(i.Service.Port>>8), byte(i.Service.Port))

		hostLen := len(i.Service.Host)
		data = append(data, byte(hostLen))
		data = append(data, []byte(i.Service.Host)...)
	}

	// Encode TXT records with length prefix
	txtData := encodeTXT(i.TXT)
	data = append(data, byte(len(txtData)>>8), byte(len(txtData)))
	data = append(data, txtData...)

	// Encode DNSKEY if present
	if i.DNSKEY != nil {
		keyData, err := encodeDNSKEY(i.DNSKEY)
		if err != nil {
			return nil, fmt.Errorf("encode DNSKEY: %w", err)
		}
		data = append(data, keyData...)
	}

	return data, nil
}

// Decode parses an Instruction from EDNS0 option data.
func (i *Instruction) Decode(data []byte) error {
	if len(data) < 5 {
		return fmt.Errorf("instruction data too short: %d bytes", len(data))
	}

	// Decode name (length-prefixed)
	nameLen := int(data[0])
	offset := 1
	if offset+nameLen > len(data) {
		return fmt.Errorf("data too short for name")
	}
	i.Name = string(data[offset : offset+nameLen])
	offset += nameLen + 1 // Skip null terminator

	if offset+4 > len(data) {
		return fmt.Errorf("data too short for flags and length")
	}

	// Decode flags
	flags := data[offset]
	offset++

	// Skip reserved byte
	if offset+1 > len(data) {
		return fmt.Errorf("data too short for reserved byte")
	}
	offset++

	// Decode service length
	if offset+2 > len(data) {
		return fmt.Errorf("data too short for service length")
	}
	serviceLen := uint32(data[offset])<<8 | uint32(data[offset+1])
	offset += 2

	// Decode service if present (not delete)
	if flags&SERVICE_DELETE_FLAG == 0 && serviceLen > 0 {
		if offset+int(serviceLen) > len(data) {
			return fmt.Errorf("data too short for service data")
		}

		serviceData := data[offset : offset+int(serviceLen)]

		if len(serviceData) < 7 { // Min: Priority + Weight + Port (6 bytes) + HostLen (1 byte)
			return fmt.Errorf("service data too short")
		}

		i.Service = &Service{
			Priority: binary.BigEndian.Uint16(serviceData[0:2]),
			Weight:   binary.BigEndian.Uint16(serviceData[2:4]),
			Port:     binary.BigEndian.Uint16(serviceData[4:6]),
		}

		hostLen := int(serviceData[6])
		if len(serviceData) < 7+hostLen {
			return fmt.Errorf("service data too short for host")
		}
		i.Service.Host = string(serviceData[7 : 7+hostLen])

		offset += int(serviceLen)
	} else {
		i.Service = nil
	}

	// Decode TXT records (remaining data after service)
	if offset < len(data) {
		txt, txtBytes := decodeTXT(data[offset:])
		i.TXT = txt
		offset += txtBytes
	}

	// Decode DNSKEY if present (would be after TXT in practice)
	if offset < len(data) {
		key, err := decodeDNSKEY(data[offset:])
		if err != nil {
			return fmt.Errorf("decode DNSKEY: %w", err)
		}
		i.DNSKEY = key
	}

	return nil
}

// encodeTXT encodes TXT records according to RFC 1035.
// The format is: [TXT Length (2 bytes)] [TXT Data...]
func encodeTXT(txt []string) []byte {
	var data []byte
	// Precompute the length for the header
	for _, s := range txt {
		if len(s) > 255 {
			s = s[:255] // Truncate if too long
		}
		data = append(data, byte(len(s)))
		data = append(data, []byte(s)...)
	}
	return data
}

// decodeTXT decodes TXT records from binary data.
// The format is: [TXT Length (2 bytes)] [TXT Data...]
// Returns the decoded TXT records and the number of bytes consumed.
func decodeTXT(data []byte) ([]string, int) {
	if len(data) < 2 {
		return nil, 0
	}

	txtLen := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2

	// If no TXT data, return early
	if txtLen == 0 {
		return nil, 2
	}

	if offset+txtLen > len(data) {
		return nil, 0 // Not enough data
	}

	var txt []string
	for remaining := txtLen; remaining > 0 && offset < len(data); {
		if offset+1 > len(data) {
			break
		}
		length := int(data[offset])
		offset++
		remaining--

		if length > remaining {
			break // Invalid TXT record length
		}

		if offset+length > len(data) {
			break // Not enough data for this TXT record
		}

		txt = append(txt, string(data[offset:offset+length]))
		offset += length
		remaining -= length
	}
	return txt, offset
}

// encodeDNSKEY encodes a DNSKEY record into binary format.
func encodeDNSKEY(key *dns.DNSKEY) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("DNSKEY is nil")
	}

	var data []byte

	// Encode flags (2 bytes)
	data = append(data, byte(key.Flags>>8), byte(key.Flags))

	// Encode protocol (1 byte)
	data = append(data, key.Protocol)

	// Encode algorithm (1 byte)
	data = append(data, key.Algorithm)

	// Encode public key with base64 length prefix (as per DNSKEY wire format)
	publicKeyBytes := []byte(key.PublicKey)
	encoded := base64.StdEncoding.EncodeToString(publicKeyBytes)
	data = append(data, byte(len(encoded)>>8), byte(len(encoded)))
	data = append(data, []byte(encoded)...)

	return data, nil
}

// decodeDNSKEY decodes a DNSKEY record from binary data.
func decodeDNSKEY(data []byte) (*dns.DNSKEY, error) {
	if len(data) < 5 { // Min: Flags(2) + Protocol(1) + Algorithm(1) + PubKeyLen(2)
		return nil, fmt.Errorf("DNSKEY data too short")
	}

	key := new(dns.DNSKEY)
	key.Flags = binary.BigEndian.Uint16(data[0:2])
	key.Protocol = data[2]
	key.Algorithm = data[3]

	pubKeyLen := int(binary.BigEndian.Uint16(data[4:6]))
	if len(data) < 6+pubKeyLen {
		return nil, fmt.Errorf("DNSKEY data too short for public key")
	}

	// Decode base64 to get raw bytes
	decoded, err := base64.StdEncoding.DecodeString(string(data[6 : 6+pubKeyLen]))
	if err != nil {
		return nil, fmt.Errorf("DNSKEY base64 decode: %w", err)
	}
	key.PublicKey = string(decoded)

	return key, nil
}

// ToRR converts the Instruction to a DNS RR for inclusion in UPDATE messages.
func (i *Instruction) ToRR() dns.RR {
	// Encode the instruction data
	data, err := i.Encode()
	if err != nil {
		return nil
	}

	// Use ERFC3597 (unknown EDNS option) with hex-encoded data
	hexData := hex.EncodeToString(data)
	return &dns.ERFC3597{
		EDNS0Code: OPTION_CODE,
		Code:      hexData,
	}
}

// ParseRR parses an Instruction from a DNS RR.
func (i *Instruction) ParseRR(rr dns.RR) error {
	switch rr := rr.(type) {
	case *dns.ERFC3597:
		if rr.EDNS0Code != OPTION_CODE {
			return fmt.Errorf("not an SRP instruction record (expected code %d, got %d)", OPTION_CODE, rr.EDNS0Code)
		}

		data, err := hex.DecodeString(rr.Code)
		if err != nil {
			return fmt.Errorf("failed to decode hex data: %w", err)
		}
		return i.Decode(data)
	default:
		return fmt.Errorf("unsupported RR type: %T", rr)
	}
}
