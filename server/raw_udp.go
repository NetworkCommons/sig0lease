package server

import (
	"encoding/binary"
	"fmt"
	"net"

	"codeberg.org/miekg/dns"
)

// extractEDNSOptions extracts EDNS0 options from raw DNS wire data
// Also returns Pseudo section records (SIG records)
func extractEDNSAndPseudoFromWire(data []byte) (*dns.OPT, []dns.RR) {
	if len(data) < 12 {
		return nil, nil
	}

	// Skip the DNS header (first 12 bytes)
	offset := 12

	// Skip questions section
	qdCount := binary.BigEndian.Uint16(data[4:6])
	for i := 0; i < int(qdCount); i++ {
		offset = skipDomainName(data, offset)
		if offset < 0 || offset+4 > len(data) {
			return nil, nil
		}
		offset += 4 // Skip type and class
	}

	// Skip answer section
	anCount := binary.BigEndian.Uint16(data[6:8])
	for i := 0; i < int(anCount); i++ {
		offset = skipDomainName(data, offset)
		if offset < 0 || offset+10 > len(data) {
			return nil, nil
		}
		rdLen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10 + int(rdLen)
		if offset > len(data) {
			return nil, nil
		}
	}

	// Skip authority section
	nsCount := binary.BigEndian.Uint16(data[8:10])
	for i := 0; i < int(nsCount); i++ {
		offset = skipDomainName(data, offset)
		if offset < 0 || offset+10 > len(data) {
			return nil, nil
		}
		rdLen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10 + int(rdLen)
		if offset > len(data) {
			return nil, nil
		}
	}

	// Now look at additional section for OPT and other records
	arCount := binary.BigEndian.Uint16(data[10:12])
	var opt *dns.OPT
	var pseudo []dns.RR

	for i := 0; i < int(arCount); i++ {
		if offset >= len(data) {
			break
		}

		nameStart := offset
		offset = skipDomainName(data, offset)
		if offset < 0 || offset+10 > len(data) {
			break
		}

		rtype := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		// Check if it's an OPT record
		if rtype == dns.TypeOPT && nameStart < offset && data[nameStart] == 0 {
			// This is an OPT record (name must be root ".")
			udpSize := binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2
			_ = data[offset] // extRCode (unused)
			offset++
			_ = data[offset] // version (unused)
			offset++
			_ = binary.BigEndian.Uint16(data[offset : offset+2]) // flags (unused)
			offset += 2

			if offset+2 > len(data) {
				break
			}
			rdLen := binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2

			if offset+int(rdLen) > len(data) {
				break
			}

			// Parse EDNS options from RDATA
			opt = &dns.OPT{
				Hdr: dns.Header{
					Name:  ".",
					TTL:   binary.BigEndian.Uint32(data[offset-8 : offset-4]),
					Class: udpSize,
				},
			}

			// Parse options
			rDataEnd := offset + int(rdLen)
			for offset < rDataEnd && offset+4 <= len(data) {
				optCode := binary.BigEndian.Uint16(data[offset : offset+2])
				optLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
				offset += 4

				if offset+int(optLen) > len(data) {
					break
				}

				optData := data[offset : offset+int(optLen)]
				offset += int(optLen)

				// Add the option as ERFC3597 for unknown option codes
				opt.Options = append(opt.Options, &dns.ERFC3597{
					EDNS0Code: optCode,
					Code:      fmt.Sprintf("%x", optData), // hex encode the data
				})
			}
		} else {
			// Not an OPT record, skip it
			// The type and class are already read above
			_ = binary.BigEndian.Uint16(data[offset : offset+2]) // class (unused)
			offset += 2
			_ = binary.BigEndian.Uint32(data[offset : offset+4]) // ttl (unused)
			offset += 4
			rdLen := binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2

			// For SIG records, we can add them to pseudo
			if rtype == dns.TypeSIG {
				// Would need more sophisticated parsing to properly handle SIG
				pseudo = append(pseudo, nil) // Placeholder
			}

			offset += int(rdLen)
		}
	}

	return opt, pseudo
}

// extractEDNSOptions extracts EDNS0 options from raw DNS wire data
// Returns the OPT record if found, nil otherwise
func extractEDNSFromWire(data []byte) *dns.OPT {
	opt, _ := extractEDNSAndPseudoFromWire(data)
	return opt
}

// skipDomainName skips over a domain name in wire format
// Returns the offset after the domain name, or -1 if invalid
func skipDomainName(data []byte, offset int) int {
	for offset < len(data) {
		label := data[offset]
		offset++

		if label == 0 {
			// Root label, end of domain name
			return offset
		}

		if (label & 0xc0) == 0xc0 {
			// Pointer, skip next byte
			offset++
			return offset
		}

		// Regular label
		if offset+int(label) > len(data) {
			return -1
		}
		offset += int(label)
	}

	return -1
}

// RawUDPConn wraps a UDP connection and extracts EDNS options from raw data
type RawUDPConn struct {
	conn *net.UDPConn
}

// NewRawUDPConn creates a new raw UDP connection wrapper
func NewRawUDPConn(conn *net.UDPConn) *RawUDPConn {
	return &RawUDPConn{conn: conn}
}

// ReadWithEDNS reads a DNS message and preserves EDNS options
func (rc *RawUDPConn) ReadWithEDNS() (*dns.Msg, *net.UDPAddr, *dns.OPT, error) {
	// Read raw data
	buf := make([]byte, 4096)
	n, remoteAddr, err := rc.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, nil, err
	}

	rawData := buf[:n]

	// Extract EDNS options from raw data
	extractedOPT := extractEDNSFromWire(rawData)

	// Unpack the message normally (this might lose EDNS options)
	msg := new(dns.Msg)
	msg.Data = make([]byte, n)
	copy(msg.Data, rawData)
	if err := msg.Unpack(); err != nil {
		return nil, remoteAddr, nil, err
	}

	return msg, remoteAddr, extractedOPT, nil
}
