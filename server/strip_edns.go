package server

import (
	"encoding/binary"
	"fmt"
)

// stripEDNSFromWire removes the OPT record from the Additional section of DNS wire data
// Returns the original data with OPT removed, and the OPT rdata
func stripEDNSFromWire(data []byte) ([]byte, []byte, error) {
	if len(data) < 12 {
		return data, nil, nil
	}

	// Parse header
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])
	nsCount := binary.BigEndian.Uint16(data[8:10])
	arCount := binary.BigEndian.Uint16(data[10:12])

	offset := 12

	// Skip questions
	for i := 0; i < int(qdCount); i++ {
		offset = skipDomainName(data, offset)
		if offset < 0 {
			return data, nil, fmt.Errorf("invalid question")
		}
		offset += 4 // type + class
	}

	// Skip answers
	for i := 0; i < int(anCount); i++ {
		offset = skipDomainName(data, offset)
		if offset < 0 {
			return data, nil, fmt.Errorf("invalid answer")
		}
		if offset+10 > len(data) {
			return data, nil, fmt.Errorf("answer too short")
		}
		rdLen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10 + int(rdLen)
	}

	// Skip authority
	for i := 0; i < int(nsCount); i++ {
		offset = skipDomainName(data, offset)
		if offset < 0 {
			return data, nil, fmt.Errorf("invalid authority")
		}
		if offset+10 > len(data) {
			return data, nil, fmt.Errorf("authority too short")
		}
		rdLen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10 + int(rdLen)
	}

	// Process additional section to find and remove OPT
	var optOffset, optLen int
	var foundOPT bool

	for i := 0; i < int(arCount); i++ {
		rrStart := offset
		offset = skipDomainName(data, offset)
		if offset < 0 {
			break
		}

		// Check type
		if offset+2 > len(data) {
			break
		}
		rtype := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		// Check class/udp size
		offset += 2
		// TTL
		offset += 4

		if offset+2 > len(data) {
			break
		}
		rdLen := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		if rtype == 41 { // OPT type
			optOffset = rrStart
			optLen = offset - rrStart + int(rdLen)
			foundOPT = true
			break
		}

		offset += int(rdLen)
	}

	if !foundOPT {
		return data, nil, nil // No OPT found
	}

	// Extract OPT rdata
	optEnd := optOffset + optLen
	optRdata := data[optOffset:optEnd]

	// Build new wire data without OPT
	newData := make([]byte, 0, len(data)-optLen)
	newData = append(newData, data[:optOffset]...)
	newData = append(newData, data[optEnd:]...)

	// Update arCount in header
	newArCount := arCount - 1
	newData[10] = byte(newArCount >> 8)
	newData[11] = byte(newArCount)

	return newData, optRdata, nil
}
