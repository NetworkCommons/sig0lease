package dnsname

import (
	"bytes"
	"errors"
	"fmt"
)

// rdataNameOffset maps the RR types whose RDATA carries a domain name at a fixed offset to that
// offset. Only names the library decodes as ordinary names are listed: the mailbox names of
// SOA (RNAME), RP, MINFO, MB, MG and MR are left out, since a dot in their first label is
// ordinary ("john.doe" in john\.doe.example.com.) and the library does escape it there.
var rdataNameOffset = map[uint16]int{
	2:  0,  // NS
	5:  0,  // CNAME
	6:  0,  // SOA: MNAME
	12: 0,  // PTR
	39: 0,  // DNAME
	15: 2,  // MX
	18: 2,  // AFSDB
	21: 2,  // RT
	36: 2,  // KX
	64: 2,  // SVCB: target
	65: 2,  // HTTPS: target
	33: 6,  // SRV: target
	24: 18, // SIG: signer name
	46: 18, // RRSIG: signer name
}

// maxPointerHops bounds how many compression pointers one name may follow, so a pointer loop
// ends in an error rather than a hang. A 255-octet name has at most 127 labels, so no
// well-formed name needs more.
const maxPointerHops = 127

var errTruncated = errors.New("dns message truncated")

// DottedWireLabel returns the first label in msg, a wire-format DNS message, that contains a
// "." octet. The library cannot carry such a label (see labels.go): it decodes it as two or
// more labels, and encoding the result again sends a different name. It checks the question
// names, every RR owner name, and the name in the RDATA of the types rdataNameOffset lists --
// every name a handler here reads and re-sends. found is false if there is no such label; err
// is non-nil only if msg is too malformed to walk.
func DottedWireLabel(msg []byte) (label string, found bool, err error) {
	if len(msg) < 12 {
		return "", false, errTruncated
	}
	qdcount := u16(msg, 4)
	rrcount := u16(msg, 6) + u16(msg, 8) + u16(msg, 10) // answer/prerequisite, authority/update, additional

	off := 12
	for range qdcount {
		if label, found, off, err = dottedName(msg, off); err != nil || found {
			return label, found, err
		}
		if off += 4; off > len(msg) { // QTYPE, QCLASS
			return "", false, errTruncated
		}
	}
	for range rrcount {
		if label, found, off, err = dottedName(msg, off); err != nil || found {
			return label, found, err
		}
		if off+10 > len(msg) {
			return "", false, errTruncated
		}
		rrtype := uint16(u16(msg, off))
		rdlength := u16(msg, off+8)
		off += 10 // TYPE, CLASS, TTL, RDLENGTH
		if off+rdlength > len(msg) {
			return "", false, errTruncated
		}
		// An empty RDATA (an RFC 2136 delete) has no name to check.
		if n, ok := rdataNameOffset[rrtype]; ok && n < rdlength {
			if label, found, _, err = dottedName(msg, off+n); err != nil || found {
				return label, found, err
			}
		}
		off += rdlength
	}
	return "", false, nil
}

// u16 reads the big-endian 16-bit field at msg[off:]; the caller has checked the bounds.
func u16(msg []byte, off int) int {
	return int(msg[off])<<8 | int(msg[off+1])
}

// dottedName walks the name at msg[off:], following compression pointers, and returns its first
// label containing "." (found true), or else the offset just past the name where it sits in
// msg.
func dottedName(msg []byte, off int) (label string, found bool, next int, err error) {
	next = -1
	for hops := 0; ; {
		if off >= len(msg) {
			return "", false, 0, errTruncated
		}
		c := int(msg[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 { // the root label ends the name
				if next < 0 {
					next = off + 1
				}
				return "", false, next, nil
			}
			if off+1+c > len(msg) {
				return "", false, 0, errTruncated
			}
			if l := msg[off+1 : off+1+c]; bytes.IndexByte(l, '.') >= 0 {
				return string(l), true, 0, nil
			}
			off += 1 + c
		case 0xC0:
			if off+1 >= len(msg) {
				return "", false, 0, errTruncated
			}
			ptr := (c&0x3F)<<8 | int(msg[off+1])
			if ptr >= off {
				return "", false, 0, fmt.Errorf("dns message has a compression pointer at offset %d that does not point backwards", off)
			}
			if hops++; hops > maxPointerHops {
				return "", false, 0, fmt.Errorf("dns message has a name with more than %d compression pointers", maxPointerHops)
			}
			if next < 0 {
				next = off + 2
			}
			off = ptr
		default:
			return "", false, 0, fmt.Errorf("dns message has a reserved label type 0x%02x at offset %d", c&0xC0, off)
		}
	}
}
