// Package lease implements the Update Lease EDNS(0) option per RFC 9664.
package lease

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"codeberg.org/miekg/dns"
)

const (
	// OPTION_CODE is the EDNS(0) option code for Update Lease
	OPTION_CODE = 2

	// MIN_LEASE is the minimum valid lease value per RFC 9664 §8
	MIN_LEASE = 30

	// MAX_LEASE is the maximum lease value (2^32-1)
	MAX_LEASE = 0xFFFFFFFF

	// MIN_KEY_LEASE is the minimum valid key-lease value
	MIN_KEY_LEASE = 30

	// MAX_KEY_LEASE is the maximum key-lease value
	MAX_KEY_LEASE = 0xFFFFFFFF
)

// LeaseOption represents the Update Lease EDNS(0) option.
type LeaseOption struct {
	Lease    uint32 // The LEASE value in seconds
	KeyLease *uint32 // Optional KEY-LEASE value (nil for 4-byte variant)
}

// Encode4Byte creates a LeaseOption with only LEASE (4-byte variant).
func Encode4Byte(lease uint32) *LeaseOption {
	return &LeaseOption{Lease: lease, KeyLease: nil}
}

// Encode8Byte creates a LeaseOption with both LEASE and KEY-LEASE (8-byte variant).
func Encode8Byte(lease, keyLease uint32) *LeaseOption {
	return &LeaseOption{Lease: lease, KeyLease: &keyLease}
}

// Validate checks that the lease values are valid per RFC 9664/9665.
func (lo *LeaseOption) Validate() error {
	if lo.Lease < MIN_LEASE {
		return fmt.Errorf("LEASE %d is below minimum %d", lo.Lease, MIN_LEASE)
	}
	if lo.KeyLease != nil && *lo.KeyLease < MIN_KEY_LEASE {
		return fmt.Errorf("KEY-LEASE %d is below minimum %d", *lo.KeyLease, MIN_KEY_LEASE)
	}
	if lo.KeyLease != nil && lo.Lease > *lo.KeyLease {
		return fmt.Errorf("LEASE %d exceeds KEY-LEASE %d", lo.Lease, *lo.KeyLease)
	}
	return nil
}

// Encode encodes the LeaseOption into an OPT RR per RFC 6891.
func (lo *LeaseOption) Encode(opt *dns.OPT) error {
	if err := lo.Validate(); err != nil {
		return err
	}

	var data string

	if lo.KeyLease == nil {
		// 4-byte variant: only LEASE
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, lo.Lease)
		data = hex.EncodeToString(buf)
	} else {
		// 8-byte variant: LEASE + KEY-LEASE
		buf := make([]byte, 8)
		binary.BigEndian.PutUint32(buf[:4], lo.Lease)
		binary.BigEndian.PutUint32(buf[4:], *lo.KeyLease)
		data = hex.EncodeToString(buf)
	}

	opt.Options = append(opt.Options, &dns.ERFC3597{
		EDNS0Code: OPTION_CODE,
		Code:      data,
	})

	return nil
}

// Decode parses a LeaseOption from an OPT RR.
func (lo *LeaseOption) Decode(opt *dns.OPT) error {
	for _, option := range opt.Options {
		if erfc, ok := option.(*dns.ERFC3597); ok && erfc.EDNS0Code == OPTION_CODE {
			data, err := hex.DecodeString(erfc.Code)
			if err != nil {
				return fmt.Errorf("invalid hex data: %w", err)
			}

			switch len(data) {
			case 4:
				// 4-byte variant: LEASE only
				lo.Lease = binary.BigEndian.Uint32(data)
				lo.KeyLease = nil
			case 8:
				// 8-byte variant: LEASE + KEY-LEASE
				lo.Lease = binary.BigEndian.Uint32(data[:4])
				keyLease := binary.BigEndian.Uint32(data[4:])
				lo.KeyLease = &keyLease
			default:
				return fmt.Errorf("invalid option length %d for Update Lease", len(data))
			}

			if err := lo.Validate(); err != nil {
				return err
			}

			return nil
		}
	}

	return fmt.Errorf("Update Lease option not found in OPT record")
}
