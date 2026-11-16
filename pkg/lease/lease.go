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

	// MAX_LEASE is the maximum lease value (2^32-1)
	MAX_LEASE = 0xFFFFFFFF

	// MAX_KEY_LEASE is the maximum key-lease value
	MAX_KEY_LEASE = 0xFFFFFFFF
)

// LeaseOption represents the Update Lease EDNS(0) option.
type LeaseOption struct {
	Lease    uint32  // The LEASE value in seconds
	KeyLease *uint32 // Optional KEY-LEASE value (nil for 4-byte variant)
}

// Encode4Byte creates a LeaseOption with only LEASE (4-byte variant): one duration for KEY and
// non-KEY records alike. Requests use the 8-byte variant; a server answers a 4-byte request
// with this one (RFC 9664 S4).
func Encode4Byte(lease uint32) *LeaseOption {
	return &LeaseOption{Lease: lease, KeyLease: nil}
}

// Encode8Byte creates a LeaseOption with both LEASE and KEY-LEASE (8-byte variant).
func Encode8Byte(lease, keyLease uint32) *LeaseOption {
	return &LeaseOption{Lease: lease, KeyLease: &keyLease}
}

// Validate checks that the lease values are valid.
func (lo *LeaseOption) Validate() error {
	if lo.KeyLease != nil && *lo.KeyLease != 0 && lo.Lease != 0 && lo.Lease > *lo.KeyLease {
		return fmt.Errorf("LEASE %d exceeds KEY-LEASE %d", lo.Lease, *lo.KeyLease)
	}
	return nil
}

// Encode encodes the LeaseOption into an OPT RR per RFC 6891, in its own variant: 8 bytes
// (LEASE + KEY-LEASE) when KeyLease is set, 4 bytes (LEASE) when it is nil.
func (lo *LeaseOption) Encode(opt *dns.OPT) error {
	if err := lo.Validate(); err != nil {
		return err
	}

	buf := binary.BigEndian.AppendUint32(nil, lo.Lease)
	if lo.KeyLease != nil {
		buf = binary.BigEndian.AppendUint32(buf, *lo.KeyLease)
	}
	data := hex.EncodeToString(buf)

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
			return lo.decodeERFC(erfc)
		}
	}

	return fmt.Errorf("Update Lease option not found in OPT record")
}

func (lo *LeaseOption) decodeERFC(erfc *dns.ERFC3597) error {
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

	return lo.Validate()
}

// FindOption scans msg's Pseudo and Extra sections for the raw UPDATE-LEASE
// EDNS(0) option (RFC 9664 Section 4, option code 2), accepting both a bare
// ERFC3597 RR and one nested inside an OPT RR's Options. This is the single
// place that knows where to look; server and client callers each layer their
// own validation/policy on top of the decoded result.
func FindOption(msg *dns.Msg) (*dns.ERFC3597, bool) {
	if msg == nil {
		return nil, false
	}

	scan := func(rrs []dns.RR) *dns.ERFC3597 {
		for _, rr := range rrs {
			if erfc, ok := rr.(*dns.ERFC3597); ok && erfc.EDNS0Code == OPTION_CODE {
				return erfc
			}
			if opt, ok := rr.(*dns.OPT); ok {
				for _, option := range opt.Options {
					if erfc, ok := option.(*dns.ERFC3597); ok && erfc.EDNS0Code == OPTION_CODE {
						return erfc
					}
				}
			}
		}
		return nil
	}

	if erfc := scan(msg.Pseudo); erfc != nil {
		return erfc, true
	}
	if erfc := scan(msg.Extra); erfc != nil {
		return erfc, true
	}
	return nil, false
}

// DecodeOption decodes a raw UPDATE-LEASE ERFC3597 option (as found by
// FindOption) into a LeaseOption.
func DecodeOption(erfc *dns.ERFC3597) (*LeaseOption, error) {
	lo := &LeaseOption{}
	if err := lo.decodeERFC(erfc); err != nil {
		return nil, err
	}
	return lo, nil
}

// FindAndDecode is the common case: locate the UPDATE-LEASE option in msg
// and decode it in one step.
func FindAndDecode(msg *dns.Msg) (*LeaseOption, error) {
	erfc, found := FindOption(msg)
	if !found {
		return nil, fmt.Errorf("Update Lease option not found in message")
	}
	return DecodeOption(erfc)
}
