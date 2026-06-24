package lease

import (
	"testing"

	"codeberg.org/miekg/dns"
)

func TestEncode4Byte(t *testing.T) {
	opt := Encode4Byte(7200)
	if opt.Lease != 7200 || opt.KeyLease != nil {
		t.Errorf("Expected Lease=7200, KeyLease=nil, got Lease=%d, KeyLease=%v", opt.Lease, opt.KeyLease)
	}
}

func TestEncode8Byte(t *testing.T) {
	opt := Encode8Byte(7200, 1209600)
	if opt.Lease != 7200 || opt.KeyLease == nil || *opt.KeyLease != 1209600 {
		t.Errorf("Expected Lease=7200, KeyLease=1209600, got Lease=%d, KeyLease=%v", opt.Lease, opt.KeyLease)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		opt     *LeaseOption
		wantErr bool
	}{
		{"Valid 4-byte", Encode4Byte(7200), false},
		{"Valid 8-byte", Encode8Byte(7200, 1209600), false},
		{"LEASE < MIN", Encode4Byte(29), true},
		{"KeyLease < MIN", func() *LeaseOption {
			opt := Encode8Byte(7200, 29)
			return opt
		}(), true},
		{"LEASE > KeyLease", func() *LeaseOption {
			opt := Encode8Byte(1209600, 7200)
			return opt
		}(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opt.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncodeDecode4Byte(t *testing.T) {
	opt1 := Encode4Byte(7200)

	// Simulate encoding to OPT record
	opt := &dns.OPT{}
	if err := opt1.Encode(opt); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	// Decode back
	var opt2 LeaseOption
	if err := opt2.Decode(opt); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if opt2.Lease != 7200 || opt2.KeyLease != nil {
		t.Errorf("Round-trip failed: got Lease=%d, KeyLease=%v", opt2.Lease, opt2.KeyLease)
	}
}

func TestEncodeDecode8Byte(t *testing.T) {
	opt1 := Encode8Byte(7200, 1209600)

	opt := &dns.OPT{}
	if err := opt1.Encode(opt); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	var opt2 LeaseOption
	if err := opt2.Decode(opt); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if opt2.Lease != 7200 || opt2.KeyLease == nil || *opt2.KeyLease != 1209600 {
		t.Errorf("Round-trip failed: got Lease=%d, KeyLease=%v", opt2.Lease, opt2.KeyLease)
	}
}
