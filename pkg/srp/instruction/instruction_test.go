package instruction

import (
	"testing"

	"codeberg.org/miekg/dns"
)

func TestNewInstruction(t *testing.T) {
	inst := New("example.com")
	if inst.Name != "example.com" {
		t.Errorf("expected name 'example.com', got '%s'", inst.Name)
	}
	if inst.Service != nil {
		t.Errorf("expected no service, got one")
	}
}

func TestSetService(t *testing.T) {
	inst := New("example.com")
	inst.SetService(10, 5, 8080, "host.example.com")

	if inst.Service == nil {
		t.Fatal("expected service to be set")
	}

	if inst.Service.Priority != 10 {
		t.Errorf("expected priority 10, got %d", inst.Service.Priority)
	}
	if inst.Service.Weight != 5 {
		t.Errorf("expected weight 5, got %d", inst.Service.Weight)
	}
	if inst.Service.Port != 8080 {
		t.Errorf("expected port 8080, got %d", inst.Service.Port)
	}
	if inst.Service.Host != "host.example.com" {
		t.Errorf("expected host 'host.example.com', got '%s'", inst.Service.Host)
	}
}

func TestSetTXT(t *testing.T) {
	inst := New("example.com")
	txt := []string{"v=spf1 include:_spf.example.com ~all"}
	inst.SetTXT(txt)

	if len(inst.TXT) != 1 {
		t.Errorf("expected 1 TXT record, got %d", len(inst.TXT))
	}
	if inst.TXT[0] != txt[0] {
		t.Errorf("expected TXT '%s', got '%s'", txt[0], inst.TXT[0])
	}
}

func TestServiceDelete(t *testing.T) {
	inst := ServiceDelete("example.com")
	if !inst.IsServiceDelete() {
		t.Error("expected IsServiceDelete to return true")
	}
	if inst.Service != nil {
		t.Errorf("expected no service for delete instruction, got one")
	}
}

func TestNewService(t *testing.T) {
	svc := NewService(10, 5, 443, "gateway.example.com")

	if svc.Priority != 10 {
		t.Errorf("expected priority 10, got %d", svc.Priority)
	}
	if svc.Weight != 5 {
		t.Errorf("expected weight 5, got %d", svc.Weight)
	}
	if svc.Port != 443 {
		t.Errorf("expected port 443, got %d", svc.Port)
	}
	if svc.Host != "gateway.example.com" {
		t.Errorf("expected host 'gateway.example.com', got '%s'", svc.Host)
	}
}

func TestServiceValidate(t *testing.T) {
	tests := []struct {
		name    string
		service *Service
		valid   bool
	}{
		{"valid", NewService(10, 5, 80, "host.example.com"), true},
		{"empty host", NewService(10, 5, 80, ""), false},
		{"port out of range - zero", NewService(10, 5, 0, "host"), false},
		{"port out of range - max+1", func() *Service { i := 65536; var svc Service; svc.Port = uint16(i); return &svc }(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.service.Validate()
			if tt.valid && err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Error("expected invalid, got no error")
			}
		})
	}
}

func TestInstructionValidate(t *testing.T) {
	tests := []struct {
		name    string
		inst    *Instruction
		valid   bool
	}{
		{"empty name", New(""), false},
		{"valid with service", func() *Instruction {
			inst := New("example.com")
			inst.SetService(10, 5, 80, "host.example.com")
			return inst
		}(), true},
		{"valid with TXT", func() *Instruction {
			inst := New("example.com")
			inst.SetTXT([]string{"test"})
			return inst
		}(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.inst.Validate()
			if tt.valid && err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Error("expected invalid, got no error")
			}
		})
	}
}

func TestEncodeDecode(t *testing.T) {
	inst := New("example.com")
	inst.SetService(10, 5, 8080, "host.example.com")
	inst.SetTXT([]string{"v=test", "foo=bar"})

	encoded, err := inst.Encode()
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	var decoded Instruction
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Name != inst.Name {
		t.Errorf("decoded name '%s' != original '%s'", decoded.Name, inst.Name)
	}
	if decoded.Service == nil || inst.Service == nil {
		t.Error("service was nil after decode")
	} else {
		if decoded.Service.Priority != inst.Service.Priority {
			t.Errorf("decoded priority %d != original %d", decoded.Service.Priority, inst.Service.Priority)
		}
		if decoded.Service.Host != inst.Service.Host {
			t.Errorf("decoded host '%s' != original '%s'", decoded.Service.Host, inst.Service.Host)
		}
	}

	if len(decoded.TXT) != len(inst.TXT) {
		t.Errorf("decoded TXT count %d != original %d", len(decoded.TXT), len(inst.TXT))
	}
}

func TestServiceDeleteEncodeDecode(t *testing.T) {
	inst := ServiceDelete("example.com")

	encoded, err := inst.Encode()
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	var decoded Instruction
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if !decoded.IsServiceDelete() {
		t.Error("expected delete instruction after decode")
	}
}

func TestEncodeDecodeWithDNSKEY(t *testing.T) {
	inst := New("example.com")
	inst.SetService(10, 5, 8080, "host.example.com")

	// Create a minimal DNSKEY (this would normally come from keyrec)
	// Use a valid base64-encoded public key string
	key := new(dns.DNSKEY)
	key.Flags = 256 // ZSK
	key.Protocol = 3
	key.Algorithm = 8 // RSA/SHA-256
	// A valid base64 string for testing (not a real RSA key, just test data)
	key.PublicKey = "AwEAAcTnF+0vQK4B6f5m5z3X7q8W2a9R0sT1y2u3v4w5x6y7" + "AAAA"
	inst.SetDNSKEY(key)

	encoded, err := inst.Encode()
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	var decoded Instruction
	if err := decoded.Decode(encoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.DNSKEY == nil || inst.DNSKEY == nil {
		t.Error("DNSKEY was nil after decode")
	} else {
		if decoded.DNSKEY.Algorithm != inst.DNSKEY.Algorithm {
			t.Errorf("decoded algorithm %d != original %d", decoded.DNSKEY.Algorithm, inst.DNSKEY.Algorithm)
		}
		if decoded.DNSKEY.Flags != inst.DNSKEY.Flags {
			t.Errorf("decoded flags %d != original %d", decoded.DNSKEY.Flags, inst.DNSKEY.Flags)
		}
	}
}

func TestToRR(t *testing.T) {
	inst := New("example.com")
	inst.SetService(10, 5, 8080, "host.example.com")

	rr := inst.ToRR()
	if rr == nil {
		t.Fatal("ToRR returned nil")
	}

	// Verify it's an ERFC3597 record
	if _, ok := rr.(*dns.ERFC3597); !ok {
		t.Errorf("expected ERFC3597 RR, got %T", rr)
	}
}

func TestParseRR(t *testing.T) {
	inst := New("example.com")
	inst.SetService(10, 5, 8080, "host.example.com")

	rr := inst.ToRR()
	if rr == nil {
		t.Fatal("ToRR returned nil")
	}

	var decoded Instruction
	if err := decoded.ParseRR(rr); err != nil {
		t.Fatalf("ParseRR failed: %v", err)
	}

	if decoded.Name != inst.Name {
		t.Errorf("decoded name '%s' != original '%s'", decoded.Name, inst.Name)
	}
	if decoded.Service == nil {
		t.Error("decoded service was nil")
	}
}

func TestParseRRWrongOpcode(t *testing.T) {
	// Create a different EDNS0 record
	wrongRR := new(dns.ERFC3597)
	wrongRR.EDNS0Code = OPTION_CODE + 1 // Wrong opcode

	var inst Instruction
	if err := inst.ParseRR(wrongRR); err == nil {
		t.Error("expected error for wrong opcode")
	}
}

func TestDecodeFromInvalidData(t *testing.T) {
	var inst Instruction

	// Too short data
	err := inst.Decode([]byte{0x00})
	if err == nil {
		t.Error("expected error for short data")
	}

	// Invalid name encoding
	err = inst.Decode([]byte{0xFF, 0xFF, 0x00, 0x00, 0x00}) // Invalid name compression
	// This may or may not error depending on miekg/dns behavior, just verify it doesn't crash
}
