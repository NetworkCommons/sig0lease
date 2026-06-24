package keyrec

import (
	"testing"

	"codeberg.org/miekg/dns"
)

func TestFromKEY(t *testing.T) {
	key := new(dns.KEY)
	key.Hdr.Name = "example.com."
	key.Flags = 0x80
	key.Protocol = 3
	key.Algorithm = ED25519
	key.PublicKey = string(make([]byte, 32))

	k, err := FromKEY(key)
	if err != nil {
		t.Fatalf("FromKEY() error = %v", err)
	}

	if k.Flags != 0x80 || k.Protocol != 3 || k.Algorithm != ED25519 {
		t.Errorf("Expected Flags=0x80, Protocol=3, Algorithm=%d, got Flags=%d, Protocol=%d, Algorithm=%d",
			ED25519, k.Flags, k.Protocol, k.Algorithm)
	}
}

func TestKeyTag(t *testing.T) {
	// Use a simple public key for testing
	publicKey := make([]byte, 32)
	for i := range publicKey {
		publicKey[i] = byte(i % 256)
	}

	k := &KeyRecord{
		Flags:     0x80,
		Protocol:  3,
		Algorithm: ED25519,
		PublicKey: publicKey,
	}

	tag1 := k.KeyTag()
	tag2 := k.KeyTag() // Should be cached
	
	if tag1 != tag2 {
		t.Errorf("KeyTag not consistent: %d vs %d", tag1, tag2)
	}
	
	if tag1 == 0 {
		t.Error("KeyTag should not be zero")
	}
}

func TestString(t *testing.T) {
	k := &KeyRecord{
		Flags:     0x80,
		Protocol:  3,
		Algorithm: ED25519,
		PublicKey: make([]byte, 32),
	}
	
	s := k.String()
	if s == "" || !contains(s, "Flags") {
		t.Errorf("String() should contain 'Flags', got: %s", s)
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
