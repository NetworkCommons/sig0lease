package keyrec

import (
	"encoding/base64"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestFromKEY(t *testing.T) {
	// Create a 32-byte public key and encode as base64
	publicKeyBytes := make([]byte, 32)
	for i := range publicKeyBytes {
		publicKeyBytes[i] = byte(i % 256)
	}

	key := new(dns.KEY)
	key.Hdr.Name = "example.com."
	key.Flags = 0x80
	key.Protocol = 3
	key.Algorithm = ED25519
	// PublicKey must be base64-encoded string when setting dns.KEY
	key.PublicKey = base64.StdEncoding.EncodeToString(publicKeyBytes)

	k, err := FromKEY(key)
	if err != nil {
		t.Fatalf("FromKEY() error = %v", err)
	}

	if k.Flags != 0x80 || k.Protocol != 3 || k.Algorithm != ED25519 {
		t.Errorf("Expected Flags=0x80, Protocol=3, Algorithm=%d, got Flags=%d, Protocol=%d, Algorithm=%d",
			ED25519, k.Flags, k.Protocol, k.Algorithm)
	}

	// Verify the public key was decoded correctly
	for i := range k.PublicKey {
		if k.PublicKey[i] != publicKeyBytes[i] {
			t.Errorf("Public key byte %d: expected %d, got %d", i, publicKeyBytes[i], k.PublicKey[i])
		}
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
