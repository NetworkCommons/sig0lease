package sig0

import (
	"os"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// getKeystoreDir retrieves the keystore directory from environment or config.
// Returns error if not defined - keystore path must be explicitly configured.
func getKeystoreDir(t *testing.T) string {
	// Priority 1: Environment variable
	if dir := os.Getenv("KEYSTORE_DIR"); dir != "" {
		return dir
	}

	// Priority 2: Config file
	if cfg, err := config.LoadConfig("config.yaml"); err == nil {
		if dir := cfg.GetKeystoreDir(); dir != "" {
			return dir
		}
	}

	// No fallback - keystore path must be configured
	t.Fatalf("KEYSTORE_DIR environment variable or config.yaml keystore_dir must be defined")
	return ""
}

func TestSignerWithRealKey(t *testing.T) {
	// Use test keys from sig0namectl keystore
	keystoreDir := getKeystoreDir(t)

	// Find the key for test.dev.zenr.io
	keyName, err := keyrec.FindKeyByZone(keystoreDir, "test.dev.zenr.io")
	if err != nil {
		t.Skipf("Could not find test key: %v", err)
	}

	// Load a test key
	loadedKey, err := keyrec.LoadKeyFromFiles(keystoreDir, keyName)
	if err != nil {
		t.Skipf("Could not load test key: %v", err)
	}

	// Create a signer
	signer, err := NewSigner(loadedKey.PublicKey, loadedKey.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Start building an UPDATE message
	zone := "test.dev.zenr.io."
	err = signer.StartUpdate(zone)
	if err != nil {
		t.Fatalf("Failed to start UPDATE: %v", err)
	}

	// Add a simple A record update (for testing)
	testRRString := "test.dev.zenr.io. 300 IN A 192.0.2.1"
	err = signer.UpdateParsedRR(testRRString)
	if err != nil {
		t.Fatalf("Failed to add RR: %v", err)
	}

	// Sign the UPDATE message
	signedMsg, err := signer.SignUpdate()
	if err != nil {
		t.Fatalf("Failed to sign UPDATE: %v", err)
	}

	// Verify the signed message has SIG record in Pseudo section
	if len(signedMsg.Pseudo) == 0 {
		t.Fatal("Expected SIG record in Pseudo section")
	}

	// Find the SIG record
	var sigRR *dns.SIG
	for _, rr := range signedMsg.Pseudo {
		if sig, ok := rr.(*dns.SIG); ok {
			sigRR = sig
			break
		}
	}

	if sigRR == nil {
		t.Fatal("No SIG record found in Extra section")
	}

	// Verify SIG record fields
	if sigRR.Algorithm != loadedKey.PublicKey.Algorithm {
		t.Errorf("Algorithm mismatch: got %d, want %d", sigRR.Algorithm, loadedKey.PublicKey.Algorithm)
	}

	if sigRR.KeyTag != loadedKey.PublicKey.KeyTag() {
		t.Errorf("KeyTag mismatch: got %d, want %d", sigRR.KeyTag, loadedKey.PublicKey.KeyTag())
	}

	// Verify inception/expiration are reasonable (±300 seconds)
	now := uint32(time.Now().Unix())
	if sigRR.Inception > now || sigRR.Inception < now-600 {
		t.Errorf("Inception time out of range: %d (now=%d)", sigRR.Inception, now)
	}

	if sigRR.Expiration < now || sigRR.Expiration > now+600 {
		t.Errorf("Expiration time out of range: %d (now=%d)", sigRR.Expiration, now)
	}

	// Verify the signature is present
	if len(sigRR.Signature) == 0 {
		t.Fatal("Signature is empty")
	}

	t.Logf("Successfully signed message")
	t.Logf("SIG Record: Algorithm=%d, KeyTag=%d, SignerName=%s",
		sigRR.Algorithm, sigRR.KeyTag, sigRR.SignerName)
	t.Logf("Inception: %d, Expiration: %d", sigRR.Inception, sigRR.Expiration)
	t.Logf("Signature length: %d chars (base64)", len(sigRR.Signature))
}

func TestVerifySignature(t *testing.T) {
	keystoreDir := getKeystoreDir(t)

	// Find the key for test.dev.zenr.io
	keyName, err := keyrec.FindKeyByZone(keystoreDir, "test.dev.zenr.io")
	if err != nil {
		t.Skipf("Could not find test key: %v", err)
	}

	// Load a test key
	loadedKey, err := keyrec.LoadKeyFromFiles(keystoreDir, keyName)
	if err != nil {
		t.Skipf("Could not load test key: %v", err)
	}

	// Create a signer and sign a message
	signer, err := NewSigner(loadedKey.PublicKey, loadedKey.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	zone := "test.dev.zenr.io."
	err = signer.StartUpdate(zone)
	if err != nil {
		t.Fatalf("Failed to start UPDATE: %v", err)
	}

	testRRString := "test.dev.zenr.io. 300 IN A 192.0.2.1"
	err = signer.UpdateParsedRR(testRRString)
	if err != nil {
		t.Fatalf("Failed to add RR: %v", err)
	}

	signedMsg, err := signer.SignUpdate()
	if err != nil {
		t.Fatalf("Failed to sign UPDATE: %v", err)
	}

	// Now verify the signature
	err = VerifySignature(signedMsg, loadedKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	t.Logf("Successfully verified signature")
}

func TestLoadKeyFromFiles(t *testing.T) {
	keystoreDir := getKeystoreDir(t)

	// Find the key for test.dev.zenr.io
	keyName, err := keyrec.FindKeyByZone(keystoreDir, "test.dev.zenr.io")
	if err != nil {
		t.Skipf("Could not find test key: %v", err)
	}

	// Test finding test.dev.zenr.io key
	loadedKey, err := keyrec.LoadKeyFromFiles(keystoreDir, keyName)
	if err != nil {
		t.Skipf("Could not load test key: %v", err)
	}

	if loadedKey.PublicKey == nil {
		t.Fatal("PublicKey is nil")
	}

	if loadedKey.PrivateKey == nil {
		t.Fatal("PrivateKey is nil")
	}

	t.Logf("Loaded key: %s", loadedKey.PublicKey.Hdr.Name)
	t.Logf("Algorithm: %d, KeyTag: %d", loadedKey.PublicKey.Algorithm, loadedKey.PublicKey.KeyTag())
	t.Logf("Public key size: %d bytes", len(loadedKey.PublicKey.PublicKey))
}
