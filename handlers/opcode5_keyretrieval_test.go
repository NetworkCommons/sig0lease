package handlers

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/NetworkCommons/sig0lease/logging"
)

func newTestHandler() *UpdateHandler {
	h := NewUpdateHandler()
	h.SetLogger(logging.NewLogger("debug", "text"))
	return h
}

func TestResolveKeyFromLeaseStoreOnly(t *testing.T) {
	h := newTestHandler()
	h.keyRetrievalMode = KeyRetrievalLeaseStoreOnly
	ctx := context.Background()

	// Register a key in the lease store.
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTSTORE111=")
	if err := h.leaseManager.Register(ctx, key.Hdr.Name, key, 120, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register key: %v", err)
	}

	// Should find the key in the lease store.
	resolved, err := h.resolveKeyForValidation(ctx, key.Hdr.Name)
	if err != nil {
		t.Fatalf("expected to find key in lease store, got error: %v", err)
	}
	if resolved == nil {
		t.Fatalf("expected resolved key, got nil")
	}
	if resolved.PublicKey != key.PublicKey {
		t.Fatalf("expected key public key %s, got %s", key.PublicKey, resolved.PublicKey)
	}

	// Should fail when key is not in lease store.
	_, err = h.resolveKeyForValidation(ctx, "unknown.dev.zenr.io.")
	if err == nil {
		t.Fatalf("expected error for unknown key in lease_store_only mode")
	}
}

func TestResolveKeyFromLeaseStoreWithFallback(t *testing.T) {
	h := newTestHandler()
	h.keyRetrievalMode = KeyRetrievalLeaseStoreWithFallback
	ctx := context.Background()

	// Register a key in the lease store.
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTFALL222=")
	if err := h.leaseManager.Register(ctx, key.Hdr.Name, key, 120, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register key: %v", err)
	}

	// Should find the key in the lease store (cache hit).
	resolved, err := h.resolveKeyForValidation(ctx, key.Hdr.Name)
	if err != nil {
		t.Fatalf("expected to find key in lease store, got error: %v", err)
	}
	if resolved == nil {
		t.Fatalf("expected resolved key, got nil")
	}
	if resolved.PublicKey != key.PublicKey {
		t.Fatalf("expected key public key %s, got %s", key.PublicKey, resolved.PublicKey)
	}

	// Should fail when key is not in lease store (DNS query goes to real DNS).
	// This is expected to fail since we're not running a local DNS server in tests.
	_, err = h.resolveKeyForValidation(ctx, "unknown.dev.zenr.io.")
	if err == nil {
		t.Fatalf("expected error for unknown key in lease_store_with_fallback mode")
	}
}

func TestResolveKeyFromDNSServerOnly(t *testing.T) {
	h := newTestHandler()
	h.keyRetrievalMode = KeyRetrievalDNSServerOnly
	ctx := context.Background()

	// Should fail when querying DNS for a non-existent key.
	_, err := h.resolveKeyForValidation(ctx, "nonexistent.example.com.")
	if err == nil {
		t.Fatalf("expected error when querying DNS for non-existent key")
	}
}

func TestResolveKeyDefaultMode(t *testing.T) {
	h := NewUpdateHandler()
	// Default mode should be lease_store_with_dns_fallback (set in Setup).
	// Since we skip Setup() in unit tests, the default is empty string,
	// which resolveKeyForValidation treats the same as lease_store_only.
	if h.keyRetrievalMode != "" {
		t.Fatalf("expected default key retrieval mode to be empty string (resolved in Setup), got %s", h.keyRetrievalMode)
	}
}

func TestResolveKeyInvalidMode(t *testing.T) {
	h := newTestHandler()
	h.keyRetrievalMode = "invalid_mode"
	ctx := context.Background()

	_, err := h.resolveKeyForValidation(ctx, "test.dev.zenr.io.")
	if err == nil {
		t.Fatalf("expected error for invalid mode")
	}
}

func TestResolveKeyEmptyName(t *testing.T) {
	h := newTestHandler()
	ctx := context.Background()

	_, err := h.resolveKeyForValidation(ctx, "")
	if err == nil {
		t.Fatalf("expected error for empty name")
	}
}

func TestSetupKeyRetrievalModeConfig(t *testing.T) {
	// Test that Setup() correctly parses key_retrieval_mode from config.
	// Create a valid keystore with a server key so Setup() succeeds.
	// We use a pre-existing test key from the repository's keystore.
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}

	tests := []struct {
		name       string
		mode       string
		expectMode KeyRetrievalMode
		expectErr  bool
	}{
		{"default_no_config", "", KeyRetrievalLeaseStoreWithFallback, false},
		{"lease_store_only", "lease_store_only", KeyRetrievalLeaseStoreOnly, false},
		{"dns_server_only", "dns_server_only", KeyRetrievalDNSServerOnly, false},
		{"lease_store_with_fallback", "lease_store_with_dns_fallback", KeyRetrievalLeaseStoreWithFallback, false},
		{"invalid_mode", "invalid_mode", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewUpdateHandler()
			h.SetLogger(logging.NewLogger("debug", "text"))
			cfg := map[string]any{
				"upstream_zone":      "dev.zenr.io.",
				"keystore_dir":       keystoreDir,
				"key_retrieval_mode": tt.mode,
			}
			err := h.Setup(cfg)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for invalid mode %q", tt.mode)
				}
				// Check that the error is about invalid mode, not about missing keystore.
				if err.Error() != "invalid key_retrieval_mode \"invalid_mode\", must be one of: lease_store_only, dns_server_only, lease_store_with_dns_fallback" {
					t.Fatalf("expected invalid mode error, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h.keyRetrievalMode != tt.expectMode {
				t.Fatalf("expected key_retrieval_mode %s, got %s", tt.expectMode, h.keyRetrievalMode)
			}
		})
	}
}

// createTestKeystore creates a temporary keystore directory with a valid server key
// so that Setup() can successfully load the upstream key.
func createTestKeystore(t *testing.T) (string, error) {
	// Use the pre-existing test key from the repository's keystore.
	// We need the key files in the top-level directory (as config points to server/ subdir).
	srcKeyFile := "../keystore/server/Kdev.zenr.io.+015+35317.key"
	srcPrivFile := "../keystore/server/Kdev.zenr.io.+015+35317.private"

	tmpDir := t.TempDir()

	// Copy the key file directly into the temp directory (not a subdirectory).
	if err := copyFile(srcKeyFile, filepath.Join(tmpDir, "Kdev.zenr.io.+015+35317.key")); err != nil {
		return "", err
	}
	// Copy the private key file.
	if err := copyFile(srcPrivFile, filepath.Join(tmpDir, "Kdev.zenr.io.+015+35317.private")); err != nil {
		return "", err
	}

	return tmpDir, nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}
