package handlers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
)

func baseSetupCfg(t *testing.T) map[string]interface{} {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	return map[string]interface{}{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}
}

func TestSetup_DefaultStorageIsInMemory(t *testing.T) {
	h := newTestHandler()
	if err := h.Setup(baseSetupCfg(t)); err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	if _, ok := h.leaseManager.(*leasepkg.InMemoryLeaseStore); !ok {
		t.Fatalf("expected default lease manager to be *InMemoryLeaseStore, got %T", h.leaseManager)
	}
}

// TestSetup_UpstreamZoneTrimmed pins where a configured zone's surrounding whitespace goes:
// Setup trims it, since dnsname.Normalize no longer does (a label may begin with a space).
func TestSetup_UpstreamZoneTrimmed(t *testing.T) {
	cfg := baseSetupCfg(t)
	cfg["upstream_zone"] = "  dev.zenr.io.\t"
	h := newTestHandler()
	if err := h.Setup(cfg); err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	if h.upstreamZone != "dev.zenr.io." {
		t.Fatalf("upstreamZone = %q, want %q", h.upstreamZone, "dev.zenr.io.")
	}

	cfg["upstream_zone"] = "   "
	if err := newTestHandler().Setup(cfg); err == nil {
		t.Fatal("expected a whitespace-only upstream_zone to be rejected as missing")
	}
}

func TestSetup_StorageTypeMemoryExplicit(t *testing.T) {
	cfg := baseSetupCfg(t)
	cfg["storage"] = map[string]any{"type": "memory"}

	h := newTestHandler()
	if err := h.Setup(cfg); err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	if _, ok := h.leaseManager.(*leasepkg.InMemoryLeaseStore); !ok {
		t.Fatalf("expected in-memory lease manager, got %T", h.leaseManager)
	}
}

func TestSetup_StorageTypeFile_CreatesFileBackedStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease_snapshot.json")
	cfg := baseSetupCfg(t)
	cfg["storage"] = map[string]any{
		"type":          "file",
		"path":          path,
		"save_interval": "50ms",
	}

	h := newTestHandler()
	if err := h.Setup(cfg); err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	defer h.leaseManager.Stop()

	if _, ok := h.leaseManager.(*leasepkg.FileLeaseStore); !ok {
		t.Fatalf("expected *FileLeaseStore, got %T", h.leaseManager)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("expected write-probe to create %s during Setup: %v", path, statErr)
	}
}

func TestSetup_StorageTypeFile_MissingPathErrors(t *testing.T) {
	cfg := baseSetupCfg(t)
	cfg["storage"] = map[string]any{"type": "file"}

	h := newTestHandler()
	err := h.Setup(cfg)
	if err == nil {
		t.Fatal("expected error for file storage missing path")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Fatalf("expected error to mention \"path\", got: %v", err)
	}
}

func TestSetup_StorageUnknownTypeErrors(t *testing.T) {
	cfg := baseSetupCfg(t)
	cfg["storage"] = map[string]any{"type": "bogus"}

	h := newTestHandler()
	err := h.Setup(cfg)
	if err == nil {
		t.Fatal("expected error for unrecognized storage type")
	}
	if !strings.Contains(err.Error(), "unrecognized") {
		t.Fatalf("expected error to mention \"unrecognized\", got: %v", err)
	}
}

func TestSetup_StorageNotAMapErrors(t *testing.T) {
	cfg := baseSetupCfg(t)
	cfg["storage"] = "oops"

	h := newTestHandler()
	if err := h.Setup(cfg); err == nil {
		t.Fatal("expected error for non-map storage config")
	}
}

func TestSetup_StorageSaveIntervalInvalidDurationErrors(t *testing.T) {
	cfg := baseSetupCfg(t)
	cfg["storage"] = map[string]any{
		"type":          "file",
		"path":          filepath.Join(t.TempDir(), "lease_snapshot.json"),
		"save_interval": "not-a-duration",
	}

	h := newTestHandler()
	if err := h.Setup(cfg); err == nil {
		t.Fatal("expected error for invalid save_interval")
	}
}

func TestSetup_StorageFileCorruptSnapshotErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease_snapshot.json")
	if err := os.WriteFile(path, []byte("not valid json{{{"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	cfg := baseSetupCfg(t)
	cfg["storage"] = map[string]any{"type": "file", "path": path}

	h := newTestHandler()
	if err := h.Setup(cfg); err == nil {
		t.Fatal("expected corrupt existing snapshot to propagate as a Setup error")
	}
}

func TestSetup_LeaseManagerAndStorageBothSetErrors(t *testing.T) {
	cfg := baseSetupCfg(t)
	cfg["lease_manager"] = leasepkg.NewInMemoryManager()
	cfg["storage"] = map[string]any{"type": "memory"}

	h := newTestHandler()
	err := h.Setup(cfg)
	if err == nil {
		t.Fatal("expected error when both lease_manager and storage are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected error to mention \"mutually exclusive\", got: %v", err)
	}
}

func TestSetup_LeaseManagerWrongTypeErrors(t *testing.T) {
	cfg := baseSetupCfg(t)
	cfg["lease_manager"] = "not a lease manager"

	h := newTestHandler()
	if err := h.Setup(cfg); err == nil {
		t.Fatal("expected error for wrong-typed lease_manager")
	}
}

// TestSetup_StaticUpstreamCoversRequestZones: "upstream" sends the handler's upstream_zone
// and the names below it -- the zones its requests name, e.g. test.dev.zenr.io. -- to the
// configured server, with no SOA/NS discovery.
func TestSetup_StaticUpstreamCoversRequestZones(t *testing.T) {
	cfg := baseSetupCfg(t)
	cfg["upstream"] = "127.0.0.1:5300"
	h := newTestHandler()
	if err := h.Setup(cfg); err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	coordinator, ok := h.upstreamCoordinator.(*updatecore.Coordinator)
	if !ok {
		t.Fatalf("expected *updatecore.Coordinator, got %T", h.upstreamCoordinator)
	}
	for _, zone := range []string{"dev.zenr.io.", "test.dev.zenr.io."} {
		server, effectiveZone, err := coordinator.ResolveSOAMasterServer(context.Background(), zone)
		if err != nil {
			t.Fatalf("ResolveSOAMasterServer(%q): %v", zone, err)
		}
		if server != "127.0.0.1:5300" || effectiveZone != "dev.zenr.io." {
			t.Fatalf("ResolveSOAMasterServer(%q) = %q, %q; want the static upstream and dev.zenr.io.", zone, server, effectiveZone)
		}
	}
}

func TestSetup_StaticUpstreamInvalidErrors(t *testing.T) {
	for _, upstream := range []any{5300, "", "127.0.0.1", "ns1.example."} {
		cfg := baseSetupCfg(t)
		cfg["upstream"] = upstream
		if err := newTestHandler().Setup(cfg); err == nil {
			t.Errorf("expected Setup to reject upstream %#v", upstream)
		}
	}
}
