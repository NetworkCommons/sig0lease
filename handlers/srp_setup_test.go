package handlers

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NetworkCommons/sig0lease/logging"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// baseSRPSetupCfg mirrors baseSetupCfg (opcode5_setup_test.go), but for SRPHandler.Setup --
// SRPHandler.Setup had NO test coverage at all before this file: every existing
// srp_handler_test.go test constructs the handler by populating fields directly
// (newSRPTestHandler), bypassing Setup's own config-parsing entirely. That gap is exactly how
// the shipped config.yaml ended up with a "storage" block under handlers.update but none
// under handlers.srp_handler -- nothing ever exercised (or would have caught) SRPHandler
// actually wiring the same "storage"/"lease_manager" options UpdateHandler.Setup already has
// thorough coverage for via the shared buildLeaseManagerFromConfig (handlers.go).
func baseSRPSetupCfg(t *testing.T) map[string]any {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	return map[string]any{
		"upstream_zone": srpTestZone,
		"keystore_dir":  keystoreDir,
	}
}

func TestSRPSetup_DefaultStorageIsInMemory(t *testing.T) {
	h := NewSRPHandler()
	h.SetLogger(logging.NewLogger("debug"))
	if err := h.Setup(baseSRPSetupCfg(t)); err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	if _, ok := h.leaseManager.(*leasepkg.InMemoryLeaseStore); !ok {
		t.Fatalf("expected default lease manager to be *InMemoryLeaseStore, got %T", h.leaseManager)
	}
}

func TestSRPSetup_StorageTypeFile_CreatesFileBackedStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "srp_lease_snapshot.json")
	cfg := baseSRPSetupCfg(t)
	cfg["storage"] = map[string]any{
		"type":          "file",
		"path":          path,
		"save_interval": "50ms",
	}

	h := NewSRPHandler()
	h.SetLogger(logging.NewLogger("debug"))
	if err := h.Setup(cfg); err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	defer h.leaseManager.Stop()

	if _, ok := h.leaseManager.(*leasepkg.FileLeaseStore); !ok {
		t.Fatalf("expected *FileLeaseStore, got %T", h.leaseManager)
	}
}

func TestSRPSetup_LeaseManagerAndStorageBothSetErrors(t *testing.T) {
	cfg := baseSRPSetupCfg(t)
	cfg["lease_manager"] = leasepkg.NewInMemoryManager()
	cfg["storage"] = map[string]any{"type": "memory"}

	h := NewSRPHandler()
	h.SetLogger(logging.NewLogger("debug"))
	err := h.Setup(cfg)
	if err == nil {
		t.Fatal("expected error when both lease_manager and storage are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected error to mention \"mutually exclusive\", got: %v", err)
	}
}

func TestSRPSetup_AdvertiseRegistrationDomainWired(t *testing.T) {
	cfg := baseSRPSetupCfg(t)
	cfg["advertise_registration_domain"] = true

	h := NewSRPHandler()
	h.SetLogger(logging.NewLogger("debug"))
	if err := h.Setup(cfg); err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	if !h.advertiseRegistrationDomain {
		t.Fatal("expected advertise_registration_domain: true in config to set h.advertiseRegistrationDomain")
	}
}

// TestSRPSetup_FileStorageSurvivesRestart is the concrete proof the user asked for: an SRP
// registration written through one SRPHandler instance backed by file storage must still be
// there after that process exits and a brand new SRPHandler instance calls Setup against the
// same path -- i.e. an actual crash/restart, not just "the shared file-store code has its own
// unit tests" (pkg/lease/file_store_test.go already covers that in isolation; this proves the
// wiring through SRPHandler.Setup specifically). Registers directly against h1.leaseManager
// (RegisterWithParent) rather than going through a full signed Handle() call -- Setup's own
// config wiring is what's under test here, not the SRP protocol handling srp_handler_test.go
// already covers exhaustively.
func TestSRPSetup_FileStorageSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "srp_lease_snapshot.json")

	id := newSRPTestIdentity(t)
	const host = "srpsetuptest1.dev.zenr.io."
	nodeKey := leasepkg.NodeKey(id.keyAt(host))

	cfg1 := baseSRPSetupCfg(t)
	cfg1["storage"] = map[string]any{"type": "file", "path": path, "save_interval": "1h"}
	h1 := NewSRPHandler()
	h1.SetLogger(logging.NewLogger("debug"))
	if err := h1.Setup(cfg1); err != nil {
		t.Fatalf("h1 Setup returned error: %v", err)
	}
	if err := h1.leaseManager.RegisterWithParent(context.Background(), "", id.keyAt(host), 3600, 3600, srpTestZone); err != nil {
		t.Fatalf("register into h1's file-backed store: %v", err)
	}
	// Stop() performs one final synchronous save (FileLeaseStore's own documented
	// flush-on-shutdown behavior) -- the deterministic way to force a save without racing
	// the 1h ticker or sleeping in a test.
	h1.leaseManager.Stop()

	cfg2 := baseSRPSetupCfg(t)
	cfg2["storage"] = map[string]any{"type": "file", "path": path, "save_interval": "1h"}
	h2 := NewSRPHandler()
	h2.SetLogger(logging.NewLogger("debug"))
	if err := h2.Setup(cfg2); err != nil {
		t.Fatalf("h2 Setup (simulating a restart against the same snapshot path) returned error: %v", err)
	}
	defer h2.leaseManager.Stop()

	rec := h2.leaseManager.Get(nodeKey)
	if rec == nil {
		t.Fatalf("expected the registration made through h1 to still be present in h2 after loading the same snapshot file, got nil")
	}
	if rec.KeyRR == nil || canonicalName(rec.KeyRR.Hdr.Name) != canonicalName(host) {
		t.Fatalf("expected the restored node's KEY to be for %s, got: %+v", host, rec.KeyRR)
	}
}
