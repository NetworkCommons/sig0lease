package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/lease"
)

func fileStorage(path string) map[string]any {
	return map[string]any{"storage": map[string]any{"type": "file", "path": path}}
}

func leaseStoreConfig(modules []string, update, srp map[string]any) *config.Config {
	return &config.Config{
		ProcessingRules: []config.ProcessingConfig{{Opcode: 5, Modules: modules}},
		Handlers:        map[string]map[string]any{"update": update, "srp_handler": srp},
	}
}

func TestCheckSeparateLeaseStores(t *testing.T) {
	both := []string{"srp_handler", "update_handler"}
	memory := map[string]any{"storage": map[string]any{"type": "memory"}}

	const shared = "must each have their own lease store"
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr string // "" for no error
	}{
		{"different files", leaseStoreConfig(both, fileStorage("data/lease.json"), fileStorage("data/srp.json")), ""},
		{"same file", leaseStoreConfig(both, fileStorage("data/lease.json"), fileStorage("data/lease.json")), shared},
		{"same file spelled differently", leaseStoreConfig(both, fileStorage("./data/lease.json"), fileStorage("data/../data/lease.json")), shared},
		{"type is case-insensitive", leaseStoreConfig(both,
			map[string]any{"storage": map[string]any{"type": " FILE ", "path": "data/lease.json"}},
			fileStorage("data/lease.json")), shared},
		{"one handler in memory", leaseStoreConfig(both, fileStorage("data/lease.json"), memory), ""},
		{"no storage section", leaseStoreConfig(both, fileStorage("data/lease.json"), map[string]any{}), ""},
		{"unusable storage section", leaseStoreConfig(both, fileStorage("data/lease.json"),
			map[string]any{"storage": map[string]any{"type": "fiel", "path": "data/lease.json"}}), "handlers.srp_handler: storage: unrecognized"},
		{"lease_manager and storage both given", leaseStoreConfig(both, fileStorage("data/lease.json"),
			map[string]any{"lease_manager": "x", "storage": map[string]any{"type": "memory"}}), "mutually exclusive"},
		{"srp_handler not enabled", leaseStoreConfig([]string{"update_handler"}, fileStorage("data/lease.json"), fileStorage("data/lease.json")), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSeparateLeaseStores(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkSeparateLeaseStores() error = %v, want none", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("checkSeparateLeaseStores() error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

// A symlink is a second name for the same snapshot file: caught once the file exists.
func TestCheckSeparateLeaseStoresSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "lease.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "srp.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	cfg := leaseStoreConfig([]string{"srp_handler", "update_handler"}, fileStorage(target), fileStorage(link))
	if err := checkSeparateLeaseStores(cfg); err == nil {
		t.Fatal("checkSeparateLeaseStores() accepted a symlink to the other handler's snapshot file")
	}
}

// dumpConfig enables both handlers for zone dev.zenr.io., signing with the repository's
// test key, each with its own snapshot file.
func dumpConfig(t *testing.T, updatePath, srpPath string) *config.Config {
	t.Helper()
	// applyUpdateHandlerEnvOverrides reads these; an empty value overrides nothing.
	t.Setenv("UPSTREAM_ZONE", "")
	t.Setenv("KEYSTORE_DIR", "")
	keystore, err := filepath.Abs("../../keystore/server")
	if err != nil {
		t.Fatal(err)
	}
	handler := func(path string) map[string]any {
		return map[string]any{
			"upstream_zone": "dev.zenr.io.",
			"keystore_dir":  keystore,
			"storage":       map[string]any{"type": "file", "path": path},
		}
	}
	return leaseStoreConfig([]string{"srp_handler", "update_handler"}, handler(updatePath), handler(srpPath))
}

// A dump writes nothing: a snapshot that exists is read and left as it was (the same file,
// not rewritten), and one that doesn't exist yet is neither created nor given a directory.
func TestDumpLeases_WritesNothing(t *testing.T) {
	dir := t.TempDir()
	updatePath := filepath.Join(dir, "lease.json")
	srpPath := filepath.Join(dir, "srp", "srp.json")

	key, err := keyrec.GenerateKey("host.dev.zenr.io.", dns.ED25519, 0, 256)
	if err != nil {
		t.Fatal(err)
	}
	store := lease.NewInMemoryManager()
	if err := store.Register(context.Background(), key.PublicKey, 3600, 7200, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSnapshot(updatePath); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(updatePath)
	if err != nil {
		t.Fatal(err)
	}
	beforeData, err := os.ReadFile(updatePath)
	if err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	if err := dumpLeases(&out, dumpConfig(t, updatePath, srpPath), "info", logging.NewLogger("error")); err != nil {
		t.Fatalf("dumpLeases() error = %v", err)
	}

	if nodeKey := lease.NodeKey(key.PublicKey); !strings.Contains(out.String(), nodeKey) {
		t.Errorf("dump does not show %s from the snapshot:\n%s", nodeKey, out.String())
	}
	after, err := os.Stat(updatePath)
	if err != nil {
		t.Fatal(err)
	}
	afterData, err := os.ReadFile(updatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) || string(afterData) != string(beforeData) {
		t.Errorf("dump rewrote %s", updatePath)
	}
	if _, err := os.Stat(filepath.Dir(srpPath)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("dump created %s (stat error %v)", filepath.Dir(srpPath), err)
	}
}

// A snapshot the proxy would refuse to start from fails the dump too, rather than showing
// an empty store.
func TestDumpLeases_RejectsCorruptSnapshot(t *testing.T) {
	dir := t.TempDir()
	updatePath := filepath.Join(dir, "lease.json")
	if err := os.WriteFile(updatePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	err := dumpLeases(&out, dumpConfig(t, updatePath, filepath.Join(dir, "srp.json")), "info", logging.NewLogger("error"))
	if err == nil || !strings.Contains(err.Error(), updatePath) {
		t.Fatalf("dumpLeases() error = %v, want one naming %s", err, updatePath)
	}
}
