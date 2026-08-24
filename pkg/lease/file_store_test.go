package lease

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileLeaseStore_ConstructorRejectsEmptyPath(t *testing.T) {
	if _, err := NewFileLeaseStore("", time.Second, nil); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestFileLeaseStore_ConstructorRejectsNonPositiveInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if _, err := NewFileLeaseStore(path, 0, nil); err == nil {
		t.Fatal("expected error for zero save_interval")
	}
	if _, err := NewFileLeaseStore(path, -time.Second, nil); err == nil {
		t.Fatal("expected error for negative save_interval")
	}
}

func TestFileLeaseStore_ConstructorMissingFileStartsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")

	store, err := NewFileLeaseStore(path, time.Hour, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer store.Stop()

	if len(store.ListAll()) != 0 {
		t.Fatalf("expected empty store, got %d records", len(store.ListAll()))
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("expected write-probe to create %s: %v", path, statErr)
	}
}

func TestFileLeaseStore_ConstructorCreatesMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "does", "not", "exist", "snapshot.json")

	store, err := NewFileLeaseStore(path, time.Hour, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer store.Stop()

	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("expected missing parent directories to be created and %s written: %v", path, statErr)
	}
}

func TestFileLeaseStore_ConstructorMkdirFailureIsHardError(t *testing.T) {
	// Force MkdirAll to fail: a regular file sitting where a directory
	// component needs to be created is not a directory and cannot be
	// descended into.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	path := filepath.Join(blocker, "subdir", "snapshot.json")

	if _, err := NewFileLeaseStore(path, time.Hour, nil); err == nil {
		t.Fatal("expected directory-creation failure to be a hard construction error")
	}
}

func TestFileLeaseStore_ConstructorLoadsExistingSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	ctx := context.Background()

	seed := NewInMemoryManager()
	defer seed.Stop()
	key := testKeyRR("preloaded.dev.zenr.io.", "AAAAPRELOAD=")
	if err := seed.Register(ctx, key, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	if err := seed.SaveSnapshot(path); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	store, err := NewFileLeaseStore(path, time.Hour, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer store.Stop()

	if got := store.Get(NodeKey(key)); got == nil {
		t.Fatal("expected preloaded record to be loaded from existing snapshot")
	}
}

func TestFileLeaseStore_ConstructorCorruptFileHardFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, []byte("not valid json{{{"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	if _, err := NewFileLeaseStore(path, time.Hour, nil); err == nil {
		t.Fatal("expected corrupt existing snapshot to be a hard construction error")
	}
}

func TestFileLeaseStore_PeriodicSave_PersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	ctx := context.Background()

	store, err := NewFileLeaseStore(path, 20*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key := testKeyRR("restart.dev.zenr.io.", "AAAARESTART=")
	if err := store.Register(ctx, key, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Poll for the periodic save to have picked up the mutation, rather than
	// a blind sleep.
	deadline := time.Now().Add(2 * time.Second)
	for {
		reloaded := NewInMemoryManager()
		if err := reloaded.LoadSnapshot(path); err == nil && reloaded.Get(NodeKey(key)) != nil {
			reloaded.Stop()
			break
		}
		reloaded.Stop()
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for periodic save to persist the registered lease")
		}
		time.Sleep(5 * time.Millisecond)
	}

	store.Stop()

	// Independent, second store pointed at the same path -- simulates a
	// process restart.
	restarted, err := NewFileLeaseStore(path, time.Hour, nil)
	if err != nil {
		t.Fatalf("unexpected error on restart: %v", err)
	}
	defer restarted.Stop()

	if got := restarted.Get(NodeKey(key)); got == nil {
		t.Fatal("expected lease to survive simulated restart")
	}
}

func TestFileLeaseStore_StopPerformsFinalSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	ctx := context.Background()

	// Interval longer than the test itself, so only Stop()'s final
	// synchronous save could possibly have written the mutation below.
	store, err := NewFileLeaseStore(path, time.Hour, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key := testKeyRR("finalsave.dev.zenr.io.", "AAAAFINALSAVE=")
	if err := store.Register(ctx, key, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register: %v", err)
	}
	store.Stop()

	reloaded := NewInMemoryManager()
	defer reloaded.Stop()
	if err := reloaded.LoadSnapshot(path); err != nil {
		t.Fatalf("load after Stop: %v", err)
	}
	if got := reloaded.Get(NodeKey(key)); got == nil {
		t.Fatal("expected Stop() to perform a final save capturing the registered lease")
	}
}

func TestFileLeaseStore_StopIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	store, err := NewFileLeaseStore(path, time.Hour, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	store.Stop()
	store.Stop() // must not panic or block
}
