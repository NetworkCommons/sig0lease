package keyrec

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFindKeysByZone_DoesNotMatchUnrelatedZoneSharingStringPrefix guards
// against a label-boundary bug: FindKeysByZone used to match key filenames
// by a bare string prefix ("K" + zoneName), which also matches an unrelated
// zone whose name happens to start with the same characters. DNS names are
// hierarchical right-to-left, so "dev.zenr.io.evil.com." is not a subzone of
// "dev.zenr.io." even though the literal string "dev.zenr.io." appears as
// its prefix -- it's a completely different zone under "evil.com.".
func TestFindKeysByZone_DoesNotMatchUnrelatedZoneSharingStringPrefix(t *testing.T) {
	dir := t.TempDir()

	legit := "Kdev.zenr.io.+015+00001"
	if err := os.WriteFile(filepath.Join(dir, legit+".key"), []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write legit key file: %v", err)
	}

	decoy := "Kdev.zenr.io.evil.com.+015+00002"
	if err := os.WriteFile(filepath.Join(dir, decoy+".key"), []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write decoy key file: %v", err)
	}

	got, err := FindKeysByZone(dir, "dev.zenr.io.", nil)
	if err != nil {
		t.Fatalf("FindKeysByZone: %v", err)
	}
	if len(got) != 1 || got[0] != legit {
		t.Fatalf("expected only %q to match zone \"dev.zenr.io.\", got %v", legit, got)
	}
}

// TestFindKeysByZone_MatchesExactZone is the straightforward positive case:
// a key filed exactly under the queried zone is found.
func TestFindKeysByZone_MatchesExactZone(t *testing.T) {
	dir := t.TempDir()

	legit := "Ktest.dev.zenr.io.+015+05044"
	if err := os.WriteFile(filepath.Join(dir, legit+".key"), []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	got, err := FindKeysByZone(dir, "test.dev.zenr.io.", nil)
	if err != nil {
		t.Fatalf("FindKeysByZone: %v", err)
	}
	if len(got) != 1 || got[0] != legit {
		t.Fatalf("expected %q, got %v", legit, got)
	}
}
