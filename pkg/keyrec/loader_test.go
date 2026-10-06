package keyrec

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
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

// TestFindKeysByZone_FixedOrder pins the order FindKeysByZone returns several matching keys
// in: ED25519 first, then any other algorithm, each group alphabetical. It used to collect
// the names in a map and return them in Go's random map order, so a caller taking the first
// name signed with a different key from one run to the next.
func TestFindKeysByZone_FixedOrder(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"Kx.example.+013+00002",
		"Kx.example.+015+00009",
		"Kx.example.+013+00001",
		"Kx.example.+015+00001",
	} {
		if err := os.WriteFile(filepath.Join(dir, name+".key"), []byte("dummy"), 0o600); err != nil {
			t.Fatalf("write key file: %v", err)
		}
	}

	want := []string{
		"Kx.example.+015+00001",
		"Kx.example.+015+00009",
		"Kx.example.+013+00001",
		"Kx.example.+013+00002",
	}
	for range 20 {
		got, err := FindKeysByZone(dir, "x.example.", nil)
		if err != nil {
			t.Fatalf("FindKeysByZone: %v", err)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestResolveOrCreateKey_SeveralMatchesWarnsAndPicksFirst checks that with two keys for the
// same owner, ResolveOrCreateKey loads the first in FindKeysByZone's order every time and
// logs a warning naming both.
func TestResolveOrCreateKey_SeveralMatchesWarnsAndPicksFirst(t *testing.T) {
	dir := t.TempDir()
	var names []string
	for range 2 {
		k, err := GenerateKey("x.example.", dns.ED25519, 0, 256)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		if err := k.SaveToFile(dir); err != nil {
			t.Fatalf("SaveToFile: %v", err)
		}
		names = append(names, k.Name)
	}
	if names[0] == names[1] {
		t.Skipf("both generated keys got keytag %s; nothing to choose between", names[0])
	}
	slices.Sort(names)

	// logging.NewLogger writes to the os.Stdout it finds when called, so swap a pipe in just
	// for the constructor.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	stdout := os.Stdout
	os.Stdout = w
	logger := logging.NewLogger("info")
	os.Stdout = stdout

	for range 20 {
		k, created, err := ResolveOrCreateKey(dir, "x.example.", 0, logger)
		if err != nil {
			t.Fatalf("ResolveOrCreateKey: %v", err)
		}
		if created {
			t.Fatalf("ResolveOrCreateKey created a key although two exist")
		}
		if k.Name != names[0] {
			t.Fatalf("loaded %s, want %s", k.Name, names[0])
		}
	}
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read log output: %v", err)
	}
	line, _, _ := strings.Cut(string(out), "\n")
	if !strings.Contains(line, "WARN") || !strings.Contains(line, names[0]) || !strings.Contains(line, names[1]) {
		t.Fatalf("want a warning naming %s and %s, got log output:\n%s", names[0], names[1], out)
	}
}
