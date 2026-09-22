// File: pkg/keyrec/generate.go
// In-memory key generation for SIG(0), independent of any keystore directory.

package keyrec

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
)

// GenerateKey creates a fresh SIG(0) key pair for name (the KEY RR's owner name) at the
// given algorithm and flags, entirely in memory -- no keystore directory, no files written.
// Uses the same codeberg.org/miekg/dns fork Generate/PrivateKeyString round-trip
// LoadKeyFromFile itself reads back (see loader.go), so a key from here is guaranteed
// loadable by anything that reads the on-disk key file format, if a caller chooses to
// persist it later (see (*LoadedKey).SaveToFile).
//
// bits follows dns.DNSKEY.Generate's own convention (algorithm-specific: 256 for
// ECDSAP256SHA256 or ED25519, 384 for ECDSAP384SHA384); 0 lets Generate error out for an
// algorithm requiring an explicit size (RSA).
func GenerateKey(name string, algorithm uint8, flags uint16, bits int) (*LoadedKey, error) {
	pub := &dns.KEY{}
	pub.Hdr = dns.Header{Name: name, Class: dns.ClassINET}
	pub.Flags = flags
	pub.Protocol = 3
	pub.Algorithm = algorithm

	priv, err := pub.Generate(bits)
	if err != nil {
		return nil, fmt.Errorf("keyrec: generate key for %s (algorithm %d): %w", name, algorithm, err)
	}

	return &LoadedKey{
		Name:       fmt.Sprintf("K%s+%03d+%d", name, algorithm, pub.KeyTag()),
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// ResolveOrCreateKey finds an existing key for owner (a fully-qualified DNS name) in dir, or
// -- only when createAlgorithm is non-zero -- generates and persists a fresh one there.
// Search is algorithm-agnostic (via FindKeysByZone's own "any algorithm, ED25519 preferred"
// ordering): an existing key of ANY algorithm satisfies the lookup, since createAlgorithm
// only says what to generate if nothing is found yet, not which algorithm to prefer among
// what already exists. created reports whether a new key was generated, so callers can tell
// the user which happened. createAlgorithm == 0 means "never create" -- a missing key is then
// an error, not silently generated, matching this package's existing strict-by-default
// convention (see cmd/sig0lease-client's historical behavior, which this generalizes).
//
// This is shared, rather than reimplemented per caller, because both of this project's CLI
// clients (cmd/sig0lease-client, cmd/sig0lease-srp-client) need the identical "find any existing
// key for this identity, or create one at an explicitly chosen algorithm" logic and would
// otherwise duplicate it.
func ResolveOrCreateKey(dir, owner string, createAlgorithm uint8, logger *logging.Logger) (key *LoadedKey, created bool, err error) {
	if dir == "" {
		return nil, false, fmt.Errorf("keystore directory is required")
	}

	existing, err := FindKeysByZone(dir, owner, logger)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("keyrec: search for existing key for %s: %w", owner, err)
	}
	// A keystore directory that doesn't exist yet is equivalent to one with no keys in it
	// -- ListKeysInDirectory's os.ReadDir fails outright rather than returning empty, but
	// that's routine on a brand-new identity's first-ever run (the create path below
	// creates the directory itself via os.MkdirAll), not a real error.
	if len(existing) > 0 {
		k, err := LoadKeyFromFile(dir, existing[0])
		if err != nil {
			return nil, false, fmt.Errorf("keyrec: load existing key %s: %w", existing[0], err)
		}
		return k, false, nil
	}

	if createAlgorithm == 0 {
		return nil, false, fmt.Errorf("no key found for %s in keystore %s (pass an algorithm to create one)", owner, dir)
	}

	bits := 256
	if createAlgorithm == dns.ECDSAP384SHA384 {
		bits = 384
	}
	k, err := GenerateKey(owner, createAlgorithm, 0, bits)
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, false, fmt.Errorf("keyrec: create keystore dir %s: %w", dir, err)
	}
	if err := k.SaveToFile(dir); err != nil {
		return nil, false, fmt.Errorf("keyrec: save generated key: %w", err)
	}
	return k, true, nil
}

// SaveToFile writes lk to <dir>/<lk.Name>.key and <dir>/<lk.Name>.private, in the same
// format LoadKeyFromFile reads. dir must already exist.
func (lk *LoadedKey) SaveToFile(dir string) error {
	keyPath := filepath.Join(dir, lk.Name+".key")
	if err := os.WriteFile(keyPath, []byte(lk.PublicKey.String()+"\n"), 0o644); err != nil {
		return fmt.Errorf("keyrec: write %s: %w", keyPath, err)
	}
	privPath := filepath.Join(dir, lk.Name+".private")
	if err := os.WriteFile(privPath, []byte(lk.PublicKey.PrivateKeyString(lk.PrivateKey)), 0o600); err != nil {
		return fmt.Errorf("keyrec: write %s: %w", privPath, err)
	}
	return nil
}
