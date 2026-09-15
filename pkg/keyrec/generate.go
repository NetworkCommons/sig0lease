// File: pkg/keyrec/generate.go
// In-memory key generation for SIG(0), independent of any keystore directory.

package keyrec

import (
	"fmt"
	"os"
	"path/filepath"

	"codeberg.org/miekg/dns"
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
