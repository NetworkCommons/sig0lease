// File: pkg/keyrec/loader.go
// Key loading and management for SIG(0) signing
// Inspired by codeberg.org/networkcommons/sig0namectl/golang/sig0/keys_nowasm.go

package keyrec

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"codeberg.org/miekg/dns"
)

// LoadedKey represents a fully loaded key with private key material for signing.
type LoadedKey struct {
	// Name is the base filename without extensions (e.g., "Kzone.+015+12345")
	Name string

	// PublicKey is the parsed KEY RR from the .key file
	PublicKey *dns.KEY

	// PrivateKey is the parsed private key material for signing
	PrivateKey crypto.PrivateKey
}

// LoadKeyFromFiles loads a DNSSEC key from keystore files.
// Provenance: Adapted from sig0namectl's LoadKeyFile() approach
// Expects files: <keystoreDir>/<keyName>.key and <keystoreDir>/<keyName>.private
// Uses codeberg.org/miekg/dns v0.6.82 API (not the old miekg/dns API)
func LoadKeyFromFiles(keystoreDir, keyName string) (*LoadedKey, error) {
	pubKeyPath := filepath.Join(keystoreDir, keyName+".key")
	privKeyPath := filepath.Join(keystoreDir, keyName+".private")

	// Read public key file (contains KEY RR in text format)
	pubKeyFile, err := os.Open(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open public key file %q: %w", pubKeyPath, err)
	}
	defer pubKeyFile.Close()

	// Parse KEY RR using dns.Read from codeberg/miekg/dns
	// This reads wire format or text format DNS records
	rr, err := dns.Read(pubKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KEY RR from %q: %w", pubKeyPath, err)
	}

	dnsKey, ok := rr.(*dns.KEY)
	if !ok {
		return nil, fmt.Errorf("expected dns.KEY from %q, got %T", pubKeyPath, rr)
	}

	// Read private key file as text
	privKeyBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %q: %w", privKeyPath, err)
	}

	// Parse private key material using NewPrivate from codeberg/miekg/dns
	// This expects DNSSEC format private key text
	privKey, err := dnsKey.NewPrivate(string(privKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from %q: %w", privKeyPath, err)
	}

	return &LoadedKey{
		Name:       keyName,
		PublicKey:  dnsKey,
		PrivateKey: privKey,
	}, nil
}

// ListKeysInDirectory lists all key names in a keystore directory.
// Provenance: Adapted from sig0namectl's ListKeys() in keys_nowasm.go
func ListKeysInDirectory(keystoreDir string) ([]string, error) {
	entries, err := os.ReadDir(keystoreDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore directory %q: %w", keystoreDir, err)
	}

	var keyNames []string
	seen := make(map[string]bool)

	// Look for .key files and extract base names
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasPrefix(name, "K") && strings.HasSuffix(name, ".key") {
			// Extract base name (remove .key suffix)
			baseName := strings.TrimSuffix(name, ".key")
			if !seen[baseName] {
				keyNames = append(keyNames, baseName)
				seen[baseName] = true
			}
		}
	}

	return keyNames, nil
}

// FindKeyByZone searches for a key by zone name in the keystore.
// Returns the key name or error if not found.
// Prefers ED25519 (algorithm 15) over other algorithms.
// Provenance: Inspired by sig0namectl's LoadOrGenerateKey()
func FindKeyByZone(keystoreDir, zoneName string) (string, error) {
	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}

	keys, err := ListKeysInDirectory(keystoreDir)
	if err != nil {
		return "", err
	}

	// Key filenames are in format: Kzone.+algorithm+keytag
	// Look for a key that starts with this zone name
	prefix := "K" + zoneName

	// First pass: look for ED25519 (algorithm 15)
	for _, keyName := range keys {
		if strings.HasPrefix(keyName, prefix) && strings.Contains(keyName, "+015+") {
			return keyName, nil
		}
	}

	// Second pass: return any other algorithm if ED25519 not found
	for _, keyName := range keys {
		if strings.HasPrefix(keyName, prefix) {
			return keyName, nil
		}
	}

	return "", fmt.Errorf("no key found for zone %s in keystore %s", zoneName, keystoreDir)
}

// KeyName returns the formatted key filename for this record (without extensions)
func (lk *LoadedKey) KeyName() string {
	zone := lk.PublicKey.Hdr.Name
	return fmt.Sprintf("K%s+%03d+%d", zone, lk.PublicKey.Algorithm, lk.PublicKey.KeyTag())
}

// Algorithm returns the DNSSEC algorithm number
func (lk *LoadedKey) Algorithm() uint8 {
	return lk.PublicKey.Algorithm
}

// AlgorithmName returns a string name for the algorithm
func (lk *LoadedKey) AlgorithmName() string {
	if name, ok := dns.AlgorithmToString[lk.PublicKey.Algorithm]; ok {
		return name
	}
	return fmt.Sprintf("Algorithm%d", lk.PublicKey.Algorithm)
}

// KeyTag returns the key tag from the public key
func (lk *LoadedKey) KeyTag() uint16 {
	return lk.PublicKey.KeyTag()
}

// String returns a human-readable representation
func (lk *LoadedKey) String() string {
	return fmt.Sprintf("LoadedKey{Name:%s, Zone:%s, Algorithm:%s, KeyTag:%d}",
		lk.Name, lk.PublicKey.Hdr.Name, lk.AlgorithmName(), lk.KeyTag())
}
