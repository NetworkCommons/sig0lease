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

// LoadKeyFromFile loads a DNSSEC key from keystore files.
// Provenance: Adapted from sig0namectl's LoadKeyFile() approach
// Expects files: <keystoreDir>/<keyName>.key and <keystoreDir>/<keyName>.private
// Uses codeberg.org/miekg/dns v0.6.82 API
func LoadKeyFromFile(keystoreDir, keyName string) (*LoadedKey, error) {
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
	curdir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error:", err)
	}
	fmt.Println("Current working directory:", curdir)

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

// FindKeysByZone searches for keys by zone name in the keystore.
// Returns the key names. possibly none.
// First searches ED25519 (algorithm 15) and then other algorithms.
// Provenance: Inspired by sig0namectl's LoadOrGenerateKey()
func FindKeysByZone(keystoreDir, zoneName string) ([]string, error) {
	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}

	keys, err := ListKeysInDirectory(keystoreDir)
	if err != nil {
		return nil, err
	}

	keyNamesSet := make(map[string]struct{}, 10)

	// Key filenames are in format: Kzone.+algorithm+keytag
	// Look for a key that starts with this zone name
	prefix := "K" + zoneName

	// First pass: look for ED25519 (algorithm 15)
	for _, keyName := range keys {
		if strings.HasPrefix(keyName, prefix) && strings.Contains(keyName, "+015+") {
			if _, exists := keyNamesSet[keyName]; !exists {
				keyNamesSet[keyName] = struct{}{}
			}
		}
	}

	// Second pass: return any other algorithm if ED25519 not found
	for _, keyName := range keys {
		if strings.HasPrefix(keyName, prefix) {
			if _, exists := keyNamesSet[keyName]; !exists {
				keyNamesSet[keyName] = struct{}{}
			}
		}
	}
	// Pre-allocate slice with the exact size of the map
	keyNames := make([]string, 0, len(keyNamesSet))

	for key := range keyNamesSet {
		keyNames = append(keyNames, key)
	}
	if len(keyNames) == 0 {
		fmt.Printf("no key found for zone %s in keystore %s", zoneName, keystoreDir)
	}
	fmt.Printf("zone %s keys %v", zoneName, keyNames)
	return keyNames, nil

}

// KeyExists searches for a key by filename without .key in the keystore.
// Returns the key name or error if none found.
func KeyExists(keystoreDir, keyName string) error {

	keyFiles, err := ListKeysInDirectory(keystoreDir)
	if err != nil {
		return err
	}

	// look for public keys
	for _, keyFile := range keyFiles {
		if keyName == keyFile {
			return nil
		}
	}

	return fmt.Errorf("no key file found for key %s in keystore %s", keyName, keystoreDir)
}

// KeyFileName returns the formatted key filename for this record (without extensions)
func (lk *LoadedKey) KeyFileName() string {
	zone := lk.PublicKey.Hdr.Name
	return fmt.Sprintf("K%s+%03d+%d", zone, lk.PublicKey.Algorithm, lk.PublicKey.KeyTag())
}

// KeyName returns the key name
func (lk *LoadedKey) KeyName() string {
	return lk.PublicKey.Hdr.Name
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

// Print key info
func (lk *LoadedKey) Print() {
	fmt.Printf("Name  %s\n", lk.Name)
	fmt.Printf("    Zone: %s\n", lk.PublicKey.Hdr.Name)
	fmt.Printf("    Algorithm: %d (15=ED25519)\n", lk.PublicKey.Algorithm)
	fmt.Printf("    KeyTag: %d\n", lk.PublicKey.KeyTag())
	fmt.Printf("    Flags: %d\n", lk.PublicKey.Flags)

	// Check for private key
	if lk.PrivateKey != nil {
		fmt.Printf("    Private key: ✓ Available\n")
	} else {
		fmt.Printf("    Private key: ✗ Not available\n")
	}
	fmt.Printf("\n")

}
