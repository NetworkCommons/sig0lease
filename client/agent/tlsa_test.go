package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCert writes a new self-signed certificate, with a new key, to path, after the PEM
// blocks in before (such as its private key, as some servers keep them in one file), and
// returns the SHA-256 of its public key in hex: a TLSA 3 1 1 record's data.
func writeCert(t *testing.T, path string, before ...*pem.Block) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "a.dev.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	for _, b := range append(before, &pem.Block{Type: "CERTIFICATE", Bytes: der}) {
		data = append(data, pem.EncodeToMemory(b)...)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// The TLSA record matches the first certificate's public key, whatever precedes it; a file
// without a certificate, or none, is an error.
func TestTLSARecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.pem")
	spki := writeCert(t, path, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not read")})
	rr, err := TLSARecord("_5269._tcp.a.dev.test.", path)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Hdr.Name != "_5269._tcp.a.dev.test." || rr.Usage != 3 || rr.Selector != 1 || rr.MatchingType != 1 || rr.Certificate != spki {
		t.Errorf("TLSARecord = %s, want _5269._tcp.a.dev.test. TLSA 3 1 1 %s", rr, spki)
	}

	if err := os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := TLSARecord("x.", path); err == nil || !strings.Contains(err.Error(), "no PEM CERTIFICATE block") {
		t.Errorf("TLSARecord of a file without a certificate = %v, want no PEM CERTIFICATE block", err)
	}
	if _, err := TLSARecord("x.", filepath.Join(dir, "none.pem")); err == nil {
		t.Error("TLSARecord of a missing file succeeded")
	}
}
