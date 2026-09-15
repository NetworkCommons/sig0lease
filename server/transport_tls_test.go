// Package server implements the DNS proxy server.
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/logging"
)

// generateTestCert writes a fresh, self-signed ECDSA P-256 certificate/key pair valid for
// 127.0.0.1 to dir, returning their paths. Generated fresh per test rather than checked in:
// this is purely a transport-layer smoke test, not a fixture pinning a specific known-answer
// signature the way pkg/sig0's SIG(0) tests do.
func generateTestCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sig0lease-test-dot"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// TestServeDoT_RoundTrips confirms serveDoT actually speaks DNS-over-TLS end to end: a real
// tls.Config-equipped dns.Client (RFC 7858 client shape, ALPN "dot" included) connects,
// completes a TLS handshake against the certificate serveDoT loaded from disk, and gets back
// a correctly-routed response -- the same handler contract serveUDP/serveTCP already have to
// meet, just wrapped in TLS.
func TestServeDoT_RoundTrips(t *testing.T) {
	dotAddr := reserveAddr(t, "tcp") // DoT is TCP framing; reserveAddr has no "tls" case of its own
	certPath, keyPath := generateTestCert(t, t.TempDir())

	logger := logging.NewLogger("debug")
	srv := &Server{
		cfg: &config.Config{Server: config.ServerConfig{
			TLS: &config.TLSConfig{Address: dotAddr, Cert: certPath, Key: keyPath},
		}},
		logger: logger,
	}

	handler := dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := &dns.Msg{MsgHeader: r.MsgHeader, Question: r.Question}
		resp.Response = true
		resp.Rcode = dns.RcodeSuccess
		resp.WriteTo(w)
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.serveDoT(ctx, handler) }()

	// A plain TCP client.New probe (waitReady's own approach) can't complete a TLS
	// handshake, so poll with the real TLS client this test needs anyway.
	root := x509.NewCertPool()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert for pool: %v", err)
	}
	if !root.AppendCertsFromPEM(certPEM) {
		t.Fatalf("failed to add test cert to pool")
	}
	// NewTransport(), not a bare &dns.Transport{}: the latter leaves Dialer/ReadTimeout/
	// WriteTimeout at their zero values, which read as "no connection ever succeeds" rather
	// than "block forever" -- NewTransport's real defaults (5s dial, 2s read/write) are
	// what a real DoT client would actually use.
	transport := dns.NewTransport()
	transport.TLSConfig = &tls.Config{
		RootCAs: root,
		// Matches the certificate's IP SAN (127.0.0.1), not its CommonName -- modern Go
		// TLS verification requires a SAN match and does not fall back to CommonName.
		ServerName: "127.0.0.1",
	}
	dotClient := &dns.Client{Transport: transport}

	deadline := time.Now().Add(2 * time.Second)
	var resp *dns.Msg
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("serveDoT exited early: %v", err)
		default:
		}
		resp, _, err = dotClient.Exchange(ctx, dns.NewMsg("dot-test.example.", dns.TypeA), "tcp", dotAddr)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("DoT query never succeeded: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("got rcode=%d, want success", resp.Rcode)
	}
}

// TestServeDoT_MissingTLSConfig pins the fail-closed case: config.Config.Validate is what's
// supposed to stop this from ever happening in a real run (a "tls" network with no
// server.tls block), but serveDoT itself must not panic or silently no-op if it's ever
// reached with one anyway.
func TestServeDoT_MissingTLSConfig(t *testing.T) {
	srv := &Server{cfg: &config.Config{}, logger: logging.NewLogger("debug")}
	err := srv.serveDoT(context.Background(), dns.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) {}))
	if err == nil {
		t.Fatal("expected an error with no server.tls configured, got nil")
	}
}
