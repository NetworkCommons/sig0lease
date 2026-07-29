package handlers

import (
	"context"
	"fmt"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

func buildSignedUpdateForTest(t *testing.T, signerKey *keyrec.LoadedKey, leaseOwner string) *dns.Msg {
	t.Helper()

	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate
	txt := &dns.TXT{Hdr: dns.Header{Name: leaseOwner, Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"payload"}
	msg.Ns = append(msg.Ns, txt)

	signed, err := sig0.SignMessage(msg, signerKey.PublicKey, signerKey.PrivateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}
	return signed
}

func buildSignedUpdateWithSignerKeyInUpdateForTest(t *testing.T, signerKey *keyrec.LoadedKey, leaseOwner string) *dns.Msg {
	t.Helper()

	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	keyRR := signerKey.PublicKey.Clone().(*dns.KEY)
	keyRR.Hdr.Name = signerKey.PublicKey.Hdr.Name
	msg.Ns = append(msg.Ns, keyRR)

	txt := &dns.TXT{Hdr: dns.Header{Name: leaseOwner, Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"payload"}
	msg.Ns = append(msg.Ns, txt)

	signed, err := sig0.SignMessage(msg, signerKey.PublicKey, signerKey.PrivateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}
	return signed
}

func TestExtractAndValidateSig0_UsesAuthoritativeSignerKey(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFiles(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := newTestHandler()
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType != dns.TypeKEY {
			return nil, nil
		}
		return []dns.RR{loaded.PublicKey}, nil
	}

	signed := buildSignedUpdateForTest(t, loaded, "test.dev.zenr.io.")
	sig, resolved, err := h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", "test.dev.zenr.io.", nil)
	if err != nil {
		t.Fatalf("expected validation success: %v", err)
	}
	if sig == nil || resolved == nil {
		t.Fatalf("expected non-nil signature and key")
	}
	if resolved.KeyTag() != loaded.PublicKey.KeyTag() {
		t.Fatalf("expected resolved key tag %d, got %d", loaded.PublicKey.KeyTag(), resolved.KeyTag())
	}
}

func TestExtractAndValidateSig0_RejectsSignerOutsideLeaseHierarchy(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFiles(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	outsideSigner := loaded.PublicKey.Clone().(*dns.KEY)
	outsideSigner.Hdr.Name = "outside.example.org."
	outsideLoaded := &keyrec.LoadedKey{
		Name:       loaded.Name,
		PublicKey:  outsideSigner,
		PrivateKey: loaded.PrivateKey,
	}

	h := newTestHandler()
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType != dns.TypeKEY {
			return nil, nil
		}
		return []dns.RR{outsideSigner}, nil
	}

	signed := buildSignedUpdateForTest(t, outsideLoaded, "test.dev.zenr.io.")
	_, _, err = h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", "test.dev.zenr.io.", nil)
	if err == nil {
		t.Fatalf("expected hierarchy validation failure")
	}
}

func TestExtractAndValidateSig0_DNSFailureDoesNotFallbackToLeaseStore(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFiles(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := newTestHandler()
	if err := h.leaseManager.Register(context.Background(), loaded.PublicKey.Hdr.Name, loaded.PublicKey, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease key: %v", err)
	}
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		return nil, fmt.Errorf("authoritative DNS unavailable")
	}

	signed := buildSignedUpdateForTest(t, loaded, "test.dev.zenr.io.")
	_, _, err = h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", "test.dev.zenr.io.", nil)
	if err == nil {
		t.Fatalf("expected failure when authoritative lookup fails")
	}
}

func TestExtractAndValidateSig0_DNSNoKeyFallsBackToLeaseStore(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFiles(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := newTestHandler()
	if err := h.leaseManager.Register(context.Background(), loaded.PublicKey.Hdr.Name, loaded.PublicKey, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease key: %v", err)
	}
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		return []dns.RR{}, nil
	}

	signed := buildSignedUpdateForTest(t, loaded, "test.dev.zenr.io.")
	_, resolved, err := h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", "test.dev.zenr.io.", nil)
	if err != nil {
		t.Fatalf("expected fallback success when authoritative DNS returns no signer key: %v", err)
	}
	if resolved == nil {
		t.Fatalf("expected resolved signer key")
	}
}

func TestExtractAndValidateSig0_RequestKeyWorksWhenDnsAndLeaseStoreDontHaveSigner(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFiles(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := newTestHandler()
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		// DNS is reachable, but has no signer KEY.
		return []dns.RR{}, nil
	}

	// No key is registered in lease-store; signer key is only in UPDATE section.
	signed := buildSignedUpdateWithSignerKeyInUpdateForTest(t, loaded, "test.dev.zenr.io.")
	requestKey := loaded.PublicKey.Clone().(*dns.KEY)

	_, resolved, err := h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", "test.dev.zenr.io.", requestKey)
	if err != nil {
		t.Fatalf("expected validation success using request KEY only: %v", err)
	}
	if resolved == nil {
		t.Fatalf("expected resolved signer key")
	}
}
