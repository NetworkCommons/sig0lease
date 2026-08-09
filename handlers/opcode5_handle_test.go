package handlers

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

func TestResolveSignerKeyForOwnershipPrefersAdditionalKey(t *testing.T) {
	h := NewUpdateHandler()
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	additional := []*dns.KEY{loaded.PublicKey.Clone().(*dns.KEY)}
	signed := buildSignedUpdateWithSignerKeyInAdditionalForTest(t, loaded, "test.dev.zenr.io.")
	sigRR, err := extractSig0(signed)
	if err != nil {
		t.Fatalf("extract sig0: %v", err)
	}

	got, err := h.resolveSignerKeyForOwnership(sigRR, additional, nil)
	if err != nil {
		t.Fatalf("expected signer key, got error: %v", err)
	}
	if got == nil || got.Hdr.Name != loaded.PublicKey.Hdr.Name {
		t.Fatalf("expected additional signing key owner, got %+v", got)
	}
}

func TestResolveSignerKeyForOwnershipUsesLeaseStoreWhenRequestMissing(t *testing.T) {
	h := NewUpdateHandler()
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	leaseKey := loaded.PublicKey.Clone().(*dns.KEY)
	signed := buildSignedUpdateForTest(t, loaded, "test.dev.zenr.io.")
	sigRR, err := extractSig0(signed)
	if err != nil {
		t.Fatalf("extract sig0: %v", err)
	}
	if err := h.leaseManager.Register(context.Background(), leaseKey, 60, 60, "example."); err != nil {
		t.Fatalf("register lease key: %v", err)
	}

	got, err := h.resolveSignerKeyForOwnership(sigRR, nil, nil)
	if err != nil {
		t.Fatalf("expected lease-store signer key, got error: %v", err)
	}
	if got == nil || got.Hdr.Name != loaded.PublicKey.Hdr.Name {
		t.Fatalf("expected lease-store signer key, got %+v", got)
	}
}

func TestResolveSignerKeyForOwnershipRejectsMissingKeyMaterial(t *testing.T) {
	h := NewUpdateHandler()
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	signed := buildSignedUpdateForTest(t, loaded, "test.dev.zenr.io.")
	sigRR, err := extractSig0(signed)
	if err != nil {
		t.Fatalf("extract sig0: %v", err)
	}

	got, err := h.resolveSignerKeyForOwnership(sigRR, nil, nil)
	if err == nil {
		t.Fatalf("expected error, got signer key %+v", got)
	}
}
