package handlers

import (
	"context"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	lease "github.com/NetworkCommons/sig0lease/pkg/lease"
)

func testKeyRR(name, pub string) *dns.KEY {
	k := &dns.KEY{
		DNSKEY: dns.DNSKEY{
			Hdr: dns.Header{
				Name:  name,
				Class: dns.ClassINET,
				TTL:   3600,
			},
		},
	}
	k.Flags = 512
	k.Protocol = 3
	k.Algorithm = 15
	k.PublicKey = pub
	return k
}

func TestLeaseExpiresAndRemoved(t *testing.T) {
	h := NewUpdateHandler()
	ctx := context.Background()
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY111=")

	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(key))
	defer h.clearLeaseTimer(lease.NodeKey(key))

	if h.leaseManager.LookupByKEY(key) == nil {
		t.Fatalf("expected active lease immediately after registration")
	}

	time.Sleep(1500 * time.Millisecond)

	if got := h.leaseManager.LookupByKEY(key); got != nil {
		t.Fatalf("expected lease removed after expiry")
	}
}

func TestLeaseRenewedAndNotRemovedPrematurely(t *testing.T) {
	h := NewUpdateHandler()
	ctx := context.Background()
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY222=")

	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(key))
	defer h.clearLeaseTimer(lease.NodeKey(key))

	time.Sleep(500 * time.Millisecond)

	if err := h.leaseManager.Register(ctx, key, 2, 2, "dev.zenr.io."); err != nil {
		t.Fatalf("refresh lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(key))

	time.Sleep(800 * time.Millisecond)
	if h.leaseManager.LookupByKEY(key) == nil {
		t.Fatalf("expected lease to remain active after renewal")
	}

	time.Sleep(1700 * time.Millisecond)
	if got := h.leaseManager.LookupByKEY(key); got != nil {
		t.Fatalf("expected renewed lease to be removed after extended expiry")
	}
}

func TestRefreshRejectedForDifferentKeyAndExpires(t *testing.T) {
	h := NewUpdateHandler()
	ctx := context.Background()
	leaseKey := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY333=")
	otherKeySameName := testKeyRR("test.dev.zenr.io.", "BBBBOTHERKEY999=")

	if err := h.leaseManager.Register(ctx, leaseKey, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(leaseKey))
	defer h.clearLeaseTimer(lease.NodeKey(leaseKey))

	if err := h.validateRefreshOwnership(otherKeySameName); err == nil {
		t.Fatalf("expected refresh ownership validation to reject mismatched key")
	}

	if h.leaseManager.LookupByKEY(leaseKey) == nil {
		t.Fatalf("expected original lease to remain active after rejected refresh")
	}

	time.Sleep(1500 * time.Millisecond)
	if got := h.leaseManager.LookupByKEY(leaseKey); got != nil {
		t.Fatalf("expected lease removed after expiry even after rejected refresh")
	}
}
