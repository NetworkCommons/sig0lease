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

	if err := h.authorizeKeyRefresh(otherKeySameName, keyIDFromKEY(otherKeySameName)); err == nil {
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

func TestAuthorizeKeyRefresh_SelfSignerCanRefreshOwnKey(t *testing.T) {
	h := NewUpdateHandler()
	ctx := context.Background()
	key := testKeyRR("test.dev.zenr.io.", "AAAASELF111=")

	if err := h.leaseManager.Register(ctx, key, 60, 60, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease: %v", err)
	}

	refreshCopy := key.Clone().(*dns.KEY)
	if err := h.authorizeKeyRefresh(refreshCopy, keyIDFromKEY(key)); err != nil {
		t.Fatalf("expected self-refresh to be authorized, got: %v", err)
	}
}

func TestAuthorizeKeyRefresh_RegisteredParentCanRefreshChildKey(t *testing.T) {
	h := NewUpdateHandler()
	ctx := context.Background()
	parentKey := testKeyRR("test.dev.zenr.io.", "AAAAPARENT111=")
	childKey := testKeyRR("client.test.dev.zenr.io.", "AAAACHILD111=")

	treeStore, ok := h.leaseManager.(lease.HierarchicalLeaseStore)
	if !ok {
		t.Fatalf("expected hierarchical lease store")
	}
	if err := h.leaseManager.Register(ctx, parentKey, 60, 60, "dev.zenr.io."); err != nil {
		t.Fatalf("register parent: %v", err)
	}
	if err := treeStore.RegisterWithParent(ctx, lease.NodeKey(parentKey), childKey, 60, 60, "dev.zenr.io."); err != nil {
		t.Fatalf("register child under parent: %v", err)
	}

	refreshCopy := childKey.Clone().(*dns.KEY)
	if err := h.authorizeKeyRefresh(refreshCopy, keyIDFromKEY(parentKey)); err != nil {
		t.Fatalf("expected the registered parent to be able to refresh its child, got: %v", err)
	}
}

// TestAuthorizeKeyRefresh_ForeignSignerCannotHijackEvenWithMatchingRDATA is
// the core regression case: KEY RDATA is public DNS data, so matching RDATA
// alone (what the old validateRefreshOwnership checked) must never be
// sufficient to authorize a "refresh" -- the signer must actually be the
// node's owner.
func TestAuthorizeKeyRefresh_ForeignSignerCannotHijackEvenWithMatchingRDATA(t *testing.T) {
	h := NewUpdateHandler()
	ctx := context.Background()
	victimKey := testKeyRR("test.dev.zenr.io.", "AAAAVICTIM111=")
	attackerKey := testKeyRR("attacker.dev.zenr.io.", "AAAAATTACKER111=")

	if err := h.leaseManager.Register(ctx, victimKey, 60, 60, "dev.zenr.io."); err != nil {
		t.Fatalf("register victim: %v", err)
	}

	// The attacker resubmits a byte-for-byte copy of the victim's public KEY
	// RDATA -- exactly what is visible to anyone via a DNS query -- signed
	// by its own, entirely unrelated key.
	copiedVictimKey := victimKey.Clone().(*dns.KEY)
	if err := h.authorizeKeyRefresh(copiedVictimKey, keyIDFromKEY(attackerKey)); err == nil {
		t.Fatalf("expected refresh by an unrelated signer to be rejected")
	}

	if got := h.leaseManager.LookupByKEY(victimKey); got == nil || got.ParentKeyName != "" {
		t.Fatalf("expected victim key to remain an untouched self-registered root node, got %+v", got)
	}
}
