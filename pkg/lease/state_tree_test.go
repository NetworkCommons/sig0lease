package lease

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func testKeyRR(name, pub string) *dns.KEY {
	k := &dns.KEY{DNSKEY: dns.DNSKEY{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 120}}}
	k.Flags = 512
	k.Protocol = 3
	k.Algorithm = 15
	k.PublicKey = pub
	return k
}

func TestRegisterWithParent_BuildsTree(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	root := testKeyRR("root.dev.zenr.io.", "AAAAROOT=")
	child := testKeyRR("child.dev.zenr.io.", "AAAACHILD=")

	if err := store.Register(ctx, root, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register root: %v", err)
	}
	if err := store.RegisterWithParent(ctx, NodeKey(root), child, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register child with parent: %v", err)
	}

	gotChild := store.Get(NodeKey(child))
	if gotChild == nil {
		t.Fatal("expected child record")
	}
	if gotChild.ParentKeyName != NodeKey(root) {
		t.Fatalf("unexpected parent key: %q", gotChild.ParentKeyName)
	}

	kids := store.ChildrenOf(NodeKey(root))
	if len(kids) != 1 || kids[0] != NodeKey(child) {
		t.Fatalf("unexpected children: %+v", kids)
	}
}

// TestRenewLease_PreservesIdentityAndRegisteredAt is the regression case for
// the design this replaced: Register/RegisterWithParent rebuilt the whole
// node on every call, including a fresh RegisteredAt and a detach/reattach
// of the same parent -- so a lease's "originally registered at" timestamp
// was silently reset on every refresh. RenewLease must only move the expiry
// forward, leaving identity (ParentKeyName, RegisteredAt, tree position)
// untouched.
func TestRenewLease_PreservesIdentityAndRegisteredAt(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	root := testKeyRR("root.dev.zenr.io.", "AAAAROOT2=")
	child := testKeyRR("child.dev.zenr.io.", "AAAACHILD2=")

	if err := store.Register(ctx, root, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register root: %v", err)
	}
	if err := store.RegisterWithParent(ctx, NodeKey(root), child, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register child with parent: %v", err)
	}

	before := store.Get(NodeKey(child))
	if before == nil {
		t.Fatal("expected child record")
	}
	registeredAt := before.RegisteredAt
	parentKeyName := before.ParentKeyName
	expiresAt := before.ExpiresAt

	time.Sleep(5 * time.Millisecond)

	if err := store.RenewLease(ctx, child, 600, 600); err != nil {
		t.Fatalf("renew child: %v", err)
	}

	after := store.Get(NodeKey(child))
	if after == nil {
		t.Fatal("expected child record after renew")
	}
	if !after.RegisteredAt.Equal(registeredAt) {
		t.Fatalf("expected RegisteredAt to survive a renew unchanged, got %v want %v", after.RegisteredAt, registeredAt)
	}
	if after.ParentKeyName != parentKeyName {
		t.Fatalf("expected ParentKeyName to survive a renew unchanged, got %q want %q", after.ParentKeyName, parentKeyName)
	}
	if after.LeaseDuration != 600 || after.KeyLeaseDuration != 600 {
		t.Fatalf("expected renewed durations to be applied, got lease=%d key-lease=%d", after.LeaseDuration, after.KeyLeaseDuration)
	}
	if !after.ExpiresAt.After(expiresAt) {
		t.Fatalf("expected ExpiresAt to move forward after renew, got %v (was %v)", after.ExpiresAt, expiresAt)
	}

	kids := store.ChildrenOf(NodeKey(root))
	if len(kids) != 1 || kids[0] != NodeKey(child) {
		t.Fatalf("expected tree structure untouched by renew, got children: %+v", kids)
	}
}

func TestRenewLease_RejectsUnregisteredKey(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	neverRegistered := testKeyRR("ghost.dev.zenr.io.", "AAAAGHOST=")
	if err := store.RenewLease(ctx, neverRegistered, 60, 60); err == nil {
		t.Fatalf("expected renewing a never-registered key to fail")
	}
}

func TestDeleteSubtree_RemovesDescendants(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	root := testKeyRR("root.dev.zenr.io.", "AAAAROOT=")
	child := testKeyRR("child.dev.zenr.io.", "AAAACHILD=")
	grand := testKeyRR("grand.dev.zenr.io.", "AAAAGRAND=")

	if err := store.Register(ctx, root, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register root: %v", err)
	}
	if err := store.RegisterWithParent(ctx, NodeKey(root), child, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register child: %v", err)
	}
	if err := store.RegisterWithParent(ctx, NodeKey(child), grand, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register grandchild: %v", err)
	}

	if err := store.DeleteSubtree(NodeKey(root)); err != nil {
		t.Fatalf("delete subtree: %v", err)
	}

	if store.Get(NodeKey(root)) != nil || store.Get(NodeKey(child)) != nil || store.Get(NodeKey(grand)) != nil {
		t.Fatal("expected entire subtree removed")
	}
}

func TestSnapshot_SaveLoad_RoundTrip(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	root := testKeyRR("root.dev.zenr.io.", "AAAAROOT=")
	child := testKeyRR("child.dev.zenr.io.", "AAAACHILD=")

	if err := store.Register(ctx, root, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register root: %v", err)
	}
	if err := store.RegisterWithParent(ctx, NodeKey(root), child, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register child: %v", err)
	}

	path := filepath.Join(t.TempDir(), "lease_snapshot.json")
	if err := store.SaveSnapshot(path); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	loaded := NewInMemoryManager()
	defer loaded.Stop()
	if err := loaded.LoadSnapshot(path); err != nil {
		t.Fatalf("load snapshot: %v", err)
	}

	if loaded.Get(NodeKey(root)) == nil || loaded.Get(NodeKey(child)) == nil {
		t.Fatal("expected loaded records")
	}
	if loaded.Get(NodeKey(child)).ParentKeyName != NodeKey(root) {
		t.Fatalf("unexpected loaded parent: %q", loaded.Get(NodeKey(child)).ParentKeyName)
	}
	kids := loaded.ChildrenOf(NodeKey(root))
	if len(kids) != 1 || kids[0] != NodeKey(child) {
		t.Fatalf("unexpected loaded children: %+v", kids)
	}
}

func TestNonKEYRecords_AreTreeNodesWithBaseRecordFields(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	owner := testKeyRR("owner.dev.zenr.io.", "AAAAOWNER=")
	if err := store.Register(ctx, owner, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register owner: %v", err)
	}

	txt := &dns.TXT{Hdr: dns.Header{Name: "host.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.Txt = []string{"payload"}
	if err := store.UpsertNonKEYRecords(NodeKey(owner), []dns.RR{txt}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert non-key records: %v", err)
	}

	set := store.GetNonKEYRecordSet(NodeKey(owner))
	if set == nil || len(set.Records) != 1 {
		t.Fatalf("expected one non-key record, got %+v", set)
	}

	for _, rec := range set.Records {
		if rec.NodeKind != NodeKindNonKEY {
			t.Fatalf("expected node kind non-key, got %q", rec.NodeKind)
		}
		if rec.ParentKeyName != NodeKey(owner) {
			t.Fatalf("unexpected parent key: %q", rec.ParentKeyName)
		}
		if rec.LeaseDuration != 120 {
			t.Fatalf("unexpected lease duration: %d", rec.LeaseDuration)
		}
	}
}

func TestSnapshot_SaveLoad_RoundTripWithNonKEYRecords(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	owner := testKeyRR("owner.dev.zenr.io.", "AAAAOWNER=")
	if err := store.Register(ctx, owner, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register owner: %v", err)
	}
	txt := &dns.TXT{Hdr: dns.Header{Name: "host.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.Txt = []string{"payload"}
	if err := store.UpsertNonKEYRecords(NodeKey(owner), []dns.RR{txt}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert non-key records: %v", err)
	}

	path := filepath.Join(t.TempDir(), "lease_snapshot_with_non_key.json")
	if err := store.SaveSnapshot(path); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	loaded := NewInMemoryManager()
	defer loaded.Stop()
	if err := loaded.LoadSnapshot(path); err != nil {
		t.Fatalf("load snapshot: %v", err)
	}

	if loaded.Get(NodeKey(owner)) == nil {
		t.Fatal("expected loaded key record")
	}
	loadedSet := loaded.GetNonKEYRecordSet(NodeKey(owner))
	if loadedSet == nil || len(loadedSet.Records) != 1 {
		t.Fatalf("expected one loaded non-key record, got %+v", loadedSet)
	}
}
