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

// TestUpsertNonKEYRecords_RejectsDifferentOwnerForIdenticalRR is the core
// property the reshape from owner-nested to flat, globally-identity-keyed
// non-KEY storage exists for: "two different keys cannot register the
// identical RR" (protocol.md) is now enforced by the store itself, not by a
// caller checking first. It also verifies the batch fails atomically: a
// second, non-conflicting record in the same call must not be applied
// either when the batch as a whole is rejected.
func TestUpsertNonKEYRecords_RejectsDifferentOwnerForIdenticalRR(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	ownerA := testKeyRR("ownera.dev.zenr.io.", "AAAAOWNERA=")
	ownerB := testKeyRR("ownerb.dev.zenr.io.", "AAAAOWNERB=")
	if err := store.Register(ctx, ownerA, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register ownerA: %v", err)
	}
	if err := store.Register(ctx, ownerB, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register ownerB: %v", err)
	}

	txt := &dns.TXT{Hdr: dns.Header{Name: "shared.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.Txt = []string{"payload"}
	if err := store.UpsertNonKEYRecords(NodeKey(ownerA), []dns.RR{txt}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert under ownerA: %v", err)
	}

	other := &dns.TXT{Hdr: dns.Header{Name: "unrelated.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	other.Txt = []string{"other"}
	if err := store.UpsertNonKEYRecords(NodeKey(ownerB), []dns.RR{txt, other}, 120, "dev.zenr.io."); err == nil {
		t.Fatalf("expected UpsertNonKEYRecords to reject a record already owned by a different node")
	}

	if existing := store.LookupNonKEYRecord(other); existing != nil {
		t.Fatalf("expected no partial application of a rejected batch, but found %q registered under %q", other.String(), existing.ParentKeyName)
	}

	existing := store.LookupNonKEYRecord(txt)
	if existing == nil || existing.ParentKeyName != NodeKey(ownerA) {
		t.Fatalf("expected record to remain owned by ownerA untouched, got %+v", existing)
	}
}

// TestListSubtreeKeys_IncludesNonKEYDescendants verifies non-KEY records are
// real participants in the tree walk (children/ListSubtreeKeys), not a
// parallel structure invisible to it, and that DeleteSubtree removes them
// as part of the same cascade that removes their owning KEY nodes.
func TestListSubtreeKeys_IncludesNonKEYDescendants(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	root := testKeyRR("root2.dev.zenr.io.", "AAAAROOT3=")
	child := testKeyRR("child2.dev.zenr.io.", "AAAACHILD3=")
	if err := store.Register(ctx, root, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register root: %v", err)
	}
	if err := store.RegisterWithParent(ctx, NodeKey(root), child, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register child: %v", err)
	}

	rootTXT := &dns.TXT{Hdr: dns.Header{Name: "root2.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	rootTXT.Txt = []string{"root-payload"}
	if err := store.UpsertNonKEYRecords(NodeKey(root), []dns.RR{rootTXT}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert root non-key record: %v", err)
	}
	childTXT := &dns.TXT{Hdr: dns.Header{Name: "child2.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	childTXT.Txt = []string{"child-payload"}
	if err := store.UpsertNonKEYRecords(NodeKey(child), []dns.RR{childTXT}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert child non-key record: %v", err)
	}

	rootTXTID := RecordKey(rootTXT)
	childTXTID := RecordKey(childTXT)

	subtree := store.ListSubtreeKeys(NodeKey(root))
	foundRootTXT, foundChild, foundChildTXT := false, false, false
	for _, id := range subtree {
		switch id {
		case rootTXTID:
			foundRootTXT = true
		case NodeKey(child):
			foundChild = true
		case childTXTID:
			foundChildTXT = true
		}
	}
	if !foundRootTXT || !foundChild || !foundChildTXT {
		t.Fatalf("expected subtree of root to include the child KEY and both non-KEY records, got %+v", subtree)
	}

	if err := store.DeleteSubtree(NodeKey(root)); err != nil {
		t.Fatalf("delete subtree: %v", err)
	}
	if store.Get(NodeKey(root)) != nil || store.Get(NodeKey(child)) != nil {
		t.Fatalf("expected KEY nodes removed")
	}
	if store.LookupNonKEYRecord(rootTXT) != nil || store.LookupNonKEYRecord(childTXT) != nil {
		t.Fatalf("expected non-KEY descendants removed by the same subtree delete")
	}
}

// TestRegisterWithParent_RejectsNonKEYNodeAsParent guards the structural
// invariant that only KEY nodes can be parents: a non-KEY node can never
// itself have children.
func TestRegisterWithParent_RejectsNonKEYNodeAsParent(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	owner := testKeyRR("owner3.dev.zenr.io.", "AAAAOWNER3=")
	if err := store.Register(ctx, owner, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register owner: %v", err)
	}
	txt := &dns.TXT{Hdr: dns.Header{Name: "data.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.Txt = []string{"payload"}
	if err := store.UpsertNonKEYRecords(NodeKey(owner), []dns.RR{txt}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert non-key record: %v", err)
	}

	nonKeyID := RecordKey(txt)
	child := testKeyRR("child3.dev.zenr.io.", "AAAACHILD4=")
	if err := store.RegisterWithParent(ctx, nonKeyID, child, 300, 300, "dev.zenr.io."); err == nil {
		t.Fatalf("expected registering a KEY under a non-KEY parent to be rejected")
	}
	if store.Get(NodeKey(child)) != nil {
		t.Fatalf("expected rejected registration to not create the child node")
	}
}

// TestLookupNonKEYRecord_GlobalRegardlessOfOwner verifies the lookup that
// replaced the old owner-scoped HasActiveNonKEYRecord: it finds a record by
// its own identity alone, with no owner argument, and returns nil for an
// RR that was never registered.
func TestLookupNonKEYRecord_GlobalRegardlessOfOwner(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	owner := testKeyRR("owner4.dev.zenr.io.", "AAAAOWNER4=")
	if err := store.Register(ctx, owner, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register owner: %v", err)
	}

	txt := &dns.TXT{Hdr: dns.Header{Name: "data4.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.Txt = []string{"payload"}

	if got := store.LookupNonKEYRecord(txt); got != nil {
		t.Fatalf("expected no record before registration, got %+v", got)
	}

	if err := store.UpsertNonKEYRecords(NodeKey(owner), []dns.RR{txt}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert non-key record: %v", err)
	}

	got := store.LookupNonKEYRecord(txt)
	if got == nil {
		t.Fatal("expected record to be found by identity")
	}
	if got.ParentKeyName != NodeKey(owner) {
		t.Fatalf("expected ParentKeyName %q, got %q", NodeKey(owner), got.ParentKeyName)
	}

	other := &dns.TXT{Hdr: dns.Header{Name: "different4.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	other.Txt = []string{"payload"}
	if got := store.LookupNonKEYRecord(other); got != nil {
		t.Fatalf("expected no match for an unregistered RR, got %+v", got)
	}
}

// TestRemoveSingleNonKEYRecord_IdempotentAndOwnershipChecked covers both
// halves of the contract: removal by a non-owner fails loudly and leaves
// the record untouched, while removing an already-absent record (the
// scenario processExpiredLease's two expiry loops can both hit for the same
// record in the same tick) is a no-op, not an error.
func TestRemoveSingleNonKEYRecord_IdempotentAndOwnershipChecked(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	ownerA := testKeyRR("ownera5.dev.zenr.io.", "AAAAOWNERA5=")
	ownerB := testKeyRR("ownerb5.dev.zenr.io.", "AAAAOWNERB5=")
	if err := store.Register(ctx, ownerA, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register ownerA: %v", err)
	}
	if err := store.Register(ctx, ownerB, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register ownerB: %v", err)
	}

	txt := &dns.TXT{Hdr: dns.Header{Name: "data5.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.Txt = []string{"payload"}
	if err := store.UpsertNonKEYRecords(NodeKey(ownerA), []dns.RR{txt}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert non-key record: %v", err)
	}
	id := RecordKey(txt)

	if err := store.RemoveSingleNonKEYRecord(NodeKey(ownerB), id); err == nil {
		t.Fatalf("expected removal by a non-owner to fail")
	}
	if store.LookupNonKEYRecord(txt) == nil {
		t.Fatalf("expected record to survive a rejected removal attempt")
	}

	if err := store.RemoveSingleNonKEYRecord(NodeKey(ownerA), id); err != nil {
		t.Fatalf("expected removal by the true owner to succeed: %v", err)
	}
	if store.LookupNonKEYRecord(txt) != nil {
		t.Fatalf("expected record removed")
	}

	if err := store.RemoveSingleNonKEYRecord(NodeKey(ownerA), id); err != nil {
		t.Fatalf("expected removing an already-absent record to be a no-op, got error: %v", err)
	}
}

// TestImportSnapshot_RejectsWrongVersion guards the clean format cut made
// when non-KEY storage moved to the flat model: a snapshot from the old
// (v1, two-slice) format must fail loudly rather than silently unmarshaling
// into an empty store.
func TestImportSnapshot_RejectsWrongVersion(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()

	if err := store.ImportSnapshot(&LeaseTreeSnapshot{Version: 1}); err == nil {
		t.Fatalf("expected importing a v1 (pre-reshape) snapshot to be rejected")
	}

	if err := store.ImportSnapshot(&LeaseTreeSnapshot{Version: leaseSnapshotVersion}); err != nil {
		t.Fatalf("expected importing an empty, correctly-versioned snapshot to succeed: %v", err)
	}
}
