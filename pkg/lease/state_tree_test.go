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

	if err := store.Register(ctx, root.Hdr.Name, root, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register root: %v", err)
	}
	if err := store.RegisterWithParent(ctx, root.Hdr.Name, child.Hdr.Name, child, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register child with parent: %v", err)
	}

	gotChild := store.Get(child.Hdr.Name)
	if gotChild == nil {
		t.Fatal("expected child record")
	}
	if gotChild.ParentKeyName != "root.dev.zenr.io" {
		t.Fatalf("unexpected parent key: %q", gotChild.ParentKeyName)
	}

	kids := store.ChildrenOf(root.Hdr.Name)
	if len(kids) != 1 || kids[0] != "child.dev.zenr.io" {
		t.Fatalf("unexpected children: %+v", kids)
	}
}

func TestDeleteSubtree_RemovesDescendants(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	root := testKeyRR("root.dev.zenr.io.", "AAAAROOT=")
	child := testKeyRR("child.dev.zenr.io.", "AAAACHILD=")
	grand := testKeyRR("grand.dev.zenr.io.", "AAAAGRAND=")

	if err := store.Register(ctx, root.Hdr.Name, root, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register root: %v", err)
	}
	if err := store.RegisterWithParent(ctx, root.Hdr.Name, child.Hdr.Name, child, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register child: %v", err)
	}
	if err := store.RegisterWithParent(ctx, child.Hdr.Name, grand.Hdr.Name, grand, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register grandchild: %v", err)
	}

	if err := store.DeleteSubtree(root.Hdr.Name); err != nil {
		t.Fatalf("delete subtree: %v", err)
	}

	if store.Get(root.Hdr.Name) != nil || store.Get(child.Hdr.Name) != nil || store.Get(grand.Hdr.Name) != nil {
		t.Fatal("expected entire subtree removed")
	}
}

func TestSnapshot_SaveLoad_RoundTrip(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	root := testKeyRR("root.dev.zenr.io.", "AAAAROOT=")
	child := testKeyRR("child.dev.zenr.io.", "AAAACHILD=")

	if err := store.Register(ctx, root.Hdr.Name, root, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register root: %v", err)
	}
	if err := store.RegisterWithParent(ctx, root.Hdr.Name, child.Hdr.Name, child, 300, 300, "dev.zenr.io."); err != nil {
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

	if loaded.Get(root.Hdr.Name) == nil || loaded.Get(child.Hdr.Name) == nil {
		t.Fatal("expected loaded records")
	}
	if loaded.Get(child.Hdr.Name).ParentKeyName != "root.dev.zenr.io" {
		t.Fatalf("unexpected loaded parent: %q", loaded.Get(child.Hdr.Name).ParentKeyName)
	}
	kids := loaded.ChildrenOf(root.Hdr.Name)
	if len(kids) != 1 || kids[0] != "child.dev.zenr.io" {
		t.Fatalf("unexpected loaded children: %+v", kids)
	}
}

func TestCleanupExpired_DeletesSubtree(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	root := testKeyRR("root.dev.zenr.io.", "AAAAROOT=")
	child := testKeyRR("child.dev.zenr.io.", "AAAACHILD=")

	if err := store.Register(ctx, root.Hdr.Name, root, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register root: %v", err)
	}
	if err := store.RegisterWithParent(ctx, root.Hdr.Name, child.Hdr.Name, child, 3600, 3600, "dev.zenr.io."); err != nil {
		t.Fatalf("register child: %v", err)
	}

	time.Sleep(1200 * time.Millisecond)
	store.cleanupExpired()

	if store.Get(root.Hdr.Name) != nil || store.Get(child.Hdr.Name) != nil {
		t.Fatal("expected expired root subtree removed")
	}
}

func TestNonKEYRecords_AreTreeNodesWithBaseRecordFields(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	owner := testKeyRR("owner.dev.zenr.io.", "AAAAOWNER=")
	if err := store.Register(ctx, owner.Hdr.Name, owner, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register owner: %v", err)
	}

	txt := &dns.TXT{Hdr: dns.Header{Name: "host.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.Txt = []string{"payload"}
	if err := store.UpsertNonKEYRecords(owner.Hdr.Name, []dns.RR{txt}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert non-key records: %v", err)
	}

	set := store.GetNonKEYRecordSet(owner.Hdr.Name)
	if set == nil || len(set.Records) != 1 {
		t.Fatalf("expected one non-key record, got %+v", set)
	}

	for _, rec := range set.Records {
		if rec.NodeKind != NodeKindNonKEY {
			t.Fatalf("expected node kind non-key, got %q", rec.NodeKind)
		}
		if rec.ParentKeyName != "owner.dev.zenr.io" {
			t.Fatalf("unexpected parent key: %q", rec.ParentKeyName)
		}
		if rec.OwnerKeyName != "owner.dev.zenr.io" {
			t.Fatalf("unexpected owner key: %q", rec.OwnerKeyName)
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
	if err := store.Register(ctx, owner.Hdr.Name, owner, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register owner: %v", err)
	}
	txt := &dns.TXT{Hdr: dns.Header{Name: "host.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.Txt = []string{"payload"}
	if err := store.UpsertNonKEYRecords(owner.Hdr.Name, []dns.RR{txt}, 120, "dev.zenr.io."); err != nil {
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

	if loaded.Get(owner.Hdr.Name) == nil {
		t.Fatal("expected loaded key record")
	}
	loadedSet := loaded.GetNonKEYRecordSet(owner.Hdr.Name)
	if loadedSet == nil || len(loadedSet.Records) != 1 {
		t.Fatalf("expected one loaded non-key record, got %+v", loadedSet)
	}
}
