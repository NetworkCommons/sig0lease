package lease

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// testKeyRR returns a KEY RR at name whose public key is the base64 encoding of label, so
// distinct labels give distinct keys and every key packs (snapshots store KEYs in wire format).
func testKeyRR(name, label string) *dns.KEY {
	k := &dns.KEY{DNSKEY: dns.DNSKEY{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 120}}}
	k.Flags = 512
	k.Protocol = 3
	k.Algorithm = 15
	k.PublicKey = base64.StdEncoding.EncodeToString([]byte(label))
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

// TestSnapshot_SaveLoad_RoundTripsDNSSDNames pins the snapshot to every octet of a DNS-SD
// name: an Instance label with spaces, uppercase and UTF-8 (RFC 6763 S4.1.1), and a subtype
// label of non-UTF-8 bytes (S7.1), as owner names and inside PTR RDATA. Presentation text
// can't carry the first -- the dns library neither escapes nor unescapes it, so a reloaded
// "Freifunk Café._http._tcp..." parsed as owner "Freifunk" and failed -- and JSON strings
// can't carry the second. It also checks the file still shows the records readably.
func TestSnapshot_SaveLoad_RoundTripsDNSSDNames(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	const (
		instance = "Freifunk Café._http._tcp.dev.zenr.io."
		subtype  = "\xff\xfe._sub._http._tcp.dev.zenr.io."
	)
	owner := testKeyRR(instance, "AAAAOWNER=")
	if err := store.Register(ctx, owner, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register owner: %v", err)
	}
	hdr := func(name string) dns.Header {
		return dns.Header{Name: name, Class: dns.ClassINET, TTL: 60}
	}
	srv := &dns.SRV{Hdr: hdr(instance)}
	srv.Port, srv.Target = 668, "host.dev.zenr.io."
	txt := &dns.TXT{Hdr: hdr(instance)}
	txt.Txt = []string{"path=/daemon"}
	ptr := &dns.PTR{Hdr: hdr("_http._tcp.dev.zenr.io.")}
	ptr.Ptr = instance
	subPTR := &dns.PTR{Hdr: hdr(subtype)}
	subPTR.Ptr = instance
	records := []dns.RR{srv, txt, ptr, subPTR}
	if err := store.UpsertNonKEYRecords(NodeKey(owner), records, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert non-key records: %v", err)
	}

	path := filepath.Join(t.TempDir(), "lease_snapshot_dnssd_names.json")
	if err := store.SaveSnapshot(path); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if !strings.Contains(string(data), "Freifunk Café._http._tcp.dev.zenr.io.\\t60\\tIN\\tSRV\\t0 0 668 host.dev.zenr.io.") {
		t.Errorf("snapshot does not show the SRV record readably:\n%s", data)
	}

	loaded := NewInMemoryManager()
	defer loaded.Stop()
	if err := loaded.LoadSnapshot(path); err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if set := loaded.GetNonKEYRecordSet(NodeKey(owner)); set == nil || len(set.Records) != len(records) {
		t.Fatalf("expected %d non-key records under the owner, got %+v", len(records), set)
	}
	for _, want := range records {
		got := loaded.LookupNonKEYRecord(want)
		if got == nil {
			t.Errorf("record not found after reload: %q", want.String())
			continue
		}
		if got.RR.String() != want.String() {
			t.Errorf("record changed across reload:\n got  %q\n want %q", got.RR.String(), want.String())
		}
	}
}

// TestSnapshot_SaveLoad_RoundTripsArbitraryNameBytes covers the names node_id and
// parent_key_name hold, beyond what DNS-SD needs: a KEY owner registered through RFC 9664 can
// be any bytes (RFC 2181 S11), including ones that aren't UTF-8 or that the escaping itself
// uses, and a name that begins with a space is a different name from the one without it. Each
// must reload as its own node, with its children, and a node_id that doesn't match its key
// must be refused.
func TestSnapshot_SaveLoad_RoundTripsArbitraryNameBytes(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()

	const odd = "\xff\x00\"\\.dev.zenr.io."
	parent := testKeyRR(odd, "PARENT")
	child := testKeyRR("child."+odd, "CHILD")
	lead := testKeyRR(" lead.dev.zenr.io.", "LEAD")
	plain := testKeyRR("lead.dev.zenr.io.", "PLAIN")
	for _, k := range []*dns.KEY{parent, lead, plain} {
		if err := store.Register(ctx, k, 300, 300, "dev.zenr.io."); err != nil {
			t.Fatalf("register %q: %v", k.Hdr.Name, err)
		}
	}
	if err := store.RegisterWithParent(ctx, NodeKey(parent), child, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register child: %v", err)
	}
	a := &dns.A{Hdr: dns.Header{Name: odd, Class: dns.ClassINET, TTL: 60}}
	a.A.Addr = netip.MustParseAddr("192.0.2.1")
	if err := store.UpsertNonKEYRecords(NodeKey(parent), []dns.RR{a}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert non-key record: %v", err)
	}

	path := filepath.Join(t.TempDir(), "lease_snapshot_arbitrary_names.json")
	if err := store.SaveSnapshot(path); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	loaded := NewInMemoryManager()
	defer loaded.Stop()
	if err := loaded.LoadSnapshot(path); err != nil {
		t.Fatalf("load snapshot: %v", err)
	}

	for _, k := range []*dns.KEY{parent, child, lead, plain} {
		rec := loaded.Get(NodeKey(k))
		if rec == nil {
			t.Errorf("KEY %q not found after reload", k.Hdr.Name)
			continue
		}
		if rec.KeyRR.Hdr.Name != k.Hdr.Name {
			t.Errorf("KEY owner changed across reload: got %q, want %q", rec.KeyRR.Hdr.Name, k.Hdr.Name)
		}
	}
	kids := map[string]bool{}
	for _, id := range loaded.ChildrenOf(NodeKey(parent)) {
		kids[id] = true
	}
	if !kids[NodeKey(child)] || !kids[RecordKey(a)] || len(kids) != 2 {
		t.Errorf("children of %q after reload = %q, want the child KEY and the A record", odd, loaded.ChildrenOf(NodeKey(parent)))
	}
	for _, k := range []*dns.KEY{lead, plain} {
		if recs := loaded.FindByName(k.Hdr.Name); len(recs) != 1 || recs[0].KeyRR.Hdr.Name != k.Hdr.Name {
			t.Errorf("FindByName(%q) after reload = %d record(s), want just that name's KEY", k.Hdr.Name, len(recs))
		}
	}

	snap, err := store.ExportSnapshot()
	if err != nil {
		t.Fatalf("export snapshot: %v", err)
	}
	for i := range snap.Nodes {
		if snap.Nodes[i].NodeKind == NodeKindKEY {
			snap.Nodes[i].NodeID = quoteNodeKey(NodeKey(plain))
		}
	}
	if err := NewInMemoryManager().ImportSnapshot(snap); err == nil {
		t.Error("expected a KEY node whose node_id isn't its key's to be refused")
	}
}

// TestUpsertNonKEYRecords_RejectsDifferentOwnerForIdenticalRR is the core
// property the reshape from owner-nested to flat, globally-identity-keyed
// non-KEY storage exists for: "two different keys cannot register the
// identical RR" (docs/siglease_rfc9664.md) is now enforced by the store itself, not by a
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
// the record untouched, while removing an already-absent record is a no-op,
// not an error.
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

// TestImportSnapshot_RejectsWrongVersion guards the clean format cuts: a
// snapshot from the old (v1, two-slice) format must fail loudly rather than
// silently unmarshaling into an empty store, and a v2 one (same shape, node
// IDs from before ASCII-only / RDATA-name case folding) must fail rather than
// load under IDs no lookup computes anymore. A v3 one stored non-KEY records as
// rr_text, which v4's rr_wire replaced.
func TestImportSnapshot_RejectsWrongVersion(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()

	if err := store.ImportSnapshot(&LeaseTreeSnapshot{Version: 1}); err == nil {
		t.Fatalf("expected importing a v1 (pre-reshape) snapshot to be rejected")
	}
	if err := store.ImportSnapshot(&LeaseTreeSnapshot{Version: 2}); err == nil {
		t.Fatalf("expected importing a v2 (pre-case-folding-fix) snapshot to be rejected")
	}
	if err := store.ImportSnapshot(&LeaseTreeSnapshot{Version: 3}); err == nil {
		t.Fatalf("expected importing a v3 (presentation-text rr_text) snapshot to be rejected")
	}

	if err := store.ImportSnapshot(&LeaseTreeSnapshot{Version: leaseSnapshotVersion}); err != nil {
		t.Fatalf("expected importing an empty, correctly-versioned snapshot to succeed: %v", err)
	}
}

// TestLoadSnapshot_RejectsHandEdits pins the snapshot file as not hand-editable: it holds the
// SHA-256 of its snapshot, and LoadSnapshot refuses any byte the proxy didn't write -- a
// record, a field only shown for reading (rr_display), whitespace, an added key -- as well as
// a file in the pre-checksum layout.
func TestLoadSnapshot_RejectsHandEdits(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	owner := testKeyRR("Freifunk Berlin._http._tcp.dev.zenr.io.", "OWNER")
	if err := store.Register(context.Background(), owner, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register owner: %v", err)
	}
	path := filepath.Join(t.TempDir(), "lease_snapshot.json")
	if err := store.SaveSnapshot(path); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if err := NewInMemoryManager().LoadSnapshot(path); err != nil {
		t.Fatalf("an unedited snapshot must load: %v", err)
	}

	snap, err := store.ExportSnapshot()
	if err != nil {
		t.Fatalf("export snapshot: %v", err)
	}
	unwrapped, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}

	edits := []struct {
		desc string
		data []byte
	}{
		{"display field changed", bytes.Replace(saved, []byte("IN\\tKEY"), []byte("IN\\tKEY "), 1)},
		{"whitespace added", bytes.Replace(saved, []byte(`"node_kind": `), []byte(`"node_kind":  `), 1)},
		{"key added", bytes.Replace(saved, []byte("{\n"), []byte("{\n  \"note\": \"x\",\n"), 1)},
		{"trailing data", append(append([]byte{}, saved...), "{}"...)},
		{"no checksum (pre-checksum layout)", unwrapped},
	}
	for _, e := range edits {
		if bytes.Equal(e.data, saved) {
			t.Fatalf("%s: the edit did not change the file", e.desc)
		}
		if err := os.WriteFile(path, e.data, 0o600); err != nil {
			t.Fatalf("%s: write: %v", e.desc, err)
		}
		if err := NewInMemoryManager().LoadSnapshot(path); err == nil {
			t.Errorf("%s: expected LoadSnapshot to refuse the edited file", e.desc)
		}
	}
}

// TestSaveSnapshot_WritesAtomically checks the parts of SaveSnapshot's temp-file-and-rename
// write that a test can reach: a save puts a new file at path rather than rewriting the old one
// in place, leaves no temporary file behind, and a save that fails (here, at the rename: path
// is a directory) removes its temporary file and reports the error. That a crash mid-save
// leaves the previous file whole follows from the rename, which a unit test can't interrupt.
func TestSaveSnapshot_WritesAtomically(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	if err := store.Register(context.Background(), testKeyRR("owner.dev.zenr.io.", "OWNER"), 300, 300, "dev.zenr.io."); err != nil {
		t.Fatalf("register owner: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "lease_snapshot.json")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatalf("seed previous file: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat previous file: %v", err)
	}
	if err := store.SaveSnapshot(path); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat saved file: %v", err)
	}
	if os.SameFile(before, after) {
		t.Error("the save rewrote the previous file in place; a crash mid-write would leave it torn")
	}
	if err := NewInMemoryManager().LoadSnapshot(path); err != nil {
		t.Fatalf("the saved snapshot must replace the previous file and load: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected only the snapshot in %s after a save, got %d entries: %v", dir, len(entries), entries)
	}

	blocked := filepath.Join(dir, "is_a_directory")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := store.SaveSnapshot(blocked); err == nil {
		t.Fatal("expected saving over a directory to fail")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "is_a_directory.*.tmp")); len(matches) != 0 {
		t.Errorf("a failed save left its temporary file behind: %v", matches)
	}
}

// ListOwners lists each KEY node and each owner of non-KEY records once, sorted -- including an
// owner with no KEY record of its own, which the snapshot keeps across a restart -- and drops
// an owner once its last record is gone.
func TestListOwners(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryManager()
	parent := testKeyRR("a.example.", "PARENT")
	child := testKeyRR("b.a.example.", "CHILD")
	if err := store.Register(ctx, parent, 60, 60, "example."); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterWithParent(ctx, NodeKey(parent), child, 60, 60, "example."); err != nil {
		t.Fatal(err)
	}
	txt := func(name, text string) dns.RR {
		rr := &dns.TXT{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 60}}
		rr.TXT.Txt = []string{text}
		return rr
	}
	const keyless = "c.example.+015+00001" // a signer with no KEY record in the store
	if err := store.UpsertNonKEYRecords(NodeKey(parent), []dns.RR{txt("a.example.", "a")}, 60, "example."); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertNonKEYRecords(keyless, []dns.RR{txt("c.example.", "1"), txt("c.example.", "2")}, 60, "example."); err != nil {
		t.Fatal(err)
	}

	want := []string{NodeKey(parent), NodeKey(child), keyless}
	slices.Sort(want)
	if got := store.ListOwners(); !slices.Equal(got, want) {
		t.Fatalf("ListOwners() = %v, want %v", got, want)
	}

	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := store.SaveSnapshot(path); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := ReadSnapshotFile(path)
	if err != nil || !found {
		t.Fatalf("ReadSnapshotFile() = found %v, error %v", found, err)
	}
	if got := loaded.ListOwners(); !slices.Equal(got, want) {
		t.Fatalf("after a snapshot round trip, ListOwners() = %v, want %v", got, want)
	}

	store.RemoveNonKEYRecords(keyless)
	if got := store.ListOwners(); slices.Contains(got, keyless) {
		t.Fatalf("ListOwners() = %v still lists %s after its records were removed", got, keyless)
	}
}
