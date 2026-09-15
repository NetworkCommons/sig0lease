package lease

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
)

// This file prototypes D3 (main/docs/rfc9665-srp-implementation-plan.md): "Reuse the
// pkg/lease tree with additive PTR/subtype helpers. Prototype the mapping against RFC
// 9665 [worked example] in Phase 1 before committing." It builds the exact worked-example
// tree from the plan's S4.4/S4.5 (host "myhost" with A/AAAA, service instance
// "Printer._ipps._tcp" with SRV/TXT and a base-type + "_print" subtype PTR) using ONLY
// the store's existing, unmodified methods, and checks the specific claims those sections
// make. Confirms the plan's own conclusion: no new store methods are needed for SRP.

func mustSRPRR(t *testing.T, spec string) dns.RR {
	t.Helper()
	rr, err := dns.New(spec)
	if err != nil {
		t.Fatalf("dns.New(%q): %v", spec, err)
	}
	return rr
}

// srpTree builds the S4.4 worked-example tree and returns the host and service instance
// node keys for the caller to inspect further.
func srpTree(t *testing.T, store *InMemoryLeaseStore) (hostNodeKey, serviceNodeKey string) {
	t.Helper()
	ctx := context.Background()
	const zone = "srp.example.com."

	hostKey := testKeyRR("myhost.srp.example.com.", "hostpubkey==")
	if err := store.Register(ctx, hostKey, 7200, 1209600, zone); err != nil {
		t.Fatalf("register host: %v", err)
	}
	hostNodeKey = NodeKey(hostKey)

	if err := store.UpsertNonKEYRecords(hostNodeKey, []dns.RR{
		mustSRPRR(t, "myhost.srp.example.com. 7200 IN A 192.0.2.1"),
		mustSRPRR(t, "myhost.srp.example.com. 7200 IN AAAA 2001:db8::1"),
	}, 7200, zone); err != nil {
		t.Fatalf("upsert host addresses: %v", err)
	}

	// Service instance: a KEY node parented to the host -- byte-identical key material
	// (a name-scoped node identity, not a second key) per S3.2.5.1 / S4.4's note.
	svcKey := testKeyRR("printer._ipps._tcp.srp.example.com.", "hostpubkey==")
	if err := store.RegisterWithParent(ctx, hostNodeKey, svcKey, 7200, 1209600, zone); err != nil {
		t.Fatalf("register service instance: %v", err)
	}
	serviceNodeKey = NodeKey(svcKey)

	// SRV/TXT and BOTH PTRs (base type + "_print" subtype) are all children of the
	// SERVICE node -- not of the PTR's own owner name, which is the service *type*,
	// shared across every instance of that type (S4.4).
	if err := store.UpsertNonKEYRecords(serviceNodeKey, []dns.RR{
		mustSRPRR(t, "printer._ipps._tcp.srp.example.com. 7200 IN SRV 0 0 631 myhost.srp.example.com."),
		mustSRPRR(t, `printer._ipps._tcp.srp.example.com. 7200 IN TXT "rp=ipp/print"`),
		mustSRPRR(t, "_ipps._tcp.srp.example.com. 7200 IN PTR printer._ipps._tcp.srp.example.com."),
		mustSRPRR(t, "_print._sub._ipps._tcp.srp.example.com. 7200 IN PTR printer._ipps._tcp.srp.example.com."),
	}, 7200, zone); err != nil {
		t.Fatalf("upsert service records: %v", err)
	}

	return hostNodeKey, serviceNodeKey
}

func TestSRPShape_WorkedExampleTree(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()

	hostNodeKey, serviceNodeKey := srpTree(t, store)

	// The service KEY node is a child of the host KEY node.
	kids := store.ChildrenOf(hostNodeKey)
	foundService := false
	for _, k := range kids {
		if k == serviceNodeKey {
			foundService = true
		}
	}
	if !foundService {
		t.Fatalf("service node %s not found among host's children: %+v", serviceNodeKey, kids)
	}

	// All four service records (SRV, TXT, 2 PTRs) are present under the service node,
	// as distinct nodes -- in particular, the base-type and subtype PTR share an owner
	// name family shape (different owner names here, but see
	// TestSRPShape_TwoInstancesShareAPTROwnerName below for the case that actually
	// stresses RecordKey uniqueness: two DIFFERENT PTRs at the SAME owner name).
	set := store.GetNonKEYRecordSet(serviceNodeKey)
	if set == nil || len(set.Records) != 4 {
		t.Fatalf("expected 4 records under the service node, got: %+v", set)
	}
	var srvCount, txtCount, ptrCount int
	for _, rec := range set.Records {
		switch rec.RR.(type) {
		case *dns.SRV:
			srvCount++
		case *dns.TXT:
			txtCount++
		case *dns.PTR:
			ptrCount++
		default:
			t.Fatalf("unexpected record type under service node: %T", rec.RR)
		}
	}
	if srvCount != 1 || txtCount != 1 || ptrCount != 2 {
		t.Fatalf("expected 1 SRV, 1 TXT, 2 PTR; got srv=%d txt=%d ptr=%d", srvCount, txtCount, ptrCount)
	}
}

// TestSRPShape_HostExpiryCascadesEverything is S4.4's cascade claim: "Cascade: host KEY
// expiry -> DeleteSubtree on the host node -> all 8 nodes gone."
func TestSRPShape_HostExpiryCascadesEverything(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	hostNodeKey, serviceNodeKey := srpTree(t, store)

	if err := store.DeleteSubtree(hostNodeKey); err != nil {
		t.Fatalf("DeleteSubtree: %v", err)
	}

	if store.Get(hostNodeKey) != nil {
		t.Fatal("host node should be gone")
	}
	if store.Get(serviceNodeKey) != nil {
		t.Fatal("service instance node should be gone (cascaded)")
	}
	if store.GetNonKEYRecordSet(serviceNodeKey) != nil {
		t.Fatal("service instance's SRV/TXT/PTR records should be gone (cascaded)")
	}
}

// TestSRPShape_ServiceInstanceLeaseExpiryLeavesKeyAndHost is S4.4's other cascade claim:
// "Service-instance lease (T0+2h) -> SRV, TXT, and both PTR nodes; the service KEY node
// survives to T0+14d (name still reserved); host untouched." RemoveNonKEYRecords is the
// local mirror of a service-instance's data-lease expiry (see S4.3 step 8 / S4.5): it
// wipes the service node's non-KEY children without touching the KEY node itself or its
// parent.
func TestSRPShape_ServiceInstanceLeaseExpiryLeavesKeyAndHost(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	hostNodeKey, serviceNodeKey := srpTree(t, store)

	store.RemoveNonKEYRecords(serviceNodeKey)

	if store.GetNonKEYRecordSet(serviceNodeKey) != nil {
		t.Fatal("expected the service instance's SRV/TXT/PTR records to be gone")
	}
	if store.Get(serviceNodeKey) == nil {
		t.Fatal("service instance KEY node itself should survive (name still reserved)")
	}
	if store.Get(hostNodeKey) == nil {
		t.Fatal("host should be untouched")
	}
	if store.GetNonKEYRecordSet(hostNodeKey) == nil {
		t.Fatal("host's own A/AAAA records should be untouched")
	}
}

// TestSRPShape_DroppedSubtypeSurvivesWipeThenReinsert is S4.5's "refresh that omits the
// _print subtype" walkthrough: the *local* mutation for a Service Description update is
// the same uniform wipe-then-reinsert used for a full refresh, just reinserting a smaller
// record set -- RemoveNonKEYRecords(service) then UpsertNonKEYRecords(service, [SRV, TXT,
// PTR_base], ...), with no separate "subtype sync" store operation.
func TestSRPShape_DroppedSubtypeSurvivesWipeThenReinsert(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	const zone = "srp.example.com."
	_, serviceNodeKey := srpTree(t, store)

	store.RemoveNonKEYRecords(serviceNodeKey)
	if err := store.UpsertNonKEYRecords(serviceNodeKey, []dns.RR{
		mustSRPRR(t, "printer._ipps._tcp.srp.example.com. 7200 IN SRV 0 0 631 myhost.srp.example.com."),
		mustSRPRR(t, `printer._ipps._tcp.srp.example.com. 7200 IN TXT "rp=ipp/print"`),
		mustSRPRR(t, "_ipps._tcp.srp.example.com. 7200 IN PTR printer._ipps._tcp.srp.example.com."),
		// _print subtype PTR deliberately omitted.
	}, 7200, zone); err != nil {
		t.Fatalf("re-upsert without subtype: %v", err)
	}

	set := store.GetNonKEYRecordSet(serviceNodeKey)
	var ptrCount int
	for _, rec := range set.Records {
		if ptr, ok := rec.RR.(*dns.PTR); ok {
			ptrCount++
			if ptr.Hdr.Name == "_print._sub._ipps._tcp.srp.example.com." {
				t.Fatalf("dropped subtype PTR is still present: %s", ptr.String())
			}
		}
	}
	if ptrCount != 1 {
		t.Fatalf("expected exactly 1 surviving PTR (the base type), got %d", ptrCount)
	}
}

// TestSRPShape_TwoInstancesShareAPTROwnerName is S4.4's "A second instance ... -> another
// KEY node under myhost, its own SRV/TXT, and its own PTR node at owner
// _ipps._tcp.srp.example.com. -- same owner as Printer's PTR, different RDATA -> different
// RecordKey -> a distinct node under the Front Desk instance. Two PTR RRs coexist at that
// owner name, each independently leased." This is the one claim that actually stresses
// RecordKey uniqueness (RFC 2136 RDATA-inclusive identity) rather than just tree shape.
func TestSRPShape_TwoInstancesShareAPTROwnerName(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()
	const zone = "srp.example.com."

	hostKey := testKeyRR("myhost.srp.example.com.", "hostpubkey==")
	if err := store.Register(ctx, hostKey, 7200, 1209600, zone); err != nil {
		t.Fatalf("register host: %v", err)
	}
	hostNodeKey := NodeKey(hostKey)

	printerKey := testKeyRR("printer._ipps._tcp.srp.example.com.", "hostpubkey==")
	if err := store.RegisterWithParent(ctx, hostNodeKey, printerKey, 7200, 1209600, zone); err != nil {
		t.Fatalf("register printer instance: %v", err)
	}
	printerNodeKey := NodeKey(printerKey)
	if err := store.UpsertNonKEYRecords(printerNodeKey, []dns.RR{
		mustSRPRR(t, "_ipps._tcp.srp.example.com. 7200 IN PTR printer._ipps._tcp.srp.example.com."),
	}, 7200, zone); err != nil {
		t.Fatalf("upsert printer PTR: %v", err)
	}

	frontDeskKey := testKeyRR("front desk._ipps._tcp.srp.example.com.", "hostpubkey==")
	if err := store.RegisterWithParent(ctx, hostNodeKey, frontDeskKey, 7200, 1209600, zone); err != nil {
		t.Fatalf("register front desk instance: %v", err)
	}
	frontDeskNodeKey := NodeKey(frontDeskKey)
	if err := store.UpsertNonKEYRecords(frontDeskNodeKey, []dns.RR{
		mustSRPRR(t, "_ipps._tcp.srp.example.com. 7200 IN PTR front\\ desk._ipps._tcp.srp.example.com."),
	}, 7200, zone); err != nil {
		t.Fatalf("upsert front desk PTR: %v", err)
	}

	printerSet := store.GetNonKEYRecordSet(printerNodeKey)
	frontDeskSet := store.GetNonKEYRecordSet(frontDeskNodeKey)
	if printerSet == nil || len(printerSet.Records) != 1 {
		t.Fatalf("expected printer's own PTR node, got: %+v", printerSet)
	}
	if frontDeskSet == nil || len(frontDeskSet.Records) != 1 {
		t.Fatalf("expected front desk's own PTR node, got: %+v", frontDeskSet)
	}
	// Different RRKey (RDATA differs -> different RecordKey) despite the identical
	// owner name -- confirmed by their both existing as two separate single-record sets
	// under two different parents, rather than one clobbering the other.
	for k := range printerSet.Records {
		if _, clash := frontDeskSet.Records[k]; clash {
			t.Fatalf("printer and front desk PTR nodes share a RecordKey %q -- should differ by target RDATA", k)
		}
	}

	// Deleting one instance's subtree removes only its own PTR, not the other's -- they
	// are genuinely independent nodes, not two entries in one shared set at that owner
	// name.
	if err := store.DeleteSubtree(printerNodeKey); err != nil {
		t.Fatalf("DeleteSubtree(printer): %v", err)
	}
	if store.GetNonKEYRecordSet(frontDeskNodeKey) == nil {
		t.Fatal("front desk's PTR should have survived deleting the printer instance")
	}
}
