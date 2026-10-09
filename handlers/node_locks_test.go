package handlers

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/srp"
)

// Concurrency tests for the lease-store node locks (docs/siglease_rfc9664.md, "Node Locks";
// docs/siglease_rfc9665.md §5): each holds one operation inside its upstream round trip and
// runs a second one against the same nodes, which must wait for the first instead of acting
// on state the first hasn't written.

// holdFirstSend returns a hook for a stub's SendUpdate that blocks the first UPDATE sent
// upstream until release is called. started reports whether that first send has begun.
func holdFirstSend() (hold func(), started func() bool, release func()) {
	var calls atomic.Int32
	gate := make(chan struct{})
	hold = func() {
		if calls.Add(1) == 1 {
			<-gate
		}
	}
	return hold, func() bool { return calls.Load() >= 1 }, sync.OnceFunc(func() { close(gate) })
}

// holdFirstUpdateSend installs holdFirstSend's hook on the RFC 9664 handler's stub.
func holdFirstUpdateSend(stub *stubUpstreamCoordinator) (started func() bool, release func()) {
	hold, started, release := holdFirstSend()
	stub.onSend = func(*dns.Msg) { hold() }
	return started, release
}

func handleAsync(h Handler, w dns.ResponseWriter, req *dns.Msg) <-chan *HandlerResult {
	out := make(chan *HandlerResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out <- h.Handle(ctx, w, req)
	}()
	return out
}

// raceSecondAgainstFirst runs first until it is held inside its upstream send, then starts
// second and gives it 200ms to get as far as it can -- with node locks it waits for first;
// without them it would run its checks, and maybe its own send, against state first has not
// written yet -- then lets first finish, and returns both results. The outcome with locks
// does not depend on the 200ms: second simply runs after first.
func raceSecondAgainstFirst(t *testing.T, h Handler, w dns.ResponseWriter, started func() bool, release func(), first, second *dns.Msg) (*HandlerResult, *HandlerResult) {
	t.Helper()
	firstRes := handleAsync(h, w, first)
	waitUntil(t, "the first operation to reach its upstream send", started)
	secondRes := handleAsync(h, w, second)
	var b *HandlerResult
	select {
	case b = <-secondRes:
	case <-time.After(200 * time.Millisecond):
	}
	release()
	a := <-firstRes
	if b == nil {
		b = <-secondRes
	}
	return a, b
}

func rcodeOf(res *HandlerResult) int {
	if res == nil || res.Message == nil {
		return -1
	}
	return int(res.Message.Rcode)
}

func loadClientKey(t *testing.T, name string) *keyrec.LoadedKey {
	t.Helper()
	k, err := keyrec.LoadKeyFromFile("../keystore/client", name)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return k
}

// lockTestHandler returns a Setup UpdateHandler whose stub upstream answers every UPDATE with
// NOERROR and publishes the KEY of each signer, and nothing else; each signer is registered
// in the lease store as a root.
func lockTestHandler(t *testing.T, signers ...*keyrec.LoadedKey) (*UpdateHandler, *stubUpstreamCoordinator) {
	t.Helper()
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{"upstream_zone": "dev.zenr.io.", "keystore_dir": keystoreDir}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	t.Cleanup(h.Shutdown)
	stub := &stubUpstreamCoordinator{
		resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}},
		query: func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
			for _, k := range signers {
				if rrType == dns.TypeKEY && dnsname.Normalize(fqdn) == dnsname.Normalize(k.PublicKey.Hdr.Name) {
					return []dns.RR{k.PublicKey}, nil
				}
			}
			return []dns.RR{}, nil
		},
	}
	h.upstreamCoordinator = stub
	for _, k := range signers {
		if err := h.leaseManager.Register(context.Background(), k.PublicKey.Clone().(*dns.KEY), 120, 120, "dev.zenr.io."); err != nil {
			t.Fatalf("register signer: %v", err)
		}
	}
	return h, stub
}

// Two signers registering the identical TXT RR at the same moment: the race this locking was
// first planned for. The second must wait for the first, then be refused as a duplicate --
// before it sends anything upstream. The signers are two different keys at one name, both
// allowed to sign for the request's zone.
func TestNodeLocks_UpdateHandler_SameRecordFromTwoSigners(t *testing.T) {
	a := loadClientKey(t, "Ktest.dev.zenr.io.+015+05044")
	b := loadClientKey(t, "Ktest.dev.zenr.io.+015+42176")
	h, stub := lockTestHandler(t, a, b)
	started, release := holdFirstUpdateSend(stub)

	const owner = "client.test.dev.zenr.io."
	reqA := buildSignedNonKeyOnlyLeaseUpdateForHandleTest(t, a, owner, 120, false)
	reqB := buildSignedNonKeyOnlyLeaseUpdateForHandleTest(t, b, owner, 120, false)
	resA, resB := raceSecondAgainstFirst(t, h, stubResponseWriter{}, started, release, reqA, reqB)

	if rcodeOf(resA) != dns.RcodeSuccess {
		t.Fatalf("first registration: expected NOERROR, got %+v", resA)
	}
	if rcodeOf(resB) != dns.RcodeRefused || resB.Reason != "duplicate registration rejected" {
		t.Fatalf("second registration of the same RR: expected REFUSED as a duplicate, got %+v", resB)
	}
	if n := stub.sentCount(); n != 1 {
		t.Fatalf("expected only the first registration's UPDATE upstream, got %d", n)
	}
	rec := h.leaseManager.LookupNonKEYRecord(reqA.Ns[0])
	if rec == nil || rec.ParentKeyName != leasepkg.NodeKey(a.PublicKey) {
		t.Fatalf("expected the TXT owned by the first signer, got %+v", rec)
	}
}

// A KEY's delete (Case C) while a registration under that KEY is in flight: the delete must
// wait, then cascade into the record the registration just attached -- not delete the KEY
// alone and leave the new record owned by a KEY that no longer exists, still published.
func TestNodeLocks_UpdateHandler_DeleteWaitsForRegistrationUnderIt(t *testing.T) {
	p := loadClientKey(t, "Ktest.dev.zenr.io.+015+05044")
	h, stub := lockTestHandler(t, p)
	started, release := holdFirstUpdateSend(stub)

	const owner = "host.test.dev.zenr.io."
	register := buildSignedNonKeyOnlyLeaseUpdateForHandleTest(t, p, owner, 120, false)
	txt := register.Ns[0]
	del := buildSignedCaseCDeleteForHandleTest(t, p, p.PublicKey.Clone().(*dns.KEY))
	resReg, resDel := raceSecondAgainstFirst(t, h, stubResponseWriter{}, started, release, register, del)

	if rcodeOf(resReg) != dns.RcodeSuccess || rcodeOf(resDel) != dns.RcodeSuccess {
		t.Fatalf("expected both to succeed, got register=%+v delete=%+v", resReg, resDel)
	}
	if rec := h.leaseManager.Get(leasepkg.NodeKey(p.PublicKey)); rec != nil {
		t.Fatalf("expected the KEY deleted, still have %+v", rec)
	}
	if rec := h.leaseManager.LookupNonKEYRecord(txt); rec != nil {
		t.Fatalf("expected the delete to cascade into the TXT registered under the KEY, still have %+v", rec)
	}
	deleted := false
	for _, msg := range stub.sentSnapshot() {
		for _, rr := range msg.Ns {
			if t, ok := rr.(*dns.TXT); ok && t.Hdr.Class == dns.ClassNONE && dnsname.Normalize(t.Hdr.Name) == dnsname.Normalize(owner) {
				deleted = true
			}
		}
	}
	if !deleted {
		t.Fatal("expected an upstream delete of the TXT registered under the deleted KEY")
	}
}

// A lease expiry firing while a request holds the node does nothing and backs off: no
// upstream delete racing the request's own write. The node has a record whose LEASE is
// already up, so an expiry that ignored the lock would send its delete.
func TestNodeLocks_UpdateHandler_ExpiryBacksOffWhileRequestHoldsNode(t *testing.T) {
	p := loadClientKey(t, "Ktest.dev.zenr.io.+015+05044")
	h, stub := lockTestHandler(t, p)
	started, release := holdFirstUpdateSend(stub)
	nodeKey := leasepkg.NodeKey(p.PublicKey)
	t.Cleanup(func() { h.timers.disarm(nodeKey) })
	due := &dns.TXT{Hdr: dns.Header{Name: "old.test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	due.TXT.Txt = []string{"due"}
	if err := h.leaseManager.UpsertNonKEYRecords(nodeKey, []dns.RR{due}, 0, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}

	res := handleAsync(h, stubResponseWriter{}, buildSignedNonKeyOnlyLeaseUpdateForHandleTest(t, p, "host.test.dev.zenr.io.", 120, false))
	waitUntil(t, "the first operation to reach its upstream send", started)

	ctx, cancel := context.WithTimeout(context.Background(), expiryTimeout)
	defer cancel()
	h.expirer().run(ctx, nodeKey)
	if n := stub.sentCount(); n != 0 {
		t.Fatalf("expiry sent %d UPDATE(s) while the request held the node", n)
	}
	if !h.timers.armed(nodeKey) {
		t.Fatal("expected the expiry to re-arm its timer to retry")
	}

	release()
	if r := <-res; rcodeOf(r) != dns.RcodeSuccess {
		t.Fatalf("request: expected NOERROR, got %+v", r)
	}
}

// Two different keys claiming one new SRP host name at the same moment. Under FCFS the name
// is the identity, so the second must wait for the first -- their NodeKeys differ, which is
// why SRP locks names -- and then lose the name with YXDOMAIN, without forwarding anything.
// refuse_on_foreign_data=false with data at the name is the case no "name not in use"
// prerequisite covers.
func TestNodeLocks_SRPHandler_SameNameFromTwoKeys(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	h.refuseOnForeignData = false
	coord.keyState = srp.AuthNoKey
	hold, started, release := holdFirstSend()
	coord.onSendUpdate = hold

	first, second := newSRPTestIdentity(t), newSRPTestIdentity(t)
	const host = "srplock1.dev.zenr.io."
	reqA := buildSRPUpdate(t, srpTestZone, first, host, []string{"192.0.2.1"}, nil, 30, 1209600, host)
	reqB := buildSRPUpdate(t, srpTestZone, second, host, []string{"192.0.2.2"}, nil, 30, 1209600, host)
	resA, resB := raceSecondAgainstFirst(t, h, stubTCPResponseWriter{}, started, release, reqA, reqB)

	if rcodeOf(resA) != dns.RcodeSuccess {
		t.Fatalf("first claim: expected NOERROR, got %+v", resA)
	}
	if rcodeOf(resB) != dns.RcodeYXDomain {
		t.Fatalf("second claim of the same name with another key: expected YXDOMAIN, got %+v", resB)
	}
	if n := len(h.leaseManager.FindByName(host)); n != 1 {
		t.Fatalf("expected one KEY node at %s, got %d", host, n)
	}
	secondKey := second.keyAt(host)
	for _, msg := range coord.sentSnapshot() {
		for _, rr := range msg.Ns {
			if k, ok := rr.(*dns.KEY); ok && k.PublicKey == secondKey.PublicKey {
				t.Fatalf("the losing claim's KEY was forwarded upstream: %v", k)
			}
		}
	}
}

// A host's KEY-LEASE expiry firing while a refresh of that host holds its lock does nothing
// and backs off: no upstream delete racing the refresh's own write.
func TestNodeLocks_SRPHandler_ExpiryBacksOffWhileRefreshHoldsNode(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srplock2.dev.zenr.io."
	hostKey := id.keyAt(host)
	nodeKey := leasepkg.NodeKey(hostKey)
	// Already past its KEY-LEASE: an expiry that ignored the lock would delete it upstream.
	if err := h.leaseManager.RegisterWithParent(context.Background(), "", hostKey, 0, 0, srpTestZone); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.timers.disarm(nodeKey) })
	hold, started, release := holdFirstSend()
	coord.onSendUpdate = hold

	res := handleAsync(h, stubTCPResponseWriter{}, buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, nil, 30, 1209600, host))
	waitUntil(t, "the first operation to reach its upstream send", started)

	ctx, cancel := context.WithTimeout(context.Background(), expiryTimeout)
	defer cancel()
	h.processExpiredNode(ctx, nodeKey)
	if n := len(coord.sentSnapshot()); n != 1 {
		t.Fatalf("expected only the refresh's UPDATE while it held the node, got %d sends", n)
	}
	if !h.timers.armed(nodeKey) {
		t.Fatal("expected the expiry to re-arm its timer to retry")
	}

	release()
	if r := <-res; rcodeOf(r) != dns.RcodeSuccess {
		t.Fatalf("refresh: expected NOERROR, got %+v", r)
	}
	if rec := h.leaseManager.Get(nodeKey); rec == nil || rec.IsExpired() {
		t.Fatalf("expected the refresh to have renewed the host, got %+v", rec)
	}
}
