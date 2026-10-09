package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	lease "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// testKeyRR builds a KEY RR at name whose public key is label's bytes, base64-encoded: a
// distinct, well-formed key per label, so the handler can sign and send upstream deletes
// for it (a label used directly as base64 made building any such delete fail).
func testKeyRR(name, label string) *dns.KEY {
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
	k.PublicKey = base64.StdEncoding.EncodeToString([]byte(label))
	return k
}

func TestLeaseExpiresAndRemoved(t *testing.T) {
	h := newTestHandler()
	ctx := context.Background()
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY111=")

	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(key))
	defer h.timers.disarm(lease.NodeKey(key))

	if h.leaseManager.LookupByKEY(key) == nil {
		t.Fatalf("expected active lease immediately after registration")
	}

	time.Sleep(1500 * time.Millisecond)

	if h.leaseManager.Get(lease.NodeKey(key)) != nil {
		t.Fatalf("expected lease removed from the store after expiry")
	}
	if n := h.upstreamCoordinator.(*stubUpstreamCoordinator).sentCount(); n != 1 {
		t.Fatalf("expected the expired KEY to be deleted upstream once, got %d sends", n)
	}
}

func TestLeaseRenewedAndNotRemovedPrematurely(t *testing.T) {
	h := newTestHandler()
	ctx := context.Background()
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY222=")

	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(key))
	defer h.timers.disarm(lease.NodeKey(key))

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
	if h.leaseManager.Get(lease.NodeKey(key)) != nil {
		t.Fatalf("expected renewed lease to be removed from the store after extended expiry")
	}
}

func TestRefreshRejectedForDifferentKeyAndExpires(t *testing.T) {
	h := newTestHandler()
	ctx := context.Background()
	leaseKey := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY333=")
	otherKeySameName := testKeyRR("test.dev.zenr.io.", "BBBBOTHERKEY999=")

	if err := h.leaseManager.Register(ctx, leaseKey, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(leaseKey))
	defer h.timers.disarm(lease.NodeKey(leaseKey))

	if err := h.authorizeKeyRefresh(otherKeySameName, keyIDFromKEY(otherKeySameName)); err == nil {
		t.Fatalf("expected refresh ownership validation to reject mismatched key")
	}

	if h.leaseManager.LookupByKEY(leaseKey) == nil {
		t.Fatalf("expected original lease to remain active after rejected refresh")
	}

	time.Sleep(1500 * time.Millisecond)
	if h.leaseManager.Get(lease.NodeKey(leaseKey)) != nil {
		t.Fatalf("expected lease removed from the store after expiry even after rejected refresh")
	}
}

func TestAuthorizeKeyRefresh_SelfSignerCanRefreshOwnKey(t *testing.T) {
	h := newTestHandler()
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
	h := newTestHandler()
	ctx := context.Background()
	parentKey := testKeyRR("test.dev.zenr.io.", "AAAAPARENT111=")
	childKey := testKeyRR("client.test.dev.zenr.io.", "AAAACHILD111=")

	if err := h.leaseManager.Register(ctx, parentKey, 60, 60, "dev.zenr.io."); err != nil {
		t.Fatalf("register parent: %v", err)
	}
	if err := h.leaseManager.RegisterWithParent(ctx, lease.NodeKey(parentKey), childKey, 60, 60, "dev.zenr.io."); err != nil {
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
	h := newTestHandler()
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

// TestUpdateHandler_FailsHardWithoutUpstream pins requireUpstream: a handler without its
// upstream coordinator or the proxy's signing key -- a state Setup refuses to produce -- has
// no function left, so reaching code that needs them panics instead of logging, retrying, or
// quietly forgetting expired records locally (which left them published upstream with nothing
// left to retry from).
func TestUpdateHandler_FailsHardWithoutUpstream(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		strip func(h *UpdateHandler)
		want  string
	}{
		{"no signing key", func(h *UpdateHandler) { h.upstreamKeyRecord = nil }, "update_handler is missing the proxy's signing key"},
		{"no coordinator", func(h *UpdateHandler) { h.upstreamCoordinator = nil }, "update_handler is missing an upstream coordinator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler()
			tc.strip(h)
			key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEYNOUPSTREAM=")
			// Already past its lease, so its expiry has an upstream delete to send.
			if err := h.leaseManager.Register(ctx, key, 0, 0, "dev.zenr.io."); err != nil {
				t.Fatalf("register key lease: %v", err)
			}

			// A relevant request: an UPDATE carrying the UPDATE-LEASE option.
			update := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
			update.Opcode = dns.OpcodeUpdate
			opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
			if err := lease.Encode8Byte(60, 60).Encode(opt); err != nil {
				t.Fatalf("encode lease option: %v", err)
			}
			update.Extra = append(update.Extra, opt)

			for name, call := range map[string]func(){
				"Handle":        func() { h.Handle(ctx, stubResponseWriter{}, update) },
				"lease expiry":  func() { h.expirer().run(ctx, lease.NodeKey(key)) },
				"upstream send": func() { _, _ = h.upstream().send(ctx, nil, nil) },
			} {
				got := func() (r any) {
					defer func() { r = recover() }()
					call()
					return nil
				}()
				if msg, _ := got.(string); !strings.Contains(msg, tc.want) {
					t.Fatalf("%s: expected a panic containing %q, got %v", name, tc.want, got)
				}
			}
			if h.leaseManager.Get(lease.NodeKey(key)) == nil {
				t.Fatalf("expected nothing to be forgotten locally before the panic")
			}
		})
	}
}

func TestExpiryRetryDelay_BacksOffToCap(t *testing.T) {
	for failures, want := range map[int]time.Duration{
		1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 8 * time.Second,
		5: maxExpiryRetryDelay, 6: maxExpiryRetryDelay, 100: maxExpiryRetryDelay,
	} {
		if got := expiryRetryDelay(failures); got != want {
			t.Fatalf("expiryRetryDelay(%d) = %s, want %s", failures, got, want)
		}
	}
}

// TestProcessExpiredLease_RetriesWithBackoff pins the shared retry policy on the RFC 9664 side:
// an expiry whose upstream delete is refused is retried after expiryRetryDelay's first 1s, not
// immediately. Before, the handler re-armed for the node's next lease event, which for a KEY
// still past due meant a retry every 100ms, indefinitely.
func TestProcessExpiredLease_RetriesWithBackoff(t *testing.T) {
	h := newTestHandler()
	stub := &stubUpstreamCoordinator{resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeRefused}}}
	h.upstreamCoordinator = stub
	ctx := context.Background()
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEYRETRY=")
	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register key lease: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)

	h.expirer().run(ctx, lease.NodeKey(key))
	defer h.timers.disarm(lease.NodeKey(key))
	if n := stub.sentCount(); n != 1 {
		t.Fatalf("expected the one refused KEY delete, got %d sends", n)
	}

	time.Sleep(600 * time.Millisecond)
	if n := stub.sentCount(); n != 1 {
		t.Fatalf("expected no retry within 600ms (backoff starts at 1s), got %d sends", n)
	}
	time.Sleep(700 * time.Millisecond)
	if n := stub.sentCount(); n != 2 {
		t.Fatalf("expected exactly one retry after ~1s, got %d sends", n)
	}
	if h.leaseManager.Get(lease.NodeKey(key)) == nil {
		t.Fatalf("expected the refused KEY to stay in the store")
	}
}

// TestProcessExpiredLease_ZoneResolutionFailureIsRetried: a failed lookup of the upstream
// zone cut is an ordinary, temporary failure. The attempt counts as incomplete and is retried
// with nothing sent or forgotten -- rather than, as before, silently sending the delete for
// the stored, unresolved zone, which may name the wrong zone in the UPDATE.
func TestProcessExpiredLease_ZoneResolutionFailureIsRetried(t *testing.T) {
	h := newTestHandler()
	stub := &stubUpstreamCoordinator{
		resp:       &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}},
		resolveErr: errors.New("SOA lookup timed out"),
	}
	h.upstreamCoordinator = stub
	ctx := context.Background()
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEYRESOLVE=")
	data := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	data.TXT.Txt = []string{"payload"}
	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register key lease: %v", err)
	}
	if err := h.leaseManager.UpsertNonKEYRecords(lease.NodeKey(key), []dns.RR{data}, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert non-key record: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)

	h.expirer().run(ctx, lease.NodeKey(key))
	defer h.timers.disarm(lease.NodeKey(key))

	if n := stub.sentCount(); n != 0 {
		t.Fatalf("expected nothing sent without a resolved zone, got %d sends", n)
	}
	if h.leaseManager.Get(lease.NodeKey(key)) == nil {
		t.Fatalf("expected the expired KEY to stay in the store")
	}
	if set := h.leaseManager.GetNonKEYRecordSet(lease.NodeKey(key)); set == nil || len(set.Records) != 1 {
		t.Fatalf("expected the expired non-KEY record to stay in the store, got %+v", set)
	}
	if !h.timers.armed(lease.NodeKey(key)) {
		t.Fatalf("expected a retry armed")
	}
}

// keylessOwnerData stores one TXT, with a 1s LEASE, under an owner that has no KEY record of its
// own: a signer that registered data without being lease-managed itself. Returns the owner.
func keylessOwnerData(t *testing.T, store LeaseManager) string {
	t.Helper()
	const owner = "signer.dev.zenr.io.+015+12345"
	data := &dns.TXT{Hdr: dns.Header{Name: "data.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	data.TXT.Txt = []string{"payload"}
	if err := store.UpsertNonKEYRecords(owner, []dns.RR{data}, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert non-key record: %v", err)
	}
	return owner
}

// After a restart, the reconciliation pass is what arms a store's timers. Data whose owner has
// no KEY record is in no KEY node's timer, so the pass must arm its owner's too: otherwise the
// data is never expired and stays published upstream.
func TestReconcile_ArmsOwnerWithoutKEYAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	before := lease.NewInMemoryManager()
	owner := keylessOwnerData(t, before)
	if err := before.SaveSnapshot(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // the data's LEASE runs out while the proxy is down

	h := newTestHandler()
	store, _, err := lease.ReadSnapshotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h.leaseManager = store
	stub := &stubUpstreamCoordinator{resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}
	h.upstreamCoordinator = stub
	t.Cleanup(func() { h.timers.disarm(owner) })

	h.timers.reconcile(h.leaseManager, h.logger, h.expireFunc)
	if !h.timers.armed(owner) {
		t.Fatalf("reconciliation armed no timer for %s", owner)
	}
	waitUntil(t, "the expired data to be deleted", func() bool { return h.leaseManager.GetNonKEYRecordSet(owner) == nil })
	sent := stub.sentSnapshot()
	if len(sent) != 1 || len(sent[0].Ns) != 1 || dns.RRToType(sent[0].Ns[0]) != dns.TypeTXT || sent[0].Ns[0].Header().Class != dns.ClassNONE {
		t.Fatalf("expected one upstream delete of the TXT, got %v", sent)
	}
}

// The dumps list data whose owner has no KEY record: KEY=absent in the summary, under "Orphan
// data leases" in the debug dump.
func TestDumpLeases_ListsOwnerWithoutKEY(t *testing.T) {
	h := newTestHandler()
	owner := keylessOwnerData(t, h.leaseManager)

	if summary := h.DumpLeasesLevel("info"); !strings.Contains(summary, owner) || !strings.Contains(summary, "KEY=absent") {
		t.Errorf("summary does not list %s with KEY=absent:\n%s", owner, summary)
	}
	if debug := h.DumpLeasesLevel("debug"); !strings.Contains(debug, "Orphan data leases:") || !strings.Contains(debug, "Non-KEY-only lease: "+owner) {
		t.Errorf("debug dump does not list %s under its orphan data leases:\n%s", owner, debug)
	}
}

// rcodeMsg is an upstream answer with rcode.
func rcodeMsg(rcode uint16) *dns.Msg {
	return &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: rcode}}
}

// deletesOf counts the RFC 2136 deletes of an RR (class NONE) of type rrType at name among
// the updates sent.
func deletesOf(sent []*dns.Msg, rrType uint16, name string) int {
	n := 0
	for _, msg := range sent {
		for _, rr := range msg.Ns {
			if dns.RRToType(rr) == rrType && rr.Header().Class == dns.ClassNONE && dnsname.Normalize(rr.Header().Name) == dnsname.Normalize(name) {
				n++
			}
		}
	}
	return n
}

// rrAt names an RR by type and owner name.
type rrAt struct {
	rrType uint16
	name   string
}

// requireRecordDeletes fails unless msg deletes each of want record by record, once, and
// nothing with a Delete All RRsets (class ANY): an expiry or delete only removes what the
// store tracks.
func requireRecordDeletes(t *testing.T, msg *dns.Msg, want ...rrAt) {
	t.Helper()
	for _, w := range want {
		if n := deletesOf([]*dns.Msg{msg}, w.rrType, w.name); n != 1 {
			t.Errorf("expected one delete of the %s at %s, got %d in Ns: %v", dns.TypeToString[w.rrType], w.name, n, msg.Ns)
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Class == dns.ClassANY {
			t.Errorf("expected no Delete All RRsets, got %v", rr)
		}
	}
}

// A lease event is one UPDATE, forgotten locally only once it is confirmed: refused, it leaves
// the KEY and its record both in place, and its retry deletes both again in one UPDATE.
func TestLeaseExpiry_RefusedUpdateForgetsNothing(t *testing.T) {
	h := newTestHandler()
	var mu sync.Mutex
	refuse := true
	stub := &stubUpstreamCoordinator{respond: func(*dns.Msg) *dns.Msg {
		mu.Lock()
		defer mu.Unlock()
		if refuse {
			return rcodeMsg(dns.RcodeRefused)
		}
		return rcodeMsg(dns.RcodeSuccess)
	}}
	h.upstreamCoordinator = stub
	ctx := context.Background()
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEYKEEP=")
	nodeKey := lease.NodeKey(key)
	data := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	data.TXT.Txt = []string{"payload"}
	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}
	if err := h.leaseManager.UpsertNonKEYRecords(nodeKey, []dns.RR{data}, 3600, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.timers.disarm(nodeKey) })
	time.Sleep(1100 * time.Millisecond)

	h.expirer().run(ctx, nodeKey)
	if h.leaseManager.Get(nodeKey) == nil || h.leaseManager.GetNonKEYRecordSet(nodeKey) == nil {
		t.Fatal("expected the refused expiry to leave the KEY and its record in the store")
	}
	if !h.timers.armed(nodeKey) {
		t.Fatal("expected a retry armed")
	}

	mu.Lock()
	refuse = false
	mu.Unlock()
	waitUntil(t, "the retry to delete the KEY and its record", func() bool {
		return h.leaseManager.Get(nodeKey) == nil && h.leaseManager.GetNonKEYRecordSet(nodeKey) == nil
	})
	sent := stub.sentSnapshot()
	if len(sent) != 2 {
		t.Fatalf("expected the refused UPDATE and its retry, got %d", len(sent))
	}
	for _, msg := range sent {
		requireRecordDeletes(t, msg, rrAt{dns.TypeKEY, "test.dev.zenr.io."}, rrAt{dns.TypeTXT, "test.dev.zenr.io."})
	}
}

// A KEY's expiry takes its whole subtree along in the same UPDATE, KEYs below it with longer
// leases included.
func TestLeaseExpiry_KEYTakesSubtreeInOneUpdate(t *testing.T) {
	h := newTestHandler()
	stub := &stubUpstreamCoordinator{resp: rcodeMsg(dns.RcodeSuccess)}
	h.upstreamCoordinator = stub
	ctx := context.Background()
	parent := testKeyRR("parent.dev.zenr.io.", "AAAATESTKEYPARENT=")
	child := testKeyRR("child.dev.zenr.io.", "AAAATESTKEYCHILD=")
	parentKey, childKey := lease.NodeKey(parent), lease.NodeKey(child)
	data := &dns.TXT{Hdr: dns.Header{Name: "child.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	data.TXT.Txt = []string{"payload"}
	if err := h.leaseManager.Register(ctx, parent, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}
	if err := h.leaseManager.RegisterWithParent(ctx, parentKey, child, 3600, 3600, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}
	if err := h.leaseManager.UpsertNonKEYRecords(childKey, []dns.RR{data}, 3600, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.timers.disarm(parentKey); h.timers.disarm(childKey) })
	time.Sleep(1100 * time.Millisecond)

	h.expirer().run(ctx, parentKey)
	sent := stub.sentSnapshot()
	if len(sent) != 1 {
		t.Fatalf("expected one UPDATE for the whole subtree, got %d", len(sent))
	}
	requireRecordDeletes(t, sent[0], rrAt{dns.TypeKEY, "parent.dev.zenr.io."}, rrAt{dns.TypeKEY, "child.dev.zenr.io."}, rrAt{dns.TypeTXT, "child.dev.zenr.io."})
	if h.leaseManager.Get(parentKey) != nil || h.leaseManager.Get(childKey) != nil || h.leaseManager.GetNonKEYRecordSet(childKey) != nil {
		t.Fatal("expected the whole subtree gone from the store")
	}
}

// A Case C delete of a KEY takes its whole subtree along in the request's one UPDATE, as the
// KEY's expiry does; refused, the request fails and nothing is forgotten.
func TestCaseCDelete_TakesSubtreeInOneUpdate(t *testing.T) {
	signer := loadClientKey(t, "Ktest.dev.zenr.io.+015+05044")
	h, stub := lockTestHandler(t, signer)
	var mu sync.Mutex
	refuse := true
	stub.respond = func(*dns.Msg) *dns.Msg {
		mu.Lock()
		defer mu.Unlock()
		if refuse {
			return rcodeMsg(dns.RcodeRefused)
		}
		return rcodeMsg(dns.RcodeSuccess)
	}
	signerKey := lease.NodeKey(signer.PublicKey)
	child := testKeyRR("child.test.dev.zenr.io.", "AAAATESTKEYCASECCHILD=")
	childKey := lease.NodeKey(child)
	data := &dns.TXT{Hdr: dns.Header{Name: "child.test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	data.TXT.Txt = []string{"payload"}
	if err := h.leaseManager.RegisterWithParent(context.Background(), signerKey, child, 3600, 3600, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}
	if err := h.leaseManager.UpsertNonKEYRecords(childKey, []dns.RR{data}, 3600, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}
	del := func() *HandlerResult {
		return h.Handle(context.Background(), stubResponseWriter{}, buildSignedCaseCDeleteForHandleTest(t, signer, signer.PublicKey.Clone().(*dns.KEY)))
	}

	if res := del(); rcodeOf(res) != dns.RcodeServerFailure {
		t.Fatalf("expected the refused delete to fail, got %+v", res)
	}
	if h.leaseManager.Get(signerKey) == nil || h.leaseManager.Get(childKey) == nil || h.leaseManager.GetNonKEYRecordSet(childKey) == nil {
		t.Fatal("expected the refused delete to forget nothing")
	}

	mu.Lock()
	refuse = false
	mu.Unlock()
	if res := del(); rcodeOf(res) != dns.RcodeSuccess {
		t.Fatalf("expected the delete to succeed, got %+v", res)
	}
	sent := stub.sentSnapshot()
	requireRecordDeletes(t, sent[len(sent)-1], rrAt{dns.TypeKEY, "test.dev.zenr.io."}, rrAt{dns.TypeKEY, "child.test.dev.zenr.io."}, rrAt{dns.TypeTXT, "child.test.dev.zenr.io."})
	if h.leaseManager.Get(signerKey) != nil || h.leaseManager.Get(childKey) != nil || h.leaseManager.GetNonKEYRecordSet(childKey) != nil {
		t.Fatal("expected the deleted KEY's whole subtree gone from the store")
	}
}
