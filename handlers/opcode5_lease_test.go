package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
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
			if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
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
				"Handle":              func() { h.Handle(ctx, stubResponseWriter{}, update) },
				"processExpiredLease": func() { h.processExpiredLease(ctx, lease.NodeKey(key)) },
				"resolveUpstreamSigningContext": func() {
					_, _, _ = resolveUpstreamSigningContext(ctx, h.Name(), h.upstreamCoordinator, h.upstreamKeyRecord, h.upstreamZone, h.logger)
				},
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

	h.processExpiredLease(ctx, lease.NodeKey(key))
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

	h.processExpiredLease(ctx, lease.NodeKey(key))
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
