package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
	"github.com/NetworkCommons/sig0lease/pkg/srp"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
)

// --- fakes ---------------------------------------------------------------------------

// fakeSRPCoordinator is srpCoordinator's test double: every upstream-facing call Handle()
// makes is recorded and driven from canned responses, so its upstream-facing branches (FCFS's
// live query, forward success/failure, expiry's delete) can be exercised without a real
// network or DNS server -- the plan's own Phase 3 gate (S12.2: "Handler tests -- mock
// UpstreamCoordinator").
type fakeSRPCoordinator struct {
	// keyState defaults to AuthNXDomain ("first come") for any name the test hasn't seeded
	// into the lease store -- matching an empty real zone, the common case.
	keyState srp.AuthoritativeKeyState
	keys     []*dns.KEY
	queryErr error

	sendResp *dns.Msg
	sendErr  error
	sent     []*dns.Msg // every updateMsg passed to SendUpdate, in call order

	// onSendUpdate, if set, runs synchronously inside SendUpdate before it returns --
	// standing in for "something else mutated the lease store while our own upstream round
	// trip was in flight" (a real concurrent request in production; here, deliberately
	// simulated in a single goroutine so the test stays deterministic).
	onSendUpdate func()

	// ptrExists/ptrExistsErr back QueryPTRExists (RFC 6763 S9's "is anything else still
	// providing this type" check). Defaulting to (false, nil) matches every existing
	// test's isolated-single-proxy world -- nothing else could possibly still be
	// providing a type this process's own store has lost track of -- so a type dropping
	// out of the local store still gets deleted from the enumeration record exactly as
	// before, without any test needing to configure this explicitly.
	ptrExists    bool
	ptrExistsErr error
}

func (f *fakeSRPCoordinator) QueryKeyAtName(ctx context.Context, zoneHint, name string) (srp.AuthoritativeKeyState, []*dns.KEY, error) {
	return f.keyState, f.keys, f.queryErr
}

func (f *fakeSRPCoordinator) SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error) {
	f.sent = append(f.sent, updateMsg)
	if f.onSendUpdate != nil {
		f.onSendUpdate()
	}
	return f.sendResp, f.sendErr
}

func (f *fakeSRPCoordinator) ResolveAuthoritativeZone(ctx context.Context, zone string) (string, error) {
	return zone, nil
}

func (f *fakeSRPCoordinator) QueryPTRExists(ctx context.Context, zoneHint, name string) (bool, error) {
	return f.ptrExists, f.ptrExistsErr
}

// stubTCPResponseWriter presents as a TCP peer -- the default test harness's response
// writer, so most tests don't have to think about SRPHandler's TCP-required gate (plan
// S7/D6). TestSRPHandle_RejectsUDPWhenNotAllowed uses the UDP-shaped stubResponseWriter
// from opcode5_sig0_validation_test.go (same package) instead.
type stubTCPResponseWriter struct{}

func (stubTCPResponseWriter) LocalAddr() net.Addr { return &net.TCPAddr{} }
func (stubTCPResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}
func (stubTCPResponseWriter) Conn() net.Conn            { return nil }
func (stubTCPResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (stubTCPResponseWriter) Close() error              { return nil }
func (stubTCPResponseWriter) Session() *dns.Session     { return nil }
func (stubTCPResponseWriter) Hijack()                   {}

// --- RR builders -----------------------------------------------------------------------
//
// Mirrors pkg/srp/srp_test.go's own small builders (unexported to that package, so not
// reusable directly): dns.New handles every presentation-format-representable shape;
// deleteAll and the KEY RR need direct struct construction (the parser can't produce a
// "Delete All RRsets" class-ANY RR, and the KEY needs runtime-generated key material).

func srpMustRR(t *testing.T, spec string) dns.RR {
	t.Helper()
	rr, err := dns.New(spec)
	if err != nil {
		t.Fatalf("dns.New(%q): %v", spec, err)
	}
	return rr
}

func srpDeleteAll(name string) *dns.ANY {
	return &dns.ANY{Hdr: dns.Header{Name: name, Class: dns.ClassANY, TTL: 0}}
}

// srpTestIdentity is one generated ECDSAP256SHA256 key pair, usable as a KEY RR at any
// owner name (the host's own, or -- to build a signer-mismatch/conflict case -- some other
// identity's).
type srpTestIdentity struct {
	priv *ecdsa.PrivateKey
}

func newSRPTestIdentity(t *testing.T) *srpTestIdentity {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &srpTestIdentity{priv: priv}
}

func (id *srpTestIdentity) keyAt(name string) *dns.KEY {
	pubBytes := elliptic.Marshal(elliptic.P256(), id.priv.PublicKey.X, id.priv.PublicKey.Y)
	k := &dns.KEY{}
	k.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600}
	k.Protocol = 3
	k.Algorithm = dns.ECDSAP256SHA256
	k.PublicKey = base64.StdEncoding.EncodeToString(pubBytes[1:])
	return k
}

func (id *srpTestIdentity) sign(t *testing.T, msg *dns.Msg, signerKeyRR *dns.KEY) *dns.Msg {
	t.Helper()
	signed, err := sig0.SignMessage(msg, signerKeyRR, id.priv)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}
	return signed
}

// --- update builders ---------------------------------------------------------------

const srpTestZone = "dev.zenr.io."

// srpInstanceSpec describes one Service Description Instruction to include in a test
// update, plus its matching Service Discovery PTR add(s) -- unless removalShaped, which
// produces a bare delete-all with no SRV/TXT/PTR (S3.3.1.1's second bullet).
type srpInstanceSpec struct {
	name          string
	port          int
	txt           string
	svctype       string // base-type PTR owner name; only used when live (!removalShaped)
	subtype       string // optional second (subtype) PTR owner name naming the same instance
	removalShaped bool
}

// buildSRPUpdateUnsigned builds a structurally-valid, UNSIGNED RFC 9665 update: one Host
// Description (host, addrs, hostKey at host's own name) plus the given service instances
// and their Service Discovery PTR adds, with an 8-byte Update-Lease option.
func buildSRPUpdateUnsigned(t *testing.T, zone string, identity *srpTestIdentity, host string, addrs []string, instances []srpInstanceSpec, lease, keyLease uint32) *dns.Msg {
	t.Helper()

	msg := dns.NewMsg(zone, dns.TypeSOA)
	msg.Opcode = dns.OpcodeUpdate

	msg.Ns = append(msg.Ns, srpDeleteAll(host))
	for _, addr := range addrs {
		msg.Ns = append(msg.Ns, srpMustRR(t, host+" 3600 IN A "+addr))
	}
	msg.Ns = append(msg.Ns, identity.keyAt(host))

	for _, inst := range instances {
		msg.Ns = append(msg.Ns, srpDeleteAll(inst.name))
		if inst.removalShaped {
			continue
		}
		msg.Ns = append(msg.Ns, srpMustRR(t, inst.name+" 3600 IN SRV 0 0 "+strconv.Itoa(inst.port)+" "+host))
		msg.Ns = append(msg.Ns, srpMustRR(t, inst.name+` 3600 IN TXT "`+inst.txt+`"`))
		msg.Ns = append(msg.Ns, srpMustRR(t, inst.svctype+" 3600 IN PTR "+inst.name))
		if inst.subtype != "" {
			msg.Ns = append(msg.Ns, srpMustRR(t, inst.subtype+" 3600 IN PTR "+inst.name))
		}
	}

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(4096)
	lo := leasepkg.Encode8Byte(lease, keyLease)
	if err := lo.Encode(opt); err != nil {
		t.Fatalf("encode lease option: %v", err)
	}
	msg.Extra = append(msg.Extra, opt)
	return msg
}

// buildSRPUpdate is buildSRPUpdateUnsigned plus a SIG(0) signature over signerName's key
// (normally == host, the only case Handle() accepts as valid; tests exercising signer
// mismatch call buildSRPUpdateUnsigned directly and sign it themselves).
func buildSRPUpdate(t *testing.T, zone string, identity *srpTestIdentity, host string, addrs []string, instances []srpInstanceSpec, lease, keyLease uint32, signerName string) *dns.Msg {
	t.Helper()
	msg := buildSRPUpdateUnsigned(t, zone, identity, host, addrs, instances, lease, keyLease)
	return identity.sign(t, msg, identity.keyAt(signerName))
}

// --- test harness --------------------------------------------------------------------

func newSRPTestHandler(t *testing.T) (*SRPHandler, *fakeSRPCoordinator) {
	t.Helper()
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	h := NewSRPHandler()
	h.SetLogger(logging.NewLogger("debug"))
	h.upstreamZone = srpTestZone
	h.keystoreDir = keystoreDir
	h.refuseOnForeignData = true

	// This harness constructs the handler's fields directly rather than calling Setup
	// (which would also need a real/fake coordinator's ResolveAuthoritativeZone wired up
	// before it returns), so it has to populate the signing-key cache Setup would
	// otherwise populate itself -- resolveUpstreamSigningContext relies on it being set.
	upstreamKey, matchedZone, err := updatecore.FindAuthorizedProxyKey(keystoreDir, srpTestZone, h.logger)
	if err != nil {
		t.Fatalf("resolve test upstream signing key: %v", err)
	}
	h.upstreamKeyRecord = upstreamKey
	h.upstreamKeyZone = matchedZone

	coord := &fakeSRPCoordinator{
		keyState: srp.AuthNXDomain,
		sendResp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}},
	}
	h.coordinator = coord
	return h, coord
}

func oneWidgetInstance() []srpInstanceSpec {
	return []srpInstanceSpec{{name: "Widget._http._tcp.dev.zenr.io.", port: 8080, txt: "path=/", svctype: "_http._tcp.dev.zenr.io."}}
}

// --- happy path + the KEY-inheritance regression ------------------------------------

// TestSRPHandle_FreshRegistration_InstanceKeyInheritsHostMaterialAtItsOwnName is this
// session's KEY-inheritance bug (RFC 9665 S3.2.5.1), pinned at the handler level: a service
// instance with no explicit KEY inherits the Host Description's key MATERIAL, but at its
// OWN owner name. Before the fix, KeyFor returned the host's KEY record verbatim (including
// the host's own name), which made pkg/lease.NodeKey (name-scoped) compute the SAME node key
// for the instance as for the host -- so applyLocalMutations's wipe-then-reinsert for the
// instance silently clobbered the host's own A record with the instance's SRV/TXT/PTR data,
// all within this single Handle() call. If that regresses, the host node's non-KEY record
// set below will contain the wrong RR type.
func TestSRPHandle_FreshRegistration_InstanceKeyInheritsHostMaterialAtItsOwnName(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest1.dev.zenr.io."
	inst := oneWidgetInstance()[0].name

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)

	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusProcessed {
		t.Fatalf("expected Processed, got %s (%s): %v", res.Status, res.Reason, res.Error)
	}
	if res.Message == nil || res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got: %+v", res.Message)
	}
	if len(coord.sent) != 2 {
		t.Fatalf("expected 2 upstream sends (registration + RFC 6763 S9 enumeration reconcile), got %d", len(coord.sent))
	}

	hostNodeKey := leasepkg.NodeKey(id.keyAt(host))
	instNodeKey := leasepkg.NodeKey(id.keyAt(inst)) // same key material as the host, computed independently at the instance's own name

	hostSet := h.leaseManager.GetNonKEYRecordSet(hostNodeKey)
	if hostSet == nil || len(hostSet.Records) != 1 {
		t.Fatalf("expected the host node to hold exactly its own A record, got: %+v", hostSet)
	}
	for _, rec := range hostSet.Records {
		if _, ok := rec.RR.(*dns.A); !ok {
			t.Fatalf("host node's record is a %T, want *dns.A -- this is exactly the KEY-inheritance bug's symptom (the instance's records landing on the host's own node)", rec.RR)
		}
	}

	instSet := h.leaseManager.GetNonKEYRecordSet(instNodeKey)
	if instSet == nil || len(instSet.Records) != 3 { // SRV + TXT + PTR
		t.Fatalf("expected the instance node to hold SRV+TXT+PTR (3 records), got: %+v", instSet)
	}
}

// TestSRPHandle_ForwardsSynthesizedKEYForInstanceThatOmittedIt pins RFC 9665 S3.3.3's own
// MUST: "After the SRP Update has been applied, every Service Description that is updated
// MUST have a KEY RR". buildSRPUpdate (like this project's own client/srp requester) never
// includes an explicit KEY in the Service Description -- Handle()'s step 7 must still forward
// one, synthesized from the Host Description's key material at the instance's own name, or
// that MUST is silently violated (and a later live FCFS query for the instance name, e.g.
// after a proxy restart, can never find one -- see synthesizeOmittedInstanceKeys's own doc
// comment for the full chain).
func TestSRPHandle_ForwardsSynthesizedKEYForInstanceThatOmittedIt(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest1b.dev.zenr.io."
	inst := oneWidgetInstance()[0].name

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("expected Processed, got %s: %v", res.Status, res.Error)
	}

	want := id.keyAt(inst)
	found := false
	for _, rr := range coord.sent[0].Ns {
		key, ok := rr.(*dns.KEY)
		if !ok || key.Hdr.Class == dns.ClassNONE {
			continue
		}
		if canonicalName(key.Hdr.Name) == canonicalName(inst) &&
			key.Algorithm == want.Algorithm && key.Protocol == want.Protocol && key.PublicKey == want.PublicKey {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a synthesized KEY add at the instance's own name (%s) matching the host's key material, got Ns: %+v", inst, coord.sent[0].Ns)
	}
}

// TestSRPHandle_RestartRefreshSucceeds_WhenUpstreamHasSynthesizedInstanceKey pins the actual
// end-to-end fix for the restart-refuses-refresh bug this project found live, mechanically
// linked rather than independently asserted: a first handler registers the instance and its
// forwarded KEY is extracted directly from what it actually sent upstream (not hand-built),
// then fed into a SECOND, entirely fresh handler (empty local lease store, simulating a proxy
// restart) as that second handler's simulated upstream state. If synthesizeOmittedInstanceKeys
// were removed, phase 1 would forward no instance KEY, phase 2's simulated upstream would have
// none to find, and this test would fail exactly the way the real bug did (REFUSED).
func TestSRPHandle_RestartRefreshSucceeds_WhenUpstreamHasSynthesizedInstanceKey(t *testing.T) {
	id := newSRPTestIdentity(t)
	const host = "srptest1c.dev.zenr.io."
	inst := oneWidgetInstance()[0].name

	// Phase 1: register through a first handler, then pull the instance's KEY straight out
	// of what it actually forwarded upstream.
	h1, coord1 := newSRPTestHandler(t)
	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	if res := h1.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("phase 1 registration: expected Processed, got %s: %v", res.Status, res.Error)
	}
	var forwardedInstKey *dns.KEY
	for _, rr := range coord1.sent[0].Ns {
		if key, ok := rr.(*dns.KEY); ok && key.Hdr.Class != dns.ClassNONE && canonicalName(key.Hdr.Name) == canonicalName(inst) {
			forwardedInstKey = key
		}
	}
	if forwardedInstKey == nil {
		t.Fatalf("phase 1: no instance KEY was forwarded upstream at all -- can't simulate a restart finding it, got Ns: %+v", coord1.sent[0].Ns)
	}

	// Phase 2: a brand new handler (nothing shared with h1 -- simulates a real proxy
	// restart) whose simulated upstream state is exactly what phase 1 actually forwarded.
	h2, coord2 := newSRPTestHandler(t)
	coord2.keyState = srp.AuthKeyPresent
	coord2.keys = []*dns.KEY{forwardedInstKey}

	// A fresh message, not the same *dns.Msg phase 1 already processed -- Handle()
	// consumes/strips the SIG(0) signature from the message it verifies, so reusing the
	// same pointer here would fail signature verification, not FCFS.
	msg2 := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	res := h2.Handle(context.Background(), stubTCPResponseWriter{}, msg2)
	if res.Status != StatusProcessed {
		t.Fatalf("phase 2 (post-restart refresh): expected Processed given the upstream has phase 1's own forwarded KEY, got %s (%s): %v", res.Status, res.Reason, res.Error)
	}
}

func TestSRPHandle_RefreshSameKey(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest2.dev.zenr.io."
	spec := oneWidgetInstance()

	first := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, spec, 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, first); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// Second call, same host/instance/key -- FCFS this time must hit the STORE (not the
	// live query), and find its own key -- the same code path a real client's periodic
	// refresh takes.
	second := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, spec, 30, 1209600, host)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, second)
	if res.Status != StatusProcessed || res.Message == nil || res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("refresh: expected NOERROR, got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}
	if len(coord.sent) != 3 {
		t.Fatalf("expected 3 upstream sends (fresh forward + its enumeration add, refresh forward -- refresh's own enumeration reconcile is a no-op and sends nothing, since the service type set is unchanged), got %d", len(coord.sent))
	}
}

// --- FCFS ------------------------------------------------------------------------------

func TestSRPHandle_FCFSConflict(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	idA := newSRPTestIdentity(t)
	idB := newSRPTestIdentity(t)
	const host = "srptest3.dev.zenr.io."
	spec := oneWidgetInstance()

	first := buildSRPUpdate(t, srpTestZone, idA, host, []string{"192.0.2.1"}, spec, 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, first); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}
	sentBefore := len(coord.sent)

	second := buildSRPUpdate(t, srpTestZone, idB, host, []string{"192.0.2.2"}, spec, 30, 1209600, host)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, second)
	if res.Status != StatusError || res.Message == nil || res.Message.Rcode != dns.RcodeYXDomain {
		t.Fatalf("expected YXDOMAIN conflict, got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}
	if len(coord.sent) != sentBefore {
		t.Fatalf("FCFS conflict must be rejected before any upstream forward (deferred-mutation) -- sent count changed from %d to %d", sentBefore, len(coord.sent))
	}
}

// TestSRPHandle_HijackViaBundledHost_Refused pins the plan's own named FCFS scenario
// (S12.2: "hijack-via-bundled-host"): an attacker who owns no names of their own bundles a
// fake Host Description for someone else's ALREADY-REGISTERED host into their own update
// (signed by their own key, not the victim's), with a service instance riding along,
// hoping the bundled service gets authorized "for free" alongside the host claim. Every
// SRP update MUST restate its own Host Description (S3.3.2), and every service instance's
// SRV target MUST equal that same update's Host Description name (enforced by
// pkg/srp.Classify's reconcile step) -- so there's no way to bundle a service under a host
// without the SAME update also claiming that host outright, and the host name is always
// the first name Handle() checks (srp.Names, step 4). The attacker's claim on the host name
// fails FCFS (a different key already holds it) before SIG(0) verification or forwarding
// ever run, so the bundled service is rejected right along with it -- never independently
// evaluated, never forwarded, and the victim's own registration is left completely
// untouched.
func TestSRPHandle_HijackViaBundledHost_Refused(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	victim := newSRPTestIdentity(t)
	attacker := newSRPTestIdentity(t)
	const host = "victimhost.dev.zenr.io."

	victimMsg := buildSRPUpdate(t, srpTestZone, victim, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, victimMsg); res.Status != StatusProcessed {
		t.Fatalf("victim's legitimate registration: expected Processed, got %s: %v", res.Status, res.Error)
	}
	sentBefore := len(coord.sent)

	hijackInst := []srpInstanceSpec{{name: "Evil._http._tcp.dev.zenr.io.", port: 6666, txt: "pwned", svctype: "_http._tcp.dev.zenr.io."}}
	attackMsg := buildSRPUpdate(t, srpTestZone, attacker, host, []string{"198.51.100.1"}, hijackInst, 30, 1209600, host)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, attackMsg)

	if res.Status != StatusError || res.Message == nil || res.Message.Rcode != dns.RcodeYXDomain {
		t.Fatalf("expected YXDOMAIN (hijack rejected at the bundled host claim), got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}
	if len(coord.sent) != sentBefore {
		t.Fatalf("hijack attempt must be rejected before any upstream forward -- sent count changed from %d to %d", sentBefore, len(coord.sent))
	}

	victimHostNodeKey := leasepkg.NodeKey(victim.keyAt(host))
	set := h.leaseManager.GetNonKEYRecordSet(victimHostNodeKey)
	if set == nil || len(set.Records) != 1 {
		t.Fatalf("expected the victim's own host A record to remain, untouched, got: %+v", set)
	}
	for _, rec := range set.Records {
		a, ok := rec.RR.(*dns.A)
		if !ok || a.A.Addr.String() != "192.0.2.1" {
			t.Fatalf("victim's A record was altered by the rejected hijack attempt: %+v", rec.RR)
		}
	}

	hijackInstNodeKey := leasepkg.NodeKey(attacker.keyAt(hijackInst[0].name))
	if h.leaseManager.Get(hijackInstNodeKey) != nil {
		t.Fatalf("expected the attacker's bundled service instance to never have been registered")
	}
}

func TestSRPHandle_ForeignDataRefusedByDefault(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	fake := h.coordinator.(*fakeSRPCoordinator)
	fake.keyState = srp.AuthNoKey // simulates an authoritative name with data but no KEY
	id := newSRPTestIdentity(t)
	const host = "srptest4.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusError || res.Message == nil || res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED, got status=%s message=%+v", res.Status, res.Message)
	}
	if len(coord.sent) != 0 {
		t.Fatalf("expected no upstream forward for a refused request, got %d", len(coord.sent))
	}
}

func TestSRPHandle_ForeignDataAllowedWhenConfigured(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	h.refuseOnForeignData = false
	fake := h.coordinator.(*fakeSRPCoordinator)
	fake.keyState = srp.AuthNoKey
	id := newSRPTestIdentity(t)
	const host = "srptest5.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusProcessed {
		t.Fatalf("expected Processed when refuse_on_foreign_data=false, got %s: %v", res.Status, res.Error)
	}
}

// --- deferred-mutation (upstream-first) -----------------------------------------------

func TestSRPHandle_UpstreamRejection_NoLocalMutation(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	fake := h.coordinator.(*fakeSRPCoordinator)
	fake.sendResp = &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeServerFailure}}
	id := newSRPTestIdentity(t)
	const host = "srptest6.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusError || res.Message == nil || res.Message.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got status=%s message=%+v", res.Status, res.Message)
	}

	if rec := h.leaseManager.Get(leasepkg.NodeKey(id.keyAt(host))); rec != nil {
		t.Fatalf("deferred-mutation violated: local store was written despite the upstream UPDATE being rejected: %+v", rec)
	}
}

// TestSRPHandle_FreshRegistration_CarriesNameNotInUsePrerequisite pins the fix for a real
// FCFS TOCTOU race: this handler's own pre-forward FCFS check (step 6) and the actual
// upstream forward (step 7) are two separate round trips with a window between them, so
// two concurrent first-time registrations of the same never-before-seen name could
// previously both observe "no local record, live NXDOMAIN" and both be forwarded with
// nothing tying the check to the write -- the authoritative server could accept both,
// breaking FCFS. Attaching an RFC 2136 "Name is not in use" prerequisite (CLASS=NONE,
// TYPE=ANY) to the forwarded UPDATE makes the authoritative server itself re-enforce the
// same condition atomically at write time.
func TestSRPHandle_FreshRegistration_CarriesNameNotInUsePrerequisite(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	coord.keyState = srp.AuthNXDomain // "never seen this name before" -- the FCFS race case
	id := newSRPTestIdentity(t)
	const host = "srptest6b.dev.zenr.io."
	const inst = "widget._http._tcp.dev.zenr.io." // Classify canonicalizes (lower-cases) names

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("expected Processed, got %s: %v", res.Status, res.Error)
	}

	if len(coord.sent) != 2 {
		t.Fatalf("expected 2 upstream sends (registration + RFC 6763 S9 enumeration reconcile), got %d", len(coord.sent))
	}
	prereqs := coord.sent[0].Answer
	wantNames := map[string]bool{host: false, inst: false}
	for _, rr := range prereqs {
		hdr := rr.Header()
		if _, ok := wantNames[hdr.Name]; !ok {
			continue
		}
		if hdr.Class != dns.ClassNONE || dns.RRToType(rr) != dns.TypeANY {
			t.Fatalf("prerequisite for %s has unexpected shape: class=%v type=%v", hdr.Name, hdr.Class, dns.RRToType(rr))
		}
		wantNames[hdr.Name] = true
	}
	for name, found := range wantNames {
		if !found {
			t.Fatalf("expected a \"Name is not in use\" prerequisite for %s in the forwarded UPDATE's Prerequisite section, got: %+v", name, prereqs)
		}
	}
}

// TestSRPHandle_UpstreamYXRRSet_MapsToYXDomainConflict pins the other half of the same
// fix: when a step-6 prerequisite no longer holds by the time the authoritative server
// itself evaluates it (a genuine race lost), the server rejects the UPDATE with
// YXRRSET/NXRRSET -- this must be reported to the client as a normal FCFS conflict
// (YXDOMAIN), the same as a conflict caught locally, not as a generic SERVFAIL, and must
// not mutate local state (the deferred-mutation pattern: nothing is written locally until
// after an upstream success).
func TestSRPHandle_UpstreamYXRRSet_MapsToYXDomainConflict(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	coord.keyState = srp.AuthNXDomain
	coord.sendResp = &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeYXRrset}}
	id := newSRPTestIdentity(t)
	const host = "srptest6c.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusError || res.Message == nil || res.Message.Rcode != dns.RcodeYXDomain {
		t.Fatalf("expected YXDOMAIN (FCFS conflict caught atomically by upstream), got status=%s message=%+v", res.Status, res.Message)
	}
	if rec := h.leaseManager.Get(leasepkg.NodeKey(id.keyAt(host))); rec != nil {
		t.Fatalf("deferred-mutation violated: local store was written despite the upstream UPDATE being rejected: %+v", rec)
	}
}

// --- transport hardening ---------------------------------------------------------------

func TestSRPHandle_RejectsUDPWhenNotAllowed(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest7.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	res := h.Handle(context.Background(), stubResponseWriter{}, msg) // UDP peer (opcode5_sig0_validation_test.go)
	if res.Status != StatusError || res.Message == nil || res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED for UDP, got status=%s message=%+v", res.Status, res.Message)
	}
	if len(coord.sent) != 0 {
		t.Fatalf("UDP rejection must happen before any upstream contact, got %d sends", len(coord.sent))
	}
}

func TestSRPHandle_AllowsUDPWhenConfigured(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	h.allowUDP = true
	id := newSRPTestIdentity(t)
	const host = "srptest7b.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	res := h.Handle(context.Background(), stubResponseWriter{}, msg)
	if res.Status != StatusProcessed {
		t.Fatalf("expected Processed when allow_udp=true, got %s: %v", res.Status, res.Error)
	}
}

// --- routing / dispatch (D2) ------------------------------------------------------------

func TestSRPHandle_NotSRPShaped_NotRelevant(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	msg := dns.NewMsg(srpTestZone, dns.TypeSOA)
	msg.Opcode = dns.OpcodeUpdate
	// No Update-section content at all -- Classify rejects for "no Host Description",
	// which Handle() must treat as NotRelevant, not Error (D2: falls through to the next
	// module / plain forwarding, exactly like a plain RFC 9664 UPDATE reaching this handler).

	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusNotRelevant {
		t.Fatalf("expected NotRelevant, got %s", res.Status)
	}
}

func TestSRPHandle_WrongZone_NotRelevant(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest8.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	msg.Question[0].Header().Name = "other.example." // not this handler's configured zone

	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusNotRelevant {
		t.Fatalf("expected NotRelevant for a foreign zone, got %s (%s)", res.Status, res.Reason)
	}
}

// --- default.service.arpa. rewrite (Phase 6, plan S4.3 step 5 / D5) -----------------------

// TestSRPHandle_DefaultServiceARPA_RejectedWhenRewriteDisabled pins the pre-Phase-6 default:
// a client addressing default.service.arpa. against a handler configured for a real zone,
// with the rewrite feature off, is declined exactly like any other foreign zone.
func TestSRPHandle_DefaultServiceARPA_RejectedWhenRewriteDisabled(t *testing.T) {
	h, _ := newSRPTestHandler(t) // rewriteDefaultServiceARPA defaults to false
	id := newSRPTestIdentity(t)
	const host = "cnnhost1.default.service.arpa."

	msg := buildSRPUpdate(t, defaultServiceARPA, id, host, []string{"192.0.2.1"}, nil, 30, 1209600, host)

	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusNotRelevant {
		t.Fatalf("expected NotRelevant with rewrite disabled, got %s (%s)", res.Status, res.Reason)
	}
}

// TestSRPHandle_DefaultServiceARPA_RewrittenToUpstreamZone is Phase 6's own happy path: a
// client that only knows default.service.arpa. (real SRP clients hardcode it, D5) reaches a
// handler configured for a real zone with the rewrite enabled. Confirms every layer sees the
// rewritten name -- the upstream forward, the local lease-store tree -- while the response
// still echoes back default.service.arpa., exactly what the client itself sent.
func TestSRPHandle_DefaultServiceARPA_RewrittenToUpstreamZone(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	h.rewriteDefaultServiceARPA = true
	id := newSRPTestIdentity(t)
	const cnnHost = "cnnhost2.default.service.arpa."
	const realHost = "cnnhost2.dev.zenr.io."
	instances := []srpInstanceSpec{{
		name: "Widget._http._tcp.default.service.arpa.", port: 8080, txt: "path=/",
		svctype: "_http._tcp.default.service.arpa.",
	}}

	msg := buildSRPUpdate(t, defaultServiceARPA, id, cnnHost, []string{"192.0.2.1"}, instances, 30, 1209600, cnnHost)

	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusProcessed || res.Message == nil || res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected Processed/NOERROR, got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}

	// The response's own Zone Section must still be default.service.arpa. -- the client's
	// own request symmetry, unaffected by what happened internally.
	if got := res.Message.Question[0].Header().Name; canonicalName(got) != canonicalName(defaultServiceARPA) {
		t.Fatalf("response Zone Section = %q, want default.service.arpa. (echoed from the request)", got)
	}

	// The upstream forward must carry the REWRITTEN names -- default.service.arpa. must not
	// appear anywhere in what actually reaches the authoritative server.
	if len(coord.sent) != 2 {
		t.Fatalf("expected 2 upstream sends (registration + RFC 6763 S9 enumeration reconcile), got %d", len(coord.sent))
	}
	sawRealHost, sawRealInstance := false, false
	for _, rr := range coord.sent[0].Ns {
		name := canonicalName(rr.Header().Name)
		if strings.Contains(name, "default.service.arpa") {
			t.Fatalf("upstream forward still carries a default.service.arpa. name: %s", rr.String())
		}
		if name == canonicalName(realHost) {
			sawRealHost = true
		}
		if srv, ok := rr.(*dns.SRV); ok {
			if strings.Contains(canonicalName(srv.SRV.Target), "default.service.arpa") {
				t.Fatalf("upstream SRV target still carries a default.service.arpa. name: %s", srv.String())
			}
			if canonicalName(srv.SRV.Target) == canonicalName(realHost) {
				sawRealInstance = true
			}
		}
	}
	if !sawRealHost {
		t.Fatalf("upstream forward never mentions the rewritten host name %s", realHost)
	}
	if !sawRealInstance {
		t.Fatalf("upstream forward's SRV target was never rewritten to point at %s", realHost)
	}

	// The local lease-store tree is keyed by the rewritten identity too.
	hostNodeKey := leasepkg.NodeKey(id.keyAt(realHost))
	if h.leaseManager.GetNonKEYRecordSet(hostNodeKey) == nil {
		t.Fatalf("local lease store has no node under the rewritten host name %s", realHost)
	}
}

// TestSRPHandle_DefaultServiceARPA_UnifiesFCFSWithRealZoneClient is the correctness property
// the whole early-rewrite design (rather than rewriting only at the very last, upstream-
// forwarding step) exists for: a constrained client that only ever addresses
// default.service.arpa. and a "direct" client addressing the real zone by name must not be
// able to squat the same logical host under two different keys -- FCFS has to see them as
// the exact same name.
func TestSRPHandle_DefaultServiceARPA_UnifiesFCFSWithRealZoneClient(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	h.rewriteDefaultServiceARPA = true
	owner := newSRPTestIdentity(t)
	attacker := newSRPTestIdentity(t)
	const realHost = "shared.dev.zenr.io."
	const cnnHost = "shared.default.service.arpa."

	// The real-zone client registers first, directly.
	first := buildSRPUpdate(t, srpTestZone, owner, realHost, []string{"192.0.2.1"}, nil, 30, 1209600, realHost)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, first); res.Status != StatusProcessed {
		t.Fatalf("real-zone registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// A different identity then tries the "same" host via default.service.arpa. -- after
	// rewrite this is the exact same name FCFS already has a record for, under a different
	// key, so it must be rejected exactly like a same-zone conflict.
	second := buildSRPUpdate(t, defaultServiceARPA, attacker, cnnHost, []string{"192.0.2.2"}, nil, 30, 1209600, cnnHost)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, second)
	if res.Status != StatusError || res.Message == nil || res.Message.Rcode != dns.RcodeYXDomain {
		t.Fatalf("expected YXDOMAIN (FCFS conflict across the rewrite boundary), got status=%s message=%+v", res.Status, res.Message)
	}
}

// --- rewriteDefaultServiceARPA / rewriteZoneSuffix (pure functions) -----------------------

func TestRewriteZoneSuffix(t *testing.T) {
	cases := []struct {
		name, realZone, want string
	}{
		{"myhost.default.service.arpa.", "dev.zenr.io.", "myhost.dev.zenr.io."},
		{"MyHost.DEFAULT.SERVICE.ARPA.", "dev.zenr.io.", "MyHost.dev.zenr.io."}, // case-insensitive match, prefix case preserved
		{"myhost.example.com.", "dev.zenr.io.", "myhost.example.com."},          // no matching suffix: unchanged
		{"default.service.arpa.", "dev.zenr.io.", "dev.zenr.io."},               // the suffix alone
		// A trailing-byte match that isn't a real subdomain (its first label is
		// "evildefault", not "default") must pass through unchanged, not be corrupted
		// by concatenating realZone onto the leftover "evil" prefix with no separating
		// dot.
		{"evildefault.service.arpa.", "dev.zenr.io.", "evildefault.service.arpa."},
	}
	for _, c := range cases {
		if got := rewriteZoneSuffix(c.name, c.realZone); got != c.want {
			t.Errorf("rewriteZoneSuffix(%q, %q) = %q, want %q", c.name, c.realZone, got, c.want)
		}
	}
}

func TestRewriteDefaultServiceARPA_OwnerAndTargetNames(t *testing.T) {
	msg := &dns.Msg{}
	msg.Ns = []dns.RR{
		srpMustRR(t, "myhost.default.service.arpa. 3600 IN A 192.0.2.1"),
		srpMustRR(t, "Widget._http._tcp.default.service.arpa. 3600 IN SRV 0 0 8080 myhost.default.service.arpa."),
		srpMustRR(t, "_http._tcp.default.service.arpa. 3600 IN PTR Widget._http._tcp.default.service.arpa."),
	}

	rewriteDefaultServiceARPA(msg, "srp.example.com.")

	if got := msg.Ns[0].Header().Name; got != "myhost.srp.example.com." {
		t.Errorf("A owner name = %q, want myhost.srp.example.com.", got)
	}
	srv := msg.Ns[1].(*dns.SRV)
	if srv.Hdr.Name != "Widget._http._tcp.srp.example.com." {
		t.Errorf("SRV owner name = %q, want Widget._http._tcp.srp.example.com.", srv.Hdr.Name)
	}
	if srv.SRV.Target != "myhost.srp.example.com." {
		t.Errorf("SRV target = %q, want myhost.srp.example.com.", srv.SRV.Target)
	}
	ptr := msg.Ns[2].(*dns.PTR)
	if ptr.Hdr.Name != "_http._tcp.srp.example.com." {
		t.Errorf("PTR owner name = %q, want _http._tcp.srp.example.com.", ptr.Hdr.Name)
	}
	if ptr.Ptr != "Widget._http._tcp.srp.example.com." {
		t.Errorf("PTR target = %q, want Widget._http._tcp.srp.example.com.", ptr.Ptr)
	}
}

// --- SIG(0) (step 4) ---------------------------------------------------------------------

func TestSRPHandle_MissingSIG0_Refused(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest9.dev.zenr.io."

	msg := buildSRPUpdateUnsigned(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusError || res.Message == nil || res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED for a missing SIG(0), got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}
	if len(coord.sent) != 0 {
		t.Fatalf("unsigned request must never reach the forward step, got %d sends", len(coord.sent))
	}
}

func TestSRPHandle_SignerNameMismatch_Refused(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest10.dev.zenr.io."

	unsigned := buildSRPUpdateUnsigned(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600)
	msg := id.sign(t, unsigned, id.keyAt("someoneelse.dev.zenr.io.")) // SIG(0) signer name != host

	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusError || res.Message == nil || res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED for signer/host mismatch, got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}
	if len(coord.sent) != 0 {
		t.Fatalf("expected no upstream forward, got %d sends", len(coord.sent))
	}
}

func TestSRPHandle_BadSignature_Refused(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	attacker := newSRPTestIdentity(t)
	const host = "srptest11.dev.zenr.io."

	unsigned := buildSRPUpdateUnsigned(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600)
	// SignerName matches the host, but the signature bytes come from a different private
	// key than the KEY RR the update itself carries for that name -- VerifySignature must
	// catch this cryptographically, not just via the name-match check above.
	msg := attacker.sign(t, unsigned, id.keyAt(host))

	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusError || res.Message == nil || res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED for a bad signature, got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}
}

// --- lease-store mutations (step 8) + forwarded message shape --------------------------

func TestSRPHandle_RemoveOneInstance(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest12.dev.zenr.io."
	inst := oneWidgetInstance()[0].name

	first := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, first); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	removal := []srpInstanceSpec{{name: inst, removalShaped: true}}
	second := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, removal, 30, 1209600, host)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, second)
	if res.Status != StatusProcessed {
		t.Fatalf("removal: expected Processed, got %s: %v", res.Status, res.Error)
	}

	instNodeKey := leasepkg.NodeKey(id.keyAt(inst))
	if set := h.leaseManager.GetNonKEYRecordSet(instNodeKey); set != nil && len(set.Records) != 0 {
		t.Fatalf("expected the instance's non-KEY records to be cleared after removal, got: %+v", set.Records)
	}

	if len(coord.sent) != 4 {
		t.Fatalf("expected 4 upstream sends (registration + its enumeration reconcile, removal + its enumeration reconcile), got %d", len(coord.sent))
	}
	// sent[0]=registration forward, sent[1]=its RFC 6763 S9 enumeration reconcile,
	// sent[2]=removal forward (checked below), sent[3]=its own enumeration reconcile.
	var foundDeleteAll, foundPTRDelete bool
	for _, rr := range coord.sent[2].Ns {
		if any, ok := rr.(*dns.ANY); ok && canonicalName(any.Hdr.Name) == canonicalName(inst) {
			foundDeleteAll = true
		}
		// The instance's own Delete All RRsets never reaches its PTR -- that's owned at
		// the (different, shared) service-type name -- so ptrDeleteDiff must emit an
		// explicit delete for it. Skipping removal-shaped instances entirely here (the
		// original implementation, on the mistaken assumption the delete-all "already
		// covers everything") was a real bug caught by the local BIND 9 harness (plan
		// S12.2/S14 Option C): it left every removed instance's PTR permanently orphaned
		// upstream.
		if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Class == dns.ClassNONE && canonicalName(ptr.Ptr) == canonicalName(inst) {
			foundPTRDelete = true
		}
	}
	if !foundDeleteAll {
		t.Fatalf("expected the removal update forwarded upstream to include the instance's own Delete All RRsets, got Ns: %+v", coord.sent[2].Ns)
	}
	if !foundPTRDelete {
		t.Fatalf("expected the removal update forwarded upstream to include an explicit PTR delete at the shared service-type name, got Ns: %+v", coord.sent[2].Ns)
	}

	// sent[3] is the removal's own RFC 6763 S9 enumeration reconcile: with no other
	// registrant providing _http._tcp (the fake's default QueryPTRExists = false), it must
	// actually delete the now-unused type from the enumeration record.
	enumOwner := "_services._dns-sd._udp." + srpTestZone
	foundEnumDelete := false
	for _, rr := range coord.sent[3].Ns {
		if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Class == dns.ClassNONE && canonicalName(ptr.Hdr.Name) == canonicalName(enumOwner) {
			foundEnumDelete = true
		}
	}
	if !foundEnumDelete {
		t.Fatalf("expected the removal's own enumeration reconcile to delete the now-unused type, got Ns: %+v", coord.sent[3].Ns)
	}
}

// TestSRPHandle_ServiceEnumeration_KeepsListedWhenAnotherRegistrantStillProvidesType pins
// the real bug this design was built to avoid, caught live against the real, shared
// dev.zenr.io. zone: a second, independent proxy process (or a restart of the same one)
// has no local knowledge of a type a DIFFERENT/earlier registrant provided, so removing the
// one instance THIS process does know about must not blindly delete the shared enumeration
// entry out from under that other, still-live registrant. QueryPTRExists standing in for
// "yes, something else still answers a real browse for this type" is exactly the live check
// reconcileServiceEnumeration performs before ever emitting a delete.
func TestSRPHandle_ServiceEnumeration_KeepsListedWhenAnotherRegistrantStillProvidesType(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest12b.dev.zenr.io."
	inst := oneWidgetInstance()[0].name

	first := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, first); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// Another registrant this process doesn't manage still answers a browse for the type.
	coord.ptrExists = true

	removal := []srpInstanceSpec{{name: inst, removalShaped: true}}
	second := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, removal, 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, second); res.Status != StatusProcessed {
		t.Fatalf("removal: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// Only the removal's own instance-forward should have been sent -- its enumeration
	// reconcile must see nothing to change (the type is neither newly present nor safe to
	// delete) and send nothing at all.
	if len(coord.sent) != 3 {
		t.Fatalf("expected 3 upstream sends (registration forward, its enumeration add, removal forward -- no enumeration send for the removal, since the type is still live elsewhere), got %d", len(coord.sent))
	}
	// The removal forward (sent[2]) legitimately includes its own, unrelated PTR delete
	// (ptrDeleteDiff, the per-type browsing PTR pointing at this specific instance) -- only
	// the RFC 6763 S9 enumeration owner name is what must never appear as a delete here.
	enumOwner := "_services._dns-sd._udp." + srpTestZone
	for _, msg := range coord.sent {
		for _, rr := range msg.Ns {
			if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Class == dns.ClassNONE && canonicalName(ptr.Hdr.Name) == canonicalName(enumOwner) {
				t.Fatalf("expected no enumeration-record delete while another registrant still provides the type, got: %s", ptr.String())
			}
		}
	}
}

// alwaysOnDomainEnumPrefixes are the three RFC 6763 S11 prefixes reconcileServiceEnumeration
// publishes whenever at least one service type is live, with no config opt-in required --
// "r"/"dr" (registration domains) are separately gated behind advertiseRegistrationDomain and
// covered by their own tests below.
var alwaysOnDomainEnumPrefixes = []string{"b", "db", "lb"}

// TestSRPHandle_BrowseDomains_AddedOnRegistrationRemovedWhenZoneEmpties exercises the three
// always-on RFC 6763 S11 domain-enumeration PTRs (b/db/lb, all self-pointing at the zone)
// reconcileServiceEnumeration now also maintains alongside the S9 type-enumeration record: a
// domain-enumeration browse tool (e.g. a "browse everything" inspector) queries one of these
// FIRST, before it ever asks for the S9 type list -- without them, a zone with perfectly
// correct S9/S4.1 data is still invisible to such a tool. This pins all three appearing
// together on the first registration and disappearing together once the zone's only
// registration is removed (mirroring the S9 type record's own add-then-delete shape, bundled
// into the same upstream messages).
func TestSRPHandle_BrowseDomains_AddedOnRegistrationRemovedWhenZoneEmpties(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest12c.dev.zenr.io."
	inst := oneWidgetInstance()[0].name

	first := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, first); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// sent[0]=registration forward, sent[1]=its RFC 6763 S9/S11 enumeration reconcile.
	for _, prefix := range alwaysOnDomainEnumPrefixes {
		owner := prefix + "._dns-sd._udp." + srpTestZone
		found := false
		for _, rr := range coord.sent[1].Ns {
			if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Class == dns.ClassINET && canonicalName(ptr.Hdr.Name) == canonicalName(owner) {
				if canonicalName(ptr.Ptr) != canonicalName(srpTestZone) {
					t.Fatalf("%s: expected the domain-enumeration PTR to point at the zone itself, got %q", prefix, ptr.Ptr)
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("expected the registration's own enumeration reconcile to add the %q domain-enumeration PTR, got Ns: %+v", prefix, coord.sent[1].Ns)
		}
	}

	removal := []srpInstanceSpec{{name: inst, removalShaped: true}}
	second := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, removal, 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, second); res.Status != StatusProcessed {
		t.Fatalf("removal: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// sent[2]=removal forward, sent[3]=its own enumeration reconcile.
	for _, prefix := range alwaysOnDomainEnumPrefixes {
		owner := prefix + "._dns-sd._udp." + srpTestZone
		found := false
		for _, rr := range coord.sent[3].Ns {
			if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Class == dns.ClassNONE && canonicalName(ptr.Hdr.Name) == canonicalName(owner) {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected the removal's own enumeration reconcile to delete the now-unused %q domain-enumeration PTR, got Ns: %+v", prefix, coord.sent[3].Ns)
		}
	}
}

// TestSRPHandle_BrowseDomains_KeptWhenAnotherRegistrantStillProvidesAType mirrors
// TestSRPHandle_ServiceEnumeration_KeepsListedWhenAnotherRegistrantStillProvidesType for the
// always-on S11 domain-enumeration PTRs: removing the only instance THIS process knows about
// must not delete b/db/lb out from under a different, still-live registrant elsewhere in the
// same shared zone.
func TestSRPHandle_BrowseDomains_KeptWhenAnotherRegistrantStillProvidesAType(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest12d.dev.zenr.io."
	inst := oneWidgetInstance()[0].name

	first := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, first); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// Another registrant this process doesn't manage still answers a browse for the type.
	coord.ptrExists = true

	removal := []srpInstanceSpec{{name: inst, removalShaped: true}}
	second := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, removal, 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, second); res.Status != StatusProcessed {
		t.Fatalf("removal: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// Same as the S9 type-enumeration analogue: with the type still live elsewhere, none of
	// these records has anything to change, so the removal's own enumeration reconcile sends
	// nothing at all -- only the removal forward itself (sent[2]) is expected.
	if len(coord.sent) != 3 {
		t.Fatalf("expected 3 upstream sends (registration forward, its enumeration add, removal forward -- no enumeration send for the removal), got %d", len(coord.sent))
	}
	for _, msg := range coord.sent {
		for _, rr := range msg.Ns {
			ptr, ok := rr.(*dns.PTR)
			if !ok || ptr.Hdr.Class != dns.ClassNONE {
				continue
			}
			for _, prefix := range alwaysOnDomainEnumPrefixes {
				owner := prefix + "._dns-sd._udp." + srpTestZone
				if canonicalName(ptr.Hdr.Name) == canonicalName(owner) {
					t.Fatalf("expected no %q domain-enumeration PTR delete while another registrant still provides a service type, got: %s", prefix, ptr.String())
				}
			}
		}
	}
}

// TestSRPHandle_RegistrationDomains_OffByDefault confirms "r"/"dr" (RFC 6763 S11's
// registration-domain records) are never published unless the operator opts in via
// advertise_registration_domain -- unlike b/db/lb, advertising this zone as an open target
// for direct RFC 2136 Dynamic Update registration is a deployment policy choice, not implied
// by SRP working here.
func TestSRPHandle_RegistrationDomains_OffByDefault(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest12e.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	for _, prefix := range []string{"r", "dr"} {
		owner := prefix + "._dns-sd._udp." + srpTestZone
		for _, sent := range coord.sent {
			for _, rr := range sent.Ns {
				if ptr, ok := rr.(*dns.PTR); ok && canonicalName(ptr.Hdr.Name) == canonicalName(owner) {
					t.Fatalf("expected no %q record without advertise_registration_domain, got: %s", prefix, ptr.String())
				}
			}
		}
	}
}

// TestSRPHandle_RegistrationDomains_PublishedWhenOptedIn confirms "r"/"dr" appear, self-
// pointing at the zone exactly like b/db/lb, once advertiseRegistrationDomain is set.
func TestSRPHandle_RegistrationDomains_PublishedWhenOptedIn(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	h.advertiseRegistrationDomain = true
	id := newSRPTestIdentity(t)
	const host = "srptest12f.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// sent[1] is the registration's own enumeration reconcile.
	for _, prefix := range []string{"r", "dr"} {
		owner := prefix + "._dns-sd._udp." + srpTestZone
		found := false
		for _, rr := range coord.sent[1].Ns {
			if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Class == dns.ClassINET && canonicalName(ptr.Hdr.Name) == canonicalName(owner) {
				if canonicalName(ptr.Ptr) != canonicalName(srpTestZone) {
					t.Fatalf("%s: expected the registration-domain PTR to point at the zone itself, got %q", prefix, ptr.Ptr)
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("expected the enumeration reconcile to add the %q registration-domain PTR when opted in, got Ns: %+v", prefix, coord.sent[1].Ns)
		}
	}
}

// TestSRPHandle_PTRDiff_DropsSubtypeOnUpdate exercises ptrDeleteDiff: upstream never
// delete-alls a PTR's owner name (it's the shared service *type*, plan S4.4/S4.5), so
// dropping a subtype registration on a live (still-SRV-shaped) instance needs its own
// explicit "Delete An RR From An RRSet" in the forwarded message, or the authoritative
// server never finds out even though the local store's wipe-then-reinsert already dropped it.
func TestSRPHandle_PTRDiff_DropsSubtypeOnUpdate(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest13.dev.zenr.io."
	const inst = "Widget._http._tcp.dev.zenr.io."
	const svctype = "_http._tcp.dev.zenr.io."
	const subtype = "_printer._sub._http._tcp.dev.zenr.io."

	withSubtype := []srpInstanceSpec{{name: inst, port: 8080, txt: "path=/", svctype: svctype, subtype: subtype}}
	first := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, withSubtype, 30, 1209600, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, first); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	withoutSubtype := []srpInstanceSpec{{name: inst, port: 8080, txt: "path=/", svctype: svctype}} // subtype dropped
	second := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, withoutSubtype, 30, 1209600, host)
	res := h.Handle(context.Background(), stubTCPResponseWriter{}, second)
	if res.Status != StatusProcessed {
		t.Fatalf("drop-subtype update: expected Processed, got %s: %v", res.Status, res.Error)
	}
	if len(coord.sent) != 3 {
		t.Fatalf("expected 3 upstream sends (fresh forward + its enumeration add, drop-subtype forward -- its own enumeration reconcile is a no-op and sends nothing, since the service type set is unchanged), got %d", len(coord.sent))
	}

	// sent[0]=fresh forward, sent[1]=its RFC 6763 S9 enumeration add, sent[2]=the
	// drop-subtype update's own forward (checked below; no enumeration reconcile follows
	// it, since dropping a subtype doesn't change the service type set).
	foundDeleteForSubtype := false
	for _, rr := range coord.sent[2].Ns {
		ptr, ok := rr.(*dns.PTR)
		if !ok || ptr.Hdr.Class != dns.ClassNONE {
			continue
		}
		if canonicalName(ptr.Hdr.Name) == canonicalName(subtype) {
			foundDeleteForSubtype = true
		}
	}
	if !foundDeleteForSubtype {
		t.Fatalf("expected an explicit PTR delete for the dropped subtype %s in the forwarded upstream message, got Ns: %+v", subtype, coord.sent[2].Ns)
	}
}

// --- expiry (S3.4 maintenance) -----------------------------------------------------------

// disarmAutoExpiry stops the background timer Handle()'s own step 9 (scheduleLeaseExpiry)
// already armed for nodeKey. The expiry tests below use a deliberately short lease so they
// don't have to wait long for IsExpired() to become true, but that means Handle() itself
// also armed a real timer that would otherwise race a test's own direct call to
// processExpiredNode -- disarming it isolates the test to exactly the call under test.
func disarmAutoExpiry(h *SRPHandler, nodeKey string) {
	h.leaseTimersMu.Lock()
	defer h.leaseTimersMu.Unlock()
	if timer, ok := h.leaseTimers[nodeKey]; ok {
		timer.Stop()
	}
	delete(h.leaseTimers, nodeKey)
}

func TestSRPHandle_ExpiryDeletesUpstreamThenLocally(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest14.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 1, 1, host) // 1s LEASE and KEY-LEASE
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// Disarm BOTH nodes' auto-armed timers, not just the host's: the instance shares the
	// same ~1s keyLease, so its own timer would otherwise race this test's manual call
	// (DeleteSubtree cascades either way, but with it racing, which goroutine's own
	// reconcileServiceEnumeration call observes/updates h.serviceTypes first becomes
	// nondeterministic -- see TestSRPHandle_ExpiryCoversWholeSubtree's identical reasoning).
	hostNodeKey := leasepkg.NodeKey(id.keyAt(host))
	instNodeKey := leasepkg.NodeKey(id.keyAt(oneWidgetInstance()[0].name))
	disarmAutoExpiry(h, hostNodeKey)
	disarmAutoExpiry(h, instNodeKey)
	time.Sleep(1100 * time.Millisecond)
	rec := h.leaseManager.Get(hostNodeKey)
	if rec == nil || !rec.IsExpired() {
		t.Fatalf("expected the host node to be expired by now, got: %+v", rec)
	}

	sentBefore := len(coord.sent)
	h.processExpiredNode(context.Background(), hostNodeKey)

	if len(coord.sent) != sentBefore+2 {
		t.Fatalf("expected exactly two additional upstream sends on expiry (the delete + its RFC 6763 S9 enumeration reconcile), got %d -> %d", sentBefore, len(coord.sent))
	}
	// The reconcile that follows the expiry delete is last; the delete itself is
	// second-to-last.
	lastSent := coord.sent[len(coord.sent)-2]
	foundDeleteAll := false
	for _, rr := range lastSent.Ns {
		// processExpiredNode sends a Delete All RRsets (class ANY) at the node's own name,
		// not a single-RR KEY delete -- the latter (this function's original
		// implementation) left the host's A record permanently orphaned upstream once the
		// local subtree was gone locally, a real bug caught by the local BIND 9 test
		// harness (plan S12.2/S14 Option C).
		if any, ok := rr.(*dns.ANY); ok && any.Hdr.Class == dns.ClassANY && canonicalName(any.Hdr.Name) == canonicalName(host) {
			foundDeleteAll = true
		}
	}
	if !foundDeleteAll {
		t.Fatalf("expected the expiry's upstream message to Delete All RRsets at the host's name, got Ns: %+v", lastSent.Ns)
	}
	if h.leaseManager.Get(hostNodeKey) != nil {
		t.Fatalf("expected the host node to be removed from the local store after a successful upstream expiry-delete")
	}
}

// TestSRPHandle_ExpiryPTRCleanup confirms processExpiredNode's PTR handling: a service
// instance's own delete-all can't reach a PTR at the (possibly shared) service-type name
// (plan S4.4/S4.5), so every PTR the expiring instance currently holds needs its own
// explicit delete alongside the delete-all -- mirroring ptrDeleteDiff's reasoning for the
// live-update path.
func TestSRPHandle_ExpiryPTRCleanup(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest14b.dev.zenr.io."
	inst := oneWidgetInstance()[0].name

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 1, 1, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	// Disarm BOTH nodes' auto-armed timers: DeleteSubtree cascades to children, so an
	// un-disarmed host timer firing first would silently remove the instance's record too
	// before this test's own manual call ever ran.
	hostNodeKey := leasepkg.NodeKey(id.keyAt(host))
	instNodeKey := leasepkg.NodeKey(id.keyAt(inst))
	disarmAutoExpiry(h, hostNodeKey)
	disarmAutoExpiry(h, instNodeKey)
	time.Sleep(1100 * time.Millisecond)

	h.processExpiredNode(context.Background(), instNodeKey)

	// The expiry delete is followed by one more upstream call (reconcileServiceEnumeration,
	// RFC 6763 S9), so it's second-to-last, not last.
	lastSent := coord.sent[len(coord.sent)-2]
	var foundDeleteAll, foundPTRDelete bool
	for _, rr := range lastSent.Ns {
		if any, ok := rr.(*dns.ANY); ok && canonicalName(any.Hdr.Name) == canonicalName(inst) {
			foundDeleteAll = true
		}
		if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Class == dns.ClassNONE && canonicalName(ptr.Ptr) == canonicalName(inst) {
			foundPTRDelete = true
		}
	}
	if !foundDeleteAll {
		t.Fatalf("expected a Delete All RRsets at the instance's own name, got Ns: %+v", lastSent.Ns)
	}
	if !foundPTRDelete {
		t.Fatalf("expected an explicit PTR delete at the shared service-type name, got Ns: %+v", lastSent.Ns)
	}
}

// TestSRPHandle_ExpiryCoversWholeSubtree pins a fourth real bug found via the local BIND 9
// harness: a host and its service instances are normally registered with matching lease
// durations, so they typically expire within milliseconds of each other via their own,
// independent timers. The original processExpiredNode built an upstream delete for ONLY the
// expiring node itself -- if a child instance's own expiry attempt fired first and was
// transiently rejected (left pending retry) and the host's own expiry then succeeded a few
// milliseconds later, DeleteSubtree(hostNodeKey) would cascade-remove that still-pending
// child from the local store anyway, permanently losing track of its unresolved upstream
// state (no later reconciliation pass would ever see it again). The fix: the expiring node's
// upstream delete now covers its WHOLE subtree, so by the time DeleteSubtree cascades
// locally, every descendant really has just been deleted upstream too. This test calls
// processExpiredNode directly on the HOST node (skipping the instance's own timer entirely,
// simulating exactly that ordering) and asserts the single resulting upstream message
// already includes deletes for both the host and the instance (+ its PTR).
func TestSRPHandle_ExpiryCoversWholeSubtree(t *testing.T) {
	h, coord := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest14d.dev.zenr.io."
	inst := oneWidgetInstance()[0].name

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 1, 1, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	hostNodeKey := leasepkg.NodeKey(id.keyAt(host))
	instNodeKey := leasepkg.NodeKey(id.keyAt(inst))
	disarmAutoExpiry(h, hostNodeKey)
	disarmAutoExpiry(h, instNodeKey)
	time.Sleep(1100 * time.Millisecond)

	// Only the host's own expiry runs -- the instance's own timer never fires at all here,
	// simulating "child's independent attempt hasn't happened yet."
	h.processExpiredNode(context.Background(), hostNodeKey)

	// processExpiredNode's own upstream delete is followed by one more upstream call
	// (reconcileServiceEnumeration, RFC 6763 S9 -- the now-empty zone's enumeration record
	// is republished after the subtree is gone), so the delete itself is second-to-last,
	// not last.
	lastSent := coord.sent[len(coord.sent)-2]
	var foundHostDelete, foundInstDelete, foundPTRDelete bool
	for _, rr := range lastSent.Ns {
		if any, ok := rr.(*dns.ANY); ok {
			switch canonicalName(any.Hdr.Name) {
			case canonicalName(host):
				foundHostDelete = true
			case canonicalName(inst):
				foundInstDelete = true
			}
		}
		if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Class == dns.ClassNONE && canonicalName(ptr.Ptr) == canonicalName(inst) {
			foundPTRDelete = true
		}
	}
	if !foundHostDelete {
		t.Fatalf("expected a Delete All RRsets at the host's own name, got Ns: %+v", lastSent.Ns)
	}
	if !foundInstDelete {
		t.Fatalf("expected the host's own expiry to ALSO cover its child instance's Delete All RRsets, got Ns: %+v", lastSent.Ns)
	}
	if !foundPTRDelete {
		t.Fatalf("expected the host's own expiry to ALSO cover its child instance's PTR delete, got Ns: %+v", lastSent.Ns)
	}
	if h.leaseManager.Get(instNodeKey) != nil {
		t.Fatalf("expected the cascaded-away instance node to be gone from the local store too")
	}
}

// TestSRPHandle_ExpiryUpstreamRejection_NoLocalMutation pins a second real bug found via
// the local BIND 9 harness: processExpiredNode originally checked only the transport-level
// error from SendUpdate, never the response's RCODE -- so a REFUSED/SERVFAIL response (BIND
// was observed to transiently REFUSE one of two near-simultaneous same-key expiry deletes
// for sibling nodes) still fell through to DeleteSubtree, removing the node locally even
// though upstream still had it. The existing 30s reconciliation pass (startLeaseReconciliation)
// is what actually recovers from this in practice; this test pins the local half: a rejected
// expiry-delete must leave the node in the local store, exactly like a transport failure does.
func TestSRPHandle_ExpiryUpstreamRejection_NoLocalMutation(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest14c.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 1, 1, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	hostNodeKey := leasepkg.NodeKey(id.keyAt(host))
	disarmAutoExpiry(h, hostNodeKey)
	time.Sleep(1100 * time.Millisecond)

	fake := h.coordinator.(*fakeSRPCoordinator)
	fake.sendResp = &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeRefused}}

	h.processExpiredNode(context.Background(), hostNodeKey)

	if h.leaseManager.Get(hostNodeKey) == nil {
		t.Fatalf("expected the host node to remain in the local store after a REFUSED upstream expiry-delete")
	}
}

// TestSRPHandle_ExpiryConcurrentRefreshRace_StillDeletesLocally pins the deliberately
// detection-only fix for the race a user identified: applyLocalMutations only runs after a
// refresh's OWN upstream write is independently confirmed, so a refresh landing while this
// node's own expiry-delete is in flight upstream leaves the node no-longer-expired by the
// time processExpiredNode checks again -- but that refresh's write and this function's
// delete are two independent, uncoordinated upstream transactions, so which one the
// authoritative server actually applied last is genuinely unknowable from here. Skipping
// DeleteSubtree in that case would be no more likely correct than not skipping it (see the
// function's own doc comment), so this only logs for operator visibility -- it does NOT
// change behavior. This test pins exactly that: DeleteSubtree still runs regardless of the
// detected race. (The log line itself isn't asserted here: logging.Logger always writes to
// os.Stdout with no injectable writer, so there's no clean capture point from a test.)
func TestSRPHandle_ExpiryConcurrentRefreshRace_StillDeletesLocally(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest14f.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, nil, nil, 1, 1, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	hostNodeKey := leasepkg.NodeKey(id.keyAt(host))
	disarmAutoExpiry(h, hostNodeKey)
	time.Sleep(1100 * time.Millisecond)

	fake := h.coordinator.(*fakeSRPCoordinator)
	// Simulate a concurrent client refresh landing (and being locally applied) WHILE this
	// expiry's own upstream delete is in flight -- exactly the window Handle()'s own
	// upstream-then-local ordering leaves open to a completely independent goroutine. Fires
	// once only: processExpiredNode's own upstream delete is followed by a second upstream
	// call (reconcileServiceEnumeration, RFC 6763 S9), by which point DeleteSubtree has
	// already run and there is no longer a lease to renew -- this callback simulates the
	// race during the expiry delete specifically, not every subsequent upstream call.
	var fired bool
	fake.onSendUpdate = func() {
		if fired {
			return
		}
		fired = true
		if err := h.leaseManager.RenewLease(context.Background(), id.keyAt(host), 3600, 3600); err != nil {
			t.Fatalf("simulated concurrent refresh: RenewLease: %v", err)
		}
	}

	h.processExpiredNode(context.Background(), hostNodeKey)

	// Detection-only: the local cascade still runs unconditionally, exactly as it would
	// without the race -- this test's job is to confirm the new detection code path adds
	// no behavior change, only visibility.
	if h.leaseManager.Get(hostNodeKey) != nil {
		t.Fatalf("expected DeleteSubtree to still run regardless of the detected race (detection-only, no behavior change)")
	}
}

func TestSRPHandle_ExpiryUpstreamFailure_LeavesLocalStateIntact(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	id := newSRPTestIdentity(t)
	const host = "srptest15.dev.zenr.io."

	msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 1, 1, host)
	if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
		t.Fatalf("fresh registration: expected Processed, got %s: %v", res.Status, res.Error)
	}

	hostNodeKey := leasepkg.NodeKey(id.keyAt(host))
	disarmAutoExpiry(h, hostNodeKey)
	time.Sleep(1100 * time.Millisecond)

	fake := h.coordinator.(*fakeSRPCoordinator)
	fake.sendErr = context.DeadlineExceeded // simulate an upstream delete that fails to send

	h.processExpiredNode(context.Background(), hostNodeKey)

	// Upstream-first: a failed expiry-delete must leave the node in the local store (so a
	// later reconciliation pass or refresh can retry), not remove it optimistically.
	if h.leaseManager.Get(hostNodeKey) == nil {
		t.Fatalf("expected the host node to remain in the local store after a failed upstream expiry-delete")
	}
}
