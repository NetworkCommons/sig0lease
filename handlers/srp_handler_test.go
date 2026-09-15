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
	if len(coord.sent) != 1 {
		t.Fatalf("expected exactly 1 upstream UPDATE sent, got %d", len(coord.sent))
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
	if len(coord.sent) != 2 {
		t.Fatalf("expected 2 upstream sends (fresh + refresh), got %d", len(coord.sent))
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
	if len(coord.sent) != 1 {
		t.Fatalf("expected exactly 1 upstream UPDATE sent, got %d", len(coord.sent))
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

	if len(coord.sent) != 2 {
		t.Fatalf("expected 2 upstream sends, got %d", len(coord.sent))
	}
	var foundDeleteAll, foundPTRDelete bool
	for _, rr := range coord.sent[1].Ns {
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
		t.Fatalf("expected the removal update forwarded upstream to include the instance's own Delete All RRsets, got Ns: %+v", coord.sent[1].Ns)
	}
	if !foundPTRDelete {
		t.Fatalf("expected the removal update forwarded upstream to include an explicit PTR delete at the shared service-type name, got Ns: %+v", coord.sent[1].Ns)
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
	if len(coord.sent) != 2 {
		t.Fatalf("expected 2 upstream sends, got %d", len(coord.sent))
	}

	foundDeleteForSubtype := false
	for _, rr := range coord.sent[1].Ns {
		ptr, ok := rr.(*dns.PTR)
		if !ok || ptr.Hdr.Class != dns.ClassNONE {
			continue
		}
		if canonicalName(ptr.Hdr.Name) == canonicalName(subtype) {
			foundDeleteForSubtype = true
		}
	}
	if !foundDeleteForSubtype {
		t.Fatalf("expected an explicit PTR delete for the dropped subtype %s in the forwarded upstream message, got Ns: %+v", subtype, coord.sent[1].Ns)
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

	hostNodeKey := leasepkg.NodeKey(id.keyAt(host))
	disarmAutoExpiry(h, hostNodeKey)
	time.Sleep(1100 * time.Millisecond)
	rec := h.leaseManager.Get(hostNodeKey)
	if rec == nil || !rec.IsExpired() {
		t.Fatalf("expected the host node to be expired by now, got: %+v", rec)
	}

	sentBefore := len(coord.sent)
	h.processExpiredNode(context.Background(), hostNodeKey)

	if len(coord.sent) != sentBefore+1 {
		t.Fatalf("expected exactly one additional upstream delete sent on expiry, got %d -> %d", sentBefore, len(coord.sent))
	}
	lastSent := coord.sent[len(coord.sent)-1]
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

	lastSent := coord.sent[len(coord.sent)-1]
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

	lastSent := coord.sent[len(coord.sent)-1]
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
	// upstream-then-local ordering leaves open to a completely independent goroutine.
	fake.onSendUpdate = func() {
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
