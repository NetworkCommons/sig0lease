package srp

import (
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
	pkgsrp "github.com/NetworkCommons/sig0lease/pkg/srp"
)

// fakeTransport records every message it's asked to send and returns canned responses in
// order (the last one repeats once exhausted) -- a small, deterministic stand-in for the
// network so Client's build/sign/retry/scheduling logic is testable without it.
type fakeTransport struct {
	sent      []*dns.Msg
	addrs     []string
	responses []*dns.Msg
	err       error
}

func (f *fakeTransport) Send(ctx context.Context, addr string, useTCP bool, msg *dns.Msg) (*dns.Msg, error) {
	f.sent = append(f.sent, msg)
	f.addrs = append(f.addrs, addr)
	if f.err != nil {
		return nil, f.err
	}
	idx := len(f.sent) - 1
	if idx >= len(f.responses) {
		idx = len(f.responses) - 1
	}
	if idx < 0 {
		return &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}, nil
	}
	return f.responses[idx], nil
}

func successResp(lease, keyLease uint32) *dns.Msg {
	resp := &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(dns.DefaultMsgSize)
	lo := leasepkg.Encode8Byte(lease, keyLease)
	_ = lo.Encode(opt)
	resp.Extra = append(resp.Extra, opt)
	return resp
}

func rcodeResp(rcode uint16) *dns.Msg {
	return &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: rcode}}
}

func testConfig(t *testing.T, transport *fakeTransport) Config {
	t.Helper()
	return Config{
		Domain:            "example.com.",
		HostLabel:         "myhost",
		Addresses:         []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		RegistrarAddr:     "127.0.0.1:8059", // bypass discovery
		RequestedLease:    30,
		RequestedKeyLease: 1209600,
		Send:              transport.Send,
		Rng:               rand.New(rand.NewSource(1)),
		Sleep:             func(ctx context.Context, d time.Duration) error { return nil },
	}
}

func TestClient_Register_BuildsSignsAndSends(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{successResp(30, 1209600)}}
	c, err := NewClient(testConfig(t, transport))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resp, outcome, err := c.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if outcome != pkgsrp.OutcomeSuccess {
		t.Fatalf("outcome = %v, want success", outcome)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("resp.Rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(transport.sent) != 1 {
		t.Fatalf("expected exactly 1 message sent, got %d", len(transport.sent))
	}
	if transport.addrs[0] != "127.0.0.1:8059" {
		t.Fatalf("sent to %q, want the configured RegistrarAddr", transport.addrs[0])
	}

	sent := transport.sent[0]
	if err := sig0.VerifySignature(sent, c.cfg.Key.PublicKey); err != nil {
		t.Fatalf("sent message does not verify against the client's own public key: %v", err)
	}

	cu, err := pkgsrp.Validate(sent)
	if err != nil {
		t.Fatalf("sent message failed Validate(): %v", err)
	}
	if cu.Host.Name != "myhost.example.com." {
		t.Fatalf("host name = %q, want %q", cu.Host.Name, "myhost.example.com.")
	}
}

func TestClient_Deregister_SendsRemovalShapedUpdate(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{successResp(0, 1209600)}}
	cfg := testConfig(t, transport)
	cfg.Instances = []InstanceConfig{{Label: "Widget", ServiceType: "_http._tcp", Port: 80}}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resp, outcome, err := c.Deregister(context.Background())
	if err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if outcome != pkgsrp.OutcomeSuccess {
		t.Fatalf("outcome = %v, want success", outcome)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("resp.Rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(transport.sent) != 1 {
		t.Fatalf("expected exactly 1 message sent, got %d", len(transport.sent))
	}

	sent := transport.sent[0]
	if err := sig0.VerifySignature(sent, c.cfg.Key.PublicKey); err != nil {
		t.Fatalf("sent message does not verify against the client's own public key: %v", err)
	}

	cu, err := pkgsrp.Validate(sent)
	if err != nil {
		t.Fatalf("sent message failed Validate(): %v", err)
	}
	if len(cu.Host.Addresses) != 0 {
		t.Fatalf("host has %d address adds, want 0 (Deregister must send zero addresses)", len(cu.Host.Addresses))
	}
	if len(cu.Instances) != 1 || cu.Instances[0].SRV != nil {
		t.Fatalf("expected exactly 1 removal-shaped instance (SRV nil), got %+v", cu.Instances)
	}
}

func TestClient_Register_DiscoversWhenNoExplicitAddr(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{successResp(30, 1209600)}}
	cfg := testConfig(t, transport)
	cfg.RegistrarAddr = ""
	cfg.Query = func(ctx context.Context, name string) ([]*dns.SRV, error) {
		return []*dns.SRV{srvRR("registrar.example.com.", 0, 0, 8853)}, nil
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if transport.addrs[0] != "registrar.example.com:8853" {
		t.Fatalf("sent to %q, want the discovered address", transport.addrs[0])
	}
}

func TestClient_Register_InterpretsConflict(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{rcodeResp(dns.RcodeYXDomain)}}
	c, err := NewClient(testConfig(t, transport))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, outcome, err := c.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if outcome != pkgsrp.OutcomeConflict {
		t.Fatalf("outcome = %v, want conflict", outcome)
	}
}

func TestClient_Rename_AppendsSuffixToHostAndInstances(t *testing.T) {
	transport := &fakeTransport{}
	cfg := testConfig(t, transport)
	cfg.Instances = []InstanceConfig{{Label: "Widget", ServiceType: "_http._tcp", Port: 8080}}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if c.hostFQDN() != "myhost.example.com." {
		t.Fatalf("initial host = %q", c.hostFQDN())
	}
	c.rename()
	if c.hostFQDN() != "myhost-2.example.com." {
		t.Fatalf("after 1 rename, host = %q, want %q", c.hostFQDN(), "myhost-2.example.com.")
	}
	if got := c.specs(false)[0].Name; got != "Widget-2._http._tcp.example.com." {
		t.Fatalf("after 1 rename, instance name = %q, want %q", got, "Widget-2._http._tcp.example.com.")
	}
	c.rename()
	if c.hostFQDN() != "myhost-3.example.com." {
		t.Fatalf("after 2 renames, host = %q, want %q", c.hostFQDN(), "myhost-3.example.com.")
	}
}

func TestClient_RegisterWithRenameRetry_SucceedsAfterConflicts(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{
		rcodeResp(dns.RcodeYXDomain),
		rcodeResp(dns.RcodeYXDomain),
		successResp(30, 1209600),
	}}
	c, err := NewClient(testConfig(t, transport))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	resp, err := c.registerWithRenameRetry(context.Background())
	if err != nil {
		t.Fatalf("registerWithRenameRetry: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("resp.Rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(transport.sent) != 3 {
		t.Fatalf("expected 3 attempts (2 conflicts + 1 success), got %d", len(transport.sent))
	}
	if c.hostFQDN() != "myhost-3.example.com." {
		t.Fatalf("expected 2 renames to have happened, host = %q", c.hostFQDN())
	}
}

func TestClient_RegisterWithRenameRetry_ExhaustsRetries(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{rcodeResp(dns.RcodeYXDomain)}} // repeats forever
	cfg := testConfig(t, transport)
	cfg.MaxRenames = 2
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.registerWithRenameRetry(context.Background())
	if err == nil {
		t.Fatal("expected an error after exhausting rename attempts")
	}
	if len(transport.sent) != 3 { // initial + 2 retries
		t.Fatalf("expected 3 attempts (1 + MaxRenames=2), got %d", len(transport.sent))
	}
}

func TestClient_RegisterWithRenameRetry_NonConflictFailureStopsImmediately(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{rcodeResp(dns.RcodeRefused)}}
	c, err := NewClient(testConfig(t, transport))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.registerWithRenameRetry(context.Background())
	if err == nil {
		t.Fatal("expected an error for REFUSED")
	}
	if len(transport.sent) != 1 {
		t.Fatalf("expected exactly 1 attempt (REFUSED is not retried), got %d", len(transport.sent))
	}
}

func TestClient_Run_SleepsInitialDelayThenRefreshesOnGrantedLease(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{successResp(30, 1209600), successResp(30, 1209600)}}
	cfg := testConfig(t, transport)

	var sleeps []time.Duration
	callCount := 0
	cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		callCount++
		if callCount >= 3 { // initial delay + 2 refresh sleeps observed is enough
			return context.Canceled
		}
		return nil
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	err = c.Run(context.Background())
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Run to return context.Canceled once Sleep signals it, got: %v", err)
	}
	if len(sleeps) < 2 {
		t.Fatalf("expected at least an initial delay + 1 refresh sleep, got %d calls", len(sleeps))
	}
	if sleeps[0] > 3*time.Second {
		t.Fatalf("first sleep (initial delay) = %v, want <= 3s", sleeps[0])
	}
	wantRefreshMin := 30 * time.Second * 80 / 100
	if sleeps[1] < wantRefreshMin {
		t.Fatalf("second sleep (refresh delay) = %v, want >= %v (80%% of granted 30s lease)", sleeps[1], wantRefreshMin)
	}
	if len(transport.sent) < 1 {
		t.Fatal("expected at least one registration to have been sent")
	}
}

// TestClient_Run_BackoffDoublesOnConsecutiveFailuresThenResets pins the shape of Run's
// retry backoff: it starts at minRegisterRetryBackoff, doubles on each consecutive
// failure, and resets back to the minimum the moment a cycle succeeds -- so the steady
// -state refresh clock after a recovery is the normal S5.2 clock, not a leftover
// multi-minute backoff from the outage that just ended.
func TestClient_Run_BackoffDoublesOnConsecutiveFailuresThenResets(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{
		rcodeResp(dns.RcodeServerFailure),
		rcodeResp(dns.RcodeServerFailure),
		successResp(30, 1209600),
	}}
	cfg := testConfig(t, transport)

	var sleeps []time.Duration
	callCount := 0
	cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		callCount++
		if callCount >= 4 { // initial delay + 2 backoffs + 1 post-success refresh sleep
			return context.Canceled
		}
		return nil
	}
	var gotErrs []error
	cfg.OnError = func(err error) { gotErrs = append(gotErrs, err) }

	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Run to stop via Sleep/ctx cancellation, got: %v", err)
	}
	if len(gotErrs) != 2 {
		t.Fatalf("expected exactly 2 OnError calls (for the 2 failed cycles), got %d: %v", len(gotErrs), gotErrs)
	}
	if len(sleeps) < 4 {
		t.Fatalf("expected at least 4 sleeps (initial, 2 backoffs, 1 refresh), got %d: %v", len(sleeps), sleeps)
	}
	if sleeps[1] != minRegisterRetryBackoff {
		t.Fatalf("first retry backoff = %v, want %v (the floor)", sleeps[1], minRegisterRetryBackoff)
	}
	if sleeps[2] != minRegisterRetryBackoff*2 {
		t.Fatalf("second retry backoff = %v, want %v (doubled)", sleeps[2], minRegisterRetryBackoff*2)
	}
	wantRefreshMin := 30 * time.Second * 80 / 100
	if sleeps[3] < wantRefreshMin {
		t.Fatalf("post-success sleep = %v, want >= %v (the reset refresh clock, not another backoff)", sleeps[3], wantRefreshMin)
	}
}

// TestClient_Run_RetriesOnDiscoveryFailure pins Run's fixed behavior: a failed
// registration cycle (discovery finding nothing, here -- but the same holds for any other
// registerWithRenameRetry error) no longer stops Run permanently. It's reported via
// Config.OnError and retried after a backoff instead, so a long-running daemon self-heals
// once discovery starts working again rather than needing an external restart. Only ctx
// (via the injected Sleep returning its cancellation) stops Run.
func TestClient_Run_RetriesOnDiscoveryFailure(t *testing.T) {
	transport := &fakeTransport{}
	cfg := testConfig(t, transport)
	cfg.RegistrarAddr = ""
	cfg.Query = func(ctx context.Context, name string) ([]*dns.SRV, error) { return nil, nil }

	var gotErrs []error
	cfg.OnError = func(err error) { gotErrs = append(gotErrs, err) }

	callCount := 0
	cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		callCount++
		if callCount >= 3 { // initial delay + a couple of retry backoffs is enough to observe retrying
			return context.Canceled
		}
		return nil
	}

	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Run to keep retrying and only stop via Sleep/ctx cancellation, got: %v", err)
	}
	if len(gotErrs) == 0 {
		t.Fatal("expected OnError to be called for the failed discovery attempts")
	}
}
