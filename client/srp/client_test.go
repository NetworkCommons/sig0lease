package srp

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/clienttest"
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
	networks  []baseclient.Network
	responses []*dns.Msg
	err       error
}

func (f *fakeTransport) Send(ctx context.Context, addr string, network baseclient.Network, msg *dns.Msg) (*dns.Msg, error) {
	f.sent = append(f.sent, msg)
	f.addrs = append(f.addrs, addr)
	f.networks = append(f.networks, network)
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

// TestNewClient_RejectsMalformedServiceType: a service type that isn't RFC 6763 S7's
// "_<service>._tcp|_udp" is refused before anything is sent -- PR #45's report registered
// "_vpnserver._wg._udp", which the registrar then enumerated as "_vpnserver._wg".
func TestNewClient_RejectsMalformedServiceType(t *testing.T) {
	transport := &fakeTransport{}
	cfg := testConfig(t, transport)
	cfg.Instances = []InstanceConfig{{Label: "vpnclient", ServiceType: "_vpnserver._wg._udp", TXT: []string{"txtver=1"}}}
	if _, err := NewClient(cfg); err == nil || !strings.Contains(err.Error(), "exactly two labels") {
		t.Fatalf("expected a service-type error, got: %v", err)
	}

	cfg.Instances = []InstanceConfig{{Label: "vpnclient", ServiceType: "_wg._udp", Subtypes: []string{"_vpnserver"}, TXT: []string{"txtver=1"}}}
	if _, err := NewClient(cfg); err != nil {
		t.Fatalf("NewClient with a two-label type and a subtype: %v", err)
	}
}

// TestNewClient_RejectsUnknownDiscoveryMode: a bad mode is a configuration error at
// NewClient, not a discovery failure that Run would report and retry on every cycle.
func TestNewClient_RejectsUnknownDiscoveryMode(t *testing.T) {
	cfg := testConfig(t, &fakeTransport{})
	cfg.Discovery = DiscoveryMode(7)
	if _, err := NewClient(cfg); err == nil || !strings.Contains(err.Error(), "unknown DiscoveryMode") {
		t.Fatalf("expected an unknown-mode error, got: %v", err)
	}
}

// TestNewClient_RejectsLabelThatIsNotOneDNSLabel: labels are joined into names by plain
// concatenation, so one containing "." would be registered as several labels -- RFC 6763
// S4.3 requires that boundary be kept, and the dns library can't carry such a label at all
// (pkg/dnsname's labels.go) -- and one over 63 octets can't be sent.
func TestNewClient_RejectsLabelThatIsNotOneDNSLabel(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"dotted host label", func(c *Config) { c.HostLabel = "my.host" }, "HostLabel"},
		{"dotted instance label", func(c *Config) { c.Instances[0].Label = "Printer v2.1" }, "label boundary"},
		{"dotted subtype", func(c *Config) { c.Instances[0].Subtypes = []string{"_a.b"} }, "subtype"},
		{"oversized instance label", func(c *Config) { c.Instances[0].Label = strings.Repeat("p", 64) }, "at most 63"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, &fakeTransport{})
			cfg.Instances = []InstanceConfig{{Label: "Printer", ServiceType: "_ipp._tcp", Port: 631}}
			tc.mutate(&cfg)
			if _, err := NewClient(cfg); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected an error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}

	// Spaces and non-ASCII text are fine in an Instance label (RFC 6763 S4.1.1), and reach
	// the registered name unchanged.
	cfg := testConfig(t, &fakeTransport{})
	cfg.Instances = []InstanceConfig{{Label: "Café Printer", ServiceType: "_ipp._tcp", Port: 631}}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got, want := c.specs(false)[0].Name, "Café Printer._ipp._tcp.example.com."; got != want {
		t.Fatalf("instance name = %q, want %q", got, want)
	}
}

func TestClient_Register_BuildsSignsAndSends(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Granted(30, 1209600)}}
	c, err := NewClient(testConfig(t, transport))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resp, outcome, err := c.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if outcome != baseclient.OutcomeSuccess {
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
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Granted(0, 0)}}
	cfg := testConfig(t, transport)
	cfg.Instances = []InstanceConfig{{Label: "Widget", ServiceType: "_http._tcp", Port: 80}}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resp, outcome, err := c.Deregister(context.Background(), false)
	if err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if outcome != baseclient.OutcomeSuccess {
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
	if lo, err := leasepkg.FindAndDecode(sent); err != nil || lo.Lease != 0 || lo.KeyLease == nil || *lo.KeyLease != 0 {
		t.Fatalf("lease option %+v (%v), want LEASE 0 and KEY-LEASE 0, a permanent removal", lo, err)
	}
}

// TestClient_Deregister_KeepingNames: keeping the names, the removal asks for the KEY-LEASE the
// client registers with (RFC 9665 S3.2.5.5.1), so the registrar holds the names for its key.
func TestClient_Deregister_KeepingNames(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Granted(0, 600)}}
	cfg := testConfig(t, transport)
	cfg.RequestedKeyLease = 600
	cfg.RequestedLease = 60
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, outcome, err := c.Deregister(context.Background(), true); err != nil || outcome != baseclient.OutcomeSuccess {
		t.Fatalf("Deregister: %v, %v", outcome, err)
	}
	if lo, err := leasepkg.FindAndDecode(transport.sent[0]); err != nil || lo.Lease != 0 || lo.KeyLease == nil || *lo.KeyLease != 600 {
		t.Fatalf("lease option %+v (%v), want LEASE 0 and KEY-LEASE 600", lo, err)
	}
}

// TestClient_Register_WithdrawsOneInstance: an instance with Remove set goes out as a bare
// Delete All RRsets (RFC 9665 S3.2.5.5.2), while the host keeps its addresses and the other
// instance is registered as usual.
func TestClient_Register_WithdrawsOneInstance(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Granted(30, 1209600)}}
	cfg := testConfig(t, transport)
	cfg.Instances = []InstanceConfig{
		{Label: "Screen", ServiceType: "_rfb._tcp", Remove: true},
		{Label: "Shell", ServiceType: "_ssh._tcp", Port: 22},
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	cu, err := pkgsrp.Validate(transport.sent[0])
	if err != nil {
		t.Fatalf("sent message failed Validate(): %v", err)
	}
	if len(cu.Host.Addresses) != 1 {
		t.Fatalf("host has %d address adds, want 1 (withdrawing an instance keeps the host)", len(cu.Host.Addresses))
	}
	srvByName := map[string]*dns.SRV{}
	for _, inst := range cu.Instances {
		srvByName[inst.Name] = inst.SRV
	}
	if srv, ok := srvByName["screen._rfb._tcp.example.com."]; !ok || srv != nil {
		t.Fatalf("Screen: present=%v SRV=%v, want a removal-shaped instance (SRV nil)", ok, srv)
	}
	if srv := srvByName["shell._ssh._tcp.example.com."]; srv == nil || srv.Port != 22 {
		t.Fatalf("Shell: SRV=%v, want a live registration on port 22", srv)
	}
	for _, d := range cu.Discovery {
		if d.Target == "screen._rfb._tcp.example.com." {
			t.Fatalf("withdrawn instance still has a Service Discovery instruction: %+v", d)
		}
	}
}

func TestClient_Register_DiscoversWhenNoExplicitAddr(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Granted(30, 1209600)}}
	cfg := testConfig(t, transport)
	cfg.RegistrarAddr = ""
	cfg.Query = (&fakeDNS{
		apexes: []string{"example.com."},
		srv:    map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {srvRR("registrar.example.com.", 0, 0, 8853)}},
		hosts:  registrarHosts,
	}).query
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if transport.addrs[0] != "192.0.2.1:8853" {
		t.Fatalf("sent to %q, want the discovered address", transport.addrs[0])
	}
}

// TestClient_Register_DiscoveryApexOnly: Config.Discovery reaches Discover. With a record at
// both the domain and its zone apex, DiscoveryApexOnly sends to the apex's registrar.
func TestClient_Register_DiscoveryApexOnly(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Granted(30, 1209600)}}
	cfg := testConfig(t, transport)
	cfg.Domain = "srp.example.com."
	cfg.RegistrarAddr = ""
	cfg.Discovery = DiscoveryApexOnly
	cfg.Query = (&fakeDNS{
		apexes: []string{"example.com."},
		srv: map[string][]*dns.SRV{
			"_dnssd-srp._tcp.example.com.":     {srvRR("apex-registrar.example.com.", 0, 0, 8853)},
			"_dnssd-srp._tcp.srp.example.com.": {srvRR("domain-registrar.example.com.", 0, 0, 8853)},
		},
		hosts: registrarHosts,
	}).query
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if transport.addrs[0] != "192.0.2.2:8853" {
		t.Fatalf("sent to %q, want apex-registrar's address", transport.addrs[0])
	}
}

func TestClient_Register_InterpretsConflict(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Answer(dns.RcodeYXDomain)}}
	c, err := NewClient(testConfig(t, transport))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, outcome, err := c.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if outcome != baseclient.OutcomeConflict {
		t.Fatalf("outcome = %v, want conflict", outcome)
	}
}

// heldBy is a DNSQuery answering a KEY query with another key's KEY at every name in held,
// and NXDOMAIN everywhere else.
func heldBy(held ...string) DNSQuery {
	return func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		resp := &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeNameError}}
		for _, h := range held {
			if strings.EqualFold(h, name) && qtype == dns.TypeKEY {
				k := &dns.KEY{}
				k.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: 300}
				k.Protocol, k.Algorithm, k.PublicKey = 3, dns.ECDSAP256SHA256, "c29tZW9uZSBlbHNl"
				resp.Rcode = dns.RcodeSuccess
				resp.Answer = []dns.RR{k}
			}
		}
		return resp, nil
	}
}

// Only the names another key holds are renamed, each from its own requested label.
func TestClient_RenameHeld_RenamesOnlyHeldNames(t *testing.T) {
	cfg := testConfig(t, &fakeTransport{})
	cfg.Instances = []InstanceConfig{
		{Label: "Widget", ServiceType: "_http._tcp", Port: 8080},
		{Label: "Shell", ServiceType: "_ssh._tcp", Port: 22},
	}
	cfg.Query = heldBy("myhost.example.com.", "Widget._http._tcp.example.com.", "Widget-2._http._tcp.example.com.")
	var saved []Labels
	cfg.OnRenamed = func(l Labels) { saved = append(saved, l) }
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.renameHeld(context.Background()); err != nil {
		t.Fatalf("renameHeld: %v", err)
	}
	specs := c.specs(false)
	if c.hostFQDN() != "myhost-2.example.com." || specs[0].Name != "Widget-2._http._tcp.example.com." || specs[1].Name != "Shell._ssh._tcp.example.com." {
		t.Fatalf("after one rename: host %q, instances %q %q; want myhost-2, Widget-2, Shell", c.hostFQDN(), specs[0].Name, specs[1].Name)
	}
	if err := c.renameHeld(context.Background()); err != nil {
		t.Fatalf("second renameHeld: %v", err)
	}
	specs = c.specs(false)
	if c.hostFQDN() != "myhost-2.example.com." || specs[0].Name != "Widget-3._http._tcp.example.com." {
		t.Fatalf("after a second rename: host %q, Widget %q; want myhost-2 kept (free), Widget-3", c.hostFQDN(), specs[0].Name)
	}
	if len(saved) != 2 || saved[1].Host != "myhost-2" || saved[1].Instances[InstanceName{Label: "Widget", ServiceType: "_http._tcp"}] != "Widget-3" {
		t.Fatalf("OnRenamed got %+v, want two calls, the last with myhost-2 and Widget-3", saved)
	}
}

// When the resolvers show no name held, the client does not guess: nothing is renamed, and
// the cycle fails for Run to retry.
func TestClient_RenameHeld_NothingHeldIsAnError(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Answer(dns.RcodeYXDomain)}}
	cfg := testConfig(t, transport)
	cfg.Query = heldBy()
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.registerWithRenameRetry(context.Background()); err == nil || !strings.Contains(err.Error(), "no name of this update holds another key") {
		t.Fatalf("expected the unexplained-conflict error, got: %v", err)
	}
	if len(transport.sent) != 1 || c.hostFQDN() != "myhost.example.com." {
		t.Fatalf("expected one attempt and no rename, got %d attempts, host %q", len(transport.sent), c.hostFQDN())
	}
}

func TestClient_RegisterWithRenameRetry_SucceedsAfterConflicts(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{
		clienttest.Answer(dns.RcodeYXDomain),
		clienttest.Answer(dns.RcodeYXDomain),
		clienttest.Granted(30, 1209600),
	}}
	cfg := testConfig(t, transport)
	cfg.Query = heldBy("myhost.example.com.", "myhost-2.example.com.")
	c, err := NewClient(cfg)
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
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Answer(dns.RcodeYXDomain)}} // repeats forever
	cfg := testConfig(t, transport)
	cfg.MaxRenames = 2
	cfg.Query = heldBy("myhost.example.com.", "myhost-2.example.com.", "myhost-3.example.com.")
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

// A client starts from the labels an earlier one renamed to, and refuses labels that are not
// renames of the requested ones.
func TestNewClient_Labels(t *testing.T) {
	cfg := testConfig(t, &fakeTransport{})
	cfg.Instances = []InstanceConfig{{Label: "Widget", ServiceType: "_http._tcp", Port: 8080}}
	widget := InstanceName{Label: "Widget", ServiceType: "_http._tcp"}
	cfg.Labels = &Labels{Host: "myhost-3", Instances: map[InstanceName]string{widget: "Widget-2", {Label: "Gone", ServiceType: "_ipp._tcp"}: "Gone-4"}}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.hostFQDN() != "myhost-3.example.com." || c.specs(false)[0].Name != "Widget-2._http._tcp.example.com." {
		t.Fatalf("host %q, instance %q; want myhost-3 and Widget-2", c.hostFQDN(), c.specs(false)[0].Name)
	}
	if got := c.Labels().Instances[InstanceName{Label: "Gone", ServiceType: "_ipp._tcp"}]; got != "Gone-4" {
		t.Fatalf("an absent instance's label must be kept, got %q", got)
	}

	for _, bad := range []Labels{
		{Host: "otherhost"},
		{Host: "myhost-1"},
		{Host: "myhost-02"},
		{Host: "myhost", Instances: map[InstanceName]string{widget: "Gadget-2"}},
	} {
		cfg.Labels = &bad
		if _, err := NewClient(cfg); err == nil || !strings.Contains(err.Error(), "rename of it") {
			t.Errorf("Labels %+v: expected a not-a-rename error, got %v", bad, err)
		}
	}
}

func TestClient_RegisterWithRenameRetry_NonConflictFailureStopsImmediately(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Answer(dns.RcodeRefused)}}
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
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Granted(30, 1209600), clienttest.Granted(30, 1209600)}}
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
	cfg.Query = (&fakeDNS{apexes: []string{"example.com."}}).query

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

// TestClient_Register_DefaultNetworkIsTCP: a Config that leaves baseclient.Network unset sends over TCP,
// RFC 9665 S3.5's requirement on networks that are not constrained.
func TestClient_Register_DefaultNetworkIsTCP(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Granted(30, 1209600)}}
	c, err := NewClient(testConfig(t, transport))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if transport.networks[0] != baseclient.NetworkTCP {
		t.Fatalf("sent over %s, want tcp", transport.networks[0])
	}
}

// TestClient_Register_TLSDiscoversTLSRegistrar: with baseclient.Network set to baseclient.NetworkTLS and no
// explicit address, the update goes over TLS to the registrar named by
// "_dnssd-srp-tls._tcp", not the "_dnssd-srp._tcp" one.
func TestClient_Register_TLSDiscoversTLSRegistrar(t *testing.T) {
	transport := &fakeTransport{responses: []*dns.Msg{clienttest.Granted(30, 1209600)}}
	cfg := testConfig(t, transport)
	cfg.RegistrarAddr = ""
	cfg.Network = baseclient.NetworkTLS
	cfg.Query = tlsAndPlainDNS().query
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if transport.addrs[0] != "192.0.2.2:853" || transport.networks[0] != baseclient.NetworkTLS {
		t.Fatalf("sent to %q over %s, want 192.0.2.2:853 over tls", transport.addrs[0], transport.networks[0])
	}
}

func TestNewClient_RejectsUnknownNetwork(t *testing.T) {
	cfg := testConfig(t, &fakeTransport{})
	cfg.Network = baseclient.Network(7)
	if _, err := NewClient(cfg); err == nil {
		t.Fatal("NewClient accepted an unknown baseclient.Network")
	}
}

// TestNetwork_String pins the protocol names baseclient.LiveTransport hands to the base client
// package's client.New, which accepts exactly these.
func TestNetwork_String(t *testing.T) {
	for n, want := range map[baseclient.Network]string{baseclient.NetworkTCP: "tcp", baseclient.NetworkTLS: "tls", baseclient.NetworkUDP: "udp"} {
		if got := n.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(n), got, want)
		}
	}
}

func TestEscapeTXT_PacksToTheRawBytes(t *testing.T) {
	raw := "a\\b\x00\xff\"q"
	m := &dns.Msg{}
	txt := &dns.TXT{Hdr: dns.Header{Name: "x.", Class: dns.ClassINET}}
	txt.TXT.Txt = []string{EscapeTXT(raw)}
	m.Answer = []dns.RR{txt}
	if err := m.Pack(); err != nil {
		t.Fatal(err)
	}
	if want := append([]byte{byte(len(raw))}, raw...); !bytes.HasSuffix(m.Data, want) {
		t.Errorf("packed TXT ends % x, want % x", m.Data[len(m.Data)-len(want):], want)
	}
}
