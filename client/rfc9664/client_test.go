package rfc9664

import (
	"context"
	"errors"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/clienttest"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

// sent is what an update asks for: its zone, the KEYs and other records in its Update
// section, and its leases.
type sent struct {
	zone     string
	keys     []string
	records  []string
	lease    uint32
	keyLease uint32
}

func summarize(t *testing.T, m *dns.Msg) sent {
	t.Helper()
	s := sent{zone: m.Question[0].Header().Name}
	lo, err := leasepkg.FindAndDecode(m)
	if err != nil || lo.KeyLease == nil {
		t.Fatalf("update carries no 8-byte Update Lease option: %v", err)
	}
	s.lease, s.keyLease = lo.Lease, *lo.KeyLease
	for _, rr := range m.Ns {
		if k, ok := rr.(*dns.KEY); ok {
			s.keys = append(s.keys, k.Hdr.Name)
			continue
		}
		s.records = append(s.records, describe([]dns.RR{rr}))
	}
	return s
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.New(s)
	if err != nil {
		t.Fatalf("dns.New(%q): %v", s, err)
	}
	return rr
}

func testKey(t *testing.T) *keyrec.LoadedKey {
	t.Helper()
	key, err := keyrec.GenerateKey("site.example.", dns.ECDSAP256SHA256, 0, 256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func testConfig(t *testing.T, send baseclient.Transport, records ...string) Config {
	t.Helper()
	cfg := Config{
		Zone:              "example",
		Label:             "site",
		Key:               testKey(t),
		RequestedLease:    30,
		RequestedKeyLease: 600,
		Server:            "127.0.0.1:8053",
		Send:              send,
		Rng:               rand.New(rand.NewSource(1)),
	}
	for _, r := range records {
		cfg.Records = append(cfg.Records, mustRR(t, r))
	}
	return cfg
}

// answering is a Transport answering each update with the next of answers, the last one
// again once they run out, and keeping what it was sent.
type answering struct {
	answers []*dns.Msg
	sent    []*dns.Msg
}

func (a *answering) Send(ctx context.Context, addr string, network baseclient.Network, msg *dns.Msg) (*dns.Msg, error) {
	a.sent = append(a.sent, msg)
	resp := a.answers[0]
	if len(a.answers) > 1 {
		a.answers = a.answers[1:]
	}
	return resp, nil
}

func TestNewClient_Refuses(t *testing.T) {
	for _, tt := range []struct {
		name   string
		modify func(*Config)
		want   string
	}{
		{"no zone", func(c *Config) { c.Zone = "" }, "Zone is required"},
		{"two labels", func(c *Config) { c.Label = "www.site" }, "Label"},
		{"no key", func(c *Config) { c.Key = nil }, "Key is required"},
		{"no server", func(c *Config) { c.Server = "" }, "Server is required"},
		{"lease above key lease", func(c *Config) { c.RequestedLease = 700 }, "must not exceed"},
		{"record elsewhere", func(c *Config) {
			c.Records = []dns.RR{mustRR(t, "other.example. 300 IN A 192.0.2.1")}
		}, "not at or below site.example."},
		{"record above", func(c *Config) {
			c.Records = []dns.RR{mustRR(t, "example. 300 IN A 192.0.2.1")}
		}, "not at or below site.example."},
		{"a KEY", func(c *Config) {
			c.Records = []dns.RR{mustRR(t, "www.site.example. 300 IN KEY 512 3 13 c29tZW9uZSBlbHNl")}
		}, "a KEY is not registered as a record"},
		{"class CH", func(c *Config) {
			c.Records = []dns.RR{mustRR(t, "site.example. 300 CH TXT \"x\"")}
		}, "want IN"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t, nil, "site.example. 300 IN A 192.0.2.1")
			tt.modify(&cfg)
			_, err := NewClient(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NewClient() error = %v, want one mentioning %q", err, tt.want)
			}
		})
	}
}

// Every request carries the name's KEY, signed with it, and the zone in its Zone Section; the
// cases differ in their records and leases (Behavior Specification item 5).
func TestClient_Cases(t *testing.T) {
	www := "www.site.example. CNAME site.example."
	for _, tt := range []struct {
		name string
		call func(*Client) (*dns.Msg, baseclient.Outcome, error)
		want sent
	}{
		{"register (Case A)", func(c *Client) (*dns.Msg, baseclient.Outcome, error) {
			return c.Register(context.Background())
		}, sent{records: []string{"site.example. A 192.0.2.1", "www.site.example. CNAME site.example."}, lease: 30, keyLease: 600}},
		{"withdraw (Case D)", func(c *Client) (*dns.Msg, baseclient.Outcome, error) {
			return c.Withdraw(context.Background(), []dns.RR{mustRR(t, www)})
		}, sent{records: []string{"www.site.example. CNAME site.example."}, lease: 0, keyLease: 600}},
		{"deregister keeping the name (Case D)", func(c *Client) (*dns.Msg, baseclient.Outcome, error) {
			return c.Deregister(context.Background(), true)
		}, sent{records: []string{"site.example. A 192.0.2.1", "www.site.example. CNAME site.example."}, lease: 0, keyLease: 600}},
		{"deregister freeing the name (Case C)", func(c *Client) (*dns.Msg, baseclient.Outcome, error) {
			return c.Deregister(context.Background(), false)
		}, sent{lease: 0, keyLease: 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tr := &answering{answers: []*dns.Msg{clienttest.Granted(30, 600)}}
			c, err := NewClient(testConfig(t, tr.Send, "site.example. 3600 IN A 192.0.2.1", www))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if _, outcome, err := tt.call(c); err != nil || outcome != baseclient.OutcomeSuccess {
				t.Fatalf("outcome %s, error %v", outcome, err)
			}
			if len(tr.sent) != 1 {
				t.Fatalf("%d updates sent, want 1", len(tr.sent))
			}
			if err := sig0.VerifySignature(tr.sent[0], c.cfg.Key.PublicKey); err != nil {
				t.Fatalf("update does not verify against the name's key: %v", err)
			}
			got := summarize(t, tr.sent[0])
			tt.want.zone, tt.want.keys = "example.", []string{"site.example."}
			if got.zone != tt.want.zone || !slices.Equal(got.keys, tt.want.keys) || !slices.Equal(got.records, tt.want.records) || got.lease != tt.want.lease || got.keyLease != tt.want.keyLease {
				t.Fatalf("sent %+v, want %+v", got, tt.want)
			}
			for _, rr := range tr.sent[0].Ns {
				if rr.Header().TTL != 300 {
					t.Errorf("%s: TTL %d, want the configured 300", rr.Header().Name, rr.Header().TTL)
				}
			}
		})
	}
}

func TestClient_RegisterNeedsARecord(t *testing.T) {
	tr := &answering{answers: []*dns.Msg{clienttest.Granted(30, 600)}}
	c, err := NewClient(testConfig(t, tr.Send))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := c.Register(context.Background()); err == nil || !strings.Contains(err.Error(), "needs a record") {
		t.Fatalf("Register() error = %v, want one about the missing record", err)
	}
	if len(tr.sent) != 0 {
		t.Fatalf("%d updates sent, want none", len(tr.sent))
	}
}

// A name another key holds is not renamed: Run reports it and tries the same name again,
// after a backoff, until the proxy accepts it.
func TestClient_RunRetriesAHeldNameWithoutRenaming(t *testing.T) {
	tr := &answering{answers: []*dns.Msg{clienttest.Answer(dns.RcodeYXDomain), clienttest.Answer(dns.RcodeYXDomain), clienttest.Granted(30, 600)}}
	cfg := testConfig(t, tr.Send, "site.example. 300 IN A 192.0.2.1")
	var errs []error
	var delays []time.Duration
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		delays = append(delays, d)
		return ctx.Err()
	}
	cfg.OnError = func(err error) { errs = append(errs, err) }
	cfg.OnRegistered = func(*dns.Msg) { cancel() }
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v, want context.Canceled", err)
	}
	if len(errs) != 2 || !strings.Contains(errs[0].Error(), "held by another key") {
		t.Fatalf("errors %v, want two about the name held by another key", errs)
	}
	if len(tr.sent) != 3 {
		t.Fatalf("%d updates sent, want 3", len(tr.sent))
	}
	for _, m := range tr.sent {
		if got := summarize(t, m); !slices.Equal(got.keys, []string{"site.example."}) {
			t.Fatalf("update for %v, want site.example. every time", got.keys)
		}
	}
	// The initial delay, then two backoffs, doubling.
	if len(delays) < 3 || delays[2] != 2*delays[1] {
		t.Fatalf("delays %v, want the initial delay and a doubling backoff", delays)
	}
}

func TestDiff_ComparesAsTheLeaseStore(t *testing.T) {
	before := []dns.RR{
		mustRR(t, "site.example. 300 IN A 192.0.2.1"),
		mustRR(t, "www.site.example. 300 IN A 192.0.2.9"),
		mustRR(t, "site.example. 300 IN TXT \"v=1\""),
	}
	after := []dns.RR{
		mustRR(t, "SITE.example. 60 IN A 192.0.2.1"),      // other case and TTL: the same record
		mustRR(t, "www.site.example. 300 IN A 192.0.2.2"), // other data: another record
	}
	var got []string
	for _, rr := range Diff(before, after) {
		got = append(got, describe([]dns.RR{rr}))
	}
	want := []string{"www.site.example. A 192.0.2.9", "site.example. TXT \"v=1\""}
	if !slices.Equal(got, want) {
		t.Fatalf("Diff() = %q, want %q", got, want)
	}
}
