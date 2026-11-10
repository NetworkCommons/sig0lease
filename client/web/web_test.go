package web

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/browse"
	"github.com/NetworkCommons/sig0lease/client/clienttest"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// memStorage is a Storage in memory, as localStorage is in a browser.
type memStorage struct {
	mu sync.Mutex
	m  map[string]string
}

func newMemStorage() *memStorage { return &memStorage{m: map[string]string{}} }

func (s *memStorage) Get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	return v, ok
}

func (s *memStorage) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
	return nil
}

func (s *memStorage) Remove(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}

// update is what an UPDATE asked: its leases, its KEY's data, and its other records, each as
// "<class> <type> <data>" (class ANY or NONE deletes).
type update struct {
	lease, keyLease uint32
	key             string
	records         []string
}

// proxy stands in for the proxy over DoH: it passes every UPDATE to the test, granting the
// leases asked, and answers a query for a TXT record from txt.
type proxy struct {
	t       *testing.T
	updates chan update
	mu      sync.Mutex
	txt     map[string][]string
}

func newProxy(t *testing.T) *proxy {
	return &proxy{t: t, updates: make(chan update, 16), txt: map[string][]string{}}
}

func (p *proxy) send(ctx context.Context, addr string, network client.Network, msg *dns.Msg) (*dns.Msg, error) {
	if addr != "http://proxy:8443" || network != client.NetworkDoH {
		p.t.Errorf("sent to %s over %s, want http://proxy:8443 over doh", addr, network)
	}
	if msg.Opcode == dns.OpcodeQuery {
		resp := &dns.Msg{MsgHeader: dns.MsgHeader{ID: msg.ID, Response: true}, Question: msg.Question}
		name := msg.Question[0].Header().Name
		p.mu.Lock()
		defer p.mu.Unlock()
		if strs, ok := p.txt[name]; ok {
			txt := &dns.TXT{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 300}}
			for _, s := range strs {
				txt.TXT.Txt = append(txt.TXT.Txt, dnsmsg.EscapeTXT(s))
			}
			resp.Answer = append(resp.Answer, txt)
		}
		return resp, nil
	}
	lo, err := leasepkg.FindAndDecode(msg)
	if err != nil || lo.KeyLease == nil {
		p.t.Errorf("update carries no 8-byte Update Lease option: %v", err)
		return clienttest.Answer(dns.RcodeFormatError), nil
	}
	u := update{lease: lo.Lease, keyLease: *lo.KeyLease}
	for _, rr := range msg.Ns {
		if k, ok := rr.(*dns.KEY); ok {
			u.key = k.PublicKey
			continue
		}
		u.records = append(u.records, dnsutil.ClassToString(rr.Header().Class)+" "+dnsutil.TypeToString(dns.RRToType(rr))+" "+rr.Data().String())
	}
	p.updates <- u
	return clienttest.Granted(lo.Lease, *lo.KeyLease), nil
}

func (p *proxy) next(t *testing.T) update {
	t.Helper()
	select {
	case u := <-p.updates:
		return u
	case <-time.After(5 * time.Second):
		t.Fatal("no update sent")
		return update{}
	}
}

func (p *proxy) none(t *testing.T) {
	t.Helper()
	select {
	case u := <-p.updates:
		t.Fatalf("unexpected update: %+v", u)
	case <-time.After(1500 * time.Millisecond):
	}
}

func newPage(t *testing.T, p *proxy, s Storage) *Page {
	t.Helper()
	page, err := New(Config{DoH: "http://proxy:8443", UpdateDomain: "dev.zenr.io", SRPDomain: "srp.dev.zenr.io", Storage: s, Send: p.send, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	return page
}

// registers fails unless u registers records with the leases a claim asks for.
func registers(t *testing.T, what string, u update, records ...string) {
	t.Helper()
	if u.lease != lease || u.keyLease != keyLease || strings.Join(u.records, "|") != strings.Join(records, "|") {
		t.Fatalf("%s: sent %+v, want %q on lease %d, key lease %d", what, u, records, lease, keyLease)
	}
}

// frees fails unless u is the KEY alone, both leases 0: the deregistration that frees the name.
func frees(t *testing.T, what string, u update) {
	t.Helper()
	if u.lease != 0 || u.keyLease != 0 || len(u.records) != 0 || u.key == "" {
		t.Fatalf("%s: sent %+v, want the KEY alone, both leases 0", what, u)
	}
}

// closePage leaves page as a closing browser tab does: with nothing sent, its name's records
// stay registered until their lease ends. Its Name, idle until its next refresh, a lease away,
// is stopped when the test ends.
func closePage(t *testing.T, page *Page) {
	n := page.name
	t.Cleanup(func() { n.Stop(); n.Wait() })
}

// TestClaim: a claim registers the message at the name with a key it keeps; the page opened
// again resumes it with the same key and the records it kept, read back as they were, so it
// withdraws nothing; a claim of another name frees the first; Release frees the name and
// forgets the claim.
func TestClaim(t *testing.T) {
	p, s := newProxy(t), newMemStorage()
	page := newPage(t, p, s)
	// A quote, a backslash and octets outside ASCII, which the records kept must read back as
	// they were sent.
	message := `café ☕ "hi" \o/`
	if err := page.Claim("Alice", message); err != nil {
		t.Fatal(err)
	}
	first := p.next(t)
	registers(t, "claim", first, `IN TXT "caf\195\169 \226\152\149 \"hi\" \\o/"`)
	if c, ok, err := page.Claimed(); err != nil || !ok || c != (Claim{Label: "alice", Message: message}) {
		t.Fatalf("Claimed = %+v, %v, %v; want alice's claim", c, ok, err)
	}
	closePage(t, page)

	again := newPage(t, p, s)
	c, ok, err := again.Claimed()
	if err != nil || !ok {
		t.Fatalf("Claimed after reopening = %+v, %v, %v", c, ok, err)
	}
	if err := again.Claim(c.Label, c.Message); err != nil {
		t.Fatal(err)
	}
	resumed := p.next(t)
	registers(t, "resumed claim", resumed, first.records...)
	if resumed.key != first.key {
		t.Fatal("the resumed claim has another key")
	}

	if err := again.Claim("bob", "hello"); err != nil {
		t.Fatal(err)
	}
	frees(t, "claiming another name", p.next(t))
	bob := p.next(t)
	registers(t, "bob's claim", bob, `IN TXT "hello"`)
	if bob.key == first.key {
		t.Fatal("bob's name has alice's key")
	}

	if err := again.Release(); err != nil {
		t.Fatal(err)
	}
	frees(t, "Release", p.next(t))
	if _, ok, _ := again.Claimed(); ok {
		t.Fatal("the claim is kept after Release")
	}
	if err := again.Release(); err == nil || !strings.Contains(err.Error(), "no name is claimed") {
		t.Fatalf("Release with nothing claimed = %v, want an error", err)
	}
	p.none(t)
}

// TestRelease_NotResumed: Release frees a claim the page opened again has not resumed.
func TestRelease_NotResumed(t *testing.T) {
	p, s := newProxy(t), newMemStorage()
	page := newPage(t, p, s)
	if err := page.Claim("alice", "hi"); err != nil {
		t.Fatal(err)
	}
	first := p.next(t)
	closePage(t, page)

	again := newPage(t, p, s)
	if err := again.Release(); err != nil {
		t.Fatal(err)
	}
	u := p.next(t)
	frees(t, "Release", u)
	if u.key != first.key {
		t.Fatal("Release sent another key")
	}
	if _, ok, _ := again.Claimed(); ok {
		t.Fatal("the claim is kept after Release")
	}
}

func TestClaim_Refused(t *testing.T) {
	page := newPage(t, newProxy(t), newMemStorage())
	for _, c := range []struct{ label, message, wantErr string }{
		{"my name", "hi", "letters, digits and hyphens"},
		{"-a", "hi", "letters, digits and hyphens"},
		{"a.b", "hi", "letters, digits and hyphens"},
		{"alice", strings.Repeat("x", 256), "at most 255"},
	} {
		if err := page.Claim(c.label, c.message); err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("Claim(%q, %d bytes) = %v, want an error containing %q", c.label, len(c.message), err, c.wantErr)
		}
	}
	if page.name != nil {
		t.Fatal("a refused claim started a name")
	}
}

// TestStorage_Damaged: what the browser keeps, damaged, fails the claim, not replaced.
func TestStorage_Damaged(t *testing.T) {
	for _, key := range []string{claimKey, keyPrefix + "alice.dev.zenr.io.", recordsPrefix + "alice.dev.zenr.io."} {
		s := newMemStorage()
		page := newPage(t, newProxy(t), s)
		if err := page.Claim("alice", "hi"); err != nil {
			t.Fatal(err)
		}
		page.stop()
		s.Set(key, "{")
		if key == claimKey {
			if _, _, err := page.Claimed(); err == nil {
				t.Errorf("Claimed with %s damaged: no error", key)
			}
			continue
		}
		if err := page.Claim("alice", "hi"); err == nil || !strings.Contains(err.Error(), "kept in this browser") {
			t.Errorf("Claim with %s damaged = %v, want an error naming the browser's storage", key, err)
		}
		if v, _ := s.Get(key); v != "{" {
			t.Errorf("%s replaced with %q", key, v)
		}
	}
}

func TestMessage(t *testing.T) {
	p := newProxy(t)
	p.txt["alice.dev.zenr.io."] = []string{`café "x"`, "two"}
	page := newPage(t, p, newMemStorage())
	if msg, err := page.Message(context.Background(), "alice"); err != nil || strings.Join(msg, "|") != `café "x"|two` {
		t.Fatalf("Message(alice) = %q, %v", msg, err)
	}
	if msg, err := page.Message(context.Background(), "bob"); err != nil || msg == nil || len(msg) != 0 {
		t.Fatalf("Message(bob) = %#v, %v; want none", msg, err)
	}
	if _, err := page.Message(context.Background(), "my name"); err == nil {
		t.Fatal("Message of a label that is no host name: no error")
	}
}

func TestNew_Refused(t *testing.T) {
	s := newMemStorage()
	for _, c := range []struct {
		cfg     Config
		wantErr string
	}{
		{Config{DoH: "proxy:8443", UpdateDomain: "u.", SRPDomain: "s.", Storage: s}, "DoH"},
		{Config{DoH: "http://proxy:8443/dns-query", UpdateDomain: "u.", SRPDomain: "s.", Storage: s}, "DoH"},
		{Config{DoH: "http://proxy:8443", SRPDomain: "s.", Storage: s}, "UpdateDomain and SRPDomain"},
		{Config{DoH: "http://proxy:8443", UpdateDomain: "u.", Storage: s}, "UpdateDomain and SRPDomain"},
		{Config{DoH: "http://proxy:8443", UpdateDomain: "u.", SRPDomain: "s."}, "Storage"},
		{Config{DoH: "http://proxy:8443", UpdateDomain: "u.", SRPDomain: "s.", Storage: s, Fallback: "dns.google"}, "Fallback"},
	} {
		if _, err := New(c.cfg); err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("New(%+v) = %v, want an error containing %q", c.cfg, err, c.wantErr)
		}
	}
}

// servers stands in for the proxy at http://proxy:8443 and the resolver at https://dns.google,
// answering from records, each server's in presentation format: the proxy refuses a name
// outside dev.zenr.io. as one it does not serve. It keeps the questions each server was asked,
// as "<name> <type>".
type servers struct {
	t       *testing.T
	records map[string][]string
	mu      sync.Mutex
	asked   map[string][]string
}

func (s *servers) send(ctx context.Context, addr string, network client.Network, msg *dns.Msg) (*dns.Msg, error) {
	q := msg.Question[0]
	name, qtype := q.Header().Name, dns.RRToType(q)
	s.mu.Lock()
	if s.asked == nil {
		s.asked = map[string][]string{}
	}
	s.asked[addr] = append(s.asked[addr], name+" "+dnsutil.TypeToString(qtype))
	s.mu.Unlock()
	resp := &dns.Msg{MsgHeader: dns.MsgHeader{ID: msg.ID, Response: true}, Question: msg.Question}
	if addr == "http://proxy:8443" && !dnsname.IsAtOrBelow(name, "dev.zenr.io.") {
		resp.Rcode = dns.RcodeRefused
		dnsmsg.AddEDE(resp, msg, dns.ExtendedErrorNotAuthoritative, "")
		return resp, nil
	}
	for _, r := range s.records[addr] {
		rr, err := dns.New(r)
		if err != nil {
			s.t.Fatal(err)
		}
		if rr.Header().Name == name && dns.RRToType(rr) == qtype {
			resp.Answer = append(resp.Answer, rr)
		}
	}
	return resp, nil
}

func (s *servers) page(t *testing.T) *Page {
	t.Helper()
	page, err := New(Config{DoH: "http://proxy:8443", Fallback: "https://dns.google", UpdateDomain: "dev.zenr.io",
		SRPDomain: "srp.dev.zenr.io", Storage: newMemStorage(), Send: s.send})
	if err != nil {
		t.Fatal(err)
	}
	return page
}

// TestBrowse_Fallback: a question the proxy refuses as a name it does not serve, as the address
// of an SRV target outside its zones, is asked of Fallback, whose answer Browse shows; every
// other question goes to the proxy alone.
func TestBrowse_Fallback(t *testing.T) {
	s := &servers{t: t, records: map[string][]string{
		"http://proxy:8443": {
			"_services._dns-sd._udp.srp.dev.zenr.io. PTR _xmpp-client._tcp.srp.dev.zenr.io.",
			"_xmpp-client._tcp.srp.dev.zenr.io. PTR chat._xmpp-client._tcp.srp.dev.zenr.io.",
			"chat._xmpp-client._tcp.srp.dev.zenr.io. SRV 0 5 5222 xmpp.example.org.",
		},
		"https://dns.google": {"xmpp.example.org. A 192.0.2.9"},
	}}
	d, err := s.page(t).Browse(context.Background())
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	if len(d.Instances) != 1 || d.Instances[0].Target != "xmpp.example.org." || strings.Join(d.Instances[0].Addresses, " ") != "192.0.2.9" {
		t.Fatalf("Browse = %+v, want chat at xmpp.example.org. with 192.0.2.9", d.Instances)
	}
	slices.Sort(s.asked["https://dns.google"])
	if got := strings.Join(s.asked["https://dns.google"], ", "); got != "xmpp.example.org. A, xmpp.example.org. AAAA" {
		t.Errorf("asked of the fallback: %s, want only the target's addresses", got)
	}
}

// TestNames: the names in the zone, read from the proxy alone, without the SRP domain's.
func TestNames(t *testing.T) {
	s := &servers{t: t, records: map[string][]string{
		"http://proxy:8443": {
			"dev.zenr.io. NSEC demo.dev.zenr.io. KEY RRSIG NSEC",
			"demo.dev.zenr.io. NSEC hello.demo.dev.zenr.io. TXT KEY RRSIG NSEC",
			`demo.dev.zenr.io. TXT "published by sig0lease-agent"`,
			"hello.demo.dev.zenr.io. NSEC demo.srp.dev.zenr.io. TXT RRSIG NSEC",
			`hello.demo.dev.zenr.io. TXT "hi (2026-11-09 14:03:12 CET)"`,
			"demo.srp.dev.zenr.io. NSEC note.dev.zenr.io. A KEY RRSIG NSEC",
			"note.dev.zenr.io. NSEC elsewhere.zenr.io. TXT RRSIG NSEC",
			`note.dev.zenr.io. TXT "by hand"`,
		},
	}}
	got, err := s.page(t).Names(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []browse.Name{
		{Name: "demo.dev.zenr.io.", Key: true, Records: []browse.Record{
			{Type: "TXT", Data: []string{"published by sig0lease-agent"}},
			{Owner: "hello", Type: "TXT", Data: []string{"hi (2026-11-09 14:03:12 CET)"}},
		}},
		{Name: "note.dev.zenr.io.", Records: []browse.Record{{Type: "TXT", Data: []string{"by hand"}}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Names:\n got %+v\nwant %+v", got, want)
	}
	if len(s.asked["https://dns.google"]) != 0 {
		t.Errorf("asked of the fallback: %q, want nothing", s.asked["https://dns.google"])
	}
}
