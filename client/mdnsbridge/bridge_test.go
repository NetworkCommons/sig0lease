package mdnsbridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client/mdnsresponder"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// fakeSource stands in for the daemon: the test drives each browse through browser(), and
// resolves and address lookups answer from the maps.
type fakeSource struct {
	mu       sync.Mutex
	browsers map[string]chan<- mdnsresponder.BrowseEvent
	started  chan string
	fail     map[string]chan error // a value sent here ends that browse with it
	resolve  map[string]mdnsresponder.ResolveResult
	addrs    map[string][]netip.Addr
}

func newFakeSource() *fakeSource {
	return &fakeSource{
		browsers: map[string]chan<- mdnsresponder.BrowseEvent{},
		started:  make(chan string, 16),
		fail:     map[string]chan error{},
		resolve:  map[string]mdnsresponder.ResolveResult{},
		addrs:    map[string][]netip.Addr{},
	}
}

func (f *fakeSource) Browse(ctx context.Context, serviceType, domain string, events chan<- mdnsresponder.BrowseEvent) error {
	f.mu.Lock()
	f.browsers[serviceType] = events
	fail := make(chan error, 1)
	f.fail[serviceType] = fail
	f.mu.Unlock()
	f.started <- serviceType
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-fail:
		return err
	}
}

func (f *fakeSource) Resolve(ctx context.Context, ifIndex uint32, name, serviceType, domain string) (mdnsresponder.ResolveResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.resolve[name]
	if !ok {
		return r, fmt.Errorf("no such instance %q", name)
	}
	return r, nil
}

func (f *fakeSource) Addresses(ctx context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.addrs[host]
	if !ok {
		return nil, fmt.Errorf("no such host %s", host)
	}
	return a, nil
}

func (f *fakeSource) waitBrowse(t *testing.T, serviceType string) {
	t.Helper()
	for {
		select {
		case got := <-f.started:
			if got == serviceType {
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no browse for %s started", serviceType)
		}
	}
}

func (f *fakeSource) send(t *testing.T, serviceType string, add bool, name string) {
	t.Helper()
	f.mu.Lock()
	ch := f.browsers[serviceType]
	f.mu.Unlock()
	ev := mdnsresponder.BrowseEvent{Add: add, InterfaceIndex: 2, Name: name, Type: serviceType + ".", Domain: "local."}
	select {
	case ch <- ev:
	case <-time.After(5 * time.Second):
		t.Fatalf("browse %s did not take event %+v", serviceType, ev)
	}
}

func (f *fakeSource) instance(name, target string, port uint16, txt ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := mdnsresponder.ResolveResult{Target: target, Port: port}
	for _, s := range txt {
		r.TXT = append(r.TXT, []byte(s))
	}
	f.resolve[name] = r
}

// registrar records every update the bridge's clients send, and accepts them all.
type registrar struct{ sent chan *dns.Msg }

func (r *registrar) Send(ctx context.Context, addr string, network clientsrp.Network, msg *dns.Msg) (*dns.Msg, error) {
	r.sent <- msg
	return &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}, nil
}

func (r *registrar) next(t *testing.T) *dns.Msg {
	t.Helper()
	select {
	case m := <-r.sent:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no update sent")
		return nil
	}
}

func (r *registrar) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-r.sent:
		t.Fatalf("unexpected update:\n%v", m)
	case <-time.After(d):
	}
}

// logs collects Logf lines.
type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logs) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.ContainsFunc(l.lines, func(s string) bool { return strings.Contains(s, sub) })
}

func (l *logs) waitFor(t *testing.T, sub string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !l.has(sub) {
		if time.Now().After(deadline) {
			l.mu.Lock()
			defer l.mu.Unlock()
			t.Fatalf("no log line containing %q in:\n%s", sub, strings.Join(l.lines, "\n"))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type harness struct {
	src    *fakeSource
	reg    *registrar
	logs   *logs
	cancel context.CancelFunc
	done   chan error
	owners chan string
}

// start runs the bridge with cfg's Source, SRP transport, Key and Logf filled in.
func start(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{
		src:    newFakeSource(),
		reg:    &registrar{sent: make(chan *dns.Msg, 32)},
		logs:   &logs{},
		done:   make(chan error, 1),
		owners: make(chan string, 16),
	}
	cfg.Source = h.src
	cfg.SRP.Domain = "srp.test."
	cfg.SRP.RegistrarAddr = "127.0.0.1:8159"
	cfg.SRP.Send = h.reg.Send
	// The initial 0-3s delay passes at once; the refresh wait (80% of the lease) lasts
	// until the client is stopped.
	cfg.SRP.Sleep = func(ctx context.Context, d time.Duration) error {
		if d < 10*time.Second {
			return ctx.Err()
		}
		<-ctx.Done()
		return ctx.Err()
	}
	if cfg.Key == nil {
		cfg.Key = func(owner string) (*keyrec.LoadedKey, error) {
			h.owners <- owner
			return keyrec.GenerateKey(owner, dns.ECDSAP256SHA256, 0, 256)
		}
	}
	cfg.Settle = 20 * time.Millisecond
	cfg.Logf = h.logs.logf
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- Run(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not return")
		}
	})
	return h
}

func (h *harness) stop(t *testing.T) error {
	t.Helper()
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err // for Cleanup
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

// update summarizes an update: host addresses, live instances (SRV owner -> port) and
// instances deleted without an SRV.
type update struct {
	addrs   []string
	srv     map[string]uint16
	txt     map[string][]string
	deleted []string
}

func summarize(m *dns.Msg) update {
	u := update{srv: map[string]uint16{}, txt: map[string][]string{}}
	for _, rr := range m.Ns {
		switch r := rr.(type) {
		case *dns.A:
			u.addrs = append(u.addrs, r.Hdr.Name+" "+r.A.Addr.String())
		case *dns.AAAA:
			u.addrs = append(u.addrs, r.Hdr.Name+" "+r.AAAA.Addr.String())
		case *dns.SRV:
			u.srv[r.Hdr.Name] = r.SRV.Port
		case *dns.TXT:
			u.txt[r.Hdr.Name] = r.TXT.Txt
		}
	}
	for _, rr := range m.Ns {
		if r, ok := rr.(*dns.ANY); ok && r.Hdr.Class == dns.ClassANY && strings.Contains(r.Hdr.Name, "._") {
			if _, live := u.srv[r.Hdr.Name]; !live {
				u.deleted = append(u.deleted, r.Hdr.Name)
			}
		}
	}
	return u
}

func TestRun_MirrorsSelectedHostAndFollowsItsInstances(t *testing.T) {
	h := start(t, Config{ServiceTypes: []string{"_http._tcp"}, Hosts: []string{"Box"}})
	h.src.instance("Widget", "box.local.", 8080, "path=/w", `back\slash`)
	h.src.instance("Elsewhere", "other.local.", 80)
	h.src.instance("Gadget", "box.local.", 9090)
	h.src.addrs["box.local."] = []netip.Addr{netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("fe80::1")}
	h.src.waitBrowse(t, "_http._tcp")

	h.src.send(t, "_http._tcp", true, "Widget")
	h.src.send(t, "_http._tcp", true, "Elsewhere")
	u := summarize(h.reg.next(t))
	if !slices.Equal(u.addrs, []string{"box.srp.test. 192.0.2.5"}) {
		t.Errorf("addresses = %v, want only box's routable one", u.addrs)
	}
	if want := map[string]uint16{"Widget._http._tcp.srp.test.": 8080}; !maps.Equal(u.srv, want) {
		t.Errorf("instances = %v, want %v (Elsewhere is on a host not asked for)", u.srv, want)
	}
	if got := u.txt["Widget._http._tcp.srp.test."]; !slices.Equal(got, []string{"path=/w", `back\\slash`}) {
		t.Errorf("TXT = %q, want the raw strings with the backslash escaped", got)
	}
	if owner := <-h.owners; owner != "box.srp.test." {
		t.Errorf("key requested for %s, want box.srp.test.", owner)
	}

	h.src.send(t, "_http._tcp", true, "Gadget")
	u = summarize(h.reg.next(t))
	if want := map[string]uint16{"Widget._http._tcp.srp.test.": 8080, "Gadget._http._tcp.srp.test.": 9090}; !maps.Equal(u.srv, want) {
		t.Errorf("after Gadget appeared: instances = %v, want %v", u.srv, want)
	}

	// Gadget goes: one update withdraws it, then the client registers what is left.
	h.src.send(t, "_http._tcp", false, "Gadget")
	u = summarize(h.reg.next(t))
	if !slices.Equal(u.deleted, []string{"Gadget._http._tcp.srp.test."}) || u.srv["Widget._http._tcp.srp.test."] != 8080 {
		t.Errorf("withdrawal = %+v, want Gadget deleted and Widget restated", u)
	}
	u = summarize(h.reg.next(t))
	if want := map[string]uint16{"Widget._http._tcp.srp.test.": 8080}; !maps.Equal(u.srv, want) || len(u.deleted) != 0 {
		t.Errorf("after the withdrawal: %+v, want Widget alone", u)
	}

	// Widget goes too: the host is deregistered, addresses and all.
	h.src.send(t, "_http._tcp", false, "Widget")
	u = summarize(h.reg.next(t))
	if len(u.addrs) != 0 || len(u.srv) != 0 || !slices.Equal(u.deleted, []string{"Widget._http._tcp.srp.test."}) {
		t.Errorf("deregistration = %+v, want no addresses and Widget deleted", u)
	}

	if err := h.stop(t); !errors.Is(err, context.Canceled) {
		t.Errorf("Run = %v, want context.Canceled", err)
	}
	h.reg.none(t, 50*time.Millisecond) // nothing left to deregister
}

func TestRun_StopDeregistersEveryHost(t *testing.T) {
	h := start(t, Config{ServiceTypes: []string{"_ssh._tcp"}, AllHosts: true})
	h.src.instance("a", "one.local.", 22)
	h.src.instance("b", "two.local.", 22)
	h.src.addrs["one.local."] = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	h.src.addrs["two.local."] = []netip.Addr{netip.MustParseAddr("2001:db8::2")}
	h.src.waitBrowse(t, "_ssh._tcp")
	h.src.send(t, "_ssh._tcp", true, "a")
	h.src.send(t, "_ssh._tcp", true, "b")
	h.reg.next(t)
	h.reg.next(t)

	h.stop(t)
	got := map[string]bool{}
	for range 2 {
		u := summarize(h.reg.next(t))
		if len(u.addrs) != 0 || len(u.deleted) != 1 {
			t.Errorf("update at stop = %+v, want a deregistration", u)
		}
		got[strings.Join(u.deleted, ",")] = true
	}
	if !got["a._ssh._tcp.srp.test."] || !got["b._ssh._tcp.srp.test."] {
		t.Errorf("deregistered %v, want both hosts", got)
	}
}

func TestRun_BrowsesEveryEnumeratedType(t *testing.T) {
	h := start(t, Config{AllHosts: true})
	h.src.waitBrowse(t, "_services._dns-sd._udp")
	// An enumeration reply names the type "_ipp" in "_tcp.local.", as dns-sd -B shows.
	h.src.mu.Lock()
	ch := h.src.browsers["_services._dns-sd._udp"]
	h.src.mu.Unlock()
	ch <- mdnsresponder.BrowseEvent{Add: true, Name: "_ipp", Type: "_tcp.local.", Domain: "."}
	ch <- mdnsresponder.BrowseEvent{Add: true, Name: "_bad_name", Type: "_tcp.local.", Domain: "."}
	h.src.waitBrowse(t, "_ipp._tcp")
	h.logs.waitFor(t, `ignoring service type "_bad_name._tcp"`)
}

func TestRun_ListRegistersNothing(t *testing.T) {
	h := start(t, Config{ServiceTypes: []string{"_http._tcp"}, Hosts: []string{"box.local."}, List: true})
	h.src.instance("Widget", "box.local.", 8080)
	h.src.instance("Other", "other.local.", 80)
	h.src.waitBrowse(t, "_http._tcp")
	h.src.send(t, "_http._tcp", true, "Widget")
	h.src.send(t, "_http._tcp", true, "Other")
	h.logs.waitFor(t, `+ "Widget" _http._tcp on box.local. port 8080 *`)
	h.logs.waitFor(t, `+ "Other" _http._tcp on other.local. port 80  `)
	h.reg.none(t, 100*time.Millisecond)
}

func TestRun_BrowseFailureStopsAndDeregisters(t *testing.T) {
	h := start(t, Config{ServiceTypes: []string{"_http._tcp"}, Hosts: []string{"box"}})
	h.src.instance("Widget", "box.local.", 8080)
	h.src.addrs["box.local."] = []netip.Addr{netip.MustParseAddr("192.0.2.5")}
	h.src.waitBrowse(t, "_http._tcp")
	h.src.send(t, "_http._tcp", true, "Widget")
	h.reg.next(t)

	h.src.mu.Lock()
	h.src.fail["_http._tcp"] <- mdnsresponder.ErrPolicyDenied
	h.src.mu.Unlock()
	select {
	case err := <-h.done:
		h.done <- err
		if !errors.Is(err, mdnsresponder.ErrPolicyDenied) {
			t.Errorf("Run = %v, want the browse's ErrPolicyDenied", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept going after its browse failed")
	}
	if u := summarize(h.reg.next(t)); len(u.addrs) != 0 {
		t.Errorf("update after the failure = %+v, want the deregistration", u)
	}
}

func TestRun_SkipsWhatSRPCannotCarry(t *testing.T) {
	h := start(t, Config{ServiceTypes: []string{"_http._tcp"}, AllHosts: true})
	h.src.instance("Printer v2.1", "box.local.", 631)
	h.src.instance("Wide", "box.example.com.", 80)
	h.src.instance("Local", "lonely.local.", 80)
	h.src.addrs["lonely.local."] = []netip.Addr{netip.MustParseAddr("fe80::7")}
	h.src.waitBrowse(t, "_http._tcp")
	h.src.send(t, "_http._tcp", true, "Printer v2.1")
	h.src.send(t, "_http._tcp", true, "Wide")
	h.src.send(t, "_http._tcp", true, "Local")
	h.logs.waitFor(t, `skipping "Printer v2.1"`)
	h.logs.waitFor(t, `skipping "Wide" _http._tcp on box.example.com.: host box.example.com. is not a .local. name`)
	h.logs.waitFor(t, "not registering lonely.local.: only loopback or link-local addresses")
	h.reg.none(t, 100*time.Millisecond)
}

func TestRun_KeyFailureStopsTheBridge(t *testing.T) {
	keyErr := errors.New("keystore is read-only")
	h := start(t, Config{
		ServiceTypes: []string{"_http._tcp"},
		AllHosts:     true,
		Key:          func(string) (*keyrec.LoadedKey, error) { return nil, keyErr },
	})
	h.src.instance("Widget", "box.local.", 8080)
	h.src.addrs["box.local."] = []netip.Addr{netip.MustParseAddr("192.0.2.5")}
	h.src.waitBrowse(t, "_http._tcp")
	h.src.send(t, "_http._tcp", true, "Widget")
	select {
	case err := <-h.done:
		h.done <- err
		if !errors.Is(err, keyErr) {
			t.Errorf("Run = %v, want the key error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept going without a key")
	}
	h.reg.none(t, 50*time.Millisecond)
}

func TestRun_NeedsHostsUnlessListing(t *testing.T) {
	err := Run(context.Background(), Config{Source: newFakeSource(), Key: func(string) (*keyrec.LoadedKey, error) { return nil, nil }})
	if err == nil || !strings.Contains(err.Error(), "hosts") {
		t.Fatalf("Run without hosts = %v, want an error asking for them", err)
	}
}

func TestEscapeTXT_PacksToTheRawBytes(t *testing.T) {
	raw := []byte("a\\b\x00\xff\"q")
	m := &dns.Msg{}
	txt := &dns.TXT{Hdr: dns.Header{Name: "x.", Class: dns.ClassINET}}
	txt.TXT.Txt = []string{escapeTXT(raw)}
	m.Answer = []dns.RR{txt}
	if err := m.Pack(); err != nil {
		t.Fatal(err)
	}
	if want := append([]byte{byte(len(raw))}, raw...); !bytes.HasSuffix(m.Data, want) {
		t.Errorf("packed TXT ends % x, want % x", m.Data[len(m.Data)-len(want):], want)
	}
}

func TestNormalizeHost(t *testing.T) {
	for _, in := range []string{"Box", "box.local", "BOX.local.", "box.LOCAL."} {
		if got := normalizeHost(in); got != "box.local." {
			t.Errorf("normalizeHost(%q) = %q, want box.local.", in, got)
		}
	}
	if got := normalizeHost("Box.Example.com"); got != "box.example.com." {
		t.Errorf("normalizeHost(Box.Example.com) = %q, want box.example.com.", got)
	}
}
