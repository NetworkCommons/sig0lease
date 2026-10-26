package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/mdnsbridge"
	"github.com/NetworkCommons/sig0lease/client/mdnsresponder"
	"github.com/NetworkCommons/sig0lease/client/rfc9664"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// registrar records every update the agent's clients send. It answers YXDOMAIN to an update
// whose host name is in taken, REFUSED to one whose host name is in refused, NOERROR to the
// rest. taken and refused are set while the agent is not running.
type registrar struct {
	sent    chan *dns.Msg
	taken   []string
	refused []string
}

func (r *registrar) Send(ctx context.Context, addr string, network baseclient.Network, msg *dns.Msg) (*dns.Msg, error) {
	r.sent <- msg
	rcode := uint16(dns.RcodeSuccess)
	switch host := summarize(msg).host; {
	case slices.Contains(r.taken, host):
		rcode = dns.RcodeYXDomain
	case slices.Contains(r.refused, host):
		rcode = dns.RcodeRefused
	}
	return &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: rcode}}, nil
}

// update is what an update registers: its host name (or RFC 9664 name) and addresses, its
// live instances, the instances it withdraws, an RFC 9664 name's other records, and the
// leases it asks for.
type update struct {
	host            string
	addrs           []string
	instances       []string
	withdrawn       []string
	records         []string
	lease, keyLease uint32
}

func summarize(m *dns.Msg) update {
	var u update
	if lo, err := leasepkg.FindAndDecode(m); err == nil && lo.KeyLease != nil {
		u.lease, u.keyLease = lo.Lease, *lo.KeyLease
	}
	for _, rr := range m.Ns {
		switch r := rr.(type) {
		case *dns.KEY:
			if !strings.Contains(r.Hdr.Name, "._") {
				u.host = r.Hdr.Name
			}
		case *dns.A:
			u.addrs = append(u.addrs, r.A.Addr.String())
		case *dns.AAAA:
			u.addrs = append(u.addrs, r.AAAA.Addr.String())
		case *dns.SRV:
			u.instances = append(u.instances, r.Hdr.Name)
		case *dns.TXT:
			if !strings.Contains(r.Hdr.Name, "._") {
				u.records = append(u.records, rfc9664.Describe(r))
			}
		}
	}
	for _, rr := range m.Ns {
		if r, ok := rr.(*dns.ANY); ok && r.Hdr.Class == dns.ClassANY && strings.Contains(r.Hdr.Name, "._") && !slices.Contains(u.instances, r.Hdr.Name) {
			u.withdrawn = append(u.withdrawn, r.Hdr.Name)
		}
	}
	slices.Sort(u.instances)
	slices.Sort(u.withdrawn)
	return u
}

// heldBy answers KEY lookups: each name in held has a KEY that is not the agent's.
func heldBy(held ...string) clientsrp.DNSQuery {
	return func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		resp := &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeNameError}}
		if slices.Contains(held, name) && qtype == dns.TypeKEY {
			k := &dns.KEY{}
			k.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: 300}
			k.Protocol, k.Algorithm, k.PublicKey = 3, dns.ECDSAP256SHA256, "c29tZW9uZSBlbHNl"
			resp.Rcode = dns.RcodeSuccess
			resp.Answer = []dns.RR{k}
		}
		return resp, nil
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

func (l *logs) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

func (l *logs) waitFor(t *testing.T, sub string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for l.count(sub) == 0 {
		if time.Now().After(deadline) {
			l.mu.Lock()
			defer l.mu.Unlock()
			t.Fatalf("no log line containing %q in:\n%s", sub, strings.Join(l.lines, "\n"))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type harness struct {
	dir, path string
	reg       *registrar
	logs      *logs
	mu        sync.Mutex
	machine   []netip.Addr
	cancel    context.CancelFunc
	done      chan error
}

// newHarness writes template to a new directory, with a registrar and this machine's
// addresses for the agent to use.
func newHarness(t *testing.T, template string) *harness {
	t.Helper()
	h := &harness{
		dir:     t.TempDir(),
		reg:     &registrar{sent: make(chan *dns.Msg, 64)},
		logs:    &logs{},
		machine: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
	}
	h.path = filepath.Join(h.dir, "agent.yaml")
	h.write(t, template)
	return h
}

func (h *harness) write(t *testing.T, template string) {
	t.Helper()
	if err := os.WriteFile(h.path, []byte(template), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) setMachine(addrs ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.machine = nil
	for _, a := range addrs {
		h.machine = append(h.machine, netip.MustParseAddr(a))
	}
}

func (h *harness) options() Options {
	return Options{
		Logf:          h.logs.logf,
		PollInterval:  20 * time.Millisecond,
		ProbeInterval: 20 * time.Millisecond,
		ProbeTimeout:  500 * time.Millisecond,
		ProbeFailures: 3,
		Settle:        10 * time.Millisecond,
		StopTimeout:   time.Second,
		Interfaces: func() ([]netip.Addr, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return slices.Clone(h.machine), nil
		},
		Send: h.reg.Send,
		// The initial 0-3s delay passes at once; the refresh wait lasts until the client
		// is stopped.
		Sleep: func(ctx context.Context, d time.Duration) error {
			if d < 10*time.Second {
				return ctx.Err()
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}
}

// start runs the agent with h's options, as changed by edit.
func (h *harness) start(t *testing.T, edit func(*Options)) {
	t.Helper()
	opts := h.options()
	if edit != nil {
		edit(&opts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan error, 1)
	go func(done chan error) { done <- Run(ctx, h.path, opts) }(h.done)
	t.Cleanup(func() { h.stop(t) })
}

// stop stops the agent and returns what Run returned.
func (h *harness) stop(t *testing.T) error {
	t.Helper()
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

// waitState waits for the state file to be what ok accepts.
func (h *harness) waitState(t *testing.T, what string, ok func(state string) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		state, err := os.ReadFile(filepath.Join(h.dir, "keys", StateFile))
		if err == nil && ok(string(state)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("state file, want %s: %v\n%s", what, err, state)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// until returns the first update that ok accepts, skipping others.
func (h *harness) until(t *testing.T, what string, ok func(update) bool) update {
	t.Helper()
	deadline := time.After(5 * time.Second)
	var seen []update
	for {
		select {
		case m := <-h.reg.sent:
			u := summarize(m)
			if ok(u) {
				return u
			}
			seen = append(seen, u)
		case <-deadline:
			h.logs.mu.Lock()
			defer h.logs.mu.Unlock()
			t.Fatalf("no update %s; saw %+v\nlog:\n%s", what, seen, strings.Join(h.logs.lines, "\n"))
			return update{}
		}
	}
}

func (h *harness) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-h.reg.sent:
		t.Fatalf("unexpected update %+v", summarize(m))
	case <-time.After(d):
	}
}

// srpTemplate is a template with one srp registrar for srp.test., through 127.0.0.1:8159;
// rest is its further fields and what it registers, written as if at the top level.
func srpTemplate(rest string) string {
	return "keystore: keys\nregistrars:\n  - protocol: srp\n    domain: srp.test.\n    server: 127.0.0.1:8159\n" + indent(rest)
}

// nameTemplate is srpTemplate's for an rfc9664 registrar for dev.test.
func nameTemplate(rest string) string {
	return "keystore: keys\nregistrars:\n  - protocol: rfc9664\n    zone: dev.test.\n    server: 127.0.0.1:8159\n" + indent(rest)
}

// indent indents each line of s as a registrar's field.
func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.SplitAfter(s, "\n") {
		if strings.TrimSpace(line) != "" {
			b.WriteString("    ")
		}
		b.WriteString(line)
	}
	return b.String()
}

// A probed service is registered once its probe passes, withdrawn after ProbeFailures
// failures in a row, and registered again when it passes; one without a probe always is.
// Stopping deregisters the host.
func TestRun_ProbesDecideWhatIsRegistered(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	h := newHarness(t, srpTemplate(fmt.Sprintf(`
hosts:
  - name: box
    addresses: [127.0.0.1]
    services:
      - {type: http, instance: Web, port: %d}
      - {type: ipp, instance: Printer, probe: none}
`, port)))
	h.start(t, nil)

	both := []string{"Printer._ipp._tcp.srp.test.", "Web._http._tcp.srp.test."}
	h.until(t, "registering Web and Printer", func(u update) bool { return slices.Equal(u.instances, both) })

	ln.Close()
	h.until(t, "withdrawing Web", func(u update) bool { return slices.Equal(u.withdrawn, []string{"Web._http._tcp.srp.test."}) })
	h.logs.waitFor(t, `box: "Web" _http._tcp: probe failed 3 times in a row, withdrawing it`)

	if ln, err = net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port)); err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h.until(t, "registering Web again", func(u update) bool { return slices.Equal(u.instances, both) })
	h.logs.waitFor(t, `box: "Web" _http._tcp: probe tcp passes`)

	if err := h.stop(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	h.until(t, "deregistering box", func(u update) bool { return len(u.addrs) == 0 && slices.Equal(u.withdrawn, both) })
}

// A service whose probe never passed is not registered: the host is, alone.
func TestRun_UnreachableServiceIsNotRegistered(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	h := newHarness(t, srpTemplate(fmt.Sprintf(`
hosts:
  - name: box
    addresses: [127.0.0.1]
    services: [{type: http, instance: Web, port: %d}]
`, port)))
	h.start(t, nil)
	h.until(t, "registering box alone", func(u update) bool {
		return u.host == "box.srp.test." && slices.Equal(u.addrs, []string{"127.0.0.1"}) && len(u.instances) == 0
	})
	h.logs.waitFor(t, `box: "Web" _http._tcp: not registered until its probe passes`)
	time.Sleep(100 * time.Millisecond) // several failed probes
	if n := h.logs.count("not registered until its probe passes"); n != 1 {
		t.Errorf("the failing probe was logged %d times, want once", n)
	}
}

// A template change is applied: a removed host is deregistered, a host's new service is
// registered. An invalid change is logged once and changes nothing.
func TestRun_FollowsTemplateChanges(t *testing.T) {
	h := newHarness(t, srpTemplate(`
hosts:
  - {name: a, addresses: [192.0.2.1], services: [{type: ipp, instance: A, probe: none}]}
  - {name: b, addresses: [192.0.2.2], services: [{type: ipp, instance: B, probe: none}]}
`))
	h.start(t, nil)
	seen := map[string]bool{}
	h.until(t, "registering a and b", func(u update) bool { seen[u.host] = true; return seen["a.srp.test."] && seen["b.srp.test."] })

	changed := `
hosts:
  - name: a
    addresses: [192.0.2.1]
    services:
      - {type: ipp, instance: A, probe: none}
      - {type: http, instance: A2, probe: none}
`
	h.write(t, srpTemplate(changed))
	h.until(t, "deregistering b", func(u update) bool { return u.host == "b.srp.test." && len(u.addrs) == 0 })
	h.until(t, "registering a with A2", func(u update) bool {
		return u.host == "a.srp.test." && slices.Equal(u.instances, []string{"A._ipp._tcp.srp.test.", "A2._http._tcp.srp.test."})
	})
	h.logs.waitFor(t, "template: b.srp.test. removed")

	h.write(t, srpTemplate(changed+"  - {name: c, addresses: []}\n"))
	h.logs.waitFor(t, "keeping the template as it was")
	time.Sleep(100 * time.Millisecond) // several polls
	if n := h.logs.count("keeping the template as it was"); n != 1 {
		t.Errorf("the invalid template was logged %d times, want once", n)
	}
	h.write(t, srpTemplate(changed))
	h.none(t, 100*time.Millisecond)
}

// on_stop decides whether a host's names outlive the agent: keep, the default, deregisters
// asking for the host's key lease, release for 0. A host removed from the template is
// deregistered as its on_stop says, then has its names freed; one whose lifetime changes is
// registered again with it.
func TestRun_OnStop(t *testing.T) {
	kept := "  - {name: kept, addresses: [192.0.2.1]}\n"
	freed := "  - {name: freed, addresses: [192.0.2.2], lease: 2m, key_lease: 10m, on_stop: release}\n"
	h := newHarness(t, srpTemplate("hosts:\n"+kept+freed+"  - {name: gone, addresses: [192.0.2.3]}\n"))
	h.start(t, nil)
	seen := map[string]update{}
	h.until(t, "registering kept, freed and gone", func(u update) bool { seen[u.host] = u; return len(seen) == 3 })
	if u := seen["freed.srp.test."]; u.lease != 120 || u.keyLease != 600 {
		t.Errorf("freed registered with %d/%d, want its own 120/600", u.lease, u.keyLease)
	}

	h.write(t, srpTemplate("hosts:\n"+kept+freed))
	if u := h.until(t, "deregistering gone", func(u update) bool { return u.host == "gone.srp.test." }); len(u.addrs) != 0 || u.keyLease != 1209600 {
		t.Errorf("removed host's first update %+v, want it deregistered keeping its names, as its on_stop says", u)
	}
	if u := h.until(t, "freeing gone's names", func(u update) bool { return u.host == "gone.srp.test." }); len(u.addrs) != 0 || len(u.withdrawn) != 0 || u.keyLease != 0 {
		t.Errorf("removed host's next update %+v, want the host alone released with KEY-LEASE 0", u)
	}

	kept = "  - {name: kept, addresses: [192.0.2.1], lease: 30m}\n"
	h.write(t, srpTemplate("hosts:\n"+kept+freed))
	if u := h.until(t, "deregistering kept", func(u update) bool { return u.host == "kept.srp.test." }); len(u.addrs) != 0 || u.keyLease != 1209600 {
		t.Errorf("kept's update on its lease changing %+v, want it deregistered keeping its names", u)
	}
	if u := h.until(t, "registering kept again", func(u update) bool { return u.host == "kept.srp.test." }); len(u.addrs) == 0 || u.lease != 1800 {
		t.Errorf("kept's next update %+v, want it registered with lease 1800", u)
	}

	if err := h.stop(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	stopped := map[string]uint32{}
	h.until(t, "deregistering kept and freed", func(u update) bool {
		if len(u.addrs) == 0 {
			stopped[u.host] = u.keyLease
		}
		return len(stopped) == 2
	})
	if stopped["kept.srp.test."] != 1209600 || stopped["freed.srp.test."] != 0 {
		t.Errorf("KEY-LEASE asked on stopping: %v, want kept 1209600 and freed 0", stopped)
	}
}

// A host removed in the same edit as a registrar change that keeps the registration (a lease)
// has its names freed; the others are deregistered keeping theirs, then registered again.
func TestRun_RemovedWithARegistrarChange(t *testing.T) {
	h := newHarness(t, srpTemplate("hosts:\n  - {name: a, addresses: [192.0.2.1]}\n  - {name: b, addresses: [192.0.2.2]}\n"))
	h.start(t, nil)
	seen := map[string]bool{}
	h.until(t, "registering a and b", func(u update) bool { seen[u.host] = true; return len(seen) == 2 })
	h.logs.waitFor(t, "a: registered")
	h.logs.waitFor(t, "b: registered")

	h.write(t, srpTemplate("lease: 30m\nhosts:\n  - {name: a, addresses: [192.0.2.1]}\n"))
	deregistered := map[string][]uint32{}
	u := h.until(t, "registering a again", func(u update) bool {
		if len(u.addrs) == 0 {
			deregistered[u.host] = append(deregistered[u.host], u.keyLease)
		}
		return u.host == "a.srp.test." && len(u.addrs) > 0
	})
	if u.lease != 1800 {
		t.Errorf("a registered again with %+v, want lease 1800", u)
	}
	if !slices.Equal(deregistered["a.srp.test."], []uint32{1209600}) || !slices.Equal(deregistered["b.srp.test."], []uint32{1209600, 0}) {
		t.Errorf("KEY-LEASEs asked deregistering: %v, want a kept (1209600), b kept then freed (1209600, 0)", deregistered)
	}
	h.logs.waitFor(t, "template: b.srp.test. removed; freeing its names")
}

// A host removed from the template while the agent was stopped has its names freed at the
// next start, before anything is registered, and is forgotten; plan says so beforehand. A
// release the registrar refuses is tried again at the following start.
func TestRun_FreesHostsRemovedWhileStopped(t *testing.T) {
	h := newHarness(t, srpTemplate("hosts:\n  - {name: a, addresses: [192.0.2.1]}\n  - {name: b, addresses: [192.0.2.2]}\n"))
	h.start(t, nil)
	h.logs.waitFor(t, "a: registered")
	h.logs.waitFor(t, "b: registered")
	h.stop(t)
	stopped := map[string]uint32{}
	h.until(t, "deregistering a and b", func(u update) bool {
		if len(u.addrs) == 0 {
			stopped[u.host] = u.keyLease
		}
		return len(stopped) == 2
	})
	if stopped["a.srp.test."] != 1209600 || stopped["b.srp.test."] != 1209600 {
		t.Fatalf("KEY-LEASE asked on stopping: %v, want both names kept", stopped)
	}

	h.write(t, srpTemplate("hosts:\n  - {name: a, addresses: [192.0.2.1]}\n"))
	plan, err := Load(h.path)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := Describe(&out, plan, h.options().Interfaces, nil); err != nil {
		t.Fatal(err)
	}
	if want := "host b.srp.test.: holds names from an earlier run that the template no longer registers; run frees them"; !strings.Contains(out.String(), want) {
		t.Errorf("plan does not say %q:\n%s", want, out.String())
	}

	h.reg.refused = []string{"b.srp.test."}
	h.start(t, nil)
	if u := h.until(t, "the first update", func(update) bool { return true }); u.host != "b.srp.test." || len(u.addrs) != 0 || u.keyLease != 0 {
		t.Fatalf("first update after the restart %+v, want b released", u)
	}
	h.logs.waitFor(t, "state: b.srp.test.: its names stay held until their key lease ends, unless the next start or template change frees them")
	h.until(t, "registering a", func(u update) bool { return u.host == "a.srp.test." && len(u.addrs) > 0 })
	h.stop(t)
	h.until(t, "deregistering a", func(u update) bool { return u.host == "a.srp.test." && len(u.addrs) == 0 })

	h.reg.refused = nil
	h.start(t, nil)
	if u := h.until(t, "the first update", func(update) bool { return true }); u.host != "b.srp.test." || len(u.addrs) != 0 || u.keyLease != 0 {
		t.Fatalf("first update after the second restart %+v, want b released again", u)
	}
	h.until(t, "registering a", func(u update) bool { return u.host == "a.srp.test." && len(u.addrs) > 0 })
	state, err := os.ReadFile(filepath.Join(h.dir, "keys", StateFile))
	if err != nil || strings.Contains(string(state), `"b.srp.test."`) || !strings.Contains(string(state), `"a.srp.test."`) {
		t.Fatalf("state file, want a and not b: %v\n%s", err, state)
	}
}

// A host renamed because another key holds its name keeps the new name across restarts.
func TestRun_KeepsRenamedNames(t *testing.T) {
	h := newHarness(t, srpTemplate("hosts: [{name: box, addresses: [192.0.2.1]}]\n"))
	h.reg.taken = []string{"box.srp.test."}
	query := heldBy("box.srp.test.")
	h.start(t, func(o *Options) { o.Query = query })
	h.until(t, "registering box-2", func(u update) bool { return u.host == "box-2.srp.test." && len(u.addrs) > 0 })
	h.logs.waitFor(t, "box: renamed: now host box-2")
	h.stop(t)
	state, err := os.ReadFile(filepath.Join(h.dir, "keys", StateFile))
	if err != nil || !strings.Contains(string(state), `"host": "box-2"`) {
		t.Fatalf("state file: %v\n%s", err, state)
	}
	h.until(t, "deregistering box-2", func(u update) bool { return u.host == "box-2.srp.test." && len(u.addrs) == 0 })

	h.start(t, func(o *Options) { o.Query = query })
	if u := h.until(t, "registering", func(u update) bool { return true }); u.host != "box-2.srp.test." {
		t.Fatalf("after a restart, the first registration is %+v, want box-2", u)
	}
}

// A state file edited by hand stops the agent: it would otherwise lose its names.
func TestRun_RefusesAnEditedStateFile(t *testing.T) {
	h := newHarness(t, srpTemplate("hosts: [{name: box, addresses: [192.0.2.1]}]\n"))
	if err := os.MkdirAll(filepath.Join(h.dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "keys", StateFile), []byte(`{"hosts": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.start(t, nil)
	select {
	case err := <-h.done:
		h.done <- err
		if err == nil || !strings.Contains(err.Error(), "must not be edited by hand") {
			t.Fatalf("Run = %v, want the state file refused", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not refuse the edited state file")
	}
}

func TestRun_RefusesAnInvalidTemplate(t *testing.T) {
	h := newHarness(t, "registrars: [{protocol: srp}]\n")
	err := Run(context.Background(), h.path, h.options())
	var v *ValidationError
	if !errors.As(err, &v) {
		t.Fatalf("Run = %v, want a ValidationError", err)
	}
}

// addresses: [auto] follows this machine's publishable addresses.
func TestRun_AutoFollowsTheMachine(t *testing.T) {
	h := newHarness(t, srpTemplate("hosts: [{name: box, addresses: [auto]}]\n"))
	h.setMachine("127.0.0.1", "fe80::1", "192.0.2.10")
	h.start(t, nil)
	h.until(t, "with 192.0.2.10", func(u update) bool { return slices.Equal(u.addrs, []string{"192.0.2.10"}) })
	h.setMachine("127.0.0.1", "192.0.2.11")
	h.until(t, "with 192.0.2.11", func(u update) bool { return slices.Equal(u.addrs, []string{"192.0.2.11"}) })
	h.logs.waitFor(t, "this machine's addresses are now [192.0.2.11]")
}

// A new registration domain means new names: everything is deregistered, the names in the
// old domain freed, then everything registered in the new one.
func TestRun_DomainChangeMovesEverything(t *testing.T) {
	h := newHarness(t, srpTemplate("hosts: [{name: box, addresses: [192.0.2.1]}]\n"))
	h.start(t, nil)
	h.logs.waitFor(t, "box: registered")
	h.write(t, strings.Replace(srpTemplate("hosts: [{name: box, addresses: [192.0.2.1]}]\n"), "srp.test.", "other.test.", 1))
	if u := h.until(t, "deregistering box.srp.test.", func(u update) bool { return u.host == "box.srp.test." && len(u.addrs) == 0 }); u.keyLease != 1209600 {
		t.Errorf("box.srp.test.'s first update %+v, want it deregistered keeping its names", u)
	}
	if u := h.until(t, "freeing box.srp.test.", func(u update) bool { return u.host == "box.srp.test." }); len(u.addrs) != 0 || u.keyLease != 0 {
		t.Errorf("box.srp.test.'s next update %+v, want its names freed", u)
	}
	h.until(t, "registering box.other.test.", func(u update) bool { return u.host == "box.other.test." && len(u.addrs) > 0 })
}

// A registrar whose server changes registers through the new one: what it registers is
// deregistered, its names freed through the old server, then registered again; another
// registrar's hosts are not touched.
func TestRun_RegistrarChangeRestartsItsOwn(t *testing.T) {
	two := func(server string) string {
		return srpTemplate("hosts: [{name: box, addresses: [192.0.2.1]}]\n") + `  - protocol: srp
    domain: other.test.
    server: ` + server + `
    hosts: [{name: box, addresses: [192.0.2.2]}]
`
	}
	h := newHarness(t, two("127.0.0.1:8159"))
	h.start(t, nil)
	seen := map[string]bool{}
	h.until(t, "registering both boxes", func(u update) bool { seen[u.host] = true; return len(seen) == 2 })

	h.write(t, two("127.0.0.1:9999"))
	var others []update
	h.until(t, "freeing box.other.test.", func(u update) bool {
		others = append(others, u)
		return u.host == "box.other.test." && len(u.addrs) == 0 && u.keyLease == 0
	})
	h.until(t, "registering box.other.test. again", func(u update) bool {
		others = append(others, u)
		return u.host == "box.other.test." && len(u.addrs) > 0
	})
	for _, u := range others {
		if u.host != "box.other.test." {
			t.Errorf("update %+v, want only box.other.test. touched", u)
		}
	}
	h.logs.waitFor(t, "template: the srp registrar for other.test. changed")
}

// A name is registered with its addresses and records, its records withdrawn as the template
// and the machine change, and deregistered on stop as its on_stop says.
func TestRun_Names(t *testing.T) {
	h := newHarness(t, nameTemplate(`
names:
  - name: site
    addresses: [auto]
    records: ['@ TXT "hello"', '_dnslink TXT "dnslink=/ipfs/x"']
`))
	h.start(t, nil)
	u := h.until(t, "registering site", func(u update) bool { return u.host == "site.dev.test." })
	if !slices.Equal(u.addrs, []string{"192.0.2.10"}) || len(u.records) != 2 || u.lease != 3600 || u.keyLease != 1209600 {
		t.Fatalf("first update %+v, want site's address and two TXT records on the default leases", u)
	}
	h.logs.waitFor(t, "site.dev.test.: registered")

	h.write(t, nameTemplate(`
names:
  - name: site
    addresses: [auto]
    records: ['@ TXT "hello"']
`))
	u = h.until(t, "withdrawing _dnslink", func(update) bool { return true })
	if !slices.Equal(u.records, []string{`_dnslink.site.dev.test. TXT "dnslink=/ipfs/x"`}) || u.lease != 0 || u.keyLease != 1209600 {
		t.Fatalf("update after the template change %+v, want _dnslink withdrawn (LEASE 0, the KEY kept)", u)
	}
	h.until(t, "registering site again", func(u update) bool { return u.lease != 0 && len(u.records) == 1 })

	h.setMachine("192.0.2.11")
	u = h.until(t, "withdrawing the old address", func(update) bool { return true })
	if !slices.Equal(u.addrs, []string{"192.0.2.10"}) || u.lease != 0 {
		t.Fatalf("update after the machine's address changed %+v, want 192.0.2.10 withdrawn", u)
	}
	h.until(t, "registering the new address", func(u update) bool { return slices.Equal(u.addrs, []string{"192.0.2.11"}) && u.lease != 0 })

	h.stop(t)
	u = h.until(t, "deregistering site", func(update) bool { return true })
	if !slices.Equal(u.addrs, []string{"192.0.2.11"}) || len(u.records) != 1 || u.lease != 0 || u.keyLease != 1209600 {
		t.Fatalf("update on stop %+v, want the records deleted and the name kept (on_stop: keep)", u)
	}
}

// A name another key holds is not renamed: the agent says so and tries the same name again.
func TestRun_NameHeldByAnotherKey(t *testing.T) {
	h := newHarness(t, nameTemplate("names: [{name: site, records: ['@ TXT x']}]\n"))
	h.reg.taken = []string{"site.dev.test."}
	h.start(t, nil)
	h.logs.waitFor(t, "site.dev.test. is held by another key (YXDOMAIN)")
	h.until(t, "the first try", func(u update) bool { return u.host == "site.dev.test." && u.lease != 0 })
	h.until(t, "a second try, after the backoff", func(u update) bool { return u.host == "site.dev.test." && u.lease != 0 })
	if n := h.logs.count("renamed"); n != 0 {
		t.Errorf("logged %d renames, want none", n)
	}
}

// A name removed from the template is deregistered as its on_stop says, then freed with its
// KEY alone, and forgotten.
func TestRun_NameRemoved(t *testing.T) {
	both := "names:\n  - {name: site, records: ['@ TXT x']}\n  - {name: gone, addresses: [192.0.2.1]}\n"
	h := newHarness(t, nameTemplate(both))
	h.start(t, nil)
	h.logs.waitFor(t, "site.dev.test.: registered")
	h.logs.waitFor(t, "gone.dev.test.: registered")

	h.write(t, nameTemplate("names:\n  - {name: site, records: ['@ TXT x']}\n"))
	if u := h.until(t, "deregistering gone", func(u update) bool { return u.host == "gone.dev.test." && u.lease == 0 }); u.keyLease != 1209600 || len(u.addrs) != 1 {
		t.Errorf("gone's first update after its removal %+v, want its address deleted, the name kept as on_stop says", u)
	}
	if u := h.until(t, "freeing gone", func(u update) bool { return u.host == "gone.dev.test." }); u.lease != 0 || u.keyLease != 0 || len(u.addrs) != 0 {
		t.Errorf("gone's next update %+v, want its KEY alone, both leases 0", u)
	}
	h.logs.waitFor(t, "template: gone.dev.test. removed; freeing it")
	h.logs.waitFor(t, "gone.dev.test.: deregistered the name alone; name freed")
	h.waitState(t, "site and not gone", func(state string) bool {
		return !strings.Contains(state, `"gone.dev.test."`) && strings.Contains(state, `"site.dev.test."`)
	})
}

// noDaemon is an mDNS daemon that is not there.
type noDaemon struct {
	mu      sync.Mutex
	browses int
}

func (d *noDaemon) Browse(ctx context.Context, serviceType, domain string, events chan<- mdnsresponder.BrowseEvent) error {
	d.mu.Lock()
	d.browses++
	d.mu.Unlock()
	return errors.New("no daemon")
}

func (d *noDaemon) Resolve(context.Context, uint32, string, string, string) (mdnsresponder.ResolveResult, error) {
	return mdnsresponder.ResolveResult{}, errors.New("no daemon")
}

func (d *noDaemon) Addresses(context.Context, string) ([]netip.Addr, error) {
	return nil, errors.New("no daemon")
}

// A mirror that stops is started again at each poll, and the failure logged once.
func TestRun_MirrorFailureIsRetried(t *testing.T) {
	h := newHarness(t, srpTemplate("mirrors: [{type: mdns, all_hosts: true, socket: /nowhere}]\n"))
	d := &noDaemon{}
	var sockets []string
	var mu sync.Mutex
	h.start(t, func(o *Options) {
		o.PollInterval = 200 * time.Millisecond // longer than each failed run
		o.MirrorSource = func(socket string) mdnsbridge.Source {
			mu.Lock()
			sockets = append(sockets, socket)
			mu.Unlock()
			return d
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		d.mu.Lock()
		n := d.browses
		d.mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the mirror was started %d times, want it started again at each poll", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := h.logs.count("mdns mirror: stopped: no daemon"); n != 1 {
		t.Errorf("the mirror's failure was logged %d times, want once", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if sockets[0] != "/nowhere" {
		t.Errorf("mirror socket %q, want /nowhere", sockets[0])
	}
}

func TestProbe(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		if status == http.StatusFound {
			http.Redirect(w, r, "http://192.0.2.1/", status) // not followed
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(srv.Listener.Addr().String())
	addrs := []netip.Addr{ap.Addr()}
	ctx := context.Background()

	for _, tc := range []struct {
		probe  Probe
		status int
		pass   bool
	}{
		{Probe{Kind: ProbeTCP}, 0, true},
		{Probe{Kind: ProbeHTTP, Path: "/health"}, http.StatusOK, true},
		{Probe{Kind: ProbeHTTP, Path: "/health"}, http.StatusFound, true},
		{Probe{Kind: ProbeHTTP, Path: "/health"}, http.StatusServiceUnavailable, false},
		{Probe{Kind: ProbeHTTP, Path: "/other"}, http.StatusOK, false},
	} {
		status = tc.status
		err := probe(ctx, tc.probe, addrs, ap.Port(), time.Second)
		if (err == nil) != tc.pass {
			t.Errorf("probe %v with status %d: %v, want pass %v", tc.probe, tc.status, err, tc.pass)
		}
	}
	// The second address answers.
	if err := probe(ctx, Probe{Kind: ProbeTCP}, []netip.Addr{netip.MustParseAddr("127.0.0.2"), ap.Addr()}, ap.Port(), time.Second); err != nil {
		t.Errorf("probe with a second address that answers: %v", err)
	}
	if err := probe(ctx, Probe{Kind: ProbeTCP}, nil, ap.Port(), time.Second); err == nil {
		t.Error("probe with no address passed")
	}
}
