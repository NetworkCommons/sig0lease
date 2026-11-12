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
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/mdnsbridge"
	"github.com/NetworkCommons/sig0lease/client/mdnsresponder"
	"github.com/NetworkCommons/sig0lease/client/rfc9664"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// registrar records every update the agent's clients send. It answers YXDOMAIN to an update
// whose host name is in taken, REFUSED to one whose host name is in refused, NOERROR to the
// rest. taken and refused are set while the agent is not running. It answers a query from
// the records set and setTXT give, without recording it; with zone set, a query outside it
// gets what the proxy answers when it forwards no queries: REFUSED, with Extended DNS Error 20.
type registrar struct {
	sent    chan *dns.Msg
	taken   []string
	refused []string
	zone    string
	mu      sync.Mutex
	records map[string][]dns.RR // by "<owner> <type>"
}

// set makes the records of type qtype at owner rrs; none removes them.
func (r *registrar) set(owner string, qtype uint16, rrs ...dns.RR) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.records == nil {
		r.records = map[string][]dns.RR{}
	}
	r.records[owner+" "+dns.TypeToString[qtype]] = rrs
}

// setTXT makes the TXT records at owner those of values, one each; none removes them.
func (r *registrar) setTXT(owner string, values ...string) {
	var rrs []dns.RR
	for _, v := range values {
		rrs = append(rrs, txtRR(owner, v))
	}
	r.set(owner, dns.TypeTXT, rrs...)
}

// txtRR returns the TXT record at owner with one string for each of values.
func txtRR(owner string, values ...string) *dns.TXT {
	txt := &dns.TXT{Hdr: dns.Header{Name: owner, Class: dns.ClassINET, TTL: 30}}
	for _, v := range values {
		txt.TXT.Txt = append(txt.TXT.Txt, dnsmsg.EscapeTXT(v))
	}
	return txt
}

func (r *registrar) Send(ctx context.Context, addr string, network baseclient.Network, msg *dns.Msg) (*dns.Msg, error) {
	if msg.Opcode == dns.OpcodeQuery {
		resp := &dns.Msg{MsgHeader: dns.MsgHeader{ID: msg.ID, Response: true, Rcode: dns.RcodeNameError}, Question: msg.Question}
		name := msg.Question[0].Header().Name
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.zone != "" && !dnsname.IsAtOrBelow(name, r.zone) {
			resp.Rcode = dns.RcodeRefused
			dnsmsg.AddEDE(resp, msg, dns.ExtendedErrorNotAuthoritative, "")
			return resp, nil
		}
		if rrs := r.records[name+" "+dns.TypeToString[dns.RRToType(msg.Question[0])]]; len(rrs) > 0 {
			resp.Answer, resp.Rcode = rrs, dns.RcodeSuccess
		}
		return resp, nil
	}
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

// rrs is what an update adds, or deletes: addresses, SRV instances and their TXT records, and
// an RFC 9664 name's other records.
type rrs struct {
	addrs        []string
	instances    []string
	instanceTXTs []string
	records      []string
}

func (s *rrs) add(rr dns.RR) {
	switch r := rr.(type) {
	case *dns.A:
		s.addrs = append(s.addrs, r.A.Addr.String())
	case *dns.AAAA:
		s.addrs = append(s.addrs, r.AAAA.Addr.String())
	case *dns.SRV:
		s.instances = append(s.instances, r.Hdr.Name)
	case *dns.TXT:
		if !strings.Contains(r.Hdr.Name, "._") {
			s.records = append(s.records, rfc9664.Describe(r))
		} else {
			s.instanceTXTs = append(s.instanceTXTs, rfc9664.Describe(r))
		}
	case *dns.TLSA:
		s.records = append(s.records, rfc9664.Describe(r))
	}
}

// update is what an update registers: its host name (or RFC 9664 name) and KEY, the records
// it adds, those it deletes (class NONE, RFC 2136 S2.5.4), the instances it withdraws, and the
// leases it asks for.
type update struct {
	host string
	key  *dns.KEY // the one at the host name
	rrs
	deleted         rrs
	withdrawn       []string
	lease, keyLease uint32
}

func summarize(m *dns.Msg) update {
	var u update
	if lo, err := leasepkg.FindAndDecode(m); err == nil && lo.KeyLease != nil {
		u.lease, u.keyLease = lo.Lease, *lo.KeyLease
	}
	for _, rr := range m.Ns {
		switch {
		case rr.Header().Class == dns.ClassNONE:
			u.deleted.add(rr)
		case rr.Header().Class == dns.ClassINET:
			u.add(rr)
		}
		if k, ok := rr.(*dns.KEY); ok && !strings.Contains(k.Hdr.Name, "._") {
			u.host, u.key = k.Hdr.Name, k
		}
	}
	for _, rr := range m.Ns {
		if r, ok := rr.(*dns.ANY); ok && r.Hdr.Class == dns.ClassANY && strings.Contains(r.Hdr.Name, "._") && !slices.Contains(u.instances, r.Hdr.Name) {
			u.withdrawn = append(u.withdrawn, r.Hdr.Name)
		}
	}
	slices.Sort(u.instances)
	slices.Sort(u.deleted.instances)
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
	l.waitN(t, sub, 1)
}

// waitN waits for n lines containing sub.
func (l *logs) waitN(t *testing.T, sub string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for l.count(sub) < n {
		if time.Now().After(deadline) {
			l.mu.Lock()
			defer l.mu.Unlock()
			t.Fatalf("want %d log lines containing %q in:\n%s", n, sub, strings.Join(l.lines, "\n"))
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

// nameTemplate is srpTemplate's for an rfc9664 registrar at 127.0.0.1:8159, its names in dev.test.
func nameTemplate(rest string) string {
	return "keystore: keys\nregistrars:\n  - protocol: rfc9664\n    server: 127.0.0.1:8159\n" + indent(rest)
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
// deregistered keeping its names, whatever its on_stop says, and registered again with it.
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
	freed = "  - {name: freed, addresses: [192.0.2.2], lease: 3m, key_lease: 10m, on_stop: release}\n"
	h.write(t, srpTemplate("hosts:\n"+kept+freed))
	restarted := map[string][]update{}
	h.until(t, "deregistering kept and freed, then registering them again", func(u update) bool {
		restarted[u.host] = append(restarted[u.host], u)
		return len(restarted["kept.srp.test."]) == 2 && len(restarted["freed.srp.test."]) == 2
	})
	for host, want := range map[string]struct{ keyLease, lease uint32 }{"kept.srp.test.": {1209600, 1800}, "freed.srp.test.": {600, 180}} {
		if u := restarted[host][0]; len(u.addrs) != 0 || u.keyLease != want.keyLease {
			t.Errorf("%s's update on its lease changing %+v, want it deregistered keeping its names (KEY-LEASE %d)", host, u, want.keyLease)
		}
		if u := restarted[host][1]; len(u.addrs) == 0 || u.lease != want.lease {
			t.Errorf("%s's next update %+v, want it registered with lease %d", host, u, want.lease)
		}
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

// A host renamed because another key holds its name keeps the new name while the agent
// runs. A restart first frees the names the rename held, which on_stop: keep kept, then asks
// for the host's own: it is renamed again while the other key holds it, and gets it once free.
func TestRun_RenameLastsUntilARestart(t *testing.T) {
	h := newHarness(t, srpTemplate("hosts: [{name: box, addresses: [192.0.2.1]}]\n"))
	h.reg.taken = []string{"box.srp.test."}
	query := heldBy("box.srp.test.")
	h.start(t, func(o *Options) { o.Query = query })
	h.until(t, "registering box-2", func(u update) bool { return u.host == "box-2.srp.test." && len(u.addrs) > 0 })
	h.logs.waitFor(t, "box: renamed: now host box-2")
	h.stop(t)
	if u := h.until(t, "deregistering box-2", func(u update) bool { return len(u.addrs) == 0 }); u.host != "box-2.srp.test." || u.keyLease != 1209600 {
		t.Fatalf("update on stopping %+v, want box-2 deregistered keeping its names", u)
	}
	state, err := os.ReadFile(filepath.Join(h.dir, "keys", StateFile))
	if err != nil || !strings.Contains(string(state), `"host": "box-2"`) || !strings.Contains(string(state), `"held": true`) {
		t.Fatalf("state file, want box held as box-2: %v\n%s", err, state)
	}
	plan, err := Load(h.path)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := Describe(&out, plan, h.options().Interfaces, nil); err != nil {
		t.Fatal(err)
	}
	if want := "renamed:   an earlier run's rename holds host box-2.srp.test.; run frees its names and asks for these again"; !strings.Contains(out.String(), want) {
		t.Errorf("plan does not say %q:\n%s", want, out.String())
	}

	h.start(t, func(o *Options) { o.Query = query })
	if u := h.until(t, "the first update", func(update) bool { return true }); u.host != "box-2.srp.test." || len(u.addrs) != 0 || u.keyLease != 0 {
		t.Fatalf("first update after a restart %+v, want box-2 freed", u)
	}
	if u := h.until(t, "the next update", func(update) bool { return true }); u.host != "box.srp.test." {
		t.Fatalf("after freeing box-2, the restart registered %+v, want box", u)
	}
	h.until(t, "registering box-2 again", func(u update) bool { return u.host == "box-2.srp.test." && len(u.addrs) > 0 })
	h.logs.waitFor(t, "box: registered")
	if n := h.logs.count("box: renamed: now host box-2"); n != 2 {
		t.Errorf("logged %d renames, want 2: one per start", n)
	}
	h.stop(t)
	h.until(t, "deregistering box-2", func(u update) bool { return len(u.addrs) == 0 })

	h.reg.taken = nil
	h.start(t, func(o *Options) { o.Query = heldBy() })
	if u := h.until(t, "the first update", func(update) bool { return true }); u.host != "box-2.srp.test." || u.keyLease != 0 {
		t.Fatalf("first update after the second restart %+v, want box-2 freed", u)
	}
	if u := h.until(t, "registering", func(u update) bool { return len(u.addrs) > 0 }); u.host != "box.srp.test." {
		t.Fatalf("with box free, the restart registered %+v, want box", u)
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

// A name is registered with its addresses and records, registered again as the template and the
// machine change, deleting in the same update what they no longer give, and deregistered on
// stop as its on_stop says.
func TestRun_Names(t *testing.T) {
	h := newHarness(t, nameTemplate(`
names:
  - name: site.dev.test.
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
  - name: site.dev.test.
    addresses: [auto]
    records: ['@ TXT "hello"']
`))
	u = h.until(t, "registering site again", func(update) bool { return true })
	if !slices.Equal(u.records, []string{`site.dev.test. TXT "hello"`}) || !slices.Equal(u.deleted.records, []string{`_dnslink.site.dev.test. TXT "dnslink=/ipfs/x"`}) || u.lease != 3600 || u.keyLease != 1209600 {
		t.Fatalf("update after the template change %+v, want the TXT record left and _dnslink deleted", u)
	}

	h.setMachine("192.0.2.11")
	u = h.until(t, "registering the new address", func(update) bool { return true })
	if !slices.Equal(u.addrs, []string{"192.0.2.11"}) || !slices.Equal(u.deleted.addrs, []string{"192.0.2.10"}) || u.lease != 3600 {
		t.Fatalf("update after the machine's address changed %+v, want 192.0.2.11 added and 192.0.2.10 deleted", u)
	}

	h.stop(t)
	u = h.until(t, "deregistering site", func(update) bool { return true })
	if len(u.addrs) != 0 || len(u.records) != 0 || !slices.Equal(u.deleted.addrs, []string{"192.0.2.11"}) || len(u.deleted.records) != 1 || u.lease != 0 || u.keyLease != 1209600 {
		t.Fatalf("update on stop %+v, want the records deleted and the name kept (on_stop: keep)", u)
	}
}

// A template's warnings are logged when the agent starts and with each change it applies.
func TestRun_LogsWarnings(t *testing.T) {
	const warning = "template: registrars[0] (rfc9664 127.0.0.1:8159): resolvers: unused"
	h := newHarness(t, nameTemplate("resolvers: [192.0.2.53:53]\nnames: [{name: site.dev.test., addresses: [auto]}]\n"))
	h.start(t, nil)
	h.logs.waitFor(t, warning)

	h.write(t, nameTemplate("resolvers: [192.0.2.53:53]\nnames: [{name: site.dev.test., addresses: [auto], records: ['@ TXT \"hello\"']}]\n"))
	h.until(t, "registering the TXT record", func(u update) bool { return len(u.records) == 1 })
	if n := h.logs.count(warning); n != 2 {
		t.Errorf("warning logged %d times, want 2: at the start and with the change", n)
	}
}

// A name's service is registered as its SRV records, with the TLSA record its certificate
// gives, once its probe passes, and deleted while its certificate cannot be read or after
// ProbeFailures failed probes in a row. A new key in the certificate replaces the TLSA record:
// each change is one update.
func TestRun_NameServices(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	h := newHarness(t, nameTemplate(fmt.Sprintf(`
names:
  - name: a.dev.test.
    addresses: [127.0.0.1]
    services:
      - {type: xmpp-server, port: %d, subdomains: [rooms], tlsa: a.pem}
      - {type: xmpp-client, port: %d}
`, port, closedPort)))
	cert := filepath.Join(h.dir, "a.pem")
	spki := writeCert(t, cert)
	h.start(t, nil)

	srvs := []string{"_xmpp-server._tcp.a.dev.test.", "_xmpp-server._tcp.rooms.a.dev.test."}
	tlsa := func(spki string) []string {
		return []string{fmt.Sprintf("_%d._tcp.a.dev.test. TLSA 3 1 1 %s", port, spki)}
	}
	u := h.until(t, "registering xmpp-server", func(u update) bool { return u.lease != 0 && len(u.instances) > 0 })
	if !slices.Equal(u.instances, srvs) || !slices.Equal(u.records, tlsa(spki)) || !slices.Equal(u.addrs, []string{"127.0.0.1"}) {
		t.Fatalf("registration %+v, want a's address, xmpp-server's SRV records for a and rooms.a and its TLSA record", u)
	}
	h.logs.waitFor(t, "a.dev.test.: _xmpp-client._tcp: not registered until its probe passes")

	newSPKI := writeCert(t, cert)
	if u = h.until(t, "replacing the TLSA record", func(update) bool { return true }); !slices.Equal(u.records, tlsa(newSPKI)) || !slices.Equal(u.instances, srvs) ||
		!slices.Equal(u.deleted.records, tlsa(spki)) || len(u.deleted.instances) != 0 || u.lease == 0 {
		t.Fatalf("registration after the new key %+v, want the SRV records and the new TLSA record, the old one deleted", u)
	}
	h.logs.waitFor(t, "a.dev.test.: _xmpp-server._tcp: certificate "+cert+" has a new key; its TLSA record follows")

	if err := os.Remove(cert); err != nil {
		t.Fatal(err)
	}
	if u = h.until(t, "deleting xmpp-server", func(update) bool { return true }); !slices.Equal(u.deleted.records, tlsa(newSPKI)) || !slices.Equal(u.deleted.instances, srvs) ||
		len(u.instances) != 0 || !slices.Equal(u.addrs, []string{"127.0.0.1"}) || u.lease == 0 {
		t.Fatalf("registration without the certificate %+v, want a's address, the SRV and TLSA records deleted", u)
	}
	h.logs.waitFor(t, "a.dev.test.: _xmpp-server._tcp: certificate: open "+cert+": no such file or directory; not registered until it can be read")
	spki = writeCert(t, cert)
	if u = h.until(t, "registering xmpp-server again", func(u update) bool { return u.lease != 0 && len(u.instances) > 0 }); !slices.Equal(u.records, tlsa(spki)) {
		t.Fatalf("registration with the certificate back %+v, want its TLSA record", u)
	}
	h.logs.waitFor(t, "a.dev.test.: _xmpp-server._tcp: certificate "+cert+" read")

	ln.Close()
	if u = h.until(t, "deleting xmpp-server after its probes", func(update) bool { return true }); !slices.Equal(u.deleted.instances, srvs) || !slices.Equal(u.deleted.records, tlsa(spki)) ||
		len(u.instances) != 0 || !slices.Equal(u.addrs, []string{"127.0.0.1"}) || u.lease == 0 {
		t.Fatalf("registration after failed probes %+v, want a's address, the SRV and TLSA records deleted", u)
	}
	h.logs.waitFor(t, "a.dev.test.: _xmpp-server._tcp: probe failed 3 times in a row, withdrawing it")
}

// A name's service changed in the template is registered as it now is: here offered for a
// subdomain too, and without its TLSA record.
func TestRun_NameServiceChanges(t *testing.T) {
	h := newHarness(t, nameTemplate("names: [{name: a.dev.test., addresses: [127.0.0.1], services: [{type: xmpp-server, probe: none, tlsa: a.pem}]}]\n"))
	spki := writeCert(t, filepath.Join(h.dir, "a.pem"))
	h.start(t, nil)
	tlsa := []string{"_5269._tcp.a.dev.test. TLSA 3 1 1 " + spki}
	if u := h.until(t, "registering a", func(u update) bool { return u.lease != 0 }); !slices.Equal(u.instances, []string{"_xmpp-server._tcp.a.dev.test."}) || !slices.Equal(u.records, tlsa) {
		t.Fatalf("registration %+v, want xmpp-server's SRV and TLSA records", u)
	}

	h.write(t, nameTemplate("names: [{name: a.dev.test., addresses: [127.0.0.1], services: [{type: xmpp-server, probe: none, subdomains: [rooms]}]}]\n"))
	if u := h.until(t, "registering a again", func(update) bool { return true }); !slices.Equal(u.instances, []string{"_xmpp-server._tcp.a.dev.test.", "_xmpp-server._tcp.rooms.a.dev.test."}) || len(u.records) != 0 ||
		!slices.Equal(u.deleted.records, tlsa) || len(u.deleted.instances) != 0 || u.lease == 0 {
		t.Fatalf("registration after the change %+v, want the SRV records for a and rooms.a, the TLSA record deleted", u)
	}
}

// A name another key holds is not renamed: the agent says so and tries the same name again.
func TestRun_NameHeldByAnotherKey(t *testing.T) {
	h := newHarness(t, nameTemplate("names: [{name: site.dev.test., records: ['@ TXT x']}]\n"))
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
	both := "names:\n  - {name: site.dev.test., records: ['@ TXT x']}\n  - {name: gone.dev.test., addresses: [192.0.2.1]}\n"
	h := newHarness(t, nameTemplate(both))
	h.start(t, nil)
	h.logs.waitFor(t, "site.dev.test.: registered")
	h.logs.waitFor(t, "gone.dev.test.: registered")

	h.write(t, nameTemplate("names:\n  - {name: site.dev.test., records: ['@ TXT x']}\n"))
	if u := h.until(t, "deregistering gone", func(u update) bool { return u.host == "gone.dev.test." && u.lease == 0 }); u.keyLease != 1209600 || len(u.deleted.addrs) != 1 || len(u.addrs) != 0 {
		t.Errorf("gone's first update after its removal %+v, want its address deleted, the name kept as on_stop says", u)
	}
	if u := h.until(t, "freeing gone", func(u update) bool { return u.host == "gone.dev.test." }); u.lease != 0 || u.keyLease != 0 || len(u.addrs) != 0 || len(u.deleted.addrs) != 0 {
		t.Errorf("gone's next update %+v, want its KEY alone, both leases 0", u)
	}
	h.logs.waitFor(t, "template: gone.dev.test. removed; freeing it")
	h.logs.waitFor(t, "gone.dev.test.: deregistered the name alone; name freed")
	h.waitState(t, "site and not gone", func(state string) bool {
		return !strings.Contains(state, `"gone.dev.test."`) && strings.Contains(state, `"site.dev.test."`)
	})
}

// While the agent runs, a host or name it still registers keeps its names when it is
// deregistered, whatever its on_stop says: here a host and a name left with no address.
// Stopping with on_stop: release then frees them.
func TestRun_KeepsNamesWhileRunning(t *testing.T) {
	h := newHarness(t, srpTemplate("on_stop: release\nhosts: [{name: box, addresses: [auto]}]\n")+`  - protocol: rfc9664
    server: 127.0.0.1:8159
    on_stop: release
    names: [{name: site.dev.test., addresses: [auto]}]
`)
	h.start(t, nil)
	byHost := func(what string) map[string]update {
		got := map[string]update{}
		h.until(t, what, func(u update) bool { got[u.host] = u; return len(got) == 2 })
		return got
	}
	byHost("registering box and site")

	h.setMachine()
	got := byHost("deregistering box and site")
	if u := got["box.srp.test."]; len(u.addrs) != 0 || u.keyLease != 1209600 {
		t.Errorf("box's update with no address %+v, want it deregistered keeping its names", u)
	}
	if u := got["site.dev.test."]; len(u.addrs) != 0 || !slices.Equal(u.deleted.addrs, []string{"192.0.2.10"}) || u.lease != 0 || u.keyLease != 1209600 {
		t.Errorf("site's update with no address %+v, want its address deleted and the name kept", u)
	}

	h.stop(t)
	got = byHost("freeing box and site")
	if u := got["box.srp.test."]; len(u.addrs) != 0 || len(u.withdrawn) != 0 || u.keyLease != 0 {
		t.Errorf("box's update on stopping %+v, want the host alone freed", u)
	}
	if u := got["site.dev.test."]; len(u.addrs) != 0 || len(u.deleted.addrs) != 0 || u.lease != 0 || u.keyLease != 0 {
		t.Errorf("site's update on stopping %+v, want its KEY alone, both leases 0", u)
	}
	h.none(t, 100*time.Millisecond)
}

// Names held from an earlier run by a host this run never registers are freed when the agent
// stops, if its on_stop is release.
func TestRun_StopFreesNamesHeldFromAnEarlierRun(t *testing.T) {
	h := newHarness(t, srpTemplate("hosts: [{name: box, addresses: [auto]}]\n"))
	h.start(t, nil)
	h.logs.waitFor(t, "box: registered")
	h.stop(t)
	h.until(t, "deregistering box, keeping its names", func(u update) bool { return u.host == "box.srp.test." && len(u.addrs) == 0 })

	h.write(t, srpTemplate("on_stop: release\nhosts: [{name: box, addresses: [auto]}]\n"))
	h.setMachine()
	h.start(t, nil)
	h.logs.waitFor(t, "box: no address to register it with")
	h.stop(t)
	if u := h.until(t, "freeing box", func(u update) bool { return u.host == "box.srp.test." }); len(u.addrs) != 0 || u.keyLease != 0 {
		t.Errorf("box's update on stopping %+v, want the host alone freed", u)
	}
	h.logs.waitFor(t, "state: box.srp.test. still holds names; freeing them (on_stop: release)")
}

// goneDaemon is an mDNS daemon that reports one instance on mac.local. for every service type
// browsed, until it goes away (gone closed): then every browse fails.
type goneDaemon struct{ gone chan struct{} }

func (d *goneDaemon) Browse(ctx context.Context, serviceType, domain string, events chan<- mdnsresponder.BrowseEvent) error {
	select {
	case <-d.gone:
		return errors.New("daemon gone")
	case events <- mdnsresponder.BrowseEvent{Add: true, InterfaceIndex: 2, Name: "Shell", Type: serviceType + ".", Domain: "local."}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-d.gone:
		return errors.New("daemon gone")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *goneDaemon) Resolve(context.Context, uint32, string, string, string) (mdnsresponder.ResolveResult, error) {
	return mdnsresponder.ResolveResult{Target: "mac.local.", Port: 22}, nil
}

func (d *goneDaemon) Addresses(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.20")}, nil
}

// A mirror that stops on its own deregisters its hosts keeping their names, whatever on_stop
// says: it is started again at the next poll. The agent stopping with on_stop: release frees
// them, also while the mirror is down.
func TestRun_MirrorFailureKeepsNames(t *testing.T) {
	h := newHarness(t, srpTemplate("on_stop: release\nmirrors: [{type: mdns, all_hosts: true, services: [_ssh._tcp], socket: /nowhere}]\n"))
	d := &goneDaemon{gone: make(chan struct{})}
	h.start(t, func(o *Options) { o.MirrorSource = func(string) mdnsbridge.Source { return d } })
	h.until(t, "registering mac", func(u update) bool { return u.host == "mac.srp.test." && len(u.addrs) > 0 })
	h.logs.waitFor(t, "mac: registered")

	close(d.gone)
	if u := h.until(t, "deregistering mac", func(u update) bool { return u.host == "mac.srp.test." }); len(u.addrs) != 0 || u.keyLease != 1209600 {
		t.Errorf("mac's update as its mirror stopped %+v, want it deregistered keeping its names", u)
	}
	h.logs.waitFor(t, "mdns mirror: stopped: ")

	h.stop(t)
	if u := h.until(t, "freeing mac", func(u update) bool { return u.host == "mac.srp.test." }); len(u.addrs) != 0 || len(u.withdrawn) != 0 || u.keyLease != 0 {
		t.Errorf("mac's update as the agent stopped %+v, want the host alone freed", u)
	}
	h.logs.waitFor(t, "state: mac.srp.test. still holds names; freeing them (on_stop: release)")
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

// TestProbe_TriesAddressesAtOnce: a probe takes at most its timeout however many addresses do
// not answer (a Mac in stealth mode lets connections to a stopped service time out), and passes
// as soon as one answers. The same address stands for several, one connection each.
func TestProbe_TriesAddressesAtOnce(t *testing.T) {
	var requests atomic.Int32
	var hangFirst atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := requests.Add(1); !hangFirst.Load() || n == 1 {
			<-r.Context().Done() // never answers; done once the probe gives up
		}
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(srv.Listener.Addr().String())
	ctx := context.Background()
	get := Probe{Kind: ProbeHTTP, Path: "/"}

	start := time.Now()
	err := probe(ctx, get, []netip.Addr{ap.Addr(), ap.Addr(), ap.Addr()}, ap.Port(), time.Second)
	if err == nil {
		t.Fatal("probe of addresses that never answer passed")
	}
	if took := time.Since(start); took >= 2*time.Second {
		t.Errorf("probe of 3 addresses that never answer took %v, want about its 1s timeout", took)
	}
	if n := strings.Count(err.Error(), "Client.Timeout exceeded"); n != 3 {
		t.Errorf("probe error has %d timeouts, want one per address: %v", n, err)
	}

	hangFirst.Store(true)
	requests.Store(0)
	start = time.Now()
	if err := probe(ctx, get, []netip.Addr{ap.Addr(), ap.Addr()}, ap.Port(), 5*time.Second); err != nil {
		t.Fatalf("probe with one address that answers: %v", err)
	}
	if took := time.Since(start); took >= 2*time.Second {
		t.Errorf("probe with one address that answers took %v; it waited for the one that does not", took)
	}
}
