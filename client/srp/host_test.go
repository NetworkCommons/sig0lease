package srp

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/clienttest"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// hostRegistrar records every update a Host's clients send. It answers YXDOMAIN to an update
// whose host name is in taken, REFUSED to one whose host name is in refused, NOERROR to the
// rest. taken and refused are set while no Host runs.
type hostRegistrar struct {
	sent    chan *dns.Msg
	taken   []string
	refused []string
}

func (r *hostRegistrar) Send(ctx context.Context, addr string, network baseclient.Network, msg *dns.Msg) (*dns.Msg, error) {
	r.sent <- msg
	switch host := sentUpdate(msg).host; {
	case slices.Contains(r.taken, host):
		return clienttest.Answer(dns.RcodeYXDomain), nil
	case slices.Contains(r.refused, host):
		return clienttest.Answer(dns.RcodeRefused), nil
	}
	return clienttest.Granted(30, 1209600), nil
}

func (r *hostRegistrar) next(t *testing.T) summary {
	t.Helper()
	select {
	case m := <-r.sent:
		return sentUpdate(m)
	case <-time.After(5 * time.Second):
		t.Fatal("no update sent")
		return summary{}
	}
}

func (r *hostRegistrar) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-r.sent:
		t.Fatalf("unexpected update: %+v", sentUpdate(m))
	case <-time.After(d):
	}
}

// summary is what an update registers: its host name and addresses, its live instances, the
// instances it withdraws, and the KEY-LEASE it asks for.
type summary struct {
	host      string
	addrs     []string
	instances []string
	withdrawn []string
	keyLease  uint32
}

func sentUpdate(m *dns.Msg) summary {
	var s summary
	if lo, err := leasepkg.FindAndDecode(m); err == nil && lo.KeyLease != nil {
		s.keyLease = *lo.KeyLease
	}
	for _, rr := range m.Ns {
		switch r := rr.(type) {
		case *dns.KEY:
			if !strings.Contains(r.Hdr.Name, "._") {
				s.host = r.Hdr.Name
			}
		case *dns.A:
			s.addrs = append(s.addrs, r.A.Addr.String())
		case *dns.SRV:
			s.instances = append(s.instances, r.Hdr.Name)
		}
	}
	for _, rr := range m.Ns {
		if r, ok := rr.(*dns.ANY); ok && r.Hdr.Class == dns.ClassANY && strings.Contains(r.Hdr.Name, "._") && !slices.Contains(s.instances, r.Hdr.Name) {
			s.withdrawn = append(s.withdrawn, r.Hdr.Name)
		}
	}
	return s
}

// memStore is a HostStore in memory: the labels each host's names are held under.
type memStore struct {
	mu   sync.Mutex
	held map[string]Labels
}

func newMemStore() *memStore {
	return &memStore{held: map[string]Labels{}}
}

func (m *memStore) Load(host string) *Labels {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.held[host]; ok {
		return &l
	}
	return nil
}

func (m *memStore) Hold(host string, labels *Labels) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if labels == nil {
		delete(m.held, host)
	} else {
		m.held[host] = *labels
	}
	return nil
}

func (m *memStore) isHeld(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.held[host]
	return ok
}

func startTestHost(t *testing.T, reg *hostRegistrar, store HostStore, query DNSQuery, logf func(string, ...any), keepNames bool) *Host {
	t.Helper()
	key, err := keyrec.GenerateKey("box.srp.test.", dns.ECDSAP256SHA256, 0, 256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	h, err := StartHost(HostConfig{
		Client: Config{
			Domain:        "srp.test.",
			HostLabel:     "box",
			Key:           key,
			RegistrarAddr: "127.0.0.1:8159",
			Send:          reg.Send,
			Query:         query,
			// The initial 0-3s delay passes at once; the refresh wait lasts until the client
			// is stopped.
			Sleep: func(ctx context.Context, d time.Duration) error {
				if d < 10*time.Second {
					return ctx.Err()
				}
				<-ctx.Done()
				return ctx.Err()
			},
		},
		Store:        store,
		KeeperConfig: baseclient.KeeperConfig{Settle: 10 * time.Millisecond, Logf: logf, KeepNames: keepNames},
	})
	if err != nil {
		t.Fatalf("StartHost: %v", err)
	}
	t.Cleanup(func() { h.Stop(); h.Wait() })
	return h
}

var boxAddr = []netip.Addr{netip.MustParseAddr("192.0.2.7")}

func TestHost_RegistersWithdrawsAndDeregisters(t *testing.T) {
	reg := &hostRegistrar{sent: make(chan *dns.Msg, 16)}
	h := startTestHost(t, reg, nil, nil, nil, false)
	web := InstanceConfig{Label: "Web", ServiceType: "_http._tcp", Port: 80}
	shell := InstanceConfig{Label: "Shell", ServiceType: "_ssh._tcp", Port: 22}

	h.Set(boxAddr, []InstanceConfig{web, shell})
	if got := reg.next(t); got.host != "box.srp.test." || len(got.instances) != 2 || len(got.withdrawn) != 0 {
		t.Fatalf("first update = %+v, want box with Web and Shell", got)
	}

	h.Set(boxAddr, []InstanceConfig{web})
	if got := reg.next(t); !slices.Equal(got.withdrawn, []string{"Shell._ssh._tcp.srp.test."}) {
		t.Fatalf("second update = %+v, want Shell withdrawn", got)
	}
	if got := reg.next(t); !slices.Equal(got.instances, []string{"Web._http._tcp.srp.test."}) || len(got.withdrawn) != 0 {
		t.Fatalf("third update = %+v, want Web alone registered", got)
	}

	h.Set(nil, nil)
	if got := reg.next(t); len(got.addrs) != 0 || !slices.Equal(got.withdrawn, []string{"Web._http._tcp.srp.test."}) {
		t.Fatalf("update after no addresses = %+v, want the host deregistered", got)
	}
	h.Stop()
	h.Wait()
	reg.none(t, 50*time.Millisecond)
}

// A host with no instance is registered with its addresses alone, and deregistered on Stop.
func TestHost_RegistersTheHostAlone(t *testing.T) {
	reg := &hostRegistrar{sent: make(chan *dns.Msg, 16)}
	h := startTestHost(t, reg, nil, nil, nil, false)

	h.Set(boxAddr, nil)
	if got := reg.next(t); got.host != "box.srp.test." || !slices.Equal(got.addrs, []string{"192.0.2.7"}) || len(got.instances) != 0 {
		t.Fatalf("update = %+v, want box with its address and nothing else", got)
	}
	h.Stop()
	h.Wait()
	if got := reg.next(t); len(got.addrs) != 0 {
		t.Fatalf("update on Stop = %+v, want the host deregistered", got)
	}
}

// With KeepNames, deregistering on Stop or on a Set with no addresses asks for the KEY-LEASE
// the host registers with, so its names stay reserved for its key; without it for a
// KEY-LEASE of 0, which frees them (RFC 9665 S3.2.5.5.1). The store records the names as held
// from the first registration until they are freed.
func TestHost_KeepNames(t *testing.T) {
	for _, tt := range []struct {
		name string
		keep bool
		want uint32
	}{
		{"Stop keeping the names", true, 1209600},
		{"Stop freeing the names", false, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reg := &hostRegistrar{sent: make(chan *dns.Msg, 16)}
			store := newMemStore()
			h := startTestHost(t, reg, store, nil, nil, tt.keep)
			h.Set(boxAddr, nil)
			reg.next(t)
			waitFor(t, "the names recorded as held", func() bool { return store.isHeld("box.srp.test.") })
			h.Stop()
			h.Wait()
			if got := reg.next(t); len(got.addrs) != 0 || got.keyLease != tt.want {
				t.Fatalf("update on stopping = %+v, want the host deregistered with KEY-LEASE %d", got, tt.want)
			}
			if held := store.isHeld("box.srp.test."); held != tt.keep {
				t.Fatalf("names recorded as held after stopping: %v, want %v", held, tt.keep)
			}
		})
	}

	reg := &hostRegistrar{sent: make(chan *dns.Msg, 16)}
	h := startTestHost(t, reg, nil, nil, nil, true)
	h.Set(boxAddr, nil)
	reg.next(t)
	h.Set(nil, nil)
	if got := reg.next(t); len(got.addrs) != 0 || got.keyLease != 1209600 {
		t.Fatalf("update after no addresses = %+v, want the host deregistered keeping its names", got)
	}
}

// A rename is used by the Host's next registrations, and recorded as the labels its names
// are held under. A new Host on the same store first frees the names the rename holds, kept
// when the first one stopped, then asks for the requested ones: it is renamed again while
// another key holds them, and gets them once they are free.
func TestHost_StartsOverAfterARename(t *testing.T) {
	reg := &hostRegistrar{sent: make(chan *dns.Msg, 16), taken: []string{"box.srp.test."}}
	store := newMemStore()
	h := startTestHost(t, reg, store, heldBy("box.srp.test."), nil, true)

	h.Set(boxAddr, nil)
	if got := reg.next(t); got.host != "box.srp.test." {
		t.Fatalf("first attempt = %+v, want box", got)
	}
	if got := reg.next(t); got.host != "box-2.srp.test." {
		t.Fatalf("retry = %+v, want box-2", got)
	}
	waitFor(t, "the names recorded as held under box-2", func() bool {
		l := store.Load("box.srp.test.")
		return l != nil && l.Host == "box-2"
	})
	h.Set(boxAddr, []InstanceConfig{{Label: "Web", ServiceType: "_http._tcp", Port: 80}})
	if got := reg.next(t); got.host != "box-2.srp.test." {
		t.Fatalf("next registration = %+v, want box-2 kept", got)
	}
	h.Stop()
	h.Wait()
	if got := reg.next(t); got.host != "box-2.srp.test." || len(got.addrs) != 0 || got.keyLease != 1209600 {
		t.Fatalf("update on stopping = %+v, want box-2 deregistered keeping its names", got)
	}

	// box is still another key's: the new Host frees box-2, and is renamed box-2 again.
	again := startTestHost(t, reg, store, heldBy("box.srp.test."), nil, true)
	if got := reg.next(t); got.host != "box-2.srp.test." || len(got.addrs) != 0 || got.keyLease != 0 {
		t.Fatalf("first update of a new Host = %+v, want box-2 freed (KEY-LEASE 0)", got)
	}
	again.Set(boxAddr, nil)
	if got := reg.next(t); got.host != "box.srp.test." {
		t.Fatalf("after freeing box-2, a new Host registered %+v, want box", got)
	}
	if got := reg.next(t); got.host != "box-2.srp.test." || len(got.addrs) == 0 {
		t.Fatalf("retry = %+v, want box-2 registered", got)
	}
	again.Stop()
	again.Wait()
	reg.next(t) // the deregistration, keeping box-2

	// box is free: the next Host frees box-2 and gets box.
	reg.taken = nil
	var logged []string
	var mu sync.Mutex
	third := startTestHost(t, reg, store, heldBy(), func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(format, args...))
	}, true)
	if got := reg.next(t); got.host != "box-2.srp.test." || got.keyLease != 0 {
		t.Fatalf("first update of the third Host = %+v, want box-2 freed", got)
	}
	third.Set(boxAddr, nil)
	if got := reg.next(t); got.host != "box.srp.test." || len(got.addrs) == 0 {
		t.Fatalf("with box free, the third Host registered %+v, want box", got)
	}
	waitFor(t, "the names recorded as held under box", func() bool {
		l := store.Load("box.srp.test.")
		return l != nil && l.Host == "box"
	})
	mu.Lock()
	defer mu.Unlock()
	if want := "box: freeing host box-2, held from an earlier run, to ask for the requested names again"; !slices.Contains(logged, want) {
		t.Errorf("the third Host did not log %q: %q", want, logged)
	}
}

// A Host that cannot free the names an earlier rename holds registers under them, as its key
// still holds them.
func TestStartHost_KeepsARenameItCannotFree(t *testing.T) {
	reg := &hostRegistrar{sent: make(chan *dns.Msg, 16), refused: []string{"box-2.srp.test."}}
	store := newMemStore()
	store.held["box.srp.test."] = Labels{Host: "box-2", Instances: map[InstanceName]string{}}
	h := startTestHost(t, reg, store, heldBy(), nil, true)
	if got := reg.next(t); got.host != "box-2.srp.test." || got.keyLease != 0 {
		t.Fatalf("first update = %+v, want box-2 freed", got)
	}
	if !store.isHeld("box.srp.test.") {
		t.Fatal("a refused release recorded the names as freed")
	}
	reg.refused = nil
	h.Set(boxAddr, nil)
	if got := reg.next(t); got.host != "box-2.srp.test." || len(got.addrs) == 0 {
		t.Fatalf("registration = %+v, want box-2, which the key still holds", got)
	}
}

func TestStartHost_NeedsKey(t *testing.T) {
	if _, err := StartHost(HostConfig{Client: Config{Domain: "srp.test.", HostLabel: "box"}}); err == nil {
		t.Fatal("expected StartHost to refuse a host without a key")
	}
}

func TestPublishableAddresses(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"),
		netip.MustParseAddr("fe80::1"), netip.MustParseAddr("169.254.1.1"),
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("ff02::1"),
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("2001:db8::1"),
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("2001:db8::1")}
	if got := PublishableAddresses(in); !slices.Equal(got, want) {
		t.Fatalf("PublishableAddresses = %v, want %v", got, want)
	}
}

// waitFor polls cond, which a Host's goroutine makes true, for up to 5 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// Release deregisters the host alone, under the labels the store keeps, freeing its names;
// the store records them as freed once the registrar confirms it, or answers that another key
// holds the host name now, and as held still when the deregistration fails.
func TestRelease(t *testing.T) {
	for _, tt := range []struct {
		name     string
		answer   *dns.Msg
		sendErr  error
		wantHeld bool
	}{
		{"freed", clienttest.Granted(0, 0), nil, false},
		{"another key holds the name", clienttest.Answer(dns.RcodeYXDomain), nil, false},
		{"refused", clienttest.Answer(dns.RcodeRefused), nil, true},
		{"unreachable", nil, fmt.Errorf("connection refused"), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key, err := keyrec.GenerateKey("box.srp.test.", dns.ECDSAP256SHA256, 0, 256)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			store := newMemStore()
			store.held["box.srp.test."] = Labels{Host: "box-2", Instances: map[InstanceName]string{}}
			var sent []summary
			var logged []string
			err = Release(HostConfig{
				Client: Config{
					Domain:        "srp.test.",
					HostLabel:     "box",
					Key:           key,
					RegistrarAddr: "127.0.0.1:8159",
					Instances:     []InstanceConfig{{Label: "Web", ServiceType: "_http._tcp", Port: 80}},
					Send: func(ctx context.Context, addr string, network baseclient.Network, msg *dns.Msg) (*dns.Msg, error) {
						sent = append(sent, sentUpdate(msg))
						return tt.answer, tt.sendErr
					},
				},
				Store:        store,
				KeeperConfig: baseclient.KeeperConfig{Logf: func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }},
			})
			if err != nil {
				t.Fatalf("Release: %v", err)
			}
			if len(sent) != 1 || sent[0].host != "box-2.srp.test." || len(sent[0].addrs) != 0 || len(sent[0].withdrawn) != 0 || sent[0].keyLease != 0 {
				t.Fatalf("sent %+v, want one deregistration of box-2 alone with KEY-LEASE 0", sent)
			}
			if held := store.isHeld("box.srp.test."); held != tt.wantHeld {
				t.Errorf("names recorded as held: %v, want %v; logged %q", held, tt.wantHeld, logged)
			}
		})
	}
}
