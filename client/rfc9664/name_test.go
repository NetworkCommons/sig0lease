package rfc9664

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/clienttest"
)

// nameRegistrar passes every update a Name's clients send to the test, and answers it with
// answer.
type nameRegistrar struct {
	sent   chan *dns.Msg
	answer *dns.Msg
}

func newNameRegistrar() *nameRegistrar {
	return &nameRegistrar{sent: make(chan *dns.Msg, 16), answer: clienttest.Granted(30, 600)}
}

func (r *nameRegistrar) Send(ctx context.Context, addr string, network baseclient.Network, msg *dns.Msg) (*dns.Msg, error) {
	r.sent <- msg
	return r.answer, nil
}

func (r *nameRegistrar) next(t *testing.T) sent {
	t.Helper()
	select {
	case m := <-r.sent:
		return summarize(t, m)
	case <-time.After(5 * time.Second):
		t.Fatal("no update sent")
		return sent{}
	}
}

func (r *nameRegistrar) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-r.sent:
		t.Fatalf("unexpected update: %+v", summarize(t, m))
	case <-time.After(d):
	}
}

// expect fails unless got registers records on lease and keyLease.
func expect(t *testing.T, what string, got sent, records []string, lease, keyLease uint32) {
	t.Helper()
	if !slices.Equal(got.records, records) || got.lease != lease || got.keyLease != keyLease {
		t.Fatalf("%s: sent %+v, want records %q, lease %d, key lease %d", what, got, records, lease, keyLease)
	}
}

// memNames is a NameStore in memory.
type memNames struct {
	mu      sync.Mutex
	held    map[string]bool
	records map[string][]dns.RR
}

func newMemNames() *memNames {
	return &memNames{held: map[string]bool{}, records: map[string][]dns.RR{}}
}

func (m *memNames) Load(name string) []dns.RR {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.records[name]
}

func (m *memNames) Save(name string, held bool, records []dns.RR) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.held[name], m.records[name] = held, records
	return nil
}

func (m *memNames) state(name string) (bool, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var records []string
	for _, rr := range m.records[name] {
		records = append(records, describe([]dns.RR{rr}))
	}
	return m.held[name], records
}

func startTestName(t *testing.T, reg *nameRegistrar, store NameStore, keepNames bool) *Name {
	t.Helper()
	cfg := testConfig(t, reg.Send)
	// The initial 0-3s delay passes at once; a retry's backoff (5s and up) and the refresh
	// wait last until the client is stopped.
	cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		if d < 4*time.Second {
			return ctx.Err()
		}
		<-ctx.Done()
		return ctx.Err()
	}
	n, err := StartName(NameConfig{
		Client:       cfg,
		Store:        store,
		KeeperConfig: baseclient.KeeperConfig{Settle: 10 * time.Millisecond, KeepNames: keepNames},
	})
	if err != nil {
		t.Fatalf("StartName: %v", err)
	}
	t.Cleanup(func() { n.Stop(); n.Wait() })
	return n
}

var (
	siteA = "site.example. A 192.0.2.1"
	wwwA  = "www.site.example. A 192.0.2.1"
)

func records(t *testing.T, rrs ...string) []dns.RR {
	t.Helper()
	var out []dns.RR
	for _, s := range rrs {
		out = append(out, mustRR(t, s))
	}
	return out
}

func TestName_RegistersWithdrawsAndDeregisters(t *testing.T) {
	reg := newNameRegistrar()
	n := startTestName(t, reg, nil, false)

	n.Set(records(t, siteA, wwwA))
	expect(t, "first update", reg.next(t), []string{siteA, wwwA}, 30, 600)

	n.Set(records(t, siteA))
	expect(t, "withdrawal", reg.next(t), []string{wwwA}, 0, 600)
	expect(t, "registration after it", reg.next(t), []string{siteA}, 30, 600)

	n.Set(nil)
	expect(t, "update after no records", reg.next(t), nil, 0, 0)
	n.Stop()
	n.Wait()
	reg.none(t, 50*time.Millisecond)
}

// With KeepNames, Stop deletes the records and keeps the KEY (Case D).
func TestName_KeepNames(t *testing.T) {
	reg := newNameRegistrar()
	n := startTestName(t, reg, nil, true)

	n.Set(records(t, siteA))
	expect(t, "registration", reg.next(t), []string{siteA}, 30, 600)
	n.Stop()
	n.Wait()
	expect(t, "update on Stop", reg.next(t), []string{siteA}, 0, 600)
}

// While the registrar answers that another key holds the name, nothing at it is the Name's:
// a change of records withdraws nothing, and Stop deregisters nothing and records the name as
// not held. Any other refusal leaves it unknown, so Stop deregisters.
func TestName_HeldByAnotherKey(t *testing.T) {
	for _, tc := range []struct {
		name       string
		answer     *dns.Msg
		deregister bool
	}{
		{"held by another key", clienttest.Answer(dns.RcodeYXDomain), false},
		{"refused", clienttest.Answer(dns.RcodeRefused), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := newNameRegistrar()
			reg.answer = tc.answer
			store := newMemNames()
			n := startTestName(t, reg, store, false)

			n.Set(records(t, siteA, wwwA))
			expect(t, "registration", reg.next(t), []string{siteA, wwwA}, 30, 600)
			n.Set(records(t, siteA))
			if !tc.deregister {
				expect(t, "registration after the change", reg.next(t), []string{siteA}, 30, 600)
			} else {
				expect(t, "withdrawal", reg.next(t), []string{wwwA}, 0, 600)
				expect(t, "registration after it", reg.next(t), []string{siteA}, 30, 600)
			}
			n.Stop()
			n.Wait()
			if tc.deregister {
				expect(t, "update on Stop", reg.next(t), nil, 0, 0)
			}
			reg.none(t, 50*time.Millisecond)
			if held, recs := store.state("site.example."); held || recs != nil {
				t.Fatalf("store: held %v, records %q; want neither", held, recs)
			}
		})
	}
}

// The records an earlier run registered, which Store kept, are withdrawn when the first Set
// lacks them; the store follows what is registered and held.
func TestName_WithdrawsWhatTheStoreKept(t *testing.T) {
	store := newMemNames()
	store.Save("site.example.", true, records(t, siteA, wwwA))
	reg := newNameRegistrar()
	n := startTestName(t, reg, store, false)

	n.Set(records(t, siteA))
	expect(t, "withdrawal", reg.next(t), []string{wwwA}, 0, 600)
	expect(t, "registration", reg.next(t), []string{siteA}, 30, 600)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if held, recs := store.state("site.example."); held && slices.Equal(recs, []string{siteA}) {
			break
		}
		if time.Now().After(deadline) {
			held, recs := store.state("site.example.")
			t.Fatalf("store: held %v, records %q; want held, %q", held, recs, []string{siteA})
		}
		time.Sleep(5 * time.Millisecond)
	}

	n.Stop()
	n.Wait()
	expect(t, "update on Stop", reg.next(t), nil, 0, 0)
	if held, recs := store.state("site.example."); held || len(recs) != 0 {
		t.Fatalf("store after the name was freed: held %v, records %q; want neither", held, recs)
	}
}

func TestStartName_RefusesABadClient(t *testing.T) {
	cfg := testConfig(t, newNameRegistrar().Send)
	cfg.Server = ""
	if _, err := StartName(NameConfig{Client: cfg}); err == nil || !strings.Contains(err.Error(), "Server is required") {
		t.Fatalf("StartName() error = %v, want one about the missing server", err)
	}
}

// Release frees the name with its KEY alone (Case C), and records it as freed only once the
// proxy confirms it, or answers that another key holds the name.
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
			store := newMemNames()
			store.Save("site.example.", true, records(t, siteA))
			var got []sent
			var logged []string
			cfg := testConfig(t, func(ctx context.Context, addr string, network baseclient.Network, msg *dns.Msg) (*dns.Msg, error) {
				got = append(got, summarize(t, msg))
				return tt.answer, tt.sendErr
			}, siteA)
			err := Release(NameConfig{
				Client:       cfg,
				Store:        store,
				KeeperConfig: baseclient.KeeperConfig{Logf: func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }},
			})
			if err != nil {
				t.Fatalf("Release: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("%d updates sent, want 1", len(got))
			}
			expect(t, "release", got[0], nil, 0, 0)
			if held, _ := store.state("site.example."); held != tt.wantHeld {
				t.Errorf("name recorded as held: %v, want %v; logged %q", held, tt.wantHeld, logged)
			}
		})
	}
}
