package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// fakeKubo is a kubo node's RPC API: its ID and addresses, the CIDs of paths in its files, and
// its pins, by CID, with their names. A pin of a CID with a gate lasts until the gate closes,
// or the request is cancelled. While down, every command fails.
type fakeKubo struct {
	srv      *httptest.Server
	mu       sync.Mutex
	down     bool
	id       string
	addrs    []string
	mfs      map[string]string
	pins     map[string]string
	gates    map[string]chan struct{}
	unpinned []string
}

func newFakeKubo(t *testing.T, id string, addrs ...string) *fakeKubo {
	k := &fakeKubo{id: id, addrs: addrs, mfs: map[string]string{}, pins: map[string]string{}, gates: map[string]chan struct{}{}}
	k.srv = httptest.NewServer(http.HandlerFunc(k.serve))
	t.Cleanup(k.srv.Close)
	return k
}

func (k *fakeKubo) serve(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	fail := func(msg string) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"Message": msg, "Code": 0, "Type": "error"})
	}
	if k.down {
		fail("down")
		return
	}
	q := r.URL.Query()
	answer := func(v any) { json.NewEncoder(w).Encode(v) }
	switch r.URL.Path {
	case "/api/v0/id":
		answer(map[string]any{"ID": k.id, "Addresses": k.addrs})
	case "/api/v0/files/stat":
		cid, ok := k.mfs[q.Get("arg")]
		if !ok {
			fail("file does not exist")
			return
		}
		answer(map[string]any{"Hash": cid, "Type": "directory"})
	case "/api/v0/pin/add":
		cid := strings.TrimPrefix(q.Get("arg"), "/ipfs/")
		if gate := k.gates[cid]; gate != nil {
			k.mu.Unlock()
			select {
			case <-gate:
			case <-r.Context().Done():
			}
			k.mu.Lock()
			if r.Context().Err() != nil {
				fail("context canceled")
				return
			}
		}
		k.pins[cid] = q.Get("name")
		answer(map[string]any{"Pins": []string{cid}})
	case "/api/v0/pin/ls":
		keys := map[string]any{}
		for cid, name := range k.pins {
			keys[cid] = map[string]string{"Type": "recursive", "Name": name}
		}
		answer(map[string]any{"Keys": keys})
	case "/api/v0/pin/rm":
		cid := strings.TrimPrefix(q.Get("arg"), "/ipfs/")
		delete(k.pins, cid)
		k.unpinned = append(k.unpinned, cid)
		answer(map[string]any{"Pins": []string{cid}})
	default:
		fail("unknown command " + r.URL.Path)
	}
}

func (k *fakeKubo) set(f func(k *fakeKubo)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f(k)
}

func (k *fakeKubo) get(f func(k *fakeKubo) bool) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return f(k)
}

// waitKubo waits until ok accepts k's state.
func waitKubo(t *testing.T, k *fakeKubo, what string, ok func(k *fakeKubo) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !k.get(ok) {
		if time.Now().After(deadline) {
			t.Fatalf("kubo, want %s: pins %v, unpinned %v", what, k.pins, k.unpinned)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// A name that publishes a path in its node's files gives the path's CID as its site, as it
// changes, and the node's addresses that mean something off the link; while the node does not
// answer, it withdraws the addresses and keeps the site, which it also keeps while the path
// cannot be read.
func TestRun_IPFSPublish(t *testing.T) {
	k := newFakeKubo(t, "12D3KooA",
		"/ip4/127.0.0.1/tcp/4001/p2p/12D3KooA",
		"/ip4/192.0.2.5/tcp/4001/p2p/12D3KooA",
		"/ip6/fe80::1/tcp/4001/p2p/12D3KooA",
		"/ip4/192.0.2.9/tcp/4001/p2p/12D3KooRelay/p2p-circuit/p2p/12D3KooA",
		"/ip6/2001:db8::5/udp/4001/quic-v1/p2p/12D3KooA",
		"/ip4/192.0.2.5/tcp/4001/p2p/12D3KooOther",
	)
	k.mfs["/community"] = "QmOne"
	h := newHarness(t, nameTemplate(fmt.Sprintf("names: [{name: a.dev.test., ipfs: {api: %q, publish: {mfs: /community}}}]\n", k.srv.URL)))
	h.start(t, nil)

	link := func(cid string) string { return `_dnslink.a.dev.test. TXT "dnslink=/ipfs/` + cid + `"` }
	addrs := []string{
		`_dnsaddr.a.dev.test. TXT "dnsaddr=/ip4/192.0.2.5/tcp/4001/p2p/12D3KooA"`,
		`_dnsaddr.a.dev.test. TXT "dnsaddr=/ip6/2001:db8::5/udp/4001/quic-v1/p2p/12D3KooA"`,
	}
	if u := h.until(t, "registering a", func(update) bool { return true }); u.lease == 0 || !slices.Equal(sorted(u.records), sorted(append([]string{link("QmOne")}, addrs...))) {
		t.Fatalf("first update %+v, want the site and the node's two addresses to publish", u)
	}
	h.logs.waitFor(t, "a.dev.test.: node 12D3KooA answers at "+k.srv.URL)
	h.logs.waitFor(t, "a.dev.test.: /community in its node's files is QmOne; the name gives it")

	k.set(func(k *fakeKubo) { k.mfs["/community"] = "QmTwo" })
	if u := h.until(t, "registering the new site", func(update) bool { return true }); u.lease == 0 || !slices.Contains(u.records, link("QmTwo")) || !slices.Equal(u.deleted.records, []string{link("QmOne")}) {
		t.Fatalf("registration %+v, want the new site, the old one deleted", u)
	}

	k.set(func(k *fakeKubo) { delete(k.mfs, "/community") })
	h.logs.waitFor(t, "a.dev.test.: /community in its node's files: kubo files/stat: file does not exist; the name keeps giving QmTwo")
	h.none(t, 100*time.Millisecond)

	k.set(func(k *fakeKubo) { k.down = true })
	if u := h.until(t, "deleting the addresses", func(update) bool { return true }); u.lease == 0 || !slices.Equal(u.records, []string{link("QmTwo")}) || !slices.Equal(sorted(u.deleted.records), sorted(addrs)) {
		t.Fatalf("registration while the node is down %+v, want the site, its addresses deleted", u)
	}
	h.logs.waitFor(t, "a.dev.test.: its node does not answer: kubo id: down; its addresses withdrawn until it does")

	k.set(func(k *fakeKubo) { k.down, k.mfs["/community"] = false, "QmTwo" })
	if u := h.until(t, "registering the addresses again", func(u update) bool { return u.lease != 0 && len(u.records) > 1 }); !slices.Equal(sorted(u.records), sorted(append([]string{link("QmTwo")}, addrs...))) {
		t.Fatalf("registration once the node answers %+v, want the site and the addresses", u)
	}
}

// A name that follows another name's site gives it once its node has pinned it, under the
// name's pin name, and then unpins the one before. A newer site replaces a pin still running.
// Started again while the followed name gives nothing, it gives what its node pinned before.
func TestRun_IPFSFollow(t *testing.T) {
	k := newFakeKubo(t, "12D3KooB", "/ip4/192.0.2.6/tcp/4001/p2p/12D3KooB")
	h := newHarness(t, nameTemplate(fmt.Sprintf("names: [{name: site.dev.test., ipfs: {api: %q, follow: a.dev.test}}]\n", k.srv.URL)))
	h.reg.setTXT("_dnslink.a.dev.test.", "dnslink=/ipfs/QmOne")
	gate := make(chan struct{})
	k.gates["QmTwo"] = gate
	defer close(gate)
	h.start(t, nil)

	link := func(cid string) string { return `_dnslink.site.dev.test. TXT "dnslink=/ipfs/` + cid + `"` }
	addr := `_dnsaddr.site.dev.test. TXT "dnsaddr=/ip4/192.0.2.6/tcp/4001/p2p/12D3KooB"`
	pinName := "sig0lease-agent site.dev.test."
	if u := h.until(t, "registering the first site", func(u update) bool { return slices.Contains(u.records, link("QmOne")) }); u.lease == 0 || !slices.Contains(u.records, addr) {
		t.Fatalf("registration %+v, want the site and the node's address", u)
	}
	if !k.get(func(k *fakeKubo) bool { return k.pins["QmOne"] == pinName }) {
		t.Fatalf("pins %v, want QmOne named %q", k.pins, pinName)
	}
	h.logs.waitFor(t, "site.dev.test.: pinning QmOne, the site a.dev.test. gives")
	h.logs.waitFor(t, "site.dev.test.: pinned QmOne; the name gives it")

	h.reg.setTXT("_dnslink.a.dev.test.", "dnslink=/ipfs/QmTwo")
	h.logs.waitFor(t, "site.dev.test.: pinning QmTwo, the site a.dev.test. gives")
	h.none(t, 100*time.Millisecond) // the site stays QmOne while QmTwo is pinned

	h.reg.setTXT("_dnslink.a.dev.test.", "dnslink=/ipfs/QmThree")
	if u := h.until(t, "registering the newest site", func(update) bool { return true }); u.lease == 0 || !slices.Contains(u.records, link("QmThree")) || !slices.Equal(u.deleted.records, []string{link("QmOne")}) {
		t.Fatalf("registration %+v, want QmThree, which replaced QmTwo's pin, and the first site deleted", u)
	}
	waitKubo(t, k, "QmOne unpinned, QmThree pinned, QmTwo never", func(k *fakeKubo) bool {
		return slices.Equal(k.unpinned, []string{"QmOne"}) && len(k.pins) == 1 && k.pins["QmThree"] == pinName
	})
	h.logs.waitFor(t, "site.dev.test.: unpinned QmOne, a site before")

	h.stop(t)
	h.until(t, "deregistering site", func(u update) bool { return u.lease == 0 })
	h.reg.setTXT("_dnslink.a.dev.test.")
	h.start(t, nil)
	if u := h.until(t, "registering site again", func(update) bool { return true }); u.lease == 0 || !slices.Equal(sorted(u.records), sorted([]string{link("QmThree"), addr})) {
		t.Fatalf("first update after the restart %+v, want the site pinned before and the address", u)
	}
	h.logs.waitFor(t, "site.dev.test.: giving QmThree, which its node pinned before, until a.dev.test.'s site is pinned")
	h.logs.waitFor(t, "site.dev.test.: a.dev.test. gives no site (no dnslink= record at _dnslink.a.dev.test.); the name keeps giving QmThree")
}

// A name that follows a site its registrar refuses as not its own, REFUSED with Extended DNS
// Error 20 as a proxy that forwards no queries answers, asks the resolvers (Options.Query) for
// it, and gives it once pinned.
func TestRun_IPFSFollowOutsideTheZone(t *testing.T) {
	k := newFakeKubo(t, "12D3KooB", "/ip4/192.0.2.6/tcp/4001/p2p/12D3KooB")
	h := newHarness(t, nameTemplate(fmt.Sprintf("names: [{name: site.dev.test., ipfs: {api: %q, follow: a.example.org}}]\n", k.srv.URL)))
	h.reg.zone = "dev.test."
	var mu sync.Mutex
	var asked []string
	resolvers := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		mu.Lock()
		asked = append(asked, name)
		mu.Unlock()
		resp := &dns.Msg{MsgHeader: dns.MsgHeader{Response: true, Rcode: dns.RcodeNameError}}
		if name == "_dnslink.a.example.org." && qtype == dns.TypeTXT {
			txt := &dns.TXT{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 30}}
			txt.TXT.Txt = []string{"dnslink=/ipfs/QmOne"}
			resp.Rcode, resp.Answer = dns.RcodeSuccess, []dns.RR{txt}
		}
		return resp, nil
	}
	h.start(t, func(o *Options) { o.Query = resolvers })

	link := `_dnslink.site.dev.test. TXT "dnslink=/ipfs/QmOne"`
	h.until(t, "registering the site the resolvers give", func(u update) bool { return slices.Contains(u.records, link) })
	h.logs.waitFor(t, "site.dev.test.: pinned QmOne; the name gives it")
	mu.Lock()
	defer mu.Unlock()
	if len(asked) == 0 || slices.ContainsFunc(asked, func(n string) bool { return n != "_dnslink.a.example.org." }) {
		t.Fatalf("asked of the resolvers: %v, want _dnslink.a.example.org. alone", asked)
	}
}
