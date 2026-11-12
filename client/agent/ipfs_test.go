package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
)

// fakeKubo is a kubo node's RPC API: its ID and addresses, the CIDs of paths in its files, its
// folders there with their entries, and its pins, by CID, with their names. A folder's CID is
// made of its entries'. A pin of a CID with a gate lasts until the gate closes, or the request
// is cancelled. While down, every command fails; a failing one fails, a hanging one lasts until
// its request is cancelled, and each is counted.
type fakeKubo struct {
	srv      *httptest.Server
	mu       sync.Mutex
	down     bool
	failing  map[string]bool // commands, by path
	hanging  map[string]bool // commands, by path
	asked    map[string]int  // the requests of each command, by path
	id       string
	addrs    []string
	mfs      map[string]string
	dirs     map[string]map[string]string // folder -> entry -> CID
	pins     map[string]string
	gates    map[string]chan struct{}
	unpinned []string
}

func newFakeKubo(t *testing.T, id string, addrs ...string) *fakeKubo {
	k := &fakeKubo{id: id, addrs: addrs, mfs: map[string]string{}, dirs: map[string]map[string]string{}, pins: map[string]string{}, gates: map[string]chan struct{}{}, failing: map[string]bool{}, hanging: map[string]bool{}, asked: map[string]int{}}
	k.srv = httptest.NewServer(http.HandlerFunc(k.serve))
	t.Cleanup(k.srv.Close)
	return k
}

// dirCID is the CID of a folder with entries.
func dirCID(entries map[string]string) string {
	var s []string
	for name, cid := range entries {
		s = append(s, name+"="+cid)
	}
	slices.Sort(s)
	return "dir(" + strings.Join(s, ",") + ")"
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
	k.asked[r.URL.Path]++
	if k.failing[r.URL.Path] {
		fail("failing")
		return
	}
	if k.hanging[r.URL.Path] {
		k.mu.Unlock()
		<-r.Context().Done()
		k.mu.Lock()
		return
	}
	q := r.URL.Query()
	answer := func(v any) { json.NewEncoder(w).Encode(v) }
	switch r.URL.Path {
	case "/api/v0/id":
		answer(map[string]any{"ID": k.id, "Addresses": k.addrs})
	case "/api/v0/files/stat":
		if entries, ok := k.dirs[q.Get("arg")]; ok {
			answer(map[string]any{"Hash": dirCID(entries), "Type": "directory"})
			return
		}
		cid, ok := k.mfs[q.Get("arg")]
		if !ok {
			fail("file does not exist")
			return
		}
		answer(map[string]any{"Hash": cid, "Type": "directory"})
	case "/api/v0/files/mkdir":
		if k.dirs[q.Get("arg")] == nil {
			k.dirs[q.Get("arg")] = map[string]string{}
		}
	case "/api/v0/files/ls":
		entries, ok := k.dirs[q.Get("arg")]
		if !ok {
			fail("file does not exist")
			return
		}
		var out []map[string]any
		for name, cid := range entries {
			out = append(out, map[string]any{"Name": name, "Type": 1, "Size": 0, "Hash": cid})
		}
		answer(map[string]any{"Entries": out})
	case "/api/v0/files/cp":
		args := q["arg"]
		dir, name := path.Split(args[1])
		entries, ok := k.dirs[strings.TrimSuffix(dir, "/")]
		switch {
		case !ok:
			fail("file does not exist")
		case entries[name] != "":
			fail("directory already has entry by that name")
		default:
			entries[name] = strings.TrimPrefix(args[0], "/ipfs/")
		}
	case "/api/v0/files/rm":
		dir, name := path.Split(q.Get("arg"))
		entries := k.dirs[strings.TrimSuffix(dir, "/")]
		if entries[name] == "" {
			fail("file does not exist")
			return
		}
		delete(entries, name)
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
			t.Fatalf("kubo, want %s: dirs %v, pins %v, unpinned %v", what, k.dirs, k.pins, k.unpinned)
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
	h.logs.waitFor(t, "a.dev.test.: /community in its node's files is QmOne; giving it")

	k.set(func(k *fakeKubo) { k.mfs["/community"] = "QmTwo" })
	if u := h.until(t, "registering the new site", func(update) bool { return true }); u.lease == 0 || !slices.Contains(u.records, link("QmTwo")) || !slices.Equal(u.deleted.records, []string{link("QmOne")}) {
		t.Fatalf("registration %+v, want the new site, the old one deleted", u)
	}

	k.set(func(k *fakeKubo) { delete(k.mfs, "/community") })
	h.logs.waitFor(t, "a.dev.test.: /community in its node's files: kubo files/stat: file does not exist; still giving QmTwo")
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

// testSwarmPSK is a swarm key file, as kubo reads it.
const testSwarmPSK = "/key/swarm/psk/1.0.0/\n/base16/\n00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"

// testSwarm returns where a swarm key file is to be, in a directory of its own, and the key
// testSwarmPSK gives; writeSwarm writes it there.
func testSwarm(t *testing.T) (string, swarmKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "swarm.key")
	writeSwarm(t, path)
	k, err := readSwarmKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, k
}

func writeSwarm(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(testSwarmPSK), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A host's service with ipfs: is registered once its node's folder and its swarm key file are
// read, its TXT record giving the folder as dnslink=, and the swarm-mac= of the host's KEY and
// the folder; it is registered again as the folder changes, and withdrawn while the swarm key
// cannot be read.
func TestRun_IPFSMember(t *testing.T) {
	k := newFakeKubo(t, "12D3KooA", "/ip4/192.0.2.5/tcp/4001/p2p/12D3KooA")
	swarmPath, swarm := testSwarm(t)
	if err := os.Remove(swarmPath); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, srpTemplate(fmt.Sprintf(`hosts:
  - name: alice
    addresses: [192.0.2.5]
    services:
      - {type: ipfs-member, instance: alice, subtypes: [site], probe: none, ipfs: {api: %q, swarm_key: %q, publish: {mfs: /community}}}
`, k.srv.URL, swarmPath)))
	h.start(t, nil)

	instance := "alice._ipfs-member._tcp.srp.test."
	gives := func(u update, cid string) bool {
		return u.key != nil && slices.Equal(u.instanceTXTs, []string{instance + ` TXT "dnslink=/ipfs/` + cid + `" "swarm-mac=` + swarm.mac(u.key, cid) + `"`})
	}
	if u := h.until(t, "registering alice", func(u update) bool { return u.host == "alice.srp.test." }); len(u.instances) != 0 {
		t.Fatalf("first update %+v, want the host alone: the folder is not read yet", u)
	}
	h.logs.waitFor(t, `alice: "alice" _ipfs-member._tcp: /community in its node's files: kubo files/stat: file does not exist; giving no site until then`)
	h.logs.waitFor(t, `alice: "alice" _ipfs-member._tcp: swarm key: open `+swarmPath+`: no such file or directory; not registered until it can be read`)

	k.set(func(k *fakeKubo) { k.mfs["/community"] = "QmOne" })
	h.logs.waitFor(t, `alice: "alice" _ipfs-member._tcp: /community in its node's files is QmOne; giving it`)
	h.none(t, 200*time.Millisecond) // the swarm key is not read yet

	writeSwarm(t, swarmPath)
	if u := h.until(t, "registering the instance", func(u update) bool { return len(u.instances) > 0 }); !slices.Equal(u.instances, []string{instance}) || !gives(u, "QmOne") {
		t.Fatalf("update %+v, want the instance, its TXT record giving the folder and its swarm-mac=", u)
	}
	h.logs.waitFor(t, `alice: "alice" _ipfs-member._tcp: swarm key `+swarmPath+` read`)

	k.set(func(k *fakeKubo) { k.mfs["/community"] = "QmTwo" })
	h.until(t, "registering the new folder", func(u update) bool { return gives(u, "QmTwo") })

	if err := os.Remove(swarmPath); err != nil {
		t.Fatal(err)
	}
	h.until(t, "withdrawing the instance", func(u update) bool { return slices.Equal(u.withdrawn, []string{instance}) })
}

// zoneCommunity is a community's listing in a test registrar: the subtype site's PTR records in
// srp.test., and each member's KEY and TXT records, its swarm-mac= made with swarm, the key of
// the swarm key file at swarmPath.
type zoneCommunity struct {
	reg       *registrar
	swarm     swarmKey
	swarmPath string
}

// followTemplate is the template whose name site.dev.test. follows the community site in
// srp.test., at the node api, with the swarm key file swarmPath and revoke_after.
func followTemplate(api, swarmPath, revokeAfter string) string {
	return nameTemplate(fmt.Sprintf("names: [{name: site.dev.test., ipfs: {api: %q, swarm_key: %q, follow: {type: ipfs-member, domain: srp.test, revoke_after: %s}}}]\n", api, swarmPath, revokeAfter))
}

const communityMembers = "site._sub._ipfs-member._tcp.srp.test."

func memberInstance(label string) string { return label + "._ipfs-member._tcp.srp.test." }

// list makes the PTR records list labels, given as written in a zone file.
func (c zoneCommunity) list(t *testing.T, labels ...string) {
	t.Helper()
	var rrs []dns.RR
	for _, l := range labels {
		rr, err := dns.New(communityMembers + " 30 IN PTR " + memberInstance(l))
		if err != nil {
			t.Fatal(err)
		}
		rrs = append(rrs, rr)
	}
	c.reg.set(communityMembers, dns.TypePTR, rrs...)
}

// member gives label's instance the KEY pub, unless "", and a TXT record giving cid, with the
// swarm-mac= the swarm key makes of the KEY and cid.
func (c zoneCommunity) member(label, pub, cid string) {
	c.txt(label, pub, "txtvers=1", "dnslink=/ipfs/"+cid, "swarm-mac="+c.swarm.mac(memberKey(label, pub), cid))
}

// txt gives label's instance the KEY pub, unless "", and a TXT record of values.
func (c zoneCommunity) txt(label, pub string, values ...string) {
	name := memberInstance(label)
	var keys []dns.RR
	if pub != "" {
		keys = append(keys, memberKey(label, pub))
	}
	c.reg.set(name, dns.TypeKEY, keys...)
	c.reg.set(name, dns.TypeTXT, txtRR(name, values...))
}

// memberKey returns the KEY pub at label's instance.
func memberKey(label, pub string) *dns.KEY {
	k := &dns.KEY{}
	k.Hdr = dns.Header{Name: memberInstance(label), Class: dns.ClassINET, TTL: 30}
	k.Protocol, k.Algorithm, k.PublicKey = 3, dns.ECDSAP256SHA256, pub
	return k
}

// A name that follows a community lists its members: the instances its subtype's PTR records
// list, each with its KEY and the folder its TXT record gives, with the swarm-mac= the swarm
// key makes of both. Its node pins each member's folder, under the name's pin name, and the
// name's site is a folder with an entry per member giving its folder once pinned; a member's
// newer folder replaces its entry, the one before unpinned. An instance whose label is not a
// host label, with no KEY, with no swarm-mac=, or with one made for another KEY (a member's
// copied) is no member. A member not listed for revoke_after loses its entry; one listed
// again before keeps it; one whose label another key holds is another member. Started again,
// the name gives the folder as it was, and an entry whose member is not listed goes after
// revoke_after.
func TestRun_IPFSCommunity(t *testing.T) {
	k := newFakeKubo(t, "12D3KooB", "/ip4/192.0.2.6/tcp/4001/p2p/12D3KooB")
	swarmPath, swarm := testSwarm(t)
	h := newHarness(t, followTemplate(k.srv.URL, swarmPath, "300ms"))
	c := zoneCommunity{h.reg, swarm, swarmPath}
	c.list(t, "alice", "bob", `mallory\032x`, "eve", "trudy", "oscar")
	c.member("alice", "a2V5IG9mIGFsaWNl", "QmA1")
	c.member("bob", "a2V5IG9mIGJvYg==", "QmB1")
	c.member(`mallory\032x`, "a2V5IG9mIG1hbGxvcnk=", "QmM1")
	c.member("eve", "", "QmE1")
	c.txt("trudy", "a2V5IG9mIHRydWR5", "dnslink=/ipfs/QmA1", "swarm-mac="+swarm.mac(memberKey("alice", "a2V5IG9mIGFsaWNl"), "QmA1"))
	c.txt("oscar", "a2V5IG9mIG9zY2Fy", "dnslink=/ipfs/QmO1")
	gate := make(chan struct{})
	k.gates["QmB1"] = gate
	h.start(t, nil)

	link := func(entries ...string) string {
		return `_dnslink.site.dev.test. TXT "dnslink=/ipfs/dir(` + strings.Join(entries, ",") + `)"`
	}
	site := func(what string, entries ...string) {
		t.Helper()
		h.until(t, what, func(u update) bool { return slices.Contains(u.records, link(entries...)) })
	}
	pinName := "sig0lease-agent site.dev.test."
	site("alice's folder, bob's still pinning", "alice=QmA1")
	h.logs.waitFor(t, "site.dev.test.: alice is a member")
	h.logs.waitFor(t, "site.dev.test.: pinning QmB1, bob's folder")
	h.logs.waitFor(t, `site.dev.test.: mallory\032x._ipfs-member._tcp.srp.test.: not a member: its label is not letters, digits and hyphens`)
	h.logs.waitFor(t, "site.dev.test.: eve._ipfs-member._tcp.srp.test.: not a member: 0 KEY records at its name, not one")
	h.logs.waitFor(t, "site.dev.test.: trudy._ipfs-member._tcp.srp.test.: not a member: its swarm-mac= is not the one the community's swarm key makes of its KEY and its folder QmA1")
	h.logs.waitFor(t, "site.dev.test.: oscar._ipfs-member._tcp.srp.test.: not a member: its TXT record gives no swarm-mac=, which the community's swarm key makes")

	close(gate)
	site("bob's folder too", "alice=QmA1", "bob=QmB1")
	h.logs.waitFor(t, "site.dev.test.: pinned QmB1, bob's folder")
	h.logs.waitFor(t, "site.dev.test.: bob's entry gives QmB1")
	if !k.get(func(k *fakeKubo) bool { return k.pins["QmA1"] == pinName && k.pins["QmB1"] == pinName }) {
		t.Fatalf("pins %v, want QmA1 and QmB1 named %q", k.pins, pinName)
	}

	c.member("alice", "a2V5IG9mIGFsaWNl", "QmA2")
	site("alice's new folder", "alice=QmA2", "bob=QmB1")
	h.logs.waitFor(t, "site.dev.test.: unpinned QmA1, which no entry gives")

	c.list(t, "alice")
	h.logs.waitFor(t, "site.dev.test.: bob is not listed; its entry goes in 300ms unless it is again")
	site("bob's entry removed", "alice=QmA2")
	h.logs.waitFor(t, "site.dev.test.: bob is not listed for 300ms: no longer a member")
	waitKubo(t, k, "QmB1 unpinned", func(k *fakeKubo) bool { return k.pins["QmB1"] == "" && len(k.pins) == 1 })

	c.list(t)
	h.logs.waitFor(t, "site.dev.test.: alice is not listed")
	c.list(t, "alice")
	h.logs.waitFor(t, "site.dev.test.: alice is listed again")
	h.none(t, 400*time.Millisecond) // alice's entry stays

	c.member("alice", "YW5vdGhlciBrZXk=", "QmA3")
	site("the new alice's folder", "alice=QmA3")
	h.logs.waitFor(t, "site.dev.test.: alice is another key's now: the member before goes, and the new one is a member")
	waitKubo(t, k, "QmA2 unpinned", func(k *fakeKubo) bool { return k.pins["QmA2"] == "" && k.pins["QmA3"] == pinName })

	h.stop(t)
	c.list(t)
	h.start(t, nil)
	site("the folder as it was", "alice=QmA3")
	h.logs.waitFor(t, "site.dev.test.: found alice's entry, giving QmA3; it goes in 300ms unless alice is listed")
	site("alice's entry removed", "")
	waitKubo(t, k, "QmA3 unpinned", func(k *fakeKubo) bool { return len(k.pins) == 0 })
}

// communityHarness is a harness whose name site.dev.test. follows the community site in
// srp.test., with revoke_after 300ms, at the node k.
func communityHarness(t *testing.T) (*harness, *fakeKubo, zoneCommunity) {
	k := newFakeKubo(t, "12D3KooB", "/ip4/192.0.2.6/tcp/4001/p2p/12D3KooB")
	swarmPath, swarm := testSwarm(t)
	h := newHarness(t, followTemplate(k.srv.URL, swarmPath, "300ms"))
	return h, k, zoneCommunity{h.reg, swarm, swarmPath}
}

const (
	communityFolder = "/sig0lease-agent/site.dev.test"
	communityPins   = "sig0lease-agent site.dev.test."
	aliceKey        = "a2V5IG9mIGFsaWNl"
)

// siteWith waits for site.dev.test. to register the folder with entries as its site.
func siteWith(t *testing.T, h *harness, what string, entries ...string) {
	t.Helper()
	link := `_dnslink.site.dev.test. TXT "dnslink=/ipfs/dir(` + strings.Join(entries, ",") + `)"`
	h.until(t, what, func(u update) bool { return slices.Contains(u.records, link) })
}

// A community's folder is read at each check. Its CID, which could not be read when it
// changed, is given once it can, with no other change to wait for. An entry removed there by
// hand is put back, as is the folder; one made there by hand goes after revoke_after, as any
// whose member is not listed.
func TestRun_IPFSCommunityFolder(t *testing.T) {
	h, k, c := communityHarness(t)
	c.list(t, "alice")
	c.member("alice", aliceKey, "QmA1")
	h.start(t, nil)
	siteWith(t, h, "alice's folder", "alice=QmA1")

	k.set(func(k *fakeKubo) { k.failing["/api/v0/files/stat"] = true })
	c.member("alice", aliceKey, "QmA2")
	h.logs.waitFor(t, "site.dev.test.: alice's entry gives QmA2")
	h.logs.waitFor(t, "site.dev.test.: "+communityFolder+" in its node's files: kubo files/stat: failing; still giving dir(alice=QmA1)")
	k.set(func(k *fakeKubo) { k.failing["/api/v0/files/stat"] = false })
	siteWith(t, h, "alice's new folder, once the folder's CID is read", "alice=QmA2")

	k.set(func(k *fakeKubo) { delete(k.dirs[communityFolder], "alice") })
	h.logs.waitN(t, "site.dev.test.: alice's entry gives QmA2", 2)
	k.set(func(k *fakeKubo) { delete(k.dirs, communityFolder) })
	h.logs.waitN(t, "site.dev.test.: alice's entry gives QmA2", 3)
	waitKubo(t, k, "alice's entry back", func(k *fakeKubo) bool { return k.dirs[communityFolder]["alice"] == "QmA2" })

	k.set(func(k *fakeKubo) { k.dirs[communityFolder]["zed"] = "QmZ" })
	h.logs.waitFor(t, "site.dev.test.: found zed's entry, giving QmZ; it goes in 300ms unless zed is listed")
	h.logs.waitFor(t, "site.dev.test.: zed is not listed for 300ms: no longer a member")
	waitKubo(t, k, "zed's entry removed, alice's kept", func(k *fakeKubo) bool {
		return len(k.dirs[communityFolder]) == 1 && k.dirs[communityFolder]["alice"] == "QmA2"
	})
	if !k.get(func(k *fakeKubo) bool { return k.pins["QmA2"] == communityPins }) {
		t.Fatalf("pins %v, want QmA2 named %q", k.pins, communityPins)
	}
}

// A member's folder the node has pinned already, not under the name's pin name, is its owner's
// pin: the member's entry gives the folder, and the pin keeps its name, and stays when the
// member gives another folder.
func TestRun_IPFSCommunityPinnedAlready(t *testing.T) {
	h, k, c := communityHarness(t)
	k.pins["QmA1"] = "mine"
	c.list(t, "alice")
	c.member("alice", aliceKey, "QmA1")
	h.start(t, nil)
	siteWith(t, h, "alice's folder", "alice=QmA1")
	h.logs.waitFor(t, "site.dev.test.: its node has QmA1, alice's folder, pinned already, not by the agent: that pin is left as it is")

	// The folder's CID is read, and the pins no entry gives unpinned, before the site is given.
	c.member("alice", aliceKey, "QmA2")
	siteWith(t, h, "alice's new folder", "alice=QmA2")
	if !k.get(func(k *fakeKubo) bool {
		return k.pins["QmA1"] == "mine" && k.pins["QmA2"] == communityPins && len(k.unpinned) == 0
	}) {
		t.Fatalf("pins %v, unpinned %v; want QmA1 still named mine, QmA2 named %q", k.pins, k.unpinned, communityPins)
	}
}

// A pin that fails is tried again at the next check, not at once, and logged once.
func TestRun_IPFSCommunityPinFails(t *testing.T) {
	h, k, c := communityHarness(t)
	k.failing["/api/v0/pin/add"] = true
	c.list(t, "alice")
	c.member("alice", aliceKey, "QmA1")
	const interval = 50 * time.Millisecond
	h.start(t, func(o *Options) { o.PollInterval = interval })
	const failure = "site.dev.test.: pinning QmA1, alice's folder: kubo pin/add: failing; trying again at the next check"
	h.logs.waitFor(t, failure)

	pins := func() (n int) {
		k.get(func(k *fakeKubo) bool { n = k.asked["/api/v0/pin/add"]; return true })
		return n
	}
	start, before := time.Now(), pins()
	time.Sleep(6 * interval)
	if tried, most := pins()-before, int(time.Since(start)/interval)+1; tried == 0 || tried > most {
		t.Fatalf("%d pins tried in %s, want one each %s", tried, time.Since(start), interval)
	}
	if n := h.logs.count(failure); n != 1 {
		t.Fatalf("the failure logged %d times, want once", n)
	}

	k.set(func(k *fakeKubo) { k.failing["/api/v0/pin/add"] = false })
	siteWith(t, h, "alice's folder, once it is pinned", "alice=QmA1")
}

// An instance that is no member is logged once while it is listed, and again when it is listed
// again after it was not. A member whose entry cannot be removed stays one, which is logged
// once, and is no longer one once it is removed.
func TestRun_IPFSCommunityLogsOnce(t *testing.T) {
	h, k, c := communityHarness(t)
	c.list(t, "alice", "eve")
	c.member("alice", aliceKey, "QmA1")
	c.member("eve", "", "QmE1")
	h.start(t, nil)
	siteWith(t, h, "alice's folder", "alice=QmA1")
	const eve = "site.dev.test.: eve._ipfs-member._tcp.srp.test.: not a member: 0 KEY records at its name, not one"
	h.logs.waitFor(t, eve)

	c.list(t)
	h.logs.waitFor(t, "site.dev.test.: alice is not listed")
	if n := h.logs.count(eve); n != 1 {
		t.Fatalf("eve logged %d times while listed, want once", n)
	}
	c.list(t, "alice", "eve")
	h.logs.waitFor(t, "site.dev.test.: alice is listed again")
	h.logs.waitN(t, eve, 2)

	k.set(func(k *fakeKubo) { k.failing["/api/v0/files/rm"] = true })
	c.list(t, "eve")
	const failure = "site.dev.test.: removing alice's entry: kubo files/rm: failing; trying again at the next check"
	h.logs.waitFor(t, failure)
	time.Sleep(100 * time.Millisecond) // several checks
	const gone = "site.dev.test.: alice is not listed for 300ms"
	if f, g := h.logs.count(failure), h.logs.count(gone); f != 1 || g != 0 {
		t.Fatalf("the failure logged %d times, want once; alice gone logged %d times, want none while her entry is there", f, g)
	}
	k.set(func(k *fakeKubo) { k.failing["/api/v0/files/rm"] = false })
	siteWith(t, h, "alice's entry removed", "")
	if n := h.logs.count(gone + ": no longer a member"); n != 1 {
		t.Fatalf("alice gone logged %d times, want once", n)
	}
}

// A request to the node cut short because the agent stops is no failure of the node's: nothing
// is logged of it.
func TestRun_IPFSCommunityStopsMidRequest(t *testing.T) {
	h, k, c := communityHarness(t)
	c.list(t, "alice")
	c.member("alice", aliceKey, "QmA1")
	h.start(t, nil)
	siteWith(t, h, "alice's folder", "alice=QmA1")

	var before int
	k.set(func(k *fakeKubo) { k.hanging["/api/v0/files/ls"], before = true, k.asked["/api/v0/files/ls"] })
	waitKubo(t, k, "the folder being read", func(k *fakeKubo) bool { return k.asked["/api/v0/files/ls"] > before })
	h.stop(t)
	if n := h.logs.count("context canceled"); n != 0 {
		h.logs.mu.Lock()
		defer h.logs.mu.Unlock()
		t.Fatalf("%d log lines of a request cancelled by the stop, want none:\n%s", n, strings.Join(h.logs.lines, "\n"))
	}
}

// The result of a pin stopped since is not the member's, though the pin it runs now asks for
// the same folder: a member whose record gave one folder, another, and the first again.
func TestCommunity_PinDoneOfAStoppedPin(t *testing.T) {
	l := &logs{}
	c := newCommunity(&ipfsNode{owner: "site.dev.test.", logf: l.logf, failed: map[string]string{}}, Follow{}, nil)
	stopped := false
	running := &pinning{cid: "QmA1", cancel: func() { stopped = true }}
	c.members["alice"] = &member{label: "alice", pin: running}
	c.pinDone(context.Background(), pinResult{key: "alice", pin: &pinning{cid: "QmA1"}, err: context.Canceled})
	if m := c.members["alice"]; m.pin != running || stopped || len(l.lines) != 0 {
		t.Fatalf("after a stopped pin's result: pin %p, want %p; stopped %t; logged %q", m.pin, running, stopped, l.lines)
	}
}

// A community's swarm key file is read at each check: while it cannot be read, its members are
// not listed, so that none goes for not being listed, and the folder is kept as it is; once it
// can be read again, they are listed again.
func TestRun_IPFSCommunitySwarmKey(t *testing.T) {
	h, _, c := communityHarness(t)
	c.list(t, "alice")
	c.member("alice", aliceKey, "QmA1")
	h.start(t, nil)
	siteWith(t, h, "alice's folder", "alice=QmA1")

	if err := os.Remove(c.swarmPath); err != nil {
		t.Fatal(err)
	}
	h.logs.waitFor(t, "site.dev.test.: swarm key: open "+c.swarmPath+": no such file or directory; the members are not listed until it can be read; keeping the folder as it is")
	c.list(t, "bob")
	c.member("bob", "a2V5IG9mIGJvYg==", "QmB1")
	h.none(t, 700*time.Millisecond) // more than revoke_after: alice's entry stays, bob gets none

	writeSwarm(t, c.swarmPath)
	siteWith(t, h, "bob's folder, alice's entry gone after revoke_after", "bob=QmB1")
	h.logs.waitFor(t, "site.dev.test.: swarm key "+c.swarmPath+" read")
	h.logs.waitFor(t, "site.dev.test.: alice is not listed; its entry goes in 300ms unless it is again")
	if n := h.logs.count("swarm key: open"); n != 1 {
		t.Fatalf("%d log lines of the swarm key not read, want 1", n)
	}
}

// A community in a domain its registrar refuses as not its own, REFUSED with Extended DNS
// Error 20 as a proxy that forwards no queries answers, is listed by asking the resolvers
// (Options.Query).
func TestRun_IPFSCommunityOutsideTheZone(t *testing.T) {
	k := newFakeKubo(t, "12D3KooB", "/ip4/192.0.2.6/tcp/4001/p2p/12D3KooB")
	swarmPath, swarm := testSwarm(t)
	h := newHarness(t, followTemplate(k.srv.URL, swarmPath, "10m"))
	h.reg.zone = "dev.test."
	resolver := &registrar{}
	c := zoneCommunity{resolver, swarm, swarmPath}
	c.list(t, "alice")
	c.member("alice", "a2V5IG9mIGFsaWNl", "QmA1")
	var mu sync.Mutex
	var asked []string
	h.start(t, func(o *Options) {
		o.Query = func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
			mu.Lock()
			asked = append(asked, name)
			mu.Unlock()
			return resolver.Send(ctx, "", baseclient.NetworkUDP, dns.NewMsg(name, qtype))
		}
	})

	h.until(t, "registering the folder the resolvers list", func(u update) bool {
		return slices.Contains(u.records, `_dnslink.site.dev.test. TXT "dnslink=/ipfs/dir(alice=QmA1)"`)
	})
	mu.Lock()
	defer mu.Unlock()
	if len(asked) == 0 || slices.ContainsFunc(asked, func(n string) bool { return !strings.HasSuffix(n, "._ipfs-member._tcp.srp.test.") }) {
		t.Fatalf("asked of the resolvers: %v, want the community's names alone", asked)
	}
}
