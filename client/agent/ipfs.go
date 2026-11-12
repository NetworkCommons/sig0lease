package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/browse"
	"github.com/NetworkCommons/sig0lease/client/kubo"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
)

// ipfsWatch is the goroutine watching the node of a name's or a host's service's ipfs:
// (watchIPFS).
type ipfsWatch struct {
	cancel   context.CancelFunc
	done     chan struct{}
	reported bool // the agent's loop has its first report; owned by the loop
}

// ipfsState is what a node gives now: its site, a CID, "" none; its addresses to publish
// (dnsaddrs), nil while it does not answer; and with SwarmKey the key its swarm-mac= is made
// with, nil while the file cannot be read.
type ipfsState struct {
	site  string
	addrs []string
	swarm swarmKey
}

// ipfsReport is a watch's report, which deliver hands, on the agent's loop, to what the watch
// is for.
type ipfsReport struct {
	w       *ipfsWatch
	state   ipfsState
	deliver func(*ipfsWatch, ipfsState)
}

// watchIPFS starts watching the node cfg gives (ipfsNode.run), for owner, what its log lines
// start with, each kubo request lasting at most ProbeTimeout; deliver gets each report. A
// community (Follow) is listed by asking r, which answers as soon as the zone has it when it
// is this project's proxy, and r's resolvers what r refuses as a name it does not serve
// (browse.Fallback): a proxy that forwards no queries refuses every name outside its zones.
func (a *agent) watchIPFS(owner string, cfg IPFS, r Registrar, deliver func(*ipfsWatch, ipfsState)) *ipfsWatch {
	ctx, cancel := context.WithCancel(context.Background())
	w := &ipfsWatch{cancel: cancel, done: make(chan struct{})}
	n := &ipfsNode{
		owner:    owner,
		cfg:      cfg,
		kubo:     kubo.New(cfg.API, a.opts.ProbeTimeout),
		logf:     a.opts.Logf,
		interval: a.opts.PollInterval,
		failed:   map[string]string{},
	}
	if cfg.Follow != nil {
		send := a.opts.Send
		if send == nil {
			send = baseclient.LiveTransport(a.opts.ProbeTimeout)
		}
		query := browse.Fallback(
			browse.Querier(send, r.Server, r.Transport),
			browse.Answers(a.resolverQuery(r.Resolvers)))
		n.community = newCommunity(n, *cfg.Follow, query)
	}
	report := func(st ipfsState) bool {
		select {
		case a.ipfsReports <- ipfsReport{w: w, state: st, deliver: deliver}:
			return true
		case <-ctx.Done():
			return false
		}
	}
	go func() {
		defer close(w.done)
		n.run(ctx, report)
	}()
	return w
}

// stop stops the watch and waits for its goroutine, the pins it runs cancelled.
func (w *ipfsWatch) stop() {
	w.cancel()
	<-w.done
}

// watchName starts watching nr's node: each report gives nr the records its node gives it,
// unless nr or its watch is gone since. nr registers nothing until the first report.
func (a *agent) watchName(nr *nameRun) {
	nr.ipfs = a.watchIPFS(nr.label(), *nr.name.IPFS, nr.registrar, func(w *ipfsWatch, st ipfsState) {
		if a.names[nr.label()] != nr || nr.ipfs != w {
			return
		}
		w.reported = true
		nr.ipfsRecords = ipfsRecords(nr.label(), st)
		nr.publish(a)
	})
}

// watchService starts watching the node of s, a host's service registering through r: each
// report gives s its node's folder and its swarm key, which its TXT record gives the folder
// and its swarm-mac= with, unless s or its watch is gone since. s is not registered until both
// are read (serviceRun.registered).
func (a *agent) watchService(s *serviceRun, r Registrar) {
	s.ipfs = a.watchIPFS(s.String(), *s.svc.IPFS, r, func(w *ipfsWatch, st ipfsState) {
		if s.gone || s.ipfs != w {
			return
		}
		w.reported = true
		if st.site != s.site || !bytes.Equal(st.swarm, s.swarm) {
			s.site, s.swarm = st.site, st.swarm
			s.on.publish(a)
		}
	})
}

// ipfsRecords returns the records a node's state gives the name owner: its site's, then its
// addresses'.
func ipfsRecords(owner string, st ipfsState) []dns.RR {
	var rrs []dns.RR
	if st.site != "" {
		rrs = append(rrs, txtRecord(dnslinkOwner(owner), "dnslink=/ipfs/"+st.site))
	}
	for _, a := range st.addrs {
		rrs = append(rrs, txtRecord(dnsaddrOwner(owner), "dnsaddr="+a))
	}
	return rrs
}

// ipfsNode is what a watch knows of the node, owned by the watch's goroutine.
type ipfsNode struct {
	owner     string // what its log lines start with
	cfg       IPFS
	kubo      *kubo.Client
	community *community // with Follow
	logf      func(format string, args ...any)
	interval  time.Duration

	id     string            // the node's peer ID, once it answered
	addrs  []string          // its addresses to publish (dnsaddrs); nil while it does not answer
	site   string            // the CID it gives as its site; "" none
	swarm  swarmKey          // with SwarmKey, read from it; nil while it cannot be read
	failed map[string]string // the last failure logged, by check, so that it is logged once
}

// run checks the node now and every interval (check) until ctx ends or report fails, reporting
// its state after the first check and whenever it changes. While the node does not answer, it
// withdraws its addresses and keeps its site: other nodes may hold the site.
//
// With Publish, the site is the path's CID in the node's files, which changes with anything
// in it. With Follow, it is the community's folder (community.check), which changes as each
// member's folder is pinned, and as members are removed. A pin that ends changes the folder at
// once (community.pinDone), with no check: the members are listed every interval, however many
// pins end, and a pin that fails is tried again at the next check, not at once.
func (n *ipfsNode) run(ctx context.Context, report func(ipfsState) bool) {
	var pins <-chan pinResult
	if n.community != nil {
		defer n.community.stop()
		pins = n.community.pins
	}
	tick := time.NewTicker(n.interval)
	defer tick.Stop()
	n.check(ctx)
	var last ipfsState
	for first := true; ; first = false {
		if st := (ipfsState{site: n.site, addrs: n.addrs, swarm: n.swarm}); first || !reflect.DeepEqual(st, last) {
			if !report(st) {
				return
			}
			last = st
		}
		select {
		case <-ctx.Done():
			return
		case r := <-pins:
			n.community.pinDone(ctx, r)
		case <-tick.C:
			n.check(ctx)
		}
	}
}

// check reads the swarm key file, with SwarmKey, and asks the node for its addresses and, if
// it answers, for its site; a community's members are listed only with the swarm key read.
func (n *ipfsNode) check(ctx context.Context) {
	if !n.readSwarm() && n.community != nil {
		return
	}
	if !n.checkNode(ctx) {
		return
	}
	switch {
	case n.cfg.Publish != "":
		n.checkPublished(ctx)
	case n.community != nil:
		n.community.check(ctx)
	}
}

// readSwarm reads the swarm key file, with SwarmKey, at each check, so that a new key or a file
// fixed counts without a restart. It reports whether the key is read, or none is needed. While
// the file cannot be read, a member is not registered (its swarm-mac= cannot be made) and a
// community does not list its members.
func (n *ipfsNode) readSwarm() bool {
	if n.cfg.SwarmKey == "" {
		return true
	}
	k, err := readSwarmKey(n.cfg.SwarmKey)
	if err != nil {
		what := "not registered until it can be read"
		if n.community != nil {
			what = "the members are not listed until it can be read; keeping the folder as it is"
		}
		n.fail("swarm key", fmt.Errorf("%w; %s", err, what))
		n.swarm = nil
		return false
	}
	if n.ok("swarm key") {
		n.logf("%s: swarm key %s read", n.owner, n.cfg.SwarmKey)
	}
	n.swarm = k
	return true
}

// checkNode asks the node for its addresses, reporting whether it answered.
func (n *ipfsNode) checkNode(ctx context.Context) bool {
	id, addrs, err := n.kubo.ID(ctx)
	if err != nil {
		n.fail("node", fmt.Errorf("its node does not answer: %w; its addresses withdrawn until it does", err))
		n.addrs = nil
		return false
	}
	if n.ok("node") || id != n.id {
		n.logf("%s: node %s answers at %s", n.owner, id, n.cfg.API)
	}
	n.id, n.addrs = id, dnsaddrs(id, addrs)
	return true
}

// dnsaddrs returns the addresses of the node id to publish, sorted: those over IPv4 or IPv6
// at an address that means something off the link (clientsrp.Publishable), each a multiaddr
// ending in /p2p/<id>, as /dnsaddr/ readers want them; relayed ones left out.
func dnsaddrs(id string, addrs []string) []string {
	var out []string
	for _, ma := range addrs {
		parts := strings.Split(ma, "/") // "", "ip4", "192.0.2.1", "tcp", "4001", ...
		if len(parts) < 3 || (parts[1] != "ip4" && parts[1] != "ip6") || !strings.HasSuffix(ma, "/p2p/"+id) || strings.Contains(ma, "/p2p-circuit/") {
			continue
		}
		if ip, err := netip.ParseAddr(parts[2]); err == nil && clientsrp.Publishable(ip) {
			out = append(out, ma)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// checkPublished reads the CID of the path the node publishes.
func (n *ipfsNode) checkPublished(ctx context.Context) {
	cid, err := n.kubo.MFSCID(ctx, n.cfg.Publish)
	if err != nil {
		n.fail("publish", fmt.Errorf("%s in its node's files: %w; %s", n.cfg.Publish, err, n.keeping()))
		return
	}
	n.ok("publish")
	n.give(cid, fmt.Sprintf("%s in its node's files", n.cfg.Publish))
}

// give makes cid, what is, the site, logging it if it is new.
func (n *ipfsNode) give(cid, what string) {
	if cid != n.site {
		n.logf("%s: %s is %s; giving it", n.owner, what, cid)
		n.site = cid
	}
}

// keeping says what is given while the site cannot be read.
func (n *ipfsNode) keeping() string {
	if n.site == "" {
		return "giving no site until then"
	}
	return "still giving " + n.site
}

// txtRecord returns the TXT record at owner whose strings, joined, are value: a string holds
// at most 255 octets, and DNSLink and /dnsaddr/ readers join a record's strings.
func txtRecord(owner, value string) *dns.TXT {
	rr := &dns.TXT{Hdr: dns.Header{Name: owner, Class: dns.ClassINET}}
	for len(value) > 255 {
		rr.TXT.Txt = append(rr.TXT.Txt, dnsmsg.EscapeTXT(value[:255]))
		value = value[255:]
	}
	rr.TXT.Txt = append(rr.TXT.Txt, dnsmsg.EscapeTXT(value))
	return rr
}

// fail logs err for the check kind, unless it is the failure last logged for it. A request cut
// short because the watch stops is no failure, and is not logged: every other request ends by
// its own time limit, which is another error.
func (n *ipfsNode) fail(kind string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	if msg := err.Error(); msg != n.failed[kind] {
		n.failed[kind] = msg
		n.logf("%s: %s", n.owner, msg)
	}
}

// ok forgets the failure of the check kind, reporting whether there was one.
func (n *ipfsNode) ok(kind string) bool {
	_, had := n.failed[kind]
	delete(n.failed, kind)
	return had
}
