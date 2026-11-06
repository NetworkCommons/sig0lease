package agent

import (
	"context"
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

// ipfsWatch is the goroutine watching the node of a name with ipfs: (watchIPFS).
type ipfsWatch struct {
	cancel   context.CancelFunc
	done     chan struct{}
	reported bool // the agent's loop has its first report; owned by the loop
}

// ipfsReport is what a name's node gives it now: its site's and its addresses' records.
type ipfsReport struct {
	nr      *nameRun
	w       *ipfsWatch
	records []dns.RR
}

// watchIPFS starts watching nr's node (ipfsNode.run), each kubo request lasting at most
// ProbeTimeout. The followed name's site is asked of nr's registrar, which answers as soon
// as the zone has it when it is this project's proxy, and of the registrar's resolvers when
// the registrar refuses it as a name it does not serve (browse.Fallback): a proxy that
// forwards no queries refuses every name outside its zones. nr registers nothing until the
// first report.
func (a *agent) watchIPFS(nr *nameRun) *ipfsWatch {
	ctx, cancel := context.WithCancel(context.Background())
	w := &ipfsWatch{cancel: cancel, done: make(chan struct{})}
	send := a.opts.Send
	if send == nil {
		send = baseclient.LiveTransport(a.opts.ProbeTimeout)
	}
	n := &ipfsNode{
		owner: nr.label(),
		cfg:   *nr.name.IPFS,
		kubo:  kubo.New(nr.name.IPFS.API, a.opts.ProbeTimeout),
		query: browse.Fallback(
			browse.Querier(send, nr.registrar.Server, nr.registrar.Transport),
			browse.Answers(a.resolverQuery(nr.registrar.Resolvers))),
		logf:     a.opts.Logf,
		interval: a.opts.PollInterval,
		failed:   map[string]string{},
	}
	report := func(records []dns.RR) bool {
		select {
		case a.ipfsReports <- ipfsReport{nr: nr, w: w, records: records}:
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

// stop stops the watch and waits for its goroutine, a pin it runs cancelled.
func (w *ipfsWatch) stop() {
	w.cancel()
	<-w.done
}

// ipfsReported hands r to its name, unless the name or its watch is gone since.
func (a *agent) ipfsReported(r ipfsReport) {
	if a.names[r.nr.label()] != r.nr || r.nr.ipfs != r.w {
		return
	}
	r.w.reported = true
	r.nr.ipfsRecords = r.records
	r.nr.publish(a)
}

// ipfsNode is what a watch knows of the node, owned by the watch's goroutine.
type ipfsNode struct {
	owner    string // the name, fully qualified
	cfg      IPFS
	kubo     *kubo.Client
	query    browse.Query // the registrar's, and the resolvers' for a name it does not serve
	logf     func(format string, args ...any)
	interval time.Duration

	id     string            // the node's peer ID, once it answered
	addrs  []string          // its addresses to publish (dnsaddrs); nil while it does not answer
	site   string            // the CID the name gives at _dnslink; "" none
	pinned string            // Follow: the followed site last pinned; "" none yet
	tried  string            // Follow: the followed site last pinned or tried, logged once
	failed map[string]string // the last failure logged, by check, so that it is logged once
}

type pinResult struct {
	cid, got string // the CID asked for, and as kubo writes it
	err      error
}

// run checks the node every interval until ctx ends or report fails, reporting the records it
// gives the name after the first check and whenever they change. While the node does not
// answer, the name withdraws its addresses and keeps its site: other nodes may hold the site.
//
// With Publish, the site is the path's CID in the node's files, which changes with anything
// in it. With Follow, it is the followed name's site once the node has pinned it all, so that
// the name only ever gives a site its node can serve whole. The node pins each new one in the
// background, under the pin name pinName, and then unpins the others under that name; a
// newer one replaces a pin still running. At the start, until a pin completes, the name gives
// what the node pinned under that name before, as the followed name may give nothing then.
func (n *ipfsNode) run(ctx context.Context, report func([]dns.RR) bool) {
	pins := make(chan pinResult, 1)
	pinning, cancelPin := "", context.CancelFunc(func() {})
	stopPin := func() {
		if pinning != "" {
			cancelPin()
			<-pins
			pinning = ""
		}
	}
	defer stopPin()
	tick := time.NewTicker(n.interval)
	defer tick.Stop()
	var last []dns.RR
	for first := true; ; first = false {
		if n.checkNode(ctx) {
			switch {
			case n.cfg.Publish != "":
				n.checkPublished(ctx)
			case n.cfg.Follow != "":
				if n.site == "" && pinning == "" {
					n.resume(ctx)
				}
				if cid := n.followed(ctx); cid != "" && cid != n.pinned && cid != pinning {
					stopPin()
					if cid != n.tried {
						n.tried = cid
						n.logf("%s: pinning %s, the site %s gives", n.owner, cid, n.cfg.Follow)
					}
					pinning, cancelPin = cid, n.startPin(ctx, cid, pins)
				}
			}
		}
		if records := n.records(); first || !reflect.DeepEqual(records, last) {
			if !report(records) {
				return
			}
			last = records
		}
		select {
		case <-ctx.Done():
			return
		case r := <-pins:
			pinning = ""
			cancelPin()
			n.pinDone(ctx, r)
		case <-tick.C:
		}
	}
}

// startPin pins cid in the background, until it is done or ctx ends, and sends the result to
// pins. The function it returns cancels it.
func (n *ipfsNode) startPin(ctx context.Context, cid string, pins chan<- pinResult) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		got, err := n.kubo.Pin(ctx, cid, n.pinName())
		pins <- pinResult{cid: cid, got: got, err: err}
	}()
	return cancel
}

// pinName is the name the node's pins of the followed sites have.
func (n *ipfsNode) pinName() string { return "sig0lease-agent " + n.owner }

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

// checkPublished reads the CID of the path the name publishes.
func (n *ipfsNode) checkPublished(ctx context.Context) {
	cid, err := n.kubo.MFSCID(ctx, n.cfg.Publish)
	if err != nil {
		n.fail("publish", fmt.Errorf("%s in its node's files: %w; %s", n.cfg.Publish, err, n.keeping()))
		return
	}
	n.ok("publish")
	if cid != n.site {
		n.logf("%s: %s in its node's files is %s; the name gives it", n.owner, n.cfg.Publish, cid)
		n.site = cid
	}
}

// resume gives the site the node pinned under pinName before, if there is one.
func (n *ipfsNode) resume(ctx context.Context) {
	cids, err := n.kubo.PinsNamed(ctx, n.pinName())
	switch {
	case err != nil:
		n.fail("resume", fmt.Errorf("listing its node's pins: %w", err))
	case len(cids) == 1:
		n.ok("resume")
		n.site = cids[0]
		n.logf("%s: giving %s, which its node pinned before, until %s's site is pinned", n.owner, n.site, n.cfg.Follow)
	case len(cids) > 1:
		n.fail("resume", fmt.Errorf("its node has %d pins named %q: giving none until %s's site is pinned", len(cids), n.pinName(), n.cfg.Follow))
	}
}

// followed returns the CID of the site the followed name gives now, its _dnslink record's
// "dnslink=/ipfs/<CID>"; "" when it gives none, or none that can be followed.
func (n *ipfsNode) followed(ctx context.Context) string {
	owner := dnslinkOwner(n.cfg.Follow)
	rrs, err := n.query(ctx, owner, dns.TypeTXT)
	if err != nil {
		n.fail("follow", fmt.Errorf("reading %s's site: %w; %s", n.cfg.Follow, err, n.keeping()))
		return ""
	}
	var links []string
	for _, rr := range rrs {
		var b strings.Builder
		for _, s := range rr.(*dns.TXT).TXT.Txt {
			b.WriteString(dnsmsg.UnescapeTXT(s))
		}
		if v, ok := strings.CutPrefix(b.String(), "dnslink="); ok {
			links = append(links, v)
		}
	}
	switch len(links) {
	case 0:
		n.fail("follow", fmt.Errorf("%s gives no site (no dnslink= record at %s); %s", n.cfg.Follow, owner, n.keeping()))
		return ""
	case 1:
	default:
		n.fail("follow", fmt.Errorf("%s gives %d sites at %s, not one; %s", n.cfg.Follow, len(links), owner, n.keeping()))
		return ""
	}
	cid, ok := strings.CutPrefix(links[0], "/ipfs/")
	if !ok || cid == "" || strings.Contains(cid, "/") {
		n.fail("follow", fmt.Errorf("%s gives %q: only a site given as /ipfs/<CID> can be followed; %s", n.cfg.Follow, links[0], n.keeping()))
		return ""
	}
	n.ok("follow")
	return cid
}

// pinDone records the end of a pin of the followed site: on success, the name gives the site,
// and the node's other pins under pinName go. A failed pin is tried again at the next check.
func (n *ipfsNode) pinDone(ctx context.Context, r pinResult) {
	if r.err != nil {
		if ctx.Err() == nil {
			n.fail("pin", fmt.Errorf("pinning %s: %w; trying again at the next check", r.cid, r.err))
		}
		return
	}
	n.ok("pin")
	n.pinned = r.cid
	if r.got != n.site {
		n.logf("%s: pinned %s; the name gives it", n.owner, r.got)
		n.site = r.got
	}
	cids, err := n.kubo.PinsNamed(ctx, n.pinName())
	if err != nil {
		n.fail("unpin", fmt.Errorf("listing its node's pins, to unpin the sites before: %w", err))
		return
	}
	for _, cid := range cids {
		if cid == r.got {
			continue
		}
		if err := n.kubo.Unpin(ctx, cid); err != nil {
			n.fail("unpin", fmt.Errorf("unpinning %s, a site before: %w", cid, err))
			continue
		}
		n.logf("%s: unpinned %s, a site before", n.owner, cid)
	}
}

// keeping says what the name gives while its site cannot be read.
func (n *ipfsNode) keeping() string {
	if n.site == "" {
		return "the name gives no site until then"
	}
	return "the name keeps giving " + n.site
}

// records returns the records the node gives the name: its site's, then its addresses'.
func (n *ipfsNode) records() []dns.RR {
	var rrs []dns.RR
	if n.site != "" {
		rrs = append(rrs, txtRecord(dnslinkOwner(n.owner), "dnslink=/ipfs/"+n.site))
	}
	for _, a := range n.addrs {
		rrs = append(rrs, txtRecord(dnsaddrOwner(n.owner), "dnsaddr="+a))
	}
	return rrs
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

// fail logs err for the check kind, unless it is the failure last logged for it.
func (n *ipfsNode) fail(kind string, err error) {
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
