package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client/browse"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/dnssd"
	pkgsrp "github.com/NetworkCommons/sig0lease/pkg/srp"
)

// community is what a name's node keeps of the community it follows (IPFS.Follow), owned by
// its watch's goroutine: an entry for each member in a folder of the node's files, giving the
// member's folder last pinned, and the folder's CID as the node's site. The folder is read at
// each check: what is changed in it by hand is put back.
//
// Each member is an instance listed under the community's subtype, by its Instance label,
// which the member's key holds, so that it registers it again under that label when it comes
// back (RFC 9665's First-Come First-Served naming, with its names kept when it stops), and
// whose TXT record gives a folder and the swarm-mac= the community's swarm key makes of its
// KEY and that folder: only a node of the community's private swarm can make it, and copied
// to an instance another key holds, it does not match that KEY. The KEY at the instance's name
// is read at each listing: another key there is another member, and the entry of the one
// before goes. The keys are not kept across a restart: after one, the key listed first at an
// entry's label is that entry's.
type community struct {
	n       *ipfsNode
	cfg     Follow
	query   browse.Query
	folder  string             // in the node's files: /sig0lease-agent/<name>
	members map[string]*member // by folded label
	pins    chan pinResult
	running sync.WaitGroup // the pins' goroutines
}

// member is one member of the community, or an entry found in the folder whose member is not
// listed since.
type member struct {
	label string    // its Instance label, the entry's name
	key   *dns.KEY  // the KEY at its instance's name; nil until listed, for an entry found
	asked string    // the CID its TXT record gave for the folder the node holds; "" none
	holds string    // that folder's CID as kubo writes it, which its entry is to give; "" none
	entry string    // the CID its entry gives, as the folder was last read; "" no entry
	pin   *pinning  // the pin running for it; nil none
	tried string    // the CID last logged as being pinned, so that each is logged once
	gone  time.Time // since when it is not listed; zero while it is
}

// pinning is a pin of a member's folder, running.
type pinning struct {
	cid    string // as the member's TXT record gives it
	cancel func()
}

// pinResult is how a pin of a member's folder ended.
type pinResult struct {
	key string   // the member's, folded label
	pin *pinning // the pin: the member's still, unless stopped since
	got string   // the folder's CID as kubo writes it
	had bool     // the node had it pinned already, not under pinName (hold)
	err error
}

// listing is one member as listed now.
type listing struct {
	label string
	key   *dns.KEY
	cid   string // the folder its TXT record gives
}

func newCommunity(n *ipfsNode, cfg Follow, query browse.Query) *community {
	return &community{
		n:       n,
		cfg:     cfg,
		query:   query,
		folder:  "/sig0lease-agent/" + strings.TrimSuffix(n.owner, "."),
		members: map[string]*member{},
		pins:    make(chan pinResult),
	}
}

// pinName is the name of the node's pins of the members' folders.
func (c *community) pinName() string { return "sig0lease-agent " + c.n.owner }

// check reads the folder (read), then lists the members: it pins each new folder one gives,
// starts counting for one no longer listed, and removes one gone for RevokeAfter, with its
// entry. A listing that fails changes nothing: a member is gone only from a listing that
// answered without it. Then each member's entry is made to give the folder the node holds for
// it, where the folder read has another or none (put), and the folder's CID is read (tidy).
func (c *community) check(ctx context.Context) {
	if !c.read(ctx) {
		return
	}
	if listed, err := c.list(ctx); err != nil {
		c.n.fail("members", fmt.Errorf("listing the members at %s: %w; keeping the folder as it is", c.cfg.Members(), err))
	} else {
		c.n.ok("members")
		now := time.Now()
		for key, l := range listed {
			c.listed(ctx, key, l)
		}
		for key, m := range c.members {
			if _, ok := listed[key]; !ok {
				c.absent(ctx, key, m, now)
			}
		}
	}
	for key, m := range c.members {
		c.put(ctx, key, m)
	}
	c.tidy(ctx)
}

// read makes the folder, unless it is there, and reads its entries: each member's, by its
// label, and any that is no member's, which is taken as one's not listed since now, so that it
// goes after RevokeAfter unless its member is listed. Those are the entries the folder holds
// at the start, and any made in it by hand since. It reports whether the folder was read.
func (c *community) read(ctx context.Context) bool {
	if err := c.n.kubo.MakeFolder(ctx, c.folder); err != nil {
		c.n.fail("folder", fmt.Errorf("making %s in its node's files: %w; trying again at the next check", c.folder, err))
		return false
	}
	entries, err := c.n.kubo.Entries(ctx, c.folder)
	if err != nil {
		c.n.fail("folder", fmt.Errorf("reading %s in its node's files: %w; trying again at the next check", c.folder, err))
		return false
	}
	c.n.ok("folder")
	for _, m := range c.members {
		m.entry = entries[m.label]
	}
	now := time.Now()
	for _, label := range sortedKeys(entries) {
		key := dnsname.Fold(label)
		if c.members[key] != nil {
			continue
		}
		cid := entries[label]
		c.members[key] = &member{label: label, asked: cid, holds: cid, entry: cid, gone: now}
		c.n.logf("%s: found %s's entry, giving %s; it goes in %s unless %s is listed", c.n.owner, label, cid, c.cfg.RevokeAfter, label)
	}
	return true
}

// list returns the members listed now, by folded label: each instance the subtype's PTR records
// list (browse.InstanceLabels), with the one KEY at its name and the folder its TXT record
// gives with its swarm-mac= (memberCID). Any other instance is not a member, which is logged:
// one whose label cannot be an entry's, that has no KEY or several, or whose TXT record gives
// no folder or no swarm-mac= the swarm key makes of it. Any question that fails fails the
// whole.
func (c *community) list(ctx context.Context) (map[string]listing, error) {
	labels, err := browse.InstanceLabels(ctx, c.query, c.cfg.Members(), c.cfg.ServiceType, c.cfg.Domain)
	if err != nil {
		return nil, err
	}
	out := map[string]listing{}
	checked := map[string]bool{}
	for _, label := range labels {
		name := label + "." + dnssd.BrowsingOwnerName(c.cfg.ServiceType, c.cfg.Domain)
		check := "member " + dnsname.Fold(label)
		checked[check] = true
		if !dnsname.IsHostLabel(label) {
			c.n.fail(check, fmt.Errorf("%s: not a member: its label is not letters, digits and hyphens, as an entry's is", name))
			continue
		}
		keys, err := c.query(ctx, name, dns.TypeKEY)
		if err != nil {
			return nil, err
		}
		if len(keys) != 1 {
			c.n.fail(check, fmt.Errorf("%s: not a member: %d KEY records at its name, not one", name, len(keys)))
			continue
		}
		txts, err := c.query(ctx, name, dns.TypeTXT)
		if err != nil {
			return nil, err
		}
		key := keys[0].(*dns.KEY)
		cid, err := memberCID(txts, key, c.n.swarm)
		if err != nil {
			c.n.fail(check, fmt.Errorf("%s: not a member: %w", name, err))
			continue
		}
		c.n.ok(check)
		out[dnsname.Fold(label)] = listing{label: label, key: key, cid: cid}
	}
	// What was last logged of an instance no longer listed is forgotten: listed again, it is
	// logged again.
	for check := range c.n.failed {
		if strings.HasPrefix(check, "member ") && !checked[check] {
			c.n.ok(check)
		}
	}
	return out, nil
}

// memberCID returns the CID of the folder an instance's TXT record gives, its dnslink= key's
// value "/ipfs/<CID>", once its swarm-mac= is the one swarm makes of key, the KEY at the
// instance's name, and that CID.
func memberCID(txts []dns.RR, key *dns.KEY, swarm swarmKey) (string, error) {
	link, ok := txtValue(txts, "dnslink")
	if !ok {
		return "", fmt.Errorf("its TXT record gives no folder (no dnslink=)")
	}
	cid, ok := strings.CutPrefix(link, "/ipfs/")
	if !ok || cid == "" || strings.Contains(cid, "/") {
		return "", fmt.Errorf("its TXT record gives %q: only a folder given as /ipfs/<CID> is pinned", link)
	}
	mac, ok := txtValue(txts, swarmMACKey)
	if !ok {
		return "", fmt.Errorf("its TXT record gives no %s=, which the community's swarm key makes", swarmMACKey)
	}
	if !swarm.verify(key, cid, mac) {
		return "", fmt.Errorf("its %s= is not the one the community's swarm key makes of its KEY and its folder %s", swarmMACKey, cid)
	}
	return cid, nil
}

// txtValue returns the value of the key k, ignoring case, in an instance's TXT records, and
// whether it is there: only a key's first occurrence counts (RFC 6763 S6.4).
func txtValue(txts []dns.RR, k string) (string, bool) {
	for _, rr := range txts {
		for _, s := range dnsmsg.TXTStrings(rr.(*dns.TXT)) {
			if key, v, _ := strings.Cut(s, "="); strings.EqualFold(key, k) {
				return v, true
			}
		}
	}
	return "", false
}

// listed records the member l, at key: one new, back, or whose label another key holds now,
// which is another member, the one before removed first. A new folder it gives is pinned, a
// pin of another folder stopped.
func (c *community) listed(ctx context.Context, key string, l listing) {
	m := c.members[key]
	switch {
	case m == nil:
		c.n.logf("%s: %s is a member", c.n.owner, l.label)
	case m.key != nil && !pkgsrp.KeysAllMatch([]*dns.KEY{l.key}, m.key):
		if !c.remove(ctx, key, m) {
			return
		}
		c.n.logf("%s: %s is another key's now: the member before goes, and the new one is a member", c.n.owner, l.label)
		m = nil
	case !m.gone.IsZero():
		c.n.logf("%s: %s is listed again", c.n.owner, l.label)
	}
	if m == nil {
		m = &member{label: l.label}
		c.members[key] = m
	}
	m.key, m.gone = l.key, time.Time{}
	if m.pin != nil && m.pin.cid != l.cid {
		c.stopPin(m)
	}
	if l.cid != m.asked && m.pin == nil {
		c.pin(ctx, key, m, l.cid)
	}
}

// absent records that the member m, at key, is not listed: from now on, the first time, and
// once that is RevokeAfter ago it is removed. A pin of its folder stops: its node may be gone.
func (c *community) absent(ctx context.Context, key string, m *member, now time.Time) {
	if m.gone.IsZero() {
		m.gone = now
		c.stopPin(m)
		c.n.logf("%s: %s is not listed; its entry goes in %s unless it is again", c.n.owner, m.label, c.cfg.RevokeAfter)
		return
	}
	if now.Sub(m.gone) >= c.cfg.RevokeAfter && c.remove(ctx, key, m) {
		c.n.logf("%s: %s is not listed for %s: no longer a member", c.n.owner, m.label, c.cfg.RevokeAfter)
	}
}

// pin makes the node hold cid, the folder of the member m, at key, in the background (hold);
// pinDone gets the result. No pin is running for m.
func (c *community) pin(ctx context.Context, key string, m *member, cid string) {
	if cid != m.tried {
		m.tried = cid
		c.n.logf("%s: pinning %s, %s's folder", c.n.owner, cid, m.label)
	}
	ctx, cancel := context.WithCancel(ctx)
	p := &pinning{cid: cid, cancel: cancel}
	m.pin = p
	c.running.Add(1)
	go func() {
		defer c.running.Done()
		r := pinResult{key: key, pin: p}
		r.got, r.had, r.err = c.hold(ctx, cid)
		select {
		case c.pins <- r:
		case <-ctx.Done():
		}
	}()
}

// hold makes the node hold cid and everything it links to, returning the CID as the node
// writes it: it pins it under pinName, which lasts until the node has fetched it all or ctx
// ends. A CID the node has pinned already under another name, or none, is its owner's pin:
// pinning it again would rename it, and the agent would unpin it later, so it is left as it
// is (had). Run by a pin's goroutine.
func (c *community) hold(ctx context.Context, cid string) (got string, had bool, err error) {
	pins, err := c.n.kubo.Pins(ctx)
	if err != nil {
		return "", false, err
	}
	if name, pinned := pins[cid]; pinned && name != c.pinName() {
		return cid, true, nil
	}
	got, err = c.n.kubo.Pin(ctx, cid, c.pinName())
	return got, false, err
}

// stopPin cancels the pin running for m, if any; its result, if it still comes, is not m's.
func (c *community) stopPin(m *member) {
	if m.pin != nil {
		m.pin.cancel()
		m.pin = nil
	}
}

// stop cancels every pin running, and waits for them.
func (c *community) stop() {
	for _, m := range c.members {
		c.stopPin(m)
	}
	c.running.Wait()
}

// pinDone records the end of a pin of a member's folder, unless the pin was stopped or the
// member removed since: on success the node holds the folder, which the member's entry gives
// from now on (put), and the folder's CID is read (tidy); a failed pin is tried again at the
// next check.
func (c *community) pinDone(ctx context.Context, r pinResult) {
	m := c.members[r.key]
	if m == nil || m.pin != r.pin {
		return
	}
	c.stopPin(m)
	if r.err != nil {
		c.n.fail("pin "+r.key, fmt.Errorf("pinning %s, %s's folder: %w; trying again at the next check", r.pin.cid, m.label, r.err))
		return
	}
	c.n.ok("pin " + r.key)
	m.asked, m.holds = r.pin.cid, r.got
	if r.had {
		c.n.logf("%s: its node has %s, %s's folder, pinned already, not by the agent: that pin is left as it is", c.n.owner, r.got, m.label)
	} else {
		c.n.logf("%s: pinned %s, %s's folder", c.n.owner, r.got, m.label)
	}
	c.put(ctx, r.key, m)
	c.tidy(ctx)
}

// put makes the entry of the member m, at key, give the folder the node holds for it, unless
// it does or the node holds none. A failure leaves m with no entry, or the one before, and the
// next check tries again.
func (c *community) put(ctx context.Context, key string, m *member) {
	if m.holds == "" || m.entry == m.holds {
		return
	}
	path := c.folder + "/" + m.label
	if m.entry != "" {
		if err := c.n.kubo.Remove(ctx, path); err != nil {
			c.n.fail("entry "+key, fmt.Errorf("removing %s's entry %s, to replace it: %w; trying again at the next check", m.label, path, err))
			return
		}
		m.entry = ""
	}
	if err := c.n.kubo.Add(ctx, m.holds, path); err != nil {
		c.n.fail("entry "+key, fmt.Errorf("adding %s's entry %s: %w; trying again at the next check", m.label, path, err))
		return
	}
	c.n.ok("entry " + key)
	m.entry = m.holds
	c.n.logf("%s: %s's entry gives %s", c.n.owner, m.label, m.holds)
}

// remove removes the member m, at key, and its entry, reporting whether it did: a member whose
// entry cannot be removed stays, its removal tried again at the next check. What was last
// logged of its pin and its entry is forgotten with it.
func (c *community) remove(ctx context.Context, key string, m *member) bool {
	c.stopPin(m)
	if m.entry != "" {
		if err := c.n.kubo.Remove(ctx, c.folder+"/"+m.label); err != nil {
			c.n.fail("entry "+key, fmt.Errorf("removing %s's entry: %w; trying again at the next check", m.label, err))
			return false
		}
	}
	delete(c.members, key)
	c.n.ok("entry " + key)
	c.n.ok("pin " + key)
	return true
}

// tidy reads the folder's CID, which the node gives as its site, and unpins the node's pins
// under pinName that no member's folder or entry is and no pin running asks for: a member's
// folders before, those of members removed, and any from before the start.
func (c *community) tidy(ctx context.Context) {
	if cid, err := c.n.kubo.MFSCID(ctx, c.folder); err != nil {
		c.n.fail("site", fmt.Errorf("%s in its node's files: %w; %s", c.folder, err, c.n.keeping()))
	} else {
		c.n.ok("site")
		c.n.give(cid, "the community's folder "+c.folder)
	}
	pins, err := c.n.kubo.Pins(ctx)
	if err != nil {
		c.n.fail("unpin", fmt.Errorf("listing its node's pins, to unpin the folders no entry gives: %w", err))
		return
	}
	used := map[string]bool{}
	for _, m := range c.members {
		used[m.holds], used[m.entry] = true, true
		if m.pin != nil {
			used[m.pin.cid] = true
		}
	}
	failed := false
	for _, cid := range sortedKeys(pins) {
		if pins[cid] != c.pinName() || used[cid] {
			continue
		}
		if err := c.n.kubo.Unpin(ctx, cid); err != nil {
			c.n.fail("unpin", fmt.Errorf("unpinning %s, which no entry gives: %w; trying again at the next check", cid, err))
			failed = true
			continue
		}
		c.n.logf("%s: unpinned %s, which no entry gives", c.n.owner, cid)
	}
	if !failed {
		c.n.ok("unpin")
	}
}
