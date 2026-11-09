package browse

import (
	"context"
	"fmt"
	"slices"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/sync/errgroup"

	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
)

// Name is a name Names found in a zone, with its records.
type Name struct {
	Name string `json:"name"` // fully qualified
	// Key is whether a KEY record at the name holds it: one registered over RFC 9664, whose
	// records include those of the names below it that hold no KEY of their own.
	Key     bool     `json:"key"`
	Records []Record `json:"records"` // by owner, in the zone's order, then by type
}

// Record is one record of a Name.
type Record struct {
	Owner string `json:"owner"` // relative to the Name: "" for the Name itself, "hello" for hello.<Name>
	Type  string `json:"type"`  // "TXT"
	// Data is a TXT record's strings, as their octets, or any other record's data in
	// presentation format, as one string.
	Data []string `json:"data"`
}

// Names lists the names below zone, by walking its NSEC chain (RFC 4034 S4): each name's NSEC
// record gives the name after it in the zone's canonical order (S6.1) and the types at it, and
// the names below zone follow one another in that order, from zone's own NSEC record to the
// first that leads out of zone. Names at or below skip, a DNS-SD domain Browse reads, are left
// out; "" leaves out none. Each name's records are then asked for, by the types its NSEC record
// lists.
//
// A name a KEY holds is listed with the records at it and at the names below it that hold no
// KEY of their own, as RFC 9664 registers a name and its records; any other name, with the
// ones at it. KEY, RRSIG and NSEC records are not listed: Key says whether a KEY holds a name.
//
// A zone with no NSEC record at its name, unsigned or signed with NSEC3, is an error, as is a
// chain that comes back to a name it went through. A name gone between the NSEC record that
// named it and its own question, as the zone changes meanwhile, is stepped over: the name
// before it is asked again, and its NSEC record names what follows it now; one that still
// names the name gone is an error. A record gone by the time it is asked for is not listed.
// Any failed question fails the whole.
func Names(ctx context.Context, q Query, zone, skip string) ([]Name, error) {
	zone = dnsutil.Fqdn(zone)
	nodes, err := walk(ctx, q, zone)
	if err != nil {
		return nil, err
	}

	// Each name, then each of its types, a question whose records go to the Name listing it.
	type question struct {
		entry   int // the Name in names
		name    string
		qtype   uint16
		owner   string // name, relative to the Name
		records []Record
	}
	names := []Name{}
	held := map[string]int{} // the names a KEY holds, folded: their index in names
	var questions []*question
	for _, n := range nodes {
		if skip != "" && dnsname.IsAtOrBelow(n.name, skip) {
			continue
		}
		key := slices.Contains(n.types, dns.TypeKEY)
		entry := -1
		if !key {
			entry = holder(n.name, zone, held)
		}
		if entry < 0 {
			entry = len(names)
			names = append(names, Name{Name: n.name, Key: key, Records: []Record{}})
			if key {
				held[dnsname.Fold(n.name)] = entry
			}
		}
		owner := relative(n.name, names[entry].Name)
		for _, t := range n.types {
			if t != dns.TypeKEY && t != dns.TypeRRSIG && t != dns.TypeNSEC {
				questions = append(questions, &question{entry: entry, name: n.name, qtype: t, owner: owner})
			}
		}
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(parallel)
	for _, qu := range questions {
		g.Go(func() error {
			rrs, err := q(gctx, qu.name, qu.qtype)
			if err != nil {
				return err
			}
			for _, rr := range rrs {
				qu.records = append(qu.records, Record{Owner: qu.owner, Type: dnsutil.TypeToString(qu.qtype), Data: data(rr)})
			}
			slices.SortFunc(qu.records, func(a, b Record) int { return slices.Compare(a.Data, b.Data) })
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	for _, qu := range questions {
		names[qu.entry].Records = append(names[qu.entry].Records, qu.records...)
	}
	return names, nil
}

// node is a name the NSEC chain went through, and the types at it.
type node struct {
	name  string
	types []uint16
}

// walk returns the names below zone, in its NSEC chain's order (Names).
func walk(ctx context.Context, q Query, zone string) ([]node, error) {
	nsec, err := nsecAt(ctx, q, zone)
	if err != nil {
		return nil, err
	}
	if nsec == nil {
		return nil, fmt.Errorf("%s has no NSEC record: a zone's names are found by its NSEC chain (RFC 4034 S4), which an unsigned zone, or one signed with NSEC3, does not have", zone)
	}
	var nodes []node
	seen := map[string]bool{dnsname.Fold(zone): true}
	prev := zone
	for {
		next := nsec.NextDomain
		if !dnsname.IsAtOrBelow(next, zone) || dnsname.EqualFold(next, zone) {
			return nodes, nil
		}
		if seen[dnsname.Fold(next)] {
			return nil, fmt.Errorf("the NSEC chain of %s comes back from %s to %s", zone, prev, next)
		}
		n, err := nsecAt(ctx, q, next)
		if err != nil {
			return nil, err
		}
		if n == nil {
			// next is gone since prev's NSEC record named it: prev's names what follows now.
			again, err := nsecAt(ctx, q, prev)
			if err != nil {
				return nil, err
			}
			if again == nil {
				return nil, fmt.Errorf("%s, and %s, the name after it, went from %s while read", prev, next, zone)
			}
			if dnsname.EqualFold(again.NextDomain, next) {
				return nil, fmt.Errorf("the NSEC record of %s names %s, which has none", prev, next)
			}
			nsec = again
			continue
		}
		seen[dnsname.Fold(next)] = true
		nodes = append(nodes, node{name: next, types: n.TypeBitMap})
		prev, nsec = next, n
	}
}

// nsecAt returns the NSEC record at name; nil when it has none.
func nsecAt(ctx context.Context, q Query, name string) (*dns.NSEC, error) {
	rrs, err := q(ctx, name, dns.TypeNSEC)
	if err != nil {
		return nil, err
	}
	switch len(rrs) {
	case 0:
		return nil, nil
	case 1:
		return rrs[0].(*dns.NSEC), nil
	}
	return nil, fmt.Errorf("%s has %d NSEC records: a name has one at most (RFC 4034 S4)", name, len(rrs))
}

// holder returns the index in names of the closest name above name, and below zone, that a KEY
// holds (held); -1 when there is none. The chain goes through a name before the names below
// it, so held has that name already.
func holder(name, zone string, held map[string]int) int {
	for {
		_, above, ok := dnsname.CutFirstLabel(name)
		if !ok || !dnsname.IsAtOrBelow(above, zone) || dnsname.EqualFold(above, zone) {
			return -1
		}
		if i, ok := held[dnsname.Fold(above)]; ok {
			return i
		}
		name = above
	}
}

// relative returns owner, at or below name, relative to name: "" for name itself.
func relative(owner, name string) string {
	if dnsname.EqualFold(owner, name) {
		return ""
	}
	return owner[:len(owner)-len(name)-1]
}

// data returns rr's data as a Record holds it.
func data(rr dns.RR) []string {
	if txt, ok := rr.(*dns.TXT); ok {
		return dnsmsg.TXTStrings(txt)
	}
	return []string{rr.Data().String()}
}
