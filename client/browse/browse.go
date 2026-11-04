// Package browse reads a DNS-SD domain (RFC 6763) with plain queries, as a client that can only
// ask questions does, such as a browser page over DNS-over-HTTPS: the service types the domain
// lists (S9), each type's instances (S4), and each instance's SRV and TXT records (S6) and its
// target's addresses.
package browse

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/sync/errgroup"

	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/dnssd"
)

// Instance is one service instance found in the domain.
type Instance struct {
	Name      string   `json:"name"`      // its Instance label, "demo http"
	Type      string   `json:"type"`      // its service type, "_http._tcp"
	Target    string   `json:"target"`    // its SRV record's target; "" when it has none
	Port      uint16   `json:"port"`      // its SRV record's port
	TXT       []string `json:"txt"`       // its TXT record's strings, as their octets
	Addresses []string `json:"addresses"` // the target's A and AAAA addresses, sorted
}

// Domain is what Browse found in a domain.
type Domain struct {
	Domain    string     `json:"domain"`
	Types     []string   `json:"types"`     // sorted
	Instances []Instance `json:"instances"` // sorted by type, then name
}

// Query asks one question and returns the answer's records of type qtype at name: none for
// NXDOMAIN or NODATA, an error for any other failure.
type Query func(ctx context.Context, name string, qtype uint16) ([]dns.RR, error)

// Querier returns the Query that sends each question to server over network with send.
func Querier(send client.Transport, server string, network client.Network) Query {
	return func(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
		resp, err := send(ctx, server, network, dns.NewMsg(name, qtype))
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", name, dnsutil.TypeToString(qtype), err)
		}
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			return nil, fmt.Errorf("%s %s: %s", name, dnsutil.TypeToString(qtype), dnsutil.RcodeToString(resp.Rcode))
		}
		var rrs []dns.RR
		for _, rr := range resp.Answer {
			if dns.RRToType(rr) == qtype && dnsname.EqualFold(rr.Header().Name, name) {
				rrs = append(rrs, rr)
			}
		}
		return rrs, nil
	}
}

// parallel is how many questions Browse has out at once.
const parallel = 8

// Browse lists domain's service types (the PTR records at _services._dns-sd._udp.<domain>),
// then each type's instances (the PTR records at <type>.<domain>), then each instance's SRV and
// TXT records and the addresses of the SRV record's target. An instance whose SRV record is
// gone by the time it is asked for, as when it is withdrawn meanwhile, is listed without a
// target. Any failed question fails the whole.
func Browse(ctx context.Context, q Query, domain string) (*Domain, error) {
	domain = dnsutil.Fqdn(domain)
	d := &Domain{Domain: domain, Types: []string{}, Instances: []Instance{}}
	ptrs, err := q(ctx, dnssd.EnumerationOwnerName(domain), dns.TypePTR)
	if err != nil {
		return nil, err
	}
	for _, target := range ptrTargets(ptrs) {
		if t, ok := strings.CutSuffix(target, "."+domain); ok {
			d.Types = append(d.Types, t)
		}
	}
	slices.Sort(d.Types)
	d.Types = slices.Compact(d.Types)

	// Two rounds, the instances of every type, then every instance's records: a question never
	// waits for a slot that one of its own round's holds.
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(parallel)
	for _, t := range d.Types {
		g.Go(func() error {
			ptrs, err := q(gctx, dnssd.BrowsingOwnerName(t, domain), dns.TypePTR)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			for _, name := range ptrTargets(ptrs) {
				if label, rest, ok := dnsname.CutFirstLabel(name); ok && dnsname.EqualFold(rest, dnssd.BrowsingOwnerName(t, domain)) {
					d.Instances = append(d.Instances, Instance{Name: label, Type: t, TXT: []string{}, Addresses: []string{}})
				}
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	g, gctx = errgroup.WithContext(ctx)
	g.SetLimit(parallel)
	for i := range d.Instances {
		in := &d.Instances[i]
		name := in.Name + "." + dnssd.BrowsingOwnerName(in.Type, domain)
		g.Go(func() error {
			txts, err := q(gctx, name, dns.TypeTXT)
			if err != nil {
				return err
			}
			for _, rr := range txts {
				for _, s := range rr.(*dns.TXT).Txt {
					in.TXT = append(in.TXT, dnsmsg.UnescapeTXT(s))
				}
			}
			srvs, err := q(gctx, name, dns.TypeSRV)
			if err != nil {
				return err
			}
			if len(srvs) == 0 {
				return nil // withdrawn since its PTR record was read
			}
			srv := srvs[0].(*dns.SRV)
			in.Target, in.Port = srv.Target, srv.Port
			for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				addrs, err := q(gctx, srv.Target, qtype)
				if err != nil {
					return err
				}
				for _, rr := range addrs {
					in.Addresses = append(in.Addresses, address(rr).String())
				}
			}
			slices.Sort(in.Addresses)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	slices.SortFunc(d.Instances, func(a, b Instance) int {
		return strings.Compare(a.Type+" "+a.Name, b.Type+" "+b.Name)
	})
	return d, nil
}

func ptrTargets(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		out = append(out, rr.(*dns.PTR).Ptr)
	}
	return out
}

func address(rr dns.RR) netip.Addr {
	switch v := rr.(type) {
	case *dns.A:
		return v.Addr
	case *dns.AAAA:
		return v.Addr
	}
	panic(fmt.Sprintf("browse: %T is not an address record", rr))
}
