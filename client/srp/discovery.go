package srp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/dnszone"
)

// defaultBootstrapResolvers are the resolvers LiveDNSQuery asks when none are configured: the
// public pair config.yaml's upstreams also lists.
var defaultBootstrapResolvers = []string{"8.8.8.8:53", "8.8.4.4:53"}

// LiveDNSQuery returns the dnszone.Query that asks resolvers in turn (dnszone.Resolvers),
// or defaultBootstrapResolvers when resolvers is empty.
func LiveDNSQuery(resolvers []string) dnszone.Query {
	if len(resolvers) == 0 {
		resolvers = defaultBootstrapResolvers
	}
	return dnszone.Resolvers(resolvers)
}

// DiscoveryMode selects the names Discover looks under for the registrar's SRV record.
type DiscoveryMode int

const (
	// DiscoveryClosest, the default, looks under the registration domain first, then under
	// each parent name in turn, ending at the apex of the zone enclosing it. The first name
	// with an SRV record wins, so a record under a subdomain names the registrar for that
	// subdomain and everything below it, the way the apex record does for the whole zone.
	// This goes beyond RFC 9665 S3.1.1, which looks only under the apex, so that a registrar
	// can serve one registration domain inside a zone without a zone cut at that domain
	// (https://github.com/NetworkCommons/sig0lease/issues/46). A domain with no record below
	// the apex finds exactly what S3.1.1 finds. A record below the apex is one that a
	// requester following S3.1.1 alone never sees -- S3.1.1 leaves other discovery
	// mechanisms open.
	DiscoveryClosest DiscoveryMode = iota
	// DiscoveryApexOnly looks only under the zone apex, as RFC 9665 S3.1.1 specifies: it
	// finds the registrar any S3.1.1 requester would find.
	DiscoveryApexOnly
)

func (m DiscoveryMode) validate() error {
	switch m {
	case DiscoveryClosest, DiscoveryApexOnly:
		return nil
	}
	return fmt.Errorf("unknown DiscoveryMode %d", m)
}

// Discover finds the SRP registrar for domain that is reachable over network. As RFC 9665
// S3.1.1 specifies, it first finds the apex of the closest DNS zone enclosing domain with SOA
// queries (RFC 8765 S6.1, dnszone.Apex). It then looks up the SRV record at
// "<service>.<name>.", where service is network's DiscoveryService -- "_dnssd-srp-tls._tcp"
// for NetworkTLS, "_dnssd-srp._tcp" otherwise, the service names RFC 9665 S10.4 registers in
// RFC 6763 S7's "_<service>._tcp" form -- for each name mode selects (see DiscoveryMode), in
// order, and stops at the first name that has one. NetworkDoH has no service, so it is never
// discovered (an error). A NetworkTLS search never falls back to
// "_dnssd-srp._tcp": S7 says a requester able to use TLS SHOULD NOT fall back to TCP. It
// never looks above the apex: a zone cut separates authority, so a registrar named in the
// parent zone speaks for nothing in the child. A failed query ends the search with its error
// instead of moving on to the next name, since the name it could not ask about may hold the
// answer. The best (lowest-priority, highest-weight-among-ties) SRV target is then resolved
// to an address with the same query, so every step of discovery asks the same resolvers: a
// target that only those resolvers know (a lab DNS, the local BIND 9 test zone) still works.
// Returns "address:port". A caller with an explicit registrar address configured should skip
// this entirely (see Config.RegistrarAddr) -- discovery is the fallback, not the only path,
// matching cmd/sig0lease-srp-client's own "dev/test tool" framing.
func Discover(ctx context.Context, query dnszone.Query, domain string, mode DiscoveryMode, network baseclient.Network) (string, error) {
	if query == nil {
		return "", fmt.Errorf("srp/client: Discover called with a nil query")
	}
	if err := mode.validate(); err != nil {
		return "", fmt.Errorf("srp/client: %w", err)
	}
	if err := network.Validate(); err != nil {
		return "", fmt.Errorf("srp/client: %w", err)
	}
	if network == baseclient.NetworkDoH {
		return "", fmt.Errorf("srp/client: no registrar is discovered over doh: RFC 9665 names no DoH service, so give the registrar's URL")
	}
	domain = dnsutil.Fqdn(domain)
	soa, err := dnszone.Apex(ctx, query, domain)
	if err != nil {
		return "", fmt.Errorf("srp/client: discovery failed for %s: %w", domain, err)
	}
	names, err := registrarSearchNames(domain, dnsutil.Fqdn(soa.Hdr.Name), mode)
	if err != nil {
		return "", fmt.Errorf("srp/client: discovery failed for %s: %w", domain, err)
	}

	var srvs []*dns.SRV
	var asked []string
	for _, n := range names {
		name := DiscoveryService(network) + "." + n
		resp, err := query(ctx, name, dns.TypeSRV)
		if err != nil {
			return "", fmt.Errorf("srp/client: discovery failed for %s: %w", domain, err)
		}
		asked = append(asked, name)
		for _, rr := range resp.Answer {
			if srv, ok := rr.(*dns.SRV); ok {
				srvs = append(srvs, srv)
			}
		}
		if len(srvs) > 0 {
			break
		}
	}
	if len(srvs) == 0 {
		return "", fmt.Errorf("srp/client: no SRP registrar found for %s: no SRV record at %s", domain, strings.Join(asked, ", "))
	}

	best := srvs[0]
	for _, s := range srvs[1:] {
		if s.Priority < best.Priority || (s.Priority == best.Priority && s.Weight > best.Weight) {
			best = s
		}
	}
	addr, err := targetAddress(ctx, query, best.Target)
	if err != nil {
		return "", fmt.Errorf("srp/client: discovery failed for %s: %w", domain, err)
	}
	return net.JoinHostPort(addr.String(), strconv.Itoa(int(best.Port))), nil
}

// targetAddress returns an address for an SRV target: its first A record, or its first AAAA
// record if it has no A record.
func targetAddress(ctx context.Context, query dnszone.Query, target string) (netip.Addr, error) {
	resp, err := query(ctx, target, dns.TypeA)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.Addr, nil
		}
	}
	resp, err = query(ctx, target, dns.TypeAAAA)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, rr := range resp.Answer {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			return aaaa.AAAA.Addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("SRV target %s has no A or AAAA record", target)
}

// registrarSearchNames returns the names Discover looks under for the registrar's SRV
// record, in the order it asks: for DiscoveryClosest, domain and then each parent of domain
// up to and including apex; for DiscoveryApexOnly, apex alone. Both names are fully
// qualified, compared without regard to ASCII case (RFC 4343), and every name returned is
// spelled as domain spells it. apex must be domain or one of its parents: an SOA owner that
// is not means the resolver answered about some other name, which is an error, not a zone to
// look in.
func registrarSearchNames(domain, apex string, mode DiscoveryMode) ([]string, error) {
	names := []string{domain}
	for !dnsname.EqualFold(names[len(names)-1], apex) {
		_, parent, _ := dnsname.CutFirstLabel(names[len(names)-1])
		if parent == "" {
			return nil, fmt.Errorf("the zone apex %s that the SOA lookup returned does not enclose %s", apex, domain)
		}
		names = append(names, parent)
	}
	if mode == DiscoveryApexOnly {
		return names[len(names)-1:], nil
	}
	return names, nil
}
