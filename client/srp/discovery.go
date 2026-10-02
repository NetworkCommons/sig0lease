package srp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
)

// DNSQuery is the shape of a live DNS lookup, injected so Discover is testable without real
// network I/O. It returns the whole response, since discovery reads both the Answer section
// (SRV, or an SOA at a zone apex) and the Authority section (the SOA a negative answer
// carries). A NOERROR or NXDOMAIN response is an answer, not an error.
type DNSQuery func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)

// defaultBootstrapResolvers mirrors pkg/updatecore.Coordinator's own default -- the same
// public resolver pair used elsewhere in this codebase to resolve records this project
// doesn't itself serve.
var defaultBootstrapResolvers = []string{"8.8.8.8:53", "8.8.4.4:53"}

// LiveDNSQuery returns a DNSQuery that performs a real lookup against resolvers (falling
// back to defaultBootstrapResolvers if empty), trying each in turn until one answers with
// NOERROR or NXDOMAIN. Any other RCODE (SERVFAIL, REFUSED, ...) counts as that resolver
// failing, like a network error.
func LiveDNSQuery(resolvers []string) DNSQuery {
	if len(resolvers) == 0 {
		resolvers = defaultBootstrapResolvers
	}
	return func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		req := dns.NewMsg(name, qtype)
		if req == nil {
			return nil, fmt.Errorf("srp/client: failed to build %s query for %s", dns.TypeToString[qtype], name)
		}

		var lastErr error
		for _, resolver := range resolvers {
			resp, err := dns.Exchange(ctx, req, "udp", resolver)
			if err != nil {
				lastErr = err
				continue
			}
			if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
				lastErr = fmt.Errorf("resolver %s answered %s", resolver, dns.RcodeToString[resp.Rcode])
				continue
			}
			return resp, nil
		}
		return nil, fmt.Errorf("srp/client: %s query for %s failed against all resolvers: %w", dns.TypeToString[qtype], name, lastErr)
	}
}

// DiscoveryMode selects the names Discover looks under for the registrar's
// "_dnssd-srp._tcp" SRV record.
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

// Discover finds the SRP registrar for domain. As RFC 9665 S3.1.1 specifies, it first finds
// the apex of the closest DNS zone enclosing domain with SOA queries (RFC 8765 S6.1, see
// zoneApex). It then looks up the SRV record at "_dnssd-srp._tcp.<name>." -- the service
// name RFC 9665 S10.4.1 registers, in RFC 6763 S7's "_<service>._tcp" form -- for each name
// mode selects (see DiscoveryMode), in order, and stops at the first name that has one. It
// never looks above the apex: a zone cut separates authority, so a registrar named in the
// parent zone speaks for nothing in the child. A failed query ends the search with its error
// instead of moving on to the next name, since the name it could not ask about may hold the
// answer. The best (lowest-priority, highest-weight-among-ties) SRV target is then resolved
// to an address with the same query, so every step of discovery asks the same resolvers: a
// target that only those resolvers know (a lab DNS, the local BIND 9 test zone) still works.
// Returns "address:port". A caller with an explicit registrar address configured should skip
// this entirely (see Config.RegistrarAddr) -- discovery is the fallback, not the only path,
// matching cmd/sig0lease-srp-client's own "dev/test tool" framing.
func Discover(ctx context.Context, query DNSQuery, domain string, mode DiscoveryMode) (string, error) {
	if query == nil {
		return "", fmt.Errorf("srp/client: Discover called with a nil DNSQuery")
	}
	if err := mode.validate(); err != nil {
		return "", fmt.Errorf("srp/client: %w", err)
	}
	domain = ensureFQDN(domain)
	zone, err := zoneApex(ctx, query, domain)
	if err != nil {
		return "", fmt.Errorf("srp/client: discovery failed for %s: %w", domain, err)
	}
	names, err := registrarSearchNames(domain, zone, mode)
	if err != nil {
		return "", fmt.Errorf("srp/client: discovery failed for %s: %w", domain, err)
	}

	var srvs []*dns.SRV
	var asked []string
	for _, n := range names {
		name := "_dnssd-srp._tcp." + n
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
func targetAddress(ctx context.Context, query DNSQuery, target string) (netip.Addr, error) {
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

// zoneApex returns the apex of the closest DNS zone enclosing name, following RFC 8765
// S6.1 steps 1-4, which RFC 9665 S3.1.1 points to: query SOA for name; an SOA in the Answer
// section (name is itself an apex) or in the Authority section (a NODATA or NXDOMAIN
// answer) gives the apex as that SOA's owner name. A response with no SOA in either
// section means stripping the leading label and asking again, down to a two-label name --
// reaching a single label (a TLD) is a configuration error and ends the search. So is the
// root zone's SOA, which is what a resolver returns when name's TLD does not exist.
//
// RFC 9665 S3.1.1 starts from the names of the records being registered. Every one of them
// is a subdomain of the registration domain, and an SRP Update covers exactly one zone
// (S3.3), so starting from domain itself finds the same zone.
func zoneApex(ctx context.Context, query DNSQuery, name string) (string, error) {
	candidate := ensureFQDN(name)
	// Labels counts the empty root label too: "example.com." has 3, "com." has 2.
	for len(dnsname.Labels(candidate)) > 2 {
		resp, err := query(ctx, candidate, dns.TypeSOA)
		if err != nil {
			return "", err
		}
		soa := firstSOA(resp.Answer)
		if soa == nil {
			soa = firstSOA(resp.Ns)
		}
		if soa != nil {
			apex := ensureFQDN(soa.Hdr.Name)
			if apex == "." {
				return "", fmt.Errorf("no zone below the root encloses %s: the resolver answered with the root zone's SOA, so the top-level domain does not exist there", ensureFQDN(name))
			}
			return apex, nil
		}
		_, candidate, _ = dnsname.CutFirstLabel(candidate)
	}
	return "", fmt.Errorf("no SOA record found for %s or any parent name above the top-level domain (RFC 8765 S6.1 step 4)", ensureFQDN(name))
}

// registrarSearchNames returns the names Discover looks under for a "_dnssd-srp._tcp" SRV
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

func firstSOA(rrs []dns.RR) *dns.SOA {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

func ensureFQDN(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
