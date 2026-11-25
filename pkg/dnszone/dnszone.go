// Package dnszone finds the zone that holds a name by asking resolvers: RFC 8765 S6.1's
// discovery, which RFC 9665 S3.1.1 points SRP requesters to (client/srp), and which the proxy's
// handlers use to find the zone their UPDATEs name and its primary server (pkg/updatecore).
package dnszone

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
)

// Query is the shape of a DNS lookup, injected so its callers are testable without real
// network I/O. It returns the whole response, since discovery reads both the Answer section
// (an SOA at a zone apex) and the Authority section (the SOA a negative answer carries). A
// NOERROR or NXDOMAIN response is an answer, not an error.
type Query func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)

// Resolvers returns the Query that asks resolvers ("host:port", over UDP) in turn until one
// answers with NOERROR or NXDOMAIN, and returns that answer. Any other RCODE (SERVFAIL,
// REFUSED, ...) counts as that resolver failing, like a network error; when every resolver
// fails, the error gives each one's failure.
func Resolvers(resolvers []string) Query {
	return func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		req := dns.NewMsg(name, qtype)
		if req == nil {
			return nil, fmt.Errorf("failed to build %s query for %s", dnsutil.TypeToString(qtype), name)
		}
		if len(resolvers) == 0 {
			return nil, fmt.Errorf("%s query for %s: no resolvers to ask", dnsutil.TypeToString(qtype), name)
		}
		var failed failures
		for _, resolver := range resolvers {
			resp, err := dns.Exchange(ctx, req, "udp", resolver)
			if err != nil {
				failed = append(failed, fmt.Errorf("resolver %s: %w", resolver, err))
				continue
			}
			if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
				failed = append(failed, fmt.Errorf("resolver %s answered %s", resolver, dnsutil.RcodeToString(resp.Rcode)))
				continue
			}
			return resp, nil
		}
		return nil, fmt.Errorf("%s query for %s failed against all resolvers: %w", dnsutil.TypeToString(qtype), name, failed)
	}
}

// failures is every resolver's failure to answer one query, in the order they were asked.
type failures []error

func (f failures) Error() string {
	texts := make([]string, len(f))
	for i, err := range f {
		texts[i] = err.Error()
	}
	return strings.Join(texts, "; ")
}

func (f failures) Unwrap() []error { return f }

// Apex returns the SOA of the closest zone enclosing name: its owner is the zone's apex, its
// MNAME the zone's primary server. It follows RFC 8765 S6.1 steps 1-4: query SOA for name; an
// SOA in the Answer section (name is itself an apex) or in the Authority section (a NODATA or
// NXDOMAIN answer) is the one. A response with no SOA in either section -- a resolver need
// not put the SOA in a negative answer, and Google Public DNS at times leaves it out -- means
// stripping the leading label and asking again, down to a two-label name: reaching a single
// label (a TLD) is a configuration error and ends the search. So is the root zone's SOA,
// which is what a resolver returns when name's TLD does not exist, and an SOA of a zone that
// does not enclose name. A failed query ends the search with its error.
func Apex(ctx context.Context, query Query, name string) (*dns.SOA, error) {
	fqdn := dnsutil.Fqdn(name)
	candidate := fqdn
	// Labels counts the empty root label too: "example.com." has 3, "com." has 2.
	for len(dnsname.Labels(candidate)) > 2 {
		resp, err := query(ctx, candidate, dns.TypeSOA)
		if err != nil {
			return nil, err
		}
		soa := firstSOA(resp.Answer)
		if soa == nil {
			soa = firstSOA(resp.Ns)
		}
		if soa != nil {
			apex := dnsutil.Fqdn(soa.Hdr.Name)
			if apex == "." {
				return nil, fmt.Errorf("no zone below the root encloses %s: the resolver answered with the root zone's SOA, so the top-level domain does not exist there", fqdn)
			}
			if !dnsname.IsAtOrBelow(fqdn, apex) {
				return nil, fmt.Errorf("the resolver answered the SOA query for %s with the SOA of %s, a zone that does not enclose %s", candidate, apex, fqdn)
			}
			return soa, nil
		}
		_, candidate, _ = dnsname.CutFirstLabel(candidate)
	}
	return nil, errors.New("no SOA record found for " + fqdn + " or any parent name above the top-level domain (RFC 8765 S6.1 step 4)")
}

func firstSOA(rrs []dns.RR) *dns.SOA {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}
