package rfc9664

import (
	"fmt"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// ParseRecords reads specs as records of name, the fully qualified name, the way a template's
// records: and sig0lease-client name's -record give them: "<owner> <type> <data>", the owner
// @ for name itself or relative to it (_dnslink, www), the data in zone-file format. A record
// must be one CheckRecords takes, not an A or AAAA at name, whose addresses are given apart
// (WithAddresses), and given once. It returns the records it read, in order, and calls bad
// with the index of each spec it could not read and why.
func ParseRecords(name string, specs []string, bad func(i int, err error)) []dns.RR {
	var records []dns.RR
	seen := map[string]bool{}
	for i, spec := range specs {
		rr, err := parseRecord(name, spec)
		if err != nil {
			bad(i, err)
			continue
		}
		key := leasepkg.RecordKey(rr)
		if seen[key] {
			bad(i, fmt.Errorf("%q twice", spec))
			continue
		}
		seen[key] = true
		records = append(records, rr)
	}
	return records
}

func parseRecord(name, spec string) (dns.RR, error) {
	spec = strings.TrimSpace(spec)
	rel, rest, _ := strings.Cut(spec, " ")
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return nil, fmt.Errorf("%q: want <owner> <type> <data>, the owner @ for the name or relative to it", spec)
	}
	if strings.HasSuffix(rel, ".") {
		return nil, fmt.Errorf("%q: owner %s: relative to the name (@ for the name itself), not fully qualified", spec, rel)
	}
	owner := name
	if rel != "@" {
		owner = rel + "." + name
	}
	rr, err := dns.New(owner + " " + rest)
	if err != nil {
		return nil, fmt.Errorf("%q: %v", spec, err)
	}
	if err := CheckRecords(name, []dns.RR{rr}); err != nil {
		return nil, fmt.Errorf("%q: %v", spec, err)
	}
	switch rr.(type) {
	case *dns.A, *dns.AAAA:
		if dnsname.EqualFold(owner, name) {
			return nil, fmt.Errorf("%q: an address of the name itself: give it with the name's addresses", spec)
		}
	}
	return rr, nil
}

// WithAddresses returns what name registers: an A or AAAA record at name for each of addrs,
// then records.
func WithAddresses(name string, addrs []netip.Addr, records []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(addrs)+len(records))
	for _, addr := range addrs {
		out = append(out, dnsmsg.AddressRR(name, addr, 0))
	}
	return append(out, records...)
}
