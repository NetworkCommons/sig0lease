package dnsmsg

import (
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// AddressRR returns owner's address record for addr, class IN: an A for an IPv4 address, an
// AAAA for an IPv6 one.
func AddressRR(owner string, addr netip.Addr, ttl uint32) dns.RR {
	hdr := dns.Header{Name: owner, Class: dns.ClassINET, TTL: ttl}
	if addr.Is4() {
		return &dns.A{Hdr: hdr, A: rdata.A{Addr: addr}}
	}
	return &dns.AAAA{Hdr: hdr, AAAA: rdata.AAAA{Addr: addr}}
}
