package client

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"codeberg.org/miekg/dns"
)

// Network is how a requester reaches its registrar: an SRP registrar (client/srp) or this
// proxy's RFC 9664 handler (client/rfc9664).
type Network int

const (
	// NetworkTCP, the default, is plain DNS over TCP, which RFC 9665 S3.5 requires on
	// networks that are not constrained.
	NetworkTCP Network = iota
	// NetworkTLS is DNS-over-TLS (RFC 7858). The registrar's certificate is not checked:
	// RFC 9665 S7 has no way to share the registrar's key, so TLS gives Opportunistic
	// Privacy only (RFC 7858 S4.1). SRP discovery then looks for the "_dnssd-srp-tls._tcp"
	// SRV record instead of "_dnssd-srp._tcp" (client/srp.DiscoveryService), and nothing
	// falls back to plain TCP (S7: a requester able to use TLS SHOULD NOT).
	NetworkTLS
	// NetworkUDP is for constrained networks (RFC 9665 S3.1.2): a registrar accepts it only
	// where it allows UDP.
	NetworkUDP
	// NetworkDoH is DNS-over-HTTPS (RFC 8484), the one DNS transport a web browser has, or
	// the same over plain HTTP: the registrar is a URL ("https://host:port"), not
	// "host:port" (CheckServer). An https registrar's certificate is not checked, as with
	// NetworkTLS. RFC 9665 names no DoH service, so an SRP registrar reached over DoH is
	// never discovered: it must be given.
	NetworkDoH
)

// networks lists every Network, in the order ParseNetwork's error names them.
var networks = []Network{NetworkTCP, NetworkUDP, NetworkTLS, NetworkDoH}

// ParseNetwork returns the Network whose String is s: "tcp", "udp", "tls" or "doh".
func ParseNetwork(s string) (Network, error) {
	for _, n := range networks {
		if s == n.String() {
			return n, nil
		}
	}
	return 0, fmt.Errorf("%q: want tcp, udp, tls or doh", s)
}

// MarshalText and UnmarshalText write and read n as its String, as in a JSON document.
func (n Network) MarshalText() ([]byte, error) { return []byte(n.String()), nil }

func (n *Network) UnmarshalText(b []byte) (err error) {
	*n, err = ParseNetwork(string(b))
	return err
}

// String returns the protocol name New takes for n.
func (n Network) String() string {
	switch n {
	case NetworkTCP:
		return "tcp"
	case NetworkTLS:
		return "tls"
	case NetworkUDP:
		return "udp"
	case NetworkDoH:
		return "doh"
	default:
		return fmt.Sprintf("Network(%d)", int(n))
	}
}

// Validate reports whether n is one of the Networks above.
func (n Network) Validate() error {
	switch n {
	case NetworkTCP, NetworkTLS, NetworkUDP, NetworkDoH:
		return nil
	}
	return fmt.Errorf("unknown Network %d", n)
}

// CheckServer reports whether s can be a registrar's address over n: for NetworkDoH an http
// or https URL with a host and no path (the requests go to its "/dns-query", RFC 8484 S6),
// for the others "host:port".
func (n Network) CheckServer(s string) error {
	if n != NetworkDoH {
		return CheckHostPort(s)
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("%q: want an http or https URL with no path, such as https://host:port", s)
	}
	return nil
}

// CheckHostPort reports whether s is "host:port", with a numeric port.
func CheckHostPort(s string) error {
	_, port, err := net.SplitHostPort(s)
	if err == nil {
		_, err = strconv.ParseUint(port, 10, 16)
	}
	if err != nil {
		return fmt.Errorf("%q: want host:port", s)
	}
	return nil
}

// Transport sends a signed UPDATE to addr over network and returns the response. Requesters
// default to LiveTransport; tests inject a fake.
type Transport func(ctx context.Context, addr string, network Network, msg *dns.Msg) (*dns.Msg, error)

// LiveTransport sends msg to addr over network with this package's Client, the same transport
// every other client and test tool in this codebase uses.
func LiveTransport(timeout time.Duration) Transport {
	return func(ctx context.Context, addr string, network Network, msg *dns.Msg) (*dns.Msg, error) {
		return New(addr, network.String(), timeout).Query(msg)
	}
}
