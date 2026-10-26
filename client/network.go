package client

import (
	"context"
	"fmt"
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
)

// ParseNetwork returns the Network whose String is s: "tcp", "udp" or "tls".
func ParseNetwork(s string) (Network, error) {
	for _, n := range []Network{NetworkTCP, NetworkUDP, NetworkTLS} {
		if s == n.String() {
			return n, nil
		}
	}
	return 0, fmt.Errorf("%q: want tcp, udp or tls", s)
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
	default:
		return fmt.Sprintf("Network(%d)", int(n))
	}
}

// Validate reports whether n is one of the Networks above.
func (n Network) Validate() error {
	switch n {
	case NetworkTCP, NetworkTLS, NetworkUDP:
		return nil
	}
	return fmt.Errorf("unknown Network %d", n)
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
