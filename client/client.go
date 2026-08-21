// Package client provides DNS query functionality for testing and client use.
package client

import (
	"context"
	"fmt"
	"net"
	"time"

	"codeberg.org/miekg/dns"
)

// Client represents a DNS client for sending queries.
type Client struct {
	server    string
	protocol  string
	timeout   time.Duration
	dnsClient *dns.Client
}

// New creates a new DNS client.
func New(server string, protocol string, timeout time.Duration) *Client {
	if protocol == "" {
		protocol = "udp"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// dns.NewClient()'s transport otherwise carries its own hardcoded
	// defaults (2s read/write, 5s dial) regardless of what the caller asked
	// for here; wire the requested timeout through so it actually governs
	// the TCP path (queryUDP already applies it via a socket deadline).
	dnsClient := dns.NewClient()
	dnsClient.Transport = &dns.Transport{
		Dialer:       &net.Dialer{Timeout: timeout},
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}

	return &Client{
		server:    server,
		protocol:  protocol,
		timeout:   timeout,
		dnsClient: dnsClient,
	}
}

// Query sends a DNS query and returns the response.
func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {
	switch c.protocol {
	case "tcp":
		return c.queryTCP(msg)
	case "udp":
		return c.queryUDP(msg)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", c.protocol)
	}
}

// queryUDP sends a DNS query over UDP.
func (c *Client) queryUDP(msg *dns.Msg) (*dns.Msg, error) {
	// Extract server host and port
	host, port, err := net.SplitHostPort(c.server)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}

	// If no port specified, use default DNS port
	if port == "" {
		host = net.JoinHostPort(host, "53")
	} else {
		// Rejoin host and port for the dial
		host = net.JoinHostPort(host, port)
	}

	// Get a UDP connection
	conn, err := net.DialTimeout("udp", host, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("connection error: %w", err)
	}
	defer conn.Close()

	// Set deadline for the operation
	deadline := time.Now().Add(c.timeout)
	conn.SetDeadline(deadline)

	// Encode the message
	err = msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack error: %w", err)
	}

	// Send the message
	if _, err = conn.Write(msg.Data); err != nil {
		return nil, fmt.Errorf("write error: %w", err)
	}

	// Receive the response. The request above advertises an EDNS UDP
	// payload size of dns.DefaultMsgSize via its OPT record (see
	// dnsmsg.NewLeaseUpdate), so a reply within that negotiated size must be
	// read whole; sizing this buffer at the historic pre-EDNS 512-byte limit
	// silently truncated any larger response (e.g. a Case C delete with
	// several status-note TXT records, or a large RSA KEY answer), corrupting
	// or failing to unpack it. dns.MaxMsgSize covers any negotiated size.
	buf := make([]byte, dns.MaxMsgSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}

	// Parse the response - Unpack needs Data to be allocated
	resp := new(dns.Msg)
	resp.Data = make([]byte, n)
	copy(resp.Data, buf[:n])
	if err = resp.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack error: %w", err)
	}

	return resp, nil
}

// queryTCP sends a DNS query over TCP.
func (c *Client) queryTCP(msg *dns.Msg) (*dns.Msg, error) {
	// Use miekg/dns client for TCP - Exchange returns (msg, rtt, err)
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	resp, _, err := c.dnsClient.Exchange(ctx, msg, "tcp", c.server)
	return resp, err
}
