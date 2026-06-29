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

	return &Client{
		server:    server,
		protocol:  protocol,
		timeout:   timeout,
		dnsClient: dns.NewClient(),
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

	// Receive the response
	buf := make([]byte, 512)
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
	ctx := context.Background()
	resp, _, err := c.dnsClient.Exchange(ctx, msg, "tcp", c.server)
	return resp, err
}

// QueryWithTimeout sends a DNS query with a custom timeout.
func (c *Client) QueryWithTimeout(msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	oldTimeout := c.timeout
	c.timeout = timeout
	defer func() { c.timeout = oldTimeout }()

	return c.Query(msg)
}

// QueryMultiple sends queries to multiple servers and returns the first response.
func (c *Client) QueryMultiple(msg *dns.Msg, servers []string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	errCh := make(chan error, len(servers))
	respCh := make(chan *dns.Msg, 1)

	for _, server := range servers {
		go func(s string) {
			msgCopy := msg.Copy()
			resp, err := c.Query(msgCopy)
			if err != nil {
				errCh <- fmt.Errorf("%s: %w", s, err)
				return
			}
			select {
			case respCh <- resp:
			default:
				// Another server already responded
			}
		}(server)
	}

	var lastErr error

	for range servers {
		select {
		case resp := <-respCh:
			return resp, nil //Success! Return immediately.
		case err := <-errCh:
			lastErr = err // Track the error, but keep waiting for others
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for response: %w", ctx.Err())
		}
	}
	// If we exit the loop, it means every single server sent an error to errCh
	return nil, fmt.Errorf("all %d servers failed. Last error: %w", len(servers), lastErr)
}

// MakeQuery creates a standard DNS query message.
func MakeQuery(name string, qtype uint16, opcode uint8) *dns.Msg {
	// Create base message with the question
	m := dns.NewMsg(name, qtype)
	if m == nil {
		return nil
	}

	m.Opcode = opcode

	// Set the Rcode to 0 (NOERROR) - for queries this is standard
	m.Rcode = 0

	return m
}

// MakeStatusQuery creates a STATUS query (opcode 2).
func MakeStatusQuery(serverName string) *dns.Msg {
	if serverName == "" {
		serverName = "."
	}
	// Create message with ANY type
	m := dns.NewMsg(serverName, dns.TypeANY)
	if m == nil {
		return nil
	}
	m.Opcode = dns.OpcodeStatus
	return m
}

// MakeUpdateQuery creates an UPDATE query (opcode 5).
func MakeUpdateQuery(zone string, rr dns.RR) *dns.Msg {
	// Create message with SOA type
	m := dns.NewMsg(zone, dns.TypeSOA)
	if m == nil {
		return nil
	}
	m.Opcode = dns.OpcodeUpdate

	// Add zone section to Ns (authority)
	if rr != nil {
		m.Ns = append(m.Ns, rr)
	}

	return m
}

// QueryWithOpcode sends a query with the specified opcode.
func (c *Client) QueryWithOpcode(name string, qtype uint16, opcode uint8) (*dns.Msg, error) {
	msg := MakeQuery(name, qtype, opcode)
	return c.Query(msg)
}
