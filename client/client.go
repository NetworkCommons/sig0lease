// Package client provides DNS query functionality for testing and client use.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
)

// Client represents a DNS client for sending queries.
type Client struct {
	server     string
	protocol   string
	timeout    time.Duration
	dnsClient  *dns.Client
	httpClient *http.Client // "doh" only
}

// New creates a new DNS client. protocol is "udp" (the default), "tcp", "tls" for
// DNS-over-TLS (RFC 7858) with the Opportunistic Privacy profile (see opportunisticTLS), or
// "doh" for DNS-over-HTTPS (RFC 8484), where server is a URL (Network.CheckServer).
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
	if protocol == "tls" {
		// With a TLSConfig, the transport dials TLS over the "tcp" network queryTCP asks
		// for: DoT is the TCP exchange inside TLS.
		dnsClient.Transport.TLSConfig = opportunisticTLS()
	}

	c := &Client{
		server:    server,
		protocol:  protocol,
		timeout:   timeout,
		dnsClient: dnsClient,
	}
	if protocol == "doh" {
		// An https server's certificate is not checked, as with "tls": the same
		// Opportunistic Privacy profile. Each exchange has its connection to itself, as
		// over TCP: a Client lives for one exchange (LiveTransport), and a kept-alive
		// connection would outlive it. In a browser (GOOS=js), net/http sends through
		// fetch, which ignores this configuration, checks certificates and manages
		// connections itself.
		c.httpClient = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				ForceAttemptHTTP2: true,
				DisableKeepAlives: true,
			},
		}
	}
	return c
}

// Query sends a DNS query and returns the response.
func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error) {
	switch c.protocol {
	case "tcp", "tls":
		return c.queryTCP(msg)
	case "udp":
		return c.queryUDP(msg)
	case "doh":
		return c.queryDoH(msg)
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

// opportunisticTLS is the TLS configuration for "tls": DNS-over-TLS with RFC 7858 S4.1's
// Opportunistic Privacy profile. For SRP it is the only profile RFC 9665 S7 uses, since there
// is no way to share a registrar's key with its requesters, and the proxy's DoT listener
// offers nothing else either. The server's certificate is not checked, so the connection is
// encrypted but the server is not authenticated: it protects against passive eavesdroppers,
// not against an active attacker in the path. NextProtos offers the "dot" ALPN identifier
// the proxy's own DoT listener advertises (server/transport_tls.go).
func opportunisticTLS() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         dns.NextProtos,
	}
}

// queryTCP sends a DNS query over TCP, or over TLS when New configured the transport for
// "tls".
func (c *Client) queryTCP(msg *dns.Msg) (*dns.Msg, error) {
	// Use miekg/dns client for TCP - Exchange returns (msg, rtt, err)
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	resp, _, err := c.dnsClient.Exchange(ctx, msg, "tcp", c.server)
	return resp, err
}

// queryDoH sends a DNS message to the server URL's "/dns-query" (RFC 8484): a query as a GET,
// with the message in its "dns" parameter, anything else, an UPDATE, as a POST. A GET has no
// body and no Content-Type, so a browser sends it to a server of another origin without asking
// first whether it may (a CORS preflight), which a public resolver such as dns.google does not
// answer; the proxy answers both. The message goes as packed, its ID included: a SIG(0)
// signature covers the ID, so it cannot be set to 0 after signing, as RFC 8484 S4.1 suggests
// for caching, and a query's random ID keeps any HTTP cache on the way from answering it.
// Anything but a 200 answer with a DNS message is an error.
func (c *Client) queryDoH(msg *dns.Msg) (*dns.Msg, error) {
	if err := msg.Pack(); err != nil {
		return nil, fmt.Errorf("pack error: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	url := strings.TrimSuffix(c.server, "/") + dnshttp.Path
	var req *http.Request
	var err error
	if msg.Opcode == dns.OpcodeQuery {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, url+"?dns="+base64.RawURLEncoding.EncodeToString(msg.Data), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(msg.Data))
		if err == nil {
			req.Header.Set("Content-Type", dnshttp.MimeType)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	req.Header.Set("Accept", dnshttp.MimeType)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection error: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("doh: %s answered %s", c.server, resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); ct != dnshttp.MimeType {
		resp.Body.Close()
		return nil, fmt.Errorf("doh: %s answered Content-Type %q, want %s", c.server, ct, dnshttp.MimeType)
	}
	reply, err := dnshttp.Response(resp)
	if err != nil {
		return nil, fmt.Errorf("unpack error: %w", err)
	}
	return reply, nil
}
