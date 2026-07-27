// Package main implements a minimal dig replacement for testing.
//
// This tool queries a specific nameserver for a given record type and
// prints the answer section in a simple format suitable for test scripts.
//
// Usage:
//
//	go build ./cmd/simpledig
//	./simpledig @nameserver name rr_type
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"codeberg.org/miekg/dns"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: simpledig @server name rr_type\n")
		os.Exit(1)
	}

	server := os.Args[1]
	// Strip leading @ prefix used in dig syntax
	if len(server) > 0 && server[0] == '@' {
		server = server[1:]
	}
	// Default to port 53 if no port specified
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}

	name := os.Args[2]
	rrTypeStr := os.Args[3]

	// Parse RR type
	rrType, ok := dns.StringToType[rrTypeStr]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown RR type: %s\n", rrTypeStr)
		os.Exit(1)
	}

	// Build query using NewMsg (which fully qualifies the name)
	msg := dns.NewMsg(name, rrType)
	if msg == nil {
		fmt.Fprintf(os.Stderr, "Could not create message for type %s\n", rrTypeStr)
		os.Exit(1)
	}

	// Send query with timeout
	c := dns.NewClient()
	c.Transport = dns.NewTransport()
	c.Transport.Dialer = &net.Dialer{Timeout: 3 * time.Second}
	c.Transport.ReadTimeout = 3 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	r, _, err := c.Exchange(ctx, msg, "udp", server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Query failed: %v\n", err)
		os.Exit(1)
	}

	if r.Rcode != dns.RcodeSuccess {
		fmt.Fprintf(os.Stderr, "Server returned: %s\n", dns.RcodeToString[r.Rcode])
		os.Exit(1)
	}

	// Print answer records
	for _, rr := range r.Answer {
		fmt.Println(rr.String())
	}

	// Print extra records (used by dump queries for TXT data)
	for _, rr := range r.Extra {
		fmt.Println(rr.String())
	}
}
