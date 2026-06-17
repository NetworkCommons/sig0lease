// Package forward implements DNS forwarding to upstream resolvers.
package forward

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
)

// Result represents the outcome of a forwarded query.
type Result struct {
	Response *dns.Msg
	Error    error
}

// Resolver forwards DNS queries to upstream servers.
type Resolver struct {
	servers  []string
	protocol string
	timeout  time.Duration
	dialer   *net.Dialer
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
}

// NewResolver creates a new DNS resolver that forwards to upstream servers.
func NewResolver(servers []string, protocol string, timeout time.Duration) (*Resolver, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("at least one upstream server required")
	}
	if protocol == "" {
		protocol = "udp"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Resolver{
		servers:  servers,
		protocol: protocol,
		timeout:  timeout,
		dialer:   &net.Dialer{Timeout: timeout},
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// Query sends a DNS query to all upstream servers and returns the first response.
func (r *Resolver) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	r.mu.Lock()
	servers := make([]string, len(r.servers))
	copy(servers, r.servers)
	r.mu.Unlock()

	resultCh := make(chan Result, len(servers))

	// Send queries concurrently to all upstreams
	for _, server := range servers {
		r.wg.Add(1)
		go func(addr string) {
			defer r.wg.Done()
			resp, err := r.exchangeWithContext(ctx, msg, addr)
			resultCh <- Result{Response: resp, Error: err}
		}(server)
	}

	// Collect responses until we get one or all fail
	ctxDone := ctx.Done()
	timeout := time.After(r.timeout)

	for i := 0; i < len(servers); i++ {
		select {
		case result := <-resultCh:
			if result.Error == nil && result.Response != nil {
				return result.Response, nil
			}
		case <-timeout:
			return nil, fmt.Errorf("query timeout")
		case <-ctxDone:
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("all upstreams failed")
}

// exchangeWithContext performs a DNS exchange with context cancellation support.
func (r *Resolver) exchangeWithContext(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	done := make(chan Result, 1)

	go func() {
		resp, err := r.exchange(ctx, server, msg)
		done <- Result{Response: resp, Error: err}
	}()

	select {
	case result := <-done:
		return result.Response, result.Error
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(r.timeout):
		return nil, fmt.Errorf("query timeout to %s", server)
	}
}

// exchange performs a single DNS exchange with an upstream server.
func (r *Resolver) exchange(ctx context.Context, server string, msg *dns.Msg) (*dns.Msg, error) {
	network := r.protocol
	if network == "" || network == "udp" {
		network = "udp"
	}
	resp, err := dns.Exchange(ctx, msg, network, server)
	if err != nil {
		return nil, fmt.Errorf("exchange to %s failed: %w", server, err)
	}
	return resp, nil
}

// extractDomain extracts the domain name from an address.
func extractDomain(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// Shutdown gracefully stops the resolver.
func (r *Resolver) Shutdown() {
	r.cancel()
	r.wg.Wait()
}

// SetServers updates the upstream server list.
func (r *Resolver) SetServers(servers []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.servers = make([]string, len(servers))
	copy(r.servers, servers)
}
