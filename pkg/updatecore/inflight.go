package updatecore

import (
	"context"
	"fmt"
	"sync"
)

// DefaultMaxInflightUpdates is BIND 9.20's default sig0checks-quota -- see
// SetMaxInflightUpdates.
const DefaultMaxInflightUpdates = 1

// inflightUpdates caps how many UPDATEs this process has in flight to each authoritative
// server at once. It is process-wide on purpose: each handler builds its own Coordinator,
// several of them can send to the same server, and the quota it protects is that server's.
var inflightUpdates = newInflightLimiter(DefaultMaxInflightUpdates)

type inflightLimiter struct {
	mu    sync.Mutex
	max   int                      // 0: no limit
	slots map[string]chan struct{} // server "host:port" -> its slots, created on first use
}

func newInflightLimiter(max int) *inflightLimiter {
	return &inflightLimiter{max: max, slots: make(map[string]chan struct{})}
}

// SetMaxInflightUpdates sets how many UPDATEs this process may have in flight to one
// authoritative server at a time; 0 means no limit. Every UPDATE the proxy sends is
// SIG(0)-signed, and BIND 9.20 verifies at most sig0checks-quota SIG(0) signatures at a time
// (default 1), answering REFUSED -- not queueing -- a SIG(0) request that arrives while it is
// already at that quota. Set this to the upstream server's sig0checks-quota so the proxy never
// exceeds it on its own. BIND frees a slot only after sending its response, so a request sent
// the instant the previous one is answered can still very occasionally be refused; the lease
// expiry retry covers that, as it does REFUSED from other SIG(0) clients of the same server.
// Call once at startup, before any UPDATE is sent.
func SetMaxInflightUpdates(max int) error {
	if max < 0 {
		return fmt.Errorf("updatecore: max in-flight UPDATEs must be 0 (no limit) or more, got %d", max)
	}
	inflightUpdates.mu.Lock()
	defer inflightUpdates.mu.Unlock()
	inflightUpdates.max = max
	inflightUpdates.slots = make(map[string]chan struct{})
	return nil
}

// acquire waits for one of server's slots, or until ctx ends, and returns the function that
// gives the slot back.
func (l *inflightLimiter) acquire(ctx context.Context, server string) (release func(), err error) {
	l.mu.Lock()
	if l.max == 0 {
		l.mu.Unlock()
		return func() {}, nil
	}
	slots, ok := l.slots[server]
	if !ok {
		slots = make(chan struct{}, l.max)
		l.slots[server] = slots
	}
	l.mu.Unlock()

	select {
	case slots <- struct{}{}:
		return func() { <-slots }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for an in-flight UPDATE slot to %s: %w", server, ctx.Err())
	}
}
