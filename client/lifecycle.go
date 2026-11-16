package client

import (
	"context"
	"math/rand"
	"time"

	"codeberg.org/miekg/dns"
)

// Lifecycle is what keeps a requester's registration alive (Run): the lease it asks for, and
// how it waits and reports.
type Lifecycle struct {
	// RequestedLease is the refresh clock's lease when a response grants none (GrantedLease).
	RequestedLease uint32
	// Rng jitters the delays; it must not be shared across goroutines (see refreshDelay).
	Rng *rand.Rand
	// Sleep waits d, or until ctx ends (SleepContext).
	Sleep func(ctx context.Context, d time.Duration) error
	// OnError, if set, is called with every error a registration cycle hits. Run itself never
	// stops because of one, so this is the caller's only hook for surfacing those failures as
	// they happen.
	OnError func(error)
	// OnRegistered, if set, is called with the registrar's response after every successful
	// registration cycle, the first and each refresh alike: Run's success-path counterpart to
	// OnError.
	OnRegistered func(resp *dns.Msg)
}

// minRegisterRetryBackoff/maxRegisterRetryBackoff bound Run's retry-on-error backoff: it
// starts at minRegisterRetryBackoff, doubles after every consecutive failure up to
// maxRegisterRetryBackoff, and resets to minRegisterRetryBackoff after any success -- the
// same "don't hammer a struggling registrar, but don't wait an hour to notice it's back
// either" shape refreshDelay's own jitter serves for the steady-state clock.
const (
	minRegisterRetryBackoff = 5 * time.Second
	maxRegisterRetryBackoff = 5 * time.Minute
)

// Run keeps a registration alive: an initial 0-3s random delay, then register, then a sleep
// for the RFC 9664 S5.2 refresh clock (80% of the granted lease + 0-5% jitter), and register
// again -- restating the full registration every time, as RFC 9665 S3.2 has SRP do ("no
// lightweight refresh") and RFC 9664 S5.2 has a refresh do. It blocks until ctx is canceled
// (Sleep returning ctx.Err()), the only thing that stops it.
//
// A failed registration -- a transient network/DNS error, a registrar rejection, a name
// another key holds -- does not stop Run: OnError is called with the error, and register is
// tried again after an exponentially increasing backoff (minRegisterRetryBackoff up to
// maxRegisterRetryBackoff), reset to the minimum after any success. A single transient blip
// during a routine refresh -- one UDP timeout, one SERVFAIL -- must not permanently stop a
// long-running daemon's registration.
func (l Lifecycle) Run(ctx context.Context, register func(context.Context) (*dns.Msg, error)) error {
	if err := l.Sleep(ctx, initialDelay(l.Rng)); err != nil {
		return err
	}

	backoff := minRegisterRetryBackoff
	for {
		resp, err := register(ctx)
		if err != nil {
			if l.OnError != nil {
				l.OnError(err)
			}
			if sleepErr := l.Sleep(ctx, backoff); sleepErr != nil {
				return sleepErr
			}
			if backoff *= 2; backoff > maxRegisterRetryBackoff {
				backoff = maxRegisterRetryBackoff
			}
			continue
		}
		backoff = minRegisterRetryBackoff

		if l.OnRegistered != nil {
			l.OnRegistered(resp)
		}

		lease, _, ok := GrantedLease(resp)
		if !ok {
			lease = l.RequestedLease
		}

		if err := l.Sleep(ctx, refreshDelay(l.Rng, lease)); err != nil {
			return err
		}
	}
}

// SleepContext is context.Context.Done()-aware time.Sleep: it returns ctx.Err() if ctx is
// canceled before d elapses, nil once d elapses normally.
func SleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// minRefreshDelay floors refreshDelay's result so a registrar that grants (or a response
// that is misparsed as) a near-zero LEASE cannot drive Run into a tight re-registration
// busy-loop -- 80% of a 0-second lease is 0, with no jitter to save it.
const minRefreshDelay = 1 * time.Second

// refreshDelay implements RFC 9664 S5.2's baseline refresh clock (a MUST, reused by SRP):
// 80% of the granted lease, plus a 0-5% random offset -- "the requester computes
// expiry from send time," so this is meant to be added to the moment the request that
// granted leaseSeconds was sent, not to "now" if some processing time has already elapsed.
// rng must be non-nil and must not be shared across goroutines -- each requester gets its
// own, never a shared package-level one.
func refreshDelay(rng *rand.Rand, leaseSeconds uint32) time.Duration {
	lease := time.Duration(leaseSeconds) * time.Second
	base := lease * 80 / 100
	jitter := time.Duration(rng.Float64() * 0.05 * float64(lease))
	d := base + jitter
	if d < minRefreshDelay {
		d = minRefreshDelay
	}
	return d
}

// initialDelay returns the "initial 0-3s random delay" -- a first-registration
// anti-thundering-herd jitter, distinct from (and only applied once, before) the ongoing
// refreshDelay clock.
func initialDelay(rng *rand.Rand) time.Duration {
	return time.Duration(rng.Float64() * float64(3*time.Second))
}
