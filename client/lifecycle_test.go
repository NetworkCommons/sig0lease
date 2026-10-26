package client

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client/clienttest"
)

func TestRefreshDelay_WithinRFC9664S52Bounds(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const lease = uint32(3600)
	minWant := time.Duration(lease) * time.Second * 80 / 100
	maxWant := minWant + time.Duration(float64(time.Duration(lease)*time.Second)*0.05)

	for i := 0; i < 100; i++ {
		got := refreshDelay(rng, lease)
		if got < minWant || got > maxWant {
			t.Fatalf("refreshDelay(%d) = %v, want in [%v, %v]", lease, got, minWant, maxWant)
		}
	}
}

func TestRefreshDelay_ZeroLease(t *testing.T) {
	// A 0 (or near-0) granted lease must not drive Client.Run into a zero-delay
	// re-registration busy-loop: refreshDelay floors at minRefreshDelay instead of
	// returning 0.
	rng := rand.New(rand.NewSource(1))
	if got := refreshDelay(rng, 0); got != minRefreshDelay {
		t.Fatalf("refreshDelay(0) = %v, want %v (the floor)", got, minRefreshDelay)
	}
}

func TestInitialDelay_WithinZeroToThreeSeconds(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 100; i++ {
		got := initialDelay(rng)
		if got < 0 || got > 3*time.Second {
			t.Fatalf("initialDelay() = %v, want in [0, 3s]", got)
		}
	}
}

// TestLifecycle_Run_BackoffDoublesOnConsecutiveFailuresThenResets pins the shape of Run's
// retry backoff: it starts at minRegisterRetryBackoff, doubles on each consecutive
// failure, and resets back to the minimum the moment a cycle succeeds -- so the steady
// -state refresh clock after a recovery is the normal S5.2 clock, not a leftover
// multi-minute backoff from the outage that just ended.
func TestLifecycle_Run_BackoffDoublesOnConsecutiveFailuresThenResets(t *testing.T) {
	granted := clienttest.Granted(30, 1209600)
	results := []error{errors.New("SERVFAIL"), errors.New("SERVFAIL"), nil}
	register := func(context.Context) (*dns.Msg, error) {
		err := results[0]
		results = results[1:]
		if err != nil {
			return nil, err
		}
		return granted, nil
	}

	var sleeps []time.Duration
	var gotErrs []error
	l := Lifecycle{
		RequestedLease: 3600,
		Rng:            rand.New(rand.NewSource(1)),
		Sleep: func(ctx context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			if len(sleeps) >= 4 { // initial delay + 2 backoffs + 1 post-success refresh sleep
				return context.Canceled
			}
			return nil
		},
		OnError: func(err error) { gotErrs = append(gotErrs, err) },
	}
	if err := l.Run(context.Background(), register); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Run to stop via Sleep/ctx cancellation, got: %v", err)
	}
	if len(gotErrs) != 2 {
		t.Fatalf("expected exactly 2 OnError calls (for the 2 failed cycles), got %d: %v", len(gotErrs), gotErrs)
	}
	if len(sleeps) != 4 {
		t.Fatalf("expected 4 sleeps (initial, 2 backoffs, 1 refresh), got %d: %v", len(sleeps), sleeps)
	}
	if sleeps[1] != minRegisterRetryBackoff {
		t.Fatalf("first retry backoff = %v, want %v (the floor)", sleeps[1], minRegisterRetryBackoff)
	}
	if sleeps[2] != minRegisterRetryBackoff*2 {
		t.Fatalf("second retry backoff = %v, want %v (doubled)", sleeps[2], minRegisterRetryBackoff*2)
	}
	wantRefreshMin := 30 * time.Second * 80 / 100
	if sleeps[3] < wantRefreshMin || sleeps[3] > 30*time.Second {
		t.Fatalf("post-success sleep = %v, want the granted 30s lease's refresh clock (the reset, not another backoff)", sleeps[3])
	}
}
