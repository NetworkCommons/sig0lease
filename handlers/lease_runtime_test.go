package handlers

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// stoppableLeaseManager wraps *leasepkg.InMemoryLeaseStore and overrides
// Stop() to record whether it was called, using the same
// embed-and-shadow pattern FileLeaseStore itself relies on.
type stoppableLeaseManager struct {
	*leasepkg.InMemoryLeaseStore
	stopped bool
}

func (s *stoppableLeaseManager) Stop() {
	s.stopped = true
}

func TestShutdown_StopsLeaseManager(t *testing.T) {
	for _, tc := range leaseHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			lm := &stoppableLeaseManager{InMemoryLeaseStore: leasepkg.NewInMemoryManager()}
			h, _ := tc.mustSetup(t, map[string]any{"lease_manager": lm})

			h.Shutdown()

			if !lm.stopped {
				t.Fatal("expected Shutdown() to call Stop() on the lease manager")
			}
		})
	}
}

// TestShutdown_SavesFileStore: a lease registered after the last periodic save is in the
// snapshot a restarted handler loads. The SRP handler used to have no Shutdown at all, so its
// file store never made its final save and lost up to save_interval of changes on every stop.
func TestShutdown_SavesFileStore(t *testing.T) {
	for _, tc := range leaseHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			storage := map[string]any{"storage": map[string]any{
				"type": "file", "path": filepath.Join(t.TempDir(), "leases.json"), "save_interval": "1h",
			}}
			key, err := keyrec.GenerateKey("shutdown-save."+tc.zone, dns.ECDSAP256SHA256, 0, 256)
			if err != nil {
				t.Fatal(err)
			}
			nodeKey := leasepkg.NodeKey(key.PublicKey)

			h1, s1 := tc.mustSetup(t, storage)
			if err := s1.leaseManager.RegisterWithParent("", key.PublicKey, 3600, 3600, tc.zone); err != nil {
				t.Fatalf("register: %v", err)
			}
			h1.Shutdown()

			_, s2 := tc.mustSetup(t, storage)
			if s2.leaseManager.Get(nodeKey) == nil {
				t.Fatal("the lease registered before Shutdown is missing after a restart from the same file")
			}
		})
	}
}

func TestShutdown_IsSafeToCallTwice(t *testing.T) {
	for _, tc := range leaseHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := tc.mustSetup(t, nil)
			h.Shutdown()
			h.Shutdown() // must not panic
		})
	}
}

// ownLockID gives a node its own id as its only lock id, for runtime tests without subtrees.
func ownLockID(nodeKey string) []string { return []string{nodeKey} }

func TestLeaseRuntime_ShutdownWaitsForRunningLeaseEvent(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var finished atomic.Bool
	r := newLeaseRuntime(ownLockID, func(ctx context.Context, nodeKey string) {
		close(started)
		<-release
		finished.Store(true)
	}, nil)
	lm := &stoppableLeaseManager{InMemoryLeaseStore: leasepkg.NewInMemoryManager()}
	r.leaseManager = lm

	go r.expireFunc("node")()
	<-started
	done := make(chan struct{})
	go func() { r.Shutdown(); close(done) }()
	select {
	case <-done:
		t.Fatal("Shutdown returned while a lease event was still running")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	<-done
	if !finished.Load() || !lm.stopped {
		t.Fatalf("after Shutdown: lease event finished=%v, store stopped=%v; want both", finished.Load(), lm.stopped)
	}
}

func TestLeaseRuntime_NoLeaseEventAfterShutdown(t *testing.T) {
	var events atomic.Int32
	r := newLeaseRuntime(ownLockID, func(ctx context.Context, nodeKey string) { events.Add(1) }, nil)
	r.timers.arm("node", time.Hour, r.expireFunc("node"))

	r.Shutdown()

	if r.timers.armed("node") {
		t.Error("Shutdown left a pending expiry timer")
	}
	r.expireFunc("node")() // a timer that fired just as Shutdown began
	if n := events.Load(); n != 0 {
		t.Fatalf("got %d lease event(s) after Shutdown, want none", n)
	}
}

func TestLeaseRuntime_ShutdownWaitsForPassThenStopsIt(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var passes atomic.Int32
	r := newLeaseRuntime(ownLockID, func(ctx context.Context, nodeKey string) {}, func(ctx context.Context) {
		if passes.Add(1) == 1 {
			close(started)
			<-release
		}
	})
	r.startLeaseReconciliation(5*time.Millisecond, logging.NewLogger("debug"))
	<-started

	done := make(chan struct{})
	go func() { r.Shutdown(); close(done) }()
	select {
	case <-done:
		t.Fatal("Shutdown returned while a reconciliation pass was still running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-done

	after := passes.Load()
	time.Sleep(30 * time.Millisecond) // several intervals
	if n := passes.Load(); n != after {
		t.Fatalf("%d reconciliation pass(es) ran after Shutdown returned", n-after)
	}
}

// TestLeaseRuntime_ShutdownCancelsRunningLeaseEvent: a lease event runs within expiryTimeout,
// and Shutdown cancels its context rather than waiting that out.
func TestLeaseRuntime_ShutdownCancelsRunningLeaseEvent(t *testing.T) {
	started := make(chan struct{})
	var ctxErr error
	var deadline time.Duration
	r := newLeaseRuntime(ownLockID, func(ctx context.Context, nodeKey string) {
		if dl, ok := ctx.Deadline(); ok {
			deadline = time.Until(dl)
		}
		close(started)
		<-ctx.Done()
		ctxErr = ctx.Err()
	}, nil)

	go r.expireFunc("node")()
	<-started
	r.Shutdown()

	if deadline <= 0 || deadline > expiryTimeout {
		t.Errorf("lease event deadline %s away, want within expiryTimeout (%s)", deadline, expiryTimeout)
	}
	if !errors.Is(ctxErr, context.Canceled) {
		t.Fatalf("lease event context ended with %v, want context.Canceled", ctxErr)
	}
}

// TestLeaseRuntime_ShutdownCancelsRunningPass: a reconciliation pass runs within
// reconcilePassTimeout, and Shutdown cancels its context rather than waiting that out.
func TestLeaseRuntime_ShutdownCancelsRunningPass(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	var ctxErr error
	var deadline time.Duration
	r := newLeaseRuntime(ownLockID, func(ctx context.Context, nodeKey string) {}, func(ctx context.Context) {
		once.Do(func() {
			if dl, ok := ctx.Deadline(); ok {
				deadline = time.Until(dl)
			}
			close(started)
			<-ctx.Done()
			ctxErr = ctx.Err()
		})
	})
	r.startLeaseReconciliation(5*time.Millisecond, logging.NewLogger("debug"))
	<-started
	r.Shutdown()

	if deadline <= 0 || deadline > reconcilePassTimeout {
		t.Errorf("pass deadline %s away, want within reconcilePassTimeout (%s)", deadline, reconcilePassTimeout)
	}
	if !errors.Is(ctxErr, context.Canceled) {
		t.Fatalf("pass context ended with %v, want context.Canceled", ctxErr)
	}
}

// TestLeaseRuntime_ShutdownStopsRetryOfCancelledLeaseEvent: a lease event cut short by
// Shutdown fails, and arms its retry (expiryTimers.finish) as any failed one does. Shutdown
// stops that timer too.
func TestLeaseRuntime_ShutdownStopsRetryOfCancelledLeaseEvent(t *testing.T) {
	started := make(chan struct{})
	var r *leaseRuntime
	r = newLeaseRuntime(ownLockID, func(ctx context.Context, nodeKey string) {
		close(started)
		<-ctx.Done()
		r.timers.arm(nodeKey, time.Hour, r.expireFunc(nodeKey))
	}, nil)

	go r.expireFunc("node")()
	<-started
	r.Shutdown()

	if r.timers.armed("node") {
		t.Fatal("Shutdown left the retry timer of the lease event it cancelled")
	}
}

// TestLeaseRuntime_PassArmsMissingTimerAndLogsError: a lease owner with no timer is left alone
// while its node locks are held -- whoever holds them may be about to arm it -- and once they
// are free it is logged as an error and armed.
func TestLeaseRuntime_PassArmsMissingTimerAndLogsError(t *testing.T) {
	r := newLeaseRuntime(ownLockID, func(ctx context.Context, nodeKey string) {}, nil)
	t.Cleanup(r.Shutdown)
	key, err := keyrec.GenerateKey("untimed.dev.zenr.io.", dns.ECDSAP256SHA256, 0, 256)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.leaseManager.RegisterWithParent("", key.PublicKey, 3600, 3600, "dev.zenr.io."); err != nil {
		t.Fatalf("register: %v", err)
	}
	nodeKey := leasepkg.NodeKey(key.PublicKey)

	// logging.NewLogger writes to the os.Stdout it finds when called, so swap a pipe in just
	// for the constructor.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = pw
	logger := logging.NewLogger("info")
	os.Stdout = stdout

	held, err := r.nodeLocks.TryAcquire(func() []string { return ownLockID(nodeKey) })
	if err != nil {
		t.Fatal(err)
	}
	r.reconcilePass(logger)
	if r.timers.armed(nodeKey) {
		t.Fatal("the pass armed a timer for a node whose locks were held")
	}
	held.Release()
	r.reconcilePass(logger)
	if !r.timers.armed(nodeKey) {
		t.Fatal("the pass did not arm the missing timer once the node's locks were free")
	}
	r.reconcilePass(logger) // the timer is there now: nothing more to report

	pw.Close()
	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "had no expiry timer"); n != 1 || !strings.Contains(string(out), "ERROR") || !strings.Contains(string(out), nodeKey) {
		t.Fatalf("want one ERROR naming %s, got %d report(s) in:\n%s", nodeKey, n, out)
	}
}
