package handlers

import (
	"context"
	"sync"
	"time"

	"github.com/NetworkCommons/sig0lease/logging"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// leaseReconcileInterval is how often the reconciliation pass runs once leaseHandler.Start has
// started it (leaseRuntime.startLeaseReconciliation).
const leaseReconcileInterval = 30 * time.Second

// reconcilePassTimeout bounds one reconciliation pass, as expiryTimeout bounds one lease
// event. A pass cut short leaves what it did not finish to the next one.
const reconcilePassTimeout = 10 * time.Second

// leaseRuntime is the lease machinery the two UPDATE handlers run the same way: the lease
// store, its expiry timers and node locks, the timer callback that runs a node's lease event,
// the reconciliation pass, and Shutdown. Each handler's leaseHandler embeds one, built by
// newLeaseRuntime with the three things that are the handler's own: its node lock ids, how a
// lease event runs (leaseExpirer, and for SRP RFC 9665's data cascade and service
// enumeration), and any work its reconciliation pass adds (SRP's service enumeration).
type leaseRuntime struct {
	leaseManager LeaseManager
	timers       *expiryTimers
	// nodeLocks serializes the requests and lease expiries that touch the same lease-store
	// nodes (docs/siglease_rfc9664.md, "Node Locks"; docs/siglease_rfc9665.md §5). Its ids
	// are the handler's own: NodeKey/RecordKey values for RFC 9664, names for SRP.
	nodeLocks *leasepkg.NodeLocks
	// lockIDs returns the node lock ids of a node and its subtree: the ids its lease event
	// takes (leaseExpirer.run), and the reconciliation pass checks a node under
	// (rearmMissingTimers).
	lockIDs func(nodeKey string) []string

	// leaseEvent runs one lease event for nodeKey; nodeKey's timer calls it (expireFunc).
	leaseEvent func(ctx context.Context, nodeKey string)
	// passExtra, when set, runs at the end of every reconciliation pass.
	passExtra func(ctx context.Context)

	// ctx is the parent of every lease event's and pass's context, and ends the
	// reconciliation loop; Shutdown cancels it (cancel).
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	stopped  bool           // set by Shutdown: no timer callback or pass starts after it
	inFlight sync.WaitGroup // the timer callbacks and the pass running now
	stopOnce sync.Once
}

// newLeaseRuntime returns a runtime with an in-memory lease store (Setup may replace it),
// whose node lock ids are lockIDs, whose timers run leaseEvent and whose reconciliation pass
// ends with passExtra, if not nil.
func newLeaseRuntime(lockIDs func(nodeKey string) []string, leaseEvent func(ctx context.Context, nodeKey string), passExtra func(ctx context.Context)) *leaseRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	return &leaseRuntime{
		leaseManager: NewInMemoryLeaseManager(),
		timers:       newExpiryTimers(),
		nodeLocks:    leasepkg.NewNodeLocks(),
		lockIDs:      lockIDs,
		leaseEvent:   leaseEvent,
		passExtra:    passExtra,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// begin counts a timer callback or pass that is about to run, unless Shutdown has begun, in
// which case it returns false and the caller must not run.
func (r *leaseRuntime) begin() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return false
	}
	r.inFlight.Add(1)
	return true
}

// scheduleLeaseExpiry arms (or re-arms) nodeKey's timer for its next lease event: its
// earliest non-KEY record's LEASE or its KEY's KEY-LEASE, whichever comes first.
func (r *leaseRuntime) scheduleLeaseExpiry(nodeKey string) {
	r.timers.schedule(r.leaseManager, nodeKey, r.expireFunc(nodeKey))
}

// expireFunc is nodeKey's timer callback: one lease event, within expiryTimeout, which
// Shutdown cuts short by cancelling its context. Once Shutdown has begun it does nothing, so
// the store does not change after its final save.
func (r *leaseRuntime) expireFunc(nodeKey string) func() {
	return func() {
		if !r.begin() {
			return
		}
		defer r.inFlight.Done()
		ctx, cancel := context.WithTimeout(r.ctx, expiryTimeout)
		defer cancel()
		r.leaseEvent(ctx, nodeKey)
	}
}

// newExpirer builds the leaseExpirer for this runtime's store, timers and locks: the engine
// both handlers end leases with. upstream is where its deletes go, and dataCascade is
// RFC 9665's (true only for SRP).
func (r *leaseRuntime) newExpirer(upstream upstreamTarget, dataCascade bool) leaseExpirer {
	return leaseExpirer{
		store:       r.leaseManager,
		timers:      r.timers,
		upstream:    upstream,
		fire:        r.expireFunc,
		locks:       r.nodeLocks,
		lockIDs:     r.lockIDs,
		dataCascade: dataCascade,
	}
}

// startLeaseReconciliation runs a reconciliation pass every interval until Shutdown:
// rearmMissingTimers, then passExtra, within reconcilePassTimeout, which Shutdown cuts short
// by cancelling its context.
func (r *leaseRuntime) startLeaseReconciliation(interval time.Duration, logger *logging.Logger) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
			}
			if !r.begin() {
				return
			}
			r.reconcilePass(logger)
			r.inFlight.Done()
		}
	}()
}

// reconcilePass is one reconciliation pass.
func (r *leaseRuntime) reconcilePass(logger *logging.Logger) {
	ctx, cancel := context.WithTimeout(r.ctx, reconcilePassTimeout)
	defer cancel()
	r.rearmMissingTimers(logger)
	if r.passExtra != nil {
		r.passExtra(ctx)
	}
}

// rearmMissingTimers arms a timer, for its next lease event, for every lease owner in the store
// that has none: each KEY node, and each owner of non-KEY records, also one without a KEY record
// of its own (LeaseStorage.ListOwners). Every path that writes a lease arms its node's timer
// before it releases the node's locks, and leaseHandler.Start armed the leases Setup loaded, so
// an owner with no timer whose locks are free lost its timer to a bug: that is logged as an
// error, and the timer armed so its leases still end, through the same lease event as every
// other. An owner whose locks are held is left to the next pass: whoever holds them may be
// between writing the store and arming the timer, or between disarming a node's timer and
// deleting it.
func (r *leaseRuntime) rearmMissingTimers(logger *logging.Logger) {
	for _, nodeKey := range r.leaseManager.ListOwners() {
		if r.timers.armed(nodeKey) {
			continue
		}
		locks, err := r.nodeLocks.TryAcquire(func() []string { return r.lockIDs(nodeKey) })
		if err != nil {
			continue
		}
		if _, owner := nextLeaseEvent(r.leaseManager, nodeKey); owner && !r.timers.armed(nodeKey) {
			logger.Errorf("Reconciliation: lease owner %s had no expiry timer, though every write of a lease arms one; arming it now", nodeKey)
			r.scheduleLeaseExpiry(nodeKey)
		}
		locks.Release()
	}
}

// Shutdown stops the lease machinery and has the store save once more. After it begins, no
// timer callback or reconciliation pass starts. It cancels the context of the callbacks and
// the pass already running and waits for them to return; then it stops every timer, including
// a retry a cut-short lease event armed, and stops the lease store, which for a file store is
// the final save. A cut-short lease event forgets nothing: the store changes only once its
// upstream UPDATE is confirmed, so its leases are in that save and expire after a restart.
// Safe to call more than once: only the first call does anything.
func (r *leaseRuntime) Shutdown() {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		r.stopped = true
		r.mu.Unlock()
		r.cancel()
		r.inFlight.Wait()
		r.timers.stopAll()
		r.leaseManager.Stop()
	})
}
