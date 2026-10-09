package lease

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// NodeLocks serializes the operations that read lease-store nodes, write upstream, and then
// change those nodes -- a handler's request, or a node's lease expiry -- so that two of them
// on the same node never interleave across the upstream round trip. The store's own mutex
// only makes each single store call atomic. See docs/siglease_rfc9664.md, "Node Locks".
//
// A lock is an id in held, nothing more: there is no mutex per node, so nothing outlives its
// holder. A set of ids is taken all or nothing, under mu, and nobody waits while holding any
// id, so overlapping sets can never deadlock, whatever order they overlap in. Ids are opaque
// strings: each handler decides what it locks (NodeKey/RecordKey for the RFC 9664 handler,
// names for SRP).
type NodeLocks struct {
	mu   sync.Mutex
	held map[string]struct{}
	// released is closed, and replaced, on every Release, waking every Acquire waiting for
	// an id to come free.
	released chan struct{}
}

// NewNodeLocks returns an empty lock table.
func NewNodeLocks() *NodeLocks {
	return &NodeLocks{held: make(map[string]struct{}), released: make(chan struct{})}
}

// NodeLockSet is a set of ids taken by TryAcquire or Acquire.
type NodeLockSet struct {
	locks    *NodeLocks
	ids      []string
	released bool // guarded by locks.mu
}

// TryAcquire takes every id lockSet returns, or none of them if any is held; the error then
// names the held ones.
//
// lockSet runs with n's mutex held, so the ids it reads from the lease store -- a node's
// current subtree, say -- are exactly the ones taken: nothing can attach a new node under one
// of them in between, because attaching a node takes its parent's lock too. Lock order is
// therefore always n's mutex, then the store's. lockSet must not call back into n.
func (n *NodeLocks) TryAcquire(lockSet func() []string) (*NodeLockSet, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	set, busy := n.tryLocked(lockSet)
	if set == nil {
		return nil, fmt.Errorf("lease-store node lock contention on %s", strings.Join(busy, ", "))
	}
	return set, nil
}

// Acquire is TryAcquire that waits, holding nothing, while any id is held. It calls lockSet
// again after every release, since the set may have changed (a subtree grown or gone), until
// it takes the whole set or ctx is done; the error then names the ids still held.
func (n *NodeLocks) Acquire(ctx context.Context, lockSet func() []string) (*NodeLockSet, error) {
	for {
		n.mu.Lock()
		set, busy := n.tryLocked(lockSet)
		released := n.released
		n.mu.Unlock()
		if set != nil {
			return set, nil
		}
		select {
		case <-released:
		case <-ctx.Done():
			return nil, fmt.Errorf("lease-store node lock contention on %s: %w", strings.Join(busy, ", "), ctx.Err())
		}
	}
}

// tryLocked takes the ids lockSet returns if none is held, and otherwise returns the held
// ones. Called with n.mu held.
func (n *NodeLocks) tryLocked(lockSet func() []string) (*NodeLockSet, []string) {
	ids := slices.Compact(slices.Sorted(slices.Values(lockSet())))
	var busy []string
	for _, id := range ids {
		if _, ok := n.held[id]; ok {
			busy = append(busy, id)
		}
	}
	if len(busy) > 0 {
		return nil, busy
	}
	for _, id := range ids {
		n.held[id] = struct{}{}
	}
	return &NodeLockSet{locks: n, ids: ids}, nil
}

// IDs returns the ids s holds, sorted.
func (s *NodeLockSet) IDs() []string {
	return slices.Clone(s.ids)
}

// Release frees every id in s and wakes the waiting Acquires. Releasing a set twice would
// free ids that another caller may have taken since, so it panics.
func (s *NodeLockSet) Release() {
	n := s.locks
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.released {
		panic(fmt.Sprintf("lease-store node locks released twice: %s", strings.Join(s.ids, ", ")))
	}
	s.released = true
	for _, id := range s.ids {
		delete(n.held, id)
	}
	close(n.released)
	n.released = make(chan struct{})
}
