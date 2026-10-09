package lease

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ids(s ...string) func() []string { return func() []string { return s } }

func TestNodeLocks_MutualExclusion(t *testing.T) {
	n := NewNodeLocks()
	a, err := n.TryAcquire(ids("x"))
	if err != nil {
		t.Fatalf("first TryAcquire: %v", err)
	}
	if _, err := n.TryAcquire(ids("x")); err == nil {
		t.Fatal("second TryAcquire of a held id succeeded")
	}
	a.Release()
	b, err := n.TryAcquire(ids("x"))
	if err != nil {
		t.Fatalf("TryAcquire after Release: %v", err)
	}
	b.Release()
}

// A set is taken whole or not at all: a failed attempt must leave none of its ids held.
func TestNodeLocks_AllOrNothing(t *testing.T) {
	n := NewNodeLocks()
	a, err := n.TryAcquire(ids("x", "y"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()

	_, err = n.TryAcquire(ids("y", "z"))
	if err == nil {
		t.Fatal("TryAcquire overlapping a held set succeeded")
	}
	if !strings.Contains(err.Error(), "y") || strings.Contains(err.Error(), "z") {
		t.Fatalf("error should name the held id y and only it: %v", err)
	}
	c, err := n.TryAcquire(ids("z"))
	if err != nil {
		t.Fatalf("z was left held by the failed attempt: %v", err)
	}
	c.Release()
}

func TestNodeLocks_DuplicateIDs(t *testing.T) {
	n := NewNodeLocks()
	s, err := n.TryAcquire(ids("b", "a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.IDs(); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("IDs() = %v, want [a b]", got)
	}
	s.Release()
	if _, err := n.TryAcquire(ids("a", "b")); err != nil {
		t.Fatalf("ids still held after Release: %v", err)
	}
}

func TestNodeLocks_AcquireWaitsForRelease(t *testing.T) {
	n := NewNodeLocks()
	a, err := n.TryAcquire(ids("x"))
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan *NodeLockSet)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := n.Acquire(ctx, ids("x", "y"))
		if err != nil {
			t.Errorf("Acquire: %v", err)
		}
		got <- s
	}()

	select {
	case <-got:
		t.Fatal("Acquire returned while x was still held")
	case <-time.After(50 * time.Millisecond):
	}
	// While it waits, the waiter holds nothing: y is still free.
	y, err := n.TryAcquire(ids("y"))
	if err != nil {
		t.Fatalf("a waiting Acquire is holding y: %v", err)
	}
	y.Release()

	a.Release()
	s := <-got
	if s == nil || !slices.Equal(s.IDs(), []string{"x", "y"}) {
		t.Fatalf("Acquire after release got %v", s)
	}
	s.Release()
}

func TestNodeLocks_AcquireGivesUpAtDeadline(t *testing.T) {
	n := NewNodeLocks()
	a, err := n.TryAcquire(ids("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = n.Acquire(ctx, ids("x", "y"))
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "x") {
		t.Fatalf("Acquire past its deadline: got %v, want a deadline error naming x", err)
	}
	y, err := n.TryAcquire(ids("y"))
	if err != nil {
		t.Fatalf("y was left held by the abandoned Acquire: %v", err)
	}
	y.Release()
}

// The single-pass subtree argument (docs/siglease_rfc9664.md, "Node Locks"): lockSet reads the subtree under the table's
// mutex on every attempt, so a child attached while a waiter waited is in the set it takes.
func TestNodeLocks_AcquireRereadsSubtree(t *testing.T) {
	store := NewInMemoryManager()
	defer store.Stop()
	ctx := context.Background()
	parent := testKeyRR("parent.dev.zenr.io.", "AAAAPARENT=")
	child := testKeyRR("child.parent.dev.zenr.io.", "AAAACHILD=")
	if err := store.RegisterWithParent(ctx, "", parent, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}
	parentKey, childKey := NodeKey(parent), NodeKey(child)
	subtree := func() []string { return append([]string{parentKey}, store.ListSubtreeKeys(parentKey)...) }

	n := NewNodeLocks()
	// A registration under parent holds {child, parent} while it works.
	reg, err := n.TryAcquire(ids(childKey, parentKey))
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan *NodeLockSet)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := n.Acquire(ctx, subtree)
		if err != nil {
			t.Errorf("Acquire: %v", err)
		}
		got <- s
	}()
	time.Sleep(20 * time.Millisecond) // let the deleter reach its wait (the result doesn't depend on it)

	if err := store.RegisterWithParent(ctx, parentKey, child, 300, 300, "dev.zenr.io."); err != nil {
		t.Fatal(err)
	}
	reg.Release()

	s := <-got
	if s == nil || !slices.Contains(s.IDs(), childKey) {
		t.Fatalf("subtree lock set %v is missing the child attached while it waited", s)
	}
	s.Release()
}

func TestNodeLocks_ReleaseTwicePanics(t *testing.T) {
	n := NewNodeLocks()
	s, err := n.TryAcquire(ids("x"))
	if err != nil {
		t.Fatal(err)
	}
	s.Release()
	defer func() {
		if recover() == nil {
			t.Fatal("second Release did not panic")
		}
	}()
	s.Release()
}

// Many goroutines taking overlapping sets: no id is ever held by two at once, and every
// Acquire eventually gets its set. Run with -race.
func TestNodeLocks_ConcurrentOverlappingSets(t *testing.T) {
	n := NewNodeLocks()
	const nodes, workers, rounds = 6, 12, 200
	var inUse [nodes]atomic.Int32
	name := func(i int) string { return fmt.Sprintf("node%d", i) }

	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for r := range rounds {
				// Each worker takes two or three neighbouring nodes, in varying order.
				first := (w + r) % nodes
				members := []int{first, (first + 1) % nodes}
				if r%2 == 0 {
					members = append(members, (first+3)%nodes)
				}
				set := make([]string, len(members))
				for i, m := range members {
					set[len(members)-1-i] = name(m)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				s, err := n.Acquire(ctx, ids(set...))
				cancel()
				if err != nil {
					t.Errorf("Acquire %v: %v", set, err)
					return
				}
				for _, m := range members {
					if inUse[m].Add(1) != 1 {
						t.Errorf("%s held twice at once", name(m))
					}
				}
				for _, m := range members {
					inUse[m].Add(-1)
				}
				s.Release()
			}
		})
	}
	wg.Wait()
}
