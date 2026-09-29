package updatecore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInflightLimiter_CapsEachServerSeparately(t *testing.T) {
	l := newInflightLimiter(2)
	ctx := context.Background()

	releaseA1, err := l.acquire(ctx, "a:53")
	if err != nil {
		t.Fatalf("first slot on a: %v", err)
	}
	if _, err := l.acquire(ctx, "a:53"); err != nil {
		t.Fatalf("second slot on a: %v", err)
	}
	if _, err := l.acquire(ctx, "b:53"); err != nil {
		t.Fatalf("a's slots must not limit b: %v", err)
	}

	// a is full: a third acquire waits until a slot is given back.
	got := make(chan error, 1)
	go func() {
		_, err := l.acquire(ctx, "a:53")
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("expected the third acquire on a to wait, got %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseA1()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("third acquire on a after a release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("expected the third acquire on a to proceed once a slot was released")
	}
}

func TestInflightLimiter_GivesUpWhenContextEnds(t *testing.T) {
	l := newInflightLimiter(1)
	if _, err := l.acquire(context.Background(), "a:53"); err != nil {
		t.Fatalf("first slot: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.acquire(ctx, "a:53"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the wait to end with the context, got %v", err)
	}
}

func TestInflightLimiter_ZeroMeansNoLimit(t *testing.T) {
	l := newInflightLimiter(0)
	for i := 0; i < 100; i++ {
		if _, err := l.acquire(context.Background(), "a:53"); err != nil {
			t.Fatalf("acquire %d with no limit: %v", i, err)
		}
	}
}

func TestSetMaxInflightUpdates_RejectsNegative(t *testing.T) {
	defer func() { _ = SetMaxInflightUpdates(DefaultMaxInflightUpdates) }()
	if err := SetMaxInflightUpdates(-1); err == nil {
		t.Fatalf("expected a negative limit to be rejected")
	}
	if err := SetMaxInflightUpdates(3); err != nil {
		t.Fatalf("set limit 3: %v", err)
	}
	if inflightUpdates.max != 3 {
		t.Fatalf("expected the process-wide limit to be 3, got %d", inflightUpdates.max)
	}
}
