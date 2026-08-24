package handlers

import (
	"testing"

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

func TestUpdateHandler_Shutdown_StopsLeaseManager(t *testing.T) {
	cfg := baseSetupCfg(t)
	lm := &stoppableLeaseManager{InMemoryLeaseStore: leasepkg.NewInMemoryManager()}
	cfg["lease_manager"] = lm

	h := newTestHandler()
	if err := h.Setup(cfg); err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}

	h.Shutdown()

	if !lm.stopped {
		t.Fatal("expected Shutdown() to call Stop() on the lease manager")
	}
}

func TestUpdateHandler_Shutdown_IsSafeToCallTwice(t *testing.T) {
	h := newTestHandler()
	if err := h.Setup(baseSetupCfg(t)); err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}

	h.Shutdown()
	h.Shutdown() // must not panic
}
