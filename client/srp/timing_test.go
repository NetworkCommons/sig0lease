package srp

import (
	"math/rand"
	"testing"
	"time"
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
	rng := rand.New(rand.NewSource(1))
	if got := refreshDelay(rng, 0); got != 0 {
		t.Fatalf("refreshDelay(0) = %v, want 0", got)
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
