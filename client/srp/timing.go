package srp

import (
	"math/rand"
	"time"
)

// refreshDelay implements RFC 9664 S5.2's baseline refresh clock (a MUST, reused by SRP per
// plan S3.4): 80% of the granted lease, plus a 0-5% random offset -- "the requester computes
// expiry from send time," so this is meant to be added to the moment the request that
// granted leaseSeconds was sent, not to "now" if some processing time has already elapsed.
// rng must be non-nil and must not be shared across goroutines (see Client.rng's doc
// comment) -- callers get one per Client from NewClient, never a shared package-level one.
func refreshDelay(rng *rand.Rand, leaseSeconds uint32) time.Duration {
	lease := time.Duration(leaseSeconds) * time.Second
	base := lease * 80 / 100
	jitter := time.Duration(rng.Float64() * 0.05 * float64(lease))
	return base + jitter
}

// initialDelay returns the roadmap's "initial 0-3s random delay" -- a first-registration
// anti-thundering-herd jitter, distinct from (and only applied once, before) the ongoing
// refreshDelay clock.
func initialDelay(rng *rand.Rand) time.Duration {
	return time.Duration(rng.Float64() * float64(3*time.Second))
}
