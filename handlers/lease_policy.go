package handlers

import "fmt"

// LeasePolicy controls clamping for lease durations. A zero bound is no bound. UpdateHandler
// and SRPHandler each hold one, read from their own "lease_policy" config by parseLeasePolicy,
// and clamp every granted lease with LeasePolicy.clamp.
type LeasePolicy struct {
	MinKeyLease uint32
	MaxKeyLease uint32
	MinRRLease  uint32
	MaxRRLease  uint32
}

// parseLeasePolicy reads a handler's "lease_policy" config map: min_key_lease_sec,
// max_key_lease_sec, min_rr_lease_sec and max_rr_lease_sec, each optional. It returns an error
// for a policy validate rejects, so the handler's Setup -- and with it the proxy -- fails at
// startup instead of granting inconsistent leases later.
func parseLeasePolicy(raw any) (LeasePolicy, error) {
	cfg, ok := raw.(map[string]any)
	if !ok {
		return LeasePolicy{}, fmt.Errorf("lease_policy must be a map")
	}
	var p LeasePolicy
	if v, ok := toUint32(cfg["min_key_lease_sec"]); ok {
		p.MinKeyLease = v
	}
	if v, ok := toUint32(cfg["max_key_lease_sec"]); ok {
		p.MaxKeyLease = v
	}
	if v, ok := toUint32(cfg["min_rr_lease_sec"]); ok {
		p.MinRRLease = v
	}
	if v, ok := toUint32(cfg["max_rr_lease_sec"]); ok {
		p.MaxRRLease = v
	}
	if err := p.validate(); err != nil {
		return LeasePolicy{}, err
	}
	return p, nil
}

// validate rejects bounds that contradict each other. Beyond each minimum not exceeding its
// maximum, the data-record (rr) bounds must not be looser than the KEY bounds. clamp bounds
// LEASE and KEY-LEASE separately, so under a looser rr bound a request comes out with LEASE
// above KEY-LEASE: with min_rr_lease_sec above min_key_lease_sec (40/40 under minimums 60/30
// becomes 60/40), and with max_rr_lease_sec above max_key_lease_sec, or unset while
// max_key_lease_sec is set (9000/9000 under maximums 7200/3600 becomes 7200/3600). clamp's
// final check then has to cut LEASE to KEY-LEASE, which in the first case goes below the
// policy's own min_rr_lease_sec. Such a policy contradicts the project-wide LEASE <= KEY-LEASE
// rule (pkg/lease.LeaseOption.Validate) and RFC 9665 S3.2.5.3's KEY-LEASE "much longer" than
// LEASE.
func (p LeasePolicy) validate() error {
	if p.MaxKeyLease > 0 && p.MinKeyLease > p.MaxKeyLease {
		return fmt.Errorf("lease_policy min_key_lease_sec (%d) cannot be greater than max_key_lease_sec (%d)", p.MinKeyLease, p.MaxKeyLease)
	}
	if p.MaxRRLease > 0 && p.MinRRLease > p.MaxRRLease {
		return fmt.Errorf("lease_policy min_rr_lease_sec (%d) cannot be greater than max_rr_lease_sec (%d)", p.MinRRLease, p.MaxRRLease)
	}
	if p.MinRRLease > p.MinKeyLease {
		return fmt.Errorf("lease_policy min_rr_lease_sec (%d) cannot be greater than min_key_lease_sec (%d): a request below min_rr_lease_sec would be granted a LEASE longer than its KEY-LEASE", p.MinRRLease, p.MinKeyLease)
	}
	if p.MaxKeyLease > 0 && (p.MaxRRLease == 0 || p.MaxRRLease > p.MaxKeyLease) {
		return fmt.Errorf("lease_policy max_rr_lease_sec (%d, 0 = no limit) must be set and not greater than max_key_lease_sec (%d): otherwise a request above max_key_lease_sec would be granted a LEASE longer than its KEY-LEASE", p.MaxRRLease, p.MaxKeyLease)
	}
	return nil
}

// clamp applies the policy to a requested LEASE and KEY-LEASE, returning the durations to
// grant. A value of exactly 0 is left alone rather than raised to the minimum: 0 means
// "delete" (RFC 9664 Cases B-D; RFC 9665 S3.2.5.5.1's removal), not "the shortest allowed
// duration". With a policy validate accepts, LEASE <= KEY-LEASE in the request stays true
// after clamping; the final check keeps it true for a request that broke it.
func (p LeasePolicy) clamp(lease, keyLease uint32) (uint32, uint32) {
	if lease != 0 {
		lease = clampLease(lease, p.MinRRLease, p.MaxRRLease)
	}
	if keyLease != 0 {
		keyLease = clampLease(keyLease, p.MinKeyLease, p.MaxKeyLease)
	}
	if lease != 0 && keyLease != 0 && lease > keyLease {
		lease = keyLease
	}
	return lease, keyLease
}
