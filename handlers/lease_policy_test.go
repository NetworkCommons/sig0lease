package handlers

import (
	"strings"
	"testing"

	"github.com/NetworkCommons/sig0lease/logging"
)

func leasePolicyCfg(minKey, maxKey, minRR, maxRR int) map[string]any {
	return map[string]any{
		"min_key_lease_sec": minKey,
		"max_key_lease_sec": maxKey,
		"min_rr_lease_sec":  minRR,
		"max_rr_lease_sec":  maxRR,
	}
}

func TestParseLeasePolicy_Accepts(t *testing.T) {
	cases := []struct {
		name string
		raw  map[string]any
	}{
		{"no bounds at all", map[string]any{}},
		{"config.yaml handlers.update", leasePolicyCfg(30, 1800, 30, 900)},
		{"config.yaml handlers.srp_handler", leasePolicyCfg(30, 1209600, 30, 7200)},
		{"test_srp.sh", leasePolicyCfg(1, 1209600, 1, 7200)},
		{"equal rr and KEY bounds", leasePolicyCfg(60, 3600, 60, 3600)},
		{"no KEY maximum, rr maximum set", map[string]any{"max_rr_lease_sec": 7200}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseLeasePolicy(tc.raw); err != nil {
				t.Fatalf("parseLeasePolicy: %v", err)
			}
		})
	}
}

// TestParseLeasePolicy_RejectsContradictions: every bound pair that would let clamp grant a
// LEASE above the KEY-LEASE of a request that asked for LEASE <= KEY-LEASE, plus each minimum
// above its maximum.
func TestParseLeasePolicy_RejectsContradictions(t *testing.T) {
	cases := []struct {
		name    string
		raw     any
		wantErr string
	}{
		{"not a map", "30", "must be a map"},
		{"KEY minimum above KEY maximum", leasePolicyCfg(4000, 3600, 30, 900), "min_key_lease_sec (4000) cannot be greater than max_key_lease_sec (3600)"},
		{"rr minimum above rr maximum", leasePolicyCfg(30, 3600, 1000, 900), "min_rr_lease_sec (1000) cannot be greater than max_rr_lease_sec (900)"},
		{"rr minimum above KEY minimum", leasePolicyCfg(30, 3600, 60, 900), "min_rr_lease_sec (60) cannot be greater than min_key_lease_sec (30)"},
		{"rr maximum above KEY maximum", leasePolicyCfg(30, 3600, 30, 7200), "max_rr_lease_sec (7200, 0 = no limit) must be set and not greater than max_key_lease_sec (3600)"},
		{"rr maximum unset, KEY maximum set", map[string]any{"max_key_lease_sec": 3600}, "max_rr_lease_sec (0, 0 = no limit) must be set"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseLeasePolicy(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parseLeasePolicy error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestLeasePolicyClamp_KeepsLeaseWithinKeyLease: under a policy validate accepts, every
// request with LEASE <= KEY-LEASE is still LEASE <= KEY-LEASE after clamping, including the
// requests that would invert under the policies TestParseLeasePolicy_RejectsContradictions
// rejects.
func TestLeasePolicyClamp_KeepsLeaseWithinKeyLease(t *testing.T) {
	p, err := parseLeasePolicy(leasePolicyCfg(60, 3600, 60, 3600))
	if err != nil {
		t.Fatalf("parseLeasePolicy: %v", err)
	}
	for _, req := range [][2]uint32{{40, 40}, {9000, 9000}, {10, 20}, {120, 100000}, {3600, 3600}} {
		lease, keyLease := p.clamp(req[0], req[1])
		if lease > keyLease {
			t.Fatalf("clamp(%d, %d) = %d/%d, LEASE above KEY-LEASE", req[0], req[1], lease, keyLease)
		}
	}
}

// TestSetup_BothHandlersRejectContradictoryLeasePolicy: both handlers read lease_policy through
// parseLeasePolicy, so a contradictory policy stops either one's Setup -- and the proxy --
// at startup.
func TestSetup_BothHandlersRejectContradictoryLeasePolicy(t *testing.T) {
	bad := leasePolicyCfg(30, 3600, 60, 900) // min_rr above min_key

	updateCfg := baseSetupCfg(t)
	updateCfg["lease_policy"] = bad
	if err := newTestHandler().Setup(updateCfg); err == nil || !strings.Contains(err.Error(), "min_rr_lease_sec (60)") {
		t.Fatalf("UpdateHandler.Setup error = %v, want the lease_policy contradiction", err)
	}

	srpCfg := baseSRPSetupCfg(t)
	srpCfg["lease_policy"] = bad
	h := NewSRPHandler()
	h.SetLogger(logging.NewLogger("error"))
	if err := h.Setup(srpCfg); err == nil || !strings.Contains(err.Error(), "min_rr_lease_sec (60)") {
		t.Fatalf("SRPHandler.Setup error = %v, want the lease_policy contradiction", err)
	}
}
