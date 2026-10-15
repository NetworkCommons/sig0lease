package handlers

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
)

// baseSetupCfg is the smallest config UpdateHandler.Setup accepts.
func baseSetupCfg(t *testing.T) map[string]any {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	return map[string]any{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}
}

// baseSRPSetupCfg is the smallest config SRPHandler.Setup accepts.
func baseSRPSetupCfg(t *testing.T) map[string]any {
	cfg := baseSetupCfg(t)
	cfg["upstream_zone"] = srpTestZone
	return cfg
}

// sharedFields is what tests read of a handler's leaseHandler after Setup. Its coordinator
// interface differs between the two handlers, so the coordinator is held here as any.
type sharedFields struct {
	*leaseRuntime
	upstreamZone string
	coordinator  any
	LeasePolicy  LeasePolicy
	recordTTL    uint32
}

func sharedFieldsOf[C upstreamClient](b *leaseHandler[C]) sharedFields {
	return sharedFields{
		leaseRuntime: b.leaseRuntime,
		upstreamZone: b.upstreamZone,
		coordinator:  b.upstreamCoordinator,
		LeasePolicy:  b.LeasePolicy,
		recordTTL:    b.recordTTL,
	}
}

// boolOptionCase is one of a handler's own boolean options: its default, and how to read it.
type boolOptionCase struct {
	key string
	def bool
	get func(Handler) bool
}

// leaseHandlerCase is one of the two UPDATE handlers, for tests that hold both to what they
// share: leaseHandler.setup and the lease runtime.
type leaseHandlerCase struct {
	name string
	zone string
	// ownBoolOptions are the boolean options only this handler reads.
	ownBoolOptions []boolOptionCase
	// setup runs a new handler's Setup with its base config plus extra, and returns the
	// handler, its shared fields and Setup's error. The handler shuts down when the test ends.
	setup func(t *testing.T, extra map[string]any) (Handler, sharedFields, error)
}

func leaseHandlerCases() []leaseHandlerCase {
	return []leaseHandlerCase{
		{
			name: "update_handler",
			zone: "dev.zenr.io.",
			ownBoolOptions: []boolOptionCase{
				{"prefer_4byte_variant", false, func(h Handler) bool { return h.(*UpdateHandler).prefer4ByteVariant }},
				{"allow_online_key_registration", false, func(h Handler) bool { return h.(*UpdateHandler).AllowOnlineKeyRegistration }},
			},
			setup: func(t *testing.T, extra map[string]any) (Handler, sharedFields, error) {
				cfg := baseSetupCfg(t)
				maps.Copy(cfg, extra)
				h := NewUpdateHandler()
				h.SetLogger(logging.NewLogger("debug"))
				t.Cleanup(h.Shutdown)
				err := h.Setup(cfg)
				return h, sharedFieldsOf(&h.leaseHandler), err
			},
		},
		{
			name: "srp_handler",
			zone: srpTestZone,
			ownBoolOptions: []boolOptionCase{
				{"allow_udp", false, func(h Handler) bool { return h.(*SRPHandler).allowUDP }},
				{"rewrite_default_service_arpa", false, func(h Handler) bool { return h.(*SRPHandler).rewriteDefaultServiceARPA }},
				{"refuse_on_foreign_data", true, func(h Handler) bool { return h.(*SRPHandler).refuseOnForeignData }},
				{"advertise_registration_domain", false, func(h Handler) bool { return h.(*SRPHandler).advertiseRegistrationDomain }},
			},
			setup: func(t *testing.T, extra map[string]any) (Handler, sharedFields, error) {
				cfg := baseSRPSetupCfg(t)
				maps.Copy(cfg, extra)
				h := NewSRPHandler()
				h.SetLogger(logging.NewLogger("debug"))
				t.Cleanup(h.Shutdown)
				err := h.Setup(cfg)
				return h, sharedFieldsOf(&h.leaseHandler), err
			},
		},
	}
}

// mustSetup is setup, failing the test on a Setup error.
func (tc leaseHandlerCase) mustSetup(t *testing.T, extra map[string]any) (Handler, sharedFields) {
	t.Helper()
	h, s, err := tc.setup(t, extra)
	if err != nil {
		t.Fatalf("%s Setup: %v", tc.name, err)
	}
	return h, s
}

func TestSetup_InMemoryStorage(t *testing.T) {
	for _, tc := range leaseHandlerCases() {
		for name, extra := range map[string]map[string]any{
			"default":         nil,
			"explicit memory": {"storage": map[string]any{"type": "memory"}},
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				_, s := tc.mustSetup(t, extra)
				if _, ok := s.leaseManager.(*leasepkg.InMemoryLeaseStore); !ok {
					t.Fatalf("lease store is %T, want *InMemoryLeaseStore", s.leaseManager)
				}
			})
		}
	}
}

func TestSetup_FileStorage(t *testing.T) {
	for _, tc := range leaseHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lease_snapshot.json")
			_, s := tc.mustSetup(t, map[string]any{"storage": map[string]any{
				"type": "file", "path": path, "save_interval": "50ms",
			}})
			if _, ok := s.leaseManager.(*leasepkg.FileLeaseStore); !ok {
				t.Fatalf("lease store is %T, want *FileLeaseStore", s.leaseManager)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("Setup did not write the snapshot at %s: %v", path, err)
			}
		})
	}
}

// TestSetup_UpstreamZoneTrimmed pins where a configured zone's surrounding whitespace goes:
// Setup trims it, since dnsname.Normalize does not (a label may begin with a space).
func TestSetup_UpstreamZoneTrimmed(t *testing.T) {
	for _, tc := range leaseHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, s := tc.mustSetup(t, map[string]any{"upstream_zone": "  " + tc.zone + "\t"})
			if s.upstreamZone != tc.zone {
				t.Fatalf("upstreamZone = %q, want %q", s.upstreamZone, tc.zone)
			}
		})
	}
}

// TestSetup_StaticUpstreamCoversRequestZones: "upstream" sends the handler's upstream_zone
// and the names below it -- the zones its requests name -- to the configured server, with no
// SOA/NS discovery.
func TestSetup_StaticUpstreamCoversRequestZones(t *testing.T) {
	for _, tc := range leaseHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, s := tc.mustSetup(t, map[string]any{"upstream": "127.0.0.1:5300"})
			coordinator, ok := s.coordinator.(*updatecore.Coordinator)
			if !ok {
				t.Fatalf("coordinator is %T, want *updatecore.Coordinator", s.coordinator)
			}
			for _, zone := range []string{tc.zone, "test." + tc.zone} {
				server, effectiveZone, err := coordinator.ResolveSOAMasterServer(context.Background(), zone)
				if err != nil {
					t.Fatalf("ResolveSOAMasterServer(%q): %v", zone, err)
				}
				if server != "127.0.0.1:5300" || effectiveZone != tc.zone {
					t.Fatalf("ResolveSOAMasterServer(%q) = %q, %q; want the static upstream and %s", zone, server, effectiveZone, tc.zone)
				}
			}
		})
	}
}

func TestSetup_ReadsLeasePolicyAndRecordTTL(t *testing.T) {
	for _, tc := range leaseHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, s := tc.mustSetup(t, map[string]any{
				"lease_policy":   leasePolicyCfg(30, 3600, 30, 900),
				"record_ttl_sec": 120,
			})
			want := LeasePolicy{MinKeyLease: 30, MaxKeyLease: 3600, MinRRLease: 30, MaxRRLease: 900}
			if s.LeasePolicy != want || s.recordTTL != 120 {
				t.Fatalf("lease policy %+v, record TTL %d; want %+v, 120", s.LeasePolicy, s.recordTTL, want)
			}
		})
	}
}

// TestSetup_RejectsBadSharedOptions: every option both handlers read fails either one's
// Setup -- and with it the proxy -- when it is wrong, rather than falling back to a default.
func TestSetup_RejectsBadSharedOptions(t *testing.T) {
	corrupt := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("not valid json{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileStorage := func(extra map[string]any) map[string]any {
		s := map[string]any{"type": "file", "path": filepath.Join(t.TempDir(), "lease_snapshot.json")}
		maps.Copy(s, extra)
		return s
	}
	bad := []struct {
		name  string
		extra map[string]any
		want  string
	}{
		{"no upstream_zone", map[string]any{"upstream_zone": nil}, "upstream_zone"},
		{"blank upstream_zone", map[string]any{"upstream_zone": "   "}, "upstream_zone"},
		{"no keystore_dir", map[string]any{"keystore_dir": ""}, "keystore_dir"},
		{"no signing key", map[string]any{"keystore_dir": t.TempDir()}, "signing key"},
		{"upstream not a string", map[string]any{"upstream": 5300}, "upstream"},
		{"upstream empty", map[string]any{"upstream": ""}, "upstream"},
		{"upstream without port", map[string]any{"upstream": "127.0.0.1"}, "upstream"},
		{"upstream a name", map[string]any{"upstream": "ns1.example."}, "upstream"},
		{"contradictory lease_policy", map[string]any{"lease_policy": leasePolicyCfg(30, 3600, 60, 900)}, "min_rr_lease_sec (60)"},
		{"record_ttl_sec 0", map[string]any{"record_ttl_sec": 0}, "record_ttl_sec"},
		{"storage not a map", map[string]any{"storage": "oops"}, "storage"},
		{"storage unknown type", map[string]any{"storage": map[string]any{"type": "bogus"}}, "unrecognized"},
		{"file storage without path", map[string]any{"storage": map[string]any{"type": "file"}}, "path"},
		{"save_interval not a duration", map[string]any{"storage": fileStorage(map[string]any{"save_interval": "not-a-duration"})}, "save_interval"},
		{"save_interval 0", map[string]any{"storage": fileStorage(map[string]any{"save_interval": "0s"})}, "save_interval"},
		{"save_interval negative", map[string]any{"storage": fileStorage(map[string]any{"save_interval": "-1s"})}, "save_interval"},
		{"corrupt snapshot", map[string]any{"storage": map[string]any{"type": "file", "path": corrupt}}, "storage"},
		{"lease_manager and storage", map[string]any{"lease_manager": leasepkg.NewInMemoryManager(), "storage": map[string]any{"type": "memory"}}, "mutually exclusive"},
		{"lease_manager wrong type", map[string]any{"lease_manager": "not a lease manager"}, "lease_manager"},
	}
	for _, tc := range leaseHandlerCases() {
		for _, b := range bad {
			t.Run(tc.name+"/"+b.name, func(t *testing.T) {
				if _, _, err := tc.setup(t, b.extra); err == nil || !strings.Contains(err.Error(), b.want) {
					t.Fatalf("Setup error = %v, want one mentioning %q", err, b.want)
				}
			})
		}
	}
}

// TestSetup_OwnBooleanOptions: each handler's own boolean options keep their default when
// absent, are read when set, and fail Setup when they are not booleans.
func TestSetup_OwnBooleanOptions(t *testing.T) {
	for _, tc := range leaseHandlerCases() {
		for _, opt := range tc.ownBoolOptions {
			t.Run(tc.name+"/"+opt.key, func(t *testing.T) {
				h, _ := tc.mustSetup(t, nil)
				if got := opt.get(h); got != opt.def {
					t.Fatalf("default %s = %v, want %v", opt.key, got, opt.def)
				}
				h, _ = tc.mustSetup(t, map[string]any{opt.key: !opt.def})
				if got := opt.get(h); got != !opt.def {
					t.Fatalf("%s set to %v reads %v", opt.key, !opt.def, got)
				}
				if _, _, err := tc.setup(t, map[string]any{opt.key: "yes"}); err == nil || !strings.Contains(err.Error(), opt.key) {
					t.Fatalf("Setup error for %s: \"yes\" = %v, want one naming the option", opt.key, err)
				}
			})
		}
	}
}

// TestStart_ArmsLeasesSetupLoaded: Setup loads a file store's leases and arms nothing, so a dump,
// which runs Setup alone, expires nothing; Start arms a timer for each of them.
func TestStart_ArmsLeasesSetupLoaded(t *testing.T) {
	for _, tc := range leaseHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			storage := map[string]any{"storage": map[string]any{
				"type": "file", "path": filepath.Join(t.TempDir(), "leases.json"), "save_interval": "1h",
			}}
			key, err := keyrec.GenerateKey("start."+tc.zone, dns.ECDSAP256SHA256, 0, 256)
			if err != nil {
				t.Fatal(err)
			}
			nodeKey := leasepkg.NodeKey(key.PublicKey)
			h1, s1 := tc.mustSetup(t, storage)
			if err := s1.leaseManager.RegisterWithParent("", key.PublicKey, 3600, 3600, tc.zone); err != nil {
				t.Fatalf("register: %v", err)
			}
			h1.Shutdown()

			h2, s2 := tc.mustSetup(t, storage)
			if s2.leaseManager.Get(nodeKey) == nil {
				t.Fatal("Setup did not load the lease")
			}
			if s2.timers.armed(nodeKey) {
				t.Fatal("Setup armed an expiry timer: a dump would expire leases")
			}
			h2.Start()
			if !s2.timers.armed(nodeKey) {
				t.Fatal("Start did not arm an expiry timer for the lease Setup loaded")
			}
		})
	}
}
