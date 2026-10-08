package handlers

import (
	"context"
	"math"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

func TestParseRecordTTL(t *testing.T) {
	ok := []struct {
		name string
		cfg  map[string]any
		want uint32
	}{
		{"absent", map[string]any{}, defaultRecordTTL},
		{"set", map[string]any{"record_ttl_sec": 120}, 120},
		{"largest TTL", map[string]any{"record_ttl_sec": math.MaxInt32}, math.MaxInt32},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRecordTTL(tc.cfg)
			if err != nil || got != tc.want {
				t.Fatalf("parseRecordTTL = %d, %v; want %d, nil", got, err, tc.want)
			}
		})
	}

	bad := []struct {
		name string
		raw  any
	}{
		{"zero", 0},
		{"negative", -1},
		{"not a number", "300"},
		{"MSB set (RFC 2181 S8)", int64(math.MaxInt32) + 1},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := parseRecordTTL(map[string]any{"record_ttl_sec": tc.raw}); err == nil {
				t.Fatalf("parseRecordTTL(%v) = %d, want an error", tc.raw, got)
			}
		})
	}
}

// TestSetup_BothHandlersReadRecordTTL: both handlers read record_ttl_sec through
// parseRecordTTL, and an invalid value stops either one's Setup.
func TestSetup_BothHandlersReadRecordTTL(t *testing.T) {
	updateCfg := baseSetupCfg(t)
	updateCfg["record_ttl_sec"] = 120
	uh := newTestHandler()
	if err := uh.Setup(updateCfg); err != nil {
		t.Fatalf("UpdateHandler.Setup: %v", err)
	}
	if uh.recordTTL != 120 {
		t.Fatalf("UpdateHandler recordTTL = %d, want 120", uh.recordTTL)
	}

	srpCfg := baseSRPSetupCfg(t)
	srpCfg["record_ttl_sec"] = 120
	sh := NewSRPHandler()
	sh.SetLogger(logging.NewLogger("error"))
	if err := sh.Setup(srpCfg); err != nil {
		t.Fatalf("SRPHandler.Setup: %v", err)
	}
	if sh.recordTTL != 120 {
		t.Fatalf("SRPHandler recordTTL = %d, want 120", sh.recordTTL)
	}

	updateCfg = baseSetupCfg(t)
	updateCfg["record_ttl_sec"] = 0
	if err := newTestHandler().Setup(updateCfg); err == nil || !strings.Contains(err.Error(), "record_ttl_sec") {
		t.Fatalf("UpdateHandler.Setup error = %v, want the record_ttl_sec error", err)
	}
	srpCfg = baseSRPSetupCfg(t)
	srpCfg["record_ttl_sec"] = 0
	sh = NewSRPHandler()
	sh.SetLogger(logging.NewLogger("error"))
	if err := sh.Setup(srpCfg); err == nil || !strings.Contains(err.Error(), "record_ttl_sec") {
		t.Fatalf("SRPHandler.Setup error = %v, want the record_ttl_sec error", err)
	}
}

// TestSRPHandle_WritesRecordTTL: the SRP handler forwards record_ttl_sec, not the requester's
// TTLs (3600 on every add here): cut to LEASE on A/SRV/TXT, to KEY-LEASE on KEYs (the
// synthesized instance KEY included), and whole on the shared Service Discovery PTR; the
// enumeration records it writes carry it too, and the lease store keeps what was forwarded.
func TestSRPHandle_WritesRecordTTL(t *testing.T) {
	cases := []struct {
		name          string
		lease         uint32
		wantData      uint32 // A, SRV, TXT
		wantKeyAndPTR uint32
	}{
		{"lease shorter than record_ttl_sec", 120, 120, defaultRecordTTL},
		{"lease longer than record_ttl_sec", 3600, defaultRecordTTL, defaultRecordTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, coord := newSRPTestHandler(t)
			id := newSRPTestIdentity(t)
			const host = "srpttl.dev.zenr.io."

			msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), tc.lease, 1209600, host)
			if res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg); res.Status != StatusProcessed {
				t.Fatalf("expected Processed, got %s: %v", res.Status, res.Error)
			}
			sent := coord.sentSnapshot()
			if len(sent) != 2 {
				t.Fatalf("expected 2 upstream sends (registration + enumeration), got %d", len(sent))
			}

			keys := 0
			for _, rr := range sent[0].Ns {
				hdr := rr.Header()
				if hdr.Class != dns.ClassINET {
					if hdr.TTL != 0 {
						t.Errorf("delete %s: TTL %d, want 0", rr, hdr.TTL)
					}
					continue
				}
				want := tc.wantData
				switch rr.(type) {
				case *dns.KEY:
					keys++
					want = tc.wantKeyAndPTR
				case *dns.PTR:
					want = tc.wantKeyAndPTR
				}
				if hdr.TTL != want {
					t.Errorf("forwarded %s: TTL %d, want %d", rr, hdr.TTL, want)
				}
			}
			if keys != 2 {
				t.Fatalf("expected the host KEY and the synthesized instance KEY, got %d KEYs", keys)
			}

			for _, rr := range sent[1].Ns {
				if hdr := rr.Header(); hdr.Class == dns.ClassINET && hdr.TTL != defaultRecordTTL {
					t.Errorf("enumeration %s: TTL %d, want %d", rr, hdr.TTL, defaultRecordTTL)
				}
			}

			hostSet := h.leaseManager.GetNonKEYRecordSet(leasepkg.NodeKey(id.keyAt(host)))
			if hostSet == nil || len(hostSet.Records) != 1 {
				t.Fatalf("expected the host's A record in the lease store, got %+v", hostSet)
			}
			for _, rec := range hostSet.Records {
				if got := rec.RR.Header().TTL; got != tc.wantData {
					t.Errorf("stored %s: TTL %d, want %d", rec.RR, got, tc.wantData)
				}
			}
		})
	}
}

func newRecordTTLUpdateHandler(t *testing.T) (*UpdateHandler, *keyrec.LoadedKey) {
	t.Helper()
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	return h, loaded
}

// TestHandle_WritesRecordTTL: the RFC 9664 handler forwards record_ttl_sec, cut to KEY-LEASE on
// the KEY and to LEASE on the data record (60 in the request), and stores what it forwarded.
func TestHandle_WritesRecordTTL(t *testing.T) {
	cases := []struct {
		name             string
		lease, keyLease  uint32
		wantTXT, wantKEY uint32
	}{
		{"leases shorter than record_ttl_sec", 120, 120, 120, 120},
		{"only LEASE shorter", 120, 3600, 120, defaultRecordTTL},
		{"leases longer than record_ttl_sec", 3600, 7200, defaultRecordTTL, defaultRecordTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, loaded := newRecordTTLUpdateHandler(t)
			stub := &stubUpstreamCoordinator{
				query: func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
					return []dns.RR{}, nil
				},
				resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}},
			}
			h.upstreamCoordinator = stub

			req := buildSignedLeaseRegistrationForHandleTest(t, loaded, "test.dev.zenr.io.", tc.lease, tc.keyLease)
			res := h.Handle(context.Background(), stubResponseWriter{}, req)
			if res == nil || res.Message == nil || res.Message.Rcode != dns.RcodeSuccess {
				t.Fatalf("expected success, got %+v", res)
			}
			if stub.sentCount() != 1 {
				t.Fatalf("expected 1 upstream send, got %d", stub.sentCount())
			}

			var txt dns.RR
			for _, rr := range stub.sent[0].Ns {
				want := tc.wantTXT
				if _, ok := rr.(*dns.KEY); ok {
					want = tc.wantKEY
				} else {
					txt = rr
				}
				if got := rr.Header().TTL; got != want {
					t.Errorf("forwarded %s: TTL %d, want %d", rr, got, want)
				}
			}
			stored := h.leaseManager.LookupNonKEYRecord(txt)
			if stored == nil || stored.RR.Header().TTL != tc.wantTXT {
				t.Fatalf("stored TXT = %+v, want TTL %d", stored, tc.wantTXT)
			}
		})
	}
}

// TestHandle_CaseB_ReRegisteredKEYGetsRecordTTL: Case B re-sends the lease store's KEY (the
// request has no KEY and KEY-LEASE 0). Its TTL is cut to the remaining lease it is
// re-registered with, on the forwarded copy only; the store's record keeps its own.
func TestHandle_CaseB_ReRegisteredKEYGetsRecordTTL(t *testing.T) {
	h, loaded := newRecordTTLUpdateHandler(t)

	signerKey := loaded.PublicKey.Clone().(*dns.KEY)
	signerKey.Hdr.TTL = 3600
	if err := h.leaseManager.Register(context.Background(), signerKey, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register signer key in lease store: %v", err)
	}
	stub := &stubUpstreamCoordinator{
		// No KEY at the signer's name: Case B puts the stored one back.
		query: func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
			return []dns.RR{}, nil
		},
		resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}},
	}
	h.upstreamCoordinator = stub

	req := buildSignedNonKeyOnlyLeaseUpdateForHandleTest(t, loaded, "host.test.dev.zenr.io.", 3600, false)
	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil || res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success, got %+v", res)
	}
	if stub.sentCount() != 1 {
		t.Fatalf("expected 1 upstream send, got %d", stub.sentCount())
	}

	keys := 0
	for _, rr := range stub.sent[0].Ns {
		got := rr.Header().TTL
		if _, ok := rr.(*dns.KEY); ok {
			keys++
			if got == 0 || got > 120 {
				t.Errorf("re-registered KEY TTL %d, want the remaining lease (at most 120)", got)
			}
			continue
		}
		if got != defaultRecordTTL {
			t.Errorf("forwarded %s: TTL %d, want %d", rr, got, defaultRecordTTL)
		}
	}
	if keys != 1 {
		t.Fatalf("expected the re-registered KEY upstream, got %d KEYs", keys)
	}

	stored := h.leaseManager.FindByName(signerKey.Hdr.Name)
	if len(stored) != 1 || !dnsname.EqualFold(stored[0].KeyRR.Hdr.Name, signerKey.Hdr.Name) || stored[0].KeyRR.Hdr.TTL != 3600 {
		t.Fatalf("expected the stored KEY to keep TTL 3600, got %+v", stored)
	}
}
