package handlers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// newEDETestHandler returns an UpdateHandler for dev.zenr.io. set up with cfgExtra, the
// signing key it loaded, and the stub upstream that answers its queries with query.
func newEDETestHandler(t *testing.T, cfgExtra map[string]any, query func(ctx context.Context, zoneHint, name string, rrType uint16) ([]dns.RR, error)) (*UpdateHandler, *keyrec.LoadedKey) {
	t.Helper()
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	cfg := map[string]any{"upstream_zone": "dev.zenr.io.", "keystore_dir": keystoreDir}
	for k, v := range cfgExtra {
		cfg[k] = v
	}
	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(cfg); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	h.upstreamCoordinator = &stubUpstreamCoordinator{query: query, resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}
	return h, loaded
}

// wantErrorReply fails unless res is an error reply with rcode and exactly one Extended DNS
// Error, infoCode, whose text contains textPart.
func wantErrorReply(t *testing.T, res *HandlerResult, rcode, infoCode uint16, textPart string) {
	t.Helper()
	if res == nil || res.Message == nil {
		t.Fatalf("expected a response message")
	}
	if res.Message.Rcode != rcode {
		t.Fatalf("rcode = %s, want %s", dns.RcodeToString[res.Message.Rcode], dns.RcodeToString[rcode])
	}
	edes := dnsmsg.EDEs(res.Message)
	if len(edes) != 1 || edes[0].InfoCode != infoCode || !strings.Contains(edes[0].ExtraText, textPart) {
		t.Fatalf("Extended DNS Errors = %v, want one with code %d and text containing %q", edes, infoCode, textPart)
	}
}

func noAuthoritativeData(ctx context.Context, zoneHint, name string, rrType uint16) ([]dns.RR, error) {
	return []dns.RR{}, nil
}

// A record of a blacklisted type makes a well-formed request that local policy refuses:
// REFUSED (RFC 2136 S2.2) with Extended DNS Error 18 (Prohibited), not FORMERR.
func TestHandle_BlacklistedTypeIsRefusedProhibited(t *testing.T) {
	h, loaded := newEDETestHandler(t, map[string]any{"blacklisted_types": []string{"TXT"}}, noAuthoritativeData)
	req := buildSignedLeaseUpdateForHandleTest(t, loaded, "host.dev.zenr.io.", leasepkg.Encode8Byte(120, 120), true)
	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	wantErrorReply(t, res, dns.RcodeRefused, dns.ExtendedErrorProhibited, "blacklisted")
}

// A failed authoritative lookup inside a check that refuses requests -- the signer's KEY, or
// a duplicate check -- is answered like every other failed authoritative lookup, SERVFAIL with
// Extended DNS Error 22 (No Reachable Authority), not refused: the request may be fine.
func TestHandle_AuthoritativeLookupFailureIsServfail(t *testing.T) {
	lookupFailure := errors.New("no authoritative server reachable")
	for _, tc := range []struct {
		name          string
		failType      uint16 // the record type whose lookup fails
		signerInReq   bool   // the signer's KEY in the Update section, so SIG(0) needs no lookup
		lease         *leasepkg.LeaseOption
		wantTextMatch string
	}{
		// No KEY in the request and none in the lease store: the signer's KEY is looked up.
		{"signer KEY", dns.TypeKEY, false, leasepkg.Encode8Byte(120, 0), "failed to resolve signer KEY"},
		// Case A: the new KEY's own duplicate check.
		{"KEY duplicate check", dns.TypeKEY, true, leasepkg.Encode8Byte(120, 120), "authoritative duplicate check failed"},
		// Case A: the records' duplicate check (filterDuplicateRegistrations).
		{"record duplicate check", dns.TypeTXT, true, leasepkg.Encode8Byte(120, 120), "authoritative duplicate check failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := func(ctx context.Context, zoneHint, name string, rrType uint16) ([]dns.RR, error) {
				if rrType == tc.failType {
					return nil, lookupFailure
				}
				return []dns.RR{}, nil
			}
			h, loaded := newEDETestHandler(t, nil, query)
			req := buildSignedLeaseUpdateForHandleTest(t, loaded, "host.dev.zenr.io.", tc.lease, tc.signerInReq)
			res := h.Handle(context.Background(), stubResponseWriter{}, req)
			wantErrorReply(t, res, dns.RcodeServerFailure, dns.ExtendedErrorNoReachableAuthority, tc.wantTextMatch)
			if !errors.Is(res.Error, lookupFailure) {
				t.Fatalf("result error %v does not wrap the lookup failure", res.Error)
			}
		})
	}
}
