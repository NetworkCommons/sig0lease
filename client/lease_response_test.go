package client

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

func TestClientUsesServerGrantedLeaseForExpiry(t *testing.T) {
	requestedLease := uint32(300)
	requestedKeyLease := uint32(600)
	grantedLease := uint32(90)
	grantedKeyLease := uint32(120)

	resp := &dns.Msg{}
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	leaseOpt := leasepkg.Encode8Byte(grantedLease, grantedKeyLease)
	if err := leaseOpt.Encode(opt); err != nil {
		t.Fatalf("encode lease option: %v", err)
	}
	resp.Extra = append(resp.Extra, opt)

	now := time.Unix(1_700_000_000, 0)
	effectiveLease, effectiveKeyLease := EffectiveLeaseDuration(resp, requestedLease, requestedKeyLease)
	if effectiveLease != grantedLease {
		t.Fatalf("expected server-granted lease %d, got %d", grantedLease, effectiveLease)
	}
	if effectiveKeyLease != grantedKeyLease {
		t.Fatalf("expected server-granted key-lease %d, got %d", grantedKeyLease, effectiveKeyLease)
	}
	dataExpiry, keyExpiry := ExpiryFromResponse(now, requestedLease, requestedKeyLease, resp)
	if dataExpiry.Sub(now) != time.Duration(grantedLease)*time.Second {
		t.Fatalf("expected data expiry delta %ds, got %s", grantedLease, dataExpiry.Sub(now))
	}
	if keyExpiry.Sub(now) != time.Duration(grantedKeyLease)*time.Second {
		t.Fatalf("expected key expiry delta %ds, got %s", grantedKeyLease, keyExpiry.Sub(now))
	}
}

func TestClientFallsBackToRequestedLeaseWhenResponseHasNoLeaseOption(t *testing.T) {
	requestedLease := uint32(180)
	requestedKeyLease := uint32(360)
	resp := &dns.Msg{}
	now := time.Unix(1_700_000_000, 0)

	effectiveLease, effectiveKeyLease := EffectiveLeaseDuration(resp, requestedLease, requestedKeyLease)
	if effectiveLease != requestedLease {
		t.Fatalf("expected requested lease %d, got %d", requestedLease, effectiveLease)
	}
	if effectiveKeyLease != requestedKeyLease {
		t.Fatalf("expected requested key-lease %d, got %d", requestedKeyLease, effectiveKeyLease)
	}
	dataExpiry, keyExpiry := ExpiryFromResponse(now, requestedLease, requestedKeyLease, resp)
	if dataExpiry.Sub(now) != time.Duration(requestedLease)*time.Second {
		t.Fatalf("expected data expiry delta %ds, got %s", requestedLease, dataExpiry.Sub(now))
	}
	if keyExpiry.Sub(now) != time.Duration(requestedKeyLease)*time.Second {
		t.Fatalf("expected key expiry delta %ds, got %s", requestedKeyLease, keyExpiry.Sub(now))
	}
}
