package main

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

func TestClientUsesServerGrantedLeaseForExpiry(t *testing.T) {
	requested := uint32(300)
	granted := uint32(90)

	resp := &dns.Msg{}
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	leaseOpt := leasepkg.Encode8Byte(granted, granted)
	if err := leaseOpt.Encode(opt); err != nil {
		t.Fatalf("encode lease option: %v", err)
	}
	resp.Extra = append(resp.Extra, opt)

	now := time.Unix(1_700_000_000, 0)
	effective := client.EffectiveLeaseDuration(resp, requested)
	if effective != granted {
		t.Fatalf("expected server-granted lease %d, got %d", granted, effective)
	}
	expires := client.ExpiryFromResponse(now, requested, resp)
	if expires.Sub(now) != time.Duration(granted)*time.Second {
		t.Fatalf("expected expiry delta %ds, got %s", granted, expires.Sub(now))
	}
}

func TestClientFallsBackToRequestedLeaseWhenResponseHasNoLeaseOption(t *testing.T) {
	requested := uint32(180)
	resp := &dns.Msg{}
	now := time.Unix(1_700_000_000, 0)

	effective := client.EffectiveLeaseDuration(resp, requested)
	if effective != requested {
		t.Fatalf("expected requested lease %d, got %d", requested, effective)
	}
	expires := client.ExpiryFromResponse(now, requested, resp)
	if expires.Sub(now) != time.Duration(requested)*time.Second {
		t.Fatalf("expected expiry delta %ds, got %s", requested, expires.Sub(now))
	}
}
