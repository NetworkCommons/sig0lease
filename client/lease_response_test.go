package client

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client/clienttest"
)

func TestClientUsesServerGrantedLeaseForExpiry(t *testing.T) {
	requestedLease := uint32(300)
	requestedKeyLease := uint32(600)
	grantedLease := uint32(90)
	grantedKeyLease := uint32(120)

	resp := clienttest.Granted(grantedLease, grantedKeyLease)

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

func TestInterpretResponse(t *testing.T) {
	cases := []struct {
		name    string
		rcode   uint16
		nilResp bool
		want    Outcome
	}{
		{name: "nil response", nilResp: true, want: OutcomeServerFailure},
		{name: "NOERROR", rcode: dns.RcodeSuccess, want: OutcomeSuccess},
		{name: "YXDOMAIN", rcode: dns.RcodeYXDomain, want: OutcomeConflict},
		{name: "REFUSED", rcode: dns.RcodeRefused, want: OutcomeRefused},
		{name: "SERVFAIL", rcode: dns.RcodeServerFailure, want: OutcomeServerFailure},
		{name: "FORMERR (other)", rcode: dns.RcodeFormatError, want: OutcomeOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp *dns.Msg
			if !tc.nilResp {
				resp = &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: tc.rcode}}
			}
			if got := InterpretResponse(resp); got != tc.want {
				t.Fatalf("InterpretResponse() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestGrantedLease_ReadsEchoedOption(t *testing.T) {
	lease, keyLease, ok := GrantedLease(clienttest.Granted(30, 1209600))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if lease != 30 || keyLease != 1209600 {
		t.Fatalf("got lease=%d keyLease=%d, want 30/1209600", lease, keyLease)
	}
}

func TestGrantedLease_NoOption(t *testing.T) {
	resp := &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}
	if _, _, ok := GrantedLease(resp); ok {
		t.Fatal("expected ok=false when the response carries no Update-Lease option")
	}
}
