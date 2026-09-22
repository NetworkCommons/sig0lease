package srp

import (
	"testing"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

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
	resp := &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(dns.DefaultMsgSize)
	lo := leasepkg.Encode8Byte(30, 1209600)
	if err := lo.Encode(opt); err != nil {
		t.Fatalf("encode lease option: %v", err)
	}
	resp.Extra = append(resp.Extra, opt)

	lease, keyLease, ok := GrantedLease(resp)
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
