package dnsmsg

import (
	"testing"

	"codeberg.org/miekg/dns"
)

// wireRoundTrip packs m and unpacks the bytes into a new message, as a server or client
// receives it.
func wireRoundTrip(t *testing.T, m *dns.Msg) *dns.Msg {
	t.Helper()
	if err := m.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	got := &dns.Msg{Data: append([]byte(nil), m.Data...)}
	if err := got.Unpack(); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return got
}

func errorReply(req *dns.Msg) *dns.Msg {
	resp := &dns.Msg{MsgHeader: req.MsgHeader}
	resp.Response = true
	resp.Rcode = dns.RcodeRefused
	return resp
}

func TestAddEDEOnlyForRequestWithOPT(t *testing.T) {
	withOPT := dns.NewMsg("example.", dns.TypeA)
	withOPT.UDPSize = 1232
	req := wireRoundTrip(t, withOPT)

	resp := errorReply(req)
	AddEDE(resp, req, dns.ExtendedErrorProhibited, "signer not authorized")
	got := wireRoundTrip(t, resp)
	edes := EDEs(got)
	if len(edes) != 1 || edes[0].InfoCode != dns.ExtendedErrorProhibited || edes[0].ExtraText != "signer not authorized" {
		t.Fatalf("reply EDEs = %v, want one 18 with the text", edes)
	}

	plain := wireRoundTrip(t, dns.NewMsg("example.", dns.TypeA))
	if plain.UDPSize != 0 {
		t.Fatalf("request without OPT unpacked with UDPSize %d", plain.UDPSize)
	}
	resp = errorReply(plain)
	AddEDE(resp, plain, dns.ExtendedErrorProhibited, "signer not authorized")
	if got := wireRoundTrip(t, resp); len(EDEs(got)) != 0 || got.UDPSize != 0 {
		t.Fatalf("reply to a request without OPT has EDEs %v, UDPSize %d; want neither", EDEs(got), got.UDPSize)
	}
}

func TestStripEDETextKeepsCodes(t *testing.T) {
	m := new(dns.Msg)
	m.Pseudo = append(m.Pseudo,
		&dns.EDE{InfoCode: dns.ExtendedErrorProhibited, ExtraText: "a"},
		&dns.EDE{InfoCode: dns.ExtendedErrorNoReachableAuthority, ExtraText: "b"})
	StripEDEText(m)
	edes := EDEs(m)
	if len(edes) != 2 || edes[0].InfoCode != dns.ExtendedErrorProhibited || edes[1].InfoCode != dns.ExtendedErrorNoReachableAuthority {
		t.Fatalf("codes changed: %v", edes)
	}
	for _, e := range edes {
		if e.ExtraText != "" {
			t.Fatalf("text kept: %q", e.ExtraText)
		}
	}
}

func TestFormatEDE(t *testing.T) {
	for _, tc := range []struct {
		ede  dns.EDE
		want string
	}{
		{dns.EDE{InfoCode: dns.ExtendedErrorProhibited, ExtraText: "no"}, "18 (Prohibited): no"},
		{dns.EDE{InfoCode: dns.ExtendedErrorNotSupported}, "21 (Not Supported)"},
		{dns.EDE{InfoCode: 4000, ExtraText: "x"}, "4000 (Unassigned): x"},
	} {
		if got := FormatEDE(&tc.ede); got != tc.want {
			t.Errorf("FormatEDE(%d, %q) = %q, want %q", tc.ede.InfoCode, tc.ede.ExtraText, got, tc.want)
		}
	}
}
