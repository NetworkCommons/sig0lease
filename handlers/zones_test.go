package handlers

import (
	"context"
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

// SeparateZones tells each handler the zones the others serve below its own, and nothing
// else; two handlers on one zone are refused.
func TestSeparateZones(t *testing.T) {
	cases := []struct {
		name               string
		updateZone         string
		srpZone            string
		wantUpdateExcludes []servedZone
		wantSRPExcludes    []servedZone
		wantErr            bool
	}{
		{name: "SRP nested in RFC 9664", updateZone: "dev.zenr.io.", srpZone: "srp.dev.zenr.io.", wantUpdateExcludes: []servedZone{{zone: "srp.dev.zenr.io.", handler: "srp_handler"}}},
		{name: "RFC 9664 nested in SRP", updateZone: "rr.dev.zenr.io.", srpZone: "dev.zenr.io.", wantSRPExcludes: []servedZone{{zone: "rr.dev.zenr.io.", handler: "update_handler"}}},
		{name: "disjoint", updateZone: "update.test.", srpZone: "srp.test."},
		{name: "same zone, any case", updateZone: "dev.zenr.io.", srpZone: "DEV.zenr.io", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uh := newTestHandler()
			uh.upstreamZone = tc.updateZone
			sh, _ := newSRPTestHandler(t)
			sh.upstreamZone = tc.srpZone

			err := SeparateZones([]ZoneHandler{uh, sh})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for two handlers on one zone")
				}
				return
			}
			if err != nil {
				t.Fatalf("SeparateZones: %v", err)
			}
			if !slices.Equal(uh.deeperZones, tc.wantUpdateExcludes) {
				t.Errorf("update_handler refuses %v, want %v", uh.deeperZones, tc.wantUpdateExcludes)
			}
			if !slices.Equal(sh.deeperZones, tc.wantSRPExcludes) {
				t.Errorf("srp_handler refuses %v, want %v", sh.deeperZones, tc.wantSRPExcludes)
			}
		})
	}
}

// With SRP's zone inside its own, the RFC 9664 handler refuses SRP's names, and names outside
// its zone, before anything goes upstream.
func TestUpdateHandle_NamesNotServed_Refused(t *testing.T) {
	cases := []struct {
		name, owner, wantText string
	}{
		{name: "in srp_handler's zone", owner: "talk.srp.dev.zenr.io.", wantText: "in zone srp.dev.zenr.io., which srp_handler serves"},
		{name: "at srp_handler's apex", owner: "srp.dev.zenr.io.", wantText: "in zone srp.dev.zenr.io., which srp_handler serves"},
		{name: "outside its zone", owner: "talk.example.org.", wantText: "outside zone dev.zenr.io., which update_handler serves"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, loaded := newEDETestHandler(t, nil, noAuthoritativeData)
			stub := h.upstreamCoordinator.(*stubUpstreamCoordinator)
			sh, _ := newSRPTestHandler(t)
			sh.upstreamZone = "srp.dev.zenr.io."
			if err := SeparateZones([]ZoneHandler{h, sh}); err != nil {
				t.Fatalf("SeparateZones: %v", err)
			}

			req := buildSignedLeaseUpdateForHandleTest(t, loaded, tc.owner, leasepkg.Encode8Byte(120, 120), true)
			res := h.Handle(context.Background(), stubResponseWriter{}, req)
			wantErrorReply(t, res, dns.RcodeRefused, dns.ExtendedErrorProhibited, tc.wantText)
			if n := stub.sentCount(); n != 0 {
				t.Fatalf("expected nothing sent upstream, got %d UPDATE(s)", n)
			}
		})
	}
}

// The SRP handler takes an update by its host: one whose host it does not serve -- in the
// RFC 9664 handler's zone inside its own, or outside its zone -- goes to the next handler,
// whatever the Zone Section says.
func TestSRPHandle_HostNotServed_NotRelevant(t *testing.T) {
	for _, host := range []string{"talk.rr.dev.zenr.io.", "talk.example.org."} {
		t.Run(host, func(t *testing.T) {
			h, coord := newSRPTestHandler(t)
			uh := newTestHandler()
			uh.upstreamZone = "rr.dev.zenr.io."
			if err := SeparateZones([]ZoneHandler{uh, h}); err != nil {
				t.Fatalf("SeparateZones: %v", err)
			}

			id := newSRPTestIdentity(t)
			req := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, host)
			if res := h.Handle(context.Background(), stubTCPResponseWriter{}, req); res.Status != StatusNotRelevant {
				t.Fatalf("expected NotRelevant, got %s (%s)", res.Status, res.Reason)
			}
			if len(coord.sent) != 0 {
				t.Fatalf("expected nothing sent upstream, got %d UPDATE(s)", len(coord.sent))
			}
		})
	}
}

// For a host it serves, the SRP handler refuses the other names it does not serve -- in the
// RFC 9664 handler's zone inside its own, or outside its zone -- once its rewrite has made them
// final and before FCFS.
func TestSRPHandle_NamesNotServed_Refused(t *testing.T) {
	cases := []struct {
		name, instance, wantText string
	}{
		{name: "in update_handler's zone", instance: "Widget._http._tcp.rr.dev.zenr.io.", wantText: "in zone rr.dev.zenr.io., which update_handler serves"},
		{name: "outside its zone", instance: "Widget._http._tcp.example.org.", wantText: "outside zone dev.zenr.io., which srp_handler serves"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, coord := newSRPTestHandler(t)
			uh := newTestHandler()
			uh.upstreamZone = "rr.dev.zenr.io."
			if err := SeparateZones([]ZoneHandler{uh, h}); err != nil {
				t.Fatalf("SeparateZones: %v", err)
			}

			id := newSRPTestIdentity(t)
			const host = "talk.dev.zenr.io."
			instance := []srpInstanceSpec{{name: tc.instance, port: 8080, txt: "path=/", svctype: strings.TrimPrefix(tc.instance, "Widget.")}}
			// The root encloses every name, so the Zone Section check passes them all on.
			req := buildSRPUpdate(t, ".", id, host, []string{"192.0.2.1"}, instance, 30, 1209600, host)
			res := h.Handle(context.Background(), stubTCPResponseWriter{}, req)
			wantErrorReply(t, res, dns.RcodeRefused, dns.ExtendedErrorProhibited, tc.wantText)
			if len(coord.sent) != 0 {
				t.Fatalf("expected nothing sent upstream, got %d UPDATE(s)", len(coord.sent))
			}
		})
	}
}

// The Zone Section only has to enclose every name in the Update section: the apex, the
// handler's zone, a signer's name above its records or the root all do; a name outside it is
// NOTZONE, and anything but one entry FORMERR.
func TestRefuseOutsideZoneSection(t *testing.T) {
	cases := []struct {
		name      string
		zone      []string
		wantRcode uint16 // RcodeSuccess: passed on
	}{
		{"zone apex", []string{"zenr.io."}, dns.RcodeSuccess},
		{"handler's zone", []string{"dev.zenr.io."}, dns.RcodeSuccess},
		{"the names' owner", []string{"site.dev.zenr.io."}, dns.RcodeSuccess},
		{"root", []string{"."}, dns.RcodeSuccess},
		{"below a name", []string{"www.site.dev.zenr.io."}, dns.RcodeNotZone},
		{"another zone", []string{"example.org."}, dns.RcodeNotZone},
		{"two entries", []string{"dev.zenr.io.", "zenr.io."}, dns.RcodeFormatError},
		{"none", nil, dns.RcodeFormatError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := new(dns.Msg)
			r.Opcode = dns.OpcodeUpdate
			for _, z := range tc.zone {
				r.Question = append(r.Question, &dns.SOA{Hdr: dns.Header{Name: z, Class: dns.ClassINET}})
			}
			r.Ns = []dns.RR{fcfsTestTXT("site.dev.zenr.io."), fcfsTestTXT("www.site.dev.zenr.io.")}
			res := refuseOutsideZoneSection(r)
			switch {
			case tc.wantRcode == dns.RcodeSuccess && res != nil:
				t.Fatalf("refused: %v", res.Error)
			case tc.wantRcode != dns.RcodeSuccess && (res == nil || res.Message == nil || res.Message.Rcode != tc.wantRcode):
				t.Fatalf("got %+v, want rcode %s", res, dns.RcodeToString[tc.wantRcode])
			}
		})
	}
}

// The RFC 9664 handler answers NOTZONE for names it serves that the Zone Section does not
// enclose, and takes the zone apex there like any other enclosing name.
func TestUpdateHandle_ZoneSection(t *testing.T) {
	for _, tc := range []struct {
		zone      string
		wantRcode uint16
	}{
		{"zenr.io.", dns.RcodeSuccess},
		{"dev.zenr.io.", dns.RcodeSuccess},
		{"other.dev.zenr.io.", dns.RcodeNotZone},
	} {
		t.Run(tc.zone, func(t *testing.T) {
			h, loaded := newEDETestHandler(t, nil, noAuthoritativeData)
			msg, err := dnsmsg.NewLeaseUpdate(tc.zone, []*dns.KEY{loaded.PublicKey}, []dns.RR{fcfsTestTXT("test.dev.zenr.io.")}, 120, 120)
			if err != nil {
				t.Fatalf("build update: %v", err)
			}
			signed, err := sig0.SignMessage(msg, loaded.PublicKey, loaded.PrivateKey)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			res := h.Handle(context.Background(), stubResponseWriter{}, signed)
			if res == nil || res.Message == nil || res.Message.Rcode != tc.wantRcode {
				t.Fatalf("got %+v, want rcode %s", res, dns.RcodeToString[tc.wantRcode])
			}
		})
	}
}
