package handlers

import (
	"context"
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
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

// With the RFC 9664 handler's zone inside its own, the SRP handler refuses that zone's names,
// and names outside its zone, once its rewrite has made them final and before FCFS.
func TestSRPHandle_NamesNotServed_Refused(t *testing.T) {
	cases := []struct {
		name, host, wantText string
	}{
		{name: "in update_handler's zone", host: "talk.rr.dev.zenr.io.", wantText: "in zone rr.dev.zenr.io., which update_handler serves"},
		{name: "outside its zone", host: "talk.example.org.", wantText: "outside zone dev.zenr.io., which srp_handler serves"},
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
			req := buildSRPUpdate(t, srpTestZone, id, tc.host, []string{"192.0.2.1"}, oneWidgetInstance(), 30, 1209600, tc.host)
			res := h.Handle(context.Background(), stubTCPResponseWriter{}, req)
			wantErrorReply(t, res, dns.RcodeRefused, dns.ExtendedErrorProhibited, tc.wantText)
			if len(coord.sent) != 0 {
				t.Fatalf("expected nothing sent upstream, got %d UPDATE(s)", len(coord.sent))
			}
		})
	}
}
