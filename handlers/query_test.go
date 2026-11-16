package handlers

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
)

// queryRoute is one query a handler passed to the zone's authoritative server.
type queryRoute struct {
	zone string
	req  *dns.Msg
}

// authoritativeAnswer returns a QueryAuthoritative that records each query in seen and answers
// it as an authoritative server would: its question, AA set, a TXT record, and an ID and RD
// bit of its own, which the handler must replace with the query's.
func authoritativeAnswer(t *testing.T, seen *[]queryRoute) func(zoneHint string, req *dns.Msg) (*dns.Msg, error) {
	return func(zoneHint string, req *dns.Msg) (*dns.Msg, error) {
		*seen = append(*seen, queryRoute{zone: zoneHint, req: req})
		resp := &dns.Msg{MsgHeader: dns.MsgHeader{ID: req.ID + 1, Response: true, Authoritative: true}}
		resp.Question = req.Question
		resp.Answer = []dns.RR{srpMustRR(t, req.Question[0].Header().Name+" 300 IN TXT \"live\"")}
		return resp, nil
	}
}

// TestAnswerQuery: each handler answers a query for one of its names with the answer of its
// zone's authoritative server, carrying the query's ID and RD bit, and passes on a name outside
// its zone or in the other handler's deeper zone.
func TestAnswerQuery(t *testing.T) {
	var seen []queryRoute
	uh := newTestHandler() // dev.zenr.io.
	uh.upstreamCoordinator.(*stubUpstreamCoordinator).authoritative = authoritativeAnswer(t, &seen)
	sh, coord := newSRPTestHandler(t)
	sh.upstreamZone = "srp.dev.zenr.io."
	coord.authoritative = authoritativeAnswer(t, &seen)
	if err := SeparateZones([]ZoneHandler{uh, sh}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		h        Handler
		qname    string
		qtype    uint16
		wantZone string // "" for NotRelevant
	}{
		{"name in update_handler's zone", uh, "chat.dev.zenr.io.", dns.TypeTXT, "dev.zenr.io."},
		{"update_handler's apex", uh, "dev.zenr.io.", dns.TypeSOA, "dev.zenr.io."},
		{"name in srp_handler's zone", sh, "_http._tcp.srp.dev.zenr.io.", dns.TypePTR, "srp.dev.zenr.io."},
		{"srp_handler's zone, to update_handler", uh, "demo.srp.dev.zenr.io.", dns.TypeA, ""},
		{"update_handler's zone, to srp_handler", sh, "chat.dev.zenr.io.", dns.TypeTXT, ""},
		{"elsewhere, to update_handler", uh, "example.com.", dns.TypeA, ""},
		{"elsewhere, to srp_handler", sh, "example.com.", dns.TypeA, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen = nil
			r := dns.NewMsg(tc.qname, tc.qtype)
			r.ID = 4242
			r.RecursionDesired = true
			res := tc.h.Handle(context.Background(), stubTCPResponseWriter{}, r)
			if tc.wantZone == "" {
				if res.Status != StatusNotRelevant || len(seen) != 0 {
					t.Fatalf("status %s with %d authoritative queries, want NotRelevant and none", res.Status, len(seen))
				}
				return
			}
			if res.Status != StatusProcessed {
				t.Fatalf("status %s (%s), want Processed", res.Status, res.Reason)
			}
			if len(seen) != 1 || seen[0].zone != tc.wantZone {
				t.Fatalf("authoritative queries %v, want one for zone %s", seen, tc.wantZone)
			}
			if seen[0].req == r {
				t.Fatalf("the handler passed the request itself on, not a copy")
			}
			resp := res.Message
			if resp.ID != r.ID || !resp.RecursionDesired || !resp.Authoritative || len(resp.Answer) != 1 {
				t.Fatalf("reply ID %d RD %v AA %v answers %d, want ID %d, RD and AA set, the one answer",
					resp.ID, resp.RecursionDesired, resp.Authoritative, len(resp.Answer), r.ID)
			}
		})
	}
}

// TestAnswerQuery_AuthoritativeFails: a query for the handler's name that its zone's
// authoritative server does not answer gets SERVFAIL, with the question and Extended DNS Error
// 22 (No Reachable Authority), never the router's upstream forwarding.
func TestAnswerQuery_AuthoritativeFails(t *testing.T) {
	uh := newTestHandler()
	uh.upstreamCoordinator.(*stubUpstreamCoordinator).authoritative = func(string, *dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("no route to ns1")
	}
	r := dns.NewMsg("chat.dev.zenr.io.", dns.TypeTXT)
	r.UDPSize = 1232
	res := uh.Handle(context.Background(), stubTCPResponseWriter{}, r)
	if res.Status != StatusError || res.Message == nil {
		t.Fatalf("status %s, message %v: want Error with a reply", res.Status, res.Message)
	}
	edes := dnsmsg.EDEs(res.Message)
	if res.Message.Rcode != dns.RcodeServerFailure || len(res.Message.Question) != 1 || len(edes) != 1 ||
		edes[0].InfoCode != dns.ExtendedErrorNoReachableAuthority {
		t.Fatalf("reply rcode %d, %d questions, EDEs %v: want SERVFAIL, the question, EDE 22",
			res.Message.Rcode, len(res.Message.Question), edes)
	}
}
