package dnszone

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
)

// startTestResolver serves DNS over UDP on a local port, answering every query with an empty
// response carrying rcode, and returns the "host:port" to reach it.
func startTestResolver(t *testing.T, rcode uint16) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	handler := dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := &dns.Msg{MsgHeader: r.MsgHeader, Question: r.Question}
		resp.Response = true
		resp.Rcode = rcode
		resp.WriteTo(w)
	})
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	// Wait for the server to start before returning: shutting down a dns.Server whose
	// ListenAndServe hasn't initialized yet races with that initialization.
	started := make(chan struct{})
	srv.NotifyStartedFunc = func(context.Context) { close(started) }
	go func() { _ = srv.ListenAndServe() }()
	<-started
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return pc.LocalAddr().String()
}

// TestResolvers_SkipsFailingResolvers: SERVFAIL means that resolver failed, so the next
// one is asked; NXDOMAIN is an answer, returned as is.
func TestResolvers_SkipsFailingResolvers(t *testing.T) {
	query := Resolvers([]string{startTestResolver(t, dns.RcodeServerFailure), startTestResolver(t, dns.RcodeNameError)})
	resp, err := query(context.Background(), "_dnssd-srp._tcp.example.com.", dns.TypeSRV)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want the second resolver's NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}

// TestResolvers_AllResolversFail: the error gives every resolver's failure, not just the
// last one's.
func TestResolvers_AllResolversFail(t *testing.T) {
	servfail, refused := startTestResolver(t, dns.RcodeServerFailure), startTestResolver(t, dns.RcodeRefused)
	query := Resolvers([]string{servfail, refused})
	_, err := query(context.Background(), "example.com.", dns.TypeSOA)
	if err == nil {
		t.Fatal("expected an error when every resolver fails")
	}
	for _, want := range []string{servfail + " answered SERVFAIL", refused + " answered REFUSED"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
}

func TestResolvers_NoResolvers(t *testing.T) {
	if _, err := Resolvers(nil)(context.Background(), "example.com.", dns.TypeSOA); err == nil {
		t.Fatal("expected an error with no resolvers to ask")
	}
}

// fakeResolver answers SOA queries for one zone, zenr.io., recording each name asked. A name
// below the apex gets NOERROR with the SOA in the Authority section, or, with minimal, with
// no SOA at all: what Google Public DNS answered the registrar at times for srp.dev.zenr.io.
type fakeResolver struct {
	minimal bool
	asked   []string
}

func (f *fakeResolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	f.asked = append(f.asked, name)
	soa, err := dns.New("zenr.io. 360 IN SOA ns1.free2air.org. root.free2air.org. 1 10800 900 604800 86400")
	if err != nil {
		return nil, err
	}
	resp := &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}
	switch {
	case !strings.HasSuffix(name, "zenr.io."):
		resp.Rcode = dns.RcodeNameError
	case name == "zenr.io.":
		resp.Answer = []dns.RR{soa}
	case !f.minimal:
		resp.Ns = []dns.RR{soa}
	}
	return resp, nil
}

// TestApex_OneQueryWhenTheSOAIsThere: the SOA in the Answer (at the apex) or the Authority
// section (below it) settles it with one query.
func TestApex_OneQueryWhenTheSOAIsThere(t *testing.T) {
	for _, name := range []string{"zenr.io.", "srp.dev.zenr.io", "_wg._udp.srp.dev.zenr.io."} {
		f := &fakeResolver{}
		soa, err := Apex(context.Background(), f.query, name)
		if err != nil {
			t.Fatalf("Apex(%q): %v", name, err)
		}
		if soa.Hdr.Name != "zenr.io." || soa.Ns != "ns1.free2air.org." {
			t.Errorf("Apex(%q) = %s, want zenr.io.'s SOA", name, soa)
		}
		if len(f.asked) != 1 {
			t.Errorf("Apex(%q) asked %q, want one query", name, f.asked)
		}
	}
}

// TestApex_WalksUpPastAnswersWithoutSOA: a negative answer with no SOA (RFC 8765 S6.1 step 4)
// sends the search to the parent name, label by label, up to the apex, whose SOA is the
// answer itself.
func TestApex_WalksUpPastAnswersWithoutSOA(t *testing.T) {
	f := &fakeResolver{minimal: true}
	soa, err := Apex(context.Background(), f.query, "srp.dev.zenr.io.")
	if err != nil {
		t.Fatalf("Apex: %v", err)
	}
	if soa.Hdr.Name != "zenr.io." || soa.Ns != "ns1.free2air.org." {
		t.Errorf("Apex = %s, want zenr.io.'s SOA", soa)
	}
	if want := []string{"srp.dev.zenr.io.", "dev.zenr.io.", "zenr.io."}; !slices.Equal(f.asked, want) {
		t.Errorf("asked %q, want %q", f.asked, want)
	}
}

// TestApex_StopsAboveTheTLD: with no SOA in any answer, the search ends at the two-label name
// and never asks for the TLD's SOA, or the root's.
func TestApex_StopsAboveTheTLD(t *testing.T) {
	var asked []string
	empty := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		asked = append(asked, name)
		return &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}, nil
	}
	if soa, err := Apex(context.Background(), empty, "srp.dev.zenr.io."); err == nil {
		t.Fatalf("Apex = %s, want an error", soa)
	}
	if want := []string{"srp.dev.zenr.io.", "dev.zenr.io.", "zenr.io."}; !slices.Equal(asked, want) {
		t.Errorf("asked %q, want %q", asked, want)
	}
}

// TestApex_RejectsRootAndUnrelatedSOA: the root's SOA (the TLD does not exist) and the SOA of
// a zone that does not hold the name are no zone of the name's.
func TestApex_RejectsRootAndUnrelatedSOA(t *testing.T) {
	for _, owner := range []string{".", "other.example."} {
		soa, err := dns.New(owner + " 360 IN SOA ns.example. root.example. 1 10800 900 604800 86400")
		if err != nil {
			t.Fatalf("build SOA: %v", err)
		}
		query := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
			return &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeNameError}, Ns: []dns.RR{soa}}, nil
		}
		if got, err := Apex(context.Background(), query, "test.nosuchtld."); err == nil {
			t.Errorf("SOA of %s: Apex = %s, want an error", owner, got)
		}
	}
}

// TestApex_QueryErrorEndsTheSearch: a failed query is the search's error, with no further
// query.
func TestApex_QueryErrorEndsTheSearch(t *testing.T) {
	wantErr := errors.New("no resolver answered")
	asked := 0
	failing := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		asked++
		return nil, wantErr
	}
	if _, err := Apex(context.Background(), failing, "srp.dev.zenr.io."); !errors.Is(err, wantErr) || asked != 1 {
		t.Fatalf("Apex: %v after %d queries, want %v after 1", err, asked, wantErr)
	}
}
