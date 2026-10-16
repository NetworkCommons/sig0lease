package updatecore

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"codeberg.org/miekg/dns"
)

// startTestAuthoritative serves DNS on one local port over both UDP and TCP, answering each
// query with answer(tcp, query), and returns the "host:port" to reach it. A dns.Server serves
// only one of its Listener and PacketConn, so each transport gets its own.
func startTestAuthoritative(t *testing.T, answer func(tcp bool, query *dns.Msg) *dns.Msg) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("listen udp on the tcp port: %v", err)
	}
	handler := dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		_, tcp := w.RemoteAddr().(*net.TCPAddr)
		answer(tcp, r).WriteTo(w)
	})
	for _, srv := range []*dns.Server{{Listener: ln, Handler: handler}, {PacketConn: pc, Handler: handler}} {
		// Wait for the server to start before returning: shutting down a dns.Server whose
		// ListenAndServe hasn't initialized yet races with that initialization.
		started := make(chan struct{})
		srv.NotifyStartedFunc = func(context.Context) { close(started) }
		go func() { _ = srv.ListenAndServe() }()
		<-started
		t.Cleanup(func() { srv.Shutdown(context.Background()) })
	}
	return ln.Addr().String()
}

func replyTo(query *dns.Msg, rcode uint16, answer ...dns.RR) *dns.Msg {
	resp := &dns.Msg{MsgHeader: query.MsgHeader, Question: query.Question, Answer: answer}
	resp.Response = true
	resp.Rcode = rcode
	return resp
}

// TestQueryRRs_FallsBackToTCPOnTruncation: the server answers over UDP with TC=1 and no
// records -- what an answer too large for UDP looks like -- and over TCP with the record.
// QueryRRs must return the TCP answer rather than read the truncated one as "nothing
// published", as the RFC 9664 handler's own copy of this query did before it moved here.
func TestQueryRRs_FallsBackToTCPOnTruncation(t *testing.T) {
	txt, err := dns.New(`host.example. 60 IN TXT "big"`)
	if err != nil {
		t.Fatalf("build TXT: %v", err)
	}
	var udpQueries, tcpQueries atomic.Int32
	addr := startTestAuthoritative(t, func(tcp bool, query *dns.Msg) *dns.Msg {
		if !tcp {
			udpQueries.Add(1)
			resp := replyTo(query, dns.RcodeSuccess)
			resp.Truncated = true
			return resp
		}
		tcpQueries.Add(1)
		return replyTo(query, dns.RcodeSuccess, txt)
	})
	c := NewCoordinator(testLogger(), nil, &StaticUpstream{Zone: "example.", Addr: addr})

	rrs, err := c.QueryRRs(context.Background(), "example.", "host.example.", dns.TypeTXT)
	if err != nil {
		t.Fatalf("QueryRRs: %v", err)
	}
	if len(rrs) != 1 || rrs[0].String() != txt.String() {
		t.Fatalf("expected the TCP answer's TXT record, got %v", rrs)
	}
	if udpQueries.Load() != 1 || tcpQueries.Load() != 1 {
		t.Fatalf("expected one truncated UDP answer then one TCP query, got udp=%d tcp=%d", udpQueries.Load(), tcpQueries.Load())
	}
}

func TestQueryRRs_NXDOMAINIsEmptyNotAnError(t *testing.T) {
	addr := startTestAuthoritative(t, func(tcp bool, query *dns.Msg) *dns.Msg {
		return replyTo(query, dns.RcodeNameError)
	})
	c := NewCoordinator(testLogger(), nil, &StaticUpstream{Zone: "example.", Addr: addr})

	rrs, err := c.QueryRRs(context.Background(), "example.", "missing.example.", dns.TypeKEY)
	if err != nil || len(rrs) != 0 {
		t.Fatalf("expected no records and no error for NXDOMAIN, got %v, %v", rrs, err)
	}
}

func TestParentZone(t *testing.T) {
	cases := []struct{ in, want string }{
		{"srp.dev.zenr.io.", "dev.zenr.io"},
		{"srp.dev.zenr.io", "dev.zenr.io"},
		{"io.", ""},
		{"io", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := parentZone(c.in); got != c.want {
			t.Errorf("parentZone(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// soaAt builds the SOA of zone apex with primary server mname.
func soaAt(t *testing.T, apex, mname string) dns.RR {
	t.Helper()
	soa, err := dns.New(apex + " 0 IN SOA " + mname + " root.example. 1 10800 900 604800 86400")
	if err != nil {
		t.Fatalf("build SOA: %v", err)
	}
	return soa
}

// TestDiscovery_OneSOAQuery: a resolver answers an SOA query for a name inside a zone with
// that zone's SOA in the authority section, NXDOMAIN or NOERROR alike, and in the answer for
// the apex itself. Discovery takes the zone and its primary server from that one answer, with
// no further query per parent label.
func TestDiscovery_OneSOAQuery(t *testing.T) {
	zenr := soaAt(t, "zenr.io.", "ns1.free2air.org.")
	var queries atomic.Int32
	addr := startTestAuthoritative(t, func(tcp bool, query *dns.Msg) *dns.Msg {
		queries.Add(1)
		switch query.Question[0].Header().Name {
		case "zenr.io.":
			return replyTo(query, dns.RcodeSuccess, zenr)
		case "dev.zenr.io.":
			resp := replyTo(query, dns.RcodeSuccess)
			resp.Ns = []dns.RR{zenr}
			return resp
		default:
			resp := replyTo(query, dns.RcodeNameError)
			resp.Ns = []dns.RR{zenr}
			return resp
		}
	})
	c := NewCoordinator(testLogger(), []string{addr}, nil)
	ctx := context.Background()

	for _, name := range []string{"test.dev.zenr.io.", "dev.zenr.io.", "zenr.io."} {
		queries.Store(0)
		server, zone, err := c.ResolveSOAMasterServer(ctx, name)
		if err != nil {
			t.Fatalf("ResolveSOAMasterServer(%q): %v", name, err)
		}
		if server != "ns1.free2air.org:53" || zone != "zenr.io." {
			t.Errorf("ResolveSOAMasterServer(%q) = %q, %q; want ns1.free2air.org:53, zenr.io.", name, server, zone)
		}
		if n := queries.Load(); n != 1 {
			t.Errorf("ResolveSOAMasterServer(%q) sent %d queries, want 1", name, n)
		}
		zone, err = c.ResolveAuthoritativeZone(ctx, name)
		if err != nil || zone != "zenr.io." {
			t.Errorf("ResolveAuthoritativeZone(%q) = %q, %v; want zenr.io.", name, zone, err)
		}
	}
}

// TestDiscovery_RejectsRootAndUnrelatedSOA: a name in no delegated zone gets the root's SOA
// in the authority section, and a broken resolver may return the SOA of a zone that doesn't
// hold the name at all; neither is a zone to send UPDATEs to.
func TestDiscovery_RejectsRootAndUnrelatedSOA(t *testing.T) {
	for _, soa := range []dns.RR{soaAt(t, ".", "a.root-servers.net."), soaAt(t, "other.example.", "ns.other.example.")} {
		addr := startTestAuthoritative(t, func(tcp bool, query *dns.Msg) *dns.Msg {
			resp := replyTo(query, dns.RcodeNameError)
			resp.Ns = []dns.RR{soa}
			return resp
		})
		c := NewCoordinator(testLogger(), []string{addr}, nil)
		if server, zone, err := c.ResolveSOAMasterServer(context.Background(), "test.nosuchtld."); err == nil {
			t.Errorf("SOA %s: expected an error, got %q, %q", soa.Header().Name, server, zone)
		}
	}
}
