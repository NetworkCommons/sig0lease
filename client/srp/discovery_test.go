package srp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func srvRR(target string, priority, weight, port uint16) *dns.SRV {
	return &dns.SRV{
		Hdr: dns.Header{Name: "_dnssd-srp._tcp.example.com.", Class: dns.ClassINET, TTL: 3600},
		SRV: rdata.SRV{Priority: priority, Weight: weight, Port: port, Target: target},
	}
}

// fakeDNS answers SOA, SRV and A/AAAA queries the way a recursive resolver would for a fixed
// set of zones, and records every query it gets as "NAME TYPE".
type fakeDNS struct {
	apexes []string                // zone apexes, as FQDNs
	srv    map[string][]*dns.SRV   // SRV records by owner name
	hosts  map[string][]netip.Addr // A and AAAA records by owner name
	// minimal leaves the SOA out of the Authority section of negative answers, as a
	// resolver configured for minimal responses may, so zoneApex has to strip labels.
	minimal   bool
	err       error  // returned for every query when set, or only for failQuery if that is set too
	failQuery string // "NAME TYPE"
	queries   []string
}

func (f *fakeDNS) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	q := name + " " + dns.TypeToString[qtype]
	f.queries = append(f.queries, q)
	if f.err != nil && (f.failQuery == "" || f.failQuery == q) {
		return nil, f.err
	}
	resp := &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}
	switch qtype {
	case dns.TypeSOA:
		apex := f.enclosingApex(name)
		if apex == "" {
			break
		}
		soa := &dns.SOA{Hdr: dns.Header{Name: apex, Class: dns.ClassINET, TTL: 3600}}
		if apex == name {
			resp.Answer = []dns.RR{soa}
		} else if !f.minimal {
			resp.Ns = []dns.RR{soa}
		}
	case dns.TypeSRV:
		if len(f.srv[name]) == 0 {
			resp.Rcode = dns.RcodeNameError
		}
		for _, s := range f.srv[name] {
			resp.Answer = append(resp.Answer, s)
		}
	case dns.TypeA, dns.TypeAAAA:
		for _, addr := range f.hosts[name] {
			hdr := dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600}
			if addr.Is4() && qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: rdata.A{Addr: addr}})
			}
			if addr.Is6() && qtype == dns.TypeAAAA {
				resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: rdata.AAAA{Addr: addr}})
			}
		}
	}
	return resp, nil
}

// registrarHosts gives every SRV target the tests use an address, numbered so each test can
// tell which target Discover picked.
var registrarHosts = map[string][]netip.Addr{
	"registrar.example.com.":        {netip.MustParseAddr("192.0.2.1")},
	"apex-registrar.example.com.":   {netip.MustParseAddr("192.0.2.2")},
	"domain-registrar.example.com.": {netip.MustParseAddr("192.0.2.3")},
	"parent.example.com.":           {netip.MustParseAddr("192.0.2.4")},
	"child.example.com.":            {netip.MustParseAddr("192.0.2.5")},
	"first.example.com.":            {netip.MustParseAddr("192.0.2.6")},
	"second.example.com.":           {netip.MustParseAddr("192.0.2.7")},
	"light.example.com.":            {netip.MustParseAddr("192.0.2.8")},
	"heavy.example.com.":            {netip.MustParseAddr("192.0.2.9")},
	"mid-registrar.example.com.":    {netip.MustParseAddr("192.0.2.10")},
}

func (f *fakeDNS) enclosingApex(name string) string {
	best := ""
	for _, apex := range f.apexes {
		if (apex == "." || name == apex || strings.HasSuffix(name, "."+apex)) && len(apex) > len(best) {
			best = apex
		}
	}
	return best
}

func TestDiscover_DomainIsZoneApex(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com."},
		srv:    map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {srvRR("registrar.example.com.", 0, 0, 853)}},
		hosts:  registrarHosts,
	}
	addr, err := Discover(context.Background(), f.query, "example.com.", DiscoveryClosest, NetworkTCP)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "192.0.2.1:853" {
		t.Fatalf("addr = %q, want %q", addr, "192.0.2.1:853")
	}
	want := []string{"example.com. SOA", "_dnssd-srp._tcp.example.com. SRV", "registrar.example.com. A"}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

// subdomainRecordDNS serves the example.com. zone with a registrar record both at the apex
// and at srp.dev.example.com., a plain subdomain inside the zone.
func subdomainRecordDNS() *fakeDNS {
	return &fakeDNS{
		apexes: []string{"example.com."},
		srv: map[string][]*dns.SRV{
			"_dnssd-srp._tcp.example.com.":         {srvRR("apex-registrar.example.com.", 0, 0, 853)},
			"_dnssd-srp._tcp.srp.dev.example.com.": {srvRR("domain-registrar.example.com.", 0, 0, 853)},
		},
		hosts: registrarHosts,
	}
}

// TestDiscover_PrefersClosestRecord: DiscoveryClosest uses the record at the registration
// domain itself over the apex's, and asks nothing further up once it has one.
func TestDiscover_PrefersClosestRecord(t *testing.T) {
	f := subdomainRecordDNS()
	addr, err := Discover(context.Background(), f.query, "srp.dev.example.com.", DiscoveryClosest, NetworkTCP)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "192.0.2.3:853" {
		t.Fatalf("addr = %q, want domain-registrar's address (the SRV at the domain itself)", addr)
	}
	want := []string{"srp.dev.example.com. SOA", "_dnssd-srp._tcp.srp.dev.example.com. SRV", "domain-registrar.example.com. A"}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

// TestDiscover_ApexOnlyIgnoresRecordsBelowApex: DiscoveryApexOnly looks only at the apex of
// the enclosing zone, as RFC 9665 S3.1.1 specifies, so the record at the domain itself is
// never asked for.
func TestDiscover_ApexOnlyIgnoresRecordsBelowApex(t *testing.T) {
	f := subdomainRecordDNS()
	addr, err := Discover(context.Background(), f.query, "srp.dev.example.com.", DiscoveryApexOnly, NetworkTCP)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "192.0.2.2:853" {
		t.Fatalf("addr = %q, want apex-registrar's address (the SRV at the zone apex)", addr)
	}
	want := []string{"srp.dev.example.com. SOA", "_dnssd-srp._tcp.example.com. SRV", "apex-registrar.example.com. A"}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

// TestDiscover_WalksUpToApex: with no record below the apex, DiscoveryClosest asks at the
// domain and at each parent in turn, and ends with the apex's record -- the one RFC 9665
// S3.1.1 finds.
func TestDiscover_WalksUpToApex(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com."},
		srv:    map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {srvRR("apex-registrar.example.com.", 0, 0, 853)}},
		hosts:  registrarHosts,
	}
	addr, err := Discover(context.Background(), f.query, "srp.dev.example.com.", DiscoveryClosest, NetworkTCP)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "192.0.2.2:853" {
		t.Fatalf("addr = %q, want apex-registrar's address", addr)
	}
	want := []string{
		"srp.dev.example.com. SOA",
		"_dnssd-srp._tcp.srp.dev.example.com. SRV",
		"_dnssd-srp._tcp.dev.example.com. SRV",
		"_dnssd-srp._tcp.example.com. SRV",
		"apex-registrar.example.com. A",
	}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

// TestDiscover_RecordCoversSubdomains: a record at dev.example.com. names the registrar for
// srp.dev.example.com. too, ahead of the apex's, the way the apex record covers its whole
// zone.
func TestDiscover_RecordCoversSubdomains(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com."},
		srv: map[string][]*dns.SRV{
			"_dnssd-srp._tcp.example.com.":     {srvRR("apex-registrar.example.com.", 0, 0, 853)},
			"_dnssd-srp._tcp.dev.example.com.": {srvRR("mid-registrar.example.com.", 0, 0, 853)},
		},
		hosts: registrarHosts,
	}
	addr, err := Discover(context.Background(), f.query, "srp.dev.example.com.", DiscoveryClosest, NetworkTCP)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "192.0.2.10:853" {
		t.Fatalf("addr = %q, want mid-registrar's address (the SRV at the domain's parent)", addr)
	}
	want := []string{
		"srp.dev.example.com. SOA",
		"_dnssd-srp._tcp.srp.dev.example.com. SRV",
		"_dnssd-srp._tcp.dev.example.com. SRV",
		"mid-registrar.example.com. A",
	}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

// TestDiscover_StopsAtZoneCut: lab.srp.dev.example.com. lies in the srp.dev.example.com.
// zone, which has no record. Discovery fails without asking above that zone's apex: the
// records at dev.example.com. and example.com. belong to the parent zone, whose registrar
// speaks for nothing in the child.
func TestDiscover_StopsAtZoneCut(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com.", "srp.dev.example.com."},
		srv: map[string][]*dns.SRV{
			"_dnssd-srp._tcp.example.com.":     {srvRR("parent.example.com.", 0, 0, 853)},
			"_dnssd-srp._tcp.dev.example.com.": {srvRR("mid-registrar.example.com.", 0, 0, 853)},
		},
		hosts: registrarHosts,
	}
	_, err := Discover(context.Background(), f.query, "lab.srp.dev.example.com.", DiscoveryClosest, NetworkTCP)
	if err == nil {
		t.Fatal("expected an error when the enclosing zone has no record")
	}
	want := []string{
		"lab.srp.dev.example.com. SOA",
		"_dnssd-srp._tcp.lab.srp.dev.example.com. SRV",
		"_dnssd-srp._tcp.srp.dev.example.com. SRV",
	}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
	if !strings.Contains(err.Error(), "_dnssd-srp._tcp.lab.srp.dev.example.com., _dnssd-srp._tcp.srp.dev.example.com.") {
		t.Fatalf("error should name every name asked, got: %v", err)
	}
}

// TestDiscover_QueryErrorStopsWalk: a failed SRV query below the apex ends discovery with
// that error. Moving on to the parent could pick a registrar that a record at the
// unanswered name would have overridden.
func TestDiscover_QueryErrorStopsWalk(t *testing.T) {
	wantErr := errors.New("resolver timed out")
	f := &fakeDNS{
		apexes:    []string{"example.com."},
		srv:       map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {srvRR("apex-registrar.example.com.", 0, 0, 853)}},
		hosts:     registrarHosts,
		err:       wantErr,
		failQuery: "_dnssd-srp._tcp.srp.dev.example.com. SRV",
	}
	_, err := Discover(context.Background(), f.query, "srp.dev.example.com.", DiscoveryClosest, NetworkTCP)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the query error to propagate, got: %v", err)
	}
	want := []string{"srp.dev.example.com. SOA", "_dnssd-srp._tcp.srp.dev.example.com. SRV"}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

// TestDiscover_RootZoneSOA: a resolver that doesn't know the TLD answers with the root
// zone's SOA (srp.test. asked of a public resolver, say). There is no zone to look in, so
// discovery fails right away instead of asking for "_dnssd-srp._tcp.<name>" up to the root.
func TestDiscover_RootZoneSOA(t *testing.T) {
	f := &fakeDNS{apexes: []string{"."}}
	_, err := Discover(context.Background(), f.query, "srp.test.", DiscoveryClosest, NetworkTCP)
	if err == nil || !strings.Contains(err.Error(), "root zone") {
		t.Fatalf("expected a root-zone error, got: %v", err)
	}
	if want := []string{"srp.test. SOA"}; !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

func TestDiscover_RejectsUnknownMode(t *testing.T) {
	f := &fakeDNS{apexes: []string{"example.com."}}
	_, err := Discover(context.Background(), f.query, "example.com.", DiscoveryMode(7), NetworkTCP)
	if err == nil || !strings.Contains(err.Error(), "unknown DiscoveryMode") {
		t.Fatalf("expected an unknown-mode error, got: %v", err)
	}
	if len(f.queries) != 0 {
		t.Fatalf("queries = %q, want none before the mode is checked", f.queries)
	}
}

func TestRegistrarSearchNames(t *testing.T) {
	cases := []struct {
		name         string
		domain, apex string
		mode         DiscoveryMode
		want         []string // nil: an error is expected
	}{
		{"domain is the apex", "example.com.", "example.com.", DiscoveryClosest, []string{"example.com."}},
		{"closest walks up to the apex", "a.b.example.com.", "example.com.", DiscoveryClosest, []string{"a.b.example.com.", "b.example.com.", "example.com."}},
		{"apex only", "a.b.example.com.", "example.com.", DiscoveryApexOnly, []string{"example.com."}},
		// RFC 4343: the SOA owner's case need not match domain's; names keep domain's spelling.
		{"apex matched without regard to case", "A.B.Example.COM.", "example.com.", DiscoveryClosest, []string{"A.B.Example.COM.", "B.Example.COM.", "Example.COM."}},
		{"apex in another tree", "a.example.com.", "example.org.", DiscoveryClosest, nil},
		{"apex below domain", "example.com.", "a.example.com.", DiscoveryApexOnly, nil},
		// Parents are whole labels: example.com. is a string suffix of badexample.com.,
		// but not a parent of it.
		{"string suffix that is not a parent", "a.badexample.com.", "example.com.", DiscoveryClosest, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := registrarSearchNames(tc.domain, tc.apex, tc.mode)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("registrarSearchNames: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("names = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDiscover_ZoneCutBelowParent: srp.dev.example.com. is delegated as its own zone, so
// its own apex -- not the parent's -- holds the SRV.
func TestDiscover_ZoneCutBelowParent(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com.", "srp.dev.example.com."},
		srv: map[string][]*dns.SRV{
			"_dnssd-srp._tcp.example.com.":         {srvRR("parent.example.com.", 0, 0, 853)},
			"_dnssd-srp._tcp.srp.dev.example.com.": {srvRR("child.example.com.", 0, 0, 853)},
		},
		hosts: registrarHosts,
	}
	addr, err := Discover(context.Background(), f.query, "srp.dev.example.com.", DiscoveryClosest, NetworkTCP)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "192.0.2.5:853" {
		t.Fatalf("addr = %q, want child's address (the delegated zone's own SRV)", addr)
	}
}

// TestDiscover_StripsLabelsWithoutAuthoritySOA: RFC 8765 S6.1 step 4 -- a negative answer
// with no SOA in it means asking again one label up, until an SOA turns up. Apex-only, so
// that the one SRV query after the SOA queries is the apex's.
func TestDiscover_StripsLabelsWithoutAuthoritySOA(t *testing.T) {
	f := &fakeDNS{
		apexes:  []string{"example.com."},
		srv:     map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {srvRR("registrar.example.com.", 0, 0, 853)}},
		hosts:   registrarHosts,
		minimal: true,
	}
	if _, err := Discover(context.Background(), f.query, "srp.dev.example.com.", DiscoveryApexOnly, NetworkTCP); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	want := []string{"srp.dev.example.com. SOA", "dev.example.com. SOA", "example.com. SOA", "_dnssd-srp._tcp.example.com. SRV", "registrar.example.com. A"}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

// TestDiscover_GivesUpAboveTLD: with no SOA anywhere, the search stops after the two-label
// name and never queries the TLD itself (RFC 8765 S6.1 step 4).
func TestDiscover_GivesUpAboveTLD(t *testing.T) {
	f := &fakeDNS{}
	if _, err := Discover(context.Background(), f.query, "a.example.com.", DiscoveryClosest, NetworkTCP); err == nil {
		t.Fatal("expected an error when no SOA record is found")
	}
	want := []string{"a.example.com. SOA", "example.com. SOA"}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

func TestDiscover_NoTrailingDotOnDomain(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com."},
		srv:    map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {srvRR("registrar.example.com.", 0, 0, 853)}},
		hosts:  registrarHosts,
	}
	if _, err := Discover(context.Background(), f.query, "example.com", DiscoveryClosest, NetworkTCP); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	want := []string{"example.com. SOA", "_dnssd-srp._tcp.example.com. SRV", "registrar.example.com. A"}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q (domain without trailing dot)", f.queries, want)
	}
}

func TestDiscover_PicksLowestPriority(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com."},
		srv: map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {
			srvRR("second.example.com.", 10, 0, 853),
			srvRR("first.example.com.", 0, 0, 853),
		}},
		hosts: registrarHosts,
	}
	addr, err := Discover(context.Background(), f.query, "example.com.", DiscoveryClosest, NetworkTCP)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "192.0.2.6:853" {
		t.Fatalf("addr = %q, want the lowest-priority target", addr)
	}
}

func TestDiscover_TiebreaksOnHighestWeight(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com."},
		srv: map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {
			srvRR("light.example.com.", 0, 10, 853),
			srvRR("heavy.example.com.", 0, 90, 853),
		}},
		hosts: registrarHosts,
	}
	addr, err := Discover(context.Background(), f.query, "example.com.", DiscoveryClosest, NetworkTCP)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "192.0.2.9:853" {
		t.Fatalf("addr = %q, want the highest-weight target among equal priorities", addr)
	}
}

// TestDiscover_FallsBackToAAAA: a target with only an AAAA record is reached over IPv6.
func TestDiscover_FallsBackToAAAA(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com."},
		srv:    map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {srvRR("v6.example.com.", 0, 0, 853)}},
		hosts:  map[string][]netip.Addr{"v6.example.com.": {netip.MustParseAddr("2001:db8::53")}},
	}
	addr, err := Discover(context.Background(), f.query, "example.com.", DiscoveryClosest, NetworkTCP)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "[2001:db8::53]:853" {
		t.Fatalf("addr = %q, want the target's AAAA address", addr)
	}
	want := []string{"example.com. SOA", "_dnssd-srp._tcp.example.com. SRV", "v6.example.com. A", "v6.example.com. AAAA"}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

func TestDiscover_TargetWithoutAddress(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com."},
		srv:    map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {srvRR("nowhere.example.com.", 0, 0, 853)}},
	}
	_, err := Discover(context.Background(), f.query, "example.com.", DiscoveryClosest, NetworkTCP)
	if err == nil || !strings.Contains(err.Error(), "no A or AAAA record") {
		t.Fatalf("expected a missing-address error, got: %v", err)
	}
}

func TestDiscover_NoRecords(t *testing.T) {
	f := &fakeDNS{apexes: []string{"example.com."}}
	if _, err := Discover(context.Background(), f.query, "example.com.", DiscoveryClosest, NetworkTCP); err == nil {
		t.Fatal("expected an error when no SRV records are found")
	}
}

func TestDiscover_QueryError(t *testing.T) {
	wantErr := errors.New("network exploded")
	f := &fakeDNS{err: wantErr}
	_, err := Discover(context.Background(), f.query, "example.com.", DiscoveryClosest, NetworkTCP)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected the query error to propagate, got: %v", err)
	}
	if len(f.queries) != 1 {
		t.Fatalf("queries = %q, want the search to stop at the first failed query", f.queries)
	}
}

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

// TestLiveDNSQuery_SkipsFailingResolvers: SERVFAIL means that resolver failed, so the next
// one is asked; NXDOMAIN is an answer, returned as is.
func TestLiveDNSQuery_SkipsFailingResolvers(t *testing.T) {
	query := LiveDNSQuery([]string{startTestResolver(t, dns.RcodeServerFailure), startTestResolver(t, dns.RcodeNameError)})
	resp, err := query(context.Background(), "_dnssd-srp._tcp.example.com.", dns.TypeSRV)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want the second resolver's NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}

func TestLiveDNSQuery_AllResolversFail(t *testing.T) {
	query := LiveDNSQuery([]string{startTestResolver(t, dns.RcodeServerFailure), startTestResolver(t, dns.RcodeRefused)})
	if _, err := query(context.Background(), "example.com.", dns.TypeSOA); err == nil {
		t.Fatal("expected an error when every resolver fails")
	}
}

// tlsAndPlainDNS serves example.com. with a registrar for each service: plain TCP
// ("_dnssd-srp._tcp") at registrar.example.com., DNS-over-TLS ("_dnssd-srp-tls._tcp") at
// apex-registrar.example.com., as RFC 9665 Appendix A's example zone publishes both.
func tlsAndPlainDNS() *fakeDNS {
	return &fakeDNS{
		apexes: []string{"example.com."},
		srv: map[string][]*dns.SRV{
			"_dnssd-srp._tcp.example.com.":     {srvRR("registrar.example.com.", 0, 0, 53)},
			"_dnssd-srp-tls._tcp.example.com.": {srvRR("apex-registrar.example.com.", 0, 0, 853)},
		},
		hosts: registrarHosts,
	}
}

// TestDiscover_TLSLooksUpTLSService: with NetworkTLS, discovery asks for
// "_dnssd-srp-tls._tcp" (RFC 9665 S3.1.1) and returns that record's registrar and port.
func TestDiscover_TLSLooksUpTLSService(t *testing.T) {
	f := tlsAndPlainDNS()
	addr, err := Discover(context.Background(), f.query, "example.com.", DiscoveryClosest, NetworkTLS)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "192.0.2.2:853" {
		t.Fatalf("addr = %q, want %q", addr, "192.0.2.2:853")
	}
	want := []string{"example.com. SOA", "_dnssd-srp-tls._tcp.example.com. SRV", "apex-registrar.example.com. A"}
	if !slices.Equal(f.queries, want) {
		t.Fatalf("queries = %q, want %q", f.queries, want)
	}
}

// TestDiscover_UDPLooksUpPlainService: NetworkUDP uses the same "_dnssd-srp._tcp" record as
// NetworkTCP; only NetworkTLS has a service of its own.
func TestDiscover_UDPLooksUpPlainService(t *testing.T) {
	f := tlsAndPlainDNS()
	addr, err := Discover(context.Background(), f.query, "example.com.", DiscoveryClosest, NetworkUDP)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "192.0.2.1:53" {
		t.Fatalf("addr = %q, want %q", addr, "192.0.2.1:53")
	}
}

// TestDiscover_TLSDoesNotFallBackToPlainService: a zone that publishes only
// "_dnssd-srp._tcp" has no registrar for a TLS requester. RFC 9665 S7: a requester able to
// use TLS SHOULD NOT fall back to TCP, so discovery fails instead of returning the plain one.
func TestDiscover_TLSDoesNotFallBackToPlainService(t *testing.T) {
	f := &fakeDNS{
		apexes: []string{"example.com."},
		srv:    map[string][]*dns.SRV{"_dnssd-srp._tcp.example.com.": {srvRR("registrar.example.com.", 0, 0, 53)}},
		hosts:  registrarHosts,
	}
	_, err := Discover(context.Background(), f.query, "srp.example.com.", DiscoveryClosest, NetworkTLS)
	if err == nil {
		t.Fatal("Discover found a registrar for TLS although only _dnssd-srp._tcp is published")
	}
	if !strings.Contains(err.Error(), "_dnssd-srp-tls._tcp.srp.example.com., _dnssd-srp-tls._tcp.example.com.") {
		t.Fatalf("error does not name the TLS SRV names it tried: %v", err)
	}
	for _, q := range f.queries {
		if strings.HasPrefix(q, "_dnssd-srp._tcp.") {
			t.Fatalf("TLS discovery asked for the plain service: %q", f.queries)
		}
	}
}

func TestDiscover_RejectsUnknownNetwork(t *testing.T) {
	f := tlsAndPlainDNS()
	if _, err := Discover(context.Background(), f.query, "example.com.", DiscoveryClosest, Network(7)); err == nil {
		t.Fatal("Discover accepted an unknown Network")
	}
	if len(f.queries) != 0 {
		t.Fatalf("Discover queried DNS before rejecting the Network: %q", f.queries)
	}
}
