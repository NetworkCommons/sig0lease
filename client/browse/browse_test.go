package browse

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
)

// zone answers queries from records given in presentation format, as an authoritative server
// would: the records at the name of the type asked, none for any other.
type zone struct {
	mu    sync.Mutex
	rrs   []dns.RR
	asked []string
	fail  string // a "<name> <type>" question that fails
}

// newZone holds records, given in presentation format, with each "\032" in a name made a space,
// as a message from the wire holds it: this library copies a label's bytes into a name string
// as they are, and its parser keeps an escape as it is written (pkg/dnsname/labels.go).
func newZone(t *testing.T, records ...string) *zone {
	z := &zone{}
	for _, s := range records {
		rr, err := dns.New(s)
		if err != nil {
			t.Fatalf("dns.New(%q): %v", s, err)
		}
		rr.Header().Name = strings.ReplaceAll(rr.Header().Name, `\032`, " ")
		if p, ok := rr.(*dns.PTR); ok {
			p.Ptr = strings.ReplaceAll(p.Ptr, `\032`, " ")
		}
		z.rrs = append(z.rrs, rr)
	}
	return z
}

func (z *zone) query(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	q := name + " " + dnsutil.TypeToString(qtype)
	z.mu.Lock()
	defer z.mu.Unlock()
	z.asked = append(z.asked, q)
	if q == z.fail {
		return nil, errors.New("SERVFAIL")
	}
	var out []dns.RR
	for _, rr := range z.rrs {
		if dns.RRToType(rr) == qtype && strings.EqualFold(rr.Header().Name, name) {
			out = append(out, rr)
		}
	}
	return out, nil
}

const domain = "srp.example."

// records is a domain with two types: two web sites, one of them withdrawn between the PTR and
// the SRV questions, and an SSH server; plus a type the enumeration lists in another domain.
var records = []string{
	"_services._dns-sd._udp.srp.example. PTR _http._tcp.srp.example.",
	"_services._dns-sd._udp.srp.example. PTR _ssh._tcp.srp.example.",
	"_services._dns-sd._udp.srp.example. PTR _ipp._tcp.elsewhere.example.",
	"_http._tcp.srp.example. PTR demo\\032http._http._tcp.srp.example.",
	"_http._tcp.srp.example. PTR gone._http._tcp.srp.example.",
	"_ssh._tcp.srp.example. PTR laptop._ssh._tcp.srp.example.",
	"demo\\032http._http._tcp.srp.example. SRV 0 0 8000 demo.srp.example.",
	"demo\\032http._http._tcp.srp.example. TXT \"path=/\" \"v=1\" \"by=caf\\195\\169 \\\"x\\\"\"",
	"laptop._ssh._tcp.srp.example. SRV 0 0 22 laptop.srp.example.",
	"demo.srp.example. A 192.0.2.7",
	"demo.srp.example. AAAA 2001:db8::7",
	"laptop.srp.example. A 192.0.2.9",
}

func TestBrowse(t *testing.T) {
	z := newZone(t, records...)
	d, err := Browse(context.Background(), z.query, "srp.example")
	if err != nil {
		t.Fatal(err)
	}
	want := &Domain{
		Domain: domain,
		Types:  []string{"_http._tcp", "_ssh._tcp"},
		Instances: []Instance{
			{Name: "demo http", Type: "_http._tcp", Target: "demo.srp.example.", Port: 8000, TXT: []string{"path=/", "v=1", `by=café "x"`}, Addresses: []string{"192.0.2.7", "2001:db8::7"}},
			{Name: "gone", Type: "_http._tcp", TXT: []string{}, Addresses: []string{}},
			{Name: "laptop", Type: "_ssh._tcp", Target: "laptop.srp.example.", Port: 22, TXT: []string{}, Addresses: []string{"192.0.2.9"}},
		},
	}
	if !reflect.DeepEqual(d, want) {
		t.Fatalf("Browse:\n got %+v\nwant %+v", d, want)
	}
}

func TestBrowse_Empty(t *testing.T) {
	d, err := Browse(context.Background(), newZone(t).query, domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Types) != 0 || len(d.Instances) != 0 || d.Types == nil || d.Instances == nil {
		t.Fatalf("Browse of an empty domain: %+v, want empty, non-nil lists", d)
	}
}

// TestBrowse_FailedQuestion: any question that fails fails the whole browse, at every round.
func TestBrowse_FailedQuestion(t *testing.T) {
	for _, q := range []string{
		"_services._dns-sd._udp.srp.example. PTR",
		"_ssh._tcp.srp.example. PTR",
		"demo http._http._tcp.srp.example. TXT",
		"laptop._ssh._tcp.srp.example. SRV",
		"demo.srp.example. AAAA",
	} {
		z := newZone(t, records...)
		z.fail = q
		if d, err := Browse(context.Background(), z.query, domain); err == nil {
			t.Errorf("%s failing: Browse = %+v, want an error", q, d)
		}
	}
}

// TestQuerier: each question carries an OPT RR; the answer's records of the type asked at the
// name asked; none for NXDOMAIN; a *RcodeError for any other rcode, with the answer's Extended
// DNS Errors; an error when the exchange fails.
func TestQuerier(t *testing.T) {
	answer := func(rcode uint16, err error, rrs ...string) client.Transport {
		return func(ctx context.Context, addr string, network client.Network, msg *dns.Msg) (*dns.Msg, error) {
			if addr != "http://proxy:8443" || network != client.NetworkDoH {
				t.Fatalf("sent to %s over %s", addr, network)
			}
			if err := msg.Pack(); err != nil {
				t.Fatal(err)
			}
			wire := &dns.Msg{Data: msg.Data}
			if err := wire.Unpack(); err != nil || wire.UDPSize == 0 {
				t.Fatalf("the question has no OPT RR (UDPSize %d, %v)", wire.UDPSize, err)
			}
			if err != nil {
				return nil, err
			}
			resp := &dns.Msg{MsgHeader: dns.MsgHeader{ID: msg.ID, Response: true, Rcode: rcode}, Question: msg.Question}
			if rcode == dns.RcodeRefused {
				resp.Pseudo = []dns.RR{&dns.EDE{InfoCode: dns.ExtendedErrorNotAuthoritative}}
			}
			for _, s := range rrs {
				rr, err := dns.New(s)
				if err != nil {
					t.Fatal(err)
				}
				resp.Answer = append(resp.Answer, rr)
			}
			return resp, nil
		}
	}
	ask := func(send client.Transport) ([]dns.RR, error) {
		return Querier(send, "http://proxy:8443", client.NetworkDoH)(context.Background(), "demo.srp.example.", dns.TypeA)
	}

	rrs, err := ask(answer(dns.RcodeSuccess, nil, "DEMO.srp.example. A 192.0.2.7", `demo.srp.example. TXT "x"`, "other.example. A 192.0.2.8"))
	if err != nil || len(rrs) != 1 || rrs[0].(*dns.A).Addr.String() != "192.0.2.7" {
		t.Fatalf("NOERROR: %v, %v; want the one A record at the name", rrs, err)
	}
	if rrs, err := ask(answer(dns.RcodeNameError, nil)); err != nil || len(rrs) != 0 {
		t.Fatalf("NXDOMAIN: %v, %v; want none", rrs, err)
	}
	if _, err := ask(answer(dns.RcodeServerFailure, nil)); err == nil || !strings.Contains(err.Error(), "SERVFAIL") {
		t.Fatalf("SERVFAIL: %v, want an error naming it", err)
	}
	_, err = ask(answer(dns.RcodeRefused, nil))
	var re *RcodeError
	if !errors.As(err, &re) || re.Rcode != dns.RcodeRefused || len(re.EDEs) != 1 || re.EDEs[0].InfoCode != dns.ExtendedErrorNotAuthoritative ||
		!strings.Contains(err.Error(), "REFUSED, Extended DNS Error 20 (Not Authoritative)") {
		t.Fatalf("REFUSED with EDE 20: %v, want a *RcodeError with the EDE, naming both", err)
	}
	if _, err := ask(answer(0, errors.New("connection refused"))); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("failed exchange: %v, want its error", err)
	}
}

// Answers follows CNAMEs: through a resolver's answer, which holds the whole chain; by asking
// for the target an authoritative server's answer stops at; to no records when the target has
// none; not at all for a CNAME question; and not round a loop. Through the proxy, a target
// outside its zones is refused, and Fallback asks the resolvers the name asked.
func TestAnswers_CNAMEs(t *testing.T) {
	rr := func(s string) dns.RR {
		r, err := dns.New(s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	const name = "_dnslink.site.example.org."
	alias := rr(name + " CNAME _dnslink.site.host.example.")
	txt := rr(`_dnslink.site.host.example. TXT "dnslink=/ipfs/QmOne"`)
	type answers map[string][]dns.RR // by name asked
	server := func(a answers, asked *[]string) func(context.Context, string, uint16) (*dns.Msg, error) {
		return func(_ context.Context, n string, qtype uint16) (*dns.Msg, error) {
			*asked = append(*asked, n)
			resp := &dns.Msg{MsgHeader: dns.MsgHeader{Response: true}, Answer: a[n]}
			if a[n] == nil {
				req := dns.NewMsg(n, qtype)
				req.UDPSize = dns.DefaultMsgSize
				resp.Rcode = dns.RcodeRefused
				dnsmsg.AddEDE(resp, req, dns.ExtendedErrorNotAuthoritative, "")
			}
			return resp, nil
		}
	}
	for _, tc := range []struct {
		name    string
		qtype   uint16
		answers answers
		want    []dns.RR
		asked   []string
		wantErr string
	}{
		{"resolver: the whole chain", dns.TypeTXT, answers{name: {alias, txt}}, []dns.RR{txt}, []string{name}, ""},
		{"authoritative: the target asked", dns.TypeTXT, answers{name: {alias}, "_dnslink.site.host.example.": {txt}}, []dns.RR{txt}, []string{name, "_dnslink.site.host.example."}, ""},
		{"the target has none", dns.TypeTXT, answers{name: {alias}, "_dnslink.site.host.example.": {}}, nil, []string{name, "_dnslink.site.host.example."}, ""},
		{"a CNAME question", dns.TypeCNAME, answers{name: {alias}}, []dns.RR{alias}, []string{name}, ""},
		{"a loop", dns.TypeTXT, answers{name: {alias, rr("_dnslink.site.host.example. CNAME " + name)}}, nil, nil, "more than 8 CNAMEs"},
	} {
		var asked []string
		rrs, err := Answers(server(tc.answers, &asked))(context.Background(), name, tc.qtype)
		switch {
		case tc.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: error %v, want %q", tc.name, err, tc.wantErr)
			}
		case err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case !slices.Equal(rrs, tc.want) || !slices.Equal(asked, tc.asked):
			t.Errorf("%s: %v, asking %v; want %v, asking %v", tc.name, rrs, asked, tc.want, tc.asked)
		}
	}

	var proxyAsked, resolverAsked []string
	q := Fallback(Answers(server(answers{name: {alias}}, &proxyAsked)), Answers(server(answers{name: {alias, txt}}, &resolverAsked)))
	rrs, err := q(context.Background(), name, dns.TypeTXT)
	if err != nil || !slices.Equal(rrs, []dns.RR{txt}) || !slices.Equal(resolverAsked, []string{name}) {
		t.Errorf("through the proxy: %v, %v, the resolvers asked %v; want the TXT record, the resolvers asked %s", rrs, err, resolverAsked, name)
	}
}

// TestFallback: only a refusal as not served, REFUSED with Extended DNS Error 20, is asked of
// the other Query, whose answer is then the answer; every other answer and failure is the first
// Query's, and a failure of the other carries both.
func TestFallback(t *testing.T) {
	refusal := func(rcode uint16, codes ...uint16) error {
		e := &RcodeError{Name: "xmpp.example.org.", Type: dns.TypeA, Rcode: rcode}
		for _, c := range codes {
			e.EDEs = append(e.EDEs, &dns.EDE{InfoCode: c})
		}
		return e
	}
	a, err := dns.New("xmpp.example.org. A 192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		first   error
		other   error
		asked   bool
		wantErr []string // what the error names; nil: no error
		wantRRs int
	}{
		{"answered", nil, nil, false, nil, 0},
		{"not served", refusal(dns.RcodeRefused, dns.ExtendedErrorProhibited, dns.ExtendedErrorNotAuthoritative), nil, true, nil, 1},
		{"not served, other fails", refusal(dns.RcodeRefused, dns.ExtendedErrorNotAuthoritative), errors.New("timeout"), true, []string{"REFUSED", "timeout"}, 0},
		{"refused, no EDE", refusal(dns.RcodeRefused), nil, false, []string{"REFUSED"}, 0},
		{"refused, another EDE", refusal(dns.RcodeRefused, dns.ExtendedErrorProhibited), nil, false, []string{"REFUSED"}, 0},
		{"SERVFAIL with EDE 20", refusal(dns.RcodeServerFailure, dns.ExtendedErrorNotAuthoritative), nil, false, []string{"SERVFAIL"}, 0},
		{"exchange fails", errors.New("connection refused"), nil, false, []string{"connection refused"}, 0},
	} {
		asked := false
		first := func(context.Context, string, uint16) ([]dns.RR, error) { return nil, tc.first }
		other := func(_ context.Context, name string, qtype uint16) ([]dns.RR, error) {
			asked = true
			if name != "xmpp.example.org." || qtype != dns.TypeA {
				t.Errorf("%s: other asked %s %d", tc.name, name, qtype)
			}
			if tc.other != nil {
				return nil, tc.other
			}
			return []dns.RR{a}, nil
		}
		rrs, err := Fallback(first, other)(context.Background(), "xmpp.example.org.", dns.TypeA)
		if asked != tc.asked {
			t.Errorf("%s: other asked: %v, want %v", tc.name, asked, tc.asked)
		}
		if len(rrs) != tc.wantRRs {
			t.Errorf("%s: %d records, want %d", tc.name, len(rrs), tc.wantRRs)
		}
		if (err != nil) != (tc.wantErr != nil) {
			t.Fatalf("%s: error %v, want one naming %q", tc.name, err, tc.wantErr)
		}
		for _, w := range tc.wantErr {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error %q does not name %q", tc.name, err, w)
			}
		}
	}
}
