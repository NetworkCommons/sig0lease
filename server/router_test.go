package server

import (
	"context"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/handlers"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
)

// stubHandler is a minimal handlers.Handler implementation used only to
// verify Router.Shutdown() fans out to every registered handler.
type stubHandler struct {
	name         string
	startHits    *int
	shutdownHits *int
}

func (s *stubHandler) Name() string                   { return s.name }
func (s *stubHandler) CanHandle(opcode uint8) bool    { return false }
func (s *stubHandler) Setup(cfg map[string]any) error { return nil }
func (s *stubHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *handlers.HandlerResult {
	return handlers.NewNotRelevantResult("stub")
}
func (s *stubHandler) Start()    { *s.startHits++ }
func (s *stubHandler) Shutdown() { *s.shutdownHits++ }

func TestRouter_Shutdown_CallsShutdownOnEveryRegisteredHandler(t *testing.T) {
	logger := logging.NewLogger("debug")
	router, err := NewRouter(map[uint8][]string{}, logger, nil, config.ServerConfig{RequestTimeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	var startA, startB, hitsA, hitsB int
	router.RegisterHandler(&stubHandler{name: "a", startHits: &startA, shutdownHits: &hitsA})
	router.RegisterHandler(&stubHandler{name: "b", startHits: &startB, shutdownHits: &hitsB})

	router.Start()
	router.Shutdown()

	if startA != 1 || startB != 1 {
		t.Fatalf("expected each handler's Start() called once, got a=%d b=%d", startA, startB)
	}
	if hitsA != 1 || hitsB != 1 {
		t.Fatalf("expected each handler's Shutdown() called once, got a=%d b=%d", hitsA, hitsB)
	}
}

// deadlineHandler records the deadline of the context it is handed.
type deadlineHandler struct {
	deadline time.Time
	ok       bool
}

func (d *deadlineHandler) Name() string                   { return "deadline" }
func (d *deadlineHandler) CanHandle(opcode uint8) bool    { return opcode == dns.OpcodeUpdate }
func (d *deadlineHandler) Setup(cfg map[string]any) error { return nil }
func (d *deadlineHandler) Start()                         {}
func (d *deadlineHandler) Shutdown()                      {}
func (d *deadlineHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *handlers.HandlerResult {
	d.deadline, d.ok = ctx.Deadline()
	return handlers.NewProcessedResult(new(dns.Msg))
}

// Route hands the handlers a context carrying server.request_timeout's deadline, even when
// the caller's own context has none.
func TestRouter_Route_GivesHandlersTheRequestDeadline(t *testing.T) {
	const timeout = 7 * time.Second
	router, err := NewRouter(map[uint8][]string{dns.OpcodeUpdate: {"deadline"}}, logging.NewLogger("debug"), nil, config.ServerConfig{RequestTimeout: timeout})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	h := &deadlineHandler{}
	router.RegisterHandler(h)

	msg := new(dns.Msg)
	msg.Opcode = dns.OpcodeUpdate
	before := time.Now()
	router.Route(context.Background(), nil, msg)
	after := time.Now()

	if !h.ok {
		t.Fatal("handler got a context with no deadline")
	}
	if h.deadline.Before(before.Add(timeout)) || h.deadline.After(after.Add(timeout)) {
		t.Fatalf("handler deadline %s is not %s after the call (called between %s and %s)", h.deadline, timeout, before, after)
	}
}

func TestNewRouter_RejectsNonPositiveRequestTimeout(t *testing.T) {
	if _, err := NewRouter(map[uint8][]string{}, logging.NewLogger("debug"), nil, config.ServerConfig{}); err == nil {
		t.Fatal("NewRouter accepted a zero request timeout")
	}
}

// ednsQuery returns a query for name/qtype as the router receives it: unpacked from the
// wire, with an OPT RR (UDP size 1232).
func ednsQuery(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := dns.NewMsg(name, qtype)
	m.UDPSize = 1232
	if err := m.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}
	got := &dns.Msg{Data: append([]byte(nil), m.Data...)}
	if err := got.Unpack(); err != nil {
		t.Fatalf("unpack query: %v", err)
	}
	return got
}

// onlyEDE returns the one Extended DNS Error in resp, failing unless there is exactly one.
func onlyEDE(t *testing.T, resp *dns.Msg) *dns.EDE {
	t.Helper()
	edes := dnsmsg.EDEs(resp)
	if len(edes) != 1 {
		t.Fatalf("Extended DNS Errors = %v, want exactly one", edes)
	}
	return edes[0]
}

// With server.diagnostics off the dump query is refused, with code 18 (Prohibited) and no
// dump; with it on it is answered.
func TestRouter_DumpQueryNeedsDiagnostics(t *testing.T) {
	for _, diagnostics := range []bool{false, true} {
		router, err := NewRouter(map[uint8][]string{}, logging.NewLogger("error"), nil, config.ServerConfig{RequestTimeout: 15 * time.Second, Diagnostics: diagnostics})
		if err != nil {
			t.Fatalf("NewRouter: %v", err)
		}
		resp := router.Route(context.Background(), nil, ednsQuery(t, dumpQueryDebugName, dns.TypeTXT))
		if !diagnostics {
			if resp.Rcode != dns.RcodeRefused || len(resp.Answer) != 0 {
				t.Fatalf("diagnostics off: rcode %s with %d answers, want REFUSED and none", dns.RcodeToString[resp.Rcode], len(resp.Answer))
			}
			if ede := onlyEDE(t, resp); ede.InfoCode != dns.ExtendedErrorProhibited || ede.ExtraText != "" {
				t.Fatalf("diagnostics off: EDE %s, want 18 (Prohibited) without text", dnsmsg.FormatEDE(ede))
			}
			continue
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
			t.Fatalf("diagnostics on: rcode %s with %d answers, want NOERROR with the dump", dns.RcodeToString[resp.Rcode], len(resp.Answer))
		}
	}
}

// errorHandler answers every UPDATE with a REFUSED reply carrying a reason.
type errorHandler struct{}

func (errorHandler) Name() string                   { return "refuser" }
func (errorHandler) CanHandle(opcode uint8) bool    { return opcode == dns.OpcodeUpdate }
func (errorHandler) Setup(cfg map[string]any) error { return nil }
func (errorHandler) Start()                         {}
func (errorHandler) Shutdown()                      {}
func (errorHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *handlers.HandlerResult {
	resp := &dns.Msg{MsgHeader: r.MsgHeader}
	resp.Response = true
	resp.Rcode = dns.RcodeRefused
	dnsmsg.AddEDE(resp, r, dns.ExtendedErrorProhibited, "signer not authorized")
	return handlers.NewErrorResult(resp, "refused", nil)
}

// A handler's error reply keeps its Extended DNS Error's reason text only with
// server.diagnostics on; its code stays either way.
func TestRouter_HandlerErrorReasonNeedsDiagnostics(t *testing.T) {
	for _, diagnostics := range []bool{false, true} {
		router, err := NewRouter(map[uint8][]string{dns.OpcodeUpdate: {"refuser"}}, logging.NewLogger("error"), nil, config.ServerConfig{RequestTimeout: 15 * time.Second, Diagnostics: diagnostics})
		if err != nil {
			t.Fatalf("NewRouter: %v", err)
		}
		router.RegisterHandler(errorHandler{})
		req := ednsQuery(t, "example.", dns.TypeSOA)
		req.Opcode = dns.OpcodeUpdate
		resp := router.Route(context.Background(), nil, req)
		want := ""
		if diagnostics {
			want = "signer not authorized"
		}
		if ede := onlyEDE(t, resp); ede.InfoCode != dns.ExtendedErrorProhibited || ede.ExtraText != want {
			t.Fatalf("diagnostics %v: EDE %s, want 18 (Prohibited) with text %q", diagnostics, dnsmsg.FormatEDE(ede), want)
		}
	}
}

// A query the router cannot forward is answered SERVFAIL with code 22 (No Reachable
// Authority), and the reason only with server.diagnostics on.
func TestRouter_ForwardFailureIsNoReachableAuthority(t *testing.T) {
	for _, diagnostics := range []bool{false, true} {
		// No resolver: forwardMessage fails at once.
		router, err := NewRouter(map[uint8][]string{}, logging.NewLogger("error"), nil, config.ServerConfig{RequestTimeout: 15 * time.Second, Diagnostics: diagnostics, Forward: true})
		if err != nil {
			t.Fatalf("NewRouter: %v", err)
		}
		req := ednsQuery(t, "example.", dns.TypeA)
		resp := router.Route(context.Background(), nil, req)
		if resp.Rcode != dns.RcodeServerFailure || resp.ID != req.ID || len(resp.Question) != 1 {
			t.Fatalf("rcode %s, ID %d (query %d), %d questions; want SERVFAIL echoing the query", dns.RcodeToString[resp.Rcode], resp.ID, req.ID, len(resp.Question))
		}
		ede := onlyEDE(t, resp)
		if ede.InfoCode != dns.ExtendedErrorNoReachableAuthority || (ede.ExtraText != "") != diagnostics {
			t.Fatalf("diagnostics %v: EDE %s, want 22 (No Reachable Authority), text only with diagnostics", diagnostics, dnsmsg.FormatEDE(ede))
		}
	}
}

// declineHandler declines every request (NotRelevant), as a handler does with one it does not
// take.
type declineHandler struct{}

func (declineHandler) Name() string                   { return "decliner" }
func (declineHandler) CanHandle(opcode uint8) bool    { return opcode == dns.OpcodeUpdate }
func (declineHandler) Setup(cfg map[string]any) error { return nil }
func (declineHandler) Start()                         {}
func (declineHandler) Shutdown()                      {}
func (declineHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *handlers.HandlerResult {
	return handlers.NewNotRelevantResult("not mine")
}

// With server.forward off, what no handler takes -- an opcode with no processing rule, or a
// request every handler of its rule declines -- is answered REFUSED with code 20 (Not
// Authoritative), echoing the query, its reason only with server.diagnostics on; the upstreams
// are not asked (there is no resolver here: asking would answer SERVFAIL with code 22).
func TestRouter_UnhandledRefusedWithoutForward(t *testing.T) {
	update := ednsQuery(t, "example.", dns.TypeSOA)
	update.Opcode = dns.OpcodeUpdate
	requests := map[string]*dns.Msg{
		"query with no rule":            ednsQuery(t, "example.", dns.TypeA),
		"update every handler declines": update,
	}
	for _, diagnostics := range []bool{false, true} {
		router, err := NewRouter(map[uint8][]string{dns.OpcodeUpdate: {"decliner"}}, logging.NewLogger("error"), nil, config.ServerConfig{RequestTimeout: 15 * time.Second, Diagnostics: diagnostics})
		if err != nil {
			t.Fatalf("NewRouter: %v", err)
		}
		router.RegisterHandler(declineHandler{})
		for name, req := range requests {
			resp := router.Route(context.Background(), nil, req)
			if resp.Rcode != dns.RcodeRefused || resp.ID != req.ID || len(resp.Question) != 1 || len(resp.Answer) != 0 {
				t.Fatalf("%s: rcode %s, ID %d (query %d), %d questions, %d answers; want REFUSED echoing the query", name, dns.RcodeToString[resp.Rcode], resp.ID, req.ID, len(resp.Question), len(resp.Answer))
			}
			ede := onlyEDE(t, resp)
			if ede.InfoCode != dns.ExtendedErrorNotAuthoritative || (ede.ExtraText != "") != diagnostics {
				t.Fatalf("%s, diagnostics %v: EDE %s, want 20 (Not Authoritative), text only with diagnostics", name, diagnostics, dnsmsg.FormatEDE(ede))
			}
		}
	}
}
