package server

import (
	"context"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/handlers"
	"github.com/NetworkCommons/sig0lease/logging"
)

// stubHandler is a minimal handlers.Handler implementation used only to
// verify Router.Shutdown() fans out to every registered handler.
type stubHandler struct {
	name         string
	shutdownHits *int
}

func (s *stubHandler) Name() string                   { return s.name }
func (s *stubHandler) CanHandle(opcode uint8) bool    { return false }
func (s *stubHandler) Setup(cfg map[string]any) error { return nil }
func (s *stubHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *handlers.HandlerResult {
	return handlers.NewNotRelevantResult("stub")
}
func (s *stubHandler) Shutdown() { *s.shutdownHits++ }

func TestRouter_Shutdown_CallsShutdownOnEveryRegisteredHandler(t *testing.T) {
	logger := logging.NewLogger("debug")
	router, err := NewRouter(map[uint8][]string{}, logger, nil, 15*time.Second)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	var hitsA, hitsB int
	router.RegisterHandler(&stubHandler{name: "a", shutdownHits: &hitsA})
	router.RegisterHandler(&stubHandler{name: "b", shutdownHits: &hitsB})

	router.Shutdown()

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
func (d *deadlineHandler) Shutdown()                      {}
func (d *deadlineHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *handlers.HandlerResult {
	d.deadline, d.ok = ctx.Deadline()
	return handlers.NewProcessedResult(new(dns.Msg))
}

// Route hands the handlers a context carrying server.request_timeout's deadline, even when
// the caller's own context has none.
func TestRouter_Route_GivesHandlersTheRequestDeadline(t *testing.T) {
	const timeout = 7 * time.Second
	router, err := NewRouter(map[uint8][]string{dns.OpcodeUpdate: {"deadline"}}, logging.NewLogger("debug"), nil, timeout)
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
	if _, err := NewRouter(map[uint8][]string{}, logging.NewLogger("debug"), nil, 0); err == nil {
		t.Fatal("NewRouter accepted a zero request timeout")
	}
}
