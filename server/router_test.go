package server

import (
	"context"
	"testing"

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
	logger := logging.NewLogger("debug", "text")
	router, err := NewRouter(map[uint8]string{}, logger, nil)
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
