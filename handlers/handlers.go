// Package handlers provides opcode-specific processing modules for the DNS proxy.
package handlers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// Handler is an interface for a DNS processing module.
type Handler interface {
	// Name returns the unique name of this handler
	Name() string

	// CanHandle returns true if this handler can process the given opcode
	CanHandle(opcode uint8) bool

	// Handle processes a DNS message and returns a HandlerResult.
	// The result status determines how the router handles the response:
	//   - StatusProcessed: Send the response message to the client
	//   - StatusNotRelevant: Packet not relevant to this handler, apply default upstream routing
	//   - StatusError: Error occurred, send error response to client
	Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult

	// Setup initializes the handler with configuration
	Setup(cfg map[string]any) error

	// Shutdown releases any resources this handler owns (background
	// goroutines, open files). Called exactly once during server shutdown.
	Shutdown()
}

// BaseHandler provides common functionality for handlers.
type BaseHandler struct {
	name    string
	opcodes []uint8
	logger  *logging.Logger
}

// SetLogger sets the logger for this handler.
func (b *BaseHandler) SetLogger(logger *logging.Logger) {
	b.logger = logger
}

// Name returns the handler's name.
func (b *BaseHandler) Name() string {
	return b.name
}

// CanHandle returns true if this handler handles the given opcode.
func (b *BaseHandler) CanHandle(opcode uint8) bool {
	for _, op := range b.opcodes {
		if op == opcode {
			return true
		}
	}
	return false
}

// Shutdown is a no-op default; handlers that own no resources needing
// release on shutdown do not need to override it.
func (b *BaseHandler) Shutdown() {}

// makeErrorResponse builds a minimal error response echoing req's header/question, with
// rcode set. msg is currently unused (kept as a parameter for call-site readability --
// see the "Note" below); shared by UpdateHandler and SRPHandler, whose two prior
// method-per-handler copies were byte-for-byte identical.
//
// Note: we don't include detailed error messages in the response. Errors are logged
// locally but responses use standard DNS rcodes. In future versions, we can add extended
// error EDNS options.
func makeErrorResponse(req *dns.Msg, rcode uint16, _ string) *dns.Msg {
	resp := &dns.Msg{MsgHeader: req.MsgHeader, Question: req.Question}
	resp.Response = true
	resp.Rcode = rcode
	return resp
}

// rcodeDescription renders resp's RCODE for a log line, or "no response" for a nil resp --
// the small "was there even a response, and what did it say" formatting repeated at every
// upstream-forward call site that has to report a rejected or missing response.
func rcodeDescription(resp *dns.Msg) string {
	if resp == nil {
		return "no response"
	}
	return fmt.Sprintf("rcode=%d (%s)", resp.Rcode, dns.RcodeToString[resp.Rcode])
}

// buildLeaseManagerFromConfig builds a LeaseStorage backend from a handler's "storage"
// config block. "memory" (or an omitted "type") is the same zero-persistence in-memory
// store both handlers' NewXxxHandler() constructors already default to; "file"
// additionally loads/saves a human-readable JSON snapshot at "path". Any unrecognized
// "type", or a "file" type missing "path", is a hard error -- never a silent fallback to
// the default. Shared by UpdateHandler.Setup and SRPHandler.Setup, whose two prior
// method-per-handler copies were identical apart from which handler's logger the "file"
// backend's save-error callback closed over -- logger takes that place here.
func buildLeaseManagerFromConfig(storageCfg map[string]any, logger *logging.Logger) (leasepkg.LeaseStorage, error) {
	storageType := "memory"
	if raw, ok := storageCfg["type"]; ok {
		s, ok := raw.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("\"type\" must be a non-empty string, got %T", raw)
		}
		storageType = strings.ToLower(strings.TrimSpace(s))
	}

	switch storageType {
	case "memory":
		return leasepkg.NewInMemoryManager(), nil

	case "file":
		path, ok := storageCfg["path"].(string)
		if !ok || strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("\"path\" is required when \"type\" is \"file\"")
		}

		interval := 30 * time.Second
		if raw, ok := storageCfg["save_interval"]; ok {
			s, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("\"save_interval\" must be a duration string (e.g. \"30s\"), got %T", raw)
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return nil, fmt.Errorf("\"save_interval\" %q is not a valid duration: %w", s, err)
			}
			interval = d
		}

		return leasepkg.NewFileLeaseStore(path, interval, func(err error) {
			logger.Errorf("%v", err)
		})

	default:
		return nil, fmt.Errorf("unrecognized \"type\" %q (expected \"memory\" or \"file\")", storageType)
	}
}
