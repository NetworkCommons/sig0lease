// Package handlers provides opcode-specific processing modules for the DNS proxy.
package handlers

import (
	"context"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
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
