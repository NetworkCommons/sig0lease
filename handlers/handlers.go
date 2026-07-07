// Package handlers provides the middleware handler chain for the DNS proxy.
package handlers

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
)

// HandlerFunc is a function type that handles a DNS request.
type HandlerFunc func(context.Context, dns.ResponseWriter, *dns.Msg) (*dns.Msg, context.Context, error)

func cloneRequest(msg *dns.Msg) (*dns.Msg, error) {
	if msg == nil {
		return nil, nil
	}

	tmp := msg.Copy()
	err := tmp.Pack()
	if err != nil {
		return nil, fmt.Errorf("clone request pack failed: %w", err)
	}

	clone := new(dns.Msg)
	clone.Data = make([]byte, len(tmp.Data))
	copy(clone.Data, tmp.Data)
	if err := clone.Unpack(); err != nil {
		return nil, fmt.Errorf("clone request unpack failed: %w", err)
	}

	return clone, nil
}

// Chain builds a middleware chain from multiple handlers.
func Chain(handlers ...HandlerFunc) HandlerFunc {
	if len(handlers) == 0 {
		return func(ctx context.Context, _ dns.ResponseWriter, r *dns.Msg) (*dns.Msg, context.Context, error) {
			return nil, ctx, nil
		}
	}

	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (*dns.Msg, context.Context, error) {
		if len(handlers) == 1 {
			req, err := cloneRequest(r)
			if err != nil {
				return nil, ctx, err
			}
			return handlers[0](ctx, w, req)
		}

		for i := range handlers {
			req, err := cloneRequest(r)
			if err != nil {
				return nil, ctx, err
			}
			resp, newCtx, err := handlers[i](ctx, w, req)
			if err != nil || resp != nil {
				return resp, newCtx, err
			}
			ctx = newCtx
		}

		return nil, ctx, nil
	}
}

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
}

// BaseHandler provides common functionality for handlers.
type BaseHandler struct {
	name    string
	opcodes []uint8
	config  map[string]any
	logger  *logging.Logger
	// FIXME: this is not implemented
	canaryFunc func() bool // For testing
}

// NewBaseHandler creates a new base handler instance.
func NewBaseHandler(name string, opcodes []uint8) *BaseHandler {
	return &BaseHandler{
		name:    name,
		opcodes: opcodes,
	}
}

// SetLogger sets the logger for this handler.
func (b *BaseHandler) SetLogger(logger *logging.Logger) {
	b.logger = logger
}

// SetConfig sets configuration for the handler.
func (b *BaseHandler) SetConfig(cfg map[string]any) {
	b.config = cfg
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

// GetConfig returns the handler's configuration.
func (b *BaseHandler) GetConfig() map[string]any {
	return b.config
}

// Opcodes returns the list of opcodes this handler handles.
func (b *BaseHandler) Opcodes() []uint8 {
	return b.opcodes
}
