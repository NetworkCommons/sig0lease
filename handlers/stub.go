// Package handlers provides stub implementations of DNS processing modules.
package handlers

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"
)

// StubHandler is a stub handler that logs and returns empty responses.
// This serves as a template for implementing actual processing modules.
type StubHandler struct {
	BaseHandler
}

// NewStubHandler creates a new stub handler for the given opcodes.
func NewStubHandler(name string, opcodes []uint8) *StubHandler {
	return &StubHandler{
		BaseHandler: BaseHandler{
			name:    name,
			opcodes: opcodes,
		},
	}
}

// Handle processes a DNS message and returns a HandlerResult.
//
// This is a generic handler that:
//   - Logs incoming request details
//   - Validates message structure
//   - Returns a properly formatted response with appropriate flags
//
// To implement specific processing, extend this handler or create new handlers.
func (h *StubHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult {
	if h.logger != nil {
		h.logger.Debugf("Stub handler %s received opcode %d from %s",
			h.name, r.Opcode, w.RemoteAddr().String())
	}

	// Validate message
	if r == nil {
		return NewErrorResult(nil, "nil message received", fmt.Errorf("nil message"))
	}

	// Validate Question section
	if len(r.Question) == 0 {
		h.logger.Warn("No question section in message")
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, "no question section")
		return NewErrorResult(msg, "no question section", nil)
	}

	if len(r.Question) > 1 {
		h.logger.Debugf("Multiple questions in message: %d", len(r.Question))
	}

	// Log question details - parse Question section properly
	if len(r.Question) > 0 {
		qHeader := r.Question[0].Header()
		h.logger.Debugf("Question: %s (%d, %d)", qHeader.Name, qHeader.TTL, qHeader.Class)
	}

	// Create response message
	resp := &dns.Msg{
		MsgHeader: r.MsgHeader,
		Question:  r.Question,
	}

	// Clear the data buffer to ensure Pack() will be called on WriteTo
	resp.Data = nil

	// Set response flags
	resp.Response = true
	if r.RecursionDesired {
		resp.RecursionAvailable = true
	}

	// Set response code (success by default for stub handler)
	resp.Rcode = dns.RcodeSuccess

	return NewProcessedResult(resp)
}

// makeErrorResponse creates a properly formatted error response.
func (h *StubHandler) makeErrorResponse(req *dns.Msg, rcode int, msg string) *dns.Msg {
	resp := &dns.Msg{
		MsgHeader: req.MsgHeader,
		Question:  req.Question,
	}

	resp.Response = true
	resp.Rcode = uint16(rcode)

	if msg != "" && h.logger != nil {
		h.logger.Debugf("Returning error response: %s", msg)
	}

	return resp
}

// Setup initializes the handler configuration.
func (h *StubHandler) Setup(cfg map[string]any) error {
	h.config = cfg
	if h.logger != nil {
		h.logger.Debugf("Stub handler %s configured with: %+v", h.name, cfg)
	}
	return nil
}
