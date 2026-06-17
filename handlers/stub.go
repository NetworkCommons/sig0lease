// Package handlers provides stub implementations of DNS processing modules.
package handlers

import (
	"context"

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

// Handle processes a DNS message - currently just logs and returns empty response.
// TODO: Implement actual processing logic for this module.
func (h *StubHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (*dns.Msg, error) {
	if h.logger != nil {
		h.logger.Debugf("Stub handler %s received opcode %d", h.name, r.Opcode)
	}

	// Copy the request to preserve all header fields including ID
	resp := r.Copy()

	// Clear the Data buffer so Pack() will be called by WriteTo to update flags
	resp.Data = nil

	// Now modify for response - clear sections and set appropriate flags
	resp.Rcode = dns.RcodeSuccess
	resp.Response = true
	resp.RecursionAvailable = true

	// Clear answer, authority, and additional sections (we'll add them if needed)
	resp.Answer = nil
	resp.Ns = nil
	resp.Extra = nil

	return resp, nil
}

// Setup initializes the handler configuration.
func (h *StubHandler) Setup(cfg map[string]any) error {
	h.config = cfg
	if h.logger != nil {
		h.logger.Debugf("Stub handler %s configured with: %+v", h.name, cfg)
	}
	return nil
}
