// Package handlers provides opcode-specific processing modules.
package handlers

import (
	"context"

	"codeberg.org/miekg/dns"
)

// UpdateHandler handles DNS opcode 5 (UPDATE queries).
//
// UPDATE queries are used for dynamic DNS updates (RFC 2136).
// This is a stub implementation - replace with actual logic as needed.
type UpdateHandler struct {
	BaseHandler
}

// NewUpdateHandler creates a new handler for opcode 5 (UPDATE) queries.
func NewUpdateHandler() *UpdateHandler {
	return &UpdateHandler{
		BaseHandler: BaseHandler{
			name:    "update_handler",
			opcodes: []uint8{dns.OpcodeUpdate},
		},
	}
}

// Handle processes an UPDATE query and returns a response.
func (h *UpdateHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (*dns.Msg, error) {
	h.logger.Debugf("Processing UPDATE query from %s", w.RemoteAddr().String())

	// Copy the request to preserve all header fields including ID
	resp := r.Copy()

	// Clear the Data buffer so Pack() will be called by WriteTo to update flags
	resp.Data = nil

	// Now modify for response - clear sections and set appropriate flags
	resp.Rcode = dns.RcodeSuccess
	resp.Response = true
	resp.Authoritative = true

	// Clear answer, authority, and additional sections (we'll add them if needed)
	resp.Answer = nil
	resp.Ns = nil
	resp.Extra = nil

	h.logger.Debugf("UPDATE query handled for %s", resp.Question[0].Header().Name)

	return resp, nil
}

// Setup initializes the handler configuration.
func (h *UpdateHandler) Setup(cfg map[string]any) error {
	h.config = cfg
	if h.logger != nil {
		h.logger.Debugf("UpdateHandler configured with: %+v", cfg)
	}
	return nil
}
