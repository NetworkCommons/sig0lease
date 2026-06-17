// Package handlers provides opcode-specific processing modules.
package handlers

import (
	"context"

	"codeberg.org/miekg/dns"
)

// StatusHandler handles DNS opcode 2 (STATUS queries).
//
// STATUS queries are used to query server status information.
// This is a stub implementation - replace with actual logic as needed.
type StatusHandler struct {
	BaseHandler
}

// NewStatusHandler creates a new handler for opcode 2 (STATUS) queries.
func NewStatusHandler() *StatusHandler {
	return &StatusHandler{
		BaseHandler: BaseHandler{
			name:    "status_handler",
			opcodes: []uint8{dns.OpcodeStatus},
		},
	}
}

// Handle processes a STATUS query and returns a status response.
func (h *StatusHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (*dns.Msg, error) {
	h.logger.Debugf("Processing STATUS query from %s", w.RemoteAddr().String())

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.Response = true
	resp.Authoritative = true

	// Copy the question section
	if len(r.Question) > 0 {
		resp.Question = make([]dns.RR, len(r.Question))
		copy(resp.Question, r.Question)
	}

	h.logger.Debugf("STATUS query handled for %s", resp.Question[0].Header().Name)

	return resp, nil
}

// Setup initializes the handler configuration.
func (h *StatusHandler) Setup(cfg map[string]any) error {
	h.config = cfg
	if h.logger != nil {
		h.logger.Debugf("StatusHandler configured with: %+v", cfg)
	}
	return nil
}
