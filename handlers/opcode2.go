// Package handlers provides opcode-specific processing modules.
package handlers

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// StatusHandler handles DNS opcode 2 (STATUS queries).
//
// STATUS queries are used to query server status information.
// Implements RFC 1035 section 4.1.3 and RFC 6895 section 2.3.
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

// Handle processes a STATUS query and returns a HandlerResult.
//
// For STATUS queries:
// - The Question section contains the server name (usually ".")
// - The Answer section contains variable status data
// - The Authority section contains additional server status RRs
// - The Additional section contains uptime-related information
//
// This implementation returns a basic status response with server identity.
func (h *StatusHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult {
	h.logger.Debugf("Processing STATUS query from %s", w.RemoteAddr().String())

	// Create response message with copied header fields
	resp := &dns.Msg{
		MsgHeader: r.MsgHeader,
		Question:  r.Question,
	}

	// Clear the data buffer to ensure Pack() will be called on WriteTo (reduntant but safe)
	resp.Data = nil

	// Set response flags
	resp.Rcode = dns.RcodeSuccess
	resp.Response = true
	resp.Authoritative = true

	// Clear sections for building our response (reduntant but safe)
	resp.Answer = nil
	resp.Ns = nil
	resp.Extra = nil

	// Parse the question (server name requested)
	var serverName string
	if len(r.Question) > 0 {
		// In miekg/dns, Question is a slice of RR, and each RR has a Header()
		// method that returns the header with the Name field
		header := r.Question[0].Header()
		serverName = header.Name
		h.logger.Debugf("STATUS query for server: %s", serverName)
	} else {
		serverName = "."
	}

	// For STATUS queries, we return status RRs in the Answer section.
	// Per RFC 6895, these are typically TXT records with server status.

	// Add a BIND-style server identification record
	statusRR := &dns.TXT{
		Hdr: dns.Header{
			Name:  serverName,
			Class: dns.ClassANY,
			TTL:   0,
		},
		TXT: rdata.TXT{Txt: []string{
			"sig0lease DNS Proxy v1.0",
			"RFC 6895 STATUS query supported",
		}},
	}
	resp.Answer = append(resp.Answer, statusRR)

	// Add an HINFO record with server information (RFC 1035)
	hinfo := &dns.HINFO{
		Hdr: dns.Header{
			Name:  serverName,
			Class: dns.ClassANY,
			TTL:   0,
		},
		HINFO: rdata.HINFO{
			Cpu: "x86_64",
			Os:  "sig0lease DNS Proxy v1.0",
		},
	}
	resp.Extra = append(resp.Extra, hinfo)

	h.logger.Debugf("STATUS query handled for %s", serverName)
	h.logger.Debugf("Answer section: %d records, Extra section: %d records",
		len(resp.Answer), len(resp.Extra))

	return NewProcessedResult(resp)
}

// Setup initializes the handler configuration.
func (h *StatusHandler) Setup(cfg map[string]any) error {
	h.config = cfg
	if h.logger != nil {
		h.logger.Debugf("StatusHandler configured with: %+v", cfg)
	}
	return nil
}
