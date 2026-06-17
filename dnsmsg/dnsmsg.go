// Package dnsmsg provides DNS message utilities for the proxy.
package dnsmsg

import (
	"codeberg.org/miekg/dns"
)

// ProcessOpcode determines how to handle a DNS message based on its opcode.
func ProcessOpcode(r *dns.Msg, config map[uint8]string) (string, bool) {
	// Check if this opcode has a configured processing module
	if moduleName, ok := config[r.Opcode]; ok {
		return moduleName, true
	}
	// No module configured - forward to upstream
	return "", false
}

// MakeResponse creates a response message from a request.
func MakeResponse(r *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.Response = true
	resp.RecursionAvailable = true
	resp.Authoritative = false

	// Copy question section if needed
	if r.Question != nil && len(r.Question) > 0 {
		resp.Question = make([]dns.RR, len(r.Question))
		for i, q := range r.Question {
			resp.Question[i] = q
		}
	}

	return resp
}

// SetReply creates a response message that is a reply to the given request.
func SetReply(resp, req *dns.Msg) {
	resp.ID = req.ID
	resp.Response = true
	resp.RecursionDesired = req.RecursionDesired
	resp.Truncated = req.Truncated
	resp.Authoritative = false
	resp.CheckingDisabled = req.CheckingDisabled
	resp.AuthenticatedData = req.AuthenticatedData
	resp.Zero = req.Zero
}

// ExtractQuestionInfo returns the query name and type as a string.
func ExtractQuestionInfo(r *dns.Msg) (string, string) {
	if len(r.Question) == 0 {
		return "", ""
	}
	q := r.Question[0]
	name := q.Header().Name
	qtype := dns.TypeToString[dns.RRToType(q)]
	return name, qtype
}

// MakeStatusResponse creates a STATUS response message.
func MakeStatusResponse(r *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.Response = true
	resp.Authoritative = true

	// For STATUS queries (opcode 2), we typically return server info
	// In a real implementation, this would include:
	// - Server version
	// - Uptime
	// - Statistics
	if r.Question != nil && len(r.Question) > 0 {
		resp.Question = make([]dns.RR, len(r.Question))
		copy(resp.Question, r.Question)
	}

	return resp
}
