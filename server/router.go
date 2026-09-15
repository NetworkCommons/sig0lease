// Package server implements the DNS proxy server.
package server

import (
	"context"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/forward"
	"github.com/NetworkCommons/sig0lease/handlers"
	"github.com/NetworkCommons/sig0lease/logging"
)

// Router routes DNS requests based on opcode to appropriate handlers or forwarder.
type Router struct {
	// opcodeMap holds, per opcode, the ordered list of module names to try (D2):
	// Route calls each in turn until one returns Processed or Error; if every one
	// declines (NotRelevant), the opcode falls through to plain upstream forwarding.
	opcodeMap map[uint8][]string
	handlers  map[string]handlers.Handler
	logger    *logging.Logger
	resolver  *forward.Resolver
}

// NewRouter creates a new router instance.
func NewRouter(opcodeMap map[uint8][]string, logger *logging.Logger, resolver *forward.Resolver) (*Router, error) {
	return &Router{
		opcodeMap: opcodeMap,
		handlers:  make(map[string]handlers.Handler),
		logger:    logger,
		resolver:  resolver,
	}, nil
}

// RegisterHandler registers a handler with the router.
func (r *Router) RegisterHandler(h handlers.Handler) {
	r.handlers[h.Name()] = h
}

// Shutdown calls Shutdown on every registered handler exactly once.
func (r *Router) Shutdown() {
	for _, h := range r.handlers {
		h.Shutdown()
	}
}

// Route determines how to handle a DNS message based on its opcode.
// Flow:
//  1. Check for internal dump query (admin/debug endpoint)
//  2. Check if opcode has any registered handlers
//  3. Try each configured handler for the opcode in order (D2):
//     - StatusProcessed: Return response to client, stop
//     - StatusNotRelevant: Try the next handler in the list
//     - StatusError: Return error response to client, stop
//  4. If no handler is configured, or every handler declined (all NotRelevant),
//     apply default forward
func (r *Router) Route(ctx context.Context, w dns.ResponseWriter, rMsg *dns.Msg) *dns.Msg {
	// Check for internal dump query (admin/debug endpoint).
	if r.isDumpQuery(rMsg) {
		return r.handleDumpQuery(rMsg)
	}

	moduleNames, found := r.moduleForOpcode(rMsg.Opcode)

	r.logger.Debugf("Route: Opcode=%d, FoundModules=%v, Modules=%v", rMsg.Opcode, found, moduleNames)

	if !found || len(moduleNames) == 0 {
		r.logger.Debugf("No handler for opcode %d, forwarding to upstream", rMsg.Opcode)
		return r.forwardToUpstream(rMsg)
	}

	for _, moduleName := range moduleNames {
		handler, ok := r.handlers[moduleName]
		if !ok {
			r.logger.Errorf("Handler not found for module: %s", moduleName)
			continue
		}

		result := handler.Handle(ctx, w, rMsg)
		if result == nil {
			r.logger.Errorf("Handler %s returned nil result for opcode %d", moduleName, rMsg.Opcode)
			continue
		}

		r.logger.Infof("Handler %s returned status=%s, reason=%s", moduleName, result.Status, result.Reason)

		switch result.Status {
		case handlers.StatusProcessed:
			r.logger.Debugf("Handler %s processed opcode %d, returning response with Rcode=%d", moduleName, rMsg.Opcode, result.Message.Rcode)
			return result.Message

		case handlers.StatusNotRelevant:
			// Not relevant to this handler -- try the next one in the ordered list
			// (D2), e.g. an SRP-shaped update tried by srp_handler first, then a
			// plain lease update falling through to update_handler.
			r.logger.Debugf("Handler %s declined packet (not relevant), trying next", moduleName)
			continue

		case handlers.StatusError:
			if result.Message != nil {
				r.logger.Errorf("Handler %s error: %v, returning error response with Rcode=%d", moduleName, result.Error, result.Message.Rcode)
				return result.Message
			}
			resp := new(dns.Msg)
			resp.ID = rMsg.ID
			resp.Rcode = dns.RcodeServerFailure
			resp.Response = true
			r.logger.Errorf("Handler %s error with no response: %v", moduleName, result.Error)
			return resp

		default:
			r.logger.Errorf("Handler %s returned unknown status: %v", moduleName, result.Status)
			continue
		}
	}

	// Every configured handler declined (or was missing/nil) -- default upstream routing.
	r.logger.Debugf("All handlers declined opcode %d, forwarding to upstream", rMsg.Opcode)
	return r.forwardToUpstream(rMsg)
}

// moduleForOpcode returns the ordered module-name list for an opcode if one is configured.
func (r *Router) moduleForOpcode(opcode uint8) ([]string, bool) {
	moduleNames, found := r.opcodeMap[opcode]
	return moduleNames, found
}

// dumpQueryName is the internal domain used for lease dump queries.
const dumpQueryName = "__dump.sig0lease.internal."

// dumpQueryDebugName is the internal domain for DEBUG-level lease dump queries.
const dumpQueryDebugName = "__dump.sig0lease.internal.debug."

// isDumpQuery checks if the message is a dump query (either INFO or DEBUG level).
func (r *Router) isDumpQuery(m *dns.Msg) bool {
	if len(m.Question) == 0 {
		return false
	}
	q := m.Question[0].Header()
	if dns.RRToType(m.Question[0]) != dns.TypeTXT {
		return false
	}
	return strings.EqualFold(q.Name, dumpQueryName) || strings.EqualFold(q.Name, dumpQueryDebugName)
}

// dumpLevelFromQuery extracts the log level from the query name.
// Returns "info" for __dump.sig0lease.internal. and "debug" for __dump.sig0lease.internal.debug.
func dumpLevelFromQuery(m *dns.Msg) string {
	if len(m.Question) == 0 {
		return "info"
	}
	q := m.Question[0].Header()
	if strings.EqualFold(q.Name, dumpQueryDebugName) {
		return "debug"
	}
	return "info"
}

// handleDumpQuery returns the lease store dump as a TXT record.
// Uses INFO level (summary) by default, DEBUG level (full dump) when queried via dumpQueryDebugName.
func (r *Router) handleDumpQuery(m *dns.Msg) *dns.Msg {
	level := dumpLevelFromQuery(m)
	var sb strings.Builder

	hasAny := false
	for _, h := range r.handlers {
		if dumper, ok := h.(interface{ DumpLeasesLevel(string) string }); ok {
			sb.WriteString(dumper.DumpLeasesLevel(level))
			hasAny = true
		} else if dumper, ok := h.(interface{ DumpLeases() string }); ok {
			// Fallback: if handler only has DumpLeases (no level support), use it.
			sb.WriteString(dumper.DumpLeases())
			hasAny = true
		}
	}
	if !hasAny {
		if level == "debug" {
			sb.WriteString("=== Lease Store Dump ===\n")
		} else {
			sb.WriteString("=== Lease Store Summary ===\n")
		}
		sb.WriteString("(no dump-capable handlers configured)\n")
	}

	dumpText := sb.String()
	resp := new(dns.Msg)
	resp.ID = m.ID
	resp.Response = true
	resp.Authoritative = true
	resp.Question = m.Question

	// Split long dump into multiple TXT chunks (max 255 bytes each).
	const maxTxtLen = 240 // leave room for quotes
	for i := 0; i < len(dumpText); i += maxTxtLen {
		end := i + maxTxtLen
		if end > len(dumpText) {
			end = len(dumpText)
		}
		txt := &dns.TXT{
			Hdr: dns.Header{
				Name:  dumpQueryName,
				Class: dns.ClassINET,
				TTL:   0,
			},
		}
		txt.TXT.Txt = append(txt.TXT.Txt, dumpText[i:end])
		resp.Answer = append(resp.Answer, txt)
	}

	return resp
}

// forwardToUpstream forwards a DNS message to the upstream resolver.
func (r *Router) forwardToUpstream(rMsg *dns.Msg) *dns.Msg {
	resp, err := r.forwardMessage(rMsg)
	if err != nil {
		r.logger.Errorf("Forward error: %v", err)
		// Create response preserving the original message ID
		resp = new(dns.Msg)
		resp.ID = rMsg.ID
		resp.Rcode = dns.RcodeServerFailure
		resp.Response = true
	}

	return resp
}

// forwardMessage sends a DNS message to upstream resolvers.
func (r *Router) forwardMessage(msg *dns.Msg) (*dns.Msg, error) {
	if r.resolver == nil {
		r.logger.Errorf("No resolver configured")
		return nil, fmt.Errorf("no resolver configured")
	}
	ctx := context.Background()
	resp, err := r.resolver.Query(ctx, msg)
	if err != nil {
		r.logger.Errorf("Forward query failed: %v", err)
		return nil, err
	}
	r.logger.Debugf("Got response from upstream: Rcode=%d, Question count=%d",
		resp.Rcode, len(resp.Question))
	return resp, nil
}
