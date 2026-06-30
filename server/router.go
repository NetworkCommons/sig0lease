// Package server implements the DNS proxy server.
package server

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/forward"
	"github.com/NetworkCommons/sig0lease/handlers"
	"github.com/NetworkCommons/sig0lease/logging"
)

// Router routes DNS requests based on opcode to appropriate handlers or forwarder.
type Router struct {
	opcodeMap map[uint8]string
	handlers  map[string]handlers.Handler
	logger    *logging.Logger
	resolver  *forward.Resolver
}

// NewRouter creates a new router instance.
func NewRouter(opcodeMap map[uint8]string, logger *logging.Logger, resolver *forward.Resolver) (*Router, error) {
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

// Route determines how to handle a DNS message based on its opcode.
// Flow:
//  1. Check if opcode has a registered handler
//  2. If yes, call handler and check result status:
//     - StatusProcessed: Return response to client
//     - StatusNotRelevant: Apply default forward (fallback action)
//     - StatusError: Return error response to client
//  3. If no handler, apply default forward
func (r *Router) Route(ctx context.Context, w dns.ResponseWriter, rMsg *dns.Msg) *dns.Msg {
	moduleName, found := r.moduleForOpcode(rMsg.Opcode)

	r.logger.Infof("Route: Opcode=%d, FoundModule=%v, Module=%s", rMsg.Opcode, found, moduleName)

	if !found {
		r.logger.Infof("No handler for opcode %d, forwarding to upstream", rMsg.Opcode)
		resp := r.forwardToUpstream(rMsg)
		return resp
	}

	handler, ok := r.handlers[moduleName]
	if !ok {
		r.logger.Errorf("Handler not found for module: %s", moduleName)
		resp := r.forwardToUpstream(rMsg)
		return resp
	}

	// Call handler and get result
	result := handler.Handle(ctx, w, rMsg)
	if result == nil {
		r.logger.Errorf("Handler returned nil result for opcode %d", rMsg.Opcode)
		return r.forwardToUpstream(rMsg)
	}

	r.logger.Infof("Handler %s returned status=%s, reason=%s", moduleName, result.Status, result.Reason)

	// Handle based on result status
	switch result.Status {
	case handlers.StatusProcessed:
		// Handler processed the packet, return the response
		r.logger.Debugf("Handler processed opcode %d, returning response with Rcode=%d", rMsg.Opcode, result.Message.Rcode)
		return result.Message

	case handlers.StatusNotRelevant:
		// Packet not relevant to this handler (e.g., UPDATE without UPDATE-LEASE EDNS option)
		// Apply fallback action: forward to upstream
		r.logger.Infof("Handler declined packet (not relevant), forwarding to upstream")
		resp := r.forwardToUpstream(rMsg)
		return resp

	case handlers.StatusError:
		// Handler encountered an error
		if result.Message != nil {
			r.logger.Errorf("Handler error: %v, returning error response with Rcode=%d", result.Error, result.Message.Rcode)
			return result.Message
		}
		// Create error response if handler didn't provide one
		resp := new(dns.Msg)
		resp.ID = rMsg.ID
		resp.Rcode = dns.RcodeServerFailure
		resp.Response = true
		r.logger.Errorf("Handler error with no response: %v", result.Error)
		return resp

	default:
		r.logger.Errorf("Unknown handler status: %v", result.Status)
		return r.forwardToUpstream(rMsg)
	}
}

// moduleForOpcode returns the module name for an opcode if one is configured.
func (r *Router) moduleForOpcode(opcode uint8) (string, bool) {
	moduleName, found := r.opcodeMap[opcode]
	return moduleName, found
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
	r.logger.Infof("Got response from upstream: Rcode=%d, Question count=%d",
		resp.Rcode, len(resp.Question))
	return resp, nil
}
