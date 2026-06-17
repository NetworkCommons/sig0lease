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
	opcodeMap      map[uint8]string
	defaultForward string
	handlers       map[string]handlers.Handler
	logger         *logging.Logger
	resolver       *forward.Resolver
}

// NewRouter creates a new router instance.
func NewRouter(opcodeMap map[uint8]string, defaultForward string, logger *logging.Logger, resolver *forward.Resolver) (*Router, error) {
	if defaultForward == "" {
		defaultForward = "8.8.8.8:53"
	}
	return &Router{
		opcodeMap:      opcodeMap,
		defaultForward: defaultForward,
		handlers:       make(map[string]handlers.Handler),
		logger:         logger,
		resolver:       resolver,
	}, nil
}

// RegisterHandler registers a handler with the router.
func (r *Router) RegisterHandler(h handlers.Handler) {
	r.handlers[h.Name()] = h
}

// Route determines how to handle a DNS message based on its opcode.
func (r *Router) Route(ctx context.Context, w dns.ResponseWriter, rMsg *dns.Msg) *dns.Msg {
	moduleName, found := r.moduleForOpcode(rMsg.Opcode)

	r.logger.Infof("Route: Opcode=%d, FoundModule=%v", rMsg.Opcode, moduleName)

	if !found {
		r.logger.Infof("No handler for opcode %d, forwarding to upstream", rMsg.Opcode)
		resp := r.forwardToUpstream(w, rMsg)
		return resp
	}

	handler, ok := r.handlers[moduleName]
	if !ok {
		r.logger.Errorf("Handler not found for module: %s", moduleName)
		resp := r.forwardToUpstream(w, rMsg)
		return resp
	}

	resp, err := handler.Handle(ctx, w, rMsg)
	if err != nil {
		r.logger.Errorf("Error handling opcode %d with module %s: %v", rMsg.Opcode, moduleName, err)
		resp := r.forwardToUpstream(w, rMsg)
		return resp
	}

	r.logger.Infof("Handler returned response: Rcode=%d", resp.Rcode)
	return resp
}

// moduleForOpcode returns the module name for an opcode if one is configured.
func (r *Router) moduleForOpcode(opcode uint8) (string, bool) {
	moduleName, found := r.opcodeMap[opcode]
	return moduleName, found
}

// forwardToUpstream forwards a DNS message to the upstream resolver.
func (r *Router) forwardToUpstream(w dns.ResponseWriter, rMsg *dns.Msg) *dns.Msg {
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
