// Package server implements the DNS proxy server.
package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease_proxy/config"
	"github.com/NetworkCommons/sig0lease_proxy/forward"
	"github.com/NetworkCommons/sig0lease_proxy/handlers"
	"github.com/NetworkCommons/sig0lease_proxy/logging"
)

// Server is the main DNS proxy server.
type Server struct {
	cfg      *config.Config
	logger   *logging.Logger
	resolver *forward.Resolver
	router   *Router
}

// New creates and returns a new Server instance.
func New(cfg *config.Config, logger *logging.Logger) (*Server, error) {
	// Create upstream resolver
	fwdServers := make([]string, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		if u.Address != "" {
			fwdServers = append(fwdServers, u.Address)
		}
	}

	resolver, err := forward.NewResolver(
		fwdServers,
		cfg.Upstreams[0].Protocol,
		cfg.Upstreams[0].Timeout,
	)
	if err != nil {
		return nil, fmt.Errorf("create resolver: %w", err)
	}

	// Create router with opcode mappings and resolver
	router, err := NewRouter(cfg.GetOpcodeMap(), cfg.DefaultForward, logger, resolver)
	if err != nil {
		resolver.Shutdown()
		return nil, fmt.Errorf("create router: %w", err)
	}

	return &Server{
		cfg:      cfg,
		logger:   logger,
		resolver: resolver,
		router:   router,
	}, nil
}

// RegisterHandler registers a processing module handler with the server.
func (s *Server) RegisterHandler(h handlers.Handler) {
	s.router.RegisterHandler(h)
}

// Serve starts the DNS proxy server and blocks until shutdown.
func (s *Server) Serve() error {
	s.logger.Infof("DNS Proxy starting on %s", s.cfg.Server.Address)

	// Create a custom handler that routes based on opcode
	router := dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		s.handleRequest(w, r)
	})

	// Start listeners for each configured network
	errCh := make(chan error, len(s.cfg.Server.Networks))

	for _, network := range s.cfg.Server.Networks {
		go func(net string) {
			var err error
			switch net {
			case "udp":
				err = s.serveUDP(router)
			case "tcp":
				err = s.serveTCP(router)
			default:
				err = fmt.Errorf("unsupported network: %s", net)
			}
			if err != nil {
				errCh <- fmt.Errorf("%s listener error: %w", net, err)
			}
		}(network)
	}

	// Collect any startup errors
	for i := 0; i < len(s.cfg.Server.Networks); i++ {
		select {
		case err := <-errCh:
			s.logger.Errorf("Listener failed: %v", err)
			s.shutdown()
			return err
		default:
			// No error yet, continue
		}
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	s.logger.Infof("DNS Proxy ready to accept queries")

	select {
	case sig := <-sigCh:
		s.logger.Infof("Received signal %v, shutting down...", sig)
	case err := <-errCh:
		return err
	}

	s.shutdown()
	return nil
}

// serveUDP starts a UDP listener.
func (s *Server) serveUDP(handler dns.HandlerFunc) error {
	addr := s.cfg.Server.Address

	// Handle port-only syntax
	if host, port, err := net.SplitHostPort(addr); err == nil && host == "" {
		addr = ":" + port
	}

	srv := &dns.Server{
		PacketConn: nil,
		Addr:       addr,
		Net:        "udp",
		Handler:    handler,
		UDPSize:    4096,
	}

	return srv.ListenAndServe()
}

// serveTCP starts a TCP listener.
func (s *Server) serveTCP(handler dns.HandlerFunc) error {
	addr := s.cfg.Server.Address

	// Handle port-only syntax
	if host, port, err := net.SplitHostPort(addr); err == nil && host == "" {
		addr = ":" + port
	}

	srv := &dns.Server{
		Listener:  nil,
		Addr:      addr,
		Net:       "tcp",
		Handler:   handler,
		TLSConfig: nil,
	}

	return srv.ListenAndServe()
}

// handleRequest is the main request handler that routes based on opcode.
func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	s.logger.Infof("handleRequest: Received DNS message from %s", w.RemoteAddr().String())
	if len(r.Question) > 0 {
		q := r.Question[0]
		s.logger.Infof("  ID: %d, Opcode: %d, Query: %s %s",
			r.ID, r.Opcode, q.Header().Name, dns.TypeToString[dns.RRToType(q)])
	}

	resp := s.router.Route(context.Background(), w, r)

	if resp != nil {
		s.logger.Infof("handleRequest: Response has Data len=%d, Rcode=%d", len(resp.Data), resp.Rcode)
		s.logger.Infof("handleRequest: About to call w.Write()...")

		// Use WriteTo which handles TCP length prefixing
		n, err := resp.WriteTo(w)
		s.logger.Infof("handleRequest: resp.WriteTo returned n=%d, err=%v", n, err)
	} else {
		s.logger.Errorf("No response generated for query from %s", w.RemoteAddr().String())
	}
}

// shutdown gracefully shuts down the server.
func (s *Server) shutdown() {
	s.logger.Info("Shutting down DNS proxy...")
	s.resolver.Shutdown()
	s.logger.Info("DNS proxy stopped")
}
