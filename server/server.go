// Package server implements the DNS proxy server.
package server

import (
	"context"
	"fmt"
	"net"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/forward"
	"github.com/NetworkCommons/sig0lease/handlers"
	"github.com/NetworkCommons/sig0lease/logging"
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
	if len(cfg.Upstreams) == 0 {
		return nil, fmt.Errorf("at least one upstream server required in config")
	}
	fwdServers := make([]string, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		if u.Address != "" {
			fwdServers = append(fwdServers, u.Address)
		}
	}
	// NOTE: config.yaml lets each upstream declare its own protocol/timeout,
	// but forward.Resolver only takes one protocol/timeout for the whole
	// pool, so only the first configured upstream's values apply -- any
	// other upstreams' protocol/timeout settings are silently ignored. This
	// is a real config-schema/behavior mismatch, not just a documentation
	// gap; fixing it properly means giving Resolver a per-server
	// protocol/timeout instead of one shared pair, which is a larger change
	// than a FIXME warrants on its own.
	resolver, err := forward.NewResolver(
		fwdServers,
		cfg.Upstreams[0].Protocol,
		cfg.Upstreams[0].Timeout,
	)
	if err != nil {
		return nil, fmt.Errorf("create resolver: %w", err)
	}

	// Create router with opcode mappings and resolver
	router, err := NewRouter(cfg.GetOpcodeMap(), logger, resolver)
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

	// Create a custom handler that passes the per-query context to handleRequest
	router := dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		s.handleRequest(ctx, w, r)
	})

	// Set up OS signal interception that automatically cancels ctx on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Create an errgroup bound to the signal context
	g, ctx := errgroup.WithContext(ctx)

	// Launch each network listener in the errgroup
	for _, network := range s.cfg.Server.Networks {
		net := network // Local copy for closure safety
		g.Go(func() error {
			switch net {
			case "udp":
				return s.serveUDP(ctx, router)
			case "tcp":
				return s.serveTCP(ctx, router)
			default:
				return fmt.Errorf("unsupported network: %s", net)
			}
		})
	}

	s.logger.Infof("DNS Proxy ready to accept queries on %v", s.cfg.Server.Networks)

	// g.Wait() blocks until:
	// 1. Any listener returns an error (e.g. port bind failure or runtime crash)
	// 2. An OS signal is received (causing ctx cancellation and listener exit)
	if err := g.Wait(); err != nil && ctx.Err() == nil {
		s.logger.Errorf("Listener failed: %v", err)
		s.shutdown()
		return err
	}

	s.logger.Infof("DNS Proxy shut down gracefully")
	s.shutdown()
	return nil
}

// serveUDP starts a custom UDP listener that preserves EDNS options
func (s *Server) serveUDP(ctx context.Context, handler dns.HandlerFunc) error {
	addr := s.cfg.Server.Address

	// Handle port-only syntax - explicitly use localhost for IPv4
	if host, port, err := net.SplitHostPort(addr); err == nil && host == "" {
		addr = "127.0.0.1:" + port
	}

	// Listen on UDP with explicit IPv4
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer conn.Close()

	// Goroutine to force unblock ReadFromUDP when ctx is canceled
	go func() {
		<-ctx.Done()
		conn.Close() // Closing conn forces ReadFromUDP to unblock with an error
	}()

	// Set buffer sizes
	conn.SetReadBuffer(65536)
	conn.SetWriteBuffer(65536)

	s.logger.Infof("UDP listener started on %s", conn.LocalAddr().String())

	// Handle incoming packets
	for {
		buf := make([]byte, 4096)
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Check if error happened because ctx was canceled (graceful exit)
			select {
			case <-ctx.Done():
				s.logger.Infof("UDP listener shutting down cleanly")
				return nil
			default:
				s.logger.Errorf("UDP read error: %v", err)
				continue
			}
		}

		// Prevent processing new packets if shutdown signal arrived mid-read
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		s.logger.Debugf("UDP: Received %d bytes from %s", n, remoteAddr.String())
		rawData := buf[:n]

		// Strict parsing: unpack raw wire message only.
		msg := new(dns.Msg)
		msg.Data = make([]byte, len(rawData))
		copy(msg.Data, rawData)
		if err := msg.Unpack(); err != nil {
			s.logger.Errorf("Dropping malformed DNS packet from %s: unpack failed: %v", remoteAddr.String(), err)
			continue
		}

		// Debug: Log message structure
		s.logger.Debugf("After unpacking: Answer=%d, Ns=%d, Extra=%d, Pseudo=%d",
			len(msg.Answer), len(msg.Ns), len(msg.Extra), len(msg.Pseudo))

		// Debug: Show what's in Extra
		for i, rr := range msg.Extra {
			s.logger.Debugf("  Extra[%d]: %T (%s)", i, rr, rr.Header().String())
		}

		// Debug: Show what's in Pseudo
		for i, rr := range msg.Pseudo {
			s.logger.Debugf("  Pseudo[%d]: %T (%s)", i, rr, rr.Header().String())
		}

		// Create a custom response writer
		w := &udpResponseWriter{
			conn:       conn,
			remoteAddr: remoteAddr,
			logger:     s.logger,
		}

		// Call the handler with context
		go handler(ctx, w, msg)
	}
}

// udpResponseWriter implements dns.ResponseWriter for UDP
type udpResponseWriter struct {
	conn       *net.UDPConn
	remoteAddr *net.UDPAddr
	logger     *logging.Logger
}

func (w *udpResponseWriter) WriteMsg(m *dns.Msg) error {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return fmt.Errorf("pack error: %w", err)
		}
	}

	n, err := w.conn.WriteToUDP(m.Data, w.remoteAddr)
	if err != nil {
		return fmt.Errorf("WriteToUDP error: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("WriteToUDP wrote 0 bytes")
	}
	return nil
}

func (w *udpResponseWriter) Write(data []byte) (int, error) {
	if w.remoteAddr == nil {
		w.logger.Errorf("UDP Write: remoteAddr is nil!")
		return 0, fmt.Errorf("remoteAddr is nil")
	}
	w.logger.Debugf("UDP Write: Writing %d bytes to %s", len(data), w.remoteAddr.String())
	n, err := w.conn.WriteToUDP(data, w.remoteAddr)
	if err != nil {
		w.logger.Errorf("UDP Write: WriteToUDP error: %v", err)
	}
	return n, err
}

func (w *udpResponseWriter) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *udpResponseWriter) RemoteAddr() net.Addr {
	return w.remoteAddr
}

func (w *udpResponseWriter) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

func (w *udpResponseWriter) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

func (w *udpResponseWriter) Hijack() {
	// Not implemented for UDP
}

func (w *udpResponseWriter) WriteCopy(m *dns.Msg) (int, error) {
	msg := m.Copy()
	return w.Write(msg.Data)
}

func (w *udpResponseWriter) WriteStringList(list []string) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (w *udpResponseWriter) Tsig(m *dns.Msg, algo string, mac string, timesigned uint64, fudge uint32) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (w *udpResponseWriter) Close() error {
	return nil
}

func (w *udpResponseWriter) Conn() net.Conn {
	return w.conn
}

func (w *udpResponseWriter) Session() *dns.Session {
	return nil // UDP does not use sessions
}

// serveTCP starts a TCP listener.
func (s *Server) serveTCP(ctx context.Context, handler dns.HandlerFunc) error {
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
	// Monitor context cancellation in the background
	go func() {
		<-ctx.Done()
		s.logger.Infof("TCP listener shutting down...")

		srv.Shutdown(ctx)
	}()

	err := srv.ListenAndServe()

	// Check if ListenAndServe returned an error due to server shutdown
	select {
	case <-ctx.Done():
		s.logger.Infof("TCP listener shut down cleanly")
		return nil
	default:
		return err
	}
}

// handleRequest is the main request handler that routes based on opcode.
func (s *Server) handleRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	s.logger.Debugf("handleRequest: Received DNS message from %s", w.RemoteAddr().String())
	if len(r.Question) > 0 {
		q := r.Question[0]
		s.logger.Debugf("  ID: %d, Opcode: %d, Query: %s %s",
			r.ID, r.Opcode, q.Header().Name, dns.TypeToString[dns.RRToType(q)])
	}

	resp := s.router.Route(ctx, w, r)

	if resp != nil {
		s.logger.Debugf("handleRequest: Response has Data len=%d, Rcode=%d", len(resp.Data), resp.Rcode)

		// Check if Data needs packing
		if len(resp.Data) == 0 {
			s.logger.Debugf("handleRequest: Data is empty, calling Pack()...")
			if err := resp.Pack(); err != nil {
				s.logger.Errorf("handleRequest: Pack() failed: %v", err)
				return
			}
			s.logger.Debugf("handleRequest: Pack() succeeded, new Data len=%d", len(resp.Data))
		}

		// Call Write directly on the response writer
		_, err := w.Write(resp.Data)
		if err != nil {
			s.logger.Errorf("handleRequest: Write error: %v", err)
		} else {
			s.logger.Debugf("handleRequest: Write succeeded")
		}
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
