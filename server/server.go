// Package server implements the DNS proxy server.
package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	fwdServers := make([]string, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		if u.Address != "" {
			fwdServers = append(fwdServers, u.Address)
		}
	}
	// FIXME: servers is a list, but protocol and timeout are single values, differently in config. Should we support per-server protocol/timeout?
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

// GetResolver returns the upstream resolver for handlers to use.
// Used for Phase 3 upstream coordination.
func (s *Server) GetResolver() *forward.Resolver {
	return s.resolver
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

// serveUDP starts a custom UDP listener that preserves EDNS options
func (s *Server) serveUDP(handler dns.HandlerFunc) error {
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

	// Set buffer sizes
	conn.SetReadBuffer(65536)
	conn.SetWriteBuffer(65536)

	s.logger.Infof("UDP listener started on %s", conn.LocalAddr().String())

	// Handle incoming packets
	for {
		buf := make([]byte, 4096)
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			s.logger.Errorf("UDP read error: %v", err)
			continue
		}

		s.logger.Infof("UDP: Received %d bytes from %s", n, remoteAddr.String())
		rawData := buf[:n]

		// Extract EDNS options from raw data before unpacking
		extractedOPT := extractEDNSFromWire(rawData)

		// Try to strip EDNS from wire before unpacking to allow successful unpacking
		dataWithoutOPT, _, stripErr := stripEDNSFromWire(rawData)
		if stripErr != nil {
			s.logger.Debugf("Could not strip EDNS: %v", stripErr)
			dataWithoutOPT = rawData
		}

		// Unpack the message (without OPT if we stripped it)
		msg := new(dns.Msg)
		msg.Data = make([]byte, len(dataWithoutOPT))
		copy(msg.Data, dataWithoutOPT)
		unpackErr := msg.Unpack()

		// If unpacking still failed, try to at least parse the header
		if unpackErr != nil {
			s.logger.Debugf("Unpack error: %v (trying to parse header)", unpackErr)
			// Try to parse at least the header from original data
			if len(rawData) >= 12 {
				// Parse header
				msg.ID = binary.BigEndian.Uint16(rawData[0:2])
				flags := binary.BigEndian.Uint16(rawData[2:4])
				msg.Opcode = uint8(flags >> 11)

				// Even if full unpack fails, use extracted EDNS
				extractedOPT = extractEDNSFromWire(rawData)
			} else {
				s.logger.Errorf("Packet too small to parse")
				continue
			}
		}

		// If we extracted EDNS options from raw data, add them back
		if extractedOPT != nil && len(msg.Extra) == 0 {
			s.logger.Debugf("Restoring EDNS options from raw data: %d options", len(extractedOPT.Options))
			msg.Extra = append(msg.Extra, extractedOPT)
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
		go handler(context.Background(), w, msg)
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
		s.logger.Infof("handleRequest: About to write response...")

		// Debug: check if Data needs packing
		if len(resp.Data) == 0 {
			s.logger.Infof("handleRequest: Data is empty, calling Pack()...")
			if err := resp.Pack(); err != nil {
				s.logger.Errorf("handleRequest: Pack() failed: %v", err)
				return
			} else {
				s.logger.Infof("handleRequest: Pack() succeeded, new Data len=%d", len(resp.Data))
			}
		}

		// Call Write directly on the response writer
		_, err := w.Write(resp.Data)
		if err != nil {
			s.logger.Errorf("handleRequest: Write error: %v", err)
		} else {
			s.logger.Infof("handleRequest: Write succeeded")
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
