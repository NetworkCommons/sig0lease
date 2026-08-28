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

// acceptMsg applies the DNS library's standard accept policy (ignore
// response-flagged messages, reject unrecognized opcodes with NOTIMP,
// reject anything without exactly one question with FORMERR) to a parsed
// message, logging any non-accept decision. It is wired explicitly into
// both serveTCP (as dns.Server.MsgAcceptFunc, replacing the implicit
// library default) and serveUDP (invoked by hand, since the raw UDP loop
// bypasses the library's server entirely), so both transports enforce the
// same policy instead of diverging by accident.
func (s *Server) acceptMsg(m *dns.Msg) dns.MsgAcceptAction {
	action := dns.DefaultMsgAcceptFunc(m)
	switch action {
	case dns.MsgIgnore:
		s.logger.Debugf("Ignoring message id=%d: response bit set", m.ID)
	case dns.MsgReject:
		s.logger.Debugf("Rejecting message id=%d opcode=%d questions=%d: FORMERR (question count != 1)", m.ID, m.Opcode, len(m.Question))
	case dns.MsgRejectNotImplemented:
		s.logger.Debugf("Rejecting message id=%d opcode=%d: NOTIMP (unrecognized opcode)", m.ID, m.Opcode)
	}
	return action
}

// invalidMsg logs a message that the dns library's TCP server could not
// parse. Wired into dns.Server.MsgInvalidFunc so TCP unpack failures are
// visible the same way serveUDP already logs its own Unpack() failures.
// Unlike serveUDP, the library doesn't hand this callback the connection,
// so the remote address isn't available here.
func (s *Server) invalidMsg(m *dns.Msg, err error) {
	s.logger.Errorf("Dropping malformed DNS/TCP message: unpack failed: %v", err)
}

// serveUDP starts a custom UDP listener that preserves EDNS options
func (s *Server) serveUDP(ctx context.Context, handler dns.HandlerFunc) error {

	// Listen on UDP with explicit IPv4. A port-only address (e.g. ":8053")
	// resolves to the wildcard IP, so the listener binds on all interfaces --
	// consistent with serveTCP.
	udpAddr, err := net.ResolveUDPAddr("udp4", s.cfg.Server.Address)
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

		// Apply the same accept/reject policy the dns library enforces on
		// TCP (see acceptMsg) so response-flagged messages, unrecognized
		// opcodes, and malformed question counts are handled identically
		// on both transports instead of UDP passing them straight to the
		// handler.
		switch action := s.acceptMsg(msg); action {
		case dns.MsgIgnore:
			continue
		case dns.MsgReject, dns.MsgRejectNotImplemented:
			msg.Rcode = dns.RcodeFormatError
			if action == dns.MsgRejectNotImplemented {
				msg.Rcode = dns.RcodeNotImplemented
			}
			msg.Response = true
			msg.Authoritative = false
			msg.Zero = false
			msg.Reset()
			if err := msg.Pack(); err != nil {
				s.logger.Errorf("UDP: failed to pack reject response for %s: %v", remoteAddr.String(), err)
				continue
			}
			if _, err := conn.WriteToUDP(msg.Data, remoteAddr); err != nil {
				s.logger.Errorf("UDP: failed to write reject response to %s: %v", remoteAddr.String(), err)
			}
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
	// dns.Msg.WriteTo relies on this: since w.conn is the one shared,
	// unconnected listening socket for every client (not a per-client
	// connected UDPConn), WriteTo can't just call w.conn.Write -- it has
	// no destination. Returning the per-request remote address here makes
	// WriteTo route the reply with WriteMsgUDP(data, nil, Addr) instead,
	// which correctly targets this request's client.
	return &dns.Session{Addr: w.remoteAddr}
}

// serveTCP starts a TCP listener.
func (s *Server) serveTCP(ctx context.Context, handler dns.HandlerFunc) error {
	// srv is declared separately (not :=) so NotifyStartedFunc below can
	// close over it and read srv.Listener, which the library only
	// populates once the bind actually succeeds.
	var srv *dns.Server
	srv = &dns.Server{
		Listener:       nil,
		Addr:           s.cfg.Server.Address,
		Net:            "tcp",
		Handler:        handler,
		TLSConfig:      nil,
		MsgAcceptFunc:  s.acceptMsg,
		MsgInvalidFunc: s.invalidMsg,
		// Mirrors serveUDP's s.logger.Infof("UDP listener started on %s",
		// conn.LocalAddr().String()): fires only after the listener has
		// actually bound (unlike a log placed before ListenAndServe, which
		// would fire even if the bind then failed), using the real bound
		// address rather than the pre-resolve config string.
		NotifyStartedFunc: func(context.Context) {
			s.logger.Infof("TCP listener started on %s", srv.Listener.Addr().String())
		},
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

		// WriteTo (not Write) is required here: it Packs resp if needed,
		// and for TCP it prefixes the message with the 2-byte length RFC
		// 1035 requires -- w.Write(resp.Data) is a dumb passthrough to the
		// socket and skips that, leaving TCP responses unframed and
		// unreadable by any real DNS-over-TCP client. For UDP, WriteTo
		// detects the *net.UDPConn and writes the raw bytes exactly as
		// Write did, so this is a no-op change on that path.
		n, err := resp.WriteTo(w)
		if err != nil {
			s.logger.Errorf("handleRequest: WriteTo error: %v", err)
		} else {
			s.logger.Debugf("handleRequest: WriteTo succeeded, wrote %d bytes", n)
		}
	} else {
		s.logger.Errorf("No response generated for query from %s", w.RemoteAddr().String())
	}
}

// shutdown gracefully shuts down the server.
func (s *Server) shutdown() {
	s.logger.Info("Shutting down DNS proxy...")
	s.router.Shutdown()
	s.resolver.Shutdown()
	s.logger.Info("DNS proxy stopped")
}
