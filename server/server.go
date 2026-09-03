// Package server implements the DNS proxy server.
package server

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

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

	// g.Wait() blocks until every listener has returned, then yields the
	// first non-nil error (if any). On an OS signal the shared ctx is
	// canceled and every serveNetwork drains and returns nil, so Wait
	// returns nil -- a clean shutdown. A non-nil result means a listener
	// genuinely failed (bind error, unsupported network); errgroup has
	// already canceled ctx and torn the others down, so just report it.
	err := g.Wait()
	s.shutdown()
	if err != nil {
		s.logger.Errorf("Listener failed: %v", err)
		return err
	}

	s.logger.Infof("DNS Proxy shut down gracefully")
	return nil
}

// acceptMsg is the dns.Server MsgAcceptFunc for both transports. It applies
// the library's standard accept policy -- ignore response-flagged messages,
// reject an unrecognized opcode with NOTIMP, reject anything without
// exactly one question with FORMERR -- to a message decoded only through
// its header and question section, and logs any non-accept decision. The
// library turns the returned action into the FORMERR/NOTIMP reply (or into
// silence for the ignore case); this wrapper only adds the logging.
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

// invalidMsg is the dns.Server MsgInvalidFunc for both transports. The
// library calls it for a message it could not parse: a wire read error, a
// failed header/question unpack, or -- via fullUnpackHandler -- the failed
// full Unpack() this proxy performs before dispatch. The library does not
// pass this callback the connection, so the remote address isn't available.
func (s *Server) invalidMsg(m *dns.Msg, err error) {
	s.logger.Errorf("Dropping malformed DNS message: unpack failed: %v", err)
}

// udpMsgSize is the UDP read-buffer size handed to the dns library (its own
// default is dns.MinMsgSize, 512, which truncates a SIG(0)-signed UPDATE on
// read). 4096 comfortably covers a signed UPDATE carrying a KEY RR plus the
// UPDATE-LEASE option; a client that needs more must use TCP.
const udpMsgSize = 4096

// serveUDP runs the dns library's UDP server for handler, blocking until
// ctx is canceled.
func (s *Server) serveUDP(ctx context.Context, handler dns.HandlerFunc) error {
	return s.serveNetwork(ctx, "udp", handler)
}

// serveTCP runs the dns library's TCP server for handler, blocking until
// ctx is canceled.
func (s *Server) serveTCP(ctx context.Context, handler dns.HandlerFunc) error {
	return s.serveNetwork(ctx, "tcp", handler)
}

// serveNetwork runs a dns.Server on the configured address for the given
// network ("udp" or "tcp"). It blocks until ctx is canceled -- a clean
// shutdown that drains in-flight queries and returns nil -- or until
// ListenAndServe fails to start, which is returned. The listen address is
// taken verbatim from config: a host-less ":port" binds every interface,
// IPv4 and IPv6 alike.
func (s *Server) serveNetwork(ctx context.Context, network string, handler dns.HandlerFunc) error {
	srv := &dns.Server{
		Addr:           s.cfg.Server.Address,
		Net:            network,
		UDPSize:        udpMsgSize,
		Handler:        s.fullUnpackHandler(handler),
		MsgAcceptFunc:  s.acceptMsg,
		MsgInvalidFunc: s.invalidMsg,
	}

	// NotifyStartedFunc fires once the socket is bound and the accept loop
	// is running. Waiting for it before the shutdown path guarantees
	// ListenAndServe has finished the server's internal init() before
	// Shutdown() can touch it, and gives us an accurate "listener up" line.
	started := make(chan struct{})
	srv.NotifyStartedFunc = func(context.Context) {
		addr := s.cfg.Server.Address
		switch {
		case srv.Listener != nil:
			addr = srv.Listener.Addr().String()
		case srv.PacketConn != nil:
			addr = srv.PacketConn.LocalAddr().String()
		}
		s.logger.Infof("%s listener started on %s", network, addr)
		close(started)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case <-started:
	case err := <-errCh:
		return fmt.Errorf("%s listener: %w", network, err)
	}

	<-ctx.Done()
	srv.Shutdown(context.Background())
	return <-errCh
}

// fullUnpackHandler wraps h so the message is fully unpacked before h runs.
//
// codeberg.org/miekg/dns hands a Handler a message decoded only through the
// question section and expects the handler to call r.Unpack() itself if it
// needs the rest -- Ns, Extra, and the Pseudo section that carries EDNS
// options such as UPDATE-LEASE (see the dns.Handler interface docs). This
// proxy always needs the whole message: SIG(0) validation reads the Update
// section and the update handler reads the UPDATE-LEASE option, so every
// dispatch path completes the unpack here, in one place. MsgAcceptFunc has
// already run by now, so a failure here is a message with a valid header
// and question but a malformed body: log it and drop, no reply.
func (s *Server) fullUnpackHandler(h dns.HandlerFunc) dns.HandlerFunc {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if err := r.Unpack(); err != nil {
			s.invalidMsg(r, err)
			return
		}
		h(ctx, w, r)
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
