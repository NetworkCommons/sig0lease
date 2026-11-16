package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
)

func init() {
	// dnshttp.Request applies dnshttp.MsgAcceptFunc to every message it reads, and the
	// library's default refuses a DNS ID other than 0, which RFC 8484 S4.1 only suggests (a
	// SHOULD, for caching): a SIG(0)-signed UPDATE keeps the ID it was signed with
	// (client.queryDoH). serveDoH applies acceptMsg itself instead, the accept policy every
	// other transport runs, so the library's own check accepts everything.
	dnshttp.MsgAcceptFunc = func(*dns.Msg) dns.MsgAcceptAction { return dns.MsgAccept }
}

// dohReadHeaderTimeout bounds how long a DoH client may take to send its request headers.
// The body and the handlers' work are bounded by the router's request timeout.
const dohReadHeaderTimeout = 10 * time.Second

// serveDoH runs a DNS-over-HTTPS listener (RFC 8484) for handler at "/dns-query", blocking
// until ctx is canceled -- a clean shutdown that drains in-flight requests and returns nil --
// or until the listener fails. Transport-level, like serveDoT: every handler is reached
// through it alike. With a certificate it serves HTTPS (HTTP/2 or HTTP/1.1), without one plain
// HTTP: a browser refuses a self-signed certificate, and a page served over plain HTTP on the
// LAN may reach a plain-HTTP listener (docs/siglease_rfc9664.md, "DNS-over-HTTPS").
//
// Requires cfg.Server.DoH (validated by config.Config.Validate before Serve reaches here).
func (s *Server) serveDoH(ctx context.Context, handler dns.HandlerFunc) error {
	cfg := s.cfg.Server.DoH
	if cfg == nil {
		return fmt.Errorf(`"doh" network enabled but server.doh is not configured`)
	}
	mux := http.NewServeMux()
	mux.Handle(dnshttp.Path, s.dohHandler(s.fullUnpackHandler(handler)))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: dohReadHeaderTimeout}

	scheme := "http"
	if cfg.Cert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return fmt.Errorf("load server.doh certificate/key: %w", err)
		}
		// ServeTLS adds HTTP/2 to NextProtos, as dnshttp.NextProtos asks.
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		scheme = "https"
	}

	ln, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return fmt.Errorf("doh listener: %w", err)
	}
	s.logger.Infof("doh listener started on %s://%s%s", scheme, ln.Addr(), dnshttp.Path)

	errCh := make(chan error, 1)
	go func() {
		if scheme == "https" {
			errCh <- srv.ServeTLS(ln, "", "")
		} else {
			errCh <- srv.Serve(ln)
		}
	}()

	select {
	case <-ctx.Done():
		srv.Shutdown(context.Background())
		if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("doh listener: %w", err)
		}
		return nil
	case err := <-errCh:
		return fmt.Errorf("doh listener: %w", err)
	}
}

// noStore is the http.ResponseWriter under dnshttp's: it replaces the Cache-Control dnshttp
// sets on every answer, max-age=600, with no-store, as the header goes out. The proxy answers
// a query for its zones from their authoritative server so that the asker sees a change at
// once; a browser that kept the answer of a GET for 10 minutes would undo that, as would an
// HTTP cache on the way. An answer to a POST, an UPDATE's, is not cached anyway.
type noStore struct{ http.ResponseWriter }

func (w noStore) WriteHeader(code int) {
	w.Header().Set("Cache-Control", "no-store")
	w.ResponseWriter.WriteHeader(code)
}

// dohHandler turns each RFC 8484 request into a DNS message and serves it as the dns.Server
// of the other transports does (serveNetwork): acceptMsg first, which ignores a response,
// answers FORMERR or NOTIMP without dispatching, or accepts; then next, with a
// dns.ResponseWriter that writes the reply as the HTTP response body. A request that is not a
// DNS message, or a message that is ignored, gets HTTP 400: there is no DNS reply to send.
//
// Every response allows any origin (CORS), so that a page served from elsewhere -- a laptop's
// web server on another port, as in the demos -- can send DNS messages from a browser; it
// answers the preflight request a browser sends first for the application/dns-message
// Content-Type. That lets any page a visitor opens reach the proxy through the visitor's
// browser, as anything on the network reaches its UDP and TCP listeners: an UPDATE still
// needs its SIG(0) signature.
func (s *Server) dohHandler(next dns.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		m, err := dnshttp.Request(r)
		if err != nil {
			s.logger.Errorf("doh: dropping a request from %s that is not a DNS message: %v", r.RemoteAddr, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		laddr, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		dw := dnshttp.NewResponseWriter(noStore{w}, r, laddr)

		switch action := s.acceptMsg(m); action {
		case dns.MsgIgnore:
			http.Error(w, "not a DNS request", http.StatusBadRequest)
			return
		case dns.MsgReject, dns.MsgRejectNotImplemented:
			// What dns.Server sends for these (its serveDNS): the header and question back,
			// as a response with the rejection's RCODE.
			m.Rcode = dns.RcodeFormatError
			if action == dns.MsgRejectNotImplemented {
				m.Rcode = dns.RcodeNotImplemented
			}
			m.Authoritative = false
			m.Response = true
			m.Zero = false
			m.Reset()
			if err := m.Pack(); err != nil {
				s.logger.Errorf("doh: pack rejection reply: %v", err)
				http.Error(w, "cannot pack reply", http.StatusInternalServerError)
				return
			}
			if _, err := m.WriteTo(dw); err != nil {
				s.logger.Errorf("doh: write rejection reply: %v", err)
			}
			return
		}
		next(r.Context(), dw, m)
	})
}
