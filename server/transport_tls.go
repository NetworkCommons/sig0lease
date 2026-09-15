package server

import (
	"context"
	"crypto/tls"
	"fmt"

	"codeberg.org/miekg/dns"
)

// serveDoT runs a DNS-over-TLS listener (RFC 7858, plan S7/Phase 7) for handler, blocking
// until ctx is canceled. Transport-level, like serveTCP/serveUDP: it benefits every handler
// this proxy runs (base RFC 9664, SRP, plain forwarding alike) rather than being specific to
// one protocol, and is opportunistic only -- no client-certificate/key-pinning
// authentication, matching what the plan calls for (SRP's own registrar-side crypto is
// SIG(0), unrelated to and unaffected by this transport).
//
// Requires cfg.Server.TLS (validated non-nil, with Address/Cert/Key all set, by
// config.Config.Validate before Serve ever reaches here). The underlying dns.Server has no
// dedicated "tls" network of its own -- per its own TLSConfig field's doc comment, a "tcp"
// server with a non-nil TLSConfig is what starts a TLS listener, so serveNetwork is reused
// unchanged with network "tcp" and this function's own address/TLS config, not
// cfg.Server.Address (DoT conventionally listens on its own port, RFC 7858 default 853,
// alongside plain DNS on 53 -- binding both to the same address would collide).
func (s *Server) serveDoT(ctx context.Context, handler dns.HandlerFunc) error {
	if s.cfg.Server.TLS == nil {
		return fmt.Errorf(`"tls" network enabled but server.tls is not configured`)
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.Server.TLS.Cert, s.cfg.Server.TLS.Key)
	if err != nil {
		return fmt.Errorf("load server.tls certificate/key: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// dns.NextProtos ({"dot"}): RFC 7858 S3.2's required ALPN identifier -- without
		// it, a DoT client performing ALPN negotiation has no way to confirm this
		// listener actually speaks DNS-over-TLS rather than some other TLS-wrapped
		// protocol on the same port.
		NextProtos: dns.NextProtos,
	}
	return s.serveNetwork(ctx, "tcp", s.cfg.Server.TLS.Address, tlsConfig, handler)
}
