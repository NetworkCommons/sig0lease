// Package server implements the DNS proxy server.
package server

import (
	"net"
	"testing"
	"time"

	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/forward"
	"github.com/NetworkCommons/sig0lease/logging"
)

// TestServeReturnsErrorWhenAListenerCannotBind pins that a listener which
// fails to start propagates out of Serve() instead of being swallowed as a
// graceful shutdown. errgroup cancels the shared context as soon as the
// failing listener returns, so the guard this replaced
// (err != nil && ctx.Err() == nil) was never true and Serve() returned nil
// on every bind failure.
func TestServeReturnsErrorWhenAListenerCannotBind(t *testing.T) {
	// Hold a UDP port open so the server's bind to the same address fails.
	occupied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer occupied.Close()

	logger := logging.NewLogger("debug")
	resolver, err := forward.NewResolver([]string{"127.0.0.1:53"}, "udp", time.Second)
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	router, err := NewRouter(map[uint8]string{}, logger, resolver)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	srv := &Server{
		cfg: &config.Config{Server: config.ServerConfig{
			Address:  occupied.LocalAddr().String(),
			Networks: []string{"udp"},
		}},
		logger:   logger,
		resolver: resolver,
		router:   router,
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Serve() returned nil despite the UDP listener failing to bind")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return after the listener failed to bind")
	}
}
