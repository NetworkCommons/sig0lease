// Package server implements the DNS proxy server.
package server

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/logging"
)

// echoHandler answers every message with a success carrying its header and question, as the
// transport tests' handlers do.
var echoHandler = dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	resp := &dns.Msg{MsgHeader: r.MsgHeader, Question: r.Question}
	resp.Response = true
	resp.Rcode = dns.RcodeSuccess
	resp.WriteTo(w)
})

// startDoH runs serveDoH with doh's settings until the test ends, and returns its error
// channel.
func startDoH(t *testing.T, doh *config.TLSConfig) <-chan error {
	t.Helper()
	srv := &Server{cfg: &config.Config{Server: config.ServerConfig{DoH: doh}}, logger: logging.NewLogger("debug")}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.serveDoH(ctx, echoHandler) }()
	return errCh
}

// Over HTTPS, the client's "doh" transport completes a handshake against a self-signed
// certificate it does not check (the Opportunistic Privacy profile "tls" has too) and keeps
// the message's ID, which the proxy accepts and echoes: a SIG(0) signature covers the ID.
func TestServeDoH_HTTPSRoundTripKeepsID(t *testing.T) {
	addr := reserveAddr(t, "tcp")
	certPath, keyPath := generateTestCert(t, t.TempDir())
	startDoH(t, &config.TLSConfig{Address: addr, Cert: certPath, Key: keyPath})
	url := "https://" + addr
	waitReady(t, url, "doh")

	msg := dns.NewMsg("https.test.", dns.TypeA)
	msg.ID = 4242
	resp, err := client.New(url, "doh", 2*time.Second).Query(msg)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || resp.ID != 4242 {
		t.Fatalf("got rcode=%d id=%d, want success with id 4242", resp.Rcode, resp.ID)
	}
}

// A GET request (RFC 8484 S4.1's other form) reaches the handler too, and every response
// allows any origin; a browser's preflight request is answered without a DNS message.
func TestServeDoH_GETAndCORS(t *testing.T) {
	addr := reserveAddr(t, "tcp")
	startDoH(t, &config.TLSConfig{Address: addr})
	url := "http://" + addr
	waitReady(t, url, "doh")

	req, err := dnshttp.NewRequest(http.MethodGet, url, dns.NewMsg("get.test.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	reply, err := dnshttp.Response(resp)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply.Rcode != dns.RcodeSuccess || reply.Question[0].Header().Name != "get.test." {
		t.Fatalf("got rcode=%d question=%v, want success for get.test.", reply.Rcode, reply.Question)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}

	preflight, err := http.NewRequest(http.MethodOptions, url+dnshttp.Path, nil)
	if err != nil {
		t.Fatal(err)
	}
	preflight.Header.Set("Origin", "http://page.example:8000")
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	preflight.Header.Set("Access-Control-Request-Headers", "content-type")
	resp, err = http.DefaultClient.Do(preflight)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || len(body) != 0 ||
		resp.Header.Get("Access-Control-Allow-Origin") != "*" ||
		resp.Header.Get("Access-Control-Allow-Methods") != "GET, POST" ||
		resp.Header.Get("Access-Control-Allow-Headers") != "Content-Type, Accept" {
		t.Fatalf("preflight got %s %v, want 204 allowing any origin, GET and POST, Content-Type", resp.Status, resp.Header)
	}
}

// A POST whose Content-Type is not application/dns-message is not a DNS request: HTTP 400.
func TestServeDoH_WrongContentType(t *testing.T) {
	addr := reserveAddr(t, "tcp")
	startDoH(t, &config.TLSConfig{Address: addr})
	url := "http://" + addr
	waitReady(t, url, "doh")

	resp, err := http.Post(url+dnshttp.Path, "text/plain", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got HTTP %s, want 400", resp.Status)
	}
}

// Canceling the context shuts the listener down cleanly: serveDoH returns nil. A listener
// that cannot bind returns its error at once.
func TestServeDoH_ShutdownAndBindFailure(t *testing.T) {
	addr := reserveAddr(t, "tcp")
	srv := &Server{cfg: &config.Config{Server: config.ServerConfig{DoH: &config.TLSConfig{Address: addr}}}, logger: logging.NewLogger("debug")}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.serveDoH(ctx, echoHandler) }()
	waitReady(t, "http://"+addr, "doh")

	again := &Server{cfg: &config.Config{Server: config.ServerConfig{DoH: &config.TLSConfig{Address: addr}}}, logger: logging.NewLogger("debug")}
	if err := again.serveDoH(context.Background(), echoHandler); err == nil {
		t.Fatalf("a second listener on %s started; want a bind error", addr)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serveDoH returned %v after cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("serveDoH did not return after cancel")
	}
}
