// Package server implements the DNS proxy server.
package server

import (
	"context"
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/logging"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat" // registers EDNS code 2 so UPDATE-LEASE unpacks; see README_proxy.md
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/lease"
)

// reserveAddr grabs an OS-assigned free port on 127.0.0.1 for the given
// network ("udp" or "tcp"), then immediately releases it so serveUDP/
// serveTCP can bind it. There's an inherent (vanishingly small on
// loopback) race between the release and the real bind; waitReady below
// retries past it.
func reserveAddr(t *testing.T, network string) string {
	t.Helper()
	switch network {
	case "udp":
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("reserve UDP port: %v", err)
		}
		addr := conn.LocalAddr().String()
		conn.Close()
		return addr
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve TCP port: %v", err)
		}
		addr := ln.Addr().String()
		ln.Close()
		return addr
	default:
		t.Fatalf("unsupported network %q", network)
		return ""
	}
}

// waitReady polls addr with well-formed queries until one succeeds,
// covering the gap between the goroutine starting and its Listen/
// ListenUDP call actually completing.
func waitReady(t *testing.T, addr, protocol string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c := client.New(addr, protocol, 100*time.Millisecond)
		if _, err := c.Query(dns.NewMsg("readiness-check.test.", dns.TypeA)); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s server on %s never became ready", protocol, addr)
}

// TestUDPTCPTransportEquivalence drives the same inputs through serveUDP
// and serveTCP -- via the real client package, which already supports both
// protocols -- and asserts they're handled identically. Both transports
// run the same dns.Server accept policy (acceptMsg, wired as its
// MsgAcceptFunc); this pins that they stay in lockstep.
func TestUDPTCPTransportEquivalence(t *testing.T) {
	udpAddr := reserveAddr(t, "udp")
	tcpAddr := reserveAddr(t, "tcp")

	logger := logging.NewLogger("debug")
	udpSrv := &Server{cfg: &config.Config{Server: config.ServerConfig{Address: udpAddr}}, logger: logger}
	tcpSrv := &Server{cfg: &config.Config{Server: config.ServerConfig{Address: tcpAddr}}, logger: logger}

	// A handler that always succeeds, so any test case that unexpectedly
	// reaches it is obvious: its Rcode (Success) never matches the FORMERR/
	// NOTIMP a correctly-rejected message should get instead. Uses
	// WriteTo, matching handleRequest's production write path -- plain
	// Write would skip TCP's required 2-byte length prefix.
	handler := dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		resp := &dns.Msg{MsgHeader: r.MsgHeader, Question: r.Question}
		resp.Response = true
		resp.Rcode = dns.RcodeSuccess
		resp.WriteTo(w)
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = udpSrv.serveUDP(ctx, handler) }()
	go func() { _ = tcpSrv.serveTCP(ctx, handler) }()

	waitReady(t, udpAddr, "udp")
	waitReady(t, tcpAddr, "tcp")

	rcode := func(r uint16) *uint16 { return &r }

	cases := []struct {
		name string
		msg  func() *dns.Msg
		// wantRcode nil means "expect no reply at all" (the ignore case).
		wantRcode *uint16
	}{
		{
			name:      "well-formed query is accepted and routed to the handler",
			msg:       func() *dns.Msg { return dns.NewMsg("accepted.test.", dns.TypeA) },
			wantRcode: rcode(dns.RcodeSuccess),
		},
		{
			name: "response-flagged message is dropped without a reply",
			msg: func() *dns.Msg {
				m := dns.NewMsg("ignored.test.", dns.TypeA)
				m.Response = true
				return m
			},
			wantRcode: nil,
		},
		{
			name: "unrecognized opcode is rejected as NOTIMP before reaching the handler",
			msg: func() *dns.Msg {
				m := dns.NewMsg("notimp.test.", dns.TypeA)
				m.Opcode = 15
				return m
			},
			wantRcode: rcode(dns.RcodeNotImplemented),
		},
		// A two-question case belongs here too (acceptMsg rejects any
		// question count != 1, not just zero), but codeberg.org/miekg/dns's
		// own Pack() can't round-trip a real QDCOUNT=2 message -- it writes
		// QDCOUNT=2 in the header but only serializes one Question RR's
		// bytes, so Unpack() always fails with "overflow name" regardless
		// of what the server under test does. That's a library limitation,
		// not something sig0lease can construct valid wire bytes for via
		// client.Client, so it's not exercisable here; the zero-question
		// case below already covers the same acceptMsg branch.
		{
			name: "zero questions is rejected as FORMERR before reaching the handler",
			msg: func() *dns.Msg {
				m := dns.NewMsg("zero.test.", dns.TypeA)
				m.Question = nil
				return m
			},
			wantRcode: rcode(dns.RcodeFormatError),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, proto := range []string{"udp", "tcp"} {
				t.Run(proto, func(t *testing.T) {
					addr := udpAddr
					timeout := 2 * time.Second
					if proto == "tcp" {
						addr = tcpAddr
					}
					if tc.wantRcode == nil {
						timeout = 300 * time.Millisecond // fail fast: we expect no reply
					}

					c := client.New(addr, proto, timeout)
					resp, err := c.Query(tc.msg())

					if tc.wantRcode == nil {
						if err == nil {
							t.Fatalf("expected no reply, got response with rcode=%d", resp.Rcode)
						}
						return
					}
					if err != nil {
						t.Fatalf("query failed: %v", err)
					}
					if resp.Rcode != *tc.wantRcode {
						t.Fatalf("got rcode=%d, want %d", resp.Rcode, *tc.wantRcode)
					}
				})
			}
		})
	}

	// Below the accept-policy table: malformed wire bytes that fail to
	// Unpack() at all. client.Client always packs a valid *dns.Msg, so this
	// needs raw sockets to put genuinely malformed bytes on the wire.
	t.Run("malformed wire bytes are dropped without a reply", func(t *testing.T) {
		t.Run("udp", func(t *testing.T) {
			conn, err := net.Dial("udp", udpAddr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte{0xFF, 0xFF, 0xFF}); err != nil {
				t.Fatalf("write: %v", err)
			}
			conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			buf := make([]byte, 512)
			if _, err := conn.Read(buf); err == nil {
				t.Fatalf("expected no reply to a malformed UDP packet")
			}
		})

		t.Run("tcp", func(t *testing.T) {
			conn, err := net.Dial("tcp", tcpAddr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			// 2-byte big-endian length prefix (4) followed by 4 garbage
			// bytes: a structurally valid TCP frame whose body is too
			// short to be a DNS header, so it fails in Unpack() rather
			// than at the length-prefix framing level.
			frame := []byte{0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF}
			if _, err := conn.Write(frame); err != nil {
				t.Fatalf("write: %v", err)
			}
			conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			buf := make([]byte, 512)
			if _, err := conn.Read(buf); err == nil {
				t.Fatalf("expected no reply to a malformed TCP frame")
			}
		})
	})
}

// TestServeTCPPreservesUpdateLeaseOption asserts the UPDATE-LEASE EDNS
// option reaches the handler intact over both transports.
//
// codeberg.org/miekg/dns hands a Handler a message decoded only through the
// question section; the handler is expected to call r.Unpack() itself to
// get Ns/Extra/Pseudo, and therefore any EDNS option (see the dns.Handler
// interface docs). fullUnpackHandler in the server package does exactly
// that on every dispatch path -- this test pins that wiring. Without it a
// register/refresh over either transport would look like "UPDATE without
// UPDATE-LEASE" to the update handler. TestUDPTCPTransportEquivalence above
// doesn't cover it: none of its cases populate Ns/Extra/Pseudo, since
// acceptMsg only looks at the header and Question.
func TestServeTCPPreservesUpdateLeaseOption(t *testing.T) {
	udpAddr := reserveAddr(t, "udp")
	tcpAddr := reserveAddr(t, "tcp")

	logger := logging.NewLogger("debug")
	udpSrv := &Server{cfg: &config.Config{Server: config.ServerConfig{Address: udpAddr}}, logger: logger}
	tcpSrv := &Server{cfg: &config.Config{Server: config.ServerConfig{Address: tcpAddr}}, logger: logger}

	// One handler serves both transports. It reports, per UPDATE, whether
	// it saw the option; filtering on the opcode keeps the plain-A
	// readiness probes waitReady sends off the channel, and the channel
	// (rather than a shared bool) keeps the observation ordered with the
	// test goroutine that reads it and race-free across handler goroutines.
	sawLeaseOpt := make(chan bool, 1)
	handler := dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if r.Opcode == dns.OpcodeUpdate {
			_, ok := lease.FindOption(r)
			sawLeaseOpt <- ok
		}
		resp := &dns.Msg{MsgHeader: r.MsgHeader, Question: r.Question}
		resp.Response = true
		resp.Rcode = dns.RcodeSuccess
		resp.WriteTo(w)
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = udpSrv.serveUDP(ctx, handler) }()
	go func() { _ = tcpSrv.serveTCP(ctx, handler) }()

	waitReady(t, udpAddr, "udp")
	waitReady(t, tcpAddr, "tcp")

	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			msg, err := dnsmsg.NewLeaseUpdate("lease-test.example.", nil, nil, 0, 0)
			if err != nil {
				t.Fatalf("build lease update: %v", err)
			}

			addr := udpAddr
			if proto == "tcp" {
				addr = tcpAddr
			}
			c := client.New(addr, proto, 2*time.Second)
			resp, err := c.Query(msg)
			if err != nil {
				t.Fatalf("query failed: %v", err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("got rcode=%d, want success", resp.Rcode)
			}
			select {
			case ok := <-sawLeaseOpt:
				if !ok {
					t.Fatalf("handler did not see the UPDATE-LEASE EDNS option -- it was lost in transit")
				}
			case <-time.After(time.Second):
				t.Fatalf("handler was never invoked for the UPDATE")
			}
		})
	}
}
