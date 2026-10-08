package updatecore

import (
	"context"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
)

// TestDescribeUpdateChange covers each RFC 2136 S2.5 Update-section shape the proxy sends.
func TestDescribeUpdateChange(t *testing.T) {
	const keyData = "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
	cases := []struct {
		name string
		rr   dns.RR
		want string
	}{
		{"add", mustRR(t, "host.zenr.io. 3600 IN A 192.0.2.1"),
			"added host.zenr.io. 3600 IN A 192.0.2.1"},
		{"add TXT keeps its strings", mustRR(t, `inst._http._tcp.zenr.io. 120 IN TXT "path=/a b" "v=1"`),
			`added inst._http._tcp.zenr.io. 120 IN TXT "path=/a b" "v=1"`},
		{"delete one RR", AsDelete(mustRR(t, "host.zenr.io. 3600 IN A 192.0.2.1")),
			"deleted host.zenr.io. A 192.0.2.1"},
		{"delete one KEY", AsDelete(mustRR(t, "host.zenr.io. 3600 IN KEY "+keyData)),
			"deleted host.zenr.io. KEY " + keyData},
		{"delete RRset", &dns.TXT{Hdr: dns.Header{Name: "host.zenr.io.", Class: dns.ClassANY}},
			"deleted RRset host.zenr.io. TXT"},
		{"delete all RRsets at a name", deleteAllForTest("host.zenr.io."),
			"deleted all RRsets at host.zenr.io."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeUpdateChange(tc.rr); got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestSendUpdate_LogsAppliedChangesOnlyOnNOERROR: each change of an update the server
// accepts is logged at INFO; an update it refuses logs nothing, since nothing changed.
func TestSendUpdate_LogsAppliedChangesOnlyOnNOERROR(t *testing.T) {
	var rcode atomic.Uint32
	addr := startTestAuthoritative(t, func(_ bool, query *dns.Msg) *dns.Msg {
		return replyTo(query, uint16(rcode.Load()))
	})

	// logging.NewLogger writes to the os.Stdout it finds when called, so swap a pipe in just
	// for the constructor.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	stdout := os.Stdout
	os.Stdout = w
	logger := logging.NewLogger("info")
	os.Stdout = stdout
	c := NewCoordinator(logger, nil, &StaticUpstream{Zone: "zenr.io.", Addr: addr})

	send := func(rrs ...dns.RR) {
		t.Helper()
		msg := dns.NewMsg("zenr.io.", dns.TypeSOA)
		msg.Opcode = dns.OpcodeUpdate
		msg.Ns = rrs
		if _, err := c.SendUpdate(context.Background(), "zenr.io.", msg); err != nil {
			t.Fatalf("SendUpdate: %v", err)
		}
	}
	rcode.Store(uint32(dns.RcodeRefused))
	send(mustRR(t, "refused.zenr.io. 60 IN A 192.0.2.9"))
	rcode.Store(uint32(dns.RcodeSuccess))
	send(deleteAllForTest("host.zenr.io."), mustRR(t, "host.zenr.io. 60 IN A 192.0.2.1"))

	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read log output: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	want := []string{
		"DNS update applied: zone=zenr.io. server=" + addr + " deleted all RRsets at host.zenr.io.",
		"DNS update applied: zone=zenr.io. server=" + addr + " added host.zenr.io. 60 IN A 192.0.2.1",
	}
	if len(lines) != len(want) {
		t.Fatalf("want %d log lines, got log output:\n%s", len(want), out)
	}
	for i, line := range lines {
		if !strings.Contains(line, "-- INFO -- ") || !strings.Contains(line, want[i]) {
			t.Fatalf("line %d: want an INFO line containing %q, got:\n%s", i, want[i], out)
		}
	}
}
