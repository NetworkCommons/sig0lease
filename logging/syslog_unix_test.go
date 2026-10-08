//go:build !windows && !plan9 && !darwin

package logging

import (
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUnixSyslog_SendsEachLevelAtItsSeverity reads what log/syslog actually puts on the
// wire, from a socket standing in for /dev/log: facility daemon (3), so PRI is 24 plus
// the severity, and the tag on every message.
func TestUnixSyslog_SendsEachLevelAtItsSeverity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	sys, err := dialSyslog("unixgram", path, syslogTag)
	if err != nil {
		t.Fatalf("dialSyslog: %v", err)
	}
	l := &Logger{logger: slog.New(newUniformHandler(nil, sys, slog.LevelDebug))}
	l.Debugf("d")
	l.Infof("i")
	l.Warnf("w")
	l.Errorf("e")

	want := []struct{ pri, msg string }{
		{"<31>", `"d"`},
		{"<30>", `"i"`},
		{"<28>", `"w"`},
		{"<27>", `"e"`},
	}
	buf := make([]byte, 2048)
	for _, w := range want {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got := string(buf[:n])
		if !strings.HasPrefix(got, w.pri) || !strings.Contains(got, " "+syslogTag+"[") || !strings.HasSuffix(strings.TrimSuffix(got, "\n"), ": "+w.msg) {
			t.Fatalf("got %q, want PRI %s, tag %s and message %s", got, w.pri, syslogTag, w.msg)
		}
	}
}
