//go:build !windows && !plan9 && !darwin

package logging

import (
	"fmt"
	"log/slog"
	"log/syslog"
)

// unixSyslog writes to the syslog daemon through Go's log/syslog, which finds the local
// socket itself (/dev/log on Linux). Not used on macOS, where its writes to
// /var/run/syslog succeed yet never reach the unified log (see syslog_darwin.go).
type unixSyslog struct {
	w *syslog.Writer
}

func openSyslog(tag string) (syslogSink, error) {
	s, err := dialSyslog("", "", tag)
	if err != nil {
		// log/syslog's own error doesn't say where it looked.
		return nil, fmt.Errorf("no syslog daemon listening on /dev/log, /var/run/syslog or /var/run/log: %w", err)
	}
	return s, nil
}

// dialSyslog connects to the syslog daemon at raddr over network, or to the local one
// when both are empty. Tests pass a socket of their own.
func dialSyslog(network, raddr, tag string) (syslogSink, error) {
	w, err := syslog.Dial(network, raddr, syslog.LOG_DAEMON|syslog.LOG_INFO, tag)
	if err != nil {
		return nil, err
	}
	return unixSyslog{w: w}, nil
}

func (s unixSyslog) write(level slog.Level, msg string) error {
	switch syslogSeverity(level) {
	case sevErr:
		return s.w.Err(msg)
	case sevWarning:
		return s.w.Warning(msg)
	case sevInfo:
		return s.w.Info(msg)
	default:
		return s.w.Debug(msg)
	}
}
