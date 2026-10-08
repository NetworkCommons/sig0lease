// Package logging provides structured logging for the DNS proxy.
//
// Every Logger produced by this package renders records through the same
// uniformHandler, so the on-disk format is defined in exactly one place:
//
//	2026/08/20 10:39:44.164+02:00 -- INFO -- "message"
//
// The only things callers may vary between Logger instances are the minimum
// level (e.g. to run one module at "debug" while the rest stay at "info") and
// the output: stdout, the system log, or both (NewLoggerWithOutput). The system
// log gets the same "message" part, with the time stamp left to syslog and the
// level carried as the record's syslog severity.
package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
)

// timeFormat renders "2026/08/20 10:39:44.164+02:00".
const timeFormat = "2006/01/02 15:04:05.000-07:00"

// Values of NewLoggerWithOutput's output.
const (
	OutputStdout = "stdout"
	OutputSyslog = "syslog"
	OutputBoth   = "both"
)

// syslogTag names the proxy in the system log (e.g. journalctl -t sig0lease).
const syslogTag = "sig0lease"

// syslogSink sends one record to the system log. Each platform supplies its own
// openSyslog (syslog_*.go).
type syslogSink interface {
	write(level slog.Level, msg string) error
}

// severity is a syslog severity (RFC 5424 S6.2.1); the values are the same in every
// platform's syslog.
type severity int

const (
	sevErr     severity = 3
	sevWarning severity = 4
	sevInfo    severity = 6
	sevDebug   severity = 7
)

// syslogSeverity maps a record's level to the syslog severity it is sent at.
func syslogSeverity(level slog.Level) severity {
	switch {
	case level >= slog.LevelError:
		return sevErr
	case level >= slog.LevelWarn:
		return sevWarning
	case level >= slog.LevelInfo:
		return sevInfo
	default:
		return sevDebug
	}
}

// uniformHandler is the sole slog.Handler implementation used by this
// package. It exists so the log line format has exactly one definition,
// shared by every Logger regardless of level, module or output.
type uniformHandler struct {
	mu    *sync.Mutex
	w     io.Writer  // stdout; nil when logging to the system log only
	sys   syslogSink // nil when logging to stdout only
	level slog.Leveler
	attrs []slog.Attr
}

func newUniformHandler(w io.Writer, sys syslogSink, level slog.Leveler) *uniformHandler {
	return &uniformHandler{mu: &sync.Mutex{}, w: w, sys: sys, level: level}
}

func (h *uniformHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *uniformHandler) Handle(_ context.Context, r slog.Record) error {
	// Quoted, so text from the network (a client's TXT data, say) can't split one
	// record into several lines in either output.
	msg := strconv.Quote(r.Message)

	appendAttr := func(a slog.Attr) bool {
		if a.Key != "" {
			msg += fmt.Sprintf(" %s=%v", a.Key, a.Value.Any())
		}
		return true
	}
	for _, a := range h.attrs {
		appendAttr(a)
	}
	r.Attrs(appendAttr)

	h.mu.Lock()
	defer h.mu.Unlock()
	var errs []error
	if h.w != nil {
		line := fmt.Sprintf("%s -- %s -- %s\n", r.Time.Format(timeFormat), r.Level.String(), msg)
		if _, err := io.WriteString(h.w, line); err != nil {
			errs = append(errs, err)
		}
	}
	if h.sys != nil {
		if err := h.sys.write(r.Level, msg); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (h *uniformHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &uniformHandler{mu: h.mu, w: h.w, sys: h.sys, level: h.level, attrs: merged}
}

func (h *uniformHandler) WithGroup(_ string) slog.Handler {
	// Groups are unused in this codebase; the flat format has no notion
	// of nesting, so this is a no-op rather than a second format.
	return h
}

// Logger wraps slog.Logger with convenience methods including Debugf.
type Logger struct {
	logger *slog.Logger
}

func levelFromString(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// NewLogger creates a new logger instance writing the package's single
// canonical log format to stdout. level is the only setting that may
// differ between instances (e.g. a per-module override), so that every
// logger in the process stays uniformly formatted.
func NewLogger(level string) *Logger {
	return &Logger{
		logger: slog.New(newUniformHandler(os.Stdout, nil, levelFromString(level))),
	}
}

// NewLoggerWithOutput creates a logger like NewLogger's, writing each record to output:
// OutputStdout, OutputSyslog (the local system log) or OutputBoth. It fails for any other
// output, and when the system log can't be opened -- including on a build that has no
// working system log (syslog_unsupported.go).
func NewLoggerWithOutput(level, output string) (*Logger, error) {
	var w io.Writer
	var sys syslogSink
	switch output {
	case OutputStdout:
		w = os.Stdout
	case OutputSyslog, OutputBoth:
		s, err := openSyslog(syslogTag)
		if err != nil {
			return nil, fmt.Errorf("open syslog: %w", err)
		}
		sys = s
		if output == OutputBoth {
			w = os.Stdout
		}
	default:
		return nil, fmt.Errorf("unknown log output %q (want %q, %q or %q)", output, OutputStdout, OutputSyslog, OutputBoth)
	}
	return &Logger{
		logger: slog.New(newUniformHandler(w, sys, levelFromString(level))),
	}, nil
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string, keysAndValues ...any) {
	l.logger.Debug(msg, keysAndValues...)
}

// Info logs an info message.
func (l *Logger) Info(msg string, keysAndValues ...any) {
	l.logger.Info(msg, keysAndValues...)
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string, keysAndValues ...any) {
	l.logger.Warn(msg, keysAndValues...)
}

// Error logs an error message.
func (l *Logger) Error(msg string, keysAndValues ...any) {
	l.logger.Error(msg, keysAndValues...)
}

// logf formats and emits a message at level, but only if level is actually
// enabled. Debugf in particular is called many times per request with
// arguments that are themselves expensive to stringify (full RRs/messages);
// formatting them only to have the handler discard the result below its
// level would pay that cost on every request regardless of log level.
func (l *Logger) logf(level slog.Level, format string, args ...any) {
	ctx := context.Background()
	if !l.logger.Enabled(ctx, level) {
		return
	}
	l.logger.Log(ctx, level, fmt.Sprintf(format, args...))
}

// Debugf logs a debug message with format.
func (l *Logger) Debugf(format string, args ...any) {
	l.logf(slog.LevelDebug, format, args...)
}

// Infof logs an info message with format.
func (l *Logger) Infof(format string, args ...any) {
	l.logf(slog.LevelInfo, format, args...)
}

// Warnf logs a warning message with format.
func (l *Logger) Warnf(format string, args ...any) {
	l.logf(slog.LevelWarn, format, args...)
}

// Errorf logs an error message with format.
func (l *Logger) Errorf(format string, args ...any) {
	l.logf(slog.LevelError, format, args...)
}
