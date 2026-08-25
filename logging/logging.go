// Package logging provides structured logging for the DNS proxy.
//
// Every Logger produced by this package renders records through the same
// uniformHandler, so the on-disk format is defined in exactly one place:
//
//	2026/08/20 10:39:44.164+02:00 -- INFO -- "message"
//
// The only thing callers may vary between Logger instances is the minimum
// level (e.g. to run one module at "debug" while the rest stay at "info");
// the format itself is not configurable per instance.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
)

// timeFormat renders "2026/08/20 10:39:44.164+02:00".
const timeFormat = "2006/01/02 15:04:05.000-07:00"

// uniformHandler is the sole slog.Handler implementation used by this
// package. It exists so the log line format has exactly one definition,
// shared by every Logger regardless of level or module.
type uniformHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Leveler
	attrs []slog.Attr
}

func newUniformHandler(w io.Writer, level slog.Leveler) *uniformHandler {
	return &uniformHandler{mu: &sync.Mutex{}, w: w, level: level}
}

func (h *uniformHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *uniformHandler) Handle(_ context.Context, r slog.Record) error {
	line := fmt.Sprintf("%s -- %s -- %s",
		r.Time.Format(timeFormat), r.Level.String(), strconv.Quote(r.Message))

	appendAttr := func(a slog.Attr) bool {
		if a.Key != "" {
			line += fmt.Sprintf(" %s=%v", a.Key, a.Value.Any())
		}
		return true
	}
	for _, a := range h.attrs {
		appendAttr(a)
	}
	r.Attrs(appendAttr)

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, line+"\n")
	return err
}

func (h *uniformHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &uniformHandler{mu: h.mu, w: h.w, level: h.level, attrs: merged}
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
		logger: slog.New(newUniformHandler(os.Stdout, levelFromString(level))),
	}
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
