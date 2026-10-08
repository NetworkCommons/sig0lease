package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

type sentRecord struct {
	sev severity
	msg string
}

type fakeSyslog struct{ sent []sentRecord }

func (f *fakeSyslog) write(level slog.Level, msg string) error {
	f.sent = append(f.sent, sentRecord{syslogSeverity(level), msg})
	return nil
}

// TestHandler_WritesEachRecordToBothOutputs: stdout gets the full line, the system log the
// quoted message alone at the level's severity -- so a newline from the network splits
// neither.
func TestHandler_WritesEachRecordToBothOutputs(t *testing.T) {
	var stdout bytes.Buffer
	sys := &fakeSyslog{}
	l := &Logger{logger: slog.New(newUniformHandler(&stdout, sys, slog.LevelDebug))}

	l.Debugf("d")
	l.Infof("added %s", "a.example. 60 IN TXT \"x\ny\"")
	l.Warnf("w")
	l.Errorf("e")

	wantSys := []sentRecord{
		{sevDebug, `"d"`},
		{sevInfo, `"added a.example. 60 IN TXT \"x\ny\""`},
		{sevWarning, `"w"`},
		{sevErr, `"e"`},
	}
	if len(sys.sent) != len(wantSys) {
		t.Fatalf("syslog got %d records, want %d: %v", len(sys.sent), len(wantSys), sys.sent)
	}
	for i, want := range wantSys {
		if sys.sent[i] != want {
			t.Fatalf("syslog record %d: got %+v, want %+v", i, sys.sent[i], want)
		}
	}

	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	wantStdout := []string{
		` -- DEBUG -- "d"`,
		` -- INFO -- "added a.example. 60 IN TXT \"x\ny\""`,
		` -- WARN -- "w"`,
		` -- ERROR -- "e"`,
	}
	if len(lines) != len(wantStdout) {
		t.Fatalf("stdout got %d lines, want %d:\n%s", len(lines), len(wantStdout), stdout.String())
	}
	for i, want := range wantStdout {
		if !strings.HasSuffix(lines[i], want) {
			t.Fatalf("stdout line %d: got %q, want it to end in %q", i, lines[i], want)
		}
	}
}

func TestHandler_LevelFiltersSyslogToo(t *testing.T) {
	sys := &fakeSyslog{}
	l := &Logger{logger: slog.New(newUniformHandler(nil, sys, slog.LevelInfo))}
	l.Debugf("dropped")
	l.Infof("kept")
	if len(sys.sent) != 1 || sys.sent[0].msg != `"kept"` {
		t.Fatalf("want only the INFO record, got %v", sys.sent)
	}
}

func TestNewLoggerWithOutput_RejectsUnknownOutput(t *testing.T) {
	for _, output := range []string{"", "file", "Syslog"} {
		if _, err := NewLoggerWithOutput("info", output); err == nil {
			t.Fatalf("NewLoggerWithOutput(%q): want an error", output)
		}
	}
}
