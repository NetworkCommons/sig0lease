//go:build windows || plan9 || (darwin && !cgo)

package logging

import (
	"fmt"
	"runtime"
)

// openSyslog fails on builds with no working system log: Windows and Plan 9 have no
// syslog, and on macOS only syslog(3) reaches the unified log, which needs cgo (see
// syslog_darwin.go) -- a macOS binary cross-compiled from another OS is built without it.
func openSyslog(string) (syslogSink, error) {
	if runtime.GOOS == "darwin" {
		return nil, fmt.Errorf("this macOS build has no syslog support: build it on macOS with cgo enabled (CGO_ENABLED=1)")
	}
	return nil, fmt.Errorf("syslog is not supported on %s", runtime.GOOS)
}
