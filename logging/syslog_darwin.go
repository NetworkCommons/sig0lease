//go:build darwin && cgo

package logging

/*
#include <stdlib.h>
#include <syslog.h>

// syslog(3) is variadic, which cgo can't call. Passing the message as the argument of
// "%s" also keeps a '%' in it from being read as a format directive.
static void sig0lease_syslog(int priority, const char *msg) { syslog(priority, "%s", msg); }
*/
import "C"

import (
	"log/slog"
	"unsafe"
)

// darwinSyslog writes through the C library's syslog(3), which macOS routes into the
// unified log (Console.app, log show). Go's log/syslog is no use there: its writes to
// /var/run/syslog succeed but never show up. syslog(3) reports no errors, so a lost
// message can't be detected here; OutputBoth keeps a copy on stdout.
type darwinSyslog struct{}

func openSyslog(tag string) (syslogSink, error) {
	// openlog keeps using the ident pointer for the life of the process, so it is never
	// freed.
	C.openlog(C.CString(tag), C.LOG_PID, C.LOG_DAEMON)
	return darwinSyslog{}, nil
}

func (darwinSyslog) write(level slog.Level, msg string) error {
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cmsg))
	C.sig0lease_syslog(C.int(syslogSeverity(level)), cmsg)
	return nil
}
