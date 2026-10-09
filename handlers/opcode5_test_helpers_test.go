package handlers

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat" // registers EDNS0 code 2 (UPDATE-LEASE); withDottedLabel unpacks messages carrying it
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// newTestHandler returns an UpdateHandler wired the way Setup leaves one -- an upstream
// coordinator and the proxy's signing key (the repository's dev.zenr.io. test key) -- without
// Setup's config parsing. Handlers never run without an upstream (see requireUpstream). The
// coordinator is a stub answering every UPDATE with NOERROR; tests that need another answer
// or the sent messages replace it. Tests that call Setup get Setup's own values instead.
func newTestHandler() *UpdateHandler {
	h := NewUpdateHandler()
	h.SetLogger(logging.NewLogger("debug"))
	key, err := keyrec.LoadKeyFromFile("../keystore/server", "Kdev.zenr.io.+015+35317")
	if err != nil {
		panic(fmt.Sprintf("newTestHandler: load test signing key: %v", err))
	}
	h.upstreamZone = "dev.zenr.io."
	h.upstreamKeyRecord = key
	h.upstreamCoordinator = &stubUpstreamCoordinator{resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}
	return h
}

// createTestKeystore creates a temporary keystore directory with a valid server key
// so that Setup() can successfully load the upstream key.
func createTestKeystore(t *testing.T) (string, error) {
	// Use the pre-existing test key from the repository's keystore.
	// We need the key files in the top-level directory (as config points to server/ subdir).
	srcKeyFile := "../keystore/server/Kdev.zenr.io.+015+35317.key"
	srcPrivFile := "../keystore/server/Kdev.zenr.io.+015+35317.private"

	tmpDir := t.TempDir()

	// Copy the key file directly into the temp directory (not a subdirectory).
	if err := copyFile(srcKeyFile, filepath.Join(tmpDir, "Kdev.zenr.io.+015+35317.key")); err != nil {
		return "", err
	}
	// Copy the private key file.
	if err := copyFile(srcPrivFile, filepath.Join(tmpDir, "Kdev.zenr.io.+015+35317.private")); err != nil {
		return "", err
	}

	return tmpDir, nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// withDottedLabel returns msg as a client would send it with its wire label from replaced by
// to -- the same length, holding a "." the library cannot produce itself (pkg/dnsname's
// labels.go) -- and decoded again, the way the server hands a request to a handler. Same
// length, so compression pointers into it stay valid; the SIG(0) signature no longer
// matches, which the handler must not get far enough to notice.
func withDottedLabel(t *testing.T, msg *dns.Msg, from, to string) *dns.Msg {
	t.Helper()
	if len(from) != len(to) {
		t.Fatalf("withDottedLabel: %q and %q differ in length", from, to)
	}
	if len(msg.Data) == 0 {
		if err := msg.Pack(); err != nil {
			t.Fatalf("pack: %v", err)
		}
	}
	f := append([]byte{byte(len(from))}, from...)
	r := append([]byte{byte(len(to))}, to...)
	if !bytes.Contains(msg.Data, f) {
		t.Fatalf("withDottedLabel: wire message has no %q label", from)
	}
	out := &dns.Msg{Data: bytes.ReplaceAll(msg.Data, f, r)}
	if err := out.Unpack(); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return out
}

// waitUntil polls cond until it holds, failing the test after 5s; what says what it waits for.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// sentUpdates records the UPDATEs a test's upstream stub is asked to send, in call order; both
// handlers' stubs embed it. A handler's expiry timers send from their own goroutines, so a test
// that lets them run reads it through sentSnapshot or sentCount.
type sentUpdates struct {
	sentMu sync.Mutex
	sent   []*dns.Msg
}

func (s *sentUpdates) recordSent(updateMsg *dns.Msg) {
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	s.sent = append(s.sent, updateMsg)
}

func (s *sentUpdates) sentSnapshot() []*dns.Msg {
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	return append([]*dns.Msg(nil), s.sent...)
}

func (s *sentUpdates) sentCount() int {
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	return len(s.sent)
}
