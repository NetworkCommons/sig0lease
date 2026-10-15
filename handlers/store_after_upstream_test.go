package handlers

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// failingUpsertStore is a lease store whose UpsertNonKEYRecords always fails.
type failingUpsertStore struct{ *leasepkg.InMemoryLeaseStore }

func (failingUpsertStore) UpsertNonKEYRecords(string, []dns.RR, uint32, string) error {
	return fmt.Errorf("injected store failure")
}

// recoverFrom runs f and returns what it panicked with, or nil.
func recoverFrom(f func()) (r any) {
	defer func() { r = recover() }()
	f()
	return nil
}

// newUpdateHandlerForHandle returns an UpdateHandler Setup for dev.zenr.io. with a stub upstream
// that applies every UPDATE and holds nothing, and the proxy's own key, which signs its requests.
func newUpdateHandlerForHandle(t *testing.T) (*UpdateHandler, *stubUpstreamCoordinator, *keyrec.LoadedKey) {
	t.Helper()
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	signer, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	h := NewUpdateHandler()
	h.SetLogger(logging.NewLogger("debug"))
	if err := h.Setup(map[string]any{"upstream_zone": "dev.zenr.io.", "keystore_dir": keystoreDir}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	t.Cleanup(h.Shutdown)
	stub := &stubUpstreamCoordinator{
		query: func(context.Context, string, string, uint16) ([]dns.RR, error) { return []dns.RR{}, nil },
		resp:  rcodeMsg(dns.RcodeSuccess),
	}
	h.upstreamCoordinator = stub
	return h, stub, signer
}

// TestHandle_StoreWriteFailingAfterUpstreamPanics: once the authoritative server has applied an
// update, the handler's own lease-store write cannot fail -- every check that could refuse it
// ran before the update was sent -- so a failure is a bug. Both handlers panic then, rather than
// answer as if nothing (SERVFAIL), or everything (NOERROR), had happened.
func TestHandle_StoreWriteFailingAfterUpstreamPanics(t *testing.T) {
	const want = "after the authoritative server applied it"

	t.Run("update_handler", func(t *testing.T) {
		h, stub, signer := newUpdateHandlerForHandle(t)
		h.leaseManager = failingUpsertStore{leasepkg.NewInMemoryManager()}
		req := buildSignedLeaseRegistrationForHandleTest(t, signer, "test.dev.zenr.io.", 120, 120)

		got := recoverFrom(func() { h.Handle(context.Background(), stubResponseWriter{}, req) })
		if msg, _ := got.(string); !strings.Contains(msg, want) {
			t.Fatalf("expected a panic containing %q, got %v", want, got)
		}
		if n := stub.sentCount(); n != 1 {
			t.Fatalf("sent %d upstream UPDATE(s) before the store write, want 1", n)
		}
	})

	t.Run("srp_handler", func(t *testing.T) {
		h, coord := newSRPTestHandler(t)
		h.leaseManager = failingUpsertStore{leasepkg.NewInMemoryManager()}
		id := newSRPTestIdentity(t)
		const host = "srpstorefail.dev.zenr.io."
		msg := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, nil, 60, 60, host)

		got := recoverFrom(func() { h.Handle(context.Background(), stubTCPResponseWriter{}, msg) })
		if msg, _ := got.(string); !strings.Contains(msg, want) {
			t.Fatalf("expected a panic containing %q, got %v", want, got)
		}
		if n := len(coord.sent); n != 1 {
			t.Fatalf("sent %d upstream UPDATE(s) before the store write, want 1", n)
		}
	})
}

// TestHandle_RefreshWithRecordOfAnotherKeyRefusedBeforeForwarding: a refresh whose records
// include one the store holds under another key is refused before anything is sent upstream,
// as a new registration is. It used to be sent, applied by the authoritative server, and only
// then fail the store write.
func TestHandle_RefreshWithRecordOfAnotherKeyRefusedBeforeForwarding(t *testing.T) {
	h, stub, signer := newUpdateHandlerForHandle(t)
	if err := h.leaseManager.Register(signer.PublicKey, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register the refreshing key: %v", err)
	}
	other, err := keyrec.GenerateKey("other.dev.zenr.io.", dns.ECDSAP256SHA256, 0, 256)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.leaseManager.Register(other.PublicKey, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register the other key: %v", err)
	}
	// The record the request below carries, held by the other key.
	held := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	held.TXT.Txt = []string{"payload"}
	otherNode := leasepkg.NodeKey(other.PublicKey)
	if err := h.leaseManager.UpsertNonKEYRecords(otherNode, []dns.RR{held}, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("upsert the other key's record: %v", err)
	}

	req := buildSignedLeaseRegistrationForHandleTest(t, signer, "test.dev.zenr.io.", 120, 120)
	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil || res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED, got %+v", res)
	}
	if n := stub.sentCount(); n != 0 {
		t.Fatalf("sent %d upstream UPDATE(s), want none", n)
	}
	if rec := h.leaseManager.LookupNonKEYRecord(held); rec == nil || rec.ParentKeyName != otherNode {
		t.Fatalf("the record is no longer held by the other key: %+v", rec)
	}
}
