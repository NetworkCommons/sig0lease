package handlers

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

// fcfsTestHandler returns an UpdateHandler for dev.zenr.io. with fcfs_naming set to fcfs, whose
// stub upstream publishes the KEYs in published (by owner name), nothing else, and answers
// every UPDATE with rcode.
func fcfsTestHandler(t *testing.T, fcfs bool, published map[string][]*dns.KEY, rcode uint16) (*UpdateHandler, *stubUpstreamCoordinator) {
	t.Helper()
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{"upstream_zone": "dev.zenr.io.", "keystore_dir": keystoreDir, "fcfs_naming": fcfs}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	t.Cleanup(h.Shutdown)
	stub := &stubUpstreamCoordinator{
		resp: rcodeMsg(rcode),
		query: func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
			var rrs []dns.RR
			if rrType == dns.TypeKEY {
				for name, keys := range published {
					if dnsname.Normalize(name) == dnsname.Normalize(fqdn) {
						for _, k := range keys {
							rrs = append(rrs, k)
						}
					}
				}
			}
			return rrs, nil
		},
	}
	h.upstreamCoordinator = stub
	return h, stub
}

func fcfsTestKey(t *testing.T, name string) *keyrec.LoadedKey {
	t.Helper()
	k, err := keyrec.GenerateKey(name, dns.ED25519, 0, 256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// buildFCFSUpdate builds an RFC 9664 update as cmd/sig0lease-client does, with the signer's
// name in the Zone section, registering keys and records, signed by signer.
func buildFCFSUpdate(t *testing.T, signer *keyrec.LoadedKey, keys []*dns.KEY, records []dns.RR, lease, keyLease uint32) *dns.Msg {
	t.Helper()
	msg, err := dnsmsg.NewLeaseUpdate(signer.PublicKey.Hdr.Name, keys, records, lease, keyLease)
	if err != nil {
		t.Fatalf("build update: %v", err)
	}
	signed, err := sig0.SignMessage(msg, signer.PublicKey, signer.PrivateKey)
	if err != nil {
		t.Fatalf("sign update: %v", err)
	}
	return signed
}

func fcfsTestTXT(name string) *dns.TXT {
	txt := &dns.TXT{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"payload"}
	return txt
}

// selfRegistration is a key registering itself, with a TXT at its own name: Case A.
func selfRegistration(t *testing.T, k *keyrec.LoadedKey) *dns.Msg {
	return buildFCFSUpdate(t, k, []*dns.KEY{k.PublicKey}, []dns.RR{fcfsTestTXT(k.PublicKey.Hdr.Name)}, 120, 120)
}

// keyPrereqNames returns the owner names of the "KEY RRset does not exist" prerequisites of
// msg, the UPDATE sent upstream.
func keyPrereqNames(msg *dns.Msg) []string {
	var names []string
	for _, rr := range msg.Answer {
		if dns.RRToType(rr) == dns.TypeKEY && rr.Header().Class == dns.ClassNONE {
			names = append(names, rr.Header().Name)
		}
	}
	return names
}

// A free name is registered, and the UPDATE has the authoritative server check that it is
// still free.
func TestFCFSNaming_FreeName(t *testing.T) {
	h, stub := fcfsTestHandler(t, true, nil, dns.RcodeSuccess)
	alice := fcfsTestKey(t, "alice.dev.zenr.io.")

	res := h.Handle(context.Background(), stubResponseWriter{}, selfRegistration(t, alice))
	if res.Status != StatusProcessed || res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}
	sent := stub.sentSnapshot()
	if len(sent) != 1 {
		t.Fatalf("expected one UPDATE upstream, got %d", len(sent))
	}
	if got := keyPrereqNames(sent[0]); len(got) != 1 || got[0] != "alice.dev.zenr.io." {
		t.Fatalf("prerequisites = %v, want \"KEY RRset does not exist\" at alice.dev.zenr.io.", got)
	}
}

// A new KEY registering itself is refused where a different key holds its name, whether this
// proxy's store or only the zone knows that key.
func TestFCFSNaming_HeldName_YXDOMAIN(t *testing.T) {
	bob := fcfsTestKey(t, "alice.dev.zenr.io.")
	cases := []struct {
		name      string
		stored    bool
		published map[string][]*dns.KEY
	}{
		{name: "published", published: map[string][]*dns.KEY{"alice.dev.zenr.io.": {bob.PublicKey}}},
		{name: "in the store", stored: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, stub := fcfsTestHandler(t, true, tc.published, dns.RcodeSuccess)
			if tc.stored {
				if err := h.leaseManager.Register(bob.PublicKey.Clone().(*dns.KEY), 120, 120, "dev.zenr.io."); err != nil {
					t.Fatalf("register holder: %v", err)
				}
			}
			stranger := fcfsTestKey(t, "alice.dev.zenr.io.")

			res := h.Handle(context.Background(), stubResponseWriter{}, selfRegistration(t, stranger))
			wantErrorReply(t, res, dns.RcodeYXDomain, dns.ExtendedErrorProhibited, "name held by a different key")
			if n := stub.sentCount(); n != 0 {
				t.Fatalf("expected nothing sent upstream, got %d UPDATE(s)", n)
			}
		})
	}
}

// A KEY registers itself only one label below the zone: at the apex, or deeper with every name
// above it free, it is refused before any name is checked.
func TestFCFSNaming_SelfRegistrationNotOneLabelBelow_Refused(t *testing.T) {
	for _, owner := range []string{"dev.zenr.io.", "_acme-challenge.alice.dev.zenr.io."} {
		t.Run(owner, func(t *testing.T) {
			h, stub := fcfsTestHandler(t, true, nil, dns.RcodeSuccess)
			k := fcfsTestKey(t, owner)

			res := h.Handle(context.Background(), stubResponseWriter{}, selfRegistration(t, k))
			wantErrorReply(t, res, dns.RcodeRefused, dns.ExtendedErrorProhibited, "only one label below zone dev.zenr.io.")
			if n := stub.sentCount(); n != 0 {
				t.Fatalf("expected nothing sent upstream, got %d UPDATE(s)", n)
			}
		})
	}
}

// A key registering a KEY below a name a different key holds is refused, whether this proxy's
// store or only the zone knows that key: only the holder registers below its name.
func TestFCFSNaming_RegistersBelowAnotherKey_YXDOMAIN(t *testing.T) {
	alice := fcfsTestKey(t, "alice.dev.zenr.io.")
	carol := fcfsTestKey(t, "lab.alice.dev.zenr.io.")
	cases := []struct {
		name   string
		stored bool
	}{
		{name: "published"},
		{name: "in the store", stored: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			published := map[string][]*dns.KEY{"alice.dev.zenr.io.": {alice.PublicKey}}
			if !tc.stored {
				published["lab.alice.dev.zenr.io."] = []*dns.KEY{carol.PublicKey}
			}
			h, stub := fcfsTestHandler(t, true, published, dns.RcodeSuccess)
			aliceRR := alice.PublicKey.Clone().(*dns.KEY)
			if err := h.leaseManager.Register(aliceRR, 120, 120, "dev.zenr.io."); err != nil {
				t.Fatalf("register alice: %v", err)
			}
			if tc.stored {
				if err := h.leaseManager.RegisterWithParent(leasepkg.NodeKey(aliceRR), carol.PublicKey.Clone().(*dns.KEY), 120, 120, "dev.zenr.io."); err != nil {
					t.Fatalf("register carol under alice: %v", err)
				}
			}
			printer := fcfsTestKey(t, "printer.lab.alice.dev.zenr.io.")

			res := h.Handle(context.Background(), stubResponseWriter{}, buildFCFSUpdate(t, alice, []*dns.KEY{printer.PublicKey}, nil, 0, 120))
			wantErrorReply(t, res, dns.RcodeYXDomain, dns.ExtendedErrorProhibited, "name held by a different key")
			if n := stub.sentCount(); n != 0 {
				t.Fatalf("expected nothing sent upstream, got %d UPDATE(s)", n)
			}
		})
	}
}

// The key holding a name registers another KEY below it (Case D): only the names below the
// holder's own are checked.
func TestFCFSNaming_HolderRegistersBelowItself(t *testing.T) {
	alice := fcfsTestKey(t, "alice.dev.zenr.io.")
	h, stub := fcfsTestHandler(t, true, map[string][]*dns.KEY{"alice.dev.zenr.io.": {alice.PublicKey}}, dns.RcodeSuccess)
	if err := h.leaseManager.Register(alice.PublicKey.Clone().(*dns.KEY), 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register alice: %v", err)
	}
	phone := fcfsTestKey(t, "phone.alice.dev.zenr.io.")

	res := h.Handle(context.Background(), stubResponseWriter{}, buildFCFSUpdate(t, alice, []*dns.KEY{phone.PublicKey}, nil, 0, 120))
	if res.Status != StatusProcessed || res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}
	sent := stub.sentSnapshot()
	if len(sent) != 1 {
		t.Fatalf("expected one UPDATE upstream, got %d", len(sent))
	}
	if got := keyPrereqNames(sent[0]); len(got) != 1 || got[0] != "phone.alice.dev.zenr.io." {
		t.Fatalf("prerequisites = %v, want \"KEY RRset does not exist\" at phone.alice.dev.zenr.io. only", got)
	}
}

// A KEY appearing between the check and the UPDATE fails the prerequisite: the request is
// answered as a conflict, not as an upstream failure.
func TestFCFSNaming_PrerequisiteFailed_YXDOMAIN(t *testing.T) {
	h, _ := fcfsTestHandler(t, true, nil, dns.RcodeYXRrset)
	alice := fcfsTestKey(t, "alice.dev.zenr.io.")

	res := h.Handle(context.Background(), stubResponseWriter{}, selfRegistration(t, alice))
	wantErrorReply(t, res, dns.RcodeYXDomain, dns.ExtendedErrorProhibited, "name held by a different key")
}

// Without fcfs_naming a new key registers itself below another key's name, two labels below
// the zone, as before, and the UPDATE carries no prerequisite.
func TestFCFSNaming_Off(t *testing.T) {
	bob := fcfsTestKey(t, "alice.dev.zenr.io.")
	h, stub := fcfsTestHandler(t, false, map[string][]*dns.KEY{"alice.dev.zenr.io.": {bob.PublicKey}}, dns.RcodeSuccess)
	stranger := fcfsTestKey(t, "_acme-challenge.alice.dev.zenr.io.")

	res := h.Handle(context.Background(), stubResponseWriter{}, selfRegistration(t, stranger))
	if res.Status != StatusProcessed || res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}
	sent := stub.sentSnapshot()
	if len(sent) != 1 || len(sent[0].Answer) != 0 {
		t.Fatalf("expected one UPDATE without prerequisites, got %v", sent)
	}
}
