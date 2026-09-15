package updatecore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

func testLogger() *logging.Logger { return logging.NewLogger("error") }

func deleteAllForTest(name string) *dns.ANY {
	return &dns.ANY{Hdr: dns.Header{Name: name, Class: dns.ClassANY, TTL: 0}}
}

func testSigningKey(t *testing.T, name string) *keyrec.LoadedKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	keyRR := &dns.KEY{}
	keyRR.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600}
	keyRR.Protocol = 3
	keyRR.Algorithm = dns.ECDSAP256SHA256
	keyRR.PublicKey = base64.StdEncoding.EncodeToString(pubBytes[1:])
	return &keyrec.LoadedKey{Name: name, PublicKey: keyRR, PrivateKey: priv}
}

func TestBuildAndSign_ProducesVerifiableMessage(t *testing.T) {
	signingKey := testSigningKey(t, "proxy.dev.zenr.io.")
	del := deleteAllForTest("myhost.dev.zenr.io.")
	add, err := dns.New("myhost.dev.zenr.io. 3600 IN A 192.0.2.1")
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}

	msg, err := BuildAndSign("dev.zenr.io.", []dns.RR{del, add}, signingKey)
	if err != nil {
		t.Fatalf("BuildAndSign: %v", err)
	}
	if len(msg.Ns) != 2 {
		t.Fatalf("expected 2 records in the Update section, got %d", len(msg.Ns))
	}
	if msg.Question[0].Header().Name != "dev.zenr.io." {
		t.Fatalf("unexpected zone in question section: %s", msg.Question[0].Header().Name)
	}

	if err := msg.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	recv := &dns.Msg{Data: msg.Data}
	if err := recv.Unpack(); err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	// Verify with pkg/sig0 directly -- BuildAndSign's whole point is producing something
	// the authoritative server (or, here, our own verifier) can check.
	if err := sig0.VerifySignature(recv, signingKey.PublicKey); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestBuildAndSign_NilSigningKey(t *testing.T) {
	if _, err := BuildAndSign("dev.zenr.io.", nil, nil); err == nil {
		t.Fatal("expected an error for a nil signing key")
	}
}

func TestAsDelete_RewritesClassAndTTL(t *testing.T) {
	add, err := dns.New("myhost.dev.zenr.io. 3600 IN A 192.0.2.1")
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	del := AsDelete(add)
	hdr := del.Header()
	if hdr.Class != dns.ClassNONE || hdr.TTL != 0 {
		t.Fatalf("expected class NONE ttl 0, got class=%v ttl=%d", hdr.Class, hdr.TTL)
	}
	// RDATA (and NAME/TYPE) unchanged -- same identity, just a different instruction.
	if del.String() == add.String() {
		t.Fatal("expected the presentation form to differ (class/ttl), but it didn't change at all")
	}
	if origHdr := add.Header(); origHdr.Class != dns.ClassINET {
		t.Fatal("AsDelete must not mutate its input")
	}
}

func TestStaticUpstream_SkipsResolution(t *testing.T) {
	c := NewCoordinator(testLogger(), nil, map[string]string{"srp.dev.zenr.io.": "127.0.0.1:5300"})

	server, effectiveZone, err := c.ResolveSOAMasterServer(context.Background(), "srp.dev.zenr.io.")
	if err != nil {
		t.Fatalf("ResolveSOAMasterServer: %v", err)
	}
	if server != "127.0.0.1:5300" {
		t.Fatalf("expected the static override address, got %q", server)
	}
	if effectiveZone != "srp.dev.zenr.io." {
		t.Fatalf("expected the effective zone to be the zone itself, got %q", effectiveZone)
	}

	zone, err := c.ResolveAuthoritativeZone(context.Background(), "srp.dev.zenr.io.")
	if err != nil {
		t.Fatalf("ResolveAuthoritativeZone: %v", err)
	}
	if zone != "srp.dev.zenr.io." {
		t.Fatalf("expected the zone itself with no NS lookup, got %q", zone)
	}
}

func TestStaticUpstream_UnconfiguredZoneNoOverride(t *testing.T) {
	// A zone with no override entry must fall through to real resolution, not silently
	// match some other configured override -- confirmed here by using an unreachable
	// bootstrap resolver and an unrelated static-upstream zone, expecting a real failure
	// rather than a bogus "success" from the override map.
	c := NewCoordinator(testLogger(), []string{"127.0.0.1:1"}, map[string]string{"other.example.": "127.0.0.1:5300"})
	if _, _, err := c.ResolveSOAMasterServer(context.Background(), "srp.dev.zenr.io."); err == nil {
		t.Fatal("expected resolution to fail for a zone with no static override and no reachable bootstrap resolver")
	}
}
