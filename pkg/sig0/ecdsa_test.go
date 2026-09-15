package sig0

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"codeberg.org/miekg/dns"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat" // registers EDNS0 code 2 (UPDATE-LEASE) so Unpack succeeds; see that package's init()
)

// TestECDSAP256RoundTrip covers D7 (RFC 9665 requires ECDSAP256SHA256 support): generate
// a fresh P-256 key, build a KEY RR the way keyrec/dnsKey.NewPrivate would (RFC 6605 S4:
// raw X||Y, no leading 0x04, flags-0 per RFC 9665 S3.2.5.1), sign a message, round-trip it
// through Pack/Unpack (the realistic wire path -- see server.fullUnpackHandler), and
// verify. This is the "sign+verify round-trip test" S8 calls for.
func TestECDSAP256RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y) // 0x04 || X || Y, 65 bytes

	keyRR := &dns.KEY{}
	keyRR.Hdr = dns.Header{Name: "signer.test.example.", Class: dns.ClassINET, TTL: 3600}
	keyRR.Flags = 0
	keyRR.Protocol = 3
	keyRR.Algorithm = dns.ECDSAP256SHA256
	keyRR.PublicKey = base64.StdEncoding.EncodeToString(pubBytes[1:]) // strip the 0x04 prefix

	msg := dns.NewMsg("test.example.", dns.TypeSOA)
	msg.Opcode = dns.OpcodeUpdate
	addRR, err := dns.New("host.test.example. 3600 IN A 192.0.2.77")
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	msg.Ns = append(msg.Ns, keyRR, addRR)
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	signed, err := SignMessage(msg, keyRR, priv)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if err := signed.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	recv := &dns.Msg{Data: signed.Data}
	if err := recv.Unpack(); err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	if err := VerifySignature(recv, keyRR); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

// TestECDSAP384RoundTrip covers the other algorithm the D7-B generalization fixed
// alongside ECDSAP256SHA256 (same bug, same rdataOnlyPrefix fix, different curve/hash) --
// unlike alg 13, nothing in this codebase actually uses alg 14 today, so this is here
// purely to validate the shared code path rather than to satisfy a protocol requirement.
func TestECDSAP384RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes := elliptic.Marshal(elliptic.P384(), priv.PublicKey.X, priv.PublicKey.Y)

	keyRR := &dns.KEY{}
	keyRR.Hdr = dns.Header{Name: "signer384.test.example.", Class: dns.ClassINET, TTL: 3600}
	keyRR.Protocol = 3
	keyRR.Algorithm = dns.ECDSAP384SHA384
	keyRR.PublicKey = base64.StdEncoding.EncodeToString(pubBytes[1:])

	msg := dns.NewMsg("test.example.", dns.TypeSOA)
	msg.Opcode = dns.OpcodeUpdate
	addRR, err := dns.New("host384.test.example. 3600 IN A 192.0.2.78")
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	msg.Ns = append(msg.Ns, keyRR, addRR)
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	signed, err := SignMessage(msg, keyRR, priv)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if err := signed.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	recv := &dns.Msg{Data: signed.Data}
	if err := recv.Unpack(); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if err := VerifySignature(recv, keyRR); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

// TestECDSAP256TamperedMessageRejected confirms a corrupted message is rejected, not just
// that a valid one is accepted -- otherwise a Verify that always returns nil would pass
// TestECDSAP256RoundTrip too.
func TestECDSAP256TamperedMessageRejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)

	keyRR := &dns.KEY{}
	keyRR.Hdr = dns.Header{Name: "signer.test.example.", Class: dns.ClassINET, TTL: 3600}
	keyRR.Protocol = 3
	keyRR.Algorithm = dns.ECDSAP256SHA256
	keyRR.PublicKey = base64.StdEncoding.EncodeToString(pubBytes[1:])

	msg := dns.NewMsg("test.example.", dns.TypeSOA)
	msg.Opcode = dns.OpcodeUpdate
	addRR, _ := dns.New("host.test.example. 3600 IN A 192.0.2.77")
	msg.Ns = append(msg.Ns, keyRR, addRR)
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, opt)

	signed, err := SignMessage(msg, keyRR, priv)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if err := signed.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	wire := append([]byte{}, signed.Data...)
	// Flip a bit in the middle of the Ns section (the A record's address octet), well
	// clear of the header and question.
	wire[len(wire)/2] ^= 0xFF

	recv := &dns.Msg{Data: wire}
	if err := recv.Unpack(); err != nil {
		// A flipped bit can also land somewhere that makes Unpack itself fail
		// (e.g. a corrupted length byte) -- either outcome is an acceptable
		// rejection of the tampered message for this test's purpose.
		return
	}
	if err := VerifySignature(recv, keyRR); err == nil {
		t.Fatalf("VerifySignature unexpectedly succeeded on a tampered message")
	}
}

// TestECDSAP256KnownAnswerFromMDNSResponder is a known-answer test (S8) pinning the RFC
// 2931 S3 hashing fix (see this package's doc comment) against a REAL SIG(0) update
// captured from mDNSResponder's srp-client (an independent implementation) during Phase 0
// of the RFC 9665 plan -- not a synthetic message. Before the fix, this failed with "dns:
// bad signature" because dns.CryptoSIG0.Verify hashes the SIG RR's full wire encoding
// instead of RDATA-only. If this regresses, real-world SRP interop (and any other
// non-ED25519 SIG(0) interop) is broken again.
func TestECDSAP256KnownAnswerFromMDNSResponder(t *testing.T) {
	const capturedHex = "f704280000010000000700020764656661756c74077365727669636504617270610000060001097370696b6574657374c00c00ff00ff000000000000c0260001000100000e100004ac110003c0260019000100000e1000440201030d92dafbafc4b54cd32d0e325d0b89b8edb415cc84a74acece9374f12a4c4ade2f6bd189dc5230a6e91e38827e8a6937c63111bfef5ff44883ae1bd7162baf80ad055f69707073045f746370c00c000c000100000e1000100d5370696b65496e7374616e6365c09cc0b300ff00ff000000000000c0b30021000100000e1000080000000022b8c026c0b30010000100000e1000020130000029058200008000000c000200080000006400093a8000001800ff00000000005400000d00000000006aa3e4286aa3e1d08b87c026a17cbcff761a5ee8f9c47b367ffc6874b3cb0c5405bd670aa047bb108e007a5b4cac816479b61238124a2b551e7a3351b11b607d973edb980910c0d77d208790"

	wire, err := hex.DecodeString(capturedHex)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}

	msg := &dns.Msg{Data: wire}
	if err := msg.Unpack(); err != nil {
		t.Fatalf("Unpack: %v (is pkg/dnscompat imported?)", err)
	}

	var keyRR *dns.KEY
	for _, rr := range msg.Ns {
		if k, ok := rr.(*dns.KEY); ok {
			keyRR = k
			break
		}
	}
	if keyRR == nil {
		t.Fatalf("no KEY RR found in captured message")
	}
	if keyRR.Algorithm != dns.ECDSAP256SHA256 {
		t.Fatalf("expected algorithm %d (ECDSAP256SHA256), got %d", dns.ECDSAP256SHA256, keyRR.Algorithm)
	}
	const wantKeyTag = 35719
	if kt := keyRR.KeyTag(); kt != wantKeyTag {
		t.Fatalf("expected keytag %d, got %d", wantKeyTag, kt)
	}

	if err := VerifySignature(msg, keyRR); err != nil {
		t.Fatalf("VerifySignature on real mDNSResponder srp-client capture: %v", err)
	}
}

// TestECDSAP256KnownAnswerFromOpenThread is the same known-answer cross-check as
// TestECDSAP256KnownAnswerFromMDNSResponder, this time against OpenThread's SRP client
// (src/core/net/srp_client.cpp) -- the RFC's credited second independent implementation.
// Captured via a temporary one-line debug dump added right before the client's
// mSocket.SendTo call, running OpenThread's own tests/nexus/test_srp_client_change_lease
// fixture (a real two-node client/server exchange inside OpenThread's in-process "nexus"
// simulation platform). Confirms this package's ECDSA P-256 SIG(0) verifier accepts a real
// signature from a second, wholly independent implementation, not just mDNSResponder's.
func TestECDSAP256KnownAnswerFromOpenThread(t *testing.T) {
	const capturedHex = "b6bf280000010000000700020764656661756c74077365727669636504617270610000060001055f69707073045f746370c00c000c000100001c20000d0a6d792d73657276696365c026c03d00ff00ff000000000000c03d0021000100001c200010000000003039076d792d686f7374c00cc03d0010000100001c20000100c06800ff00ff000000000000c068001c000100001c20001020010000000000000000000000000001c0680019000100001c2000440201030d0a83eb639a9055831b24b95e0e9f3a75abef87435e4d0102d5ee6e0cf75c22b07b49ef4afc8c002d525ff6e6c2f821168f9f104fb0901d0460d841c193e9a64400002904f800008000000c0002000800001c200012750000001800ff00000000005400000d000000000000000000000000000000c0684718756d19593986e8b8dcaee2f42083a2b672ace558294668fe15dcc48d8c989505a119e731bb1bf7ca6d59a74ff18d4ab88b45bd9dd5818ea88ea7b0afad85"

	wire, err := hex.DecodeString(capturedHex)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}

	msg := &dns.Msg{Data: wire}
	if err := msg.Unpack(); err != nil {
		t.Fatalf("Unpack: %v (is pkg/dnscompat imported?)", err)
	}

	var keyRR *dns.KEY
	for _, rr := range msg.Ns {
		if k, ok := rr.(*dns.KEY); ok {
			keyRR = k
			break
		}
	}
	if keyRR == nil {
		t.Fatalf("no KEY RR found in captured message")
	}
	if keyRR.Algorithm != dns.ECDSAP256SHA256 {
		t.Fatalf("expected algorithm %d (ECDSAP256SHA256), got %d", dns.ECDSAP256SHA256, keyRR.Algorithm)
	}
	const wantKeyTag = 55321
	if kt := keyRR.KeyTag(); kt != wantKeyTag {
		t.Fatalf("expected keytag %d, got %d", wantKeyTag, kt)
	}

	if err := VerifySignature(msg, keyRR); err != nil {
		t.Fatalf("VerifySignature on real OpenThread srp-client capture: %v", err)
	}
}
