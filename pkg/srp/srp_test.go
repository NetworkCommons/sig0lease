package srp

import (
	"encoding/hex"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat" // registers EDNS0 code 2 (UPDATE-LEASE); needed by the real-capture test's Unpack
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// --- small RR builders -------------------------------------------------------------
//
// dns.KEY embeds dns.DNSKEY which embeds rdata.DNSKEY, so its fields are set by
// assignment rather than a nested struct literal (see pkg/sig0/ecdsa_test.go, which hits
// the same fork quirk). deleteAll builds a raw RFC 2136 S2.5.3 "Delete All RRsets From A
// Name" -- a *dns.ANY with class ANY -- which this fork's presentation-format parser
// cannot produce, so it's built directly.

func mustRR(t *testing.T, spec string) dns.RR {
	t.Helper()
	rr, err := dns.New(spec)
	if err != nil {
		t.Fatalf("dns.New(%q): %v", spec, err)
	}
	return rr
}

func deleteAll(name string) *dns.ANY {
	return &dns.ANY{Hdr: dns.Header{Name: name, Class: dns.ClassANY, TTL: 0}}
}

func keyRR(name string, algorithm uint8, flags uint16, publicKeyB64 string) *dns.KEY {
	k := &dns.KEY{}
	k.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600}
	k.Flags = flags
	k.Protocol = 3
	k.Algorithm = algorithm
	k.PublicKey = publicKeyB64
	return k
}

func ptrDelete(name, target string) *dns.PTR {
	p := &dns.PTR{}
	p.Hdr = dns.Header{Name: name, Class: dns.ClassNONE, TTL: 0}
	p.Ptr = target
	return p
}

// leaseOpt appends a valid Update-Lease option (8-byte variant) to msg.
func leaseOpt(t *testing.T, msg *dns.Msg, lease, keyLease uint32) {
	t.Helper()
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(4096)
	lo := leasepkg.Encode8Byte(lease, keyLease)
	if err := lo.Encode(opt); err != nil {
		t.Fatalf("lo.Encode: %v", err)
	}
	msg.Extra = append(msg.Extra, opt)
}

// rawLeaseOpt appends an Update-Lease option built directly from raw LEASE/KEY-LEASE
// values, bypassing leasepkg.LeaseOption.Encode's own LEASE<=KEY-LEASE guard -- for
// exercising Validate()'s rejection of a value combination our own encoder would never
// let a well-behaved caller produce, but a real wire message (malicious or just buggy)
// could still arrive with.
func rawLeaseOpt(msg *dns.Msg, lease, keyLease uint32) {
	buf := make([]byte, 8)
	buf[0], buf[1], buf[2], buf[3] = byte(lease>>24), byte(lease>>16), byte(lease>>8), byte(lease)
	buf[4], buf[5], buf[6], buf[7] = byte(keyLease>>24), byte(keyLease>>16), byte(keyLease>>8), byte(keyLease)
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(4096)
	opt.Options = append(opt.Options, &dns.ERFC3597{EDNS0Code: leasepkg.OPTION_CODE, Code: hex.EncodeToString(buf)})
	msg.Extra = append(msg.Extra, opt)
}

// newUpdate builds a bare SRP-shaped dns.Msg (opcode UPDATE, one question, empty
// Answer/Prerequisite) with rrs as the Update section, ready for Classify/Validate.
func newUpdate(zone string, rrs ...dns.RR) *dns.Msg {
	msg := dns.NewMsg(zone, dns.TypeSOA)
	msg.Opcode = dns.OpcodeUpdate
	msg.Ns = append(msg.Ns, rrs...)
	return msg
}

// --- RFC 9665 Appendix C ("Figure 2: Example Zone File") ---------------------------
//
// Not literally an UPDATE message (it's the resulting zone file), but it's the RFC's own
// worked example, complete with a real ECDSAP256SHA256 public key and its stated key ID
// (14495) -- reconstructed here as the UPDATE that would produce it, both as a positive
// classification fixture and as a correctness check on this package's own KeyTag
// computation (via dns.KEY.KeyTag(), not reimplemented here).
const appendixCPublicKey = "qweEmaaq0FAWok5//ftuQtZgiZoiFSUsm0srWREdywQU9dpvtOhrdKWUuPT3uEFF5TZU6B4q1z1I662GdaUwqg=="

func appendixCUpdate(t *testing.T) *dns.Msg {
	t.Helper()
	key := keyRR("demohost.default.service.arpa.", dns.ECDSAP256SHA256, 0, appendixCPublicKey)
	if got, want := key.KeyTag(), uint16(14495); got != want {
		t.Fatalf("Appendix C fixture key tag = %d, RFC states %d -- fixture is wrong, not the code under test", got, want)
	}

	msg := newUpdate("default.service.arpa.",
		// Host Description
		deleteAll("demohost.default.service.arpa."),
		mustRR(t, "demohost.default.service.arpa. 3600 IN AAAA 2001:db8:0:2::2"),
		key,
		// Service Description
		deleteAll("demo._ipps._tcp.default.service.arpa."),
		mustRR(t, "demo._ipps._tcp.default.service.arpa. 3600 IN SRV 0 0 631 demohost.default.service.arpa."),
		mustRR(t, `demo._ipps._tcp.default.service.arpa. 3600 IN TXT ""`),
		// Service Discovery
		mustRR(t, "_ipps._tcp.default.service.arpa. 3600 IN PTR demo._ipps._tcp.default.service.arpa."),
	)
	leaseOpt(t, msg, 7200, 1209600)
	return msg
}

func TestClassify_RFC9665AppendixCExample(t *testing.T) {
	cu, err := Classify(appendixCUpdate(t))
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if cu.Host == nil || cu.Host.Name != "demohost.default.service.arpa." {
		t.Fatalf("unexpected host: %+v", cu.Host)
	}
	if len(cu.Host.Addresses) != 1 {
		t.Fatalf("expected 1 host address, got %d", len(cu.Host.Addresses))
	}
	if len(cu.Instances) != 1 || cu.Instances[0].Name != "demo._ipps._tcp.default.service.arpa." {
		t.Fatalf("unexpected instances: %+v", cu.Instances)
	}
	if cu.Instances[0].SRV == nil || len(cu.Instances[0].TXT) != 1 {
		t.Fatalf("unexpected instance shape: %+v", cu.Instances[0])
	}
	if len(cu.Discovery) != 1 || cu.Discovery[0].Target != "demo._ipps._tcp.default.service.arpa." {
		t.Fatalf("unexpected discovery: %+v", cu.Discovery)
	}
}

func TestValidate_RFC9665AppendixCExample(t *testing.T) {
	if _, err := Validate(appendixCUpdate(t)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// --- real mDNSResponder srp-client capture -----------
//
// Captured live from the mDNSResponder srp-client reference binary -- the same fixture
// pkg/sig0/ecdsa_test.go's known-answer test uses.
// Confirms this package's classifier accepts a real independent implementation's message
// shape, not just synthetic fixtures built to match this package's own assumptions.
const capturedSRPClientHex = "f704280000010000000700020764656661756c74077365727669636504617270610000060001097370696b6574657374c00c00ff00ff000000000000c0260001000100000e100004ac110003c0260019000100000e1000440201030d92dafbafc4b54cd32d0e325d0b89b8edb415cc84a74acece9374f12a4c4ade2f6bd189dc5230a6e91e38827e8a6937c63111bfef5ff44883ae1bd7162baf80ad055f69707073045f746370c00c000c000100000e1000100d5370696b65496e7374616e6365c09cc0b300ff00ff000000000000c0b30021000100000e1000080000000022b8c026c0b30010000100000e1000020130000029058200008000000c000200080000006400093a8000001800ff00000000005400000d00000000006aa3e4286aa3e1d08b87c026a17cbcff761a5ee8f9c47b367ffc6874b3cb0c5405bd670aa047bb108e007a5b4cac816479b61238124a2b551e7a3351b11b607d973edb980910c0d77d208790"

func capturedSRPClientMessage(t *testing.T) *dns.Msg {
	t.Helper()
	wire, err := hex.DecodeString(capturedSRPClientHex)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	msg := &dns.Msg{Data: wire}
	if err := msg.Unpack(); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	return msg
}

func TestValidate_RealMDNSResponderCapture(t *testing.T) {
	cu, err := Validate(capturedSRPClientMessage(t))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cu.Host.Name != "spiketest.default.service.arpa." {
		t.Fatalf("unexpected host: %s", cu.Host.Name)
	}
	if len(cu.Instances) != 1 || cu.Instances[0].Name != "spikeinstance._ipps._tcp.default.service.arpa." {
		t.Fatalf("unexpected instances: %+v", cu.Instances)
	}
}

// --- real OpenThread srp-client capture (post-Phase-5 follow-up) --------------------
//
// Captured live from OpenThread's own SRP client (`src/core/net/srp_client.cpp`), the
// RFC's credited second independent implementation, via a temporary one-line debug dump
// added right before the client's `mSocket.SendTo` call in a local checkout, running the
// project's own `tests/nexus/test_srp_client_change_lease` fixture (a real two-node
// client/server exchange inside OpenThread's in-process "nexus" simulation platform --
// see openthread/tests/nexus/build.sh). The dump was removed afterward; only these wire
// bytes were kept. Same purpose as the mDNSResponder capture above: confirms this
// package's classifier accepts a second, wholly independent real-world message shape --
// including this implementation independently choosing the same flags=513 KEY convention
// mDNSResponder uses -- not just synthetic fixtures built to match this package's own
// assumptions. The matching SIG(0) cryptographic cross-check lives in
// pkg/sig0/ecdsa_test.go's TestECDSAP256KnownAnswerFromOpenThread.
const capturedOpenThreadHex = "b6bf280000010000000700020764656661756c74077365727669636504617270610000060001055f69707073045f746370c00c000c000100001c20000d0a6d792d73657276696365c026c03d00ff00ff000000000000c03d0021000100001c200010000000003039076d792d686f7374c00cc03d0010000100001c20000100c06800ff00ff000000000000c068001c000100001c20001020010000000000000000000000000001c0680019000100001c2000440201030d0a83eb639a9055831b24b95e0e9f3a75abef87435e4d0102d5ee6e0cf75c22b07b49ef4afc8c002d525ff6e6c2f821168f9f104fb0901d0460d841c193e9a64400002904f800008000000c0002000800001c200012750000001800ff00000000005400000d000000000000000000000000000000c0684718756d19593986e8b8dcaee2f42083a2b672ace558294668fe15dcc48d8c989505a119e731bb1bf7ca6d59a74ff18d4ab88b45bd9dd5818ea88ea7b0afad85"

func capturedOpenThreadMessage(t *testing.T) *dns.Msg {
	t.Helper()
	wire, err := hex.DecodeString(capturedOpenThreadHex)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	msg := &dns.Msg{Data: wire}
	if err := msg.Unpack(); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	return msg
}

func TestValidate_RealOpenThreadCapture(t *testing.T) {
	cu, err := Validate(capturedOpenThreadMessage(t))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cu.Host.Name != "my-host.default.service.arpa." {
		t.Fatalf("unexpected host: %s", cu.Host.Name)
	}
	if len(cu.Instances) != 1 || cu.Instances[0].Name != "my-service._ipps._tcp.default.service.arpa." {
		t.Fatalf("unexpected instances: %+v", cu.Instances)
	}
	if cu.Instances[0].SRV == nil || cu.Instances[0].SRV.SRV.Port != 12345 {
		t.Fatalf("unexpected SRV: %+v", cu.Instances[0].SRV)
	}
}

// --- near-miss table: each row violates exactly one RFC 9665 S3.3.1/S3.3.2 clause -----

func TestClassify_Rejections(t *testing.T) {
	const zone = "example.com."
	const host = "myhost.example.com."
	const inst = "printer._ipps._tcp.example.com."
	const svctype = "_ipps._tcp.example.com."
	const pub = "AAAAB3NzaC1yc2EAAAADAQABAAAB" // arbitrary well-formed base64; classification doesn't validate key material itself

	validHost := func() []dns.RR {
		return []dns.RR{
			deleteAll(host),
			mustRR(t, host+" 3600 IN A 192.0.2.1"),
			keyRR(host, 13, 0, pub),
		}
	}
	validInstance := func() []dns.RR {
		return []dns.RR{
			deleteAll(inst),
			mustRR(t, inst+" 3600 IN SRV 0 0 631 "+host),
			mustRR(t, inst+` 3600 IN TXT "a"`),
		}
	}
	validDiscovery := func() []dns.RR {
		return []dns.RR{mustRR(t, svctype+" 3600 IN PTR "+inst)}
	}

	cases := []struct {
		name    string
		rrs     []dns.RR
		wantErr string // substring expected in the error; empty means "just must error"
	}{
		{
			name: "no host description at all",
			rrs:  append(validInstance(), validDiscovery()...),
		},
		{
			name: "two hostnames",
			rrs: append(append(validHost(),
				deleteAll("otherhost.example.com."),
				mustRR(t, "otherhost.example.com. 3600 IN A 192.0.2.2"),
			), append(validInstance(), validDiscovery()...)...),
			wantErr: "more than one hostname",
		},
		{
			name: "SRV target does not match host",
			rrs: append(validHost(), append([]dns.RR{
				deleteAll(inst),
				mustRR(t, inst+" 3600 IN SRV 0 0 631 wronghost.example.com."),
				mustRR(t, inst+` 3600 IN TXT "a"`),
			}, validDiscovery()...)...),
			wantErr: "SRV target",
		},
		{
			name: "SRV present but no TXT",
			rrs: append(validHost(), append([]dns.RR{
				deleteAll(inst),
				mustRR(t, inst+" 3600 IN SRV 0 0 631 "+host),
			}, validDiscovery()...)...),
			wantErr: "no TXT add",
		},
		{
			name:    "PTR add targets an instance with no Service Description",
			rrs:     append(validHost(), validDiscovery()...),
			wantErr: "no Service Description",
		},
		{
			name:    "instance not referenced by any Service Discovery add",
			rrs:     append(validHost(), validInstance()...),
			wantErr: "not referenced by any Service Discovery",
		},
		{
			// A/AAAA always route to host-address handling regardless of which name
			// they're at (see addHostAddress), so an A record showing up at a name
			// that's already an established service instance surfaces as a second,
			// conflicting hostname claim -- a correct rejection, just via that specific
			// diagnostic rather than a "Service Description may not add A records" one.
			name: "A record at a Service Description name",
			rrs: append(validHost(), append(append(validInstance(),
				mustRR(t, inst+" 3600 IN A 192.0.2.9"),
			), validDiscovery()...)...),
			wantErr: "more than one hostname",
		},
		{
			name: "subtype PTR add with no preceding base-type add",
			rrs: append(append(validHost(), validInstance()...),
				mustRR(t, "_print._sub._ipps._tcp.example.com. 3600 IN PTR "+inst),
			),
			wantErr: "no preceding base-type PTR add",
		},
		{
			name:    "duplicate Delete All RRsets for the same name",
			rrs:     append(validHost(), deleteAll(host)),
			wantErr: "more than one Delete All RRsets",
		},
		{
			name:    "unrecognized RR type in Update section",
			rrs:     append(validHost(), mustRR(t, host+` 3600 IN CNAME other.example.com.`)),
			wantErr: "unrecognized RR type",
		},
		{
			name:    "KEY add for a name that is neither host nor instance",
			rrs:     append(validHost(), keyRR("nobody.example.com.", 13, 0, pub)),
			wantErr: "neither the Host Description name nor a service instance name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Classify(newUpdate(zone, tc.rrs...))
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestClassify_MultipleTXTAdds confirms the deliberate divergence from srp-parse.c (which
// rejects a second TXT add outright): RFC 9665's own S3.1 table allows 1..n TXT adds.
func TestClassify_MultipleTXTAdds(t *testing.T) {
	const host = "myhost.example.com."
	const inst = "printer._ipps._tcp.example.com."
	rrs := []dns.RR{
		deleteAll(host), mustRR(t, host+" 3600 IN A 192.0.2.1"), keyRR(host, 13, 0, "AAAA"),
		deleteAll(inst),
		mustRR(t, inst+" 3600 IN SRV 0 0 631 "+host),
		mustRR(t, inst+` 3600 IN TXT "a"`),
		mustRR(t, inst+` 3600 IN TXT "b"`),
		mustRR(t, "_ipps._tcp.example.com. 3600 IN PTR "+inst),
	}
	cu, err := Classify(newUpdate("example.com.", rrs...))
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(cu.Instances[0].TXT) != 2 {
		t.Fatalf("expected 2 TXT records, got %d", len(cu.Instances[0].TXT))
	}
}

// TestClassify_RemovalShapedServiceInstance confirms S3.3.1.1's second bullet: a bare
// Delete-All-RRsets (no SRV/TXT, no A/AAAA) that isn't claimed as the host is accepted as
// a removal-shaped instance, matching srp-parse.c's "presumed removes" handling -- neither
// package tries to confirm it against a store here (that's pkg/srp/fcfs.go's job).
func TestClassify_RemovalShapedServiceInstance(t *testing.T) {
	const host = "myhost.example.com."
	const inst = "printer._ipps._tcp.example.com."
	rrs := []dns.RR{
		deleteAll(host), mustRR(t, host+" 3600 IN A 192.0.2.1"), keyRR(host, 13, 0, "AAAA"),
		deleteAll(inst), // bare: no SRV, no TXT -- a removal
		ptrDelete("_ipps._tcp.example.com.", inst),
	}
	cu, err := Classify(newUpdate("example.com.", rrs...))
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(cu.Instances) != 1 || cu.Instances[0].SRV != nil {
		t.Fatalf("expected 1 removal-shaped instance, got: %+v", cu.Instances)
	}
}

// TestClassify_BareHostRemoval confirms S3.3.1.3's "zero Add operations, in the case of
// deleting a registration": a bare Delete-All-RRsets + KEY, no A/AAAA, is accepted as the
// Host Description when nothing else claims it -- the host-removal fallback.
func TestClassify_BareHostRemoval(t *testing.T) {
	const host = "myhost.example.com."
	rrs := []dns.RR{
		deleteAll(host),
		keyRR(host, 13, 0, "AAAA"),
	}
	cu, err := Classify(newUpdate("example.com.", rrs...))
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if cu.Host == nil || cu.Host.Name != host || len(cu.Host.Addresses) != 0 {
		t.Fatalf("unexpected host: %+v", cu.Host)
	}
}

// --- Validate()-level checks (beyond Classify) --------------------------------------

func TestValidate_Rejections(t *testing.T) {
	build := func() *dns.Msg { return appendixCUpdate(t) }

	t.Run("no lease option", func(t *testing.T) {
		msg := dns.NewMsg("default.service.arpa.", dns.TypeSOA)
		msg.Opcode = dns.OpcodeUpdate
		full := build()
		msg.Ns = full.Ns
		// deliberately no leaseOpt() call
		if _, err := Validate(msg); err == nil || !strings.Contains(err.Error(), "Update-Lease") {
			t.Fatalf("expected an Update-Lease error, got: %v", err)
		}
	})

	t.Run("KEY-LEASE less than LEASE", func(t *testing.T) {
		msg := dns.NewMsg("default.service.arpa.", dns.TypeSOA)
		msg.Opcode = dns.OpcodeUpdate
		msg.Ns = build().Ns
		rawLeaseOpt(msg, 7200, 3600) // LEASE > KEY-LEASE: invalid; built raw since our own encoder refuses to
		if _, err := Validate(msg); err == nil {
			t.Fatalf("expected an error for LEASE > KEY-LEASE")
		}
	})

	t.Run("prerequisites present", func(t *testing.T) {
		msg := build()
		msg.Answer = append(msg.Answer, mustRR(t, "demohost.default.service.arpa. IN ANY"))
		if _, err := Validate(msg); err == nil || !strings.Contains(err.Error(), "prerequisite") {
			t.Fatalf("expected a prerequisite error, got: %v", err)
		}
	})

	t.Run("multiple zone section entries", func(t *testing.T) {
		msg := build()
		msg.Question = append(msg.Question, msg.Question[0])
		if _, err := Validate(msg); err == nil || !strings.Contains(err.Error(), "Zone Section") {
			t.Fatalf("expected a Zone Section error, got: %v", err)
		}
	})

	t.Run("TTL inconsistency", func(t *testing.T) {
		msg := build()
		// A second TXT add at the same service instance with a different TTL: TTL
		// consistency (S4) applies within one RRset (same name+type+class), which SRV
		// and TXT never share (they're different types) -- so the inconsistency has to
		// come from two RRs of the *same* type, e.g. two TXT adds.
		msg.Ns = append(msg.Ns, mustRR(t, `demo._ipps._tcp.default.service.arpa. 60 IN TXT "extra"`))
		if _, err := Validate(msg); err == nil || !strings.Contains(err.Error(), "inconsistent TTLs") {
			t.Fatalf("expected an inconsistent-TTLs error, got: %v", err)
		}
	})

	t.Run("TTL inconsistency across a shared PTR RRset", func(t *testing.T) {
		// Two different service instances of the same type share one PTR owner name
		// (the service type) -- a TTL mismatch between their own PTR adds must be
		// caught even though neither instance's SRV/TXT records share that owner name
		// with the other's, so the mismatch can't be seen from either instance alone.
		const host = "myhost.default.service.arpa."
		const inst1 = "printer._ipps._tcp.default.service.arpa."
		const inst2 = "scanner._ipps._tcp.default.service.arpa."
		const svcType = "_ipps._tcp.default.service.arpa."
		key := keyRR(host, dns.ECDSAP256SHA256, 0, appendixCPublicKey)

		ptr1 := &dns.PTR{}
		ptr1.Hdr = dns.Header{Name: svcType, Class: dns.ClassINET, TTL: 60}
		ptr1.Ptr = inst1

		ptr2 := &dns.PTR{}
		ptr2.Hdr = dns.Header{Name: svcType, Class: dns.ClassINET, TTL: 120} // different TTL
		ptr2.Ptr = inst2

		msg := newUpdate("default.service.arpa.",
			deleteAll(host), mustRR(t, host+" 3600 IN A 192.0.2.1"), key,
			deleteAll(inst1), mustRR(t, inst1+" 60 IN SRV 0 0 631 "+host), mustRR(t, inst1+` 60 IN TXT ""`), ptr1,
			deleteAll(inst2), mustRR(t, inst2+" 60 IN SRV 0 0 631 "+host), mustRR(t, inst2+` 60 IN TXT ""`), ptr2,
		)
		leaseOpt(t, msg, 60, 3600)
		if _, err := Validate(msg); err == nil || !strings.Contains(err.Error(), "inconsistent TTLs") {
			t.Fatalf("expected an inconsistent-TTLs error for the shared PTR RRset, got: %v", err)
		}
	})

	t.Run("mismatched KEY RDATA", func(t *testing.T) {
		msg := build()
		// The Appendix C fixture omits the Service Description's KEY (S3.2.5.1: "MAY be
		// omitted for brevity"), so there's only one KEY to begin with -- add a second,
		// explicit, deliberately-different one at the service instance to actually
		// exercise the cross-KEY comparison.
		msg.Ns = append(msg.Ns, keyRR("demo._ipps._tcp.default.service.arpa.", dns.ECDSAP256SHA256, 0, "differentkeymaterial"))
		if _, err := Validate(msg); err == nil || !strings.Contains(err.Error(), "MUST be identical") {
			t.Fatalf("expected a KEY-mismatch error, got: %v", err)
		}
	})
}
