package handlers

import (
	"context"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// updateWithLeaseData returns an UPDATE whose Update Lease option carries hexData as is, so a
// test can send lengths and values the encoder would not produce.
func updateWithLeaseData(hexData string) *dns.Msg {
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	msg.Opcode = dns.OpcodeUpdate
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	opt.Options = append(opt.Options, &dns.ERFC3597{EDNS0Code: leasepkg.OPTION_CODE, Code: hexData})
	msg.Extra = append(msg.Extra, opt)
	return msg
}

// TestDecodeLease_RcodeFitsTheHeader: every option decodeLease turns down gets an RCODE of the
// header's own four bits, FORMERR for an option RFC 9664 does not allow and REFUSED for a
// 4-byte one without prefer_4byte_variant. It once answered all of them with 16, an extended
// RCODE whose header bits are 0, so mDNSResponder took the refusal for NOERROR.
func TestDecodeLease_RcodeFitsTheHeader(t *testing.T) {
	keyLease600 := uint32(600)
	tests := []struct {
		name         string
		data         string
		prefer4Byte  bool
		wantRcode    uint16
		wantLease    uint32
		wantKeyLease *uint32 // nil: the 4-byte variant
	}{
		{"8-byte", "00000078" + "00000258", false, dns.RcodeSuccess, 120, &keyLease600},
		{"4-byte, prefer_4byte_variant off", "00001c20", false, dns.RcodeRefused, 0, nil},
		{"4-byte, prefer_4byte_variant on", "00001c20", true, dns.RcodeSuccess, 7200, nil},
		{"6 bytes", "000000780000", true, dns.RcodeFormatError, 0, nil},
		{"LEASE above KEY-LEASE", "00000258" + "00000078", false, dns.RcodeFormatError, 0, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler()
			h.prefer4ByteVariant = tt.prefer4Byte
			lo, rcode, err := h.decodeLease(updateWithLeaseData(tt.data))
			if rcode != tt.wantRcode {
				t.Fatalf("rcode = %s (err %v), want %s", dns.RcodeToString[rcode], err, dns.RcodeToString[tt.wantRcode])
			}
			if tt.wantRcode != dns.RcodeSuccess {
				if err == nil {
					t.Fatalf("rcode %s without an error", dns.RcodeToString[rcode])
				}
				return
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if lo.Lease != tt.wantLease || (lo.KeyLease == nil) != (tt.wantKeyLease == nil) ||
				(lo.KeyLease != nil && *lo.KeyLease != *tt.wantKeyLease) {
				t.Fatalf("option = %d/%v, want %d/%v", lo.Lease, lo.KeyLease, tt.wantLease, tt.wantKeyLease)
			}
		})
	}
}

// TestRequestedLeases_FourByteFollowsRecordKinds: the 8-byte variant's two values pass through;
// the 4-byte variant's one value goes to the KEYs and to the other records the Update section
// has (RFC 9664 S4), which selects Case A, B or D as the 8-byte variant would.
func TestRequestedLeases_FourByteFollowsRecordKinds(t *testing.T) {
	tests := []struct {
		name                 string
		lo                   *leasepkg.LeaseOption
		hasKeys, hasOthers   bool
		wantLease, wantKeyLe uint32
	}{
		{"8-byte", leasepkg.Encode8Byte(120, 600), true, true, 120, 600},
		{"4-byte, KEYs and other records: Case A", leasepkg.Encode4Byte(600), true, true, 600, 600},
		{"4-byte, other records only: Case B", leasepkg.Encode4Byte(600), false, true, 600, 0},
		{"4-byte, KEYs only: Case D", leasepkg.Encode4Byte(600), true, false, 0, 600},
		{"4-byte, no records: Case B, refused there", leasepkg.Encode4Byte(600), false, false, 600, 0},
		{"4-byte 0: Case C", leasepkg.Encode4Byte(0), true, true, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lease, keyLease := requestedLeases(tt.lo, tt.hasKeys, tt.hasOthers)
			if lease != tt.wantLease || keyLease != tt.wantKeyLe {
				t.Fatalf("LEASE/KEY-LEASE = %d/%d, want %d/%d", lease, keyLease, tt.wantLease, tt.wantKeyLe)
			}
		})
	}
}

// TestCheckLeaseMinimums: a duration below its lease_policy minimum is refused; 0, a delete,
// never is.
func TestCheckLeaseMinimums(t *testing.T) {
	h := newTestHandler()
	h.LeasePolicy = LeasePolicy{MinRRLease: 30, MinKeyLease: 60}
	tests := []struct {
		lease, keyLease uint32
		wantErr         bool
	}{
		{30, 60, false},
		{0, 0, false},
		{30, 0, false},
		{0, 60, false},
		{20, 60, true},
		{30, 50, true},
		{0, 50, true},
	}
	for _, tt := range tests {
		if err := h.checkLeaseMinimums(tt.lease, tt.keyLease); (err != nil) != tt.wantErr {
			t.Errorf("checkLeaseMinimums(%d, %d) = %v, want error %v", tt.lease, tt.keyLease, err, tt.wantErr)
		}
	}
}

// setupFourByteHandler is an UpdateHandler on dev.zenr.io. with the given prefer_4byte_variant,
// a lease_policy capping LEASE at 900 s and KEY-LEASE at 1800 s, and an authoritative server
// that accepts every UPDATE and, if signerKeyAtAuthoritative, has the signer's KEY. It returns
// the signer's key too.
func setupFourByteHandler(t *testing.T, prefer4Byte, signerKeyAtAuthoritative bool) (*UpdateHandler, *keyrec.LoadedKey) {
	t.Helper()
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{
		"upstream_zone":        "dev.zenr.io.",
		"keystore_dir":         keystoreDir,
		"prefer_4byte_variant": prefer4Byte,
		"lease_policy": map[string]any{
			"min_rr_lease_sec": 30, "max_rr_lease_sec": 900,
			"min_key_lease_sec": 30, "max_key_lease_sec": 1800,
		},
	}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	authoritative := func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType == dns.TypeKEY && signerKeyAtAuthoritative {
			return []dns.RR{loaded.PublicKey}, nil
		}
		return []dns.RR{}, nil
	}
	h.upstreamCoordinator = &stubUpstreamCoordinator{query: authoritative, resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}
	return h, loaded
}

// wireRcode is resp's RCODE as a requester reading only the header sees it: the header's four
// bits, without the extended bits the OPT RR may carry.
func wireRcode(t *testing.T, resp *dns.Msg) uint16 {
	t.Helper()
	if err := resp.Pack(); err != nil {
		t.Fatalf("pack response: %v", err)
	}
	return uint16(resp.Data[3] & 0x0F)
}

// TestHandle_FourByteVariant_KeysAndRecordsShareOneLease: with prefer_4byte_variant, a 4-byte
// request carrying a KEY and a TXT is Case A with one lease for both. The policy grants the TXT
// at most 900 s and would grant the KEY 1800 s, but RFC 9664 S4 has them expire together, so
// both get 900 s, and the reply says so in the 4-byte variant.
func TestHandle_FourByteVariant_KeysAndRecordsShareOneLease(t *testing.T) {
	h, signer := setupFourByteHandler(t, true, false)
	req := buildSignedLeaseUpdateForHandleTest(t, signer, "test.dev.zenr.io.", leasepkg.Encode4Byte(7200), true)

	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil || res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("result = %+v, want NOERROR", res)
	}
	granted, err := leasepkg.FindAndDecode(res.Message)
	if err != nil {
		t.Fatalf("reply carries no Update Lease option: %v", err)
	}
	if granted.KeyLease != nil || granted.Lease != 900 {
		t.Fatalf("granted %d/%v, want the 4-byte variant with 900", granted.Lease, granted.KeyLease)
	}
	keyLease := h.leaseManager.LookupByKEY(signer.PublicKey.Clone().(*dns.KEY))
	if keyLease == nil || keyLease.LeaseDuration != 900 || keyLease.KeyLeaseDuration != 900 {
		t.Fatalf("stored KEY lease = %+v, want 900 s", keyLease)
	}
	if txtLease := h.leaseManager.LookupNonKEYRecord(req.Ns[1]); txtLease == nil || txtLease.LeaseDuration != 900 {
		t.Fatalf("stored TXT lease = %+v, want 900 s", txtLease)
	}
}

// TestHandle_FourByteVariant_RecordsOnly: a 4-byte request with only non-KEY records, as
// mDNSResponder sends, is Case B under the signer's managed KEY, answered in the 4-byte variant.
func TestHandle_FourByteVariant_RecordsOnly(t *testing.T) {
	h, signer := setupFourByteHandler(t, true, true)
	if err := h.leaseManager.Register(signer.PublicKey.Clone().(*dns.KEY), 1800, 1800, "dev.zenr.io."); err != nil {
		t.Fatalf("register signer key: %v", err)
	}
	req := buildSignedLeaseUpdateForHandleTest(t, signer, "host.test.dev.zenr.io.", leasepkg.Encode4Byte(600), false)

	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil || res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("result = %+v, want NOERROR", res)
	}
	granted, err := leasepkg.FindAndDecode(res.Message)
	if err != nil || granted.KeyLease != nil || granted.Lease != 600 {
		t.Fatalf("granted %+v (%v), want the 4-byte variant with 600", granted, err)
	}
	if txtLease := h.leaseManager.LookupNonKEYRecord(req.Ns[0]); txtLease == nil || txtLease.LeaseDuration != 600 {
		t.Fatalf("stored TXT lease = %+v, want 600 s", txtLease)
	}
}

// TestHandle_FourByteVariant_RefusedInTheHeader: without prefer_4byte_variant a 4-byte request
// is REFUSED, in the header's own RCODE bits, before anything is sent upstream.
func TestHandle_FourByteVariant_RefusedInTheHeader(t *testing.T) {
	h, signer := setupFourByteHandler(t, false, false)
	req := buildSignedLeaseUpdateForHandleTest(t, signer, "test.dev.zenr.io.", leasepkg.Encode4Byte(7200), true)

	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil {
		t.Fatalf("expected a response")
	}
	if got := wireRcode(t, res.Message); got != dns.RcodeRefused || res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("header RCODE %s, full RCODE %d; want REFUSED in the header", dns.RcodeToString[got], res.Message.Rcode)
	}
	if sent := h.upstreamCoordinator.(*stubUpstreamCoordinator).sentCount(); sent != 0 {
		t.Fatalf("%d UPDATEs sent upstream, want none", sent)
	}
}

// TestSetup_FourByteVariantNeedsOneLeaseForKeysAndRecords: prefer_4byte_variant needs a
// lease_policy with a duration both KEYs and other records may have; one whose KEY minimum is
// above the LEASE maximum makes Setup fail rather than grant a KEY less than its minimum.
func TestSetup_FourByteVariantNeedsOneLeaseForKeysAndRecords(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	policy := map[string]any{"max_rr_lease_sec": 900, "min_key_lease_sec": 3600, "max_key_lease_sec": 7200}
	for _, prefer4Byte := range []bool{false, true} {
		h := NewUpdateHandler()
		h.SetLogger(newTestHandler().logger)
		err := h.Setup(map[string]any{
			"upstream_zone":        "dev.zenr.io.",
			"keystore_dir":         keystoreDir,
			"prefer_4byte_variant": prefer4Byte,
			"lease_policy":         policy,
		})
		if prefer4Byte && (err == nil || !strings.Contains(err.Error(), "prefer_4byte_variant")) {
			t.Fatalf("Setup with prefer_4byte_variant = %v, want it refused", err)
		}
		if !prefer4Byte && err != nil {
			t.Fatalf("Setup without prefer_4byte_variant: %v", err)
		}
	}
}
