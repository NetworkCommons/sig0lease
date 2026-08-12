package handlers

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/lease"
)

func TestParseLeaseRegistrationIncludesKeyLease(t *testing.T) {
	h := NewUpdateHandler()
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	l := lease.Encode8Byte(120, 600)
	if err := l.Encode(opt); err != nil {
		t.Fatalf("encode lease: %v", err)
	}
	msg.Extra = append(msg.Extra, opt)

	gotLease, gotKeyLease, err := h.parseLease(msg)
	if err != nil {
		t.Fatalf("parse lease: %v", err)
	}
	if gotLease != 120 || gotKeyLease != 600 {
		t.Fatalf("unexpected lease values lease=%d key-lease=%d", gotLease, gotKeyLease)
	}
}

func TestExtractUpdateRecordsAcceptsMultipleKeys(t *testing.T) {
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate
	msg.Ns = append(msg.Ns,
		testKeyRR("test.dev.zenr.io.", "AAAATESTKEY111="),
		testKeyRR("test.dev.zenr.io.", "AAAATESTKEY222="),
	)

	keyRRs, _, err := extractUpdateRecords(msg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keyRRs) != 2 {
		t.Fatalf("expected 2 KEY RRs, got %d", len(keyRRs))
	}
	if keyRRs[0].PublicKey[0] != 'A' || keyRRs[1].PublicKey[0] != 'A' {
		t.Fatalf("expected valid KEY RRs")
	}
}

func TestExtractUpdateRecordsAcceptsGenericRRTypes(t *testing.T) {
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate
	msg.Ns = append(msg.Ns,
		testKeyRR("test.dev.zenr.io.", "AAAATESTKEY111="),
		&dns.SRV{Hdr: dns.Header{Name: "_service._tcp.test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}, SRV: rdata.SRV{Target: "target.test.dev.zenr.io.", Port: 443, Priority: 10, Weight: 20}},
	)

	keyRR, other, err := extractUpdateRecords(msg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keyRR == nil {
		t.Fatalf("expected key rr")
	}
	if len(other) != 1 {
		t.Fatalf("expected one non-key rr, got %d", len(other))
	}
	if _, ok := other[0].(*dns.SRV); !ok {
		t.Fatalf("expected SRV rr, got %T", other[0])
	}
}

func TestConstructUpstreamUpdateIncludesDataOnlyRecordsOnce(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := newTestHandler()

	key1 := loaded.PublicKey.Clone().(*dns.KEY)
	key2 := loaded.PublicKey.Clone().(*dns.KEY)
	txt := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}}
	txt.TXT.Txt = []string{"payload"}

	msg, err := h.constructUpstreamUpdate([]*dns.KEY{key1, key2}, []dns.RR{txt}, loaded, "dev.zenr.io.")
	if err != nil {
		t.Fatalf("construct upstream update: %v", err)
	}
	if len(msg.Ns) != 3 {
		t.Fatalf("expected 3 upstream records (2 KEY + 1 TXT), got %d", len(msg.Ns))
	}
	txtCount := 0
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.TXT); ok {
			txtCount++
		}
	}
	if txtCount != 1 {
		t.Fatalf("expected TXT record to appear once, got %d", txtCount)
	}

	dataOnlyMsg, err := h.constructUpstreamUpdate(nil, []dns.RR{txt}, loaded, "dev.zenr.io.")
	if err != nil {
		t.Fatalf("construct upstream update for data-only request: %v", err)
	}
	if len(dataOnlyMsg.Ns) != 1 {
		t.Fatalf("expected 1 upstream record for data-only request, got %d", len(dataOnlyMsg.Ns))
	}
}

func TestClampLeaseDurationsAppliesBoundsAndKeepsOrder(t *testing.T) {
	h := NewUpdateHandler()
	h.LeasePolicy = LeasePolicy{
		MinKeyLease: 20,
		MaxKeyLease: 30,
		MinRRLease:  10,
		MaxRRLease:  20,
	}

	lease, keyLease := h.clampLeaseDurations(25, 100)
	if keyLease != 30 {
		t.Fatalf("expected key-lease clamped to 30, got %d", keyLease)
	}
	if lease != 20 {
		t.Fatalf("expected lease clamped to 20, got %d", lease)
	}

	h.LeasePolicy = LeasePolicy{
		MinKeyLease: 20,
		MaxKeyLease: 25,
		MinRRLease:  10,
		MaxRRLease:  30,
	}
	lease, keyLease = h.clampLeaseDurations(29, 29)
	if lease != 25 || keyLease != 25 {
		t.Fatalf("expected lease<=key-lease invariant after clamp, got lease=%d key-lease=%d", lease, keyLease)
	}
}

func TestClampLeaseDurationsPreservesZeroSemantics(t *testing.T) {
	h := NewUpdateHandler()
	h.LeasePolicy = LeasePolicy{
		MinKeyLease: 20,
		MaxKeyLease: 30,
		MinRRLease:  10,
		MaxRRLease:  20,
	}

	lease, keyLease := h.clampLeaseDurations(0, 0)
	if lease != 0 || keyLease != 0 {
		t.Fatalf("expected zero delete semantics preserved, got lease=%d key-lease=%d", lease, keyLease)
	}

	lease, keyLease = h.clampLeaseDurations(0, 99)
	if lease != 0 || keyLease != 30 {
		t.Fatalf("expected key-only lease semantics preserved with clamped key-lease, got lease=%d key-lease=%d", lease, keyLease)
	}
}

func TestDataLeaseExpiresBeforeKeyLease(t *testing.T) {
	h := NewUpdateHandler()
	ctx := context.Background()
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY444=")
	data := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	data.TXT.Txt = []string{"payload"}

	if err := h.leaseManager.Register(ctx, key, 2, 2, "dev.zenr.io."); err != nil {
		t.Fatalf("register key lease: %v", err)
	}
	h.setDataLease(lease.NodeKey(key), []dns.RR{data}, 1, "dev.zenr.io.")
	h.scheduleLeaseExpiry(lease.NodeKey(key))
	defer h.clearLeaseTimer(lease.NodeKey(key))

	time.Sleep(1300 * time.Millisecond)
	dataLease := h.getDataLease(lease.NodeKey(key))
	// Expired records are removed outright, not flagged in place.
	if dataLease != nil && len(dataLease.Records) != 0 {
		t.Fatalf("expected expired record to be removed, got %d remaining", len(dataLease.Records))
	}
	if got := h.leaseManager.LookupByKEY(key); got == nil {
		t.Fatalf("expected key lease still active after data lease expiry")
	}

	time.Sleep(1100 * time.Millisecond)
	if got := h.leaseManager.LookupByKEY(key); got != nil {
		t.Fatalf("expected key lease removed after key-lease expiry")
	}
}

func TestExtractUpdateRecordsWithNoKEYRR(t *testing.T) {
	// KEY RR is optional in UPDATE records; non-KEY records are still extracted.
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	// Only non-KEY RRs, no KEY RR.
	txt := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}}
	txt.TXT.Txt = []string{"payload"}
	msg.Ns = append(msg.Ns, txt)

	keyRR, other, err := extractUpdateRecords(msg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keyRR != nil {
		t.Fatalf("expected no KEY RR, got %+v", keyRR)
	}
	if len(other) != 1 {
		t.Fatalf("expected 1 non-KEY RR, got %d", len(other))
	}
}

func TestExtractUpdateRecordsNoKEYRR_NoOtherRecords(t *testing.T) {
	// Empty update section is accepted by extraction; caller validates matrix semantics.
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate
	// Empty Ns section — no KEY RR, no other RRs.

	keyRR, other, err := extractUpdateRecords(msg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keyRR != nil {
		t.Fatalf("expected nil KEY RR")
	}
	if len(other) != 0 {
		t.Fatalf("expected no non-KEY records, got %d", len(other))
	}
}

func TestKeyLeaseZeroDeleteKeyNoOtherRecords(t *testing.T) {
	// Case 2: KEY-LEASE == 0, LEASE != 0, no otherRecords → delete key
	h := NewUpdateHandler()
	ctx := context.Background()

	// First, register a key lease.
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY555=")
	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register initial lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(key))

	// Verify the lease exists.
	if h.leaseManager.LookupByKEY(key) == nil {
		t.Fatalf("expected active lease after registration")
	}

	// Now simulate the deletion path: KEY-LEASE == 0, LEASE != 0, no otherRecords.
	// This calls leaseManager.Delete directly (as the Handle() deletion path would).
	if err := h.leaseManager.Delete(lease.NodeKey(key)); err != nil {
		t.Fatalf("delete key lease: %v", err)
	}
	h.clearLeaseTimer(lease.NodeKey(key))

	if got := h.leaseManager.LookupByKEY(key); got != nil {
		t.Fatalf("expected lease removed after deletion")
	}
}

func TestKeyLeaseZeroDeleteKeyAndDataWithOtherRecords(t *testing.T) {
	// Case 3: KEY-LEASE == 0, LEASE == 0, otherRecords present → delete KEY and data
	h := NewUpdateHandler()
	ctx := context.Background()

	// Register a key lease with data.
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY666=")
	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register initial lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(key))

	// Register a data lease.
	data := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	data.TXT.Txt = []string{"payload"}
	h.setDataLease(lease.NodeKey(key), []dns.RR{data}, 1, "dev.zenr.io()")

	// Verify both leases exist.
	if h.leaseManager.LookupByKEY(key) == nil {
		t.Fatalf("expected active key lease after registration")
	}
	dataLease := h.getDataLease(lease.NodeKey(key))
	if dataLease == nil || len(dataLease.Records) == 0 {
		t.Fatalf("expected active data lease after registration")
	}

	// Now simulate deletion: KEY-LEASE == 0, LEASE == 0, otherRecords present.
	// Deleting the KEY removes its non-KEY records outright, too.
	if err := h.leaseManager.Delete(lease.NodeKey(key)); err != nil {
		t.Fatalf("delete key lease: %v", err)
	}
	h.clearLeaseTimer(lease.NodeKey(key))

	// Verify both leases are gone.
	if got := h.leaseManager.LookupByKEY(key); got != nil {
		t.Fatalf("expected key lease removed after deletion")
	}
	dataLease = h.getDataLease(lease.NodeKey(key))
	if dataLease != nil && len(dataLease.Records) != 0 {
		t.Fatalf("expected data lease records to be removed after key deletion, got %d remaining", len(dataLease.Records))
	}
}

func TestKeyLeaseZeroDataOnlyRegistration(t *testing.T) {
	// Case 1: KEY-LEASE == 0, LEASE != 0, otherRecords present → register data lease only
	h := NewUpdateHandler()
	ctx := context.Background()

	// Register a key lease (existing key).
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY777=")
	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register initial lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(key))

	// Now register a data lease only (KEY-LEASE == 0, otherRecords present).
	data := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	data.TXT.Txt = []string{"payload"}
	h.setDataLease(lease.NodeKey(key), []dns.RR{data}, 1, "dev.zenr.io()")
	h.scheduleLeaseExpiry(lease.NodeKey(key))

	// Verify key lease still active.
	if h.leaseManager.LookupByKEY(key) == nil {
		t.Fatalf("expected key lease still active")
	}

	// Verify data lease was registered.
	dataLease := h.getDataLease(lease.NodeKey(key))
	if dataLease == nil || len(dataLease.Records) == 0 {
		t.Fatalf("expected data lease to be registered")
	}
}

func TestKeyLeaseZeroDeleteKeyNoOtherRecords_Expires(t *testing.T) {
	// Full lifecycle test: register, delete key (KEY-LEASE == 0, no otherRecords), verify expiry
	h := NewUpdateHandler()
	ctx := context.Background()

	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY888=")
	if err := h.leaseManager.Register(ctx, key, 1, 1, "dev.zenr.io."); err != nil {
		t.Fatalf("register initial lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(key))

	// Wait for initial lease to expire.
	time.Sleep(1500 * time.Millisecond)
	if h.leaseManager.LookupByKEY(key) != nil {
		t.Fatalf("expected initial lease to have expired")
	}

	// Now register a new lease and immediately delete it (KEY-LEASE == 0, no otherRecords).
	if err := h.leaseManager.Register(ctx, key, 2, 2, "dev.zenr.io()"); err != nil {
		t.Fatalf("register new lease: %v", err)
	}
	h.scheduleLeaseExpiry(lease.NodeKey(key))

	// Immediately delete (simulating KEY-LEASE == 0, LEASE != 0, no otherRecords).
	if err := h.leaseManager.Delete(lease.NodeKey(key)); err != nil {
		t.Fatalf("delete key lease: %v", err)
	}
	h.clearLeaseTimer(lease.NodeKey(key))

	if got := h.leaseManager.LookupByKEY(key); got != nil {
		t.Fatalf("expected key lease to be removed immediately after deletion")
	}
}

func TestRecordKey_SameRecordDifferentTTL_ProducesSameKey(t *testing.T) {
	// Per rfc2136 - 1.1 - Comparison Rules: TTL is excluded from RR comparison.
	// Same name+type+rdata but different TTLs produce the same key (they are equal).
	mx1 := &dns.MX{Hdr: dns.Header{Name: "mailtrap.io.", Class: dns.ClassINET, TTL: 60}, MX: rdata.MX{Preference: 5, Mx: "mail1.mailtrap.io."}}
	mx2 := &dns.MX{Hdr: dns.Header{Name: "mailtrap.io.", Class: dns.ClassINET, TTL: 300}, MX: rdata.MX{Preference: 5, Mx: "mail1.mailtrap.io."}}

	key1 := recordKey(mx1)
	key2 := recordKey(mx2)
	if key1 != key2 {
		t.Fatalf("same MX record with different TTLs produced different keys (expected same per rfc2136 - 1.1): %q vs %q", key1, key2)
	}
	if strings.Contains(key1, "60") == true || strings.Contains(key1, "300") == true {
		t.Fatalf("record key should NOT contain TTL (excluded per rfc2136 - 1.1), got: %q", key1)
	}
}

func TestRecordKey_DistinguishesDifferentPriorities(t *testing.T) {
	// Different MX priorities must produce different keys.
	mxLow := &dns.MX{Hdr: dns.Header{Name: "mailtrap.io.", Class: dns.ClassINET, TTL: 60}, MX: rdata.MX{Preference: 5, Mx: "mail1.mailtrap.io."}}
	mxHigh := &dns.MX{Hdr: dns.Header{Name: "mailtrap.io.", Class: dns.ClassINET, TTL: 60}, MX: rdata.MX{Preference: 10, Mx: "mail2.mailtrap.io."}}

	keyLow := recordKey(mxLow)
	keyHigh := recordKey(mxHigh)
	if keyLow == keyHigh {
		t.Fatalf("different MX priorities produced same key: %q", keyLow)
	}
}

func TestSetDataLease_StoresMXRecordsWithDifferentPriority(t *testing.T) {
	h := NewUpdateHandler()
	ctx := context.Background()

	key := testKeyRR("test.dev.zenr.io.", "AAAAMXPRIORITYKEY=")
	if err := h.leaseManager.Register(ctx, key, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register key lease: %v", err)
	}

	mxLow := &dns.MX{Hdr: dns.Header{Name: key.Hdr.Name, Class: dns.ClassINET, TTL: 60}, MX: rdata.MX{Preference: 10, Mx: "mx1.test.dev.zenr.io."}}
	mxHigh := &dns.MX{Hdr: dns.Header{Name: key.Hdr.Name, Class: dns.ClassINET, TTL: 60}, MX: rdata.MX{Preference: 20, Mx: "mx1.test.dev.zenr.io."}}

	h.setDataLease(lease.NodeKey(key), []dns.RR{mxLow, mxHigh}, 120, "dev.zenr.io.")

	dataLease := h.getDataLease(lease.NodeKey(key))
	if dataLease == nil {
		t.Fatalf("expected data lease")
	}
	if len(dataLease.Records) != 2 {
		t.Fatalf("expected 2 distinct MX records, got %d", len(dataLease.Records))
	}
}

func TestFilterDuplicateRegistrations_RejectsDuplicateRecord(t *testing.T) {
	h := NewUpdateHandler()
	existing := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	existing.TXT.Txt = []string{"existing"}
	newRec := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	newRec.TXT.Txt = []string{"new"}

	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType != dns.TypeTXT {
			return nil, nil
		}
		return []dns.RR{existing}, nil
	}

	accepted, notes, err := h.filterDuplicateRegistrations(context.Background(), "test.dev.zenr.io.", "test.dev.zenr.io.", []dns.RR{existing, newRec})
	if err == nil {
		t.Fatal("expected duplicate registration to be rejected")
	}
	if len(accepted) != 0 {
		t.Fatalf("expected no accepted records on duplicate rejection, got %d", len(accepted))
	}
	if len(notes) != 0 {
		t.Fatalf("expected no duplicate notes on rejection, got %d", len(notes))
	}
}

func TestFilterDuplicateRegistrations_RejectsAuthoritativeDuplicateRecord(t *testing.T) {
	h := NewUpdateHandler()
	record := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	record.TXT.Txt = []string{"existing"}

	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType != dns.TypeTXT {
			return nil, nil
		}
		return []dns.RR{record}, nil
	}

	accepted, notes, err := h.filterDuplicateRegistrations(context.Background(), "test.dev.zenr.io.", "test.dev.zenr.io.", []dns.RR{record})
	if err == nil {
		t.Fatal("expected duplicate registration to be rejected")
	}
	if len(accepted) != 0 {
		t.Fatalf("expected no accepted records for duplicate, got %d", len(accepted))
	}
	if len(notes) != 0 {
		t.Fatalf("expected no duplicate notes on rejection, got %d", len(notes))
	}
}

func TestRecordKey_DistinguishesDifferentTypes(t *testing.T) {
	// Same name but different RR types must produce different keys.
	ip, _ := netip.AddrFromSlice(net.ParseIP("10.0.0.1").To4())
	aRec := &dns.A{Hdr: dns.Header{Name: "server.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}, A: rdata.A{Addr: ip}}
	txtRec := &dns.TXT{Hdr: dns.Header{Name: "server.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}, TXT: rdata.TXT{Txt: []string{"hello"}}}

	keyA := recordKey(aRec)
	keyTXT := recordKey(txtRec)
	if keyA == keyTXT {
		t.Fatalf("different RR types produced same key: %q", keyA)
	}
}

func TestSetDataLease_SameRecordDifferentTTL_SingleEntry(t *testing.T) {
	// Register a record with TTL=60, then same record at TTL=120.
	// Per rfc2136 - 1.1 - Comparison Rules: TTL is excluded from RR comparison.
	// Same record with different TTLs overwrites the previous entry (single entry).
	h := NewUpdateHandler()
	ctx := context.Background()

	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY999=")
	if err := h.leaseManager.Register(ctx, key, 2, 2, "dev.zenr.io."); err != nil {
		t.Fatalf("register key lease: %v", err)
	}

	// First registration: TTL 60.
	txt1 := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt1.Txt = []string{"hello"}
	h.setDataLease(lease.NodeKey(key), []dns.RR{txt1}, 60, "dev.zenr.io.")

	dataLease := h.getDataLease(lease.NodeKey(key))
	if len(dataLease.Records) != 1 {
		t.Fatalf("expected 1 record after first registration, got %d", len(dataLease.Records))
	}

	// Second registration: same record (name+type+rdata), but TTL 120.
	// Per rfc2136 - 1.1 - Comparison Rules, TTL is excluded from comparison,
	// so this overwrites the first entry rather than creating a new one.
	txt2 := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}}
	txt2.Txt = []string{"hello"}
	h.setDataLease(lease.NodeKey(key), []dns.RR{txt2}, 120, "dev.zenr.io.")

	dataLease = h.getDataLease(lease.NodeKey(key))
	if len(dataLease.Records) != 1 {
		t.Fatalf("expected 1 record (RFC 2136: TTL excluded from comparison, overwrite), got %d", len(dataLease.Records))
	}
}

func TestExtractUpdateRecordsRejectsBlacklistedTypes(t *testing.T) {
	// Test that blacklisted RR types are rejected with a format error.
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	// Add a NULL record (blacklisted).
	nullRec := &dns.NULL{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}, NULL: rdata.NULL{Null: "\x00\x01"}}
	msg.Ns = append(msg.Ns, nullRec)

	// Create a blacklist containing NULL (type 10).
	blacklist := map[uint16]struct{}{
		dns.TypeNULL: {},
	}

	_, _, err := extractUpdateRecords(msg, blacklist)
	if err == nil {
		t.Fatalf("expected error for blacklisted type NULL")
	}
	if !strings.Contains(err.Error(), "blacklisted") {
		t.Fatalf("expected error message to contain 'blacklisted', got: %v", err)
	}
}

func TestExtractUpdateRecordsAllowsNonBlacklistedTypes(t *testing.T) {
	// Test that non-blacklisted RR types are accepted.
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	// Add a KEY RR and an MX record (not blacklisted).
	msg.Ns = append(msg.Ns, testKeyRR("test.dev.zenr.io.", "AAAATESTKEY222="))
	mx := &dns.MX{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}, MX: rdata.MX{Preference: 10, Mx: "mx1.test.dev.zenr.io."}}
	msg.Ns = append(msg.Ns, mx)

	// Create a blacklist that does NOT contain MX (type 15).
	blacklist := map[uint16]struct{}{
		dns.TypeNULL:   {},
		dns.TypeNXNAME: {},
	}

	keyRR, other, err := extractUpdateRecords(msg, blacklist)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keyRR == nil {
		t.Fatalf("expected key RR")
	}
	if len(other) != 1 {
		t.Fatalf("expected 1 other record, got %d", len(other))
	}
	if _, ok := other[0].(*dns.MX); !ok {
		t.Fatalf("expected MX record, got %T", other[0])
	}
}

func TestExtractUpdateRecordsBlacklistedTypeWithKeyRR(t *testing.T) {
	// Test that a blacklisted non-KEY type is rejected even when a KEY RR is present.
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	// Add a KEY RR and a blacklisted NXNAME record.
	msg.Ns = append(msg.Ns,
		testKeyRR("test.dev.zenr.io.", "AAAATESTKEY111="),
		&dns.NXNAME{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}},
	)

	// Create a blacklist containing NXNAME (type 67).
	blacklist := map[uint16]struct{}{
		dns.TypeNXNAME: {},
	}

	_, _, err := extractUpdateRecords(msg, blacklist)
	if err == nil {
		t.Fatalf("expected error for blacklisted type NXNAME")
	}
	if !strings.Contains(err.Error(), "blacklisted") {
		t.Fatalf("expected error message to contain 'blacklisted', got: %v", err)
	}
}

func TestUpdateHandlerSetupParsesBlacklistedTypes(t *testing.T) {
	// Test that Setup correctly parses blacklisted_types from config and
	// that blacklisted types are rejected while non-blacklisted types pass.
	// The blacklist is user-configurable; this test verifies behavior, not count.
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	h := NewUpdateHandler()
	h.SetLogger(logging.NewLogger("debug", "text"))
	cfg := map[string]interface{}{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
		"blacklisted_types": []string{
			"NULL",
			"NXNAME",
			"RFC3597",
			"WALLET",
			"CLA",
			"IPN",
		},
	}
	err = h.Setup(cfg)
	if err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}

	// NULL should be rejected by the blacklist.
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeNULL)
	msg.Opcode = dns.OpcodeUpdate
	nullRec := &dns.NULL{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}, NULL: rdata.NULL{Null: "\x00\x01"}}
	msg.Ns = append(msg.Ns, nullRec)
	_, _, err = extractUpdateRecords(msg, h.blacklistedTypes)
	if err == nil {
		t.Fatalf("expected error for blacklisted type NULL")
	}
	if !strings.Contains(err.Error(), "blacklisted") {
		t.Fatalf("expected error message to contain 'blacklisted', got: %v", err)
	}

	// NXNAME should be rejected by the blacklist.
	msg2 := dns.NewMsg("test.dev.zenr.io.", dns.TypeNXNAME)
	msg2.Opcode = dns.OpcodeUpdate
	nxRec := &dns.NXNAME{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}}
	msg2.Ns = append(msg2.Ns, nxRec)
	_, _, err = extractUpdateRecords(msg2, h.blacklistedTypes)
	if err == nil {
		t.Fatalf("expected error for blacklisted type NXNAME")
	}
	if !strings.Contains(err.Error(), "blacklisted") {
		t.Fatalf("expected error message to contain 'blacklisted', got: %v", err)
	}

	// Non-blacklisted type (TXT) should pass through extractUpdateRecords.
	msg3 := dns.NewMsg("test.dev.zenr.io.", dns.TypeTXT)
	msg3.Opcode = dns.OpcodeUpdate
	msg3.Ns = append(msg3.Ns, testKeyRR("test.dev.zenr.io.", "AAAATESTKEY333="))
	txtRec := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}, TXT: rdata.TXT{Txt: []string{"data"}}}
	msg3.Ns = append(msg3.Ns, txtRec)
	_, otherRecords, err := extractUpdateRecords(msg3, h.blacklistedTypes)
	if err != nil {
		t.Fatalf("expected TXT (non-blacklisted) to pass, got error: %v", err)
	}
	if len(otherRecords) != 1 {
		t.Fatalf("expected 1 other record for TXT, got %d", len(otherRecords))
	}
}

func TestUpdateHandlerSetupHandlesUnknownBlacklistedTypes(t *testing.T) {
	// Test that Setup gracefully handles unknown type names in the blacklist
	// (skips them with a warning) while still blacklisting valid types.
	// The actual blacklist content is user-configurable; this test verifies
	// behavior: known types are rejected, unknown names are harmlessly ignored.
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	h := NewUpdateHandler()
	h.SetLogger(logging.NewLogger("debug", "text"))
	cfg := map[string]interface{}{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
		"blacklisted_types": []string{
			"NULL",
			"TOTALLY_UNKNOWN_TYPE",
			"MX",
		},
	}
	err = h.Setup(cfg)
	if err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}

	// NULL should be rejected.
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeNULL)
	msg.Opcode = dns.OpcodeUpdate
	nullRec := &dns.NULL{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}, NULL: rdata.NULL{Null: "\x00\x01"}}
	msg.Ns = append(msg.Ns, nullRec)
	_, _, err = extractUpdateRecords(msg, h.blacklistedTypes)
	if err == nil {
		t.Fatalf("expected error for blacklisted type NULL")
	}

	// MX should be rejected.
	msg2 := dns.NewMsg("test.dev.zenr.io.", dns.TypeMX)
	msg2.Opcode = dns.OpcodeUpdate
	mxRec := &dns.MX{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120}, MX: rdata.MX{Preference: 10, Mx: "mx.example.com."}}
	msg2.Ns = append(msg2.Ns, mxRec)
	_, _, err = extractUpdateRecords(msg2, h.blacklistedTypes)
	if err == nil {
		t.Fatalf("expected error for blacklisted type MX")
	}

	// TOTALLY_UNKNOWN_TYPE is not a real RR type, so it doesn't appear in
	// the blacklist. This verifies that unknown names are harmlessly skipped
	// without causing Setup to fail.
	if _, ok := h.blacklistedTypes[dns.StringToType["TOTALLY_UNKNOWN_TYPE"]]; ok {
		t.Fatalf("expected TOTALLY_UNKNOWN_TYPE to not be in the blacklist (unknown names are skipped)")
	}
}

func TestUpdateHandlerNoBlacklistAllowsAllTypes(t *testing.T) {
	// Test that without a blacklist, all types are accepted.
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	h := NewUpdateHandler()
	h.SetLogger(logging.NewLogger("debug", "text"))
	cfg := map[string]interface{}{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}
	err = h.Setup(cfg)
	if err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	if h.blacklistedTypes != nil {
		t.Fatalf("expected nil blacklistedTypes when not configured, got %d entries", len(h.blacklistedTypes))
	}
}
