package handlers

import (
	"context"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
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

	gotLease, gotKeyLease, isRefresh, err := h.parseLease(msg)
	if err != nil {
		t.Fatalf("parse lease: %v", err)
	}
	if isRefresh {
		t.Fatalf("expected registration variant")
	}
	if gotLease != 120 || gotKeyLease != 600 {
		t.Fatalf("unexpected lease values lease=%d key-lease=%d", gotLease, gotKeyLease)
	}
}

func TestExtractUpdateRecordsRejectsMultipleKeys(t *testing.T) {
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate
	msg.Ns = append(msg.Ns,
		testKeyRR("test.dev.zenr.io.", "AAAATESTKEY111="),
		testKeyRR("test.dev.zenr.io.", "AAAATESTKEY222="),
	)

	_, _, err := extractUpdateRecords(msg)
	if err == nil {
		t.Fatalf("expected multiple KEY rejection")
	}
}

func TestApplyTTLPolicyClampsKeyAndOtherRecords(t *testing.T) {
	h := NewUpdateHandler()
	h.ttlPolicy = TTLPolicy{
		MinKeyTTL: 120,
		MaxKeyTTL: 300,
		MinRRTTL:  30,
		MaxRRTTL:  60,
	}

	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY333=")
	key.Hdr.TTL = 10
	txt := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 999}}
	txt.TXT.Txt = []string{"hello"}

	newKey, rr := h.applyTTLPolicy(key, []dns.RR{txt})
	if newKey.Hdr.TTL != 120 {
		t.Fatalf("expected key ttl clamped to min, got %d", newKey.Hdr.TTL)
	}
	if len(rr) != 1 {
		t.Fatalf("expected one non-key rr")
	}
	if rr[0].Header().TTL != 60 {
		t.Fatalf("expected rr ttl clamped to max, got %d", rr[0].Header().TTL)
	}
}

func TestDataLeaseExpiresBeforeKeyLease(t *testing.T) {
	h := NewUpdateHandler()
	ctx := context.Background()
	key := testKeyRR("test.dev.zenr.io.", "AAAATESTKEY444=")
	data := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	data.TXT.Txt = []string{"payload"}

	if err := h.leaseManager.Register(ctx, key.Hdr.Name, key, 2, "dev.zenr.io."); err != nil {
		t.Fatalf("register key lease: %v", err)
	}
	h.setDataLease(key.Hdr.Name, []dns.RR{data}, 1, "dev.zenr.io.")
	h.scheduleLeaseExpiry(key.Hdr.Name)
	defer h.clearLeaseTimer(key.Hdr.Name)

	time.Sleep(1300 * time.Millisecond)
	dataLease := h.getDataLease(key.Hdr.Name)
	if dataLease == nil || !dataLease.Deleted {
		t.Fatalf("expected non-key records to be marked deleted after data lease expiry")
	}
	if got := h.leaseManager.Lookup(key.Hdr.Name); got == nil {
		t.Fatalf("expected key lease still active after data lease expiry")
	}

	time.Sleep(1100 * time.Millisecond)
	if got := h.leaseManager.Lookup(key.Hdr.Name); got != nil {
		t.Fatalf("expected key lease removed after key-lease expiry")
	}
}
