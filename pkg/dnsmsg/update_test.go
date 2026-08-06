package dnsmsg

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/NetworkCommons/sig0lease/pkg/lease"
)

func TestNewDataOnlyUpdate(t *testing.T) {
	// Create a TXT record for testing.
	txt := &dns.TXT{
		Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120},
	}
	txt.TXT.Txt = []string{"hello world"}

	msg, err := NewDataOnlyUpdate("dev.zenr.io.", []dns.RR{txt}, 300)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if msg == nil {
		t.Fatalf("expected non-nil message")
	}

	// Verify opcode is UPDATE.
	if msg.Opcode != dns.OpcodeUpdate {
		t.Fatalf("expected opcode %d (UPDATE), got %d", dns.OpcodeUpdate, msg.Opcode)
	}

	// Verify authority section has the TXT record but no KEY RR.
	if len(msg.Ns) != 1 {
		t.Fatalf("expected 1 record in authority section, got %d", len(msg.Ns))
	}
	if _, ok := msg.Ns[0].(*dns.TXT); !ok {
		t.Fatalf("expected TXT record in authority section, got %T", msg.Ns[0])
	}

	// Verify no KEY RR in authority section.
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.KEY); ok {
			t.Fatalf("unexpected KEY RR in authority section")
		}
	}

	// Verify UPDATE-LEASE EDNS option exists with KEY-LEASE = 0.
	if len(msg.Extra) != 1 {
		t.Fatalf("expected 1 OPT record in extra section, got %d", len(msg.Extra))
	}
	opt, ok := msg.Extra[0].(*dns.OPT)
	if !ok {
		t.Fatalf("expected OPT record in extra section, got %T", msg.Extra[0])
	}

	// Decode the lease option.
	var leaseOpt lease.LeaseOption
	if err := leaseOpt.Decode(opt); err != nil {
		t.Fatalf("failed to decode lease option: %v", err)
	}
	if leaseOpt.Lease != 300 {
		t.Fatalf("expected lease duration 300, got %d", leaseOpt.Lease)
	}
	if leaseOpt.KeyLease == nil {
		t.Fatalf("expected KEY-LEASE to be present (8-byte variant)")
	}
	if *leaseOpt.KeyLease != 0 {
		t.Fatalf("expected KEY-LEASE 0 (data-only), got %d", *leaseOpt.KeyLease)
	}
}

func TestNewDataOnlyUpdateEmptyZone(t *testing.T) {
	txt := &dns.TXT{
		Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120},
	}
	txt.TXT.Txt = []string{"hello"}

	_, err := NewDataOnlyUpdate("", []dns.RR{txt}, 300)
	if err == nil {
		t.Fatalf("expected error for empty zone")
	}
}

func TestNewDataOnlyUpdateNoRecords(t *testing.T) {
	msg, err := NewDataOnlyUpdate("dev.zenr.io.", nil, 300)
	if err != nil {
		t.Fatalf("expected no error for empty data-only update, got: %v", err)
	}
	if msg == nil {
		t.Fatalf("expected non-nil message")
	}
	if len(msg.Ns) != 0 {
		t.Fatalf("expected no authority records, got %d", len(msg.Ns))
	}
}

func TestNewDataOnlyUpdateShortLease(t *testing.T) {
	txt := &dns.TXT{
		Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120},
	}
	txt.TXT.Txt = []string{"hello"}

	_, err := NewDataOnlyUpdate("dev.zenr.io.", []dns.RR{txt}, 10)
	if err != nil {
		t.Fatalf("expected no errors for lease < 30 seconds")
	}
}

func TestNewDataOnlyUpdateMultipleRecords(t *testing.T) {
	txt1 := &dns.TXT{
		Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120},
	}
	txt1.TXT.Txt = []string{"hello"}
	txt2 := &dns.TXT{
		Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120},
	}
	txt2.TXT.Txt = []string{"world"}

	msg, err := NewDataOnlyUpdate("dev.zenr.io.", []dns.RR{txt1, txt2}, 600)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(msg.Ns) != 2 {
		t.Fatalf("expected 2 records in authority section, got %d", len(msg.Ns))
	}

	// Verify KEY-LEASE = 0.
	opt := msg.Extra[0].(*dns.OPT)
	var leaseOpt lease.LeaseOption
	if err := leaseOpt.Decode(opt); err != nil {
		t.Fatalf("failed to decode lease option: %v", err)
	}
	if leaseOpt.KeyLease == nil || *leaseOpt.KeyLease != 0 {
		t.Fatalf("expected KEY-LEASE 0, got %v", leaseOpt.KeyLease)
	}
}

func TestNewDataOnlyUpdatePacksSuccessfully(t *testing.T) {
	txt := &dns.TXT{
		Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 120},
	}
	txt.TXT.Txt = []string{"hello world"}

	msg, err := NewDataOnlyUpdate("dev.zenr.io.", []dns.RR{txt}, 300)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the message can be packed (wire format).
	if err := msg.Pack(); err != nil {
		t.Fatalf("expected message to pack successfully, got: %v", err)
	}
}

func TestNewDataOnlyUpdateWithSRVRecord(t *testing.T) {
	srv := &dns.SRV{
		Hdr: dns.Header{Name: "_http._tcp.dev.zenr.io.", Class: dns.ClassINET, TTL: 300},
		SRV: rdata.SRV{Target: "server.dev.zenr.io.", Port: 8080, Priority: 10, Weight: 10},
	}

	msg, err := NewDataOnlyUpdate("dev.zenr.io.", []dns.RR{srv}, 600)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(msg.Ns) != 1 {
		t.Fatalf("expected 1 record in authority section, got %d", len(msg.Ns))
	}
	if _, ok := msg.Ns[0].(*dns.SRV); !ok {
		t.Fatalf("expected SRV record in authority section, got %T", msg.Ns[0])
	}

	// Verify packed message.
	if err := msg.Pack(); err != nil {
		t.Fatalf("expected message to pack successfully, got: %v", err)
	}
}

func TestNewDataOnlyUpdateWithARecord(t *testing.T) {
	a := &dns.A{
		Hdr: dns.Header{Name: "server.dev.zenr.io.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("10.0.0.1")},
	}

	msg, err := NewDataOnlyUpdate("dev.zenr.io.", []dns.RR{a}, 300)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(msg.Ns) != 1 {
		t.Fatalf("expected 1 record in authority section, got %d", len(msg.Ns))
	}
	if _, ok := msg.Ns[0].(*dns.A); !ok {
		t.Fatalf("expected A record in authority section, got %T", msg.Ns[0])
	}
}
