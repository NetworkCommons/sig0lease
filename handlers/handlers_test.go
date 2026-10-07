package handlers

import (
	"context"
	"encoding/binary"
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/logging"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// wireCounts packs resp and returns its four section counts as they go on the wire -- what a
// requester that reads the header, such as mDNSResponder's srp-client, actually sees.
func wireCounts(t *testing.T, resp *dns.Msg) (zone, prereq, update, additional uint16) {
	t.Helper()
	if err := resp.Pack(); err != nil {
		t.Fatalf("pack response: %v", err)
	}
	b := resp.Data
	return binary.BigEndian.Uint16(b[4:]), binary.BigEndian.Uint16(b[6:]), binary.BigEndian.Uint16(b[8:]), binary.BigEndian.Uint16(b[10:])
}

func grantedLease(t *testing.T, resp *dns.Msg) (lease, keyLease uint32) {
	t.Helper()
	lo, err := leasepkg.FindAndDecode(resp)
	if err != nil {
		t.Fatalf("response carries no Update Lease option: %v", err)
	}
	if lo.KeyLease == nil {
		t.Fatalf("response lease option is the 4-byte variant, want 8-byte")
	}
	return lo.Lease, *lo.KeyLease
}

// testUpdateRequest is an UPDATE as the server hands it to a handler: unpacked from the wire,
// so the EDNS it carries sits in its header (UDPSize, the DO bit), as in every real lease
// update. A reply that copies that header must still end up with exactly one OPT RR.
func testUpdateRequest() *dns.Msg {
	req := dns.NewMsg("dev.zenr.io.", dns.TypeSOA)
	req.ID = 4711
	req.Opcode = dns.OpcodeUpdate
	req.UDPSize = 1232
	req.Security = true
	return req
}

// TestLeaseResponse_OnlyTheOPTRecord pins the shape of every successful lease-update reply:
// RFC 2136 S3.8 allows copying all of the request's sections or none, and the reply copies
// none, so its one record is the OPT RR carrying the granted lease (RFC 6891 S6.1.1: one OPT
// RR at most). mDNSResponder's srp-client reads the lease only from exactly that shape (zone,
// prerequisite and update counts 0, additional count 1); a reply that echoed the Zone
// section, or carried a second OPT RR, made it ignore the lease and refresh on the one it had
// asked for.
func TestLeaseResponse_OnlyTheOPTRecord(t *testing.T) {
	req := testUpdateRequest()
	resp := leaseResponse(req, 120, 300, logging.NewLogger("error"))

	if resp.ID != req.ID || resp.Opcode != dns.OpcodeUpdate || !resp.Response || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("header = %+v, want the request's ID and Opcode, QR set, NOERROR", resp.MsgHeader)
	}
	zone, prereq, update, additional := wireCounts(t, resp)
	if zone != 0 || prereq != 0 || update != 0 || additional != 1 {
		t.Fatalf("section counts = %d/%d/%d/%d, want 0/0/0/1 (only the OPT RR)", zone, prereq, update, additional)
	}
	if lease, keyLease := grantedLease(t, resp); lease != 120 || keyLease != 300 {
		t.Fatalf("granted lease = %d/%d, want 120/300", lease, keyLease)
	}
}

// TestMakeErrorResponse_NoSections: an error reply copies none of the request's sections
// either. Its additional section holds only the OPT RR answering the request's EDNS.
func TestMakeErrorResponse_NoSections(t *testing.T) {
	req := testUpdateRequest()
	resp := makeErrorResponse(req, dns.RcodeRefused, "")
	if resp.ID != req.ID || resp.Opcode != dns.OpcodeUpdate || !resp.Response || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("header = %+v, want the request's ID and Opcode, QR set, REFUSED", resp.MsgHeader)
	}
	if zone, prereq, update, additional := wireCounts(t, resp); zone != 0 || prereq != 0 || update != 0 || additional != 1 {
		t.Fatalf("section counts = %d/%d/%d/%d, want 0/0/0/1 (only the OPT RR)", zone, prereq, update, additional)
	}
}

// TestUpdateHandlerSuccessResponse_NotesInTheOPTRecord: the RFC 9664 handler's reply is
// leaseResponse plus its status notes, each an Extended DNS Error option (RFC 8914) in the
// same OPT RR, so it too copies none of the request's sections (RFC 2136 S3.8). Checked after
// a pack/unpack round trip, i.e. as a client reads it.
func TestUpdateHandlerSuccessResponse_NotesInTheOPTRecord(t *testing.T) {
	h := NewUpdateHandler()
	h.SetLogger(logging.NewLogger("error"))
	notes := []string{"record not found for delete: a", "KEY b. not found for delete"}

	resp := h.buildSuccessResponse(testUpdateRequest(), notes, 120, 300)

	zone, prereq, update, additional := wireCounts(t, resp)
	if zone != 0 || prereq != 0 || update != 0 || additional != 1 {
		t.Fatalf("section counts = %d/%d/%d/%d, want 0/0/0/1 (only the OPT RR)", zone, prereq, update, additional)
	}
	received := &dns.Msg{Data: resp.Data}
	if err := received.Unpack(); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if got := client.StatusNotes(received); !slices.Equal(got, notes) {
		t.Fatalf("status notes = %q, want %q", got, notes)
	}
	if lease, keyLease := grantedLease(t, received); lease != 120 || keyLease != 300 {
		t.Fatalf("granted lease = %d/%d, want 120/300", lease, keyLease)
	}
}

// TestSRPHandle_SuccessReplyIsOnlyTheGrantedLease runs a registration through Handle with a
// lease policy that grants less than requested, and checks the reply on the wire: no
// sections but the OPT RR, carrying the clamped values.
func TestSRPHandle_SuccessReplyIsOnlyTheGrantedLease(t *testing.T) {
	h, _ := newSRPTestHandler(t)
	h.LeasePolicy = LeasePolicy{MinRRLease: 30, MaxRRLease: 120, MinKeyLease: 30, MaxKeyLease: 300}
	id := newSRPTestIdentity(t)
	const host = "replyshape.dev.zenr.io."
	built := buildSRPUpdate(t, srpTestZone, id, host, []string{"192.0.2.1"}, oneWidgetInstance(), 3600, 604800, host)
	// As the server hands it over: unpacked from the wire, so its EDNS is in the header.
	if err := built.Pack(); err != nil {
		t.Fatalf("pack request: %v", err)
	}
	msg := &dns.Msg{Data: built.Data}
	if err := msg.Unpack(); err != nil {
		t.Fatalf("unpack request: %v", err)
	}

	res := h.Handle(context.Background(), stubTCPResponseWriter{}, msg)
	if res.Status != StatusProcessed || res.Message == nil || res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected Processed/NOERROR, got status=%s message=%+v err=%v", res.Status, res.Message, res.Error)
	}
	zone, prereq, update, additional := wireCounts(t, res.Message)
	if zone != 0 || prereq != 0 || update != 0 || additional != 1 {
		t.Fatalf("section counts = %d/%d/%d/%d, want 0/0/0/1 (only the OPT RR)", zone, prereq, update, additional)
	}
	if lease, keyLease := grantedLease(t, res.Message); lease != 120 || keyLease != 300 {
		t.Fatalf("granted lease = %d/%d, want the clamped 120/300", lease, keyLease)
	}
}
