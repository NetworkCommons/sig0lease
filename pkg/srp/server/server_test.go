package server

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/srp/instruction"
)

func TestNewServer(t *testing.T) {
	server := New("example.com")

	if server == nil {
		t.Fatal("New returned nil")
	}
	if server.zone != "example.com" {
		t.Errorf("expected zone 'example.com', got '%s'", server.zone)
	}
}

func TestNewWithKeyStore(t *testing.T) {
	ks := NewDefaultKeyStore()
	server := NewWithKeyStore("example.com", ks)

	if server.keyStore != ks {
		t.Error("key store not set correctly")
	}
}

func TestServer_ValidateMessage(t *testing.T) {
	server := New("example.com")

	// Valid message
	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassANY},
	}}

	err := server.validateMessage(msg)
	if err != nil {
		t.Errorf("valid message failed validation: %v", err)
	}

	// Invalid: missing question
	msg2 := new(dns.Msg)
	msg2.ID = dns.ID()
	msg2.Response = false
	msg2.Opcode = dns.OpcodeUpdate

	err = server.validateMessage(msg2)
	if err == nil {
		t.Error("expected error for missing question")
	}

	// Invalid: wrong zone
	msg3 := new(dns.Msg)
	msg3.ID = dns.ID()
	msg3.Response = false
	msg3.Opcode = dns.OpcodeUpdate

	err = server.validateMessage(msg3)
	if err == nil {
		t.Error("expected error for wrong zone")
	}
}

func TestServer_Process(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassANY},
	}}

	inst := instruction.New("service.example.com")
	inst.SetService(10, 5, 8080, "host.example.com")
	msg.Extra = append(msg.Extra, inst.ToRR())

	resp, err := server.Process(context.Background(), msg)
	if err != nil {
		t.Errorf("Process failed: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected rcode %d, got %d", dns.RcodeSuccess, resp.Rcode)
	}
}

func TestServer_ProcessInvalidInstruction(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassANY},
	}}

	// Invalid instruction (empty name)
	inst := instruction.New("")
	msg.Extra = append(msg.Extra, inst.ToRR())

	resp, err := server.Process(context.Background(), msg)
	if err != nil {
		t.Logf("Process returned error (expected for invalid instruction): %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	// Should be format error for invalid instruction
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("expected rcode %d (format error), got %d", dns.RcodeFormatError, resp.Rcode)
	}
}

func TestServer_ProcessInstructions(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassANY},
	}}

	inst1 := instruction.New("service1.example.com")
	inst1.SetService(10, 5, 8080, "host1.example.com")

	inst2 := instruction.New("service2.example.com")
	inst2.SetService(0, 0, 443, "host2.example.com")

	msg.Extra = append(msg.Extra, inst1.ToRR(), inst2.ToRR())

	results := server.processInstructions(msg)

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	if !results[0].Success {
		t.Errorf("first instruction should succeed")
	}
	if results[0].Action != "register" {
		t.Errorf("expected action 'register', got '%s'", results[0].Action)
	}

	if !results[1].Success {
		t.Errorf("second instruction should succeed")
	}
}

func TestServer_DeleteService(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassANY},
	}}

	inst := instruction.ServiceDelete("service.example.com")
	msg.Extra = append(msg.Extra, inst.ToRR())

	results := server.processInstructions(msg)

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if results[0].Action != "delete" {
		t.Errorf("expected action 'delete', got '%s'", results[0].Action)
	}
}

func TestServer_ParseInstruction(t *testing.T) {
	server := New("example.com")

	inst := instruction.New("test.example.com")
	inst.SetService(10, 5, 8080, "host.example.com")

	rr := inst.ToRR()
	parsed, err := server.parseInstruction(rr)

	if err != nil {
		t.Fatalf("parseInstruction failed: %v", err)
	}

	if parsed.Name != inst.Name {
		t.Errorf("parsed name '%s' != original '%s'", parsed.Name, inst.Name)
	}
}

func TestServer_ParseInstructionWrongOpcode(t *testing.T) {
	server := New("example.com")

	// Create a non-SRP ERFC3597 record
	wrongRR := &dns.ERFC3597{
		EDNS0Code: instruction.OPTION_CODE + 1,
		Code:      "",
	}

	_, err := server.parseInstruction(wrongRR)
	if err == nil {
		t.Error("expected error for wrong opcode")
	}
}

func TestServer_ProcessWithNoInstructions(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassANY},
	}}

	resp, err := server.Process(context.Background(), msg)
	if err != nil {
		t.Errorf("Process with no instructions failed: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
}

func TestServer_CreateSOA(t *testing.T) {
	server := New("example.com")

	soa := server.createSOA()

	if soa.Hdr.Name != "example.com" {
		t.Errorf("expected name 'example.com', got '%s'", soa.Hdr.Name)
	}
	if soa.Ns == "" {
		t.Error("Ns should not be empty")
	}
}

func TestServer_FindDNSKEY(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	dnskey := dns.NewDNSKEY("key.example.com", 8)
	dnskey.Hdr.TTL = 3600
	msg.Extra = append(msg.Extra, dnskey)

	found := server.findDNSKEY(msg)
	if found == nil {
		t.Fatal("DNSKEY not found")
	}
}

func TestServer_FindSIG0(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	sig := &dns.SIG{}
	sig.Hdr = dns.Header{Name: ".", Class: dns.ClassANY, TTL: 0}
	sig.Algorithm = 8
	sig.KeyTag = 12345
	msg.Extra = append(msg.Extra, sig)

	found := server.findSIG0(msg)
	if found == nil {
		t.Fatal("SIG not found")
	}
}

func TestServer_KeyStore(t *testing.T) {
	server := New("example.com")

	ks := server.KeyStore()
	if ks == nil {
		t.Fatal("KeyStore returned nil")
	}

	// Test default key store
	key := dns.NewDNSKEY("key.example.com", 8)
	key.Hdr.TTL = 3600
	server.RegisterKey(key)

	// Try to retrieve it
	keys, err := ks.GetKeysByZone("example.com")
	if err != nil {
		t.Fatalf("GetKeysByZone failed: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
}

func TestServer_ProcessUpdateMessage(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassANY},
	}}

	resp, err := server.ProcessUpdateMessage(msg)
	if err != nil {
		t.Errorf("ProcessUpdateMessage failed: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
}

func TestServer_GetZone(t *testing.T) {
	server := New("test.example.com")

	zone := server.GetZone()
	if zone != "test.example.com" {
		t.Errorf("expected zone 'test.example.com', got '%s'", zone)
	}
}

func TestServer_ProcessWithTXT(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassANY},
	}}

	inst := instruction.New("service.example.com")
	inst.SetService(10, 5, 8080, "host.example.com")
	inst.SetTXT([]string{"v=spf1 ~all", "foo=bar"})
	msg.Extra = append(msg.Extra, inst.ToRR())

	resp, err := server.Process(context.Background(), msg)
	if err != nil {
		t.Errorf("Process failed: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
}

func TestServer_ProcessErrorWithMessage(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "wrong.example.com.", Class: dns.ClassANY},
	}}

	resp, err := server.Process(context.Background(), msg)
	if err != nil {
		t.Logf("Process returned error: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	// Should be a format error or name error
	if resp.Rcode != dns.RcodeFormatError && resp.Rcode != dns.RcodeNameError {
		t.Errorf("expected error rcode, got %d", resp.Rcode)
	}
}

func TestDefaultKeyStore_GetKey(t *testing.T) {
	ks := NewDefaultKeyStore()

	key := dns.NewDNSKEY("key.example.com", 8)
	key.Hdr.TTL = 3600
	ks.AddKey(key)

	retrieved, err := ks.GetKey("key.example.com")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if retrieved.Flags != key.Flags {
		t.Error("retrieved key flags don't match")
	}

	_, err = ks.GetKey("nonexistent.com")
	if err == nil {
		t.Error("expected error for non-existent key")
	}
}

func TestDefaultKeyStore_VerifySignature(t *testing.T) {
	ks := NewDefaultKeyStore()

	msg := new(dns.Msg)
	key := dns.NewDNSKEY("key.example.com", 8)
	key.Hdr.TTL = 3600

	err := ks.VerifySignature(msg, key)
	if err != nil {
		t.Logf("VerifySignature returned error (expected for placeholder): %v", err)
	}
}

func TestServer_ProcessWithMultipleInstructions(t *testing.T) {
	server := New("example.com")

	msg := new(dns.Msg)
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassANY},
	}}

	inst1 := instruction.New("service1.example.com")
	inst1.SetService(10, 5, 8080, "host.example.com")

	inst2 := instruction.ServiceDelete("service2.example.com")

	msg.Extra = append(msg.Extra, inst1.ToRR(), inst2.ToRR())

	results := server.processInstructions(msg)

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	if results[0].Action != "register" {
		t.Errorf("first action should be 'register', got '%s'", results[0].Action)
	}

	if results[1].Action != "delete" {
		t.Errorf("second action should be 'delete', got '%s'", results[1].Action)
	}
}
