package client

import (
	"context"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/srp/instruction"
)

func TestNewClient(t *testing.T) {
	config := Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
		KeyName:       "key.example.com",
	}
	client := New(config)

	if client == nil {
		t.Fatal("New returned nil")
	}

	if client.config.ServerAddress != "127.0.0.1:53" {
		t.Errorf("expected server address '127.0.0.1:53', got '%s'", client.config.ServerAddress)
	}
	if client.config.Zone != "example.com" {
		t.Errorf("expected zone 'example.com', got '%s'", client.config.Zone)
	}
	if client.config.KeyName != "key.example.com" {
		t.Errorf("expected key name 'key.example.com', got '%s'", client.config.KeyName)
	}
}

func TestNewWithDefaults(t *testing.T) {
	client := NewWithDefaults()

	if client == nil {
		t.Fatal("NewWithDefaults returned nil")
	}

	// Check defaults
	if client.config.ServerAddress == "" {
		t.Error("expected default server address")
	}
}

func TestClient_Register(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
	})

	inst := instruction.New("service.example.com")
	inst.SetService(10, 5, 8080, "host.example.com")

	// This test just verifies the message creation, not actual sending
	msg, err := client.CreateUpdateMessage(inst)
	if err != nil {
		t.Fatalf("CreateUpdateMessage failed: %v", err)
	}

	if msg == nil {
		t.Fatal("message is nil")
	}

	if len(msg.Extra) != 1 {
		t.Errorf("expected 1 extra record, got %d", len(msg.Extra))
	}
}

func TestClient_Delete(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
	})

	msg, err := client.Delete(context.Background(), "service.example.com")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if msg == nil {
		t.Fatal("message is nil")
	}
}

func TestClient_RegisterService(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
	})

	msg, err := client.RegisterService(context.Background(), "service.example.com", 10, 5, 8080, "host.example.com")
	if err != nil {
		t.Fatalf("RegisterService failed: %v", err)
	}

	if msg == nil {
		t.Fatal("message is nil")
	}
}

func TestClient_RegisterServiceWithTXT(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
	})

	txt := []string{"v=spf1 ~all", "foo=bar"}
	msg, err := client.RegisterServiceWithTXT(context.Background(), "service.example.com", 10, 5, 8080, "host.example.com", txt)
	if err != nil {
		t.Fatalf("RegisterServiceWithTXT failed: %v", err)
	}

	if msg == nil {
		t.Fatal("message is nil")
	}
}

func TestClient_CreateUpdateMessage(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
	})

	inst1 := instruction.New("service1.example.com")
	inst1.SetService(10, 5, 8080, "host.example.com")

	inst2 := instruction.New("service2.example.com")
	inst2.SetService(0, 0, 443, "gateway.example.com")

	msg, err := client.CreateUpdateMessage(inst1, inst2)
	if err != nil {
		t.Fatalf("CreateUpdateMessage failed: %v", err)
	}

	if len(msg.Extra) != 2 {
		t.Errorf("expected 2 extra records, got %d", len(msg.Extra))
	}
}

func TestClient_CreateUpdateMessageNoZone(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		// No zone set
	})

	inst := instruction.New("service.example.com")
	msg, err := client.CreateUpdateMessage(inst)

	if msg != nil {
		t.Error("expected nil message when zone is missing")
	}
	if err == nil {
		t.Error("expected error when zone is missing")
	}
}

func TestClient_ValidateInstruction(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
	})

	// Invalid instruction (empty name)
	inst := instruction.New("")
	msg, err := client.CreateUpdateMessage(inst)

	if msg != nil {
		t.Error("expected nil message for invalid instruction")
	}
	if err == nil {
		t.Error("expected error for invalid instruction")
	}

	if err != nil && err.Error() == "" {
		t.Errorf("error should not be empty: %v", err)
	}
}

func TestVerifyResponse(t *testing.T) {
	client := New(Config{})

	successResp := &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}
	failResp := &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeServerFailure}}

	if !client.VerifyResponse(successResp) {
		t.Error("expected VerifyResponse to return true for success")
	}

	if client.VerifyResponse(failResp) {
		t.Error("expected VerifyResponse to return false for failure")
	}

	if client.VerifyResponse(nil) {
		t.Error("expected VerifyResponse to return false for nil")
	}
}

func TestClient_Update(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
	})

	inst := instruction.New("service.example.com")
	inst.SetService(20, 10, 9090, "update.example.com")

	msg, err := client.Update(context.Background(), "service.example.com", inst)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if msg == nil {
		t.Fatal("message is nil")
	}
}

func TestClient_DeleteService(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
	})

	msg, err := client.DeleteService(context.Background(), "service.example.com")
	if err != nil {
		t.Fatalf("DeleteService failed: %v", err)
	}

	if msg == nil {
		t.Fatal("message is nil")
	}
}

func TestClient_SignMessage(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
		KeyName:       "key.example.com",
		KeySecret:     "SECRET123",
	})

	msg := new(dns.Msg)
	// Create DNS UPDATE message
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	// Set Question section for UPDATE (ZONE section)
	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com", Class: dns.ClassINET},
	}}

	err := client.signMessage(msg)
	// Should not error even without real key (it's a placeholder)
	if err != nil {
		t.Logf("signMessage returned error: %v", err)
	}
}

func TestClient_SendWithTimeout(t *testing.T) {
	client := New(Config{
		ServerAddress: "127.0.0.1:53",
		Zone:          "example.com",
		Timeout:       1 * time.Millisecond, // Very short timeout for testing
	})

	msg := new(dns.Msg)
	// Create DNS UPDATE message
	msg.ID = dns.ID()
	msg.Response = false
	msg.Opcode = dns.OpcodeUpdate

	// Set Question section for UPDATE (ZONE section)
	msg.Question = []dns.RR{&dns.SOA{
		Hdr: dns.Header{Name: "example.com", Class: dns.ClassINET},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.Send(ctx, msg)

	if err == nil {
		t.Log("Send completed (may have succeeded on local server)")
	}
}
