package srp

import (
	"context"
	"errors"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func srvRR(target string, priority, weight, port uint16) *dns.SRV {
	return &dns.SRV{
		Hdr: dns.Header{Name: "_dnssd-srp._tcp.example.com.", Class: dns.ClassINET, TTL: 3600},
		SRV: rdata.SRV{Priority: priority, Weight: weight, Port: port, Target: target},
	}
}

func TestDiscover_QueriesExpectedName(t *testing.T) {
	var gotName string
	query := func(ctx context.Context, name string) ([]*dns.SRV, error) {
		gotName = name
		return []*dns.SRV{srvRR("registrar.example.com.", 0, 0, 853)}, nil
	}
	addr, err := Discover(context.Background(), query, "example.com.")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if gotName != "_dnssd-srp._tcp.example.com." {
		t.Fatalf("queried name = %q, want %q", gotName, "_dnssd-srp._tcp.example.com.")
	}
	if addr != "registrar.example.com:853" {
		t.Fatalf("addr = %q, want %q", addr, "registrar.example.com:853")
	}
}

func TestDiscover_NoTrailingDotOnDomain(t *testing.T) {
	var gotName string
	query := func(ctx context.Context, name string) ([]*dns.SRV, error) {
		gotName = name
		return []*dns.SRV{srvRR("registrar.example.com.", 0, 0, 853)}, nil
	}
	if _, err := Discover(context.Background(), query, "example.com"); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if gotName != "_dnssd-srp._tcp.example.com." {
		t.Fatalf("queried name = %q, want %q (domain without trailing dot)", gotName, "_dnssd-srp._tcp.example.com.")
	}
}

func TestDiscover_PicksLowestPriority(t *testing.T) {
	query := func(ctx context.Context, name string) ([]*dns.SRV, error) {
		return []*dns.SRV{
			srvRR("second.example.com.", 10, 0, 853),
			srvRR("first.example.com.", 0, 0, 853),
		}, nil
	}
	addr, err := Discover(context.Background(), query, "example.com.")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "first.example.com:853" {
		t.Fatalf("addr = %q, want the lowest-priority target", addr)
	}
}

func TestDiscover_TiebreaksOnHighestWeight(t *testing.T) {
	query := func(ctx context.Context, name string) ([]*dns.SRV, error) {
		return []*dns.SRV{
			srvRR("light.example.com.", 0, 10, 853),
			srvRR("heavy.example.com.", 0, 90, 853),
		}, nil
	}
	addr, err := Discover(context.Background(), query, "example.com.")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "heavy.example.com:853" {
		t.Fatalf("addr = %q, want the highest-weight target among equal priorities", addr)
	}
}

func TestDiscover_NoRecords(t *testing.T) {
	query := func(ctx context.Context, name string) ([]*dns.SRV, error) { return nil, nil }
	if _, err := Discover(context.Background(), query, "example.com."); err == nil {
		t.Fatal("expected an error when no SRV records are found")
	}
}

func TestDiscover_QueryError(t *testing.T) {
	wantErr := errors.New("network exploded")
	query := func(ctx context.Context, name string) ([]*dns.SRV, error) { return nil, wantErr }
	_, err := Discover(context.Background(), query, "example.com.")
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected the query error to propagate, got: %v", err)
	}
}
