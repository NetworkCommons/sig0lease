package srp

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
)

func testHostKey(name string) *dns.KEY {
	// Deliberately non-zero flags here -- BuildUpdate must zero them regardless (S3.3.3),
	// so a test that starts from an already-zero value couldn't catch a regression.
	return keyRR(name, dns.ECDSAP256SHA256, 257, "AAAABase64PubKeyMaterial")
}

func TestBuildUpdate_HostOnly_RoundTripsThroughClassifyAndValidate(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.1")
	spec := UpdateSpec{
		Zone:      "example.com.",
		Host:      "myhost.example.com.",
		Addresses: []netip.Addr{addr},
		Key:       testHostKey("myhost.example.com."),
		Lease:     30,
		KeyLease:  1209600,
	}
	msg, err := BuildUpdate(spec)
	if err != nil {
		t.Fatalf("BuildUpdate: %v", err)
	}

	cu, err := Validate(msg)
	if err != nil {
		t.Fatalf("Validate(BuildUpdate(...)): %v", err)
	}
	if cu.Host.Name != spec.Host {
		t.Fatalf("host name = %q, want %q", cu.Host.Name, spec.Host)
	}
	if len(cu.Host.Addresses) != 1 {
		t.Fatalf("expected 1 host address, got %d", len(cu.Host.Addresses))
	}
	if cu.Host.Key.Flags != 0 {
		t.Fatalf("host KEY flags = %d, want 0 (S3.2.5.1/S3.3.3 requester MUST)", cu.Host.Key.Flags)
	}
	if len(cu.Instances) != 0 {
		t.Fatalf("expected 0 instances, got %d", len(cu.Instances))
	}
}

func TestBuildUpdate_WithInstanceAndSubtype_RoundTrips(t *testing.T) {
	spec := UpdateSpec{
		Zone: "example.com.",
		Host: "myhost.example.com.",
		Key:  testHostKey("myhost.example.com."),
		Instances: []InstanceSpec{
			{
				Name:        "Printer._ipps._tcp.example.com.",
				ServiceType: "_ipps._tcp.example.com.",
				Subtypes:    []string{"_universal._sub._ipps._tcp.example.com."},
				Port:        631,
				TXT:         []string{"txtvers=1", "rp=ipp/print"},
			},
		},
		Lease:    30,
		KeyLease: 1209600,
	}
	msg, err := BuildUpdate(spec)
	if err != nil {
		t.Fatalf("BuildUpdate: %v", err)
	}

	cu, err := Validate(msg)
	if err != nil {
		t.Fatalf("Validate(BuildUpdate(...)): %v", err)
	}
	if len(cu.Instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(cu.Instances))
	}
	inst := cu.Instances[0]
	if inst.SRV == nil || inst.SRV.Port != 631 || inst.SRV.Target != spec.Host {
		t.Fatalf("unexpected SRV: %+v", inst.SRV)
	}
	// One TXT RR carrying two character-strings in its RDATA -- a single "add," not two.
	// Deliberate: mDNSResponder's own registrar rejects a second, separate TXT RR add
	// outright (see TestClassify_MultipleTXTAdds's doc comment), so this is also the
	// interop-safe encoding for multi-value TXT content, not just a valid one.
	if len(inst.TXT) != 1 {
		t.Fatalf("expected exactly 1 TXT add, got %d", len(inst.TXT))
	}
	if got := inst.TXT[0].TXT.Txt; len(got) != 2 || got[0] != "txtvers=1" || got[1] != "rp=ipp/print" {
		t.Fatalf("unexpected TXT RDATA strings: %v", got)
	}
	if inst.Key != nil {
		t.Fatalf("expected the instance to inherit the host's key (no explicit KEY add), got %+v", inst.Key)
	}
	if len(cu.Discovery) != 2 { // base type + 1 subtype
		t.Fatalf("expected 2 Service Discovery adds (base + subtype), got %d", len(cu.Discovery))
	}
	foundBase, foundSubtype := false, false
	for _, d := range cu.Discovery {
		switch d.Name {
		case "_ipps._tcp.example.com.":
			foundBase = true
		case "_universal._sub._ipps._tcp.example.com.":
			foundSubtype = true
		}
		if d.Target != inst.Name {
			t.Fatalf("discovery target = %q, want %q", d.Target, inst.Name)
		}
	}
	if !foundBase || !foundSubtype {
		t.Fatalf("expected both base-type and subtype PTR adds, got: %+v", cu.Discovery)
	}
}

func TestBuildUpdate_NoTXT_DefaultsToOneEmptyString(t *testing.T) {
	spec := UpdateSpec{
		Zone: "example.com.",
		Host: "myhost.example.com.",
		Key:  testHostKey("myhost.example.com."),
		Instances: []InstanceSpec{
			{Name: "Printer._ipps._tcp.example.com.", ServiceType: "_ipps._tcp.example.com.", Port: 631},
		},
		Lease:    30,
		KeyLease: 1209600,
	}
	msg, err := BuildUpdate(spec)
	if err != nil {
		t.Fatalf("BuildUpdate: %v", err)
	}
	cu, err := Validate(msg)
	if err != nil {
		t.Fatalf("Validate(BuildUpdate(...)): %v", err)
	}
	if len(cu.Instances) != 1 || len(cu.Instances[0].TXT) != 1 {
		t.Fatalf("expected exactly 1 (default, empty) TXT add, got: %+v", cu.Instances)
	}
}

func TestBuildUpdate_ExplicitInstanceKey_MustMatchHostMaterial(t *testing.T) {
	hostKey := testHostKey("myhost.example.com.")
	spec := UpdateSpec{
		Zone: "example.com.",
		Host: "myhost.example.com.",
		Key:  hostKey,
		Instances: []InstanceSpec{
			{
				Name: "Printer._ipps._tcp.example.com.", ServiceType: "_ipps._tcp.example.com.", Port: 631,
				Key: hostKey, // same material, explicit anyway -- S3.2.5.1 permits this
			},
		},
		Lease:    30,
		KeyLease: 1209600,
	}
	msg, err := BuildUpdate(spec)
	if err != nil {
		t.Fatalf("BuildUpdate: %v", err)
	}
	cu, err := Validate(msg)
	if err != nil {
		t.Fatalf("Validate(BuildUpdate(...)): %v", err)
	}
	if cu.Instances[0].Key == nil {
		t.Fatalf("expected an explicit instance KEY to be preserved")
	}
	if cu.Instances[0].Key.Flags != 0 {
		t.Fatalf("explicit instance KEY flags = %d, want 0", cu.Instances[0].Key.Flags)
	}
}

func TestBuildUpdate_RemovalShapedInstance(t *testing.T) {
	spec := UpdateSpec{
		Zone:      "example.com.",
		Host:      "myhost.example.com.",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		Key:       testHostKey("myhost.example.com."),
		Instances: []InstanceSpec{
			{Name: "Printer._ipps._tcp.example.com.", Remove: true},
		},
		Lease:    30,
		KeyLease: 1209600,
	}
	msg, err := BuildUpdate(spec)
	if err != nil {
		t.Fatalf("BuildUpdate: %v", err)
	}
	cu, err := Validate(msg)
	if err != nil {
		t.Fatalf("Validate(BuildUpdate(...)): %v", err)
	}
	if len(cu.Instances) != 1 || cu.Instances[0].SRV != nil {
		t.Fatalf("expected 1 removal-shaped instance, got: %+v", cu.Instances)
	}
	if len(cu.Discovery) != 0 {
		t.Fatalf("expected no Service Discovery adds for a removal-shaped instance, got: %+v", cu.Discovery)
	}
}

func TestBuildUpdate_HostRemoval_NoAddresses(t *testing.T) {
	spec := UpdateSpec{
		Zone:     "example.com.",
		Host:     "myhost.example.com.",
		Key:      testHostKey("myhost.example.com."),
		Lease:    30,
		KeyLease: 1209600,
	}
	msg, err := BuildUpdate(spec)
	if err != nil {
		t.Fatalf("BuildUpdate: %v", err)
	}
	cu, err := Validate(msg)
	if err != nil {
		t.Fatalf("Validate(BuildUpdate(...)): %v", err)
	}
	if len(cu.Host.Addresses) != 0 {
		t.Fatalf("expected 0 host addresses (removal fallback), got %d", len(cu.Host.Addresses))
	}
}

func TestBuildUpdate_IPv6Address(t *testing.T) {
	spec := UpdateSpec{
		Zone:      "example.com.",
		Host:      "myhost.example.com.",
		Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		Key:       testHostKey("myhost.example.com."),
		Lease:     30,
		KeyLease:  1209600,
	}
	msg, err := BuildUpdate(spec)
	if err != nil {
		t.Fatalf("BuildUpdate: %v", err)
	}
	cu, err := Validate(msg)
	if err != nil {
		t.Fatalf("Validate(BuildUpdate(...)): %v", err)
	}
	if len(cu.Host.Addresses) != 1 {
		t.Fatalf("expected 1 host address, got %d", len(cu.Host.Addresses))
	}
	if _, ok := cu.Host.Addresses[0].(*dns.AAAA); !ok {
		t.Fatalf("expected an AAAA record, got %T", cu.Host.Addresses[0])
	}
}

func TestBuildUpdate_Rejections(t *testing.T) {
	base := UpdateSpec{
		Zone: "example.com.", Host: "myhost.example.com.", Key: testHostKey("myhost.example.com."),
		Lease: 30, KeyLease: 1209600,
	}

	t.Run("missing zone", func(t *testing.T) {
		s := base
		s.Zone = ""
		if _, err := BuildUpdate(s); err == nil {
			t.Fatal("expected an error for a missing zone")
		}
	})
	t.Run("missing host", func(t *testing.T) {
		s := base
		s.Host = ""
		if _, err := BuildUpdate(s); err == nil {
			t.Fatal("expected an error for a missing host")
		}
	})
	t.Run("missing key", func(t *testing.T) {
		s := base
		s.Key = nil
		if _, err := BuildUpdate(s); err == nil {
			t.Fatal("expected an error for a missing key")
		}
	})
	t.Run("lease exceeds key-lease", func(t *testing.T) {
		s := base
		s.Lease = 3600
		s.KeyLease = 60
		if _, err := BuildUpdate(s); err == nil {
			t.Fatal("expected an error when LEASE > KEY-LEASE")
		}
	})
	t.Run("instance with no name", func(t *testing.T) {
		s := base
		s.Instances = []InstanceSpec{{ServiceType: "_ipps._tcp.example.com.", Port: 631}}
		if _, err := BuildUpdate(s); err == nil {
			t.Fatal("expected an error for an instance with no name")
		}
	})
	t.Run("live instance with no service type", func(t *testing.T) {
		s := base
		s.Instances = []InstanceSpec{{Name: "Printer._ipps._tcp.example.com.", Port: 631}}
		if _, err := BuildUpdate(s); err == nil {
			t.Fatal("expected an error for a live instance with no service type")
		}
	})
}
