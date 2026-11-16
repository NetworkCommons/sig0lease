package agent

import (
	"net"
	"net/netip"
	"slices"
	"testing"
)

// TestInterfaceAddresses_LeavesOutOnlyIPv6 checks InterfaceAddresses against net.InterfaceAddrs:
// it returns every IPv4 address, and nothing that is not an address of this machine.
func TestInterfaceAddresses_LeavesOutOnlyIPv6(t *testing.T) {
	got, err := InterfaceAddresses()
	if err != nil {
		t.Fatal(err)
	}
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var all []netip.Addr
	for _, a := range ifAddrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				all = append(all, ip.Unmap())
			}
		}
	}
	for _, a := range all {
		if a.Is4() && !slices.Contains(got, a) {
			t.Errorf("IPv4 address %s left out", a)
		}
	}
	for _, a := range got {
		if !slices.Contains(all, a) {
			t.Errorf("%s returned, not an address of this machine (%v)", a, all)
		}
	}
}
