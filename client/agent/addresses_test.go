package agent

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
)

// TestInterfaceAddresses_LeavesOutOnlyIPv6 checks InterfaceAddresses against net.Interfaces:
// it returns every IPv4 address of an interface that is up, and nothing that is not an address
// of such an interface.
func TestInterfaceAddresses_LeavesOutOnlyIPv6(t *testing.T) {
	got, err := InterfaceAddresses()
	if err != nil {
		t.Fatal(err)
	}
	ifis, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var up []netip.Addr
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		ifAddrs, err := ifi.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range ifAddrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					up = append(up, ip.Unmap())
				}
			}
		}
	}
	for _, a := range up {
		if a.Is4() && !slices.Contains(got, a) {
			t.Errorf("IPv4 address %s left out", a)
		}
	}
	for _, a := range got {
		if !slices.Contains(up, a) {
			t.Errorf("%s returned, not an address of an interface that is up (%v)", a, up)
		}
	}
}

// TestInterfaceAddresses_LeavesOutDownInterfaces checks interfaceAddresses on made-up
// interfaces: a down interface's addresses are left out without being read, as Docker's bridge
// keeps 172.17.0.1 on Linux while no container runs; an up interface's are returned, but for
// the IPv6 ones unpublished reports.
func TestInterfaceAddresses_LeavesOutDownInterfaces(t *testing.T) {
	ifis := []net.Interface{
		{Index: 1, Name: "en0", Flags: net.FlagUp | net.FlagRunning},
		{Index: 2, Name: "docker0"},
		{Index: 3, Name: "utun0", Flags: net.FlagUp},
	}
	byIndex := map[int][]string{
		1: {"192.168.2.9/24", "2a02:a469:7646::af29/64", "2a02:a469:7646::7e3/64", "fd4e:3732:3131::3d9/64"},
		2: {"172.17.0.1/16", "fd00:17::1/64"},
		3: {"10.8.0.2/32"},
	}
	addrs := func(ifi *net.Interface) ([]net.Addr, error) {
		if ifi.Flags&net.FlagUp == 0 {
			return nil, errors.New(ifi.Name + " read, but it is down")
		}
		var out []net.Addr
		for _, s := range byIndex[ifi.Index] {
			ip, n, err := net.ParseCIDR(s)
			if err != nil {
				t.Fatal(err)
			}
			n.IP = ip
			out = append(out, n)
		}
		return out, nil
	}
	temporary := netip.MustParseAddr("2a02:a469:7646::7e3")
	unpublished := func(_ net.Interface, a netip.Addr) (bool, error) { return a == temporary, nil }
	got, err := interfaceAddresses(ifis, addrs, unpublished)
	if err != nil {
		t.Fatal(err)
	}
	var want []netip.Addr
	for _, s := range []string{"192.168.2.9", "2a02:a469:7646::af29", "fd4e:3732:3131::3d9", "10.8.0.2"} {
		want = append(want, netip.MustParseAddr(s))
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
