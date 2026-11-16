package agent

import (
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestInterfaceAddresses_Flags checks InterfaceAddresses against ifconfig, which names each IPv6
// address's flags: a temporary, tentative, duplicate, detached or anycast global address is
// left out, any other kept.
func TestInterfaceAddresses_Flags(t *testing.T) {
	got, err := InterfaceAddresses()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/sbin/ifconfig", "-a").Output()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, line := range strings.Split(string(out), "\n") {
		// "inet6 <address>[%<zone>] prefixlen <n> [<flag>...] [scopeid <id>]"
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "inet6" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			t.Fatalf("ifconfig line %q: %v", line, err)
		}
		if !a.IsGlobalUnicast() {
			continue
		}
		want := true
		for _, flag := range f[2:] {
			switch flag {
			case "temporary", "tentative", "duplicated", "detached", "anycast":
				want = false
			}
		}
		if slices.Contains(got, a) != want {
			t.Errorf("%s (%s): returned %v, want %v", a, strings.Join(f[2:], " "), !want, want)
		}
		checked++
	}
	t.Logf("checked %d global IPv6 addresses", checked)
}
