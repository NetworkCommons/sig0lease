package agent

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestInterfaceAddresses_Flags checks InterfaceAddresses against /proc/net/if_inet6, which
// shows each IPv6 address's flags: a temporary, tentative or duplicate global address is left
// out, any other kept.
func TestInterfaceAddresses_Flags(t *testing.T) {
	got, err := InterfaceAddresses()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("/proc/net/if_inet6")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("no IPv6: /proc/net/if_inet6 is missing")
	}
	if err != nil {
		t.Fatal(err)
	}
	const unpublished = syscall.IFA_F_TEMPORARY | syscall.IFA_F_TENTATIVE | syscall.IFA_F_DADFAILED
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// The address, the interface's index, the prefix length, the scope, the flags (all
		// hexadecimal) and the interface's name.
		f := strings.Fields(line)
		if len(f) != 6 {
			t.Fatalf("/proc/net/if_inet6 line %q", line)
		}
		raw, err := hex.DecodeString(f[0])
		if err != nil {
			t.Fatalf("/proc/net/if_inet6 line %q: %v", line, err)
		}
		a, ok := netip.AddrFromSlice(raw)
		flags, err := strconv.ParseUint(f[4], 16, 32)
		if !ok || err != nil {
			t.Fatalf("/proc/net/if_inet6 line %q: address %v, flags %v", line, ok, err)
		}
		if !a.IsGlobalUnicast() {
			continue
		}
		if want := flags&unpublished == 0; slices.Contains(got, a) != want {
			t.Errorf("%s on %s, flags %#x: returned %v, want %v", a, f[5], flags, !want, want)
		}
		checked++
	}
	t.Logf("checked %d global IPv6 addresses", checked)
}
