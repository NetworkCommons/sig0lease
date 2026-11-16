//go:build !linux && !darwin

package agent

import (
	"net"
	"net/netip"
)

// unpublishedIPv6 cannot tell temporary addresses from the others here, so InterfaceAddresses
// leaves out none.
func unpublishedIPv6() (unpublished func(net.Interface, netip.Addr) (bool, error), done func(), err error) {
	return func(net.Interface, netip.Addr) (bool, error) { return false, nil }, func() {}, nil
}
