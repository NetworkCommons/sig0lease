package agent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

// IPv6 address flags, from <netinet6/in6_var.h>.
const (
	in6IffAnycast    = 0x01
	in6IffTentative  = 0x02
	in6IffDuplicated = 0x04
	in6IffDetached   = 0x08
	in6IffTemporary  = 0x80
)

// in6Ifreq is <netinet6/in6_var.h>'s struct in6_ifreq: the interface's name, then a union of 272
// bytes (its largest member, struct icmp6_ifstat, is 34 counters of 64 bits), which holds
// ifru_addr on the way in and ifru_flags6, an int, on the way out.
type in6Ifreq struct {
	name [syscall.IFNAMSIZ]byte
	addr syscall.RawSockaddrInet6
	_    [272 - syscall.SizeofSockaddrInet6]byte
}

// siocgifaflagIn6 is SIOCGIFAFLAG_IN6, _IOWR('i', 73, struct in6_ifreq).
const siocgifaflagIn6 = 0xc0000000 | unsafe.Sizeof(in6Ifreq{})<<16 | 'i'<<8 | 73

// unpublishedIPv6 asks the kernel for each IPv6 address's flags (SIOCGIFAFLAG_IN6), as
// mDNSResponder does, and tells InterfaceAddresses to leave out those that are temporary,
// tentative, duplicate, detached or anycast. done closes the socket it asks through.
func unpublishedIPv6() (unpublished func(net.Interface, netip.Addr) (bool, error), done func(), err error) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, nil, os.NewSyscallError("socket", err)
	}
	return func(ifi net.Interface, a netip.Addr) (bool, error) {
		if len(ifi.Name) >= syscall.IFNAMSIZ {
			return false, fmt.Errorf("interface name longer than %d bytes", syscall.IFNAMSIZ-1)
		}
		var req in6Ifreq
		copy(req.name[:], ifi.Name)
		req.addr = syscall.RawSockaddrInet6{Len: syscall.SizeofSockaddrInet6, Family: syscall.AF_INET6, Addr: a.As16()}
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocgifaflagIn6, uintptr(unsafe.Pointer(&req)))
		switch {
		case errors.Is(errno, syscall.EADDRNOTAVAIL), errors.Is(errno, syscall.ENXIO):
			return true, nil // the address, or its interface, went since it was listed
		case errno != 0:
			return false, os.NewSyscallError("ioctl SIOCGIFAFLAG_IN6", errno)
		}
		flags := *(*int32)(unsafe.Pointer(&req.addr))
		return flags&(in6IffAnycast|in6IffTentative|in6IffDuplicated|in6IffDetached|in6IffTemporary) != 0, nil
	}, func() { syscall.Close(fd) }, nil
}
