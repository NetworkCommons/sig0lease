package agent

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
)

// unpublishedIPv6 reads every IPv6 address's flags from the kernel (RTM_GETADDR), and tells
// InterfaceAddresses to leave out those that are temporary, tentative or failed duplicate
// address detection. done does nothing.
func unpublishedIPv6() (unpublished func(net.Interface, netip.Addr) (bool, error), done func(), err error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_INET6)
	if err != nil {
		return nil, nil, os.NewSyscallError("netlinkrib", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, nil, os.NewSyscallError("parsenetlinkmessage", err)
	}
	type ifAddr struct {
		index int
		addr  netip.Addr
	}
	flagged := map[ifAddr]bool{}
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.NLMSG_ERROR:
			if len(m.Data) < 4 {
				return nil, nil, fmt.Errorf("an NLMSG_ERROR message of %d bytes", len(m.Data))
			}
			return nil, nil, os.NewSyscallError("netlink RTM_GETADDR", syscall.Errno(-int32(binary.NativeEndian.Uint32(m.Data[:4]))))
		case syscall.RTM_NEWADDR:
		default:
			continue
		}
		// struct ifaddrmsg: family, prefix length, flags, scope (a byte each), then the
		// interface's index; IFA_LOCAL, if any, is the address, and IFA_ADDRESS the peer's.
		if len(m.Data) < syscall.SizeofIfAddrmsg {
			return nil, nil, fmt.Errorf("an RTM_NEWADDR message of %d bytes", len(m.Data))
		}
		flags, index := m.Data[2], int(binary.NativeEndian.Uint32(m.Data[4:8]))
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return nil, nil, os.NewSyscallError("parsenetlinkrouteattr", err)
		}
		var local, address []byte
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.IFA_LOCAL:
				local = a.Value
			case syscall.IFA_ADDRESS:
				address = a.Value
			}
		}
		if local != nil {
			address = local
		}
		addr, ok := netip.AddrFromSlice(address)
		if !ok {
			return nil, nil, fmt.Errorf("an RTM_NEWADDR message with an address of %d bytes", len(address))
		}
		if flags&(syscall.IFA_F_TEMPORARY|syscall.IFA_F_TENTATIVE|syscall.IFA_F_DADFAILED) != 0 {
			flagged[ifAddr{index, addr}] = true
		}
	}
	return func(ifi net.Interface, a netip.Addr) (bool, error) {
		return flagged[ifAddr{ifi.Index, a}], nil
	}, func() {}, nil
}
