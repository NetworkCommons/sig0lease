// Package clienttest has the registrar answers the client packages' tests share.
package clienttest

import (
	"fmt"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// Granted is a registrar's NOERROR answer granting lease and keyLease: the 8-byte Update
// Lease option echoed (RFC 9664 S4).
func Granted(lease, keyLease uint32) *dns.Msg {
	resp := &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(dns.DefaultMsgSize)
	if err := leasepkg.Encode8Byte(lease, keyLease).Encode(opt); err != nil {
		panic(fmt.Sprintf("clienttest.Granted(%d, %d): %v", lease, keyLease, err))
	}
	resp.Extra = append(resp.Extra, opt)
	return resp
}

// Answer is a registrar's answer with rcode and nothing else.
func Answer(rcode uint16) *dns.Msg {
	return &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: rcode}}
}
