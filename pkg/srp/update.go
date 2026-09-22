// update.go builds an unsigned RFC 9665 SRP UPDATE message from a declarative spec -- the
// requester-side counterpart to Classify/Validate. Pure logic: no network I/O, no crypto
// beyond shaping the KEY RR from already-generated key material -- pkg/srp stays
// network-free; client/srp owns key generation, discovery,
// scheduling, and actually sending the result.
package srp

import (
	"fmt"
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

// InstanceSpec describes one Service Description Instruction (plus its Service Discovery
// PTR add(s)) to include in a built update. Every field is a fully-qualified name -- this
// package stays free of "join a label onto a domain" ergonomics, which belongs to the
// caller (client/srp).
type InstanceSpec struct {
	// Name is the service instance's own FQDN, e.g. "MyPrinter._ipps._tcp.example.com."
	Name string
	// ServiceType is the base service type's FQDN (the Service Discovery PTR's owner
	// name), e.g. "_ipps._tcp.example.com."
	ServiceType string
	// Subtypes are additional DNS-SD subtype FQDNs (RFC 6763 S7.1) naming the same
	// instance, e.g. "_universal._sub._ipps._tcp.example.com." -- each gets its own PTR
	// add, always emitted after ServiceType's (Classify requires a subtype PTR add to be
	// preceded, in the same update, by a base-type PTR add with the same target).
	Subtypes []string
	Port     uint16
	// TXT holds the instance's TXT strings. A live instance needs at least one (S3.1); a
	// nil/empty slice defaults to a single empty string, matching common practice (and
	// RFC 9665 Appendix C's own example, `TXT ""`).
	TXT []string
	// Key is an explicit KEY for this instance, or nil to inherit the Host Description's
	// key (S3.2.5.1's normal case, and what BuildUpdate always assumes for Remove).
	Key *dns.KEY
	// Remove makes this a removal-shaped Service Description: a bare Delete All RRsets,
	// no SRV/TXT/PTR at all (S3.3.1.1's second bullet). ServiceType/Subtypes/Port/TXT/Key
	// are ignored when true.
	Remove bool
}

// UpdateSpec is everything BuildUpdate needs to construct one SRP UPDATE.
type UpdateSpec struct {
	Zone      string // Zone Section name; must equal Host's own registration domain
	Host      string // Host Description FQDN
	Addresses []netip.Addr
	// Key is the Host Description's KEY RR. Only its algorithm/protocol/public-key
	// material is used -- BuildUpdate overwrites Hdr.Name/Hdr.Class/Hdr.TTL to match Host
	// and KeyLease, and unconditionally zeroes Flags (S3.2.5.1/S3.3.3: requesters MUST
	// send flags 0, regardless of what the caller's key material happens to carry).
	Key       *dns.KEY
	Instances []InstanceSpec
	Lease     uint32
	KeyLease  uint32
}

// BuildUpdate constructs an unsigned SRP UPDATE: the Host Description Instruction
// (delete-all + address adds + KEY), one Service Description Instruction per instance
// (delete-all + SRV + TXT, or a bare delete-all for Remove), one Service Discovery
// Instruction (PTR add) per live instance's service type and subtype, and an 8-byte
// Update-Lease option. It always restates every instruction fully -- S3.2's "no lightweight
// refresh": there is no partial-update form, so a caller wanting an instance to remain
// discoverable must pass it again on every call (S4.5/S10 item 10) -- BuildUpdate itself has
// no memory of a previous call.
//
// The result is unsigned; sign it with pkg/sig0.SignMessage using the same key material as
// spec.Key before sending.
func BuildUpdate(spec UpdateSpec) (*dns.Msg, error) {
	if spec.Zone == "" {
		return nil, fmt.Errorf("srp: BuildUpdate: zone is required")
	}
	if spec.Host == "" {
		return nil, fmt.Errorf("srp: BuildUpdate: host is required")
	}
	if spec.Key == nil {
		return nil, fmt.Errorf("srp: BuildUpdate: key is required")
	}
	if spec.Lease > spec.KeyLease {
		return nil, fmt.Errorf("srp: BuildUpdate: lease (%d) must not exceed key-lease (%d)", spec.Lease, spec.KeyLease)
	}

	msg := dns.NewMsg(spec.Zone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("srp: BuildUpdate: failed to construct message for zone %q", spec.Zone)
	}
	msg.Opcode = dns.OpcodeUpdate

	msg.Ns = append(msg.Ns, deleteAllRR(spec.Host))
	for _, addr := range spec.Addresses {
		if addr.Is4() {
			msg.Ns = append(msg.Ns, &dns.A{Hdr: dns.Header{Name: spec.Host, Class: dns.ClassINET, TTL: spec.Lease}, A: rdata.A{Addr: addr}})
		} else {
			msg.Ns = append(msg.Ns, &dns.AAAA{Hdr: dns.Header{Name: spec.Host, Class: dns.ClassINET, TTL: spec.Lease}, AAAA: rdata.AAAA{Addr: addr}})
		}
	}
	msg.Ns = append(msg.Ns, hostKeyRR(spec.Key, spec.Host, spec.KeyLease))

	for _, inst := range spec.Instances {
		if inst.Name == "" {
			return nil, fmt.Errorf("srp: BuildUpdate: instance name is required")
		}
		msg.Ns = append(msg.Ns, deleteAllRR(inst.Name))
		if inst.Remove {
			continue
		}
		if inst.ServiceType == "" {
			return nil, fmt.Errorf("srp: BuildUpdate: instance %s: service type is required unless Remove", inst.Name)
		}

		srv := &dns.SRV{
			Hdr: dns.Header{Name: inst.Name, Class: dns.ClassINET, TTL: spec.Lease},
			SRV: rdata.SRV{Priority: 0, Weight: 0, Port: inst.Port, Target: spec.Host},
		}
		msg.Ns = append(msg.Ns, srv)

		txt := inst.TXT
		if len(txt) == 0 {
			txt = []string{""}
		}
		txtRR := &dns.TXT{Hdr: dns.Header{Name: inst.Name, Class: dns.ClassINET, TTL: spec.Lease}}
		txtRR.TXT.Txt = txt
		msg.Ns = append(msg.Ns, txtRR)

		if inst.Key != nil {
			msg.Ns = append(msg.Ns, hostKeyRR(inst.Key, inst.Name, spec.KeyLease))
		}

		msg.Ns = append(msg.Ns, ptrAdd(inst.ServiceType, inst.Name, spec.Lease))
		for _, subtype := range inst.Subtypes {
			msg.Ns = append(msg.Ns, ptrAdd(subtype, inst.Name, spec.Lease))
		}
	}

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(dns.DefaultMsgSize)
	lo := leasepkg.Encode8Byte(spec.Lease, spec.KeyLease)
	if err := lo.Encode(opt); err != nil {
		return nil, fmt.Errorf("srp: BuildUpdate: encode Update-Lease option: %w", err)
	}
	msg.Extra = append(msg.Extra, opt)

	return msg, nil
}

// hostKeyRR returns a copy of key with its owner name/class/TTL set for name and ttl, and
// Flags unconditionally zeroed (S3.2.5.1/S3.3.3's requester-side MUST -- see UpdateSpec.Key).
func hostKeyRR(key *dns.KEY, name string, ttl uint32) *dns.KEY {
	cpy := *key
	cpy.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: ttl}
	cpy.Flags = 0
	return &cpy
}

func ptrAdd(owner, target string, ttl uint32) *dns.PTR {
	p := &dns.PTR{}
	p.Hdr = dns.Header{Name: owner, Class: dns.ClassINET, TTL: ttl}
	p.Ptr = target
	return p
}

// deleteAllRR builds a raw RFC 2136 S2.5.3 "Delete All RRsets From A Name" (class ANY) --
// this fork's presentation-format parser can't produce this shape. Named
// distinctly from srp_test.go's own (test-only, so unusable from this production file)
// deleteAll helper of the same shape.
func deleteAllRR(name string) *dns.ANY {
	return &dns.ANY{Hdr: dns.Header{Name: name, Class: dns.ClassANY, TTL: 0}}
}
