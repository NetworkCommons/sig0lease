// Package srp implements RFC 9665 (DNS-SD Service Registration Protocol) message
// classification and structural validation. It is pure logic: no network I/O, no lease
// store access -- see main/docs/rfc9665-srp-implementation-plan.md S4.1. FCFS
// (pkg/srp/fcfs.go, needs a store view) and the handler wiring (handlers/srp_handler.go)
// are later phases; this file covers Classify(), the first step of S4.3's happy path.
//
// The classification algorithm below closely follows the reference implementation in
// mDNSResponder/ServiceRegistration/srp-parse.c (srp_evaluate), which the plan's S12.3
// names as the cross-check for this package -- see the deliberate divergences noted
// inline (multiple TXT adds; the LEASE-independent host-removal fallback; no
// base-type-precedes-subtype requirement on PTR deletes).
package srp

import (
	"fmt"

	"codeberg.org/miekg/dns"
)

// HostDescription is RFC 9665 S3.3.1.3's (exactly one, per update) Host Description
// Instruction: a Delete All RRsets on the hostname, exactly one KEY add, and zero or more
// A/AAAA adds (zero addresses means "delete this host's registration").
type HostDescription struct {
	Name      string   // canonical (lower-cased, dot-terminated) hostname
	Delete    dns.RR   // the "Delete All RRsets From A Name" RR for Name
	Key       *dns.KEY // the Host Description's KEY add; nil until the key-matching pass fills it in
	Addresses []dns.RR // 0..n *dns.A / *dns.AAAA adds, in encounter order
}

// ServiceInstance is RFC 9665 S3.3.1.2's Service Description Instruction: a Delete All
// RRsets on the service-instance name, an optional KEY add (inherits the host's key when
// absent), and either an SRV+TXT pair (a live registration) or neither (a removal --
// S3.3.1.1's second bullet: a Service Discovery "Delete An RR From An RRSet" targets a
// Service Description shaped exactly this way).
type ServiceInstance struct {
	Name   string   // canonical service-instance name
	Delete dns.RR   // the "Delete All RRsets From A Name" RR for Name
	Key    *dns.KEY // explicit KEY add for this instance, or nil (inherits the host's key)
	SRV    *dns.SRV // nil for a removal-shaped instance
	// TXT holds every TXT add for this instance. RFC 9665's S3.1 table allows 1..n TXT
	// adds when SRV is present; mDNSResponder's own registrar (srp-parse.c) is stricter
	// and rejects a second TXT add outright -- this package follows the RFC text over
	// that implementation choice and allows more than one.
	TXT []*dns.TXT
	// removalShaped records whether this instance was created via an SRV/TXT sighting
	// (false) or is an "unconsumed" bare Delete-All with no SRV/TXT, discovered only
	// during reconciliation (true) -- see the S3.3.1.1 second-bullet case. A
	// removal-shaped instance is not required to be referenced by any Service Discovery
	// instruction in this update (matching srp-parse.c: such deletes are "presumed to be
	// removes of service instances previously registered" and can only actually be
	// confirmed against the lease store, not from message shape alone -- pkg/srp/fcfs.go's
	// job, not this file's).
	removalShaped bool
}

// ServiceDiscovery is one RFC 9665 S3.3.1.1 Service Discovery Instruction: a single PTR
// add or delete. Note there can be several of these sharing the same Name (one service
// type can list several instances) or the same Target (an instance can be discoverable
// under its base type and under one or more subtypes) -- each is still counted and
// validated as its own, separate instruction, never merged.
type ServiceDiscovery struct {
	Name   string // canonical owner name of the PTR (a service type, or a subtype name)
	Target string // canonical PTR target -- must name a ServiceInstance in the same update
	IsAdd  bool   // true: "Add To An RRSet"; false: "Delete An RR From An RRSet"
	RR     *dns.PTR
	// BaseType is non-empty when Name has the DNS-SD subtype shape
	// "<sub>._sub.<Service>.<Domain>" (RFC 6763 S7.1), and holds the base service type's
	// canonical name in that case.
	BaseType string
}

// ClassifiedUpdate is the result of a successful Classify(): every instruction found in
// the message, structurally cross-referenced (every Service Discovery target resolves to
// a ServiceInstance present in the same update; every SRV-bearing ServiceInstance targets
// the Host; every KEY add resolves to either the Host or a ServiceInstance and all KEY
// adds carry identical RDATA). It does not mean the update is authorized (FCFS, SIG(0)) or
// that TTLs/lease options are valid -- see Validate() for the remaining S3.3.2 checks
// Classify() deliberately leaves to it.
type ClassifiedUpdate struct {
	Host      *HostDescription
	Instances []*ServiceInstance // in first-sighting order
	Discovery []ServiceDiscovery // every Service Discovery instruction, in encounter order
}

// classifyState accumulates the single-pass scan before the reconciliation pass runs.
type classifyState struct {
	deletes   map[string]dns.RR // canonical name -> its Delete All RRsets RR
	consumed  map[string]bool   // canonical name -> claimed by host or an SRV/TXT instance
	host      *HostDescription
	instances map[string]*ServiceInstance
	order     []*ServiceInstance // encounter order, for deterministic output
	discovery []ServiceDiscovery
	ptrAdds   []int // indices into discovery that are adds, for the subtype-precedes check
	keyAdds   []*dns.KEY
}

// Classify extracts and cross-references every RFC 9665 instruction in msg's Update (Ns)
// section. It returns an error -- never a partial/best-effort result -- for anything that
// doesn't fit one of the three recognized instruction shapes; per S3.3.2, that means the
// message is not an SRP update at all. Classify does not look at msg.Question, msg.Answer,
// or the lease option -- callers needing the "no prerequisites" / "single zone" / "lease
// option present" checks use Validate, which wraps this.
func Classify(msg *dns.Msg) (*ClassifiedUpdate, error) {
	if msg == nil {
		return nil, fmt.Errorf("srp: nil message")
	}

	st := &classifyState{
		deletes:   make(map[string]dns.RR),
		consumed:  make(map[string]bool),
		instances: make(map[string]*ServiceInstance),
	}

	// First pass: collect every Delete All RRsets up front, so an add that happens to
	// arrive (in this fork's Ns ordering) before its own delete is not rejected purely on
	// ordering grounds -- RFC 2136/9665 requires deletes to precede the adds they'd
	// otherwise be clobbered by at the *authoritative server*, which is a wire-order
	// concern for constructUpstreamUpdate (pkg/updatecore, a later phase), not a
	// classification concern here.
	for _, rr := range msg.Ns {
		if rr == nil || rr.Header() == nil {
			return nil, fmt.Errorf("srp: nil RR in Update section")
		}
		if v, ok := rr.(*dns.ANY); ok {
			name := canonicalName(v.Hdr.Name)
			if _, dup := st.deletes[name]; dup {
				return nil, fmt.Errorf("srp: more than one Delete All RRsets for %s", name)
			}
			st.deletes[name] = rr
		}
	}

	// Second pass: classify every non-delete-all RR.
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.ANY); ok {
			continue // already handled above
		}
		hdr := rr.Header()
		name := canonicalName(hdr.Name)

		switch v := rr.(type) {
		case *dns.KEY:
			if hdr.Class != dns.ClassINET {
				return nil, fmt.Errorf("srp: unrecognized KEY update (class %s) at %s -- SRP only uses KEY adds", dns.ClassToString[hdr.Class], name)
			}
			st.keyAdds = append(st.keyAdds, v)

		case *dns.A:
			if hdr.Class != dns.ClassINET {
				return nil, fmt.Errorf("srp: unrecognized A update (class %s) at %s -- SRP only uses A/AAAA adds", dns.ClassToString[hdr.Class], name)
			}
			if err := st.addHostAddress(name, rr); err != nil {
				return nil, err
			}

		case *dns.AAAA:
			if hdr.Class != dns.ClassINET {
				return nil, fmt.Errorf("srp: unrecognized AAAA update (class %s) at %s -- SRP only uses A/AAAA adds", dns.ClassToString[hdr.Class], name)
			}
			if err := st.addHostAddress(name, rr); err != nil {
				return nil, err
			}

		case *dns.SRV:
			if hdr.Class != dns.ClassINET {
				return nil, fmt.Errorf("srp: unrecognized SRV update (class %s) at %s -- SRP only uses SRV adds", dns.ClassToString[hdr.Class], name)
			}
			inst, err := st.instanceFor(name)
			if err != nil {
				return nil, err
			}
			if inst.SRV != nil {
				return nil, fmt.Errorf("srp: more than one SRV add for service instance %s", name)
			}
			inst.SRV = v

		case *dns.TXT:
			if hdr.Class != dns.ClassINET {
				return nil, fmt.Errorf("srp: unrecognized TXT update (class %s) at %s -- SRP only uses TXT adds", dns.ClassToString[hdr.Class], name)
			}
			inst, err := st.instanceFor(name)
			if err != nil {
				return nil, err
			}
			inst.TXT = append(inst.TXT, v)

		case *dns.PTR:
			if err := st.addPTR(name, v, hdr); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("srp: unrecognized RR type %s at %s -- not a recognized SRP instruction", dns.TypeToString[dns.RRToType(rr)], name)
		}
	}

	if err := st.reconcile(); err != nil {
		return nil, err
	}

	return &ClassifiedUpdate{Host: st.host, Instances: st.order, Discovery: st.discovery}, nil
}

// addHostAddress implements S3.3.1.3: an A/AAAA add must be preceded by a Delete All
// RRsets for its name, and every A/AAAA add in the update must be at the *same* name --
// "an SRP Update MUST contain exactly one Host Description Instruction" (S3.3.2).
func (st *classifyState) addHostAddress(name string, rr dns.RR) error {
	del, ok := st.deletes[name]
	if !ok {
		return fmt.Errorf("srp: %s ADD for %s with no preceding Delete All RRsets", dns.TypeToString[dns.RRToType(rr)], name)
	}
	if st.host == nil {
		st.host = &HostDescription{Name: name, Delete: del}
		st.consumed[name] = true
	} else if st.host.Name != name {
		return fmt.Errorf("srp: more than one hostname in update (%s and %s) -- an SRP update may contain only one Host Description", st.host.Name, name)
	}
	st.host.Addresses = append(st.host.Addresses, rr)
	return nil
}

// instanceFor returns the ServiceInstance for name, creating it (and consuming its
// pending Delete All RRsets) on first sight, implementing S3.3.1.2's "must be preceded by
// a Delete All RRsets for the service instance name."
func (st *classifyState) instanceFor(name string) (*ServiceInstance, error) {
	if inst, ok := st.instances[name]; ok {
		return inst, nil
	}
	del, ok := st.deletes[name]
	if !ok {
		return nil, fmt.Errorf("srp: ADD for service instance %s with no preceding Delete All RRsets", name)
	}
	inst := &ServiceInstance{Name: name, Delete: del}
	st.instances[name] = inst
	st.order = append(st.order, inst)
	st.consumed[name] = true
	return inst, nil
}

// addPTR implements S3.3.1.1's shape check (exactly one add or delete of a PTR RR) and
// the DNS-SD subtype convention (RFC 6763 S7.1): a subtype PTR add must be preceded, in
// this same update, by a base-type PTR add with the identical target -- mirroring
// srp-parse.c's ordering check for adds. Deliberately not enforced for PTR deletes: a
// client removing a subtype registration has no protocol reason to also be adding (or
// re-adding) the base type in the same message, and RFC 9665's own text ties the
// subtype/base-type relationship to "Service Discovery Instructions" generally without
// tying deletes to a co-occurring base-type add the way srp-parse.c's implementation
// happens to.
func (st *classifyState) addPTR(name string, v *dns.PTR, hdr *dns.Header) error {
	baseType, isSubtype := isSubtypePTROwner(name)
	target := canonicalName(v.Ptr)

	switch hdr.Class {
	case dns.ClassINET:
		if isSubtype {
			found := false
			for _, i := range st.ptrAdds {
				d := st.discovery[i]
				if d.BaseType == "" && d.Name == baseType && d.Target == target {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("srp: subtype PTR add %s (target %s) has no preceding base-type PTR add for %s with the same target", name, target, baseType)
			}
		}
		st.ptrAdds = append(st.ptrAdds, len(st.discovery))
		st.discovery = append(st.discovery, ServiceDiscovery{Name: name, Target: target, IsAdd: true, RR: v, BaseType: baseTypeOrEmpty(isSubtype, baseType)})
		return nil

	case dns.ClassNONE:
		st.discovery = append(st.discovery, ServiceDiscovery{Name: name, Target: target, IsAdd: false, RR: v, BaseType: baseTypeOrEmpty(isSubtype, baseType)})
		return nil

	default:
		return fmt.Errorf("srp: unrecognized PTR update (class %s) at %s -- SRP only uses PTR adds/deletes", dns.ClassToString[hdr.Class], name)
	}
}

func baseTypeOrEmpty(isSubtype bool, baseType string) string {
	if isSubtype {
		return baseType
	}
	return ""
}

// reconcile runs the whole-update cross-checks that need every instruction to have been
// seen first: the host-removal fallback, service-instance-vs-Service-Discovery
// cross-references, every Service Instance's SRV target naming the Host, unconsumed
// Delete-All-RRsets becoming removal-shaped instances, and the KEY-ownership pass.
func (st *classifyState) reconcile() error {
	// Host-removal fallback (S3.3.1.3's "zero Add operations, in the case of deleting a
	// registration"): if no A/AAAA established a host, the first KEY add whose name has
	// a pending Delete All RRsets becomes the (address-less) host. Deliberately
	// LEASE-independent, unlike srp-parse.c's host_lease==0 gate -- Classify() never sees
	// the lease option (Validate(), a layer up, owns that -- see the package doc
	// comment), and the structural shape ("a bare delete-all whose name carries the
	// update's key") is sufficient to identify the host regardless of what lease value
	// Validate() later finds attached.
	if st.host == nil {
		for _, k := range st.keyAdds {
			name := canonicalName(k.Hdr.Name)
			if del, ok := st.deletes[name]; ok && !st.consumed[name] {
				st.host = &HostDescription{Name: name, Delete: del}
				st.consumed[name] = true
				break
			}
		}
	}
	if st.host == nil {
		return fmt.Errorf("srp: update does not include a Host Description (no Delete-All-RRsets name has an A/AAAA add, and none unclaimed carries a KEY add)")
	}

	// Every PTR add's target must resolve to a ServiceInstance in this same update
	// (S3.3.1.1, first bullet) that is SRV/TXT-shaped (a live registration, not a
	// removal) -- and every such instance must be referenced by at least one PTR add.
	referenced := make(map[string]bool, len(st.instances))
	for _, i := range st.ptrAdds {
		d := st.discovery[i]
		inst, ok := st.instances[d.Target]
		if !ok || inst.SRV == nil {
			return fmt.Errorf("srp: Service Discovery add %s targets %s, which has no Service Description (Delete-All-RRsets + SRV/TXT adds) in this update", d.Name, d.Target)
		}
		referenced[d.Target] = true
	}
	for name, inst := range st.instances {
		if inst.SRV == nil {
			continue // removal-shaped instances are exempt -- see the ServiceInstance doc comment
		}
		if len(inst.TXT) == 0 {
			return fmt.Errorf("srp: service instance %s has an SRV add with no TXT add (S3.3.1.2 requires at least one TXT add when SRV is present)", name)
		}
		if canonicalName(inst.SRV.Target) != st.host.Name {
			return fmt.Errorf("srp: service instance %s's SRV target %s does not match the Host Description name %s", name, inst.SRV.Target, st.host.Name)
		}
		if !referenced[name] {
			return fmt.Errorf("srp: service instance %s is not referenced by any Service Discovery add in this update", name)
		}
	}

	// Every Delete-All-RRsets not yet claimed by the host or an SRV/TXT instance becomes
	// a removal-shaped ServiceInstance (S3.3.1.1's second bullet / S3.3.1.2's "no SRV, no
	// TXT" case). Whether it actually corresponds to something previously registered is
	// for the lease store to say (pkg/srp/fcfs.go, a later phase) -- matching
	// srp-parse.c's own "these can't be validated here" deferral.
	for name, del := range st.deletes {
		if st.consumed[name] {
			continue
		}
		inst := &ServiceInstance{Name: name, Delete: del, removalShaped: true}
		st.instances[name] = inst
		st.order = append(st.order, inst)
		st.consumed[name] = true
	}

	// KEY-ownership pass (S3.2.5.1): every KEY add's name must be either the host or a
	// service instance, and -- once every KEY has been resolved -- all of them must carry
	// byte-identical RDATA (checked by Validate(), which needs to compare across the
	// Host's and every ServiceInstance's resolved Key field; Classify() only resolves
	// ownership here).
	for _, k := range st.keyAdds {
		name := canonicalName(k.Hdr.Name)
		switch {
		case name == st.host.Name:
			if st.host.Key == nil {
				st.host.Key = k
			} else {
				return fmt.Errorf("srp: more than one KEY add for host %s", name)
			}
		default:
			inst, ok := st.instances[name]
			if !ok {
				return fmt.Errorf("srp: KEY add for %s, which is neither the Host Description name nor a service instance name", name)
			}
			if inst.Key != nil {
				return fmt.Errorf("srp: more than one KEY add for service instance %s", name)
			}
			inst.Key = k
		}
	}
	if st.host.Key == nil {
		return fmt.Errorf("srp: Host Description %s has no KEY add (S3.3.1.3 requires exactly one)", st.host.Name)
	}

	return nil
}
