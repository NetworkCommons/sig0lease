package srp

import (
	"fmt"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
)

// Validate runs Classify plus every remaining RFC 9665 S3.3.1/S3.3.2 structural check
// that needs more than the Update section alone: a single Zone Section entry, no
// prerequisites, a present and internally-consistent Update-Lease option, TTL consistency
// (S4 -- a MUST, reject rather than normalize, unlike the base RFC 9664 handler's
// pkg/updatecore.NormalizeTTLs), identical KEY RDATA across every KEY add, and flags-0 KEY
// adds (S3.2.5.1). It does not verify SIG(0) or FCFS -- those need the lease store and the
// SIG(0) signer identity, both outside this package's pure-logic scope (S4.3 steps 4-5).
//
// Assumes the caller has already confirmed msg.Opcode == dns.OpcodeUpdate (the router
// dispatch layer's job, not this package's) and that msg has been fully unpacked.
func Validate(msg *dns.Msg) (*ClassifiedUpdate, error) {
	if msg == nil {
		return nil, fmt.Errorf("srp: nil message")
	}

	// "MUST contain a single entry in the Zone Section" (S3.3.1).
	if len(msg.Question) != 1 {
		return nil, fmt.Errorf("srp: expected exactly one Zone Section entry, got %d", len(msg.Question))
	}

	// "A DNS update that contains any prerequisites is not an SRP update" (S3.3.2). In
	// RFC 2136 terms the Prerequisite section is what a non-update DNS message calls the
	// Answer section.
	if len(msg.Answer) != 0 {
		return nil, fmt.Errorf("srp: update contains %d prerequisite(s) -- not an SRP update", len(msg.Answer))
	}

	cu, err := Classify(msg)
	if err != nil {
		return nil, err
	}

	if err := validatePostClassify(msg, cu); err != nil {
		return nil, err
	}

	return cu, nil
}

// ValidateClassified runs every check Validate performs beyond Classify itself, against a
// ClassifiedUpdate the caller has already computed -- for a caller that has already run
// Classify once (e.g. handlers/srp_handler.go's Handle, which classifies in its own step 1
// to decide relevance before Validate would otherwise redundantly classify the identical
// message a second time in step 2). cu must be Classify(msg)'s own result for msg;
// behavior is undefined otherwise.
func ValidateClassified(msg *dns.Msg, cu *ClassifiedUpdate) error {
	if msg == nil {
		return fmt.Errorf("srp: nil message")
	}
	if len(msg.Question) != 1 {
		return fmt.Errorf("srp: expected exactly one Zone Section entry, got %d", len(msg.Question))
	}
	if len(msg.Answer) != 0 {
		return fmt.Errorf("srp: update contains %d prerequisite(s) -- not an SRP update", len(msg.Answer))
	}
	return validatePostClassify(msg, cu)
}

// validatePostClassify is every S3.3.2 check that needs a ClassifiedUpdate but not
// Classify() itself -- shared by Validate (which just computed cu) and ValidateClassified
// (whose caller already had one).
func validatePostClassify(msg *dns.Msg, cu *ClassifiedUpdate) error {
	if err := validateLeaseOption(msg); err != nil {
		return err
	}
	if err := validateTTLConsistency(cu); err != nil {
		return err
	}
	if err := validateKeys(cu); err != nil {
		return err
	}
	return nil
}

// validateLeaseOption implements S3.3.2's "MUST include an EDNS(0) Update Lease option
// [RFC9664]. The LEASE time ... MUST be less than or equal to the KEY-LEASE time." Reuses
// pkg/lease.FindOption/LeaseOption.Decode/Validate rather than re-parsing the option --
// those already handle both wire shapes this fork's EDNS0 unpacking can produce (see
// pkg/lease.FindOption's doc comment) and already implement the LEASE<=KEY-LEASE check.
func validateLeaseOption(msg *dns.Msg) error {
	erfc, ok := leasepkg.FindOption(msg)
	if !ok {
		return fmt.Errorf("srp: no Update-Lease EDNS(0) option present -- not an SRP update")
	}
	var lo leasepkg.LeaseOption
	opt := &dns.OPT{Options: []dns.EDNS0{erfc}}
	if err := lo.Decode(opt); err != nil {
		return fmt.Errorf("srp: invalid Update-Lease option: %w", err)
	}
	return nil // lo.Decode already calls lo.Validate() internally (see pkg/lease.LeaseOption.decodeERFC)
}

// validateTTLConsistency implements S4's TTL-consistency MUST for the SRP path: reject
// rather than normalize (contrast pkg/updatecore.NormalizeTTLs, used by the base RFC 9664
// handler). Runs across every add RR gathered during classification -- Host Description
// addresses, every Service Instance's SRV/TXT, and every Service Discovery PTR add -- KEY
// adds are checked as their own RRset too, even though S3.2.5.1 already requires them to be
// byte-identical (which implies but doesn't by itself guarantee equal TTLs).
//
// Service Discovery PTR adds matter here specifically because their owner name (a service
// type) is shared across every instance of that type: two different instances registering
// under the same type with different TTLs on their PTR adds would otherwise land at the
// same PTR RRset with inconsistent TTLs and go undetected, since neither instance's own
// SRV/TXT records share that owner name.
func validateTTLConsistency(cu *ClassifiedUpdate) error {
	var all []dns.RR
	all = append(all, cu.Host.Addresses...)
	if cu.Host.Key != nil {
		all = append(all, cu.Host.Key)
	}
	for _, inst := range cu.Instances {
		if inst.SRV != nil {
			all = append(all, inst.SRV)
		}
		for _, txt := range inst.TXT {
			all = append(all, txt)
		}
		if inst.Key != nil {
			all = append(all, inst.Key)
		}
	}
	for _, d := range cu.Discovery {
		if d.IsAdd {
			all = append(all, d.RR)
		}
	}
	if err := updatecore.CheckConsistentTTLs(all); err != nil {
		return fmt.Errorf("srp: %w", err)
	}
	return nil
}

// validateKeys implements S3.2.5.1's "Each KEY record MUST contain the same public key."
//
// It deliberately does NOT check the flags field. RFC 9665 S3.3.3 is explicit and
// two-sided here: requesters "MUST set the flags field in the KEY RR to all zeroes," but
// "SRP registrars ... MUST accept and store the flags field in the KEY RR as received,
// WITHOUT CHECKING OR MODIFYING its value" -- rejecting on a non-zero flags value would be
// exactly the registrar-side check the RFC forbids. (This was caught by
// TestValidate_RealMDNSResponderCapture: the real captured mDNSResponder srp-client
// message carries flags=513, not 0 -- that client doesn't fully honor the requester-side
// MUST, and per the text above that's not this registrar's problem to enforce.) The
// flags-0 requirement belongs entirely to client/srp (a later phase), which constructs
// the KEY adds a requester sends.
func validateKeys(cu *ClassifiedUpdate) error {
	keys := []*dns.KEY{cu.Host.Key}
	for _, inst := range cu.Instances {
		if inst.Key != nil {
			keys = append(keys, inst.Key)
		}
	}
	first := keys[0]
	for _, k := range keys[1:] {
		if !keysIdentical(first, k) {
			return fmt.Errorf("srp: KEY add for %s does not match the KEY add for %s -- all KEY RRs in an SRP update MUST be identical", k.Hdr.Name, first.Hdr.Name)
		}
	}
	return nil
}

// keysIdentical compares algorithm/protocol/public-key -- the key material -- but
// deliberately not flags (see validateKeys) or owner name (which legitimately differs
// between the host and a service instance carrying an explicit, rather than inherited,
// copy of the same key).
func keysIdentical(a, b *dns.KEY) bool {
	return a.Algorithm == b.Algorithm &&
		a.Protocol == b.Protocol &&
		a.PublicKey == b.PublicKey
}
