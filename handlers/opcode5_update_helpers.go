package handlers

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
	"github.com/NetworkCommons/sig0lease/pkg/srp"
)

// summarizeRRTypes builds a compact, deterministic "TYPE:count" summary of
// the RR types present in an UPDATE request's KEY and non-KEY records, for
// INFO-level request logging (e.g. "KEY:1 TXT:2 A:1").
func summarizeRRTypes(keyRRs []*dns.KEY, otherRRs []dns.RR) string {
	counts := make(map[string]int)
	for _, rr := range keyRRs {
		if rr == nil {
			continue
		}
		counts[dns.TypeToString[dns.RRToType(rr)]]++
	}
	for _, rr := range otherRRs {
		if rr == nil {
			continue
		}
		counts[dns.TypeToString[dns.RRToType(rr)]]++
	}
	if len(counts) == 0 {
		return "(none)"
	}

	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Strings(types)

	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%s:%d", t, counts[t]))
	}
	return strings.Join(parts, " ")
}

// blacklistedTypeError is extractUpdateRecords' error for a record of a type the handler's
// blacklisted_types names: a well-formed request refused by local policy, so REFUSED (RFC 2136
// S2.2), not FORMERR like the other errors extractUpdateRecords returns.
type blacklistedTypeError struct {
	rrType uint16
}

func (e *blacklistedTypeError) Error() string {
	return fmt.Sprintf("RR type %s (code %d) is blacklisted for registration", dns.TypeToString[e.rrType], e.rrType)
}

func extractUpdateRecords(msg *dns.Msg, blacklistedTypes map[uint16]struct{}) ([]*dns.KEY, []dns.RR, error) {
	var keyRRs []*dns.KEY
	other := make([]dns.RR, 0, len(msg.Ns))

	for _, rr := range msg.Ns {
		if rr == nil || rr.Header() == nil {
			return nil, nil, fmt.Errorf("nil RR encountered in UPDATE section")
		}
		switch v := rr.(type) {
		case *dns.KEY:
			if v.Algorithm == 0 || v.Protocol == 0 || strings.TrimSpace(v.PublicKey) == "" {
				return nil, nil, fmt.Errorf("incomplete KEY RR in update records: full KEY RDATA is required")
			}
			keyRRs = append(keyRRs, v)
		default:
			// Check blacklist: reject blacklisted RR types.
			if blacklistedTypes != nil {
				if _, blacklisted := blacklistedTypes[dns.RRToType(rr)]; blacklisted {
					return nil, nil, &blacklistedTypeError{rrType: dns.RRToType(rr)}
				}
			}
			other = append(other, rr)
		}
	}

	return keyRRs, other, nil
}

func extractAdditionalSigningKeys(msg *dns.Msg) ([]*dns.KEY, error) {
	keys := make([]*dns.KEY, 0)
	for _, rr := range msg.Extra {
		key, ok := rr.(*dns.KEY)
		if !ok {
			continue
		}
		if key.Algorithm == 0 || key.Protocol == 0 || strings.TrimSpace(key.PublicKey) == "" {
			return nil, fmt.Errorf("incomplete KEY RR in Additional section: full KEY RDATA is required")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func extractSig0(msg *dns.Msg) (*dns.SIG, error) {
	var sigRR *dns.SIG

	// Look for SIG in Pseudo section first (RFC 2535 SIG(0))
	for _, rr := range msg.Pseudo {
		if sig, ok := rr.(*dns.SIG); ok && sigRR == nil {
			sigRR = sig
		}
	}

	// If not found in Pseudo, look in Extra (shouldn't be there but check anyway)
	if sigRR == nil {
		for _, rr := range msg.Extra {
			if sig, ok := rr.(*dns.SIG); ok && sigRR == nil {
				sigRR = sig
			}
		}
	}

	if sigRR == nil {
		return nil, fmt.Errorf("no SIG(0) in message")
	}

	return sigRR, nil
}

// Verify that each RR in the Update section is at or below
// signerAuthorizedForNewRegistration reports whether a signer may author new
// lease-store state — a new KEY RR, or non-KEY RRs owned by itself. This is
// one policy, applied identically regardless of record type: the signer must
// already be lease-managed, be registering itself in this same request, or —
// only if explicitly enabled — be a signer resolved solely via authoritative
// DNS (signerKeySourceAuthoritative). AllowOnlineKeyRegistration governs that
// third case generically; it is not specific to KEY RRs.
func (h *UpdateHandler) signerAuthorizedForNewRegistration(signerManaged, signerInUpdate bool, signerSource signerKeySource) bool {
	if signerManaged || signerInUpdate {
		return true
	}
	return signerSource == signerKeySourceAuthoritative && h.AllowOnlineKeyRegistration
}

func (h *UpdateHandler) validateSignerHierarchyForUpdateRecords(signerName string, keyRRs []*dns.KEY, otherRecords []dns.RR) error {
	signerCanon := dnsname.Normalize(signerName)
	if signerCanon == "" {
		return fmt.Errorf("SIG(0) signer name is empty")
	}

	for _, keyRR := range keyRRs {
		if keyRR == nil || keyRR.Hdr.Name == "" {
			return fmt.Errorf("invalid KEY RR owner name in update section")
		}
		keyOwner := keyRR.Hdr.Name
		keyOwnerCanon := dnsname.Normalize(keyOwner)
		if keyOwnerCanon == signerCanon {
			// Exception: signer self-KEY update is allowed.
			continue
		}
		if !dnsname.IsAtOrBelow(keyOwnerCanon, signerCanon) {
			return fmt.Errorf("KEY RR owner %q is outside signer subtree %q", keyOwner, signerName)
		}
	}

	for _, rr := range otherRecords {
		if rr == nil || rr.Header() == nil {
			return fmt.Errorf("invalid non-KEY RR in update section")
		}
		owner := rr.Header().Name
		ownerCanon := dnsname.Normalize(owner)
		if !dnsname.IsAtOrBelow(ownerCanon, signerCanon) {
			return fmt.Errorf("non-KEY RR owner %q is outside signer subtree %q", owner, signerName)
		}
	}

	return nil
}

// keyID uniquely identifies a KEY by canonical owner name, algorithm, and key tag.
// Two keys with the same name but different algorithm or tag are separate identities.
type keyID struct {
	Name      string // canonical (lower-case, no trailing dot)
	Algorithm uint8
	KeyTag    uint16
}

func keyIDFromKEY(k *dns.KEY) keyID {
	return keyID{Name: dnsname.Normalize(k.Hdr.Name), Algorithm: k.Algorithm, KeyTag: k.KeyTag()}
}

func keyIDFromSIG(sig *dns.SIG) keyID {
	return keyID{Name: dnsname.Normalize(sig.SignerName), Algorithm: sig.Algorithm, KeyTag: sig.KeyTag}
}

// groupOtherRecordsByTargetKey assigns non-KEY RRs to their owning key identity.
// By default (useHierarchy=false) all non-KEY RRs are owned by the signing key.
// When useHierarchy is true, ownership is inferred by DNS name hierarchy: each
// non-KEY RR is assigned to the KEY whose owner name is its longest ancestor;
// the signer breaks ties among keys at equal depth.
//
// useHierarchy is currently never set to true by Handle() -- it is reserved
// for a possible future per-handler config option (e.g.
// "non_key_ownership: signer|hierarchy") that would let a deployment opt
// into hierarchy-based ownership instead of the current signer-owns-
// everything rule. Until such an option exists and is wired up, this branch
// is exercised only by unit tests, not by any production code path; if that
// config option doesn't materialize, this branch should be removed rather
// than carried indefinitely as dead weight.
func groupOtherRecordsByTargetKey(signerID keyID, updateKeyRRs []*dns.KEY, updateOtherRRs []dns.RR, useHierarchy bool) (map[keyID][]dns.RR, error) {
	grouped := make(map[keyID][]dns.RR)
	if len(updateOtherRRs) == 0 {
		return grouped, nil
	}

	if !useHierarchy {
		grouped[signerID] = append(grouped[signerID], updateOtherRRs...)
		return grouped, nil
	}

	// Hierarchy mode: assign by closest ancestor KEY name.
	if len(updateKeyRRs) == 0 {
		owner := dnsname.Normalize(updateOtherRRs[0].Header().Name)
		for _, rr := range updateOtherRRs {
			if rr == nil || rr.Header() == nil {
				return nil, fmt.Errorf("invalid non-KEY RR in update section")
			}
			rrOwner := dnsname.Normalize(rr.Header().Name)
			if rrOwner != owner {
				return nil, fmt.Errorf("mixed non-KEY owner names are not allowed without KEY RRs in update section")
			}
			grouped[signerID] = append(grouped[signerID], rr)
		}
		return grouped, nil
	}

	if len(updateKeyRRs) == 1 {
		kid := keyIDFromKEY(updateKeyRRs[0])
		grouped[kid] = append(grouped[kid], updateOtherRRs...)
		return grouped, nil
	}

	keyIDs := make([]keyID, 0, len(updateKeyRRs))
	for _, keyRR := range updateKeyRRs {
		if keyRR == nil || keyRR.Hdr.Name == "" {
			return nil, fmt.Errorf("invalid KEY RR owner name in update section")
		}
		keyIDs = append(keyIDs, keyIDFromKEY(keyRR))
	}

	for _, rr := range updateOtherRRs {
		if rr == nil || rr.Header() == nil {
			return nil, fmt.Errorf("invalid non-KEY RR in update section")
		}
		rrOwner := dnsname.Normalize(rr.Header().Name)
		var best keyID
		bestLen := -1
		ambiguous := false

		for _, kid := range keyIDs {
			if !dnsname.IsAtOrBelow(rrOwner, kid.Name) {
				continue
			}
			if len(kid.Name) > bestLen {
				best = kid
				bestLen = len(kid.Name)
				ambiguous = false
				continue
			}
			if len(kid.Name) == bestLen {
				// Same name length: signer breaks the tie; otherwise ambiguous.
				if kid == signerID {
					best = kid
					ambiguous = false
				} else if best != signerID {
					ambiguous = true
				}
			}
		}

		if bestLen == -1 {
			return nil, fmt.Errorf("non-KEY RR owner %q does not map to any KEY owner in multi-KEY update", rr.Header().Name)
		}
		if ambiguous {
			return nil, fmt.Errorf("non-KEY RR owner %q maps ambiguously to multiple KEY owners", rr.Header().Name)
		}

		grouped[best] = append(grouped[best], rr)
	}

	return grouped, nil
}

// rrEqual compares two DNS RRs for RFC 2136 equality.
// Per rfc2136 - 1.1 - Comparison Rules: two RRs are considered equal if
// their NAME, CLASS, TYPE, RDLENGTH, and RDATA fields are equal.
// The TTL field is explicitly excluded from the comparison.
//
// Special RR types (rfc2136 - 1.1 - Comparison Rules):
//
//	SOA:  compare only NAME, CLASS, TYPE (only one SOA per zone)
//	CNAME: compare only NAME, CLASS, TYPE (only one CNAME per name)
//	WKS:  compare only NAME, CLASS, TYPE, ADDRESS, PROTOCOL (services mask excluded)
func rrEqual(a, b dns.RR) bool {
	if a == nil || b == nil {
		return false
	}
	hdrA := a.Header()
	hdrB := b.Header()

	if hdrA == nil || hdrB == nil {
		return false
	}

	// Common fields: NAME, CLASS, TYPE
	if !dnsname.EqualFold(hdrA.Name, hdrB.Name) {
		return false
	}
	if hdrA.Class != hdrB.Class {
		return false
	}
	if dns.RRToType(a) != dns.RRToType(b) {
		return false
	}

	typA := dns.RRToType(a)

	// Special RR types per rfc2136 - 1.1 - Comparison Rules
	switch typA {
	case dns.TypeSOA:
		// SOA: compare only NAME, CLASS and TYPE
		return true
	case dns.TypeCNAME:
		// CNAME: compare only NAME, CLASS, and TYPE
		return true
	case uint16(4): // WKS type code (not exported by the dns library)
		// rfc2136 - 1.1 - Comparison Rules: WKS compare only NAME, CLASS, TYPE, ADDRESS, and PROTOCOL
		// (services mask excluded). The dns library does not provide support for WKS RRs
		// (no dns.WK type, no TypeWKS constant), so we have no proper parser for the RDATA.
		// We fall back to comparing the full data string, which may include the services mask;
		// this is not fully RFC 2136 compliant for WKS, but there is no better option available.
		return a.Data().String() == b.Data().String()
	default:
		// Other RR types: compare RDLENGTH and RDATA (TTL excluded)
		if a.Data().Len() != b.Data().Len() {
			return false
		}
		return a.Data().String() == b.Data().String()
	}
}

func (h *UpdateHandler) authoritativeHasRR(ctx context.Context, zoneHint string, rr dns.RR) (bool, error) {
	if rr == nil || rr.Header() == nil {
		return false, fmt.Errorf("rr is nil")
	}
	rrs, err := h.upstreamCoordinator.QueryRRs(ctx, zoneHint, rr.Header().Name, dns.RRToType(rr))
	if err != nil {
		return false, err
	}
	for _, existing := range rrs {
		if rrEqual(existing, rr) {
			return true, nil
		}
	}
	return false, nil
}

// authoritativeLookupError is a failed query to the authoritative server, returned by a check
// that otherwise refuses the request: the request itself may be fine, so refusalResult answers
// it SERVFAIL, like every other failed authoritative lookup, not REFUSED.
type authoritativeLookupError struct {
	err error
}

func (e *authoritativeLookupError) Error() string { return e.err.Error() }
func (e *authoritativeLookupError) Unwrap() error { return e.err }

// refusalResult answers err, the error of a check that refuses the request: SERVFAIL with
// Extended DNS Error 22 (No Reachable Authority) if the check could not query the
// authoritative server (authoritativeLookupError), else REFUSED with 18 (Prohibited) and
// reason.
func refusalResult(r *dns.Msg, reason string, err error) *HandlerResult {
	var lookup *authoritativeLookupError
	if errors.As(err, &lookup) {
		msg := makeErrorResponse(r, dns.RcodeServerFailure, dns.ExtendedErrorNoReachableAuthority, err.Error())
		return NewErrorResult(msg, "authoritative lookup failed", err)
	}
	msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited, err.Error())
	return NewErrorResult(msg, reason, err)
}

// refuseAuthoritativeDuplicate returns an error if the authoritative server already holds rr
// -- data outside this proxy's management, not the requester's to claim -- or, as an
// authoritativeLookupError, if the server could not be asked.
func (h *UpdateHandler) refuseAuthoritativeDuplicate(ctx context.Context, zoneHint string, rr dns.RR) error {
	exists, err := h.authoritativeHasRR(ctx, zoneHint, rr)
	if err != nil {
		return &authoritativeLookupError{err: fmt.Errorf("authoritative duplicate check failed: %w", err)}
	}
	if exists {
		return fmt.Errorf("duplicate registration rejected: authoritative RR already exists for %s", rr.String())
	}
	return nil
}

// refuseNewKey runs the checks a KEY the request registers anew (Case A or D) must pass: no
// identical KEY already published (refuseAuthoritativeDuplicate), and, with fcfs_naming, a
// self-registration one label below the zone and no other key holding its name (fcfsNewKey).
// It returns the prerequisites the upstream UPDATE must carry, or the reply refusing the
// request.
//
// A KEY registers itself only one label below the zone so that every name deeper down is
// registered by the key holding the name above it, and goes when that key goes (its subtree's
// cascade). A KEY registering itself deeper could have a free name above it, and a newcomer
// taking that name would be a signer above it (validateSignerHierarchyForUpdateRecords), able
// to write records at its names. Checking below the newcomer cannot stop that: no DNS query
// lists the names below a name.
func (h *UpdateHandler) refuseNewKey(ctx context.Context, r *dns.Msg, zoneHint string, keyRR *dns.KEY, signerID keyID, signerName string) ([]dns.RR, *HandlerResult) {
	if err := h.refuseAuthoritativeDuplicate(ctx, zoneHint, keyRR); err != nil {
		return nil, refusalResult(r, "duplicate registration rejected", err)
	}
	if !h.fcfsNaming {
		return nil, nil
	}
	// The name keyRR's holder already holds: the zone's apex, the operator's, for a KEY
	// registering itself, else its signer's name.
	top := signerName
	if keyIDFromKEY(keyRR) == signerID {
		if _, parent, _ := dnsname.CutFirstLabel(keyRR.Hdr.Name); dnsname.Normalize(parent) != dnsname.Normalize(h.upstreamZone) {
			err := fmt.Errorf("KEY %s registers itself, which fcfs_naming allows only one label below zone %s: a deeper name is registered by the key holding the name above it", keyRR.Hdr.Name, h.upstreamZone)
			return nil, refusalResult(r, "FCFS self-registration below the zone's first level", err)
		}
		top = h.upstreamZone
	}
	prereqs, heldAt, err := h.fcfsNewKey(ctx, zoneHint, keyRR, top)
	if err != nil {
		return nil, refusalResult(r, "FCFS evaluation failed", err)
	}
	if heldAt != "" {
		h.logger.Infof("FCFS conflict for KEY %s: %s is held by a different key", keyRR.Hdr.Name, heldAt)
		return nil, fcfsConflictResult(r, fmt.Sprintf("FCFS conflict for %s at %s", keyRR.Hdr.Name, heldAt))
	}
	return prereqs, nil
}

// fcfsNewKey is fcfs_naming for keyRR, a KEY registered anew: RFC 9665's FCFS Naming
// (S3.2.4.1), widened from a name to the names below it, since an RFC 9664 key writes records
// at and below its own name (validateSignerHierarchyForUpdateRecords). keyRR is refused --
// heldAt names where -- when a different key holds its name or a name above it, up to but not
// including top, the name its holder holds. Each name is checked as SRP checks its own
// (srp.Evaluate), and returns the prerequisite that has the authoritative server check it
// again when it applies the UPDATE.
func (h *UpdateHandler) fcfsNewKey(ctx context.Context, zoneHint string, keyRR *dns.KEY, top string) (prereqs []dns.RR, heldAt string, err error) {
	// refuseNamesNotServed keeps every name inside the zone, refuseNewKey a KEY registering
	// itself one label below the apex, and validateSignerHierarchyForUpdateRecords every KEY at
	// or below its signer.
	if !dnsname.IsAtOrBelow(keyRR.Hdr.Name, top) {
		panic(fmt.Sprintf("fcfs_naming: KEY %s is not at or below %s", keyRR.Hdr.Name, top))
	}
	view := leaseStoreView{store: h.leaseManager}
	for name := keyRR.Hdr.Name; dnsname.IsAtOrBelow(name, top) && dnsname.Normalize(name) != dnsname.Normalize(top); {
		result, prereq, err := srp.Evaluate(ctx, view, h.upstreamCoordinator.QueryKeyAtName, zoneHint, name, keyRR, false)
		if err != nil {
			return nil, "", &authoritativeLookupError{err: fmt.Errorf("FCFS evaluation failed: %w", err)}
		}
		switch result {
		case srp.FCFSProceed:
			if prereq != nil {
				prereqs = append(prereqs, prereq)
			}
		case srp.FCFSConflict:
			return nil, name, nil
		default:
			panic(fmt.Sprintf("fcfs_naming: srp.Evaluate returned %s for %s, which it cannot without refuse_on_foreign_data", result, name))
		}
		_, name, _ = dnsname.CutFirstLabel(name)
	}
	return prereqs, "", nil
}

func (h *UpdateHandler) authoritativeHasKeyAtName(ctx context.Context, zoneHint string, fqdn string) (bool, error) {
	rrs, err := h.upstreamCoordinator.QueryRRs(ctx, zoneHint, fqdn, dns.TypeKEY)
	if err != nil {
		return false, err
	}
	return len(rrs) > 0, nil
}

// filterDuplicateRegistrations checks each candidate record against the
// lease store first, since the store -- not the authoritative DNS server --
// is the source of truth for what this proxy already manages: the DNS
// server can be wiped, reset, or fail over to an empty secondary for
// reasons entirely outside the proxy's control, and none of that should let
// a record we still believe we're actively leasing be silently reassigned
// to a different key. Only a record the store has no knowledge of at all
// falls through to a live authoritative-DNS check, to catch data that
// exists outside our management (registered before this proxy existed, or
// by some other process) rather than ours to claim.
func (h *UpdateHandler) filterDuplicateRegistrations(ctx context.Context, keyName, zoneHint string, records []dns.RR) ([]dns.RR, []string, error) {
	accepted := make([]dns.RR, 0, len(records))
	notes := make([]string, 0)

	for _, rr := range records {
		if rr == nil || rr.Header() == nil {
			continue
		}
		if existing := h.leaseManager.LookupNonKEYRecord(rr); existing != nil {
			if existing.ParentKeyName != keyName {
				return nil, nil, fmt.Errorf("duplicate registration rejected: %s is already registered under a different key", rr.String())
			}
			// Already active under this same key: a refresh.
			accepted = append(accepted, rr)
			continue
		}

		// Not under our control locally: fail the whole request if the
		// authoritative zone already contains an identical RR anyway.
		if err := h.refuseAuthoritativeDuplicate(ctx, zoneHint, rr); err != nil {
			return nil, nil, err
		}
		accepted = append(accepted, rr)
	}

	return accepted, notes, nil
}

// signerKeySource records how a SIG(0) signer's KEY material was resolved.
// This provenance drives policy decisions downstream (see AllowOnlineKeyRegistration):
// a key resolved only via authoritative DNS was neither proven in this request
// nor previously brought under lease management by this proxy.
type signerKeySource int

const (
	signerKeySourceUnknown signerKeySource = iota
	signerKeySourceRequest
	signerKeySourceLeaseStore
	signerKeySourceAuthoritative
)

// extractAndValidateSig0 extracts and validates SIG(0) from the message.
// KEY RRs in Additional are interpreted as signing-key material.
// KEY RRs in Update are interpreted as update targets, but may still be used as
// verification candidates when they match the signer identity.
//
// Resolution follows the three-stage fallback: request-provided KEY RRs
// (Additional or Update), then the lease store, then authoritative DNS.
func (h *UpdateHandler) extractAndValidateSig0(ctx context.Context, msg *dns.Msg, downstreamZone string, additionalSigningKeys []*dns.KEY, updateKeys []*dns.KEY) (*dns.SIG, *dns.KEY, signerKeySource, error) {
	sigRR, err := extractSig0(msg)
	if err != nil {
		return nil, nil, signerKeySourceUnknown, err
	}
	downstreamZoneCanon := dnsname.Normalize(downstreamZone)
	if downstreamZoneCanon == "" {
		return nil, nil, signerKeySourceUnknown, fmt.Errorf("empty downstream zone")
	}
	signerCanon := dnsname.Normalize(sigRR.SignerName)
	if signerCanon == "" {
		return nil, nil, signerKeySourceUnknown, fmt.Errorf("SIG(0) signer name is empty")
	}
	if !dnsname.IsAtOrBelow(downstreamZoneCanon, signerCanon) {
		return nil, nil, signerKeySourceUnknown, fmt.Errorf("SIG(0) signer %q is outside allowed hierarchy for downstream zone %q", sigRR.SignerName, downstreamZone)
	}

	verifyFromCandidates := func(candidates []*dns.KEY) (*dns.KEY, error) {
		var lastErr error
		for _, dnskey := range candidates {
			if dnskey == nil {
				continue
			}
			if err := sig0.VerifySignature(msg, dnskey); err == nil {
				h.logger.Debugf("SIG(0) cryptographic verification passed for %s", dnskey.Hdr.Name)
				return dnskey, nil
			} else {
				lastErr = err
			}
		}
		if lastErr != nil {
			return nil, fmt.Errorf("SIG(0) cryptographic verification failed for all candidates: %w", lastErr)
		}
		return nil, nil
	}

	verifyCandidates := make([]*dns.KEY, 0, len(additionalSigningKeys)+len(updateKeys))
	for _, key := range additionalSigningKeys {
		if key == nil {
			continue
		}
		if dnsname.Normalize(key.Hdr.Name) == signerCanon && key.KeyTag() == sigRR.KeyTag && key.Algorithm == sigRR.Algorithm {
			verifyCandidates = append(verifyCandidates, key)
		}
	}
	for _, key := range updateKeys {
		if key == nil {
			continue
		}
		if dnsname.Normalize(key.Hdr.Name) == signerCanon && key.KeyTag() == sigRR.KeyTag && key.Algorithm == sigRR.Algorithm {
			verifyCandidates = append(verifyCandidates, key)
		}
	}
	if resolved, err := verifyFromCandidates(verifyCandidates); err != nil {
		return nil, nil, signerKeySourceUnknown, err
	} else if resolved != nil {
		return sigRR, resolved, signerKeySourceRequest, nil
	}

	// Check if the key is present in the Lease Store
	leaseRecord := h.leaseManager.LookupBySIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag)
	if leaseRecord != nil && leaseRecord.KeyRR != nil {
		leaseKey := leaseRecord.KeyRR
		if dnsname.Normalize(leaseKey.Hdr.Name) == signerCanon && leaseKey.KeyTag() == sigRR.KeyTag && leaseKey.Algorithm == sigRR.Algorithm {
			if resolved, err := verifyFromCandidates([]*dns.KEY{leaseKey}); err != nil {
				return nil, nil, signerKeySourceUnknown, err
			} else if resolved != nil {
				h.logger.Debugf("Using signer KEY from lease store for %s", sigRR.SignerName)
				return sigRR, resolved, signerKeySourceLeaseStore, nil
			}
		}
	}

	// Check if the key is present online
	authRRS, err := h.upstreamCoordinator.QueryRRs(ctx, downstreamZone, sigRR.SignerName, dns.TypeKEY)
	if err != nil {
		return nil, nil, signerKeySourceUnknown, &authoritativeLookupError{err: fmt.Errorf("failed to resolve signer KEY from authoritative DNS: %w", err)}
	}
	authCandidates := make([]*dns.KEY, 0, len(authRRS))
	for _, rr := range authRRS {
		key, ok := rr.(*dns.KEY)
		if !ok {
			continue
		}
		if key.KeyTag() == sigRR.KeyTag && key.Algorithm == sigRR.Algorithm {
			authCandidates = append(authCandidates, key)
		}
	}
	if len(authCandidates) == 0 {
		h.logger.Debugf("No authoritative KEY match for signer %s (keytag=%d algorithm=%d)", sigRR.SignerName, sigRR.KeyTag, sigRR.Algorithm)
		return nil, nil, signerKeySourceUnknown, fmt.Errorf("no matching KEY candidate found for signer %q in request, lease store, or authoritative DNS", sigRR.SignerName)
	}

	if resolved, err := verifyFromCandidates(authCandidates); err != nil {
		return nil, nil, signerKeySourceUnknown, err
	} else if resolved != nil {
		return sigRR, resolved, signerKeySourceAuthoritative, nil
	}

	return nil, nil, signerKeySourceUnknown, fmt.Errorf("no matching KEY candidate found for signer %q in request, lease store, or authoritative DNS", sigRR.SignerName)
}

// upstreamUpdateRecords returns the Update section of the UPDATE Cases A, B and D forward:
// the KEYs and non-KEY records to add, carrying the TTLs Handle already set (record_ttl_sec),
// then as RFC 2136 deletes (class NONE, TTL 0) the non-KEY records Case D asked to remove.
// Combining both into a single signed UPDATE means one round trip is either fully confirmed or
// not, so there is no window where the accompanying delete could succeed upstream while the
// KEY add/refresh it was staged alongside never gets sent, or vice versa.
func upstreamUpdateRecords(keyRRs []*dns.KEY, otherRecords []dns.RR, recordsToDelete []dns.RR) []dns.RR {
	records := make([]dns.RR, 0, len(keyRRs)+len(otherRecords)+len(recordsToDelete))
	for _, keyRR := range keyRRs {
		records = append(records, keyRR)
	}
	records = append(records, otherRecords...)
	return append(records, asDeletes(recordsToDelete...)...)
}

// makeErrorResponse creates a properly formatted error response.
