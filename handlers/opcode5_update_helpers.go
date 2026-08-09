package handlers

import (
	"context"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

func newUnsignedUpstreamUpdate(upstreamZone string) (*dns.Msg, error) {
	msg := dns.NewMsg(upstreamZone, dns.TypeSOA)
	if msg == nil {
		return nil, fmt.Errorf("failed to create DNS message")
	}

	msg.Opcode = dns.OpcodeUpdate
	msg.RecursionDesired = false
	msg.Answer = nil
	msg.Ns = nil

	return msg, nil
}

func (h *UpdateHandler) signUpstreamUpdate(msg *dns.Msg, opName string, signingKey *keyrec.LoadedKey) (*dns.Msg, error) {
	if signingKey == nil || signingKey.PrivateKey == nil || signingKey.PublicKey == nil {
		return nil, fmt.Errorf("upstream SIG(0) key is not configured")
	}

	signedMsg, err := sig0.SignMessage(msg, signingKey.PublicKey, signingKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign upstream %s with SIG(0): %w", opName, err)
	}

	return signedMsg, nil
}

func (h *UpdateHandler) constructUpstreamDelete(clientKeyRR *dns.KEY, signingKey *keyrec.LoadedKey, upstreamZone string) (*dns.Msg, error) {
	msg, err := newUnsignedUpstreamUpdate(upstreamZone)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS delete message: %w", err)
	}

	deleteRR := *clientKeyRR
	deleteRR.Hdr.Class = dns.ClassNONE
	deleteRR.Hdr.TTL = 0
	msg.Ns = append(msg.Ns, &deleteRR)

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	msg.Extra = append(msg.Extra, opt)

	return h.signUpstreamUpdate(msg, "DELETE", signingKey)
}

func (h *UpdateHandler) constructUpstreamDeleteForRecords(records []dns.RR, signingKey *keyrec.LoadedKey, upstreamZone string) (*dns.Msg, error) {
	msg, err := newUnsignedUpstreamUpdate(upstreamZone)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS delete message: %w", err)
	}

	for _, rr := range records {
		if rr == nil {
			continue
		}
		hdr := rr.Header()
		if hdr == nil {
			continue
		}

		// RFC 2136 delete: class NONE + TTL 0 with full RDATA for RR delete.
		cpy := copyRR(rr)
		cpyHdr := cpy.Header()
		cpyHdr.Class = dns.ClassNONE
		cpyHdr.TTL = 0
		msg.Ns = append(msg.Ns, cpy)
	}

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	msg.Extra = append(msg.Extra, opt)

	return h.signUpstreamUpdate(msg, "DELETE", signingKey)
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
					return nil, nil, fmt.Errorf("RR type %s (code %d) is blacklisted for registration",
						dns.TypeToString[dns.RRToType(rr)], dns.RRToType(rr))
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

func canonicalName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// Check that candidate is above or at basename, and if mustBeAbove is true
// it must be strictly above
func isNameAtOrAbove(baseName, candidate string, mustBeAbove bool) bool {
	base := canonicalName(baseName)
	c := canonicalName(candidate)
	if base == "" || c == "" {
		return false
	}
	if c == base {
		if mustBeAbove {
			return false
		} else {
			return true
		}

	}
	return strings.HasSuffix(base, "."+c)
}

// Verify that each RR in the Update section is at or below
func (h *UpdateHandler) validateSignerHierarchyForUpdateRecords(signerName string, keyRRs []*dns.KEY, otherRecords []dns.RR) error {
	signerCanon := canonicalName(signerName)
	if signerCanon == "" {
		return fmt.Errorf("SIG(0) signer name is empty")
	}

	for _, keyRR := range keyRRs {
		if keyRR == nil || keyRR.Hdr.Name == "" {
			return fmt.Errorf("invalid KEY RR owner name in update section")
		}
		keyOwner := keyRR.Hdr.Name
		keyOwnerCanon := canonicalName(keyOwner)
		if keyOwnerCanon == signerCanon {
			// Exception: signer self-KEY update is allowed.
			continue
		}
		if !isNameAtOrAbove(keyOwnerCanon, signerCanon, false) {
			return fmt.Errorf("KEY RR owner %q is outside signer subtree %q", keyOwner, signerName)
		}
	}

	for _, rr := range otherRecords {
		if rr == nil || rr.Header() == nil {
			return fmt.Errorf("invalid non-KEY RR in update section")
		}
		owner := rr.Header().Name
		ownerCanon := canonicalName(owner)
		if !isNameAtOrAbove(ownerCanon, signerCanon, false) {
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
	return keyID{Name: canonicalName(k.Hdr.Name), Algorithm: k.Algorithm, KeyTag: k.KeyTag()}
}

func keyIDFromSIG(sig *dns.SIG) keyID {
	return keyID{Name: canonicalName(sig.SignerName), Algorithm: sig.Algorithm, KeyTag: sig.KeyTag}
}

// groupOtherRecordsByTargetKey assigns non-KEY RRs to their owning key identity.
// By default (useHierarchy=false) all non-KEY RRs are owned by the signing key.
// When useHierarchy is true, ownership is inferred by DNS name hierarchy: each
// non-KEY RR is assigned to the KEY whose owner name is its longest ancestor;
// the signer breaks ties among keys at equal depth.
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
		owner := canonicalName(updateOtherRRs[0].Header().Name)
		for _, rr := range updateOtherRRs {
			if rr == nil || rr.Header() == nil {
				return nil, fmt.Errorf("invalid non-KEY RR in update section")
			}
			rrOwner := canonicalName(rr.Header().Name)
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
		rrOwner := canonicalName(rr.Header().Name)
		var best keyID
		bestLen := -1
		ambiguous := false

		for _, kid := range keyIDs {
			if !isNameAtOrAbove(rrOwner, kid.Name, false) {
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
	if !strings.EqualFold(hdrA.Name, hdrB.Name) {
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

func (h *UpdateHandler) queryAuthoritativeRRs(ctx context.Context, zoneHint string, fqdn string, rrType uint16) ([]dns.RR, error) {
	if h.authoritativeLookup != nil {
		return h.authoritativeLookup(ctx, zoneHint, fqdn, rrType)
	}

	dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator)
	if !ok {
		return nil, fmt.Errorf("authoritative lookup requires default upstream coordinator")
	}

	soaServer, _, err := dc.resolveSOAMasterServer(ctx, zoneHint)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve authoritative server for %s: %w", zoneHint, err)
	}

	req := dns.NewMsg(fqdn, rrType)
	if req == nil {
		return nil, fmt.Errorf("failed to build authoritative query")
	}
	req.RecursionDesired = false

	resp, udpErr := dns.Exchange(ctx, req, "udp", soaServer)
	if udpErr != nil {
		resp, err = dns.Exchange(ctx, req, "tcp", soaServer)
		if err != nil {
			return nil, fmt.Errorf("authoritative lookup failed (udp: %v, tcp: %v)", udpErr, err)
		}
	}
	if resp == nil {
		return nil, fmt.Errorf("authoritative lookup returned nil response")
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("authoritative lookup rcode=%d (%s)", resp.Rcode, dns.RcodeToString[resp.Rcode])
	}

	rrs := make([]dns.RR, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		if rr != nil && rr.Header() != nil && dns.RRToType(rr) == rrType {
			rrs = append(rrs, rr)
		}
	}

	return rrs, nil
}

func (h *UpdateHandler) authoritativeHasRR(ctx context.Context, zoneHint string, rr dns.RR) (bool, error) {
	if rr == nil || rr.Header() == nil {
		return false, fmt.Errorf("rr is nil")
	}
	rrs, err := h.queryAuthoritativeRRs(ctx, zoneHint, rr.Header().Name, dns.RRToType(rr))
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

func (h *UpdateHandler) authoritativeHasKeyAtName(ctx context.Context, zoneHint string, fqdn string) (bool, error) {
	rrs, err := h.queryAuthoritativeRRs(ctx, zoneHint, fqdn, dns.TypeKEY)
	if err != nil {
		return false, err
	}
	return len(rrs) > 0, nil
}

func (h *UpdateHandler) filterDuplicateRegistrations(ctx context.Context, keyName, zoneHint string, records []dns.RR) ([]dns.RR, []string, error) {
	accepted := make([]dns.RR, 0, len(records))
	notes := make([]string, 0)

	for _, rr := range records {
		if rr == nil || rr.Header() == nil {
			continue
		}
		if h.hasActiveDataRecord(keyName, rr) {
			accepted = append(accepted, rr)
			continue
		}

		// New registration attempt for this RR: fail the whole request if
		// the authoritative zone already contains an identical RR.
		exists, err := h.authoritativeHasRR(ctx, zoneHint, rr)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			return nil, nil, fmt.Errorf("duplicate registration rejected: authoritative RR already exists for %s", rr.String())
		}
		accepted = append(accepted, rr)
	}

	return accepted, notes, nil
}

func (h *UpdateHandler) rollbackLeaseStateForUpdate(nodeKeys []string) {
	seen := make(map[string]struct{}, len(nodeKeys))
	for _, nodeKey := range nodeKeys {
		nk := canonicalName(nodeKey)
		if nk == "" {
			continue
		}
		if _, ok := seen[nk]; ok {
			continue
		}
		seen[nk] = struct{}{}

		if err := h.leaseManager.Delete(nk); err != nil {
			h.logger.Debugf("rollback: failed to delete key lease for %s: %v", nk, err)
		}
		h.removeDataLease(nk)
		h.clearLeaseTimer(nk)
	}
}

func (h *UpdateHandler) resolveSignerKeyForOwnership(sigRR *dns.SIG, additionalSigningKeys, updateKeys []*dns.KEY) (*dns.KEY, error) {
	signerCanon := canonicalName(sigRR.SignerName)
	if signerCanon == "" {
		return nil, fmt.Errorf("SIG(0) signer name is empty")
	}

	matchesSigner := func(key *dns.KEY) bool {
		return key != nil && strings.EqualFold(canonicalName(key.Hdr.Name), signerCanon) && key.KeyTag() == sigRR.KeyTag && key.Algorithm == sigRR.Algorithm
	}

	for _, key := range additionalSigningKeys {
		if matchesSigner(key) {
			return key, nil
		}
	}
	for _, key := range updateKeys {
		if matchesSigner(key) {
			return key, nil
		}
	}

	leaseRecord := h.leaseManager.LookupBySIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag)
	if leaseRecord != nil && leaseRecord.KeyRR != nil && matchesSigner(leaseRecord.KeyRR) {
		return leaseRecord.KeyRR, nil
	}

	return nil, fmt.Errorf("signing KEY %q must be present in the request or lease store", sigRR.SignerName)
}

// extractAndValidateSig0 extracts and validates SIG(0) from the message.
// KEY RRs in Additional are interpreted as signing-key material.
// KEY RRs in Update are interpreted as update targets, but may still be used as
// verification candidates when they match the signer identity.
func (h *UpdateHandler) extractAndValidateSig0(ctx context.Context, msg *dns.Msg, downstreamZone string, signerKeyHint *dns.KEY, additionalSigningKeys []*dns.KEY, updateKeys []*dns.KEY) (*dns.SIG, *dns.KEY, error) {
	sigRR, err := extractSig0(msg)
	if err != nil {
		return nil, nil, err
	}
	downstreamZoneCanon := canonicalName(downstreamZone)
	if downstreamZoneCanon == "" {
		return nil, nil, fmt.Errorf("empty downstream zone")
	}
	signerCanon := canonicalName(sigRR.SignerName)
	if signerCanon == "" {
		return nil, nil, fmt.Errorf("SIG(0) signer name is empty")
	}
	if !isNameAtOrAbove(downstreamZoneCanon, signerCanon, false) {
		return nil, nil, fmt.Errorf("SIG(0) signer %q is outside allowed hierarchy for downstream zone %q", sigRR.SignerName, downstreamZone)
	}
	if signerKeyHint != nil {
		if !strings.EqualFold(canonicalName(signerKeyHint.Hdr.Name), signerCanon) || signerKeyHint.KeyTag() != sigRR.KeyTag || signerKeyHint.Algorithm != sigRR.Algorithm {
			return nil, nil, fmt.Errorf("provided signer KEY does not match SIG(0) signer %q", sigRR.SignerName)
		}
		if err := sig0.VerifySignature(msg, signerKeyHint); err != nil {
			return nil, nil, fmt.Errorf("SIG(0) cryptographic verification failed using provided signer KEY: %w", err)
		}
		h.logger.Debugf("SIG(0) cryptographic verification passed for provided signer KEY %s", signerKeyHint.Hdr.Name)
		return sigRR, signerKeyHint, nil
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
		if strings.EqualFold(canonicalName(key.Hdr.Name), signerCanon) && key.KeyTag() == sigRR.KeyTag && key.Algorithm == sigRR.Algorithm {
			verifyCandidates = append(verifyCandidates, key)
		}
	}
	for _, key := range updateKeys {
		if key == nil {
			continue
		}
		if strings.EqualFold(canonicalName(key.Hdr.Name), signerCanon) && key.KeyTag() == sigRR.KeyTag && key.Algorithm == sigRR.Algorithm {
			verifyCandidates = append(verifyCandidates, key)
		}
	}
	if resolved, err := verifyFromCandidates(verifyCandidates); err != nil {
		return nil, nil, err
	} else if resolved != nil {
		return sigRR, resolved, nil
	}

	// Check if the key is present in the Lease Store
	leaseRecord := h.leaseManager.LookupBySIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag)
	if leaseRecord != nil && leaseRecord.KeyRR != nil {
		leaseKey := leaseRecord.KeyRR
		if strings.EqualFold(canonicalName(leaseKey.Hdr.Name), signerCanon) && leaseKey.KeyTag() == sigRR.KeyTag && leaseKey.Algorithm == sigRR.Algorithm {
			if resolved, err := verifyFromCandidates([]*dns.KEY{leaseKey}); err != nil {
				return nil, nil, err
			} else if resolved != nil {
				h.logger.Debugf("Using signer KEY from lease store for %s", sigRR.SignerName)
				return sigRR, resolved, nil
			}
		}
	}

	// Check if the key is present online
	authRRS, err := h.queryAuthoritativeRRs(ctx, downstreamZone, sigRR.SignerName, dns.TypeKEY)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve signer KEY from authoritative DNS: %w", err)
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
		return nil, nil, fmt.Errorf("no matching KEY candidate found for signer %q in request, lease store, or authoritative DNS", sigRR.SignerName)
	}

	if resolved, err := verifyFromCandidates(authCandidates); err != nil {
		return nil, nil, err
	} else if resolved != nil {
		return sigRR, resolved, nil
	}

	return nil, nil, fmt.Errorf("no matching KEY candidate found for signer %q in request, lease store, or authoritative DNS", sigRR.SignerName)
}

// constructUpstreamUpdate builds an UPDATE message for the upstream zone.
// This UPDATE will be sent to the authoritative server for the upstream zone.
// If upstream key is loaded, it will be signed with SIG(0).
func (h *UpdateHandler) constructUpstreamUpdate(clientKeyRRs []*dns.KEY, otherRecords []dns.RR, signingKey *keyrec.LoadedKey, upstreamZone string) (*dns.Msg, error) {
	msg, err := newUnsignedUpstreamUpdate(upstreamZone)
	if err != nil {
		return nil, err
	}

	policyOther := make([]dns.RR, 0, len(otherRecords))
	for _, rr := range otherRecords {
		cpy := copyRR(rr)
		if cpy == nil || cpy.Header() == nil {
			continue
		}
		hdr := cpy.Header()
		hdr.TTL = clampTTL(hdr.TTL, h.LeasePolicy.MinRRLease, h.LeasePolicy.MaxRRLease)
		policyOther = append(policyOther, cpy)
	}
	for _, keyRR := range clientKeyRRs {
		policyKey := copyRR(keyRR).(*dns.KEY)
		policyKey.Hdr.TTL = clampTTL(policyKey.Hdr.TTL, h.LeasePolicy.MinKeyLease, h.LeasePolicy.MaxKeyLease)
		msg.Ns = append(msg.Ns, policyKey)
	}

	// Update section: optional KEYs plus supported non-KEY records.
	msg.Ns = append(msg.Ns, policyOther...)
	if len(msg.Ns) == 0 {
		return msg, nil
	}

	// Add OPT for EDNS support
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	msg.Extra = append(msg.Extra, opt)

	signedMsg, err := h.signUpstreamUpdate(msg, "UPDATE", signingKey)
	if err != nil {
		return nil, err
	}
	msg = signedMsg
	h.logger.Debugf("Signed upstream UPDATE with key: %s", signingKey)

	return msg, nil
}

// makeErrorResponse creates a properly formatted error response.
