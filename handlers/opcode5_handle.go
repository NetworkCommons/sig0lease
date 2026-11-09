package handlers

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

func (h *UpdateHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult {
	h.logger.Debugf("UPDATE handler: Processing message from %s", w.RemoteAddr().String())

	// Validate message structure
	if r == nil {
		return NewErrorResult(nil, "nil message received", fmt.Errorf("nil message"))
	}
	if r.Opcode == dns.OpcodeQuery {
		return h.answerQuery(ctx, r)
	}

	// CHECK 1: Verify UPDATE-LEASE EDNS option is present
	// If missing, this is a regular UPDATE not relevant to sig0lease
	if !h.hasUpdateLeaseOption(r) {
		h.logger.Debugf("UPDATE packet lacks UPDATE-LEASE EDNS option, not sig0lease relevant")
		return NewNotRelevantResult("UPDATE without UPDATE-LEASE EDNS option - not sig0lease")
	}

	h.logger.Debugf("UPDATE-LEASE EDNS option present, processing as sig0lease packet")
	// From here on the request is this handler's, and everything below needs the upstream.
	requireUpstream(h.Name(), h.upstreamCoordinator != nil, h.upstreamKeyRecord != nil)

	if res := refuseDottedLabels(r); res != nil {
		h.logger.Debugf("Refusing UPDATE: %v", res.Error)
		return res
	}
	// Whether the names are this handler's first, then whether the Zone Section encloses
	// them: RFC 2136 S3.1 then S3.4.1.3.
	if res := h.refuseNamesNotServed(r); res != nil {
		h.logger.Debugf("Refusing UPDATE: %v", res.Error)
		return res
	}
	if res := refuseOutsideZoneSection(r); res != nil {
		h.logger.Debugf("Refusing UPDATE: %v", res.Error)
		return res
	}

	requestedLease, rcode, err := h.decodeLease(r)
	if err != nil {
		h.logger.Debugf("Lease parsing failed: %v", err)
		infoCode := dns.ExtendedErrorOther
		if rcode == dns.RcodeRefused {
			// decodeLease's one REFUSED: the 4-byte variant, while prefer_4byte_variant is off.
			infoCode = dns.ExtendedErrorNotSupported
		}
		msg := makeErrorResponse(r, rcode, infoCode, fmt.Sprintf("invalid lease: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("lease parsing failed: %v", err), err)
	}

	recs, err := extractUpdateRecords(r, h.blacklistedTypes)
	if err != nil {
		h.logger.Debugf("Invalid update records: %v", err)
		var blacklisted *blacklistedTypeError
		var rrsetDelete *rrsetDeleteError
		switch {
		case errors.As(err, &blacklisted):
			msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited, err.Error())
			return NewErrorResult(msg, err.Error(), err)
		case errors.As(err, &rrsetDelete):
			msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorNotSupported, err.Error())
			return NewErrorResult(msg, err.Error(), err)
		}
		msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	leaseDuration, keyLeaseDuration := requestedLeases(requestedLease, len(recs.keyAdds) > 0, len(recs.otherAdds) > 0)
	if err := checkUpdateRecords(recs, leaseDuration, keyLeaseDuration); err != nil {
		h.logger.Debugf("Invalid update records: %v", err)
		msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	// A duration outside lease_policy is raised to its minimum or cut to its maximum, as the
	// SRP handler does; the reply's Update Lease option tells the requester what it got.
	originalLeaseDuration := leaseDuration
	originalKeyLeaseDuration := keyLeaseDuration
	leaseDuration, keyLeaseDuration = h.LeasePolicy.clamp(leaseDuration, keyLeaseDuration)
	if requestedLease.KeyLease == nil && leaseDuration != 0 && keyLeaseDuration != 0 {
		// A 4-byte request gets one value back for its KEYs and its other records, which
		// expire together (RFC 9664 S4); clamp left LEASE <= KEY-LEASE, so the KEYs get the
		// LEASE. Setup refuses a lease_policy under which that falls below min_key_lease_sec.
		keyLeaseDuration = leaseDuration
	}
	if leaseDuration != originalLeaseDuration || keyLeaseDuration != originalKeyLeaseDuration {
		h.logger.Debugf("Lease policy clamped request durations: lease=%d->%d key-lease=%d->%d",
			originalLeaseDuration, leaseDuration, originalKeyLeaseDuration, keyLeaseDuration)
	}
	grantedLease := grantedLeaseOption(requestedLease, leaseDuration, keyLeaseDuration)

	h.logger.Debugf("Parsed lease duration: %d seconds key-lease=%d", leaseDuration, keyLeaseDuration)

	h.logger.Infof("UPDATE request for zone %s: LEASE=%d KEY-LEASE=%d RRs=%s deletes=%s",
		h.upstreamZone, leaseDuration, keyLeaseDuration,
		summarizeRRTypes(recs.keyAdds, recs.otherAdds), summarizeRRTypes(recs.keyDeletes, recs.otherDeletes))

	additionalSigningKeys, err := extractAdditionalSigningKeys(r)
	if err != nil {
		h.logger.Debugf("Invalid Additional KEY records: %v", err)
		msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	// A KEY the request deletes names the signer as well as one it adds does (item 1.3).
	sigRR, signerKey, signerSource, err := h.extractAndValidateSig0(ctx, r, additionalSigningKeys, slices.Concat(recs.keyAdds, recs.keyDeletes))
	if err != nil {
		h.logger.Debugf("SIG(0) validation failed: %v", err)
		return refusalResult(r, "SIG(0) validation failed", fmt.Errorf("SIG(0) validation failed: %w", err))
	}

	// Replace the requester's TTLs with record_ttl_sec (see parseRecordTTL), cut to the
	// granted KEY-LEASE on KEYs and to the granted LEASE on everything else -- one TTL per
	// RRset, so RFC 2181 S5.2 holds whatever the requester sent. Done in place, after the
	// signature over the original TTLs is checked, so the lease store keeps what the zone
	// gets. Deletes go upstream with TTL 0.
	for _, keyRR := range recs.keyAdds {
		keyRR.Hdr.TTL = min(h.recordTTL, keyLeaseDuration)
	}
	for _, rr := range recs.otherAdds {
		rr.Header().TTL = min(h.recordTTL, leaseDuration)
	}

	if err := h.validateSignerHierarchyForUpdateRecords(sigRR.SignerName,
		slices.Concat(recs.keyAdds, recs.keyDeletes), slices.Concat(recs.otherAdds, recs.otherDeletes)); err != nil {
		h.logger.Debugf("Update hierarchy validation failed: %v", err)
		msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited, fmt.Sprintf("hierarchy validation failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("hierarchy validation failed: %v", err), err)
	}

	signerID := keyIDFromSIG(sigRR)
	signerNodeKey := leasepkg.NodeKeyFromSIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag)
	// Deleting the signer's KEY takes everything it registered (item 5.3.2), the records and
	// KEYs this request would add or refresh with it included.
	if recs.adds() && slices.ContainsFunc(recs.keyDeletes, func(k *dns.KEY) bool { return keyIDFromKEY(k) == signerID }) {
		err := fmt.Errorf("the request deletes its signer's KEY %s, which takes everything that KEY registered, and adds or refreshes records with it", sigRR.SignerName)
		msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther, err.Error())
		return NewErrorResult(msg, "invalid update", err)
	}

	// useHierarchy is hardcoded false: non-KEY RRs always belong to the
	// signer (docs/siglease_rfc9664.md 5.2.3). See groupOtherRecordsByTargetKey's doc
	// comment -- the useHierarchy=true path is reserved for a possible
	// future config option and is not reachable from here today.
	updateOtherRRsByKeyOwner, err := groupOtherRecordsByTargetKey(signerID, recs.keyAdds, recs.otherAdds, false)
	if err != nil {
		h.logger.Debugf("Failed to map non-KEY records to KEY owners: %v", err)
		msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited, fmt.Sprintf("invalid mixed-owner update: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("invalid mixed-owner update: %v", err), err)
	}

	h.logger.Debugf("SIG(0) validated: Algorithm=%d, KeyTag=%d, Signer=%s",
		sigRR.Algorithm, sigRR.KeyTag, sigRR.SignerName)
	if sigRR.Algorithm != 15 {
		h.logger.Warnf("Non-default DNSSEC algorithm used in request signer: %d", sigRR.Algorithm)
	}
	h.logger.Debugf("Resolved signer KEY: %s", signerKey.Hdr.Name)

	// From here to the local apply, this request reads lease-store nodes, writes upstream, and
	// then changes those nodes: hold their locks throughout, waiting while another request or
	// a lease expiry holds any of them (docs/siglease_rfc9664.md, "Node Locks"). Taken only
	// now, after SIG(0) verification, so an unverified request can never hold a lock.
	locks, err := h.nodeLocks.Acquire(ctx, h.requestLockSet(signerID, recs))
	if err != nil {
		h.logger.Warnf("UPDATE for zone %s: %v", h.upstreamZone, err)
		msg := makeErrorResponse(r, dns.RcodeServerFailure, dns.ExtendedErrorOther, "lease store busy, try again")
		return NewErrorResult(msg, "lease-store node lock contention", err)
	}
	defer locks.Release()

	var allNotes []string
	upstreamKeys := make([]*dns.KEY, 0)
	var acceptedRecordsForUpstream []dns.RR
	// deletesForUpstream are the RFC 2136 deletes of what this request deletes: its records,
	// and each of its KEYs with everything at and below it.
	var deletesForUpstream []dns.RR
	// fcfsPrereqs are the prerequisites fcfs_naming attaches to the upstream UPDATE for the
	// KEYs registered anew (refuseNewKey).
	var fcfsPrereqs []dns.RR
	type pendingLeaseMutation struct {
		keyName string
		apply   func() error
	}
	pendingMutations := make([]pendingLeaseMutation, 0)

	// Deletes. Only what this proxy manages is deleted, upstream and in the store; anything
	// else named is reported in a note, not refused (item 7). Authorization is ownership, not
	// just DNS-name hierarchy (item 5.3.1): a record may only be deleted by the KEY that
	// registered it, which for a non-KEY record is always the signer (5.2.3), and a KEY by
	// itself or by the KEY that registered it. A signer merely "at or above" a record it did
	// not register cannot delete it directly, only by deleting the record's actual parent, as
	// a KEY's delete takes everything at and below it, exactly as its expiry does
	// (subtreeLeases, leaseExpirer). Absent and not the signer's look the same, so a delete
	// cannot probe for records outside the signer's own subtree.
	keysToDelete := make([]*dns.KEY, 0, len(recs.keyDeletes))
	for _, keyRR := range recs.keyDeletes {
		existing := h.leaseManager.LookupByKEY(keyRR)
		isSelf := keyIDFromKEY(keyRR) == signerID
		if existing == nil || (!isSelf && existing.ParentKeyName != signerNodeKey) {
			allNotes = append(allNotes, fmt.Sprintf("KEY %s not found for delete", keyRR.Hdr.Name))
			continue
		}
		keysToDelete = append(keysToDelete, keyRR)
	}
	recordsToDelete := make([]dns.RR, 0, len(recs.otherDeletes))
	for _, rr := range recs.otherDeletes {
		existing := h.leaseManager.LookupNonKEYRecord(rr)
		if existing == nil || existing.ParentKeyName != signerNodeKey {
			allNotes = append(allNotes, fmt.Sprintf("record not found for delete: %s", rr.String()))
			continue
		}
		recordsToDelete = append(recordsToDelete, rr)
	}
	if len(keysToDelete) > 0 || len(recordsToDelete) > 0 {
		deletesForUpstream = asDeletes(recordsToDelete...)
		for _, keyRR := range keysToDelete {
			deletesForUpstream = append(deletesForUpstream, subtreeDeletes(h.leaseManager, leasepkg.NodeKey(keyRR))...)
		}
		pendingMutations = append(pendingMutations, pendingLeaseMutation{
			keyName: signerNodeKey,
			apply: func() error {
				// Only the records named here: RemoveNonKEYRecords would forget every record of
				// the signer's, and leave those this request did not delete published with no
				// lease to end them.
				for _, rr := range recordsToDelete {
					if err := h.leaseManager.RemoveSingleNonKEYRecord(signerNodeKey, leasepkg.RecordKey(rr)); err != nil {
						return err
					}
				}
				if len(recordsToDelete) > 0 {
					h.scheduleLeaseExpiry(signerNodeKey)
				}
				for _, keyRR := range keysToDelete {
					forgetSubtree(h.leaseManager, h.timers, leasepkg.NodeKey(keyRR), "delete")
					h.logger.Debugf("Deleted key for %s", keyRR.Hdr.Name)
				}
				return nil
			},
		})
	}

	// Adds: registrations and refreshes, on the granted LEASE and KEY-LEASE.
	if recs.adds() {
		// A signer may only author new lease-store state in this request -- a new KEY RR, or
		// non-KEY RRs, which always belong to it (5.2.3) -- if it is already lease-managed, is
		// itself one of the KEY RRs this request adds, or (if configured) is an authorized
		// online-only signer. This is one policy regardless of record type; otherwise there is
		// no valid owner for the new state, and it must not be silently dropped or partially
		// applied, it must fail the request. A refresh of a KEY is its owner's
		// (authorizeKeyRefresh).
		signerManaged := h.leaseManager.LookupBySIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag) != nil
		signerInUpdate := false
		newKey := false
		for _, kr := range recs.keyAdds {
			if keyIDFromKEY(kr) == signerID {
				signerInUpdate = true
			}
			if h.leaseManager.LookupByKEY(kr) == nil {
				newKey = true
			}
		}
		if (newKey || len(recs.otherAdds) > 0) && !h.signerAuthorizedForNewRegistration(signerManaged, signerInUpdate, signerSource) {
			msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited,
				"signing key must be managed, present in the Update section, or (if allow_online_key_registration is enabled) an authorized online signer, to register new records")
			return NewErrorResult(msg, "signer not authorized for new registration",
				fmt.Errorf("signer %q is neither lease-managed, present in the Update section, nor an authorized online signer", sigRR.SignerName))
		}

		for _, keyRR := range recs.keyAdds {
			keyName := keyRR.Hdr.Name
			existingKey := h.leaseManager.LookupByKEY(keyRR)
			keyIsRefresh := existingKey != nil

			if keyIsRefresh {
				if err := h.authorizeKeyRefresh(keyRR, signerID); err != nil {
					msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited, err.Error())
					return NewErrorResult(msg, err.Error(), err)
				}
			} else {
				prereqs, res := h.refuseNewKey(ctx, r, keyRR, signerID, sigRR.SignerName)
				if res != nil {
					return res
				}
				fcfsPrereqs = append(fcfsPrereqs, prereqs...)
			}

			// Every path below stores this key's records once the upstream server has
			// applied them, when a store write must no longer fail (see the mutation loop at
			// the end): refuse now, before anything is sent, a record the store holds under
			// another key, or the authoritative server holds outside this proxy's management.
			acceptedRecords, notes, err := h.filterDuplicateRegistrations(ctx, leasepkg.NodeKey(keyRR), updateOtherRRsByKeyOwner[keyIDFromKEY(keyRR)])
			if err != nil {
				return refusalResult(r, "duplicate registration rejected", err)
			}
			acceptedRecordsForUpstream = append(acceptedRecordsForUpstream, acceptedRecords...)
			allNotes = append(allNotes, notes...)
			pendingKeyRR := keyRR
			pendingKeyName := keyName
			pendingRecords := acceptedRecords

			if keyIsRefresh {
				effectiveKeyLease, keyAtFQDN, err := h.effectiveRefreshKeyLease(ctx, keyRR, existingKey, keyLeaseDuration)
				if err != nil {
					msg := makeErrorResponse(r, dns.RcodeServerFailure, dns.ExtendedErrorNoReachableAuthority, fmt.Sprintf("authoritative key lookup failed: %v", err))
					return NewErrorResult(msg, "authoritative key lookup failed", err)
				}
				// Managed locally but missing at the DNS server, the KEY is registered
				// again with the lease time still left in the lease store (item 4.2), not
				// the full requested one; otherwise this is a refresh, and the KEY,
				// already published, is not sent again.
				pendingKeyLease := effectiveKeyLease
				pendingMutations = append(pendingMutations, pendingLeaseMutation{
					keyName: pendingKeyName,
					apply: func() error {
						if err := h.leaseManager.RenewLease(pendingKeyRR, pendingKeyLease, pendingKeyLease); err != nil {
							return err
						}
						if len(pendingRecords) > 0 {
							// Upsert rather than refresh-only: the records may include a
							// non-KEY RR that is new to this key even though the key
							// itself is being refreshed.
							if err := h.leaseManager.UpsertNonKEYRecords(leasepkg.NodeKey(pendingKeyRR), pendingRecords, leaseDuration, h.upstreamZone); err != nil {
								return err
							}
						}
						h.scheduleLeaseExpiry(leasepkg.NodeKey(pendingKeyRR))
						h.logger.Debugf("Lease refreshed for %s (key lease=%d, non-KEY lease=%d seconds)", pendingKeyName, pendingKeyLease, leaseDuration)
						return nil
					},
				})
				if !keyAtFQDN {
					upstreamKeys = append(upstreamKeys, keyRR)
				}
				continue
			}

			pendingMutations = append(pendingMutations, pendingLeaseMutation{
				keyName: pendingKeyName,
				apply: func() error {
					if err := h.registerKeyLease(signerID, pendingKeyRR, keyLeaseDuration, keyLeaseDuration); err != nil {
						return err
					}
					if len(pendingRecords) > 0 {
						if err := h.leaseManager.UpsertNonKEYRecords(leasepkg.NodeKey(pendingKeyRR), pendingRecords, leaseDuration, h.upstreamZone); err != nil {
							return err
						}
					}
					h.scheduleLeaseExpiry(leasepkg.NodeKey(pendingKeyRR))
					return nil
				},
			})

			h.logger.Debugf("Lease processed for %s (lease=%d seconds, key-lease=%d seconds)", keyName, leaseDuration, keyLeaseDuration)

			upstreamKeys = append(upstreamKeys, keyRR)
		}

		// Non-KEY RRs always belong to the signer (docs/siglease_rfc9664.md 5.2.3), grouped
		// above under signerID regardless of which KEY RR(s) are in this request. The loop
		// above only reaches that data when the signer itself is one of the KEY RRs it adds
		// (signerInUpdate). When it is not -- the signer adds records alone, or registers a
		// *different* KEY, an already-managed parent minting a new child or an authorized
		// online-only signer doing the same -- that data must still be attached to the
		// signer's own node here, or it is silently dropped.
		if !signerInUpdate {
			if dataForSigner := updateOtherRRsByKeyOwner[signerID]; len(dataForSigner) > 0 {
				// A signer this proxy leases whose KEY the authoritative DNS no longer has is
				// registered again with the lease time it has left (item 4.2), as a KEY in the
				// request is above.
				if signerLease := h.leaseManager.LookupBySIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag); signerLease != nil {
					remainingLease, keyAtFQDN, err := h.effectiveRefreshKeyLease(ctx, signerLease.KeyRR, signerLease, keyLeaseDuration)
					if err != nil {
						msg := makeErrorResponse(r, dns.RcodeServerFailure, dns.ExtendedErrorNoReachableAuthority, fmt.Sprintf("authoritative key lookup failed: %v", err))
						return NewErrorResult(msg, "authoritative key lookup failed", err)
					}
					if !keyAtFQDN {
						pendingKeyRR := signerLease.KeyRR
						pendingMutations = append(pendingMutations, pendingLeaseMutation{
							keyName: pendingKeyRR.Hdr.Name,
							apply: func() error {
								return h.leaseManager.RenewLease(pendingKeyRR, remainingLease, remainingLease)
							},
						})
						// The stored KEY, not one from this request, so it has not had its
						// TTL set above: set it on a copy, leaving the store's record alone.
						upstreamKeyRR := copyRR(pendingKeyRR).(*dns.KEY)
						upstreamKeyRR.Hdr.TTL = min(h.recordTTL, remainingLease)
						upstreamKeys = append(upstreamKeys, upstreamKeyRR)
						allNotes = append(allNotes, fmt.Sprintf("KEY %s was missing at the authoritative DNS and has been re-registered with remaining lease", pendingKeyRR.Hdr.Name))
					}
				}

				acceptedRecords, notes, err := h.filterDuplicateRegistrations(ctx, signerNodeKey, dataForSigner)
				if err != nil {
					return refusalResult(r, "duplicate registration rejected", err)
				}
				pendingMutations = append(pendingMutations, pendingLeaseMutation{
					keyName: signerNodeKey,
					apply: func() error {
						if err := h.leaseManager.UpsertNonKEYRecords(signerNodeKey, acceptedRecords, leaseDuration, h.upstreamZone); err != nil {
							return err
						}
						h.scheduleLeaseExpiry(signerNodeKey)
						return nil
					},
				})
				acceptedRecordsForUpstream = append(acceptedRecordsForUpstream, acceptedRecords...)
				allNotes = append(allNotes, notes...)
			}
		}
	}

	// Upstream forwarding: the deletes, the KEY RRs to register, and the non-KEY RRs to add,
	// all in one UPDATE, which the authoritative server applies as a whole (RFC 2136 S3.7):
	// a resolver sees a record replaced by another, never neither nor both, and the halves
	// of a request are confirmed or rejected together.
	if len(upstreamKeys) > 0 || len(acceptedRecordsForUpstream) > 0 || len(deletesForUpstream) > 0 {
		h.logger.Debugf("Sending UPDATE to upstream (configured zone=%s), keys=%d", h.upstreamZone, len(upstreamKeys))
		upstreamResp, err := h.upstream().send(ctx, fcfsPrereqs, upstreamUpdateRecords(deletesForUpstream, upstreamKeys, acceptedRecordsForUpstream))
		if err != nil {
			h.logger.Debugf("UPDATE for zone=%s keys=%d: %v", h.upstreamZone, len(upstreamKeys), err)
			if upstreamResp != nil && prerequisiteFailed(upstreamResp.Rcode, fcfsPrereqs) {
				// A KEY appeared, through another writer, at a name fcfsNewKey found free.
				return fcfsConflictResult(r, fmt.Sprintf("FCFS conflict detected atomically by upstream prerequisite: %v", err))
			}
			msg := makeErrorResponse(r, dns.RcodeServerFailure, dns.ExtendedErrorNoReachableAuthority, err.Error())
			return NewErrorResult(msg, err.Error(), err)
		}
		h.logger.Debugf("Upstream UPDATE response: Answers=%d, Ns=%d, Extra=%d",
			len(upstreamResp.Answer), len(upstreamResp.Ns), len(upstreamResp.Extra))
	}

	// The upstream server has applied the update, so a store write must not fail now: each
	// one can fail only on a state the checks above rule out while this request holds its
	// node locks -- a node renewed that is not in the store, or a record already registered
	// under another key (filterDuplicateRegistrations). A failure is therefore a bug, and the
	// store can no longer be left as it was, since DNS has changed: the records would stay
	// published with no lease to end them. It panics, as a lease expiry does on a store write
	// that fails after its upstream delete.
	for _, mutation := range pendingMutations {
		if err := mutation.apply(); err != nil {
			panic(fmt.Sprintf("update_handler: lease-store update of %s after the authoritative server applied it: %v", mutation.keyName, err))
		}
	}

	h.logger.Debugf("Sending success response (%d status notes)", len(allNotes))
	return NewProcessedResult(h.buildSuccessResponse(r, allNotes, grantedLease))
}

// requestLockSet returns the lease-store nodes Handle locks for one request
// (docs/siglease_rfc9664.md, "Node Locks"). Each KEY it deletes is locked together with that
// KEY's whole current subtree, which the delete cascades into, and each record it deletes.
// Each KEY and record it adds may be a registration, so it is locked together with the
// signer's node, their only possible parent: a new KEY is registered under its signer, and
// non-KEY records always belong to the signer. A refresh would not need the parent, but
// whether an RR is a refresh is only known from the checks this lock protects.
func (h *UpdateHandler) requestLockSet(signerID keyID, recs updateRecords) func() []string {
	return func() []string {
		ids := make([]string, 0, 1+len(recs.keyAdds)+len(recs.otherAdds)+len(recs.keyDeletes)+len(recs.otherDeletes))
		if recs.adds() {
			ids = append(ids, leasepkg.NodeKeyFromSIG(signerID.Name, signerID.Algorithm, signerID.KeyTag))
		}
		for _, keyRR := range recs.keyAdds {
			ids = append(ids, leasepkg.NodeKey(keyRR))
		}
		for _, keyRR := range recs.keyDeletes {
			nodeKey := leasepkg.NodeKey(keyRR)
			ids = append(ids, nodeKey)
			ids = append(ids, h.leaseManager.ListSubtreeKeys(nodeKey)...)
		}
		for _, rr := range slices.Concat(recs.otherAdds, recs.otherDeletes) {
			ids = append(ids, leasepkg.RecordKey(rr))
		}
		return ids
	}
}

// buildSuccessResponse builds a successful UPDATE response: leaseResponse with granted (the
// LEASE and KEY-LEASE actually applied after LeasePolicy clamping, so the client can detect if
// the proxy granted less than what was requested for either value; see grantedLeaseOption),
// plus the status notes.
func (h *UpdateHandler) buildSuccessResponse(r *dns.Msg, notes []string, granted *leasepkg.LeaseOption) *dns.Msg {
	resp := leaseResponse(r, granted)
	appendStatusNotes(resp, r, notes)
	return resp
}

// appendStatusNotes adds each note to resp as an Extended DNS Error option (RFC 8914):
// INFO-CODE 0, "Other", with the note as its EXTRA-TEXT. RFC 8914 S2 allows EDE in any
// response, NOERROR included, and more than one per message, and means EXTRA-TEXT for people
// to read, not for parsing. The options travel in resp's one OPT RR, so the reply still
// copies none of the request's sections (RFC 2136 S3.8). The notes, and the KEY RRs this
// handler used to echo, once went in the answer slot, which in an UPDATE reply is the
// Prerequisite section.
func appendStatusNotes(resp, req *dns.Msg, notes []string) {
	for _, note := range notes {
		dnsmsg.AddEDE(resp, req, dns.ExtendedErrorOther, note)
	}
}
