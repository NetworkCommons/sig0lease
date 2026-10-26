package handlers

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	if res := h.refuseNamesNotServed(r); res != nil {
		h.logger.Debugf("Refusing UPDATE: %v", res.Error)
		return res
	}

	if len(r.Question) != 1 {
		msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther, "exactly one question required")
		return NewErrorResult(msg, "invalid question count", fmt.Errorf("multiple questions"))
	}

	// Extract zone and class from question
	qHeader := r.Question[0].Header()
	zone := qHeader.Name
	class := qHeader.Class

	h.logger.Debugf("UPDATE for zone: %s (class: %d)", zone, class)

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

	updateKeyRRs, updateOtherRRs, err := extractUpdateRecords(r, h.blacklistedTypes)
	if err != nil {
		h.logger.Debugf("Invalid update records: %v", err)
		var blacklisted *blacklistedTypeError
		if errors.As(err, &blacklisted) {
			msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited, err.Error())
			return NewErrorResult(msg, err.Error(), err)
		}
		msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	leaseDuration, keyLeaseDuration := requestedLeases(requestedLease, len(updateKeyRRs) > 0, len(updateOtherRRs) > 0)

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

	h.logger.Infof("UPDATE request for zone %s: LEASE=%d KEY-LEASE=%d RRs=%s",
		zone, leaseDuration, keyLeaseDuration, summarizeRRTypes(updateKeyRRs, updateOtherRRs))

	additionalSigningKeys, err := extractAdditionalSigningKeys(r)
	if err != nil {
		h.logger.Debugf("Invalid Additional KEY records: %v", err)
		msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	sigRR, signerKey, signerSource, err := h.extractAndValidateSig0(ctx, r, zone, additionalSigningKeys, updateKeyRRs)
	if err != nil {
		h.logger.Debugf("SIG(0) validation failed: %v", err)
		return refusalResult(r, "SIG(0) validation failed", fmt.Errorf("SIG(0) validation failed: %w", err))
	}

	// Replace the requester's TTLs with record_ttl_sec (see parseRecordTTL), cut to the
	// granted KEY-LEASE on KEYs and to the granted LEASE on everything else -- one TTL per
	// RRset, so RFC 2181 S5.2 holds whatever the requester sent. Done in place, after the
	// signature over the original TTLs is checked, so the lease store keeps what the zone
	// gets. Records under a lease of 0 (Cases C and D) are deletes, which go upstream with
	// TTL 0 anyway.
	for _, keyRR := range updateKeyRRs {
		keyRR.Hdr.TTL = min(h.recordTTL, keyLeaseDuration)
	}
	for _, rr := range updateOtherRRs {
		rr.Header().TTL = min(h.recordTTL, leaseDuration)
	}

	if err := h.validateSignerHierarchyForUpdateRecords(sigRR.SignerName, updateKeyRRs, updateOtherRRs); err != nil {
		h.logger.Debugf("Update hierarchy validation failed: %v", err)
		msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited, fmt.Sprintf("hierarchy validation failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("hierarchy validation failed: %v", err), err)
	}

	signerID := keyIDFromSIG(sigRR)
	// useHierarchy is hardcoded false: non-KEY RRs always belong to the
	// signer (docs/siglease_rfc9664.md 5.1.4). See groupOtherRecordsByTargetKey's doc
	// comment -- the useHierarchy=true path is reserved for a possible
	// future config option and is not reachable from here today.
	updateOtherRRsByKeyOwner, err := groupOtherRecordsByTargetKey(signerID, updateKeyRRs, updateOtherRRs, false)
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

	// Log all extracted request KEY RRs.
	for i, keyRR := range updateKeyRRs {
		h.logger.Debugf("Extracted request KEY RR[%d]: %s", i, keyRR.String())
	}

	// From here to the local apply, this request reads lease-store nodes, writes upstream, and
	// then changes those nodes: hold their locks throughout, waiting while another request or
	// a lease expiry holds any of them (docs/siglease_rfc9664.md, "Node Locks"). Taken only
	// now, after SIG(0) verification, so an unverified request can never hold a lock.
	locks, err := h.nodeLocks.Acquire(ctx, h.requestLockSet(leaseDuration, keyLeaseDuration, signerID, updateKeyRRs, updateOtherRRs))
	if err != nil {
		h.logger.Warnf("UPDATE for zone %s: %v", zone, err)
		msg := makeErrorResponse(r, dns.RcodeServerFailure, dns.ExtendedErrorOther, "lease store busy, try again")
		return NewErrorResult(msg, "lease-store node lock contention", err)
	}
	defer locks.Release()

	// KEY-LEASE!=0, LEASE!=0 requires at least one KEY RR and a Non-KEY RRs.

	var allNotes []string
	upstreamKeys := make([]*dns.KEY, 0)
	var acceptedRecordsForUpstream []dns.RR
	// recordsToDeleteForUpstream accumulates Case D's accompanying non-KEY
	// deletes (see the case-D loop below), forwarded in the same shared
	// upstream call as the KEY add/refresh at the end of Handle().
	var recordsToDeleteForUpstream []dns.RR
	// fcfsPrereqs are the prerequisites fcfs_naming attaches to the upstream UPDATE for the
	// KEYs registered anew (refuseNewKey).
	var fcfsPrereqs []dns.RR
	type pendingLeaseMutation struct {
		keyName string
		apply   func() error
	}
	pendingMutations := make([]pendingLeaseMutation, 0)

	// Case dispatch is defined by the LEASE / KEY-LEASE matrix at top level.
	if keyLeaseDuration != 0 && leaseDuration != 0 {
		// Case A: full registration/refresh, requires at least one KEY and one non-KEY RR.
		if len(updateKeyRRs) == 0 || len(updateOtherRRs) == 0 {
			msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther,
				"KEY-LEASE!=0 and LEASE!=0 requires at least one KEY RR and one non-KEY RR")
			return NewErrorResult(msg, "invalid update for register/refresh", fmt.Errorf("missing required KEY and/or non-KEY record"))
		}

		// A signer may only author new registrations in this request — the new
		// KEY RR(s) below, and ownership of the non-KEY RRs that always
		// accompany them in Case A — if it is already lease-managed, is
		// itself one of the KEY RRs in this Update section, or (if
		// configured) is an authorized online-only signer. This is one
		// policy regardless of record type; otherwise there is no valid
		// owner for the new state, and it must not be silently dropped or
		// partially applied, it must fail the request.
		signerManaged := h.leaseManager.LookupBySIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag) != nil
		signerInUpdate := false
		for _, kr := range updateKeyRRs {
			if keyIDFromKEY(kr) == signerID {
				signerInUpdate = true
				break
			}
		}
		if !h.signerAuthorizedForNewRegistration(signerManaged, signerInUpdate, signerSource) {
			msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited,
				"signing key must be managed, present in the Update section, or (if allow_online_key_registration is enabled) an authorized online signer, to register new records")
			return NewErrorResult(msg, "signer not authorized for new registration",
				fmt.Errorf("signer %q is neither lease-managed, present in the Update section, nor an authorized online signer", sigRR.SignerName))
		}

		for _, keyRR := range updateKeyRRs {
			keyName := keyRR.Hdr.Name
			existingKey := h.leaseManager.LookupByKEY(keyRR)
			keyIsRefresh := existingKey != nil

			if keyIsRefresh {
				if err := h.authorizeKeyRefresh(keyRR, signerID); err != nil {
					msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited, err.Error())
					return NewErrorResult(msg, err.Error(), err)
				}
			} else {
				prereqs, res := h.refuseNewKey(ctx, r, zone, keyRR, signerID, sigRR.SignerName)
				if res != nil {
					return res
				}
				fcfsPrereqs = append(fcfsPrereqs, prereqs...)
				// Signer authorization for new registrations was already
				// checked once for the whole request above; Case A always
				// requires non-KEY RRs, so that check already covers this path.
			}

			// Every path below stores this key's records once the upstream server has
			// applied them, when a store write must no longer fail (see the mutation loop at
			// the end): refuse now, before anything is sent, a record the store holds under
			// another key, or the authoritative server holds outside this proxy's management.
			acceptedRecords, notes, err := h.filterDuplicateRegistrations(ctx, leasepkg.NodeKey(keyRR), zone, updateOtherRRsByKeyOwner[keyIDFromKEY(keyRR)])
			if err != nil {
				return refusalResult(r, "duplicate registration rejected", err)
			}
			acceptedRecordsForUpstream = append(acceptedRecordsForUpstream, acceptedRecords...)
			allNotes = append(allNotes, notes...)
			pendingKeyRR := keyRR
			pendingKeyName := keyName
			pendingRecords := acceptedRecords

			if keyIsRefresh {
				effectiveKeyLease, keyAtFQDN, err := h.effectiveRefreshKeyLease(ctx, zone, keyRR, existingKey, keyLeaseDuration)
				if err != nil {
					msg := makeErrorResponse(r, dns.RcodeServerFailure, dns.ExtendedErrorNoReachableAuthority, fmt.Sprintf("authoritative key lookup failed: %v", err))
					return NewErrorResult(msg, "authoritative key lookup failed", err)
				}
				if !keyAtFQDN {
					// Key is managed locally but missing at the DNS server: re-register
					// it with the lease time that is still left in the lease store.
					pendingKeyLease := effectiveKeyLease
					pendingMutations = append(pendingMutations, pendingLeaseMutation{
						keyName: pendingKeyName,
						apply: func() error {
							if err := h.leaseManager.RenewLease(pendingKeyRR, pendingKeyLease, pendingKeyLease); err != nil {
								return err
							}
							if err := h.leaseManager.UpsertNonKEYRecords(leasepkg.NodeKey(pendingKeyRR), pendingRecords, leaseDuration, h.upstreamZone); err != nil {
								return err
							}
							h.scheduleLeaseExpiry(leasepkg.NodeKey(pendingKeyRR))
							h.logger.Debugf("Lease renewed for %s (KEY-LEASE != 0, key missing at FQDN, remaining key lease=%d)", pendingKeyName, pendingKeyLease)
							return nil
						},
					})
					upstreamKeys = append(upstreamKeys, keyRR)
					continue
				}

				// Normal refresh: ownership already validated above. Defer the
				// actual write until upstream confirms success, same as every
				// other lease-store mutation.
				pendingMutations = append(pendingMutations, pendingLeaseMutation{
					keyName: pendingKeyName,
					apply: func() error {
						if err := h.leaseManager.RenewLease(pendingKeyRR, keyLeaseDuration, keyLeaseDuration); err != nil {
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
						h.logger.Debugf("Lease refreshed for %s (non-KEY lease=%d seconds)", pendingKeyName, leaseDuration)
						return nil
					},
				})
				continue
			}

			// Normal path (not refresh): KEY-LEASE != 0 and LEASE != 0.
			pendingMutations = append(pendingMutations, pendingLeaseMutation{
				keyName: pendingKeyName,
				apply: func() error {
					if err := h.registerKeyLease(keyIDFromSIG(sigRR), pendingKeyRR, keyLeaseDuration, keyLeaseDuration); err != nil {
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

		// Non-KEY RRs always belong to the signer (docs/siglease_rfc9664.md 5.1.4), grouped
		// above under signerID regardless of which KEY RR(s) are in this
		// request. The loop above only reaches that data when the signer
		// itself is one of the iterated KEY RRs (signerInUpdate). When the
		// signer is instead delegating a *different* KEY's registration --
		// an already-managed parent minting a new child, or an authorized
		// online-only signer doing the same -- that data must still be
		// attached to the signer's own node here, or it is silently dropped.
		if !signerInUpdate {
			dataForSigner := updateOtherRRsByKeyOwner[signerID]
			if len(dataForSigner) > 0 {
				signerNodeKey := leasepkg.NodeKeyFromSIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag)
				acceptedRecords, notes, err := h.filterDuplicateRegistrations(ctx, signerNodeKey, zone, dataForSigner)
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
	} else if keyLeaseDuration == 0 && leaseDuration != 0 {
		// Case B: non-KEY-only registration/refresh.
		if len(updateOtherRRs) == 0 {
			msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther,
				"KEY-LEASE=0 and LEASE!=0 requires at least one non-KEY RR")
			return NewErrorResult(msg, "invalid non-KEY-only lease request", fmt.Errorf("no non-KEY RR present"))
		}
		if len(updateKeyRRs) > 0 {
			msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther,
				"KEY-LEASE=0 and LEASE!=0 does not allow KEY RRs in Update section")
			return NewErrorResult(msg, "invalid non-KEY-only lease request", fmt.Errorf("unexpected KEY RR in non-KEY-only lease request"))
		}

		signerLease := h.leaseManager.LookupBySIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag)
		if signerLease == nil {
			msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited,
				"KEY-LEASE=0 and LEASE!=0 requires signing KEY to already be managed")
			return NewErrorResult(msg, "signing key not managed for non-KEY-only lease", fmt.Errorf("signing key not found in lease store"))
		}

		signerOwnerKey := leasepkg.NodeKey(signerKey)
		keyExists, err := h.authoritativeHasKeyAtName(ctx, zone, signerKey.Hdr.Name)
		if err != nil {
			msg := makeErrorResponse(r, dns.RcodeServerFailure, dns.ExtendedErrorNoReachableAuthority, fmt.Sprintf("authoritative key lookup failed: %v", err))
			return NewErrorResult(msg, "authoritative key lookup failed", err)
		}
		if !keyExists {
			// Key is managed locally but missing at the DNS server: put it back
			// with the lease time still remaining in the lease store, mirroring
			// Case A's re-registration behavior, instead of failing the request.
			remainingLease := uint32(signerLease.TimeRemaining() / time.Second)
			if remainingLease == 0 {
				remainingLease = 1
			}
			pendingKeyRR := signerLease.KeyRR
			pendingKeyLease := remainingLease
			pendingMutations = append(pendingMutations, pendingLeaseMutation{
				keyName: pendingKeyRR.Hdr.Name,
				apply: func() error {
					return h.leaseManager.RenewLease(pendingKeyRR, pendingKeyLease, pendingKeyLease)
				},
			})
			// The stored KEY, not one from this request (KEY-LEASE is 0 here), so it has
			// not had its TTL set above: set it on a copy, leaving the store's record alone.
			upstreamKeyRR := copyRR(pendingKeyRR).(*dns.KEY)
			upstreamKeyRR.Hdr.TTL = min(h.recordTTL, pendingKeyLease)
			upstreamKeys = append(upstreamKeys, upstreamKeyRR)
			allNotes = append(allNotes, fmt.Sprintf("KEY %s was missing at the authoritative DNS and has been re-registered with remaining lease", pendingKeyRR.Hdr.Name))
		}

		acceptedRecords, notes, err := h.filterDuplicateRegistrations(ctx, signerOwnerKey, zone, updateOtherRRs)
		if err != nil {
			return refusalResult(r, "duplicate registration rejected", err)
		}
		if len(acceptedRecords) > 0 {
			pendingMutations = append(pendingMutations, pendingLeaseMutation{
				keyName: signerOwnerKey,
				apply: func() error {
					if err := h.leaseManager.UpsertNonKEYRecords(signerOwnerKey, acceptedRecords, leaseDuration, h.upstreamZone); err != nil {
						return err
					}
					h.scheduleLeaseExpiry(signerOwnerKey)
					return nil
				},
			})
		}

		acceptedRecordsForUpstream = append(acceptedRecordsForUpstream, acceptedRecords...)
		allNotes = append(allNotes, notes...)
	} else if keyLeaseDuration == 0 && leaseDuration == 0 {
		// Case C: delete matrix. Only forward upstream, and only touch the
		// local lease store, for records we actually manage; records that
		// aren't found locally are reported via a note but otherwise ignored
		// (docs/siglease_rfc9664.md item 7).
		//
		// Authorization is ownership-based, not just DNS-name hierarchy: a
		// record (KEY or non-KEY) may only be deleted by its immediate
		// parent -- the KEY that registered it -- or, for a KEY, by itself,
		// whoever registered it.
		// A signer merely hierarchically "at or above" a record it did not
		// itself register cannot delete it directly; it can only reach that
		// data by deleting the record's actual parent, which cascades.
		if len(updateKeyRRs) == 0 && len(updateOtherRRs) == 0 {
			msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther,
				"KEY-LEASE=0 and LEASE=0 requires at least one KEY RR or one non-KEY RR")
			return NewErrorResult(msg, "invalid delete request", fmt.Errorf("no records present for delete"))
		}

		signerOwnerKey := leasepkg.NodeKey(signerKey)

		keysToDelete := make([]*dns.KEY, 0, len(updateKeyRRs))
		for _, keyRR := range updateKeyRRs {
			existing := h.leaseManager.LookupByKEY(keyRR)
			isSelf := keyIDFromKEY(keyRR) == signerID
			if existing == nil || (!isSelf && existing.ParentKeyName != signerOwnerKey) {
				allNotes = append(allNotes, fmt.Sprintf("KEY %s not found for delete", keyRR.Hdr.Name))
				continue
			}
			keysToDelete = append(keysToDelete, keyRR)
		}

		recordsToDelete := make([]dns.RR, 0, len(updateOtherRRs))
		for _, rr := range updateOtherRRs {
			existing := h.leaseManager.LookupNonKEYRecord(rr)
			if existing == nil || existing.ParentKeyName != signerOwnerKey {
				allNotes = append(allNotes, fmt.Sprintf("record not found for delete: %s", rr.String()))
				continue
			}
			recordsToDelete = append(recordsToDelete, rr)
		}

		if len(keysToDelete) == 0 && len(recordsToDelete) == 0 {
			// Nothing locally managed to delete, so there is nothing to
			// confirm upstream either: just report the notes.
			return NewProcessedResult(h.buildSuccessResponse(r, allNotes, grantedLease))
		}

		// One UPDATE deletes the records named here and, for each named KEY, everything at and
		// below it -- a KEY's delete takes its subtree along, exactly as its expiry does
		// (subtreeLeases, leaseExpirer). Nothing is forgotten locally before that UPDATE is
		// confirmed; if it is not, the request fails and nothing has changed.
		deletes := asDeletes(recordsToDelete...)
		for _, keyRR := range keysToDelete {
			keys, records := subtreeLeases(h.leaseManager, leasepkg.NodeKey(keyRR))
			deletes = append(deletes, asDeletes(keys...)...)
			deletes = append(deletes, recordDeletes(records)...)
		}
		if _, err := h.upstream().send(ctx, nil, deletes); err != nil {
			msg := makeErrorResponse(r, dns.RcodeServerFailure, dns.ExtendedErrorNoReachableAuthority, err.Error())
			return NewErrorResult(msg, err.Error(), err)
		}

		// Upstream confirmed. Remove only the records named here --
		// h.leaseManager.RemoveNonKEYRecords(signerOwnerKey) would wipe the owner's *entire*
		// non-KEY record set locally, silently forgetting (and thus orphaning upstream forever)
		// any other records under the same owner that this request never asked to delete --
		// and each named KEY's subtree.
		for _, rr := range recordsToDelete {
			if err := h.leaseManager.RemoveSingleNonKEYRecord(signerOwnerKey, leasepkg.RecordKey(rr)); err != nil {
				panic(fmt.Sprintf("Case C delete of %s: %v", rr.String(), err))
			}
		}
		for _, keyRR := range keysToDelete {
			nodeKey := leasepkg.NodeKey(keyRR)
			for _, descendant := range append([]string{nodeKey}, h.leaseManager.ListSubtreeKeys(nodeKey)...) {
				h.timers.disarm(descendant)
			}
			if err := h.leaseManager.DeleteSubtree(nodeKey); err != nil {
				panic(fmt.Sprintf("Case C delete of %s: %v", nodeKey, err))
			}
			h.logger.Debugf("Deleted key for %s (KEY-LEASE=0, LEASE=0)", keyRR.Hdr.Name)
		}

		return NewProcessedResult(h.buildSuccessResponse(r, allNotes, grantedLease))
	} else if keyLeaseDuration != 0 && leaseDuration == 0 {
		// Case D: KEY-only registration/refresh with optional non-KEY deletes.
		if len(updateKeyRRs) == 0 {
			msg := makeErrorResponse(r, dns.RcodeFormatError, dns.ExtendedErrorOther,
				"KEY-LEASE!=0 and LEASE=0 requires at least one KEY RR")
			return NewErrorResult(msg, "invalid key-only lease request", fmt.Errorf("missing required KEY record"))
		}

		signerManaged := h.leaseManager.LookupBySIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag) != nil
		signerInUpdate := false
		for _, kr := range updateKeyRRs {
			if keyIDFromKEY(kr) == signerID {
				signerInUpdate = true
				break
			}
		}

		for _, keyRR := range updateKeyRRs {
			keyName := keyRR.Hdr.Name
			scopedOtherRecords := updateOtherRRsByKeyOwner[keyIDFromKEY(keyRR)]
			notes := make([]string, 0)
			// Only records actually present locally are real deletions: a
			// record named here that isn't found gets a note (docs/siglease_rfc9664.md
			// item 7) but must not be sent upstream as a delete or removed
			// from local state that never had it.
			recordsToDelete := make([]dns.RR, 0, len(scopedOtherRecords))
			for _, rr := range scopedOtherRecords {
				existing := h.leaseManager.LookupNonKEYRecord(rr)
				if existing == nil || existing.ParentKeyName != leasepkg.NodeKey(keyRR) {
					notes = append(notes, fmt.Sprintf("record not found for delete: %s", rr.String()))
					continue
				}
				recordsToDelete = append(recordsToDelete, rr)
			}

			effectiveKeyLease := keyLeaseDuration
			existingKey := h.leaseManager.LookupByKEY(keyRR)
			keyIsRefresh := existingKey != nil
			if !keyIsRefresh {
				// New KEY registration: the same checks as Case A's
				// (docs/siglease_rfc9664.md item 6 applies to every case, not just Case A).
				prereqs, res := h.refuseNewKey(ctx, r, zone, keyRR, signerID, sigRR.SignerName)
				if res != nil {
					return res
				}
				fcfsPrereqs = append(fcfsPrereqs, prereqs...)
				if !h.signerAuthorizedForNewRegistration(signerManaged, signerInUpdate, signerSource) {
					msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited,
						"signing key must be managed, present in the Update section, or (if allow_online_key_registration is enabled) an authorized online signer, to register a new KEY RR")
					return NewErrorResult(msg, "signer not authorized for new registration",
						fmt.Errorf("signer %q is neither lease-managed, present in the Update section, nor an authorized online signer", sigRR.SignerName))
				}
			} else {
				if err := h.authorizeKeyRefresh(keyRR, signerID); err != nil {
					msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited, err.Error())
					return NewErrorResult(msg, err.Error(), err)
				}
				// Key is managed locally but missing at the DNS server: put it
				// back with the lease time still remaining, rather than granting
				// the full newly-requested duration.
				lease, _, err := h.effectiveRefreshKeyLease(ctx, zone, keyRR, existingKey, keyLeaseDuration)
				if err != nil {
					msg := makeErrorResponse(r, dns.RcodeServerFailure, dns.ExtendedErrorNoReachableAuthority, fmt.Sprintf("authoritative key lookup failed: %v", err))
					return NewErrorResult(msg, "authoritative key lookup failed", err)
				}
				effectiveKeyLease = lease
			}

			pendingKeyRR := keyRR
			pendingKeyName := keyName
			pendingRecordsToRemove := recordsToDelete
			pendingKeyLease := effectiveKeyLease
			pendingIsRefresh := keyIsRefresh
			pendingMutations = append(pendingMutations, pendingLeaseMutation{
				keyName: pendingKeyName,
				apply: func() error {
					var err error
					if pendingIsRefresh {
						err = h.leaseManager.RenewLease(pendingKeyRR, pendingKeyLease, pendingKeyLease)
					} else {
						err = h.registerKeyLease(keyIDFromSIG(sigRR), pendingKeyRR, pendingKeyLease, pendingKeyLease)
					}
					if err != nil {
						return err
					}
					// Remove only the specific records confirmed deleted
					// upstream (see recordsToDeleteForUpstream below) --
					// h.leaseManager.RemoveNonKEYRecords(nodeKey) would wipe
					// every non-KEY record this key owns, including ones this
					// request never named, silently orphaning them upstream
					// forever. The upstream delete for these records was
					// already confirmed successful before apply() ever runs
					// (see the shared upstream-forwarding block below), and
					// this request holds their node locks, so a failure here
					// (the record owned by another node) is impossible: it
					// fails hard, as in Case C and lease expiry.
					for _, rr := range pendingRecordsToRemove {
						if err := h.leaseManager.RemoveSingleNonKEYRecord(leasepkg.NodeKey(pendingKeyRR), leasepkg.RecordKey(rr)); err != nil {
							panic(fmt.Sprintf("Case D delete of %s for %s: %v", rr.String(), pendingKeyName, err))
						}
					}
					h.scheduleLeaseExpiry(leasepkg.NodeKey(pendingKeyRR))
					return nil
				},
			})

			upstreamKeys = append(upstreamKeys, keyRR)
			recordsToDeleteForUpstream = append(recordsToDeleteForUpstream, recordsToDelete...)
			allNotes = append(allNotes, notes...)
		}
	}

	// Upstream forwarding: forward KEY RRs that need to be registered
	// upstream, non-KEY RRs that need to be added, and (Case D) non-KEY
	// records that need to be deleted -- all in one combined UPDATE, so
	// the add and delete halves of a single request are confirmed or
	// rejected together rather than racing across two separate round trips.
	if len(upstreamKeys) > 0 || len(acceptedRecordsForUpstream) > 0 || len(recordsToDeleteForUpstream) > 0 {
		h.logger.Debugf("Sending UPDATE to upstream (configured zone=%s), keys=%d", h.upstreamZone, len(upstreamKeys))
		upstreamResp, err := h.upstream().send(ctx, fcfsPrereqs, upstreamUpdateRecords(upstreamKeys, acceptedRecordsForUpstream, recordsToDeleteForUpstream))
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
// (docs/siglease_rfc9664.md, "Node Locks"). A delete (Case C: LEASE=0, KEY-LEASE=0) locks each
// KEY it names together with that KEY's whole current subtree, which the delete cascades
// into, and each non-KEY record it names. Every other case may register what it names, so it
// locks each named KEY and non-KEY record together with the signer's node, their only
// possible parent: a new KEY is registered under its signer, and non-KEY records always
// belong to the signer. A refresh would not need the parent, but whether an RR is a refresh
// is only known from the checks this lock protects.
func (h *UpdateHandler) requestLockSet(leaseDuration, keyLeaseDuration uint32, signerID keyID, keyRRs []*dns.KEY, otherRRs []dns.RR) func() []string {
	deleting := leaseDuration == 0 && keyLeaseDuration == 0
	return func() []string {
		ids := make([]string, 0, 1+len(keyRRs)+len(otherRRs))
		if !deleting {
			ids = append(ids, leasepkg.NodeKeyFromSIG(signerID.Name, signerID.Algorithm, signerID.KeyTag))
		}
		for _, keyRR := range keyRRs {
			nodeKey := leasepkg.NodeKey(keyRR)
			ids = append(ids, nodeKey)
			if deleting {
				ids = append(ids, h.leaseManager.ListSubtreeKeys(nodeKey)...)
			}
		}
		for _, rr := range otherRRs {
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
