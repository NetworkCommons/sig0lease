package handlers

import (
	"context"
	"fmt"
	"time"

	"codeberg.org/miekg/dns"
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

	if len(r.Question) != 1 {
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, "exactly one question required")
		return NewErrorResult(msg, "invalid question count", fmt.Errorf("multiple questions"))
	}

	// Extract zone and class from question
	qHeader := r.Question[0].Header()
	zone := qHeader.Name
	class := qHeader.Class

	h.logger.Debugf("UPDATE for zone: %s (class: %d)", zone, class)

	leaseDuration, keyLeaseDuration, err := h.parseLease(r)
	if err != nil {
		h.logger.Debugf("Lease parsing failed: %v", err)
		msg := h.makeErrorResponse(r, uint16(16), fmt.Sprintf("invalid lease: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("lease parsing failed: %v", err), err)
	}

	originalLeaseDuration := leaseDuration
	originalKeyLeaseDuration := keyLeaseDuration
	leaseDuration, keyLeaseDuration = h.clampLeaseDurations(leaseDuration, keyLeaseDuration)
	if leaseDuration != originalLeaseDuration || keyLeaseDuration != originalKeyLeaseDuration {
		h.logger.Debugf("Lease policy clamped request durations: lease=%d->%d key-lease=%d->%d",
			originalLeaseDuration, leaseDuration, originalKeyLeaseDuration, keyLeaseDuration)
	}

	h.logger.Debugf("Parsed lease duration: %d seconds key-lease=%d", leaseDuration, keyLeaseDuration)

	updateKeyRRs, updateOtherRRs, err := extractUpdateRecords(r, h.blacklistedTypes)
	if err != nil {
		h.logger.Debugf("Invalid update records: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}
	h.logger.Infof("UPDATE request for zone %s: LEASE=%d KEY-LEASE=%d RRs=%s",
		zone, leaseDuration, keyLeaseDuration, summarizeRRTypes(updateKeyRRs, updateOtherRRs))

	additionalSigningKeys, err := extractAdditionalSigningKeys(r)
	if err != nil {
		h.logger.Debugf("Invalid Additional KEY records: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	sigRR, signerKey, signerSource, err := h.extractAndValidateSig0(ctx, r, zone, additionalSigningKeys, updateKeyRRs)
	if err != nil {
		h.logger.Debugf("SIG(0) validation failed: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("SIG(0) validation failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("SIG(0) validation failed: %v", err), err)
	}

	if err := h.validateSignerHierarchyForUpdateRecords(sigRR.SignerName, updateKeyRRs, updateOtherRRs); err != nil {
		h.logger.Debugf("Update hierarchy validation failed: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("hierarchy validation failed: %v", err))
		return NewErrorResult(msg, fmt.Sprintf("hierarchy validation failed: %v", err), err)
	}

	signerID := keyIDFromSIG(sigRR)
	updateOtherRRsByKeyOwner, err := groupOtherRecordsByTargetKey(signerID, updateKeyRRs, updateOtherRRs, false)
	if err != nil {
		h.logger.Debugf("Failed to map non-KEY records to KEY owners: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("invalid mixed-owner update: %v", err))
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

	// KEY-LEASE!=0, LEASE!=0 requires at least one KEY RR and a Non-KEY RRs.

	var allNotes []string
	var responseKeys []*dns.KEY
	upstreamKeys := make([]*dns.KEY, 0)
	var acceptedRecordsForUpstream []dns.RR
	type pendingLeaseMutation struct {
		keyName string
		apply   func() error
	}
	pendingMutations := make([]pendingLeaseMutation, 0)

	// Case dispatch is defined by the LEASE / KEY-LEASE matrix at top level.
	if keyLeaseDuration != 0 && leaseDuration != 0 {
		// Case A: full registration/refresh, requires at least one KEY and one non-KEY RR.
		if len(updateKeyRRs) == 0 || len(updateOtherRRs) == 0 {
			msg := h.makeErrorResponse(r, dns.RcodeFormatError,
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
			msg := h.makeErrorResponse(r, dns.RcodeRefused,
				"signing key must be managed, present in the Update section, or (if allow_online_key_registration is enabled) an authorized online signer, to register new records")
			return NewErrorResult(msg, "signer not authorized for new registration",
				fmt.Errorf("signer %q is neither lease-managed, present in the Update section, nor an authorized online signer", sigRR.SignerName))
		}

		for _, keyRR := range updateKeyRRs {
			keyName := keyRR.Hdr.Name
			scopedOtherRecords := updateOtherRRsByKeyOwner[keyIDFromKEY(keyRR)]
			existingKey := h.leaseManager.LookupByKEY(keyRR)
			keyIsRefresh := existingKey != nil

			if keyIsRefresh {
				if err := h.validateRefreshOwnership(keyRR); err != nil {
					msg := h.makeErrorResponse(r, dns.RcodeRefused, err.Error())
					return NewErrorResult(msg, err.Error(), err)
				}

				keyAtFQDN, err := h.authoritativeHasKeyAtName(ctx, zone, keyRR.Hdr.Name)
				if err != nil {
					msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("authoritative key lookup failed: %v", err))
					return NewErrorResult(msg, "authoritative key lookup failed", err)
				}
				if !keyAtFQDN {
					remainingLease := uint32(existingKey.TimeRemaining() / time.Second)
					if remainingLease == 0 {
						remainingLease = 1
					}

					// Key is managed locally but missing at the DNS server: re-register
					// it with the lease time that is still left in the lease store.
					pendingKeyRR := keyRR
					pendingKeyName := keyName
					pendingRecords := scopedOtherRecords
					pendingKeyLease := remainingLease
					pendingMutations = append(pendingMutations, pendingLeaseMutation{
						keyName: pendingKeyName,
						apply: func() error {
							if err := h.registerKeyLease(ctx, keyIDFromSIG(sigRR), pendingKeyRR, pendingKeyLease, pendingKeyLease); err != nil {
								return err
							}
							h.setNonKeyLease(leasepkg.NodeKey(pendingKeyRR), pendingRecords, leaseDuration, h.upstreamZone)
							h.scheduleLeaseExpiry(leasepkg.NodeKey(pendingKeyRR))
							h.logger.Debugf("Lease re-registered for %s (KEY-LEASE != 0, key missing at FQDN, remaining key lease=%d)", pendingKeyName, pendingKeyLease)
							return nil
						},
					})

					responseKeys = append(responseKeys, keyRR)
					upstreamKeys = append(upstreamKeys, keyRR)
					acceptedRecordsForUpstream = append(acceptedRecordsForUpstream, scopedOtherRecords...)
					continue
				}

				// Normal refresh: ownership already validated above. Defer the
				// actual write until upstream confirms success, same as every
				// other lease-store mutation.
				pendingKeyRR := keyRR
				pendingKeyName := keyName
				pendingRecords := scopedOtherRecords
				pendingMutations = append(pendingMutations, pendingLeaseMutation{
					keyName: pendingKeyName,
					apply: func() error {
						if err := h.registerKeyLease(ctx, keyIDFromSIG(sigRR), pendingKeyRR, keyLeaseDuration, keyLeaseDuration); err != nil {
							return err
						}
						if len(pendingRecords) > 0 {
							// Upsert rather than refresh-only: scopedOtherRecords may
							// include a non-KEY RR that is new to this key even though
							// the key itself is being refreshed.
							h.setNonKeyLease(leasepkg.NodeKey(pendingKeyRR), pendingRecords, leaseDuration, h.upstreamZone)
						}
						h.scheduleLeaseExpiry(leasepkg.NodeKey(pendingKeyRR))
						h.logger.Debugf("Lease refreshed for %s (non-KEY lease=%d seconds)", pendingKeyName, leaseDuration)
						return nil
					},
				})

				responseKeys = append(responseKeys, keyRR)
				acceptedRecordsForUpstream = append(acceptedRecordsForUpstream, scopedOtherRecords...)
				continue
			}

			// Normal path (not refresh): KEY-LEASE != 0 and LEASE != 0.
			partialNotes := make([]string, 0)
			registerKey := true
			if h.leaseManager.LookupByKEY(keyRR) == nil {
				exists, err := h.authoritativeHasRR(ctx, zone, keyRR)
				if err != nil {
					msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("authoritative duplicate check failed: %v", err))
					return NewErrorResult(msg, "authoritative duplicate check failed", err)
				}
				if exists {
					msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("duplicate registration rejected: authoritative RR already exists for %s", keyRR.String()))
					return NewErrorResult(msg, "duplicate registration rejected", fmt.Errorf("authoritative RR already exists for %s", keyRR.String()))
				}
				// Signer authorization for new registrations was already
				// checked once for the whole request above; Case A always
				// requires non-KEY RRs, so that check already covers this path.
			}

			acceptedRecords, notes, err := h.filterDuplicateRegistrations(ctx, leasepkg.NodeKey(keyRR), zone, scopedOtherRecords)
			if err != nil {
				msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("duplicate registration rejected: %v", err))
				return NewErrorResult(msg, "duplicate registration rejected", err)
			}
			partialNotes = append(partialNotes, notes...)

			if registerKey {
				pendingKeyRR := keyRR
				pendingKeyName := keyName
				pendingRecords := acceptedRecords
				pendingMutations = append(pendingMutations, pendingLeaseMutation{
					keyName: pendingKeyName,
					apply: func() error {
						if err := h.registerKeyLease(ctx, keyIDFromSIG(sigRR), pendingKeyRR, keyLeaseDuration, keyLeaseDuration); err != nil {
							return err
						}
						if len(pendingRecords) > 0 {
							h.setNonKeyLease(leasepkg.NodeKey(pendingKeyRR), pendingRecords, leaseDuration, h.upstreamZone)
						}
						h.scheduleLeaseExpiry(leasepkg.NodeKey(pendingKeyRR))
						return nil
					},
				})
			}

			h.logger.Debugf("Lease processed for %s (lease=%d seconds, key-lease=%d seconds)", keyName, leaseDuration, keyLeaseDuration)

			if registerKey {
				responseKeys = append(responseKeys, keyRR)
				upstreamKeys = append(upstreamKeys, keyRR)
			}
			acceptedRecordsForUpstream = append(acceptedRecordsForUpstream, acceptedRecords...)
			allNotes = append(allNotes, partialNotes...)
		}

		// Non-KEY RRs always belong to the signer (protocol.md 5.1.4), grouped
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
					msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("duplicate registration rejected: %v", err))
					return NewErrorResult(msg, "duplicate registration rejected", err)
				}
				pendingMutations = append(pendingMutations, pendingLeaseMutation{
					keyName: signerNodeKey,
					apply: func() error {
						h.setNonKeyLease(signerNodeKey, acceptedRecords, leaseDuration, h.upstreamZone)
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
			msg := h.makeErrorResponse(r, dns.RcodeRefused,
				"KEY-LEASE=0 and LEASE!=0 requires at least one non-KEY RR")
			return NewErrorResult(msg, "invalid non-KEY-only lease request", fmt.Errorf("no non-KEY RR present"))
		}
		if len(updateKeyRRs) > 0 {
			msg := h.makeErrorResponse(r, dns.RcodeRefused,
				"KEY-LEASE=0 and LEASE!=0 does not allow KEY RRs in Update section")
			return NewErrorResult(msg, "invalid non-KEY-only lease request", fmt.Errorf("unexpected KEY RR in non-KEY-only lease request"))
		}

		signerLease := h.leaseManager.LookupBySIG(sigRR.SignerName, sigRR.Algorithm, sigRR.KeyTag)
		if signerLease == nil {
			msg := h.makeErrorResponse(r, dns.RcodeRefused,
				"KEY-LEASE=0 and LEASE!=0 requires signing KEY to already be managed")
			return NewErrorResult(msg, "signing key not managed for non-KEY-only lease", fmt.Errorf("signing key not found in lease store"))
		}

		signerOwnerKey := leasepkg.NodeKey(signerKey)
		keyExists, err := h.authoritativeHasKeyAtName(ctx, zone, signerKey.Hdr.Name)
		if err != nil {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("authoritative key lookup failed: %v", err))
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
					return h.registerKeyLease(ctx, keyIDFromSIG(sigRR), pendingKeyRR, pendingKeyLease, pendingKeyLease)
				},
			})
			responseKeys = append(responseKeys, pendingKeyRR)
			upstreamKeys = append(upstreamKeys, pendingKeyRR)
			allNotes = append(allNotes, fmt.Sprintf("KEY %s was missing at the authoritative DNS and has been re-registered with remaining lease", pendingKeyRR.Hdr.Name))
		}

		acceptedRecords, notes, err := h.filterDuplicateRegistrations(ctx, signerOwnerKey, zone, updateOtherRRs)
		if err != nil {
			msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("duplicate registration rejected: %v", err))
			return NewErrorResult(msg, "duplicate registration rejected", err)
		}
		if len(acceptedRecords) > 0 {
			pendingMutations = append(pendingMutations, pendingLeaseMutation{
				keyName: signerOwnerKey,
				apply: func() error {
					h.setNonKeyLease(signerOwnerKey, acceptedRecords, leaseDuration, h.upstreamZone)
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
		// (protocol.md item 7).
		//
		// Authorization is ownership-based, not just DNS-name hierarchy: a
		// record (KEY or non-KEY) may only be deleted by its immediate
		// parent -- the KEY that registered it -- or by itself in the case
		// of a self-registered (root) KEY, which has no parent to defer to.
		// A signer merely hierarchically "at or above" a record it did not
		// itself register cannot delete it directly; it can only reach that
		// data by deleting the record's actual parent, which cascades.
		if len(updateKeyRRs) == 0 && len(updateOtherRRs) == 0 {
			msg := h.makeErrorResponse(r, dns.RcodeFormatError,
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
			if !h.hasActiveNonKeyRecord(signerOwnerKey, rr) {
				allNotes = append(allNotes, fmt.Sprintf("record not found for delete: %s", rr.String()))
				continue
			}
			recordsToDelete = append(recordsToDelete, rr)
		}

		if len(keysToDelete) == 0 && len(recordsToDelete) == 0 {
			// Nothing locally managed to delete, so there is nothing to
			// confirm upstream either: just report the notes.
			return NewProcessedResult(h.buildSuccessResponse(r, zone, allNotes, nil, leaseDuration, keyLeaseDuration))
		}

		signingKey, effectiveUpstreamZone, err := h.resolveUpstreamSigningContext(ctx)
		if err != nil {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, err.Error())
			return NewErrorResult(msg, err.Error(), err)
		}

		deleteMsg, err := h.constructUpstreamDeleteForKeysAndRecords(keysToDelete, recordsToDelete, signingKey, effectiveUpstreamZone)
		if err != nil {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream delete construction failed: %v", err))
			return NewErrorResult(msg, "upstream delete construction failed", err)
		}
		if h.upstreamCoordinator == nil {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "upstream coordinator not configured")
			return NewErrorResult(msg, "upstream coordinator not configured", fmt.Errorf("upstream coordinator is nil"))
		}
		upstreamResp, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveUpstreamZone, deleteMsg)
		if err != nil {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream delete failed: %v", err))
			return NewErrorResult(msg, fmt.Sprintf("upstream delete failed: %v", err), err)
		}
		if upstreamResp == nil {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "upstream delete returned nil response")
			return NewErrorResult(msg, "upstream delete returned nil response", fmt.Errorf("nil upstream response"))
		}
		if upstreamResp.Rcode != dns.RcodeSuccess {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure,
				fmt.Sprintf("upstream rejected delete: rcode=%d (%s)", upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode]))
			return NewErrorResult(msg,
				fmt.Sprintf("upstream rejected delete: rcode=%d (%s)", upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode]), nil)
		}

		// Upstream confirmed: apply local deletes now. Descendants of a
		// deleted KEY are cascaded and cleaned up upstream best-effort
		// (mirroring the lease-expiry cascade in processExpiredLease); the
		// records explicitly named in this request are the ones the request
		// is accountable for, so their upstream delete was already confirmed
		// above before any local state changed.
		for _, keyRR := range keysToDelete {
			nodeKey := leasepkg.NodeKey(keyRR)
			if hs, ok := h.leaseManager.(leasepkg.HierarchicalLeaseStore); ok {
				for _, childKey := range hs.ListSubtreeKeys(nodeKey) {
					h.deleteNodeUpstream(ctx, childKey)
					h.removeNonKeyLease(childKey)
					h.clearLeaseTimer(childKey)
				}
			}
			// The KEY's own directly-owned non-KEY data (not just descendant
			// KEY nodes) must be cleaned up upstream here too, or it is
			// forgotten locally but never removed from the authoritative DNS
			// server -- the same divergence processExpiredLease already
			// guards against on lease-expiry. Non-KEY-only, not the full
			// deleteNodeUpstream: the KEY RR was already deleted upstream
			// above, so re-deleting it here would just be a second, redundant
			// round trip to the real authoritative server for no benefit.
			h.deleteNodeNonKeyUpstream(ctx, nodeKey)
			if err := h.leaseManager.Delete(nodeKey); err != nil {
				h.logger.Warnf("Failed to delete key lease for %s: %v (upstream delete already succeeded, local state may now diverge)", keyRR.Hdr.Name, err)
			}
			h.removeNonKeyLease(nodeKey)
			h.clearLeaseTimer(nodeKey)
			h.logger.Debugf("Deleted key for %s (KEY-LEASE=0, LEASE=0)", keyRR.Hdr.Name)
		}
		// Remove only the specific records that were actually deleted
		// upstream above -- removeNonKeyLease(signerOwnerKey) would wipe the
		// owner's *entire* non-KEY record set locally, silently forgetting
		// (and thus orphaning upstream forever) any other records under the
		// same owner that this request never asked to delete.
		for _, rr := range recordsToDelete {
			h.removeSingleNonKeyRecord(signerOwnerKey, recordKey(rr))
		}

		return NewProcessedResult(h.buildSuccessResponse(r, zone, allNotes, nil, leaseDuration, keyLeaseDuration))
	} else if keyLeaseDuration != 0 && leaseDuration == 0 {
		// Case D: KEY-only registration/refresh with optional non-KEY deletes.
		if len(updateKeyRRs) == 0 {
			msg := h.makeErrorResponse(r, dns.RcodeFormatError,
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
			if len(scopedOtherRecords) > 0 {
				for _, rr := range scopedOtherRecords {
					if !h.hasActiveNonKeyRecord(leasepkg.NodeKey(keyRR), rr) {
						notes = append(notes, fmt.Sprintf("record not found for delete: %s", rr.String()))
					}
				}
			}

			effectiveKeyLease := keyLeaseDuration
			existingKey := h.leaseManager.LookupByKEY(keyRR)
			if existingKey == nil {
				// New KEY registration: must not already exist identically at the
				// authoritative DNS, mirroring Case A's duplicate protection
				// (protocol.md item 6 applies to every case, not just Case A).
				exists, err := h.authoritativeHasRR(ctx, zone, keyRR)
				if err != nil {
					msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("authoritative duplicate check failed: %v", err))
					return NewErrorResult(msg, "authoritative duplicate check failed", err)
				}
				if exists {
					msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("duplicate registration rejected: authoritative RR already exists for %s", keyRR.String()))
					return NewErrorResult(msg, "duplicate registration rejected", fmt.Errorf("authoritative RR already exists for %s", keyRR.String()))
				}
				if !h.signerAuthorizedForNewRegistration(signerManaged, signerInUpdate, signerSource) {
					msg := h.makeErrorResponse(r, dns.RcodeRefused,
						"signing key must be managed, present in the Update section, or (if allow_online_key_registration is enabled) an authorized online signer, to register a new KEY RR")
					return NewErrorResult(msg, "signer not authorized for new registration",
						fmt.Errorf("signer %q is neither lease-managed, present in the Update section, nor an authorized online signer", sigRR.SignerName))
				}
			} else {
				if err := h.validateRefreshOwnership(keyRR); err != nil {
					msg := h.makeErrorResponse(r, dns.RcodeRefused, err.Error())
					return NewErrorResult(msg, err.Error(), err)
				}
				keyAtFQDN, err := h.authoritativeHasKeyAtName(ctx, zone, keyRR.Hdr.Name)
				if err != nil {
					msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("authoritative key lookup failed: %v", err))
					return NewErrorResult(msg, "authoritative key lookup failed", err)
				}
				if !keyAtFQDN {
					// Key is managed locally but missing at the DNS server: put it
					// back with the lease time still remaining, rather than
					// granting the full newly-requested duration.
					remaining := uint32(existingKey.TimeRemaining() / time.Second)
					if remaining == 0 {
						remaining = 1
					}
					effectiveKeyLease = remaining
				}
			}

			pendingKeyRR := keyRR
			pendingKeyName := keyName
			pendingRecords := scopedOtherRecords
			pendingKeyLease := effectiveKeyLease
			pendingMutations = append(pendingMutations, pendingLeaseMutation{
				keyName: pendingKeyName,
				apply: func() error {
					if err := h.registerKeyLease(ctx, keyIDFromSIG(sigRR), pendingKeyRR, pendingKeyLease, pendingKeyLease); err != nil {
						return err
					}
					if len(pendingRecords) > 0 {
						h.removeNonKeyLease(leasepkg.NodeKey(pendingKeyRR))
					}
					h.scheduleLeaseExpiry(leasepkg.NodeKey(pendingKeyRR))
					return nil
				},
			})

			responseKeys = append(responseKeys, keyRR)
			upstreamKeys = append(upstreamKeys, keyRR)
			allNotes = append(allNotes, notes...)
		}
	}

	// Upstream forwarding: forward KEY RRs that need to be registered upstream.
	// This handles the case where some or all KEY RRs were registered locally
	// but also need to be forwarded to the authoritative server.
	if len(upstreamKeys) > 0 || len(acceptedRecordsForUpstream) > 0 {
		signingKey, effectiveUpstreamZone, err := h.resolveUpstreamSigningContext(ctx)
		if err != nil {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, err.Error())
			return NewErrorResult(msg, err.Error(), err)
		}

		upstreamUpdate, err := h.constructUpstreamUpdate(upstreamKeys, acceptedRecordsForUpstream, signingKey, effectiveUpstreamZone)
		if err != nil {
			h.logger.Debugf("Failed to construct upstream UPDATE: %v", err)
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream construction failed: %v", err))
			return NewErrorResult(msg, fmt.Sprintf("upstream construction failed: %v", err), err)
		}
		if len(upstreamUpdate.Ns) == 0 {
			// No records to forward, just return success.
			return NewProcessedResult(h.buildSuccessResponse(r, zone, allNotes, nil, leaseDuration, keyLeaseDuration))
		}

		// Send UPDATE to upstream and fail-closed if upstream does not accept it.
		if h.upstreamCoordinator == nil {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "upstream coordinator not configured")
			return NewErrorResult(msg, "upstream coordinator not configured", fmt.Errorf("upstream coordinator is nil"))
		}

		h.logger.Debugf("Sending UPDATE to upstream zone=%s (configured=%s), keys=%d",
			effectiveUpstreamZone, h.upstreamZone, len(upstreamKeys))
		upstreamResp, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveUpstreamZone, upstreamUpdate)
		if err != nil {
			h.logger.Debugf("Upstream UPDATE transport/processing error for zone=%s keys=%d: %v",
				h.upstreamZone, len(upstreamKeys), err)
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream update failed: %v", err))
			return NewErrorResult(msg, fmt.Sprintf("upstream update failed: %v", err), err)
		}
		if upstreamResp == nil {
			h.logger.Debugf("Upstream UPDATE returned nil response for zone=%s keys=%d",
				h.upstreamZone, len(upstreamKeys))
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "upstream update returned nil response")
			return NewErrorResult(msg, "upstream update returned nil response", fmt.Errorf("nil upstream response"))
		}

		h.logger.Debugf("Upstream UPDATE response: Rcode=%d (%s), Answers=%d, Ns=%d, Extra=%d",
			upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode],
			len(upstreamResp.Answer), len(upstreamResp.Ns), len(upstreamResp.Extra))
		if upstreamResp.Rcode != dns.RcodeSuccess {
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure,
				fmt.Sprintf("upstream rejected update: rcode=%d (%s)",
					upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode]))
			return NewErrorResult(msg,
				fmt.Sprintf("upstream rejected update: rcode=%d (%s)",
					upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode]), nil)
		}
	}

	for _, mutation := range pendingMutations {
		if err := mutation.apply(); err != nil {
			h.logger.Debugf("post-upstream lease-store update failed for %s: %v", mutation.keyName, err)
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("lease-store update failed for %s: %v", mutation.keyName, err))
			return NewErrorResult(msg, fmt.Sprintf("lease-store update failed for %s", mutation.keyName), err)
		}
	}

	h.logger.Debugf("Sending success response (%d KEY RRs processed)", len(responseKeys))

	// Echo back the KEY RRs in response to confirm registration.
	answers := make([]dns.RR, 0, len(responseKeys))
	for _, key := range responseKeys {
		answers = append(answers, key)
	}
	return NewProcessedResult(h.buildSuccessResponse(r, zone, allNotes, answers, leaseDuration, keyLeaseDuration))
}

// buildSuccessResponse builds a successful UPDATE response echoing the given
// answer RRs and status notes (as TXT records). It also echoes the LEASE and
// KEY-LEASE durations actually applied to this request (after LeasePolicy
// clamping), so the client can detect if the proxy granted less than what
// was requested for either value.
func (h *UpdateHandler) buildSuccessResponse(r *dns.Msg, zone string, notes []string, answers []dns.RR, leaseDuration, keyLeaseDuration uint32) *dns.Msg {
	resp := &dns.Msg{
		MsgHeader: r.MsgHeader,
		Question:  r.Question,
	}
	resp.Response = true
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	appendStatusNotes(resp, zone, notes)
	resp.Answer = append(resp.Answer, answers...)

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	leaseOpt := leasepkg.Encode8Byte(leaseDuration, keyLeaseDuration)
	if err := leaseOpt.Encode(opt); err != nil {
		h.logger.Debugf("failed to encode response lease option: %v", err)
	}
	resp.Extra = append(resp.Extra, opt)

	return resp
}

func (h *UpdateHandler) makeErrorResponse(req *dns.Msg, rcode uint16, msg string) *dns.Msg {
	resp := &dns.Msg{
		MsgHeader: req.MsgHeader,
		Question:  req.Question,
	}

	resp.Response = true
	resp.Rcode = rcode

	// Note: we don't include detailed error messages in the response.
	// Errors are logged locally but responses use standard DNS rcodes.
	// In future versions, we can add extended error EDNS options.

	return resp
}

func appendStatusNotes(resp *dns.Msg, zone string, notes []string) {
	if resp == nil || len(notes) == 0 {
		return
	}
	for _, note := range notes {
		txt := &dns.TXT{Hdr: dns.Header{Name: zone, Class: dns.ClassINET, TTL: 0}}
		txt.TXT.Txt = []string{note}
		resp.Answer = append(resp.Answer, txt)
	}
}
