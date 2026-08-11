package handlers

import (
	"context"
	"fmt"

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

	additionalSigningKeys, err := extractAdditionalSigningKeys(r)
	if err != nil {
		h.logger.Debugf("Invalid Additional KEY records: %v", err)
		msg := h.makeErrorResponse(r, dns.RcodeFormatError, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	sigRR, err := extractSig0(r)
	if err != nil {
		msg := h.makeErrorResponse(r, dns.RcodeRefused, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	signerKey, err := h.resolveSignerKeyForOwnership(sigRR, additionalSigningKeys, updateKeyRRs)
	if err != nil {
		msg := h.makeErrorResponse(r, dns.RcodeRefused, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	// Ownership must come from the signer KEY.
	// The provided signer KEY is the ownership key, so verification should use it first.
	sigRR, signerKey, err = h.extractAndValidateSig0(ctx, r, zone, signerKey, additionalSigningKeys, updateKeyRRs)
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

	// KEY-LEASE!=0, LEASE!=0 requires KEY RR. Non-KEY RRs are optional:
	// missing non-KEY RRs means KEY-only refresh/registration.
	if keyLeaseDuration != 0 && leaseDuration != 0 {
		if len(updateKeyRRs) == 0 {
			msg := h.makeErrorResponse(r, dns.RcodeFormatError,
				"KEY-LEASE!=0 and LEASE!=0 requires at least one KEY RR")
			return NewErrorResult(msg, "invalid update matrix for register/refresh", fmt.Errorf("missing required KEY record"))
		}
	}

	// Process all KEY RRs through the appropriate case.
	// Each KEY RR represents a separate key registration/refresh/delete.
	var allNotes []string
	var responseKeys []*dns.KEY
	upstreamKeys := make([]*dns.KEY, 0)
	var acceptedRecordsForUpstream []dns.RR
	type pendingLeaseMutation struct {
		keyName string
		apply   func() error
	}
	pendingMutations := make([]pendingLeaseMutation, 0)

	for _, keyRR := range updateKeyRRs {
		keyName := keyRR.Hdr.Name
		scopedOtherRecords := updateOtherRRsByKeyOwner[keyIDFromKEY(keyRR)]
		keyIsRefresh := h.leaseManager.LookupByKEY(keyRR) != nil

		// KEY-LEASE != 0, LEASE == 0: KEY lease registration (Case 4).
		if keyLeaseDuration != 0 && leaseDuration == 0 {
			notes := make([]string, 0)
			if len(scopedOtherRecords) > 0 {
				for _, rr := range scopedOtherRecords {
					if !h.hasActiveDataRecord(leasepkg.NodeKey(keyRR), rr) {
						notes = append(notes, fmt.Sprintf("record not found for delete: %s", rr.String()))
					}
				}
			}

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
						h.deleteDataLease(leasepkg.NodeKey(pendingKeyRR))
					}
					h.scheduleLeaseExpiry(leasepkg.NodeKey(pendingKeyRR))
					return nil
				},
			})

			responseKeys = append(responseKeys, keyRR)
			upstreamKeys = append(upstreamKeys, keyRR)
			allNotes = append(allNotes, notes...)
			continue
		}

		// KEY-LEASE == 0, LEASE == 0: delete matrix (Case 3).
		if keyLeaseDuration == 0 && leaseDuration == 0 {
			notes := make([]string, 0)
			if h.leaseManager.LookupByKEY(keyRR) == nil {
				notes = append(notes, fmt.Sprintf("KEY %s not found for delete", keyName))
			}
			if err := h.leaseManager.Delete(leasepkg.NodeKey(keyRR)); err != nil {
				h.logger.Debugf("Failed to delete key lease for %s: %v", keyName, err)
			}
			h.clearLeaseTimer(leasepkg.NodeKey(keyRR))

			if len(scopedOtherRecords) > 0 {
				for _, rr := range scopedOtherRecords {
					if !h.hasActiveDataRecord(leasepkg.NodeKey(keyRR), rr) {
						notes = append(notes, fmt.Sprintf("record not found for delete: %s", rr.String()))
					}
				}
				h.deleteDataLease(leasepkg.NodeKey(keyRR))
			}
			h.logger.Debugf("Deleted key for %s (KEY-LEASE=0, LEASE=0)", keyName)

			allNotes = append(allNotes, notes...)
			continue
		}

		// KEY-LEASE == 0, LEASE != 0: data-only lease (Case 1 or 2).
		if keyLeaseDuration == 0 && leaseDuration != 0 {
			// Case 2: no other RRs — error.
			if len(scopedOtherRecords) == 0 {
				msg := h.makeErrorResponse(r, dns.RcodeRefused,
					"KEY-LEASE=0 and LEASE!=0 requires at least one non-KEY RR")
				return NewErrorResult(msg, "invalid data-only lease request", fmt.Errorf("no non-KEY RR present"))
			}

			// Case 1: KEY-LEASE=0, LEASE!=0, other RRs present.
			keyExists, err := h.authoritativeHasKeyAtName(ctx, zone, keyName)
			if err != nil {
				msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("authoritative key lookup failed: %v", err))
				return NewErrorResult(msg, "authoritative key lookup failed", err)
			}
			if !keyExists {
				msg := h.makeErrorResponse(r, dns.RcodeRefused,
					"KEY-LEASE=0 requires existing KEY at FQDN; cannot register KEY with zero key-lease")
				return NewErrorResult(msg, "key missing for KEY-LEASE=0 data update", fmt.Errorf("missing existing key at FQDN"))
			}

			acceptedRecords, notes, err := h.filterDuplicateRegistrations(ctx, leasepkg.NodeKey(keyRR), zone, scopedOtherRecords)
			if err != nil {
				msg := h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("duplicate registration rejected: %v", err))
				return NewErrorResult(msg, "duplicate registration rejected", err)
			}
			if len(acceptedRecords) > 0 {
				h.setDataLease(leasepkg.NodeKey(keyRR), acceptedRecords, leaseDuration, h.upstreamZone)
			}
			h.scheduleLeaseExpiry(leasepkg.NodeKey(keyRR))

			allNotes = append(allNotes, notes...)
			// For data-only leases, we don't add a KEY to the response.
			continue
		}

		// KEY-LEASE != 0, LEASE != 0: normal registration (Case 1).
		// This is the full registration path.
		if keyIsRefresh {
			// Normal refresh: validate ownership and refresh key/data lease.
			if err := h.validateRefreshOwnership(keyRR); err != nil {
				// Ownership check failed (key mismatch). Promote to full registration
				// if the key does not exist at the FQDN — the client is re-registering
				// (they have valid lease-times from before and lost the key at the DNS).
				existingKey := h.leaseManager.LookupByKEY(keyRR)
				if existingKey == nil {
					// Key not at FQDN: promote to full registration (both key and data RRs).
					pendingKeyRR := keyRR
					pendingKeyName := keyName
					pendingRecords := scopedOtherRecords
					pendingMutations = append(pendingMutations, pendingLeaseMutation{
						keyName: pendingKeyName,
						apply: func() error {
							if err := h.registerKeyLease(ctx, keyIDFromSIG(sigRR), pendingKeyRR, keyLeaseDuration, keyLeaseDuration); err != nil {
								return err
							}
							h.setDataLease(leasepkg.NodeKey(pendingKeyRR), pendingRecords, leaseDuration, h.upstreamZone)
							h.scheduleLeaseExpiry(leasepkg.NodeKey(pendingKeyRR))
							h.logger.Debugf("Lease re-registered for %s (KEY-LEASE != 0, key not at FQDN, promoted from refresh)", pendingKeyName)
							return nil
						},
					})

					responseKeys = append(responseKeys, keyRR)
					upstreamKeys = append(upstreamKeys, keyRR)
					acceptedRecordsForUpstream = append(acceptedRecordsForUpstream, scopedOtherRecords...)
					continue
				}
				// Key exists at FQDN: return ownership error (existing behavior).
				msg := h.makeErrorResponse(r, dns.RcodeRefused, err.Error())
				return NewErrorResult(msg, err.Error(), err)
			}
			// Key refresh always extends key lease if ownership validated.
			if err := h.registerKeyLease(ctx, keyIDFromSIG(sigRR), keyRR, keyLeaseDuration, keyLeaseDuration); err != nil {
				msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("lease registration failed for %s: %v", keyName, err))
				return NewErrorResult(msg, fmt.Sprintf("lease registration failed for %s: %v", keyName, err), err)
			}

			if len(scopedOtherRecords) > 0 {
				if err := h.refreshDataLease(leasepkg.NodeKey(keyRR), leaseDuration); err != nil {
					msg := h.makeErrorResponse(r, dns.RcodeRefused, err.Error())
					return NewErrorResult(msg, err.Error(), err)
				}
			}
			h.scheduleLeaseExpiry(leasepkg.NodeKey(keyRR))

			h.logger.Debugf("Lease refreshed for %s (data lease=%d seconds)", keyName, leaseDuration)

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
						h.setDataLease(leasepkg.NodeKey(pendingKeyRR), pendingRecords, leaseDuration, h.upstreamZone)
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

	// Upstream forwarding: forward KEY RRs that need to be registered upstream.
	// This handles the case where some or all KEY RRs were registered locally
	// but also need to be forwarded to the authoritative server.
	if len(upstreamKeys) > 0 || len(acceptedRecordsForUpstream) > 0 {
		signingKey, matchedKeyZone, err := h.findAuthorizedProxyKeyForZone(h.upstreamZone)
		if err != nil {
			h.logger.Debugf("Failed to resolve proxy authorization key for upstream zone %s: %v", h.upstreamZone, err)
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream signing key resolution failed: %v", err))
			return NewErrorResult(msg, fmt.Sprintf("upstream signing key resolution failed: %v", err), err)
		}
		h.logger.Debugf("Resolved proxy authorization key for upstream zone %s from key zone %s", h.upstreamZone, matchedKeyZone)

		// Determine effective upstream zone from the upstream coordinator.
		effectiveUpstreamZone := h.upstreamZone
		if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
			resolvedZone, err := dc.resolveAuthoritativeZone(ctx, h.upstreamZone)
			if err != nil {
				h.logger.Debugf("Failed to resolve effective upstream zone from %s: %v", h.upstreamZone, err)
				msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream zone resolution failed: %v", err))
				return NewErrorResult(msg, fmt.Sprintf("upstream zone resolution failed: %v", err), err)
			}
			effectiveUpstreamZone = resolvedZone
			h.logger.Debugf("Resolved effective upstream zone: configured=%s effective=%s", h.upstreamZone, effectiveUpstreamZone)
		}

		upstreamUpdate, err := h.constructUpstreamUpdate(upstreamKeys, acceptedRecordsForUpstream, signingKey, effectiveUpstreamZone)
		if err != nil {
			h.logger.Debugf("Failed to construct upstream UPDATE: %v", err)
			msg := h.makeErrorResponse(r, dns.RcodeServerFailure, fmt.Sprintf("upstream construction failed: %v", err))
			return NewErrorResult(msg, fmt.Sprintf("upstream construction failed: %v", err), err)
		}
		if len(upstreamUpdate.Ns) == 0 {
			// No records to forward, just return success.
			resp := &dns.Msg{MsgHeader: r.MsgHeader, Question: r.Question}
			resp.Response = true
			resp.Authoritative = true
			resp.Rcode = dns.RcodeSuccess
			appendStatusNotes(resp, zone, allNotes)
			opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
			opt.SetUDPSize(uint16(dns.DefaultMsgSize))
			resp.Extra = append(resp.Extra, opt)
			return NewProcessedResult(resp)
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

	// Build response with all processed KEY RRs.
	resp := &dns.Msg{
		MsgHeader: r.MsgHeader,
		Question:  r.Question,
	}

	resp.Response = true
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	appendStatusNotes(resp, zone, allNotes)

	// Echo back the KEY RRs in response to confirm registration.
	for _, key := range responseKeys {
		resp.Answer = append(resp.Answer, key)
	}

	// Add OPT with response lease option
	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	resp.Extra = append(resp.Extra, opt)

	h.logger.Debugf("Sending success response (%d KEY RRs processed)", len(responseKeys))

	return NewProcessedResult(resp)
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
