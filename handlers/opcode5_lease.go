package handlers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

func (h *UpdateHandler) clampLeaseDurations(leaseDuration, keyLeaseDuration uint32) (uint32, uint32) {
	if leaseDuration != 0 {
		leaseDuration = clampTTL(leaseDuration, h.LeasePolicy.MinRRLease, h.LeasePolicy.MaxRRLease)
	}
	if keyLeaseDuration != 0 {
		keyLeaseDuration = clampTTL(keyLeaseDuration, h.LeasePolicy.MinKeyLease, h.LeasePolicy.MaxKeyLease)
	}
	if leaseDuration != 0 && keyLeaseDuration != 0 && leaseDuration > keyLeaseDuration {
		// Preserve LEASE <= KEY-LEASE invariant when policy clamps tighten durations.
		leaseDuration = keyLeaseDuration
	}
	return leaseDuration, keyLeaseDuration
}

// authorizeKeyRefresh verifies that signerID may refresh the already
// -registered KEY RR clientKeyRR. Two things must hold: the resubmitted
// RDATA must match what is on record (a KEY RR's name+algo+keytag identity
// alone is not a full identity check), and the signer must actually be the
// node's owner -- either the key itself (self-refresh) or its recorded
// ParentKeyName (the entity that originally registered it).
//
// The RDATA check alone is not enough: KEY RDATA is public DNS data, so
// anyone can resubmit a byte-for-byte copy of someone else's registered KEY
// RR. Without the ownership check below, that copy would be accepted as a
// legitimate "refresh" by any signer that separately clears
// signerAuthorizedForNewRegistration (e.g. it is registering itself for the
// first time in the same request, or is an allowed online signer) --
// registerKeyLease/RegisterWithParent recompute and overwrite the node's
// parent on every call, so the resubmitting signer would silently become
// the record's owner.
func (h *UpdateHandler) authorizeKeyRefresh(clientKeyRR *dns.KEY, signerID keyID) error {
	if clientKeyRR == nil {
		return fmt.Errorf("refresh rejected: missing key")
	}

	existing := h.leaseManager.LookupByKEY(clientKeyRR)
	if existing == nil {
		return fmt.Errorf("refresh rejected: lease does not exist")
	}
	if !keyRREqual(existing.KeyRR, clientKeyRR) {
		return fmt.Errorf("refresh rejected: key mismatch")
	}

	if keyIDFromKEY(clientKeyRR) != signerID {
		signerOwnerKey := leasepkg.NodeKeyFromSIG(signerID.Name, signerID.Algorithm, signerID.KeyTag)
		if existing.ParentKeyName != signerOwnerKey {
			return fmt.Errorf("refresh rejected: signer %q is not the registered owner of %q", signerID.Name, clientKeyRR.Hdr.Name)
		}
	}

	return nil
}

// effectiveRefreshKeyLease determines the key-lease duration to actually
// grant a refresh (Case A and Case D share this once ownership has already
// been authorized via authorizeKeyRefresh): the full requestedKeyLease when
// the key is still published at its authoritative FQDN, or whatever lease
// time remains locally (floored at 1s so a near-expiry key isn't handed a
// zero-length lease) when it has disappeared from authoritative DNS and
// needs to be re-published rather than granted a fresh full-length lease.
func (h *UpdateHandler) effectiveRefreshKeyLease(ctx context.Context, zone string, keyRR *dns.KEY, existingKey *leasepkg.Record, requestedKeyLease uint32) (effectiveKeyLease uint32, keyAtFQDN bool, err error) {
	keyAtFQDN, err = h.authoritativeHasKeyAtName(ctx, zone, keyRR.Hdr.Name)
	if err != nil {
		return 0, false, err
	}
	if keyAtFQDN {
		return requestedKeyLease, true, nil
	}

	remaining := uint32(existingKey.TimeRemaining() / time.Second)
	if remaining == 0 {
		remaining = 1
	}
	return remaining, false, nil
}

func (h *UpdateHandler) registerKeyLease(ctx context.Context, signerID keyID, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32) error {
	parent := ""
	signerNodeKey := leasepkg.NodeKeyFromSIG(signerID.Name, signerID.Algorithm, signerID.KeyTag)
	keyNodeKey := leasepkg.NodeKey(keyRR)
	if signerNodeKey != keyNodeKey {
		parent = signerNodeKey
	}
	return h.leaseManager.RegisterWithParent(ctx, parent, keyRR, leaseDuration, keyLeaseDuration, h.upstreamZone)
}

func (h *UpdateHandler) nextLeaseEventAfter(keyName string) (time.Duration, bool) {
	var next *time.Time

	if keyRec := h.leaseManager.Get(keyName); keyRec != nil {
		t := keyRec.ExpiresAt
		next = &t
	}

	if nonKeyRec := h.leaseManager.GetNonKEYRecordSet(keyName); nonKeyRec != nil {
		for _, entry := range nonKeyRec.Records {
			t := entry.ExpiresAt
			if next == nil || t.Before(*next) {
				next = &t
			}
		}
	}

	if next == nil {
		return 0, false
	}

	d := time.Until(*next)
	if d < 0 {
		d = 0
	}
	if d < 100*time.Millisecond {
		d = 100 * time.Millisecond
	}

	return d, true
}

func (h *UpdateHandler) clearLeaseTimer(nodeKey string) {
	h.leaseTimersMu.Lock()
	defer h.leaseTimersMu.Unlock()

	if t, ok := h.leaseTimers[nodeKey]; ok {
		t.Stop()
		delete(h.leaseTimers, nodeKey)
	}
}

func (h *UpdateHandler) scheduleLeaseExpiry(nodeKey string) {
	h.clearLeaseTimer(nodeKey)

	d, ok := h.nextLeaseEventAfter(nodeKey)
	if !ok {
		return
	}

	t := time.AfterFunc(d, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		h.processExpiredLease(ctx, nodeKey)
	})

	h.leaseTimersMu.Lock()
	h.leaseTimers[nodeKey] = t
	h.leaseTimersMu.Unlock()
}

// startLeaseReconciliation periodically ensures every KEY node in the lease
// store has a live expiry timer. It exists to catch nodes that never got one
// scheduled (e.g. a future snapshot-restore path that populates the store
// without calling scheduleLeaseExpiry) or lost theirs to a bug. It never
// deletes anything itself: for any node found already expired, scheduling
// its timer fires processExpiredLease almost immediately — the same
// upstream-aware path used for every other expiry, not a second
// implementation of it.
func (h *UpdateHandler) startLeaseReconciliation(interval time.Duration) {
	h.reconcileTicker = time.NewTicker(interval)
	go func() {
		for range h.reconcileTicker.C {
			h.reconcileLeaseTimers()
		}
	}()
}

func (h *UpdateHandler) reconcileLeaseTimers() {
	for _, rec := range h.leaseManager.ListAll() {
		if rec == nil || rec.KeyRR == nil {
			continue
		}
		nodeKey := leasepkg.NodeKey(rec.KeyRR)

		h.leaseTimersMu.Lock()
		_, tracked := h.leaseTimers[nodeKey]
		h.leaseTimersMu.Unlock()

		if !tracked {
			h.logger.Debugf("Reconciliation: no active expiry timer for %s, scheduling now", nodeKey)
			h.scheduleLeaseExpiry(nodeKey)
		}
	}
}

// Shutdown stops the reconciliation ticker and releases the lease storage
// backend's own resources (e.g. a file-backed store's periodic-save
// goroutine, which also performs one final synchronous save here). Safe to
// call once during server shutdown; overrides BaseHandler's no-op default.
func (h *UpdateHandler) Shutdown() {
	if h.reconcileTicker != nil {
		h.reconcileTicker.Stop()
	}
	if h.leaseManager != nil {
		h.leaseManager.Stop()
	}
}

type leaseDumpNode struct {
	keyRec    *leasepkg.Record
	nonKeyRec *NonKEYLeaseRecord
	children  []string
}

func valueOrNone(value string) string {
	if value == "" {
		return "(none)"
	}
	return value
}

func (h *UpdateHandler) dumpLeaseTreeLevel() string {
	var sb strings.Builder
	sb.WriteString("=== Lease Store Dump ===\n")

	nodes := make(map[string]*leaseDumpNode)

	addNode := func(name string) *leaseDumpNode {
		name = canonicalName(name)
		if name == "" {
			return nil
		}
		node, ok := nodes[name]
		if !ok {
			node = &leaseDumpNode{}
			nodes[name] = node
		}
		return node
	}

	for _, rec := range h.leaseManager.ListAll() {
		if rec == nil || rec.KeyRR == nil {
			continue
		}
		if node := addNode(rec.KeyRR.Hdr.Name); node != nil {
			node.keyRec = rec
		}
	}

	for _, node := range nodes {
		if node == nil || node.keyRec == nil {
			continue
		}
		// GetNonKEYRecordSet is keyed by the composite NodeKey
		// (name+algo+keytag), not the plain DNS owner name used as this
		// map's key -- same class of lookup bug already fixed for the
		// INFO-level summary dump (DumpLeasesLevel).
		set := h.leaseManager.GetNonKEYRecordSet(leasepkg.NodeKey(node.keyRec.KeyRR))
		if set == nil {
			continue
		}
		// GetNonKEYRecordSet already returns a cloned, point-in-time view --
		// no need to re-clone it into a second, handlers-local copy.
		node.nonKeyRec = set
	}

	if len(nodes) == 0 {
		sb.WriteString("(empty)\n")
		return sb.String()
	}

	rootsByZone := make(map[string][]string)
	orphanNonKeyOnly := make([]string, 0)

	for name, node := range nodes {
		if node == nil {
			continue
		}
		if node.keyRec == nil {
			if node.nonKeyRec != nil {
				orphanNonKeyOnly = append(orphanNonKeyOnly, name)
			}
			continue
		}

		parentName := canonicalName(node.keyRec.ParentKeyName)
		if parentName != "" {
			if parentNode, ok := nodes[parentName]; ok && parentNode != nil && parentNode.keyRec != nil {
				parentNode.children = append(parentNode.children, name)
				continue
			}
		}

		zone := canonicalName(node.keyRec.UpstreamZone)
		if zone == "" {
			zone = "(unknown)"
		}
		rootsByZone[zone] = append(rootsByZone[zone], name)
	}

	zoneNames := make([]string, 0, len(rootsByZone))
	for zone := range rootsByZone {
		zoneNames = append(zoneNames, zone)
	}
	sort.Strings(zoneNames)

	var writeNode func(name, indent string)
	writeNode = func(name, indent string) {
		node := nodes[name]
		if node == nil {
			return
		}

		if node.keyRec != nil {
			sb.WriteString(fmt.Sprintf("%sKey: %s\n", indent, name))
			sb.WriteString(fmt.Sprintf("%s  ParentKey: %s\n", indent, valueOrNone(canonicalName(node.keyRec.ParentKeyName))))
			sb.WriteString(fmt.Sprintf("%s  UpstreamZone: %s\n", indent, valueOrNone(node.keyRec.UpstreamZone)))
			sb.WriteString(fmt.Sprintf("%s  KeyRR: %s\n", indent, node.keyRec.KeyRR.String()))
			sb.WriteString(fmt.Sprintf("%s  ExpiresAt: %s\n", indent, node.keyRec.ExpiresAt.Format(time.RFC3339)))
			sb.WriteString(fmt.Sprintf("%s  LeaseDuration: %ds\n", indent, node.keyRec.LeaseDuration))
			sb.WriteString(fmt.Sprintf("%s  KeyLeaseDuration: %ds\n", indent, node.keyRec.KeyLeaseDuration))
			sb.WriteString(fmt.Sprintf("%s  RegisteredAt: %s\n", indent, node.keyRec.RegisteredAt.Format(time.RFC3339)))
			sb.WriteString(fmt.Sprintf("%s  IsExpired: %v\n", indent, node.keyRec.IsExpired()))
		} else {
			sb.WriteString(fmt.Sprintf("%sNon-KEY-only lease: %s\n", indent, name))
		}

		if node.nonKeyRec != nil {
			sb.WriteString(fmt.Sprintf("%s  Non-KEY lease:\n", indent))
			if len(node.nonKeyRec.Records) > 0 {
				sb.WriteString(fmt.Sprintf("%s    Records:\n", indent))
				recordKeys := make([]string, 0, len(node.nonKeyRec.Records))
				for rk := range node.nonKeyRec.Records {
					recordKeys = append(recordKeys, rk)
				}
				sort.Strings(recordKeys)
				for _, rk := range recordKeys {
					entry := node.nonKeyRec.Records[rk]
					if entry == nil {
						continue
					}
					sb.WriteString(fmt.Sprintf("%s      %s\n", indent, rk))
					sb.WriteString(fmt.Sprintf("%s        RR: %s\n", indent, entry.RR.String()))
					sb.WriteString(fmt.Sprintf("%s        ExpiresAt: %s\n", indent, entry.ExpiresAt.Format(time.RFC3339)))
					sb.WriteString(fmt.Sprintf("%s        LeaseDuration: %ds\n", indent, entry.LeaseDuration))
				}
			} else {
				sb.WriteString(fmt.Sprintf("%s    Records: (none)\n", indent))
			}
			sb.WriteString(fmt.Sprintf("%s    UpstreamZone: %s\n", indent, valueOrNone(node.nonKeyRec.UpstreamZone)))
		}

		if len(node.children) > 0 {
			sort.Strings(node.children)
			sb.WriteString(fmt.Sprintf("%s  Children:\n", indent))
			for _, child := range node.children {
				writeNode(child, indent+"    ")
			}
		}

		sb.WriteString("\n")
	}

	for _, zone := range zoneNames {
		sb.WriteString(fmt.Sprintf("Zone: %s\n", zone))
		for _, name := range rootsByZone[zone] {
			writeNode(name, "  ")
		}
	}

	if len(orphanNonKeyOnly) > 0 {
		sort.Strings(orphanNonKeyOnly)
		sb.WriteString("Orphan data leases:\n")
		for _, name := range orphanNonKeyOnly {
			writeNode(name, "  ")
		}
	}

	return sb.String()
}

// DumpLeasesLevel returns lease state dump at the specified log level.
// Supported levels: "debug" (full dump), "info" (summary), anything else = "info".
//
// DEBUG format (full dump):
//
//	=== Lease Store Dump ===
//	KEY lease: <keyName>
//	  KeyRR: <dns.KEY string>
//	  ExpiresAt: <time>
//	  LeaseDuration: <seconds>s
//	  KeyLeaseDuration: <seconds>s
//	  UpstreamZone: <zone>
//	  RegisteredAt: <time>
//	Non-KEY lease: <keyName>
//	  Records:
//	    <recordKey>
//	      RR: <dns.RR string>
//	      ExpiresAt: <time>
//	      LeaseDuration: <seconds>s
//	  ExpiresAt: <time>
//	  LeaseDuration: <seconds>s
//	  UpstreamZone: <zone>
//
// INFO format (summary):
//
//	=== Lease Store Summary ===
//	Key: <keyName>  KEY=<active|expired|absent>  NonKEY=<count>  Status=<active|empty|absent>
//
// Keys that appear only in the KEY lease (no non-KEY lease) represent KEY-only registrations.
// Keys that appear only in the non-KEY lease (no KEY lease) represent non-KEY-only refreshes.
// Keys that appear in both have an active KEY + non-KEY RR lease.
func (h *UpdateHandler) DumpLeasesLevel(level string) string {
	// Normalize level.
	lower := strings.ToLower(strings.TrimSpace(level))
	isDebug := lower == "debug"

	// Lock timers to prevent schedule/expire during dump.
	h.leaseTimersMu.Lock()
	defer h.leaseTimersMu.Unlock()

	if isDebug {
		return h.dumpLeaseTreeLevel()
	}

	var sb strings.Builder

	// Collect all node keys. Get/getNonKeyLease are keyed by the composite
	// NodeKey (name.+algo+tag), not the plain DNS owner name, so that is
	// what must be collected here for the lookups below to find anything.
	keyNames := make(map[string]bool)
	for _, rec := range h.leaseManager.ListAll() {
		if rec.KeyRR == nil {
			continue
		}
		keyNames[leasepkg.NodeKey(rec.KeyRR)] = true
	}

	// INFO level: summary output.
	sb.WriteString("=== Lease Store Summary ===\n")
	if len(keyNames) == 0 {
		sb.WriteString("(empty)\n")
		return sb.String()
	}

	// Sort key names for deterministic output.
	sortedNames := make([]string, 0, len(keyNames))
	for name := range keyNames {
		sortedNames = append(sortedNames, name)
	}
	// Simple insertion sort (small N).
	for i := 1; i < len(sortedNames); i++ {
		for j := i; j > 0 && sortedNames[j] < sortedNames[j-1]; j-- {
			sortedNames[j], sortedNames[j-1] = sortedNames[j-1], sortedNames[j]
		}
	}

	for _, name := range sortedNames {
		keyRec := h.leaseManager.Get(name)
		nonKeyRec := h.leaseManager.GetNonKEYRecordSet(name)

		// Determine key status.
		keyStatus := "absent"
		if keyRec != nil {
			if keyRec.IsExpired() {
				keyStatus = "expired"
			} else {
				keyStatus = "active"
			}
		}

		// Count live non-KEY records. A record's presence is what defines
		// "active" — deleted or expired records are removed, not flagged.
		nonKeyCount := 0
		nonKeyStatus := "absent"
		if nonKeyRec != nil {
			nonKeyCount = len(nonKeyRec.Records)
			if nonKeyCount > 0 {
				nonKeyStatus = "active"
			} else {
				nonKeyStatus = "empty"
			}
		}

		sb.WriteString(fmt.Sprintf("Key: %-40s KEY=%-8s NonKEY=%d  Status=%s\n",
			name, keyStatus, nonKeyCount, nonKeyStatus))
	}

	return sb.String()
}

// DumpLeases is a convenience method that returns the full DEBUG-level dump.
// Deprecated: use DumpLeasesLevel("debug") instead.
func (h *UpdateHandler) DumpLeases() string {
	return h.DumpLeasesLevel("debug")
}

func (h *UpdateHandler) processExpiredLease(ctx context.Context, nodeKey string) {
	defer h.scheduleLeaseExpiry(nodeKey)

	record := h.leaseManager.Get(nodeKey)
	nonKeyLease := h.leaseManager.GetNonKEYRecordSet(nodeKey)
	if record == nil && (nonKeyLease == nil || len(nonKeyLease.Records) == 0) {
		h.clearLeaseTimer(nodeKey)
		return
	}

	now := time.Now()

	// Per-record expiry: expire each expired non-KEY record individually. A
	// record is only removed locally once its upstream delete has actually
	// succeeded (or there was nothing to send it with in the first place);
	// on failure it stays tracked with its already-past ExpiresAt, so the
	// timer this function reschedules on every exit (see defer above) retries
	// it on the next tick instead of silently forgetting a record that is
	// still published at authoritative DNS.
	if nonKeyLease != nil {
		effectiveZone := nonKeyLease.UpstreamZone
		if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
			resolvedZone, err := dc.resolveAuthoritativeZone(ctx, nonKeyLease.UpstreamZone)
			if err == nil {
				effectiveZone = resolvedZone
			}
		}

		var signingKey *keyrec.LoadedKey
		if h.upstreamCoordinator != nil {
			resolvedKey, matchedKeyZone, err := h.findAuthorizedProxyKeyForZone(nonKeyLease.UpstreamZone)
			if err != nil {
				h.logger.Debugf("Failed to resolve proxy authorization key for non-KEY lease-expiry deletes in zone %s: %v", nonKeyLease.UpstreamZone, err)
			} else {
				signingKey = resolvedKey
				h.logger.Debugf("Resolved proxy authorization key for non-KEY lease-expiry deletes in zone %s from key zone %s", nonKeyLease.UpstreamZone, matchedKeyZone)
			}
		}

		for key, entry := range nonKeyLease.Records {
			if !now.Before(entry.ExpiresAt) {
				upstreamDeleted := true
				if h.upstreamCoordinator != nil && signingKey != nil {
					deleteMsg, err := h.constructUpstreamDeleteForRecords([]dns.RR{entry.RR}, signingKey, effectiveZone)
					if err != nil {
						h.logger.Warnf("Failed to construct upstream non-KEY lease-expiry delete for %s record %s: %v (will retry)", nodeKey, key, err)
						upstreamDeleted = false
					} else if _, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveZone, deleteMsg); err != nil {
						h.logger.Warnf("Upstream non-KEY lease-expiry delete failed for %s record %s: %v (will retry)", nodeKey, key, err)
						upstreamDeleted = false
					}
				}
				if upstreamDeleted {
					if err := h.leaseManager.RemoveSingleNonKEYRecord(nodeKey, key); err != nil {
						h.logger.Warnf("Failed to remove expired non-KEY record %s for %s locally: %v", key, nodeKey, err)
					}
				}
			}
		}
	}

	if record == nil || now.Before(record.ExpiresAt) {
		return
	}

	// KEY is expired. Cascade upstream deletes to the entire subtree first.
	for _, childKey := range h.leaseManager.ListSubtreeKeys(nodeKey) {
		h.deleteNodeUpstream(ctx, childKey)
		h.clearLeaseTimer(childKey)
	}

	// The KEY cannot outlive its own lease, so any non-KEY records still owned
	// by it must be deleted upstream now too, even if their own LEASE has not
	// individually elapsed yet. Without this, records whose LEASE outlasts the
	// remaining KEY-LEASE are marked deleted locally but never removed from
	// the authoritative DNS server. As with the per-record loop above, a
	// record is only forgotten locally once its upstream delete actually
	// succeeds -- the deferred scheduleLeaseExpiry still retries it later
	// even though the KEY itself may already be gone.
	if nonKeyLease != nil {
		effectiveNonKeyZone := nonKeyLease.UpstreamZone
		if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
			if resolved, err := dc.resolveAuthoritativeZone(ctx, nonKeyLease.UpstreamZone); err == nil {
				effectiveNonKeyZone = resolved
			}
		}
		var catchupSigningKey *keyrec.LoadedKey
		if h.upstreamCoordinator != nil {
			resolvedKey, _, err := h.findAuthorizedProxyKeyForZone(nonKeyLease.UpstreamZone)
			if err != nil {
				h.logger.Warnf("Failed to resolve proxy authorization key for non-KEY lease-expiry deletes on KEY expiry in zone %s: %v (will retry)", nonKeyLease.UpstreamZone, err)
			} else {
				catchupSigningKey = resolvedKey
			}
		}
		for key, entry := range nonKeyLease.Records {
			upstreamDeleted := true
			if h.upstreamCoordinator != nil && catchupSigningKey != nil {
				deleteMsg, err := h.constructUpstreamDeleteForRecords([]dns.RR{entry.RR}, catchupSigningKey, effectiveNonKeyZone)
				if err != nil {
					h.logger.Warnf("Failed to construct upstream delete for %s record %s on KEY expiry: %v (will retry)", nodeKey, key, err)
					upstreamDeleted = false
				} else if _, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveNonKeyZone, deleteMsg); err != nil {
					h.logger.Warnf("Upstream delete failed for %s record %s on KEY expiry: %v (will retry)", nodeKey, key, err)
					upstreamDeleted = false
				}
			} else if h.upstreamCoordinator != nil && catchupSigningKey == nil {
				// Signing key resolution already failed and was warned about
				// above; without it we cannot attempt this record's delete.
				upstreamDeleted = false
			}
			if upstreamDeleted {
				if err := h.leaseManager.RemoveSingleNonKEYRecord(nodeKey, key); err != nil {
					h.logger.Warnf("Failed to remove non-KEY record %s for %s locally on KEY expiry: %v", key, nodeKey, err)
				}
			}
		}
	}

	effectiveUpstreamZone := record.UpstreamZone
	if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
		resolvedZone, err := dc.resolveAuthoritativeZone(ctx, record.UpstreamZone)
		if err == nil {
			effectiveUpstreamZone = resolvedZone
		}
	}

	keyUpstreamDeleted := true
	if h.upstreamCoordinator != nil && record.KeyRR != nil {
		signingKey, matchedKeyZone, err := h.findAuthorizedProxyKeyForZone(record.UpstreamZone)
		if err != nil {
			h.logger.Warnf("Failed to resolve proxy authorization key for key lease-expiry delete in zone %s: %v (will retry)", record.UpstreamZone, err)
		} else {
			h.logger.Debugf("Resolved proxy authorization key for key lease-expiry delete in zone %s from key zone %s", record.UpstreamZone, matchedKeyZone)
		}
		deleteMsg, err := h.constructUpstreamDelete(record.KeyRR, signingKey, effectiveUpstreamZone)
		if err != nil {
			h.logger.Warnf("Failed to construct upstream lease-expiry delete for %s: %v (will retry)", nodeKey, err)
			keyUpstreamDeleted = false
		} else {
			if _, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveUpstreamZone, deleteMsg); err != nil {
				h.logger.Warnf("Upstream lease-expiry delete failed for %s: %v (will retry)", nodeKey, err)
				keyUpstreamDeleted = false
			}
		}
	}

	// Only forget the KEY locally once its upstream delete actually
	// succeeded (or there was nothing to send it with): the deferred
	// scheduleLeaseExpiry above reschedules a near-immediate retry
	// otherwise, since Get(nodeKey) still finds it with its already-past
	// ExpiresAt. Forgetting it unconditionally would leave it published at
	// authoritative DNS forever with no way for the proxy to rediscover it.
	if !keyUpstreamDeleted {
		return
	}

	if err := h.leaseManager.Delete(nodeKey); err != nil {
		h.logger.Warnf("Failed to delete expired local lease for %s: %v (upstream KEY delete already succeeded, local state may now diverge)", nodeKey, err)
	}
	// Not a blanket h.leaseManager.RemoveNonKEYRecords(nodeKey): the two
	// loops above already removed each record they confirmed deleted
	// upstream, one at a time.
	// Wiping the whole set here would also discard any record that failed
	// its upstream delete and is waiting on the rescheduled timer to retry.
	h.clearLeaseTimer(nodeKey)
}

// deleteNodeNonKeyUpstream sends upstream DNS deletes for a node's own non-KEY
// records only (no KEY involved). Split out of deleteNodeUpstream so a
// caller that has already deleted the node's KEY RR upstream itself (Case C)
// doesn't also pay for a redundant, no-op re-delete of that same KEY RR --
// each upstream delete is a real network round trip to the authoritative
// server, and doubling them raises the odds of a timeout/SERVFAIL for no
// benefit. Failures are logged instead of silently discarded.
func (h *UpdateHandler) deleteNodeNonKeyUpstream(ctx context.Context, nodeKey string) {
	nonKeyLease := h.leaseManager.GetNonKEYRecordSet(nodeKey)
	if nonKeyLease == nil {
		return
	}

	effectiveZone := nonKeyLease.UpstreamZone
	if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
		if resolved, err := dc.resolveAuthoritativeZone(ctx, nonKeyLease.UpstreamZone); err == nil {
			effectiveZone = resolved
		}
	}
	if h.upstreamCoordinator == nil {
		return
	}
	signingKey, _, err := h.findAuthorizedProxyKeyForZone(nonKeyLease.UpstreamZone)
	if err != nil {
		h.logger.Warnf("Failed to resolve proxy authorization key for %s non-KEY deletes in zone %s: %v (local state will still be forgotten)", nodeKey, nonKeyLease.UpstreamZone, err)
		return
	}
	for key, entry := range nonKeyLease.Records {
		deleteMsg, err := h.constructUpstreamDeleteForRecords([]dns.RR{entry.RR}, signingKey, effectiveZone)
		if err != nil {
			h.logger.Warnf("Failed to construct upstream delete for %s record %s: %v (local state will still be forgotten)", nodeKey, key, err)
			continue
		}
		if _, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveZone, deleteMsg); err != nil {
			h.logger.Warnf("Upstream delete failed for %s record %s: %v (local state will still be forgotten)", nodeKey, key, err)
		}
	}
}

// deleteNodeUpstream sends upstream DNS deletes for a descendant node's KEY
// and non-KEY records. Best-effort: unlike processExpiredLease's handling of
// a node's own records, callers of this function remove the descendant's
// local state unconditionally afterward (see the ListSubtreeKeys cascades in
// processExpiredLease and Case C), so a failure here can still leave a
// descendant's records orphaned upstream with no local record to retry from.
// Failures are now at least logged instead of silently discarded.
func (h *UpdateHandler) deleteNodeUpstream(ctx context.Context, nodeKey string) {
	h.deleteNodeNonKeyUpstream(ctx, nodeKey)

	record := h.leaseManager.Get(nodeKey)
	if record != nil && record.KeyRR != nil && h.upstreamCoordinator != nil {
		effectiveZone := record.UpstreamZone
		if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
			if resolved, err := dc.resolveAuthoritativeZone(ctx, record.UpstreamZone); err == nil {
				effectiveZone = resolved
			}
		}
		signingKey, _, err := h.findAuthorizedProxyKeyForZone(record.UpstreamZone)
		if err != nil {
			h.logger.Warnf("Failed to resolve proxy authorization key for descendant %s KEY delete in zone %s: %v (local state will still be forgotten)", nodeKey, record.UpstreamZone, err)
		} else {
			deleteMsg, err := h.constructUpstreamDelete(record.KeyRR, signingKey, effectiveZone)
			if err != nil {
				h.logger.Warnf("Failed to construct upstream KEY delete for descendant %s: %v (local state will still be forgotten)", nodeKey, err)
			} else if _, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveZone, deleteMsg); err != nil {
				h.logger.Warnf("Upstream KEY delete failed for descendant %s: %v (local state will still be forgotten)", nodeKey, err)
			}
		}
	}
}

// Handle processes an UPDATE query and returns a HandlerResult.
//
// Sig0lease packet detection (RFC 9664 Section 4):
//   - Opcode must be UPDATE (5) - handled by router
//   - Must contain EDNS(0) OPT RR with OPTION_CODE 2 (UPDATE-LEASE)
//   - If UPDATE-LEASE is absent, packet is not sig0lease relevant → StatusNotRelevant
//
// Registration Flow (if UPDATE-LEASE present):
//  1. Validate message structure (single question for downstream zone)
//  2. Parse 8-byte lease EDNS(0) option (RFC 9664)
//  3. Extract and validate client SIG(0) signature (RFC 2931)
//  4. Extract KEY RR from update records
//  5. Register lease in-memory with persistence hook
//  6. Construct UPDATE for upstream zone
//  7. Sign UPDATE with upstream key
//  8. Send to upstream authoritative server
//  9. Return response to client
//
// The DNS UPDATE message format:
//   - Question section: Downstream zone name and class (typically ClassINET)
//   - Answer section: Prerequisite records (unused in this implementation)
//   - Authority section: Update records (typically KEY RRs being registered)
//   - Additional section: EDNS options (including 8-byte Update Lease and SIG(0))
