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

func (h *UpdateHandler) applyLeasePolicy(keyRR *dns.KEY, other []dns.RR) (*dns.KEY, []dns.RR) {
	newKey := copyRR(keyRR).(*dns.KEY)
	newKey.Hdr.TTL = clampTTL(newKey.Hdr.TTL, h.LeasePolicy.MinKeyLease, h.LeasePolicy.MaxKeyLease)

	newOther := make([]dns.RR, 0, len(other))
	for _, rr := range other {
		cpy := copyRR(rr)
		hdr := cpy.Header()
		hdr.TTL = clampTTL(hdr.TTL, h.LeasePolicy.MinRRLease, h.LeasePolicy.MaxRRLease)
		newOther = append(newOther, cpy)
	}

	return newKey, newOther
}

func (h *UpdateHandler) validateRefreshOwnership(clientKeyRR *dns.KEY) error {
	if clientKeyRR == nil {
		return fmt.Errorf("refresh rejected: missing key")
	}

	clientKeyName := clientKeyRR.Hdr.Name
	existing := h.leaseManager.Lookup(clientKeyName)
	if existing == nil {
		return fmt.Errorf("refresh rejected: lease does not exist")
	}
	if !keyRREqual(existing.KeyRR, clientKeyRR) {
		return fmt.Errorf("refresh rejected: key mismatch")
	}

	return nil
}

func (h *UpdateHandler) registerKeyLease(ctx context.Context, signerName, keyName string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32) error {
	if hs, ok := h.leaseManager.(leasepkg.HierarchicalLeaseStore); ok {
		parent := ""
		signerCanon := canonicalName(signerName)
		keyCanon := canonicalName(keyName)
		if signerCanon != "" && keyCanon != "" && signerCanon != keyCanon {
			parent = signerName
		}
		return hs.RegisterWithParent(ctx, parent, keyName, keyRR, leaseDuration, keyLeaseDuration, h.upstreamZone)
	}

	return h.leaseManager.Register(ctx, keyName, keyRR, leaseDuration, keyLeaseDuration, h.upstreamZone)
}

func (h *UpdateHandler) setDataLease(keyName string, records []dns.RR, leaseDuration uint32, upstreamZone string) {
	if treeStore, ok := h.leaseManager.(leasepkg.LeaseTreeStore); ok {
		if err := treeStore.UpsertNonKEYRecords(keyName, records, leaseDuration, upstreamZone); err != nil {
			h.logger.Debugf("failed to store non-KEY records in lease tree for %s: %v", keyName, err)
		}
		return
	}

	h.dataLeasesMu.Lock()
	defer h.dataLeasesMu.Unlock()

	keyName = canonicalName(keyName)
	rec, ok := h.dataLeases[keyName]
	if !ok {
		rec = &DataLeaseRecord{Records: make(map[string]*dataRecordEntry)}
		h.dataLeases[keyName] = rec
	}

	// Merge: update or append each record by DNS RR identity key.
	for _, newRR := range records {
		if newRR == nil || newRR.Header() == nil {
			continue
		}
		key := recordKey(newRR)
		if key == "" {
			continue
		}
		if existing, exists := rec.Records[key]; exists {
			// Update existing record: replace RDATA, update lease.
			existing.RR = newRR
			existing.LeaseDuration = leaseDuration
			existing.ExpiresAt = time.Now().Add(time.Duration(leaseDuration) * time.Second)
			existing.Deleted = false
		} else {
			// New record: append.
			rec.Records[key] = &dataRecordEntry{
				RR:            newRR,
				ExpiresAt:     time.Now().Add(time.Duration(leaseDuration) * time.Second),
				LeaseDuration: leaseDuration,
				Deleted:       false,
			}
		}
	}

	rec.UpstreamZone = upstreamZone
	rec.Deleted = false
}

func (h *UpdateHandler) refreshDataLease(keyName string, leaseDuration uint32) error {
	if treeStore, ok := h.leaseManager.(leasepkg.LeaseTreeStore); ok {
		return treeStore.RefreshNonKEYRecords(keyName, leaseDuration)
	}

	h.dataLeasesMu.Lock()
	defer h.dataLeasesMu.Unlock()

	keyName = canonicalName(keyName)
	rec, ok := h.dataLeases[keyName]
	if !ok {
		return fmt.Errorf("refresh rejected: lease does not exist")
	}

	// Refresh all individual records.
	for _, entry := range rec.Records {
		if !entry.Deleted {
			entry.LeaseDuration = leaseDuration
			entry.ExpiresAt = time.Now().Add(time.Duration(leaseDuration) * time.Second)
		}
	}
	rec.Deleted = false
	return nil
}

func (h *UpdateHandler) deleteDataLease(keyName string) {
	if treeStore, ok := h.leaseManager.(leasepkg.LeaseTreeStore); ok {
		treeStore.MarkNonKEYRecordsDeleted(keyName)
		return
	}

	h.dataLeasesMu.Lock()
	defer h.dataLeasesMu.Unlock()
	keyName = canonicalName(keyName)
	rec, ok := h.dataLeases[keyName]
	if !ok {
		return
	}
	// Mark all records as deleted (but keep the entry for expiry tracking).
	for _, entry := range rec.Records {
		entry.Deleted = true
	}
}

func (h *UpdateHandler) removeDataLease(keyName string) {
	if treeStore, ok := h.leaseManager.(leasepkg.LeaseTreeStore); ok {
		treeStore.RemoveNonKEYRecords(keyName)
		return
	}

	h.dataLeasesMu.Lock()
	defer h.dataLeasesMu.Unlock()
	keyName = canonicalName(keyName)
	delete(h.dataLeases, keyName)
}

func (h *UpdateHandler) getDataLease(keyName string) *DataLeaseRecord {
	if treeStore, ok := h.leaseManager.(leasepkg.LeaseTreeStore); ok {
		set := treeStore.GetNonKEYRecordSet(keyName)
		if set == nil {
			return nil
		}
		rec := &DataLeaseRecord{
			Records:      make(map[string]*dataRecordEntry, len(set.Records)),
			UpstreamZone: set.UpstreamZone,
			Deleted:      set.Deleted,
		}
		for rrKey, node := range set.Records {
			if node == nil {
				continue
			}
			rec.Records[rrKey] = &dataRecordEntry{
				RR:            copyRR(node.RR),
				ExpiresAt:     node.ExpiresAt,
				LeaseDuration: node.LeaseDuration,
				Deleted:       node.Deleted,
			}
		}
		return rec
	}

	h.dataLeasesMu.RLock()
	defer h.dataLeasesMu.RUnlock()
	keyName = canonicalName(keyName)
	rec, ok := h.dataLeases[keyName]
	if !ok {
		return nil
	}
	// Return a shallow copy of the entry map (pointers preserved).
	return &DataLeaseRecord{
		Records:       rec.Records,
		ExpiresAt:     rec.ExpiresAt,
		UpstreamZone:  rec.UpstreamZone,
		LeaseDuration: rec.LeaseDuration,
		Deleted:       rec.Deleted,
	}
}

func (h *UpdateHandler) hasActiveDataRecord(keyName string, rr dns.RR) bool {
	if rr == nil {
		return false
	}
	if treeStore, ok := h.leaseManager.(leasepkg.LeaseTreeStore); ok {
		return treeStore.HasActiveNonKEYRecord(keyName, rr)
	}
	rec := h.getDataLease(keyName)
	if rec == nil {
		return false
	}
	key := recordKey(rr)
	if key == "" {
		return false
	}
	entry, ok := rec.Records[key]
	if !ok {
		return false
	}
	return !entry.Deleted
}

func (h *UpdateHandler) markDataLeaseDeleted(keyName string) {
	if treeStore, ok := h.leaseManager.(leasepkg.LeaseTreeStore); ok {
		treeStore.MarkNonKEYRecordsDeleted(keyName)
		return
	}

	h.dataLeasesMu.Lock()
	defer h.dataLeasesMu.Unlock()
	keyName = canonicalName(keyName)
	if rec, ok := h.dataLeases[keyName]; ok {
		rec.Deleted = true
	}
}

func (h *UpdateHandler) nextLeaseEventAfter(keyName string) (time.Duration, bool) {
	var next *time.Time

	if keyRec := h.leaseManager.Get(keyName); keyRec != nil {
		t := keyRec.ExpiresAt
		next = &t
	}

	if dataRec := h.getDataLease(keyName); dataRec != nil {
		for _, entry := range dataRec.Records {
			if !entry.Deleted {
				t := entry.ExpiresAt
				if next == nil || t.Before(*next) {
					next = &t
				}
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

func (h *UpdateHandler) clearLeaseTimer(keyName string) {
	h.leaseTimersMu.Lock()
	defer h.leaseTimersMu.Unlock()

	if t, ok := h.leaseTimers[keyName]; ok {
		t.Stop()
		delete(h.leaseTimers, keyName)
	}
}

func (h *UpdateHandler) scheduleLeaseExpiry(keyName string) {
	h.clearLeaseTimer(keyName)

	d, ok := h.nextLeaseEventAfter(keyName)
	if !ok {
		return
	}

	t := time.AfterFunc(d, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		h.processExpiredLease(ctx, keyName)
	})

	h.leaseTimersMu.Lock()
	h.leaseTimers[keyName] = t
	h.leaseTimersMu.Unlock()
}

type leaseDumpNode struct {
	keyRec   *leasepkg.Record
	dataRec  *DataLeaseRecord
	children []string
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

	if treeStore, ok := h.leaseManager.(leasepkg.LeaseTreeStore); ok {
		for name, node := range nodes {
			if node == nil || node.keyRec == nil {
				continue
			}
			set := treeStore.GetNonKEYRecordSet(name)
			if set == nil {
				continue
			}
			rec := &DataLeaseRecord{
				Records:      make(map[string]*dataRecordEntry, len(set.Records)),
				UpstreamZone: set.UpstreamZone,
				Deleted:      set.Deleted,
			}
			for rrKey, entry := range set.Records {
				if entry == nil {
					continue
				}
				rec.Records[rrKey] = &dataRecordEntry{
					RR:            copyRR(entry.RR),
					ExpiresAt:     entry.ExpiresAt,
					LeaseDuration: entry.LeaseDuration,
					Deleted:       entry.Deleted,
				}
			}
			node.dataRec = rec
		}
	} else {
		for name, rec := range h.dataLeases {
			if rec == nil {
				continue
			}
			node := addNode(name)
			if node == nil {
				continue
			}
			node.dataRec = rec
		}
	}

	if len(nodes) == 0 {
		sb.WriteString("(empty)\n")
		return sb.String()
	}

	rootsByZone := make(map[string][]string)
	orphanDataOnly := make([]string, 0)

	for name, node := range nodes {
		if node == nil {
			continue
		}
		if node.keyRec == nil {
			if node.dataRec != nil {
				orphanDataOnly = append(orphanDataOnly, name)
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
			sb.WriteString(fmt.Sprintf("%sData-only lease: %s\n", indent, name))
		}

		if node.dataRec != nil {
			sb.WriteString(fmt.Sprintf("%s  Data lease:\n", indent))
			if len(node.dataRec.Records) > 0 {
				sb.WriteString(fmt.Sprintf("%s    Records:\n", indent))
				recordKeys := make([]string, 0, len(node.dataRec.Records))
				for rk := range node.dataRec.Records {
					recordKeys = append(recordKeys, rk)
				}
				sort.Strings(recordKeys)
				for _, rk := range recordKeys {
					entry := node.dataRec.Records[rk]
					if entry == nil {
						continue
					}
					sb.WriteString(fmt.Sprintf("%s      %s\n", indent, rk))
					sb.WriteString(fmt.Sprintf("%s        RR: %s\n", indent, entry.RR.String()))
					sb.WriteString(fmt.Sprintf("%s        ExpiresAt: %s\n", indent, entry.ExpiresAt.Format(time.RFC3339)))
					sb.WriteString(fmt.Sprintf("%s        LeaseDuration: %ds\n", indent, entry.LeaseDuration))
					sb.WriteString(fmt.Sprintf("%s        Deleted: %v\n", indent, entry.Deleted))
				}
			} else {
				sb.WriteString(fmt.Sprintf("%s    Records: (none)\n", indent))
			}
			sb.WriteString(fmt.Sprintf("%s    UpstreamZone: %s\n", indent, valueOrNone(node.dataRec.UpstreamZone)))
			sb.WriteString(fmt.Sprintf("%s    Deleted: %v\n", indent, node.dataRec.Deleted))
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

	if len(orphanDataOnly) > 0 {
		sort.Strings(orphanDataOnly)
		sb.WriteString("Orphan data leases:\n")
		for _, name := range orphanDataOnly {
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
//	Data lease: <keyName>
//	  Records:
//	    <recordKey>
//	      RR: <dns.RR string>
//	      ExpiresAt: <time>
//	      LeaseDuration: <seconds>s
//	      Deleted: <bool>
//	  ExpiresAt: <time>
//	  LeaseDuration: <seconds>s
//	  UpstreamZone: <zone>
//	  Deleted: <bool>
//
// INFO format (summary):
//
//	=== Lease Store Summary ===
//	Key: <keyName>  KEY=<active|expired|absent>  Data=<count>  Status=<active|expired|deleted>
//
// Keys that appear only in the KEY lease (no data lease) represent KEY-only registrations.
// Keys that appear only in the data lease (no KEY lease) represent data-only refreshes.
// Keys that appear in both have an active KEY + data RR lease.
func (h *UpdateHandler) DumpLeasesLevel(level string) string {
	// Normalize level.
	lower := strings.ToLower(strings.TrimSpace(level))
	isDebug := lower == "debug"

	// Lock timers to prevent schedule/expire during dump.
	h.leaseTimersMu.Lock()
	defer h.leaseTimersMu.Unlock()

	// Lock data leases for consistent snapshot.
	h.dataLeasesMu.RLock()
	defer h.dataLeasesMu.RUnlock()

	if isDebug {
		return h.dumpLeaseTreeLevel()
	}

	var sb strings.Builder

	// Collect all key names from both stores.
	keyNames := make(map[string]bool)
	for _, rec := range h.leaseManager.ListAll() {
		keyNames[rec.KeyRR.Hdr.Name] = true
	}
	for name := range h.dataLeases {
		keyNames[name] = true
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
		dataRec := h.getDataLease(name)

		// Determine key status.
		keyStatus := "absent"
		if keyRec != nil {
			if keyRec.IsExpired() {
				keyStatus = "expired"
			} else {
				keyStatus = "active"
			}
		}

		// Count live data records.
		dataCount := 0
		dataStatus := "absent"
		if dataRec != nil {
			dataStatus = "active"
			if dataRec.Deleted {
				dataStatus = "deleted"
			}
			for _, entry := range dataRec.Records {
				if !entry.Deleted {
					dataCount++
				}
			}
			if dataCount == 0 && !dataRec.Deleted {
				dataStatus = "empty"
			}
		}

		sb.WriteString(fmt.Sprintf("Key: %-40s KEY=%-8s Data=%d  Status=%s\n",
			name, keyStatus, dataCount, dataStatus))
	}

	return sb.String()
}

// DumpLeases is a convenience method that returns the full DEBUG-level dump.
// Deprecated: use DumpLeasesLevel("debug") instead.
func (h *UpdateHandler) DumpLeases() string {
	return h.DumpLeasesLevel("debug")
}

func (h *UpdateHandler) processExpiredLease(ctx context.Context, keyName string) {
	defer h.scheduleLeaseExpiry(keyName)

	record := h.leaseManager.Get(keyName)
	dataLease := h.getDataLease(keyName)
	if record == nil && (dataLease == nil || len(dataLease.Records) == 0) {
		h.clearLeaseTimer(keyName)
		return
	}

	now := time.Now()

	// Per-record expiry: expire each expired data record individually.
	if dataLease != nil {
		expiredAny := false
		effectiveZone := dataLease.UpstreamZone
		if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
			resolvedZone, err := dc.resolveAuthoritativeZone(ctx, dataLease.UpstreamZone)
			if err == nil {
				effectiveZone = resolvedZone
			}
		}

		var signingKey *keyrec.LoadedKey
		if h.upstreamCoordinator != nil {
			resolvedKey, matchedKeyZone, err := h.findAuthorizedProxyKeyForZone(effectiveZone)
			if err != nil {
				h.logger.Debugf("Failed to resolve proxy authorization key for data lease-expiry deletes in zone %s: %v", effectiveZone, err)
			} else {
				signingKey = resolvedKey
				h.logger.Debugf("Resolved proxy authorization key for data lease-expiry deletes in zone %s from key zone %s", effectiveZone, matchedKeyZone)
			}
		}

		for key, entry := range dataLease.Records {
			if !entry.Deleted && !now.Before(entry.ExpiresAt) {
				expiredAny = true
				if h.upstreamCoordinator != nil && signingKey != nil {
					deleteMsg, err := h.constructUpstreamDeleteForRecords([]dns.RR{entry.RR}, signingKey, effectiveZone)
					if err != nil {
						h.logger.Debugf("Failed to construct upstream data lease-expiry delete for %s record %s: %v", keyName, key, err)
					} else if _, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveZone, deleteMsg); err != nil {
						h.logger.Debugf("Upstream data lease-expiry delete failed for %s record %s: %v", keyName, key, err)
					}
				}
				entry.Deleted = true
			}
		}
		if expiredAny {
			h.markDataLeaseDeleted(keyName)
		}
	}

	if record == nil || now.Before(record.ExpiresAt) {
		return
	}

	effectiveUpstreamZone := record.UpstreamZone
	if dc, ok := h.upstreamCoordinator.(*DefaultUpstreamCoordinator); ok {
		resolvedZone, err := dc.resolveAuthoritativeZone(ctx, record.UpstreamZone)
		if err == nil {
			effectiveUpstreamZone = resolvedZone
		}
	}

	if h.upstreamCoordinator != nil && record.KeyRR != nil {
		signingKey, matchedKeyZone, err := h.findAuthorizedProxyKeyForZone(effectiveUpstreamZone)
		if err != nil {
			h.logger.Debugf("Failed to resolve proxy authorization key for key lease-expiry delete in zone %s: %v", effectiveUpstreamZone, err)
		} else {
			h.logger.Debugf("Resolved proxy authorization key for key lease-expiry delete in zone %s from key zone %s", effectiveUpstreamZone, matchedKeyZone)
		}
		deleteMsg, err := h.constructUpstreamDelete(record.KeyRR, signingKey, effectiveUpstreamZone)
		if err != nil {
			h.logger.Debugf("Failed to construct upstream lease-expiry delete for %s: %v", keyName, err)
		} else {
			if _, err := h.upstreamCoordinator.SendUpdate(ctx, effectiveUpstreamZone, deleteMsg); err != nil {
				h.logger.Debugf("Upstream lease-expiry delete failed for %s: %v", keyName, err)
			}
		}
	}

	if err := h.leaseManager.Delete(keyName); err != nil {
		h.logger.Debugf("Failed to delete expired local lease for %s: %v", keyName, err)
	}
	h.deleteDataLease(keyName)
	h.clearLeaseTimer(keyName)
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
