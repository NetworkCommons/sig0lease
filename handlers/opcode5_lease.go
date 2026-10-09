package handlers

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
)

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

// nextLeaseEvent returns how long until nodeKey's next lease event -- the earlier of its
// KEY's own expiry (KEY-LEASE) and its earliest non-KEY record's expiry (LEASE) -- or false
// if the store holds neither for it. Both UpdateHandler and SRPHandler arm their per-node
// expiry timers from this, so a node's non-KEY records always expire on their own LEASE
// instead of riding along with the KEY until KEY-LEASE.
func nextLeaseEvent(store LeaseManager, nodeKey string) (time.Duration, bool) {
	var next *time.Time

	if keyRec := store.Get(nodeKey); keyRec != nil {
		t := keyRec.ExpiresAt
		next = &t
	}

	if nonKeyRec := store.GetNonKEYRecordSet(nodeKey); nonKeyRec != nil {
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

// leaseExpirer ends the leases of one handler's store; both handlers use it, so a lease ends
// the same way in each. One lease event of a node is one UPDATE that deletes, record by record,
// every KEY and non-KEY record the event ends -- "at the same time", as RFC 9665 S5.1 requires
// of a host and its services -- and those are forgotten locally only once that UPDATE is
// confirmed. If it is not, nothing is forgotten, and the whole event is retried after the
// backoff (expiryTimers.finish). Only what the store tracks is deleted, never a Delete All
// RRsets at a name, which would also take records other writers put there.
type leaseExpirer struct {
	store    LeaseManager
	timers   *expiryTimers
	upstream upstreamTarget
	fire     func(nodeKey string) func()
	locks    *leasepkg.NodeLocks
	// lockIDs gives the handler's lock ids for a node and its whole subtree.
	lockIDs func(nodeKey string) []string
	// dataCascade makes the data expiry of a node take the data of every KEY node below it
	// along, whatever their own LEASE: RFC 9665 S5.1, "when the lease on a hostname expires,
	// the hostname and all services that reference it MUST be removed at the same time". An
	// instance registered by an earlier update and omitted from the host's latest one keeps
	// that update's LEASE; without the cascade a longer one would stay advertised against a
	// host with no addresses. RFC 9664 has no such rule.
	dataCascade bool
}

// dueRecord is a non-KEY record a lease event deletes, with the node that owns it.
type dueRecord struct {
	owner string
	rrKey string
	rr    dns.RR
}

// subtreeLeases returns every KEY and non-KEY record at and below nodeKey: what a KEY's
// expiry, or its Case C delete, takes away.
func subtreeLeases(store LeaseManager, nodeKey string) ([]*dns.KEY, []dueRecord) {
	var keys []*dns.KEY
	var records []dueRecord
	for _, owner := range append([]string{nodeKey}, store.ListSubtreeKeys(nodeKey)...) {
		if rec := store.Get(owner); rec != nil {
			keys = append(keys, rec.KeyRR)
		}
		records = append(records, ownRecords(store, owner, time.Time{})...)
	}
	return keys, records
}

// ownRecords returns owner's non-KEY records whose lease has ended by due, sorted; a zero due
// means all of them.
func ownRecords(store LeaseManager, owner string, due time.Time) []dueRecord {
	set := store.GetNonKEYRecordSet(owner)
	if set == nil {
		return nil
	}
	var records []dueRecord
	for rrKey, rec := range set.Records {
		if due.IsZero() || !due.Before(rec.ExpiresAt) {
			records = append(records, dueRecord{owner: owner, rrKey: rrKey, rr: rec.RR})
		}
	}
	slices.SortFunc(records, func(a, b dueRecord) int { return strings.Compare(a.rrKey, b.rrKey) })
	return records
}

// recordDeletes returns records as the UPDATE instructions that delete them.
func recordDeletes(records []dueRecord) []dns.RR {
	deletes := make([]dns.RR, 0, len(records))
	for _, r := range records {
		deletes = append(deletes, updatecore.AsDelete(r.rr))
	}
	return deletes
}

// run is a timer's lease event for nodeKey: it takes the node locks of nodeKey and its subtree
// and runs expire. A timer has nobody waiting on its answer, so it does not wait for a request
// holding any of them: it backs off and tries again, exactly like a failed attempt
// (docs/siglease_rfc9664.md, "Node Locks"). Reports whether anything was removed; the locks
// are released by the time it returns.
func (e leaseExpirer) run(ctx context.Context, nodeKey string) bool {
	locks, err := e.locks.TryAcquire(func() []string { return e.lockIDs(nodeKey) })
	if err != nil {
		delay := e.timers.finish(e.store, nodeKey, false, e.fire(nodeKey))
		e.upstream.logger.Infof("%s: lease expiry of %s: %v; retrying in %s", e.upstream.handler, nodeKey, err, delay)
		return false
	}
	defer locks.Release()
	return e.expire(ctx, nodeKey)
}

// expire runs nodeKey's lease event, its caller holding the node locks of nodeKey and its
// subtree, and re-arms nodeKey's timer: for its next lease event, or after the retry backoff
// if the UPDATE failed. If nodeKey's KEY has expired, the event ends its whole subtree
// (subtreeLeases), whatever the leases below it; otherwise it ends nodeKey's own records whose
// LEASE has run out, and with dataCascade, once one has, all the data of the KEY nodes below
// it. Reports whether anything was removed.
func (e leaseExpirer) expire(ctx context.Context, nodeKey string) bool {
	now := time.Now()
	var keys []*dns.KEY
	var records []dueRecord
	keyExpired := false
	if rec := e.store.Get(nodeKey); rec != nil && !now.Before(rec.ExpiresAt) {
		keyExpired = true
		keys, records = subtreeLeases(e.store, nodeKey)
	} else if records = ownRecords(e.store, nodeKey, now); len(records) > 0 && e.dataCascade {
		for _, child := range e.store.ListSubtreeKeys(nodeKey) {
			if e.store.Get(child) != nil {
				records = append(records, ownRecords(e.store, child, time.Time{})...)
			}
		}
	}
	if len(keys) == 0 && len(records) == 0 {
		// Nothing due: a raced refresh, or a node already gone.
		e.timers.finish(e.store, nodeKey, true, e.fire(nodeKey))
		return false
	}

	if _, err := e.upstream.send(ctx, nil, append(asDeletes(keys...), recordDeletes(records)...)); err != nil {
		delay := e.timers.finish(e.store, nodeKey, false, e.fire(nodeKey))
		e.upstream.logger.Warnf("%s: lease expiry of %s: %v; nothing forgotten, retrying in %s", e.upstream.handler, nodeKey, err, delay)
		return false
	}

	if keyExpired {
		// Every write to this node or its subtree takes one of the locks held here, so nothing
		// can have refreshed it during the upstream delete above. If something did, the
		// locking is broken, and the refresh's add and this delete raced upstream with no way to
		// tell which one the authoritative server applied last: fail hard instead of deleting
		// locally anyway.
		if rec := e.store.Get(nodeKey); rec != nil && !rec.IsExpired() {
			panic(fmt.Sprintf("%s: %s was refreshed while its expiry held its node locks and was deleting it upstream", e.upstream.handler, nodeKey))
		}
		for _, descendant := range e.store.ListSubtreeKeys(nodeKey) {
			e.timers.disarm(descendant)
		}
		if err := e.store.DeleteSubtree(nodeKey); err != nil {
			panic(fmt.Sprintf("%s: lease expiry of %s: %v", e.upstream.handler, nodeKey, err))
		}
	} else {
		for _, r := range records {
			if err := e.store.RemoveSingleNonKEYRecord(r.owner, r.rrKey); err != nil {
				panic(fmt.Sprintf("%s: lease expiry of %s: %v", e.upstream.handler, nodeKey, err))
			}
		}
	}
	e.upstream.logger.Infof("%s: lease expiry of %s: %d KEY(s) and %d record(s) deleted upstream and locally", e.upstream.handler, nodeKey, len(keys), len(records))
	e.timers.finish(e.store, nodeKey, true, e.fire(nodeKey))
	return true
}

// maxExpiryRetryDelay caps expiryRetryDelay's backoff, well below startLeaseReconciliation's
// 30s interval, which is only a safety net for a node that lost its timer altogether.
const maxExpiryRetryDelay = 16 * time.Second

// expiryRetryDelay is how long a handler waits before retrying a lease expiry that left
// something pending (an upstream delete that failed or was refused), given how many
// consecutive attempts for that node have now failed (1 on the first failure): 1s, doubling,
// capped at maxExpiryRetryDelay. No standard prescribes this -- RFC 9664 §7 assumes the
// authoritative server expires records itself -- but every second an expired record stays
// published upstream is a second its "MUST NOT return that RR in answers" is not met, so
// retries start quickly and back off only while a failure persists.
func expiryRetryDelay(failures int) time.Duration {
	delay := time.Second
	for i := 1; i < failures && delay < maxExpiryRetryDelay; i++ {
		delay *= 2
	}
	return min(delay, maxExpiryRetryDelay)
}

// expiryTimers is the per-node expiry timer table both handlers keep: at most one pending
// timer per KEY node, plus each node's run of consecutive failed expiry attempts, which sets
// how long its next retry waits (expiryRetryDelay). Sharing it keeps the two handlers'
// scheduling and retry behaviour identical.
type expiryTimers struct {
	mu       sync.Mutex
	timers   map[string]*time.Timer
	failures map[string]int
}

func newExpiryTimers() *expiryTimers {
	return &expiryTimers{timers: make(map[string]*time.Timer), failures: make(map[string]int)}
}

// arm replaces nodeKey's pending timer, if any, with one that calls fire after delay.
func (t *expiryTimers) arm(nodeKey string, delay time.Duration, fire func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.armLocked(nodeKey, delay, fire)
}

func (t *expiryTimers) armLocked(nodeKey string, delay time.Duration, fire func()) {
	if old, ok := t.timers[nodeKey]; ok {
		old.Stop()
	}
	t.timers[nodeKey] = time.AfterFunc(delay, fire)
}

// schedule arms nodeKey's timer for its next lease event (nextLeaseEvent), or disarms it if
// the node has nothing left to expire.
func (t *expiryTimers) schedule(store LeaseManager, nodeKey string, fire func()) {
	delay, ok := nextLeaseEvent(store, nodeKey)
	if !ok {
		t.disarm(nodeKey)
		return
	}
	t.arm(nodeKey, delay, fire)
}

// finish re-arms nodeKey's timer after an expiry attempt: after the retry backoff if the
// attempt left anything pending (complete false), or for the node's next lease event
// otherwise, ending its run of failures. Returns the backoff delay when retrying, else 0.
func (t *expiryTimers) finish(store LeaseManager, nodeKey string, complete bool, fire func()) time.Duration {
	if complete {
		t.mu.Lock()
		delete(t.failures, nodeKey)
		t.mu.Unlock()
		t.schedule(store, nodeKey, fire)
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures[nodeKey]++
	delay := expiryRetryDelay(t.failures[nodeKey])
	t.armLocked(nodeKey, delay, fire)
	return delay
}

// disarm stops and forgets nodeKey's pending timer and its failure run, for a node that is
// gone or whose expiry is being handled elsewhere.
func (t *expiryTimers) disarm(nodeKey string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.timers[nodeKey]; ok {
		old.Stop()
		delete(t.timers, nodeKey)
	}
	delete(t.failures, nodeKey)
}

// armed reports whether nodeKey has a timer in the table, pending or already firing.
func (t *expiryTimers) armed(nodeKey string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.timers[nodeKey]
	return ok
}

// reconcile arms a timer, for its next lease event, for every lease owner in store that has
// none: each KEY node, and each owner of non-KEY records, also one without a KEY record of its
// own (store.ListOwners). fire gives a node's timer callback. Both handlers run it every 30s
// (startLeaseReconciliation): it is how a store loaded from a snapshot at startup gets its
// timers, and it catches a node that lost its timer to a bug. It never deletes anything itself:
// a node already past its lease event gets a timer that fires almost at once, into the same
// upstream-aware expiry as every other.
func (t *expiryTimers) reconcile(store LeaseManager, logger *logging.Logger, fire func(nodeKey string) func()) {
	for _, nodeKey := range store.ListOwners() {
		if !t.armed(nodeKey) {
			logger.Debugf("Reconciliation: no active expiry timer for %s, scheduling now", nodeKey)
			t.schedule(store, nodeKey, fire(nodeKey))
		}
	}
}

func (h *UpdateHandler) scheduleLeaseExpiry(nodeKey string) {
	h.timers.schedule(h.leaseManager, nodeKey, h.expireFunc(nodeKey))
}

// expiryTimeout bounds one expiry attempt, both handlers': it holds the node's locks
// (docs/siglease_rfc9664.md, "Node Locks") while it deletes upstream.
const expiryTimeout = 10 * time.Second

// expireFunc is nodeKey's timer callback: one lease event (leaseExpirer.run).
func (h *UpdateHandler) expireFunc(nodeKey string) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), expiryTimeout)
		defer cancel()
		h.expirer().run(ctx, nodeKey)
	}
}

// startLeaseReconciliation runs expiryTimers.reconcile every interval, until Shutdown.
func (h *UpdateHandler) startLeaseReconciliation(interval time.Duration) {
	h.reconcileTicker = time.NewTicker(interval)
	go func() {
		for range h.reconcileTicker.C {
			h.timers.reconcile(h.leaseManager, h.logger, h.expireFunc)
		}
	}()
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
		name = dnsname.Normalize(name)
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

	// An owner of non-KEY records with no KEY record of its own (ListOwners) is listed by
	// its node key, under "Orphan data leases" below.
	for _, owner := range h.leaseManager.ListOwners() {
		if h.leaseManager.Get(owner) != nil {
			continue
		}
		if node := addNode(owner); node != nil {
			node.nonKeyRec = h.leaseManager.GetNonKEYRecordSet(owner)
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

		parentName := dnsname.Normalize(node.keyRec.ParentKeyName)
		if parentName != "" {
			if parentNode, ok := nodes[parentName]; ok && parentNode != nil && parentNode.keyRec != nil {
				parentNode.children = append(parentNode.children, name)
				continue
			}
		}

		zone := dnsname.Normalize(node.keyRec.UpstreamZone)
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
			sb.WriteString(fmt.Sprintf("%s  ParentKey: %s\n", indent, valueOrNone(dnsname.Normalize(node.keyRec.ParentKeyName))))
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
// Keys that appear only in the non-KEY lease (KEY=absent) own data but have no KEY record in
// the store, such as a signer that registered data without being lease-managed itself.
// Keys that appear in both have an active KEY + non-KEY RR lease.
func (h *UpdateHandler) DumpLeasesLevel(level string) string {
	// Normalize level.
	lower := strings.ToLower(strings.TrimSpace(level))
	isDebug := lower == "debug"

	// Lock timers to prevent schedule/expire during dump.
	h.timers.mu.Lock()
	defer h.timers.mu.Unlock()

	if isDebug {
		return h.dumpLeaseTreeLevel()
	}

	var sb strings.Builder

	// Every lease owner, by its composite NodeKey (name.+algo+tag), sorted: each KEY node, and
	// each owner of non-KEY records, also one with no KEY record of its own (KEY=absent).
	owners := h.leaseManager.ListOwners()

	// INFO level: summary output.
	sb.WriteString("=== Lease Store Summary ===\n")
	if len(owners) == 0 {
		sb.WriteString("(empty)\n")
		return sb.String()
	}

	for _, name := range owners {
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

// upstream is where this handler's UPDATEs go (upstreamTarget.send).
func (h *UpdateHandler) upstream() upstreamTarget {
	return upstreamTarget{handler: h.Name(), coordinator: h.upstreamCoordinator, signingKey: h.upstreamKeyRecord, zone: h.upstreamZone, logger: h.logger}
}

// expirer is how this handler ends leases (leaseExpirer). Its lock ids are NodeKeys and
// RecordKeys, and RFC 9664 has no data cascade.
func (h *UpdateHandler) expirer() leaseExpirer {
	return leaseExpirer{
		store:    h.leaseManager,
		timers:   h.timers,
		upstream: h.upstream(),
		fire:     h.expireFunc,
		locks:    h.nodeLocks,
		lockIDs: func(nodeKey string) []string {
			return append([]string{nodeKey}, h.leaseManager.ListSubtreeKeys(nodeKey)...)
		},
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
