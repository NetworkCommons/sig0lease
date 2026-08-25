package lease

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
)

type NodeKind string

const (
	NodeKindKEY    NodeKind = "key"
	NodeKindNonKEY NodeKind = "non-key"
)

// leaseSnapshotVersion is the on-disk snapshot format version. Bumped from 1
// to 2 when non-KEY records moved from owner-nested storage to flat, first-
// class tree nodes (same identity model KEY nodes already had) -- a v1 file
// does not unmarshal into this shape, so ImportSnapshot rejects anything
// that isn't exactly this version rather than silently loading as empty.
const leaseSnapshotVersion = 2

// BaseRecord is the shared lease node model used by KEY and non-KEY records.
type BaseRecord struct {
	NodeKind      NodeKind
	RRType        uint16
	ExpiresAt     time.Time
	LeaseDuration uint32
	RegisteredAt  time.Time
	ParentKeyName string
}

// Record represents an active KEY lease node (KEYRecord in the protocol model).
// It embeds BaseRecord and keeps compatibility with existing callers.
type Record struct {
	BaseRecord
	KeyName          string
	KeyRR            *dns.KEY
	KeyLeaseDuration uint32
	UpstreamZone     string
}

// KEYRecord is an alias to Record for clarity in tree-oriented code.
type KEYRecord = Record

// NonKEYRecord represents a non-KEY RR lease node in the tree. Like a KEY
// node, it is a first-class node with its own globally unique identity
// (RRKey, computed by RecordKey) -- it is not merely an entry in some
// owner's local set. ParentKeyName (inherited from BaseRecord) is the one
// and only place its owner is recorded.
type NonKEYRecord struct {
	BaseRecord
	RRKey        string
	RR           dns.RR
	UpstreamZone string
}

// NonKEYRecordSet is a read-only, point-in-time view of the non-KEY records
// owned by one node, returned by GetNonKEYRecordSet. It is not how records
// are stored internally -- see InMemoryLeaseStore.nonKeyRecords.
type NonKEYRecordSet struct {
	Records      map[string]*NonKEYRecord
	UpstreamZone string
}

// IsExpired returns true if the lease has expired.
func (r *Record) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// TimeRemaining returns the time until lease expiration.
func (r *Record) TimeRemaining() time.Duration {
	remaining := time.Until(r.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// LeaseStorage is the single storage-backend abstraction for lease state:
// KEY-lease lifecycle, tree/hierarchy operations, non-KEY record sets, and
// snapshot import/export/persistence. Every backend (in-memory, file-backed,
// or a caller-supplied Go-embedded implementation) must implement all of it
// -- there is no narrower interface to fall back to, and callers must not
// type-assert down to a subset. Implementations must be thread-safe.
//
// KEY and non-KEY records are both tree nodes with a globally unique
// identity (see NodeKey / RecordKey) and a ParentKeyName; a non-KEY node can
// never itself be a parent (RegisterWithParent rejects that). Uniqueness is
// enforced by the store itself, not by callers pre-checking: UpsertNonKEYRecords
// fails outright if any of the given records already exist under a
// different owner, rather than silently allowing two different keys to
// register the identical RR.
type LeaseStorage interface {
	// -- KEY lease lifecycle --

	// Register creates or updates a KEY lease. The node identity is derived from keyRR.
	Register(ctx context.Context, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
	// RenewLease extends an already-registered KEY lease's timers in place.
	// The node identity is derived from keyRR; it is an error if no such
	// node is already registered. Unlike Register, it never touches
	// ParentKeyName, RegisteredAt, or the node's position in the tree --
	// renewing a lease is not re-creating the node.
	RenewLease(ctx context.Context, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32) error
	// FindByName returns all non-expired records at the given DNS name.
	FindByName(dnsName string) []*Record
	// LookupByKEY returns the non-expired record matching k's exact identity (name+algo+tag).
	LookupByKEY(k *dns.KEY) *Record
	// LookupBySIG returns the non-expired record matching the SIG(0) signer identity.
	LookupBySIG(signerName string, algorithm uint8, keyTag uint16) *Record
	// Get returns the record for nodeKey (composite key), including expired records.
	Get(nodeKey string) *Record
	// Delete removes the subtree rooted at the composite nodeKey.
	Delete(nodeKey string) error
	ListExpiring(within time.Duration) []*Record
	ListAll() []*Record
	SetPersistenceHook(hook func(ctx context.Context, op string, record *Record) error)

	// -- Tree / hierarchy --

	// RegisterWithParent creates or updates a KEY lease with an optional
	// parent composite node key. Fails if parentNodeKey already identifies a
	// non-KEY record -- a non-KEY node can never be a parent.
	RegisterWithParent(ctx context.Context, parentNodeKey string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
	DeleteSubtree(nodeKey string) error
	ChildrenOf(nodeKey string) []string
	// ListSubtreeKeys returns composite node keys of all descendants
	// (KEY and non-KEY alike), deepest first.
	ListSubtreeKeys(nodeKey string) []string

	// -- Snapshot import/export/persistence --

	ExportSnapshot() (*LeaseTreeSnapshot, error)
	ImportSnapshot(snapshot *LeaseTreeSnapshot) error
	SaveSnapshot(path string) error
	LoadSnapshot(path string) error

	// -- Non-KEY record sets --

	// UpsertNonKEYRecords registers or refreshes records under ownerNodeKey.
	// Fails outright, applying none of the given records, if any of them
	// already exists in the store under a different owner -- this is the
	// store's own enforcement of "two different keys cannot register the
	// identical RR" (protocol.md), not merely a caller-side convention.
	UpsertNonKEYRecords(ownerNodeKey string, records []dns.RR, leaseDuration uint32, upstreamZone string) error
	RemoveNonKEYRecords(ownerNodeKey string)
	// RemoveSingleNonKEYRecord removes the record identified by rrKey.
	// Idempotent: a no-op, not an error, if no such record exists. Returns
	// an error, without effect, if the record exists but is owned by a
	// different node than ownerNodeKey.
	RemoveSingleNonKEYRecord(ownerNodeKey, rrKey string) error
	GetNonKEYRecordSet(ownerNodeKey string) *NonKEYRecordSet
	// LookupNonKEYRecord returns the record matching rr's RFC 2136 identity
	// anywhere in the store (regardless of owner), or nil if none exists.
	// Callers compare the result's ParentKeyName against their own candidate
	// owner to distinguish "mine" (refresh) from "someone else's" (reject).
	LookupNonKEYRecord(rr dns.RR) *NonKEYRecord

	// -- Lifecycle --

	// Stop releases any resources this backend owns (background goroutines,
	// open files, timers). Must be safe to call even when the backend owns
	// nothing (a no-op), and safe to call exactly once from a shutdown path.
	Stop()
}

// LeaseTreeSnapshot is a storage-neutral representation of the lease tree.
type LeaseTreeSnapshot struct {
	Version     int            `json:"version"`
	GeneratedAt time.Time      `json:"generated_at"`
	Nodes       []NodeSnapshot `json:"nodes"`
}

// NodeSnapshot is a persisted tree node row -- KEY or non-KEY, discriminated
// by NodeKind. Which of the KEY-only / non-KEY-only fields below are
// populated follows from that. A record that has been deleted or expired is
// removed from the store, so it is never persisted; there is no "deleted"
// flag to carry here.
type NodeSnapshot struct {
	NodeKind      NodeKind  `json:"node_kind"`
	NodeID        string    `json:"node_id"` // composite identity: KEY -> NodeKey(keyRR), non-KEY -> RecordKey(rr)
	ParentKeyName string    `json:"parent_key_name,omitempty"`
	RRType        uint16    `json:"rr_type,omitempty"`
	UpstreamZone  string    `json:"upstream_zone"`
	LeaseDuration uint32    `json:"lease_duration"`
	RegisteredAt  time.Time `json:"registered_at"`
	ExpiresAt     time.Time `json:"expires_at"`

	// KEY-only.
	KeyLeaseDuration uint32 `json:"key_lease_duration,omitempty"`
	RRName           string `json:"rr_name,omitempty"`
	RRClass          uint16 `json:"rr_class,omitempty"`
	RRTTL            uint32 `json:"rr_ttl,omitempty"`
	KeyFlags         uint16 `json:"key_flags,omitempty"`
	KeyProtocol      uint8  `json:"key_protocol,omitempty"`
	KeyAlgorithm     uint8  `json:"key_algorithm,omitempty"`
	KeyData          string `json:"key_data,omitempty"`

	// non-KEY-only: full presentation-format RR, reparsed via dns.New on import.
	RRText string `json:"rr_text,omitempty"`
}

// InMemoryLeaseStore is an in-memory lease manager implementation.
//
// KEY nodes (leases) and non-KEY nodes (nonKeyRecords) are each a flat map
// keyed by the node's own globally unique identity -- the same shape for
// both, so two attempts to register the identical identity (a KEY, or a
// non-KEY RR under a different owner) collide at the map itself instead of
// requiring every caller to remember to check first. children records
// parent/child edges for both kinds of node together: a KEY's children can
// be further KEY nodes or non-KEY nodes; a non-KEY node's entry in children
// is always absent, since it can never be a parent.
//
// The store never deletes anything on its own initiative: expiry is a
// handler-level concern, because only the handler can also send the
// corresponding upstream DNS delete. A store-driven timer here would race
// the handler's own precise per-node timer and — whichever fired first —
// silently erase local state without ever notifying the authoritative
// server. See UpdateHandler.reconcileLeaseTimers for the single, upstream-
// aware path that owns expiry.
type InMemoryLeaseStore struct {
	mu              sync.RWMutex
	leases          map[string]*Record             // composite NodeKey → Record (KEY nodes)
	nonKeyRecords   map[string]*NonKEYRecord        // RecordKey(rr) → NonKEYRecord (non-KEY nodes)
	nameIdx         map[string][]string             // DNS name → []NodeKey (KEY nodes only)
	children        map[string]map[string]struct{}  // node identity → set of child identities (KEY or non-KEY)
	rootsByZone     map[string]map[string]struct{}  // KEY nodes with no parent, by zone
	persistenceHook func(ctx context.Context, op string, record *Record) error
}

var _ LeaseStorage = (*InMemoryLeaseStore)(nil)

// NewInMemoryManager creates a new in-memory lease manager.
func NewInMemoryManager() *InMemoryLeaseStore {
	return &InMemoryLeaseStore{
		leases:        make(map[string]*Record),
		nonKeyRecords: make(map[string]*NonKEYRecord),
		nameIdx:       make(map[string][]string),
		children:      make(map[string]map[string]struct{}),
		rootsByZone:   make(map[string]map[string]struct{}),
	}
}

// Register creates or updates a KEY lease. Node identity is derived from keyRR.
func (m *InMemoryLeaseStore) Register(ctx context.Context, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error {
	return m.RegisterWithParent(ctx, "", keyRR, leaseDuration, keyLeaseDuration, upstreamZone)
}

// RegisterWithParent creates or updates a KEY lease with an optional parent composite node key.
func (m *InMemoryLeaseStore) RegisterWithParent(ctx context.Context, parentNodeKey string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if keyRR == nil {
		return fmt.Errorf("key rr is nil")
	}
	dnsName := normalizeName(keyRR.Hdr.Name)
	if dnsName == "" {
		return fmt.Errorf("key name is empty")
	}
	nodeKey := NodeKey(keyRR)

	parentNodeKey = normalizeName(parentNodeKey)
	if parentNodeKey == nodeKey {
		parentNodeKey = ""
	}
	if parentNodeKey != "" {
		if _, ok := m.nonKeyRecords[parentNodeKey]; ok {
			return fmt.Errorf("cannot register KEY %s under %s: a non-KEY record can never be a parent", nodeKey, parentNodeKey)
		}
	}
	upstreamZone = normalizeZone(upstreamZone)

	now := time.Now()
	record := &Record{
		BaseRecord: BaseRecord{
			NodeKind:      NodeKindKEY,
			RRType:        dns.RRToType(keyRR),
			ExpiresAt:     now.Add(time.Duration(leaseDuration) * time.Second),
			LeaseDuration: leaseDuration,
			RegisteredAt:  now,
			ParentKeyName: parentNodeKey,
		},
		KeyName:          dnsName,
		KeyRR:            keyRR,
		KeyLeaseDuration: keyLeaseDuration,
		UpstreamZone:     upstreamZone,
	}

	if existing, ok := m.leases[nodeKey]; ok {
		m.detachNodeLocked(nodeKey, existing.ParentKeyName, existing.UpstreamZone)
	} else {
		m.nameIdx[dnsName] = append(m.nameIdx[dnsName], nodeKey)
	}
	m.leases[nodeKey] = record
	m.attachNodeLocked(nodeKey, parentNodeKey, upstreamZone)

	if m.persistenceHook != nil {
		_ = m.persistenceHook(ctx, "register", cloneRecord(record))
	}
	return nil
}

// RenewLease extends an already-registered KEY lease's timers in place.
// Unlike Register/RegisterWithParent, it never rebuilds the node: it leaves
// ParentKeyName, RegisteredAt, and the node's position in the tree
// completely untouched, since renewing a lease is not re-creating it.
func (m *InMemoryLeaseStore) RenewLease(ctx context.Context, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if keyRR == nil {
		return fmt.Errorf("key rr is nil")
	}
	nodeKey := NodeKey(keyRR)

	existing, ok := m.leases[nodeKey]
	if !ok {
		return fmt.Errorf("no existing lease for %s to renew", nodeKey)
	}

	existing.ExpiresAt = time.Now().Add(time.Duration(leaseDuration) * time.Second)
	existing.LeaseDuration = leaseDuration
	existing.KeyLeaseDuration = keyLeaseDuration
	existing.KeyRR = keyRR

	if m.persistenceHook != nil {
		_ = m.persistenceHook(ctx, "renew", cloneRecord(existing))
	}
	return nil
}

func (m *InMemoryLeaseStore) FindByName(dnsName string) []*Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	dnsName = normalizeName(dnsName)
	var out []*Record
	for _, nodeKey := range m.nameIdx[dnsName] {
		if rec := m.leases[nodeKey]; rec != nil && !rec.IsExpired() {
			out = append(out, cloneRecord(rec))
		}
	}
	return out
}

func (m *InMemoryLeaseStore) LookupByKEY(k *dns.KEY) *Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec := m.leases[NodeKey(k)]
	if rec == nil || rec.IsExpired() {
		return nil
	}
	return cloneRecord(rec)
}

func (m *InMemoryLeaseStore) LookupBySIG(signerName string, algorithm uint8, keyTag uint16) *Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec := m.leases[NodeKeyFromSIG(signerName, algorithm, keyTag)]
	if rec == nil || rec.IsExpired() {
		return nil
	}
	return cloneRecord(rec)
}

// Get returns the record for the exact composite nodeKey, including expired records.
func (m *InMemoryLeaseStore) Get(nodeKey string) *Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if rec, ok := m.leases[normalizeName(nodeKey)]; ok {
		return cloneRecord(rec)
	}
	return nil
}

func (m *InMemoryLeaseStore) Delete(nodeKey string) error {
	return m.DeleteSubtree(nodeKey)
}

// DeleteSubtree removes the subtree rooted at the exact composite nodeKey.
func (m *InMemoryLeaseStore) DeleteSubtree(nodeKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	nk := normalizeName(nodeKey)
	if nk == "" {
		return fmt.Errorf("node key is empty")
	}
	m.deleteSubtreeLocked(context.Background(), nk)
	return nil
}

// ChildrenOf returns the composite node keys of direct children (KEY or
// non-KEY) of the exact composite nodeKey.
func (m *InMemoryLeaseStore) ChildrenOf(nodeKey string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	set := m.children[normalizeName(nodeKey)]
	if len(set) == 0 {
		return nil
	}
	children := make([]string, 0, len(set))
	for child := range set {
		children = append(children, child)
	}
	sort.Strings(children)
	return children
}

// ListSubtreeKeys returns composite node keys of all descendants (KEY and
// non-KEY alike) of nodeKey, deepest first.
func (m *InMemoryLeaseStore) ListSubtreeKeys(nodeKey string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nk := normalizeName(nodeKey)

	all := make([]string, 0)
	stack := []string{nk}
	visited := map[string]bool{nk: true}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for child := range m.children[cur] {
			if !visited[child] {
				visited[child] = true
				all = append(all, child)
				stack = append(stack, child)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return len(all[i]) > len(all[j]) })
	return all
}

func (m *InMemoryLeaseStore) ListExpiring(within time.Duration) []*Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var expiring []*Record
	cutoff := time.Now().Add(within)
	for _, record := range m.leases {
		if !record.IsExpired() && record.ExpiresAt.Before(cutoff) {
			expiring = append(expiring, cloneRecord(record))
		}
	}
	return expiring
}

func (m *InMemoryLeaseStore) ListAll() []*Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var all []*Record
	for _, record := range m.leases {
		all = append(all, cloneRecord(record))
	}
	return all
}

func (m *InMemoryLeaseStore) SetPersistenceHook(hook func(ctx context.Context, op string, record *Record) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.persistenceHook = hook
}

// UpsertNonKEYRecords attaches records to ownerNodeKey. The owner is not
// required to have a KEY Record in m.leases: a non-KEY record can be owned
// by a "phantom" node the same way a child KEY can already have a
// ParentKeyName pointing at one (see RegisterWithParent/attachNodeLocked).
// This lets a signer that is deliberately never self-registered (e.g. an
// online-only key authorized via AllowOnlineKeyRegistration) still own data.
//
// Every record is validated against the whole batch before any of them is
// applied: if any of the given records already exists in the store under a
// different owner, the entire call fails and nothing is written -- the same
// "fail the parts that would otherwise succeed" policy used for duplicate
// KEY/RR registration elsewhere (protocol.md item 6), because partially
// applying a batch here would leave the store's consistency unguaranteed.
func (m *InMemoryLeaseStore) UpsertNonKEYRecords(ownerNodeKey string, records []dns.RR, leaseDuration uint32, upstreamZone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ownerNodeKey = normalizeName(ownerNodeKey)
	if ownerNodeKey == "" {
		return fmt.Errorf("owner key name is empty")
	}

	type candidate struct {
		id string
		rr dns.RR
	}
	toApply := make([]candidate, 0, len(records))

	for _, rr := range records {
		if rr == nil || rr.Header() == nil {
			continue
		}
		id := RecordKey(rr)
		if id == "" {
			continue
		}
		if existing, ok := m.nonKeyRecords[id]; ok && existing.ParentKeyName != ownerNodeKey {
			return fmt.Errorf("non-KEY record %s is already registered under a different owner (%s)", rr.String(), existing.ParentKeyName)
		}
		toApply = append(toApply, candidate{id: id, rr: rr})
	}

	now := time.Now()
	zone := normalizeZone(upstreamZone)
	for _, c := range toApply {
		entry, ok := m.nonKeyRecords[c.id]
		if !ok {
			entry = &NonKEYRecord{
				BaseRecord: BaseRecord{
					NodeKind:      NodeKindNonKEY,
					ParentKeyName: ownerNodeKey,
				},
				RRKey: c.id,
			}
			m.nonKeyRecords[c.id] = entry
			m.attachNodeLocked(c.id, ownerNodeKey, "")
		}
		entry.RR = c.rr.Clone()
		entry.RRType = dns.RRToType(c.rr)
		entry.UpstreamZone = zone
		entry.LeaseDuration = leaseDuration
		entry.RegisteredAt = now
		entry.ExpiresAt = now.Add(time.Duration(leaseDuration) * time.Second)
	}
	return nil
}

// RemoveNonKEYRecords removes every non-KEY record owned by ownerNodeKey.
// KEY children of ownerNodeKey (if any) are untouched -- this only ever
// removes non-KEY records, never cascades into a KEY subtree.
func (m *InMemoryLeaseStore) RemoveNonKEYRecords(ownerNodeKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ownerNodeKey = normalizeName(ownerNodeKey)
	kids := m.children[ownerNodeKey]
	for childID := range kids {
		if _, ok := m.nonKeyRecords[childID]; ok {
			delete(m.nonKeyRecords, childID)
			delete(kids, childID)
		}
	}
	if len(kids) == 0 {
		delete(m.children, ownerNodeKey)
	}
}

// RemoveSingleNonKEYRecord removes the record identified by rrKey, leaving
// the rest of ownerNodeKey's records untouched. Idempotent: a missing record
// is a no-op, not an error (deleting something already gone -- e.g. a
// caller racing its own earlier removal of the same record -- has already
// reached its desired end state). Returns an error, without effect, if the
// record exists but is owned by a different node: a caller passing a
// mismatched owner is a bug worth surfacing loudly rather than silently
// deleting nothing (or, worse, the wrong thing).
func (m *InMemoryLeaseStore) RemoveSingleNonKEYRecord(ownerNodeKey, rrKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ownerNodeKey = normalizeName(ownerNodeKey)
	entry, ok := m.nonKeyRecords[rrKey]
	if !ok {
		// Idempotent delete: a record that's already gone (e.g. a caller
		// racing its own earlier removal of the same record, which happens
		// legitimately when a record's own LEASE and its owning KEY's
		// KEY-LEASE expire in the same tick) is not an error -- the desired
		// end state ("this record is absent") already holds.
		return nil
	}
	if entry.ParentKeyName != ownerNodeKey {
		return fmt.Errorf("non-KEY record %q is not owned by %q (owned by %q)", rrKey, ownerNodeKey, entry.ParentKeyName)
	}

	delete(m.nonKeyRecords, rrKey)
	if kids := m.children[ownerNodeKey]; kids != nil {
		delete(kids, rrKey)
		if len(kids) == 0 {
			delete(m.children, ownerNodeKey)
		}
	}
	return nil
}

// GetNonKEYRecordSet returns a point-in-time, cloned view of the non-KEY
// records owned by ownerNodeKey, or nil if it owns none.
func (m *InMemoryLeaseStore) GetNonKEYRecordSet(ownerNodeKey string) *NonKEYRecordSet {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ownerNodeKey = normalizeName(ownerNodeKey)
	kids := m.children[ownerNodeKey]
	if len(kids) == 0 {
		return nil
	}

	records := make(map[string]*NonKEYRecord)
	zone := ""
	for childID := range kids {
		rec, ok := m.nonKeyRecords[childID]
		if !ok {
			continue // a KEY child, not a non-KEY one
		}
		records[childID] = cloneNonKeyRecord(rec)
		zone = rec.UpstreamZone
	}
	if len(records) == 0 {
		return nil
	}
	return &NonKEYRecordSet{Records: records, UpstreamZone: zone}
}

// LookupNonKEYRecord returns the record matching rr's RFC 2136 identity
// anywhere in the store, regardless of owner, or nil if none exists.
func (m *InMemoryLeaseStore) LookupNonKEYRecord(rr dns.RR) *NonKEYRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id := RecordKey(rr)
	if id == "" {
		return nil
	}
	return cloneNonKeyRecord(m.nonKeyRecords[id])
}

func (m *InMemoryLeaseStore) ExportSnapshot() (*LeaseTreeSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nodes := make([]NodeSnapshot, 0, len(m.leases)+len(m.nonKeyRecords))

	keyIDs := make([]string, 0, len(m.leases))
	for id := range m.leases {
		keyIDs = append(keyIDs, id)
	}
	sort.Strings(keyIDs)
	for _, id := range keyIDs {
		rec := m.leases[id]
		if rec == nil || rec.KeyRR == nil {
			continue
		}
		nodes = append(nodes, NodeSnapshot{
			NodeKind:         NodeKindKEY,
			NodeID:           id,
			ParentKeyName:    rec.ParentKeyName,
			RRType:           rec.RRType,
			UpstreamZone:     rec.UpstreamZone,
			LeaseDuration:    rec.LeaseDuration,
			RegisteredAt:     rec.RegisteredAt,
			ExpiresAt:        rec.ExpiresAt,
			KeyLeaseDuration: rec.KeyLeaseDuration,
			RRName:           rec.KeyRR.Hdr.Name,
			RRClass:          rec.KeyRR.Hdr.Class,
			RRTTL:            rec.KeyRR.Hdr.TTL,
			KeyFlags:         rec.KeyRR.Flags,
			KeyProtocol:      rec.KeyRR.Protocol,
			KeyAlgorithm:     rec.KeyRR.Algorithm,
			KeyData:          rec.KeyRR.PublicKey,
		})
	}

	nonKeyIDs := make([]string, 0, len(m.nonKeyRecords))
	for id := range m.nonKeyRecords {
		nonKeyIDs = append(nonKeyIDs, id)
	}
	sort.Strings(nonKeyIDs)
	for _, id := range nonKeyIDs {
		rec := m.nonKeyRecords[id]
		if rec == nil || rec.RR == nil {
			continue
		}
		nodes = append(nodes, NodeSnapshot{
			NodeKind:      NodeKindNonKEY,
			NodeID:        id,
			ParentKeyName: rec.ParentKeyName,
			RRType:        rec.RRType,
			UpstreamZone:  rec.UpstreamZone,
			LeaseDuration: rec.LeaseDuration,
			RegisteredAt:  rec.RegisteredAt,
			ExpiresAt:     rec.ExpiresAt,
			RRText:        rec.RR.String(),
		})
	}

	return &LeaseTreeSnapshot{
		Version:     leaseSnapshotVersion,
		GeneratedAt: time.Now().UTC(),
		Nodes:       nodes,
	}, nil
}

func (m *InMemoryLeaseStore) ImportSnapshot(snapshot *LeaseTreeSnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("snapshot is nil")
	}
	if snapshot.Version != leaseSnapshotVersion {
		return fmt.Errorf("unsupported snapshot version %d (expected %d)", snapshot.Version, leaseSnapshotVersion)
	}

	newLeases := make(map[string]*Record)
	newNonKeyRecords := make(map[string]*NonKEYRecord)

	for _, node := range snapshot.Nodes {
		switch node.NodeKind {
		case NodeKindKEY:
			if strings.TrimSpace(node.KeyData) == "" {
				return fmt.Errorf("snapshot key data is empty for %s", node.NodeID)
			}
			nodeID := normalizeName(node.NodeID)
			if nodeID == "" {
				return fmt.Errorf("snapshot key node has empty node id")
			}

			keyRR := &dns.KEY{DNSKEY: dns.DNSKEY{Hdr: dns.Header{Name: node.RRName, Class: node.RRClass, TTL: node.RRTTL}}}
			keyRR.Flags = node.KeyFlags
			keyRR.Protocol = node.KeyProtocol
			keyRR.Algorithm = node.KeyAlgorithm
			keyRR.PublicKey = node.KeyData

			rrType := node.RRType
			if rrType == 0 {
				rrType = dns.RRToType(keyRR)
				if rrType == 0 {
					rrType = dns.TypeKEY
				}
			}

			rec := &Record{
				BaseRecord: BaseRecord{
					NodeKind:      NodeKindKEY,
					RRType:        rrType,
					ExpiresAt:     node.ExpiresAt,
					LeaseDuration: node.LeaseDuration,
					RegisteredAt:  node.RegisteredAt,
					ParentKeyName: normalizeName(node.ParentKeyName),
				},
				KeyName:          normalizeName(node.RRName),
				KeyRR:            keyRR,
				KeyLeaseDuration: node.KeyLeaseDuration,
				UpstreamZone:     normalizeZone(node.UpstreamZone),
			}
			if rec.RegisteredAt.IsZero() {
				rec.RegisteredAt = time.Now()
			}
			newLeases[nodeID] = rec

		case NodeKindNonKEY:
			nodeID := node.NodeID
			if nodeID == "" {
				return fmt.Errorf("snapshot non-key node has empty node id")
			}
			parent := normalizeName(node.ParentKeyName)
			if parent == "" {
				return fmt.Errorf("snapshot non-key node %s has empty parent", nodeID)
			}
			rr, err := dns.New(node.RRText)
			if err != nil {
				return fmt.Errorf("invalid non-key RR for node %s: %w", nodeID, err)
			}
			rrType := node.RRType
			if rrType == 0 {
				rrType = dns.RRToType(rr)
			}
			newNonKeyRecords[nodeID] = &NonKEYRecord{
				BaseRecord: BaseRecord{
					NodeKind:      NodeKindNonKEY,
					RRType:        rrType,
					ExpiresAt:     node.ExpiresAt,
					LeaseDuration: node.LeaseDuration,
					RegisteredAt:  node.RegisteredAt,
					ParentKeyName: parent,
				},
				RRKey:        nodeID,
				RR:           rr,
				UpstreamZone: normalizeZone(node.UpstreamZone),
			}

		default:
			return fmt.Errorf("snapshot node %s has unknown node_kind %q", node.NodeID, node.NodeKind)
		}
	}

	// Rebuild the tree/name indices from ParentKeyName now that every node
	// is known -- children/rootsByZone/nameIdx are all derived, not persisted.
	newChildren := make(map[string]map[string]struct{})
	newRootsByZone := make(map[string]map[string]struct{})
	newNameIdx := make(map[string][]string)

	for nodeID, rec := range newLeases {
		newNameIdx[rec.KeyName] = append(newNameIdx[rec.KeyName], nodeID)
		if rec.ParentKeyName != "" {
			if newChildren[rec.ParentKeyName] == nil {
				newChildren[rec.ParentKeyName] = make(map[string]struct{})
			}
			newChildren[rec.ParentKeyName][nodeID] = struct{}{}
			continue
		}
		if rec.UpstreamZone == "" {
			continue
		}
		if newRootsByZone[rec.UpstreamZone] == nil {
			newRootsByZone[rec.UpstreamZone] = make(map[string]struct{})
		}
		newRootsByZone[rec.UpstreamZone][nodeID] = struct{}{}
	}
	for nodeID, rec := range newNonKeyRecords {
		if newChildren[rec.ParentKeyName] == nil {
			newChildren[rec.ParentKeyName] = make(map[string]struct{})
		}
		newChildren[rec.ParentKeyName][nodeID] = struct{}{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.leases = newLeases
	m.nonKeyRecords = newNonKeyRecords
	m.nameIdx = newNameIdx
	m.children = newChildren
	m.rootsByZone = newRootsByZone
	return nil
}

func (m *InMemoryLeaseStore) SaveSnapshot(path string) error {
	snapshot, err := m.ExportSnapshot()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	return nil
}

func (m *InMemoryLeaseStore) LoadSnapshot(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}
	var snapshot LeaseTreeSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("unmarshal snapshot: %w", err)
	}
	return m.ImportSnapshot(&snapshot)
}

// Stop satisfies LeaseStorage.Stop(). InMemoryLeaseStore owns no background
// goroutine or file handle, so this is a no-op; persistence-owning backends
// (see FileLeaseStore) override it to flush state and release resources.
func (m *InMemoryLeaseStore) Stop() {}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// NodeKey returns the canonical composite lease-store key for a KEY RR.
// Format: dnsname.+algo+keytag (same convention as BIND key files).
func NodeKey(k *dns.KEY) string {
	return fmt.Sprintf("%s.+%03d+%05d", normalizeName(k.Hdr.Name), k.Algorithm, k.KeyTag())
}

// NodeKeyFromSIG computes the composite lease-store key from SIG(0) signer fields.
func NodeKeyFromSIG(signerName string, algorithm uint8, keyTag uint16) string {
	return fmt.Sprintf("%s.+%03d+%05d", normalizeName(signerName), algorithm, keyTag)
}

// dnsNameFromNodeKey extracts the DNS name portion of a composite node key.
func dnsNameFromNodeKey(nodeKey string) string {
	if i := strings.LastIndex(nodeKey, ".+"); i > 0 {
		return nodeKey[:i]
	}
	return nodeKey
}

func normalizeZone(zone string) string {
	return normalizeName(zone)
}

func cloneRecord(r *Record) *Record {
	if r == nil {
		return nil
	}
	copy := *r
	return &copy
}

func cloneNonKeyRecord(r *NonKEYRecord) *NonKEYRecord {
	if r == nil {
		return nil
	}
	copy := *r
	if copy.RR != nil {
		copy.RR = copy.RR.Clone()
	}
	return &copy
}

// RecordKey returns the canonical, globally unique identity for a non-KEY
// RR's lease-store node, per RFC 2136 - 1.1 - Comparison Rules: two RRs are
// equal if their NAME, CLASS, TYPE, RDLENGTH, and RDATA fields are equal.
// The TTL field is explicitly excluded from the comparison.
//
// Special RR types (rfc2136 - 1.1 - Comparison Rules):
//
//	SOA:   compare only NAME, CLASS, TYPE (only one SOA per zone)
//	CNAME: compare only NAME, CLASS, TYPE (only one CNAME per name)
//	WKS:   compare only NAME, CLASS, TYPE, ADDRESS, PROTOCOL (services mask
//	       excluded). The dns library does not provide support for WKS RRs
//	       (no dns.WK type, no TypeWKS constant), so there is no proper
//	       parser for the RDATA; the full data string is used instead, which
//	       may include the services mask -- not fully RFC 2136 compliant for
//	       WKS, but there is no better option available.
//
// This is the one function that must be used everywhere a non-KEY record's
// identity is computed -- the store's own keys, duplicate/ownership checks,
// and deletion-by-key all have to agree on the same string for the same RR,
// or a lookup with different casing than what was stored silently misses.
func RecordKey(rr dns.RR) string {
	if rr == nil || rr.Header() == nil {
		return ""
	}
	hdr := rr.Header()
	name := strings.ToLower(hdr.Name)
	class := hdr.Class
	typ := dns.RRToType(rr)

	switch typ {
	case dns.TypeSOA, dns.TypeCNAME:
		return fmt.Sprintf("%s %d %d", name, class, typ)
	case uint16(4): // WKS type code (not exported by the dns library)
		return fmt.Sprintf("%s %d %d %s", name, class, typ, rr.Data().String())
	default:
		return fmt.Sprintf("%s %d %d %d %s", name, class, typ, rr.Data().Len(), rr.Data().String())
	}
}

func (m *InMemoryLeaseStore) attachNodeLocked(nodeKey, parentNodeKey, zone string) {
	if parentNodeKey != "" {
		if _, ok := m.children[parentNodeKey]; !ok {
			m.children[parentNodeKey] = make(map[string]struct{})
		}
		m.children[parentNodeKey][nodeKey] = struct{}{}
		return
	}
	if zone == "" {
		return
	}
	if _, ok := m.rootsByZone[zone]; !ok {
		m.rootsByZone[zone] = make(map[string]struct{})
	}
	m.rootsByZone[zone][nodeKey] = struct{}{}
}

func (m *InMemoryLeaseStore) detachNodeLocked(nodeKey, parentNodeKey, zone string) {
	if parentNodeKey != "" {
		if kids, ok := m.children[parentNodeKey]; ok {
			delete(kids, nodeKey)
			if len(kids) == 0 {
				delete(m.children, parentNodeKey)
			}
		}
		return
	}
	if zone == "" {
		return
	}
	if roots, ok := m.rootsByZone[zone]; ok {
		delete(roots, nodeKey)
		if len(roots) == 0 {
			delete(m.rootsByZone, zone)
		}
	}
}

// deleteSubtreeLocked removes rootKey and every descendant reachable through
// children, whether each is a KEY node (m.leases) or a non-KEY node
// (m.nonKeyRecords).
func (m *InMemoryLeaseStore) deleteSubtreeLocked(ctx context.Context, rootKey string) {
	stack := []string{rootKey}
	seen := make(map[string]struct{})
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := seen[current]; ok {
			continue
		}
		seen[current] = struct{}{}
		for child := range m.children[current] {
			stack = append(stack, child)
		}
	}

	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})

	for _, key := range keys {
		if rec, ok := m.leases[key]; ok {
			m.detachNodeLocked(key, rec.ParentKeyName, rec.UpstreamZone)
			if m.persistenceHook != nil {
				_ = m.persistenceHook(ctx, "delete", cloneRecord(rec))
			}
			delete(m.leases, key)
			dnsName := dnsNameFromNodeKey(key)
			if existing := m.nameIdx[dnsName]; len(existing) > 0 {
				updated := existing[:0]
				for _, nk := range existing {
					if nk != key {
						updated = append(updated, nk)
					}
				}
				if len(updated) == 0 {
					delete(m.nameIdx, dnsName)
				} else {
					m.nameIdx[dnsName] = updated
				}
			}
		} else if nkRec, ok := m.nonKeyRecords[key]; ok {
			m.detachNodeLocked(key, nkRec.ParentKeyName, "")
			delete(m.nonKeyRecords, key)
		}
		delete(m.children, key)
	}
}
