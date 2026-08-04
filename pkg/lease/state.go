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

// NonKEYRecord represents a non-KEY RR lease node in the tree.
type NonKEYRecord struct {
	BaseRecord
	OwnerKeyName string
	RRKey        string
	RR           dns.RR
	UpstreamZone string
	Deleted      bool
}

// NonKEYRecordSet groups non-KEY records by owner key.
type NonKEYRecordSet struct {
	Records      map[string]*NonKEYRecord
	UpstreamZone string
	Deleted      bool
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

// LeaseStore manages lifecycle of client leases. Implementations must be thread-safe.
type LeaseStore interface {
	Register(ctx context.Context, keyName string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
	Lookup(keyName string) *Record
	Get(keyName string) *Record
	Delete(keyName string) error
	ListExpiring(within time.Duration) []*Record
	ListAll() []*Record
	SetPersistenceHook(hook func(ctx context.Context, op string, record *Record) error)
}

// HierarchicalLeaseStore adds tree-oriented and persistence-oriented operations
// on top of LeaseStore.
type HierarchicalLeaseStore interface {
	LeaseStore
	RegisterWithParent(ctx context.Context, parentKeyName string, keyName string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
	DeleteSubtree(keyName string) error
	ChildrenOf(keyName string) []string
	ExportSnapshot() (*LeaseTreeSnapshot, error)
	ImportSnapshot(snapshot *LeaseTreeSnapshot) error
	SaveSnapshot(path string) error
	LoadSnapshot(path string) error
}

// LeaseTreeStore extends tree operations with non-KEY node storage.
type LeaseTreeStore interface {
	HierarchicalLeaseStore
	UpsertNonKEYRecords(ownerKeyName string, records []dns.RR, leaseDuration uint32, upstreamZone string) error
	RefreshNonKEYRecords(ownerKeyName string, leaseDuration uint32) error
	MarkNonKEYRecordsDeleted(ownerKeyName string)
	RemoveNonKEYRecords(ownerKeyName string)
	GetNonKEYRecordSet(ownerKeyName string) *NonKEYRecordSet
	HasActiveNonKEYRecord(ownerKeyName string, rr dns.RR) bool
}

// LeaseTreeSnapshot is a storage-neutral representation of the lease tree.
type LeaseTreeSnapshot struct {
	Version     int                  `json:"version"`
	GeneratedAt time.Time            `json:"generated_at"`
	KeyNodes    []LeaseNodeSnapshot  `json:"key_nodes"`
	NonKEYNodes []NonKEYNodeSnapshot `json:"non_key_nodes"`
}

// LeaseNodeSnapshot is a persisted KEY node row.
type LeaseNodeSnapshot struct {
	KeyName          string    `json:"key_name"`
	RRType           uint16    `json:"rr_type,omitempty"`
	ParentKeyName    string    `json:"parent_key_name,omitempty"`
	UpstreamZone     string    `json:"upstream_zone"`
	LeaseDuration    uint32    `json:"lease_duration"`
	KeyLeaseDuration uint32    `json:"key_lease_duration"`
	RegisteredAt     time.Time `json:"registered_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	RRName           string    `json:"rr_name"`
	RRClass          uint16    `json:"rr_class"`
	RRTTL            uint32    `json:"rr_ttl"`
	KeyFlags         uint16    `json:"key_flags"`
	KeyProtocol      uint8     `json:"key_protocol"`
	KeyAlgorithm     uint8     `json:"key_algorithm"`
	KeyData          string    `json:"key_data"`
	ChildKeys        []string  `json:"child_keys,omitempty"`
}

// NonKEYNodeSnapshot is a persisted non-KEY node row.
type NonKEYNodeSnapshot struct {
	OwnerKeyName  string    `json:"owner_key_name"`
	RRType        uint16    `json:"rr_type,omitempty"`
	ParentKeyName string    `json:"parent_key_name"`
	RRKey         string    `json:"rr_key"`
	RRText        string    `json:"rr_text"`
	UpstreamZone  string    `json:"upstream_zone"`
	LeaseDuration uint32    `json:"lease_duration"`
	RegisteredAt  time.Time `json:"registered_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Deleted       bool      `json:"deleted"`
}

// InMemoryLeaseStore is an in-memory lease manager implementation.
type InMemoryLeaseStore struct {
	mu              sync.RWMutex
	leases          map[string]*Record
	children        map[string]map[string]struct{}
	rootsByZone     map[string]map[string]struct{}
	nonKeySets      map[string]*NonKEYRecordSet
	persistenceHook func(ctx context.Context, op string, record *Record) error
	cleanupTicker   *time.Ticker
	cleanupDone     chan struct{}
}

// NewInMemoryManager creates a new in-memory lease manager.
func NewInMemoryManager() *InMemoryLeaseStore {
	m := &InMemoryLeaseStore{
		leases:      make(map[string]*Record),
		children:    make(map[string]map[string]struct{}),
		rootsByZone: make(map[string]map[string]struct{}),
		nonKeySets:  make(map[string]*NonKEYRecordSet),
		cleanupDone: make(chan struct{}),
	}
	m.cleanupTicker = time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-m.cleanupTicker.C:
				m.cleanupExpired()
			case <-m.cleanupDone:
				return
			}
		}
	}()
	return m
}

// Register creates or updates a KEY lease.
func (m *InMemoryLeaseStore) Register(ctx context.Context, keyName string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error {
	return m.RegisterWithParent(ctx, "", keyName, keyRR, leaseDuration, keyLeaseDuration, upstreamZone)
}

// RegisterWithParent creates or updates a KEY lease with an optional parent key.
func (m *InMemoryLeaseStore) RegisterWithParent(ctx context.Context, parentKeyName string, keyName string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	keyName = normalizeName(keyName)
	if keyName == "" {
		return fmt.Errorf("key name is empty")
	}
	if keyRR == nil {
		return fmt.Errorf("key rr is nil")
	}

	parentKeyName = normalizeName(parentKeyName)
	upstreamZone = normalizeZone(upstreamZone)
	if parentKeyName == keyName {
		parentKeyName = ""
	}

	now := time.Now()
	record := &Record{
		BaseRecord: BaseRecord{
			NodeKind:      NodeKindKEY,
			RRType:        dns.RRToType(keyRR),
			ExpiresAt:     now.Add(time.Duration(leaseDuration) * time.Second),
			LeaseDuration: leaseDuration,
			RegisteredAt:  now,
			ParentKeyName: parentKeyName,
		},
		KeyName:          keyName,
		KeyRR:            keyRR,
		KeyLeaseDuration: keyLeaseDuration,
		UpstreamZone:     upstreamZone,
	}

	if existing, ok := m.leases[keyName]; ok {
		m.detachNodeLocked(existing.KeyName, existing.ParentKeyName, existing.UpstreamZone)
	}
	m.leases[keyName] = record
	m.attachNodeLocked(keyName, parentKeyName, upstreamZone)

	if m.persistenceHook != nil {
		_ = m.persistenceHook(ctx, "register", cloneRecord(record))
	}
	return nil
}

func (m *InMemoryLeaseStore) Lookup(keyName string) *Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keyName = normalizeName(keyName)
	record, exists := m.leases[keyName]
	if !exists || record.IsExpired() {
		return nil
	}
	return cloneRecord(record)
}

func (m *InMemoryLeaseStore) Get(keyName string) *Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keyName = normalizeName(keyName)
	record := m.leases[keyName]
	if record == nil {
		return nil
	}
	return cloneRecord(record)
}

func (m *InMemoryLeaseStore) Delete(keyName string) error {
	return m.DeleteSubtree(keyName)
}

func (m *InMemoryLeaseStore) DeleteSubtree(keyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	keyName = normalizeName(keyName)
	if keyName == "" {
		return fmt.Errorf("key name is empty")
	}
	m.deleteSubtreeLocked(context.Background(), keyName)
	return nil
}

func (m *InMemoryLeaseStore) ChildrenOf(keyName string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keyName = normalizeName(keyName)
	set := m.children[keyName]
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

func (m *InMemoryLeaseStore) UpsertNonKEYRecords(ownerKeyName string, records []dns.RR, leaseDuration uint32, upstreamZone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ownerKeyName = normalizeName(ownerKeyName)
	if ownerKeyName == "" {
		return fmt.Errorf("owner key name is empty")
	}
	if _, ok := m.leases[ownerKeyName]; !ok {
		return fmt.Errorf("owner key %s not found", ownerKeyName)
	}

	set := m.ensureNonKeySetLocked(ownerKeyName)
	now := time.Now()
	for _, rr := range records {
		if rr == nil || rr.Header() == nil {
			continue
		}
		rrKey := rrNodeKey(rr)
		if rrKey == "" {
			continue
		}
		entry, ok := set.Records[rrKey]
		if !ok {
			entry = &NonKEYRecord{
				BaseRecord: BaseRecord{
					NodeKind:      NodeKindNonKEY,
					RRType:        dns.RRToType(rr),
					ParentKeyName: ownerKeyName,
				},
				OwnerKeyName: ownerKeyName,
				RRKey:        rrKey,
			}
			set.Records[rrKey] = entry
		}
		entry.RR = rr.Clone()
		entry.RRType = dns.RRToType(rr)
		entry.UpstreamZone = normalizeZone(upstreamZone)
		entry.LeaseDuration = leaseDuration
		entry.RegisteredAt = now
		entry.ExpiresAt = now.Add(time.Duration(leaseDuration) * time.Second)
		entry.Deleted = false
	}
	set.UpstreamZone = normalizeZone(upstreamZone)
	set.Deleted = false
	return nil
}

func (m *InMemoryLeaseStore) RefreshNonKEYRecords(ownerKeyName string, leaseDuration uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ownerKeyName = normalizeName(ownerKeyName)
	set := m.nonKeySets[ownerKeyName]
	if set == nil {
		return fmt.Errorf("refresh rejected: lease does not exist")
	}
	now := time.Now()
	for _, entry := range set.Records {
		if entry.Deleted {
			continue
		}
		entry.LeaseDuration = leaseDuration
		entry.RegisteredAt = now
		entry.ExpiresAt = now.Add(time.Duration(leaseDuration) * time.Second)
	}
	set.Deleted = false
	return nil
}

func (m *InMemoryLeaseStore) MarkNonKEYRecordsDeleted(ownerKeyName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ownerKeyName = normalizeName(ownerKeyName)
	set := m.nonKeySets[ownerKeyName]
	if set == nil {
		return
	}
	for _, entry := range set.Records {
		entry.Deleted = true
	}
	set.Deleted = true
}

func (m *InMemoryLeaseStore) RemoveNonKEYRecords(ownerKeyName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ownerKeyName = normalizeName(ownerKeyName)
	delete(m.nonKeySets, ownerKeyName)
}

func (m *InMemoryLeaseStore) GetNonKEYRecordSet(ownerKeyName string) *NonKEYRecordSet {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ownerKeyName = normalizeName(ownerKeyName)
	set := m.nonKeySets[ownerKeyName]
	if set == nil {
		return nil
	}
	return cloneNonKeySet(set)
}

func (m *InMemoryLeaseStore) HasActiveNonKEYRecord(ownerKeyName string, rr dns.RR) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ownerKeyName = normalizeName(ownerKeyName)
	set := m.nonKeySets[ownerKeyName]
	if set == nil {
		return false
	}
	k := rrNodeKey(rr)
	if k == "" {
		return false
	}
	entry, ok := set.Records[k]
	if !ok {
		return false
	}
	return !entry.Deleted
}

func (m *InMemoryLeaseStore) ExportSnapshot() (*LeaseTreeSnapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keyNodes := make([]LeaseNodeSnapshot, 0, len(m.leases))
	keys := make([]string, 0, len(m.leases))
	for key := range m.leases {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		rec := m.leases[key]
		if rec == nil || rec.KeyRR == nil {
			continue
		}
		childKeys := make([]string, 0)
		for child := range m.children[key] {
			childKeys = append(childKeys, child)
		}
		sort.Strings(childKeys)

		keyNodes = append(keyNodes, LeaseNodeSnapshot{
			KeyName:          rec.KeyName,
			RRType:           rec.RRType,
			ParentKeyName:    rec.ParentKeyName,
			UpstreamZone:     rec.UpstreamZone,
			LeaseDuration:    rec.LeaseDuration,
			KeyLeaseDuration: rec.KeyLeaseDuration,
			RegisteredAt:     rec.RegisteredAt,
			ExpiresAt:        rec.ExpiresAt,
			RRName:           rec.KeyRR.Hdr.Name,
			RRClass:          rec.KeyRR.Hdr.Class,
			RRTTL:            rec.KeyRR.Hdr.TTL,
			KeyFlags:         rec.KeyRR.Flags,
			KeyProtocol:      rec.KeyRR.Protocol,
			KeyAlgorithm:     rec.KeyRR.Algorithm,
			KeyData:          rec.KeyRR.PublicKey,
			ChildKeys:        childKeys,
		})
	}

	nonKeyNodes := make([]NonKEYNodeSnapshot, 0)
	ownerNames := make([]string, 0, len(m.nonKeySets))
	for owner := range m.nonKeySets {
		ownerNames = append(ownerNames, owner)
	}
	sort.Strings(ownerNames)
	for _, owner := range ownerNames {
		set := m.nonKeySets[owner]
		if set == nil {
			continue
		}
		rrKeys := make([]string, 0, len(set.Records))
		for rrKey := range set.Records {
			rrKeys = append(rrKeys, rrKey)
		}
		sort.Strings(rrKeys)
		for _, rrKey := range rrKeys {
			rec := set.Records[rrKey]
			if rec == nil || rec.RR == nil {
				continue
			}
			nonKeyNodes = append(nonKeyNodes, NonKEYNodeSnapshot{
				OwnerKeyName:  owner,
				RRType:        rec.RRType,
				ParentKeyName: rec.ParentKeyName,
				RRKey:         rec.RRKey,
				RRText:        rec.RR.String(),
				UpstreamZone:  rec.UpstreamZone,
				LeaseDuration: rec.LeaseDuration,
				RegisteredAt:  rec.RegisteredAt,
				ExpiresAt:     rec.ExpiresAt,
				Deleted:       rec.Deleted,
			})
		}
	}

	return &LeaseTreeSnapshot{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		KeyNodes:    keyNodes,
		NonKEYNodes: nonKeyNodes,
	}, nil
}

func (m *InMemoryLeaseStore) ImportSnapshot(snapshot *LeaseTreeSnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("snapshot is nil")
	}

	newLeases := make(map[string]*Record, len(snapshot.KeyNodes))
	newChildren := make(map[string]map[string]struct{}, len(snapshot.KeyNodes))
	newRootsByZone := make(map[string]map[string]struct{})
	newNonKeySets := make(map[string]*NonKEYRecordSet)

	for _, node := range snapshot.KeyNodes {
		keyName := normalizeName(node.KeyName)
		if keyName == "" {
			return fmt.Errorf("snapshot key node has empty key name")
		}
		if strings.TrimSpace(node.KeyData) == "" {
			return fmt.Errorf("snapshot key data is empty for %s", keyName)
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
			KeyName:          keyName,
			KeyRR:            keyRR,
			KeyLeaseDuration: node.KeyLeaseDuration,
			UpstreamZone:     normalizeZone(node.UpstreamZone),
		}
		if rec.RegisteredAt.IsZero() {
			rec.RegisteredAt = time.Now()
		}
		newLeases[keyName] = rec
	}

	for keyName, rec := range newLeases {
		if rec.ParentKeyName != "" {
			if _, ok := newChildren[rec.ParentKeyName]; !ok {
				newChildren[rec.ParentKeyName] = make(map[string]struct{})
			}
			newChildren[rec.ParentKeyName][keyName] = struct{}{}
			continue
		}
		if rec.UpstreamZone == "" {
			continue
		}
		if _, ok := newRootsByZone[rec.UpstreamZone]; !ok {
			newRootsByZone[rec.UpstreamZone] = make(map[string]struct{})
		}
		newRootsByZone[rec.UpstreamZone][keyName] = struct{}{}
	}

	for _, node := range snapshot.NonKEYNodes {
		owner := normalizeName(node.OwnerKeyName)
		if owner == "" {
			return fmt.Errorf("snapshot non-key owner is empty")
		}
		rr, err := dns.New(node.RRText)
		if err != nil {
			return fmt.Errorf("invalid non-key RR for owner %s: %w", owner, err)
		}
		set := newNonKeySets[owner]
		if set == nil {
			set = &NonKEYRecordSet{Records: make(map[string]*NonKEYRecord)}
			newNonKeySets[owner] = set
		}
		rrKey := node.RRKey
		if rrKey == "" {
			rrKey = rrNodeKey(rr)
		}
		rrType := node.RRType
		if rrType == 0 {
			rrType = dns.RRToType(rr)
		}
		set.Records[rrKey] = &NonKEYRecord{
			BaseRecord: BaseRecord{
				NodeKind:      NodeKindNonKEY,
				RRType:        rrType,
				ExpiresAt:     node.ExpiresAt,
				LeaseDuration: node.LeaseDuration,
				RegisteredAt:  node.RegisteredAt,
				ParentKeyName: normalizeName(node.ParentKeyName),
			},
			OwnerKeyName: owner,
			RRKey:        rrKey,
			RR:           rr,
			UpstreamZone: normalizeZone(node.UpstreamZone),
			Deleted:      node.Deleted,
		}
		if set.UpstreamZone == "" {
			set.UpstreamZone = normalizeZone(node.UpstreamZone)
		}
		if node.Deleted {
			set.Deleted = true
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.leases = newLeases
	m.children = newChildren
	m.rootsByZone = newRootsByZone
	m.nonKeySets = newNonKeySets
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

func (m *InMemoryLeaseStore) cleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	expiredRoots := make([]string, 0)
	for keyName, record := range m.leases {
		if record.IsExpired() {
			expiredRoots = append(expiredRoots, keyName)
		}
	}
	for _, keyName := range expiredRoots {
		m.deleteSubtreeLocked(context.Background(), keyName)
	}

	for owner, set := range m.nonKeySets {
		if _, ok := m.leases[owner]; !ok {
			set.Deleted = true
			for _, rec := range set.Records {
				rec.Deleted = true
			}
			continue
		}
		for rrKey, rec := range set.Records {
			if rec == nil {
				delete(set.Records, rrKey)
				continue
			}
			if rec.ExpiresAt.Before(time.Now()) {
				rec.Deleted = true
			}
		}
	}
}

// Stop terminates cleanup goroutine.
func (m *InMemoryLeaseStore) Stop() {
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
		close(m.cleanupDone)
	}
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
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

func cloneNonKeySet(s *NonKEYRecordSet) *NonKEYRecordSet {
	if s == nil {
		return nil
	}
	out := &NonKEYRecordSet{
		Records:      make(map[string]*NonKEYRecord, len(s.Records)),
		UpstreamZone: s.UpstreamZone,
		Deleted:      s.Deleted,
	}
	for k, v := range s.Records {
		out.Records[k] = cloneNonKeyRecord(v)
	}
	return out
}

func (m *InMemoryLeaseStore) ensureNonKeySetLocked(ownerKeyName string) *NonKEYRecordSet {
	set := m.nonKeySets[ownerKeyName]
	if set == nil {
		set = &NonKEYRecordSet{Records: make(map[string]*NonKEYRecord)}
		m.nonKeySets[ownerKeyName] = set
	}
	if set.Records == nil {
		set.Records = make(map[string]*NonKEYRecord)
	}
	return set
}

func rrNodeKey(rr dns.RR) string {
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
	case uint16(4):
		return fmt.Sprintf("%s %d %d %s", name, class, typ, rr.Data().String())
	default:
		return fmt.Sprintf("%s %d %d %d %s", name, class, typ, rr.Data().Len(), rr.Data().String())
	}
}

func (m *InMemoryLeaseStore) attachNodeLocked(keyName, parentKeyName, zone string) {
	if parentKeyName != "" {
		if _, ok := m.children[parentKeyName]; !ok {
			m.children[parentKeyName] = make(map[string]struct{})
		}
		m.children[parentKeyName][keyName] = struct{}{}
		return
	}
	if zone == "" {
		return
	}
	if _, ok := m.rootsByZone[zone]; !ok {
		m.rootsByZone[zone] = make(map[string]struct{})
	}
	m.rootsByZone[zone][keyName] = struct{}{}
}

func (m *InMemoryLeaseStore) detachNodeLocked(keyName, parentKeyName, zone string) {
	if parentKeyName != "" {
		if kids, ok := m.children[parentKeyName]; ok {
			delete(kids, keyName)
			if len(kids) == 0 {
				delete(m.children, parentKeyName)
			}
		}
		return
	}
	if zone == "" {
		return
	}
	if roots, ok := m.rootsByZone[zone]; ok {
		delete(roots, keyName)
		if len(roots) == 0 {
			delete(m.rootsByZone, zone)
		}
	}
}

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
		rec := m.leases[key]
		if rec != nil {
			m.detachNodeLocked(key, rec.ParentKeyName, rec.UpstreamZone)
			if m.persistenceHook != nil {
				_ = m.persistenceHook(ctx, "delete", cloneRecord(rec))
			}
			delete(m.leases, key)
		}
		delete(m.children, key)
		if set := m.nonKeySets[key]; set != nil {
			set.Deleted = true
			for _, rec := range set.Records {
				rec.Deleted = true
			}
		}
	}
}
