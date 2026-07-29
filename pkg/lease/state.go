package lease

import (
	"context"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
)

// Record represents an active lease for a client key.
type Record struct {
	KeyRR            *dns.KEY
	ExpiresAt        time.Time
	LeaseDuration    uint32
	KeyLeaseDuration uint32
	UpstreamZone     string
	RegisteredAt     time.Time
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

// Manager manages lifecycle of client leases. Implementations must be thread-safe.
type Manager interface {
	Register(ctx context.Context, keyName string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
	Lookup(keyName string) *Record
	Get(keyName string) *Record
	Delete(keyName string) error
	ListExpiring(within time.Duration) []*Record
	ListAll() []*Record
	SetPersistenceHook(hook func(ctx context.Context, op string, record *Record) error)
}

// InMemoryManager is an in-memory lease manager implementation.
type InMemoryManager struct {
	mu              sync.RWMutex
	leases          map[string]*Record
	persistenceHook func(ctx context.Context, op string, record *Record) error
	cleanupTicker   *time.Ticker
	cleanupDone     chan struct{}
}

// NewInMemoryManager creates a new in-memory lease manager.
func NewInMemoryManager() *InMemoryManager {
	m := &InMemoryManager{
		leases:      make(map[string]*Record),
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

// Register creates or updates a lease.
func (m *InMemoryManager) Register(ctx context.Context, keyName string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Normalize key name for consistent storage and lookup.
	keyName = strings.TrimSuffix(strings.ToLower(keyName), ".")

	record := &Record{
		KeyRR:            keyRR,
		ExpiresAt:        time.Now().Add(time.Duration(leaseDuration) * time.Second),
		LeaseDuration:    leaseDuration,
		KeyLeaseDuration: keyLeaseDuration, // Store actual KEY-LEASE value (0 when no KEY RRs registered)
		UpstreamZone:     upstreamZone,
		RegisteredAt:     time.Now(),
	}
	m.leases[keyName] = record
	if m.persistenceHook != nil {
		_ = m.persistenceHook(ctx, "register", record)
	}
	return nil
}

// Lookup returns active lease or nil.
func (m *InMemoryManager) Lookup(keyName string) *Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Normalize key name for consistent lookup.
	keyName = strings.TrimSuffix(strings.ToLower(keyName), ".")

	record, exists := m.leases[keyName]
	if !exists || record.IsExpired() {
		return nil
	}
	return record
}

// Get returns lease regardless of expiry or nil.
func (m *InMemoryManager) Get(keyName string) *Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Normalize key name for consistent lookup.
	keyName = strings.TrimSuffix(strings.ToLower(keyName), ".")

	return m.leases[keyName]
}

// Delete removes a lease.
func (m *InMemoryManager) Delete(keyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Normalize key name for consistent deletion.
	keyName = strings.TrimSuffix(strings.ToLower(keyName), ".")

	delete(m.leases, keyName)
	return nil
}

// ListExpiring returns non-expired leases expiring within duration.
func (m *InMemoryManager) ListExpiring(within time.Duration) []*Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var expiring []*Record
	cutoff := time.Now().Add(within)
	for _, record := range m.leases {
		if !record.IsExpired() && record.ExpiresAt.Before(cutoff) {
			expiring = append(expiring, record)
		}
	}
	return expiring
}

// ListAll returns all leases regardless of expiry status.
func (m *InMemoryManager) ListAll() []*Record {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var all []*Record
	for _, record := range m.leases {
		all = append(all, record)
	}
	return all
}

// SetPersistenceHook sets callback for persistence operations.
func (m *InMemoryManager) SetPersistenceHook(hook func(ctx context.Context, op string, record *Record) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.persistenceHook = hook
}

func (m *InMemoryManager) cleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for keyName, record := range m.leases {
		if record.IsExpired() {
			delete(m.leases, keyName)
		}
	}
}

// Stop terminates cleanup goroutine.
func (m *InMemoryManager) Stop() {
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
		close(m.cleanupDone)
	}
}
