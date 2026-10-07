package handlers

import (
	"fmt"
	"math"
)

// defaultRecordTTL is the TTL both handlers give the records they write upstream when their
// config has no "record_ttl_sec".
const defaultRecordTTL = 300

// parseRecordTTL reads a handler's "record_ttl_sec": the TTL the handler gives every record it
// writes upstream, in place of the TTL the requester sent. RFC 9665 S4 makes a requester's
// TTL advisory and lets the registrar override it; S5.1 keeps the lease and the TTL apart.
// A requester may send its lease as the TTL (OpenThread's client does by default), which
// would leave stale data in resolver caches for as long as the lease -- days, for a KEY.
// Each handler cuts this TTL to the granted lease where S4 asks for it (a TTL SHOULD NOT be
// longer than the lease). Absent, it is defaultRecordTTL; present, it must be a TTL in
// 1..2^31-1 (RFC 2181 S8), or Setup fails.
func parseRecordTTL(cfg map[string]any) (uint32, error) {
	raw, ok := cfg["record_ttl_sec"]
	if !ok {
		return defaultRecordTTL, nil
	}
	ttl, ok := toUint32(raw)
	if !ok || ttl == 0 || ttl > math.MaxInt32 {
		return 0, fmt.Errorf("record_ttl_sec must be an integer between 1 and %d, got %v", math.MaxInt32, raw)
	}
	return ttl, nil
}
