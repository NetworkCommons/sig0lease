package handlers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

func toUint32(v any) (uint32, bool) {
	switch n := v.(type) {
	case int:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	case int64:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	case float64:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	case uint32:
		return n, true
	case uint64:
		return uint32(n), true
	default:
		return 0, false
	}
}

// parseStringSlice accepts the two shapes a YAML/JSON list unmarshals into
// under map[string]any ([]string, or []interface{} of strings) and returns
// a clean []string, skipping blank/non-string entries. Returns nil for any
// other type (including a missing key, i.e. raw == nil).
func parseStringSlice(raw any) []string {
	switch v := raw.(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	default:
		return nil
	}
}

// Setup initializes the handler configuration.
//
// Configuration options:
//   - "upstream_zone": Authoritative zone (e.g., "dev.zenr.io.") [REQUIRED]
//   - "upstream_key": Path to upstream private key file [OPTIONAL, needed for upstream UPDATE signing]
//   - "upstream_coordinator": Custom UpstreamCoordinator implementation [OPTIONAL]
//   - "bootstrap_resolvers": []string of resolver addresses (e.g. "8.8.8.8:53")
//     used by the default upstream coordinator to look up SOA/NS records when
//     locating the authoritative server for a zone [OPTIONAL, ignored when
//     "upstream_coordinator" is set]. cmd/sig0lease/main.go populates this
//     from the top-level "upstreams" config when not set explicitly here, so
//     zone-authority resolution uses the same operator-configured resolvers
//     as generic forwarding. Falls back to a small built-in default if unset.
//   - "lease_manager": Custom LeaseManager implementation [OPTIONAL, defaults to InMemoryLeaseManager].
//     Go-embedding only: a LeaseManager value, not expressible in YAML, so
//     this can only be set by code constructing the cfg map directly, never
//     via config.yaml. A present-but-wrong-type value is a Setup error, not
//     a silently-ignored one. Mutually exclusive with "storage" below.
//   - "storage": Selects the lease storage backend [OPTIONAL, config-file-settable,
//     defaults to an in-memory store with no persistence]. Mutually exclusive
//     with "lease_manager". Shape: {"type": "memory"|"file", "path": "...",
//     "save_interval": "30s"}. "type" defaults to "memory" if omitted --
//     identical to today's default behavior, leases are lost on restart.
//     "file" additionally requires "path" and persists a human-readable JSON
//     snapshot there: loaded once on Setup (a corrupt existing file is a hard
//     Setup error), saved periodically on "save_interval" (default 30s), and
//     flushed once more on Shutdown(). Any unrecognized "type", or "file"
//     missing "path", is a Setup error.
//   - "persistence_hook": Persistence function for leases [OPTIONAL]. Same
//     Go-embedding-only caveat as lease_manager: a func value, not settable
//     from config.yaml.
//   - "lease_policy": Bounds applied to local lease durations and forwarded RR TTLs [OPTIONAL]
//   - "prefer_4byte_variant": Enable 4-byte variant for backward compatibility [OPTIONAL, defaults to false]
//   - "allow_online_key_registration": Allow a signer resolved only via authoritative DNS
//     (not lease-managed, not present in the request) to register new KEY RRs [OPTIONAL, defaults to false]
func (h *UpdateHandler) Setup(cfg map[string]any) error {
	// Extract upstream zone
	if zone, ok := cfg["upstream_zone"].(string); ok && zone != "" {
		h.upstreamZone = zone
		h.logger.Debugf("UpdateHandler upstream zone: %s", zone)
	} else {
		return fmt.Errorf("upstream_zone is required in config")
	}

	// Keystore directory - required for loading keys
	keystoreDir, ok := cfg["keystore_dir"].(string)
	if !ok || keystoreDir == "" {
		return fmt.Errorf("keystore_dir is required in config handlers.update section")
	}
	h.keystoreDir = keystoreDir
	h.logger.Debugf("Using keystore directory: %s", keystoreDir)

	// Load proxy authorization key used for signing forwarded upstream UPDATEs.
	// The key can live at the configured zone or any parent zone.
	upstreamKey, matchedZone, err := h.findAuthorizedProxyKeyForZone(h.upstreamZone)
	if err != nil {
		return fmt.Errorf("failed to resolve upstream signing key for zone %s: %w", h.upstreamZone, err)
	}
	h.upstreamKeyRecord = upstreamKey
	h.logger.Debugf("Loaded upstream key for configured zone %s from key zone %s: %s", h.upstreamZone, matchedZone, upstreamKey)

	// Optional: exactly one of "lease_manager" (Go-embedding only) or
	// "storage" (config-file-selectable) may be given. Both present at once
	// is ambiguous. Neither present keeps the default in-memory,
	// no-persistence store NewUpdateHandler() already set.
	rawLeaseManager, lmPresent := cfg["lease_manager"]
	lmPresent = lmPresent && rawLeaseManager != nil
	rawStorage, storagePresent := cfg["storage"]
	storagePresent = storagePresent && rawStorage != nil

	switch {
	case lmPresent && storagePresent:
		return fmt.Errorf(`update handler config: "lease_manager" and "storage" are mutually exclusive, got both`)

	case lmPresent:
		lm, ok := rawLeaseManager.(LeaseManager)
		if !ok || lm == nil {
			return fmt.Errorf("update handler config: \"lease_manager\" must implement lease.LeaseStorage, got %T", rawLeaseManager)
		}
		h.leaseManager = lm
		h.logger.Debugf("Custom lease manager configured")

	case storagePresent:
		storageCfg, ok := rawStorage.(map[string]any)
		if !ok {
			return fmt.Errorf("update handler config: \"storage\" must be a map, got %T", rawStorage)
		}
		lm, err := h.buildLeaseManagerFromConfig(storageCfg)
		if err != nil {
			return fmt.Errorf("update handler config: storage: %w", err)
		}
		h.leaseManager = lm
		h.logger.Debugf("Storage backend configured from config: %+v", storageCfg)
	}

	// Optional: Persistence hook for leases (Go-embedding only, see Setup doc comment).
	if hook, ok := cfg["persistence_hook"].(func(context.Context, string, *LeaseRecord) error); ok {
		h.leaseManager.SetPersistenceHook(hook)
		h.logger.Debugf("Persistence hook configured for leases")
	}

	// Optional: Lease/TTL policy hook
	if raw, ok := cfg["lease_policy"]; ok {
		policy, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("lease_policy must be a map")
		}
		if v, ok := toUint32(policy["min_key_lease_sec"]); ok {
			h.LeasePolicy.MinKeyLease = v
		}
		if v, ok := toUint32(policy["max_key_lease_sec"]); ok {
			h.LeasePolicy.MaxKeyLease = v
		}
		if v, ok := toUint32(policy["min_rr_lease_sec"]); ok {
			h.LeasePolicy.MinRRLease = v
		}
		if v, ok := toUint32(policy["max_rr_lease_sec"]); ok {
			h.LeasePolicy.MaxRRLease = v
		}

		if h.LeasePolicy.MaxKeyLease > 0 && h.LeasePolicy.MinKeyLease > 0 && h.LeasePolicy.MinKeyLease > h.LeasePolicy.MaxKeyLease {
			return fmt.Errorf("lease_policy min_key_lease_sec cannot be greater than max_key_lease_sec")
		}
		if h.LeasePolicy.MaxRRLease > 0 && h.LeasePolicy.MinRRLease > 0 && h.LeasePolicy.MinRRLease > h.LeasePolicy.MaxRRLease {
			return fmt.Errorf("lease_policy min_rr_lease_sec cannot be greater than max_rr_lease_sec")
		}

		h.logger.Debugf("Lease policy configured: key[min=%d,max=%d] rr[min=%d,max=%d]",
			h.LeasePolicy.MinKeyLease, h.LeasePolicy.MaxKeyLease, h.LeasePolicy.MinRRLease, h.LeasePolicy.MaxRRLease)
	}

	// Optional: Custom upstream coordinator
	if coordinator, ok := cfg["upstream_coordinator"].(UpstreamCoordinator); ok && coordinator != nil {
		h.upstreamCoordinator = coordinator
		h.logger.Debugf("Custom upstream coordinator configured")
	} else {
		bootstrapResolvers := parseStringSlice(cfg["bootstrap_resolvers"])
		h.upstreamCoordinator = NewDefaultUpstreamCoordinator(h.logger, bootstrapResolvers)
		if len(bootstrapResolvers) > 0 {
			h.logger.Debugf("Default upstream coordinator configured with bootstrap resolvers: %v", bootstrapResolvers)
		} else {
			h.logger.Debugf("Default upstream coordinator configured with built-in default bootstrap resolvers")
		}
	}

	// Check if 4-byte variant is explicitly enabled via config for backward compatibility.
	// Default: false (always use 8-byte variant for all lease requests).
	if prefer, ok := cfg["prefer_4byte_variant"].(bool); ok {
		h.prefer4ByteVariant = prefer
	}

	// Whether a signer resolved only via authoritative DNS may register new KEY RRs.
	// Default: false (fail closed).
	if allow, ok := cfg["allow_online_key_registration"].(bool); ok {
		h.AllowOnlineKeyRegistration = allow
	}

	// Parse blacklisted RR types from config.
	if raw, ok := cfg["blacklisted_types"]; ok {
		h.blacklistedTypes = make(map[uint16]struct{})
		switch v := raw.(type) {
		case []string:
			for _, typeName := range v {
				typeName = strings.TrimSpace(strings.ToUpper(typeName))
				if typeCode, ok := dns.StringToType[typeName]; ok {
					h.blacklistedTypes[typeCode] = struct{}{}
					h.logger.Debugf("Blacklisted RR type: %s (code %d)", typeName, typeCode)
				} else {
					h.logger.Warnf("Unknown RR type name %q in blacklisted_types, skipping", typeName)
				}
			}
		case []interface{}:
			for _, item := range v {
				if typeName, ok := item.(string); ok {
					typeName = strings.TrimSpace(strings.ToUpper(typeName))
					if typeCode, ok := dns.StringToType[typeName]; ok {
						h.blacklistedTypes[typeCode] = struct{}{}
						h.logger.Debugf("Blacklisted RR type: %s (code %d)", typeName, typeCode)
					} else {
						h.logger.Warnf("Unknown RR type name %q in blacklisted_types, skipping", typeName)
					}
				}
			}
		default:
			h.logger.Warnf("blacklisted_types has unexpected type %T, expected []string", raw)
		}
		if len(h.blacklistedTypes) > 0 {
			h.logger.Debugf("Blacklisted RR types: %d entries", len(h.blacklistedTypes))
		}
	}

	// Backup expiry-timer reconciliation: catches any lease-store node that
	// lacks a live expiry timer (e.g. after a future snapshot restore) and
	// schedules one, routing it through the same upstream-aware expiry path
	// as every other lease instead of leaving it unmanaged.
	h.startLeaseReconciliation(30 * time.Second)

	return nil
}

// buildLeaseManagerFromConfig builds a LeaseStorage backend from the
// handlers.update.storage config block. "memory" (or an omitted "type") is
// the same zero-persistence in-memory store NewUpdateHandler() already
// defaults to; "file" additionally loads/saves a human-readable JSON
// snapshot at "path". Any unrecognized "type", or a "file" type missing
// "path", is a hard error -- never a silent fallback to the default.
func (h *UpdateHandler) buildLeaseManagerFromConfig(storageCfg map[string]any) (leasepkg.LeaseStorage, error) {
	storageType := "memory"
	if raw, ok := storageCfg["type"]; ok {
		s, ok := raw.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("\"type\" must be a non-empty string, got %T", raw)
		}
		storageType = strings.ToLower(strings.TrimSpace(s))
	}

	switch storageType {
	case "memory":
		return leasepkg.NewInMemoryManager(), nil

	case "file":
		path, ok := storageCfg["path"].(string)
		if !ok || strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("\"path\" is required when \"type\" is \"file\"")
		}

		interval := 30 * time.Second
		if raw, ok := storageCfg["save_interval"]; ok {
			s, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("\"save_interval\" must be a duration string (e.g. \"30s\"), got %T", raw)
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return nil, fmt.Errorf("\"save_interval\" %q is not a valid duration: %w", s, err)
			}
			interval = d
		}

		return leasepkg.NewFileLeaseStore(path, interval, func(err error) {
			h.logger.Errorf("%v", err)
		})

	default:
		return nil, fmt.Errorf("unrecognized \"type\" %q (expected \"memory\" or \"file\")", storageType)
	}
}
