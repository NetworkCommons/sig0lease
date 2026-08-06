package handlers

import (
	"context"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
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

// Setup initializes the handler configuration.
//
// Configuration options:
//   - "upstream_zone": Authoritative zone (e.g., "dev.zenr.io.") [REQUIRED]
//   - "upstream_key": Path to upstream private key file [OPTIONAL, needed for upstream UPDATE signing]
//   - "upstream_coordinator": Custom UpstreamCoordinator implementation [OPTIONAL]
//   - "lease_manager": Custom LeaseManager implementation [OPTIONAL, defaults to InMemoryLeaseManager]
//   - "persistence_hook": Persistence function for leases [OPTIONAL]
//   - "lease_policy": Bounds applied to local lease durations and forwarded RR TTLs [OPTIONAL]
//   - "prefer_4byte_variant": Enable 4-byte variant for backward compatibility [OPTIONAL, defaults to false]
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

	// Optional: Custom lease manager
	// FIXME option for lease_manager is not in config
	// and unclear how to define it
	if lm, ok := cfg["lease_manager"].(LeaseManager); ok && lm != nil {
		h.leaseManager = lm
		h.logger.Debugf("Custom lease manager configured")
	}

	// Optional: Persistence hook for leases
	// FIXME option for persistence_hook is not in config
	// and unclear how to define it
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
		h.upstreamCoordinator = NewDefaultUpstreamCoordinator(h.logger)
		h.logger.Debugf("Default upstream coordinator configured")
	}

	// Check if 4-byte variant is explicitly enabled via config for backward compatibility.
	// Default: false (always use 8-byte variant for all lease requests).
	if prefer, ok := cfg["prefer_4byte_variant"].(bool); ok {
		h.prefer4ByteVariant = prefer
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

	return nil
}
