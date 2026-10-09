package handlers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
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
//   - "upstream": a static "host:port" for the authoritative server of upstream_zone and
//     every name below it (the zones of the requests it handles), in place of SOA
//     discovery; anything but a "host:port" string is a Setup error (see
//     buildCoordinatorFromConfig). Same option as SRPHandler.Setup's. [OPTIONAL]
//   - "bootstrap_resolvers": []string of resolver addresses (e.g. "8.8.8.8:53")
//     the upstream coordinator asks for SOA records when locating the
//     authoritative server for a zone [OPTIONAL]. cmd/sig0lease/main.go populates this
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
//   - "lease_policy": Bounds applied to granted LEASE/KEY-LEASE [OPTIONAL]
//   - "record_ttl_sec": TTL of every record this handler writes upstream, in place of the
//     requester's (see parseRecordTTL) [OPTIONAL, defaults to defaultRecordTTL]
//   - "prefer_4byte_variant": Enable 4-byte variant for backward compatibility [OPTIONAL, defaults to false]
//   - "allow_online_key_registration": Allow a signer resolved only via authoritative DNS
//     (not lease-managed, not present in the request) to register new KEY RRs [OPTIONAL, defaults to false]
func (h *UpdateHandler) Setup(cfg map[string]any) error {
	// Extract upstream zone. Surrounding whitespace is trimmed here, where the name comes from
	// configuration: dnsname.Normalize keeps it, since a DNS label may begin with a space.
	zone, _ := cfg["upstream_zone"].(string)
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return fmt.Errorf("upstream_zone is required in config")
	}
	h.upstreamZone = zone
	h.logger.Debugf("UpdateHandler upstream zone: %s", zone)

	// Keystore directory - required for loading keys
	keystoreDir, ok := cfg["keystore_dir"].(string)
	if !ok || keystoreDir == "" {
		return fmt.Errorf("keystore_dir is required in config handlers.update section")
	}
	h.keystoreDir = keystoreDir
	h.logger.Debugf("Using keystore directory: %s", keystoreDir)

	// Load proxy authorization key used for signing forwarded upstream UPDATEs.
	// The key can live at the configured zone or any parent zone.
	upstreamKey, matchedZone, err := updatecore.FindAuthorizedProxyKey(h.keystoreDir, h.upstreamZone, h.logger)
	if err != nil {
		return fmt.Errorf("failed to resolve upstream signing key for zone %s: %w", h.upstreamZone, err)
	}
	h.upstreamKeyRecord = upstreamKey
	h.logger.Debugf("Loaded upstream key for configured zone %s from key zone %s: %s", h.upstreamZone, matchedZone, upstreamKey)

	// Optional: exactly one of "lease_manager" (Go-embedding only) or "storage"
	// (config-file-selectable); neither keeps the in-memory, no-persistence default.
	leaseManager, err := LeaseStoreFromConfig(cfg, h.logger, false)
	if err != nil {
		return fmt.Errorf("update handler config: %w", err)
	}
	h.leaseManager = leaseManager

	// Optional: Persistence hook for leases (Go-embedding only, see Setup doc comment).
	if hook, ok := cfg["persistence_hook"].(func(context.Context, string, *LeaseRecord) error); ok {
		h.leaseManager.SetPersistenceHook(hook)
		h.logger.Debugf("Persistence hook configured for leases")
	}

	// Optional: Lease policy
	if raw, ok := cfg["lease_policy"]; ok {
		policy, err := parseLeasePolicy(raw)
		if err != nil {
			return err
		}
		h.LeasePolicy = policy
		h.logger.Debugf("Lease policy configured: key[min=%d,max=%d] rr[min=%d,max=%d]",
			h.LeasePolicy.MinKeyLease, h.LeasePolicy.MaxKeyLease, h.LeasePolicy.MinRRLease, h.LeasePolicy.MaxRRLease)
	}

	recordTTL, err := parseRecordTTL(cfg)
	if err != nil {
		return err
	}
	h.recordTTL = recordTTL

	coordinator, err := buildCoordinatorFromConfig(cfg, h.upstreamZone, h.logger)
	if err != nil {
		return fmt.Errorf("update handler config: %w", err)
	}
	h.upstreamCoordinator = coordinator

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
