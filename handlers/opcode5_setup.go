package handlers

import (
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
)

// Setup initializes the handler configuration: the options both UPDATE handlers read
// (upstream_zone, keystore_dir, upstream, bootstrap_resolvers, lease_policy, record_ttl_sec,
// lease_manager or storage; see leaseHandler.setup), and these of its own:
//   - "prefer_4byte_variant": Accept requests whose Update Lease is the 4-byte variant, one
//     lease for every record, as older requesters such as macOS's mDNSResponder send; they are
//     REFUSED otherwise [OPTIONAL, defaults to false]
//   - "allow_online_key_registration": Allow a signer resolved only via authoritative DNS
//     (not lease-managed, not present in the request) to register new KEY RRs [OPTIONAL, defaults to false]
//   - "blacklisted_types": RR type names this handler refuses to register [OPTIONAL]
func (h *UpdateHandler) Setup(cfg map[string]any) error {
	var err error
	// Whether requests may use the 4-byte Update Lease variant. Default: false (8-byte only).
	if h.prefer4ByteVariant, err = boolOption(cfg, "prefer_4byte_variant", false); err != nil {
		return err
	}

	// Whether a signer resolved only via authoritative DNS may register new KEY RRs.
	// Default: false (fail closed).
	if h.AllowOnlineKeyRegistration, err = boolOption(cfg, "allow_online_key_registration", false); err != nil {
		return err
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

	if err := h.setup(cfg); err != nil {
		return err
	}
	// A 4-byte request gets one lease for its KEYs and its other records (RFC 9664 S4), at
	// most max_rr_lease_sec: refuse a policy whose KEYs may not have that short a lease.
	if p := h.LeasePolicy; h.prefer4ByteVariant && p.MaxRRLease != 0 && p.MinKeyLease > p.MaxRRLease {
		return fmt.Errorf("prefer_4byte_variant: a 4-byte Update Lease grants KEY and non-KEY records one lease, but lease_policy min_key_lease_sec (%d) is above max_rr_lease_sec (%d)", p.MinKeyLease, p.MaxRRLease)
	}
	return nil
}
