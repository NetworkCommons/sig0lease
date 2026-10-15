package handlers

import (
	"strings"

	"codeberg.org/miekg/dns"
)

// Setup initializes the handler configuration: the options both UPDATE handlers read
// (upstream_zone, keystore_dir, upstream, bootstrap_resolvers, lease_policy, record_ttl_sec,
// lease_manager or storage; see leaseHandler.setup), and these of its own:
//   - "prefer_4byte_variant": Enable 4-byte variant for backward compatibility [OPTIONAL, defaults to false]
//   - "allow_online_key_registration": Allow a signer resolved only via authoritative DNS
//     (not lease-managed, not present in the request) to register new KEY RRs [OPTIONAL, defaults to false]
//   - "blacklisted_types": RR type names this handler refuses to register [OPTIONAL]
func (h *UpdateHandler) Setup(cfg map[string]any) error {
	var err error
	// Whether to use the 4-byte variant for backward compatibility.
	// Default: false (always use 8-byte variant for all lease requests).
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

	return h.setup(cfg)
}
