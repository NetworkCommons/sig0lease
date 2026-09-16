package handlers

import (
	"fmt"
	"time"

	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
)

// Setup initializes the SRP handler configuration.
//
// Configuration options:
//   - "upstream_zone": the one zone this handler instance serves (D10: one zone, one
//     protocol) [REQUIRED]
//   - "keystore_dir": directory holding this proxy's own SIG(0) signing keys [REQUIRED]
//   - "upstream": a static "host:port" override for upstream_zone (D4) -- when set,
//     skips SOA/NS discovery entirely for this zone. [OPTIONAL]
//   - "bootstrap_resolvers": []string of resolver addresses used to resolve SOA/NS
//     records when "upstream" is not set. [OPTIONAL]
//   - "allow_udp": permit UDP for this zone (plan S7/D6 -- TCP is required by default,
//     for non-CNN zones this proxy targets). [OPTIONAL, defaults to false]
//   - "rewrite_default_service_arpa": accept requests whose Zone Section is literally
//     "default.service.arpa." (real SRP clients hardcode this name -- they have no way to
//     discover any other zone, D5) *in addition to* upstream_zone, rewriting every name in
//     the update to upstream_zone before FCFS/forwarding so the rest of the pipeline (and
//     the authoritative server) never sees default.service.arpa. at all. The response still
//     echoes back default.service.arpa., matching what the client itself sent. [OPTIONAL,
//     defaults to false]
//   - "refuse_on_foreign_data": RFC 9665 S3.3.3's NOERROR-no-KEY case -- true refuses the
//     update (REFUSED) when a name exists at the authoritative server with data but no
//     KEY; false lets the delete-all-then-add clobber it. [OPTIONAL, defaults to true]
//   - "advertise_registration_domain": also publish the RFC 6763 S11 "r"/"dr" registration-
//     domain records (self-pointing at upstream_zone) alongside the always-on "b"/"db"/"lb"
//     browsing-domain records once at least one service type is live. Unlike browsing,
//     advertising this zone as an open target for direct RFC 2136 Dynamic Update
//     registration (not just SRP) is a deployment policy choice -- SIG(0)/FCFS still gate who
//     can actually write, but this controls whether domain-enumeration tools are told to try.
//     [OPTIONAL, defaults to false]
//   - "lease_policy": bounds applied to granted LEASE/KEY-LEASE, same shape as the base
//     handler's. [OPTIONAL]
//   - "lease_manager" / "storage": same mutually-exclusive lease-store backend selection
//     as UpdateHandler.Setup -- see that method's doc comment for the full shape.
//     [OPTIONAL, defaults to an in-memory store with no persistence]
func (h *SRPHandler) Setup(cfg map[string]any) error {
	zone, ok := cfg["upstream_zone"].(string)
	if !ok || zone == "" {
		return fmt.Errorf("upstream_zone is required in config")
	}
	h.upstreamZone = zone
	h.logger.Debugf("SRPHandler upstream zone: %s", zone)

	keystoreDir, ok := cfg["keystore_dir"].(string)
	if !ok || keystoreDir == "" {
		return fmt.Errorf("keystore_dir is required in config handlers.srp_handler section")
	}
	h.keystoreDir = keystoreDir

	// Fail fast (matching UpdateHandler.Setup) rather than discovering a missing
	// signing key on the first real request, and cache the result for the life of the
	// handler instead of re-reading it from the keystore directory on every request and
	// every lease-expiry tick (see resolveUpstreamSigningContext).
	upstreamKey, matchedZone, err := updatecore.FindAuthorizedProxyKey(h.keystoreDir, h.upstreamZone, h.logger)
	if err != nil {
		return fmt.Errorf("failed to resolve upstream signing key for zone %s: %w", h.upstreamZone, err)
	}
	h.upstreamKeyRecord = upstreamKey
	h.upstreamKeyZone = matchedZone
	h.logger.Debugf("Loaded upstream key for configured zone %s from key zone %s", h.upstreamZone, matchedZone)

	staticUpstream := map[string]string{}
	if addr, ok := cfg["upstream"].(string); ok && addr != "" {
		staticUpstream[h.upstreamZone] = addr
		h.logger.Debugf("SRP zone %s configured with static upstream override: %s", h.upstreamZone, addr)
	}
	bootstrapResolvers := parseStringSlice(cfg["bootstrap_resolvers"])
	h.coordinator = updatecore.NewCoordinator(h.logger, bootstrapResolvers, staticUpstream)

	if allow, ok := cfg["allow_udp"].(bool); ok {
		h.allowUDP = allow
	}

	if rewrite, ok := cfg["rewrite_default_service_arpa"].(bool); ok {
		h.rewriteDefaultServiceARPA = rewrite
	}

	// Default true (fail closed against foreign/orphaned data) unless explicitly
	// disabled -- see pkg/srp.Evaluate's doc comment for what this actually gates.
	h.refuseOnForeignData = true
	if refuse, ok := cfg["refuse_on_foreign_data"].(bool); ok {
		h.refuseOnForeignData = refuse
	}

	if advertise, ok := cfg["advertise_registration_domain"].(bool); ok {
		h.advertiseRegistrationDomain = advertise
	}

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
	}

	rawLeaseManager, lmPresent := cfg["lease_manager"]
	lmPresent = lmPresent && rawLeaseManager != nil
	rawStorage, storagePresent := cfg["storage"]
	storagePresent = storagePresent && rawStorage != nil

	switch {
	case lmPresent && storagePresent:
		return fmt.Errorf(`srp handler config: "lease_manager" and "storage" are mutually exclusive, got both`)

	case lmPresent:
		lm, ok := rawLeaseManager.(LeaseManager)
		if !ok || lm == nil {
			return fmt.Errorf("srp handler config: \"lease_manager\" must implement lease.LeaseStorage, got %T", rawLeaseManager)
		}
		h.leaseManager = lm

	case storagePresent:
		storageCfg, ok := rawStorage.(map[string]any)
		if !ok {
			return fmt.Errorf("srp handler config: \"storage\" must be a map, got %T", rawStorage)
		}
		lm, err := buildLeaseManagerFromConfig(storageCfg, h.logger)
		if err != nil {
			return fmt.Errorf("srp handler config: storage: %w", err)
		}
		h.leaseManager = lm
	}

	h.startLeaseReconciliation(30 * time.Second)

	return nil
}
