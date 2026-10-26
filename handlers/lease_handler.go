package handlers

import (
	"context"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
)

// leaseHandler is what the two UPDATE handlers, UpdateHandler (RFC 9664) and SRPHandler
// (RFC 9665), are made of alike: the handler basics, the lease runtime, the configuration
// both read the same way (setup), and upstream, where both send their UPDATEs. Each handler
// embeds one, built by newLeaseHandler. C is the handler's own coordinator interface
// (UpstreamCoordinator, srpCoordinator): the part of *updatecore.Coordinator that handler
// uses, so that a test stub implements only that part.
type leaseHandler[C upstreamClient] struct {
	BaseHandler
	*leaseRuntime

	upstreamZone string // the one zone this handler serves (e.g. "dev.zenr.io.")
	// deeperZones are the zones other handlers of this proxy serve below upstreamZone, whose
	// names are theirs, not this handler's (SeparateZones, refuseNamesNotServed).
	deeperZones []servedZone
	keystoreDir string
	// upstreamKeyRecord is the proxy's own SIG(0) key for upstreamZone, which signs every
	// UPDATE the handler sends (upstreamTarget.send). setup loads it once: a rotated key on
	// disk needs a restart.
	upstreamKeyRecord   *keyrec.LoadedKey
	upstreamCoordinator C
	LeasePolicy         LeasePolicy
	recordTTL           uint32 // TTL of every record this handler writes upstream (parseRecordTTL)
}

// The coordinator setup builds is the one both handlers use, so it must implement both
// handlers' coordinator interfaces; setup's assertion to C relies on these.
var (
	_ UpstreamCoordinator = (*updatecore.Coordinator)(nil)
	_ srpCoordinator      = (*updatecore.Coordinator)(nil)
)

// newLeaseHandler returns the shared part of the UPDATE handler named name, whose node lock ids
// are lockIDs, whose lease events run leaseEvent and whose reconciliation pass ends with
// passExtra, if not nil (newLeaseRuntime).
func newLeaseHandler[C upstreamClient](name string, lockIDs func(nodeKey string) []string, leaseEvent func(ctx context.Context, nodeKey string), passExtra func(ctx context.Context)) leaseHandler[C] {
	return leaseHandler[C]{
		BaseHandler:  BaseHandler{name: name, opcodes: []uint8{dns.OpcodeUpdate}},
		leaseRuntime: newLeaseRuntime(lockIDs, leaseEvent, passExtra),
		recordTTL:    defaultRecordTTL,
	}
}

// servedZone is a zone and the name of the handler serving it.
type servedZone struct {
	zone, handler string
}

// ZoneHandler is an UPDATE handler serving one zone: UpdateHandler and SRPHandler.
type ZoneHandler interface {
	Handler
	// UpstreamZone is the zone the handler serves (upstream_zone), once Setup has read it.
	UpstreamZone() string
	setDeeperZones(zones []servedZone)
}

// UpstreamZone is the zone this handler serves.
func (b *leaseHandler[C]) UpstreamZone() string { return b.upstreamZone }

func (b *leaseHandler[C]) setDeeperZones(zones []servedZone) { b.deeperZones = zones }

// SeparateZones gives every name at most one of hs: the handler whose zone is the closest one
// above it, as a zone cut does in DNS. Each handler learns the zones the others serve below its
// own, and refuses their names (refuseNamesNotServed); with srp.dev.zenr.io. for srp_handler and
// dev.zenr.io. for update_handler, update_handler refuses every name at or below
// srp.dev.zenr.io. Two handlers serving one zone leave no closest one, and are an error. The
// proxy calls it once, after every handler's Setup and before serving.
func SeparateZones(hs []ZoneHandler) error {
	for _, h := range hs {
		var deeper []servedZone
		for _, other := range hs {
			if other == h {
				continue
			}
			if dnsname.Normalize(other.UpstreamZone()) == dnsname.Normalize(h.UpstreamZone()) {
				return fmt.Errorf("%s and %s both serve zone %s: a zone must have one handler", h.Name(), other.Name(), h.UpstreamZone())
			}
			if dnsname.IsAtOrBelow(other.UpstreamZone(), h.UpstreamZone()) {
				deeper = append(deeper, servedZone{zone: other.UpstreamZone(), handler: other.Name()})
			}
		}
		h.setDeeperZones(deeper)
	}
	return nil
}

// refuseNamesNotServed refuses r when its Update section names a record this handler does not
// serve: one outside upstreamZone, or one in a zone another handler serves below it
// (SeparateZones). Every owner name the requester sent counts, deletes included. Each handler
// calls it once the names are final, before anything is looked up or locked.
func (b *leaseHandler[C]) refuseNamesNotServed(r *dns.Msg) *HandlerResult {
	for _, rr := range r.Ns {
		name := rr.Header().Name
		var err error
		if !dnsname.IsAtOrBelow(name, b.upstreamZone) {
			err = fmt.Errorf("%s is outside zone %s, which %s serves", name, b.upstreamZone, b.Name())
		}
		for _, z := range b.deeperZones {
			if err == nil && dnsname.IsAtOrBelow(name, z.zone) {
				err = fmt.Errorf("%s is in zone %s, which %s serves", name, z.zone, z.handler)
			}
		}
		if err != nil {
			msg := makeErrorResponse(r, dns.RcodeRefused, dns.ExtendedErrorProhibited, err.Error())
			return NewErrorResult(msg, "name not served by this handler", err)
		}
	}
	return nil
}

// upstream is where this handler's UPDATEs go and what signs them.
func (b *leaseHandler[C]) upstream() upstreamTarget {
	return upstreamTarget{handler: b.Name(), coordinator: b.upstreamCoordinator, signingKey: b.upstreamKeyRecord, zone: b.upstreamZone, logger: b.logger}
}

// setup reads the configuration both UPDATE handlers take the same way. Each handler's Setup
// reads its own options first and ends with it. The lease store is built last, once nothing
// else can fail, because a file store starts saving as soon as it is built. Nothing expires
// until Start.
//
// Configuration options:
//   - "upstream_zone": the one zone this handler serves (e.g. "dev.zenr.io.") [REQUIRED]
//   - "keystore_dir": directory holding this proxy's own SIG(0) signing keys. The key for
//     upstream_zone, or for a zone above it, is loaded here
//     (updatecore.FindAuthorizedProxyKey), so a missing key fails Setup instead of the
//     first request. [REQUIRED]
//   - "upstream": a static "host:port" for the authoritative server of upstream_zone and
//     every name below it, in place of SOA discovery; anything but a "host:port" string is
//     a Setup error (see buildCoordinatorFromConfig). [OPTIONAL]
//   - "bootstrap_resolvers": []string of resolver addresses (e.g. "8.8.8.8:53") the
//     coordinator asks for SOA records when locating the authoritative server for a zone.
//     cmd/sig0lease/main.go fills it in from the top-level "upstreams" config when not set
//     here, so zone-authority resolution uses the same operator-configured resolvers as
//     generic forwarding. Falls back to a small built-in default if unset. [OPTIONAL]
//   - "lease_policy": bounds applied to granted LEASE/KEY-LEASE (parseLeasePolicy).
//     [OPTIONAL]
//   - "record_ttl_sec": TTL of every record this handler writes upstream, in place of the
//     requester's (parseRecordTTL). [OPTIONAL, defaults to defaultRecordTTL]
//   - "lease_manager": a LeaseManager to use as the lease store. Go-embedding only: a
//     LeaseManager value is not expressible in YAML, so only code building the cfg map
//     directly can set it. A value of the wrong type is a Setup error. Mutually exclusive
//     with "storage". [OPTIONAL]
//   - "storage": selects the lease store [OPTIONAL, defaults to an in-memory store with no
//     persistence]. Mutually exclusive with "lease_manager". Shape: {"type":
//     "memory"|"file", "path": "...", "save_interval": "30s"}. "type" defaults to "memory",
//     whose leases are lost on restart. "file" also requires "path" and persists a
//     human-readable JSON snapshot there: loaded once here (a corrupt existing file is a
//     Setup error), saved every "save_interval" (default 30s), and saved once more on
//     Shutdown. An unrecognized "type", or "file" without "path", is a Setup error.
func (b *leaseHandler[C]) setup(cfg map[string]any) error {
	// Surrounding whitespace is trimmed here, where the name comes from configuration:
	// dnsname.Normalize keeps it, since a DNS label may begin with a space.
	zone, _ := cfg["upstream_zone"].(string)
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return fmt.Errorf("upstream_zone is required in config")
	}
	b.upstreamZone = zone
	b.logger.Debugf("%s upstream zone: %s", b.Name(), zone)

	keystoreDir, ok := cfg["keystore_dir"].(string)
	if !ok || keystoreDir == "" {
		return fmt.Errorf("keystore_dir is required in config")
	}
	b.keystoreDir = keystoreDir
	b.logger.Debugf("Using keystore directory: %s", keystoreDir)

	upstreamKey, matchedZone, err := updatecore.FindAuthorizedProxyKey(b.keystoreDir, b.upstreamZone, b.logger)
	if err != nil {
		return fmt.Errorf("failed to resolve upstream signing key for zone %s: %w", b.upstreamZone, err)
	}
	b.upstreamKeyRecord = upstreamKey
	b.logger.Debugf("Loaded upstream key for configured zone %s from key zone %s: %s", b.upstreamZone, matchedZone, upstreamKey)

	coordinator, err := buildCoordinatorFromConfig(cfg, b.upstreamZone, b.logger)
	if err != nil {
		return err
	}
	b.upstreamCoordinator = any(coordinator).(C)

	if raw, ok := cfg["lease_policy"]; ok {
		policy, err := parseLeasePolicy(raw)
		if err != nil {
			return err
		}
		b.LeasePolicy = policy
		b.logger.Debugf("Lease policy configured: key[min=%d,max=%d] rr[min=%d,max=%d]",
			policy.MinKeyLease, policy.MaxKeyLease, policy.MinRRLease, policy.MaxRRLease)
	}

	recordTTL, err := parseRecordTTL(cfg)
	if err != nil {
		return err
	}
	b.recordTTL = recordTTL

	leaseManager, err := LeaseStoreFromConfig(cfg, b.logger, false)
	if err != nil {
		return err
	}
	b.leaseManager = leaseManager
	return nil
}

// Start begins the handler's lease expiry: it arms an expiry timer for every lease owner in
// the store -- the leases Setup loaded from a snapshot -- and starts the reconciliation pass.
// The server calls it once, before it serves. A dump runs Setup alone, so nothing in its store
// expires and nothing is written upstream.
func (b *leaseHandler[C]) Start() {
	owners := b.leaseManager.ListOwners()
	for _, nodeKey := range owners {
		b.scheduleLeaseExpiry(nodeKey)
	}
	b.logger.Infof("%s: expiry timers armed for the %d lease owner(s) in the store", b.Name(), len(owners))
	b.startLeaseReconciliation(leaseReconcileInterval, b.logger)
}

// leaseStoreView adapts LeaseManager to srp.StoreView, the narrow read-only interface
// srp.Evaluate needs: SRP's FCFS check (SRPHandler.Handle) and the RFC 9664 handler's
// fcfs_naming (UpdateHandler.fcfsNewKey) alike.
type leaseStoreView struct{ store LeaseManager }

func (v leaseStoreView) KeysAtName(name string) []*dns.KEY {
	records := v.store.FindByName(name)
	keys := make([]*dns.KEY, 0, len(records))
	for _, rec := range records {
		if rec.KeyRR == nil {
			panic(fmt.Sprintf("lease store: KEY node %s at %s has no KEY RR", rec.KeyName, name))
		}
		keys = append(keys, rec.KeyRR)
	}
	return keys
}

// fcfsConflictResult is either handler's answer to an update a different key's name stops
// (srp.FCFSConflict), found by its own check or by the authoritative server's prerequisite
// (prerequisiteFailed): YXDOMAIN, which RFC 9665 S3.3.3 has the SRP registrar answer.
func fcfsConflictResult(r *dns.Msg, reason string) *HandlerResult {
	msg := makeErrorResponse(r, dns.RcodeYXDomain, dns.ExtendedErrorProhibited, "name held by a different key")
	return NewErrorResult(msg, reason, fmt.Errorf("YXDOMAIN"))
}

// prerequisiteFailed reports whether rcode is the authoritative server's answer to one of
// prereqs no longer holding (RFC 2136 S3.2.2): YXDOMAIN to "Name is not in use" (TYPE ANY),
// YXRRSET to "KEY RRset does not exist" (TYPE KEY). Only prerequisites produce these, so
// either one without its prerequisite in prereqs is an impossible answer, not an FCFS
// conflict.
func prerequisiteFailed(rcode uint16, prereqs []dns.RR) bool {
	var prereqType uint16
	switch rcode {
	case dns.RcodeYXDomain:
		prereqType = dns.TypeANY
	case dns.RcodeYXRrset:
		prereqType = dns.TypeKEY
	default:
		return false
	}
	for _, rr := range prereqs {
		if dns.RRToType(rr) == prereqType {
			return true
		}
	}
	return false
}

// boolOption reads the optional boolean option key from a handler's config: def when absent,
// and a Setup error when present but not a boolean, rather than def.
func boolOption(cfg map[string]any, key string, def bool) (bool, error) {
	raw, ok := cfg[key]
	if !ok {
		return def, nil
	}
	v, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be true or false, got %T", key, raw)
	}
	return v, nil
}

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
