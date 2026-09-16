package handlers

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnssd"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
	"github.com/NetworkCommons/sig0lease/pkg/srp"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
)

// serviceEnumerationTTL is the TTL used for the RFC 6763 S9 Service Type Enumeration PTR and
// S11 Browse Domain PTR records this handler maintains (reconcileServiceEnumeration). These
// are proxy-maintained infrastructure records with no single client lease to derive a TTL
// from, unlike every other record this handler writes, which take their TTL from a specific
// client's granted LEASE.
const serviceEnumerationTTL = 3600

// SRPHandler implements handlers.Handler for opcode 5 (UPDATE), the RFC 9665 SRP path --
// a sibling to UpdateHandler, never a branch inside it: SRP's message shape and
// authorization model (FCFS, delete-all-then-add, no per-record parent/key walk)
// contradict two of UpdateHandler's own checks (validateSignerHierarchyForUpdateRecords,
// filterDuplicateRegistrations), so it needs its own Handle() rather than a mode flag on
// the existing one. See docs/siglease_rfc9665.md for the design
// this implements; comments below cite RFC 9665 sections as "S<n>".
type SRPHandler struct {
	BaseHandler

	upstreamZone string // the one zone this handler instance serves (one zone, one protocol per handler instance)
	keystoreDir  string
	leaseManager LeaseManager
	coordinator  srpCoordinator

	// upstreamKeyRecord is the proxy's own SIG(0) signing key for upstreamZone, resolved
	// once by Setup and cached for the handler's lifetime (see resolveUpstreamSigningContext)
	// rather than re-read from keystoreDir on every request and every lease-expiry tick.
	// upstreamKeyZone is the zone it was actually found at (upstreamZone itself, or a
	// parent -- FindAuthorizedProxyKey walks up), cached alongside it purely for logging.
	upstreamKeyRecord *keyrec.LoadedKey
	upstreamKeyZone   string

	allowUDP                  bool // TCP required unless the zone is flagged allow_udp
	refuseOnForeignData       bool // RFC 9665 S3.3.3's NOERROR-no-KEY case. Default true.
	rewriteDefaultServiceARPA bool // accept default.service.arpa. as an alias for upstreamZone
	LeasePolicy               LeasePolicy

	// serviceTypesMu guards serviceTypes, this process's own tracked view of the RFC 6763
	// S9 enumeration record's contents -- see reconcileServiceEnumeration. Starts nil/empty
	// on every process start, deliberately: it is NOT reconstructed from a live upstream
	// read, so a freshly started (or restarted) process only ever ADDS types it newly
	// discovers in its own lease store on its own account -- it never blindly deletes a
	// type it simply hasn't relearned about. A type that drops out of this process's own
	// local knowledge is only actually removed from the upstream record after a live
	// QueryPTRExists confirms no other registrant (a different process, or an earlier run
	// of this same one) still provides it.
	serviceTypesMu sync.Mutex
	serviceTypes   map[string]bool

	// domainEnumPresent is this process's own last-confirmed-written presence state for each
	// RFC 6763 S11 domain-enumeration prefix (dnssd.BrowseDomainPrefix and friends) -- see
	// reconcileServiceEnumeration. Guarded by serviceTypesMu alongside serviceTypes since both
	// are only ever read/written together, inside the same reconcile pass. Starts nil (every
	// lookup then defaults to false) on every process start, for the same restart-safety
	// reason serviceTypes starts nil: a prefix is only removed once a live QueryPTRExists
	// confirms no service type remains anywhere in the zone, not just gone from this
	// process's own local view.
	domainEnumPresent map[string]bool

	// advertiseRegistrationDomain gates the "r"/"dr" prefixes (RFC 6763 S11's registration-
	// domain records) specifically -- unlike "b"/"db"/"lb" (always published once at least
	// one service type is live), advertising this zone as an open target for direct RFC 2136
	// Dynamic Update registration (not just SRP) is a deployment policy choice, not implied
	// by SRP working here. Default false (config: srp_handler.advertise_registration_domain).
	advertiseRegistrationDomain bool

	leaseTimersMu sync.Mutex
	leaseTimers   map[string]*time.Timer
}

// srpCoordinator is the subset of *updatecore.Coordinator's exported surface Handle and its
// helpers use. An interface, not the concrete type, purely so handler-level tests can
// exercise every upstream-facing branch -- FCFS's live query, a rejected/successful forward, expiry's
// upstream delete -- without a real network or DNS server. *updatecore.Coordinator satisfies
// this structurally; Setup assigns one directly, with no wrapper type in between.
type srpCoordinator interface {
	QueryKeyAtName(ctx context.Context, zoneHint, name string) (srp.AuthoritativeKeyState, []*dns.KEY, error)
	SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error)
	ResolveAuthoritativeZone(ctx context.Context, zone string) (string, error)
	// QueryPTRExists reports whether at least one PTR record currently exists live at
	// name -- used by reconcileServiceEnumeration (RFC 6763 S9) to confirm a type is truly
	// gone everywhere before removing it from the enumeration record, not just gone from
	// this process's own local lease-store view.
	QueryPTRExists(ctx context.Context, zoneHint, name string) (bool, error)
}

// NewSRPHandler creates a new handler for opcode 5 (UPDATE), RFC 9665 SRP path.
func NewSRPHandler() *SRPHandler {
	return &SRPHandler{
		BaseHandler: BaseHandler{
			name:    "srp_handler",
			opcodes: []uint8{dns.OpcodeUpdate},
		},
		leaseManager:        NewInMemoryLeaseManager(),
		refuseOnForeignData: true,
		leaseTimers:         make(map[string]*time.Timer),
	}
}

// leaseStoreView adapts LeaseManager to srp.StoreView -- the narrow read-only interface
// Evaluate (S3.3.3 FCFS) needs. Defined here, not in pkg/srp or pkg/updatecore: it's glue
// specific to how this handler's store is shaped, not shared plumbing.
type leaseStoreView struct{ store LeaseManager }

func (v leaseStoreView) KeyAtName(name string) (*dns.KEY, bool) {
	records := v.store.FindByName(name)
	if len(records) == 0 || records[0].KeyRR == nil {
		return nil, false
	}
	// Multiple distinct KEY nodes at one DNS name (different algorithm/keytag) is
	// possible in principle but not a shape SRP itself ever produces (S3.2.5.1: one key
	// governs the whole update) -- taking the first is a deliberate simplification, not
	// an attempt to disambiguate a case that shouldn't arise from SRP traffic itself.
	return records[0].KeyRR, true
}

// defaultServiceARPA is the zone name real SRP clients hardcode when they have no other
// way to discover their registration domain (RFC 9665 S3.3.1). Dot-terminated and
// lower-case -- every comparison/rewrite against it below matches on that same shape.
const defaultServiceARPA = "default.service.arpa."

// zoneEnabled reports whether zone (from the request's own Zone Section) is one this
// handler instance will accept: the one zone it's configured to serve (one zone, one
// protocol per handler instance -- enforced here, in each handler's own early checks,
// rather than by a central dispatcher), or -- when rewriteDefaultServiceARPA is
// on -- default.service.arpa. as well, an alias Handle rewrites away before anything else
// sees it. Compared canonically since the request's own casing/trailing dot can't be
// assumed to match the configured value.
func (h *SRPHandler) zoneEnabled(zone string) bool {
	z := canonicalName(zone) // handlers.canonicalName: lower-cased, trailing dot stripped
	if z == canonicalName(h.upstreamZone) {
		return true
	}
	return h.rewriteDefaultServiceARPA && z == canonicalName(defaultServiceARPA)
}

// rewriteDefaultServiceARPA rewrites every name msg.Ns's records carry that ends in
// default.service.arpa. (case-insensitively) to end in realZone instead, in place: every
// RR's own owner name (via its Header -- generic across every SRP RR type, so this needs
// no type switch for that part), plus SRV.Target and PTR.Ptr, the only two name-typed RDATA
// fields SRP itself ever produces. msg.Question is never touched by this function -- see
// Handle's step 5 comment for why.
func rewriteDefaultServiceARPA(msg *dns.Msg, realZone string) {
	for _, rr := range msg.Ns {
		hdr := rr.Header()
		hdr.Name = rewriteZoneSuffix(hdr.Name, realZone)
		switch v := rr.(type) {
		case *dns.SRV:
			v.SRV.Target = rewriteZoneSuffix(v.SRV.Target, realZone)
		case *dns.PTR:
			v.Ptr = rewriteZoneSuffix(v.Ptr, realZone)
		}
	}
}

// rewriteZoneSuffix replaces a trailing default.service.arpa. (case-insensitive) on name
// with realZone, leaving every label before it untouched; a name that doesn't carry that
// suffix -- or whose suffix match doesn't fall on a label boundary, e.g.
// "evildefault.service.arpa." (a plain byte-suffix match on the trailing bytes, but not
// actually a subdomain of default.service.arpa. -- its first label is "evildefault", not
// "default") -- passes through unchanged rather than being corrupted by concatenating
// realZone onto a leftover partial label with no separating dot. Defensive: every name
// reaching this function should already legitimately carry the suffix, since
// rewriteDefaultServiceARPA is only called once zoneEnabled has confirmed the request's own
// Zone Section is exactly default.service.arpa. -- but a record's owner/target name is
// client-controlled data, not re-derived from the (trusted) Zone Section, so it must be
// checked on its own rather than assumed safe by association.
func rewriteZoneSuffix(name, realZone string) string {
	if len(name) < len(defaultServiceARPA) {
		return name
	}
	cut := len(name) - len(defaultServiceARPA)
	tail := name[cut:]
	if !strings.EqualFold(tail, defaultServiceARPA) {
		return name
	}
	if cut > 0 && name[cut-1] != '.' {
		// The match doesn't start on a label boundary (no preceding dot, and this
		// isn't an exact match cut==0 either) -- e.g. "evildefault.service.arpa." only
		// matches "default.service.arpa." on its trailing bytes, not as a real
		// subdomain.
		return name
	}
	return name[:cut] + realZone
}

// Handle implements RFC 9665's ten-step happy path. Every early-return before step 7
// (forwarding) touches neither the lease store nor the network, so a rejected request
// leaves no trace to clean up.
func (h *SRPHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult {
	if r == nil {
		return NewErrorResult(nil, "nil message received", fmt.Errorf("nil message"))
	}

	// Step 1: classify. NotRelevant (not an error) if the message isn't SRP-shaped at
	// all -- the router falls through to the next handler in the ordered
	// list, or to plain forwarding.
	cu, err := srp.Classify(r)
	if err != nil {
		h.logger.Debugf("SRP handler: not SRP-shaped, declining: %v", err)
		return NewNotRelevantResult(fmt.Sprintf("not an SRP update: %v", err))
	}

	if len(r.Question) != 1 {
		return NewNotRelevantResult("not an SRP update: expected exactly one Zone Section entry")
	}
	zone := r.Question[0].Header().Name
	if !h.zoneEnabled(zone) {
		h.logger.Debugf("SRP handler: zone %s is not the configured zone %s, declining", zone, h.upstreamZone)
		return NewNotRelevantResult(fmt.Sprintf("zone %s not enabled for SRP on this handler", zone))
	}

	h.logger.Infof("SRP UPDATE for zone %s: host=%s instances=%d discovery=%d",
		zone, cu.Host.Name, len(cu.Instances), len(cu.Discovery))

	// Step 2: structural validation. ValidateClassified runs every check Validate does
	// beyond Classify itself, reusing step 1's own cu rather than re-classifying the
	// identical message a second time (a real, measurable cost per request -- Classify
	// walks the whole Update section, not a cheap length check).
	if err := srp.ValidateClassified(r, cu); err != nil {
		h.logger.Debugf("SRP handler: structural validation failed: %v", err)
		msg := makeErrorResponse(r, dns.RcodeRefused, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}

	// Step 3: transport check. Source-address allow-list is a stub: parse the config,
	// wire the call site, leave the list empty (= allow all) until real filtering is needed.
	if !h.allowUDP {
		if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
			h.logger.Debugf("SRP handler: rejecting UDP request for zone %s (allow_udp not set)", zone)
			msg := makeErrorResponse(r, dns.RcodeRefused, "TCP required for SRP on this zone")
			return NewErrorResult(msg, "TCP required, got UDP", fmt.Errorf("UDP rejected: allow_udp not set for zone %s", zone))
		}
	}
	// TODO(srp): srp.allowed_source_prefixes source-address allow-list (stub, not yet enforced).

	// Step 4: SIG(0) verify against the Host Description KEY (S3.3.3) -- always
	// present in a structurally-valid SRP update, so no three-stage signer resolution
	// (extractAndValidateSig0) is needed the way the base handler's is. Deliberately
	// ahead of FCFS (step 6, below) here -- moved up from an earlier draft that ran FCFS
	// first: the rewrite in step 5 mutates r.Ns in place, and that mutation must happen
	// only after the signature covering the *original* bytes has been checked, and only
	// before FCFS reads names that need to already be in their final (rewritten) form.
	sigRR, err := extractSig0(r)
	if err != nil {
		msg := makeErrorResponse(r, dns.RcodeRefused, "missing SIG(0)")
		return NewErrorResult(msg, err.Error(), err)
	}
	if canonicalName(sigRR.SignerName) != canonicalName(cu.Host.Name) {
		err := fmt.Errorf("SIG(0) signer %q does not match Host Description name %q", sigRR.SignerName, cu.Host.Name)
		msg := makeErrorResponse(r, dns.RcodeRefused, "signer does not match host")
		return NewErrorResult(msg, err.Error(), err)
	}
	if err := sig0.VerifySignature(r, cu.Host.Key); err != nil {
		h.logger.Infof("SRP handler: SIG(0) verification failed for %s: %v", cu.Host.Name, err)
		msg := makeErrorResponse(r, dns.RcodeRefused, "SIG(0) verification failed")
		return NewErrorResult(msg, err.Error(), err)
	}

	// Step 5: default.service.arpa. -> real-zone rewrite, when this zone
	// opted in. Rewrites every name r.Ns carries (owner names, plus SRV.Target/PTR.Ptr --
	// the only name-typed RDATA fields SRP itself produces) from under
	// default.service.arpa. to under h.upstreamZone, in place, then re-runs Validate to
	// get a cu reflecting the rewritten names. Everything from here on -- FCFS, the local
	// lease-store tree, the upstream forward -- works with exactly one name per logical
	// record, under h.upstreamZone, regardless of which zone the client actually
	// addressed: a constrained client (default.service.arpa.) and a direct client
	// (h.upstreamZone) naming the same host correctly collide in FCFS instead of silently
	// writing two different local nodes that both resolve to the same upstream name.
	// r.Question is deliberately left untouched -- makeErrorResponse/buildSuccessResponse
	// both echo it verbatim, so the response still shows the client exactly the zone name
	// it itself sent, matching normal RFC 2136 request/response symmetry.
	// zoneEnabled already confirmed the incoming zone is either h.upstreamZone or (when
	// rewriteDefaultServiceARPA is set) default.service.arpa. -- checking the latter here
	// is enough to decide whether a rewrite is needed; no need to re-check the config
	// flag itself. Harmless no-op if h.upstreamZone happens to literally be
	// default.service.arpa. too (an explicitly-configured real zone of that name).
	if canonicalName(zone) == canonicalName(defaultServiceARPA) {
		rewriteDefaultServiceARPA(r, h.upstreamZone)
		cu, err = srp.Validate(r)
		if err != nil {
			// Rewriting only ever changes names, uniformly; a validation failure here
			// would mean the rewrite itself produced a malformed message, a coding
			// error rather than a client one -- but fail closed rather than proceed
			// with a stale cu.
			h.logger.Errorf("SRP handler: re-validation after default.service.arpa. rewrite failed: %v", err)
			msg := makeErrorResponse(r, dns.RcodeServerFailure, "internal error")
			return NewErrorResult(msg, err.Error(), err)
		}
	}

	// Step 6: FCFS (S3.3.3). Checked names are the host and each service instance name
	// only (srp.Names) -- SRV/TXT/PTR owner names are never independently checked
	// (authorized transitively through their instance). cu's names are
	// under h.upstreamZone unconditionally by this point (step 5 above).
	//
	// Evaluate's own check here and the actual forward in step 7 below are two separate
	// round trips with a window between them -- collecting each name's prerequisite RR
	// (nil for most; see Evaluate's doc comment) and attaching them to the step-7
	// UPDATE closes that window by having the authoritative server itself re-check, and
	// enforce, the same FCFS condition atomically at write time, rather than trusting
	// how long ago this loop's own query ran.
	view := leaseStoreView{store: h.leaseManager}
	prereqs := make([]dns.RR, 0, len(cu.Instances)+1)
	for _, name := range srp.Names(cu) {
		key := srp.KeyFor(cu, name)
		result, prereq, err := srp.Evaluate(ctx, view, h.coordinator.QueryKeyAtName, h.upstreamZone, name, key, h.refuseOnForeignData)
		if err != nil {
			h.logger.Errorf("SRP handler: FCFS evaluation failed for %s: %v", name, err)
			msg := makeErrorResponse(r, dns.RcodeServerFailure, "FCFS evaluation failed")
			return NewErrorResult(msg, err.Error(), err)
		}
		switch result {
		case srp.FCFSConflict:
			h.logger.Infof("SRP handler: FCFS conflict for %s -- name held by a different key", name)
			msg := makeErrorResponse(r, dns.RcodeYXDomain, "name held by a different key")
			return NewErrorResult(msg, fmt.Sprintf("FCFS conflict for %s", name), fmt.Errorf("YXDOMAIN"))
		case srp.FCFSForeignData:
			h.logger.Infof("SRP handler: FCFS refused for %s -- foreign data present, no KEY", name)
			msg := makeErrorResponse(r, dns.RcodeRefused, "name occupied by non-SRP data")
			return NewErrorResult(msg, fmt.Sprintf("foreign data at %s", name), fmt.Errorf("REFUSED"))
		}
		if prereq != nil {
			prereqs = append(prereqs, prereq)
		}
	}

	// Step 7: build the upstream UPDATE and forward it, before touching the local
	// store at all (deferred-mutation pattern, reused from UpdateHandler). The outgoing
	// message is the Update section's records, exactly as classified above -- the
	// client's own bytes verbatim when it addressed h.upstreamZone directly, or the
	// step-5 rewritten form when it addressed default.service.arpa. -- plus an explicit
	// delete for any PTR this update's Service Discovery instructions drop (plan
	// S4.4/S4.5: upstream never delete-alls a PTR's owner name, so dropping a subtype
	// needs its own instruction; the local store, by contrast, wipes the whole service
	// subtree uniformly in step 8) -- plus a synthesized KEY add for any live instance
	// whose own Service Description omitted its KEY (RFC 9665 S3.3.3's own MUST: every
	// Service Description that's updated must end up with a KEY RR published, regardless
	// of whether the requester's message included one -- see
	// synthesizeOmittedInstanceKeys's own doc comment).
	forwardRecords := make([]dns.RR, 0, len(r.Ns))
	for _, rr := range r.Ns {
		forwardRecords = append(forwardRecords, rr)
	}
	forwardRecords = append(forwardRecords, h.ptrDeleteDiff(cu)...)
	forwardRecords = append(forwardRecords, synthesizeOmittedInstanceKeys(cu)...)

	signingKey, effectiveZone, err := h.resolveUpstreamSigningContext(ctx)
	if err != nil {
		h.logger.Errorf("SRP handler: failed to resolve upstream signing context: %v", err)
		msg := makeErrorResponse(r, dns.RcodeServerFailure, "upstream signing key resolution failed")
		return NewErrorResult(msg, err.Error(), err)
	}

	upstreamMsg, err := updatecore.BuildAndSign(effectiveZone, prereqs, forwardRecords, signingKey)
	if err != nil {
		h.logger.Errorf("SRP handler: failed to build upstream UPDATE: %v", err)
		msg := makeErrorResponse(r, dns.RcodeServerFailure, "failed to build upstream UPDATE")
		return NewErrorResult(msg, err.Error(), err)
	}

	upstreamResp, err := h.coordinator.SendUpdate(ctx, effectiveZone, upstreamMsg)
	if err != nil {
		h.logger.Errorf("SRP handler: upstream UPDATE failed for zone %s: %v", effectiveZone, err)
		msg := makeErrorResponse(r, dns.RcodeServerFailure, "upstream UPDATE failed")
		return NewErrorResult(msg, err.Error(), err)
	}
	if upstreamResp == nil || upstreamResp.Rcode != dns.RcodeSuccess {
		rcodeDesc := "no response"
		if upstreamResp != nil {
			rcodeDesc = fmt.Sprintf("rcode=%d", upstreamResp.Rcode)
		}
		h.logger.Errorf("SRP handler: upstream UPDATE rejected for zone %s: %s", effectiveZone, rcodeDesc)
		if upstreamResp != nil && (upstreamResp.Rcode == dns.RcodeYXRrset || upstreamResp.Rcode == dns.RcodeNXRrset) {
			// One of step 6's FCFS prerequisites, satisfied when this handler checked
			// it, no longer held by the time the authoritative server itself evaluated
			// it: a concurrent registration for one of these names landed in between.
			// This is a genuine FCFS conflict caught atomically by the authoritative
			// server rather than this handler's own (unavoidably TOCTOU) pre-forward
			// check -- report it exactly like the pre-forward conflict case above.
			msg := makeErrorResponse(r, dns.RcodeYXDomain, "name held by a different key")
			return NewErrorResult(msg, fmt.Sprintf("FCFS conflict detected atomically by upstream prerequisite: %s", rcodeDesc), fmt.Errorf("YXDOMAIN"))
		}
		msg := makeErrorResponse(r, dns.RcodeServerFailure, "upstream UPDATE rejected")
		return NewErrorResult(msg, fmt.Sprintf("upstream %s", rcodeDesc), fmt.Errorf("upstream rejected the update"))
	}

	// Step 8: upstream confirmed -- stage local lease-store mutations. Every node
	// touched by a Delete All RRsets in this update is wiped and reinserted
	// uniformly (RemoveNonKEYRecords then UpsertNonKEYRecords, both pre-existing, no
	// new store method needed). A node the update doesn't mention (an omitted
	// service instance) is simply never touched here.
	lease, keyLease, err := h.parseLease(r)
	if err != nil {
		// Validate() already confirmed the option is present and internally
		// consistent (LEASE<=KEY-LEASE); a failure here would be a coding error, not
		// a client one, but fail closed rather than mutate the store with zero
		// values.
		h.logger.Errorf("SRP handler: lease option re-parse failed after upstream success: %v", err)
		msg := makeErrorResponse(r, dns.RcodeServerFailure, "internal error")
		return NewErrorResult(msg, err.Error(), err)
	}
	lease, keyLease = h.clampLease(lease, keyLease)

	touchedNodeKeys, err := h.applyLocalMutations(ctx, cu, lease, keyLease, effectiveZone)
	if err != nil {
		// The upstream write already succeeded -- the two stores can only diverge
		// from here, never silently fail the client's request. Log loudly; the 30s
		// reconciliation pass (if wired the same way UpdateHandler's is) or the next
		// refresh will correct it. Still respond success: from the requester's
		// perspective, and the authoritative server's, the update happened.
		h.logger.Errorf("SRP handler: local lease-store mutation failed after upstream success (store now diverged from authoritative): %v", err)
	}

	// Step 9: schedule expiry timers for every node this update touched.
	for _, nodeKey := range touchedNodeKeys {
		h.scheduleLeaseExpiry(nodeKey)
	}

	// RFC 6763 S9, not one of the S4.3 ten steps above (those are RFC 9665's own protocol
	// flow): recompute and republish this zone's Service Type Enumeration record so this
	// registration is visible to "browse everything" tools, not just a targeted per-type
	// browse. Best-effort -- a rejected/failed write here doesn't fail the client's own
	// already-successful registration; the periodic reconciliation (startLeaseReconciliation)
	// retries it on the next tick regardless.
	h.reconcileServiceEnumeration(ctx)

	// Step 10: NOERROR + echo the granted LEASE/KEY-LEASE.
	resp := h.buildSuccessResponse(r, lease, keyLease)
	return NewProcessedResult(resp)
}

// collectLiveServiceTypes scans the lease store for every currently-registered, unexpired
// service instance (a KEY node whose non-KEY children include an SRV record) and returns the
// RFC 6763 two-label service type of each -- the input reconcileServiceEnumeration needs to
// recompute this zone's Service Type Enumeration record (S9) from scratch. Duplicates are
// expected and fine: BuildEnumerationRecords dedupes.
func (h *SRPHandler) collectLiveServiceTypes() []string {
	var types []string
	for _, rec := range h.leaseManager.ListAll() {
		if rec == nil || rec.KeyRR == nil || rec.IsExpired() {
			continue
		}
		set := h.leaseManager.GetNonKEYRecordSet(leasepkg.NodeKey(rec.KeyRR))
		if set == nil {
			continue
		}
		for _, nkRec := range set.Records {
			srv, ok := nkRec.RR.(*dns.SRV)
			if !ok {
				continue
			}
			if svcType, ok := dnssd.ServiceTypeFromInstanceName(srv.Hdr.Name); ok {
				types = append(types, svcType)
			}
			break // one SRV per instance node -- no need to keep scanning this node's set
		}
	}
	return types
}

// reconcileServiceEnumeration brings this zone's RFC 6763 S9 Service Type Enumeration record
// (_services._dns-sd._udp.<zone>) in line with the live lease store, via a targeted diff
// against this process's own last-confirmed-written view (h.serviceTypes) -- see
// dnssd.DiffEnumerationRecords's doc comment for why a full delete-all-then-reinsert is
// unsafe here (it would erase another process's still-live entries) and h.serviceTypes's own
// doc comment for why that view starts empty on every process start rather than being seeded
// from a live upstream read.
//
// A type this process's own local knowledge no longer has an instance of is NOT deleted
// outright: it's confirmed missing everywhere first, via a live QueryPTRExists at its
// per-type browsing name (RFC 6763 S4.1 -- the exact name a real browse would query, so this
// is asking the same question a real client would get a real answer to). This closes a gap a
// local-store-only view can't see on its own: a shared real zone can have more than one
// independent registrant (or registrar process, across a restart) providing the SAME type --
// observed live against the real dev.zenr.io. shared environment, where a second proxy
// process's own empty local view, reconciled naively, deleted a still-live type a first,
// already-gone process had registered. A type the live check still finds elsewhere is kept
// in the tracked state (so a later reconcile re-checks it, rather than forgetting it was ever
// a candidate) and simply isn't included in this round's delete. A query that itself fails
// fails safe the same way -- keep, don't delete, log, and let the next reconcile retry.
//
// Alongside the S9 type set, this also maintains all five S11 domain-enumeration PTRs
// (dnssd.DiffSelfPointingDomainRecord): "b"/"db"/"lb" present whenever at least one service
// type is known live in the zone (by this process's own local knowledge OR confirmed still
// live elsewhere via the same survivors check the type diff already performs), absent
// otherwise; "r"/"dr" the same, additionally gated on h.advertiseRegistrationDomain (off by
// default -- advertising this zone as an open target for direct RFC 2136 registration, not
// just SRP, is a deployment policy choice). A domain-enumeration browse tool queries one or
// more of these FIRST, before ever asking for the S9 type list -- without them, a zone with
// perfectly correct S9/S4.1 records is still invisible to such a tool, since it never gets
// that far. Reusing the type diff's own survivors safety check here means the same
// protection applies to all five: this process only ever removes one once it has
// independently confirmed, via a live query, that no service type remains anywhere in the
// zone -- not just gone from its own local view.
//
// A no-op diff (nothing left to add or delete after this) sends no upstream UPDATE at all.
// Called both synchronously after a successful Handle()/expiry (prompt visibility for a
// genuine change) and periodically from startLeaseReconciliation (self-heals a type this
// process's own local store has picked up, or confirmed gone, since the last tick).
func (h *SRPHandler) reconcileServiceEnumeration(ctx context.Context) {
	current := h.collectLiveServiceTypes()
	currentSet := make(map[string]bool, len(current))
	for _, t := range current {
		currentSet[strings.ToLower(t)] = true
	}

	h.serviceTypesMu.Lock()
	previous := make([]string, 0, len(h.serviceTypes))
	for t := range h.serviceTypes {
		previous = append(previous, t)
	}
	wasDomainEnumPresent := make(map[string]bool, len(h.domainEnumPresent))
	for prefix, present := range h.domainEnumPresent {
		wasDomainEnumPresent[prefix] = present
	}
	h.serviceTypesMu.Unlock()

	// previousForDiff feeds DiffEnumerationRecords: it must still include a type this
	// process has confirmed is gone everywhere, so the diff (which deletes whatever's in
	// "previous" but not "current") actually emits that delete -- survivors are excluded
	// instead, so the diff leaves their still-valid upstream entry untouched. survivors is
	// tracked separately so it can be folded back into h.serviceTypes below (kept for a
	// later reconcile to re-check, without generating any upstream instruction now).
	previousForDiff := make([]string, 0, len(previous))
	var survivors []string
	for _, t := range previous {
		if currentSet[strings.ToLower(t)] {
			previousForDiff = append(previousForDiff, t) // still known locally too -- unaffected
			continue
		}
		stillLive, err := h.coordinator.QueryPTRExists(ctx, h.upstreamZone, dnssd.BrowsingOwnerName(t, h.upstreamZone))
		switch {
		case err != nil:
			h.logger.Errorf("SRP handler: service-type enumeration: failed to confirm %s has no other live instances, leaving it listed: %v", t, err)
			survivors = append(survivors, t)
		case stillLive:
			h.logger.Debugf("SRP handler: service-type enumeration: %s still has a live instance this process doesn't manage, leaving it listed", t)
			survivors = append(survivors, t)
		default:
			previousForDiff = append(previousForDiff, t) // confirmed gone everywhere -- the diff below deletes it
		}
	}

	// anyLive is true once at least one service type is known live in the zone, whether
	// from this process's own local knowledge (currentSet) or confirmed still live
	// elsewhere via the survivors check above -- exactly the same fact the type-enumeration
	// record itself would end up expressing ("is the S9 record non-empty"), just as a
	// boolean rather than a set. Reusing survivors here means a domain-enumeration record is
	// never removed just because this process's own local view emptied out; it needs the
	// same live confirmation a type's own removal does.
	anyLive := len(currentSet) > 0 || len(survivors) > 0
	// registrationOptedIn additionally gates "r"/"dr" on h.advertiseRegistrationDomain -- if
	// it's (or becomes) false while one of them was previously published, this naturally
	// emits a delete for it below, exactly like anyLive turning false does for the other
	// three. A fixed-order slice, not a map, so the resulting upstream instructions have a
	// deterministic order (map iteration order doesn't, and DiffEnumerationRecords's own
	// output is already sorted for the same reason).
	registrationOptedIn := anyLive && h.advertiseRegistrationDomain
	wantedDomainEnum := []struct {
		prefix    string
		isPresent bool
	}{
		{dnssd.BrowseDomainPrefix, anyLive},
		{dnssd.DefaultBrowseDomainPrefix, anyLive},
		{dnssd.LegacyBrowseDomainPrefix, anyLive},
		{dnssd.RegistrationDomainPrefix, registrationOptedIn},
		{dnssd.DefaultRegistrationDomainPrefix, registrationOptedIn},
	}
	var domainEnumRecords []dns.RR
	newDomainEnumPresent := make(map[string]bool, len(wantedDomainEnum))
	for _, w := range wantedDomainEnum {
		domainEnumRecords = append(domainEnumRecords, dnssd.DiffSelfPointingDomainRecord(w.prefix, h.upstreamZone, wasDomainEnumPresent[w.prefix], w.isPresent, serviceEnumerationTTL)...)
		newDomainEnumPresent[w.prefix] = w.isPresent
	}

	records := dnssd.DiffEnumerationRecords(h.upstreamZone, previousForDiff, current, serviceEnumerationTTL)
	records = append(records, domainEnumRecords...)
	newState := func() map[string]bool {
		state := make(map[string]bool, len(currentSet)+len(survivors))
		for t := range currentSet {
			state[t] = true
		}
		for _, t := range survivors {
			state[strings.ToLower(t)] = true
		}
		return state
	}
	if len(records) == 0 {
		h.serviceTypesMu.Lock()
		h.serviceTypes = newState()
		h.domainEnumPresent = newDomainEnumPresent
		h.serviceTypesMu.Unlock()
		return
	}

	signingKey, effectiveZone, err := h.resolveUpstreamSigningContext(ctx)
	if err != nil {
		h.logger.Errorf("SRP handler: service-type enumeration: failed to resolve signing context: %v", err)
		return
	}
	upstreamMsg, err := updatecore.BuildAndSign(effectiveZone, nil, records, signingKey)
	if err != nil {
		h.logger.Errorf("SRP handler: service-type enumeration: failed to build upstream UPDATE: %v", err)
		return
	}
	upstreamResp, err := h.coordinator.SendUpdate(ctx, effectiveZone, upstreamMsg)
	if err != nil {
		h.logger.Errorf("SRP handler: service-type enumeration: upstream UPDATE failed: %v", err)
		return
	}
	if upstreamResp == nil || upstreamResp.Rcode != dns.RcodeSuccess {
		rcodeDesc := "no response"
		if upstreamResp != nil {
			rcodeDesc = fmt.Sprintf("rcode=%d (%s)", upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode])
		}
		h.logger.Errorf("SRP handler: service-type enumeration: upstream UPDATE rejected: %s", rcodeDesc)
		return
	}

	h.serviceTypesMu.Lock()
	h.serviceTypes = newState()
	h.domainEnumPresent = newDomainEnumPresent
	h.serviceTypesMu.Unlock()

	h.logger.Debugf("SRP handler: service-type enumeration reconciled for zone %s (%d change(s))", h.upstreamZone, len(records))
}

// synthesizeOmittedInstanceKeys returns an explicit "Add To An RRSet" KEY instruction (RFC
// 2136 S2.5.1) for every live (SRV-present) service instance in cu whose own Service
// Description Instruction omitted its KEY. RFC 9665 S3.2.5.1 lets a requester omit it "for
// brevity" -- client/srp, this project's own requester, always takes that option -- but
// S3.3.3 is unconditional on the other side of that trade: "After the SRP Update has been
// applied, every Service Description that is updated MUST have a KEY RR, which MUST have the
// same value as the KEY RR ... in the Host Description." That's a requirement on the
// resulting zone state, not just registrar-internal bookkeeping -- the requester omitting the
// KEY from the wire message doesn't relieve the registrar of making sure one ends up
// published. Without this, a live instance registered by a client that omitted its KEY has
// none published upstream at all, which -- independent of anything else -- makes a live FCFS
// query for that name after any local lease-store amnesia (most commonly a proxy restart)
// indistinguishable from genuinely foreign, unowned data (see pkg/srp.Evaluate's own doc
// comment on the AuthNoKey case).
//
// srp.KeyFor already computes exactly the right value for this (same algorithm/protocol/
// public-key/TTL as the Host Description's own KEY, owner name rewritten to the instance) --
// it's reused here as-is for the local lease store's own bookkeeping; this function is the
// one place that also forwards it upstream. A removal-shaped instance (SRV == nil) is
// excluded: its Delete All RRsets already removes whatever KEY might exist there, and there
// is no live Service Description left afterward for the MUST to apply to. An instance whose
// Service Description DID include an explicit KEY is also excluded -- it's already part of
// r.Ns, forwarded verbatim, and synthesizing a second copy would be redundant.
func synthesizeOmittedInstanceKeys(cu *srp.ClassifiedUpdate) []dns.RR {
	var records []dns.RR
	for _, inst := range cu.Instances {
		if inst.SRV == nil || inst.Key != nil {
			continue
		}
		records = append(records, srp.KeyFor(cu, inst.Name))
	}
	return records
}

// ptrDeleteDiff implements the one piece of genuinely new logic the lease-store mapping
// needs: for each service instance in this update -- live (SRV present) or
// removal-shaped (bare delete-all) alike -- read its CURRENT PTR children from the store
// and diff them against this update's own named Service Discovery adds for that instance
// (none, for a removal-shaped instance, so every currently-stored PTR is "not named" and
// gets deleted -- exactly the removal semantics wanted). Any PTR currently in the store but
// not named as an add here is about to be silently dropped by the *local* wipe-then-reinsert
// in step 8 -- but upstream never delete-alls a PTR's owner name (it's the service *type*,
// shared with every other instance), so the outgoing message needs an explicit delete for
// it, or the authoritative server never finds out.
//
// Earlier versions of this function skipped removal-shaped instances entirely, on the
// assumption that "a removal-shaped instance's own delete-all already covers everything" --
// that assumption was wrong: the delete-all is scoped to the INSTANCE's own name, which
// never reaches a PTR owned at the (different, shared) service-type name. That left every
// removed instance's PTR(s) permanently orphaned upstream -- a real bug caught by the local
// BIND 9 test harness, the same failure mode independently found
// and fixed in processExpiredNode for the expiry path.
func (h *SRPHandler) ptrDeleteDiff(cu *srp.ClassifiedUpdate) []dns.RR {
	var diff []dns.RR
	for _, inst := range cu.Instances {
		instNodeKey := leasepkg.NodeKey(srp.KeyFor(cu, inst.Name))
		set := h.leaseManager.GetNonKEYRecordSet(instNodeKey)
		if set == nil {
			continue
		}

		named := make(map[string]bool)
		for _, d := range cu.Discovery {
			if d.IsAdd && d.Target == inst.Name {
				named[leasepkg.RecordKey(d.RR)] = true
			}
		}

		for rrKey, rec := range set.Records {
			if _, ok := rec.RR.(*dns.PTR); !ok {
				continue
			}
			if !named[rrKey] {
				diff = append(diff, updatecore.AsDelete(rec.RR))
			}
		}
	}
	return diff
}

// applyLocalMutations performs step 8 and returns every node key it touched, for the
// caller to schedule expiry timers against (step 9). Follows the deferred-mutation
// pattern's other half: this is only ever called after the upstream write already
// succeeded.
func (h *SRPHandler) applyLocalMutations(ctx context.Context, cu *srp.ClassifiedUpdate, lease, keyLease uint32, upstreamZone string) ([]string, error) {
	var touched []string
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	hostNodeKey := leasepkg.NodeKey(cu.Host.Key)
	hostErr := h.registerOrRenew(ctx, "", cu.Host.Key, keyLease, upstreamZone)
	note(hostErr)
	touched = append(touched, hostNodeKey)

	h.leaseManager.RemoveNonKEYRecords(hostNodeKey)
	if len(cu.Host.Addresses) > 0 {
		note(h.leaseManager.UpsertNonKEYRecords(hostNodeKey, cu.Host.Addresses, lease, upstreamZone))
	}

	// If the host's own node failed to register/renew locally (upstream already
	// succeeded regardless -- see this function's own doc comment), parenting instances
	// under hostNodeKey below would give them a ParentKeyName pointing at a node that
	// doesn't actually exist in the store: unreachable via the host's subtree for
	// cascade-expiry/deletion, and never itself corrected since nothing else revisits
	// ParentKeyName after registration. Register them as their own roots instead --
	// still tracked, still get their own expiry timer -- accepting the lesser cost of
	// losing cascade-with-host semantics for this cycle, corrected on the next
	// successful refresh (S3.2's "restate everything" already re-runs this whole
	// function).
	instanceParentKey := hostNodeKey
	if hostErr != nil {
		instanceParentKey = ""
	}

	for _, inst := range cu.Instances {
		key := srp.KeyFor(cu, inst.Name)
		instNodeKey := leasepkg.NodeKey(key)
		note(h.registerOrRenew(ctx, instanceParentKey, key, keyLease, upstreamZone))
		touched = append(touched, instNodeKey)

		if inst.SRV == nil {
			// Removal-shaped: the instance's own delete-all is the whole point --
			// wipe its non-KEY children (SRV/TXT/PTRs, whichever a prior
			// registration left) and add nothing back.
			h.leaseManager.RemoveNonKEYRecords(instNodeKey)
			continue
		}

		records := make([]dns.RR, 0, 2+len(inst.TXT)+len(cu.Discovery))
		records = append(records, inst.SRV)
		for _, txt := range inst.TXT {
			records = append(records, txt)
		}
		for _, d := range cu.Discovery {
			if d.IsAdd && d.Target == inst.Name {
				records = append(records, d.RR)
			}
		}

		// Wipe + reinsert the WHOLE service subtree (SRV, TXT, and PTRs together) --
		// mirrors the Service Description's own Delete All RRsets, and gives S3.3.4
		// subtype atomicity for free: only PTRs named in this update survive.
		h.leaseManager.RemoveNonKEYRecords(instNodeKey)
		note(h.leaseManager.UpsertNonKEYRecords(instNodeKey, records, lease, upstreamZone))
	}

	return touched, firstErr
}

// registerOrRenew creates keyRR's lease-store node (parented to parentNodeKey, "" for the
// zone root) if it doesn't already exist as a live node, or renews its timers in place if
// it does -- RenewLease deliberately never touches ParentKeyName or tree position, so a
// refresh of an existing host/instance can't accidentally relocate it.
func (h *SRPHandler) registerOrRenew(ctx context.Context, parentNodeKey string, keyRR *dns.KEY, keyLease uint32, upstreamZone string) error {
	nodeKey := leasepkg.NodeKey(keyRR)
	if existing := h.leaseManager.Get(nodeKey); existing != nil && !existing.IsExpired() {
		return h.leaseManager.RenewLease(ctx, keyRR, keyLease, keyLease)
	}
	return h.leaseManager.RegisterWithParent(ctx, parentNodeKey, keyRR, keyLease, keyLease, upstreamZone)
}

// resolveUpstreamSigningContext resolves the proxy's own signing key and the effective
// (post-SOA-resolution, or static-override) upstream zone -- the SRP-handler equivalent
// of UpdateHandler.resolveUpstreamSigningContext, written separately rather than shared
// because that one is a method on *UpdateHandler and type-asserts down to
// *updatecore.Coordinator for its zone-resolution fallback, where srpCoordinator declares
// ResolveAuthoritativeZone directly; both are thin now that the actual resolution logic
// lives in pkg/updatecore. The signing key itself is Setup's own upstreamKeyRecord, cached
// once there rather than re-read from keystoreDir on every call -- see that field's doc
// comment.
func (h *SRPHandler) resolveUpstreamSigningContext(ctx context.Context) (*keyrec.LoadedKey, string, error) {
	if h.upstreamKeyRecord == nil {
		return nil, "", fmt.Errorf("upstream signing key resolution failed: no key cached (Setup did not run or did not succeed)")
	}
	signingKey := h.upstreamKeyRecord
	h.logger.Debugf("Using cached proxy authorization key for upstream zone %s (found at key zone %s)", h.upstreamZone, h.upstreamKeyZone)

	effectiveZone, err := h.coordinator.ResolveAuthoritativeZone(ctx, h.upstreamZone)
	if err != nil {
		return nil, "", fmt.Errorf("upstream zone resolution failed: %w", err)
	}
	h.logger.Debugf("Resolved effective upstream zone: configured=%s effective=%s", h.upstreamZone, effectiveZone)
	return signingKey, effectiveZone, nil
}

// parseLease decodes the Update-Lease option. Unlike UpdateHandler.parseLease, this does
// not re-derive validity (LEASE<=KEY-LEASE, 8-byte-vs-4-byte-variant policy) -- Validate()
// (S3.3.2, called in step 2) already confirmed the option is present and internally
// consistent before Handle() ever reaches this call, so a failure here would be a coding
// error, not a client one (see its call site's comment).
func (h *SRPHandler) parseLease(msg *dns.Msg) (uint32, uint32, error) {
	erfc, found := leasepkg.FindOption(msg)
	if !found {
		return 0, 0, fmt.Errorf("no Update-Lease EDNS option found")
	}
	lo, err := leasepkg.DecodeOption(erfc)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid lease option: %w", err)
	}
	if lo.KeyLease == nil {
		return 0, 0, fmt.Errorf("SRP requires the 8-byte Update-Lease variant (LEASE + KEY-LEASE)")
	}
	return lo.Lease, *lo.KeyLease, nil
}

// clampLease applies LeasePolicy bounds to the granted LEASE/KEY-LEASE, mirroring
// UpdateHandler.clampLeaseDurations (unexported there, so reimplemented rather than
// shared -- a handful of lines, not worth cross-type coupling for).
func (h *SRPHandler) clampLease(lease, keyLease uint32) (uint32, uint32) {
	return clampTTL(lease, h.LeasePolicy.MinRRLease, h.LeasePolicy.MaxRRLease),
		clampTTL(keyLease, h.LeasePolicy.MinKeyLease, h.LeasePolicy.MaxKeyLease)
}

func (h *SRPHandler) buildSuccessResponse(r *dns.Msg, lease, keyLease uint32) *dns.Msg {
	resp := &dns.Msg{MsgHeader: r.MsgHeader, Question: r.Question}
	resp.Response = true
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	leaseOpt := leasepkg.Encode8Byte(lease, keyLease)
	if err := leaseOpt.Encode(opt); err != nil {
		h.logger.Debugf("failed to encode response lease option: %v", err)
	}
	resp.Extra = append(resp.Extra, opt)
	return resp
}

// scheduleLeaseExpiry arms (or re-arms) a timer that, on firing, sends the corresponding
// upstream delete and then removes the node locally -- the same upstream-aware,
// deferred-mutation-respecting expiry UpdateHandler.scheduleLeaseExpiry implements,
// reimplemented here (rather than shared) for the same reason resolveUpstreamSigningContext
// is: that one is tightly coupled to *UpdateHandler's own case-matrix and mutation model.
func (h *SRPHandler) scheduleLeaseExpiry(nodeKey string) {
	h.leaseTimersMu.Lock()
	defer h.leaseTimersMu.Unlock()

	if existing, ok := h.leaseTimers[nodeKey]; ok {
		existing.Stop()
	}

	rec := h.leaseManager.Get(nodeKey)
	if rec == nil {
		delete(h.leaseTimers, nodeKey)
		return
	}
	delay := time.Until(rec.ExpiresAt)
	if delay < 0 {
		delay = 0
	}
	h.leaseTimers[nodeKey] = time.AfterFunc(delay, func() {
		h.processExpiredNode(context.Background(), nodeKey)
	})
}

// processExpiredNode removes an expired node's data both upstream and locally. Unlike
// UpdateHandler.processExpiredLease, this has no Case A/B/C/D-style branching to
// replicate: an expired KEY node's subtree is simply deleted, upstream first.
//
// The upstream delete must cover everything DeleteSubtree is about to remove locally, not
// just the KEY record: a Delete All RRsets at this node's own name reaches the KEY plus
// every non-KEY record applyLocalMutations stores directly there (a host's A/AAAA, a
// service instance's SRV/TXT) -- but a PTR's owner name is the (possibly shared) service
// *type*, never this node's own name, so the delete-all can't reach it;
// every PTR this node currently holds needs its own explicit delete, exactly mirroring
// ptrDeleteDiff's reasoning. A single-RR KEY delete (the original implementation here)
// left every non-KEY record permanently orphaned upstream once the local subtree was gone
// -- a real bug caught by the local BIND 9 test harness.
//
// It also covers nodeKey's WHOLE subtree, not just nodeKey itself -- a host and its
// service instances are normally registered with matching lease durations (Handle()'s
// applyLocalMutations passes the same keyLease to every touched node), so they typically
// expire within milliseconds of each other via their own, independent timers. If a child's
// own expiry attempt fires first and is transiently rejected (leaving it pending retry),
// and the host's own expiry then succeeds moments later, DeleteSubtree(nodeKey) below would
// otherwise cascade-remove that still-pending child from the local store anyway -- silently
// and permanently losing track of its unresolved upstream state (no future reconciliation
// pass would ever see it again). Building the upstream delete for the whole subtree here
// means that by the time DeleteSubtree runs, every descendant's data really has just been
// deleted upstream too (redundantly re-deleting an already-cleaned child, if its own attempt
// had already succeeded, is a harmless RFC 2136 no-op). Also caught by the local BIND 9 test
// harness.
func (h *SRPHandler) processExpiredNode(ctx context.Context, nodeKey string) {
	h.leaseTimersMu.Lock()
	delete(h.leaseTimers, nodeKey)
	h.leaseTimersMu.Unlock()

	rec := h.leaseManager.Get(nodeKey)
	if rec == nil || !rec.IsExpired() {
		return // raced a refresh; nothing to do
	}

	var deletes []dns.RR
	for _, nk := range append([]string{nodeKey}, h.leaseManager.ListSubtreeKeys(nodeKey)...) {
		r := h.leaseManager.Get(nk)
		if r == nil || r.KeyRR == nil {
			continue
		}
		deletes = append(deletes, deleteAllRR(r.KeyRR.Hdr.Name))
		if set := h.leaseManager.GetNonKEYRecordSet(nk); set != nil {
			for _, nkRec := range set.Records {
				if _, ok := nkRec.RR.(*dns.PTR); ok {
					deletes = append(deletes, updatecore.AsDelete(nkRec.RR))
				}
			}
		}
	}

	signingKey, effectiveZone, err := h.resolveUpstreamSigningContext(ctx)
	if err != nil {
		h.logger.Errorf("SRP handler: expiry of %s: failed to resolve signing context: %v", nodeKey, err)
		return
	}
	upstreamMsg, err := updatecore.BuildAndSign(effectiveZone, nil, deletes, signingKey)
	if err != nil {
		h.logger.Errorf("SRP handler: expiry of %s: failed to build upstream delete: %v", nodeKey, err)
		return
	}
	upstreamResp, err := h.coordinator.SendUpdate(ctx, effectiveZone, upstreamMsg)
	if err != nil {
		h.logger.Errorf("SRP handler: expiry of %s: upstream delete failed (will retry on next reconciliation pass): %v", nodeKey, err)
		return
	}
	// SendUpdate only reports a network/transport-level error -- it does not itself
	// reject a non-success RCODE (see updatecore.Coordinator.SendUpdate), so a REFUSED or
	// SERVFAIL response would otherwise fall through to DeleteSubtree below and remove
	// this node locally even though upstream still has it, violating the upstream-first
	// invariant this whole handler is built on. Caught by the local BIND 9 test harness.
	if upstreamResp == nil || upstreamResp.Rcode != dns.RcodeSuccess {
		rcodeDesc := "no response"
		if upstreamResp != nil {
			rcodeDesc = fmt.Sprintf("rcode=%d (%s)", upstreamResp.Rcode, dns.RcodeToString[upstreamResp.Rcode])
		}
		h.logger.Errorf("SRP handler: expiry of %s: upstream delete rejected (will retry on next reconciliation pass): %s", nodeKey, rcodeDesc)
		return
	}

	// Detection only -- this does not attempt to resolve anything, and does not change what
	// happens below. Handle() only calls applyLocalMutations (which is what bumps
	// ExpiresAt) AFTER its own upstream write is independently confirmed, so if nodeKey is
	// no longer expired here, a client's refresh for this exact node landed -- and was
	// itself already applied upstream -- sometime during this function's own upstream round
	// trip above. That refresh's write and this function's delete are two independent,
	// uncoordinated upstream transactions with no ordering guarantee between them: each got
	// its own NOERROR from the authoritative server, but neither send can tell which one the
	// server actually applied last. So the true resulting upstream state is genuinely
	// indeterminate from here -- not something a local heuristic can safely guess at either
	// way (skipping DeleteSubtree below would be no more likely correct than not skipping
	// it). Closing this for real needs serializing operations against the same subtree,
	// deferred future work; until then this is surfaced for operator visibility only.
	if rec := h.leaseManager.Get(nodeKey); rec != nil && !rec.IsExpired() {
		h.logger.Errorf("SRP handler: RACE DETECTED during expiry of %s: this node was refreshed by a concurrent request while this function's own expiry-delete (just confirmed rcode=%d) was in flight upstream. The refresh's add and this delete are two independent, uncoordinated upstream transactions -- which one the authoritative server actually applied last cannot be determined from here. Local state is being removed below regardless; if the refresh's write landed after this delete, the authoritative server and the local store are now diverged, and will not self-correct until the client's next full refresh cycle or this node's next natural expiry.", nodeKey, upstreamResp.Rcode)
	}

	if err := h.leaseManager.DeleteSubtree(nodeKey); err != nil {
		h.logger.Errorf("SRP handler: expiry of %s: local DeleteSubtree failed: %v", nodeKey, err)
		return
	}
	h.logger.Infof("SRP handler: expiry of %s: upstream delete confirmed, local subtree removed", nodeKey)

	// RFC 6763 S9: an expired node may have been the last live instance of its service
	// type -- recompute the enumeration record so it stops listing a type nothing still
	// provides. Same best-effort reasoning as the call in Handle().
	h.reconcileServiceEnumeration(ctx)
}

// deleteAllRR builds a raw RFC 2136 S2.5.3 "Delete All RRsets From A Name" (class ANY) --
// this fork's presentation-format parser can't produce this shape, so it
// needs direct construction, same as pkg/srp's own (unexported, so not reusable from here)
// deleteAll helper.
func deleteAllRR(name string) dns.RR {
	return &dns.ANY{Hdr: dns.Header{Name: name, Class: dns.ClassANY, TTL: 0}}
}

// startLeaseReconciliation is the SRP-handler equivalent of
// UpdateHandler.startLeaseReconciliation: ensures every KEY node has a live expiry timer,
// catching any node a future snapshot-restore path doesn't itself arm one for.
func (h *SRPHandler) startLeaseReconciliation(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			for _, rec := range h.leaseManager.ListAll() {
				if rec.KeyRR == nil {
					continue
				}
				nodeKey := leasepkg.NodeKey(rec.KeyRR)
				h.leaseTimersMu.Lock()
				_, has := h.leaseTimers[nodeKey]
				h.leaseTimersMu.Unlock()
				if !has {
					h.scheduleLeaseExpiry(nodeKey)
				}
			}
			// RFC 6763 S9 self-heal: recompute the enumeration record from current
			// store state on every tick regardless of whether anything above changed,
			// catching anything a missed/raced incremental call (Handle(),
			// processExpiredNode) left stale -- see reconcileServiceEnumeration's own
			// doc comment.
			h.reconcileServiceEnumeration(context.Background())
		}
	}()
}

// DumpLeasesLevel implements the same dump-endpoint interface UpdateHandler does (see
// server/router.go's handleDumpQuery), so SRP-managed state shows up in the same
// __dump.sig0lease.internal[.debug] query operators already use. A simpler format than
// UpdateHandler's tree-indented dump -- flat, one section per node -- since SRP's tree
// shape (documented in docs/siglease_rfc9665.md's lease-store mapping section) doesn't need the same visual nesting to be legible.
func (h *SRPHandler) DumpLeasesLevel(level string) string {
	h.leaseTimersMu.Lock()
	defer h.leaseTimersMu.Unlock()

	isDebug := strings.ToLower(strings.TrimSpace(level)) == "debug"

	var sb strings.Builder
	if isDebug {
		sb.WriteString("=== SRP Lease Store Dump ===\n")
	} else {
		sb.WriteString("=== SRP Lease Store Summary ===\n")
	}

	all := h.leaseManager.ListAll()
	if len(all) == 0 {
		sb.WriteString("(empty)\n")
		return sb.String()
	}
	sort.Slice(all, func(i, j int) bool {
		return leasepkg.NodeKey(all[i].KeyRR) < leasepkg.NodeKey(all[j].KeyRR)
	})

	for _, rec := range all {
		if rec.KeyRR == nil {
			continue
		}
		nodeKey := leasepkg.NodeKey(rec.KeyRR)
		set := h.leaseManager.GetNonKEYRecordSet(nodeKey)
		nonKeyCount := 0
		if set != nil {
			nonKeyCount = len(set.Records)
		}
		status := "active"
		if rec.IsExpired() {
			status = "expired"
		}
		if !isDebug {
			sb.WriteString(fmt.Sprintf("Key: %-40s KEY=%-8s NonKEY=%d\n", nodeKey, status, nonKeyCount))
			continue
		}
		sb.WriteString(fmt.Sprintf("Key: %s\n  KeyRR: %s\n  Status: %s\n  ExpiresAt: %s\n  ParentKeyName: %q\n",
			nodeKey, rec.KeyRR.String(), status, rec.ExpiresAt.Format(time.RFC3339), rec.ParentKeyName))
		if set != nil {
			for _, nk := range set.Records {
				sb.WriteString(fmt.Sprintf("    RR: %s\n      ExpiresAt: %s\n", nk.RR.String(), nk.ExpiresAt.Format(time.RFC3339)))
			}
		}
	}
	return sb.String()
}
