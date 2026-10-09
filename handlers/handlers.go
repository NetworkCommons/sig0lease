// Package handlers provides opcode-specific processing modules for the DNS proxy.
package handlers

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/updatecore"
)

// Handler is an interface for a DNS processing module.
type Handler interface {
	// Name returns the unique name of this handler
	Name() string

	// CanHandle returns true if this handler can process the given opcode
	CanHandle(opcode uint8) bool

	// Handle processes a DNS message and returns a HandlerResult.
	// The result status determines how the router handles the response:
	//   - StatusProcessed: Send the response message to the client
	//   - StatusNotRelevant: Packet not relevant to this handler, apply default upstream routing
	//   - StatusError: Error occurred, send error response to client
	Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult

	// Setup initializes the handler with configuration
	Setup(cfg map[string]any) error

	// Shutdown releases any resources this handler owns (background
	// goroutines, open files). Called exactly once during server shutdown.
	Shutdown()
}

// BaseHandler provides common functionality for handlers.
type BaseHandler struct {
	name    string
	opcodes []uint8
	logger  *logging.Logger
}

// SetLogger sets the logger for this handler.
func (b *BaseHandler) SetLogger(logger *logging.Logger) {
	b.logger = logger
}

// Name returns the handler's name.
func (b *BaseHandler) Name() string {
	return b.name
}

// CanHandle returns true if this handler handles the given opcode.
func (b *BaseHandler) CanHandle(opcode uint8) bool {
	for _, op := range b.opcodes {
		if op == opcode {
			return true
		}
	}
	return false
}

// Shutdown is a no-op default; handlers that own no resources needing
// release on shutdown do not need to override it.
func (b *BaseHandler) Shutdown() {}

// updateResponse starts the reply to the UPDATE request req: req's header (so its ID and
// Opcode) with QR and rcode set, and no sections. RFC 2136 S3.8 lets a reply either copy
// every section of the request or carry none; every reply UpdateHandler and SRPHandler send
// carries none. Copying only the Zone section, as they once did, is neither, and
// mDNSResponder's srp-client then ignores the granted lease: it reads the Update Lease option
// only from a reply whose one record is the OPT RR, and otherwise refreshes on the lease it
// asked for.
func updateResponse(req *dns.Msg, rcode uint16) *dns.Msg {
	resp := &dns.Msg{MsgHeader: req.MsgHeader}
	resp.Response = true
	resp.Rcode = rcode
	return resp
}

// leaseResponse is the NOERROR reply to a lease update: updateResponse plus the Update Lease
// option carrying the LEASE and KEY-LEASE actually granted (RFC 9664 S4), so the requester
// refreshes on those rather than on what it asked for.
//
// The option goes in resp.Pseudo, from which the dns library builds the reply's one OPT RR,
// together with the EDNS fields of the header copied from req. An OPT RR added to resp.Extra
// instead, as this code once did, became a second OPT RR whenever req used EDNS -- which every
// lease update does -- and RFC 6891 S6.1.1 allows one. mDNSResponder's srp-client then ignored
// the granted lease, since it reads it only from a reply whose one record is the OPT RR.
func leaseResponse(req *dns.Msg, lease, keyLease uint32, logger *logging.Logger) *dns.Msg {
	resp := updateResponse(req, dns.RcodeSuccess)
	resp.Authoritative = true
	resp.UDPSize = uint16(dns.DefaultMsgSize)

	opt := &dns.OPT{}
	if err := leasepkg.Encode8Byte(lease, keyLease).Encode(opt); err != nil {
		logger.Debugf("failed to encode response lease option: %v", err)
	}
	for _, option := range opt.Options {
		resp.Pseudo = append(resp.Pseudo, option)
	}
	return resp
}

// makeErrorResponse builds the error reply to req (updateResponse with rcode). msg is
// currently unused (kept as a parameter for call-site readability -- see the "Note" below);
// shared by UpdateHandler and SRPHandler.
//
// Note: we don't include detailed error messages in the response. Errors are logged
// locally but responses use standard DNS rcodes. In future versions, we can add extended
// error EDNS options.
func makeErrorResponse(req *dns.Msg, rcode uint16, _ string) *dns.Msg {
	return updateResponse(req, rcode)
}

// refuseDottedLabels returns an error result -- REFUSED -- if the request r, as it arrived on
// the wire, carries a DNS label with a "." octet in it, and nil otherwise. The dns library
// decodes such a label as two or more labels (pkg/dnsname's labels.go), so a handler that
// sends r's names on -- both do, re-encoded in an update under the proxy's own signature --
// would register a different name than the one requested, and say nothing. RFC 6763 S4.1.1
// allows a "." in an Instance label and RFC 2181 S11 in any label, so this is the proxy's
// limit, not the requester's error. Plain forwarding sends r's original bytes and is
// unaffected, which is why each handler calls this only once it has taken the request.
//
// A request built in-process rather than read off the wire has no wire form (Data) to check.
func refuseDottedLabels(r *dns.Msg) *HandlerResult {
	if len(r.Data) == 0 {
		return nil
	}
	label, found, err := dnsname.DottedWireLabel(r.Data)
	if err != nil {
		msg := makeErrorResponse(r, dns.RcodeFormatError, err.Error())
		return NewErrorResult(msg, err.Error(), err)
	}
	if !found {
		return nil
	}
	err = fmt.Errorf("label %q contains \".\", which this proxy cannot carry: its DNS library would send it on as several labels", label)
	msg := makeErrorResponse(r, dns.RcodeRefused, err.Error())
	return NewErrorResult(msg, err.Error(), err)
}

// rcodeDescription renders resp's RCODE for a log line, or "no response" for a nil resp --
// the small "was there even a response, and what did it say" formatting repeated at every
// upstream-forward call site that has to report a rejected or missing response.
func rcodeDescription(resp *dns.Msg) string {
	if resp == nil {
		return "no response"
	}
	return fmt.Sprintf("rcode=%d (%s)", resp.Rcode, dns.RcodeToString[resp.Rcode])
}

// updateSender is the UPDATE-sending half of both handlers' upstream coordinators.
type updateSender interface {
	SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error)
}

// asDeletes returns rrs as RFC 2136 "Delete An RR From An RRset" instructions
// (updatecore.AsDelete), for updatecore.BuildAndSign.
func asDeletes[RR dns.RR](rrs ...RR) []dns.RR {
	deletes := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		deletes = append(deletes, updatecore.AsDelete(rr))
	}
	return deletes
}

// requireUpstream panics unless the named handler has both its upstream coordinator and the
// proxy's own SIG(0) signing key. Setup refuses to produce a handler without either, and
// cmd/sig0lease exits when Setup fails, so getting here without them means a handler was
// built some other way -- a programming error. The proxy has no function without an
// upstream it can sign for, so it fails outright rather than logging, retrying, or skipping
// the upstream half of an operation.
func requireUpstream(handler string, hasCoordinator, hasSigningKey bool) {
	if hasCoordinator && hasSigningKey {
		return
	}
	var missing []string
	if !hasCoordinator {
		missing = append(missing, "an upstream coordinator")
	}
	if !hasSigningKey {
		missing = append(missing, "the proxy's signing key")
	}
	panic(fmt.Sprintf("%s is missing %s: Setup did not run or did not succeed", handler, strings.Join(missing, " and ")))
}

// upstreamClient is what upstreamTarget needs of a handler's coordinator; both handlers'
// coordinator interfaces include it.
type upstreamClient interface {
	updateSender
	ResolveAuthoritativeZone(ctx context.Context, zone string) (string, error)
}

// upstreamTarget is where one handler's UPDATEs go and what signs them: its coordinator, the
// proxy's signing key that Setup loaded once (a rotated key on disk needs a restart), and the
// handler's configured upstream zone. Each handler builds one from its own fields.
type upstreamTarget struct {
	handler     string
	coordinator upstreamClient
	signingKey  *keyrec.LoadedKey
	zone        string
	logger      *logging.Logger
}

// send sends one UPDATE of prereqs and records to the authoritative server and reads its
// answer. Every UPDATE either handler sends -- a request's forward, a delete, a lease expiry,
// the RFC 6763 enumeration -- goes through it, so every one is built, signed and read the
// same way: the configured zone is resolved to its zone cut (SOA discovery, or a static
// upstream), the message is built and signed by updatecore.BuildAndSign, and a transport
// error, no answer, or any RCODE but NOERROR is a failure (the coordinator itself reports
// transport errors only). The answer is returned whenever there is one, for a caller that
// tells rejections apart (SRP's FCFS prerequisites). A handler without its coordinator or
// signing key is a programming error (requireUpstream panics).
func (t upstreamTarget) send(ctx context.Context, prereqs, records []dns.RR) (*dns.Msg, error) {
	requireUpstream(t.handler, t.coordinator != nil, t.signingKey != nil)
	zone, err := t.coordinator.ResolveAuthoritativeZone(ctx, t.zone)
	if err != nil {
		return nil, fmt.Errorf("upstream zone resolution failed: %w", err)
	}
	t.logger.Debugf("Resolved effective upstream zone: configured=%s effective=%s", t.zone, zone)
	msg, err := updatecore.BuildAndSign(zone, prereqs, records, t.signingKey)
	if err != nil {
		return nil, fmt.Errorf("building the upstream UPDATE: %w", err)
	}
	resp, err := t.coordinator.SendUpdate(ctx, zone, msg)
	if err != nil {
		return nil, fmt.Errorf("upstream UPDATE failed: %w", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return resp, fmt.Errorf("upstream UPDATE rejected: %s", rcodeDescription(resp))
	}
	return resp, nil
}

// buildCoordinatorFromConfig builds a handler's upstream coordinator from its config:
// "bootstrap_resolvers", the resolvers discovery asks for a name's SOA, and "upstream", an
// optional static "host:port" of upstreamZone's authoritative server, used in place of
// discovery for upstreamZone and every name at or below it (updatecore.StaticUpstream).
// Shared by UpdateHandler.Setup and SRPHandler.Setup. An "upstream" that is not a
// "host:port" string is an error, not ignored: a proxy silently sending to the discovered
// server instead of the configured one would update a different zone than intended.
func buildCoordinatorFromConfig(cfg map[string]any, upstreamZone string, logger *logging.Logger) (*updatecore.Coordinator, error) {
	var static *updatecore.StaticUpstream
	if raw, ok := cfg["upstream"]; ok && raw != nil {
		addr, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf(`"upstream" must be a "host:port" string, got %T`, raw)
		}
		addr = strings.TrimSpace(addr)
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf(`"upstream" must be "host:port": %w`, err)
		}
		static = &updatecore.StaticUpstream{Zone: upstreamZone, Addr: addr}
		logger.Debugf("Zone %s and the names below it configured with static upstream: %s", upstreamZone, addr)
	}
	bootstrapResolvers := parseStringSlice(cfg["bootstrap_resolvers"])
	if len(bootstrapResolvers) > 0 {
		logger.Debugf("Upstream coordinator bootstrap resolvers: %v", bootstrapResolvers)
	} else {
		logger.Debugf("Upstream coordinator uses the built-in default bootstrap resolvers")
	}
	return updatecore.NewCoordinator(logger, bootstrapResolvers, static), nil
}

// leaseStorageConfig is a handler's "storage" config section, as parseLeaseStorageConfig reads
// it.
type leaseStorageConfig struct {
	// path is a "file" store's snapshot file, or "" for a "memory" store.
	path string
	// saveInterval is how often a "file" store saves its snapshot.
	saveInterval time.Duration
}

// parseLeaseStorageConfig reads a handler's "storage" config section. "memory" (or an omitted
// "type") is the zero-persistence in-memory store; "file" additionally loads/saves a
// human-readable JSON snapshot at "path", every "save_interval" (default 30s). Any
// unrecognized "type", a "file" type missing "path", or a save_interval that is not a positive
// duration (leasepkg.CheckSaveInterval) is a hard error -- never a silent fallback to the
// default.
func parseLeaseStorageConfig(storageCfg map[string]any) (leaseStorageConfig, error) {
	storageType := "memory"
	if raw, ok := storageCfg["type"]; ok {
		s, ok := raw.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return leaseStorageConfig{}, fmt.Errorf("\"type\" must be a non-empty string, got %T", raw)
		}
		storageType = strings.ToLower(strings.TrimSpace(s))
	}

	switch storageType {
	case "memory":
		return leaseStorageConfig{}, nil

	case "file":
		path, ok := storageCfg["path"].(string)
		if !ok || strings.TrimSpace(path) == "" {
			return leaseStorageConfig{}, fmt.Errorf("\"path\" is required when \"type\" is \"file\"")
		}

		interval := 30 * time.Second
		if raw, ok := storageCfg["save_interval"]; ok {
			s, ok := raw.(string)
			if !ok {
				return leaseStorageConfig{}, fmt.Errorf("\"save_interval\" must be a duration string (e.g. \"30s\"), got %T", raw)
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return leaseStorageConfig{}, fmt.Errorf("\"save_interval\" %q is not a valid duration: %w", s, err)
			}
			if err := leasepkg.CheckSaveInterval(d); err != nil {
				return leaseStorageConfig{}, err
			}
			interval = d
		}
		return leaseStorageConfig{path: path, saveInterval: interval}, nil

	default:
		return leaseStorageConfig{}, fmt.Errorf("unrecognized \"type\" %q (expected \"memory\" or \"file\")", storageType)
	}
}

// selectLeaseStore reads which lease store a handler's Setup config selects: "lease_manager", a
// LeaseManager given directly (Go embedding only), or "storage", a config section
// (parseLeaseStorageConfig). The two are mutually exclusive; neither (both results nil) means
// the in-memory, no-persistence default. A value of the wrong type is an error.
func selectLeaseStore(cfg map[string]any) (given LeaseManager, storage *leaseStorageConfig, err error) {
	rawLeaseManager, lmPresent := cfg["lease_manager"]
	lmPresent = lmPresent && rawLeaseManager != nil
	rawStorage, storagePresent := cfg["storage"]
	storagePresent = storagePresent && rawStorage != nil

	switch {
	case lmPresent && storagePresent:
		return nil, nil, fmt.Errorf(`"lease_manager" and "storage" are mutually exclusive, got both`)

	case lmPresent:
		lm, ok := rawLeaseManager.(LeaseManager)
		if !ok || lm == nil {
			return nil, nil, fmt.Errorf("\"lease_manager\" must implement lease.LeaseStorage, got %T", rawLeaseManager)
		}
		return lm, nil, nil

	case storagePresent:
		storageCfg, ok := rawStorage.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("\"storage\" must be a map, got %T", rawStorage)
		}
		parsed, err := parseLeaseStorageConfig(storageCfg)
		if err != nil {
			return nil, nil, fmt.Errorf("storage: %w", err)
		}
		return nil, &parsed, nil

	default:
		return nil, nil, nil
	}
}

// LeaseStoreFromConfig returns the lease store a handler's Setup config selects
// (selectLeaseStore): the "lease_manager" given, one built from the "storage" section, or the
// in-memory default. A "file" store loads its snapshot, writes it straight back and keeps
// saving it (leasepkg.NewFileLeaseStore); logger receives its save errors. With readOnly, a
// "file" store is instead its snapshot as it is now, read into an in-memory store that never
// saves, and nothing is created or written: cmd/sig0lease's dump mode hands that to Setup as
// "lease_manager". Both handlers' Setup use it with readOnly false.
func LeaseStoreFromConfig(cfg map[string]any, logger *logging.Logger, readOnly bool) (LeaseManager, error) {
	given, storage, err := selectLeaseStore(cfg)
	switch {
	case err != nil:
		return nil, err

	case given != nil:
		logger.Debugf("Custom lease manager configured")
		return given, nil

	case storage == nil || storage.path == "":
		return NewInMemoryLeaseManager(), nil

	case readOnly:
		store, found, err := leasepkg.ReadSnapshotFile(storage.path)
		if err != nil {
			return nil, fmt.Errorf("storage: %w", err)
		}
		if !found {
			logger.Infof("No lease snapshot at %s yet: the store is empty", storage.path)
		}
		return store, nil

	default:
		store, err := leasepkg.NewFileLeaseStore(storage.path, storage.saveInterval, func(err error) {
			logger.Errorf("%v", err)
		})
		if err != nil {
			return nil, fmt.Errorf("storage: %w", err)
		}
		logger.Debugf("File lease store at %s, saved every %s", storage.path, storage.saveInterval)
		return store, nil
	}
}

// LeaseSnapshotPath returns the snapshot file of the file store a handler's Setup config
// selects (selectLeaseStore), or "" if it selects none. cmd/sig0lease checks the handlers'
// snapshot files with it before any Setup runs.
func LeaseSnapshotPath(cfg map[string]any) (string, error) {
	_, storage, err := selectLeaseStore(cfg)
	if err != nil || storage == nil {
		return "", err
	}
	return storage.path, nil
}
