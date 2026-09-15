## github.com/NetworkCommons/sig0lease/client
```
package client // import "github.com/NetworkCommons/sig0lease/client"

Package client provides DNS query functionality for testing and client use.

FUNCTIONS

func EffectiveLeaseDuration(resp *dns.Msg, requestedLease, requestedKeyLease uint32) (lease uint32, keyLease uint32)
    EffectiveLeaseDuration returns the LEASE and KEY-LEASE durations the client
    should use for expiry calculations. If the server response contains an
    UPDATE-LEASE option, those (possibly clamped) values are authoritative — the
    proxy applies its own LeasePolicy bounds and may grant less than what was
    requested for either value independently. Otherwise the originally-requested
    values are used. For the 4-byte variant (a single shared value), that value
    is used for both.

func ExpiryFromResponse(now time.Time, requestedLease, requestedKeyLease uint32, resp *dns.Msg) (dataExpiry, keyExpiry time.Time)
    ExpiryFromResponse computes the data-record and KEY expiration times using
    the server-granted LEASE and KEY-LEASE when present in the response.


TYPES

type Client struct {
	// Has unexported fields.
}
    Client represents a DNS client for sending queries.

func New(server string, protocol string, timeout time.Duration) *Client
    New creates a new DNS client.

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error)
    Query sends a DNS query and returns the response.

```

## github.com/NetworkCommons/sig0lease/client/srp
```
package srp // import "github.com/NetworkCommons/sig0lease/client/srp"

Package srp implements an RFC 9665 SRP requester: discovery, message building
(via pkg/srp), the RFC 9664 S5.2 refresh scheduler, and YXDOMAIN rename-retry.
This is the library plan D8 calls the deliverable; cmd/sig0lease-srp is a thin,
non-shipped dev/test CLI over it. Deliberately not a full RFC 9665 requester
(no mDNS-based default.service.arpa. discovery, no CNN transport handling --
both explicitly deferred, D5/D6) -- this targets the Phase 3 registrar's actual
supported shape: an explicitly configured zone, reached over TCP by default.

FUNCTIONS

func Discover(ctx context.Context, query SRVQuery, domain string) (string, error)
    Discover finds the SRP registrar for domain via a
    `_dnssd-srp._tcp.<domain>.` SRV lookup -- ordinary DNS-SD service
    discovery (RFC 6763), applied to bootstrap SRP itself, per RFC 9665's
    own discovery convention (see the plan's Appendix C zone skeleton's
    optional `_dnssd-srp._tcp` SRV record). Returns "host:port" for the best
    (lowest-priority, highest-weight-among-ties) answer. A caller with an
    explicit registrar address configured should skip this entirely (see
    Config.RegistrarAddr) -- discovery is the fallback, not the only path,
    matching D8's "dev/test tool" framing for cmd/sig0lease-srp.


TYPES

type Client struct {
	// Has unexported fields.
}
    Client is one SRP identity's registration lifecycle: build, sign, send,
    and (via Run) keep alive on the RFC 9664 S5.2 refresh clock, renaming on
    YXDOMAIN conflict.

func NewClient(cfg Config) (*Client, error)
    NewClient validates cfg, applies defaults, and generates a signing key if
    cfg.Key is nil.

func (c *Client) Deregister(ctx context.Context) (*dns.Msg, pkgsrp.Outcome, error)
    Deregister withdraws this identity's entire registration in one message:
    the host's address data (S3.3.1.3's "zero Add operations means delete this
    host's registration") and every configured service instance (each restated
    as a bare Delete-All, InstanceSpec.Remove). Matches S3.2's "no lightweight
    refresh" -- a removal is a normal UPDATE that restates everything, not a
    distinct wire operation. One-shot, like Register; there is no rename-retry
    equivalent since a removal can't conflict (FCFS only ever blocks an
    add-shaped instruction).

    Also requests LEASE=0. RFC 9665 S3.3.1.3's own removal signal is purely
    structural (zero address Adds), not lease-based -- RFC 9664's LEASE=0 Case
    C has no direct SRP analog, per this project's own earlier reading of
    the RFC text. But a real registrar (mDNSResponder/ServiceRegistration's
    srp-mdns-proxy, srp-parse.c's "does not include a host description" path)
    additionally requires host_lease==0 before it will recognize a zero-address
    host update as a removal at all -- confirmed by live interop testing
    (tests/test_mdnsresponder_interop.sh), not assumed. Sending LEASE=0 is still
    fully RFC 9665-conformant (a requester may request any lease value including
    0) and is required in practice for this to interoperate with that real
    implementation.

func (c *Client) Register(ctx context.Context) (*dns.Msg, pkgsrp.Outcome, error)
    Register performs exactly one build-sign-send-interpret cycle:
    no rename-retry, no scheduling. Callers wanting the full lifecycle (initial
    delay, refresh clock, automatic rename-retry) should use Run instead;
    Register is the primitive Run is built from, and is also useful standalone
    for a one-shot CLI invocation.

func (c *Client) Run(ctx context.Context) error
    Run performs the full RFC 9665 requester lifecycle: an initial 0-3s random
    delay (plan roadmap), then registers (with rename-retry on conflict),
    then sleeps for the RFC 9664 S5.2 refresh clock (80% of the granted lease +
    0-5% jitter) and re-registers -- restating the full registration every time,
    per S3.2's "no lightweight refresh." Blocks until ctx is canceled or a
    non-recoverable error occurs (discovery failure, rename attempts exhausted,
    a registrar rejection Register can't interpret as a conflict).

type Config struct {
	Domain    string // registration domain (Zone Section name); trailing dot optional
	HostLabel string // base host label -- see InstanceConfig's doc comment
	Addresses []netip.Addr
	Instances []InstanceConfig

	// Key is this identity's SIG(0) signing key. Nil generates a fresh P-256 key at
	// NewClient (D7's default) -- SRP identities are typically ephemeral/device-local, so
	// generating rather than requiring a pre-provisioned keystore file is the common case.
	Key *keyrec.LoadedKey

	RequestedLease    uint32 // default 3600 (1h)
	RequestedKeyLease uint32 // default 1209600 (14d, S3.4's "typically 14 days")

	// RegistrarAddr, if set, bypasses discovery entirely -- an explicit "host:port",
	// matching every other test/dev client this project's test suite already uses.
	// Discovery (Domain's `_dnssd-srp._tcp` SRV) is the fallback when this is empty.
	RegistrarAddr string
	Resolvers     []string // bootstrap resolvers for discovery; LiveSRVQuery's default if empty
	Query         SRVQuery // discovery implementation; LiveSRVQuery(Resolvers) if nil

	UseTCP     bool          // default true (S3.5's MUST for non-constrained networks)
	Timeout    time.Duration // per-request transport timeout; default 20s
	MaxRenames int           // default 5 -- rename-retry attempts before giving up on YXDOMAIN

	Send  Transport                                  // default liveTransport(Timeout)
	Rng   *rand.Rand                                 // default a fresh per-Client source (see timing.go's doc comments)
	Sleep func(context.Context, time.Duration) error // default ctxSleep
}
    Config configures a Client. See NewClient's doc comment for defaults.

type InstanceConfig struct {
	Label       string   // single label, e.g. "MyPrinter" -- not a full instance name
	ServiceType string   // e.g. "_ipps._tcp" -- not a full service-type name
	Subtypes    []string // additional bare subtype labels, e.g. "_universal"
	Port        uint16
	TXT         []string
}
    InstanceConfig describes one service instance to register, in the same
    "label relative to Domain" terms as HostLabel -- Client joins these into
    fully-qualified names when building the update (pkg/srp.BuildUpdate itself
    takes only already-qualified names).

type SRVQuery func(ctx context.Context, name string) ([]*dns.SRV, error)
    SRVQuery is the shape of a live SRV lookup, injected so Discover is testable
    without real network I/O. Returns the answer's SRV records (possibly none),
    in whatever order the server returned them.

func LiveSRVQuery(resolvers []string) SRVQuery
    LiveSRVQuery returns an SRVQuery that performs a real SRV lookup against
    resolvers (falling back to defaultBootstrapResolvers if empty), trying each
    in turn until one answers with NOERROR.

type Transport func(ctx context.Context, addr string, useTCP bool, msg *dns.Msg) (*dns.Msg, error)
    Transport sends a signed SRP UPDATE to addr and returns the response.
    Config.Send defaults to a real network implementation (see liveTransport);
    tests inject a fake.

```

## github.com/NetworkCommons/sig0lease/cmd/sig0lease
```
Package main implements the DNS proxy server.
```

## github.com/NetworkCommons/sig0lease/cmd/sig0lease-client
```
Package main implements a sig0lease client for sending UPDATE-LEASE requests
with SIG(0) authentication to the sig0lease proxy.
```

## github.com/NetworkCommons/sig0lease/cmd/sig0lease-srp
```
Package main implements sig0lease-srp, a thin CLI over client/srp -- a dev/test
tool (plan D8), not a shipped product. The library is the deliverable; this just
exercises it.
```

## github.com/NetworkCommons/sig0lease/config
```
package config // import "github.com/NetworkCommons/sig0lease/config"

Package config provides configuration for the DNS proxy.

TYPES

type Config struct {
	// Downstream server settings
	Server ServerConfig `yaml:"server"`

	// Upstream resolver settings
	Upstreams []UpstreamConfig `yaml:"upstreams"`

	// Opcode processing rules - opcodes listed here are processed by modules
	ProcessingRules []ProcessingConfig `yaml:"processing_rules"`

	// Handler-specific configuration (e.g., for update handler)
	Handlers map[string]map[string]interface{} `yaml:"handlers"`
}
    Config is the top-level configuration structure.

func LoadConfig(path string) (*Config, error)
    LoadConfig reads configuration from a file.

func NewDefaultConfig() *Config
    NewDefaultConfig returns a configuration with sensible defaults.

func (c *Config) GetKeystoreDir() string
    GetKeystoreDir returns the keystore directory from handler configuration.
    Returns empty string if not configured.

func (c *Config) GetOpcodeMap() map[uint8][]string
    GetOpcodeMap creates a map from opcode to its ordered module list for fast
    lookup (D2).

func (c *Config) Use4ByteVariant() bool
    Use4ByteVariant returns true if 4-byte variant is explicitly enabled via
    config. Returns false by default (8-byte variant is the default for all
    lease requests).

func (c *Config) Validate() error
    Validate checks that the configuration is valid.

type ProcessingConfig struct {
	// Opcode is the DNS opcode to match (0=QUERY, 1=IQUERY, 2=STATUS, etc.)
	Opcode uint8 `yaml:"opcode"`
	// Modules is the ordered list of processing module names to try for this opcode
	// (D2, main/docs/rfc9665-srp-implementation-plan.md S4.2): the router calls each
	// in turn until one returns Processed or Error; if every one declines (NotRelevant),
	// the opcode falls through to plain upstream forwarding. A single-module list (the
	// common case today, e.g. just "update_handler") behaves exactly as the old
	// single-"module" field did.
	Modules []string `yaml:"modules"`
}
    ProcessingConfig holds opcode-specific processing configuration.

type ServerConfig struct {
	// Address is the address to listen on (e.g., ":53")
	Address string `yaml:"address"`
	// Networks are the network protocols to enable ("udp", "tcp", "tls")
	Networks []string `yaml:"networks"`
	// TLS configures the "tls" network (DNS-over-TLS, RFC 7858, plan S7/Phase 7):
	// opportunistic only, no client-certificate/key-pinning auth -- transport-level, so it
	// benefits every handler (base RFC 9664, SRP, plain forwarding alike), not just one
	// protocol. Required when "tls" appears in Networks; ignored otherwise.
	TLS *TLSConfig `yaml:"tls,omitempty"`
}
    ServerConfig holds server listening configuration.

type TLSConfig struct {
	// Address is the DoT listener's own address (e.g., ":853").
	Address string `yaml:"address"`
	// Cert is the path to a PEM-encoded certificate (or certificate chain).
	Cert string `yaml:"cert"`
	// Key is the path to the PEM-encoded private key matching Cert.
	Key string `yaml:"key"`
}
    TLSConfig holds the DNS-over-TLS listener's own address and certificate.
    A separate Address (rather than reusing ServerConfig.Address) because DoT
    conventionally listens on its own port (853, RFC 7858) alongside plain
    DNS on 53 -- binding both to one address would collide, since they're two
    independent net.Listeners either way.

type UpstreamConfig struct {
	// Address is the upstream DNS server address (e.g., "8.8.8.8:53")
	Address string `yaml:"address"`
	// Protocol is the protocol to use ("udp", "tcp", "tls", "https")
	Protocol string `yaml:"protocol"`
	// Timeout for upstream queries
	Timeout time.Duration `yaml:"timeout"`
}
    UpstreamConfig holds upstream resolver configuration.

```

## github.com/NetworkCommons/sig0lease/forward
```
package forward // import "github.com/NetworkCommons/sig0lease/forward"

Package forward implements DNS forwarding to upstream resolvers.

TYPES

type Resolver struct {
	// Has unexported fields.
}
    Resolver forwards DNS queries to upstream servers. NOTE: servers is a list,
    but protocol and timeout are single shared values, applied to every
    server -- config.yaml lets each upstream declare its own, but only
    server/server.go's New() picks one upstream's values for the whole pool (see
    the NOTE there). Not fixed here since per-server protocol/timeout would need
    a real API change to this struct.

func NewResolver(servers []string, protocol string, timeout time.Duration) (*Resolver, error)
    NewResolver creates a new DNS resolver that forwards to upstream servers.

func (r *Resolver) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
    Query sends a DNS query to all upstream servers and returns the first
    response.

func (r *Resolver) Shutdown()
    Shutdown gracefully stops the resolver.

type Result struct {
	Response *dns.Msg
	Error    error
}
    Result represents the outcome of a forwarded query.

```

## github.com/NetworkCommons/sig0lease/handlers
```
package handlers // import "github.com/NetworkCommons/sig0lease/handlers"

Package handlers provides opcode-specific processing modules for the DNS proxy.

Package handlers provides opcode-specific processing modules.

Package handlers provides result types for handler responses.

TYPES

type BaseHandler struct {
	// Has unexported fields.
}
    BaseHandler provides common functionality for handlers.

func (b *BaseHandler) CanHandle(opcode uint8) bool
    CanHandle returns true if this handler handles the given opcode.

func (b *BaseHandler) Name() string
    Name returns the handler's name.

func (b *BaseHandler) SetLogger(logger *logging.Logger)
    SetLogger sets the logger for this handler.

func (b *BaseHandler) Shutdown()
    Shutdown is a no-op default; handlers that own no resources needing release
    on shutdown do not need to override it.

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
    Handler is an interface for a DNS processing module.

type HandlerResult struct {
	// Status indicates whether the packet was processed or if router should take default routing path.
	Status HandlerStatus

	// Message is the DNS response message.
	// For StatusProcessed or StatusError, this is sent to the client.
	// For StatusNotRelevant, this may be nil (router will use default routing).
	Message *dns.Msg

	// Reason is a human-readable explanation of the status (useful for logging).
	Reason string

	// Error is the underlying error (if any).
	Error error
}
    HandlerResult encapsulates a handler's response and status code.

func NewErrorResult(msg *dns.Msg, reason string, err error) *HandlerResult
    NewErrorResult creates a result indicating an error occurred.

func NewNotRelevantResult(reason string) *HandlerResult
    NewNotRelevantResult creates a result indicating the packet is not relevant
    to this handler.

func NewProcessedResult(msg *dns.Msg) *HandlerResult
    NewProcessedResult creates a result indicating successful processing.

type HandlerStatus uint8
    HandlerStatus represents the result of a handler's processing attempt.

const (
	// StatusProcessed indicates the handler successfully processed the packet
	// and the response should be sent to the client.
	StatusProcessed HandlerStatus = iota

	// StatusNotRelevant indicates the handler determined this packet is not
	// relevant to its protocol (e.g., UPDATE without UPDATE-LEASE EDNS option).
	// The router should apply its default upstream routing.
	StatusNotRelevant

	// StatusError indicates the handler encountered an error.
	// The response contains error details and should be sent to the client.
	StatusError
)
func (s HandlerStatus) String() string
    String returns a human-readable name for the status.

type InMemoryLeaseManager = leasepkg.InMemoryLeaseStore
    InMemoryLeaseManager is a reusable in-memory lease manager implementation.

func NewInMemoryLeaseManager() *InMemoryLeaseManager
    NewInMemoryLeaseManager creates a new in-memory lease manager.

type LeaseManager = leasepkg.LeaseStorage
    LeaseManager is the shared lease manager abstraction.

type LeasePolicy struct {
	MinKeyLease uint32
	MaxKeyLease uint32
	MinRRLease  uint32
	MaxRRLease  uint32
}
    LeasePolicy controls clamping for lease durations and forwarded RR TTLs.

type LeaseRecord = leasepkg.Record
    LeaseRecord is the shared lease state record used by handlers.

type NonKEYLeaseRecord = leasepkg.NonKEYRecordSet
    NonKEYLeaseRecord is the non-KEY equivalent of LeaseRecord: an alias
    straight onto pkg/lease's own type, rather than a second, hand-maintained
    copy of the same shape. leaseManager.GetNonKEYRecordSet already returns
    cloned data, so there is nothing left for a handlers-local wrapper type to
    add. Its Records map's value type (*leasepkg.NonKEYRecord) is used directly
    wherever a single entry is needed, rather than a second alias.

type SRPHandler struct {
	BaseHandler

	LeasePolicy LeasePolicy

	// Has unexported fields.
}
    SRPHandler implements handlers.Handler for opcode 5 (UPDATE), the RFC 9665
    SRP path -- a sibling to UpdateHandler (D1), never a branch inside it:
    SRP's message shape and authorization model (FCFS, delete-all-then-add,
    no per-record parent/key walk) contradict two of UpdateHandler's own checks
    (validateSignerHierarchyForUpdateRecords, filterDuplicateRegistrations),
    so it needs its own Handle() rather than a mode flag on the existing one.
    See main/docs/rfc9665-srp-implementation-plan.md S4 for the design this
    implements; comments below cite it as "S<n>" for RFC 9665 sections and "plan
    S<n>" for the plan document's own sections.

func NewSRPHandler() *SRPHandler
    NewSRPHandler creates a new handler for opcode 5 (UPDATE), RFC 9665 SRP
    path.

func (h *SRPHandler) DumpLeasesLevel(level string) string
    DumpLeasesLevel implements the same dump-endpoint interface UpdateHandler
    does (see server/router.go's handleDumpQuery), so SRP-managed state shows up
    in the same __dump.sig0lease.internal[.debug] query operators already use.
    A simpler format than UpdateHandler's tree-indented dump -- flat,
    one section per node -- since SRP's tree shape (documented in the plan S4.4)
    doesn't need the same visual nesting to be legible.

func (h *SRPHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult
    Handle implements the plan's S4.3 ten-step happy path. Every early-return
    before step 7 (forwarding) touches neither the lease store nor the network,
    so a rejected request leaves no trace to clean up.

func (h *SRPHandler) Setup(cfg map[string]any) error
    Setup initializes the SRP handler configuration.

    Configuration options:
      - "upstream_zone": the one zone this handler instance serves (D10:
        one zone, one protocol) [REQUIRED]
      - "keystore_dir": directory holding this proxy's own SIG(0) signing keys
        [REQUIRED]
      - "upstream": a static "host:port" override for upstream_zone (D4) -- when
        set, skips SOA/NS discovery entirely for this zone. [OPTIONAL]
      - "bootstrap_resolvers": []string of resolver addresses used to resolve
        SOA/NS records when "upstream" is not set. [OPTIONAL]
      - "allow_udp": permit UDP for this zone (plan S7/D6 -- TCP is required by
        default, for non-CNN zones this proxy targets). [OPTIONAL, defaults to
        false]
      - "rewrite_default_service_arpa": accept requests whose Zone Section
        is literally "default.service.arpa." (real SRP clients hardcode
        this name -- they have no way to discover any other zone, D5) *in
        addition to* upstream_zone, rewriting every name in the update to
        upstream_zone before FCFS/forwarding so the rest of the pipeline (and
        the authoritative server) never sees default.service.arpa. at all.
        The response still echoes back default.service.arpa., matching what the
        client itself sent. [OPTIONAL, defaults to false]
      - "refuse_on_foreign_data": RFC 9665 S3.3.3's NOERROR-no-KEY case -- true
        refuses the update (REFUSED) when a name exists at the authoritative
        server with data but no KEY; false lets the delete-all-then-add clobber
        it. [OPTIONAL, defaults to true]
      - "lease_policy": bounds applied to granted LEASE/KEY-LEASE, same shape as
        the base handler's. [OPTIONAL]
      - "lease_manager" / "storage": same mutually-exclusive lease-store backend
        selection as UpdateHandler.Setup -- see that method's doc comment
        for the full shape. [OPTIONAL, defaults to an in-memory store with no
        persistence]

type UpdateHandler struct {
	BaseHandler

	LeasePolicy LeasePolicy

	// AllowOnlineKeyRegistration controls whether a signer resolved only via
	// authoritative DNS (not in the lease store, not present anywhere in the
	// request) may authorize registration of new KEY RRs. Such a signer can
	// always be used for SIG(0) verification and for deletes; this flag only
	// gates whether it may also be used to create new managed state. Default
	// false (fail closed).
	AllowOnlineKeyRegistration bool

	// Has unexported fields.
}
    UpdateHandler handles DNS opcode 5 (UPDATE queries).

    This implementation supports the following features:
      - Basic key registration with 8-byte lease EDNS(0) option (RFC 9664)
      - SIG(0) client authentication (RFC 2931)
      - In-memory lease tracking with configurable persistence hooks
      - Future SRP support

func NewUpdateHandler() *UpdateHandler
    NewUpdateHandler creates a new handler for opcode 5 (UPDATE) queries.

func (h *UpdateHandler) DumpLeases() string
    DumpLeases is a convenience method that returns the full DEBUG-level dump.
    Deprecated: use DumpLeasesLevel("debug") instead.

func (h *UpdateHandler) DumpLeasesLevel(level string) string
    DumpLeasesLevel returns lease state dump at the specified log level.
    Supported levels: "debug" (full dump), "info" (summary), anything else =
    "info".

    DEBUG format (full dump):

        === Lease Store Dump ===
        KEY lease: <keyName>
          KeyRR: <dns.KEY string>
          ExpiresAt: <time>
          LeaseDuration: <seconds>s
          KeyLeaseDuration: <seconds>s
          UpstreamZone: <zone>
          RegisteredAt: <time>
        Non-KEY lease: <keyName>
          Records:
            <recordKey>
              RR: <dns.RR string>
              ExpiresAt: <time>
              LeaseDuration: <seconds>s
          ExpiresAt: <time>
          LeaseDuration: <seconds>s
          UpstreamZone: <zone>

    INFO format (summary):

        === Lease Store Summary ===
        Key: <keyName>  KEY=<active|expired|absent>  NonKEY=<count>  Status=<active|empty|absent>

    Keys that appear only in the KEY lease (no non-KEY lease) represent KEY-only
    registrations. Keys that appear only in the non-KEY lease (no KEY lease)
    represent non-KEY-only refreshes. Keys that appear in both have an active
    KEY + non-KEY RR lease.

func (h *UpdateHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult

func (h *UpdateHandler) Setup(cfg map[string]any) error
    Setup initializes the handler configuration.

    Configuration options:
      - "upstream_zone": Authoritative zone (e.g., "dev.zenr.io.") [REQUIRED]
      - "upstream_key": Path to upstream private key file [OPTIONAL, needed for
        upstream UPDATE signing]
      - "upstream_coordinator": Custom UpstreamCoordinator implementation
        [OPTIONAL]
      - "bootstrap_resolvers": []string of resolver addresses (e.g.
        "8.8.8.8:53") used by the default upstream coordinator to look up SOA/NS
        records when locating the authoritative server for a zone [OPTIONAL,
        ignored when "upstream_coordinator" is set]. cmd/sig0lease/main.go
        populates this from the top-level "upstreams" config when not
        set explicitly here, so zone-authority resolution uses the same
        operator-configured resolvers as generic forwarding. Falls back to a
        small built-in default if unset.
      - "lease_manager": Custom LeaseManager implementation [OPTIONAL, defaults
        to InMemoryLeaseManager]. Go-embedding only: a LeaseManager value,
        not expressible in YAML, so this can only be set by code constructing
        the cfg map directly, never via config.yaml. A present-but-wrong-type
        value is a Setup error, not a silently-ignored one. Mutually exclusive
        with "storage" below.
      - "storage": Selects the lease storage backend [OPTIONAL,
        config-file-settable, defaults to an in-memory store with no
        persistence]. Mutually exclusive with "lease_manager". Shape: {"type":
        "memory"|"file", "path": "...", "save_interval": "30s"}. "type" defaults
        to "memory" if omitted -- identical to today's default behavior,
        leases are lost on restart. "file" additionally requires "path" and
        persists a human-readable JSON snapshot there: loaded once on Setup
        (a corrupt existing file is a hard Setup error), saved periodically on
        "save_interval" (default 30s), and flushed once more on Shutdown().
        Any unrecognized "type", or "file" missing "path", is a Setup error.
      - "persistence_hook": Persistence function for leases [OPTIONAL]. Same
        Go-embedding-only caveat as lease_manager: a func value, not settable
        from config.yaml.
      - "lease_policy": Bounds applied to local lease durations and forwarded RR
        TTLs [OPTIONAL]
      - "prefer_4byte_variant": Enable 4-byte variant for backward compatibility
        [OPTIONAL, defaults to false]
      - "allow_online_key_registration": Allow a signer resolved only via
        authoritative DNS (not lease-managed, not present in the request) to
        register new KEY RRs [OPTIONAL, defaults to false]

func (h *UpdateHandler) Shutdown()
    Shutdown stops the reconciliation ticker and releases the lease storage
    backend's own resources (e.g. a file-backed store's periodic-save goroutine,
    which also performs one final synchronous save here). Safe to call once
    during server shutdown; overrides BaseHandler's no-op default.

type UpstreamCoordinator interface {
	// SendUpdate sends a DNS UPDATE message to the upstream authoritative server.
	// Returns the response message or an error.
	SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error)
}
    UpstreamCoordinator handles communication with the upstream authoritative
    server. pkg/updatecore.Coordinator is the production implementation,
    constructed directly in Setup (below) via updatecore.NewCoordinator
    -- this interface exists so tests and operators can substitute their
    own (config's "upstream_coordinator" option, or a test stub; see
    handlers/opcode5_sig0_validation_test.go's stubUpstreamCoordinator).

```

## github.com/NetworkCommons/sig0lease/logging
```
package logging // import "github.com/NetworkCommons/sig0lease/logging"

Package logging provides structured logging for the DNS proxy.

Every Logger produced by this package renders records through the same
uniformHandler, so the on-disk format is defined in exactly one place:

    2026/08/20 10:39:44.164+02:00 -- INFO -- "message"

The only thing callers may vary between Logger instances is the minimum level
(e.g. to run one module at "debug" while the rest stay at "info"); the format
itself is not configurable per instance.

TYPES

type Logger struct {
	// Has unexported fields.
}
    Logger wraps slog.Logger with convenience methods including Debugf.

func NewLogger(level string) *Logger
    NewLogger creates a new logger instance writing the package's single
    canonical log format to stdout. level is the only setting that may differ
    between instances (e.g. a per-module override), so that every logger in the
    process stays uniformly formatted.

func (l *Logger) Debug(msg string, keysAndValues ...any)
    Debug logs a debug message.

func (l *Logger) Debugf(format string, args ...any)
    Debugf logs a debug message with format.

func (l *Logger) Error(msg string, keysAndValues ...any)
    Error logs an error message.

func (l *Logger) Errorf(format string, args ...any)
    Errorf logs an error message with format.

func (l *Logger) Info(msg string, keysAndValues ...any)
    Info logs an info message.

func (l *Logger) Infof(format string, args ...any)
    Infof logs an info message with format.

func (l *Logger) Warn(msg string, keysAndValues ...any)
    Warn logs a warning message.

func (l *Logger) Warnf(format string, args ...any)
    Warnf logs a warning message with format.

```

## github.com/NetworkCommons/sig0lease/pkg/dnscompat
```
package dnscompat // import "github.com/NetworkCommons/sig0lease/pkg/dnscompat"

```

## github.com/NetworkCommons/sig0lease/pkg/dnsmsg
```
package dnsmsg // import "github.com/NetworkCommons/sig0lease/pkg/dnsmsg"


FUNCTIONS

func NewLeaseUpdate(zone string, keyRRs []*dns.KEY, additional []dns.RR, leaseDuration, keyLeaseDuration uint32) (*dns.Msg, error)
    NewLeaseUpdate builds a DNS UPDATE registration message with one optional
    KEY RR, optional additional RRs, and an 8-byte UPDATE-LEASE option.

func ParseAdditionalRRSpec(spec string) (dns.RR, error)
    ParseAdditionalRRSpec parses a DNS RR in standard presentation format.

    Required form:

        owner ttl class type rdata...

```

## github.com/NetworkCommons/sig0lease/pkg/keyrec
```
package keyrec // import "github.com/NetworkCommons/sig0lease/pkg/keyrec"


FUNCTIONS

func FindKeysByZone(keystoreDir, zoneName string, logger *logging.Logger) ([]string, error)
    FindKeysByZone searches for keys by zone name in the keystore. Returns the
    key names. possibly none. First searches ED25519 (algorithm 15) and then
    other algorithms. Provenance: Inspired by sig0namectl's LoadOrGenerateKey()

func KeyExists(keystoreDir, keyName string, logger *logging.Logger) error
    KeyExists searches for a key by filename without .key in the keystore.
    Returns the key name or error if none found.

func ListKeysInDirectory(keystoreDir string, logger *logging.Logger) ([]string, error)
    ListKeysInDirectory lists all key names in a keystore directory. logger may
    be nil (no logging); when non-nil and no keys are found, the current working
    directory is logged too, since keystoreDir is often a relative path and an
    empty result is frequently caused by it resolving against an unexpected CWD.
    Provenance: Adapted from sig0namectl's ListKeys() in keys_nowasm.go


TYPES

type LoadedKey struct {
	// Name is the base filename without extensions (e.g., "Kzone.+015+12345")
	Name string

	// PublicKey is the parsed KEY RR from the .key file
	PublicKey *dns.KEY

	// PrivateKey is the parsed private key material for signing
	PrivateKey crypto.PrivateKey
}
    LoadedKey represents a fully loaded key with private key material for
    signing.

func GenerateKey(name string, algorithm uint8, flags uint16, bits int) (*LoadedKey, error)
    GenerateKey creates a fresh SIG(0) key pair for name (the KEY RR's owner
    name) at the given algorithm and flags, entirely in memory -- no keystore
    directory, no files written. Uses the same codeberg.org/miekg/dns fork
    Generate/PrivateKeyString round-trip LoadKeyFromFile itself reads back (see
    loader.go), so a key from here is guaranteed loadable by anything that reads
    the on-disk key file format, if a caller chooses to persist it later (see
    (*LoadedKey).SaveToFile).

    bits follows dns.DNSKEY.Generate's own convention (algorithm-specific: 256
    for ECDSAP256SHA256 or ED25519, 384 for ECDSAP384SHA384); 0 lets Generate
    error out for an algorithm requiring an explicit size (RSA).

func LoadKeyFromFile(keystoreDir, keyName string) (*LoadedKey, error)
    LoadKeyFromFile loads a DNSSEC key from keystore files. Provenance:
    Adapted from sig0namectl's LoadKeyFile() approach Expects files:
    <keystoreDir>/<keyName>.key and <keystoreDir>/<keyName>.private Uses
    codeberg.org/miekg/dns v0.6.82 API

func (lk *LoadedKey) Algorithm() uint8
    Algorithm returns the DNSSEC algorithm number

func (lk *LoadedKey) AlgorithmName() string
    AlgorithmName returns a string name for the algorithm

func (lk *LoadedKey) KeyFileName() string
    KeyFileName returns the formatted key filename for this record (without
    extensions)

func (lk *LoadedKey) KeyName() string
    KeyName returns the key name

func (lk *LoadedKey) KeyTag() uint16
    KeyTag returns the key tag from the public key

func (lk *LoadedKey) Print()
    Print key info

func (lk *LoadedKey) SaveToFile(dir string) error
    SaveToFile writes lk to <dir>/<lk.Name>.key and <dir>/<lk.Name>.private,
    in the same format LoadKeyFromFile reads. dir must already exist.

func (lk *LoadedKey) String() string
    String returns a human-readable representation

```

## github.com/NetworkCommons/sig0lease/pkg/lease
```
package lease // import "github.com/NetworkCommons/sig0lease/pkg/lease"

Package lease implements the Update Lease EDNS(0) option per RFC 9664.

CONSTANTS

const (
	// OPTION_CODE is the EDNS(0) option code for Update Lease
	OPTION_CODE = 2

	// MAX_LEASE is the maximum lease value (2^32-1)
	MAX_LEASE = 0xFFFFFFFF

	// MAX_KEY_LEASE is the maximum key-lease value
	MAX_KEY_LEASE = 0xFFFFFFFF
)

FUNCTIONS

func FindOption(msg *dns.Msg) (*dns.ERFC3597, bool)
    FindOption scans msg's Pseudo and Extra sections for the raw UPDATE-LEASE
    EDNS(0) option (RFC 9664 Section 4, option code 2), accepting both a bare
    ERFC3597 RR and one nested inside an OPT RR's Options. This is the single
    place that knows where to look; server and client callers each layer their
    own validation/policy on top of the decoded result.

func NodeKey(k *dns.KEY) string
    NodeKey returns the canonical composite lease-store key for a KEY RR.
    Format: dnsname.+algo+keytag (same convention as BIND key files).

func NodeKeyFromSIG(signerName string, algorithm uint8, keyTag uint16) string
    NodeKeyFromSIG computes the composite lease-store key from SIG(0) signer
    fields.

func RecordKey(rr dns.RR) string
    RecordKey returns the canonical, globally unique identity for a non-KEY
    RR's lease-store node, per RFC 2136 - 1.1 - Comparison Rules: two RRs are
    equal if their NAME, CLASS, TYPE, RDLENGTH, and RDATA fields are equal.
    The TTL field is explicitly excluded from the comparison.

    Special RR types (rfc2136 - 1.1 - Comparison Rules):

        SOA:   compare only NAME, CLASS, TYPE (only one SOA per zone)
        CNAME: compare only NAME, CLASS, TYPE (only one CNAME per name)
        WKS:   compare only NAME, CLASS, TYPE, ADDRESS, PROTOCOL (services mask
               excluded). The dns library does not provide support for WKS RRs
               (no dns.WK type, no TypeWKS constant), so there is no proper
               parser for the RDATA; the full data string is used instead, which
               may include the services mask -- not fully RFC 2136 compliant for
               WKS, but there is no better option available.

    This is the one function that must be used everywhere a non-KEY record's
    identity is computed -- the store's own keys, duplicate/ownership checks,
    and deletion-by-key all have to agree on the same string for the same RR,
    or a lookup with different casing than what was stored silently misses.


TYPES

type BaseRecord struct {
	NodeKind      NodeKind
	RRType        uint16
	ExpiresAt     time.Time
	LeaseDuration uint32
	RegisteredAt  time.Time
	ParentKeyName string
}
    BaseRecord is the shared lease node model used by KEY and non-KEY records.

type FileLeaseStore struct {
	*InMemoryLeaseStore

	// Has unexported fields.
}
    FileLeaseStore is a LeaseStorage backend that keeps the full lease tree
    in memory (via the embedded *InMemoryLeaseStore, which supplies every
    LeaseStorage data method) and additionally persists it as human-readable
    JSON using the existing SaveSnapshot/LoadSnapshot mechanism: once on
    construction (load-on-start), on a periodic ticker, and once more,
    synchronously, on Stop() (flush-on-shutdown).

func NewFileLeaseStore(path string, saveInterval time.Duration, onSaveError func(error)) (*FileLeaseStore, error)
    NewFileLeaseStore creates a file-backed lease store.

      - path's parent directory is created (including any missing ancestors)
        if it does not already exist. Failure to create it is a hard
        construction-time error, not a silent fallback to some other location.
      - If a file already exists at path, it is loaded immediately. A present
        but corrupt/unparseable file is a hard error -- data loss must be loud,
        never silently treated as "start empty".
      - If no file exists yet, the store starts empty.
      - Either way, NewFileLeaseStore performs one synchronous save to path
        before returning, so an unwritable path/directory is also a hard
        construction-time error rather than a silent background failure
        discovered only much later on the first periodic tick.
      - onSaveError is invoked (from the background goroutine, and once more
        from Stop()) if a later periodic or final save fails. It may be nil,
        in which case such failures are dropped.

func (fs *FileLeaseStore) Stop()
    Stop stops the periodic-save goroutine and performs one final synchronous
    save so state as of Stop() is not lost. Safe to call more than once
    (only the first call does anything). This overrides the embedded
    InMemoryLeaseStore's no-op Stop() by ordinary Go method-shadowing.

type InMemoryLeaseStore struct {
	// Has unexported fields.
}
    InMemoryLeaseStore is an in-memory lease manager implementation.

    KEY nodes (leases) and non-KEY nodes (nonKeyRecords) are each a flat map
    keyed by the node's own globally unique identity -- the same shape for both,
    so two attempts to register the identical identity (a KEY, or a non-KEY RR
    under a different owner) collide at the map itself instead of requiring
    every caller to remember to check first. children records parent/child edges
    for both kinds of node together: a KEY's children can be further KEY nodes
    or non-KEY nodes; a non-KEY node's entry in children is always absent,
    since it can never be a parent.

    The store never deletes anything on its own initiative: expiry is
    a handler-level concern, because only the handler can also send the
    corresponding upstream DNS delete. A store-driven timer here would race
    the handler's own precise per-node timer and — whichever fired first —
    silently erase local state without ever notifying the authoritative server.
    See UpdateHandler.reconcileLeaseTimers for the single, upstream- aware path
    that owns expiry.

func NewInMemoryManager() *InMemoryLeaseStore
    NewInMemoryManager creates a new in-memory lease manager.

func (m *InMemoryLeaseStore) ChildrenOf(nodeKey string) []string
    ChildrenOf returns the composite node keys of direct children (KEY or
    non-KEY) of the exact composite nodeKey.

func (m *InMemoryLeaseStore) Delete(nodeKey string) error

func (m *InMemoryLeaseStore) DeleteSubtree(nodeKey string) error
    DeleteSubtree removes the subtree rooted at the exact composite nodeKey.

func (m *InMemoryLeaseStore) ExportSnapshot() (*LeaseTreeSnapshot, error)

func (m *InMemoryLeaseStore) FindByName(dnsName string) []*Record

func (m *InMemoryLeaseStore) Get(nodeKey string) *Record
    Get returns the record for the exact composite nodeKey, including expired
    records.

func (m *InMemoryLeaseStore) GetNonKEYRecordSet(ownerNodeKey string) *NonKEYRecordSet
    GetNonKEYRecordSet returns a point-in-time, cloned view of the non-KEY
    records owned by ownerNodeKey, or nil if it owns none.

func (m *InMemoryLeaseStore) ImportSnapshot(snapshot *LeaseTreeSnapshot) error

func (m *InMemoryLeaseStore) ListAll() []*Record

func (m *InMemoryLeaseStore) ListExpiring(within time.Duration) []*Record

func (m *InMemoryLeaseStore) ListSubtreeKeys(nodeKey string) []string
    ListSubtreeKeys returns composite node keys of all descendants (KEY and
    non-KEY alike) of nodeKey, deepest first.

func (m *InMemoryLeaseStore) LoadSnapshot(path string) error

func (m *InMemoryLeaseStore) LookupByKEY(k *dns.KEY) *Record

func (m *InMemoryLeaseStore) LookupBySIG(signerName string, algorithm uint8, keyTag uint16) *Record

func (m *InMemoryLeaseStore) LookupNonKEYRecord(rr dns.RR) *NonKEYRecord
    LookupNonKEYRecord returns the record matching rr's RFC 2136 identity
    anywhere in the store, regardless of owner, or nil if none exists.

func (m *InMemoryLeaseStore) Register(ctx context.Context, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
    Register creates or updates a KEY lease. Node identity is derived from
    keyRR.

func (m *InMemoryLeaseStore) RegisterWithParent(ctx context.Context, parentNodeKey string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
    RegisterWithParent creates or updates a KEY lease with an optional parent
    composite node key.

func (m *InMemoryLeaseStore) RemoveNonKEYRecords(ownerNodeKey string)
    RemoveNonKEYRecords removes every non-KEY record owned by ownerNodeKey. KEY
    children of ownerNodeKey (if any) are untouched -- this only ever removes
    non-KEY records, never cascades into a KEY subtree.

func (m *InMemoryLeaseStore) RemoveSingleNonKEYRecord(ownerNodeKey, rrKey string) error
    RemoveSingleNonKEYRecord removes the record identified by rrKey, leaving
    the rest of ownerNodeKey's records untouched. Idempotent: a missing record
    is a no-op, not an error (deleting something already gone -- e.g. a caller
    racing its own earlier removal of the same record -- has already reached its
    desired end state). Returns an error, without effect, if the record exists
    but is owned by a different node: a caller passing a mismatched owner is a
    bug worth surfacing loudly rather than silently deleting nothing (or, worse,
    the wrong thing).

func (m *InMemoryLeaseStore) RenewLease(ctx context.Context, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32) error
    RenewLease extends an already-registered KEY lease's timers in place.
    Unlike Register/RegisterWithParent, it never rebuilds the node: it leaves
    ParentKeyName, RegisteredAt, and the node's position in the tree completely
    untouched, since renewing a lease is not re-creating it.

func (m *InMemoryLeaseStore) SaveSnapshot(path string) error

func (m *InMemoryLeaseStore) SetPersistenceHook(hook func(ctx context.Context, op string, record *Record) error)

func (m *InMemoryLeaseStore) Stop()
    Stop satisfies LeaseStorage.Stop(). InMemoryLeaseStore owns no background
    goroutine or file handle, so this is a no-op; persistence-owning backends
    (see FileLeaseStore) override it to flush state and release resources.

func (m *InMemoryLeaseStore) UpsertNonKEYRecords(ownerNodeKey string, records []dns.RR, leaseDuration uint32, upstreamZone string) error
    UpsertNonKEYRecords attaches records to ownerNodeKey. The owner is not
    required to have a KEY Record in m.leases: a non-KEY record can be owned by
    a "phantom" node the same way a child KEY can already have a ParentKeyName
    pointing at one (see RegisterWithParent/attachNodeLocked). This lets a
    signer that is deliberately never self-registered (e.g. an online-only key
    authorized via AllowOnlineKeyRegistration) still own data.

    Every record is validated against the whole batch before any of them is
    applied: if any of the given records already exists in the store under a
    different owner, the entire call fails and nothing is written -- the same
    "fail the parts that would otherwise succeed" policy used for duplicate
    KEY/RR registration elsewhere (protocol.md item 6), because partially
    applying a batch here would leave the store's consistency unguaranteed.

type KEYRecord = Record
    KEYRecord is an alias to Record for clarity in tree-oriented code.

type LeaseOption struct {
	Lease    uint32  // The LEASE value in seconds
	KeyLease *uint32 // Optional KEY-LEASE value (nil for 4-byte variant)
}
    LeaseOption represents the Update Lease EDNS(0) option.

func DecodeOption(erfc *dns.ERFC3597) (*LeaseOption, error)
    DecodeOption decodes a raw UPDATE-LEASE ERFC3597 option (as found by
    FindOption) into a LeaseOption.

func Encode4Byte(lease uint32) *LeaseOption
    Encode4Byte creates a LeaseOption with only LEASE (4-byte variant).
    Deprecated: For backward compatibility when 4-byte variant is enabled via
    config. The 8-byte variant is now the default for all lease requests.

func Encode8Byte(lease, keyLease uint32) *LeaseOption
    Encode8Byte creates a LeaseOption with both LEASE and KEY-LEASE (8-byte
    variant).

func FindAndDecode(msg *dns.Msg) (*LeaseOption, error)
    FindAndDecode is the common case: locate the UPDATE-LEASE option in msg and
    decode it in one step.

func (lo *LeaseOption) Decode(opt *dns.OPT) error
    Decode parses a LeaseOption from an OPT RR.

func (lo *LeaseOption) Encode(opt *dns.OPT) error
    Encode encodes the LeaseOption into an OPT RR per RFC 6891. The 8-byte
    variant is always used (LEASE + KEY-LEASE). When KeyLease == nil, KEY-LEASE
    is set to defaultKeyLease (0).

func (lo *LeaseOption) Validate() error
    Validate checks that the lease values are valid.

type LeaseStorage interface {

	// Register creates or updates a KEY lease. The node identity is derived from keyRR.
	Register(ctx context.Context, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
	// RenewLease extends an already-registered KEY lease's timers in place.
	// The node identity is derived from keyRR; it is an error if no such
	// node is already registered. Unlike Register, it never touches
	// ParentKeyName, RegisteredAt, or the node's position in the tree --
	// renewing a lease is not re-creating the node.
	RenewLease(ctx context.Context, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32) error
	// FindByName returns all non-expired records at the given DNS name.
	FindByName(dnsName string) []*Record
	// LookupByKEY returns the non-expired record matching k's exact identity (name+algo+tag).
	LookupByKEY(k *dns.KEY) *Record
	// LookupBySIG returns the non-expired record matching the SIG(0) signer identity.
	LookupBySIG(signerName string, algorithm uint8, keyTag uint16) *Record
	// Get returns the record for nodeKey (composite key), including expired records.
	Get(nodeKey string) *Record
	// Delete removes the subtree rooted at the composite nodeKey.
	Delete(nodeKey string) error
	ListExpiring(within time.Duration) []*Record
	ListAll() []*Record
	SetPersistenceHook(hook func(ctx context.Context, op string, record *Record) error)

	// RegisterWithParent creates or updates a KEY lease with an optional
	// parent composite node key. Fails if parentNodeKey already identifies a
	// non-KEY record -- a non-KEY node can never be a parent.
	RegisterWithParent(ctx context.Context, parentNodeKey string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
	DeleteSubtree(nodeKey string) error
	ChildrenOf(nodeKey string) []string
	// ListSubtreeKeys returns composite node keys of all descendants
	// (KEY and non-KEY alike), deepest first.
	ListSubtreeKeys(nodeKey string) []string

	ExportSnapshot() (*LeaseTreeSnapshot, error)
	ImportSnapshot(snapshot *LeaseTreeSnapshot) error
	SaveSnapshot(path string) error
	LoadSnapshot(path string) error

	// UpsertNonKEYRecords registers or refreshes records under ownerNodeKey.
	// Fails outright, applying none of the given records, if any of them
	// already exists in the store under a different owner -- this is the
	// store's own enforcement of "two different keys cannot register the
	// identical RR" (protocol.md), not merely a caller-side convention.
	UpsertNonKEYRecords(ownerNodeKey string, records []dns.RR, leaseDuration uint32, upstreamZone string) error
	RemoveNonKEYRecords(ownerNodeKey string)
	// RemoveSingleNonKEYRecord removes the record identified by rrKey.
	// Idempotent: a no-op, not an error, if no such record exists. Returns
	// an error, without effect, if the record exists but is owned by a
	// different node than ownerNodeKey.
	RemoveSingleNonKEYRecord(ownerNodeKey, rrKey string) error
	GetNonKEYRecordSet(ownerNodeKey string) *NonKEYRecordSet
	// LookupNonKEYRecord returns the record matching rr's RFC 2136 identity
	// anywhere in the store (regardless of owner), or nil if none exists.
	// Callers compare the result's ParentKeyName against their own candidate
	// owner to distinguish "mine" (refresh) from "someone else's" (reject).
	LookupNonKEYRecord(rr dns.RR) *NonKEYRecord

	// Stop releases any resources this backend owns (background goroutines,
	// open files, timers). Must be safe to call even when the backend owns
	// nothing (a no-op), and safe to call exactly once from a shutdown path.
	Stop()
}
    LeaseStorage is the single storage-backend abstraction for lease state:
    KEY-lease lifecycle, tree/hierarchy operations, non-KEY record sets, and
    snapshot import/export/persistence. Every backend (in-memory, file-backed,
    or a caller-supplied Go-embedded implementation) must implement all of it
    -- there is no narrower interface to fall back to, and callers must not
    type-assert down to a subset. Implementations must be thread-safe.

    KEY and non-KEY records are both tree nodes with a globally unique identity
    (see NodeKey / RecordKey) and a ParentKeyName; a non-KEY node can never
    itself be a parent (RegisterWithParent rejects that). Uniqueness is enforced
    by the store itself, not by callers pre-checking: UpsertNonKEYRecords fails
    outright if any of the given records already exist under a different owner,
    rather than silently allowing two different keys to register the identical
    RR.

type LeaseTreeSnapshot struct {
	Version     int            `json:"version"`
	GeneratedAt time.Time      `json:"generated_at"`
	Nodes       []NodeSnapshot `json:"nodes"`
}
    LeaseTreeSnapshot is a storage-neutral representation of the lease tree.

type NodeKind string

const (
	NodeKindKEY    NodeKind = "key"
	NodeKindNonKEY NodeKind = "non-key"
)
type NodeSnapshot struct {
	NodeKind      NodeKind  `json:"node_kind"`
	NodeID        string    `json:"node_id"` // composite identity: KEY -> NodeKey(keyRR), non-KEY -> RecordKey(rr)
	ParentKeyName string    `json:"parent_key_name,omitempty"`
	RRType        uint16    `json:"rr_type,omitempty"`
	UpstreamZone  string    `json:"upstream_zone"`
	LeaseDuration uint32    `json:"lease_duration"`
	RegisteredAt  time.Time `json:"registered_at"`
	ExpiresAt     time.Time `json:"expires_at"`

	// KEY-only.
	KeyLeaseDuration uint32 `json:"key_lease_duration,omitempty"`
	RRName           string `json:"rr_name,omitempty"`
	RRClass          uint16 `json:"rr_class,omitempty"`
	RRTTL            uint32 `json:"rr_ttl,omitempty"`
	KeyFlags         uint16 `json:"key_flags,omitempty"`
	KeyProtocol      uint8  `json:"key_protocol,omitempty"`
	KeyAlgorithm     uint8  `json:"key_algorithm,omitempty"`
	KeyData          string `json:"key_data,omitempty"`

	// non-KEY-only: full presentation-format RR, reparsed via dns.New on import.
	RRText string `json:"rr_text,omitempty"`
}
    NodeSnapshot is a persisted tree node row -- KEY or non-KEY, discriminated
    by NodeKind. Which of the KEY-only / non-KEY-only fields below are populated
    follows from that. A record that has been deleted or expired is removed from
    the store, so it is never persisted; there is no "deleted" flag to carry
    here.

type NonKEYRecord struct {
	BaseRecord
	RRKey        string
	RR           dns.RR
	UpstreamZone string
}
    NonKEYRecord represents a non-KEY RR lease node in the tree. Like a KEY
    node, it is a first-class node with its own globally unique identity (RRKey,
    computed by RecordKey) -- it is not merely an entry in some owner's local
    set. ParentKeyName (inherited from BaseRecord) is the one and only place its
    owner is recorded.

type NonKEYRecordSet struct {
	Records      map[string]*NonKEYRecord
	UpstreamZone string
}
    NonKEYRecordSet is a read-only, point-in-time view of the non-KEY records
    owned by one node, returned by GetNonKEYRecordSet. It is not how records are
    stored internally -- see InMemoryLeaseStore.nonKeyRecords.

type Record struct {
	BaseRecord
	KeyName          string
	KeyRR            *dns.KEY
	KeyLeaseDuration uint32
	UpstreamZone     string
}
    Record represents an active KEY lease node (KEYRecord in the protocol
    model). It embeds BaseRecord and keeps compatibility with existing callers.

func (r *Record) IsExpired() bool
    IsExpired returns true if the lease has expired.

func (r *Record) TimeRemaining() time.Duration
    TimeRemaining returns the time until lease expiration.

```

## github.com/NetworkCommons/sig0lease/pkg/sig0
```
package sig0 // import "github.com/NetworkCommons/sig0lease/pkg/sig0"

Package sig0 implements SIG(0) request/response signing as per RFC 2931.
Uses codeberg.org/miekg/dns SIG(0) facilities for proper cryptographic signing.
Provenance: RFC 2931 (Transaction Signatures with SIG(0))

# A note on codeberg.org/miekg/dns's SIG(0) hashing bug

codeberg.org/miekg/dns v0.6.82's dns.CryptoSIG0.Sign/Verify compute the SIG(0)
hash input as the SIG RR's *full wire encoding* (owner name + TYPE + CLASS
+ TTL + RDLENGTH, followed by RDATA) -- but RFC 2931 S3 is explicit that
the signed "data" is "RDATA | message", where RDATA is only the SIG's RDATA
fields (with the Signature field itself omitted), never that RR envelope.
This was root-caused by instrumenting a local copy of the library and
independently confirmed against mDNSResponder's own C implementation
(ServiceRegistration/towire.c: dns_sig0_signature_to_wire_, which hashes a
`rr`/`rdlen` pointing at RDATA only) -- see README_proxy.md's "miekg/dns
Shortcomings" section for the full writeup and reproduction.

sig0SignerImpl below replaces dns.CryptoSIG0.Sign/Verify with a from-scratch,
RFC-correct implementation for every algorithm this package validates (ED25519,
ECDSAP256SHA256, ECDSAP384SHA384) via the shared rdataOnlyPrefix helper, rather
than only working around the bug for one algorithm as a previous version of
this file did by accident (its ED25519 special case built an RDATA-only prefix
by hand for unrelated reasons -- CryptoSIG0.Sign has no Ed25519 case at all --
and so had always been correct, while every other algorithm silently inherited
the library's bug). RSA algorithms (RSAMD5/RSASHA1/RSASHA256/RSASHA512) still
delegate to the buggy dns.CryptoSIG0 path: nothing in this codebase uses
or tests them, and implementing RSA sign/verify from scratch without any
test vectors to validate against would trade a known, documented gap for an
unverified one.

FUNCTIONS

func SignMessage(msg *dns.Msg, keyRR *dns.KEY, privateKey crypto.PrivateKey) (*dns.Msg, error)
    SignMessage signs any DNS message with SIG(0) using shared logic for both
    client and server paths.

func VerifySignature(msg *dns.Msg, keyRR *dns.KEY) error
    VerifySignature verifies a SIG(0) signature on a message. This is useful
    for servers to verify client-signed requests. Provenance: RFC 2931 SIG(0)
    verification + codeberg/miekg/dns SIG0Verify()

```

## github.com/NetworkCommons/sig0lease/pkg/srp
```
package srp // import "github.com/NetworkCommons/sig0lease/pkg/srp"

Package srp implements RFC 9665 (DNS-SD Service Registration Protocol) message
classification and structural validation. It is pure logic: no network I/O,
no lease store access -- see main/docs/rfc9665-srp-implementation-plan.md
S4.1. FCFS (pkg/srp/fcfs.go, needs a store view) and the handler wiring
(handlers/srp_handler.go) are later phases; this file covers Classify(),
the first step of S4.3's happy path.

The classification algorithm below closely follows the reference implementation
in mDNSResponder/ServiceRegistration/srp-parse.c (srp_evaluate), which the
plan's S12.3 names as the cross-check for this package -- see the deliberate
divergences noted inline (multiple TXT adds; the LEASE-independent host-removal
fallback; no base-type-precedes-subtype requirement on PTR deletes).

update.go builds an unsigned RFC 9665 SRP UPDATE message from a declarative
spec -- the requester-side counterpart to Classify/Validate. Pure logic:
no network I/O, no crypto beyond shaping the KEY RR from already-generated key
material (see plan S4.1 for why pkg/srp stays network-free; client/srp, Phase 4,
owns key generation, discovery, scheduling, and actually sending the result).

CONSTANTS

const (
	AuthNXDomain   = updatecore.AuthNXDomain
	AuthNoKey      = updatecore.AuthNoKey
	AuthKeyPresent = updatecore.AuthKeyPresent
)

FUNCTIONS

func BuildUpdate(spec UpdateSpec) (*dns.Msg, error)
    BuildUpdate constructs an unsigned SRP UPDATE: the Host Description
    Instruction (delete-all + address adds + KEY), one Service Description
    Instruction per instance (delete-all + SRV + TXT, or a bare delete-all for
    Remove), one Service Discovery Instruction (PTR add) per live instance's
    service type and subtype, and an 8-byte Update-Lease option. It always
    restates every instruction fully -- S3.2's "no lightweight refresh":
    there is no partial-update form, so a caller wanting an instance to
    remain discoverable must pass it again on every call (S4.5/S10 item 10) --
    BuildUpdate itself has no memory of a previous call.

    The result is unsigned; sign it with pkg/sig0.SignMessage using the same key
    material as spec.Key before sending.

func GrantedLease(resp *dns.Msg) (lease, keyLease uint32, ok bool)
    GrantedLease reads the LEASE/KEY-LEASE the registrar actually granted off
    a successful response's echoed Update-Lease option (plan S4.3 step 10) --
    which may differ from what was requested (the registrar's own LeasePolicy
    can clamp either value independently). ok is false if resp carries no
    (decodable) Update-Lease option, in which case the requester should fall
    back to what it originally requested.

func KeyFor(cu *ClassifiedUpdate, name string) *dns.KEY
    KeyFor returns the KEY that governs name: an instance's own explicit KEY if
    it has one, otherwise a copy of the Host Description's KEY with its owner
    name rewritten to name (S3.2.5.1: "the SRP registrar MUST behave AS IF the
    same KEY record that is given for the Host Description is also given for
    each Service Description for which no KEY record is provided" -- "as if...
    given for" that name, not the literal host-owned RR object). Returning
    cu.Host.Key verbatim here was a real bug caught by a live end-to-end test
    (plan S12, Phase 3): callers that derive a lease-store node identity from
    the result (pkg/lease.NodeKey is name-scoped) would silently collide the
    instance's node with the host's, since both would carry the host's own owner
    name.

    name must be cu.Host.Name or one of cu.Instances' names -- anything else is
    a caller bug, not a data problem, so KeyFor panics rather than returning a
    zero value a caller could silently misuse.

func Names(cu *ClassifiedUpdate) []string
    Names returns every name Evaluate must be called for to authorize cu
    (S3.3's "the checked names are the Host Description name and each Service
    Description name -- nothing else"): the host, plus each service instance's
    own name. SRV/TXT/PTR owner names are deliberately never included -- they
    have no independent identity to check (S4.4/S4.5's "nothing walks up
    from the SRV node" reasoning), and per S3.3.1.1 every Service Discovery
    instruction is authorized transitively through its target instance's own
    check.


TYPES

type AuthoritativeKeyQuery = updatecore.AuthoritativeKeyQuery
    AuthoritativeKeyState and AuthoritativeKeyQuery are defined in
    pkg/updatecore, not here, even though this file is where they're consumed --
    pkg/updatecore.Coordinator is the real implementation (needs network I/O),
    and this package already imports pkg/updatecore for CheckConsistentTTLs,
    so defining them here instead would create an import cycle. See
    pkg/updatecore/authquery.go's doc comment for the full reasoning.

type AuthoritativeKeyState = updatecore.AuthoritativeKeyState
    AuthoritativeKeyState and AuthoritativeKeyQuery are defined in
    pkg/updatecore, not here, even though this file is where they're consumed --
    pkg/updatecore.Coordinator is the real implementation (needs network I/O),
    and this package already imports pkg/updatecore for CheckConsistentTTLs,
    so defining them here instead would create an import cycle. See
    pkg/updatecore/authquery.go's doc comment for the full reasoning.

type ClassifiedUpdate struct {
	Host      *HostDescription
	Instances []*ServiceInstance // in first-sighting order
	Discovery []ServiceDiscovery // every Service Discovery instruction, in encounter order
}
    ClassifiedUpdate is the result of a successful Classify(): every instruction
    found in the message, structurally cross-referenced (every Service
    Discovery target resolves to a ServiceInstance present in the same update;
    every SRV-bearing ServiceInstance targets the Host; every KEY add resolves
    to either the Host or a ServiceInstance and all KEY adds carry identical
    RDATA). It does not mean the update is authorized (FCFS, SIG(0)) or that
    TTLs/lease options are valid -- see Validate() for the remaining S3.3.2
    checks Classify() deliberately leaves to it.

func Classify(msg *dns.Msg) (*ClassifiedUpdate, error)
    Classify extracts and cross-references every RFC 9665 instruction in msg's
    Update (Ns) section. It returns an error -- never a partial/best-effort
    result -- for anything that doesn't fit one of the three recognized
    instruction shapes; per S3.3.2, that means the message is not an SRP update
    at all. Classify does not look at msg.Question, msg.Answer, or the lease
    option -- callers needing the "no prerequisites" / "single zone" / "lease
    option present" checks use Validate, which wraps this.

func Validate(msg *dns.Msg) (*ClassifiedUpdate, error)
    Validate runs Classify plus every remaining RFC 9665 S3.3.1/S3.3.2
    structural check that needs more than the Update section alone: a single
    Zone Section entry, no prerequisites, a present and internally-consistent
    Update-Lease option, TTL consistency (S4 -- a MUST, reject rather than
    normalize, unlike the base RFC 9664 handler's pkg/updatecore.NormalizeTTLs),
    identical KEY RDATA across every KEY add, and flags-0 KEY adds (S3.2.5.1).
    It does not verify SIG(0) or FCFS -- those need the lease store and the
    SIG(0) signer identity, both outside this package's pure-logic scope (S4.3
    steps 4-5).

    Assumes the caller has already confirmed msg.Opcode == dns.OpcodeUpdate (the
    router dispatch layer's job, not this package's) and that msg has been fully
    unpacked.

type FCFSResult int
    FCFSResult is the outcome of evaluating one name under S3.3.3's
    First-Come-First-Served rule.

const (
	// FCFSProceed: first-come (name doesn't exist anywhere we can tell), or the update's
	// key already owns this name (a refresh).
	FCFSProceed FCFSResult = iota
	// FCFSConflict: a different key holds this name -- the response RCODE is YXDOMAIN.
	FCFSConflict
	// FCFSForeignData: the name exists with data but no KEY, and
	// srp.refuse_on_foreign_data is true (the default) -- REFUSED.
	FCFSForeignData
)
func Evaluate(ctx context.Context, view StoreView, query AuthoritativeKeyQuery, zoneHint, name string, updateKey *dns.KEY, refuseOnForeignData bool) (FCFSResult, error)
    Evaluate implements RFC 9665 S3.3.3 FCFS for a single name -- the Host
    Description name, or one Service Description name -- against updateKey, the
    KEY that governs it (the Host Description's KEY, or a Service Description's
    own explicit KEY when it has one; per S3.2.5.1 every KEY in a valid update
    is identical anyway, so callers may simply pass ClassifiedUpdate.Host.Key
    for every name -- see the package-level Names helper).

    Per the plan's S3.3 table:

        lease store has a KEY at name, matches updateKey        -> FCFSProceed  (refresh)
        lease store has a KEY at name, does NOT match           -> FCFSConflict (YXDOMAIN)
        no local record; live query: NXDOMAIN                   -> FCFSProceed  (first come)
        no local record; live query: NOERROR, no KEY             -> refuseOnForeignData ? FCFSForeignData : FCFSProceed
        no local record; live query: NOERROR, KEY matches        -> FCFSProceed
        no local record; live query: NOERROR, KEY doesn't match  -> FCFSConflict (YXDOMAIN)

    The lease store is checked first and trusted over a live query when both
    are available: it is the source of truth for what this proxy already manages
    (see handlers.filterDuplicateRegistrations's doc comment for the base
    handler's identical reasoning) -- a live query only runs for a name the
    store has no opinion on.

func (r FCFSResult) String() string

type HostDescription struct {
	Name      string   // canonical (lower-cased, dot-terminated) hostname
	Delete    dns.RR   // the "Delete All RRsets From A Name" RR for Name
	Key       *dns.KEY // the Host Description's KEY add; nil until the key-matching pass fills it in
	Addresses []dns.RR // 0..n *dns.A / *dns.AAAA adds, in encounter order
}
    HostDescription is RFC 9665 S3.3.1.3's (exactly one, per update) Host
    Description Instruction: a Delete All RRsets on the hostname, exactly one
    KEY add, and zero or more A/AAAA adds (zero addresses means "delete this
    host's registration").

type InstanceSpec struct {
	// Name is the service instance's own FQDN, e.g. "MyPrinter._ipps._tcp.example.com."
	Name string
	// ServiceType is the base service type's FQDN (the Service Discovery PTR's owner
	// name), e.g. "_ipps._tcp.example.com."
	ServiceType string
	// Subtypes are additional DNS-SD subtype FQDNs (RFC 6763 S7.1) naming the same
	// instance, e.g. "_universal._sub._ipps._tcp.example.com." -- each gets its own PTR
	// add, always emitted after ServiceType's (Classify requires a subtype PTR add to be
	// preceded, in the same update, by a base-type PTR add with the same target).
	Subtypes []string
	Port     uint16
	// TXT holds the instance's TXT strings. A live instance needs at least one (S3.1); a
	// nil/empty slice defaults to a single empty string, matching common practice (and
	// RFC 9665 Appendix C's own example, `TXT ""`).
	TXT []string
	// Key is an explicit KEY for this instance, or nil to inherit the Host Description's
	// key (S3.2.5.1's normal case, and what BuildUpdate always assumes for Remove).
	Key *dns.KEY
	// Remove makes this a removal-shaped Service Description: a bare Delete All RRsets,
	// no SRV/TXT/PTR at all (S3.3.1.1's second bullet). ServiceType/Subtypes/Port/TXT/Key
	// are ignored when true.
	Remove bool
}
    InstanceSpec describes one Service Description Instruction (plus its
    Service Discovery PTR add(s)) to include in a built update. Every field is
    a fully-qualified name -- this package stays free of "join a label onto a
    domain" ergonomics, which belongs to the caller (client/srp).

type Outcome int
    Outcome classifies a registrar's response to an SRP UPDATE, from the
    requester's side -- the counterpart to the RCODEs handlers/srp_handler.go's
    Handle() produces.

const (
	// OutcomeSuccess: NOERROR. The registration was accepted; GrantedLease reads the
	// granted LEASE/KEY-LEASE off the same response.
	OutcomeSuccess Outcome = iota
	// OutcomeConflict: YXDOMAIN (S3.3.3's FCFS conflict). A different key already holds
	// one of the names in this update. Per plan S10 item 9, this is "rename and retry,"
	// not a hard failure -- see client/srp's rename-retry loop.
	OutcomeConflict
	// OutcomeRefused: REFUSED. Covers every registrar-side rejection that isn't a naming
	// conflict -- SIG(0) failure, foreign non-SRP data present (refuse_on_foreign_data),
	// malformed update, TCP-required-but-got-UDP, and so on. The RCODE alone doesn't tell
	// the requester which; retrying the identical request is unlikely to help.
	OutcomeRefused
	// OutcomeServerFailure: SERVFAIL, or no response at all (nil resp).
	OutcomeServerFailure
	// OutcomeOther: any other RCODE.
	OutcomeOther
)
func InterpretResponse(resp *dns.Msg) Outcome
    InterpretResponse classifies resp's RCODE for a requester. A nil resp
    (e.g. a transport error before any response arrived) is treated as
    OutcomeServerFailure.

func (o Outcome) String() string

type ServiceDiscovery struct {
	Name   string // canonical owner name of the PTR (a service type, or a subtype name)
	Target string // canonical PTR target -- must name a ServiceInstance in the same update
	IsAdd  bool   // true: "Add To An RRSet"; false: "Delete An RR From An RRSet"
	RR     *dns.PTR
	// BaseType is non-empty when Name has the DNS-SD subtype shape
	// "<sub>._sub.<Service>.<Domain>" (RFC 6763 S7.1), and holds the base service type's
	// canonical name in that case.
	BaseType string
}
    ServiceDiscovery is one RFC 9665 S3.3.1.1 Service Discovery Instruction:
    a single PTR add or delete. Note there can be several of these sharing the
    same Name (one service type can list several instances) or the same Target
    (an instance can be discoverable under its base type and under one or more
    subtypes) -- each is still counted and validated as its own, separate
    instruction, never merged.

type ServiceInstance struct {
	Name   string   // canonical service-instance name
	Delete dns.RR   // the "Delete All RRsets From A Name" RR for Name
	Key    *dns.KEY // explicit KEY add for this instance, or nil (inherits the host's key)
	SRV    *dns.SRV // nil for a removal-shaped instance
	// TXT holds every TXT add for this instance. RFC 9665's S3.1 table allows 1..n TXT
	// adds when SRV is present; mDNSResponder's own registrar (srp-parse.c) is stricter
	// and rejects a second TXT add outright -- this package follows the RFC text over
	// that implementation choice and allows more than one.
	TXT []*dns.TXT

	// Has unexported fields.
}
    ServiceInstance is RFC 9665 S3.3.1.2's Service Description Instruction:
    a Delete All RRsets on the service-instance name, an optional KEY add
    (inherits the host's key when absent), and either an SRV+TXT pair (a live
    registration) or neither (a removal -- S3.3.1.1's second bullet: a Service
    Discovery "Delete An RR From An RRSet" targets a Service Description shaped
    exactly this way).

type StoreView interface {
	// KeyAtName returns the live (non-expired) KEY record the lease store currently
	// manages at name, and whether one was found. A name the store has never seen, or
	// whose only record there has expired, reports ok=false -- Evaluate then falls back
	// to a live authoritative query, exactly as S3.3.3 describes.
	KeyAtName(name string) (key *dns.KEY, ok bool)
}
    StoreView is the minimal read-only view into the lease store Evaluate needs.
    A thin, intentionally narrow adapter over pkg/lease.LeaseStorage.FindByName
    -- narrow so this package depends on a two-line interface it can trivially
    fake in tests, not on the store's full read/write surface.

type UpdateSpec struct {
	Zone      string // Zone Section name; must equal Host's own registration domain
	Host      string // Host Description FQDN
	Addresses []netip.Addr
	// Key is the Host Description's KEY RR. Only its algorithm/protocol/public-key
	// material is used -- BuildUpdate overwrites Hdr.Name/Hdr.Class/Hdr.TTL to match Host
	// and KeyLease, and unconditionally zeroes Flags (S3.2.5.1/S3.3.3: requesters MUST
	// send flags 0, regardless of what the caller's key material happens to carry).
	Key       *dns.KEY
	Instances []InstanceSpec
	Lease     uint32
	KeyLease  uint32
}
    UpdateSpec is everything BuildUpdate needs to construct one SRP UPDATE.

```

## github.com/NetworkCommons/sig0lease/pkg/updatecore
```
package updatecore // import "github.com/NetworkCommons/sig0lease/pkg/updatecore"

Package updatecore holds forwarding plumbing shared by the RFC
9664 update-lease handler and the RFC 9665 SRP handler (see
main/docs/rfc9665-srp-implementation-plan.md S4.1, D1/D8). It is a public
package, not internal/, matching this repo's convention.

Package updatecore holds forwarding plumbing shared by the RFC
9664 update-lease handler and the RFC 9665 SRP handler (see
main/docs/rfc9665-srp-implementation-plan.md S4.1, D1/D8). It is a public
package, not internal/, matching this repo's convention.

FUNCTIONS

func AsDelete(rr dns.RR) dns.RR
    AsDelete returns a copy of rr rewritten as an RFC 2136 S2.5.4 "Delete An RR
    From An RRSet" instruction: class NONE, TTL 0, RDATA unchanged (which RR the
    delete targets is carried by NAME+TYPE+RDATA, same as any other RR identity
    in this codebase -- pkg/lease.RecordKey uses the identical convention).

func BuildAndSign(upstreamZone string, records []dns.RR, signingKey *keyrec.LoadedKey) (*dns.Msg, error)
    BuildAndSign constructs a new UPDATE message for upstreamZone containing
    exactly records (in the given order) as the Update section, and signs it
    with signingKey.

    Unlike the base RFC 9664 handler's constructUpstreamUpdate (handlers/
    opcode5_update_helpers.go), this does no per-record-type branching or TTL
    clamping -- S4.3 step 7's SRP forward is simpler by construction: it's
    exactly "the same adds/deletes [the requester sent], re-signed with proxy
    key" (plus, for a Service Description, the pkg/srp-computed PTR-delete diff
    appended by the caller before this is called -- see the plan's S4.4/S4.5).
    Any clamping SRP wants happens earlier, against the classified instructions,
    not here.

func CheckConsistentTTLs(records []dns.RR) error
    CheckConsistentTTLs implements the RFC 9665 S4 MUST for the SRP path:
    every RRset in an update must carry one TTL across all its RRs. Unlike
    NormalizeTTLs, this never rewrites anything -- SRP requires rejecting a
    violation outright (REFUSED), not silently correcting it. Returns the first
    inconsistency found, naming the owner, type, and the conflicting TTL values,
    or nil if every RRset present is consistent. Single-RR RRsets (the common
    case) are trivially consistent and never inspected beyond membership.

func FindAuthorizedProxyKey(keystoreDir, zone string, logger *logging.Logger) (*keyrec.LoadedKey, string, error)
    FindAuthorizedProxyKey loads the proxy's own SIG(0) signing key
    for zone from keystoreDir, walking up to parent zones if the
    exact zone has no key -- extracted from what was previously
    (*handlers.UpdateHandler).findAuthorizedProxyKeyForZone, now a standalone
    function so handlers/srp_handler.go can use it without depending on
    *handlers.UpdateHandler.

func NormalizeTTLs(records []dns.RR) int
    NormalizeTTLs implements the RFC 2181 S5.2 (erratum-corrected) guidance for
    the base RFC 9664 handler: a resolver encountering an RRset with differing
    TTLs should treat the lowest TTL as authoritative for the whole set.
    Unlike CheckConsistentTTLs, this mutates each affected RR's Hdr.TTL in
    place to its RRset's minimum, rather than rejecting the update -- the base
    handler's policy is "normalize", not "refuse". Must run before LeasePolicy
    clamping (S6) so clamping sees the already-uniform value. Returns the number
    of distinct RRsets that needed rewriting, for caller logging; 0 means every
    RRset present was already consistent and nothing was touched.


TYPES

type AuthoritativeKeyQuery func(ctx context.Context, zoneHint, name string) (AuthoritativeKeyState, []*dns.KEY, error)
    AuthoritativeKeyQuery performs one live KEY-at-name query against
    the authoritative server for name (scoped by zoneHint) and reports
    its tri-state result plus, for AuthKeyPresent, the KEY RR(s) found.
    Coordinator.QueryKeyAtName is the real implementation; pkg/srp.Evaluate
    takes this as an injected function type so tests can supply a canned
    response instead of a live server.

type AuthoritativeKeyState int
    AuthoritativeKeyState is the tri-state result of a live KEY-at-name query
    against the authoritative server, consumed by pkg/srp.Evaluate (S3.3.3
    FCFS) when the lease store has no local record for a name. This is the
    RCODE-aware distinction the base RFC 9664 handler's queryAuthoritativeRRs
    discards -- keeping it is what makes the NXDOMAIN/NODATA/KEY-present cases
    distinguishable at all.

    Defined here rather than in pkg/srp (which consumes it) because Coordinator,
    the real implementation, lives here and needs actual network I/O -- pkg/srp
    stays pure logic with no network I/O of its own and imports this type rather
    than the reverse, which would create an import cycle (pkg/srp already
    imports this package for CheckConsistentTTLs).

const (
	// AuthNXDomain: the name does not exist. First come -- proceed.
	AuthNXDomain AuthoritativeKeyState = iota
	// AuthNoKey: the name exists (NOERROR) but has no KEY RRset -- foreign or orphaned
	// data. Handled per srp.refuse_on_foreign_data (see pkg/srp.Evaluate's doc comment).
	AuthNoKey
	// AuthKeyPresent: the name exists and a KEY RRset was found; the keys are returned
	// alongside this state.
	AuthKeyPresent
)
type Coordinator struct {
	// Has unexported fields.
}
    Coordinator resolves the authoritative server for a zone (SOA MNAME, or a
    configured per-zone static override, D4) and performs the two things both
    handlers need against it: sending a signed UPDATE, and a live KEY-at-name
    query (S3.3.3 FCFS).

    This is the extraction of what was previously
    handlers.DefaultUpstreamCoordinator's entire body. Both handlers/opcode5.go
    (RFC 9664) and handlers/srp_handler.go (RFC 9665) construct and hold a
    *Coordinator directly -- there is no per-package wrapper type.

func NewCoordinator(logger *logging.Logger, bootstrapResolvers []string, staticUpstream map[string]string) *Coordinator
    NewCoordinator creates a Coordinator. bootstrapResolvers falls back
    to defaultBootstrapResolvers when empty. staticUpstream may be nil (no
    overrides).

func (c *Coordinator) QueryKeyAtName(ctx context.Context, zoneHint, name string) (AuthoritativeKeyState, []*dns.KEY, error)
    QueryKeyAtName is the real implementation of AuthoritativeKeyQuery (S3.3.3
    FCFS): one live QTYPE=KEY query at name against zoneHint's resolved
    authoritative server (ResolveSOAMasterServer, honoring a static override),
    reporting the tri-state result pkg/srp needs. This is also the pre-forward
    cost S5 describes -- the same query backs both the FCFS check (S3.3) and,
    when reused by a caller, the "does this name already have a KEY" question
    the base handler asks elsewhere.

func (c *Coordinator) ResolveAuthoritativeZone(ctx context.Context, zone string) (string, error)
    ResolveAuthoritativeZone finds the zone cut (the name that actually has NS
    records) for zone or one of its parents -- or, for a zone matching a static
    upstream override (D4), zone itself, with no NS lookup at all (the operator
    has already asserted the zone cut by configuring the override).

func (c *Coordinator) ResolveSOAMasterServer(ctx context.Context, zone string) (server, effectiveZone string, err error)
    ResolveSOAMasterServer returns the "host:port" of zone's SOA MNAME (walking
    up to parent zones if the exact name has none) and the effective zone that
    answered, or -- if zone exactly matches a configured static upstream (D4) --
    that override address with zone itself as the effective zone, skipping the
    lookup entirely.

func (c *Coordinator) SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error)
    SendUpdate sends updateMsg (already built and signed) to upstreamZone's
    authoritative server, resolved via ResolveSOAMasterServer (so a static
    override, D4, is honored), trying UDP then falling back to TCP.

```

## github.com/NetworkCommons/sig0lease/server
```
package server // import "github.com/NetworkCommons/sig0lease/server"

Package server implements the DNS proxy server.

Package server implements the DNS proxy server.

TYPES

type Router struct {
	// Has unexported fields.
}
    Router routes DNS requests based on opcode to appropriate handlers or
    forwarder.

func NewRouter(opcodeMap map[uint8][]string, logger *logging.Logger, resolver *forward.Resolver) (*Router, error)
    NewRouter creates a new router instance.

func (r *Router) RegisterHandler(h handlers.Handler)
    RegisterHandler registers a handler with the router.

func (r *Router) Route(ctx context.Context, w dns.ResponseWriter, rMsg *dns.Msg) *dns.Msg
    Route determines how to handle a DNS message based on its opcode. Flow:
     1. Check for internal dump query (admin/debug endpoint)
     2. Check if opcode has any registered handlers
     3. Try each configured handler for the opcode in order (D2):
        - StatusProcessed: Return response to client, stop - StatusNotRelevant:
        Try the next handler in the list - StatusError: Return error response to
        client, stop
     4. If no handler is configured, or every handler declined (all
        NotRelevant), apply default forward

func (r *Router) Shutdown()
    Shutdown calls Shutdown on every registered handler exactly once.

type Server struct {
	// Has unexported fields.
}
    Server is the main DNS proxy server.

func New(cfg *config.Config, logger *logging.Logger) (*Server, error)
    New creates and returns a new Server instance.

func (s *Server) RegisterHandler(h handlers.Handler)
    RegisterHandler registers a processing module handler with the server.

func (s *Server) Serve() error
    Serve starts the DNS proxy server and blocks until shutdown.

```

## github.com/NetworkCommons/sig0lease/tests
```

```

## github.com/NetworkCommons/sig0lease/tests/srp_client_tester
```
Package main implements a minimal RFC 9665 SRP UPDATE test client, used only by
tests/test_srp.sh. This mirrors tests/blacklisted_tester.go's precedent: a small
Go helper for something the shell alone can't do (build, sign, and send a real
SRP UPDATE) and no existing binary does yet -- client/srp and cmd/sig0lease-srp
are Phase 4, not built yet. This is deliberately NOT that client: no discovery,
no refresh scheduler, no YXDOMAIN rename-retry -- just enough to drive
test_srp.sh's scenarios.

Identity is a P-256 (ECDSAP256SHA256) key pair persisted as a raw private-key
file at -keyfile: created on first use, reused on subsequent calls (so a shell
test case can control fresh-vs-reuse identity simply by removing or keeping that
file between calls).
```

