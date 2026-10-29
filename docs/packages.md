## github.com/NetworkCommons/sig0lease/client
```
package client // import "github.com/NetworkCommons/sig0lease/client"

Package client provides DNS query functionality for testing and client use.

FUNCTIONS

func DescribeAnswer(resp *dns.Msg, outcome Outcome) string
    DescribeAnswer describes a registrar's answer for an error: its outcome,
    RCODE and EDEs.

func EffectiveLeaseDuration(resp *dns.Msg, requestedLease, requestedKeyLease uint32) (lease uint32, keyLease uint32)
    EffectiveLeaseDuration returns the LEASE and KEY-LEASE durations the client
    should use for expiry calculations: what resp grants (GrantedLease), or,
    if it carries no Update-Lease option, what was requested.

func ExpiryFromResponse(now time.Time, requestedLease, requestedKeyLease uint32, resp *dns.Msg) (dataExpiry, keyExpiry time.Time)
    ExpiryFromResponse computes the data-record and KEY expiration times using
    the server-granted LEASE and KEY-LEASE when present in the response.

func GrantedLease(resp *dns.Msg) (lease, keyLease uint32, ok bool)
    GrantedLease reads the LEASE/KEY-LEASE the registrar actually granted off
    a successful response's echoed Update-Lease option -- which may differ from
    what was requested (the registrar's own LeasePolicy can clamp either value
    independently). For the 4-byte variant (a single shared value), that value
    is both. ok is false if resp carries no (decodable) Update-Lease option,
    in which case the requester should fall back to what it requested.

func Report(logf func(format string, args ...any), action, done string, outcome Outcome, err error) bool
    Report logs to logf how action went, done if it succeeded, and reports
    whether it did.

func SleepContext(ctx context.Context, d time.Duration) error
    SleepContext is context.Context.Done()-aware time.Sleep: it returns
    ctx.Err() if ctx is canceled before d elapses, nil once d elapses normally.


TYPES

type Client struct {
	// Has unexported fields.
}
    Client represents a DNS client for sending queries.

func New(server string, protocol string, timeout time.Duration) *Client
    New creates a new DNS client. protocol is "udp" (the default), "tcp",
    or "tls" for DNS-over-TLS (RFC 7858) with the Opportunistic Privacy profile
    (see opportunisticTLS).

func (c *Client) Query(msg *dns.Msg) (*dns.Msg, error)
    Query sends a DNS query and returns the response.

type Keeper[S any] struct {
	// Has unexported fields.
}
    Keeper keeps one registration current as what it should register changes:
    it takes the states Set gives it, collects further ones until none comes
    for Settle, stops keeping the previous registration, and moves to the latest
    (Moves.To); Stop stops keeping it and leaves (Moves.Leave).

func StartKeeper[S any](cfg KeeperConfig, moves Moves[S]) *Keeper[S]
    StartKeeper starts a Keeper. cfg must have its defaults
    (KeeperConfig.Defaults). It does nothing until the first Set.

func (k *Keeper[S]) Set(s S)
    Set replaces what should be registered with s, replacing any earlier Set the
    Keeper has not taken yet. It never blocks. Set must not be called from more
    than one goroutine at a time.

func (k *Keeper[S]) Stop()
    Stop starts stopping the Keeper: it stops keeping the registration and
    leaves (Moves.Leave); Wait waits for it to finish. It may be called more
    than once.

func (k *Keeper[S]) Wait()
    Wait returns once the Keeper has stopped (Stop).

type KeeperConfig struct {
	// Settle is how long changes are collected before the registration is sent again; default 1s.
	Settle time.Duration
	// StopTimeout bounds each withdrawal or deregistration sent outside the refresh clock;
	// default 10s.
	StopTimeout time.Duration
	// KeepNames makes deregistering, on Stop or when nothing is left to register, keep the
	// names reserved for the key until the KEY-LEASE ends, so that it gets them back when it
	// returns. Without it the names are freed.
	KeepNames bool
	// Logf receives the log lines, each starting with the name kept. Default: none.
	Logf func(format string, args ...any)
	// OnFatal is called, at most once, with an error no later change can cure: a client
	// configuration the protocol's NewClient refuses. Nothing more is registered until Stop.
	OnFatal func(error)
}
    KeeperConfig configures how one registration is kept as what it should
    register changes: client/srp's Host and client/rfc9664's Name.

func (cfg *KeeperConfig) Defaults()
    Defaults applies the defaults of the fields left zero.

type Lifecycle struct {
	// RequestedLease is the refresh clock's lease when a response grants none (GrantedLease).
	RequestedLease uint32
	// Rng jitters the delays; it must not be shared across goroutines (see refreshDelay).
	Rng *rand.Rand
	// Sleep waits d, or until ctx ends (SleepContext).
	Sleep func(ctx context.Context, d time.Duration) error
	// OnError, if set, is called with every error a registration cycle hits. Run itself never
	// stops because of one, so this is the caller's only hook for surfacing those failures as
	// they happen.
	OnError func(error)
	// OnRegistered, if set, is called with the registrar's response after every successful
	// registration cycle, the first and each refresh alike: Run's success-path counterpart to
	// OnError.
	OnRegistered func(resp *dns.Msg)
}
    Lifecycle is what keeps a requester's registration alive (Run): the lease it
    asks for, and how it waits and reports.

func (l Lifecycle) Run(ctx context.Context, register func(context.Context) (*dns.Msg, error)) error
    Run keeps a registration alive: an initial 0-3s random delay, then register,
    then a sleep for the RFC 9664 S5.2 refresh clock (80% of the granted lease
    + 0-5% jitter), and register again -- restating the full registration every
    time, as RFC 9665 S3.2 has SRP do ("no lightweight refresh") and RFC 9664
    S5.2 has a refresh do. It blocks until ctx is canceled (Sleep returning
    ctx.Err()), the only thing that stops it.

    A failed registration -- a transient network/DNS error, a registrar
    rejection, a name another key holds -- does not stop Run: OnError is
    called with the error, and register is tried again after an exponentially
    increasing backoff (minRegisterRetryBackoff up to maxRegisterRetryBackoff),
    reset to the minimum after any success. A single transient blip during a
    routine refresh -- one UDP timeout, one SERVFAIL -- must not permanently
    stop a long-running daemon's registration.

type Moves[S any] struct {
	// To moves to next, from what the previous call registered: it sends whatever withdraws
	// what next lacks, and returns the registration to keep (run until its ctx ends), nil for
	// none. An error is one no later state can cure: the Keeper reports it to OnFatal and
	// waits to be stopped.
	To func(next S) (keep func(context.Context), err error)
	// Kept, if set, is called once a registration To returned has stopped, before the next
	// To or Leave.
	Kept func()
	// Leave deregisters what To registered, as the Keeper stops. Its error goes to OnFatal.
	Leave func() error
}
    Moves are what a Keeper does, each called from its goroutine alone.

type Network int
    Network is how a requester reaches its registrar: an SRP registrar
    (client/srp) or this proxy's RFC 9664 handler (client/rfc9664).

const (
	// NetworkTCP, the default, is plain DNS over TCP, which RFC 9665 S3.5 requires on
	// networks that are not constrained.
	NetworkTCP Network = iota
	// NetworkTLS is DNS-over-TLS (RFC 7858). The registrar's certificate is not checked:
	// RFC 9665 S7 has no way to share the registrar's key, so TLS gives Opportunistic
	// Privacy only (RFC 7858 S4.1). SRP discovery then looks for the "_dnssd-srp-tls._tcp"
	// SRV record instead of "_dnssd-srp._tcp" (client/srp.DiscoveryService), and nothing
	// falls back to plain TCP (S7: a requester able to use TLS SHOULD NOT).
	NetworkTLS
	// NetworkUDP is for constrained networks (RFC 9665 S3.1.2): a registrar accepts it only
	// where it allows UDP.
	NetworkUDP
)
func ParseNetwork(s string) (Network, error)
    ParseNetwork returns the Network whose String is s: "tcp", "udp" or "tls".

func (n Network) MarshalText() ([]byte, error)
    MarshalText and UnmarshalText write and read n as its String, as in a JSON
    document.

func (n Network) String() string
    String returns the protocol name New takes for n.

func (n *Network) UnmarshalText(b []byte) (err error)

func (n Network) Validate() error
    Validate reports whether n is one of the Networks above.

type Outcome int
    Outcome classifies a registrar's response to an UPDATE, from the requester's
    side: an SRP registrar's (client/srp, RFC 9665) or this proxy's RFC 9664
    handler's (client/rfc9664).

const (
	// OutcomeSuccess: NOERROR. The registration was accepted; GrantedLease reads the
	// granted LEASE/KEY-LEASE off the same response.
	OutcomeSuccess Outcome = iota
	// OutcomeConflict: YXDOMAIN, a First-Come First-Served conflict (RFC 9665 S3.3.3, and
	// the RFC 9664 handler's fcfs_naming): a different key already holds one of the names in
	// the update. An SRP requester renames and retries (client/srp); an RFC 9664 one, whose
	// names are typed and linked, waits for the name to be freed (client/rfc9664).
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

type Transport func(ctx context.Context, addr string, network Network, msg *dns.Msg) (*dns.Msg, error)
    Transport sends a signed UPDATE to addr over network and returns the
    response. Requesters default to LiveTransport; tests inject a fake.

func LiveTransport(timeout time.Duration) Transport
    LiveTransport sends msg to addr over network with this package's Client,
    the same transport every other client and test tool in this codebase uses.

```

## github.com/NetworkCommons/sig0lease/client/agent
```
package agent // import "github.com/NetworkCommons/sig0lease/client/agent"

Package agent is sig0lease-agent: one long-running client per machine that keeps
what a template (YAML) describes registered: hosts and their services through
SRP registrars (RFC 9665), and names and their records through this project's
proxy (RFC 9664).

A template lists its registrars, each with a protocol. An srp one holds hosts --
each one SRP identity with its own key -- and each host's services. A service
is an instance of a service type: a built-in preset ("ssh", "http", ...), or a
type the template defines with the same fields. A service whose probe fails is
withdrawn and registered again once it passes. Complex types are code, not data:
a template uses them but cannot define them; "mdns", under an srp registrar's
mirrors:, mirrors what a running mDNSResponder sees (client/mdnsbridge).
An rfc9664 one holds names, each with its own key, its addresses and its records
(client/rfc9664). See docs/sig0lease-agent.md.

CONSTANTS

const StateFile = "sig0lease-agent-state.json"
    StateFile is the agent's state, in the keystore: every host it registered,
    mirrored ones included, by requested host name, while its names may be held
    for its key, and under which labels if a rename changed any, and every name,
    while it may be held or has records registered. With it the agent frees
    the names of hosts and names the template no longer registers, even after
    a restart (agent.release), a host restarted frees the names a rename held
    before asking for its own again (clientsrp.StartHost), and a name's records
    the template no longer has are withdrawn.


FUNCTIONS

func Describe(w io.Writer, plan *Plan, interfaces func() ([]netip.Addr, error), logger *logging.Logger) error
    Describe writes what Run would register for plan. It reads, and changes
    nothing: this machine's addresses for auto (interfaces, InterfaceAddresses
    if nil), the keys the keystore holds, and in StateFile the names that Run
    frees: those an earlier run's renames hold (clientsrp.StartHost), and those
    of hosts and names the template no longer registers (agent.release).

func InterfaceAddresses() ([]netip.Addr, error)
    InterfaceAddresses returns the addresses of every interface of this machine.

func Run(ctx context.Context, path string, opts Options) error
    Run keeps what the template at path describes registered until ctx ends,
    then deregisters it all and returns ctx's error. It reads the template again
    every PollInterval: a valid change is applied, an invalid one logged while
    the agent keeps what it runs. Run returns early only for what it cannot go
    on without: a first template that is invalid, a keystore it cannot use,
    a state file edited by hand, a host or name its client refuses.


TYPES

type Host struct {
	Name      string
	Auto      bool         // this machine's addresses too, as they change
	Addresses []netip.Addr // literal addresses
	Services  []Service
	Lifetime  // the registrar's, with what the host overrides
}
    Host is one SRP identity: a name, its addresses and its services.

type Lifetime struct {
	Lease     uint32 // seconds
	KeyLease  uint32 // seconds
	KeepNames bool   // on_stop: keep; release frees them (clientsrp.HostConfig.KeepNames)
}
    Lifetime is how long a host's registration lasts: its records, its key,
    and whether its names outlive the agent stopping.

func (l Lifetime) String() string

type Mirror struct {
	Type         string // "mdns"
	Socket       string
	Hosts        []string // mDNS hosts, as given
	AllHosts     bool
	ServiceTypes []string // empty: every type the daemon sees
}
    Mirror is a complex type that makes its own hosts.

type Name struct {
	Name      string       // the label
	Auto      bool         // this machine's addresses too, as they change
	Addresses []netip.Addr // literal addresses
	Records   []dns.RR     // at or below the name, fully qualified; no address of the name
	Lifetime               // the registrar's, with what the name overrides
}
    Name is one RFC 9664 name: a label right below its registrar's zone, held by
    its own key, with its addresses and records.

type Options struct {
	// Logf receives the agent's log lines; a host's start with its label, a name's with the
	// name. Default: none.
	Logf func(format string, args ...any)
	// Logger receives keyrec's warnings about the keystore; default logging.NewLogger("info").
	Logger *logging.Logger
	// PollInterval is how often the template and this machine's addresses are read again;
	// default 10s.
	PollInterval time.Duration
	// A probed service is probed every ProbeInterval (default 30s), each attempt taking at
	// most ProbeTimeout (5s) per address, and withdrawn after ProbeFailures (3) failures in a
	// row. It is registered once a probe passes.
	ProbeInterval time.Duration
	ProbeTimeout  time.Duration
	ProbeFailures int
	// Settle and StopTimeout are each host's and name's (client.KeeperConfig).
	Settle      time.Duration
	StopTimeout time.Duration
	// Interfaces returns this machine's addresses, for addresses: [auto]; default those of
	// every interface. Only publishable ones are used (clientsrp.PublishableAddresses).
	Interfaces func() ([]netip.Addr, error)
	// Send, Query and Sleep are every SRP client's (clientsrp.Config), Send and Sleep every
	// RFC 9664 client's too (rfc9664.Config); nil: the clients' own.
	Send  baseclient.Transport
	Query clientsrp.DNSQuery
	Sleep func(context.Context, time.Duration) error
	// MirrorSource is the daemon an mdns mirror asks, given its socket; default
	// mdnsbridge.DaemonSource.
	MirrorSource func(socket string) mdnsbridge.Source
}
    Options tune Run; a zero field takes its default.

type Plan struct {
	Keystore   string      // absolute: one key per host and name, and the agent's state file
	Registrars []Registrar // in the template's order
}
    Plan is a valid template: everything the agent registers.

func Load(path string) (*Plan, error)
    Load reads and validates the template at path.

func Parse(data []byte, path string) (*Plan, error)
    Parse validates data, the template read from path; a relative keystore is
    relative to path's directory, and with none CLIENT_KEYSTORE_DIR is used
    (keyrec.KeystoreDir).

func (p *Plan) Mirror(t string) (Registrar, Mirror, bool)
    Mirror returns the template's mirror of type t, and the registrar it
    registers through.

type Probe struct {
	Kind ProbeKind
	Path string // ProbeHTTP's path
}
    Probe checks that a service answers, at one of its host's addresses and its
    port.

func (p Probe) String() string

type ProbeKind int
    ProbeKind is how a service is checked.

const (
	ProbeNone ProbeKind = iota // never checked: always registered
	ProbeTCP                   // a TCP connection to the port succeeds
	ProbeHTTP                  // an HTTP GET of Path answers 2xx or 3xx
)
type Protocol string
    Protocol is what a registrar is registered with.

const (
	SRP     Protocol = "srp"     // RFC 9665 (client/srp): hosts with their services, and mirrors
	RFC9664 Protocol = "rfc9664" // RFC 9664 through this project's proxy (client/rfc9664): names
)
type Registrar struct {
	Protocol  Protocol
	Domain    string             // SRP: the domain; RFC 9664: the zone. Fully qualified.
	Server    string             // "host:port"; SRP only: "" to discover the registrar
	Transport baseclient.Network //
	Resolvers []string           // SRP: for discovery and KEY lookups; nil: client/srp's default
	Lifetime                     // every host's or name's, unless it gives its own; the mirrors' hosts'
	Hosts     []Host             // SRP
	Mirrors   []Mirror           // SRP
	Names     []Name             // RFC 9664
}
    Registrar is where and how its hosts or names register.

func (r Registrar) Owner(label string) string
    Owner returns the name a host or name labelled label registers through r,
    fully qualified.

func (r Registrar) String() string

type Service struct {
	Type     string // the type's name: a preset or one the template defines
	Instance clientsrp.InstanceConfig
	Probe    Probe
}
    Service is one instance of a service type on a host.

type TypeInfo struct {
	Name    string
	Complex bool
	// Summary is the type's fields, as a template would write them, or what a complex type does.
	Summary string
}
    TypeInfo describes a service type for listings.

func Types() []TypeInfo
    Types lists the types a template can use: the presets and the complex types,
    by name.

type ValidationError struct {
	Path     string
	Problems []string
}
    ValidationError lists every problem a template has.

func (e *ValidationError) Error() string

```

## github.com/NetworkCommons/sig0lease/client/clienttest
```
package clienttest // import "github.com/NetworkCommons/sig0lease/client/clienttest"

Package clienttest has the registrar answers the client packages' tests share.

FUNCTIONS

func Answer(rcode uint16) *dns.Msg
    Answer is a registrar's answer with rcode and nothing else.

func Granted(lease, keyLease uint32) *dns.Msg
    Granted is a registrar's NOERROR answer granting lease and keyLease:
    the 8-byte Update Lease option echoed (RFC 9664 S4).

```

## github.com/NetworkCommons/sig0lease/client/mdnsbridge
```
package mdnsbridge // import "github.com/NetworkCommons/sig0lease/client/mdnsbridge"

Package mdnsbridge mirrors services that a running mDNSResponder sees on the
local link into a DNS zone through an SRP registrar. It learns them from the
daemon itself (browse, resolve and address lookups over its client socket,
see client/mdnsresponder) and registers each selected host, with its addresses
and its instances, through client/srp: one SRP identity, so one signing key,
per mDNS host.

When the daemon reports an instance gone, the bridge withdraws it; when a host
has no instance left, or the bridge stops, it deregisters the host. What it does
not follow: subtypes (a browse does not report them), and a host's later address
or TXT changes (it resolves an instance and looks up its host's addresses when
they first appear).

FUNCTIONS

func Run(ctx context.Context, cfg Config) error
    Run mirrors until ctx ends, then deregisters every host it registered and
    returns ctx's error. A browse that fails, such as one macOS refuses for lack
    of Local Network permission, stops it the same way, returning that error.

func Selects(hosts []string, allHosts bool, target string) bool
    Selects reports whether a bridge given Hosts hosts and AllHosts allHosts
    mirrors the mDNS host named target, as the user gives one ("MyMac",
    "mymac.local.").


TYPES

type Config struct {
	Source Source

	// ServiceTypes lists the types to mirror, e.g. "_ssh._tcp". Empty mirrors every type the
	// daemon enumerates (RFC 6763 S9, _services._dns-sd._udp.local.).
	ServiceTypes []string
	// Hosts lists the mDNS hosts whose instances are mirrored, as "name.local." or "name".
	// AllHosts mirrors every host on the link instead. Unless List is set, one of the two is
	// required: copying a whole network into a public zone has to be asked for.
	Hosts    []string
	AllHosts bool
	// List only reports what the daemon sees, marking the hosts that would be mirrored, and
	// registers nothing.
	List bool

	// SRP is the template for every host's SRP client: Domain, registrar, transport, leases.
	// Run sets HostLabel, Addresses, Instances and Key per host.
	SRP clientsrp.Config
	// Key returns the signing key for a host's name in SRP.Domain, e.g. from a keystore
	// (keyrec.ResolveOrCreateKey), so that a restarted bridge keeps its names.
	Key func(owner string) (*keyrec.LoadedKey, error)
	// Store, if set, keeps whether each host's names are held, and under which labels
	// (clientsrp.HostConfig.Store).
	Store clientsrp.HostStore
	// Exclude lists host labels never to mirror, compared without regard to case: hosts
	// something else registers under the same name and key, such as sig0lease-agent's own.
	Exclude []string

	// Settle and StopTimeout are each host's (client.KeeperConfig, with its defaults):
	// StopTimeout bounds the deregistrations sent when Run stops.
	Settle      time.Duration
	StopTimeout time.Duration
	// KeepNames keeps a host's names reserved for its key when it is deregistered, because
	// its last instance went or Run stopped (clientsrp.HostConfig.KeepNames).
	KeepNames bool
	Logf      func(format string, args ...any)
}
    Config configures Run.

type Source interface {
	Browse(ctx context.Context, serviceType, domain string, events chan<- mdnsresponder.BrowseEvent) error
	Resolve(ctx context.Context, interfaceIndex uint32, name, serviceType, domain string) (mdnsresponder.ResolveResult, error)
	Addresses(ctx context.Context, host string) ([]netip.Addr, error)
}
    Source is the daemon's side of the bridge. DaemonSource is the real one.

func DaemonSource(path string) Source
    DaemonSource is the mDNSResponder daemon listening on the Unix socket at
    path.

```

## github.com/NetworkCommons/sig0lease/client/mdnsresponder
```
package mdnsresponder // import "github.com/NetworkCommons/sig0lease/client/mdnsresponder"

Package mdnsresponder talks to a running mDNSResponder daemon over its own
client socket: the Unix-domain socket every DNS-SD application reaches
through dns_sd.h (mDNSShared/dnssd_clientstub.c on the client side,
mDNSShared/uds_daemon.c in the daemon). It implements the three read-only
operations a bridge needs -- browse, resolve and address lookup -- in pure Go,
so one binary talks to the system daemon on macOS and to mDNSPosix's mdnsd on
Linux without cgo.

Each operation gets its own connection, as DNSServiceBrowse and friends do
without kDNSServiceFlagsShareConnection. The daemon then returns the request's
status as four bytes on that same socket (no separate error socket is passed),
followed by the replies; closing the connection cancels the operation.

FUNCTIONS

func Addresses(ctx context.Context, socketPath string, interfaceIndex uint32, host string, settle time.Duration) ([]netip.Addr, error)
    Addresses returns host's IPv4 and IPv6 addresses on interfaceIndex (0 for
    any), as the daemon reports them through DNSServiceGetAddrInfo. The daemon
    sends each address as its own reply and nothing marks the last, so Addresses
    collects replies until none has arrived for settle, or until ctx ends.
    It fails if no address arrived.

func Browse(ctx context.Context, socketPath, serviceType, domain string, events chan<- BrowseEvent) error
    Browse browses for instances of serviceType ("_http._tcp") in domain
    ("local.") on every interface and sends each reply to events until ctx ends,
    when it returns ctx's error. A failed reply, including a policy denial,
    ends it with that error.

func DefaultSocketPath() string
    DefaultSocketPath is where the daemon listens on this OS:
    /var/run/mDNSResponder on macOS (dnssd_ipc.h's MDNS_UDS_SERVERPATH default),
    /var/run/mdnsd elsewhere (the path mDNSPosix/Makefile compiles into mdnsd).


TYPES

type BrowseEvent struct {
	Add            bool
	InterfaceIndex uint32
	Name           string // instance name as UTF-8 text, unescaped, e.g. "Living Room"
	Type           string // e.g. "_http._tcp."
	Domain         string // e.g. "local."
}
    BrowseEvent is one browse reply: an instance appeared (Add) or went away on
    one interface. The same instance is reported once per interface it is seen
    on.

type Error int32
    Error is a DNSServiceErrorType the daemon returned, as a request status or
    in a reply.

const (
	ErrNoSuchRecord Error = -65554 // kDNSServiceErr_NoSuchRecord
	ErrNoAuth       Error = -65555 // kDNSServiceErr_NoAuth
	ErrPolicyDenied Error = -65570 // kDNSServiceErr_PolicyDenied
)
func (e Error) Error() string

type ResolveResult struct {
	FullName string // escaped, e.g. `Living\032Room._http._tcp.local.`
	Target   string // host name, e.g. "printer.local."
	Port     uint16
	// TXT holds the instance's TXT strings as raw bytes, in order (RFC 6763 S6).
	TXT [][]byte
}
    ResolveResult is a resolved service instance.

func Resolve(ctx context.Context, socketPath string, interfaceIndex uint32, name, serviceType, domain string) (ResolveResult, error)
    Resolve resolves the instance a browse reply named (its Name, Type and
    Domain, unchanged) on interfaceIndex, and returns the first answer.

```

## github.com/NetworkCommons/sig0lease/client/rfc9664
```
package rfc9664 // import "github.com/NetworkCommons/sig0lease/client/rfc9664"

Package rfc9664 implements a requester for this proxy's RFC 9664 handler
(update_handler): one name, held by its own key, with records at and below it,
registered as a DNS UPDATE signed with SIG(0) and kept on an Update Lease (RFC
9664). The name is one label below the zone, the only name a key registers for
itself under the handler's fcfs_naming (docs/siglease_rfc9664.md, "First-Come
First-Served Naming"). Every request carries the name's KEY in its Update
section, so the proxy verifies it with the key it registers, and is one of the
handler's lease cases (Behavior Specification item 5):

  - Register: Case A, the KEY and the records, both leases non-zero;
  - Withdraw, and Deregister keeping the name: Case D, the KEY and the records
    to delete, a LEASE of 0 and the KEY-LEASE, which keeps the name for the key;
  - Deregister freeing the name: Case C, the KEY alone, both leases 0, which
    deletes the KEY and everything it registered.

A name another key holds is answered YXDOMAIN. An SRP requester renames
(client/srp), as its names are found by browsing; an RFC 9664 name is typed or
linked (a URL, a DNSLink path, a Matrix ID), so a rename would publish records
nobody reads. Run therefore keeps trying the name, with a backoff: it registers
once the other key's lease ends, which is when a name an earlier key of the
requester's own holds comes back to it.

Name keeps one name registered as its records change, as client/srp's Host does
a host.

FUNCTIONS

func CheckRecords(name string, records []dns.RR) error
    CheckRecords reports whether records can be registered for name: each at
    name or below it, of class IN, and neither a KEY (name's own is its key's)
    nor a SIG.

func Describe(rr dns.RR) string
    Describe describes rr for people: its owner, type and data, without the TTL
    a lease overrides and the class, always IN.

func Diff(before, after []dns.RR) []dns.RR
    Diff returns the records of before that after lacks, compared as the
    proxy's lease store does (lease.RecordKey: owner, class, type and data,
    not the TTL).

func ParseRecords(name string, specs []string, bad func(i int, err error)) []dns.RR
    ParseRecords reads specs as records of name, the fully qualified name,
    the way a template's records: and sig0lease-client name's -record give them:
    "<owner> <type> <data>", the owner @ for name itself or relative to
    it (_dnslink, www), the data in zone-file format. A record must be one
    CheckRecords takes, not an A or AAAA at name, whose addresses are given
    apart (WithAddresses), and given once. It returns the records it read, in
    order, and calls bad with the index of each spec it could not read and why.

func Release(cfg NameConfig) error
    Release frees a name that is not running and may still be held from an
    earlier run: one deregistration of the KEY alone with both leases 0 (Case
    C), which deletes every record the key registered with it, bounded by
    cfg.StopTimeout. cfg.Store records the name as freed once the proxy confirms
    it, or answers that another key holds it now. Release returns an error only
    for a client configuration NewClient refuses; a deregistration that fails is
    logged, and the name stays recorded as held.

func WithAddresses(name string, addrs []netip.Addr, records []dns.RR) []dns.RR
    WithAddresses returns what name registers: an A or AAAA record at name for
    each of addrs, then records.


TYPES

type Client struct {
	// Has unexported fields.
}
    Client is one name's registration: build, sign, send, and (Run) keep it on
    the refresh clock.

func NewClient(cfg Config) (*Client, error)
    NewClient validates cfg and applies its defaults.

func (c *Client) Deregister(ctx context.Context, keepName bool) (*dns.Msg, baseclient.Outcome, error)
    Deregister deletes the name's records. With keepName it deletes
    Config.Records and keeps the KEY for RequestedKeyLease (Case D), so that no
    other key takes the name meanwhile; without it, it deletes the KEY (Case C),
    which takes every record the key registered with it, and the name is free.

func (c *Client) Name() string
    Name returns the name the client registers, fully qualified.

func (c *Client) Register(ctx context.Context) (*dns.Msg, baseclient.Outcome, error)
    Register registers the name's KEY and Config.Records, on the requested
    leases (Case A). The handler needs a record besides the KEY in a
    registration: with no records, Register fails, and Deregister keeping the
    name holds it alone.

func (c *Client) Run(ctx context.Context) error
    Run keeps the name registered (client.Lifecycle.Run): it registers,
    then again on the RFC 9664 S5.2 refresh clock, until ctx is canceled.
    A registration that fails, a name another key holds included, is reported to
    Config.OnError and tried again after a backoff.

func (c *Client) Withdraw(ctx context.Context, records []dns.RR) (*dns.Msg, baseclient.Outcome, error)
    Withdraw deletes records, registered earlier, from the name, and refreshes
    its KEY (Case D).

type Config struct {
	Zone  string // the zone the name is in, sent as the Zone Section; trailing dot optional
	Label string // the name's single label: the name is Label.Zone
	// Key is the name's SIG(0) key: required, as the key is what holds the name.
	Key *keyrec.LoadedKey
	// Records are what Register registers: records at the name or below it, fully
	// qualified, of class IN. No KEY, the name's own being Key's, and no SIG. Their TTLs are
	// replaced with TTL.
	Records []dns.RR

	RequestedLease    uint32 // default 3600 (1h)
	RequestedKeyLease uint32 // default 1209600 (14d)
	// TTL is the TTL suggested for every record registered, the KEY included; the proxy may
	// override it. Independent of the leases: a lease is not a TTL. Default 300.
	TTL uint32

	// Server is the proxy, "host:port". Required: RFC 9664 has no registrar discovery.
	Server  string
	Network baseclient.Network // default NetworkTCP
	Timeout time.Duration      // per-request transport timeout; default 20s

	Send  baseclient.Transport                       // default baseclient.LiveTransport(Timeout)
	Rng   *rand.Rand                                 // default a fresh per-Client source (see client.Lifecycle.Rng)
	Sleep func(context.Context, time.Duration) error // default baseclient.SleepContext

	// OnError and OnRegistered are Run's (client.Lifecycle).
	OnError      func(error)
	OnRegistered func(resp *dns.Msg)
}
    Config configures a Client. See NewClient for the defaults.

type Name struct {
	*baseclient.Keeper[[]dns.RR]

	// Has unexported fields.
}
    Name keeps one name registered as its records change: each Set restates
    the records, and the Name registers them (Client.Run, refreshing on the
    lease clock), first withdrawing those that are gone, those Store kept from
    an earlier run included. No records means no registration: the name is
    deregistered, as it is when the Name stops (the Keeper's Stop and Wait).
    While the registrar answers that another key holds the name, nothing at it
    is this key's: no withdrawal or deregistration is sent.

func StartName(cfg NameConfig) (*Name, error)
    StartName starts keeping cfg.Client's name registered. It registers nothing
    until the first Set, which withdraws the records Store has for the name that
    the Set lacks.

func (n *Name) Set(records []dns.RR)
    Set replaces the records the name should have registered (Keeper.Set).

type NameConfig struct {
	// Client is the template for every Client the Name makes: Zone, Label, Key, the proxy,
	// transport and leases. The Name sets Records, OnRegistered and OnError.
	Client Config
	// Store, if set, keeps the records registered at the name, loaded at start and saved
	// after every registration and deregistration, and whether the name is held.
	Store NameStore
	// KeeperConfig: KeepNames applies to deregistering the name, on Stop or a Set with no
	// records (Client.Deregister).
	baseclient.KeeperConfig
}
    NameConfig configures StartName.

type NameStore interface {
	// Load returns the records saved for name, the fully qualified name, or nil.
	Load(name string) []dns.RR
	// Save records what name holds: whether the name is held for its key (true after every
	// registration that succeeded, false once a deregistration freed it), and the records
	// registered there. A store need not write anything when nothing changes.
	Save(name string, held bool, records []dns.RR) error
}
    NameStore keeps what a name needs across restarts: the records registered at
    it, so that those a later start no longer has are withdrawn, and whether the
    name is held for its key, so that a name no longer wanted can be freed after
    a restart (Release).

```

## github.com/NetworkCommons/sig0lease/client/srp
```
package srp // import "github.com/NetworkCommons/sig0lease/client/srp"

Package srp implements an RFC 9665 SRP requester: discovery, message building
(via pkg/srp), the RFC 9664 S5.2 refresh scheduler, YXDOMAIN rename-retry, and
Host, which keeps one host registered as what it offers changes. This library
is the deliverable; cmd/sig0lease-srp-client is a thin, non-shipped dev/test
CLI over it, and cmd/sig0lease-agent registers a template's hosts with it.
Deliberately not a full RFC 9665 requester (no mDNS-based default.service.arpa.
discovery, no CNN transport handling -- both out of scope for now) -- this
targets the registrar's actual supported shape: an explicitly configured zone,
reached over TCP by default.

FUNCTIONS

func Discover(ctx context.Context, query DNSQuery, domain string, mode DiscoveryMode, network baseclient.Network) (string, error)
    Discover finds the SRP registrar for domain that is reachable over network.
    As RFC 9665 S3.1.1 specifies, it first finds the apex of the closest DNS
    zone enclosing domain with SOA queries (RFC 8765 S6.1, see zoneApex).
    It then looks up the SRV record at "<service>.<name>.", where service
    is network's DiscoveryService -- "_dnssd-srp-tls._tcp" for NetworkTLS,
    "_dnssd-srp._tcp" otherwise, the service names RFC 9665 S10.4 registers
    in RFC 6763 S7's "_<service>._tcp" form -- for each name mode selects
    (see DiscoveryMode), in order, and stops at the first name that has one.
    A NetworkTLS search never falls back to "_dnssd-srp._tcp": S7 says a
    requester able to use TLS SHOULD NOT fall back to TCP. It never looks
    above the apex: a zone cut separates authority, so a registrar named in
    the parent zone speaks for nothing in the child. A failed query ends the
    search with its error instead of moving on to the next name, since the name
    it could not ask about may hold the answer. The best (lowest-priority,
    highest-weight-among-ties) SRV target is then resolved to an address with
    the same query, so every step of discovery asks the same resolvers: a target
    that only those resolvers know (a lab DNS, the local BIND 9 test zone) still
    works. Returns "address:port". A caller with an explicit registrar address
    configured should skip this entirely (see Config.RegistrarAddr) -- discovery
    is the fallback, not the only path, matching cmd/sig0lease-srp-client's own
    "dev/test tool" framing.

func DiscoveryService(n baseclient.Network) string
    DiscoveryService returns the service whose SRV record names a registrar
    reachable over n: "_dnssd-srp-tls._tcp" for NetworkTLS (RFC 9665 S10.4.2),
    "_dnssd-srp._tcp" otherwise (S10.4.1).

func EscapeTXT(raw string) string
    EscapeTXT turns raw, one TXT string's octets, into the form
    InstanceConfig.TXT takes. It is presentation text, as codeberg.org/miekg/dns
    packs it, where a backslash starts an escape, so only backslashes need
    escaping for every other octet to go out as it is.

func PublishableAddresses(addrs []netip.Addr) []netip.Addr
    PublishableAddresses returns the addresses in addrs that mean something off
    the link: not loopback, link-local, unspecified or multicast.

func Release(cfg HostConfig) error
    Release frees the names a host that is not running may still hold from an
    earlier run: one deregistration of the host alone asking for a KEY-LEASE of
    0, under the labels cfg.Store keeps for it, bounded by cfg.StopTimeout. The
    registrar removes the host's service instances with it (RFC 9665 S3.2.5.5.1:
    "even if the SRP requester doesn't list them"). cfg.Store records the names
    as freed once the registrar confirms it, or answers that another key holds
    the host name now. Release returns an error only for a client configuration
    NewClient refuses; a deregistration that fails is logged, and the names stay
    recorded as held.


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

func (c *Client) Deregister(ctx context.Context, keepNames bool) (*dns.Msg, baseclient.Outcome, error)
    Deregister withdraws this identity's entire registration in one message:
    the host's address data (S3.3.1.3's "zero Add operations means delete this
    host's registration") and every configured service instance (each restated
    as a bare Delete-All, InstanceSpec.Remove). Matches S3.2's "no lightweight
    refresh" -- a removal is a normal UPDATE that restates everything, not a
    distinct wire operation. One-shot, like Register; there is no rename-retry
    equivalent since a removal can't conflict (FCFS only ever blocks an
    add-shaped instruction).

    Also requests LEASE=0: S3.2.5.5.1's removal is both, a LEASE of 0 and no
    address (S3.3.1.3 allows zero address Adds only "in the case of deleting a
    registration"). Registrars go by the LEASE: srp-mdns-proxy (srp-parse.c,
    host_lease == 0, confirmed by tests/test_mdnsresponder_interop.sh),
    OpenThread's (Host::IsDeleted) and this proxy (pkg/srp.RemoveHost) take
    any LEASE of 0 as a removal, and refuse, or for srp-mdns-proxy tolerate,
    no address with a LEASE (pkg/srp's validateHostAddresses).

    keepNames picks the KEY-LEASE, RFC 9665 S3.2.5.5.1's two kinds of removal:
    "If the registration is to be permanently removed, KEY-LEASE SHOULD also
    be zero. Otherwise, it SHOULD be set to the same value it had previously;
    this holds the name in reserve for when the SRP requester is once again able
    to provide the service." So with keepNames the KEYs stay, at the host's name
    and each instance's, for c.cfg.RequestedKeyLease; without it they go with
    the rest and the names are free.

func (c *Client) Labels() Labels
    Labels returns the labels the client registers under now, after any renames.

func (c *Client) Register(ctx context.Context) (*dns.Msg, baseclient.Outcome, error)
    Register performs exactly one build-sign-send-interpret cycle:
    no rename-retry, no scheduling. Callers wanting the full lifecycle (initial
    delay, refresh clock, automatic rename-retry) should use Run instead;
    Register is the primitive Run is built from, and is also useful standalone
    for a one-shot CLI invocation.

func (c *Client) Run(ctx context.Context) error
    Run performs the full RFC 9665 requester lifecycle (client.Lifecycle.Run):
    it registers, with rename-retry on conflict, then again on the RFC 9664 S5.2
    refresh clock, restating the full registration every time, per S3.2's "no
    lightweight refresh", until ctx is canceled. A failed registration does not
    stop it: Config.OnError is called, and it tries again after a backoff.

type Config struct {
	Domain    string // registration domain (Zone Section name); trailing dot optional
	HostLabel string // base host label -- see InstanceConfig's doc comment
	Addresses []netip.Addr
	Instances []InstanceConfig

	// Key is this identity's SIG(0) signing key. Nil generates a fresh P-256 key at
	// NewClient (the default) -- SRP identities are typically ephemeral/device-local, so
	// generating rather than requiring a pre-provisioned keystore file is the common case.
	Key *keyrec.LoadedKey

	RequestedLease    uint32 // default 3600 (1h)
	RequestedKeyLease uint32 // default 1209600 (14d, S3.4's "typically 14 days")
	// TTL is the TTL suggested for every record registered, KEYs included; the registrar may
	// override it (RFC 9665 S4). Independent of the leases: a lease is not a TTL (S5.1).
	// Default 300.
	TTL uint32

	// RegistrarAddr, if set, bypasses discovery entirely -- an explicit "host:port",
	// matching every other test/dev client this project's test suite already uses.
	// Discovery (the `_dnssd-srp._tcp` SRV, or `_dnssd-srp-tls._tcp` for NetworkTLS,
	// closest to Domain within its zone, or at the zone apex only -- see Discover and
	// Discovery) is the fallback when this is empty.
	RegistrarAddr string
	Discovery     DiscoveryMode // where discovery looks for the SRV; DiscoveryClosest (the zero value) by default
	Resolvers     []string      // bootstrap resolvers for discovery; LiveDNSQuery's default if empty
	Query         DNSQuery      // discovery implementation; LiveDNSQuery(Resolvers) if nil

	Network    baseclient.Network // default NetworkTCP (S3.5's MUST for non-constrained networks)
	Timeout    time.Duration      // per-request transport timeout; default 20s
	MaxRenames int                // default 5 -- rename-retry attempts before giving up on YXDOMAIN

	// Labels, if set, are the labels to register under instead of the requested ones: what an
	// earlier Client renamed them to (Client.Labels, OnRenamed), so that a Host keeps its
	// names from one registration to the next, and Release frees the names it holds. Each must
	// be the label it stands for, or a rename of it. Entries for instances not in Instances are
	// kept, for when those instances return.
	Labels *Labels
	// OnRenamed, if set, is called with the labels in use after every rename, from the
	// goroutine registering (Run's, or Register's caller's).
	OnRenamed func(Labels)

	Send  baseclient.Transport                       // default baseclient.LiveTransport(Timeout)
	Rng   *rand.Rand                                 // default a fresh per-Client source (see client.Lifecycle.Rng)
	Sleep func(context.Context, time.Duration) error // default baseclient.SleepContext

	// OnError, if set, is called from Run with every error a registration cycle hits
	// (transient network/DNS failure, a registrar rejection, rename attempts exhausted).
	// Run itself never stops because of one -- see Run's own doc comment -- so this is
	// the caller's only hook for surfacing/logging those failures as they happen; nil is
	// a valid no-op default.
	OnError func(error)

	// OnRegistered, if set, is called from Run with the registrar's response after every
	// successful registration cycle -- the initial registration and each subsequent
	// refresh alike, Run's success-path counterpart to OnError. Without it, a caller
	// running the full lifecycle has no visibility into whether it's still actually
	// succeeding (as opposed to just not having crashed) or what the registrar is
	// currently granting; nil is a valid no-op default.
	OnRegistered func(resp *dns.Msg)
}
    Config configures a Client. See NewClient's doc comment for defaults.

type DNSQuery func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
    DNSQuery is the shape of a live DNS lookup, injected so Discover is testable
    without real network I/O. It returns the whole response, since discovery
    reads both the Answer section (SRV, or an SOA at a zone apex) and the
    Authority section (the SOA a negative answer carries). A NOERROR or NXDOMAIN
    response is an answer, not an error.

func LiveDNSQuery(resolvers []string) DNSQuery
    LiveDNSQuery returns a DNSQuery that performs a real lookup against
    resolvers (falling back to defaultBootstrapResolvers if empty), trying
    each in turn until one answers with NOERROR or NXDOMAIN. Any other RCODE
    (SERVFAIL, REFUSED, ...) counts as that resolver failing, like a network
    error.

type DiscoveryMode int
    DiscoveryMode selects the names Discover looks under for the registrar's SRV
    record.

const (
	// DiscoveryClosest, the default, looks under the registration domain first, then under
	// each parent name in turn, ending at the apex of the zone enclosing it. The first name
	// with an SRV record wins, so a record under a subdomain names the registrar for that
	// subdomain and everything below it, the way the apex record does for the whole zone.
	// This goes beyond RFC 9665 S3.1.1, which looks only under the apex, so that a registrar
	// can serve one registration domain inside a zone without a zone cut at that domain
	// (https://github.com/NetworkCommons/sig0lease/issues/46). A domain with no record below
	// the apex finds exactly what S3.1.1 finds. A record below the apex is one that a
	// requester following S3.1.1 alone never sees -- S3.1.1 leaves other discovery
	// mechanisms open.
	DiscoveryClosest DiscoveryMode = iota
	// DiscoveryApexOnly looks only under the zone apex, as RFC 9665 S3.1.1 specifies: it
	// finds the registrar any S3.1.1 requester would find.
	DiscoveryApexOnly
)
type Host struct {
	*baseclient.Keeper[hostState]

	// Has unexported fields.
}
    Host keeps one host registered as what it offers changes: each Set restates
    its addresses and instances, and the Host registers them (Client.Run,
    refreshing on the lease clock), first withdrawing instances that are gone.
    No addresses means no registration: the host is deregistered (RFC 9665
    S3.3.1.3), as it is when the Host stops (the Keeper's Stop and Wait).
    Labels carry over from one registration to the next, so a renamed host
    keeps its names while it runs; a new Host asks for the requested names again
    (StartHost).

func StartHost(cfg HostConfig) (*Host, error)
    StartHost starts keeping cfg.Client.HostLabel registered. It registers
    nothing until the first Set. Every Host asks for the requested names: if
    cfg.Store says an earlier Host's rename holds names, kept when it stopped,
    StartHost first frees them (Release), so that they are not held beside the
    requested ones. If that fails, the Host registers under them, as its key
    still holds them, and the next start tries again.

func (h *Host) Set(addrs []netip.Addr, instances []InstanceConfig)
    Set replaces what the host should have registered with addrs and instances
    (Keeper.Set).

type HostConfig struct {
	// Client is the template for every Client the Host makes: Domain, HostLabel, Key, the
	// registrar, transport and leases. Key is required: a host keeps one identity. The Host
	// sets Addresses, Instances, Labels, OnRenamed, OnRegistered and OnError.
	Client Config
	// Store, if set, keeps whether the host's names are held, and under which labels.
	Store HostStore
	// KeeperConfig: KeepNames applies to deregistering the host, on Stop or a Set with no
	// addresses (Client.Deregister).
	baseclient.KeeperConfig
}
    HostConfig configures StartHost.

type HostStore interface {
	// Load returns the labels the names of the host whose requested name is host are held
	// under, or nil if none are held.
	Load(host string) *Labels
	// Hold records the labels the host's names are held under: after every registration that
	// succeeded; nil once a deregistration freed them. A store need not write anything when
	// nothing changes.
	Hold(host string, labels *Labels) error
}
    HostStore keeps what a host needs across restarts: whether its names are
    held for its key, and under which labels (see Labels), so that they can
    be freed after a restart: those of a host no longer wanted (Release),
    and those a rename holds, as every start asks for the requested names again
    (StartHost).

type InstanceConfig struct {
	Label       string   // single label, e.g. "My Printer" -- not a full instance name; NewClient rejects one containing "." (dnsname.CheckLabel)
	ServiceType string   // e.g. "_ipps._tcp" -- not a full service-type name; NewClient rejects any other shape (dnssd.ValidateServiceType)
	Subtypes    []string // additional bare subtype labels, e.g. "_universal"; checked like Label
	Port        uint16
	TXT         []string // presentation text, where a backslash starts an escape: see EscapeTXT
	// Remove withdraws this instance instead of registering it (RFC 9665 S3.2.5.5.2, first
	// method): the update carries a bare Delete All RRsets for its name, and Port, TXT and
	// Subtypes are ignored. The host and every other instance are registered as usual.
	Remove bool
}
    InstanceConfig describes one service instance to register, in the same
    "label relative to Domain" terms as HostLabel -- Client joins these into
    fully-qualified names when building the update (pkg/srp.BuildUpdate itself
    takes only already-qualified names).

type InstanceName struct {
	Label       string
	ServiceType string
}
    InstanceName identifies a requested instance: its label as configured
    (InstanceConfig.Label) and its service type.

type Labels struct {
	Host      string
	Instances map[InstanceName]string
}
    Labels are the labels a registration uses after renames: the host's, and
    each instance's by its requested name. A label is renamed when a different
    key holds the name it makes, to the requested label with "-2" appended,
    then "-3", and so on (see renameHeld); an instance absent from Instances is
    registered under its requested label.

func (l Labels) Renamed(hostLabel string) bool
    Renamed reports whether l differs from the requested labels: hostLabel for
    the host, and each instance's own.

```

## github.com/NetworkCommons/sig0lease/cmd/internal/cli
```
package cli // import "github.com/NetworkCommons/sig0lease/cmd/internal/cli"

Package cli has what this project's client commands share, so that they read
alike: sig0lease-client and sig0lease-srp-client take "<command> [flags]
[args]" (the SRP client has no command), with the same flags for the same
things (-server, -transport, -keystore, -k, -lease, -key-lease, -ttl), the same
signing-key convention, the same reply printing, and, for the commands that keep
a registration, the same modes (-once, -deregister, -keep-names).

FUNCTIONS

func DefineKeystore(fs *flag.FlagSet, dir *string)
    DefineKeystore defines -keystore on fs, read into dir: the directory holding
    the signing keys (KeystoreDir).

func Exit(resp *dns.Msg, outcome client.Outcome, err error)
    Exit prints the reply to a single request, and exits non-zero unless it
    succeeded.

func Fail(err error)
    Fail prints err and exits 1.

func KeystoreDir(given string) (string, error)
    KeystoreDir is the keystore given, else the one CLIENT_KEYSTORE_DIR names
    (keyrec.KeystoreDir).

func PrintEDEs(resp *dns.Msg)
    PrintEDEs prints the Extended DNS Errors (RFC 8914) in resp, one per line:
    the reason for a refusal, or a success's notes.

func PrintReply(resp *dns.Msg, outcome client.Outcome)
    PrintReply prints resp's status and Extended DNS Errors, and, for a success,
    the leases granted.

func Stamp() string
    Stamp prefixes a line a running command prints with the time.


TYPES

type Endpoint struct {
	Server    string
	Transport client.Network
}
    Endpoint holds the flags saying where a command sends: -server and
    -transport.

func (e *Endpoint) Define(fs *flag.FlagSet, server string)
    Define defines Endpoint's flags on fs; server says what -server is for that
    command.

func (e *Endpoint) RequireServer() error
    RequireServer reports a missing -server, for the commands that cannot
    discover one.

type Modes struct {
	Once       bool
	Deregister bool
	KeepNames  bool
}
    Modes holds the flags that choose what such a command does: by default
    it keeps the registration until Ctrl-C or SIGTERM; -once registers once,
    -deregister deregisters.

func (m *Modes) Check() error
    Check reports flags that do not go together.

func (m *Modes) Define(fs *flag.FlagSet, what string)
    Define defines Modes' flags on fs; what names what -deregister withdraws.

func (m *Modes) Run(c Requester)
    Run does with c what the modes say, printing each reply, and exits
    non-zero when that failed. Kept registered, c prints its own replies (its
    OnRegistered and OnError).

type Repeatable []string
    Repeatable collects every occurrence of a flag, in order.

func (r *Repeatable) Set(v string) error

func (r *Repeatable) String() string

type Request struct {
	Endpoint
	Keystore string
	KeyAlg   uint
	Lease    uint
	KeyLease uint
	TTL      uint
}
    Request holds the flags of a command that sends signed updates: Endpoint's,
    -keystore, -k, -lease, -key-lease and -ttl.

func (r *Request) Check() error
    Check reports a flag value a request cannot carry.

func (r *Request) Define(fs *flag.FlagSet, server string)
    Define defines Request's flags on fs; server says what -server is for that
    command.

func (r *Request) Key(owner string) (*keyrec.LoadedKey, error)
    Key finds owner's signing key in the keystore or, with -k, generates one
    there (keyrec.ResolveOrCreateKey), and says when it did.

type Requester interface {
	Register(ctx context.Context) (*dns.Msg, client.Outcome, error)
	Deregister(ctx context.Context, keepNames bool) (*dns.Msg, client.Outcome, error)
	Run(ctx context.Context) error
}
    Requester is what a command that keeps a registration drives: client/srp's
    Client or client/rfc9664's.

```

## github.com/NetworkCommons/sig0lease/cmd/sig0lease
```
Package main implements the DNS proxy server.
```

## github.com/NetworkCommons/sig0lease/cmd/sig0lease-agent
```
Package main implements sig0lease-agent: the long-running client that keeps what
a template describes registered: hosts and services through SRP registrars,
names and their records through the sig0lease proxy's RFC 9664 handler
(client/agent). See docs/sig0lease-agent.md.
```

## github.com/NetworkCommons/sig0lease/cmd/sig0lease-client
```
Package main implements sig0lease-client, the RFC 9664 client of this project's
proxy. Its update commands (register, refresh, register-tamper) send exactly
the update their arguments describe, the shapes the proxy must refuse included,
so the test suites can check its answers; name keeps a name registered through
client/rfc9664, as sig0lease-srp-client does a host through client/srp. Both
spell their flags alike (cmd/internal/cli).
```

## github.com/NetworkCommons/sig0lease/cmd/sig0lease-srp-client
```
Package main implements sig0lease-srp-client, a thin CLI over client/srp
-- a dev/test tool, not a shipped product. The library is the deliverable;
this just exercises it. The long-running client that keeps a machine's
services registered, mirroring what the local mDNSResponder sees among them, is
sig0lease-agent. Its flags are spelled as sig0lease-client's (cmd/internal/cli).
```

## github.com/NetworkCommons/sig0lease/config
```
package config // import "github.com/NetworkCommons/sig0lease/config"

Package config provides configuration for the DNS proxy.

TYPES

type AuthoritativeConfig struct {
	// MaxInflightUpdates caps how many UPDATEs the proxy has in flight to one authoritative
	// server at a time; 0 means no limit. Every UPDATE it sends is SIG(0)-signed, and BIND 9.20
	// answers REFUSED to a SIG(0) request beyond its sig0checks-quota (default 1) instead of
	// queueing it, so set this to the upstream server's sig0checks-quota.
	MaxInflightUpdates int `yaml:"max_inflight_updates"`
}
    AuthoritativeConfig holds limits on the UPDATEs this proxy sends to
    authoritative servers.

type Config struct {
	// Downstream server settings
	Server ServerConfig `yaml:"server"`

	// Upstream resolver settings
	Upstreams []UpstreamConfig `yaml:"upstreams"`

	// Opcode processing rules - opcodes listed here are processed by modules
	ProcessingRules []ProcessingConfig `yaml:"processing_rules"`

	// Handler-specific configuration (e.g., for update handler)
	Handlers map[string]map[string]interface{} `yaml:"handlers"`

	// Limits on the UPDATEs sent to authoritative servers, shared by every handler
	Authoritative AuthoritativeConfig `yaml:"authoritative"`
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
    lookup.

func (c *Config) Use4ByteVariant() bool
    Use4ByteVariant returns true if 4-byte variant is explicitly enabled via
    config. Returns false by default (8-byte variant is the default for all
    lease requests).

func (c *Config) Validate() error
    Validate checks that the configuration is valid.

type ProcessingConfig struct {
	// Opcode is the DNS opcode to match (0=QUERY, 1=IQUERY, 2=STATUS, etc.)
	Opcode uint8 `yaml:"opcode"`
	// Modules is the ordered list of processing module names to try for this opcode:
	// the router calls each in turn until one returns Processed or Error; if every one
	// declines (NotRelevant), the opcode falls through to plain upstream forwarding. A
	// single-module list (the common case today, e.g. just "update_handler") behaves
	// exactly as the old single-"module" field did.
	Modules []string `yaml:"modules"`
}
    ProcessingConfig holds opcode-specific processing configuration.

type ServerConfig struct {
	// Address is the address to listen on (e.g., ":53")
	Address string `yaml:"address"`
	// Networks are the network protocols to enable ("udp", "tcp", "tls")
	Networks []string `yaml:"networks"`
	// TLS configures the "tls" network (DNS-over-TLS, RFC 7858):
	// opportunistic only, no client-certificate/key-pinning auth -- transport-level, so it
	// benefits every handler (base RFC 9664, SRP, plain forwarding alike), not just one
	// protocol. Required when "tls" appears in Networks; ignored otherwise.
	TLS *TLSConfig `yaml:"tls,omitempty"`
	// RequestTimeout bounds how long the handlers may work on one request, including any
	// wait for a lease-store node another request holds (docs/siglease_rfc9664.md, "Node
	// Locks"). Must be positive: without a bound, a waiter could wait forever.
	RequestTimeout time.Duration `yaml:"request_timeout"`
	// Diagnostics lets clients see the proxy's internals, for testing and debugging: the
	// reason text in the Extended DNS Error (RFC 8914) of each error reply, and the lease-store
	// dump query (__dump.sig0lease.internal[.debug]. TXT). Off by default, as it should be in
	// production: error replies then carry only the Extended DNS Error's code, and the dump
	// query is answered REFUSED with code 18 (Prohibited).
	Diagnostics bool `yaml:"diagnostics"`
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

FUNCTIONS

func LeaseSnapshotPath(cfg map[string]any) (string, error)
    LeaseSnapshotPath returns the snapshot file of the file store a handler's
    Setup config selects (selectLeaseStore), or "" if it selects none.
    cmd/sig0lease checks the handlers' snapshot files with it before any Setup
    runs.

func SeparateZones(hs []ZoneHandler) error
    SeparateZones gives every name at most one of hs: the handler whose zone
    is the closest one above it, as a zone cut does in DNS. Each handler
    learns the zones the others serve below its own, and refuses their
    names (refuseNamesNotServed); with srp.dev.zenr.io. for srp_handler and
    dev.zenr.io. for update_handler, update_handler refuses every name at or
    below srp.dev.zenr.io. Two handlers serving one zone leave no closest one,
    and are an error. The proxy calls it once, after every handler's Setup and
    before serving.


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

	// Start begins the handler's background work, such as lease expiry. The server calls it
	// once, after Setup and before it serves; a dump never calls it.
	Start()

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

func LeaseStoreFromConfig(cfg map[string]any, logger *logging.Logger, readOnly bool) (LeaseManager, error)
    LeaseStoreFromConfig returns the lease store a handler's Setup
    config selects (selectLeaseStore): the "lease_manager" given,
    one built from the "storage" section, or the in-memory default.
    A "file" store loads its snapshot, writes it straight back and keeps
    saving it (leasepkg.NewFileLeaseStore); logger receives its save errors.
    With readOnly, a "file" store is instead its snapshot as it is now,
    read into an in-memory store that never saves, and nothing is created or
    written: cmd/sig0lease's dump mode hands that to Setup as "lease_manager".
    leaseHandler.setup uses it with readOnly false, for both handlers.

type LeasePolicy struct {
	MinKeyLease uint32
	MaxKeyLease uint32
	MinRRLease  uint32
	MaxRRLease  uint32
}
    LeasePolicy controls clamping for lease durations. A zero bound is no
    bound. UpdateHandler and SRPHandler each hold one, read from their own
    "lease_policy" config by parseLeasePolicy, and clamp every granted lease
    with LeasePolicy.clamp.

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
	leaseHandler[srpCoordinator]

	// Has unexported fields.
}
    SRPHandler implements handlers.Handler for opcode 5 (UPDATE), the RFC
    9665 SRP path -- a sibling to UpdateHandler, never a branch inside it:
    SRP's message shape and authorization model (FCFS, delete-all-then-add,
    no per-record parent/key walk) contradict two of UpdateHandler's own checks
    (validateSignerHierarchyForUpdateRecords, filterDuplicateRegistrations),
    so it needs its own Handle() rather than a mode flag on the existing one.
    See docs/siglease_rfc9665.md for the design this implements; comments below
    cite RFC 9665 sections as "S<n>".

func NewSRPHandler() *SRPHandler
    NewSRPHandler creates a new handler for opcode 5 (UPDATE), RFC 9665 SRP
    path.

func (h *SRPHandler) DumpLeasesLevel(level string) string
    DumpLeasesLevel implements the same dump-endpoint interface UpdateHandler
    does (see server/router.go's handleDumpQuery), so SRP-managed state shows up
    in the same __dump.sig0lease.internal[.debug] query operators already use. A
    simpler format than UpdateHandler's tree-indented dump -- flat, one section
    per node -- since SRP's tree shape (documented in docs/siglease_rfc9665.md's
    lease-store mapping section) doesn't need the same visual nesting to be
    legible.

func (h *SRPHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult
    Handle implements RFC 9665's ten-step happy path. Every early-return before
    step 7 (forwarding) touches neither the lease store nor the network,
    so a rejected request leaves no trace to clean up.

func (h *SRPHandler) Setup(cfg map[string]any) error
    Setup initializes the SRP handler configuration: the options both UPDATE
    handlers read (upstream_zone, keystore_dir, upstream, bootstrap_resolvers,
    lease_policy, record_ttl_sec, lease_manager or storage; see
    leaseHandler.setup), and these of its own:
      - "allow_udp": permit UDP for this zone (TCP is required by default,
        for non-CNN zones this proxy targets). [OPTIONAL, defaults to false]
      - "rewrite_default_service_arpa": accept requests whose Zone Section
        is literally "default.service.arpa." (real SRP clients hardcode
        this name -- they have no way to discover any other zone) *in
        addition to* upstream_zone, rewriting every name in the update to
        upstream_zone before FCFS/forwarding so the rest of the pipeline (and
        the authoritative server) never sees default.service.arpa. at all.
        The response still echoes back default.service.arpa., matching what the
        client itself sent. [OPTIONAL, defaults to false]
      - "refuse_on_foreign_data": RFC 9665 S3.3.3's NOERROR-no-KEY case -- true
        refuses the update (REFUSED) when a name exists at the authoritative
        server with data but no KEY; false lets the delete-all-then-add clobber
        it. [OPTIONAL, defaults to true]
      - "advertise_registration_domain": also publish the RFC 6763 S11 "r"/"dr"
        registration- domain records (self-pointing at upstream_zone),
        independent of whether any service type is currently live -- unlike the
        always-on "b"/"db"/"lb" browsing-domain records, which only appear once
        at least one service type is live. Advertising this zone as an open
        target for direct RFC 2136 Dynamic Update registration (not just SRP) is
        a deployment policy choice -- SIG(0)/FCFS still gate who can actually
        write, but this controls whether domain-enumeration tools are told to
        try. [OPTIONAL, defaults to false]

func (r SRPHandler) Shutdown()
    Shutdown stops the lease machinery and has the store save once more. After
    it begins, no timer callback or reconciliation pass starts. It cancels the
    context of the callbacks and the pass already running and waits for them to
    return; then it stops every timer, including a retry a cut-short lease event
    armed, and stops the lease store, which for a file store is the final save.
    A cut-short lease event forgets nothing: the store changes only once its
    upstream UPDATE is confirmed, so its leases are in that save and expire
    after a restart. Safe to call more than once: only the first call does
    anything.

func (b *SRPHandler) Start()
    Start begins the handler's lease expiry: it arms an expiry timer for every
    lease owner in the store -- the leases Setup loaded from a snapshot -- and
    starts the reconciliation pass. The server calls it once, before it serves.
    A dump runs Setup alone, so nothing in its store expires and nothing is
    written upstream.

func (b *SRPHandler) UpstreamZone() string
    UpstreamZone is the zone this handler serves.

type UpdateHandler struct {
	leaseHandler[UpstreamCoordinator]

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
      - Lease tracking in a memory or file lease store
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
    registrations. Keys that appear only in the non-KEY lease (KEY=absent) own
    data but have no KEY record in the store, such as a signer that registered
    data without being lease-managed itself. Keys that appear in both have an
    active KEY + non-KEY RR lease.

func (h *UpdateHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult

func (h *UpdateHandler) Setup(cfg map[string]any) error
    Setup initializes the handler configuration: the options both UPDATE
    handlers read (upstream_zone, keystore_dir, upstream, bootstrap_resolvers,
    lease_policy, record_ttl_sec, lease_manager or storage; see
    leaseHandler.setup), and these of its own:
      - "prefer_4byte_variant": Accept requests whose Update Lease is the 4-byte
        variant, one lease for every record, as older requesters such as macOS's
        mDNSResponder send; they are REFUSED otherwise [OPTIONAL, defaults to
        false]
      - "allow_online_key_registration": Allow a signer resolved only via
        authoritative DNS (not lease-managed, not present in the request) to
        register new KEY RRs [OPTIONAL, defaults to false]
      - "fcfs_naming": First-Come First-Served naming, as RFC 9665 S3.2.4.1
        gives SRP: a KEY holds its name and the names below it, so a new KEY
        is refused (YXDOMAIN) where a different KEY holds its name or a name
        above it in the zone, unless that KEY's holder registers it, and a KEY
        registers itself only one label below the zone (REFUSED elsewhere)
        [OPTIONAL, defaults to false]
      - "blacklisted_types": RR type names this handler refuses to register
        [OPTIONAL]

func (r UpdateHandler) Shutdown()
    Shutdown stops the lease machinery and has the store save once more. After
    it begins, no timer callback or reconciliation pass starts. It cancels the
    context of the callbacks and the pass already running and waits for them to
    return; then it stops every timer, including a retry a cut-short lease event
    armed, and stops the lease store, which for a file store is the final save.
    A cut-short lease event forgets nothing: the store changes only once its
    upstream UPDATE is confirmed, so its leases are in that save and expire
    after a restart. Safe to call more than once: only the first call does
    anything.

func (b *UpdateHandler) Start()
    Start begins the handler's lease expiry: it arms an expiry timer for every
    lease owner in the store -- the leases Setup loaded from a snapshot -- and
    starts the reconciliation pass. The server calls it once, before it serves.
    A dump runs Setup alone, so nothing in its store expires and nothing is
    written upstream.

func (b *UpdateHandler) UpstreamZone() string
    UpstreamZone is the zone this handler serves.

type UpstreamCoordinator interface {

	// ResolveAuthoritativeZone returns the apex of the zone holding zone: the zone an UPDATE
	// for names under zone must name.
	ResolveAuthoritativeZone(ctx context.Context, zone string) (string, error)
	// QueryRRs returns the rrType records at name from zoneHint's authoritative server --
	// none for NXDOMAIN -- for the handler's checks of what is already published.
	QueryRRs(ctx context.Context, zoneHint, name string, rrType uint16) ([]dns.RR, error)
	// QueryKeyAtName reports the KEYs at name, telling NXDOMAIN from a name without one:
	// fcfs_naming's live check (srp.Evaluate), as for the SRP handler.
	QueryKeyAtName(ctx context.Context, zoneHint, name string) (srp.AuthoritativeKeyState, []*dns.KEY, error)
	// Has unexported methods.
}
    UpstreamCoordinator handles communication with the upstream
    authoritative server. pkg/updatecore.Coordinator is the production
    implementation, constructed in Setup via buildCoordinatorFromConfig
    -- this interface exists so tests can set a stub in its place (see
    handlers/opcode5_sig0_validation_test.go's stubUpstreamCoordinator).
    It covers everything the handler asks of the upstream side, so a stub is
    used the same way as the production implementation, never bypassed.

type ZoneHandler interface {
	Handler
	// UpstreamZone is the zone the handler serves (upstream_zone), once Setup has read it.
	UpstreamZone() string
	// Has unexported methods.
}
    ZoneHandler is an UPDATE handler serving one zone: UpdateHandler and
    SRPHandler.

```

## github.com/NetworkCommons/sig0lease/logging
```
package logging // import "github.com/NetworkCommons/sig0lease/logging"

Package logging provides structured logging for the DNS proxy.

Every Logger produced by this package renders records through the same
uniformHandler, so the on-disk format is defined in exactly one place:

    2026/08/20 10:39:44.164+02:00 -- INFO -- "message"

The only things callers may vary between Logger instances are the minimum
level (e.g. to run one module at "debug" while the rest stay at "info") and the
output: stdout, the system log, or both (NewLoggerWithOutput). The system log
gets the same "message" part, with the time stamp left to syslog and the level
carried as the record's syslog severity.

CONSTANTS

const (
	OutputStdout = "stdout"
	OutputSyslog = "syslog"
	OutputBoth   = "both"
)
    Values of NewLoggerWithOutput's output.


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

func NewLoggerWithOutput(level, output string) (*Logger, error)
    NewLoggerWithOutput creates a logger like NewLogger's, writing each record
    to output: OutputStdout, OutputSyslog (the local system log) or OutputBoth.
    It fails for any other output, and when the system log can't be opened --
    including on a build that has no working system log (syslog_unsupported.go).

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

func AddEDE(resp, req *dns.Msg, infoCode uint16, text string)
    AddEDE adds an Extended DNS Error (RFC 8914) with infoCode and text to resp,
    the reply to req, if req carried an OPT RR: RFC 8914 S2 allows the option
    only in a reply to a request that did. The option goes in resp.Pseudo,
    from which the dns library builds resp's one OPT RR.

    text is EXTRA-TEXT, for people to read, not for parsing (RFC 8914 S2).
    Every reply the proxy builds gets its EDE here; the server removes the text
    of an error reply's EDEs unless server.diagnostics is on (StripEDEText).

func AddressRR(owner string, addr netip.Addr, ttl uint32) dns.RR
    AddressRR returns owner's address record for addr, class IN: an A for an
    IPv4 address, an AAAA for an IPv6 one.

func EDEs(m *dns.Msg) []*dns.EDE
    EDEs returns the Extended DNS Errors in m, in order.

func FormatEDE(e *dns.EDE) string
    FormatEDE renders e for people: its INFO-CODE, the code's name in the IANA
    "Extended DNS Error Codes" registry, and its EXTRA-TEXT, if any.

func NewLeaseUpdate(zone string, keyRRs []*dns.KEY, additional []dns.RR, leaseDuration, keyLeaseDuration uint32) (*dns.Msg, error)
    NewLeaseUpdate builds a DNS UPDATE registration message with one optional
    KEY RR, optional additional RRs, and an 8-byte UPDATE-LEASE option.

func ParseAdditionalRRSpec(spec string) (dns.RR, error)
    ParseAdditionalRRSpec parses a DNS RR in standard presentation format.

    Required form:

        owner ttl class type rdata...

func StripEDEText(m *dns.Msg)
    StripEDEText empties the EXTRA-TEXT of every Extended DNS Error in m and
    keeps its INFO-CODE.

```

## github.com/NetworkCommons/sig0lease/pkg/dnsname
```
package dnsname // import "github.com/NetworkCommons/sig0lease/pkg/dnsname"

Package dnsname implements DNS name case-insensitivity exactly as the DNS
defines it: only the US-ASCII letters A-Z and a-z match each other; every other
octet must match exactly (RFC 1035 S2.3.3, RFC 4343 S3). It is the one place the
rest of the proxy should fold names for comparison or map keying.

Go's strings.ToLower/strings.EqualFold are not a substitute: they fold Unicode,
so they treat names BIND considers different as equal ("CAFÉ" vs "CAFé";
U+212A KELVIN SIGN vs ASCII "k"), and ToLower rewrites bytes that aren't valid
UTF-8 to U+FFFD, changing the name's length. codeberg.org/miekg/dns keeps name
labels as raw bytes (no \DDD escaping), so those bytes do reach the proxy
-- DNS-SD instance names in particular are UTF-8 text (RFC 6763 S4.1.1). The
library's own dnsutil.Canonical folds ASCII only but goes through strings.Map,
which has the same U+FFFD rewrite, so it is not used either.

It is likewise the one place the module splits a name into labels or checks that
a string can be sent as one label (labels.go, whose opening comment explains
why splitting at "." is exact for this library's name strings), and finds,
in a wire-format message, the labels the library cannot carry (wire.go).

Fold keeps a name's trailing dot, for code that works on fully-qualified names
(pkg/srp, pkg/dnssd split them into labels ending in the empty root label);
Normalize drops it, for the lease store, the handlers and pkg/updatecore,
which key and compare names without it.

This package depends only on the standard library, so any package in the module
can import it.

FUNCTIONS

func CheckLabel(label string) error
    CheckLabel returns an error unless label can be sent as exactly one DNS
    label: 1 to 63 octets, with no "." (which the library would send as a
    label boundary -- see above). RFC 6763 S4.3 requires software that joins an
    Instance label onto <Service>.<Domain> to keep that label boundary intact;
    with this library, refusing such a label is the only way to. Every other
    octet is allowed: S4.1.1 makes Instance labels arbitrary UTF-8 text,
    spaces included.

func CutFirstLabel(name string) (first, rest string, ok bool)
    CutFirstLabel splits name after its first label, returning that label and
    the name that follows it: "Widget._http._tcp.example.com." -> ("Widget",
    "_http._tcp.example.com.", true). This is how a Service Instance Name
    divides into <Instance> and <Service>.<Domain>, since RFC 6763 S4.1 makes
    <Instance> exactly one label however many <Domain> has. ok is false if name
    is a single label with nothing after it, in which case first is name and
    rest is "".

func DottedWireLabel(msg []byte) (label string, found bool, err error)
    DottedWireLabel returns the first label in msg, a wire-format DNS message,
    that contains a "." octet. The library cannot carry such a label (see
    labels.go): it decodes it as two or more labels, and encoding the result
    again sends a different name. It checks the question names, every RR owner
    name, and the name in the RDATA of the types rdataNameOffset lists -- every
    name a handler here reads and re-sends. found is false if there is no such
    label; err is non-nil only if msg is too malformed to walk.

func EqualFold(a, b string) bool
    EqualFold reports whether a and b are equal under Fold, without allocating.

func Fold(name string) string
    Fold returns name with the US-ASCII letters A-Z replaced by a-z and every
    other byte unchanged. The result always has the same length as name.

func IsAtOrBelow(name, zone string) bool
    IsAtOrBelow reports whether name is zone itself or a name below it,
    comparing whole labels under Fold: "test.srp.test." is below "srp.test.",
    "evilsrp.test." is not. Trailing dots are optional on both. Every name is at
    or below the root zone ("." or "").

func Labels(name string) []string
    Labels splits name into its labels. A fully-qualified name's last
    element is the empty root label -- "widget._http._tcp.example.com." ->
    ["widget","_http","_tcp","example","com",""] -- so a caller can tell it from
    a relative name. Returns nil for "".

func Normalize(name string) string
    Normalize returns the form the lease store, the handlers and pkg/updatecore
    compare and key names by: ASCII case folded (see Fold) and the trailing
    dot removed, so "Demo.Example." and "demo.example" both normalize to
    "demo.example". It does not trim whitespace: a label may begin with a
    space or U+00A0 (RFC 6763 S4.1.1 allows any non-control character),
    so " demo.example." is a different name. A name read from configuration is
    trimmed where it is read (the handlers' Setup), not here.

```

## github.com/NetworkCommons/sig0lease/pkg/dnssd
```
package dnssd // import "github.com/NetworkCommons/sig0lease/pkg/dnssd"

Package dnssd holds pure logic for RFC 6763 (DNS-Based Service Discovery)
concerns that sit alongside, but outside, RFC 9665's own Service Registration
Protocol: the S7 service name shape both SRP ends check (names.go),
and S9's Service Type Enumeration meta-record (this file). An SRP client's
Service Description never carries this record itself (S9 predates SRP
and isn't part of what a client restates), so a registrar that wants
registered services to be discoverable by "browse everything" tools --
not just a targeted per-type browse -- has to maintain it independently.
See handlers.SRPHandler.reconcileServiceEnumeration for how this package's pure
functions are combined with live lease-store state and turned into an upstream
UPDATE.

CONSTANTS

const (
	BrowseDomainPrefix              = "b"  // list of domains recommended for browsing
	DefaultBrowseDomainPrefix       = "db" // single recommended default browsing domain
	LegacyBrowseDomainPrefix        = "lb" // "legacy"/"automatic" browsing domain(s)
	RegistrationDomainPrefix        = "r"  // list of domains recommended for registering via Dynamic Update
	DefaultRegistrationDomainPrefix = "dr" // single recommended default registration domain
)
    RFC 6763 S11 defines five domain-enumeration meta-record prefixes,
    each rooted at "<prefix>._dns-sd._udp.<domain>.": these are a different,
    earlier query than S9 type enumeration -- a browse tool that implements full
    domain enumeration asks one or more of these FIRST, to learn which domain
    to browse/register in at all, and only then queries EnumerationOwnerName
    (or a specific type's BrowsingOwnerName) against whatever it got back --
    it never queries those on the originally-entered name directly. A zone with
    services registered via SRP but none of these records is therefore invisible
    to such a tool even though its S9/S4.1 records are otherwise perfectly
    correct. See SRPHandler.reconcileServiceEnumeration for why this registrar
    publishes a trivial self-pointing answer for each (this zone IS its own
    recommended browsing/registration domain -- one zone per handler instance):
    "b"/"db"/"lb" once it has at least one live registration; "r"/"dr"
    independently, gated only on its own opt-in config setting.


FUNCTIONS

func BrowsingOwnerName(svcType, zone string) string
    BrowsingOwnerName returns the RFC 6763 S4.1 per-type Service Instance
    Enumeration PTR owner name for svcType in zone: "<svcType>.<zone>" (e.g.
    "_http._tcp.example.com."). This is the name a normal DNS-SD browse
    queries directly; SRPHandler also uses it as a live ground-truth
    check before removing svcType from the S9 enumeration record -- see
    reconcileServiceEnumeration's doc comment.

func DiffEnumerationRecords(zone string, previous, current []string, ttl uint32) []dns.RR
    DiffEnumerationRecords returns targeted add/delete instructions to bring
    zone's Service Type Enumeration record from previous to current (both
    deduplicated, case-insensitively, before comparing) -- an RFC 2136 S2.5.1
    Add to an RRset for each type newly present in current, and an S2.5.4 Delete
    An RR From An RRSet (single-RR, not a delete-all) for each type that was in
    previous but has dropped out of current. Each add points at "<type>.<zone>"
    -- the canonical two-label service type plus the same domain, per S9's own
    worked example ("_http._tcp.<Domain>"). Returns nil if previous and current
    describe the same set (no update needed at all).

    This is deliberately NOT a delete-all-then-reinsert of the whole record:
    this handler's own local knowledge of "what's currently live" is
    authoritative only for what it has itself seen (RFC 9665 clients restate
    everything on every refresh, so a long-running process's local view
    converges quickly) -- but a delete-all is authoritative over everything at
    that name, including entries a DIFFERENT proxy process, or an earlier run
    of this same one before a restart, wrote for a type this process hasn't
    relearned about yet. A delete-all would silently erase those on every
    reconcile until every such type's owner happens to re-register through the
    current process -- observed live against a real, multi-run shared zone:
    a second proxy process, restarted after a first had registered one service
    type, wiped that type's still-live entry the moment it reconciled its own
    (empty) view of the world. Targeted single-RR deletes only ever remove a
    (type, previous) pair this function was explicitly told was previously true,
    so a fresh process's first-ever call (previous typically empty) can only
    ever ADD, never destroy another process's data.

func DiffSelfPointingDomainRecord(prefix, zone string, wasPresent, isPresent bool, ttl uint32) []dns.RR
    DiffSelfPointingDomainRecord returns the single add or delete instruction
    needed to bring one RFC 6763 S11 domain-enumeration PTR (named by prefix,
    self-pointing: "this zone IS its own recommended browsing/registration
    domain") from wasPresent to isPresent, or nil if no change is needed.
    Unlike DiffEnumerationRecords, which diffs a whole set of service types,
    every S11 record this registrar ever publishes has the same trivial rdata
    (the zone itself) regardless of which of the five prefixes it is, so there's
    nothing to diff beyond the presence flag itself.

func DomainEnumerationOwnerName(prefix, zone string) string
    DomainEnumerationOwnerName returns the RFC 6763 S11 domain-enumeration
    meta-record owner name for one of the *DomainPrefix constants above,
    in zone: "<prefix>._dns-sd._udp.<zone>".

func EnumerationOwnerName(zone string) string
    EnumerationOwnerName returns the RFC 6763 S9 Service Type Enumeration PTR
    owner name for zone: "_services._dns-sd._udp.<zone>". Fixed at "._udp"
    regardless of whether the individual service types being enumerated are
    themselves "._tcp" -- S9 defines exactly one enumeration name per zone,
    not one per protocol. zone must already be dot-terminated (this package does
    no normalization of its own, matching the rest of this codebase's convention
    of trusting an already-canonical zone at this layer).

func ServiceTypeFromInstanceName(name string) (svcType string, ok bool)
    ServiceTypeFromInstanceName extracts the two-label DNS-SD service
    type (e.g. "_http._tcp") from a Service Instance Name shaped
    "<Instance>.<Service>.<Domain>." -- RFC 6763 S4.1 is explicit that the
    Instance portion always occupies exactly one label, so <Service> always
    starts at the second label regardless of how many labels <Domain> itself
    has. ok is false if what follows the Instance label isn't a service name
    (ServiceTypeFromServiceName).

func ServiceTypeFromServiceName(name string) (svcType string, ok bool)
    ServiceTypeFromServiceName returns the two-label DNS-SD service type (e.g.
    "_http._tcp") of a name shaped "<Service>.<Domain>." -- a base-type
    browse name such as "_http._tcp.example.com.". RFC 6763 S7 fixes
    <Service> at exactly two labels: an underscore-prefixed Service Name,
    then "_tcp" or "_udp". ok is false for any other shape, e.g.
    "_vpnserver._wg._udp.example.com.", whose second label is "_wg".

    This is the registrar-side structural check: it doesn't hold the Service
    Name to RFC 6335's syntax rules (see ValidateServiceType for that), so a
    registrar keeps accepting types a sloppy but otherwise working requester
    sends.

func ValidateServiceType(svcType string) error
    ValidateServiceType checks svcType, a bare service type with no
    domain (e.g. "_http._tcp"), against RFC 6763 S7: exactly two labels,
    the first an underscore plus a Service Name valid per RFC 6335 S5.1,
    the second "_tcp" or "_udp". It is the requester's check -- stricter
    than ServiceTypeFromServiceName, since a requester should only ever send
    well-formed types.

```

## github.com/NetworkCommons/sig0lease/pkg/keyrec
```
package keyrec // import "github.com/NetworkCommons/sig0lease/pkg/keyrec"


CONSTANTS

const KeystoreEnv = "CLIENT_KEYSTORE_DIR"
    KeystoreEnv names the environment variable every client of this project
    falls back to for its keystore directory.


FUNCTIONS

func FindKeysByZone(keystoreDir, zoneName string, logger *logging.Logger) ([]string, error)
    FindKeysByZone searches for keys by zone name in the keystore. Returns the
    key names, possibly none, in a fixed order: ED25519 (algorithm 15) keys
    first, then keys of any other algorithm, each group sorted alphabetically.
    The order is fixed so that a caller taking the first name picks the same key
    on every run. Provenance: Inspired by sig0namectl's LoadOrGenerateKey()

func KeyExists(keystoreDir, keyName string, logger *logging.Logger) error
    KeyExists searches for a key by filename without .key in the keystore.
    Returns the key name or error if none found.

func KeystoreDir(given, how string) (string, error)
    KeystoreDir applies the keystore-location convention shared by
    sig0lease-client, sig0lease-srp-client and sig0lease-agent: a directory
    given explicitly (a flag, a template's keystore:) wins, CLIENT_KEYSTORE_DIR
    is the fallback, and having neither is an error, which says how to give one:
    how, such as "pass -keystore=<dir>", or CLIENT_KEYSTORE_DIR.

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

func ResolveOrCreateKey(dir, owner string, createAlgorithm uint8, logger *logging.Logger) (key *LoadedKey, created bool, err error)
    ResolveOrCreateKey finds an existing key for owner (a fully-qualified
    DNS name) in dir, or -- only when createAlgorithm is non-zero --
    generates and persists a fresh one there. Search is algorithm-agnostic
    (via FindKeysByZone's own "any algorithm, ED25519 preferred" ordering):
    an existing key of ANY algorithm satisfies the lookup, since createAlgorithm
    only says what to generate if nothing is found yet, not which algorithm
    to prefer among what already exists. When several keys match, the first
    in FindKeysByZone's order is used, so every run picks the same one, and
    logger (if non-nil) gets a warning naming them all. created reports whether
    a new key was generated, so callers can tell the user which happened.
    createAlgorithm == 0 means "never create" -- a missing key is then an error,
    not silently generated, matching this package's existing strict-by-default
    convention (cmd/sig0lease-client's, which this generalizes).

    This is shared, rather than reimplemented per caller, because both of this
    project's CLI clients (cmd/sig0lease-client, cmd/sig0lease-srp-client) need
    the identical "find any existing key for this identity, or create one at an
    explicitly chosen algorithm" logic and would otherwise duplicate it.

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

func CheckSaveInterval(d time.Duration) error
    CheckSaveInterval returns an error unless d, a file store's save interval,
    is positive. NewFileLeaseStore checks it, and so does the handlers'
    storage-section parser, which reads it from a handler's configuration even
    where no file store is built from it (cmd/sig0lease's dump mode).

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

func NodeKeyName(nodeKey string) string
    NodeKeyName extracts the DNS name portion of a KEY node's composite key
    (NodeKey): the name as dnsname.Normalize returns it. Only meaningful for a
    KEY node's key, not a non-KEY record's RecordKey.

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

    Names compare as RFC 2136 S1.1.2 requires (RFC 1035 S2.3.3: US-ASCII
    case only, see pkg/dnsname) -- the owner name, and also the domain names
    inside the RDATA of the types BIND compares that way (see foldRDATANames).
    Any other RDATA, TXT included, is compared exactly.

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
    corresponding upstream DNS delete. A store-driven timer here would race the
    handler's own precise per-node timer and — whichever fired first — silently
    erase local state without ever notifying the authoritative server. See
    the handlers package's per-node expiry timers (expiryTimers), the single,
    upstream-aware path that owns expiry.

func NewInMemoryManager() *InMemoryLeaseStore
    NewInMemoryManager creates a new in-memory lease manager.

func ReadSnapshotFile(path string) (store *InMemoryLeaseStore, found bool, err error)
    ReadSnapshotFile returns a store holding the snapshot saved at path,
    and whether there was a file there; with none, the store is empty.
    It only reads: NewFileLeaseStore loads its snapshot with it, and so does
    cmd/sig0lease's dump mode, which must not write. A file that is there but
    corrupt or unreadable is an error, never an empty store.

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

func (m *InMemoryLeaseStore) ListOwners() []string
    ListOwners implements LeaseStorage.ListOwners.

func (m *InMemoryLeaseStore) ListSubtreeKeys(nodeKey string) []string
    ListSubtreeKeys returns composite node keys of all descendants (KEY and
    non-KEY alike) of nodeKey, deepest first.

func (m *InMemoryLeaseStore) LoadSnapshot(path string) error

func (m *InMemoryLeaseStore) LookupByKEY(k *dns.KEY) *Record

func (m *InMemoryLeaseStore) LookupBySIG(signerName string, algorithm uint8, keyTag uint16) *Record

func (m *InMemoryLeaseStore) LookupNonKEYRecord(rr dns.RR) *NonKEYRecord
    LookupNonKEYRecord returns the record matching rr's RFC 2136 identity
    anywhere in the store, regardless of owner, or nil if none exists.

func (m *InMemoryLeaseStore) Register(keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
    Register creates or updates a KEY lease. Node identity is derived from
    keyRR.

func (m *InMemoryLeaseStore) RegisterWithParent(parentNodeKey string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
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

func (m *InMemoryLeaseStore) RenewLease(keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32) error
    RenewLease extends an already-registered KEY lease's timers in place.
    Unlike Register/RegisterWithParent, it never rebuilds the node: it leaves
    ParentKeyName, RegisteredAt, and the node's position in the tree completely
    untouched, since renewing a lease is not re-creating it.

func (m *InMemoryLeaseStore) SaveSnapshot(path string) error
    SaveSnapshot writes the store's snapshot to path, atomically and with its
    SHA-256, so that LoadSnapshot refuses a file edited by hand or torn by a
    crash (pkg/sealedfile).

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
    applied: if any of the given records already exists in the store under
    a different owner, the entire call fails and nothing is written -- the
    same "fail the parts that would otherwise succeed" policy used for
    duplicate KEY/RR registration elsewhere (docs/siglease_rfc9664.md item 6),
    because partially applying a batch here would leave the store's consistency
    unguaranteed.

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
    Encode4Byte creates a LeaseOption with only LEASE (4-byte variant): one
    duration for KEY and non-KEY records alike. Requests use the 8-byte variant;
    a server answers a 4-byte request with this one (RFC 9664 S4).

func Encode8Byte(lease, keyLease uint32) *LeaseOption
    Encode8Byte creates a LeaseOption with both LEASE and KEY-LEASE (8-byte
    variant).

func FindAndDecode(msg *dns.Msg) (*LeaseOption, error)
    FindAndDecode is the common case: locate the UPDATE-LEASE option in msg and
    decode it in one step.

func (lo *LeaseOption) Decode(opt *dns.OPT) error
    Decode parses a LeaseOption from an OPT RR.

func (lo *LeaseOption) Encode(opt *dns.OPT) error
    Encode encodes the LeaseOption into an OPT RR per RFC 6891, in its own
    variant: 8 bytes (LEASE + KEY-LEASE) when KeyLease is set, 4 bytes (LEASE)
    when it is nil.

func (lo *LeaseOption) Validate() error
    Validate checks that the lease values are valid.

type LeaseStorage interface {

	// Register creates or updates a KEY lease. The node identity is derived from keyRR.
	Register(keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
	// RenewLease extends an already-registered KEY lease's timers in place.
	// The node identity is derived from keyRR; it is an error if no such
	// node is already registered. Unlike Register, it never touches
	// ParentKeyName, RegisteredAt, or the node's position in the tree --
	// renewing a lease is not re-creating the node.
	RenewLease(keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32) error
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
	ListAll() []*Record
	// ListOwners returns, sorted, the node key of every node that holds a lease: each KEY
	// node, and each owner of non-KEY records -- also an owner with no KEY record of its own,
	// such as a signer that registered data without being lease-managed itself. A handler
	// times each owner's lease events with one expiry timer, so this is what its
	// reconciliation walks.
	ListOwners() []string

	// RegisterWithParent creates or updates a KEY lease with an optional
	// parent composite node key. Fails if parentNodeKey already identifies a
	// non-KEY record -- a non-KEY node can never be a parent.
	RegisterWithParent(parentNodeKey string, keyRR *dns.KEY, leaseDuration uint32, keyLeaseDuration uint32, upstreamZone string) error
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
	// identical RR" (docs/siglease_rfc9664.md), not merely a caller-side convention.
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
type NodeLockSet struct {
	// Has unexported fields.
}
    NodeLockSet is a set of ids taken by TryAcquire or Acquire.

func (s *NodeLockSet) IDs() []string
    IDs returns the ids s holds, sorted.

func (s *NodeLockSet) Release()
    Release frees every id in s and wakes the waiting Acquires. Releasing a set
    twice would free ids that another caller may have taken since, so it panics.

type NodeLocks struct {
	// Has unexported fields.
}
    NodeLocks serializes the operations that read lease-store nodes, write
    upstream, and then change those nodes -- a handler's request, or a node's
    lease expiry -- so that two of them on the same node never interleave across
    the upstream round trip. The store's own mutex only makes each single store
    call atomic. See docs/siglease_rfc9664.md, "Node Locks".

    A lock is an id in held, nothing more: there is no mutex per node,
    so nothing outlives its holder. A set of ids is taken all or nothing,
    under mu, and nobody waits while holding any id, so overlapping sets can
    never deadlock, whatever order they overlap in. Ids are opaque strings: each
    handler decides what it locks (NodeKey/RecordKey for the RFC 9664 handler,
    names for SRP).

func NewNodeLocks() *NodeLocks
    NewNodeLocks returns an empty lock table.

func (n *NodeLocks) Acquire(ctx context.Context, lockSet func() []string) (*NodeLockSet, error)
    Acquire is TryAcquire that waits, holding nothing, while any id is held.
    It calls lockSet again after every release, since the set may have changed
    (a subtree grown or gone), until it takes the whole set or ctx is done;
    the error then names the ids still held.

func (n *NodeLocks) TryAcquire(lockSet func() []string) (*NodeLockSet, error)
    TryAcquire takes every id lockSet returns, or none of them if any is held;
    the error then names the held ones.

    lockSet runs with n's mutex held, so the ids it reads from the lease store
    -- a node's current subtree, say -- are exactly the ones taken: nothing
    can attach a new node under one of them in between, because attaching a
    node takes its parent's lock too. Lock order is therefore always n's mutex,
    then the store's. lockSet must not call back into n.

type NodeSnapshot struct {
	NodeKind NodeKind `json:"node_kind"`
	// NodeID is a KEY node's NodeKey(keyRR), the value its children's ParentKeyName holds. It
	// is written so a reader can match the two up, and import checks it against the key in
	// RRWire: the file's checksum (snapshotFile) refuses a hand edit, and this check refuses a
	// file whose IDs aren't the ones the store computes. A non-KEY node's RecordKey(rr) is
	// derived from RRWire instead; nothing refers to it. Both fields hold names, so any bytes,
	// but a JSON string only valid UTF-8: they are written with quoteNodeKey's escapes.
	NodeID        string    `json:"node_id,omitempty"`
	ParentKeyName string    `json:"parent_key_name,omitempty"`
	RRType        uint16    `json:"rr_type,omitempty"`
	UpstreamZone  string    `json:"upstream_zone"`
	LeaseDuration uint32    `json:"lease_duration"`
	RegisteredAt  time.Time `json:"registered_at"`
	ExpiresAt     time.Time `json:"expires_at"`

	// KEY-only.
	KeyLeaseDuration uint32 `json:"key_lease_duration,omitempty"`

	// The node's RR, KEY or not. RRWire is the RR in DNS wire format (base64 in the JSON), and
	// the only field import rebuilds the record from. Wire format keeps every octet of every
	// name: a DNS-SD Instance label may hold spaces (RFC 6763 S4.1.1), which presentation text
	// can't carry with this dns library (it neither escapes nor unescapes them), and a subtype
	// label arbitrary 8-bit bytes (S7.1), which a JSON string can't carry. RRDisplay is the
	// same RR as rr.String(), for people reading the file; it is never read back, though the
	// file's checksum still covers it, so editing it fails the load like any other edit.
	RRWire    []byte `json:"rr_wire"`
	RRDisplay string `json:"rr_display"`
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

## github.com/NetworkCommons/sig0lease/pkg/sealedfile
```
package sealedfile // import "github.com/NetworkCommons/sig0lease/pkg/sealedfile"

Package sealedfile keeps a JSON document in a file that is written atomically
and carries the SHA-256 of the document: the proxy's lease store snapshot
and sig0lease-agent's state. These files are not meant to be edited by hand,
and Read enforces that: it accepts only a file identical, byte for byte,
to what Write makes of the document it holds, so any edit -- to a value,
to the whitespace, or to the layout -- is refused. It is a checksum, not a
signature: the keys a program could sign with sit on the same host as the file,
so a signature would make the check no harder to get past on purpose.

FUNCTIONS

func Read(path string, v any) error
    Read unmarshals the document stored at path into v. A file that is not, byte
    for byte, what Write wrote is an error. A missing file is an error wrapping
    fs.ErrNotExist, so a caller can tell "nothing saved yet" from a broken file
    with errors.Is.

func Write(path string, v any) error
    Write stores v, marshaled to JSON, at path, atomically (see writeAtomic).

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
(ServiceRegistration/towire.c: dns_sig0_signature_to_wire_, which hashes
a `rr`/`rdlen` pointing at RDATA only) -- see docs/siglease_rfc9664.md's
"miekg/dns Shortcomings" section for the full writeup and reproduction.

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
no lease store access -- see docs/siglease_rfc9665.md's architecture section.
FCFS (pkg/srp/fcfs.go, needs a store view) and the handler wiring
(handlers/srp_handler.go) build on it; this file covers Classify(), the first
step of RFC 9665's happy path.

The classification algorithm below closely follows the reference implementation
in mDNSResponder/ServiceRegistration/srp-parse.c (srp_evaluate), used as
a cross-check for this package -- see the deliberate divergences noted
inline (multiple TXT adds; the LEASE-independent host-removal fallback;
no base-type-precedes-subtype requirement on PTR deletes).

update.go builds an unsigned RFC 9665 SRP UPDATE message from a declarative spec
-- the requester-side counterpart to Classify/Validate. Pure logic: no network
I/O, no crypto beyond shaping the KEY RR from already-generated key material
-- pkg/srp stays network-free; client/srp owns key generation, discovery,
scheduling, and actually sending the result.

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

func KeyFor(cu *ClassifiedUpdate, name string) *dns.KEY
    KeyFor returns the KEY that governs name: an instance's own explicit KEY if
    it has one, otherwise a copy of the Host Description's KEY with its owner
    name rewritten to name (S3.2.5.1: "the SRP registrar MUST behave AS IF the
    same KEY record that is given for the Host Description is also given for
    each Service Description for which no KEY record is provided" -- "as if...
    given for" that name, not the literal host-owned RR object). Returning
    cu.Host.Key verbatim here was a real bug caught by a live end-to-end test:
    callers that derive a lease-store node identity from the result
    (pkg/lease.NodeKey is name-scoped) would silently collide the instance's
    node with the host's, since both would carry the host's own owner name.

    The inherited KEY's owner name is the instance name as the requester spelled
    it (its Delete All RRsets owner), not the lower-cased inst.Name: the handler
    forwards this KEY upstream as the instance's published KEY, and RFC 1035
    S2.3.3 asks for the original case to be preserved -- otherwise a "DemoScene"
    instance ends up with its SRV/TXT at "DemoScene" and its KEY at "demoscene".

    name must be cu.Host.Name or one of cu.Instances' names -- anything else is
    a caller bug, not a data problem, so KeyFor panics rather than returning a
    zero value a caller could silently misuse.

func KeysAllMatch(keys []*dns.KEY, key *dns.KEY) bool
    KeysAllMatch reports whether every KEY in keys is key's (same algorithm,
    protocol and public key): whether a name holding keys is free for key,
    by the rule Evaluate applies. A requester uses it too, to find which of its
    names a conflict is about (client/srp).

func Names(cu *ClassifiedUpdate) []string
    Names returns every name Evaluate must be called for to authorize cu
    (S3.3's "the checked names are the Host Description name and each Service
    Description name -- nothing else"): the host, plus each service instance's
    own name. SRV/TXT/PTR owner names are deliberately never included -- they
    have no independent identity to check (S4.4/S4.5's "nothing walks up
    from the SRV node" reasoning), and per S3.3.1.1 every Service Discovery
    instruction is authorized transitively through its target instance's own
    check.

func RemoveHost(msg *dns.Msg, cu *ClassifiedUpdate, freeNames bool) []dns.RR
    RemoveHost makes msg and cu, an update with a LEASE of 0, the removal of
    its host and of every service instance it lists. S3.2.5.5.1 defines the
    removal as "an SRP Update ... with an Update Lease option that has a LEASE
    value of zero", with "no 'Add to an RRSet' instructions for that hostname".
    Adds a requester sends anyway are dropped, as both reference registrars
    do (srp-mdns-proxy's host_lease == 0, OpenThread's Host::IsDeleted);
    OpenThread's client sends its addresses with every removal. Dropped:
    the Host Description's addresses, each listed instance's SRV and TXT,
    which leaves it a removal (Removal), and every Service Discovery add. The
    Delete All RRsets and the Service Discovery deletes stay. KEY adds stay too,
    holding the names (a KEY-LEASE that is not 0), unless freeNames (a KEY-LEASE
    of 0): the KEYs then go with the rest, and adding them back after their
    names' Delete All RRsets would undo that. cu keeps its KEYs either way,
    for FCFS. RemoveHost returns the adds it dropped from msg's Update section,
    KEYs aside: every removal carries those.

func ValidateClassified(msg *dns.Msg, cu *ClassifiedUpdate) error
    ValidateClassified runs every check Validate performs beyond Classify
    itself, against a ClassifiedUpdate the caller has already computed -- for a
    caller that has already run Classify once (e.g. handlers/srp_handler.go's
    Handle, which classifies in its own step 1 to decide relevance before
    Validate would otherwise redundantly classify the identical message a second
    time in step 2). cu must be Classify(msg)'s own result for msg; behavior is
    undefined otherwise.


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
    Update-Lease option, an address in the Host Description unless the LEASE is
    0 (S3.3.1.3), TTL consistency (S4 -- a MUST, reject rather than normalize),
    identical KEY RDATA across every KEY add, flags-0 KEY adds (S3.2.5.1),
    and DNS-SD-shaped service names on every Service Discovery add (RFC 6763
    S4.1/S7). It does not verify SIG(0) or FCFS -- those need the lease store
    and the SIG(0) signer identity, both outside this package's pure-logic scope
    (S4.3 steps 4-5).

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
func Evaluate(ctx context.Context, view StoreView, query AuthoritativeKeyQuery, zoneHint, name string, updateKey *dns.KEY, refuseOnForeignData bool) (FCFSResult, dns.RR, error)
    Evaluate implements RFC 9665 S3.3.3 FCFS for a single name -- the Host
    Description name, or one Service Description name -- against updateKey, the
    KEY that governs it (the Host Description's KEY, or a Service Description's
    own explicit KEY when it has one; per S3.2.5.1 every KEY in a valid update
    is identical anyway, so callers may simply pass ClassifiedUpdate.Host.Key
    for every name -- see the package-level Names helper).

    Per RFC 9665 S3.3.3's FCFS table:

        lease store has KEYs at name, all match updateKey         -> FCFSProceed  (refresh)
        lease store has KEYs at name, any does NOT match          -> FCFSConflict (YXDOMAIN)
        no local record; live query: NXDOMAIN                     -> FCFSProceed  (first come)
        no local record; live query: NOERROR, no KEY               -> refuseOnForeignData ? FCFSForeignData : FCFSProceed
        no local record; live query: NOERROR, every KEY matches    -> FCFSProceed
        no local record; live query: NOERROR, any KEY doesn't match -> FCFSConflict (YXDOMAIN)

    "Any" is S3.3.3's own wording: "If any existing KEY record corresponding
    to a KEY record in the SRP Update does not match ... the SRP registrar
    MUST reject the SRP Update". A name holding the update's key next to
    someone else's is held by both, so neither may take it over. SRP itself
    never leaves two KEYs at a name; such a name was written by something else
    (handlers.SeparateZones keeps this proxy's other handler out of SRP's zone).

    The RFC 9664 handler's fcfs_naming option uses this same rule for its new
    KEYs, calling Evaluate with refuseOnForeignData false for the new KEY's
    name and each name above it that the KEY's signer does not already hold
    (handlers.UpdateHandler.fcfsNewKey). There a holder may put further KEYs at
    its own name, so a name with several KEYs is normal.

    The lease store is checked first and trusted over a live query when both
    are available: it is the source of truth for what this proxy already manages
    (see handlers.filterDuplicateRegistrations's doc comment for the base
    handler's identical reasoning) -- a live query only runs for a name the
    store has no opinion on.

    The second return value is an RFC 2136 prerequisite RR the caller should
    attach to the upstream UPDATE it forwards for an FCFSProceed name, or nil
    if none is needed. It closes the gap between this function's own check and
    the caller's later, separate upstream write: without it, two concurrent
    first-time claims of the same name -- through another process, since the
    caller's node locks serialize its own -- can both pass this check (neither
    has forwarded its UPDATE yet) and both be accepted upstream, breaking FCFS.
    The prerequisite makes the authoritative server itself re-check, atomically
    at write time, what the policy requires of a first-time claim:

        refuseOnForeignData true:  nothing at the name    -> "Name is not in use" (RFC 2136 S2.4.4)
        refuseOnForeignData false: no KEY at the name      -> "RRset does not exist" for KEY (S2.4.3)

    With refuseOnForeignData false, non-SRP data at the name may be taken over,
    so only a KEY appearing must stop the claim; "Name is not in use" would also
    stop it on non-SRP data the policy allows. Only a first-time claim gets one:
    a name that already holds this key (in the store, or live) needs none,
    since a competing key fails this check with a conflict. A store-trusted
    refresh getting none also preserves the store's behavior of silently
    re-establishing a record that disappeared from authoritative DNS while still
    locally unexpired.

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
	Name   string   // canonical service-instance name -- for comparison only; Delete's owner keeps the requester's case
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

func Removal(name string) *ServiceInstance
    Removal returns the Service Description Instruction removing the service
    instance name: a bare Delete All RRsets, as a requester removing that one
    instance sends (S3.2.5.5.2). A registrar adds one for each instance a host
    removal does not list (S3.2.5.5.1).

type StoreView interface {
	// KeysAtName returns every live (non-expired) KEY record the lease store currently
	// manages at name. None for a name the store has never seen, or whose records there
	// have all expired -- Evaluate then falls back to a live authoritative query, exactly
	// as S3.3.3 describes.
	KeysAtName(name string) []*dns.KEY
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
	// and TTL, and unconditionally zeroes Flags (S3.2.5.1/S3.3.3: requesters MUST
	// send flags 0, regardless of what the caller's key material happens to carry).
	Key       *dns.KEY
	Instances []InstanceSpec
	Lease     uint32
	KeyLease  uint32
	// TTL is the TTL of every record the update adds, KEYs included: the requester's
	// suggestion, which a registrar may override (S4). It is not derived from Lease or
	// KeyLease, since a lease is not a TTL (S5.1). Required.
	TTL uint32
}
    UpdateSpec is everything BuildUpdate needs to construct one SRP UPDATE.

```

## github.com/NetworkCommons/sig0lease/pkg/updatecore
```
package updatecore // import "github.com/NetworkCommons/sig0lease/pkg/updatecore"

Package updatecore holds forwarding plumbing shared by the RFC 9664 update-lease
handler and the RFC 9665 SRP handler (see docs/siglease_rfc9665.md's upstream
forward section). It is a public package, not internal/, matching this repo's
convention.

Package updatecore holds forwarding plumbing shared by the RFC 9664 update-lease
handler and the RFC 9665 SRP handler (see docs/siglease_rfc9665.md's upstream
forward section). It is a public package, not internal/, matching this repo's
convention.

CONSTANTS

const DefaultMaxInflightUpdates = 1
    DefaultMaxInflightUpdates is BIND 9.20's default sig0checks-quota -- see
    SetMaxInflightUpdates.


FUNCTIONS

func AsDelete(rr dns.RR) dns.RR
    AsDelete returns a copy of rr rewritten as an RFC 2136 S2.5.4 "Delete An RR
    From An RRSet" instruction: class NONE, TTL 0, RDATA unchanged (which RR the
    delete targets is carried by NAME+TYPE+RDATA, same as any other RR identity
    in this codebase -- pkg/lease.RecordKey uses the identical convention).

func BuildAndSign(upstreamZone string, prereqs, records []dns.RR, signingKey *keyrec.LoadedKey) (*dns.Msg, error)
    BuildAndSign constructs a new UPDATE message for upstreamZone containing
    prereqs (in the given order) as the Prerequisite section and records (in the
    given order) as the Update section, and signs it with signingKey. prereqs
    may be nil/empty -- most callers have none. Every UPDATE both handlers send
    is built here (handlers' upstreamTarget.send); it does no per-record-type
    branching, the callers assemble the records. The registrar's own TTLs are
    set earlier, against the classified instructions (handlers.applyRecordTTL),
    not here.

func CheckConsistentTTLs(records []dns.RR) error
    CheckConsistentTTLs implements the RFC 9665 S4 MUST for the SRP path:
    every RRset in an update must carry one TTL across all its RRs. It never
    rewrites anything -- SRP requires rejecting a violation outright (REFUSED),
    not silently correcting it. Returns the first inconsistency found, naming
    the owner, type, and the conflicting TTL values, or nil if every RRset
    present is consistent. Single-RR RRsets (the common case) are trivially
    consistent and never inspected beyond membership.

func FindAuthorizedProxyKey(keystoreDir, zone string, logger *logging.Logger) (*keyrec.LoadedKey, string, error)
    FindAuthorizedProxyKey loads the proxy's own SIG(0) signing key
    for zone from keystoreDir, walking up to parent zones if the
    exact zone has no key -- extracted from what was previously
    (*handlers.UpdateHandler).findAuthorizedProxyKeyForZone, now a standalone
    function so handlers/srp_handler.go can use it without depending on
    *handlers.UpdateHandler.

func SetMaxInflightUpdates(max int) error
    SetMaxInflightUpdates sets how many UPDATEs this process may have in
    flight to one authoritative server at a time; 0 means no limit. Every
    UPDATE the proxy sends is SIG(0)-signed, and BIND 9.20 verifies at most
    sig0checks-quota SIG(0) signatures at a time (default 1), answering REFUSED
    -- not queueing -- a SIG(0) request that arrives while it is already at that
    quota. Set this to the upstream server's sig0checks-quota so the proxy never
    exceeds it on its own. BIND frees a slot only after sending its response,
    so a request sent the instant the previous one is answered can still very
    occasionally be refused; the lease expiry retry covers that, as it does
    REFUSED from other SIG(0) clients of the same server. Call once at startup,
    before any UPDATE is sent.


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
    against the authoritative server, consumed by pkg/srp.Evaluate (S3.3.3 FCFS)
    when the lease store has no local record for a name. This is the RCODE-aware
    distinction Coordinator.QueryRRs (the base RFC 9664 handler's lookup)
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
    configured static upstream) and performs the two things both handlers need
    against it: sending a signed UPDATE, and a live KEY-at-name query (S3.3.3
    FCFS).

    This is the extraction of what was previously
    handlers.DefaultUpstreamCoordinator's entire body. Both handlers/opcode5.go
    (RFC 9664) and handlers/srp_handler.go (RFC 9665) construct and hold a
    *Coordinator directly -- there is no per-package wrapper type.

func NewCoordinator(logger *logging.Logger, bootstrapResolvers []string, static *StaticUpstream) *Coordinator
    NewCoordinator creates a Coordinator. bootstrapResolvers falls back to
    defaultBootstrapResolvers when empty. static may be nil (discovery for every
    name).

func (c *Coordinator) QueryKeyAtName(ctx context.Context, zoneHint, name string) (AuthoritativeKeyState, []*dns.KEY, error)
    QueryKeyAtName is the real implementation of AuthoritativeKeyQuery (S3.3.3
    FCFS): one live QTYPE=KEY query at name against zoneHint's resolved
    authoritative server (ResolveSOAMasterServer, honoring a static override),
    reporting the tri-state result pkg/srp needs. This is also the pre-forward
    cost S5 describes -- the same query backs both the FCFS check (S3.3) and,
    when reused by a caller, the "does this name already have a KEY" question
    the base handler asks elsewhere.

func (c *Coordinator) QueryPTRExists(ctx context.Context, zoneHint, name string) (bool, error)
    QueryPTRExists reports whether at least one PTR record currently exists live
    at name (typically a per-type browsing name "<type>.<zone>", RFC 6763 S4.1)
    against zoneHint's resolved authoritative server -- same query/fallback
    shape as QueryKeyAtName, but a simple presence check rather than a tri-state
    result, since the only question here is "does anything else still provide
    this type." Used by handlers.SRPHandler.reconcileServiceEnumeration
    immediately before removing a type from the RFC 6763 S9 enumeration record,
    to confirm no OTHER registrant this process's own local lease store doesn't
    know about still provides it -- see that function's doc comment for why a
    local-only view can't safely decide this alone.

func (c *Coordinator) QueryRRs(ctx context.Context, zoneHint, name string, rrType uint16) ([]dns.RR, error)
    QueryRRs returns the rrType records at name from zoneHint's authoritative
    server -- none for NXDOMAIN -- with the same query/fallback shape as
    QueryKeyAtName. Used by the RFC 9664 handler's checks of what is already
    published (signer KEYs, duplicate registrations).

func (c *Coordinator) ResolveAuthoritativeZone(ctx context.Context, zone string) (string, error)
    ResolveAuthoritativeZone returns the apex of the zone holding zone -- the
    zone an UPDATE for names under zone must name (discoverZone) -- or, when the
    static upstream covers zone, its zone, with no lookup.

func (c *Coordinator) ResolveSOAMasterServer(ctx context.Context, zone string) (server, effectiveZone string, err error)
    ResolveSOAMasterServer returns the "host:port" of the primary server (SOA
    MNAME, port 53) of the zone holding zone, and that zone (discoverZone) --
    or, when the static upstream covers zone, its address and zone, with no
    lookup.

func (c *Coordinator) SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error)
    SendUpdate sends updateMsg (already built and signed) to upstreamZone's
    authoritative server, resolved via ResolveSOAMasterServer (so a static
    override is honored), trying UDP then falling back to TCP. Each change of an
    update the server accepts is logged at INFO (logAppliedChanges).

type StaticUpstream struct {
	Zone string // e.g. "srp.test."
	Addr string // "host:port"
}
    StaticUpstream is a configured authoritative server for one zone: for Zone
    and every name at or below it, the Coordinator sends to Addr and takes Zone
    as the zone, with no discovery. Configuring it is the operator's assertion
    that Addr serves Zone and that no zone cut lies below Zone -- the handlers'
    "upstream" setting.

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

func NewRouter(opcodeMap map[uint8][]string, logger *logging.Logger, resolver *forward.Resolver, requestTimeout time.Duration, diagnostics bool) (*Router, error)
    NewRouter creates a new router instance.

func (r *Router) RegisterHandler(h handlers.Handler)
    RegisterHandler registers a handler with the router.

func (r *Router) Route(ctx context.Context, w dns.ResponseWriter, rMsg *dns.Msg) *dns.Msg
    Route determines how to handle a DNS message based on its opcode. Flow:
     1. Check for internal dump query (admin/debug endpoint), refused unless
        server.diagnostics is on
     2. Check if opcode has any registered handlers
     3. Try each configured handler for the opcode in order: - StatusProcessed:
        Return response to client, stop - StatusNotRelevant: Try the next
        handler in the list - StatusError: Return error response to client, stop
     4. If no handler is configured, or every handler declined (all
        NotRelevant), apply default forward

func (r *Router) Shutdown()
    Shutdown calls Shutdown on every registered handler exactly once.

func (r *Router) Start()
    Start calls Start on every registered handler exactly once.

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

