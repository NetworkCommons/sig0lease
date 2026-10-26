// Package srp implements an RFC 9665 SRP requester: discovery, message building (via
// pkg/srp), the RFC 9664 S5.2 refresh scheduler, YXDOMAIN rename-retry, and Host, which keeps
// one host registered as what it offers changes. This library is the deliverable;
// cmd/sig0lease-srp-client is a thin, non-shipped dev/test CLI over it, and cmd/sig0lease-agent
// registers a template's hosts with it. Deliberately not a full RFC 9665 requester (no mDNS-based
// default.service.arpa. discovery, no CNN transport handling -- both out of scope for now)
// -- this targets the registrar's actual supported shape: an explicitly
// configured zone, reached over TCP by default.
package srp

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat" // registers EDNS0 code 2 (UPDATE-LEASE); required to unpack a registrar's response
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/dnssd"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
	pkgsrp "github.com/NetworkCommons/sig0lease/pkg/srp"
)

// InstanceConfig describes one service instance to register, in the same "label relative
// to Domain" terms as HostLabel -- Client joins these into fully-qualified names when
// building the update (pkg/srp.BuildUpdate itself takes only already-qualified names).
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

// EscapeTXT turns raw, one TXT string's octets, into the form InstanceConfig.TXT takes. It is
// presentation text, as codeberg.org/miekg/dns packs it, where a backslash starts an escape,
// so only backslashes need escaping for every other octet to go out as it is.
func EscapeTXT(raw string) string {
	return strings.ReplaceAll(raw, `\`, `\\`)
}

// InstanceName identifies a requested instance: its label as configured
// (InstanceConfig.Label) and its service type.
type InstanceName struct {
	Label       string
	ServiceType string
}

// Labels are the labels a registration uses after renames: the host's, and each instance's
// by its requested name. A label is renamed when a different key holds the name it makes,
// to the requested label with "-2" appended, then "-3", and so on (see renameHeld); an
// instance absent from Instances is registered under its requested label.
type Labels struct {
	Host      string
	Instances map[InstanceName]string
}

// clone returns a copy of l that shares no map with it.
func (l Labels) clone() Labels {
	out := Labels{Host: l.Host, Instances: make(map[InstanceName]string, len(l.Instances))}
	for k, v := range l.Instances {
		out.Instances[k] = v
	}
	return out
}

// renameOf reports whether label is requested or a rename of it, as renameHeld makes them.
func renameOf(requested, label string) bool {
	if label == requested {
		return true
	}
	n, ok := strings.CutPrefix(label, requested+"-")
	if !ok {
		return false
	}
	i, err := strconv.Atoi(n)
	return err == nil && i >= 2 && strconv.Itoa(i) == n
}

// nextRename returns the label to try after label, requested or a rename of it, is held.
func nextRename(requested, label string) string {
	if label == requested {
		return requested + "-2"
	}
	i, _ := strconv.Atoi(strings.TrimPrefix(label, requested+"-"))
	return requested + "-" + strconv.Itoa(i+1)
}

// DiscoveryService returns the service whose SRV record names a registrar reachable over n:
// "_dnssd-srp-tls._tcp" for NetworkTLS (RFC 9665 S10.4.2), "_dnssd-srp._tcp" otherwise
// (S10.4.1).
func DiscoveryService(n baseclient.Network) string {
	if n == baseclient.NetworkTLS {
		return "_dnssd-srp-tls._tcp"
	}
	return "_dnssd-srp._tcp"
}

// Config configures a Client. See NewClient's doc comment for defaults.
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
	// earlier Client renamed them to (Client.Labels, OnRenamed), so that a requester keeps its
	// names across restarts. Each must be the label it stands for, or a rename of it. Entries
	// for instances not in Instances are kept, for when those instances return.
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

// Client is one SRP identity's registration lifecycle: build, sign, send, and (via Run)
// keep alive on the RFC 9664 S5.2 refresh clock, renaming on YXDOMAIN conflict.
type Client struct {
	cfg Config

	// labels are the CURRENT (possibly renamed) labels -- changed by renameHeld, read by
	// specs and hostFQDN. cfg.HostLabel/cfg.Instances[i].Label are never changed, so a caller
	// can always see what was originally requested.
	labels Labels
}

// NewClient validates cfg, applies defaults, and generates a signing key if cfg.Key is nil.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("srp/client: Domain is required")
	}
	if cfg.HostLabel == "" {
		return nil, fmt.Errorf("srp/client: HostLabel is required")
	}
	// specs and hostFQDN join these labels into names by plain concatenation, so each must be
	// exactly one label for the joined name to mean what was asked for (RFC 6763 S4.3).
	if err := dnsname.CheckLabel(cfg.HostLabel); err != nil {
		return nil, fmt.Errorf("srp/client: HostLabel: %w", err)
	}
	for _, inst := range cfg.Instances {
		if err := dnsname.CheckLabel(inst.Label); err != nil {
			return nil, fmt.Errorf("srp/client: instance: %w", err)
		}
		if err := dnssd.ValidateServiceType(inst.ServiceType); err != nil {
			return nil, fmt.Errorf("srp/client: instance %q: %w", inst.Label, err)
		}
		for _, st := range inst.Subtypes {
			if err := dnsname.CheckLabel(st); err != nil {
				return nil, fmt.Errorf("srp/client: instance %q: subtype: %w", inst.Label, err)
			}
		}
	}
	if err := cfg.Discovery.validate(); err != nil {
		return nil, fmt.Errorf("srp/client: Discovery: %w", err)
	}
	if err := cfg.Network.Validate(); err != nil {
		return nil, fmt.Errorf("srp/client: Network: %w", err)
	}
	if cfg.RequestedLease == 0 {
		cfg.RequestedLease = 3600
	}
	if cfg.RequestedKeyLease == 0 {
		cfg.RequestedKeyLease = 1209600
	}
	if cfg.TTL == 0 {
		cfg.TTL = 300
	}
	if cfg.RequestedLease > cfg.RequestedKeyLease {
		return nil, fmt.Errorf("srp/client: RequestedLease (%d) must not exceed RequestedKeyLease (%d)", cfg.RequestedLease, cfg.RequestedKeyLease)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	if cfg.MaxRenames <= 0 {
		cfg.MaxRenames = 5
	}
	if cfg.Send == nil {
		cfg.Send = baseclient.LiveTransport(cfg.Timeout)
	}
	if cfg.Rng == nil {
		cfg.Rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	if cfg.Sleep == nil {
		cfg.Sleep = baseclient.SleepContext
	}
	if cfg.Query == nil {
		cfg.Query = LiveDNSQuery(cfg.Resolvers)
	}
	if cfg.Key == nil {
		// SRP identities default to P-256, flags-0 (BuildUpdate enforces flags-0
		// regardless, but 0 here too so Config.Key reads correctly if a caller inspects it).
		k, err := keyrec.GenerateKey(dnsutil.Fqdn(cfg.HostLabel+"."+cfg.Domain), dns.ECDSAP256SHA256, 0, 256)
		if err != nil {
			return nil, fmt.Errorf("srp/client: generate signing key: %w", err)
		}
		cfg.Key = k
	}

	labels := Labels{Host: cfg.HostLabel, Instances: map[InstanceName]string{}}
	if cfg.Labels != nil {
		labels = cfg.Labels.clone()
		if !renameOf(cfg.HostLabel, labels.Host) {
			return nil, fmt.Errorf("srp/client: Labels: host label %q is not %q or a rename of it", labels.Host, cfg.HostLabel)
		}
		for name, label := range labels.Instances {
			if !renameOf(name.Label, label) {
				return nil, fmt.Errorf("srp/client: Labels: instance label %q is not %q or a rename of it", label, name.Label)
			}
			if err := dnsname.CheckLabel(label); err != nil {
				return nil, fmt.Errorf("srp/client: Labels: instance: %w", err)
			}
		}
		if err := dnsname.CheckLabel(labels.Host); err != nil {
			return nil, fmt.Errorf("srp/client: Labels: host: %w", err)
		}
	}

	return &Client{cfg: cfg, labels: labels}, nil
}

// Labels returns the labels the client registers under now, after any renames.
func (c *Client) Labels() Labels { return c.labels.clone() }

// instanceLabel returns the label inst is registered under now.
func (c *Client) instanceLabel(inst InstanceConfig) string {
	if label, ok := c.labels.Instances[InstanceName{Label: inst.Label, ServiceType: inst.ServiceType}]; ok {
		return label
	}
	return inst.Label
}

// registrarAddr resolves where to send the update: Config.RegistrarAddr if set, otherwise
// discovery.
func (c *Client) registrarAddr(ctx context.Context) (string, error) {
	if c.cfg.RegistrarAddr != "" {
		return c.cfg.RegistrarAddr, nil
	}
	return Discover(ctx, c.cfg.Query, c.cfg.Domain, c.cfg.Discovery, c.cfg.Network)
}

func (c *Client) hostFQDN() string {
	return dnsutil.Fqdn(c.labels.Host + "." + c.cfg.Domain)
}

// instanceFQDN is the name inst is registered at now.
func (c *Client) instanceFQDN(inst InstanceConfig) string {
	return dnsutil.Fqdn(c.instanceLabel(inst) + "." + inst.ServiceType + "." + c.cfg.Domain)
}

// specs builds the current (possibly renamed) UpdateSpec instance list, joining each
// instance's label onto its service type and Domain. remove marks every instance
// removal-shaped (InstanceSpec.Remove) for Deregister; Register passes false, so only the
// instances whose InstanceConfig.Remove is set are withdrawn.
func (c *Client) specs(remove bool) []pkgsrp.InstanceSpec {
	out := make([]pkgsrp.InstanceSpec, len(c.cfg.Instances))
	for i, inst := range c.cfg.Instances {
		svcType := dnsutil.Fqdn(inst.ServiceType + "." + c.cfg.Domain)
		name := c.instanceFQDN(inst)
		subtypes := make([]string, len(inst.Subtypes))
		for j, st := range inst.Subtypes {
			subtypes[j] = dnsutil.Fqdn(st + "._sub." + inst.ServiceType + "." + c.cfg.Domain)
		}
		out[i] = pkgsrp.InstanceSpec{
			Name:        name,
			ServiceType: svcType,
			Subtypes:    subtypes,
			Port:        inst.Port,
			TXT:         inst.TXT,
			Remove:      remove || inst.Remove,
		}
	}
	return out
}

// keyRR builds the KEY RR representing this client's current signing identity, at the
// current host name (renamed KEY ownership follows the host -- see rename's doc comment).
func (c *Client) keyRR() *dns.KEY {
	k := c.cfg.Key.PublicKey.Clone().(*dns.KEY)
	k.Hdr.Name = c.hostFQDN()
	return k
}

// renameHeld implements the "YXDOMAIN means rename and retry, not hard fail" behavior. The
// RCODE alone doesn't tell the requester which name (the host, or a specific service instance)
// conflicted (S3.3.3's FCFS checks every name in the update), so renameHeld asks: it looks up
// the KEYs at each name of the update (Config.Query, the resolvers), and renames the names
// where a KEY is not this client's -- the registrar's own rule (pkg/srp.KeysAllMatch) -- and
// only those, so a host keeps the names nobody else holds. The signing key itself never
// changes -- only the names.
//
// If no name shows another key, the resolvers have not seen what the registrar has (a cached
// answer from before the other key came, or resolvers that do not see the zone at all), and
// renameHeld returns an error rather than guess: Run tries again later, when the resolvers may
// know, instead of renaming names nobody may hold.
func (c *Client) renameHeld(ctx context.Context) error {
	ours := c.keyRR()
	held := func(name string) (bool, error) {
		resp, err := c.cfg.Query(ctx, name, dns.TypeKEY)
		if err != nil {
			return false, fmt.Errorf("srp/client: KEY lookup for %s: %w", name, err)
		}
		var keys []*dns.KEY
		for _, rr := range resp.Answer {
			if k, ok := rr.(*dns.KEY); ok && dnsname.EqualFold(k.Hdr.Name, name) {
				keys = append(keys, k)
			}
		}
		return !pkgsrp.KeysAllMatch(keys, ours), nil
	}

	next := c.labels.clone()
	var renamed []string
	hostHeld, err := held(c.hostFQDN())
	if err != nil {
		return err
	}
	if hostHeld {
		next.Host = nextRename(c.cfg.HostLabel, c.labels.Host)
		renamed = append(renamed, c.hostFQDN())
	}
	for _, inst := range c.cfg.Instances {
		if inst.Remove {
			continue // a withdrawal never conflicts (FCFS only blocks an add)
		}
		instHeld, err := held(c.instanceFQDN(inst))
		if err != nil {
			return err
		}
		if instHeld {
			next.Instances[InstanceName{Label: inst.Label, ServiceType: inst.ServiceType}] = nextRename(inst.Label, c.instanceLabel(inst))
			renamed = append(renamed, c.instanceFQDN(inst))
		}
	}
	if len(renamed) == 0 {
		return fmt.Errorf("srp/client: the registrar answered YXDOMAIN, but no name of this update holds another key at the resolvers (%s and its instances); trying again later", c.hostFQDN())
	}
	if err := dnsname.CheckLabel(next.Host); err != nil {
		return fmt.Errorf("srp/client: cannot rename %s: %w", c.hostFQDN(), err)
	}
	for _, label := range next.Instances {
		if err := dnsname.CheckLabel(label); err != nil {
			return fmt.Errorf("srp/client: cannot rename an instance: %w", err)
		}
	}
	c.labels = next
	if c.cfg.OnRenamed != nil {
		c.cfg.OnRenamed(c.labels.clone())
	}
	return nil
}

// buildSignSend is the shared build-sign-send-interpret cycle both Register and Deregister
// use, differing only in the UpdateSpec's Addresses/Instances/Lease/KeyLease shape.
func (c *Client) buildSignSend(ctx context.Context, addresses []netip.Addr, instances []pkgsrp.InstanceSpec, lease, keyLease uint32) (*dns.Msg, baseclient.Outcome, error) {
	addr, err := c.registrarAddr(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("srp/client: %w", err)
	}

	spec := pkgsrp.UpdateSpec{
		Zone:      dnsutil.Fqdn(c.cfg.Domain),
		Host:      c.hostFQDN(),
		Addresses: addresses,
		Key:       c.keyRR(),
		Instances: instances,
		Lease:     lease,
		KeyLease:  keyLease,
		TTL:       c.cfg.TTL,
	}
	msg, err := pkgsrp.BuildUpdate(spec)
	if err != nil {
		return nil, 0, fmt.Errorf("srp/client: %w", err)
	}

	signed, err := sig0.SignMessage(msg, c.keyRR(), c.cfg.Key.PrivateKey)
	if err != nil {
		return nil, 0, fmt.Errorf("srp/client: sign update: %w", err)
	}

	resp, err := c.cfg.Send(ctx, addr, c.cfg.Network, signed)
	if err != nil {
		return nil, 0, fmt.Errorf("srp/client: send update to %s: %w", addr, err)
	}
	return resp, baseclient.InterpretResponse(resp), nil
}

// Register performs exactly one build-sign-send-interpret cycle: no rename-retry, no
// scheduling. Callers wanting the full lifecycle (initial delay, refresh clock, automatic
// rename-retry) should use Run instead; Register is the primitive Run is built from, and is
// also useful standalone for a one-shot CLI invocation.
func (c *Client) Register(ctx context.Context) (*dns.Msg, baseclient.Outcome, error) {
	return c.buildSignSend(ctx, c.cfg.Addresses, c.specs(false), c.cfg.RequestedLease, c.cfg.RequestedKeyLease)
}

// Deregister withdraws this identity's entire registration in one message: the host's
// address data (S3.3.1.3's "zero Add operations means delete this host's registration") and
// every configured service instance (each restated as a bare Delete-All,
// InstanceSpec.Remove). Matches S3.2's "no lightweight refresh" -- a removal is a normal
// UPDATE that restates everything, not a distinct wire operation. One-shot, like Register;
// there is no rename-retry equivalent since a removal can't conflict (FCFS only ever blocks
// an add-shaped instruction).
//
// Also requests LEASE=0: S3.2.5.5.1's removal is both, a LEASE of 0 and no address (S3.3.1.3
// allows zero address Adds only "in the case of deleting a registration"). Registrars go by
// the LEASE: srp-mdns-proxy (srp-parse.c, host_lease == 0, confirmed by
// tests/test_mdnsresponder_interop.sh), OpenThread's (Host::IsDeleted) and this proxy
// (pkg/srp.RemoveHost) take any LEASE of 0 as a removal, and refuse, or for srp-mdns-proxy
// tolerate, no address with a LEASE (pkg/srp's validateHostAddresses).
//
// keepNames picks the KEY-LEASE, RFC 9665 S3.2.5.5.1's two kinds of removal: "If the
// registration is to be permanently removed, KEY-LEASE SHOULD also be zero. Otherwise, it
// SHOULD be set to the same value it had previously; this holds the name in reserve for when
// the SRP requester is once again able to provide the service." So with keepNames the KEYs
// stay, at the host's name and each instance's, for c.cfg.RequestedKeyLease; without it they
// go with the rest and the names are free.
func (c *Client) Deregister(ctx context.Context, keepNames bool) (*dns.Msg, baseclient.Outcome, error) {
	var keyLease uint32
	if keepNames {
		keyLease = c.cfg.RequestedKeyLease
	}
	return c.buildSignSend(ctx, nil, c.specs(true), 0, keyLease)
}

// registerWithRenameRetry calls Register, renaming and retrying on OutcomeConflict up to
// Config.MaxRenames times.
func (c *Client) registerWithRenameRetry(ctx context.Context) (*dns.Msg, error) {
	for attempt := 0; attempt <= c.cfg.MaxRenames; attempt++ {
		resp, outcome, err := c.Register(ctx)
		if err != nil {
			return nil, err
		}
		if outcome != baseclient.OutcomeConflict {
			if outcome != baseclient.OutcomeSuccess {
				return resp, fmt.Errorf("srp/client: registration failed: %s", baseclient.DescribeAnswer(resp, outcome))
			}
			return resp, nil
		}
		if err := c.renameHeld(ctx); err != nil {
			return resp, err
		}
	}
	return nil, fmt.Errorf("srp/client: gave up after %d rename attempts, still conflicting", c.cfg.MaxRenames)
}

// Run performs the full RFC 9665 requester lifecycle (client.Lifecycle.Run): it registers,
// with rename-retry on conflict, then again on the RFC 9664 S5.2 refresh clock, restating the
// full registration every time, per S3.2's "no lightweight refresh", until ctx is canceled.
// A failed registration does not stop it: Config.OnError is called, and it tries again after a
// backoff.
func (c *Client) Run(ctx context.Context) error {
	return baseclient.Lifecycle{
		RequestedLease: c.cfg.RequestedLease,
		Rng:            c.cfg.Rng,
		Sleep:          c.cfg.Sleep,
		OnError:        c.cfg.OnError,
		OnRegistered:   c.cfg.OnRegistered,
	}.Run(ctx, c.registerWithRenameRetry)
}
