// Package srp implements an RFC 9665 SRP requester: discovery, message building (via
// pkg/srp), the RFC 9664 S5.2 refresh scheduler, and YXDOMAIN rename-retry. This library is
// the deliverable; cmd/sig0lease-srp-client is a thin, non-shipped dev/test
// CLI over it. Deliberately not a full RFC 9665 requester (no mDNS-based
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
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat" // registers EDNS0 code 2 (UPDATE-LEASE); required to unpack a registrar's response
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
	pkgsrp "github.com/NetworkCommons/sig0lease/pkg/srp"
)

// InstanceConfig describes one service instance to register, in the same "label relative
// to Domain" terms as HostLabel -- Client joins these into fully-qualified names when
// building the update (pkg/srp.BuildUpdate itself takes only already-qualified names).
type InstanceConfig struct {
	Label       string   // single label, e.g. "MyPrinter" -- not a full instance name
	ServiceType string   // e.g. "_ipps._tcp" -- not a full service-type name
	Subtypes    []string // additional bare subtype labels, e.g. "_universal"
	Port        uint16
	TXT         []string
}

// Transport sends a signed SRP UPDATE to addr and returns the response. Config.Send
// defaults to a real network implementation (see liveTransport); tests inject a fake.
type Transport func(ctx context.Context, addr string, useTCP bool, msg *dns.Msg) (*dns.Msg, error)

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

	// hostLabel/instanceLabels are the CURRENT (possibly renamed) labels -- mutated by
	// rename(), read by specs(). cfg.HostLabel/cfg.Instances[i].Label are never mutated,
	// so a caller can always see what was originally requested.
	hostLabel      string
	instanceLabels []string
	renameSuffix   int
}

// NewClient validates cfg, applies defaults, and generates a signing key if cfg.Key is nil.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("srp/client: Domain is required")
	}
	if cfg.HostLabel == "" {
		return nil, fmt.Errorf("srp/client: HostLabel is required")
	}
	if cfg.RequestedLease == 0 {
		cfg.RequestedLease = 3600
	}
	if cfg.RequestedKeyLease == 0 {
		cfg.RequestedKeyLease = 1209600
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
		cfg.Send = liveTransport(cfg.Timeout)
	}
	if cfg.Rng == nil {
		cfg.Rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	if cfg.Sleep == nil {
		cfg.Sleep = ctxSleep
	}
	if cfg.Query == nil {
		cfg.Query = LiveSRVQuery(cfg.Resolvers)
	}
	if cfg.Key == nil {
		// SRP identities default to P-256, flags-0 (BuildUpdate enforces flags-0
		// regardless, but 0 here too so Config.Key reads correctly if a caller inspects it).
		k, err := keyrec.GenerateKey(ensureFQDN(cfg.HostLabel+"."+cfg.Domain), dns.ECDSAP256SHA256, 0, 256)
		if err != nil {
			return nil, fmt.Errorf("srp/client: generate signing key: %w", err)
		}
		cfg.Key = k
	}

	instanceLabels := make([]string, len(cfg.Instances))
	for i, inst := range cfg.Instances {
		instanceLabels[i] = inst.Label
	}

	return &Client{cfg: cfg, hostLabel: cfg.HostLabel, instanceLabels: instanceLabels}, nil
}

// registrarAddr resolves where to send the update: Config.RegistrarAddr if set, otherwise
// discovery.
func (c *Client) registrarAddr(ctx context.Context) (string, error) {
	if c.cfg.RegistrarAddr != "" {
		return c.cfg.RegistrarAddr, nil
	}
	return Discover(ctx, c.cfg.Query, c.cfg.Domain)
}

func (c *Client) hostFQDN() string {
	return ensureFQDN(c.hostLabel + "." + c.cfg.Domain)
}

// specs builds the current (possibly renamed) UpdateSpec instance list, joining each
// instance's label onto its service type and Domain. remove marks every instance
// removal-shaped (InstanceSpec.Remove) for Deregister; Register always passes false.
func (c *Client) specs(remove bool) []pkgsrp.InstanceSpec {
	out := make([]pkgsrp.InstanceSpec, len(c.cfg.Instances))
	for i, inst := range c.cfg.Instances {
		svcType := ensureFQDN(inst.ServiceType + "." + c.cfg.Domain)
		name := ensureFQDN(c.instanceLabels[i] + "." + inst.ServiceType + "." + c.cfg.Domain)
		subtypes := make([]string, len(inst.Subtypes))
		for j, st := range inst.Subtypes {
			subtypes[j] = ensureFQDN(st + "._sub." + inst.ServiceType + "." + c.cfg.Domain)
		}
		out[i] = pkgsrp.InstanceSpec{
			Name:        name,
			ServiceType: svcType,
			Subtypes:    subtypes,
			Port:        inst.Port,
			TXT:         inst.TXT,
			Remove:      remove,
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

// rename implements the "YXDOMAIN means rename and retry, not hard
// fail" behavior. The RCODE alone doesn't tell the requester which name (the host, or a specific
// service instance) actually conflicted (S3.3.3's FCFS checks every name in the update),
// so rename conservatively renames EVERYTHING -- host label and every instance label --
// together, appending the same incrementing numeric suffix: whichever name(s) collided,
// the retry uses names nobody has tried yet, at the cost of occasionally renaming something
// that didn't need it. The signing key itself never changes -- only the identity's name.
func (c *Client) rename() {
	c.renameSuffix++
	suffix := "-" + strconv.Itoa(c.renameSuffix+1)
	c.hostLabel = c.cfg.HostLabel + suffix
	for i, inst := range c.cfg.Instances {
		c.instanceLabels[i] = inst.Label + suffix
	}
}

// buildSignSend is the shared build-sign-send-interpret cycle both Register and Deregister
// use, differing only in the UpdateSpec's Addresses/Instances/Lease/KeyLease shape.
func (c *Client) buildSignSend(ctx context.Context, addresses []netip.Addr, instances []pkgsrp.InstanceSpec, lease, keyLease uint32) (*dns.Msg, pkgsrp.Outcome, error) {
	addr, err := c.registrarAddr(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("srp/client: %w", err)
	}

	spec := pkgsrp.UpdateSpec{
		Zone:      ensureFQDN(c.cfg.Domain),
		Host:      c.hostFQDN(),
		Addresses: addresses,
		Key:       c.keyRR(),
		Instances: instances,
		Lease:     lease,
		KeyLease:  keyLease,
	}
	msg, err := pkgsrp.BuildUpdate(spec)
	if err != nil {
		return nil, 0, fmt.Errorf("srp/client: %w", err)
	}

	signed, err := sig0.SignMessage(msg, c.keyRR(), c.cfg.Key.PrivateKey)
	if err != nil {
		return nil, 0, fmt.Errorf("srp/client: sign update: %w", err)
	}

	resp, err := c.cfg.Send(ctx, addr, c.cfg.UseTCP, signed)
	if err != nil {
		return nil, 0, fmt.Errorf("srp/client: send update to %s: %w", addr, err)
	}
	return resp, pkgsrp.InterpretResponse(resp), nil
}

// Register performs exactly one build-sign-send-interpret cycle: no rename-retry, no
// scheduling. Callers wanting the full lifecycle (initial delay, refresh clock, automatic
// rename-retry) should use Run instead; Register is the primitive Run is built from, and is
// also useful standalone for a one-shot CLI invocation.
func (c *Client) Register(ctx context.Context) (*dns.Msg, pkgsrp.Outcome, error) {
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
// Also requests LEASE=0. RFC 9665 S3.3.1.3's own removal signal is purely structural (zero
// address Adds), not lease-based -- RFC 9664's LEASE=0 Case C has no direct SRP analog, per
// this project's own earlier reading of the RFC text. But a real registrar
// (mDNSResponder/ServiceRegistration's srp-mdns-proxy, srp-parse.c's
// "does not include a host description" path) additionally requires host_lease==0 before it
// will recognize a zero-address host update as a removal at all -- confirmed by live
// interop testing (tests/test_mdnsresponder_interop.sh), not assumed. Sending LEASE=0 is
// still fully RFC 9665-conformant (a requester may request any lease value including 0) and
// is required in practice for this to interoperate with that real implementation.
//
// Also requests KEY-LEASE=0, unlike Register's use of c.cfg.RequestedKeyLease: RFC 9665
// S3.2.5.5.1 is explicit that "if the registration is to be permanently removed, KEY-LEASE
// SHOULD also be zero" -- and Deregister always means permanent removal, never a lightweight
// refresh, so there is no configured value to fall back to here.
func (c *Client) Deregister(ctx context.Context) (*dns.Msg, pkgsrp.Outcome, error) {
	return c.buildSignSend(ctx, nil, c.specs(true), 0, 0)
}

// registerWithRenameRetry calls Register, renaming and retrying on OutcomeConflict up to
// Config.MaxRenames times.
func (c *Client) registerWithRenameRetry(ctx context.Context) (*dns.Msg, error) {
	for attempt := 0; attempt <= c.cfg.MaxRenames; attempt++ {
		resp, outcome, err := c.Register(ctx)
		if err != nil {
			return nil, err
		}
		if outcome != pkgsrp.OutcomeConflict {
			if outcome != pkgsrp.OutcomeSuccess {
				return resp, fmt.Errorf("srp/client: registration failed: %s (rcode=%d)", outcome, resp.Rcode)
			}
			return resp, nil
		}
		c.rename()
	}
	return nil, fmt.Errorf("srp/client: gave up after %d rename attempts, still conflicting", c.cfg.MaxRenames)
}

// minRegisterRetryBackoff/maxRegisterRetryBackoff bound Run's retry-on-error backoff: it
// starts at minRegisterRetryBackoff, doubles after every consecutive failure up to
// maxRegisterRetryBackoff, and resets to minRegisterRetryBackoff after any success -- the
// same "don't hammer a struggling registrar, but don't wait an hour to notice it's back
// either" shape refreshDelay's own jitter serves for the steady-state clock.
const (
	minRegisterRetryBackoff = 5 * time.Second
	maxRegisterRetryBackoff = 5 * time.Minute
)

// Run performs the full RFC 9665 requester lifecycle: an initial 0-3s random delay (plan
// roadmap), then registers (with rename-retry on conflict), then sleeps for the RFC 9664
// S5.2 refresh clock (80% of the granted lease + 0-5% jitter) and re-registers -- restating
// the full registration every time, per S3.2's "no lightweight refresh." Blocks until ctx
// is canceled (via Sleep returning ctx.Err()); that is the only thing that stops Run.
//
// A failed registration cycle -- a transient network/DNS error, a registrar rejection,
// rename attempts exhausted against a persistent conflict -- does not stop Run: Config.OnError
// (if set) is called with the error, and the cycle is retried after an exponentially
// increasing backoff (see minRegisterRetryBackoff/maxRegisterRetryBackoff), reset back to
// the minimum after any success. Earlier versions of this method returned immediately on
// any such error, meaning a single transient blip during a routine refresh -- one UDP
// timeout, one SERVFAIL -- permanently stopped a long-running daemon's registration with
// no automatic recovery; self-healing from that class of failure is the whole point of a
// background Run loop rather than a one-shot Register call.
func (c *Client) Run(ctx context.Context) error {
	if err := c.cfg.Sleep(ctx, initialDelay(c.cfg.Rng)); err != nil {
		return err
	}

	backoff := minRegisterRetryBackoff
	for {
		resp, err := c.registerWithRenameRetry(ctx)
		if err != nil {
			if c.cfg.OnError != nil {
				c.cfg.OnError(err)
			}
			if sleepErr := c.cfg.Sleep(ctx, backoff); sleepErr != nil {
				return sleepErr
			}
			if backoff *= 2; backoff > maxRegisterRetryBackoff {
				backoff = maxRegisterRetryBackoff
			}
			continue
		}
		backoff = minRegisterRetryBackoff

		if c.cfg.OnRegistered != nil {
			c.cfg.OnRegistered(resp)
		}

		lease, _, ok := pkgsrp.GrantedLease(resp)
		if !ok {
			lease = c.cfg.RequestedLease
		}

		if err := c.cfg.Sleep(ctx, refreshDelay(c.cfg.Rng, lease)); err != nil {
			return err
		}
	}
}

// ctxSleep is context.Context.Done()-aware time.Sleep: it returns ctx.Err() if ctx is
// canceled before d elapses, nil once d elapses normally.
func ctxSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// liveTransport sends msg to addr over UDP or TCP using the existing base client package,
// the same transport every other client/test tool in this codebase already uses.
func liveTransport(timeout time.Duration) Transport {
	return func(ctx context.Context, addr string, useTCP bool, msg *dns.Msg) (*dns.Msg, error) {
		protocol := "udp"
		if useTCP {
			protocol = "tcp"
		}
		c := baseclient.New(addr, protocol, timeout)
		return c.Query(msg)
	}
}
