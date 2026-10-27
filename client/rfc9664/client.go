// Package rfc9664 implements a requester for this proxy's RFC 9664 handler (update_handler):
// one name, held by its own key, with records at and below it, registered as a DNS UPDATE
// signed with SIG(0) and kept on an Update Lease (RFC 9664). The name is one label below the
// zone, the only name a key registers for itself under the handler's fcfs_naming
// (docs/siglease_rfc9664.md, "First-Come First-Served Naming"). Every request carries the
// name's KEY in its Update section, so the proxy verifies it with the key it registers, and
// is one of the handler's lease cases (Behavior Specification item 5):
//
//   - Register: Case A, the KEY and the records, both leases non-zero;
//   - Withdraw, and Deregister keeping the name: Case D, the KEY and the records to delete,
//     a LEASE of 0 and the KEY-LEASE, which keeps the name for the key;
//   - Deregister freeing the name: Case C, the KEY alone, both leases 0, which deletes the KEY
//     and everything it registered.
//
// A name another key holds is answered YXDOMAIN. An SRP requester renames (client/srp), as
// its names are found by browsing; an RFC 9664 name is typed or linked (a URL, a DNSLink path,
// a Matrix ID), so a rename would publish records nobody reads. Run therefore keeps trying
// the name, with a backoff: it registers once the other key's lease ends, which is when a
// name an earlier key of the requester's own holds comes back to it.
//
// Name keeps one name registered as its records change, as client/srp's Host does a host.
package rfc9664

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat" // registers EDNS0 code 2 (UPDATE-LEASE); required to unpack the proxy's response
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

// Config configures a Client. See NewClient for the defaults.
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

// Client is one name's registration: build, sign, send, and (Run) keep it on the refresh clock.
type Client struct {
	cfg  Config
	name string
}

// NewClient validates cfg and applies its defaults.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Zone == "" {
		return nil, fmt.Errorf("rfc9664/client: Zone is required")
	}
	cfg.Zone = dnsutil.Fqdn(cfg.Zone)
	if err := dnsname.CheckLabel(cfg.Label); err != nil {
		return nil, fmt.Errorf("rfc9664/client: Label: %w", err)
	}
	if cfg.Key == nil {
		return nil, fmt.Errorf("rfc9664/client: Key is required")
	}
	if cfg.Server == "" {
		return nil, fmt.Errorf("rfc9664/client: Server is required")
	}
	if err := cfg.Network.Validate(); err != nil {
		return nil, fmt.Errorf("rfc9664/client: Network: %w", err)
	}
	name := cfg.name()
	if err := CheckRecords(name, cfg.Records); err != nil {
		return nil, fmt.Errorf("rfc9664/client: %w", err)
	}
	if cfg.RequestedLease == 0 {
		cfg.RequestedLease = 3600
	}
	if cfg.RequestedKeyLease == 0 {
		cfg.RequestedKeyLease = 1209600
	}
	if cfg.RequestedLease > cfg.RequestedKeyLease {
		return nil, fmt.Errorf("rfc9664/client: RequestedLease (%d) must not exceed RequestedKeyLease (%d)", cfg.RequestedLease, cfg.RequestedKeyLease)
	}
	if cfg.TTL == 0 {
		cfg.TTL = 300
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
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
	return &Client{cfg: cfg, name: name}, nil
}

// name is the name cfg registers, fully qualified.
func (cfg Config) name() string { return cfg.Label + "." + dnsutil.Fqdn(cfg.Zone) }

// CheckRecords reports whether records can be registered for name: each at name or below it,
// of class IN, and neither a KEY (name's own is its key's) nor a SIG.
func CheckRecords(name string, records []dns.RR) error {
	for _, rr := range records {
		hdr := rr.Header()
		switch {
		case !dnsname.IsAtOrBelow(hdr.Name, name):
			return fmt.Errorf("record %s: not at or below %s, the name the key holds", rr, name)
		case hdr.Class != dns.ClassINET:
			return fmt.Errorf("record %s: class %s, want IN", rr, dns.ClassToString[hdr.Class])
		}
		switch rr.(type) {
		case *dns.KEY, *dns.SIG:
			return fmt.Errorf("record %s: a %s is not registered as a record (the name's KEY is its key's)", rr, dns.TypeToString[dns.RRToType(rr)])
		}
	}
	return nil
}

// Name returns the name the client registers, fully qualified.
func (c *Client) Name() string { return c.name }

// Register registers the name's KEY and Config.Records, on the requested leases (Case A).
// The handler needs a record besides the KEY in a registration: with no records, Register
// fails, and Deregister keeping the name holds it alone.
func (c *Client) Register(ctx context.Context) (*dns.Msg, baseclient.Outcome, error) {
	if len(c.cfg.Records) == 0 {
		return nil, 0, fmt.Errorf("rfc9664/client: %s: a registration needs a record besides the KEY", c.name)
	}
	return c.send(ctx, c.cfg.Records, c.cfg.RequestedLease, c.cfg.RequestedKeyLease)
}

// Withdraw deletes records, registered earlier, from the name, and refreshes its KEY (Case D).
func (c *Client) Withdraw(ctx context.Context, records []dns.RR) (*dns.Msg, baseclient.Outcome, error) {
	if err := CheckRecords(c.name, records); err != nil {
		return nil, 0, fmt.Errorf("rfc9664/client: %w", err)
	}
	return c.send(ctx, records, 0, c.cfg.RequestedKeyLease)
}

// Deregister deletes the name's records. With keepName it deletes Config.Records and keeps the
// KEY for RequestedKeyLease (Case D), so that no other key takes the name meanwhile;
// without it, it deletes the KEY (Case C), which takes every record the key registered with
// it, and the name is free.
func (c *Client) Deregister(ctx context.Context, keepName bool) (*dns.Msg, baseclient.Outcome, error) {
	if keepName {
		return c.send(ctx, c.cfg.Records, 0, c.cfg.RequestedKeyLease)
	}
	return c.send(ctx, nil, 0, 0)
}

// Run keeps the name registered (client.Lifecycle.Run): it registers, then again on the RFC
// 9664 S5.2 refresh clock, until ctx is canceled. A registration that fails, a name another
// key holds included, is reported to Config.OnError and tried again after a backoff.
func (c *Client) Run(ctx context.Context) error {
	return baseclient.Lifecycle{
		RequestedLease: c.cfg.RequestedLease,
		Rng:            c.cfg.Rng,
		Sleep:          c.cfg.Sleep,
		OnError:        c.cfg.OnError,
		OnRegistered:   c.cfg.OnRegistered,
	}.Run(ctx, c.register)
}

// errHeld is the error Run reports while another key holds the name (YXDOMAIN).
var errHeld = errors.New("held by another key (YXDOMAIN)")

// register is one of Run's registrations: an error unless the proxy accepted it.
func (c *Client) register(ctx context.Context) (*dns.Msg, error) {
	resp, outcome, err := c.Register(ctx)
	switch {
	case err != nil:
		return nil, err
	case outcome == baseclient.OutcomeConflict:
		return resp, fmt.Errorf("rfc9664/client: %s is %w; trying again later: the name is registered once that key's lease ends", c.name, errHeld)
	case outcome != baseclient.OutcomeSuccess:
		return resp, fmt.Errorf("rfc9664/client: registering %s failed: %s", c.name, baseclient.DescribeAnswer(resp, outcome))
	}
	return resp, nil
}

// send signs and sends an update of the name's KEY and records on lease and keyLease, and
// classifies the answer.
func (c *Client) send(ctx context.Context, records []dns.RR, lease, keyLease uint32) (*dns.Msg, baseclient.Outcome, error) {
	key := c.cfg.Key.PublicKey.Clone().(*dns.KEY)
	key.Hdr = dns.Header{Name: c.name, Class: dns.ClassINET, TTL: c.cfg.TTL}
	update := make([]dns.RR, len(records))
	for i, rr := range records {
		update[i] = rr.Clone()
		update[i].Header().TTL = c.cfg.TTL
	}
	msg, err := dnsmsg.NewLeaseUpdate(c.cfg.Zone, []*dns.KEY{key}, update, lease, keyLease)
	if err != nil {
		return nil, 0, fmt.Errorf("rfc9664/client: %w", err)
	}
	signed, err := sig0.SignMessage(msg, key, c.cfg.Key.PrivateKey)
	if err != nil {
		return nil, 0, fmt.Errorf("rfc9664/client: sign update: %w", err)
	}
	resp, err := c.cfg.Send(ctx, c.cfg.Server, c.cfg.Network, signed)
	if err != nil {
		return nil, 0, fmt.Errorf("rfc9664/client: send update to %s: %w", c.cfg.Server, err)
	}
	return resp, baseclient.InterpretResponse(resp), nil
}

// Diff returns the records of before that after lacks, compared as the proxy's lease store
// does (lease.RecordKey: owner, class, type and data, not the TTL).
func Diff(before, after []dns.RR) []dns.RR {
	var out []dns.RR
	for _, b := range before {
		if !slices.ContainsFunc(after, func(a dns.RR) bool { return leasepkg.RecordKey(a) == leasepkg.RecordKey(b) }) {
			out = append(out, b)
		}
	}
	return out
}
