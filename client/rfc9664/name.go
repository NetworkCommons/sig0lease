package rfc9664

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
)

// NameStore keeps what a name needs across restarts: the records registered at it, so that
// those a later start no longer has are withdrawn, and whether the name is held for its key,
// so that a name no longer wanted can be freed after a restart (Release).
type NameStore interface {
	// Load returns the records saved for name, the fully qualified name, or nil.
	Load(name string) []dns.RR
	// Save records what name holds: whether the name is held for its key (true after every
	// registration that succeeded, false once a deregistration freed it), and the records
	// registered there. A store need not write anything when nothing changes.
	Save(name string, held bool, records []dns.RR) error
}

// NameConfig configures StartName.
type NameConfig struct {
	// Client is the template for every Client the Name makes: Name, Key, the proxy,
	// transport and leases. The Name sets Records, OnRegistered and OnError.
	Client Config
	// Store, if set, keeps the records registered at the name, loaded at start and saved
	// after every registration and deregistration, and whether the name is held.
	Store NameStore
	// KeeperConfig: KeepNames applies to deregistering the name on Stop (Client.Deregister).
	// A Set with no records deregisters it keeping it, as the Name still runs.
	baseclient.KeeperConfig
}

// Name keeps one name registered as its records change: each Set restates the records, and
// the Name registers them (Client.Run, refreshing on the lease clock), deleting those that
// are gone in the same request (Config.Gone), those Store kept from an earlier run included.
// No records means no registration: the name is deregistered and kept for its key, as the
// Name still runs. When the Name stops (the Keeper's Stop and Wait), it is deregistered and
// kept or freed, as KeepNames says. While the registrar answers that another key holds the
// name, nothing at it is this key's: no record is deleted, and no deregistration is sent.
type Name struct {
	*baseclient.Keeper[[]dns.RR]
	cfg     NameConfig
	applied []dns.RR // what was last sent to be registered; nil: nothing
	// gone is what the registration of applied deletes (Config.Gone) until one succeeds:
	// records registered before that applied lacks. The running client's callbacks clear it;
	// to and leave read it once the Keeper has stopped that client, as heldByOther.
	gone []dns.RR
	// heldByOther is whether the registrar's last answer to registering applied was that
	// another key holds the name: then nothing at the name is this key's, to withdraw or
	// deregister. The running client's callbacks write it; to and leave read it once the
	// Keeper has stopped that client.
	heldByOther bool
	holding     bool // a Set with no records deregistered the name, keeping it
}

// StartName starts keeping cfg.Client's name registered. It registers nothing until the
// first Set, which withdraws the records Store has for the name that the Set lacks.
func StartName(cfg NameConfig) (*Name, error) {
	cfg.Client.Records = nil
	if _, err := NewClient(cfg.Client); err != nil {
		return nil, err
	}
	cfg.Defaults()
	n := &Name{cfg: cfg}
	if cfg.Store != nil {
		n.applied = cfg.Store.Load(cfg.Client.name())
	}
	n.Keeper = baseclient.StartKeeper(cfg.KeeperConfig, baseclient.Moves[[]dns.RR]{To: n.to, Leave: n.leave})
	return n, nil
}

// Release frees a name that has nothing registered and may still be held: one not running,
// from an earlier run, or a Name's that stops after a Set with no records kept it. It sends
// one deregistration deleting the KEY alone (class NONE, both leases 0), which deletes every record
// the key registered with it, bounded by cfg.StopTimeout. cfg.Store records the name as freed
// once the proxy confirms it, or answers that another key holds it now. Release returns an
// error only for a client configuration NewClient refuses; a deregistration that fails is
// logged, and the name stays recorded as held.
func Release(cfg NameConfig) error {
	cfg.Defaults()
	cfg.Client.Records = nil
	client, err := NewClient(cfg.Client)
	if err != nil {
		return err
	}
	deregister(cfg, client, false)
	return nil
}

// Set replaces the records the name should have registered (Keeper.Set).
func (n *Name) Set(records []dns.RR) { n.Keeper.Set(slices.Clone(records)) }

// logf logs a line about cfg's name, starting with it.
func (cfg NameConfig) logf(format string, args ...any) {
	cfg.Logf(cfg.Client.name()+": "+format, args...)
}

// save records in cfg.Store, if set, what the name holds.
func save(cfg NameConfig, held bool, records []dns.RR) {
	if cfg.Store == nil {
		return
	}
	if err := cfg.Store.Save(cfg.Client.name(), held, records); err != nil {
		cfg.logf("recording what it holds: %v", err)
	}
}

// client makes the Client that registers records, deleting gone with the first registration
// that succeeds.
func (n *Name) client(records, gone []dns.RR) (*Client, error) {
	c := n.cfg.Client
	c.Records = records
	c.Gone = gone
	c.OnRegistered = func(resp *dns.Msg) {
		n.heldByOther = false
		save(n.cfg, true, records)
		lease, keyLease, _ := baseclient.GrantedLease(resp)
		n.cfg.logf("registered %s, lease %ds, key lease %ds", describe(records), lease, keyLease)
		if len(gone) > 0 {
			n.cfg.logf("withdrew %s", describe(gone))
			gone, n.gone = nil, nil
		}
	}
	c.OnError = func(err error) {
		n.heldByOther = errors.Is(err, errHeld)
		n.cfg.logf("%v", err)
	}
	return NewClient(c)
}

// to moves the name to next (Moves.To): it deregisters the name, keeping it, if next has no
// records, and otherwise keeps next registered, the first registration deleting the records
// next lacks, unless another key holds the name: those last applied, and those an earlier
// registration was to delete if none has succeeded since.
func (n *Name) to(next []dns.RR) (func(context.Context), error) {
	if len(next) == 0 {
		registered := len(n.applied) > 0 && !n.heldByOther
		err := n.leave(true)
		n.holding = n.holding || registered
		n.applied = nil
		return nil, err
	}
	var gone []dns.RR
	if !n.heldByOther {
		gone = Diff(slices.Concat(n.applied, n.gone), next)
	}
	c, err := n.client(next, gone)
	if err != nil {
		return nil, err
	}
	if len(gone) > 0 {
		n.cfg.logf("registering %s, withdrawing %s", describe(next), describe(gone))
	} else {
		n.cfg.logf("registering %s", describe(next))
	}
	n.applied, n.gone, n.holding = next, gone, false
	return func(ctx context.Context) {
		_ = c.Run(ctx) // returns only once ctx ends; OnRegistered/OnError report each cycle
	}, nil
}

// leave deregisters what was last registered, keeping the name if keepName (Moves.Leave),
// with the records a registration was to delete if none has succeeded since: nothing when
// another key holds the name. With nothing registered, it frees the name a Set with no
// records kept, unless keepName.
func (n *Name) leave(keepName bool) error {
	if len(n.applied) == 0 {
		if n.holding && !keepName {
			n.holding = false
			return Release(n.cfg)
		}
		return nil
	}
	if n.heldByOther {
		n.cfg.logf("another key holds the name; nothing of this name's to deregister")
		save(n.cfg, false, nil)
		return nil
	}
	c, err := n.client(slices.Concat(n.applied, n.gone), nil)
	if err != nil {
		return err
	}
	n.gone = nil
	deregister(n.cfg, c, keepName)
	return nil
}

// deregister sends c's deregistration of the name, keeping it or freeing it, within
// cfg.StopTimeout, logs how it went, and records what the name holds after it in cfg.Store:
// what a Name does when it stops or has no records left, and what Release does. A YXDOMAIN
// means another key holds the name now: the name's KEY ran out, and its records with it, so
// nothing is left to free.
func deregister(cfg NameConfig, c *Client, keepName bool) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.StopTimeout)
	defer cancel()
	_, outcome, err := c.Deregister(ctx, keepName)
	action := "deregistering " + describe(c.cfg.Records)
	switch {
	case err == nil && outcome == baseclient.OutcomeConflict:
		cfg.logf("%s: another key holds the name now; nothing of this name's is left to free", action)
		save(cfg, false, nil)
	case keepName:
		if baseclient.Report(cfg.logf, action, "deregistered "+describe(c.cfg.Records)+"; name kept for its key", outcome, err) {
			save(cfg, true, nil)
		}
	default:
		if baseclient.Report(cfg.logf, action, "deregistered "+describe(c.cfg.Records)+"; name freed", outcome, err) {
			save(cfg, false, nil)
		}
	}
}

func describe(records []dns.RR) string {
	if len(records) == 0 {
		return "the name alone"
	}
	parts := make([]string, len(records))
	for i, rr := range records {
		parts[i] = Describe(rr)
	}
	return strings.Join(parts, ", ")
}

// Describe describes rr for people: its owner, type and data, without the TTL a lease
// overrides and the class, always IN.
func Describe(rr dns.RR) string {
	return fmt.Sprintf("%s %s %s", rr.Header().Name, dns.TypeToString[dns.RRToType(rr)], rr.Data())
}
