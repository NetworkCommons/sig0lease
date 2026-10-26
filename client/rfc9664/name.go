package rfc9664

import (
	"context"
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

// Name keeps one name registered as its records change: each Set restates the records, and
// the Name registers them (Client.Run, refreshing on the lease clock), first withdrawing those
// that are gone, those Store kept from an earlier run included. No records means no
// registration: the name is deregistered, as it is when the Name stops (the Keeper's Stop
// and Wait).
type Name struct {
	*baseclient.Keeper[[]dns.RR]
	cfg     NameConfig
	applied []dns.RR // what was last registered; nil: nothing
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

// Release frees a name that is not running and may still be held from an earlier run: one
// deregistration of the KEY alone with both leases 0 (Case C), which deletes every record the
// key registered with it, bounded by cfg.StopTimeout. cfg.Store records the name as freed
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

// client makes the Client that registers records.
func (n *Name) client(records []dns.RR) (*Client, error) {
	c := n.cfg.Client
	c.Records = records
	c.OnRegistered = func(resp *dns.Msg) {
		save(n.cfg, true, records)
		lease, keyLease, _ := baseclient.GrantedLease(resp)
		n.cfg.logf("registered %s, lease %ds, key lease %ds", describe(records), lease, keyLease)
	}
	c.OnError = func(err error) { n.cfg.logf("%v", err) }
	return NewClient(c)
}

// to moves the name to next (Moves.To): it deregisters the name if next has no records, and
// otherwise withdraws the records next lacks, then keeps next registered.
func (n *Name) to(next []dns.RR) (func(context.Context), error) {
	if len(next) == 0 {
		err := n.leave()
		n.applied = nil
		return nil, err
	}
	c, err := n.client(next)
	if err != nil {
		return nil, err
	}
	if gone := Diff(n.applied, next); len(gone) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), n.cfg.StopTimeout)
		_, outcome, err := c.Withdraw(ctx, gone)
		cancel()
		baseclient.Report(n.cfg.logf, "withdrawing "+describe(gone), "withdrew "+describe(gone), outcome, err)
	}
	n.cfg.logf("registering %s", describe(next))
	n.applied = next
	return func(ctx context.Context) {
		_ = c.Run(ctx) // returns only once ctx ends; OnRegistered/OnError report each cycle
	}, nil
}

// leave deregisters what was last registered, if anything (Moves.Leave).
func (n *Name) leave() error {
	if len(n.applied) == 0 {
		return nil
	}
	c, err := n.client(n.applied)
	if err != nil {
		return err
	}
	deregister(n.cfg, c, n.cfg.KeepNames)
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
