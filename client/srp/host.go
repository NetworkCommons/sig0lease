package srp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	baseclient "github.com/NetworkCommons/sig0lease/client"
)

// HostStore keeps what a host needs across restarts: whether its names are held for its key,
// and under which labels (see Labels), so that they can be freed after a restart: those of a
// host no longer wanted (Release), and those a rename holds, as every start asks for the
// requested names again (StartHost).
type HostStore interface {
	// Load returns the labels the names of the host whose requested name is host are held
	// under, or nil if none are held.
	Load(host string) *Labels
	// Hold records the labels the host's names are held under: after every registration that
	// succeeded; nil once a deregistration freed them. A store need not write anything when
	// nothing changes.
	Hold(host string, labels *Labels) error
}

// HostConfig configures StartHost.
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

// Host keeps one host registered as what it offers changes: each Set restates its addresses
// and instances, and the Host registers them (Client.Run, refreshing on the lease clock),
// first withdrawing instances that are gone. No addresses means no registration: the host is
// deregistered (RFC 9665 S3.3.1.3), as it is when the Host stops (the Keeper's Stop and Wait).
// Labels carry over from one registration to the next, so a renamed host keeps its names
// while it runs; a new Host asks for the requested names again (StartHost).
type Host struct {
	*baseclient.Keeper[hostState]
	cfg     HostConfig
	owner   string // the requested host name, HostStore's key
	labels  *Labels
	applied hostState // what was last registered; no addresses: nothing
	running *Client   // the client the Keeper keeps running, if any
}

// hostState is what a host should have registered.
type hostState struct {
	addrs     []netip.Addr
	instances []InstanceConfig
}

// StartHost starts keeping cfg.Client.HostLabel registered. It registers nothing until the
// first Set. Every Host asks for the requested names: if cfg.Store says an earlier Host's
// rename holds names, kept when it stopped, StartHost first frees them (Release), so that
// they are not held beside the requested ones. If that fails, the Host registers under them,
// as its key still holds them, and the next start tries again.
func StartHost(cfg HostConfig) (*Host, error) {
	if cfg.Client.Key == nil {
		return nil, errors.New("srp/host: Client.Key is required")
	}
	cfg.Defaults()
	h := &Host{cfg: cfg, owner: cfg.owner()}
	if cfg.Store != nil {
		if held := cfg.Store.Load(h.owner); held != nil && held.Renamed(cfg.Client.HostLabel) {
			cfg.logf("freeing %s, held from an earlier run, to ask for the requested names again", describeLabels(*held))
			if err := Release(cfg); err != nil {
				return nil, err
			}
			if h.labels = cfg.Store.Load(h.owner); h.labels != nil {
				cfg.logf("registering under %s again, as its key still holds them", describeLabels(*h.labels))
			}
		}
	}
	h.Keeper = baseclient.StartKeeper(cfg.KeeperConfig, baseclient.Moves[hostState]{To: h.to, Kept: h.kept, Leave: h.leave})
	return h, nil
}

// owner is the host's requested name, HostStore's key.
func (cfg *HostConfig) owner() string {
	return dnsutil.Fqdn(cfg.Client.HostLabel + "." + cfg.Client.Domain)
}

// Release frees the names a host that is not running may still hold from an earlier run: one
// deregistration of the host alone asking for a KEY-LEASE of 0, under the labels cfg.Store
// keeps for it, bounded by cfg.StopTimeout. The registrar removes the host's service instances
// with it (RFC 9665 S3.2.5.5.1: "even if the SRP requester doesn't list them"). cfg.Store
// records the names as freed once the registrar confirms it, or answers that another key
// holds the host name now. Release returns an error only for a client configuration NewClient
// refuses; a deregistration that fails is logged, and the names stay recorded as held.
func Release(cfg HostConfig) error {
	cfg.Defaults()
	c := cfg.Client
	c.Instances = nil
	if cfg.Store != nil {
		c.Labels = cfg.Store.Load(cfg.owner())
	}
	client, err := NewClient(c)
	if err != nil {
		return fmt.Errorf("srp/host %s: %w", c.HostLabel, err)
	}
	deregister(cfg, client, nil, false)
	return nil
}

// Set replaces what the host should have registered with addrs and instances (Keeper.Set).
func (h *Host) Set(addrs []netip.Addr, instances []InstanceConfig) {
	h.Keeper.Set(hostState{addrs: slices.Clone(addrs), instances: slices.Clone(instances)})
}

// logf logs a line about cfg's host, starting with its label.
func (cfg HostConfig) logf(format string, args ...any) {
	cfg.Logf(cfg.Client.HostLabel+": "+format, args...)
}

// hold records in cfg.Store, if set, the labels the host's names are held under; nil: none.
func hold(cfg HostConfig, labels *Labels) {
	if cfg.Store == nil {
		return
	}
	if err := cfg.Store.Hold(cfg.owner(), labels); err != nil {
		cfg.logf("recording whether its names are held: %v", err)
	}
}

// client makes the Client that registers s.
func (h *Host) client(s hostState) (*Client, error) {
	c := h.cfg.Client
	c.Addresses = s.addrs
	c.Instances = s.instances
	c.Labels = h.labels
	c.OnRenamed = func(l Labels) { h.cfg.logf("renamed: now %s", describeLabels(l)) }
	var client *Client
	c.OnRegistered = func(resp *dns.Msg) {
		labels := client.Labels() // from Run's goroutine, the one renaming
		hold(h.cfg, &labels)
		lease, keyLease, _ := baseclient.GrantedLease(resp)
		h.cfg.logf("registered %s, lease %ds, key lease %ds", describe(s.instances), lease, keyLease)
	}
	c.OnError = func(err error) { h.cfg.logf("%v", err) }
	var err error
	if client, err = NewClient(c); err != nil {
		return nil, fmt.Errorf("srp/host %s: %w", h.cfg.Client.HostLabel, err)
	}
	return client, nil
}

// to moves the host to next (Moves.To): it deregisters the host if next has no addresses,
// and otherwise withdraws the instances next lacks, then keeps next registered.
func (h *Host) to(next hostState) (func(context.Context), error) {
	if len(next.addrs) == 0 {
		err := h.leave()
		h.applied = hostState{}
		return nil, err
	}
	if gone := withdrawn(h.applied.instances, next.instances); len(h.applied.addrs) > 0 && len(gone) > 0 {
		c, err := h.client(hostState{addrs: next.addrs, instances: append(slices.Clone(next.instances), gone...)})
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), h.cfg.StopTimeout)
		_, outcome, err := c.Register(ctx)
		cancel()
		baseclient.Report(h.cfg.logf, "withdrawing "+describe(gone), "withdrew "+describe(gone), outcome, err)
	}
	c, err := h.client(next)
	if err != nil {
		return nil, err
	}
	h.cfg.logf("registering %s at %v%s", describe(next.instances), next.addrs, h.renamed())
	h.running, h.applied = c, next
	return func(ctx context.Context) {
		_ = c.Run(ctx) // returns only once ctx ends; OnRegistered/OnError report each cycle
	}, nil
}

// kept takes the labels the stopped client ran under (Moves.Kept): Run may have renamed, and
// the next client starts from there.
func (h *Host) kept() {
	labels := h.running.Labels()
	h.labels = &labels
	h.running = nil
}

// leave deregisters what was last registered, if anything (Moves.Leave).
func (h *Host) leave() error {
	if len(h.applied.addrs) == 0 {
		return nil
	}
	c, err := h.client(h.applied)
	if err != nil {
		return err
	}
	deregister(h.cfg, c, h.applied.instances, h.cfg.KeepNames)
	return nil
}

// deregister sends c's deregistration of the host and instances, keeping the names or freeing
// them, within cfg.StopTimeout, logs how it went, and records freed names in cfg.Store: what a
// Host does when it stops, and what Release does. A YXDOMAIN to the deregistration of the
// host alone means another key holds the host name now: the host's KEY ran out, and its
// instances' with it, so the host holds no name any more.
func deregister(cfg HostConfig, c *Client, instances []InstanceConfig, keepNames bool) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.StopTimeout)
	defer cancel()
	_, outcome, err := c.Deregister(ctx, keepNames)
	action := "deregistering " + describe(instances)
	switch {
	case err == nil && outcome == baseclient.OutcomeConflict && len(instances) == 0:
		cfg.logf("%s: another key holds the host name now; nothing of this host's is left to free", action)
		hold(cfg, nil)
	case keepNames:
		baseclient.Report(cfg.logf, action, "deregistered "+describe(instances)+"; names kept for its key", outcome, err)
	default:
		if baseclient.Report(cfg.logf, action, "deregistered "+describe(instances)+"; names freed", outcome, err) {
			hold(cfg, nil)
		}
	}
}

// withdrawn returns the instances in before that after lacks, marked for removal.
func withdrawn(before, after []InstanceConfig) []InstanceConfig {
	var out []InstanceConfig
	for _, b := range before {
		if !slices.ContainsFunc(after, func(a InstanceConfig) bool {
			return a.ServiceType == b.ServiceType && a.Label == b.Label
		}) {
			out = append(out, InstanceConfig{Label: b.Label, ServiceType: b.ServiceType, Remove: true})
		}
	}
	return out
}

// renamed describes the labels the host registers under, if an earlier rename changed any.
func (h *Host) renamed() string {
	if h.labels == nil || !h.labels.Renamed(h.cfg.Client.HostLabel) {
		return ""
	}
	return " (renamed: " + describeLabels(*h.labels) + ")"
}

func describe(insts []InstanceConfig) string {
	if len(insts) == 0 {
		return "the host alone"
	}
	parts := make([]string, len(insts))
	for i, c := range insts {
		parts[i] = fmt.Sprintf("%q %s", c.Label, c.ServiceType)
	}
	return strings.Join(parts, ", ")
}

func describeLabels(l Labels) string {
	parts := []string{"host " + l.Host}
	names := make([]InstanceName, 0, len(l.Instances))
	for n := range l.Instances {
		names = append(names, n)
	}
	slices.SortFunc(names, func(a, b InstanceName) int {
		return strings.Compare(a.ServiceType+"\x00"+a.Label, b.ServiceType+"\x00"+b.Label)
	})
	for _, n := range names {
		if label := l.Instances[n]; label != n.Label {
			parts = append(parts, fmt.Sprintf("%q %s as %q", n.Label, n.ServiceType, label))
		}
	}
	return strings.Join(parts, ", ")
}

// PublishableAddresses returns the addresses in addrs that mean something off the link:
// not loopback, link-local, unspecified or multicast.
func PublishableAddresses(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
			continue
		}
		out = append(out, a)
	}
	return out
}
