// Package mdnsbridge mirrors services that a running mDNSResponder sees on the local link
// into a DNS zone through an SRP registrar. It learns them from the daemon itself (browse,
// resolve and address lookups over its client socket, see client/mdnsresponder) and
// registers each selected host, with its addresses and its instances, through client/srp:
// one SRP identity, so one signing key, per mDNS host.
//
// When the daemon reports an instance gone, the bridge withdraws it; when a host has no
// instance left, or the bridge stops, it deregisters the host. What it does not follow:
// subtypes (a browse does not report them), and a host's later address or TXT changes (it
// resolves an instance and looks up its host's addresses when they first appear).
package mdnsbridge

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client/mdnsresponder"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/dnssd"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	pkgsrp "github.com/NetworkCommons/sig0lease/pkg/srp"
)

// Source is the daemon's side of the bridge. DaemonSource is the real one.
type Source interface {
	Browse(ctx context.Context, serviceType, domain string, events chan<- mdnsresponder.BrowseEvent) error
	Resolve(ctx context.Context, interfaceIndex uint32, name, serviceType, domain string) (mdnsresponder.ResolveResult, error)
	Addresses(ctx context.Context, host string) ([]netip.Addr, error)
}

// DaemonSource is the mDNSResponder daemon listening on the Unix socket at path.
func DaemonSource(path string) Source { return daemon(path) }

type daemon string

func (d daemon) Browse(ctx context.Context, serviceType, domain string, events chan<- mdnsresponder.BrowseEvent) error {
	return mdnsresponder.Browse(ctx, string(d), serviceType, domain, events)
}

func (d daemon) Resolve(ctx context.Context, interfaceIndex uint32, name, serviceType, domain string) (mdnsresponder.ResolveResult, error) {
	return mdnsresponder.Resolve(ctx, string(d), interfaceIndex, name, serviceType, domain)
}

// addressSettle is how long Addresses waits for one more address after the last.
const addressSettle = 500 * time.Millisecond

func (d daemon) Addresses(ctx context.Context, host string) ([]netip.Addr, error) {
	return mdnsresponder.Addresses(ctx, string(d), 0, host, addressSettle)
}

// Config configures Run.
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

	// Settle is how long a host's changes are collected before its registration is sent
	// again; default 1s.
	Settle time.Duration
	// StopTimeout bounds the deregistrations sent when Run stops; default 10s.
	StopTimeout time.Duration
	Logf        func(format string, args ...any)
}

// lookupTimeout bounds one resolve or address lookup.
const lookupTimeout = 5 * time.Second

// Run mirrors until ctx ends, then deregisters every host it registered and returns
// ctx's error. A browse that fails, such as one macOS refuses for lack of Local Network
// permission, stops it the same way, returning that error.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Source == nil {
		return errors.New("mdnsbridge: Source is required")
	}
	if !cfg.List && !cfg.AllHosts && len(cfg.Hosts) == 0 {
		return errors.New("mdnsbridge: name the hosts to mirror, or mirror all hosts")
	}
	if !cfg.List && cfg.Key == nil {
		return errors.New("mdnsbridge: Key is required")
	}
	for _, t := range cfg.ServiceTypes {
		if err := dnssd.ValidateServiceType(t); err != nil {
			return fmt.Errorf("mdnsbridge: service type: %w", err)
		}
	}
	if cfg.Settle <= 0 {
		cfg.Settle = time.Second
	}
	if cfg.StopTimeout <= 0 {
		cfg.StopTimeout = 10 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	b := &bridge{
		cfg:       cfg,
		hostsWant: map[string]bool{},
		browsing:  map[string]bool{},
		instances: map[instanceKey]*instance{},
		hosts:     map[string]*host{},
		events:    make(chan browseEvent),
		results:   make(chan func()),
		failed:    make(chan error, 1),
	}
	for _, h := range cfg.Hosts {
		b.hostsWant[normalizeHost(h)] = true
	}
	return b.run(ctx)
}

// instanceKey names one instance on the link: its service type ("_http._tcp") and name.
type instanceKey struct{ serviceType, name string }

type instance struct {
	interfaces map[uint32]bool // where the daemon currently reports it
	gen        int             // bumped when it goes away, so a late resolve is dropped
	host       string          // normalized target once resolved and mirrored, else ""
}

type host struct {
	label     string
	addrs     []netip.Addr // nil until looked up
	lookingUp bool
	instances map[instanceKey]clientsrp.InstanceConfig
	worker    *worker
}

type browseEvent struct {
	serviceType string // the type browsed, or "" for the type enumeration
	ev          mdnsresponder.BrowseEvent
}

type bridge struct {
	cfg       Config
	hostsWant map[string]bool
	browsing  map[string]bool
	instances map[instanceKey]*instance
	hosts     map[string]*host
	events    chan browseEvent
	results   chan func() // lookup results, applied on the run goroutine
	failed    chan error
	wg        sync.WaitGroup // browse and lookup goroutines
	workers   sync.WaitGroup
}

func (b *bridge) run(ctx context.Context) error {
	loopCtx, stop := context.WithCancel(ctx)
	defer stop()

	if len(b.cfg.ServiceTypes) == 0 {
		b.browse(loopCtx, "")
	} else {
		for _, t := range b.cfg.ServiceTypes {
			b.browse(loopCtx, t)
		}
	}

	var err error
loop:
	for {
		select {
		case e := <-b.events:
			b.handle(loopCtx, e)
		case apply := <-b.results:
			apply()
		case err = <-b.failed:
			break loop
		case <-ctx.Done():
			err = ctx.Err()
			break loop
		}
	}
	stop()
	// Lookups and browses end with loopCtx; drain what they still try to deliver.
	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	for waiting := true; waiting; {
		select {
		case <-b.events:
		case <-b.results:
		case <-b.failed:
		case <-done:
			waiting = false
		}
	}
	for _, h := range b.hosts {
		if h.worker != nil {
			h.worker.stop()
		}
	}
	b.workers.Wait()
	return err
}

// browse starts browsing serviceType in local., or the service type enumeration for "".
func (b *bridge) browse(ctx context.Context, serviceType string) {
	b.browsing[serviceType] = true
	name := serviceType
	if name == "" {
		name = "_services._dns-sd._udp"
	}
	ch := make(chan mdnsresponder.BrowseEvent)
	b.wg.Add(2)
	go func() {
		defer b.wg.Done()
		defer close(ch)
		err := b.cfg.Source.Browse(ctx, name, "local.", ch)
		if ctx.Err() == nil {
			if err == nil {
				err = fmt.Errorf("mdnsbridge: browse %s ended", name)
			}
			select {
			case b.failed <- err:
			default:
			}
		}
	}()
	go func() {
		defer b.wg.Done()
		for ev := range ch {
			select {
			case b.events <- browseEvent{serviceType: serviceType, ev: ev}:
			case <-ctx.Done():
			}
		}
	}()
}

func (b *bridge) handle(ctx context.Context, e browseEvent) {
	if e.serviceType == "" {
		// A type enumeration reply names the type as instance name "_http" in type
		// "_tcp.local." (RFC 6763 S9). Types are never unbrowsed: their instances go away
		// one by one.
		proto, _, _ := strings.Cut(e.ev.Type, ".")
		t := e.ev.Name + "." + proto
		if !e.ev.Add || b.browsing[t] {
			return
		}
		if err := dnssd.ValidateServiceType(t); err != nil {
			b.cfg.Logf("ignoring service type %q: %v", t, err)
			b.browsing[t] = true
			return
		}
		b.browse(ctx, t)
		return
	}

	key := instanceKey{serviceType: e.serviceType, name: e.ev.Name}
	inst := b.instances[key]
	if e.ev.Add {
		if inst == nil {
			inst = &instance{interfaces: map[uint32]bool{}}
			b.instances[key] = inst
		}
		first := len(inst.interfaces) == 0
		inst.interfaces[e.ev.InterfaceIndex] = true
		if first {
			b.resolve(ctx, key, inst, e.ev)
		}
		return
	}
	if inst == nil {
		return
	}
	delete(inst.interfaces, e.ev.InterfaceIndex)
	if len(inst.interfaces) > 0 {
		return
	}
	inst.gen++
	if inst.host != "" {
		if b.cfg.List {
			b.cfg.Logf("- %q %s on %s", key.name, key.serviceType, inst.host)
		} else {
			b.cfg.Logf("- %q %s on %s: gone", key.name, key.serviceType, inst.host)
			h := b.hosts[inst.host]
			delete(h.instances, key)
			b.publish(ctx, inst.host, h)
		}
		inst.host = ""
	}
}

// resolve looks up an instance that appeared, then hands it to added.
func (b *bridge) resolve(ctx context.Context, key instanceKey, inst *instance, ev mdnsresponder.BrowseEvent) {
	gen := inst.gen
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
		res, err := b.cfg.Source.Resolve(lctx, ev.InterfaceIndex, ev.Name, ev.Type, ev.Domain)
		cancel()
		b.deliver(ctx, func() {
			if inst.gen != gen || b.instances[key] != inst {
				return // gone again meanwhile
			}
			if err != nil {
				b.cfg.Logf("skipping %q %s: %v", key.name, key.serviceType, err)
				return
			}
			b.added(ctx, key, inst, res)
		})
	}()
}

func (b *bridge) deliver(ctx context.Context, apply func()) {
	select {
	case b.results <- apply:
	case <-ctx.Done():
	}
}

func (b *bridge) added(ctx context.Context, key instanceKey, inst *instance, res mdnsresponder.ResolveResult) {
	target := dnsname.Normalize(res.Target) + "."
	selected := b.cfg.AllHosts || b.hostsWant[target]
	if b.cfg.List {
		mark := " "
		if selected {
			mark = "*"
		}
		b.cfg.Logf("+ %q %s on %s port %d %s", key.name, key.serviceType, target, res.Port, mark)
		inst.host = target
		return
	}
	if !selected {
		return
	}
	label, err := hostLabel(target)
	if err == nil {
		err = dnsname.CheckLabel(key.name)
	}
	if err != nil {
		b.cfg.Logf("skipping %q %s on %s: %v", key.name, key.serviceType, target, err)
		return
	}
	txt := make([]string, len(res.TXT))
	for i, s := range res.TXT {
		txt[i] = escapeTXT(s)
	}
	h := b.hosts[target]
	if h == nil {
		h = &host{label: label, instances: map[instanceKey]clientsrp.InstanceConfig{}}
		b.hosts[target] = h
	}
	h.instances[key] = clientsrp.InstanceConfig{Label: key.name, ServiceType: key.serviceType, Port: res.Port, TXT: txt}
	inst.host = target
	b.cfg.Logf("+ %q %s on %s port %d", key.name, key.serviceType, target, res.Port)
	if h.addrs == nil {
		b.lookupAddresses(ctx, target, h)
		return
	}
	b.publish(ctx, target, h)
}

func (b *bridge) lookupAddresses(ctx context.Context, target string, h *host) {
	if h.lookingUp {
		return
	}
	h.lookingUp = true
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
		addrs, err := b.cfg.Source.Addresses(lctx, target)
		cancel()
		b.deliver(ctx, func() {
			h.lookingUp = false
			if err == nil {
				addrs = usableAddresses(addrs)
				if len(addrs) == 0 {
					err = errors.New("only loopback or link-local addresses, which mean nothing outside the link")
				}
			}
			if err != nil {
				// SRP cannot register a host without addresses (zero address Adds mean
				// delete, RFC 9665 S3.3.1.3); the host is tried again when another of its
				// instances appears.
				b.cfg.Logf("not registering %s: %v", target, err)
				return
			}
			h.addrs = addrs
			b.cfg.Logf("  %s has %v", target, addrs)
			b.publish(ctx, target, h)
		})
	}()
}

// publish hands h's current instances to its worker, starting one if needed.
func (b *bridge) publish(ctx context.Context, target string, h *host) {
	if h.addrs == nil {
		if len(h.instances) > 0 {
			b.lookupAddresses(ctx, target, h)
		}
		return
	}
	if h.worker == nil {
		if len(h.instances) == 0 {
			return
		}
		h.worker = b.startWorker(h.label)
	}
	insts := make([]clientsrp.InstanceConfig, 0, len(h.instances))
	for _, c := range h.instances {
		insts = append(insts, c)
	}
	slices.SortFunc(insts, func(a, c clientsrp.InstanceConfig) int {
		return strings.Compare(a.ServiceType+"\x00"+a.Label, c.ServiceType+"\x00"+c.Label)
	})
	h.worker.set(state{addrs: slices.Clone(h.addrs), instances: insts})
}

// hostLabel returns the label a .local. host keeps in the SRP domain.
func hostLabel(target string) (string, error) {
	label, rest, ok := dnsname.CutFirstLabel(target)
	if !ok || !dnsname.EqualFold(rest, "local.") {
		return "", fmt.Errorf("host %s is not a .local. name", target)
	}
	return label, dnsname.CheckLabel(label)
}

// normalizeHost turns a host name as a user gives it into the form resolved targets are
// compared in: "MyMac", "mymac.local" and "mymac.local." all become "mymac.local.".
func normalizeHost(h string) string {
	h = dnsname.Normalize(h)
	if !strings.Contains(h, ".") {
		h += ".local"
	}
	return h + "."
}

func usableAddresses(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
			continue
		}
		out = append(out, a)
	}
	return out
}

// escapeTXT turns one raw TXT string into the form codeberg.org/miekg/dns packs: its
// strings are presentation text, where a backslash starts an escape, so only backslashes
// need escaping for every other byte to go out as it is.
func escapeTXT(raw []byte) string {
	return strings.ReplaceAll(string(raw), `\`, `\\`)
}

// state is what a host should have registered.
type state struct {
	addrs     []netip.Addr
	instances []clientsrp.InstanceConfig
}

// worker owns one host's SRP client. Changes reach it through set, latest first; it
// collects them for Settle, then registers the new state, withdrawing instances that left.
type worker struct {
	b       *bridge
	label   string
	updates chan state
	quit    chan struct{}
}

func (b *bridge) startWorker(label string) *worker {
	w := &worker{b: b, label: label, updates: make(chan state, 1), quit: make(chan struct{})}
	b.workers.Add(1)
	go w.run()
	return w
}

// set replaces any state the worker has not taken yet. Only the run goroutine calls it.
func (w *worker) set(s state) {
	select {
	case <-w.updates:
	default:
	}
	w.updates <- s
}

func (w *worker) stop() { close(w.quit) }

func (w *worker) logf(format string, args ...any) {
	w.b.cfg.Logf(w.label+": "+format, args...)
}

func (w *worker) run() {
	defer w.b.workers.Done()
	cfg := w.b.cfg
	owner := w.label + "." + strings.TrimSuffix(cfg.SRP.Domain, ".") + "."
	key, err := cfg.Key(owner)
	if err != nil {
		w.fail(fmt.Errorf("mdnsbridge: signing key for %s: %w", owner, err))
		return
	}

	var applied state    // what was last registered
	var cancelRun func() // stops the running client
	var runDone chan struct{}
	stopRun := func() {
		if cancelRun != nil {
			cancelRun()
			<-runDone
			cancelRun = nil
		}
	}
	client := func(s state) (*clientsrp.Client, error) {
		c := cfg.SRP
		c.HostLabel = w.label
		c.Addresses = s.addrs
		c.Instances = s.instances
		c.Key = key
		c.OnRegistered = func(resp *dns.Msg) {
			lease, keyLease, _ := pkgsrp.GrantedLease(resp)
			w.logf("registered %s, lease %ds, key lease %ds", describe(s.instances), lease, keyLease)
		}
		c.OnError = func(err error) { w.logf("%v", err) }
		return clientsrp.NewClient(c)
	}

	shutdown := func() {
		stopRun()
		if len(applied.instances) > 0 {
			w.deregister(client, applied)
		}
	}

	for {
		var next state
		select {
		case next = <-w.updates:
		case <-w.quit:
			shutdown()
			return
		}
		// Collect further changes until none arrives for Settle.
		for settling := true; settling; {
			select {
			case next = <-w.updates:
			case <-time.After(cfg.Settle):
				settling = false
			case <-w.quit:
				shutdown()
				return
			}
		}
		stopRun()

		if len(next.instances) == 0 {
			if len(applied.instances) > 0 {
				w.deregister(client, applied)
			}
			applied = state{}
			continue
		}
		if gone := withdrawn(applied.instances, next.instances); len(gone) > 0 {
			c, err := client(state{addrs: next.addrs, instances: append(slices.Clone(next.instances), gone...)})
			if err != nil {
				w.fail(err)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), cfg.StopTimeout)
			_, outcome, err := c.Register(ctx)
			cancel()
			w.report("withdrawing "+describe(gone), "withdrew "+describe(gone), outcome, err)
		}
		c, err := client(next)
		if err != nil {
			w.fail(err)
			return
		}
		w.logf("registering %s at %v", describe(next.instances), next.addrs)
		ctx, cancel := context.WithCancel(context.Background())
		cancelRun, runDone = cancel, make(chan struct{})
		go func(done chan struct{}) {
			defer close(done)
			_ = c.Run(ctx) // returns only once ctx ends; OnRegistered/OnError report each cycle
		}(runDone)
		applied = next
	}
}

func (w *worker) deregister(client func(state) (*clientsrp.Client, error), s state) {
	c, err := client(s)
	if err != nil {
		w.fail(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), w.b.cfg.StopTimeout)
	defer cancel()
	_, outcome, err := c.Deregister(ctx)
	w.report("deregistering "+describe(s.instances), "deregistered "+describe(s.instances), outcome, err)
}

// fail stops the bridge with err, for errors no later change can cure (a key that cannot be
// loaded or created, a client configuration the bridge itself built wrong), then waits to be
// stopped.
func (w *worker) fail(err error) {
	select {
	case w.b.failed <- err:
	default:
	}
	<-w.quit
}

func (w *worker) report(action, done string, outcome pkgsrp.Outcome, err error) {
	switch {
	case err != nil:
		w.logf("%s: %v", action, err)
	case outcome != pkgsrp.OutcomeSuccess:
		w.logf("%s: registrar answered %s", action, outcome)
	default:
		w.logf("%s", done)
	}
}

// withdrawn returns the instances in before that after lacks, marked for removal.
func withdrawn(before, after []clientsrp.InstanceConfig) []clientsrp.InstanceConfig {
	var out []clientsrp.InstanceConfig
	for _, b := range before {
		if !slices.ContainsFunc(after, func(a clientsrp.InstanceConfig) bool {
			return a.ServiceType == b.ServiceType && a.Label == b.Label
		}) {
			out = append(out, clientsrp.InstanceConfig{Label: b.Label, ServiceType: b.ServiceType, Remove: true})
		}
	}
	return out
}

func describe(insts []clientsrp.InstanceConfig) string {
	parts := make([]string, len(insts))
	for i, c := range insts {
		parts[i] = fmt.Sprintf("%q %s", c.Label, c.ServiceType)
	}
	return strings.Join(parts, ", ")
}
