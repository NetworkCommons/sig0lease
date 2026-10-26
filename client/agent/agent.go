package agent

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/mdnsbridge"
	"github.com/NetworkCommons/sig0lease/client/rfc9664"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// Options tune Run; a zero field takes its default.
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

func (o *Options) defaults() {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Logger == nil {
		o.Logger = logging.NewLogger("info")
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 10 * time.Second
	}
	if o.ProbeInterval <= 0 {
		o.ProbeInterval = 30 * time.Second
	}
	if o.ProbeTimeout <= 0 {
		o.ProbeTimeout = 5 * time.Second
	}
	if o.ProbeFailures <= 0 {
		o.ProbeFailures = 3
	}
	if o.Interfaces == nil {
		o.Interfaces = InterfaceAddresses
	}
	if o.MirrorSource == nil {
		o.MirrorSource = mdnsbridge.DaemonSource
	}
}

// InterfaceAddresses returns the addresses of every interface of this machine.
func InterfaceAddresses() ([]netip.Addr, error) {
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range ifAddrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

// Run keeps what the template at path describes registered until ctx ends, then deregisters
// it all and returns ctx's error. It reads the template again every PollInterval: a valid
// change is applied, an invalid one logged while the agent keeps what it runs. Run returns
// early only for what it cannot go on without: a first template that is invalid, a keystore
// it cannot use, a state file edited by hand, a host or name its client refuses.
func Run(ctx context.Context, path string, opts Options) error {
	opts.defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	plan, err := Parse(data, path)
	if err != nil {
		return err
	}
	machine, err := machineAddresses(opts.Interfaces)
	if err != nil {
		return fmt.Errorf("this machine's addresses: %w", err)
	}
	probeCtx, cancelProbes := context.WithCancel(context.Background())
	a := &agent{
		opts:         opts,
		path:         path,
		seen:         data,
		machine:      machine,
		probeCtx:     probeCtx,
		hosts:        map[string]*hostRun{},
		names:        map[string]*nameRun{},
		mirrors:      map[string]*mirrorRun{},
		mirrorFailed: map[string]string{},
		fatal:        make(chan error, 1),
		probed:       make(chan probeResult),
		mirrorEnded:  make(chan mirrorEnd),
	}
	defer func() {
		cancelProbes()
		a.stopAll()
		a.probes.Wait()
	}()
	if err := a.start(plan); err != nil {
		return err
	}

	poll := time.NewTicker(opts.PollInterval)
	defer poll.Stop()
	probes := time.NewTicker(opts.ProbeInterval)
	defer probes.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-a.fatal:
			return err
		case r := <-a.probed:
			a.probeDone(r)
		case e := <-a.mirrorEnded:
			a.mirrorStopped(e)
		case <-probes.C:
			for _, hr := range a.hosts {
				for _, s := range hr.services {
					a.probe(s)
				}
			}
		case <-poll.C:
			if err := a.poll(); err != nil {
				return err
			}
		}
	}
}

// agent is Run's state, owned by Run's goroutine.
type agent struct {
	opts Options
	path string
	plan *Plan
	seen []byte // the template as last read
	bad  string // the last problem logged about the template, so that it is logged once

	store      *hostStore
	machine    []netip.Addr // this machine's publishable addresses
	machineErr string       // the last error reading them, logged once

	hosts        map[string]*hostRun   // by fully qualified name
	names        map[string]*nameRun   // by fully qualified name
	mirrors      map[string]*mirrorRun // by type
	mirrorFailed map[string]string     // the last failure logged, by mirror type

	probeCtx context.Context // ends when Run returns
	probes   sync.WaitGroup

	fatal       chan error
	probed      chan probeResult
	mirrorEnded chan mirrorEnd
}

// hostRun is one template host and what was last asked of its clientsrp.Host.
type hostRun struct {
	registrar Registrar // its registrar's connection (Registrar.connection)
	host      Host
	worker    *clientsrp.Host
	services  []*serviceRun
	set       bool
	addrs     []netip.Addr
	instances []clientsrp.InstanceConfig
}

// nameRun is one template name and what was last asked of its rfc9664.Name.
type nameRun struct {
	registrar Registrar // its registrar's connection (Registrar.connection)
	name      Name
	worker    *rfc9664.Name
	set       bool
	records   []dns.RR
}

// serviceRun is one service and its probes.
type serviceRun struct {
	host     *hostRun
	svc      Service
	up       bool // registered: no probe, or the last one passed and not ProbeFailures failed since
	failures int  // in a row
	probing  bool
	gone     bool // no longer in the template; a probe still running is ignored
}

type probeResult struct {
	s   *serviceRun
	err error
}

type mirrorRun struct {
	registrar Registrar // its registrar's connection (Registrar.connection)
	mirror    Mirror
	exclude   []string
	started   time.Time
	cancel    func()
	done      chan struct{}
}

type mirrorEnd struct {
	m   *mirrorRun
	err error
}

func (a *agent) logf(format string, args ...any) { a.opts.Logf(format, args...) }

func machineAddresses(interfaces func() ([]netip.Addr, error)) ([]netip.Addr, error) {
	addrs, err := interfaces()
	if err != nil {
		return nil, err
	}
	addrs = clientsrp.PublishableAddresses(addrs)
	slices.SortFunc(addrs, netip.Addr.Compare)
	return slices.Compact(addrs), nil
}

// start registers plan, with nothing running, once the names the state file records for
// hosts and names plan does not register are freed (release).
func (a *agent) start(plan *Plan) error {
	if err := os.MkdirAll(plan.Keystore, 0o700); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	store, err := openHostStore(plan.Keystore)
	if err != nil {
		return err
	}
	a.plan, a.store = plan, store
	a.logf("keystore %s", plan.Keystore)
	if err := a.release(plan); err != nil {
		return err
	}
	for _, r := range plan.Registrars {
		if err := a.startRegistrar(r); err != nil {
			return err
		}
	}
	return nil
}

// startRegistrar registers what r registers, none of it running: its hosts, its names, and
// its mirrors not running yet.
func (a *agent) startRegistrar(r Registrar) error {
	switch r.Protocol {
	case SRP:
		registrar := r.Server
		if registrar == "" {
			registrar = "the registrar " + clientsrp.DiscoveryService(r.Transport) + " discovery finds"
		}
		a.logf("registering in %s through %s over %s", r.Domain, registrar, r.Transport)
	case RFC9664:
		a.logf("registering names in %s through %s over %s", r.Domain, r.Server, r.Transport)
	}
	for _, h := range r.Hosts {
		if err := a.startHost(r, h); err != nil {
			return err
		}
	}
	for _, n := range r.Names {
		if err := a.startName(r, n); err != nil {
			return err
		}
	}
	for _, m := range r.Mirrors {
		if a.mirrors[m.Type] == nil {
			a.startMirror(r, m)
		}
	}
	return nil
}

// srpConfig is every SRP client's configuration for registering through r, before a host's
// name, key and leases.
func (a *agent) srpConfig(r savedRegistrar) clientsrp.Config {
	return clientsrp.Config{
		Domain:        r.Domain,
		RegistrarAddr: r.Server,
		Resolvers:     r.Resolvers,
		Network:       r.Transport,
		Send:          a.opts.Send,
		Query:         a.opts.Query,
		Sleep:         a.opts.Sleep,
	}
}

// nameConfig is every RFC 9664 client's configuration for registering through r, before a
// name's label, key and leases.
func (a *agent) nameConfig(r savedRegistrar) rfc9664.Config {
	return rfc9664.Config{
		Zone:    r.Domain,
		Server:  r.Server,
		Network: r.Transport,
		Send:    a.opts.Send,
		Sleep:   a.opts.Sleep,
	}
}

// keeperConfig is every host's and name's client.KeeperConfig, keeping its names on stop or
// not.
func (a *agent) keeperConfig(keepNames bool) baseclient.KeeperConfig {
	return baseclient.KeeperConfig{
		Settle:      a.opts.Settle,
		StopTimeout: a.opts.StopTimeout,
		KeepNames:   keepNames,
		Logf:        a.opts.Logf,
		OnFatal: func(err error) {
			select {
			case a.fatal <- err:
			default:
			}
		},
	}
}

// release frees the names the state file records as held for hosts and names plan does not
// register (wanted), and forgets them: hosts and names removed from the template, while the
// agent ran or not, hosts a mirror no longer selects, and hosts and names registered in
// another domain or zone, through another registrar or from another keystore. Any of them
// still running has been stopped first. A release that fails is logged, and tried again at
// the next start or template change; until then, the names stay held until their key lease
// ends.
func (a *agent) release(plan *Plan) error {
	for _, owner := range a.store.unwanted(plan) {
		e, _ := a.store.entry(owner)
		if e.Held {
			a.logf("state: %s holds names the template no longer registers; freeing them", owner)
			key, _, err := keyrec.ResolveOrCreateKey(a.store.keystore, owner, 0, a.opts.Logger)
			if err != nil {
				a.logf("state: %s: %v; its names stay held until their key lease ends", owner, err)
			} else {
				if err := a.releaseHeld(owner, e, key); err != nil {
					return err
				}
				if e, _ := a.store.entry(owner); e.Held {
					a.logf("state: %s: its names stay held until their key lease ends, unless the next start or template change frees them", owner)
					continue
				}
			}
		}
		if err := a.store.forget(owner); err != nil {
			a.logf("state: forgetting %s: %v", owner, err)
		}
	}
	return nil
}

// releaseHeld frees the names of owner, whose entry e is, with its key: an SRP host's
// (clientsrp.Release) or an RFC 9664 name's (rfc9664.Release).
func (a *agent) releaseHeld(owner string, e savedHost, key *keyrec.LoadedKey) error {
	label, _, _ := dnsname.CutFirstLabel(owner)
	kc := baseclient.KeeperConfig{StopTimeout: a.opts.StopTimeout, Logf: a.opts.Logf}
	if e.Source == sourceNames {
		c := a.nameConfig(e.Registrar)
		c.Label, c.Key = label, key
		return rfc9664.Release(rfc9664.NameConfig{Client: c, Store: a.store.names(e.Registrar), KeeperConfig: kc})
	}
	c := a.srpConfig(e.Registrar)
	c.HostLabel, c.Key = label, key
	return clientsrp.Release(clientsrp.HostConfig{Client: c, Store: a.store.view(e.Source, e.Registrar), KeeperConfig: kc})
}

// key returns owner's signing key in keystore, creating an ECDSA P-256 one if it has none.
// Mirrors call it from their own goroutines.
func (a *agent) key(keystore, owner string) (*keyrec.LoadedKey, error) {
	k, created, err := keyrec.ResolveOrCreateKey(keystore, owner, dns.ECDSAP256SHA256, a.opts.Logger)
	if err != nil {
		return nil, err
	}
	if created {
		a.logf("generated signing key %s", k.Name)
	}
	return k, nil
}

func (a *agent) startHost(r Registrar, h Host) error {
	owner := r.Owner(h.Name)
	key, err := a.key(a.plan.Keystore, owner)
	if err != nil {
		return fmt.Errorf("signing key for %s: %w", owner, err)
	}
	c := a.srpConfig(savedRegistrarOf(r))
	c.HostLabel = h.Name
	c.Key = key
	c.RequestedLease, c.RequestedKeyLease = h.Lease, h.KeyLease
	w, err := clientsrp.StartHost(clientsrp.HostConfig{
		Client:       c,
		Store:        a.store.view(sourceHosts, savedRegistrarOf(r)),
		KeeperConfig: a.keeperConfig(h.KeepNames),
	})
	if err != nil {
		return err
	}
	hr := &hostRun{registrar: r.connection(), host: h, worker: w}
	for _, svc := range h.Services {
		hr.services = append(hr.services, newService(hr, svc))
	}
	a.hosts[owner] = hr
	a.publish(hr)
	for _, s := range hr.services {
		a.probe(s)
	}
	return nil
}

func (a *agent) startName(r Registrar, n Name) error {
	owner := r.Owner(n.Name)
	key, err := a.key(a.plan.Keystore, owner)
	if err != nil {
		return fmt.Errorf("signing key for %s: %w", owner, err)
	}
	c := a.nameConfig(savedRegistrarOf(r))
	c.Label, c.Key = n.Name, key
	c.RequestedLease, c.RequestedKeyLease = n.Lease, n.KeyLease
	w, err := rfc9664.StartName(rfc9664.NameConfig{
		Client:       c,
		Store:        a.store.names(savedRegistrarOf(r)),
		KeeperConfig: a.keeperConfig(n.KeepNames),
	})
	if err != nil {
		return err
	}
	nr := &nameRun{registrar: r.connection(), name: n, worker: w}
	a.names[owner] = nr
	a.publishName(nr)
	return nil
}

func newService(hr *hostRun, svc Service) *serviceRun {
	return &serviceRun{host: hr, svc: svc, up: svc.Probe.Kind == ProbeNone}
}

// addresses returns a host's or name's addresses now: its literal ones, then this machine's
// for auto.
func (a *agent) addresses(auto bool, literal []netip.Addr) []netip.Addr {
	addrs := slices.Clone(literal)
	if auto {
		for _, m := range a.machine {
			if !slices.Contains(addrs, m) {
				addrs = append(addrs, m)
			}
		}
	}
	return addrs
}

// publish hands hr's addresses and the services that are up to its host, if they changed.
func (a *agent) publish(hr *hostRun) {
	addrs := a.addresses(hr.host.Auto, hr.host.Addresses)
	var insts []clientsrp.InstanceConfig
	for _, s := range hr.services {
		if s.up {
			insts = append(insts, s.svc.Instance)
		}
	}
	if hr.set && slices.Equal(addrs, hr.addrs) && reflect.DeepEqual(insts, hr.instances) {
		return
	}
	if len(addrs) == 0 {
		a.logf("%s: no address to register it with", hr.host.Name)
	}
	hr.set, hr.addrs, hr.instances = true, addrs, insts
	hr.worker.Set(addrs, insts)
}

// publishName hands nr's records to its name, its addresses' first, if they changed.
func (a *agent) publishName(nr *nameRun) {
	owner := nr.registrar.Owner(nr.name.Name)
	var records []dns.RR
	for _, addr := range a.addresses(nr.name.Auto, nr.name.Addresses) {
		records = append(records, dnsmsg.AddressRR(owner, addr, 0))
	}
	records = append(records, nr.name.Records...)
	if nr.set && reflect.DeepEqual(records, nr.records) {
		return
	}
	if len(records) == 0 {
		a.logf("%s: no address or record to register it with", owner)
	}
	nr.set, nr.records = true, records
	nr.worker.Set(records)
}

// probe starts probing s, unless it has no probe or one is running.
func (a *agent) probe(s *serviceRun) {
	if s.svc.Probe.Kind == ProbeNone || s.probing || s.gone {
		return
	}
	s.probing = true
	p, addrs, port, timeout := s.svc.Probe, a.addresses(s.host.host.Auto, s.host.host.Addresses), s.svc.Instance.Port, a.opts.ProbeTimeout
	a.probes.Add(1)
	go func() {
		defer a.probes.Done()
		err := probe(a.probeCtx, p, addrs, port, timeout)
		select {
		case a.probed <- probeResult{s: s, err: err}:
		case <-a.probeCtx.Done():
		}
	}()
}

func (a *agent) probeDone(r probeResult) {
	s := r.s
	s.probing = false
	if s.gone {
		return
	}
	name := fmt.Sprintf("%s: %q %s", s.host.host.Name, s.svc.Instance.Label, s.svc.Instance.ServiceType)
	if r.err == nil {
		s.failures = 0
		if !s.up {
			s.up = true
			a.logf("%s: probe %s passes", name, s.svc.Probe)
			a.publish(s.host)
		}
		return
	}
	s.failures++
	switch {
	case s.up && s.failures < a.opts.ProbeFailures:
		a.logf("%s: probe failed (%d of %d before it is withdrawn): %v", name, s.failures, a.opts.ProbeFailures, r.err)
	case s.up:
		s.up = false
		a.logf("%s: probe failed %d times in a row, withdrawing it: %v", name, s.failures, r.err)
		a.publish(s.host)
	case s.failures == 1:
		a.logf("%s: not registered until its probe passes: %v", name, r.err)
	}
}

// poll reads this machine's addresses and the template again, and restarts failed mirrors.
func (a *agent) poll() error {
	if addrs, err := machineAddresses(a.opts.Interfaces); err != nil {
		if msg := err.Error(); msg != a.machineErr {
			a.machineErr = msg
			a.logf("reading this machine's addresses: %v; keeping %v", err, a.machine)
		}
	} else {
		a.machineErr = ""
		if !slices.Equal(addrs, a.machine) {
			a.logf("this machine's addresses are now %v", addrs)
			a.machine = addrs
			for _, hr := range a.hosts {
				if hr.host.Auto {
					a.publish(hr)
				}
			}
			for _, nr := range a.names {
				if nr.name.Auto {
					a.publishName(nr)
				}
			}
		}
	}

	data, err := os.ReadFile(a.path)
	switch {
	case err == nil && bytes.Equal(data, a.seen):
		a.bad = ""
	default:
		var plan *Plan
		if err == nil {
			plan, err = Parse(data, a.path)
		}
		if err != nil {
			if msg := err.Error(); msg != a.bad {
				a.bad = msg
				a.logf("%v\nkeeping the template as it was", err)
			}
			break
		}
		a.seen, a.bad = data, ""
		if err := a.apply(plan); err != nil {
			return err
		}
	}

	for _, r := range a.plan.Registrars {
		for _, m := range r.Mirrors {
			if a.mirrors[m.Type] == nil {
				a.startMirror(r, m)
			}
		}
	}
	return nil
}

// apply moves what runs from a.plan to plan, freeing the names of what plan no longer
// registers (release).
func (a *agent) apply(plan *Plan) error {
	if plan.Keystore != a.plan.Keystore {
		a.logf("template: the keystore changed; deregistering everything, then registering it again")
		a.stopAll()
		if err := a.release(plan); err != nil {
			return err
		}
		return a.start(plan)
	}
	a.stopRemoved(plan)
	var restart []Registrar
	for _, r := range plan.Registrars {
		i := slices.IndexFunc(a.plan.Registrars, r.same)
		switch {
		case i < 0:
			a.logf("template: the %s added", r)
		case !reflect.DeepEqual(a.plan.Registrars[i].connection(), r.connection()):
			a.logf("template: the %s changed; deregistering what it registers, then registering it again", r)
			a.stopWhere(r.same)
		default:
			continue
		}
		restart = append(restart, r)
	}
	a.plan = plan

	for _, r := range plan.Registrars {
		if !slices.ContainsFunc(restart, r.same) {
			if err := a.updateRegistrar(r); err != nil {
				return err
			}
		}
	}
	for t, mr := range a.mirrors {
		r, m, ok := plan.Mirror(t)
		if !ok || !r.same(mr.registrar) || !reflect.DeepEqual(m, mr.mirror) || !slices.Equal(hostNames(r), mr.exclude) {
			a.logf("template: the %s mirror changed; restarting it", t)
			a.stopMirror(t)
		}
	}
	if err := a.release(plan); err != nil {
		return err
	}
	for _, r := range restart {
		if err := a.startRegistrar(r); err != nil {
			return err
		}
	}
	return nil // poll starts the mirrors not running
}

// updateRegistrar moves what r registers to r, whose connection is unchanged.
func (a *agent) updateRegistrar(r Registrar) error {
	for _, h := range r.Hosts {
		owner := r.Owner(h.Name)
		switch hr := a.hosts[owner]; {
		case hr == nil:
			a.logf("template: %s added", owner)
		case hr.host.Lifetime == h.Lifetime:
			a.updateHost(hr, h)
			continue
		default:
			// Its client and Host take the lifetime when they start.
			a.logf("template: %s's lease, key_lease or on_stop changed; deregistering it, then registering it again", owner)
			stop([]*hostRun{hr}, nil)
			delete(a.hosts, owner)
		}
		if err := a.startHost(r, h); err != nil {
			return err
		}
	}
	for _, n := range r.Names {
		owner := r.Owner(n.Name)
		switch nr := a.names[owner]; {
		case nr == nil:
			a.logf("template: %s added", owner)
		case nr.name.Lifetime == n.Lifetime:
			if !reflect.DeepEqual(nr.name, n) {
				a.logf("template: %s changed", owner)
				nr.name = n
				a.publishName(nr)
			}
			continue
		default:
			a.logf("template: %s's lease, key_lease or on_stop changed; deregistering it, then registering it again", owner)
			stop(nil, []*nameRun{nr})
			delete(a.names, owner)
		}
		if err := a.startName(r, n); err != nil {
			return err
		}
	}
	return nil
}

// stopRemoved stops the hosts and names plan no longer has, before anything else in plan is
// applied; release then frees their names, whatever their on_stop says.
func (a *agent) stopRemoved(plan *Plan) {
	owners := map[string]bool{}
	for _, r := range plan.Registrars {
		for _, h := range r.Hosts {
			owners[r.Owner(h.Name)] = true
		}
		for _, n := range r.Names {
			owners[r.Owner(n.Name)] = true
		}
	}
	var hosts []*hostRun
	for owner, hr := range a.hosts {
		if !owners[owner] {
			a.logf("template: %s removed; freeing its names", owner)
			hosts = append(hosts, hr)
			delete(a.hosts, owner)
		}
	}
	var names []*nameRun
	for owner, nr := range a.names {
		if !owners[owner] {
			a.logf("template: %s removed; freeing it", owner)
			names = append(names, nr)
			delete(a.names, owner)
		}
	}
	stop(hosts, names)
}

// updateHost moves hr to h, the same host in a new template. A service whose port and probe
// are unchanged keeps its probes' state; any other starts over, registered once a probe
// passes.
func (a *agent) updateHost(hr *hostRun, h Host) {
	if reflect.DeepEqual(hr.host, h) {
		return
	}
	a.logf("template: %s changed", hr.registrar.Owner(h.Name))
	key := func(s Service) string {
		return dnsname.Fold(s.Instance.Label) + "\x00" + dnsname.Fold(s.Instance.ServiceType)
	}
	old := map[string]*serviceRun{}
	for _, s := range hr.services {
		old[key(s.svc)] = s
	}
	hr.host = h
	var services, added []*serviceRun
	for _, svc := range h.Services {
		s := old[key(svc)]
		delete(old, key(svc))
		if s != nil && s.svc.Instance.Port == svc.Instance.Port && s.svc.Probe == svc.Probe {
			s.svc = svc
		} else {
			if s != nil {
				s.gone = true
			}
			s = newService(hr, svc)
			added = append(added, s)
		}
		services = append(services, s)
	}
	for _, s := range old {
		s.gone = true
	}
	hr.services = services
	a.publish(hr)
	for _, s := range added {
		a.probe(s)
	}
}

// hostNames returns the labels of r's hosts.
func hostNames(r Registrar) []string {
	names := make([]string, len(r.Hosts))
	for i, h := range r.Hosts {
		names[i] = h.Name
	}
	return names
}

// startMirror starts m, a complex type that makes its own hosts, registered through r.
func (a *agent) startMirror(r Registrar, m Mirror) {
	if m.Type != "mdns" {
		panic(fmt.Sprintf("agent: a mirror of type %q passed validation", m.Type))
	}
	keystore := a.plan.Keystore
	ctx, cancel := context.WithCancel(context.Background())
	mr := &mirrorRun{registrar: r.connection(), mirror: m, exclude: hostNames(r), started: time.Now(), cancel: cancel, done: make(chan struct{})}
	srp := a.srpConfig(savedRegistrarOf(r))
	srp.RequestedLease, srp.RequestedKeyLease = r.Lease, r.KeyLease
	cfg := mdnsbridge.Config{
		Source:       a.opts.MirrorSource(m.Socket),
		ServiceTypes: m.ServiceTypes,
		Hosts:        m.Hosts,
		AllHosts:     m.AllHosts,
		SRP:          srp,
		Key:          func(owner string) (*keyrec.LoadedKey, error) { return a.key(keystore, owner) },
		Store:        a.store.view(m.Type, savedRegistrarOf(r)),
		Exclude:      mr.exclude,
		Settle:       a.opts.Settle,
		StopTimeout:  a.opts.StopTimeout,
		KeepNames:    r.KeepNames,
		Logf:         func(format string, args ...any) { a.opts.Logf(m.Type+" mirror: "+format, args...) },
	}
	if a.mirrorFailed[m.Type] == "" {
		a.logf("%s mirror: mirroring what the daemon at %s sees", m.Type, m.Socket)
	}
	a.mirrors[m.Type] = mr
	go func() {
		defer close(mr.done)
		err := mdnsbridge.Run(ctx, cfg)
		if ctx.Err() != nil {
			return
		}
		select {
		case a.mirrorEnded <- mirrorEnd{m: mr, err: err}:
		case <-ctx.Done():
		}
	}()
}

// mirrorStopped records a mirror that stopped on its own: poll starts it again. A failure
// like the last is logged again only once the mirror ran for a poll interval in between.
func (a *agent) mirrorStopped(e mirrorEnd) {
	t := e.m.mirror.Type
	if a.mirrors[t] != e.m {
		return
	}
	<-e.m.done
	delete(a.mirrors, t)
	msg := e.err.Error()
	if msg != a.mirrorFailed[t] || time.Since(e.m.started) >= a.opts.PollInterval {
		a.logf("%s mirror: stopped: %v; starting it again every %s", t, e.err, a.opts.PollInterval)
	}
	a.mirrorFailed[t] = msg
}

func (a *agent) stopMirror(t string) {
	mr := a.mirrors[t]
	mr.cancel()
	<-mr.done
	delete(a.mirrors, t)
	delete(a.mirrorFailed, t)
}

// stopAll deregisters everything, keeping the names each host's and name's on_stop keeps:
// every host, every name, and every mirror's hosts.
func (a *agent) stopAll() { a.stopWhere(func(Registrar) bool { return true }) }

// stopWhere deregisters what registers through the registrars in selects, keeping the names
// each host's and name's on_stop keeps: hosts, names and mirrors' hosts.
func (a *agent) stopWhere(in func(Registrar) bool) {
	var mirrors []string
	for t, mr := range a.mirrors {
		if in(mr.registrar) {
			mr.cancel()
			mirrors = append(mirrors, t)
		}
	}
	var hosts []*hostRun
	for owner, hr := range a.hosts {
		if in(hr.registrar) {
			hosts = append(hosts, hr)
			delete(a.hosts, owner)
		}
	}
	var names []*nameRun
	for owner, nr := range a.names {
		if in(nr.registrar) {
			names = append(names, nr)
			delete(a.names, owner)
		}
	}
	stop(hosts, names)
	for _, t := range mirrors {
		a.stopMirror(t)
	}
}

// stop deregisters hosts and names, all at once, keeping the names each one's on_stop keeps.
func stop(hosts []*hostRun, names []*nameRun) {
	var workers []interface {
		Stop()
		Wait()
	}
	for _, hr := range hosts {
		for _, s := range hr.services {
			s.gone = true
		}
		workers = append(workers, hr.worker)
	}
	for _, nr := range names {
		workers = append(workers, nr.worker)
	}
	for _, w := range workers {
		w.Stop()
	}
	for _, w := range workers {
		w.Wait()
	}
}
