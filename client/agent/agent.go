package agent

import (
	"bytes"
	"context"
	"fmt"
	"maps"
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
	// A probed service is probed every ProbeInterval (default 30s), each attempt trying all
	// its addresses at once for at most ProbeTimeout (5s), and withdrawn after ProbeFailures
	// (3) failures in a row. It is registered once a probe passes.
	ProbeInterval time.Duration
	ProbeTimeout  time.Duration
	ProbeFailures int
	// Settle and StopTimeout are each host's and name's (client.KeeperConfig).
	Settle      time.Duration
	StopTimeout time.Duration
	// Interfaces returns this machine's addresses, for addresses: [auto]; default
	// InterfaceAddresses. Only publishable ones are used (clientsrp.PublishableAddresses).
	Interfaces func() ([]netip.Addr, error)
	// Send, Query and Sleep are every SRP client's (clientsrp.Config), Send and Sleep every
	// RFC 9664 client's too (rfc9664.Config); nil: the clients' own. Query also asks what a
	// name that follows a community asks the resolvers (watchIPFS); nil: the registrar's
	// resolvers (clientsrp.LiveDNSQuery).
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

// InterfaceAddresses returns the addresses of every interface of this machine, but for the IPv6
// ones not to publish, as mDNSResponder's SRP client leaves them out on macOS: temporary
// addresses (RFC 8981), there so that the machine's connections cannot be linked to it, and
// those not usable, yet or at all (tentative, duplicate, detached), or anycast. Linux and macOS
// tell them apart (unpublishedIPv6); elsewhere every address is returned.
func InterfaceAddresses() ([]netip.Addr, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	unpublished, done, err := unpublishedIPv6()
	if err != nil {
		return nil, fmt.Errorf("reading the IPv6 addresses' flags: %w", err)
	}
	defer done()
	var out []netip.Addr
	for _, ifi := range ifis {
		ifAddrs, err := ifi.Addrs()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ifi.Name, err)
		}
		for _, a := range ifAddrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			if ip = ip.Unmap(); ip.Is6() && ip.IsGlobalUnicast() {
				skip, err := unpublished(ifi, ip)
				if err != nil {
					return nil, fmt.Errorf("%s on %s: %w", ip, ifi.Name, err)
				}
				if skip {
					continue
				}
			}
			out = append(out, ip)
		}
	}
	return out, nil
}

// Run keeps what the template at path describes registered until ctx ends, then deregisters
// it all and returns ctx's error. It reads the template again every PollInterval: a valid
// change is applied, an invalid one logged while the agent keeps what it runs. Run returns
// early only for what it cannot go on without: a first template that is invalid, a keystore
// it cannot use, a state file edited by hand, a host or name its client refuses. A template's
// warnings (Plan.Warnings) are logged, at the start and with each change.
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
		ipfsReports:  make(chan ipfsReport),
	}
	defer func() {
		cancelProbes()
		a.end()
		a.probes.Wait()
	}()
	a.warn(plan)
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
		case r := <-a.ipfsReports:
			r.deliver(r.w, r.state)
		case <-probes.C:
			for _, hr := range a.hosts {
				for _, s := range hr.services {
					a.probe(s)
				}
			}
			for _, nr := range a.names {
				for _, s := range nr.services {
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
	ipfsReports chan ipfsReport
}

// hostRun is one template host and what was last asked of its clientsrp.Host.
type hostRun struct {
	registrar Registrar // its registrar's connection (Registrar.connection)
	host      Host
	key       *dns.KEY // its signing key's, which the registrar puts at its names
	worker    *clientsrp.Host
	services  []*serviceRun
	set       bool
	addrs     []netip.Addr
	instances []clientsrp.InstanceConfig
}

// nameRun is one template name and what was last asked of its rfc9664.Name.
type nameRun struct {
	registrar   Registrar // its registrar's connection (Registrar.connection)
	name        Name
	worker      *rfc9664.Name
	services    []*serviceRun
	ipfs        *ipfsWatch // with name.IPFS
	ipfsRecords []dns.RR   // what its node gives it, as last reported
	set         bool
	records     []dns.RR
}

// holder is what services run on: a host or a name.
type holder interface {
	label() string                   // what its log lines start with
	addresses(a *agent) []netip.Addr // now: its services are probed there
	publish(a *agent)                // hands what is registered now to its worker, if it changed
	registrarOf() Registrar          // its registrar's connection
}

// serviceRun is one service and its probes.
type serviceRun struct {
	on       holder
	svc      Service
	up       bool // no probe, or the last one passed and not ProbeFailures failed since
	failures int  // in a row
	probing  bool
	gone     bool // no longer in the template; a probe still running is ignored
	// A name's service with a TLSA: the record its certificate gives, nil while the certificate
	// cannot be read (readCertificate), and the last such error, logged once.
	tlsa    *dns.TLSA
	tlsaErr string
	// A host's service with ipfs: its node's watch; the folder its TXT record gives, "" until
	// the node gives one; and the swarm key its swarm-mac= is made with, nil until read.
	ipfs  *ipfsWatch
	site  string
	swarm swarmKey
}

// registered reports whether s is registered: up, with a TLSA its certificate read, and with
// ipfs: its folder and its swarm key read.
func (s *serviceRun) registered() bool {
	return s.up && (s.svc.TLSA == "" || s.tlsa != nil) && (s.svc.IPFS == nil || (s.site != "" && s.swarm != nil))
}

// instance returns s's instance as registered now by a host whose KEY is key: with ipfs:, its
// TXT record gives its node's folder, and the swarm-mac= of key and the folder.
func (s *serviceRun) instance(key *dns.KEY) clientsrp.InstanceConfig {
	in := s.svc.Instance
	if s.svc.IPFS != nil {
		in.TXT = append(slices.Clone(in.TXT),
			dnsmsg.EscapeTXT("dnslink=/ipfs/"+s.site),
			dnsmsg.EscapeTXT(swarmMACKey+"="+s.swarm.mac(key, s.site)))
	}
	return in
}

// drop marks s gone, no longer registered by the template, and stops watching its node.
func (s *serviceRun) drop() {
	s.gone = true
	if s.ipfs != nil {
		s.ipfs.stop()
		s.ipfs = nil
	}
}

func (s *serviceRun) String() string { return s.on.label() + ": " + s.svc.String() }

type probeResult struct {
	s   *serviceRun
	err error
}

type mirrorRun struct {
	registrar Registrar // its registrar's connection (Registrar.connection)
	mirror    Mirror
	exclude   []string
	started   time.Time
	cancel    context.CancelCauseFunc // mdnsbridge.ErrRestart: its hosts keep their names
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
		a.logf("registering names through %s over %s", r.Server, r.Transport)
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
		Network:       r.Transport,
		Send:          a.opts.Send,
		Query:         a.resolverQuery(r.Resolvers),
		Sleep:         a.opts.Sleep,
	}
}

// resolverQuery is how the agent asks a registrar's resolvers, given in its template (nil:
// client/srp's default ones): an SRP client, for discovery and KEY lookups, and a name that
// follows a community, for the names of members its registrar does not serve.
func (a *agent) resolverQuery(resolvers []string) clientsrp.DNSQuery {
	if a.opts.Query != nil {
		return a.opts.Query
	}
	return clientsrp.LiveDNSQuery(resolvers)
}

// nameConfig is every RFC 9664 client's configuration for registering through r, before a
// name's name, key and leases.
func (a *agent) nameConfig(r savedRegistrar) rfc9664.Config {
	return rfc9664.Config{
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
// agent ran or not, hosts a mirror no longer selects, hosts registered in another domain, and
// hosts and names registered through another registrar or from another keystore. Any of them
// still running has been stopped first. A release that fails is logged, and tried again at
// the next start or template change; until then, the names stay held until their key lease
// ends.
func (a *agent) release(plan *Plan) error {
	for _, owner := range a.store.unwanted(plan) {
		e, _ := a.store.entry(owner)
		if e.Held {
			a.logf("state: %s holds names the template no longer registers; freeing them", owner)
			if key := a.heldKey(owner); key != nil {
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

// heldKey returns owner's key, to free the names it holds; nil, logged, if it cannot be loaded.
func (a *agent) heldKey(owner string) *keyrec.LoadedKey {
	key, _, err := keyrec.ResolveOrCreateKey(a.store.keystore, owner, 0, a.opts.Logger)
	if err != nil {
		a.logf("state: %s: %v; its names stay held until their key lease ends", owner, err)
		return nil
	}
	return key
}

// releaseHeld frees the names of owner, whose entry e is, with its key: an SRP host's
// (clientsrp.Release) or an RFC 9664 name's (rfc9664.Release).
func (a *agent) releaseHeld(owner string, e savedHost, key *keyrec.LoadedKey) error {
	kc := baseclient.KeeperConfig{StopTimeout: a.opts.StopTimeout, Logf: a.opts.Logf}
	if e.Source == sourceNames {
		c := a.nameConfig(e.Registrar)
		c.Name, c.Key = owner, key
		return rfc9664.Release(rfc9664.NameConfig{Client: c, Store: a.store.names(e.Registrar), KeeperConfig: kc})
	}
	label, _, _ := dnsname.CutFirstLabel(owner)
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
	hr := &hostRun{registrar: r.connection(), host: h, key: key.PublicKey, worker: w}
	for _, svc := range h.Services {
		hr.services = append(hr.services, newService(hr, svc))
	}
	a.hosts[owner] = hr
	hr.publish(a)
	a.startServices(hr, hr.services)
	return nil
}

func (a *agent) startName(r Registrar, n Name) error {
	owner := n.Name
	key, err := a.key(a.plan.Keystore, owner)
	if err != nil {
		return fmt.Errorf("signing key for %s: %w", owner, err)
	}
	c := a.nameConfig(savedRegistrarOf(r))
	c.Name, c.Key = owner, key
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
	for _, svc := range n.Services {
		nr.services = append(nr.services, newService(nr, svc))
	}
	if n.IPFS != nil {
		a.watchName(nr)
	}
	a.names[owner] = nr
	a.readCertificates(nr)
	nr.publish(a)
	a.startServices(nr, nr.services)
	return nil
}

func newService(on holder, svc Service) *serviceRun {
	return &serviceRun{on: on, svc: svc, up: svc.Probe.Kind == ProbeNone}
}

// startServices starts watching the node of each of services, of on, that has ipfs:, and
// probing each of them.
func (a *agent) startServices(on holder, services []*serviceRun) {
	for _, s := range services {
		if s.svc.IPFS != nil {
			a.watchService(s, on.registrarOf())
		}
		a.probe(s)
	}
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

func (hr *hostRun) label() string { return hr.host.Name }

func (hr *hostRun) registrarOf() Registrar { return hr.registrar }

func (hr *hostRun) addresses(a *agent) []netip.Addr {
	return a.addresses(hr.host.Auto, hr.host.Addresses)
}

// publish hands hr's addresses and the services registered now to its host, if they changed.
func (hr *hostRun) publish(a *agent) {
	addrs := hr.addresses(a)
	var insts []clientsrp.InstanceConfig
	for _, s := range hr.services {
		if s.registered() {
			insts = append(insts, s.instance(hr.key))
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

func (nr *nameRun) label() string { return nr.name.Name }

func (nr *nameRun) registrarOf() Registrar { return nr.registrar }

func (nr *nameRun) addresses(a *agent) []netip.Addr {
	return a.addresses(nr.name.Auto, nr.name.Addresses)
}

// publish hands nr's records to its name, if they changed: its addresses', its own, those of
// each service registered now, then those its node gives it. A name with ipfs: waits for its
// node's first report.
func (nr *nameRun) publish(a *agent) {
	if nr.ipfs != nil && !nr.ipfs.reported {
		return
	}
	owner := nr.label()
	records := slices.Clone(nr.name.Records)
	for _, s := range nr.services {
		if s.registered() {
			records = append(records, s.svc.SRV(owner)...)
			if s.tlsa != nil {
				records = append(records, s.tlsa)
			}
		}
	}
	records = append(records, nr.ipfsRecords...)
	records = rfc9664.WithAddresses(owner, nr.addresses(a), records)
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
	p, addrs, port, timeout := s.svc.Probe, s.on.addresses(a), s.svc.Instance.Port, a.opts.ProbeTimeout
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
	if r.err == nil {
		s.failures = 0
		if !s.up {
			s.up = true
			a.logf("%s: probe %s passes", s, s.svc.Probe)
			s.on.publish(a)
		}
		return
	}
	s.failures++
	switch {
	case s.up && s.failures < a.opts.ProbeFailures:
		a.logf("%s: probe failed (%d of %d before it is withdrawn): %v", s, s.failures, a.opts.ProbeFailures, r.err)
	case s.up:
		s.up = false
		a.logf("%s: probe failed %d times in a row, withdrawing it: %v", s, s.failures, r.err)
		s.on.publish(a)
	case s.failures == 1:
		a.logf("%s: not registered until its probe passes: %v", s, r.err)
	}
}

// readCertificates reads again the certificate of each of nr's services with a TLSA, and
// reports whether any service's TLSA record changed. A certificate that cannot be read leaves
// its service unregistered until it can: a client checking the service through DANE would
// refuse it, the TLSA record left behind matching the key the service no longer has, and the
// SRV records alone would let others reach it without the check asked for.
func (a *agent) readCertificates(nr *nameRun) (changed bool) {
	for _, s := range nr.services {
		var rr *dns.TLSA
		var err error
		if s.svc.TLSA != "" {
			rr, err = TLSARecord(s.svc.TLSAOwner(nr.label()), s.svc.TLSA)
		}
		switch {
		case err != nil:
			if msg := err.Error(); msg != s.tlsaErr {
				s.tlsaErr = msg
				a.logf("%s: %v; not registered until it can be read", s, err)
			}
		case s.tlsaErr != "":
			s.tlsaErr = ""
			a.logf("%s: certificate %s read", s, s.svc.TLSA)
		case s.tlsa != nil && rr != nil && s.tlsa.Certificate != rr.Certificate:
			a.logf("%s: certificate %s has a new key; its TLSA record follows", s, s.svc.TLSA)
		}
		if !reflect.DeepEqual(rr, s.tlsa) {
			s.tlsa, changed = rr, true
		}
	}
	return changed
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
					hr.publish(a)
				}
			}
			for _, nr := range a.names {
				if nr.name.Auto {
					nr.publish(a)
				}
			}
		}
	}
	for _, nr := range a.names {
		if a.readCertificates(nr) {
			nr.publish(a)
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
		a.warn(plan)
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

// warn logs plan's warnings, when the agent starts and when the template changes.
func (a *agent) warn(plan *Plan) {
	for _, w := range plan.Warnings {
		a.logf("template: %s", w)
	}
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
			a.logf("template: the %s changed; deregistering what it registers, keeping the names, then registering it again", r)
			a.stopWhere(r.same, true)
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
			a.stopMirror(t, mdnsbridge.ErrRestart)
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
			a.logf("template: %s's lease, key_lease or on_stop changed; deregistering it, keeping its names, then registering it again", owner)
			stop([]*hostRun{hr}, nil, true)
			delete(a.hosts, owner)
		}
		if err := a.startHost(r, h); err != nil {
			return err
		}
	}
	for _, n := range r.Names {
		owner := n.Name
		switch nr := a.names[owner]; {
		case nr == nil:
			a.logf("template: %s added", owner)
		case nr.name.Lifetime == n.Lifetime:
			a.updateName(nr, n)
			continue
		default:
			a.logf("template: %s's lease, key_lease or on_stop changed; deregistering it, keeping it, then registering it again", owner)
			stop(nil, []*nameRun{nr}, true)
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
	nameRegistrars := map[string]Registrar{} // an RFC 9664 name's, which can move between proxies
	for _, r := range plan.Registrars {
		for _, h := range r.Hosts {
			owners[r.Owner(h.Name)] = true
		}
		for _, n := range r.Names {
			nameRegistrars[n.Name] = r
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
		switch r, ok := nameRegistrars[owner]; {
		case !ok:
			a.logf("template: %s removed; freeing it", owner)
		case !r.same(nr.registrar):
			a.logf("template: %s moved to the %s; freeing it at the %s", owner, r, nr.registrar)
		default:
			continue
		}
		names = append(names, nr)
		delete(a.names, owner)
	}
	stop(hosts, names, false)
}

// updateHost moves hr to h, the same host in a new template (moveServices).
func (a *agent) updateHost(hr *hostRun, h Host) {
	if reflect.DeepEqual(hr.host, h) {
		return
	}
	a.logf("template: %s changed", hr.registrar.Owner(h.Name))
	hr.host = h
	var added []*serviceRun
	hr.services, added = moveServices(hr, hr.services, h.Services)
	hr.publish(a)
	a.startServices(hr, added)
}

// updateName moves nr to n, the same name with the same lifetime in a new template
// (moveServices), its certificates read again. Its node is watched again if its ipfs:
// changed; until the new watch's first report, the name keeps what it registers.
func (a *agent) updateName(nr *nameRun, n Name) {
	if reflect.DeepEqual(nr.name, n) {
		return
	}
	a.logf("template: %s changed", nr.label())
	ipfsChanged := !reflect.DeepEqual(nr.name.IPFS, n.IPFS)
	nr.name = n
	if ipfsChanged {
		if nr.ipfs != nil {
			nr.ipfs.stop()
			nr.ipfs = nil
		}
		if n.IPFS != nil {
			a.watchName(nr)
		} else {
			nr.ipfsRecords = nil
		}
	}
	var added []*serviceRun
	nr.services, added = moveServices(nr, nr.services, n.Services)
	a.readCertificates(nr)
	nr.publish(a)
	a.startServices(nr, added)
}

// moveServices returns the services svcs of on, a host or name in a new template, from those
// running, and those of them added, to be started (startServices). One whose instance name,
// service type, port, probe and ipfs: are unchanged keeps its probes' and its node's state;
// any other starts over, registered once a probe passes. The others are dropped.
func moveServices(on holder, running []*serviceRun, svcs []Service) (services, added []*serviceRun) {
	key := func(s Service) string {
		return dnsname.Fold(s.Instance.Label) + "\x00" + dnsname.Fold(s.Instance.ServiceType)
	}
	old := map[string]*serviceRun{}
	for _, s := range running {
		old[key(s.svc)] = s
	}
	for _, svc := range svcs {
		s := old[key(svc)]
		delete(old, key(svc))
		if s != nil && s.svc.Instance.Port == svc.Instance.Port && s.svc.Probe == svc.Probe && reflect.DeepEqual(s.svc.IPFS, svc.IPFS) {
			s.svc = svc
		} else {
			if s != nil {
				s.drop()
			}
			s = newService(on, svc)
			added = append(added, s)
		}
		services = append(services, s)
	}
	for _, s := range old {
		s.drop()
	}
	return services, added
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
	ctx, cancel := context.WithCancelCause(context.Background())
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

// stopMirror stops the mirror of type t, ending its ctx with cause (mdnsbridge.ErrRestart, or
// nil).
func (a *agent) stopMirror(t string, cause error) {
	mr := a.mirrors[t]
	mr.cancel(cause)
	<-mr.done
	delete(a.mirrors, t)
	delete(a.mirrorFailed, t)
}

// end stops everything as the agent stops, keeping the names each host's and name's on_stop
// keeps (stopAll). Then it frees the names the state file still records as held for a host
// or name the template registers whose on_stop is release: kept while the agent ran by one
// not registered as it stopped, such as the hosts of a mirror that stopped on its own
// (mdnsbridge.Run), or held from an earlier run by one this run never registered.
func (a *agent) end() {
	if a.store == nil {
		return // start failed before anything ran
	}
	a.stopAll()
	entries := a.store.entries()
	for _, owner := range slices.Sorted(maps.Keys(entries)) {
		e := entries[owner]
		if l, ok := wanted(a.plan, a.store.keystore, owner, e); !ok || l.KeepNames || !e.Held {
			continue
		}
		a.logf("state: %s still holds names; freeing them (on_stop: release)", owner)
		if key := a.heldKey(owner); key != nil {
			if err := a.releaseHeld(owner, e, key); err != nil {
				a.logf("state: %s: %v; its names stay held until their key lease ends", owner, err)
			}
		}
	}
}

// stopAll deregisters everything, keeping the names each host's and name's on_stop keeps:
// every host, every name, and every mirror's hosts.
func (a *agent) stopAll() { a.stopWhere(func(Registrar) bool { return true }, false) }

// stopWhere deregisters what registers through the registrars in selects: hosts, names and
// mirrors' hosts. They keep their names if restart, as they are to be registered again, and
// otherwise as each one's on_stop says.
func (a *agent) stopWhere(in func(Registrar) bool, restart bool) {
	var cause error
	if restart {
		cause = mdnsbridge.ErrRestart
	}
	var mirrors []string
	for t, mr := range a.mirrors {
		if in(mr.registrar) {
			mr.cancel(cause)
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
	stop(hosts, names, restart)
	for _, t := range mirrors {
		a.stopMirror(t, cause)
	}
}

// stop deregisters hosts and names, all at once, keeping their names if restart, as they are
// to be registered again, and otherwise as each one's on_stop says.
func stop(hosts []*hostRun, names []*nameRun, restart bool) {
	var workers []interface {
		Stop()
		StopKeepingNames()
		Wait()
	}
	for _, hr := range hosts {
		for _, s := range hr.services {
			s.drop()
		}
		workers = append(workers, hr.worker)
	}
	for _, nr := range names {
		for _, s := range nr.services {
			s.drop()
		}
		if nr.ipfs != nil {
			nr.ipfs.stop()
		}
		workers = append(workers, nr.worker)
	}
	for _, w := range workers {
		if restart {
			w.StopKeepingNames()
		} else {
			w.Stop()
		}
	}
	for _, w := range workers {
		w.Wait()
	}
}
