// Package main implements sig0lease-srp-client, a thin CLI over client/srp -- a dev/test tool,
// not a shipped product. The library is the deliverable; this just exercises it. With -mdns it
// runs client/mdnsbridge instead, registering what the local mDNSResponder sees.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client/mdnsbridge"
	"github.com/NetworkCommons/sig0lease/client/mdnsresponder"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/logging"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat" // registers EDNS0 code 2 (UPDATE-LEASE); matches cmd/sig0lease/main.go and cmd/sig0lease-client/main.go's own convention (client/srp also self-registers this, so it's redundant here, not load-bearing)
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	pkgsrp "github.com/NetworkCommons/sig0lease/pkg/srp"
)

// repeatableFlag collects every occurrence of a flag.Value flag, in order.
type repeatableFlag []string

func (r *repeatableFlag) String() string     { return strings.Join(*r, ",") }
func (r *repeatableFlag) Set(v string) error { *r = append(*r, v); return nil }

func main() {
	domain := flag.String("domain", "", "registration domain (required)")
	host := flag.String("host", "", "base host label, e.g. \"myhost\" (required)")
	server := flag.String("server", "", "explicit registrar \"host:port\"; empty triggers _dnssd-srp._tcp discovery (_dnssd-srp-tls._tcp with -tls)")
	discovery := flag.String("discovery", "closest", `where discovery looks for the registrar's SRV: "closest" (the domain, then each parent up to its zone apex) or "apex" (the zone apex only, as RFC 9665 S3.1.1 specifies)`)
	lease := flag.Uint("lease", 3600, "requested LEASE seconds")
	keylease := flag.Uint("keylease", 1209600, "requested KEY-LEASE seconds")
	ttl := flag.Uint("ttl", 300, "TTL seconds suggested for every registered record, KEYs included; independent of the leases, and the registrar may override it")
	udp := flag.Bool("udp", false, "use UDP instead of TCP (SRP requires TCP by default, S3.5)")
	useTLS := flag.Bool("tls", false, "use DNS-over-TLS (RFC 7858, opportunistic: the registrar's certificate is not checked) instead of TCP; discovery then looks for _dnssd-srp-tls._tcp")
	once := flag.Bool("once", false, "send exactly one registration and exit, instead of running the full refresh lifecycle")
	deregister := flag.Bool("deregister", false, "send exactly one Deregister (withdraw host + every -instance) and exit, instead of registering; implies -once")
	keystoreDir := flag.String("keystore", "", "directory to load this identity's signing key from; falls back to CLIENT_KEYSTORE_DIR if unset")
	keyAlg := flag.Uint("k", 0, "DNSSEC algorithm (13=ECDSAP256SHA256, 15=ED25519) to generate a NEW signing key with if none exists yet; omit to require an existing key")
	maxRenames := flag.Int("max-renames", 5, "rename-retry attempts on YXDOMAIN before giving up")

	mdns := flag.Bool("mdns", false, "mirror the services the local mDNSResponder sees, one SRP host per mDNS host, instead of registering -host")
	mdnsSocket := flag.String("mdns-socket", mdnsresponder.DefaultSocketPath(), "the mDNSResponder daemon's client socket (with -mdns)")
	mdnsAllHosts := flag.Bool("mdns-all-hosts", false, "with -mdns, mirror every host on the link instead of the -mdns-host ones")
	mdnsList := flag.Bool("mdns-list", false, "with -mdns, only print what the daemon sees, marking with * what would be mirrored; registers nothing")

	var addrs, instances, removes, txts, subtypes, resolvers, mdnsHosts, mdnsTypes repeatableFlag
	flag.Var(&addrs, "addr", "host A/AAAA address to publish (repeatable)")
	flag.Var(&resolvers, "resolver", "resolver \"host:port\" for every discovery lookup -- zone apex SOA, registrar SRV, registrar address (repeatable); default 8.8.8.8:53, 8.8.4.4:53")
	flag.Var(&instances, "instance", `service instance "Label:_svctype._proto:port" (repeatable)`)
	flag.Var(&removes, "remove", `service instance "Label:_svctype._proto" to withdraw in this update (repeatable)`)
	flag.Var(&txts, "txt", `TXT string for a declared instance, "Label:content" (repeatable)`)
	flag.Var(&subtypes, "subtype", `DNS-SD subtype for a declared instance, "Label:subtypelabel" (repeatable)`)
	flag.Var(&mdnsHosts, "mdns-host", `with -mdns, an mDNS host to mirror, e.g. "mymac.local." (repeatable)`)
	flag.Var(&mdnsTypes, "mdns-type", `with -mdns, a service type to mirror, e.g. "_ssh._tcp" (repeatable; default every type the daemon enumerates)`)

	flag.Usage = printUsage
	flag.Parse()

	if *mdns {
		var conflicting []string
		flag.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "host", "addr", "instance", "remove", "txt", "subtype", "once", "deregister":
				conflicting = append(conflicting, "-"+f.Name)
			}
		})
		if len(conflicting) > 0 {
			fmt.Fprintf(os.Stderr, "ERROR: -mdns takes hosts and instances from mDNSResponder; drop %s\n", strings.Join(conflicting, " "))
			os.Exit(1)
		}
	} else if *mdnsList || *mdnsAllHosts || len(mdnsHosts) > 0 || len(mdnsTypes) > 0 {
		fmt.Fprintln(os.Stderr, "ERROR: -mdns-host, -mdns-type, -mdns-all-hosts and -mdns-list need -mdns")
		os.Exit(1)
	}

	if *mdns && *mdnsList {
		// Nothing is registered, so no registrar, domain or keystore is needed.
		runBridge(mdnsbridge.Config{
			Source:       mdnsbridge.DaemonSource(*mdnsSocket),
			ServiceTypes: []string(mdnsTypes),
			Hosts:        []string(mdnsHosts),
			AllHosts:     *mdnsAllHosts,
			List:         true,
		}, *mdnsSocket)
		return
	}

	if *mdns && *domain == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -domain is required")
		printUsage()
		os.Exit(1)
	}
	if !*mdns && (*domain == "" || *host == "") {
		fmt.Fprintln(os.Stderr, "ERROR: -domain and -host are required")
		printUsage()
		os.Exit(1)
	}
	if *ttl == 0 {
		// client/srp reads a zero TTL as "unset" and would send its default instead.
		fmt.Fprintln(os.Stderr, "ERROR: -ttl must be at least 1")
		os.Exit(1)
	}

	network := clientsrp.NetworkTCP
	switch {
	case *udp && *useTLS:
		fmt.Fprintln(os.Stderr, "ERROR: -udp and -tls are mutually exclusive")
		os.Exit(1)
	case *udp:
		network = clientsrp.NetworkUDP
	case *useTLS:
		network = clientsrp.NetworkTLS
	}

	var discoveryMode clientsrp.DiscoveryMode
	switch *discovery {
	case "closest":
		discoveryMode = clientsrp.DiscoveryClosest
	case "apex":
		discoveryMode = clientsrp.DiscoveryApexOnly
	default:
		fmt.Fprintf(os.Stderr, "ERROR: invalid -discovery %q, want \"closest\" or \"apex\"\n", *discovery)
		os.Exit(1)
	}

	if *mdns {
		if !*mdnsAllHosts && len(mdnsHosts) == 0 {
			fmt.Fprintln(os.Stderr, "ERROR: -mdns needs -mdns-host (repeatable) or -mdns-all-hosts; -mdns-list shows the hosts on the link")
			os.Exit(1)
		}
		dir := resolveKeystoreDir(*keystoreDir)
		runBridge(mdnsbridge.Config{
			Source:       mdnsbridge.DaemonSource(*mdnsSocket),
			ServiceTypes: []string(mdnsTypes),
			Hosts:        []string(mdnsHosts),
			AllHosts:     *mdnsAllHosts,
			SRP: clientsrp.Config{
				Domain:            *domain,
				RequestedLease:    uint32(*lease),
				RequestedKeyLease: uint32(*keylease),
				TTL:               uint32(*ttl),
				RegistrarAddr:     *server,
				Discovery:         discoveryMode,
				Resolvers:         []string(resolvers),
				Network:           network,
				MaxRenames:        *maxRenames,
			},
			Key: func(owner string) (*keyrec.LoadedKey, error) {
				return resolveKeyFor(dir, owner, uint8(*keyAlg))
			},
		}, *mdnsSocket)
		return
	}

	var parsedAddrs []netip.Addr
	for _, a := range addrs {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: invalid -addr %q: %v\n", a, err)
			os.Exit(1)
		}
		parsedAddrs = append(parsedAddrs, addr)
	}

	instCfgs, err := parseInstances(instances, removes, txts, subtypes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	dir := resolveKeystoreDir(*keystoreDir)
	key, err := resolveKey(dir, *host, *domain, uint8(*keyAlg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	cfg := clientsrp.Config{
		Domain:            *domain,
		HostLabel:         *host,
		Addresses:         parsedAddrs,
		Instances:         instCfgs,
		Key:               key,
		RequestedLease:    uint32(*lease),
		RequestedKeyLease: uint32(*keylease),
		TTL:               uint32(*ttl),
		RegistrarAddr:     *server,
		Discovery:         discoveryMode,
		Resolvers:         []string(resolvers),
		Network:           network,
		MaxRenames:        *maxRenames,
		OnRegistered: func(resp *dns.Msg) {
			fmt.Printf("[%s] ", time.Now().Format(time.RFC3339))
			printResult(resp, pkgsrp.OutcomeSuccess)
		},
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "[%s] ERROR: %v\n", time.Now().Format(time.RFC3339), err)
		},
	}
	c, err := clientsrp.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== sig0lease-srp-client ===\n")
	fmt.Printf("Domain: %s\n", *domain)
	fmt.Printf("Host: %s.%s\n", *host, strings.TrimSuffix(*domain, "."))
	fmt.Printf("Keystore: %s\n", dir)
	fmt.Printf("Key: %s (algorithm %d, keytag %d)\n", key.Name, key.PublicKey.Algorithm, key.PublicKey.KeyTag())
	if *server != "" {
		fmt.Printf("Registrar: %s (explicit)\n", *server)
	} else if discoveryMode == clientsrp.DiscoveryApexOnly {
		fmt.Printf("Registrar: discovered via %s.<zone apex enclosing %s>\n", network.DiscoveryService(), strings.TrimSuffix(*domain, "."))
	} else {
		fmt.Printf("Registrar: discovered via the closest %s SRV from %s up to its zone apex\n", network.DiscoveryService(), strings.TrimSuffix(*domain, "."))
	}
	fmt.Printf("Transport: %s\n", network)
	fmt.Printf("Instances: %d\n\n", len(instCfgs))

	if *deregister {
		resp, outcome, err := c.Deregister(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		printResult(resp, outcome)
		if outcome != pkgsrp.OutcomeSuccess {
			os.Exit(1)
		}
		return
	}

	if *once {
		resp, outcome, err := c.Register(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		printResult(resp, outcome)
		if outcome != pkgsrp.OutcomeSuccess {
			os.Exit(1)
		}
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	fmt.Println("Running full lifecycle (initial delay, refresh clock, rename-retry). Ctrl-C to stop.")
	if err := c.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Stopped.")
}

func printResult(resp *dns.Msg, outcome pkgsrp.Outcome) {
	fmt.Printf("Status: %s (Rcode=%d)\n", dns.RcodeToString[resp.Rcode], resp.Rcode)
	if outcome == pkgsrp.OutcomeSuccess {
		if lease, keyLease, ok := pkgsrp.GrantedLease(resp); ok {
			fmt.Printf("Granted: LEASE=%d KEY-LEASE=%d\n", lease, keyLease)
		}
	}
}

// resolveKeystoreDir applies this project's unified keystore-location convention (same on
// both cmd/sig0lease-client and cmd/sig0lease-srp-client): an explicit flag wins, CLIENT_KEYSTORE_DIR
// is the fallback, and having neither is a fatal error -- there is no more "empty means an
// ephemeral unsaved key" special case (that was sig0lease-srp-client-only and predates this
// consistency requirement; every identity is now persisted like the base client's already is).
func resolveKeystoreDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("CLIENT_KEYSTORE_DIR"); env != "" {
		return env
	}
	fmt.Fprintln(os.Stderr, "ERROR: keystore directory is required: pass -keystore=<dir> or set CLIENT_KEYSTORE_DIR")
	os.Exit(1)
	return ""
}

// resolveKey finds an existing signing key for host+domain in dir, or -- only when
// algorithm is non-zero (the -k flag was passed) -- generates and persists a new one at that
// algorithm. A missing key with no -k given is an error, matching sig0lease-client's own
// strict default (see the keyrec.ResolveOrCreateKey doc comment for the shared logic).
// The logger carries ResolveOrCreateKey's warning when more than one key in dir matches.
func resolveKey(dir, host, domain string, algorithm uint8) (*keyrec.LoadedKey, error) {
	return resolveKeyFor(dir, ensureFQDN(host+"."+strings.TrimSuffix(domain, ".")), algorithm)
}

// resolveKeyFor is resolveKey for an already-joined owner name, which -mdns gets per host.
func resolveKeyFor(dir, owner string, algorithm uint8) (*keyrec.LoadedKey, error) {
	k, created, err := keyrec.ResolveOrCreateKey(dir, owner, algorithm, logging.NewLogger("info"))
	if err != nil {
		return nil, err
	}
	if created {
		fmt.Printf("Generated new signing key: %s (algorithm %d)\n", k.Name, k.PublicKey.Algorithm)
	}
	return k, nil
}

// runBridge runs -mdns until Ctrl-C or SIGTERM, then exits; a failure exits 1.
func runBridge(cfg mdnsbridge.Config, socket string) {
	cfg.Logf = func(format string, args ...any) {
		fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
	}
	fmt.Printf("=== sig0lease-srp-client -mdns ===\n")
	fmt.Printf("mDNSResponder: %s\n", socket)
	if cfg.List {
		fmt.Println("Listing only; * marks what would be mirrored. Ctrl-C to stop.")
	} else {
		fmt.Printf("Domain: %s\n", cfg.SRP.Domain)
		if cfg.SRP.RegistrarAddr != "" {
			fmt.Printf("Registrar: %s (explicit)\n", cfg.SRP.RegistrarAddr)
		} else {
			fmt.Printf("Registrar: discovered via %s\n", cfg.SRP.Network.DiscoveryService())
		}
		fmt.Println("Mirroring. Ctrl-C or SIGTERM deregisters every host and stops.")
	}
	fmt.Println()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := mdnsbridge.Run(ctx, cfg); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Stopped.")
}

// ensureFQDN appends a trailing dot if name doesn't already have one.
func ensureFQDN(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// parseInstances assembles InstanceConfig entries from -instance/-remove/-txt/-subtype,
// matched by label.
func parseInstances(instances, removes, txts, subtypes repeatableFlag) ([]clientsrp.InstanceConfig, error) {
	byLabel := map[string]*clientsrp.InstanceConfig{}
	var order []string

	for _, spec := range instances {
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf(`invalid -instance %q, want "Label:_svctype._proto:port"`, spec)
		}
		port, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid -instance %q: bad port: %w", spec, err)
		}
		if _, exists := byLabel[parts[0]]; exists {
			return nil, fmt.Errorf("duplicate -instance label %q", parts[0])
		}
		byLabel[parts[0]] = &clientsrp.InstanceConfig{Label: parts[0], ServiceType: parts[1], Port: uint16(port)}
		order = append(order, parts[0])
	}

	for _, spec := range removes {
		label, svcType, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf(`invalid -remove %q, want "Label:_svctype._proto"`, spec)
		}
		if _, exists := byLabel[label]; exists {
			return nil, fmt.Errorf("duplicate instance label %q (an -instance and a -remove, or two -remove)", label)
		}
		byLabel[label] = &clientsrp.InstanceConfig{Label: label, ServiceType: svcType, Remove: true}
		order = append(order, label)
	}

	for _, spec := range txts {
		label, content, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf(`invalid -txt %q, want "Label:content"`, spec)
		}
		inst, ok := byLabel[label]
		if !ok {
			return nil, fmt.Errorf("-txt references undeclared instance label %q (declare it with -instance first)", label)
		}
		if inst.Remove {
			return nil, fmt.Errorf("-txt references instance label %q, which -remove withdraws", label)
		}
		inst.TXT = append(inst.TXT, content)
	}

	for _, spec := range subtypes {
		label, subtype, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf(`invalid -subtype %q, want "Label:subtypelabel"`, spec)
		}
		inst, ok := byLabel[label]
		if !ok {
			return nil, fmt.Errorf("-subtype references undeclared instance label %q (declare it with -instance first)", label)
		}
		if inst.Remove {
			return nil, fmt.Errorf("-subtype references instance label %q, which -remove withdraws", label)
		}
		inst.Subtypes = append(inst.Subtypes, subtype)
	}

	out := make([]clientsrp.InstanceConfig, 0, len(order))
	for _, label := range order {
		out = append(out, *byLabel[label])
	}
	return out, nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `sig0lease-srp-client - RFC 9665 SRP requester (dev/test tool over client/srp)

Usage:
  sig0lease-srp-client -domain=<domain> -host=<label> [options]
  sig0lease-srp-client -mdns -domain=<domain> (-mdns-host=<name> ... | -mdns-all-hosts) [options]
  sig0lease-srp-client -mdns -mdns-list

Required:
  -domain string       registration domain, e.g. srp.dev.zenr.io.
  -host string          base host label, e.g. myhost (not the full FQDN)

Options:
  -addr value            host A/AAAA address to publish (repeatable)
  -instance value        service instance "Label:_svctype._proto:port" (repeatable); _proto is
                         _tcp or _udp -- to narrow a type further, add a -subtype instead of a label
  -remove value           service instance "Label:_svctype._proto" to withdraw in this update,
                         keeping the host and every -instance (repeatable)
  -txt value              TXT string for a declared instance, "Label:content" (repeatable)
  -subtype value          DNS-SD subtype for a declared instance, "Label:subtypelabel" (repeatable)
  -server string          explicit registrar "host:port"; empty triggers _dnssd-srp._tcp discovery
                         (_dnssd-srp-tls._tcp with -tls)
  -discovery string       where discovery looks for the registrar's SRV: "closest" (default:
                         the domain, then each parent up to its zone apex; the first record
                         wins) or "apex" (the zone apex only, as RFC 9665 S3.1.1 specifies --
                         what a stock SRP client would find); ignored with -server
  -resolver value          resolver "host:port" for every discovery lookup: zone apex SOA,
                         registrar SRV, registrar address (repeatable; default 8.8.8.8:53,
                         8.8.4.4:53); ignored with -server
  -lease uint              requested LEASE seconds (default 3600)
  -keylease uint            requested KEY-LEASE seconds (default 1209600)
  -ttl uint                 TTL seconds suggested for every registered record, KEYs included
                            (default 300). Independent of the leases; the registrar may
                            override it (RFC 9665 S4)
  -udp                      use UDP instead of TCP (SRP requires TCP by default, S3.5)
  -tls                      use DNS-over-TLS (RFC 7858) instead of TCP. Opportunistic, as RFC 9665
                            S7 specifies: encrypted, but the registrar's certificate is not
                            checked. Discovery looks for _dnssd-srp-tls._tcp instead of
                            _dnssd-srp._tcp and never falls back to plain TCP; with -server, give
                            the registrar's DoT port. Not with -udp
  -once                    send exactly one registration and exit, instead of running the full lifecycle
  -deregister               send exactly one Deregister (withdraw host + every -instance) and exit; implies -once
  -keystore string          directory holding this identity's signing key; falls back to the
                            CLIENT_KEYSTORE_DIR environment variable if unset (an explicit flag
                            always wins); one of the two is required
  -k uint                   DNSSEC algorithm (13=ECDSAP256SHA256, 15=ED25519) to generate a NEW
                            signing key with if this identity (-host+-domain) doesn't have one
                            in the keystore yet; omit to require an existing key (error if
                            missing) -- same convention as sig0lease-client's -k
  -max-renames int           rename-retry attempts on YXDOMAIN before giving up (default 5)

Mirroring what mDNSResponder sees (-mdns):
  -mdns                     ask the running mDNSResponder daemon, over its client socket, for
                            the services on the link, and register each selected mDNS host
                            ("mymac.local." becomes mymac.<domain>) with its addresses and
                            instances. An instance the daemon reports gone is withdrawn; a host
                            with none left, and every host when this stops, is deregistered.
                            Each host gets its own key in the keystore (-k to create them).
                            Not with -host, -addr, -instance, -remove, -txt, -subtype, -once,
                            -deregister. Subtypes, and later address or TXT changes, are not
                            followed
  -mdns-host value          mDNS host to mirror, e.g. mymac.local. (repeatable); on a Mac,
                            scutil --get LocalHostName prints this machine's
  -mdns-all-hosts           mirror every host on the link instead
  -mdns-type value          service type to mirror, e.g. _ssh._tcp (repeatable); default every
                            type the daemon enumerates
  -mdns-list                print the instances the daemon sees, * marking those that would be
                            mirrored, and register nothing; needs no -domain or keystore
  -mdns-socket string       the daemon's socket (default /var/run/mDNSResponder on macOS,
                            /var/run/mdnsd, mDNSPosix's mdnsd, elsewhere)

Examples:
  // One-shot registration of a host with one service instance, against an explicit registrar;
  // -k 13 generates an ECDSAP256SHA256 key on first run, reused on every later run
  sig0lease-srp-client -domain=srp.test. -host=myhost -addr=192.0.2.1 -server=127.0.0.1:8059 \
    -instance=Widget:_http._tcp:8080 -txt=Widget:path=/ -once -keystore=./srp-identity -k=13

  // Full lifecycle (persistent refresh + rename-retry), discovering the registrar; requires
  // -host.myhost's key to already exist in ./srp-identity, since -k is not given here
  sig0lease-srp-client -domain=srp.dev.zenr.io. -host=myhost -addr=192.0.2.1 \
    -instance=Widget:_http._tcp:8080 -keystore=./srp-identity

  // On a Mac: publish its Remote Login, File Sharing and Screen Sharing services, as macOS
  // advertises them, under srp.dev.zenr.io. through a registrar at 192.0.2.10:8053
  sig0lease-srp-client -mdns -mdns-host=$(scutil --get LocalHostName).local. \
    -mdns-type=_ssh._tcp -mdns-type=_smb._tcp -mdns-type=_rfb._tcp \
    -domain=srp.dev.zenr.io. -server=192.0.2.10:8053 -keystore=./mdns-identities -k=13
`)
}
