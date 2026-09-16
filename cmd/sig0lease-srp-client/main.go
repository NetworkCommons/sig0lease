// Package main implements sig0lease-srp-client, a thin CLI over client/srp -- a dev/test tool
// (plan D8), not a shipped product. The library is the deliverable; this just exercises it.
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

	"codeberg.org/miekg/dns"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
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
	server := flag.String("server", "", "explicit registrar \"host:port\"; empty triggers _dnssd-srp._tcp discovery")
	lease := flag.Uint("lease", 3600, "requested LEASE seconds")
	keylease := flag.Uint("keylease", 1209600, "requested KEY-LEASE seconds")
	udp := flag.Bool("udp", false, "use UDP instead of TCP (SRP requires TCP by default, S3.5)")
	once := flag.Bool("once", false, "send exactly one registration and exit, instead of running the full refresh lifecycle")
	deregister := flag.Bool("deregister", false, "send exactly one Deregister (withdraw host + every -instance) and exit, instead of registering; implies -once")
	keystoreDir := flag.String("keystore", "", "directory to load this identity's signing key from; falls back to CLIENT_KEYSTORE_DIR if unset")
	keyAlg := flag.Uint("k", 0, "DNSSEC algorithm (13=ECDSAP256SHA256, 15=ED25519) to generate a NEW signing key with if none exists yet; omit to require an existing key")
	maxRenames := flag.Int("max-renames", 5, "rename-retry attempts on YXDOMAIN before giving up")

	var addrs, instances, txts, subtypes, resolvers repeatableFlag
	flag.Var(&addrs, "addr", "host A/AAAA address to publish (repeatable)")
	flag.Var(&resolvers, "resolver", "bootstrap resolver \"host:port\" for _dnssd-srp._tcp discovery (repeatable); default 8.8.8.8:53, 8.8.4.4:53")
	flag.Var(&instances, "instance", `service instance "Label:_svctype._proto:port" (repeatable)`)
	flag.Var(&txts, "txt", `TXT string for a declared instance, "Label:content" (repeatable)`)
	flag.Var(&subtypes, "subtype", `DNS-SD subtype for a declared instance, "Label:subtypelabel" (repeatable)`)

	flag.Usage = printUsage
	flag.Parse()

	if *domain == "" || *host == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -domain and -host are required")
		printUsage()
		os.Exit(1)
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

	instCfgs, err := parseInstances(instances, txts, subtypes)
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
		RegistrarAddr:     *server,
		Resolvers:         []string(resolvers),
		UseTCP:            !*udp,
		MaxRenames:        *maxRenames,
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
	} else {
		fmt.Printf("Registrar: discovered via _dnssd-srp._tcp.%s\n", strings.TrimSuffix(*domain, "."))
	}
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
func resolveKey(dir, host, domain string, algorithm uint8) (*keyrec.LoadedKey, error) {
	name := ensureFQDN(host + "." + strings.TrimSuffix(domain, "."))
	k, created, err := keyrec.ResolveOrCreateKey(dir, name, algorithm, nil)
	if err != nil {
		return nil, err
	}
	if created {
		fmt.Printf("Generated new signing key: %s (algorithm %d)\n", k.Name, k.PublicKey.Algorithm)
	}
	return k, nil
}

// ensureFQDN appends a trailing dot if name doesn't already have one.
func ensureFQDN(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// parseInstances assembles InstanceConfig entries from -instance/-txt/-subtype, matched by
// label.
func parseInstances(instances, txts, subtypes repeatableFlag) ([]clientsrp.InstanceConfig, error) {
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

	for _, spec := range txts {
		label, content, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf(`invalid -txt %q, want "Label:content"`, spec)
		}
		inst, ok := byLabel[label]
		if !ok {
			return nil, fmt.Errorf("-txt references undeclared instance label %q (declare it with -instance first)", label)
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

Required:
  -domain string       registration domain, e.g. srp.dev.zenr.io.
  -host string          base host label, e.g. myhost (not the full FQDN)

Options:
  -addr value            host A/AAAA address to publish (repeatable)
  -instance value        service instance "Label:_svctype._proto:port" (repeatable)
  -txt value              TXT string for a declared instance, "Label:content" (repeatable)
  -subtype value          DNS-SD subtype for a declared instance, "Label:subtypelabel" (repeatable)
  -server string          explicit registrar "host:port"; empty triggers _dnssd-srp._tcp discovery
  -resolver value          bootstrap resolver "host:port" for discovery (repeatable)
  -lease uint              requested LEASE seconds (default 3600)
  -keylease uint            requested KEY-LEASE seconds (default 1209600)
  -udp                      use UDP instead of TCP (SRP requires TCP by default, S3.5)
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

Examples:
  // One-shot registration of a host with one service instance, against an explicit registrar;
  // -k 13 generates an ECDSAP256SHA256 key on first run, reused on every later run
  sig0lease-srp-client -domain=srp.test. -host=myhost -addr=192.0.2.1 -server=127.0.0.1:8059 \
    -instance=Widget:_http._tcp:8080 -txt=Widget:path=/ -once -keystore=./srp-identity -k=13

  // Full lifecycle (persistent refresh + rename-retry), discovering the registrar; requires
  // -host.myhost's key to already exist in ./srp-identity, since -k is not given here
  sig0lease-srp-client -domain=srp.dev.zenr.io. -host=myhost -addr=192.0.2.1 \
    -instance=Widget:_http._tcp:8080 -keystore=./srp-identity
`)
}
