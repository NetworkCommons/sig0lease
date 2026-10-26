// Package main implements sig0lease-srp-client, a thin CLI over client/srp -- a dev/test tool,
// not a shipped product. The library is the deliverable; this just exercises it. The
// long-running client that keeps a machine's services registered, mirroring what the local
// mDNSResponder sees among them, is sig0lease-agent. Its flags are spelled as
// sig0lease-client's (cmd/internal/cli).
package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/cmd/internal/cli"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat" // registers EDNS0 code 2 (UPDATE-LEASE); matches cmd/sig0lease/main.go and cmd/sig0lease-client/main.go's own convention (client/srp also self-registers this, so it's redundant here, not load-bearing)
)

func main() {
	var req cli.Request
	var modes cli.Modes
	req.Define(flag.CommandLine, `explicit registrar "host:port"; empty: discovered through _dnssd-srp._tcp (_dnssd-srp-tls._tcp with -transport tls)`)
	modes.Define(flag.CommandLine, "the host and every -instance")
	domain := flag.String("domain", "", "registration domain (required)")
	host := flag.String("host", "", "base host label, e.g. \"myhost\" (required)")
	discovery := flag.String("discovery", "closest", `where discovery looks for the registrar's SRV: "closest" (the domain, then each parent up to its zone apex) or "apex" (the zone apex only, as RFC 9665 S3.1.1 specifies)`)
	maxRenames := flag.Int("max-renames", 5, "rename-retry attempts on YXDOMAIN before giving up")
	var addrs, resolvers, instances, removes, txts, subtypes cli.Repeatable
	flag.Var(&addrs, "addr", "host A/AAAA address to publish (repeatable)")
	flag.Var(&resolvers, "resolver", "resolver \"host:port\" for every discovery lookup -- zone apex SOA, registrar SRV, registrar address (repeatable); default 8.8.8.8:53, 8.8.4.4:53")
	flag.Var(&instances, "instance", `service instance "Label:_svctype._proto:port" (repeatable)`)
	flag.Var(&removes, "remove", `service instance "Label:_svctype._proto" to withdraw in this update (repeatable)`)
	flag.Var(&txts, "txt", `TXT string for a declared instance, "Label:content" (repeatable)`)
	flag.Var(&subtypes, "subtype", `DNS-SD subtype for a declared instance, "Label:subtypelabel" (repeatable)`)

	flag.Usage = printUsage
	flag.Parse()

	if *domain == "" || *host == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -domain and -host are required")
		printUsage()
		os.Exit(2)
	}
	if flag.NArg() != 0 {
		cli.Fail(fmt.Errorf("unexpected arguments %q: everything is a flag", flag.Args()))
	}
	if err := req.Check(); err != nil {
		cli.Fail(err)
	}
	if err := modes.Check(); err != nil {
		cli.Fail(err)
	}

	var discoveryMode clientsrp.DiscoveryMode
	switch *discovery {
	case "closest":
		discoveryMode = clientsrp.DiscoveryClosest
	case "apex":
		discoveryMode = clientsrp.DiscoveryApexOnly
	default:
		cli.Fail(fmt.Errorf("invalid -discovery %q, want \"closest\" or \"apex\"", *discovery))
	}

	var parsedAddrs []netip.Addr
	for _, a := range addrs {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			cli.Fail(fmt.Errorf("invalid -addr %q: %v", a, err))
		}
		parsedAddrs = append(parsedAddrs, addr)
	}
	// RFC 9665 S3.3.1.3: a Host Description without an address is a removal.
	if len(parsedAddrs) == 0 && !modes.Deregister {
		cli.Fail(fmt.Errorf("-addr is required to register: a host without an address is a removal (RFC 9665 S3.3.1.3); use -deregister"))
	}

	instCfgs, err := parseInstances(instances, removes, txts, subtypes)
	if err != nil {
		cli.Fail(err)
	}

	// Every identity is kept in a keystore (keyrec.KeystoreDir), none is an unsaved one-off.
	key, err := req.Key(*host + "." + dnsutil.Fqdn(*domain))
	if err != nil {
		cli.Fail(err)
	}

	cfg := clientsrp.Config{
		Domain:            *domain,
		HostLabel:         *host,
		Addresses:         parsedAddrs,
		Instances:         instCfgs,
		Key:               key,
		RequestedLease:    uint32(req.Lease),
		RequestedKeyLease: uint32(req.KeyLease),
		TTL:               uint32(req.TTL),
		RegistrarAddr:     req.Server,
		Discovery:         discoveryMode,
		Resolvers:         []string(resolvers),
		Network:           req.Transport,
		MaxRenames:        *maxRenames,
		OnRegistered: func(resp *dns.Msg) {
			fmt.Print(cli.Stamp())
			cli.PrintReply(resp, baseclient.OutcomeSuccess)
		},
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "%sERROR: %v\n", cli.Stamp(), err)
		},
	}
	c, err := clientsrp.NewClient(cfg)
	if err != nil {
		cli.Fail(err)
	}

	fmt.Printf("=== sig0lease-srp-client ===\n")
	fmt.Printf("Domain: %s\n", *domain)
	fmt.Printf("Host: %s.%s\n", *host, strings.TrimSuffix(*domain, "."))
	fmt.Printf("Key: %s (algorithm %d, keytag %d)\n", key.Name, key.PublicKey.Algorithm, key.PublicKey.KeyTag())
	if req.Server != "" {
		fmt.Printf("Registrar: %s (explicit)\n", req.Server)
	} else if discoveryMode == clientsrp.DiscoveryApexOnly {
		fmt.Printf("Registrar: discovered via %s.<zone apex enclosing %s>\n", clientsrp.DiscoveryService(req.Transport), strings.TrimSuffix(*domain, "."))
	} else {
		fmt.Printf("Registrar: discovered via the closest %s SRV from %s up to its zone apex\n", clientsrp.DiscoveryService(req.Transport), strings.TrimSuffix(*domain, "."))
	}
	fmt.Printf("Transport: %s\n", req.Transport)
	fmt.Printf("Instances: %d\n\n", len(instCfgs))

	modes.Run(c)
}

// parseInstances assembles InstanceConfig entries from -instance/-remove/-txt/-subtype,
// matched by label.
func parseInstances(instances, removes, txts, subtypes cli.Repeatable) ([]clientsrp.InstanceConfig, error) {
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
  sig0lease-srp-client -domain <domain> -host <label> [flags]

A machine's services are kept registered, and what its mDNSResponder sees mirrored, by
sig0lease-agent (docs/sig0lease-agent.md); this tool sends what its flags say. Its flags are
spelled as sig0lease-client's.

What to register:
  -domain string          registration domain, e.g. srp.dev.zenr.io. (required)
  -host string            base host label, e.g. myhost, not the full name (required)
  -addr value             host A/AAAA address to publish (repeatable); at least one, unless
                          -deregister
  -instance value         service instance "Label:_svctype._proto:port" (repeatable); _proto is
                          _tcp or _udp -- to narrow a type further, add a -subtype instead of a label
  -remove value           service instance "Label:_svctype._proto" to withdraw in this update,
                          keeping the host and every -instance (repeatable)
  -txt value              TXT string for a declared instance, "Label:content" (repeatable)
  -subtype value          DNS-SD subtype for a declared instance, "Label:subtypelabel" (repeatable)

Where and how:
  -server string          registrar "host:port"; empty: discovered through _dnssd-srp._tcp
                          (_dnssd-srp-tls._tcp with -transport tls)
  -discovery string       where discovery looks for the registrar's SRV: "closest" (default:
                          the domain, then each parent up to its zone apex; the first record
                          wins) or "apex" (the zone apex only, as RFC 9665 S3.1.1 specifies --
                          what a stock SRP client would find); ignored with -server
  -resolver value         resolver "host:port" for every discovery lookup: zone apex SOA,
                          registrar SRV, registrar address (repeatable; default 8.8.8.8:53,
                          8.8.4.4:53); ignored with -server
  -transport string       tcp (default), udp or tls: DNS over TLS (RFC 7858), opportunistic as
                          RFC 9665 S7 specifies, so the registrar's certificate is not checked.
                          With tls, discovery looks for _dnssd-srp-tls._tcp and never falls back
                          to plain TCP; with -server, give the registrar's DoT port
  -lease uint             LEASE to ask for, in seconds (default 3600)
  -key-lease uint         KEY-LEASE to ask for, in seconds (default 1209600)
  -ttl uint               TTL suggested for every registered record, KEYs included, in seconds
                          (default 300); independent of the leases, and the registrar may
                          override it (RFC 9665 S4)
  -max-renames int        rename-retry attempts on YXDOMAIN before giving up (default 5)

Key:
  -keystore string        directory holding this identity's signing key (default
                          $CLIENT_KEYSTORE_DIR; one of the two is required)
  -k uint                 DNSSEC algorithm (13=ECDSAP256SHA256, 15=ED25519) to generate a key
                          with if this identity (-host + -domain) has none yet; left out, a
                          missing key is an error

What to do (default: keep it registered on the lease clock, renaming on YXDOMAIN, until
Ctrl-C):
  -once                   send one registration and exit
  -deregister             send one deregistration of the host and every -instance and exit;
                          the names are freed (KEY-LEASE 0), unless -keep-names
  -keep-names             with -deregister: keep the names for this identity's key, asking for
                          -key-lease (RFC 9665 S3.2.5.5.1)

Examples:
  // One registration of a host with one service instance, against an explicit registrar;
  // -k 13 generates an ECDSAP256SHA256 key on first run, reused on every later run
  sig0lease-srp-client -domain srp.test. -host myhost -addr 192.0.2.1 -server 127.0.0.1:8059 \
    -instance Widget:_http._tcp:8080 -txt Widget:path=/ -once -keystore ./srp-identity -k 13

  // Kept registered, discovering the registrar; myhost's key must already be in
  // ./srp-identity, since -k is not given
  sig0lease-srp-client -domain srp.dev.zenr.io. -host myhost -addr 192.0.2.1 \
    -instance Widget:_http._tcp:8080 -keystore ./srp-identity
`)
}
