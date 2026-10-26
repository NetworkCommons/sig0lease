// Package cli has what this project's client commands share, so that they read alike:
// sig0lease-client and sig0lease-srp-client take "<command> [flags] [args]" (the SRP client
// has no command), with the same flags for the same things (-server, -transport, -keystore,
// -k, -lease, -key-lease, -ttl), the same signing-key convention, the same reply printing,
// and, for the commands that keep a registration, the same modes (-once, -deregister,
// -keep-names).
package cli

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// Repeatable collects every occurrence of a flag, in order.
type Repeatable []string

func (r *Repeatable) String() string     { return strings.Join(*r, ",") }
func (r *Repeatable) Set(v string) error { *r = append(*r, v); return nil }

// Endpoint holds the flags saying where a command sends: -server and -transport.
type Endpoint struct {
	Server    string
	Transport client.Network
}

// Define defines Endpoint's flags on fs; server says what -server is for that command.
func (e *Endpoint) Define(fs *flag.FlagSet, server string) {
	fs.StringVar(&e.Server, "server", "", server)
	fs.TextVar(&e.Transport, "transport", client.NetworkTCP, "tcp, udp or tls: DNS over TLS (RFC 7858), opportunistic, so the certificate is not checked")
}

// RequireServer reports a missing -server, for the commands that cannot discover one.
func (e *Endpoint) RequireServer() error {
	if e.Server == "" {
		return fmt.Errorf(`-server is required: the proxy's "host:port"`)
	}
	return nil
}

// DefineKeystore defines -keystore on fs, read into dir: the directory holding the signing
// keys (KeystoreDir).
func DefineKeystore(fs *flag.FlagSet, dir *string) {
	fs.StringVar(dir, "keystore", "", "directory holding the signing keys (default $"+keyrec.KeystoreEnv+")")
}

// KeystoreDir is the keystore given, else the one CLIENT_KEYSTORE_DIR names
// (keyrec.KeystoreDir).
func KeystoreDir(given string) (string, error) {
	return keyrec.KeystoreDir(given, "pass -keystore=<dir>")
}

// Request holds the flags of a command that sends signed updates: Endpoint's, -keystore, -k,
// -lease, -key-lease and -ttl.
type Request struct {
	Endpoint
	Keystore string
	KeyAlg   uint
	Lease    uint
	KeyLease uint
	TTL      uint
}

// Define defines Request's flags on fs; server says what -server is for that command.
func (r *Request) Define(fs *flag.FlagSet, server string) {
	r.Endpoint.Define(fs, server)
	DefineKeystore(fs, &r.Keystore)
	fs.UintVar(&r.KeyAlg, "k", 0, "DNSSEC algorithm (13=ECDSAP256SHA256, 15=ED25519) to generate a signing key with when none exists; left out, a missing key is an error")
	fs.UintVar(&r.Lease, "lease", 3600, "LEASE to ask for, in seconds: how long the records last unless refreshed")
	fs.UintVar(&r.KeyLease, "key-lease", 1209600, "KEY-LEASE to ask for, in seconds: how long the names stay reserved for the key")
	fs.UintVar(&r.TTL, "ttl", 300, "TTL suggested for the records the command builds, KEYs included, in seconds; independent of the leases, and the registrar may override it")
}

// Check reports a flag value a request cannot carry.
func (r *Request) Check() error {
	switch {
	case r.Lease > math.MaxUint32 || r.KeyLease > math.MaxUint32:
		return fmt.Errorf("-lease and -key-lease must fit 32 bits")
	case r.TTL == 0 || r.TTL > math.MaxInt32:
		return fmt.Errorf("-ttl must be between 1 and %d", math.MaxInt32)
	case r.KeyAlg > math.MaxUint8:
		return fmt.Errorf("-k must be a DNSSEC algorithm number")
	}
	return nil
}

// Key finds owner's signing key in the keystore or, with -k, generates one there
// (keyrec.ResolveOrCreateKey), and says when it did.
func (r *Request) Key(owner string) (*keyrec.LoadedKey, error) {
	dir, err := KeystoreDir(r.Keystore)
	if err != nil {
		return nil, err
	}
	// The logger carries ResolveOrCreateKey's warning when more than one key matches.
	k, created, err := keyrec.ResolveOrCreateKey(dir, owner, uint8(r.KeyAlg), logging.NewLogger("info"))
	if err != nil {
		return nil, err
	}
	if created {
		fmt.Printf("Generated new signing key: %s (algorithm %d)\n", k.Name, k.PublicKey.Algorithm)
	}
	return k, nil
}

// PrintEDEs prints the Extended DNS Errors (RFC 8914) in resp, one per line: the reason for a
// refusal, or a success's notes.
func PrintEDEs(resp *dns.Msg) {
	for _, ede := range dnsmsg.EDEs(resp) {
		fmt.Printf("EDE %s\n", dnsmsg.FormatEDE(ede))
	}
}

// PrintReply prints resp's status and Extended DNS Errors, and, for a success, the leases
// granted.
func PrintReply(resp *dns.Msg, outcome client.Outcome) {
	fmt.Printf("Status: %s (Rcode=%d)\n", dns.RcodeToString[resp.Rcode], resp.Rcode)
	PrintEDEs(resp)
	if outcome == client.OutcomeSuccess {
		if lease, keyLease, ok := client.GrantedLease(resp); ok {
			fmt.Printf("Granted: LEASE=%d KEY-LEASE=%d\n", lease, keyLease)
		}
	}
}

// Stamp prefixes a line a running command prints with the time.
func Stamp() string { return "[" + time.Now().Format(time.RFC3339) + "] " }

// Requester is what a command that keeps a registration drives: client/srp's Client or
// client/rfc9664's.
type Requester interface {
	Register(ctx context.Context) (*dns.Msg, client.Outcome, error)
	Deregister(ctx context.Context, keepNames bool) (*dns.Msg, client.Outcome, error)
	Run(ctx context.Context) error
}

// Modes holds the flags that choose what such a command does: by default it keeps the
// registration until Ctrl-C or SIGTERM; -once registers once, -deregister deregisters.
type Modes struct {
	Once       bool
	Deregister bool
	KeepNames  bool
}

// Define defines Modes' flags on fs; what names what -deregister withdraws.
func (m *Modes) Define(fs *flag.FlagSet, what string) {
	fs.BoolVar(&m.Once, "once", false, "send one registration and exit, instead of keeping it registered on the lease clock")
	fs.BoolVar(&m.Deregister, "deregister", false, "send one deregistration of "+what+" and exit; the names are freed (KEY-LEASE 0) unless -keep-names")
	fs.BoolVar(&m.KeepNames, "keep-names", false, "with -deregister: keep the names for the key, asking for -key-lease")
}

// Check reports flags that do not go together.
func (m *Modes) Check() error {
	switch {
	case m.Once && m.Deregister:
		return fmt.Errorf("-once and -deregister are different requests: give one")
	case m.KeepNames && !m.Deregister:
		return fmt.Errorf("-keep-names is for -deregister")
	}
	return nil
}

// Run does with c what the modes say, printing each reply, and exits non-zero when that
// failed. Kept registered, c prints its own replies (its OnRegistered and OnError).
func (m *Modes) Run(c Requester) {
	if m.Once || m.Deregister {
		var resp *dns.Msg
		var outcome client.Outcome
		var err error
		if m.Deregister {
			resp, outcome, err = c.Deregister(context.Background(), m.KeepNames)
		} else {
			resp, outcome, err = c.Register(context.Background())
		}
		Exit(resp, outcome, err)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	fmt.Println("Keeping it registered on the lease clock. Ctrl-C to stop.")
	if err := c.Run(ctx); err != nil && ctx.Err() == nil {
		Fail(err)
	}
	fmt.Println("Stopped.")
}

// Exit prints the reply to a single request, and exits non-zero unless it succeeded.
func Exit(resp *dns.Msg, outcome client.Outcome, err error) {
	if err != nil {
		Fail(err)
	}
	PrintReply(resp, outcome)
	if outcome != client.OutcomeSuccess {
		os.Exit(1)
	}
}

// Fail prints err and exits 1.
func Fail(err error) {
	fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	os.Exit(1)
}
