// Package main implements sig0lease-client, the RFC 9664 client of this project's proxy. Its
// update commands (register, refresh, register-tamper) send exactly the update their
// arguments describe, the shapes the proxy must refuse included, so the test suites can check
// its answers; name keeps a name registered through client/rfc9664, as sig0lease-srp-client
// does a host through client/srp. Both spell their flags alike (cmd/internal/cli).
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/rfc9664"
	"github.com/NetworkCommons/sig0lease/cmd/internal/cli"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

const proxyUsage = `the proxy's "host:port" (required; its DoT address with -transport tls)`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	command, args := os.Args[1], os.Args[2:]
	switch command {
	case "register", "refresh", "register-tamper":
		cmdUpdate(command, args)
	case "name":
		cmdName(args)
	case "verify":
		cmdVerify(args)
	case "list-keys":
		cmdListKeys(args)
	case "help", "-h", "-help", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "ERROR: unknown command %q\n\n", command)
		printUsage()
		os.Exit(2)
	}
}

// newFlagSet is a command's flag set: a bad flag prints the usage and exits 2.
func newFlagSet(command string) *flag.FlagSet {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	fs.Usage = printUsage
	return fs
}

// Signer key placement modes for -signer. These exercise the three
// ways the proxy can resolve a signer's KEY material: present directly in
// the request (update or additional section), or absent from the request
// entirely (resolved via the lease store or authoritative DNS instead).
const (
	signerLocationAuto       = "auto" // default: additional, unless a matching KEY rr-spec is already in Update
	signerLocationUpdate     = "update"
	signerLocationAdditional = "additional"
	signerLocationNone       = "none"
)

// keyRRFromClientKey builds a *dns.KEY RR from the already-loaded signing
// key, so callers don't need to re-derive or re-type its RDATA by hand.
func keyRRFromClientKey(clientKey *keyrec.LoadedKey, ttl uint32) *dns.KEY {
	keyRR := new(dns.KEY)
	keyRR.Hdr.Name = clientKey.KeyName()
	keyRR.Hdr.Class = dns.ClassINET
	keyRR.Hdr.TTL = ttl
	keyRR.Flags = clientKey.PublicKey.Flags
	keyRR.Protocol = clientKey.PublicKey.Protocol
	keyRR.Algorithm = clientKey.PublicKey.Algorithm
	keyRR.PublicKey = clientKey.PublicKey.PublicKey
	return keyRR
}

func addSignerKeyToAdditional(msg *dns.Msg, clientKey *keyrec.LoadedKey, ttl uint32) {
	signingKeyRR := keyRRFromClientKey(clientKey, ttl)
	msg.Extra = append(msg.Extra, signingKeyRR)
	fmt.Printf("  ✓ Added signer KEY RR to Additional section: %s\n", signingKeyRR.String())
}

// cmdUpdate sends the one update register, refresh or register-tamper describes: the
// signing key, the KEY and other records given, on the leases given, the signer's KEY where
// -signer puts it; register-tamper flips one bit of it after signing.
func cmdUpdate(command string, args []string) {
	fs := newFlagSet(command)
	var req cli.Request
	req.Define(fs, proxyUsage)
	signerLocation := fs.String("signer", signerLocationAuto, "where the signer's KEY goes: update, additional or none (default: additional, unless a KEY rr-spec for it is in the Update section)")
	sameKey := fs.Bool("same-key", false, "add the signing key's own KEY to the Update section, to lease it without typing its rr-spec")
	zone := fs.String("zone", "", "the Zone Section (default: the signing key's name, which encloses every name it may write)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	args = fs.Args()
	switch *signerLocation {
	case signerLocationAuto, signerLocationUpdate, signerLocationAdditional, signerLocationNone:
	default:
		cli.Fail(fmt.Errorf("invalid -signer %q (want update, additional or none)", *signerLocation))
	}
	if err := req.Check(); err != nil {
		cli.Fail(err)
	}
	if err := req.RequireServer(); err != nil {
		cli.Fail(err)
	}
	if len(args) < 1 {
		cli.Fail(fmt.Errorf("give the signing key: %s [flags] <keyname> [rr-spec...]", command))
	}
	operation, tamper := command, command == "register-tamper"
	if tamper {
		operation = "register"
	}
	proxyAddr, keyTTL := req.Server, uint32(req.TTL)
	leaseDuration, keyLeaseDuration := uint32(req.Lease), uint32(req.KeyLease)
	keyname := args[0]
	rrSpecs := args[1:]
	updateKeyRRs := make([]*dns.KEY, 0)
	updateOtherRRs := make([]dns.RR, 0, len(rrSpecs))
	for _, spec := range rrSpecs {
		rr, err := dnsmsg.ParseAdditionalRRSpec(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Invalid rr-spec %q: %v\n", spec, err)
			os.Exit(1)
		}
		if keyRR, ok := rr.(*dns.KEY); ok {
			if keyRR.Algorithm == 0 || keyRR.Protocol == 0 || strings.TrimSpace(keyRR.PublicKey) == "" {
				fmt.Fprintf(os.Stderr, "ERROR: Invalid KEY rr-spec %q: full KEY RDATA is required\n", spec)
				os.Exit(1)
			}
			updateKeyRRs = append(updateKeyRRs, keyRR)
			continue
		}
		updateOtherRRs = append(updateOtherRRs, rr)
	}

	// Load (or, with -k, find-or-create) the client key used for SIG(0) signing. Without -k,
	// keyname is the exact on-disk key filename. With -k, keyname is instead an owner name
	// (e.g. "test.dev.zenr.io."): any existing key for that name is reused regardless of its
	// algorithm, and a new one is generated at -k's algorithm only if none exists.
	keystoreDir, err := cli.KeystoreDir(req.Keystore)
	if err != nil {
		cli.Fail(err)
	}
	var clientKey *keyrec.LoadedKey
	if req.KeyAlg != 0 {
		fmt.Printf("Resolving client key for owner name (%s) from keystore (%s), creating with algorithm %d if not found\n", keyname, keystoreDir, req.KeyAlg)
		k, err := req.Key(keyname)
		if err != nil {
			cli.Fail(err)
		}
		clientKey = k
		fmt.Printf("  ✓ Client key: %s\n", clientKey.Name)
	} else {
		fmt.Printf("Loading client key for key name (%s) from keystore (%s)\n", keyname, keystoreDir)
		if err := keyrec.KeyExists(keystoreDir, keyname, nil); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Could not find client key for key name %s: %v\n", keyname, err)
			os.Exit(1)
		}
		fmt.Printf("  Found client key: %s\n", keyname)

		k, err := keyrec.LoadKeyFromFile(keystoreDir, keyname)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to load client key: %v\n", err)
			os.Exit(1)
		}
		clientKey = k
	}

	if *sameKey {
		for _, rr := range updateKeyRRs {
			if dnsname.EqualFold(rr.Hdr.Name, clientKey.KeyName()) {
				fmt.Fprintf(os.Stderr, "ERROR: -same-key conflicts with an explicit KEY rr-spec for %s already among the rr-spec arguments\n", clientKey.KeyName())
				os.Exit(1)
			}
		}
		if *signerLocation == signerLocationNone {
			fmt.Fprintf(os.Stderr, "ERROR: -same-key conflicts with -signer none: the signing key must appear in the Update section\n")
			os.Exit(1)
		}
		updateKeyRRs = append(updateKeyRRs, keyRRFromClientKey(clientKey, keyTTL))
		fmt.Printf("  ✓ -same-key: reusing signing key %s as the Update-section lease payload\n", clientKey.KeyName())
	}

	fmt.Printf("=== sig0lease Client %s ===\n", operation)
	fmt.Printf("Proxy: %s\n", proxyAddr)

	fmt.Printf("Key Name: %s\n", clientKey.KeyName())
	fmt.Printf("  ✓ Loaded successfully\n")
	clientKey.Print()

	if tamper {
		fmt.Printf("Mode: tamper one payload bit after signing\n")
	}
	fmt.Printf("Lease: %d seconds\n", leaseDuration)
	fmt.Printf("Key-Lease: %d seconds\n", keyLeaseDuration)
	if len(updateKeyRRs) > 0 {
		fmt.Printf("Update KEY RRs: %d\n", len(updateKeyRRs))
	}
	if len(updateOtherRRs) > 0 {
		fmt.Printf("Update non-KEY RRs: %d\n", len(updateOtherRRs))
	}
	fmt.Printf("\n")

	// Build UPDATE payload using shared packet factory
	fmt.Printf("\nBuilding UPDATE message payload\n")

	if len(updateKeyRRs) > 0 {
		fmt.Printf("\nAdding explicit KEY RR(s) to Authority section\n")
		for _, rr := range updateKeyRRs {
			fmt.Printf("  ✓ Added KEY RR: %s\n", rr.String())
		}
	} else {
		fmt.Printf("\nNo explicit KEY rr-spec provided; signer KEY will be sent in Additional section only\n")
	}

	if len(updateOtherRRs) > 0 {
		fmt.Printf("\nAdding non-KEY RR(s) to Authority section\n")
		for _, rr := range updateOtherRRs {
			fmt.Printf("  ✓ Added RR: %s\n", rr.String())
		}
	}

	// The Zone Section only has to enclose every name in the update; the signing key's name
	// encloses every name it may write (docs/siglease_rfc9664.md, "The Zone Section").
	zoneSection := *zone
	if zoneSection == "" {
		zoneSection = clientKey.KeyName()
	}
	fmt.Printf("Zone Section: %s\n", zoneSection)
	msg, err := dnsmsg.NewLeaseUpdate(zoneSection, updateKeyRRs, updateOtherRRs, leaseDuration, keyLeaseDuration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to build update packet for %s: %v\n", operation, err)
		os.Exit(1)
	}

	signerKeyInUpdate := false
	for _, rr := range updateKeyRRs {
		if rr == nil {
			continue
		}
		if dnsname.EqualFold(rr.Hdr.Name, clientKey.KeyName()) &&
			rr.Flags == clientKey.PublicKey.Flags &&
			rr.Protocol == clientKey.PublicKey.Protocol &&
			rr.Algorithm == clientKey.PublicKey.Algorithm &&
			strings.TrimSpace(rr.PublicKey) == strings.TrimSpace(clientKey.PublicKey.PublicKey) {
			signerKeyInUpdate = true
			break
		}
	}

	fmt.Printf("\nSigner KEY placement: -signer %s\n", *signerLocation)
	switch *signerLocation {
	case signerLocationUpdate:
		if !signerKeyInUpdate {
			fmt.Fprintf(os.Stderr, "ERROR: -signer update requires a KEY rr-spec for %s among the rr-spec arguments\n", clientKey.KeyName())
			os.Exit(1)
		}
		fmt.Printf("  ✓ Signer KEY RR present in Update section\n")
	case signerLocationAdditional:
		addSignerKeyToAdditional(msg, clientKey, keyTTL)
	case signerLocationNone:
		if signerKeyInUpdate {
			fmt.Fprintf(os.Stderr, "ERROR: -signer none conflicts with a KEY rr-spec for %s already among the rr-spec arguments\n", clientKey.KeyName())
			os.Exit(1)
		}
		fmt.Printf("  ✓ Signer KEY RR omitted from request; proxy must resolve it via the lease store or authoritative DNS\n")
	case signerLocationAuto:
		if signerKeyInUpdate {
			fmt.Printf("  ✓ Signer KEY RR already present in Authority section; not duplicated in Additional\n")
		} else {
			addSignerKeyToAdditional(msg, clientKey, keyTTL)
		}
	}

	fmt.Printf("\nAdded UPDATE-LEASE EDNS option\n")
	fmt.Printf("  ✓ Added UPDATE-LEASE EDNS option\n")
	fmt.Printf("    LEASE: %d seconds\n", leaseDuration)
	fmt.Printf("    KEY-LEASE: %d seconds\n", keyLeaseDuration)

	// Sign with SIG(0)
	fmt.Printf("\nSigning with SIG(0)\n")
	fmt.Printf("  Message before signing:\n")
	fmt.Printf("    Question: %d\n", len(msg.Question))
	fmt.Printf("    Answer: %d\n", len(msg.Answer))
	fmt.Printf("    Ns: %d\n", len(msg.Ns))
	fmt.Printf("    Extra: %d\n", len(msg.Extra))
	fmt.Printf("    Pseudo: %d\n", len(msg.Pseudo))
	for i, rr := range msg.Extra {
		fmt.Printf("      Extra[%d]: %T = %v\n", i, rr, rr)
	}

	signedMsg, err := sig0.SignMessage(msg, clientKey.PublicKey, clientKey.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to sign message: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Message after signing:\n")
	fmt.Printf("    Question: %d\n", len(signedMsg.Question))
	fmt.Printf("    Answer: %d\n", len(signedMsg.Answer))
	fmt.Printf("    Ns: %d\n", len(signedMsg.Ns))
	fmt.Printf("    Extra: %d\n", len(signedMsg.Extra))
	fmt.Printf("    Pseudo: %d\n", len(signedMsg.Pseudo))
	for i, rr := range signedMsg.Extra {
		fmt.Printf("      Extra[%d]: %T\n", i, rr)
	}
	for i, rr := range signedMsg.Pseudo {
		fmt.Printf("      Pseudo[%d]: %T\n", i, rr)
	}
	fmt.Printf("  ✓ Message signed with SIG(0)\n")
	fmt.Printf("    Signer: %s\n", clientKey.PublicKey.Hdr.Name)
	fmt.Printf("    Algorithm: %d\n", clientKey.PublicKey.Algorithm)

	if tamper {
		fmt.Printf("\nTampering signed payload\n")
		if err := flipOnePayloadBit(signedMsg); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to tamper signed message: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  ✓ Flipped one bit in payload KEY RDATA after signing\n")
	}

	// Send to proxy
	fmt.Printf("\nSending to proxy (%s) over %s\n", proxyAddr, req.Transport)

	// Check message before packing
	fmt.Printf("  Message structure before sending:\n")
	fmt.Printf("    Extra: %d records\n", len(signedMsg.Extra))
	fmt.Printf("    Pseudo: %d records\n", len(signedMsg.Pseudo))

	// Pack to see what gets sent
	if err := signedMsg.Pack(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Pack failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("    Packed size: %d bytes\n", len(signedMsg.Data))

	c := client.New(proxyAddr, req.Transport.String(), 20*time.Second)
	resp, err := c.Query(signedMsg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to send query: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✓ Response received\n")

	// Display response
	fmt.Printf("\nResponse from proxy\n")
	fmt.Printf("  Status: %s (Rcode=%d)\n", dns.RcodeToString[resp.Rcode], resp.Rcode)
	fmt.Printf("  Flags: AA=%v, RD=%v, RA=%v\n", resp.Authoritative, resp.RecursionDesired, resp.RecursionAvailable)

	if resp.Rcode == dns.RcodeSuccess {
		effectiveLease, effectiveKeyLease := client.EffectiveLeaseDuration(resp, leaseDuration, keyLeaseDuration)
		fmt.Printf("\n✓ %s SUCCESSFUL\n", strings.ToUpper(operation))
		fmt.Printf("  Lease granted for: %s\n", keyname)
		fmt.Printf("  Lease duration: %d seconds (%d minutes)", effectiveLease, effectiveLease/60)
		if effectiveLease != leaseDuration {
			fmt.Printf(" (requested %d, changed by proxy)", leaseDuration)
		}
		fmt.Println()
		fmt.Printf("  Key-lease duration: %d seconds (%d minutes)", effectiveKeyLease, effectiveKeyLease/60)
		if effectiveKeyLease != keyLeaseDuration {
			fmt.Printf(" (requested %d, changed by proxy)", keyLeaseDuration)
		}
		fmt.Println()
		dataExpiry, keyExpiry := client.ExpiryFromResponse(time.Now(), leaseDuration, keyLeaseDuration, resp)
		fmt.Printf("  Data expiration time: %s\n", dataExpiry.Format(time.RFC3339))
		fmt.Printf("  Key expiration time: %s\n", keyExpiry.Format(time.RFC3339))
		printExtendedErrors(resp)
	} else {
		fmt.Printf("\n✗ %s FAILED\n", strings.ToUpper(operation))
		fmt.Printf("  Response code: %s\n", dns.RcodeToString[resp.Rcode])
		printExtendedErrors(resp)
		os.Exit(1)
	}
}

// cmdName keeps one name registered through client/rfc9664, as sig0lease-srp-client keeps
// a host through client/srp: the name, one label below the zone, with its own key, its
// addresses and records; or it registers, withdraws or deregisters them once.
func cmdName(args []string) {
	fs := newFlagSet("name")
	var req cli.Request
	var modes cli.Modes
	req.Define(fs, proxyUsage)
	modes.Define(fs, "the name: its records go, and its KEY too unless -keep-names")
	zone := fs.String("zone", "", "the proxy's zone, its update_handler's upstream_zone (required)")
	label := fs.String("name", "", "the name's label, one below the zone (required)")
	withdraw := fs.Bool("withdraw", false, "send one withdrawal of the -addr and -record records and exit, keeping the name and anything else it has")
	var addrs, records cli.Repeatable
	fs.Var(&addrs, "addr", "an address of the name: an A or AAAA record at it (repeatable)")
	fs.Var(&records, "record", `a record "<owner> <type> <data>", the owner @ for the name itself or relative to it (repeatable)`)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	switch {
	case *zone == "" || *label == "":
		cli.Fail(fmt.Errorf("-zone and -name are required"))
	case fs.NArg() != 0:
		cli.Fail(fmt.Errorf("unexpected arguments %q: everything is a flag", fs.Args()))
	case *withdraw && (modes.Once || modes.Deregister):
		cli.Fail(fmt.Errorf("-withdraw, -once and -deregister are different requests: give one"))
	}
	for _, check := range []func() error{req.Check, req.RequireServer, modes.Check} {
		if err := check(); err != nil {
			cli.Fail(err)
		}
	}

	name := *label + "." + dnsutil.Fqdn(*zone)
	var problems []string
	var parsed []netip.Addr
	for _, a := range addrs {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			problems = append(problems, fmt.Sprintf("-addr %q: %v", a, err))
			continue
		}
		parsed = append(parsed, addr)
	}
	recs := rfc9664.ParseRecords(name, records, func(_ int, err error) {
		problems = append(problems, fmt.Sprintf("-record %v", err))
	})
	if len(problems) > 0 {
		cli.Fail(fmt.Errorf("%s", strings.Join(problems, "; ")))
	}
	all := rfc9664.WithAddresses(name, parsed, recs)

	key, err := req.Key(name)
	if err != nil {
		cli.Fail(err)
	}
	c, err := rfc9664.NewClient(rfc9664.Config{
		Zone:              *zone,
		Label:             *label,
		Key:               key,
		Records:           all,
		RequestedLease:    uint32(req.Lease),
		RequestedKeyLease: uint32(req.KeyLease),
		TTL:               uint32(req.TTL),
		Server:            req.Server,
		Network:           req.Transport,
		OnRegistered: func(resp *dns.Msg) {
			fmt.Print(cli.Stamp())
			cli.PrintReply(resp, client.OutcomeSuccess)
		},
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "%sERROR: %v\n", cli.Stamp(), err)
		},
	})
	if err != nil {
		cli.Fail(err)
	}

	fmt.Printf("=== sig0lease-client name ===\n")
	fmt.Printf("Name: %s\n", name)
	fmt.Printf("Key: %s (algorithm %d, keytag %d)\n", key.Name, key.PublicKey.Algorithm, key.PublicKey.KeyTag())
	fmt.Printf("Proxy: %s over %s\n", req.Server, req.Transport)
	for _, rr := range all {
		fmt.Printf("Record: %s\n", rfc9664.Describe(rr))
	}
	fmt.Println()

	if *withdraw {
		cli.Exit(c.Withdraw(context.Background(), all))
		return
	}
	modes.Run(c)
}

// printExtendedErrors prints the Extended DNS Errors (RFC 8914) in resp, if the proxy sent
// any: the reason for a failure, or a success's status notes.
func printExtendedErrors(resp *dns.Msg) {
	if len(dnsmsg.EDEs(resp)) == 0 {
		return
	}
	fmt.Printf("\nExtended DNS Errors:\n")
	cli.PrintEDEs(resp)
}

func flipOnePayloadBit(msg *dns.Msg) error {
	for _, rr := range msg.Ns {
		key, ok := rr.(*dns.KEY)
		if !ok {
			continue
		}
		pub, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil {
			return fmt.Errorf("decode KEY public key: %w", err)
		}
		if len(pub) == 0 {
			return fmt.Errorf("empty KEY public key")
		}
		pub[0] ^= 0x01
		key.PublicKey = base64.StdEncoding.EncodeToString(pub)
		return nil
	}

	for _, rr := range msg.Extra {
		key, ok := rr.(*dns.KEY)
		if !ok {
			continue
		}
		pub, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil {
			return fmt.Errorf("decode KEY public key: %w", err)
		}
		if len(pub) == 0 {
			return fmt.Errorf("empty KEY public key")
		}
		pub[0] ^= 0x01
		key.PublicKey = base64.StdEncoding.EncodeToString(pub)
		return nil
	}

	return fmt.Errorf("no KEY RR found in update or additional payload")
}

// cmdVerify checks if a key registration is active
func cmdVerify(args []string) {
	fs := newFlagSet("verify")
	var to cli.Endpoint
	to.Define(fs, proxyUsage)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if err := to.RequireServer(); err != nil {
		cli.Fail(err)
	}
	if fs.NArg() != 1 {
		cli.Fail(fmt.Errorf("give one name: verify [flags] <name>"))
	}
	proxyAddr, protocol, zone := to.Server, to.Transport.String(), fs.Arg(0)

	fmt.Printf("=== Verifying Key Registration ===\n")
	fmt.Printf("Proxy: %s\n", proxyAddr)
	fmt.Printf("Zone: %s\n", zone)
	fmt.Printf("Protocol: %s\n", protocol)

	// Send a standard query for the key record
	msg := dns.NewMsg(zone, dns.TypeKEY)
	c := client.New(proxyAddr, protocol, 20*time.Second)
	resp, err := c.Query(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Query failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Response from proxy:\n")
	fmt.Printf("  Status: %s (Rcode=%d)\n", dns.RcodeToString[resp.Rcode], resp.Rcode)

	if len(resp.Answer) > 0 {
		fmt.Printf("  ✓ Key found in answer section:\n")
		for _, rr := range resp.Answer {
			if key, ok := rr.(*dns.KEY); ok {
				fmt.Printf("    Name: %s\n", key.Hdr.Name)
				// The TTL the proxy gave the record, not its lease: the proxy keeps the
				// two apart (record_ttl_sec), and a query has no way to learn the lease.
				fmt.Printf("    TTL: %d\n", key.Hdr.TTL)
				fmt.Printf("    Algorithm: %d\n", key.Algorithm)
				fmt.Printf("    KeyTag: %d\n", key.KeyTag())
			} else {
				fmt.Printf("    %s\n", rr.String())
			}
		}
	} else {
		fmt.Printf("  ✗ Key not found (no answer records)\n")
	}
}

// cmdListKeys lists available keys in the keystore
func cmdListKeys(args []string) {
	fs := newFlagSet("list-keys")
	var keystore string
	cli.DefineKeystore(fs, &keystore)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		cli.Fail(fmt.Errorf("list-keys takes no arguments"))
	}
	dir, err := cli.KeystoreDir(keystore)
	if err != nil {
		cli.Fail(err)
	}

	fmt.Printf("=== Available Keys in Keystore ===\n")
	fmt.Printf("Directory: %s\n\n", dir)
	keyFiles, err := keyrec.ListKeysInDirectory(dir, nil)
	if err != nil {
		fmt.Printf("Error: %v)\n", err)
		return
	}
	if len(keyFiles) == 0 {
		fmt.Printf("No keys found in keystore\n")
		return
	}

	fmt.Printf("Found %d key(s):\n\n", len(keyFiles))

	for _, keyName := range keyFiles {
		loadedKey, err := keyrec.LoadKeyFromFile(dir, keyName)
		if err != nil {
			fmt.Printf("  ✗ %s (failed to load: %v)\n", keyName, err)
			continue
		}
		loadedKey.Print()

	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `sig0lease-client - RFC 9664 client of the sig0lease proxy (dev/test tool)

Usage:
  sig0lease-client <command> [flags] [args]

Flags come before the arguments. They are spelled as sig0lease-srp-client's.

Commands:
  name [flags]
      Keep one name registered through client/rfc9664, as sig0lease-srp-client keeps a host:
      the name, one label below the proxy's zone, with its own key, its addresses and records,
      refreshed on the lease clock until Ctrl-C. A name another key holds is tried again
      with a backoff, never renamed.

      -zone string        the proxy's zone, its update_handler's upstream_zone (required)
      -name string        the name's label (required)
      -addr value         an address of the name, as an A or AAAA record at it (repeatable)
      -record value       a record "<owner> <type> <data>", the owner @ for the name itself or
                          relative to it: '_dnslink TXT "dnslink=/ipfs/bafy..."',
                          "www CNAME site.dev.zenr.io." (repeatable)
      -once               send one registration and exit
      -withdraw           send one withdrawal of the -addr and -record records and exit, keeping
                          the name and anything else it has (Case D)
      -deregister         send one deregistration and exit: the records and the KEY go, so the
                          name is free (Case C), unless -keep-names keeps the KEY (Case D)
      -keep-names         with -deregister: keep the name for the key, asking for -key-lease

      Plus the request flags below; the key is the name's own, in the keystore.

      sig0lease-client name -server 127.0.0.1:8053 -zone dev.zenr.io. -name mysite -k 13 \
        -addr 192.0.2.10 -record '_dnslink TXT "dnslink=/ipfs/bafy..."'

  register [flags] <keyname> [rr-spec...]
  refresh [flags] <keyname> [rr-spec...]
  register-tamper [flags] <keyname> [rr-spec...]
      Send exactly the update described, the shapes the proxy must refuse included: the
      KEY and other records given, signed with keyname's key, on -lease and -key-lease.
      register-tamper flips one bit of it after signing; refresh differs from register only
      in the name it prints.

      keyname             without -k, the exact file name of a key in the keystore
                          (Ktest.dev.zenr.io.+015+05044); with -k, an owner name
                          (test.dev.zenr.io.) whose key is found or generated
      rr-spec             a record in zone-file format, "<owner> <ttl> <class> <type> <rdata>"
      -signer string      where the signer's KEY goes: update (a KEY rr-spec for it must be
                          given), additional, or none (the proxy must find it in its lease store
                          or the authoritative DNS). Default: additional, unless a KEY rr-spec
                          for it is among the rr-specs
      -same-key           add the signing key's own KEY to the Update section, to lease it
                          without typing its rr-spec; not with a KEY rr-spec for it, nor
                          -signer none
      -zone string        the Zone Section, any name enclosing the update's names (default: the
                          signing key's name)

      Plus the request flags below; -ttl is the TTL of the KEYs the command builds from the
      signing key (-same-key, -signer additional), rr-specs carry their own.

      The proxy dispatches on the two leases and requires records to match:
        KEY-LEASE != 0, LEASE != 0   at least one KEY and one other record
        KEY-LEASE = 0,  LEASE != 0   other records only, the signer already leased
        KEY-LEASE != 0, LEASE = 0    at least one KEY
        both 0                        KEYs only: delete them and what they registered

      // Lease the signing key itself (-lease 0): -same-key adds its KEY
      sig0lease-client register -server 127.0.0.1:8053 -lease 0 -key-lease 3600 -same-key \
        Ktest.dev.zenr.io.+015+05044
      // The key and a record
      sig0lease-client register -server 127.0.0.1:8053 -lease 300 -key-lease 3600 -same-key \
        Ktest.dev.zenr.io.+015+05044 'client.test.dev.zenr.io. 300 IN TXT "hello"'
      // A record signed by a key already leased, the key left out of the request
      sig0lease-client register -server 127.0.0.1:8053 -lease 300 -key-lease 0 -signer none \
        Ktest.dev.zenr.io.+015+05044 'client.test.dev.zenr.io. 300 IN TXT "hello"'
      // Another key, registered by the signer, whose KEY goes to Additional
      sig0lease-client register -server 127.0.0.1:8053 -lease 0 -key-lease 3600 \
        Ktest.dev.zenr.io.+015+05044 "client.test.dev.zenr.io. 3600 IN KEY 512 3 15 c2yG..."
      // -k 13: an owner name, its ECDSAP256SHA256 key generated on first use
      sig0lease-client register -server 127.0.0.1:8053 -lease 0 -key-lease 3600 -same-key -k 13 \
        test.dev.zenr.io.

  verify [-server host:port] [-transport tcp|udp|tls] <name>
      Ask the proxy for the KEY at name.

  list-keys [-keystore dir]
      List the keys in the keystore.

Request flags (name, register, refresh, register-tamper):
  -server string          the proxy's "host:port" (required; its DoT address with -transport tls)
  -transport string       tcp (default), udp or tls: DNS over TLS (RFC 7858), opportunistic, so
                          the proxy's certificate is not checked
  -keystore string        directory holding the signing keys (default $CLIENT_KEYSTORE_DIR; one
                          of the two is required)
  -k uint                 DNSSEC algorithm (13=ECDSAP256SHA256, 15=ED25519) to generate a key
                          with when none exists; left out, a missing key is an error
  -lease uint             LEASE to ask for, in seconds (default 3600)
  -key-lease uint         KEY-LEASE to ask for, in seconds (default 1209600)
  -ttl uint               TTL suggested for the records the command builds, in seconds (default
                          300); independent of the leases, and the proxy may override it
`)
}
