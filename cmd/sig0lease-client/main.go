// Package main implements a sig0lease client for sending UPDATE-LEASE requests
// with SIG(0) authentication to the sig0lease proxy.
package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

var (
	keystoreDir = ""
)

func main() {
	if len(os.Args) < 3 {
		printUsage()
		os.Exit(1)
	}

	proxyAddr := os.Args[1]
	command := os.Args[2]
	args, keystoreFlag := extractKeystoreFlag(os.Args[3:])

	switch command {
	case "register":
		keystoreDir = resolveKeystoreDir(keystoreFlag)
		cmdRegister(proxyAddr, args)
	case "refresh":
		keystoreDir = resolveKeystoreDir(keystoreFlag)
		cmdRefresh(proxyAddr, args)
	case "register-tamper":
		keystoreDir = resolveKeystoreDir(keystoreFlag)
		cmdRegisterTamper(proxyAddr, args)
	case "verify":
		cmdVerify(proxyAddr, args)
	case "list-keys":
		keystoreDir = resolveKeystoreDir(keystoreFlag)
		cmdListKeys()
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

// extractKeystoreFlag pulls a --keystore=<dir> token out of args, wherever it appears,
// returning the remaining positional args and the flag's value (empty if not given).
func extractKeystoreFlag(args []string) ([]string, string) {
	const prefix = "--keystore="
	dir := ""
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			dir = strings.TrimPrefix(a, prefix)
			continue
		}
		out = append(out, a)
	}
	return out, dir
}

// resolveKeystoreDir applies this project's unified keystore-location convention (same on
// both cmd/sig0lease-client and cmd/sig0lease-srp-client): an explicit --keystore= flag wins,
// CLIENT_KEYSTORE_DIR is the fallback, and having neither is a fatal error.
func resolveKeystoreDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("CLIENT_KEYSTORE_DIR"); env != "" {
		return env
	}
	fmt.Fprintf(os.Stderr, "ERROR: keystore directory is required: pass --keystore=<dir> or set CLIENT_KEYSTORE_DIR\n")
	os.Exit(1)
	return ""
}

// cmdRegister sends a sig0lease UPDATE-LEASE registration request
func cmdRegister(proxyAddr string, args []string) {
	cmdRegRefWithMode(proxyAddr, args, "register", false)
}

// cmdRegisterTamper sends a registration request but flips one bit in payload after signing.
func cmdRegisterTamper(proxyAddr string, args []string) {
	cmdRegRefWithMode(proxyAddr, args, "register", true)
}
func cmdRefresh(proxyAddr string, args []string) {
	cmdRegRefWithMode(proxyAddr, args, "refresh", false)
}

// Signer key placement modes for --signer=<mode>. These exercise the three
// ways the proxy can resolve a signer's KEY material: present directly in
// the request (update or additional section), or absent from the request
// entirely (resolved via the lease store or authoritative DNS instead).
const (
	signerLocationAuto       = "auto" // default: additional, unless a matching KEY rr-spec is already in Update
	signerLocationUpdate     = "update"
	signerLocationAdditional = "additional"
	signerLocationNone       = "none"
)

// extractSignerLocationFlag pulls a --signer=<mode> token out of args,
// wherever it appears, returning the remaining positional args and the
// requested mode (signerLocationAuto if not specified).
func extractSignerLocationFlag(args []string) ([]string, string) {
	const prefix = "--signer="
	location := signerLocationAuto
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			location = strings.TrimPrefix(a, prefix)
			continue
		}
		out = append(out, a)
	}
	return out, location
}

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

func addSignerKeyToAdditional(msg *dns.Msg, clientKey *keyrec.LoadedKey, keyLeaseDuration uint32) {
	signingKeyRR := keyRRFromClientKey(clientKey, keyLeaseDuration)
	msg.Extra = append(msg.Extra, signingKeyRR)
	fmt.Printf("  ✓ Added signer KEY RR to Additional section: %s\n", signingKeyRR.String())
}

// extractSameKeyFlag pulls a bare --same-key token out of args, wherever it
// appears, returning the remaining positional args and whether it was set.
func extractSameKeyFlag(args []string) ([]string, bool) {
	const flag = "--same-key"
	sameKey := false
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == flag {
			sameKey = true
			continue
		}
		out = append(out, a)
	}
	return out, sameKey
}

// extractKeyAlgFlag pulls a --k=<algorithm> token out of args, wherever it appears,
// returning the remaining positional args, the parsed algorithm, and whether it was given.
// When given, keyname (cmdRegRefWithMode's first positional arg) is treated as an owner
// name to find-or-create a key for, rather than an exact keystore filename -- see that
// function's own doc comment.
func extractKeyAlgFlag(args []string) ([]string, uint8, bool) {
	const prefix = "--k="
	out := make([]string, 0, len(args))
	var alg uint8
	var provided bool
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			v := strings.TrimPrefix(a, prefix)
			n, err := strconv.ParseUint(v, 10, 8)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: invalid --k=%s: %v\n", v, err)
				os.Exit(1)
			}
			alg = uint8(n)
			provided = true
			continue
		}
		out = append(out, a)
	}
	return out, alg, provided
}

// extractTCPFlag pulls a bare --tcp token out of args, wherever it appears,
// returning the remaining positional args and whether it was set. Absent,
// the client uses UDP (client.New's own default).
func extractTCPFlag(args []string) ([]string, bool) {
	const flag = "--tcp"
	useTCP := false
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == flag {
			useTCP = true
			continue
		}
		out = append(out, a)
	}
	return out, useTCP
}

// queryProtocol maps --tcp's presence to the protocol string client.New expects.
func queryProtocol(useTCP bool) string {
	if useTCP {
		return "tcp"
	}
	return "udp"
}

func cmdRegRefWithMode(proxyAddr string, args []string, operation string, tamper bool) {
	args, signerLocation := extractSignerLocationFlag(args)
	switch signerLocation {
	case signerLocationAuto, signerLocationUpdate, signerLocationAdditional, signerLocationNone:
	default:
		fmt.Fprintf(os.Stderr, "ERROR: invalid --signer=%s (expected update|additional|none)\n", signerLocation)
		os.Exit(1)
	}
	args, sameKey := extractSameKeyFlag(args)
	args, useTCP := extractTCPFlag(args)
	args, keyAlg, keyAlgProvided := extractKeyAlgFlag(args)

	if len(args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: sig0lease-client <proxy> register|register-tamper|refresh <keyname> [lease] [key-lease] [rr-spec...] [--signer=update|additional|none] [--same-key] [--tcp] [--k=<algorithm>]\n")
		os.Exit(1)
	}

	keyname := args[0]

	// Parse lease durations and optional rr-spec(s).
	var keyLeaseDuration, leaseDuration uint32
	if val, err := strconv.ParseUint(args[1], 10, 32); err == nil {
		leaseDuration = uint32(val)
	} else {
		fmt.Fprintf(os.Stderr, "ERROR: Invalid lease duration %s: %v\n", args[1], err)
		os.Exit(1)
	}

	if val, err := strconv.ParseUint(args[2], 10, 32); err == nil {
		keyLeaseDuration = uint32(val)
	} else {
		fmt.Fprintf(os.Stderr, "ERROR: Invalid key-lease duration %s: %v\n", args[1], err)
		os.Exit(1)
	}

	rrSpecs := args[3:]
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

	// Load (or, with --k=<algorithm>, find-or-create) the client key used for SIG(0) signing.
	// Without --k, keyname is the exact on-disk key filename, as it always has been --
	// zero behavior change for existing callers. With --k, keyname is instead an owner
	// name (e.g. "test.dev.zenr.io."): any existing key for that name is reused regardless
	// of its algorithm, and a new one is generated at --k's algorithm only if none exists.
	var clientKey *keyrec.LoadedKey
	if keyAlgProvided {
		fmt.Printf("Resolving client key for owner name (%s) from keystore (%s), creating with algorithm %d if not found\n", keyname, keystoreDir, keyAlg)
		k, created, err := keyrec.ResolveOrCreateKey(keystoreDir, keyname, keyAlg, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		clientKey = k
		if created {
			fmt.Printf("  ✓ Generated new client key: %s\n", clientKey.Name)
		} else {
			fmt.Printf("  ✓ Found existing client key: %s\n", clientKey.Name)
		}
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

	if sameKey {
		for _, rr := range updateKeyRRs {
			if strings.EqualFold(rr.Hdr.Name, clientKey.KeyName()) {
				fmt.Fprintf(os.Stderr, "ERROR: --same-key conflicts with an explicit KEY rr-spec for %s already among the rr-spec arguments\n", clientKey.KeyName())
				os.Exit(1)
			}
		}
		if signerLocation == signerLocationNone {
			fmt.Fprintf(os.Stderr, "ERROR: --same-key conflicts with --signer=none: the signing key must appear in the Update section\n")
			os.Exit(1)
		}
		updateKeyRRs = append(updateKeyRRs, keyRRFromClientKey(clientKey, keyLeaseDuration))
		fmt.Printf("  ✓ --same-key: reusing signing key %s as the Update-section lease payload\n", clientKey.KeyName())
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

	// the zone is the name of the key, zone := clientKey.PublicKey.Hdr.Name
	msg, err := dnsmsg.NewLeaseUpdate(clientKey.KeyName(), updateKeyRRs, updateOtherRRs, leaseDuration, keyLeaseDuration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to build update packet for %s: %v\n", operation, err)
		os.Exit(1)
	}

	signerKeyInUpdate := false
	for _, rr := range updateKeyRRs {
		if rr == nil {
			continue
		}
		if strings.EqualFold(rr.Hdr.Name, clientKey.KeyName()) &&
			rr.Flags == clientKey.PublicKey.Flags &&
			rr.Protocol == clientKey.PublicKey.Protocol &&
			rr.Algorithm == clientKey.PublicKey.Algorithm &&
			strings.TrimSpace(rr.PublicKey) == strings.TrimSpace(clientKey.PublicKey.PublicKey) {
			signerKeyInUpdate = true
			break
		}
	}

	fmt.Printf("\nSigner KEY placement: --signer=%s\n", signerLocation)
	switch signerLocation {
	case signerLocationUpdate:
		if !signerKeyInUpdate {
			fmt.Fprintf(os.Stderr, "ERROR: --signer=update requires a KEY rr-spec for %s among the rr-spec arguments\n", clientKey.KeyName())
			os.Exit(1)
		}
		fmt.Printf("  ✓ Signer KEY RR present in Update section\n")
	case signerLocationAdditional:
		addSignerKeyToAdditional(msg, clientKey, keyLeaseDuration)
	case signerLocationNone:
		if signerKeyInUpdate {
			fmt.Fprintf(os.Stderr, "ERROR: --signer=none conflicts with a KEY rr-spec for %s already among the rr-spec arguments\n", clientKey.KeyName())
			os.Exit(1)
		}
		fmt.Printf("  ✓ Signer KEY RR omitted from request; proxy must resolve it via the lease store or authoritative DNS\n")
	case signerLocationAuto:
		if signerKeyInUpdate {
			fmt.Printf("  ✓ Signer KEY RR already present in Authority section; not duplicated in Additional\n")
		} else {
			addSignerKeyToAdditional(msg, clientKey, keyLeaseDuration)
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
	protocol := queryProtocol(useTCP)
	fmt.Printf("\nSending to proxy (%s) over %s\n", proxyAddr, protocol)

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

	c := client.New(proxyAddr, protocol, 20*time.Second)
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

		if len(resp.Answer) > 0 {
			fmt.Printf("\nAnswer Section:\n")
			for _, rr := range resp.Answer {
				fmt.Printf("  %s\n", rr.String())
			}
		}
	} else {
		fmt.Printf("\n✗ %s FAILED\n", strings.ToUpper(operation))
		fmt.Printf("  Response code: %s\n", dns.RcodeToString[resp.Rcode])

		if len(resp.Answer) > 0 {
			fmt.Printf("\nAnswer Section:\n")
			for _, rr := range resp.Answer {
				fmt.Printf("  %s\n", rr.String())
			}
		}
		os.Exit(1)
	}
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
func cmdVerify(proxyAddr string, args []string) {
	args, useTCP := extractTCPFlag(args)
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: sig0lease-client <proxy> verify <zone> [--tcp]\n")
		os.Exit(1)
	}

	zone := args[0]
	protocol := queryProtocol(useTCP)

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
				fmt.Printf("    TTL: %d (expires in %d seconds)\n", key.Hdr.TTL, key.Hdr.TTL)
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
func cmdListKeys() {
	dir := keystoreDir

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
	fmt.Fprintf(os.Stderr, `
sig0lease Client - Register and verify DNS UPDATE-LEASE requests with SIG(0) authentication

Usage:
  sig0lease-client <proxy> <command> [args...]

Commands:
	register <keyname> [lease] [key-lease] [rr-spec...] [--signer=update|additional|none] [--same-key] [--tcp] [--k=<algorithm>]
		Send a sig0lease UPDATE-LEASE registration request

		keyname: without --k, the exact filename of an existing key in the keystore
			(e.g., Ktest.dev.zenr.io.+015+05044) -- unchanged from before, must already
			exist. With --k, an owner name instead (e.g., test.dev.zenr.io.) -- see --k.
		lease: lease duration in seconds
		key-lease: key-lease duration in seconds
			rr-spec: optional additional RR in DNS presentation format:
				<owner> <ttl> <class> <type> <rdata...>
			--signer: where the signer's KEY RR should appear in the request. Tests the
				proxy's signer resolution: request-provided (--signer=update/additional) vs.
				resolved server-side (lease store or authoritative DNS if --signer=none).
					update:     signer's own KEY rr-spec must also be passed; no Additional copy
					additional: signer KEY is placed in the Additional section (default when
					            no matching KEY rr-spec is given)
					none:       signer KEY is omitted entirely; proxy must resolve it from the
					            lease store or authoritative DNS
			--same-key: lease the same key used to sign the request, without retyping its
				KEY rr-spec. Builds the KEY RR from the loaded signing key and adds it to
				the Update section; conflicts with an explicit KEY rr-spec for the same
				name and with --signer=none.
			--tcp: send the request over TCP instead of the default UDP.
			--k=<algorithm>: DNSSEC algorithm (13=ECDSAP256SHA256, 15=ED25519) to generate
				a NEW signing key with if keyname (read as an owner name when --k is
				given) doesn't have one in the keystore yet. Any existing key for that
				owner name is reused regardless of algorithm; omit --k entirely to keep
				keyname meaning an exact filename that must already exist (the default,
				unchanged behavior). Same convention as sig0lease-srp-client's -k.

		Note: the server dispatches on the LEASE/KEY-LEASE combination and
		requires specific RR kinds to be present for each (handlers/opcode5_handle.go):
			KEY-LEASE!=0 and LEASE!=0: requires >=1 KEY RR and >=1 non-KEY RR
			KEY-LEASE=0  and LEASE!=0: requires >=1 non-KEY RR and 0 KEY RRs (signer must already be managed)
			KEY-LEASE!=0 and LEASE=0:  requires >=1 KEY RR (KEY-only lease)
		A duration with no matching RR present is rejected, not silently ignored.

		Example:
		// Key-only registration: lease the signing key itself (LEASE=0, KEY-LEASE!=0);
		// --same-key supplies the required KEY RR without retyping it
		sig0lease-client 127.0.0.1:8053 register Ktest.dev.zenr.io.+015+05044 0 3600 --same-key
		// Same, repeating the key (no --same-key): the KEY rr-spec must be typed
		// out in full
		sig0lease-client 127.0.0.1:8053 register Ktest.dev.zenr.io.+015+05044 0 3600 "test.dev.zenr.io. 3600 IN KEY 512 3 15 s1Uf18NtAIacuPDIgMdw2SJ//8fm+xjLb5MPWqwxqzQ="
		// Key and other RRs registration (LEASE!=0 and KEY-LEASE!=0 requires both kinds present)
		sig0lease-client 127.0.0.1:8053 register Ktest.dev.zenr.io.+015+05044 300 3600 --same-key "client.test.dev.zenr.io. 300 IN TXT \"hello\""
		// Non-KEY-only registration signed by an already-managed key, key omitted from the request
		sig0lease-client 127.0.0.1:8053 register Ktest.dev.zenr.io.+015+05044 300 0 --signer=none "client.test.dev.zenr.io. 300 IN TXT \"hello\""
		// Register a different key than the one signing the request (delegation),
		// without --same-key: only the other key is leased, and the signer's own
		// KEY RR is added to Additional so the proxy can still verify it
		sig0lease-client 127.0.0.1:8053 register Ktest.dev.zenr.io.+015+05044 0 3600 "client.test.dev.zenr.io. 3600 IN KEY 512 3 15 c2yGNXxlrWu1LX/n9AqrCp+rIbm9FWcotgnMomlrM2E="
		// Same, but also register the signer's own key-lease in the same request via
		// --same-key: both KEY RRs end up in the Update section, no Additional copy
		sig0lease-client 127.0.0.1:8053 register Ktest.dev.zenr.io.+015+05044 0 3600 --same-key "client.test.dev.zenr.io. 3600 IN KEY 512 3 15 c2yGNXxlrWu1LX/n9AqrCp+rIbm9FWcotgnMomlrM2E="
		// Same request over TCP instead of UDP
		sig0lease-client 127.0.0.1:8053 register Ktest.dev.zenr.io.+015+05044 0 3600 --same-key --tcp
		// --k=13: keyname is an owner name here, not a filename -- generates an
		// ECDSAP256SHA256 key on first run (reused on every later run for the same name)
		sig0lease-client 127.0.0.1:8053 register test.dev.zenr.io. 0 3600 --same-key --k=13

	refresh <keyname> [lease] [key-lease] [rr-spec...] [--signer=update|additional|none] [--same-key] [--tcp] [--k=<algorithm>]
		Send a sig0lease UPDATE-LEASE refresh request (8-byte variant)

		keyname: filename of the key in the keystore (e.g., Ktest.dev.zenr.io.+015+05044)
		lease: new lease duration in seconds
		key-lease: key-lease duration in seconds
		--signer: see register above
		--same-key: see register above
		--tcp: see register above
		--k: see register above

		Example:
		// Key-only refresh: renew the signing key's own lease (LEASE=0, KEY-LEASE!=0);
		// --same-key supplies the required KEY RR without retyping it
        sig0lease-client 127.0.0.1:8053 refresh Ktest.dev.zenr.io.+015+05044 0 3600 --same-key
	    // Key and other RRs refresh (LEASE!=0 and KEY-LEASE!=0 requires both kinds present)
        sig0lease-client 127.0.0.1:8053 refresh Ktest.dev.zenr.io.+015+05044 300 3600 --same-key "client.test.dev.zenr.io. 300 IN TXT \"hello\""

		All the other register examples above (repetitive KEY rr-spec form,
		non-KEY-only with --signer=none, registering a different key with and
		without --same-key) apply the same way to refresh; just substitute the
		command name.


  verify <zone> [--tcp]
    Query if a key registration is active

    --tcp: send the query over TCP instead of the default UDP.

    Example:
      sig0lease-client 127.0.0.1:8053 verify test.dev.zenr.io.
      sig0lease-client 127.0.0.1:8053 verify test.dev.zenr.io. --tcp

  list-keys [--keystore=<dir>]
    List available keys in keystore

    Example:
      sig0lease-client dummy list-keys --keystore=./keystore/client

  help
    Show this help message

Keystore location (register, refresh, register-tamper, list-keys):
  --keystore=<dir>: directory holding client keys. If omitted, falls back to the
    CLIENT_KEYSTORE_DIR environment variable. One of the two is required; an explicit
    flag always wins over the environment variable. Same convention as sig0lease-srp-client's
    -keystore flag / CLIENT_KEYSTORE_DIR fallback.

Environment:
  CLIENT_KEYSTORE_DIR: fallback keystore directory path, used when --keystore= is not given.
`)
}
