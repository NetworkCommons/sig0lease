// Package main implements a sig0lease client for sending UPDATE-LEASE requests
// with SIG(0) authentication to the sig0lease proxy.
//
// Usage:
//
//	sig0lease-client <proxy> <command> [args...]
//
// Commands:
//
//	register <zone> <keyname> [lease] [key-lease]
//	  Send a sig0lease UPDATE-LEASE registration request
//	  zone: downstream zone (e.g., test.dev.zenr.io.)
//	  keyname: key name to register (e.g., client.test.dev.zenr.io.)
//	  lease: lease duration in seconds (default: 300)
//	  key-lease: key-lease duration in seconds (default: 3600)
//
//	verify <zone> <keyname>
//	  Query if a key registration is active
//
//	list-keys <keystore-dir>
//	  List available keys in keystore
//
// Examples:
//
//	sig0lease-client 127.0.0.1:8053 register test.dev.zenr.io. client.test.dev.zenr.io.
//	sig0lease-client 127.0.0.1:8053 register test.dev.zenr.io. client.test.dev.zenr.io. 300 3600
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/config"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/lease"
)

var (
	defaultLease    = uint32(300)  // 5 minutes
	defaultKeyLease = uint32(3600) // 1 hour
	keystoreDir     = ""           // Will be loaded from config
)

func init() {
	// Try to load keystore from environment first (highest priority)
	keystoreDir = os.Getenv("KEYSTORE_DIR")
	if keystoreDir != "" {
		return
	}

	// Try to load from config.yaml (second priority)
	cfg, err := config.LoadConfig("config.yaml")
	if err == nil {
		keystoreDir = cfg.GetKeystoreDir()
	}

	// No fallback - keystore path must be explicitly configured
	if keystoreDir == "" {
		fmt.Fprintf(os.Stderr, "ERROR: keystore_dir is required but not configured\n")
		fmt.Fprintf(os.Stderr, "Configure via:\n")
		fmt.Fprintf(os.Stderr, "  1. KEYSTORE_DIR environment variable, or\n")
		fmt.Fprintf(os.Stderr, "  2. keystore_dir in config.yaml (handlers.update.keystore_dir)\n")
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 3 {
		printUsage()
		os.Exit(1)
	}

	proxyAddr := os.Args[1]
	command := os.Args[2]

	switch command {
	case "register":
		cmdRegister(proxyAddr, os.Args[3:])
	case "verify":
		cmdVerify(proxyAddr, os.Args[3:])
	case "list-keys":
		cmdListKeys(os.Args[3:])
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

// cmdRegister sends a sig0lease UPDATE-LEASE registration request
func cmdRegister(proxyAddr string, args []string) {
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: sig0lease-client <proxy> register <zone> <keyname> [lease] [key-lease]\n")
		os.Exit(1)
	}

	zone := args[0]
	keyname := args[1]

	// Parse optional lease durations
	leaseDuration := uint32(defaultLease)
	keyLeaseDuration := uint32(defaultKeyLease)

	if len(args) > 2 {
		if val, err := strconv.ParseUint(args[2], 10, 32); err == nil {
			leaseDuration = uint32(val)
		}
	}

	if len(args) > 3 {
		if val, err := strconv.ParseUint(args[3], 10, 32); err == nil {
			keyLeaseDuration = uint32(val)
		}
	}

	fmt.Printf("=== sig0lease Client Registration ===\n")
	fmt.Printf("Proxy: %s\n", proxyAddr)
	fmt.Printf("Zone: %s\n", zone)
	fmt.Printf("Key Name: %s\n", keyname)
	fmt.Printf("Lease: %d seconds\n", leaseDuration)
	fmt.Printf("Key-Lease: %d seconds\n", keyLeaseDuration)
	fmt.Printf("\n")

	// Step 1: Find and load the key from keystore
	fmt.Printf("Step 1: Loading key from keystore (%s)\n", keystoreDir)
	keyName, err := keyrec.FindKeyByZone(keystoreDir, zone)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not find key for zone %s: %v\n", zone, err)
		os.Exit(1)
	}
	fmt.Printf("  Found key: %s\n", keyName)

	loadedKey, err := keyrec.LoadKeyFromFiles(keystoreDir, keyName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to load key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✓ Loaded successfully\n")
	fmt.Printf("    Algorithm: %d (15=ED25519)\n", loadedKey.PublicKey.Algorithm)
	fmt.Printf("    KeyTag: %d\n", loadedKey.PublicKey.KeyTag())
	fmt.Printf("    Name: %s\n", loadedKey.PublicKey.Hdr.Name)

	// Step 2: Create UPDATE message for downstream zone
	fmt.Printf("\nStep 2: Creating UPDATE message\n")
	msg := dns.NewMsg(zone, dns.TypeSOA)
	msg.Opcode = dns.OpcodeUpdate
	fmt.Printf("  ✓ Created UPDATE message for zone: %s\n", zone)

	// Step 3: Add KEY RR to Authority section (UPDATE section in DNS UPDATE)
	fmt.Printf("\nStep 3: Adding KEY RR to Authority section\n")
	// Create a KEY RR with the loaded key material
	keyRR := new(dns.KEY)
	keyRR.Hdr.Name = keyname
	keyRR.Hdr.Class = dns.ClassINET
	keyRR.Hdr.TTL = keyLeaseDuration
	keyRR.Flags = loadedKey.PublicKey.Flags
	keyRR.Protocol = loadedKey.PublicKey.Protocol
	keyRR.Algorithm = loadedKey.PublicKey.Algorithm
	keyRR.PublicKey = loadedKey.PublicKey.PublicKey
	msg.Ns = append(msg.Ns, keyRR)
	fmt.Printf("  ✓ Added KEY RR: %s\n", keyRR.String())

	// Step 4: Add UPDATE-LEASE EDNS option (code 2)
	fmt.Printf("\nStep 4: Adding UPDATE-LEASE EDNS option\n")
	leaseOpt := lease.Encode8Byte(leaseDuration, keyLeaseDuration)
	if err := leaseOpt.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Invalid lease values: %v\n", err)
		os.Exit(1)
	}

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	if err := leaseOpt.Encode(opt); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to encode lease option: %v\n", err)
		os.Exit(1)
	}
	msg.Extra = append(msg.Extra, opt)
	fmt.Printf("  ✓ Added UPDATE-LEASE EDNS option\n")
	fmt.Printf("    LEASE: %d seconds\n", leaseDuration)
	fmt.Printf("    KEY-LEASE: %d seconds\n", keyLeaseDuration)

	// Step 5: Sign with SIG(0)
	fmt.Printf("\nStep 5: Signing with SIG(0)\n")
	fmt.Printf("  Message before signing:\n")
	fmt.Printf("    Question: %d\n", len(msg.Question))
	fmt.Printf("    Answer: %d\n", len(msg.Answer))
	fmt.Printf("    Ns: %d\n", len(msg.Ns))
	fmt.Printf("    Extra: %d\n", len(msg.Extra))
	fmt.Printf("    Pseudo: %d\n", len(msg.Pseudo))
	for i, rr := range msg.Extra {
		fmt.Printf("      Extra[%d]: %T = %v\n", i, rr, rr)
	}

	signer, err := client.NewSig0Signer(loadedKey.PublicKey, loadedKey.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to create signer: %v\n", err)
		os.Exit(1)
	}

	signedMsg, err := signer.SignMessage(msg)
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
	fmt.Printf("    Signer: %s\n", loadedKey.PublicKey.Hdr.Name)
	fmt.Printf("    Algorithm: %d\n", loadedKey.PublicKey.Algorithm)

	// Step 6: Send to proxy
	fmt.Printf("\nStep 6: Sending to proxy (%s)\n", proxyAddr)

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

	c := client.New(proxyAddr, "udp", 5*time.Second)
	resp, err := c.Query(signedMsg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to send query: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✓ Response received\n")

	// Step 7: Display response
	fmt.Printf("\nStep 7: Response from proxy\n")
	fmt.Printf("  Status: %s (Rcode=%d)\n", dns.RcodeToString[resp.Rcode], resp.Rcode)
	fmt.Printf("  Flags: AA=%v, RD=%v, RA=%v\n", resp.Authoritative, resp.RecursionDesired, resp.RecursionAvailable)

	if resp.Rcode == dns.RcodeSuccess {
		fmt.Printf("\n✓ REGISTRATION SUCCESSFUL\n")
		fmt.Printf("  Lease granted for: %s\n", keyname)
		fmt.Printf("  Lease duration: %d seconds (%d minutes)\n", leaseDuration, leaseDuration/60)
		fmt.Printf("  Key-lease duration: %d seconds (%d hours)\n", keyLeaseDuration, keyLeaseDuration/3600)
		fmt.Printf("  Expiration time: %s\n", time.Now().Add(time.Duration(leaseDuration)*time.Second).Format(time.RFC3339))

		if len(resp.Answer) > 0 {
			fmt.Printf("\nAnswer Section:\n")
			for _, rr := range resp.Answer {
				fmt.Printf("  %s\n", rr.String())
			}
		}
	} else {
		fmt.Printf("\n✗ REGISTRATION FAILED\n")
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

// cmdVerify checks if a key registration is active
func cmdVerify(proxyAddr string, args []string) {
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: sig0lease-client <proxy> verify <zone> <keyname>\n")
		os.Exit(1)
	}

	zone := args[0]
	keyname := args[1]

	fmt.Printf("=== Verifying Key Registration ===\n")
	fmt.Printf("Proxy: %s\n", proxyAddr)
	fmt.Printf("Zone: %s\n", zone)
	fmt.Printf("Key Name: %s\n\n", keyname)

	// Send a standard query for the key record
	msg := dns.NewMsg(keyname, dns.TypeKEY)
	c := client.New(proxyAddr, "udp", 5*time.Second)
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
func cmdListKeys(args []string) {
	dir := keystoreDir
	if len(args) > 0 && args[0] != "" {
		dir = args[0]
	}

	fmt.Printf("=== Available Keys in Keystore ===\n")
	fmt.Printf("Directory: %s\n\n", dir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to read keystore: %v\n", err)
		os.Exit(1)
	}

	keyFiles := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".key") {
			baseName := strings.TrimSuffix(name, ".key")
			keyFiles[baseName] = true
		}
	}

	if len(keyFiles) == 0 {
		fmt.Printf("No keys found in keystore\n")
		return
	}

	fmt.Printf("Found %d key(s):\n\n", len(keyFiles))

	for keyName := range keyFiles {
		loadedKey, err := keyrec.LoadKeyFromFiles(dir, keyName)
		if err != nil {
			fmt.Printf("  ✗ %s (failed to load: %v)\n", keyName, err)
			continue
		}

		fmt.Printf("  %s\n", keyName)
		fmt.Printf("    Zone: %s\n", loadedKey.PublicKey.Hdr.Name)
		fmt.Printf("    Algorithm: %d (15=ED25519)\n", loadedKey.PublicKey.Algorithm)
		fmt.Printf("    KeyTag: %d\n", loadedKey.PublicKey.KeyTag())
		fmt.Printf("    Flags: %d\n", loadedKey.PublicKey.Flags)

		// Check for private key
		if loadedKey.PrivateKey != nil {
			fmt.Printf("    Private key: ✓ Available\n")
		} else {
			fmt.Printf("    Private key: ✗ Not available\n")
		}
		fmt.Printf("\n")
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `
sig0lease Client - Register and verify DNS UPDATE-LEASE requests with SIG(0) authentication

Usage:
  sig0lease-client <proxy> <command> [args...]

Commands:
  register <zone> <keyname> [lease] [key-lease]
    Send a sig0lease UPDATE-LEASE registration request
    
    zone: downstream zone (e.g., test.dev.zenr.io.)
    keyname: key name to register (e.g., client.test.dev.zenr.io.)
    lease: lease duration in seconds (default: 300)
    key-lease: key-lease duration in seconds (default: 3600)
    
    Example:
      sig0lease-client 127.0.0.1:8053 register test.dev.zenr.io. client.test.dev.zenr.io.
      sig0lease-client 127.0.0.1:8053 register test.dev.zenr.io. client.test.dev.zenr.io. 300 3600

  verify <zone> <keyname>
    Query if a key registration is active
    
    Example:
      sig0lease-client 127.0.0.1:8053 verify test.dev.zenr.io. client.test.dev.zenr.io.

  list-keys [keystore-dir]
    List available keys in keystore
    
    Example:
      sig0lease-client dummy list-keys
      sig0lease-client dummy list-keys /path/to/keystore

  help
    Show this help message

Examples:

  1. List available keys:
     sig0lease-client dummy list-keys

  2. Register a client key with default lease (5 min) and key-lease (1 hour):
     sig0lease-client 127.0.0.1:8053 register test.dev.zenr.io. client.test.dev.zenr.io.

  3. Register with custom durations (10 min lease, 24 hour key-lease):
     sig0lease-client 127.0.0.1:8053 register test.dev.zenr.io. client.test.dev.zenr.io. 600 86400

  4. Verify a registration:
     sig0lease-client 127.0.0.1:8053 verify test.dev.zenr.io. client.test.dev.zenr.io.

Environment:
  KEYSTORE_DIR: Keystore directory path (required - must be set via environment or config.yaml)
`)
}
