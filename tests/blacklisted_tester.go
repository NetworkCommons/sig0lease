package main

// Package main implements a blacklisted RR type tester for the sig0lease proxy.
//
// This tool constructs NULL and NXNAME records programmatically (which cannot be
// parsed from DNS presentation format strings) and sends them to the proxy as
// registration requests. The proxy should reject these with RcodeFormatError
// because they are blacklisted for registration.
//
// Build with ldflags to inject test parameters:
//
// 	go build -ldflags="-X main.rrType=NULL -X main.rrOwner=test.dev.zenr.io. -X main.leaseDuration=30 -X main.keyLeaseSec=30 -X main.proxyAddr=127.0.0.1:8053 -X main.zone=test.dev.zenr.io." ./tests/blacklisted_tester.go

import (
	"fmt"
	"os"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/NetworkCommons/sig0lease/client"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

var (
	rrType        string // NULL or NXNAME
	rrOwner       string // owner name for the RR
	leaseDuration uint32 = 30
	keyLeaseSec   uint32 = 30
	proxyAddr     string // proxy address (e.g., 127.0.0.1:8053)
	zone          string // downstream zone
	keystoreDir   string = os.Getenv("CLIENT_KEYSTORE_DIR")
)

func main() {
	if rrType == "" || rrOwner == "" || proxyAddr == "" || zone == "" {
		fmt.Fprintf(os.Stderr, "ERROR: Missing required parameters.\n")
		fmt.Fprintf(os.Stderr, "Usage: build with -ldflags=\"-X main.rrType=... -X main.rrOwner=... -X main.proxyAddr=... -X main.zone=...\"\n")
		os.Exit(1)
	}

	// Validate rrType
	if rrType != "NULL" && rrType != "NXNAME" {
		fmt.Fprintf(os.Stderr, "ERROR: rrType must be NULL or NXNAME, got %q\n", rrType)
		os.Exit(1)
	}

	fmt.Printf("=== Blacklisted RR Type Tester ===\n")
	fmt.Printf("RR Type: %s\n", rrType)
	fmt.Printf("RR Owner: %s\n", rrOwner)
	fmt.Printf("Zone: %s\n", zone)
	fmt.Printf("Proxy: %s\n", proxyAddr)
	fmt.Printf("Lease: %d seconds\n", leaseDuration)
	fmt.Printf("Key-Lease: %d seconds\n", keyLeaseSec)
	fmt.Printf("\n")

	// Step 1: Load client key by keyname
	fmt.Printf("Step 1: Loading client key for key name (%s) from keystore (%s)\n", rrOwner, keystoreDir)
	if keystoreDir == "" {
		fmt.Fprintf(os.Stderr, "ERROR: CLIENT_KEYSTORE_DIR environment variable not set\n")
		os.Exit(1)
	}

	clientKeyName, err := keyrec.FindKeyByZone(keystoreDir, rrOwner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not find client key for key name %s: %v\n", rrOwner, err)
		os.Exit(1)
	}
	fmt.Printf("  Found client key: %s\n", clientKeyName)

	clientKey, err := keyrec.LoadKeyFromFiles(keystoreDir, clientKeyName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to load client key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✓ Loaded successfully\n")
	fmt.Printf("    Algorithm: %d (15=ED25519)\n", clientKey.PublicKey.Algorithm)
	fmt.Printf("    KeyTag: %d\n", clientKey.PublicKey.KeyTag())

	// Step 2: Build KEY RR for Authority section
	keyRR := new(dns.KEY)
	keyRR.Hdr.Name = rrOwner
	keyRR.Hdr.Class = dns.ClassINET
	keyRR.Hdr.TTL = keyLeaseSec
	keyRR.Flags = clientKey.PublicKey.Flags
	keyRR.Protocol = clientKey.PublicKey.Protocol
	keyRR.Algorithm = clientKey.PublicKey.Algorithm
	keyRR.PublicKey = clientKey.PublicKey.PublicKey
	fmt.Printf("  ✓ KEY RR: %s\n", keyRR.String())

	// Step 3: Construct the blacklisted RR programmatically (bypassing ParseAdditionalRRSpec)
	fmt.Printf("\nStep 2: Constructing blacklisted RR (%s)\n", rrType)
	var additionalRR dns.RR

	switch rrType {
	case "NULL":
		// NULL RR: dns.NULL embeds rdata.NULL with Null string field
		// Field name is NULL (capital), containing rdata.NULL struct with Null string field
		nullRR := &dns.NULL{
			Hdr: dns.Header{
				Name:  rrOwner,
				Class: dns.ClassINET,
				TTL:   leaseDuration,
			},
			NULL: rdata.NULL{Null: "\x00\x01"},
		}
		additionalRR = nullRR
		fmt.Printf("  ✓ Constructed NULL RR: owner=%s class=%d ttl=%d\n", rrOwner, dns.ClassINET, leaseDuration)

	case "NXNAME":
		// NXNAME RR: has NO rdata (no struct to embed), only Header
		nxnameRR := &dns.NXNAME{
			Hdr: dns.Header{
				Name:  rrOwner,
				Class: dns.ClassINET,
				TTL:   leaseDuration,
			},
		}
		additionalRR = nxnameRR
		fmt.Printf("  ✓ Constructed NXNAME RR: owner=%s class=%d ttl=%d (no rdata)\n", rrOwner, dns.ClassINET, leaseDuration)
	}

	// Step 4: Build registration UPDATE message
	fmt.Printf("\nStep 3: Building UPDATE message payload\n")
	msg, err := dnsmsg.NewRegistrationUpdate(zone, keyRR, []dns.RR{additionalRR}, leaseDuration, keyLeaseSec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to build registration update packet: %v\n", err)
		os.Exit(1)
	}

	// Step 5: Sign with SIG(0)
	fmt.Printf("\nStep 4: Signing with SIG(0)\n")
	signedMsg, err := sig0.SignMessage(msg, clientKey.PublicKey, clientKey.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to sign message: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✓ Message signed with SIG(0)\n")
	fmt.Printf("    Signer: %s\n", clientKey.PublicKey.Hdr.Name)
	fmt.Printf("    Algorithm: %d\n", clientKey.PublicKey.Algorithm)

	// Step 6: Send to proxy
	fmt.Printf("\nStep 5: Sending to proxy (%s)\n", proxyAddr)

	if err := signedMsg.Pack(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Pack failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("    Packed size: %d bytes\n", len(signedMsg.Data))

	c := client.New(proxyAddr, "udp", 20*time.Second)
	resp, err := c.Query(signedMsg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to send query: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✓ Response received\n")

	// Step 7: Display response
	fmt.Printf("\nStep 6: Response from proxy\n")
	fmt.Printf("  Status: %s (Rcode=%d)\n", dns.RcodeToString[resp.Rcode], resp.Rcode)
	fmt.Printf("  Flags: AA=%v, RD=%v, RA=%v\n", resp.Authoritative, resp.RecursionDesired, resp.RecursionAvailable)

	if resp.Rcode == dns.RcodeSuccess {
		fmt.Printf("\n✗ REGISTRATION SUCCEEDED (expected rejection)\n")
		os.Exit(1)
	} else {
		fmt.Printf("\n✓ REGISTRATION REJECTED (Rcode=%d: %s)\n", resp.Rcode, dns.RcodeToString[resp.Rcode])
		if len(resp.Answer) > 0 {
			fmt.Printf("\nAnswer Section:\n")
			for _, rr := range resp.Answer {
				fmt.Printf("  %s\n", rr.String())
			}
		}
		if len(resp.Ns) > 0 {
			fmt.Printf("\nAuthority Section:\n")
			for _, rr := range resp.Ns {
				fmt.Printf("  %s\n", rr.String())
			}
		}
	}
}
