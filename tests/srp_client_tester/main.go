// Package main implements a minimal RFC 9665 SRP UPDATE test client, used only by
// tests/test_srp.sh. This mirrors tests/blacklisted_tester.go's precedent: a small Go
// helper for something the shell alone can't do (build, sign, and send a real SRP UPDATE)
// and no existing binary did yet at the time this was written -- client/srp and
// cmd/sig0lease-srp-client were not built yet. This is deliberately NOT that client: no
// discovery, no refresh scheduler, no
// YXDOMAIN rename-retry -- just enough to drive test_srp.sh's scenarios.
//
// Identity is a P-256 (ECDSAP256SHA256) key pair persisted as a raw private-key file at
// -keyfile: created on first use, reused on subsequent calls (so a shell test case can
// control fresh-vs-reuse identity simply by removing or keeping that file between calls).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	"codeberg.org/miekg/dns"
	_ "github.com/NetworkCommons/sig0lease/pkg/dnscompat"
	"github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

// loadOrCreateKey loads a P-256 private key from path, generating and saving a new one if
// the file doesn't exist yet. Returns the private key and its raw marshaled public point
// (Marshal's leading 0x04 byte included -- callers slice it off for the KEY RR wire form).
func loadOrCreateKey(path string) (*ecdsa.PrivateKey, []byte) {
	if data, err := os.ReadFile(path); err == nil {
		priv, err := x509.ParseECPrivateKey(data)
		must(err)
		return priv, elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	der, err := x509.MarshalECPrivateKey(priv)
	must(err)
	must(os.WriteFile(path, der, 0600))
	return priv, elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
}

// inst2svctype derives an instance's base service type from its own FQDN by stripping the
// leading instance-name label -- e.g. "Widget._http._tcp.srp.test." -> "_http._tcp.srp.test.".
func inst2svctype(inst string) string {
	parts := strings.SplitN(inst, ".", 2)
	if len(parts) != 2 {
		return inst
	}
	return parts[1]
}

func main() {
	server := flag.String("server", "127.0.0.1:8059", "proxy address")
	zone := flag.String("zone", "srp.test.", "SRP zone (Zone Section)")
	host := flag.String("host", "", "host FQDN (required)")
	addr := flag.String("addr", "192.0.2.1", "host A record address; empty = host removal (no address adds)")
	inst := flag.String("inst", "", "service instance FQDN; empty = host-only update")
	port := flag.Int("port", 8080, "SRV port for -inst")
	txt := flag.String("txt", "path=/", "TXT content for -inst")
	svctype := flag.String("svctype", "", "PTR owner (service type) FQDN for -inst; defaults to inst's own base type")
	instRemove := flag.Bool("inst-remove", false, "make -inst removal-shaped (bare delete-all, no SRV/TXT/PTR)")
	leaseSec := flag.Uint("lease", 30, "LEASE seconds")
	keyLeaseSec := flag.Uint("keylease", 1209600, "KEY-LEASE seconds")
	keyFile := flag.String("keyfile", "", "path to this identity's persisted private key (created on first use; required)")
	tcp := flag.Bool("tcp", true, "use TCP (SRP requires TCP by default unless allow_udp)")
	flag.Parse()

	if *host == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "USAGE: -host and -keyfile are required")
		os.Exit(1)
	}

	priv, pub := loadOrCreateKey(*keyFile)

	keyRR := func(name string) *dns.KEY {
		k := &dns.KEY{}
		k.Hdr = dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600}
		k.Protocol = 3
		k.Algorithm = dns.ECDSAP256SHA256
		k.PublicKey = base64.StdEncoding.EncodeToString(pub[1:])
		return k
	}
	deleteAll := func(name string) *dns.ANY {
		return &dns.ANY{Hdr: dns.Header{Name: name, Class: dns.ClassANY, TTL: 0}}
	}

	msg := dns.NewMsg(*zone, dns.TypeSOA)
	msg.Opcode = dns.OpcodeUpdate
	msg.Ns = append(msg.Ns, deleteAll(*host))
	if *addr != "" {
		a, err := dns.New(fmt.Sprintf("%s 3600 IN A %s", *host, *addr))
		must(err)
		msg.Ns = append(msg.Ns, a)
	}
	msg.Ns = append(msg.Ns, keyRR(*host))

	if *inst != "" {
		msg.Ns = append(msg.Ns, deleteAll(*inst))
		if !*instRemove {
			srv, err := dns.New(fmt.Sprintf("%s 3600 IN SRV 0 0 %d %s", *inst, *port, *host))
			must(err)
			txtRR, err := dns.New(fmt.Sprintf(`%s 3600 IN TXT "%s"`, *inst, *txt))
			must(err)
			msg.Ns = append(msg.Ns, srv, txtRR)

			st := *svctype
			if st == "" {
				st = inst2svctype(*inst)
			}
			ptr, err := dns.New(fmt.Sprintf("%s 3600 IN PTR %s", st, *inst))
			must(err)
			msg.Ns = append(msg.Ns, ptr)
		}
	}

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(4096)
	lo := lease.Encode8Byte(uint32(*leaseSec), uint32(*keyLeaseSec))
	must(lo.Encode(opt))
	msg.Extra = append(msg.Extra, opt)

	signed, err := sig0.SignMessage(msg, keyRR(*host), priv)
	must(err)

	network := "udp"
	if *tcp {
		network = "tcp"
	}
	resp, err := dns.Exchange(context.Background(), signed, network, *server)
	must(err)

	fmt.Printf("Status: %s (Rcode=%d)\n", dns.RcodeToString[resp.Rcode], resp.Rcode)
	if erfc, ok := lease.FindOption(resp); ok {
		var got lease.LeaseOption
		if err := got.Decode(&dns.OPT{Options: []dns.EDNS0{erfc}}); err == nil {
			kl := "nil"
			if got.KeyLease != nil {
				kl = fmt.Sprintf("%d", *got.KeyLease)
			}
			fmt.Printf("Granted: LEASE=%d KEY-LEASE=%s\n", got.Lease, kl)
		}
	}
	fmt.Printf("KeyTag: %d\n", keyRR(*host).KeyTag())
	if resp.Rcode != dns.RcodeSuccess {
		os.Exit(2)
	}
}
