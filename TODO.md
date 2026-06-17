# sig0lease Proxy Implementation Plan

Based on the project documentation and standards, here's the implementation plan:

## Key Learnings from sig0namectl (to be copied)

1. **Key Management** (`sig0/keys.go`):
   - `Signer` struct with private key and update message
   - `LoadOrGenerateKey()` - FCFS style key management
   - `StartUpdate()`, `SignUpdate()`, `UpdateRR()` / `RemoveRR()` methods

2. **SIG(0) Signing** (`sig0/update.go`):
   - `SignUpdate()` creates SIG RR with proper fields
   - Uses miekg/dns library for signing
   - Handles message packing/unpacking

3. **DOH Queries** (`sig0/doh.go`):
   - `SendDOHQuery()` - DNS over HTTPS using shynome/doh-client
   - `FindDOHEndpoint()` - SVCB-based endpoint discovery

4. **Request Key Flow** (`sig0/request_key.go`):
   - SOA lookup for zone identification
   - Signal zone (_signal) query and DoH endpoint discovery
   - KEY RR registration with PTR record

5. **Query Helpers** (`sig0/query.go`, `sig0/answers.go`):
   - `QueryWithType()`, `QuerySOA()`, `QueryKEY()`
   - `AnySOA()` - flexible SOA extraction from answer sections

## sig0lease Proxy Structure

```
pkg/
├── lease/          # RFC 9664 - Update Lease EDNS(0) option
│   ├── lease.go    # LeaseOption type, encode/decode
│   └── lease_test.go
│
├── keyrec/         # RFC 2539 + RFC 4034 - KEY record (Diffie-Hellman)
│   ├── keyrec.go   # KeyRecord type with flags, protocol, algorithm
│   └── keyrec_test.go
│
├── sig0/           # RFC 2931 - SIG(0) signing & verification
│   ├── signer.go   # KeyStore interface, Signer type
│   ├── verifier.go # Verify(msg, publicKey) error
│   └── algorithm.go # Algorithm mapping (ECDSAP256SHA256 required)
│
├── srp/            # RFC 9665 - Service Registration Protocol
│   ├── server/     # SRP proxy server
│   │   ├── server.go      # Listener, Accept(update) error
│   │   ├── validate.go    # Instruction validation
│   │   └── lease_mgr.go   # Lease lifecycle tracking
│   ├── client/     # SRP client
│   │   ├── client.go      # Registrar(addr, key) type
│   │   └── refresh.go     # Refresh loop with 80% + jitter
│   ├── instruction.go # Instruction types (ptr, srv, txt, KEY)
│   └── names.go    # FCFS naming with conflict detection
│
├── dnsif/          # Abstracted DNS transport layer
│   ├── transport.go      # UpdateClient interface
│   └── upstream/         # Upstream resolver (forwarding)
│       └── resolver.go   # miekg/dns-based forwarding
│
└── discovery/      # Registrar discovery (RFC 9665 §3.1)
    ├── discover.go     # SOA-based zone apex + SRV lookup
    └── discover_test.go

cmd/
├── sig0lease-proxy/   # Main proxy binary
│   ├── main.go
│   └── config.go      # YAML config loading
└── sig0lease-client/  # SRP client (for testing)
    └── main.go
```

## First Steps Implementation Order

1. **sig0 package** - Copy key signing logic from sig0namectl:
   - Signer struct with KeyStore interface
   - SignUpdate() method for SIG(0) signing
   - Test against miekg/dns library

2. **lease package** - RFC 9664 EDNS option:
   - Encode/decode LeaseOption (4-byte and 8-byte variants)
   - Validation per RFC 9665 §3.3.2

3. **srp/instruction.go** - DNS-SD instruction construction:
   - ServiceDiscovery, ServiceDescription, HostDescription types
   - Wire format assembly for RFC 9665 §3.3.1

4. **dnsif/upstream/resolver.go** - Forwarding to upstream:
   - miekg/dns-based forwarder (already started)
   - Add SIG(0) signing option before forwarding

## Implementation Notes

- sig0namectl uses `github.com/shynome/doh-client` for DoH
- We should use standard `github.com/miekg/dns` throughout
- The handler architecture in sig0lease_proxy should wrap these packages:
  - Handlers are distinct modules that can be registered
  - Each handler implements the Handler interface
  - Handlers receive DNS messages, process them, and return responses
