# sig0lease — Package Architecture

Agent module for automated DNS-SD service registration using the Service Registration Protocol (SRP) with SIG(0) and TSIG authentication, targeting a `golang.org/x/dns` / `miekg/dns`-based Go implementation against a BIND 9 test server.

## Directory Layout

```
agent/
├── go.mod
├── main.go                      # bootstrap (dev only — removed at project start)
│
├── pkg/                          # public library packages (imported by tests / consumers)
│   ├── lease/                    # RFC 9664 — Update Lease EDNS(0) option
│   │   ├── lease.go              # LeaseOption type, wire encode/decode, 4-byte & 8-byte variants
│   │   └── lease_test.go         # property-based: all combinations of 4/8 byte / min/max values
│   │
│   ├── keyrec/                   # RFC 2539 + RFC 4034 — KEY record (Diffie-Hellman storage in DNS)
│   │   ├── keyrec.go             # KeyRecord type with flags, protocol, algorithm, public key
│   │   └── keyrec_test.go        # encode/decode round-trip; invalid flag values rejected
│   │
│   ├── sig0/                     # RFC 2931 — SIG(0) request/response signing
│   │   ├── signer.go             # KeyStore interface, Signer type (sign DNS message with private key)
│   │   ├── verifier.go           # Verify(msg, publicKey) error — validates SIG(0) RRs
│   │   └── algorithm.go          # ECDSAP256SHA256 (algorithm 13) and TSIG algorithm map
│   │                               # per RFC 9665 §6.6: ECDSAP256SHA256 required, others optional
│   │   ├── signer_test.go
│   │   ├── verifier_test.go
│   │   └── algorithm_test.go
│   │
│   ├── srp/                      # RFC 9665 — Service Registration Protocol (core domain logic)
│   │   ├── server/               # SRP proxy server: parses, validates, forwards SRP updates
│   │   │   ├── server.go         # Listener, Accept(update) error — validates instructions per §3.3
│   │   │   ├── validate.go       # Instruction validation: ServiceDiscovery / ServiceDescription / HostDescription
│   │   │   ├── lease_mgr.go      # Lease lifecycle tracking (in-memory map for proto)
│   │   │   └── server_test.go
│   │   │
│   │   ├── client/               # SRP client: generates, signs, sends leases to registrar
│   │   │   ├── client.go         # Registrar(addr, key) type — Dial, Register(Service) error
│   │   │   ├── refresh.go        # Refresh loop with 80% + random jitter per RFC 9664 §5.2
│   │   │   └── client_test.go
│   │   │
│   │   ├── instruction.go        # Instruction types (ptr, srv, txt, KEY) and wire assembly
│   │   ├── instruction_test.go   # construct valid/invalid updates; RFC 9665 §3.3 constraints
│   │   └── names.go              # FCFS naming: conflict detection, name generation per §3.2.4.1
│   │                               # + §3.2.5.2 (append number on YXDomain)
│   │
│   ├── dnsif/                    # Abstracted DNS transport layer — decouples proto from BIND 9 specifics
│   │   ├── transport.go          # UpdateClient interface: SendUpdate(context, *dns.Msg) (*dns.Msg, error)
│   │   └── bind9/                # BIND 9 specific implementation
│   │       ├── bind9.go          # TCP conn to authoritative zone; TSIG & SIG(0) support
│   │       └── bind9_test.go
│   │
│   └── discovery/                # SRP registrar / domain discovery (RFC 9665 §3.1, §11 of RFC 6763)
│       ├── discover.go           # SOA-based zone apex discovery + _dnssd-srp._tcp SRV lookup
│       └── discover_test.go
│
├── cmd/                          # executables (thin wrappers over pkg/)
│   └── sig0lease-server/         # SRP proxy server CLI
│       ├── main.go
│       └── config.go             # Config struct + YAML/TOML loader
│
├── testdata/                     # Test fixtures — keys, zone files, BIND configs
│   ├── keys/                     # SIG(0) ECDSA P-256 key pairs (PEM/PKCS#8)
│   │   ├── host1.pem             # private + public for FCFS naming tests
│   │   └── host2.pem
│   ├── zones/                    # Zone file templates for BIND 9 test server
│   │   ├── default-service.arpa.zone
│   │   └── reverse.zone
│   └── bind.conf                 # Minimal BIND 9 configuration for testing
│
├── docs/
│   ├── project.md                # Project description (existing)
│   ├── rfc9665.txt               # SRP RFC (existing)
│   ├── rfc9664.txt               # Update Lease RFC (existing)
│   ├── rfc2931.txt               # SIG(0) RFC (existing)
│   ├── rfc9460.txt               # SVCB/HTTPS RFC (existing, informational)
│   ├── dns-parameters.txt        # IANA DNS parameters (existing, reference)
│   ├── architecture.md           # This file
│   └── tests.md                  # Test plan (separate document)
│
└── .claude/                      # Claude Code config
```

## Package Relationships & RFC Traceability

Each package is designed to have a single responsible RFC or standard. Cross-cutting concerns are collected in `sig0` and `dnsif`.

### 1. `pkg/lease` — Update Lease Option (RFC 9664)

**Responsible standard**: RFC 9664 §4 — "Lease Update Request and Response Format"

| Responsibility | Detail |
|---|---|
| Wire format | EDNS(0) OPT RR option, OPTION-CODE=2. 4-byte (LEASE only) or 8-byte (LEASE + KEY-LEASE) variants. |
| API surface | `type LeaseOption struct { Lease uint32; KeyLease *uint32 }` — `Encode(*dns.OPTRR)` / `Decode(*dns.OPTRR) error` |
| Validation | LEASE ≤ KEY-LEASE (required by RFC 9665 §3.3.2). Values in network byte order. |
| Non-responsibilities | Lease storage, expiry scheduling, garbage collection — those are server concerns (`srp/server/lease_mgr`). |

**Tests**: Encode/decode round-trips for both variants; reject malformed (wrong option-code, truncated data); min/max boundary values per RFC 9664 §8.

### 2. `pkg/keyrec` — KEY Record Type (RFC 2539, RFC 4034)

**Responsible standards**: RFC 2539 (Diffie-Hellman KEY), RFC 4034 §4 (KEY RR for DNSSEC).

| Responsibility | Detail |
|---|---|
| Wire format | KEY RR with flags=0, protocol=3 (DH), algorithm per key type. |
| API surface | `type KeyRecord struct { Flags uint16; Protocol uint8; Algorithm uint8; PublicKey []byte }` — Encode/Decode to/from `*dns.KEY`. |
| Constraints | Per RFC 9665 §3.2.5.1: flags MUST be zero in SRP context. One KEY per Host Description + one (optional) per Service Description, all holding the same public key. |

**Tests**: Encode/decode round-trips; reject non-zero flags for SRP use; verify PublicKey is non-nil for valid keys.

### 3. `pkg/sig0` — SIG(0) Signing & Verification (RFC 2931)

**Responsible standard**: RFC 2931 — "DNS Request and Transaction Signatures (SIG(0)s)".

| Responsibility | Detail |
|---|---|
| API surface | `type KeyStore interface { PrivateKey() crypto.PrivateKey; PublicKey() dns.PublicKey }`<br>`type Signer struct { Store KeyStore }` — `Sign(msg *dns.Msg) (*dns.SIG, error)`<br>`func Verify(msg *dns.Msg, pub dns.PublicKey) error` |
| Algorithms | **Required**: ECDSAP256SHA256 (algorithm 13). Per RFC 9665 §6.6: registrars MUST implement this. Other algorithms per RFC 8624 are optional ("SHOULD").<br>**TSIG**: Also support HMAC-SHA256 for TSIG-based authentication as an alternative path. |
| Interaction with miekg/dns | Use `dns.StartSIG(msg, sig)` / `dns.InsertRR(msg, sig)` or manually build the SIG RR in the Additional section. |

**Tests**: Sign a valid message → verify succeeds. Verify with wrong key → error. Multiple algorithms: test ECDSAP256SHA256 is always accepted; others are rejected if not configured. TSIG path: sign/verify with HMAC-SHA256. Time-window validation (SIG validity period).

### 4. `pkg/srp/instruction.go` — DNS-SD Instruction Construction (RFC 9665 §3.3.1)

**Responsible standard**: RFC 9665 §3.3.1 — "Validation of DNS Update Add and Delete RRs".

| Responsibility | Detail |
|---|---|
| Service Discovery Instruction | Exactly one PTR RR: `_<service>._tcp.<zone>.` → `<instance>._ipps._tcp.` (example). Per §3.3.1.1. |
| Service Description Instruction | DeleteAll + optional KEY + optional SRV + required TXT. Per §3.3.1.2. |
| Host Description Instruction | DeleteAll + exactly one KEY + zero or more A/AAAA. Per §3.3.1.3. |
| Wire assembly | Builds a single `*dns.Msg` with Zone section + Update RRs (no prerequisites per §3.2.3). |

**Tests**: Construct valid instructions for all three types; verify assembled message structure. Attempt to build invalid instructions — assert rejection: missing KEY, wrong RR type count, prerequisites present, etc. Edge cases: compressed SRV target (§3.2.5.4), no SRV but existing KEY check.

### 5. `pkg/srp/names.go` — FCFS Naming (RFC 9665 §3.2.4.1, §3.2.5.2)

**Responsible standard**: RFC 9665 §3.2.4.1 + §3.2.5.2.

| Responsibility | Detail |
|---|---|
| Name generation | Given a preferred name, produce `<name>.default.service.arpa.` or `<name>-<N>.default.service.arpa.` on conflict. |
| Conflict handling | YXDomain RCODE → increment number or pick random suffix. No circular retry if Refused (dictionary-blocked names). |

**Tests**: Preferred name available → returns it. Name taken → returns incremented variant. Refused name → stops incrementing, returns error.

### 6. `pkg/srp/server/` — SRP Proxy Server (RFC 9665 §3.2–§3.3, §4, §5)

**Responsible standard**: RFC 9665 §3.2 (Protocol Details), §3.3 (Validation), §4 (TTL Consistency), §5 (Lease Maintenance).

| Responsibility | Detail |
|---|---|
| Listener | TCP listener (and optionally TLS per §7) accepting SRP updates from requesters. |
| Validation pipeline | 1. Parse DNS Update (§3.3.1). 2. Validate instructions as ServiceDiscovery/ServiceDescription/HostDescription (§3.3.1.1–1.3). 3. Validate update requirements (§3.3.2: no prerequisites, must have Update Lease). 4. FCFS name + SIG(0) validation (§3.3.3). |
| Lease management | Track KEY-LEASE and LEASE timers; garbage-collect stale records after expiry (RFC 9664 §7). |
| Response | Send back RCODE + optional Update Lease option in response (RFC 9665 §3.3.5). |
| Forwarding | Delegates authoritative zone update to `dnsif.UpdateClient` (BIND 9 or stub). |

**Tests**: Valid registration → NoError with granted lease. Name conflict → YXDomain. Missing KEY → Refused (§3.3.2). TTL inconsistency → Refused (§4). Expired lease → garbage collect and stop serving record. TSIG auth path: validate TSIG before processing.

### 7. `pkg/srp/client/` — SRP Client (RFC 9665 §3.2.5, RFC 9664 §4–§5)

**Responsible standard**: RFC 9665 §3.2.5 (SRP Requester Behavior), RFC 9664 §4–§5 (Registration/Refresh).

| Responsibility | Detail |
|---|---|
| Registration | Build + sign SRP update with instructions for one hostname + N services → send via `dnsif`. Handle response RCODE. On YXDomain, try alternate name (§3.2.5.2). |
| Refresh loop | Schedule refresh at 80% of granted lease + random(0–5%) jitter per RFC 9664 §5.2. Re-dial if connection lost. |
| Lease negotiation | Honor server-granted leases (may differ from requested) per RFC 9664 §4.2/§5.2. |

**Tests**: Happy-path register → verify message sent, response parsed. Refresh scheduling: verify refresh fires at correct time. YXDomain handling: try alternate name. Server unresponsive: retry strategy per RFC 9664 §5.2/§6.

### 8. `pkg/dnsif/` — Transport Abstraction

| Responsibility | Detail |
|---|---|
| Interface | `type UpdateClient interface { SendUpdate(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) }` |
| BIND 9 impl | TCP connection to BIND 9 test server zone; supports TSIG (HMAC-SHA256) and SIG(0) signing. |

**Tests**: Bind9 transport: round-trip update through real BIND 9 instance (integration test in `testdata/`).

### 9. `pkg/discovery/` — Registrar Discovery

| Responsibility | Detail |
|---|---|
| Zone apex | SOA-based discovery per RFC 8765 §6.1. |
| SRP registrar | Query `_dnssd-srp._tcp.<zone>.` (or `_dnssd-srp-tls._tcp.<zone>.`) SRV record per RFC 9665 §3.1.1. |

**Tests**: SOA walk for zone apex. SRV record lookup returning registrar addr:port.

---

## RFC-to-Package Traceability Table

| Package | Primary RFC(s) | Secondary / Reference |
|---|---|---|
| `pkg/lease` | 9664 §4 | |
| `pkg/keyrec` | 2539, 4034 | |
| `pkg/sig0/signer` | 2931 | 8624 (algorithm requirements) |
| `pkg/sig0/verifier` | 2931 §4–§5 | 8624 |
| `pkg/srp/instruction` | 9665 §3.3.1 | 2136 (DNS Update wire format), 6763 (DNS-SD) |
| `pkg/srp/names` | 9665 §3.2.4.1, §3.2.5.2 | |
| `pkg/srp/server` | 9665 §3.2–§3.3, §4, §5, §7 (TLS) | 9664 §7 (garbage collection), 8945 (TSIG path) |
| `pkg/srp/client` | 9665 §3.2.5 | 9664 §4–§5, 1035 (UDP retransmission) |
| `pkg/dnsif/bind9` | 2136 | 8945 (TSIG), 7858 (DoT if applicable) |
| `pkg/discovery` | 9665 §3.1, §11 of RFC 6763 | 8765 §6.1 (zone apex) |

---

## Dependencies

| Dependency | Purpose |
|---|---|
| `github.com/miekg/dns` | DNS wire format, message building, RR types (recommended by project) |
| Standard library `crypto/ecdsa`, `crypto/tls`, `encoding/binary` | SIG(0) signing, TLS transport, lease encoding |
| (optional) `gopkg.in/yaml.v3` or `github.com/pelletier/go-toml/v2` | Server config parsing for `cmd/sig0lease-server` |
