# Proxy

Proxy is a DNS proxy for SIG(0)-authenticated UPDATE-LEASE registration flows, according to [RFC 9664](https://datatracker.ietf.org/doc/rfc9664/) and [RFC 2931](https://datatracker.ietf.org/doc/rfc2931/). It accepts DNS UPDATE packets, validates the downstream SIG(0) signature, applies the lease/update policy, and forwards the resulting UPDATE to the authoritative server selected for the zone.

The code also supports standard DNS routing for packets that are not relevant to this flow.


## What It Does

The project is intended to provide a light, explicit control point for lease registration traffic:

- Receive DNS queries over UDP and TCP.
- Route the registration opcode to the update handler and forward unrelated traffic upstream.
- Process DNS UPDATE requests carrying an UPDATE-LEASE EDNS option.
- Verify downstream SIG(0) signatures before the proxy accepts the request.
- Re-sign the upstream UPDATE with the proxy's zone key before forwarding.
- Forward unhandled opcodes to the configured upstream resolver path.

## Main Commands

Build the server and client:

```bash
make build
make build-client
```

Run the proxy with a config file:

```bash
make run-server
```

or directly:

```bash
./bin/<your OS>/sig0lease ./config.yaml
```

Run the client against a proxy:

```bash
make run-client ADDR=127.0.0.1:8053 CMD="register test.dev.zenr.io. test.dev.zenr.io."
```

The client requires an explicit keystore directory:

```bash
CLIENT_KEYSTORE_DIR=/path/to/keystore ./bin/<your OS>/sig0lease-client 127.0.0.1:8053 register test.dev.zenr.io. test.dev.zenr.io.
```

Useful end-to-end commands:

```bash
make test-register ADDR=127.0.0.1:8053 CLIENT_KEYSTORE_DIR=/path/to/keystore ZONE=test.dev.zenr.io. KEYNAME=test.dev.zenr.io.
make test-register-badsig ADDR=127.0.0.1:8053 CLIENT_KEYSTORE_DIR=/path/to/keystore ZONE=test.dev.zenr.io. KEYNAME=test.dev.zenr.io.
make test-integration
```

## Client Use Cases

The client binary currently supports these flows:

- `register` - create and send a signed UPDATE-LEASE registration request.
- `register-tamper` - sign the request, then flip one payload bit to confirm the proxy rejects a bad SIG(0).
- `verify` - query whether a registration is currently active.
- `list-keys` - list available keystore entries.

Examples:

```bash
sig0lease-client 127.0.0.1:8053 register test.dev.zenr.io. test.dev.zenr.io. 300 3600
sig0lease-client 127.0.0.1:8053 register-tamper test.dev.zenr.io. test.dev.zenr.io. 300 3600
sig0lease-client 127.0.0.1:8053 verify test.dev.zenr.io. test.dev.zenr.io.
sig0lease-client 127.0.0.1:8053 list-keys /path/to/keystore
```

## Proxy Use Cases

The proxy is designed to support two practical scenarios:

- Registration: a client submits an authenticated UPDATE-LEASE request and the proxy forwards a signed UPDATE to the authoritative server.
- Pass-through routing: non-registration traffic is forwarded according to the configured opcode routing and upstream settings.

## Protocol Behavior

This section describes how the proxy interprets UPDATE-LEASE packets. It reflects the current implementation; `protocol.md` in the repository root is kept as a more granular, spec-style reference for the same rules and is not duplicated in full here.

### UPDATE-LEASE EDNS Option Encoding

Clients include an UPDATE-LEASE option (EDNS option code 2) in their UPDATE packets. Two encodings are supported:

- **8-byte variant (default):** 4 bytes encode the LEASE value (lease duration for non-KEY RRs), followed by 4 bytes encoding the KEY-LEASE value (lease duration for KEY RRs). Both are big-endian `uint32` values.
- **4-byte variant (legacy):** 4 bytes encode a single LEASE value used for both KEY and non-KEY RRs. Off by default; enabled per handler via `prefer_4byte_variant`.

LEASE and KEY-LEASE together select one of four behavioral cases:

| Case | KEY-LEASE | LEASE | Behavior |
|---|---|---|---|
| A | Non-zero | Non-zero | Full registration/refresh of a KEY RR and its non-KEY RRs together. |
| B | 0 | Non-zero | Non-KEY-only registration/refresh; the signing KEY must already be managed. |
| C | 0 | 0 | Delete: removes whichever of the named KEY/non-KEY RRs are actually locally managed. |
| D | Non-zero | 0 | KEY-only registration/refresh, with optional deletion of accompanying non-KEY RRs. |

Both the request-side decoding (`handlers/opcode5_lease_option.go`) and the response/client-side decoding (`client/lease_response.go`) share one low-level decoder (`pkg/lease.FindOption` + `pkg/lease.DecodeOption`/`FindAndDecode`) so there is a single place that knows how to locate and parse the option, whether it appears as a bare `ERFC3597` RR or nested inside an `OPT` record's options.

### Signer Resolution (Three-Stage Fallback)

Before processing the case matrix, the proxy validates the SIG(0) signature on the UPDATE packet (`UpdateHandler.extractAndValidateSig0`). The signer key must be at or above the FQDN of every record in the Update section. Candidate signer key material is tried in order:

1. **Request-provided:** a KEY RR matching the SIG(0) signer identity (name, algorithm, key tag) present in the Update or Additional section.
2. **Lease store:** a KEY previously registered under that identity.
3. **Authoritative DNS:** a KEY RR published at the signer's name, queried live.

The first candidate that cryptographically verifies the signature is used. If verification succeeds via stage 3 only (not request-provided, not lease-managed), the signer is "online-only" — its material was neither proven fresh in this request nor already under lease management.

### Online-Only Signers and `allow_online_key_registration`

An online-only signer can always be used to authenticate a request — SIG(0) verification does not depend on the flag. What the signer is subsequently *allowed to do* does:

- **Deletes (Case C)** are ownership-based, independent of this flag: a record (KEY or non-KEY) may only be deleted by its immediate parent — the KEY that registered it — or, for a self-registered (root) KEY with no parent of its own, by itself. Hierarchy alone is not enough: a signer that is merely at or above a record's name by DNS naming, but is not the record's actual `ParentKeyName`, cannot delete it directly. Such a signer can still remove the data, but only indirectly, by deleting the record's true parent, which cascades (see "Upstream Forwarding and Write Ordering" below).
- **Authoring new lease-store state** — a new KEY RR, or non-KEY RRs owned by the signer — requires the signer to be either already lease-managed, itself present in the Update section (a normal self-registration), or, if `allow_online_key_registration: true` is configured for the handler, an online-only signer. This is one policy (`UpdateHandler.signerAuthorizedForNewRegistration`) applied identically to KEY and non-KEY registration in Case A and Case D; it is not KEY-RR-specific. Default is `false` (fail closed).

When an online-only signer registers a *different* KEY RR than itself (e.g. delegating a new child key it will never itself be lease-managed under), any non-KEY RRs in the same request are still attached to the **signer's own node** per the rule below — including when that node has no backing KEY record (a signer that is deliberately never self-registered). The lease store permits this "phantom owner" for non-KEY records the same way it already permits a KEY RR's `ParentKeyName` to reference a node that has no record of its own.

### Non-KEY RR Ownership

Non-KEY RRs registered in Case A always belong to the signer of the request — never to some other KEY RR that happens to be registered in the same packet — regardless of whether the signer is itself present in the Update section. If the signer is present, this happens naturally as part of that KEY's own registration/refresh; if not (the signer is only authorizing a different KEY's registration), the data is attached to the signer's node in a separate step after the per-KEY loop.

Additional rules:

- The signer KEY used for SIG(0) verification and a KEY RR being registered/refreshed in the Update section can be different keys.
- Multiple KEY RRs can be present in the Update section; each is dispatched independently.
- A KEY used only for signing should be in the Additional section; a KEY in the Update section is interpreted as intended for lease register/refresh/delete.
- **Key lease ownership:** when a KEY RR is registered (Case A or D), its public key becomes the "owner" for the non-KEY RRs registered alongside it and for other KEY RRs registered under it. This is tracked via `ParentKeyName` in the lease tree.

### Registration and Refresh Details

- **Refresh ownership check:** before treating a KEY RR as a refresh of an existing lease, `UpdateHandler.validateRefreshOwnership` compares the *actual* stored KEY RDATA (flags, protocol, algorithm, public key) against the one in the request. The lease store's node key is a composite of name + algorithm + key tag, which is not collision-free (the key tag is a 16-bit checksum); this check is what makes ownership verification exact rather than relying on the composite key alone.
- **Missing-at-FQDN recovery:** if a signer's managed KEY is found to be missing at the authoritative DNS (Cases A, B, D), the proxy re-registers it with whatever lease time remains in the local store, rather than granting a fresh full-duration lease or failing the request outright.
- **Duplicate registration rejection:** before treating a KEY or non-KEY RR as a *new* registration, the proxy checks whether an identical record already exists at the authoritative DNS. If so, the request fails — this applies uniformly to every case that can register something new (Cases A and D for KEY RRs; Cases A and B for non-KEY RRs), not only to the KEY-RR path.
- **Delete semantics (Case C):** for each named KEY or non-KEY RR, if it is not found in the local lease store *or* the signer is not its immediate parent (nor, for a KEY RR, the record itself), the request does not fail — a note identical to the not-found case ("... not found for delete") is returned informing the client, and that record is excluded from both the local delete and the upstream delete. This deliberately does not distinguish "doesn't exist" from "exists but you don't own it," so a delete attempt cannot be used to probe for the existence of records outside the signer's own subtree. Only records the signer is actually authorized to delete are included in the upstream delete request.

### Upstream Forwarding and Write Ordering

The proxy never mutates the local lease store before the corresponding upstream UPDATE has been confirmed successful:

1. All case-matrix outcomes are staged as deferred mutations.
2. The proxy signs and forwards the resulting change to the authoritative server (add-style for Cases A/B/D, a combined RFC 2136 delete for Case C).
3. Only if the upstream server returns `NOERROR` are the staged local mutations applied.
4. If the upstream server rejects the update (or is unreachable), the proxy returns an error to the client and the local lease store is left exactly as it was before the request — there is nothing to roll back, because nothing was written yet.

This means the local lease store's view of the world and the authoritative DNS server's view can never diverge as a direct result of a single request's outcome. Case C's delete additionally cascades: deleting a KEY also removes its descendant subtree, with best-effort upstream cleanup for the descendants (they are not blocking — a single unreachable descendant does not fail the whole delete).

### TTL Clamping and Response Echo

Before forwarding, the proxy clamps LEASE and KEY-LEASE (and, correspondingly, RR/KEY TTLs) to `LeasePolicy` bounds (`min_key_lease_sec`/`max_key_lease_sec`/`min_rr_lease_sec`/`max_rr_lease_sec`). The *actual* durations used after clamping — not the client's originally-requested values — are echoed back to the client in the response's UPDATE-LEASE option, so the client can detect when the proxy granted less than what was requested. `client.EffectiveLeaseDuration(resp, requestedLease, requestedKeyLease)` returns both the effective LEASE and KEY-LEASE from a response.

### Blacklisted RR Types

The proxy maintains a configurable list of blacklisted RR types (`handlers.update.blacklisted_types` in `config.yaml`). Any UPDATE packet attempting to register one of these RR types is rejected outright.

### Storage Model and Expiry

The lease store is a tree rooted at each configured zone. Children of a root must be KEY nodes; a KEY node can itself be the parent of other KEY nodes (registered by it) or non-KEY nodes (data it owns). Expiry of a KEY node cascades to its entire subtree.

- `BaseRecord` fields (type, expiry, lease duration, registration time, parent) are shared by KEY (`Record`) and non-KEY (`NonKEYRecord`) nodes.
- **Deletion is always physical, never a soft flag.** A record is either present in the store (active) or absent (gone) — there is no intermediate "marked deleted" state to track or eventually reap.
- **Expiry is handler-driven, not store-driven.** `UpdateHandler.processExpiredLease` — triggered by a per-node `time.AfterFunc` timer (`scheduleLeaseExpiry`, re-armed after every mutation and after every expiry event) — is the only code path that removes an expired KEY or non-KEY record, and it always attempts the corresponding upstream delete first. The store itself never deletes anything on its own initiative, because it has no way to also notify the authoritative server.
- **Reconciliation backstop:** `UpdateHandler.startLeaseReconciliation` runs every 30 seconds and ensures every KEY node in the store has a live expiry timer, scheduling one via the same `scheduleLeaseExpiry` for any node that lacks one (for example, a node populated by a future snapshot-restore path that doesn't itself arm a timer). For an already-expired node this routes it through the same `processExpiredLease` almost immediately — there is exactly one deletion implementation, not a second one that might skip the upstream call.

**Storage backend abstraction.** All of the above is defined against a single interface, `lease.LeaseStorage` (`pkg/lease/state.go`) — KEY lifecycle, tree/hierarchy, non-KEY record sets, and snapshot import/export/persistence all live on this one interface, and every backend must implement all of it. There is no narrower interface for a partial implementation to fall back to, and the handler never type-asserts down to a subset: a backend either supports the full feature set or `Setup()` fails to configure it at all.

Two backends are selectable via `handlers.update.storage` in `config.yaml` (see the Configuration section below):

- **`type: memory`** (default) — `InMemoryLeaseStore`. Zero persistence: a process restart drops all lease state, and clients simply re-register (the "Signer Resolution" three-stage fallback above still lets an unrelated signer authenticate against live authoritative DNS even with an empty store; only lease bookkeeping, not authentication, is lost).
- **`type: file`** — `FileLeaseStore` (`pkg/lease/file_store.go`), which wraps an `InMemoryLeaseStore` and adds human-readable JSON persistence via the existing `ExportSnapshot`/`ImportSnapshot`/`SaveSnapshot`/`LoadSnapshot` mechanism: loaded once at `Setup()` (a corrupt existing file is a hard `Setup()` error, never a silent "start empty"), saved periodically on `save_interval`, and flushed once more on `Shutdown()`.

### Reference to Source Files

- `handlers/opcode5_handle.go` — `Handle()`, the full case dispatch, `buildSuccessResponse`.
- `handlers/opcode5_lease.go` — lease-store read/write helpers, `validateRefreshOwnership`, `processExpiredLease`, `scheduleLeaseExpiry`, `startLeaseReconciliation`, `UpdateHandler.Shutdown`.
- `handlers/opcode5_update_helpers.go` — SIG(0) resolution (`extractAndValidateSig0`), upstream message construction, duplicate-registration checks.
- `handlers/opcode5_lease_option.go` — UPDATE-LEASE option parsing and request-side policy validation.
- `handlers/opcode5_setup.go` — `Setup()`, including storage-backend selection (`buildLeaseManagerFromConfig`).
- `pkg/lease/state.go` — the unified `LeaseStorage` interface and `InMemoryLeaseStore`, the tree-structured in-memory implementation.
- `pkg/lease/file_store.go` — `FileLeaseStore`, the periodic/shutdown-flush JSON-snapshot-backed implementation.
- `pkg/lease/lease.go` — `LeaseOption` encode/decode and the shared `FindOption`/`DecodeOption`/`FindAndDecode` helpers.
- `client/lease_response.go` — client-side decoding of the server's granted LEASE/KEY-LEASE.

## Configuration

`config.yaml` controls:

- listening address and enabled transport networks;
- default upstream resolvers;
- handler-specific settings such as the upstream zone, keystore directory, lease policy bounds, blacklisted RR types, `allow_online_key_registration`, and the lease storage backend (`storage.type: memory|file`, see "Storage Model and Expiry" above) for the update handler;
- opcode-to-module routing.

The update handler uses the configured zone to discover the authoritative server for the effective zone, then sends the rewritten UPDATE there.

## SRP (RFC 9665)

Alongside the RFC 9664 lease flow above, the proxy implements [RFC 9665](https://datatracker.ietf.org/doc/rfc9665/) (DNS-SD Service Registration Protocol) — a tightly constrained profile of DNS UPDATE for devices registering their own services (host address + one or more service instances) on a "First Come, First Served" basis, authenticated by SIG(0). It's a **sibling** request path to the RFC 9664 handler above, not a mode on it: SRP's message shape and authorization model are different enough (FCFS by name rather than a signer-hierarchy walk, mandatory delete-all-then-add, no lightweight refresh) that it has its own handler, `handlers/srp_handler.go`, sharing only the genuinely common plumbing (`pkg/lease`, `pkg/sig0`, `pkg/updatecore`'s upstream-forward/re-sign path).

### Enabling it

Add an `srp_handler` block under `handlers:` and route opcode 5 (UPDATE) to it in `processing_rules` (see `config.yaml` for a worked example). Key options:

- `upstream_zone` (required) — the one zone this handler instance serves (one zone, one protocol per handler instance; run a second handler instance for a second zone).
- `keystore_dir` (required) — this proxy's own SIG(0) signing key for the zone, resolved the same way the RFC 9664 handler's is.
- `upstream` (optional) — a static `host:port` override, skipping SOA/NS discovery for this zone entirely; needed for any zone (like `default.service.arpa.`, see below) that isn't really delegated.
- `allow_udp` (optional, default `false`) — SRP requires TCP by default; set this for zones expecting constrained (CNN) devices that can't reliably do TCP.
- `rewrite_default_service_arpa` (optional, default `false`) — real SRP client implementations (Apple's `srp-client`, OpenThread's SRP client) hardcode `default.service.arpa.` as their zone, having no other way to discover one. With this on, the handler additionally accepts requests addressed to `default.service.arpa.` and rewrites every name in the update to `upstream_zone` before doing anything else with it (FCFS, the local lease-store tree, and the upstream forward all end up working with exactly one real name per host, regardless of which zone the client actually addressed) — the response still echoes back `default.service.arpa.`, exactly what the client sent.
- `refuse_on_foreign_data` (optional, default `true`) — RFC 9665 §3.3.3's NOERROR-no-KEY case: refuse (rather than clobber) a name that already has non-SRP data at the authoritative server.
- `lease_policy` — same shape as the RFC 9664 handler's (`min_key_lease_sec`/`max_key_lease_sec`/`min_rr_lease_sec`/`max_rr_lease_sec`).
- `lease_manager` / `storage` — same mutually-exclusive lease-store backend selection as the RFC 9664 handler.

### The SRP requester

`client/srp` is the actual client-side deliverable: discovery (`_dnssd-srp._tcp.<domain>.` SRV lookup), the RFC 9664 §5.2 refresh clock (80% of the granted lease, jittered), automatic rename-retry on a `YXDOMAIN` conflict, and now `Deregister` (withdraws a whole identity — host address data and every configured instance — in one message, requesting `LEASE=0`). `cmd/sig0lease-srp` is a thin CLI over it for development/testing, not a shipped product (there's deliberately no `make build-srp` target) — run it directly:

```bash
go run ./cmd/sig0lease-srp -domain=srp.example.com. -host=myhost -addr=192.0.2.1 \
  -instance=Widget:_http._tcp:8080 -txt=Widget:path=/ -server=127.0.0.1:8159 -once
```

`go run ./cmd/sig0lease-srp -h` lists every flag, including `-deregister` and the full-lifecycle (no `-once`) mode that runs the refresh clock unattended.

### Testing it

`make test-srp` runs the full register/refresh/conflict/remove/expiry suite against a real, disposable local BIND 9 (no external dependency). `make test-mdnsresponder-interop` runs the same registrar and client against the real, unmodified Apple `mDNSResponder/ServiceRegistration` binaries — a sibling checkout, not vendored; see `tests/README.md` for how to set it up, including the exact commit this was last validated against.

## DNS-over-TLS

The server can offer DNS-over-TLS ([RFC 7858](https://datatracker.ietf.org/doc/rfc7858/)) as a third listener alongside plain UDP/TCP — transport-level, so it benefits every handler above (RFC 9664, RFC 9665 SRP, and plain forwarding alike), not something protocol-specific. Opportunistic only: no client-certificate authentication.

Add `"tls"` to `server.networks` and a `server.tls` block:

```yaml
server:
  address: ":53"
  networks: [udp, tcp, tls]
  tls:
    address: ":853"   # DoT's own port -- conventionally separate from plain DNS on 53
    cert: /path/to/cert.pem
    key: /path/to/key.pem
```

## Project Layout

- `cmd/sig0lease/` - proxy entrypoint
- `cmd/sig0lease-client/` - client entrypoint (RFC 9664 lease flow)
- `cmd/sig0lease-srp/` - thin dev/test CLI over `client/srp` (RFC 9665 SRP requester) — not a
  shipped product; see the "SRP (RFC 9665)" section below
- `client/srp/` - the RFC 9665 SRP requester library (`Client`, discovery, RFC 9664 S5.2
  refresh scheduler, `YXDOMAIN` rename-retry) — this is the actual SRP client deliverable,
  `cmd/sig0lease-srp` just exercises it
- `config/` - YAML config loading and validation
- `forward/` - upstream forwarding logic
- `handlers/` - opcode handlers and result types, including `srp_handler.go` (the RFC 9665
  SRP registrar path, a sibling to the RFC 9664 update handler, never a mode on it)
- `pkg/keyrec/` - keystore loading helpers (`LoadedKey`, `LoadKeyFromFile`, `FindKeysByZone`,
  `GenerateKey`)
- `pkg/lease/` - lease store, tree model, and UPDATE-LEASE option encoding/decoding (shared
  by both the RFC 9664 and RFC 9665 paths)
- `pkg/sig0/` - SIG(0) signing and verification helpers
- `pkg/srp/` - RFC 9665 message classification/validation (`Classify`, `Validate`), FCFS
  (`Evaluate`), and the requester-side message builder/response interpreter (`BuildUpdate`,
  `InterpretResponse`) — pure logic, no network I/O
- `pkg/updatecore/` - upstream forward/re-sign plumbing shared by both the RFC 9664 and
  RFC 9665 (SRP) handlers (SOA/NS resolution, per-zone static `upstream` override, TTL
  consistency checks)
- `server/` - UDP/TCP/TLS (DNS-over-TLS, RFC 7858) listener and request dispatch

See `docs/rfc9665-srp-implementation-plan.md` for the full RFC 9665 design writeup (locked
architectural decisions, worked examples, and a phase-by-phase revision history covering
every real bug found and fixed along the way) — it's the source of truth for anything SRP
that isn't covered below.

## Validation
(requires client key, see this [README](./keystore/README.md))
```bash
CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-unit
CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-update   # RFC 9664 lease flow, live against a real BIND 9
make test-srp                                                  # RFC 9665 SRP flow, live against a real BIND 9
make test-mdnsresponder-interop                                 # RFC 9665 SRP, live against real independent mDNSResponder binaries
make build
```

For a complete behavior check, run the registration and tamper flows against a live proxy instance.


## miekg/dns Shortcomings

The current implementation depends on `codeberg.org/miekg/dns`, but several library edge cases required compatibility shims.
The project uses `codeberg.org/miekg/dns v0.6.82`, but several sharp edges had to be patched or worked around.

### UPDATE-LEASE unpack mismatch

The library exposes `CodeUPDATELEASE`, but in v0.6.82 the EDNS option unpack dispatcher does not include a `*UPDATELEASE` case. That causes parsing to fail with:

`dns: no option unpack defined`

This is not a protocol problem in sig0lease; it is a library dispatch gap.

### Applied patch

sig0lease adds a compatibility package at [pkg/dnscompat/updatelease.go](pkg/dnscompat/updatelease.go) that registers EDNS code `2` with an `ERFC3597` constructor at process startup. This allows strict unpacking to succeed without adding parser fallback logic.

### UPDATE-LEASE unpacked form is not an OPT wrapper

After unpack, the library represents code `2` as a direct `*dns.ERFC3597` RR in the `Pseudo` section rather than as an `OPT` containing nested options in the shape the project initially expected.

### Applied patch

The update handler now checks both `Pseudo` and `Extra`, and it accepts either:

- direct `*dns.ERFC3597` records with EDNS code `2`, or
- `*dns.OPT` records containing an `ERFC3597` option.

### Multi-question messages don't round-trip through Pack/Unpack

`Msg.Question` is typed `[]RR`, but its doc comment says it "holds a single 'RR'" -- and in v0.6.82 that's enforced by a bug rather than by the type system. Setting `len(m.Question) > 1` and calling `Pack()` writes `QDCOUNT` from `len(m.Question)`, but the packing loop only serializes the first Question RR's bytes onto the wire. The result is an internally inconsistent message: the header claims N questions, the body contains one. Unpacking that message anywhere (including round-tripping it back through the same library) fails with:

`dns unpack: overflow name`

This is a library packing bug, not a sig0lease protocol issue -- real DNS traffic essentially never sets QDCOUNT > 1 anyway, and this project's own `acceptMsg` (see [server/server.go](server/server.go)) rejects any message where `len(m.Question) != 1` with FORMERR, matching the library's own `DefaultMsgAcceptFunc`. No compatibility patch was written for it. It surfaced while writing [server/transport_equivalence_test.go](server/transport_equivalence_test.go), which needed a genuine two-question wire message to test that FORMERR-rejection branch; that specific case had to be dropped since the library can't produce valid bytes for it, and the message-with-zero-questions case was kept in its place to cover the same `acceptMsg` branch.

### The handler must call `Unpack()` itself to see Ns/Extra/Pseudo

`codeberg.org/miekg/dns` (unlike `github.com/miekg/dns` v1.x, whose server fully decoded the message before calling the handler) hands the `Handler` a message that has only been parsed through the question section. `MsgAcceptFunc` runs on that partial parse; the server then invokes the handler with the rest of the wire message still sitting unparsed in `r.Data`. Getting `Ns`, `Extra`, and the `Pseudo` section that carries EDNS options (including UPDATE-LEASE) requires the handler to call `r.Unpack()` itself -- this is stated on the `dns.Handler` interface doc comment. A handler that skips it sees every UPDATE as "UPDATE without UPDATE-LEASE option", on both UDP and TCP.

This is a deliberate API contract in the fork, not a defect, so there is nothing to wait on upstream.

### Applied handling

`server/server.go` serves both transports with the library's own `dns.Server` (`serveUDP`/`serveTCP` are thin wrappers around it) and wraps every dispatch path in `fullUnpackHandler`, which calls `r.Unpack()` once -- completing the parse the server started -- before the request reaches the router. The update handler therefore always receives a fully-decoded message. `server/transport_equivalence_test.go`'s `TestServeTCPPreservesUpdateLeaseOption` pins that the option survives to the handler over both transports.

### SIG(0) hashes the full SIG RR instead of RDATA-only (RFC 2931 non-compliance)

`dns.CryptoSIG0.Sign`/`Verify` (`sig0_signer.go`) compute the SIG(0) hash input as the SIG RR's *full wire encoding* -- owner name (1 byte, always root) + TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = an 11-byte envelope, followed by RDATA -- via `sbuf := make([]byte, s.Len()); packRR(s, sbuf, 0, nil)`, then hashes `sbuf || message`.

RFC 2931 S3 is explicit that this is wrong:

> data = RDATA | request - SIG(0)
>
> where "|" is concatenation and RDATA is the RDATA of the SIG(0) being calculated less the signature itself.

RDATA-only means no owner name, TYPE, CLASS, or RDLENGTH -- just TypeCovered/Algorithm/Labels/OrigTTL/Expiration/Inception/KeyTag/SignerName. The library's extra 11-byte envelope means it computes a different hash than any RFC-compliant implementation, silently. This project's own `pkg/sig0` had already accidentally routed around it for ED25519 (algorithm 15) -- `sig0SignerImpl`'s ED25519 case has never called `dns.CryptoSIG0.Sign`/`Verify` at all (they have no ED25519 case; `AlgorithmToHash` has no entry for it), so it always built its own RDATA-only prefix by hand for unrelated reasons. Every other algorithm silently inherited the bug, undetected because nothing in this project's test suite had ever driven a non-ED25519 signature through a real, independent verifier -- until the RFC 9665 SRP work needed ECDSAP256SHA256 (algorithm 13) and captured a real signature from `mDNSResponder`'s `srp-client` (an independent implementation) to test against. That verification failed with `dns: bad signature`; instrumenting a local copy of the library (a temporary `replace` directive, reverted after) pinned the exact hash-input bytes, and trimming the library's 11-byte envelope off made the real signature verify. Independently confirmed against `mDNSResponder`'s own C source: `ServiceRegistration/towire.c`'s `dns_sig0_signature_to_wire_` calls `srp_sign(output, max, message, msglen, rr, rdlen, key)` where `rr`/`rdlen` point at the RDATA fields only (`start`/`txn->p - start`, both set *after* the 11-byte envelope is written) -- and `sign-mbedtls.c`'s `srp_sign` hashes exactly `rr[:rdlen] | message[:msglen]`, i.e. RDATA-only, matching the RFC.

### Applied patch

`pkg/sig0/signer.go` no longer delegates to `dns.CryptoSIG0.Sign`/`Verify` for ED25519 (as before), ECDSAP256SHA256, or ECDSAP384SHA384. A shared `rdataOnlyPrefix(sig *dns.SIG) []byte` helper builds the correct RFC-2931 hash-input prefix once; each of those three algorithms hashes/signs/verifies against it directly (ECDSA via `crypto/ecdsa` with raw `r||s` output per RFC 6605 S4, never ASN.1 DER). `pkg/sig0/ecdsa_test.go` covers both algorithms with a generate-sign-wire-round-trip-verify test, a tampered-message-is-rejected test, and a known-answer test pinned to the actual captured `mDNSResponder` message (`TestECDSAP256KnownAnswerFromMDNSResponder`) so a regression here fails a test, not just a future interop attempt.

RSA algorithms (RSAMD5/RSASHA1/RSASHA256/RSASHA512) still delegate to `dns.CryptoSIG0` and so still carry the same bug -- nothing in this codebase uses or tests them, and no RSA test keys or vectors exist here to validate a from-scratch implementation against, so extending the same fix to RSA was deliberately deferred rather than shipped unverified. If RSA SIG(0) is ever needed, apply the identical `rdataOnlyPrefix` treatment, validated against a real RSA key and, ideally, another independent implementation's signature the way the ECDSA fix was.

This bug was not reported upstream to `codeberg.org/miekg/dns` (deliberate choice, not an oversight) -- this section is written to make that easy to do later: the RFC 2931 S3 quote above, the exact library code path (`sig0_signer.go`'s `CryptoSIG0.Verify`, the `sbuf := packRR(s, sbuf, 0, nil)` line), and a reproducible known-answer case (`pkg/sig0/ecdsa_test.go`'s `TestECDSAP256KnownAnswerFromMDNSResponder`, or the raw captured bytes noted in that test) are everything an upstream issue would need.

## Applied Compatibility Patches

The following project-side patches are currently in place:

1. `pkg/dnscompat` imports `codeberg.org/miekg/dns` and registers code `2` as `ERFC3597` on startup.
2. `cmd/sig0lease/main.go` imports the compatibility package so the proxy process gets the patch before reading packets.
3. `cmd/sig0lease-client/main.go` imports the same compatibility package so client-side pack/unpack behavior stays consistent.
4. `pkg/lease.FindOption` recognizes UPDATE-LEASE whether it arrives as a direct `ERFC3597` record or under an `OPT` wrapper, for both request and response parsing.
5. `server/server.go` wraps the handler chain in `fullUnpackHandler`, which calls `r.Unpack()` before dispatch so every request (UDP and TCP) reaches the router fully decoded, per the `dns.Handler` contract (see above).
6. `pkg/sig0/signer.go` replaces `dns.CryptoSIG0.Sign`/`Verify` for ED25519, ECDSAP256SHA256, and ECDSAP384SHA384 with an RFC-2931-correct, RDATA-only hash-input implementation (`rdataOnlyPrefix`), fixing a library bug that hashes the full SIG RR wire encoding instead.

# Implementation Status

## Authoritative Forwarding

1. Target resolution
- The proxy resolves the effective authoritative zone and SOA MNAME and forwards UPDATE there.

2. Upstream signing
- Forwarded UPDATE messages are signed with the proxy's key for the zone.

## Test Layout

1. Unit tests
- Unit tests remain next to packages (for example in handlers and pkg).

2. Integration tests
- Integration scripts and integration helpers are under tests.

## Client Behavior

1. Lease adoption from server response
- Client expiry calculations adopt the server-returned LEASE and KEY-LEASE values independently when present (`client.EffectiveLeaseDuration`, `client.ExpiryFromResponse`) — the proxy's `LeasePolicy` can clamp either value differently, so both are read back rather than assuming they moved together.
- If no lease option is returned, the client falls back to the originally-requested LEASE and KEY-LEASE.
