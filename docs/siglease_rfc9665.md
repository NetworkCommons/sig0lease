# SRP (RFC 9665) — Service Registration Protocol

This document describes the proxy's implementation of [RFC 9665](https://datatracker.ietf.org/doc/rfc9665/)
(DNS-SD Service Registration Protocol, SRP): a client library and CLI, a registrar (server)
handler, and the shared infrastructure they use. It describes the current implementation, not
a plan.

See `docs/siglease_rfc9664.md` for the base RFC 9664 lease-UPDATE proxy this builds on, and
for the parts explicitly shared between the two (SIG(0) signing, the lease store, upstream
forward/re-sign, DNS-over-TLS). Common ground is called out at each point below rather than
repeated in full.

## 1. What SRP is, and what's reused

RFC 9665 (SRP) is not a new wire option. It is a profile of DNS UPDATE: a tightly constrained
message shape (three kinds of "instruction"), a specific authentication model ("First Come,
First Served" naming with SIG(0)), and a set of maintenance rules — all layered on the
RFC 9664 Update-Lease option the base handler already implements (see
`docs/siglease_rfc9664.md`).

SRP is implemented as a **sibling handler** (`handlers/srp_handler.go` + `pkg/srp`), not a mode
on the base `UpdateHandler`: SRP's message shape and authorization model are different enough
(FCFS by name rather than a signer-hierarchy walk, mandatory delete-all-then-add, no
lightweight refresh) that several of the base handler's own checks
(`validateSignerHierarchyForUpdateRecords`, duplicate-registration rejection) are simply wrong
for SRP traffic. The plumbing that genuinely is shared — SIG(0) signing/verification
(`pkg/sig0`), the lease store (`pkg/lease`), and upstream forward/re-sign — lives in
`pkg/updatecore`, used by both handlers.

## 2. Package layout

```
pkg/srp/            pure logic, no network, no DNS I/O
  instruction.go     instruction types + Classify() (message -> ClassifiedUpdate)
  validate.go        structural validation (§3.1/§3.2 below), TTL consistency
  names.go           canonical-name + DNS-SD subtype helpers
  fcfs.go            FCFS: Evaluate() (tri-state, takes an injected StoreView +
                     AuthoritativeKeyQuery, no network I/O of its own), plus
                     Names()/KeyFor() helpers over a ClassifiedUpdate
  update.go          SRP-update builder, used by the client
  response.go        RCODE mapping + granted-lease echo

pkg/updatecore/       shared forwarding plumbing (RFC 9664 handler and SRP handler alike)
  coordinator.go      SOA/NS resolution, per-zone static-upstream override,
                      construct/forward/re-sign, the tri-state QueryKeyAtName
  ttl.go              RRset TTL consistency: check (SRP) | normalize-to-min (base)

pkg/dnssd/            RFC 6763 §9/§11 record logic (pure), separate from RFC 9665 protocol
                      logic since it's a distinct RFC

handlers/
  srp_handler.go       implements handlers.Handler for opcode 5 (SRP path)
  srp_setup.go         config parsing for the srp_handler block

server/
  router.go            opcode -> ordered list of handlers, tried in turn

cmd/sig0lease-srp-client/main.go   thin SRP requester CLI (dev/test tool, not a shipped
                                   product — the library is the deliverable)
client/srp/                        discovery, refresh scheduler, conflict-retry loop,
                                   Register/Deregister/Run
```

`pkg/lease`, `pkg/sig0`, `pkg/keyrec`, `pkg/dnscompat`, `forward`, `config`, `logging` carry
over unchanged, with only additive helpers.

## 3. Routing

`processing_rules` carries an ordered `modules` list per opcode:

```yaml
processing_rules:
  - opcode: 5
    modules: ["srp_handler", "update_handler"]   # tried in order
```

`server/router.go` calls each configured handler for the opcode in turn; the first one to
return `Processed` or `Error` wins. If every handler returns `NotRelevant`, the request falls
through to plain upstream forwarding. `SRPHandler.Handle()` returns `NotRelevant` when
`pkg/srp.Classify` decides the message isn't SRP-shaped, or when the request's zone isn't one
this handler instance is configured to serve — each `srp_handler` instance serves exactly one
zone, and `{srp_handler, update_handler}` are never both enabled for the same zone at once
(same-zone cross-protocol manipulation is prevented by keeping the two protocols on disjoint
zones, not by extra runtime checks).

## 4. The SRP Update message

A single DNS UPDATE containing **only** the following, grouped into "instructions" (RFC 9665
§3.2.1, §3.3.1):

| Instruction | Contents | Notes |
|---|---|---|
| **Host Description** (exactly 1) | `Delete All RRsets` on the hostname · exactly 1 `KEY` add · 0..n `A`/`AAAA` adds | 0 address adds = delete registration. The hostname's KEY is the FCFS anchor. |
| **Service Description** (0..n) | `Delete All RRsets` on the service-instance name · 0..1 `KEY` add · 0..1 `SRV` add · 1..n `TXT` adds (if SRV present) | KEY may be omitted → inherits the Host Description KEY. SRV target **must** equal the Host Description hostname. |
| **Service Discovery** (0..n) | exactly 1 `PTR` add **or** exactly 1 `PTR` delete, target = a service-instance name that has a Service Description in the same update | One instruction per subtype. |

Hard requirements the handler enforces:

- **Exactly one hostname** in the whole update (more than one ⇒ not an SRP update).
- **No prerequisites** (any prerequisite ⇒ not an SRP update).
- **Must** carry an 8-byte Update-Lease option with `LEASE ≤ KEY-LEASE` (missing, or
  `KEY-LEASE < LEASE` ⇒ not an SRP update).
- **All KEY RRs identical** and equal to the SIG(0) signing key (§3.2.5.1). KEY `flags` are
  never checked by the registrar — RFC 9665 §3.3.3 is explicit that flags must be stored
  exactly as received, without checking or modifying them; this is one-directional (a
  requester MUST send flags 0, the registrar MUST NOT enforce that).
- **TTL consistency** within every RRset in the update (§4) — rejected with `REFUSED` if
  violated; this is a MUST on the SRP path, unlike the base handler's normalize-to-minimum
  behavior (both live in the shared `pkg/updatecore/ttl.go`, see `docs/siglease_rfc9664.md`).
- Any add/delete that isn't part of a recognised instruction ⇒ not an SRP update ⇒ the
  registrar rejects with `REFUSED`.

There is no lightweight refresh. Every SRP update carries a complete Host Description
(`Delete All RRsets` + KEY add) and its own `LEASE`/`KEY-LEASE`; a "refresh" is simply
re-sending the registration. An update need not re-state every service — services it omits
keep their previous lease and expire on their own per-instance schedule. Because of this,
`client/srp` always restates Service Discovery for any service that should stay discoverable:
there is no incremental-modify primitive anywhere in SRP, so a client's natural model is to
resend its complete current state on every registration/refresh.

Compressed SRV target names (§3.2.5.4) are accepted, matching real client behavior.

## 5. Validation and FCFS

1. The message is a syntactically valid RFC 2136 UPDATE.
2. **Structural validation** (`pkg/srp.Validate`) — classify every instruction and confirm the
   whole-update requirements in §4 above.
3. **FCFS name check** (`pkg/srp.Evaluate`, RFC 9665 §3.3.3) — for the hostname and each
   service-instance name, look up the lease store; if the store has no entry, issue one live
   `KEY`-at-name query. The result is tri-state:

   | query result | meaning | action |
   |---|---|---|
   | `NXDOMAIN` | name does not exist | proceed (first come) |
   | `NOERROR`, no KEY in the answer | name exists, has RRsets, no KEY — foreign/orphaned data | `srp_handler.refuse_on_foreign_data` (default `true`): `REFUSED`; `false`: proceed (delete-all-then-add replaces it) |
   | `NOERROR`, KEY present, RDATA matches the update's KEY (explicit or inherited) | same owner | proceed |
   | `NOERROR`, KEY present, RDATA differs | different owner | `YXDOMAIN` |

   This is the same query used for the pre-forward cost described in `docs/siglease_rfc9664.md`
   — reading its RCODE is free. Because a real, independent write can land between this
   read and the eventual forwarded UPDATE (a TOCTOU window), the forwarded UPDATE for a
   never-before-seen name also carries an RFC 2136 prerequisite ("Name is not in use"), so the
   authoritative server itself atomically re-enforces FCFS at write time; a prerequisite
   failure maps to the same `YXDOMAIN` a normal FCFS conflict would produce.
4. **SIG(0) verify** against the KEY in the Host Description (§3.3.3) — always present in the
   request, so no three-stage signer resolution (as used by the base handler) is needed. Fail
   ⇒ `REFUSED`.
5. Apply as a normal RFC 2136 update via the shared forward path (`docs/siglease_rfc9664.md`).
   After applying, every updated Service Description carries a KEY equal to the Host
   Description KEY (see §7 below — the registrar synthesizes this when a client omits it).
6. Response RCODE ∈ `{NOERROR, SERVFAIL, REFUSED, YXDOMAIN}`; the response always echoes the
   granted `LEASE`/`KEY-LEASE`.

**Authorization for SRP is steps 2 and 3, nothing more.** Once structural validation confirms
every KEY in the update equals the signing key, per-name FCFS is the entire ownership check —
there is no per-record parent/key walk. PTRs are authorized transitively: each targets a
service instance with a Service Description in the same update, and that instance is
FCFS-checked (§3.3.1.1).

If a `default.service.arpa.`-addressed request and a real-zone-addressed request named the
same logical host, the rewrite in §9 below runs before FCFS specifically so both are compared
under one name — otherwise FCFS would never see the collision and a later write could silently
overwrite an earlier one.

## 6. Lease-store mapping

| SRP concept | `pkg/lease` node | schedule |
|---|---|---|
| Hostname + its KEY | KEY `Record`, root of the zone subtree | `KeyLeaseDuration` |
| `A`/`AAAA` for the host | `NonKEYRecord`, parent = host node | `LeaseDuration` |
| Service instance (+ inherited/explicit KEY) | KEY `Record`, parent = host node | `KeyLeaseDuration` |
| `SRV`/`TXT` for the instance | `NonKEYRecord`, parent = service node | `LeaseDuration` |
| Service Discovery `PTR` | `NonKEYRecord`, parent = **service** node | `LeaseDuration` |

This reuses `pkg/lease` exactly as it exists for the base handler, with no new store methods,
no new `NodeKind`, and no snapshot-format change: the local mutation for every node a
`Delete All RRsets` touches (host A/AAAA, service SRV/TXT/PTRs alike) is a uniform
wipe-then-reinsert via the existing `RemoveNonKEYRecords` + `UpsertNonKEYRecords`. Applying that
same wipe-then-reinsert to a service node's SRV, TXT, and PTR children together also gives
subtype atomicity (§3.3.4) for free: only PTRs named in the current update survive the
reinsert.

For SRP specifically, `ParentKeyName` is cascade/grouping only, not authorization — unlike the
base handler, where it is both (see `docs/siglease_rfc9664.md`). This is safe because §3.2.5.1
guarantees one key across the whole update: the service-instance KEY node and the host KEY node
hold byte-identical KEY RDATA even though their node keys differ (node keys are name-scoped).
Any residual "does this key govern this name" question is answered by FCFS, not by walking the
tree.

**The one piece of genuinely new logic** is not a store method: before wiping, the handler
reads a service node's *current* PTR children and diffs them against the update's named Service
Discovery instructions, so the *outgoing* upstream message can carry an explicit
`Delete An RR From An RRSet` for anything being dropped. Upstream, unlike the local store, is
never told to delete-all a PTR's owner name — that name is the shared service *type*, common to
every other instance of the same type, so it can never be delete-all'd without destroying other
instances' discoverability. A PTR only ever moves via an individual add/delete instruction.

**Maintenance rules (§5.1):**

- Lease time governs the hostname. When the hostname's KEY-LEASE expires, the hostname and
  every service instance targeting it are removed together (cascade).
- The registrar also tracks a lease per service instance independently (a client may
  re-register a host with a different service set and drop the old one).
- KEY records survive on the KEY-LEASE schedule (typically 14 days) even after the data lease
  expires, reserving the name.
- A Service Discovery PTR is removed whenever its target service instance is removed.
- The baseline refresh clock is 80% of the lease plus a 0–5% random offset (RFC 9664 §5.2, a
  MUST — shared with the base handler, see `docs/siglease_rfc9664.md`).

## 7. KEY synthesis for Service Descriptions

RFC 9665 §3.3.3 is unconditional: *"After the SRP Update has been applied, every Service
Description that is updated MUST have a KEY RR,"* which must equal the Host Description KEY.
A requester is allowed to omit the per-instance KEY in its own request (§3.2.5.1, "MAY be
omitted for brevity") — `client/srp` always does this — but the resulting authoritative zone
state must still carry it regardless of whether the requester sent it explicitly.

The handler's upstream forward step synthesizes this KEY for every live (SRV-present) instance
whose own Service Description omitted one (`synthesizeOmittedInstanceKeys`, derived via the same
`pkg/srp.KeyFor` logic already used for the local lease store's own bookkeeping), before
building the outgoing UPDATE. Without this, a service instance's KEY would only ever exist in
this process's own lease store, never at the authoritative server — so a registrar restart
(losing local lease-store state) would make the very next refresh of that instance fail FCFS's
live-query fallback with `REFUSED`, since the query would find SRV/TXT data with no KEY at that
name at all.

## 8. Transport and crypto

- On non-constrained networks, TCP is required (anti off-path spoofing); a UDP SRP update is
  rejected with `REFUSED` unless the zone is flagged `allow_udp` for constrained (CNN) devices.
- The registrar implements ECDSAP256SHA256 (algorithm 13), required by RFC 9665 for
  interoperability with real requesters. `client/srp` generates P-256 keys by default and
  always emits a flags-0 KEY, per §3.2.5.1. ED25519 (algorithm 15) also stays fully supported,
  used elsewhere in this project (`sig0namectl` and the existing keystore).
- The server can offer DNS-over-TLS (opportunistic, no client-certificate authentication) as a
  transport-level listener that benefits this handler along with every other one — see
  `docs/siglease_rfc9664.md`.
- Source-address filtering (RFC 9665 §3.1.3's SHOULD) is a wired but dormant stub:
  `srp_handler.allowed_source_prefixes` is parsed and the check point exists, but an empty list
  (the only value currently supported end-to-end) allows every source. See §11 below.

### A library bug this work uncovered, fixed for every algorithm but RSA

`codeberg.org/miekg/dns`'s `CryptoSIG0.Sign`/`Verify` hash the SIG RR's *full wire encoding*
(owner name + TYPE + CLASS + TTL + RDLENGTH, then RDATA) instead of RDATA-only, violating
RFC 2931 §3 ("data = RDATA | request − SIG(0)"). This project's own ED25519 path had always
avoided the bug by accident (its hand-built prefix was already RDATA-only for unrelated
reasons); every other algorithm silently inherited it, undetected until SRP's ECDSAP256SHA256
requirement needed to verify a real signature captured from `mDNSResponder`'s `srp-client` — an
independent implementation — and failed. Fixed in `pkg/sig0/signer.go` for ED25519,
ECDSAP256SHA256, and ECDSAP384SHA384 via one shared `rdataOnlyPrefix` helper (ECDSA via
`crypto/ecdsa`, raw `r‖s` output per RFC 6605 §4, never ASN.1 DER); regression-tested against
the real captured message. RSA (RSAMD5/RSASHA1/RSASHA256/RSASHA512) still delegates to the
buggy library path — deliberately left unfixed, since no RSA keys or test vectors exist in this
codebase to validate a from-scratch implementation against (see §11). This has not been
reported upstream; it's documented in full, with the exact code path and a reproducible
known-answer case, in `docs/siglease_rfc9664.md`'s "miekg/dns Shortcomings" section so filing an
issue later is straightforward.

## 9. `default.service.arpa.` support

Every real SRP requester implementation hardcodes `default.service.arpa.` as its registration
zone, having no other way to discover one. Setting `srp_handler.rewrite_default_service_arpa:
true` lets a zone additionally accept requests addressed to `default.service.arpa.`, rewriting
every name in the update (each RR's own owner name, plus `SRV.Target`/`PTR.Ptr`, the only two
name-typed RDATA fields SRP produces) to the configured `upstream_zone` before FCFS or
forwarding ever see it. The response's Zone Section is left untouched, so the client still sees
exactly the zone name it sent.

The rewrite runs *after* SIG(0) verification (which covers the original, unrewritten bytes) but
*before* FCFS: FCFS's live upstream query and the whole local lease-store tree need
real-zone-shaped names, since `default.service.arpa.` doesn't exist anywhere upstream and a live
query against it would always return `NXDOMAIN` regardless of actual prior state. Rewriting
only at the upstream-facing call sites while keeping the local store keyed by the client's
original `default.service.arpa.` name was considered and rejected: it would let a constrained
client and a direct client naming the same real host collide upstream without FCFS ever seeing
it, since the two would occupy different local-store keys right up until the second write
silently overwrote the first at the authoritative server.

## 10. RFC 6763 companion records

RFC 9665 itself never populates two kinds of DNS-SD "browse" record — an SRP client's Service
Description only ever restates its own host/instance data. `pkg/dnssd` (pure logic, kept
separate from RFC 9665 protocol logic in `pkg/srp` since it's a distinct RFC) plus
`SRPHandler.reconcileServiceEnumeration` maintain both, unconditionally, for every `srp_handler`
instance:

- **RFC 6763 §9 Service Type Enumeration** — a PTR at `_services._dns-sd._udp.<zone>`, one per
  distinct two-label service type actually registered (e.g. `_http._tcp.<zone>`). Without it,
  individually-registered services are still resolvable by a targeted per-type browse, but
  "browse everything on this zone" tools — which query this name first — find nothing.
- **RFC 6763 §11 Domain Enumeration** — the `b`/`db`/`lb` (browsing) and `r`/`dr`
  (registration) prefixes under `_dns-sd._udp.<zone>`. `b`/`db`/`lb` are always published, once
  at least one service type is live, as trivial self-pointing PTRs — some browse tools query one
  of these *before* the §9 record, so without it their browse tree dead-ends at the first step
  and never reaches a query the §9 record would otherwise answer correctly. `r`/`dr` are
  opt-in only, via `srp_handler.advertise_registration_domain` (default `false`): unlike
  browsing, these tell a domain-enumeration client "you may attempt direct RFC 2136 registration
  here," which is a deployment policy choice, not something implied by SRP already working on
  the zone.

**Safety on a real, shared, multi-process zone.** Both mechanisms track their own
process-local view of "what's currently live" (reset on every process start, never seeded from
a live upstream read) and only ever delete a record after a live `QueryPTRExists` check at the
real per-type browsing name confirms it's gone everywhere, not just gone from this process's own
view. A naive delete-all-then-reinsert design was tried first and found actively destructive
against the real, shared `dev.zenr.io.` zone: a second proxy process (or a restart of the same
one) has an empty local view, and reconciling from that empty view deleted another, independently
registered instance's still-live entry for a type this process didn't yet know about locally. The
fixed design means a fresh process's first-ever reconcile can only ever *add*, never destroy
another process's or another run's still-valid data. A no-op diff sends no upstream UPDATE at
all.

Both mechanisms reconcile from three call sites: synchronously after a successful registration
or removal, synchronously after an expiry, and once per tick from the same periodic
reconciliation pass the lease store's own expiry-timer bookkeeping already uses (a self-heal
after a restart or a missed/raced write). Scope is `srp_handler` only — the base RFC 9664
`UpdateHandler` accepts arbitrary RRs and has no concept of a "service description" to key this
off of.

## 11. Known limitations and possible future work

- **Source-address filtering** (§3.1.3) — the config option and check point exist, but the
  allow-list is always empty in practice (allow-all); real prefix-based filtering has not been
  implemented.
- **RSA SIG(0) algorithms** (RSAMD5/RSASHA1/RSASHA256/RSASHA512) still carry the RDATA-only
  hashing bug described in §8, unlike ED25519/ECDSAP256SHA256/ECDSAP384SHA384. Extending the fix
  would need a real RSA key and, ideally, an independent implementation's signature to validate
  against, neither of which exists in this codebase today.
- **A prohibited-name dictionary, a pre-registered-keys-only mode, and reverse-PTR
  auto-population** (all optional registrar features RFC 9665 permits but doesn't require) are
  not implemented.
- **Withholding the KEY record from queries** (a privacy option RFC 9665 discusses) is not
  achievable under this proxy's forward model — the KEY is written into the real authoritative
  zone, which the proxy itself does not serve. This would only be possible under a standalone
  authoritative registrar, which is a permanently out-of-scope architecture for this project (the
  proxy always forwards to a separate authoritative server it does not run).
- **OpenThread network-level interop** was investigated and found architecturally infeasible
  without a full Thread Border Router (`openthread/ot-br-posix`): OpenThread's SRP client/server
  run as CLI commands inside a simulated Thread mesh node whose "radio" is a closed bus between
  processes on one host, with no interface anything outside the simulation (including this
  project's code) can reach. A real Border Router is a separate, materially heavier project.
  What exists instead is a genuine cross-implementation regression fixture: a real signed SRP
  registration message captured directly from OpenThread's own client
  (`pkg/srp/srp_test.go`'s `TestValidate_RealOpenThreadCapture`,
  `pkg/sig0/ecdsa_test.go`'s `TestECDSAP256KnownAnswerFromOpenThread`), giving independent
  cross-implementation signal without needing live network interop.
- **`mDNSResponder`'s own `srp-dns-proxy` reference binary** (an SRP-to-RFC-2136 registrar from
  the same upstream project, architecturally the closest external analog to this project's own
  forward path) does not build in the pinned upstream snapshot — unrelated source drift in that
  checkout, not something this project's own code can fix. It remains useful as a source-level
  reference only.

## 12. Testing and interop

- `make test-srp` runs a full register → refresh → conflict → remove-one → remove-all → expiry
  suite against a disposable local BIND 9, with no external dependency — this is the CI gate.
- `make test-mdnsresponder-interop` runs the same registrar, plus `client/srp`, against the
  real, unmodified Apple `mDNSResponder/ServiceRegistration` binaries (a sibling checkout, not
  vendored — see `tests/README.md` for setup and the exact pinned commit). It covers plain
  registration, host-only registration, and all three subtype variants in the direction of a real
  `srp-client` against this project's registrar; and Register plus Deregister in the direction of
  `client/srp` against the real `srp-mdns-proxy` registrar. (`srp-client`'s own
  `--remove-added-service`/`--delete-registrations` flags were found to hang indefinitely — a
  confirmed bug in that binary's own reconnect logic, unrelated to this project, and not
  exercised by the test as a result.)
- The real, shared `srp.dev.zenr.io.` zone (under `zenr.io.` at `ns1.free2air.org`) is a
  developer-visible environment other people can `dig`/browse against directly; see
  `docs/srp-live-demo.md` for a walkthrough. Local BIND 9 (above) is what CI actually gates on.

## 13. SRP requester (`client/srp` and `cmd/sig0lease-srp-client`)

`client/srp` is the actual client-side deliverable. `cmd/sig0lease-srp-client` is a thin,
non-shipped CLI over it for development and testing — there's deliberately no `make
build-srp-client` target.

Capabilities:

- **Discovery** — a real `_dnssd-srp._tcp.<domain>.` SRV lookup (RFC 9665's own discovery
  convention), used whenever no explicit registrar address is configured.
- **Register** — one build-sign-send-interpret cycle. Supports a bare host registration (no
  service instances), any number of service instances, multiple addresses, multiple TXT strings
  per instance, and DNS-SD subtypes per instance.
- **Deregister** — withdraws the host and every configured instance in one message, requesting
  `LEASE=0`. RFC 9665's own removal signal is structural (zero address adds in the Host
  Description); some real-world registrars (`srp-mdns-proxy`) additionally require
  `LEASE=0`/`host_lease==0` before recognizing a zero-address host update as a removal at all, so
  `client/srp` sends both — fully RFC 9665-conformant either way.
- **Full lifecycle (`Run`)** — an initial 0–3s random startup delay, register-with-rename-retry
  on conflict (a `YXDOMAIN` renames both the host label and every instance label together with
  the same incrementing suffix, since the RCODE alone never says which name conflicted), then
  sleeps for the RFC 9664 §5.2 refresh clock (80% of the *granted*, not requested, lease plus
  0–5% jitter) and repeats, unattended, until canceled. A transient send/network error retries
  with exponential backoff (5s up to 5m, reset on success) rather than terminating the client
  permanently, reported via an injectable error hook.
- **Identity/keystore** — `-keystore=<dir>` with a `CLIENT_KEYSTORE_DIR` environment-variable
  fallback (the same convention as `cmd/sig0lease-client`); a missing key is an error unless
  `-k=13` (ECDSAP256SHA256) or `-k=15` (ED25519) is given, in which case one is generated for
  that host+domain identity and reused on every later run.

`go run ./cmd/sig0lease-srp-client -h` lists every flag.
