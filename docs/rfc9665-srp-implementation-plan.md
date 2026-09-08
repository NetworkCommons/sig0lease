# RFC 9665 (DNS-SD Service Registration Protocol) — Implementation Plan

Status: **draft for review** · Scope: `./main` (proxy + client) · Builds on: the RFC 9664
Update‑Lease implementation already in `handlers/opcode5*`, `pkg/lease`, `pkg/sig0`.

This document proposes how to add **SRP registrar** support to the proxy and
**SRP requester** support to the client, lists the decisions that need to be made
(with pros/cons and a recommendation for each), and calls out the issues that are
likely to bite during implementation.

---

## 1. Executive summary

RFC 9665 (SRP) is *not* a new wire option. It is a **profile of DNS UPDATE**: a
tightly constrained message shape (three kinds of "instruction"), a specific
authentication model ("First Come, First Served" naming with SIG(0)), and a set
of maintenance rules — all layered on the RFC 9664 Update‑Lease option we already
support.

The proxy today implements a *general‑purpose* SIG(0)‑authenticated leased‑UPDATE
mechanism (the "sig0lease" protocol, see `protocol.md`). SRP is **more
restrictive** than that mechanism in almost every dimension, and it makes a few
assumptions that directly contradict checks the current handler enforces. As a
result:

- **`pkg/*` is highly reusable** — `pkg/lease` (option + store), `pkg/sig0`,
  `pkg/keyrec`, `forward`, `pkg/dnscompat` all carry over.
- **The request‑handling logic is not** — SRP needs its own message classifier,
  its own validator, its own FCFS/authorization model, and its own response
  codes. It should be a **sibling handler**, not a layer on top of
  `UpdateHandler`.
- The honest answer to "can this be additional packages that build on the
  existing proxy?" is: **yes for the plumbing, no for the policy.** The recommended
  shape is a new `pkg/srp` + a new handler, plus a small refactor that lifts the
  genuinely shared plumbing out of `UpdateHandler` into an internal package both
  handlers use.

---

## 2. What RFC 9665 actually requires

### 2.1 The SRP Update message (§3.2.1, §3.3.1)

A single DNS UPDATE (opcode 5) containing **only** the following, grouped into
"instructions":

| Instruction | Contents | Notes |
|---|---|---|
| **Host Description** (exactly 1) | `Delete All RRsets` on the hostname · exactly 1 `KEY` add · 0..n `A`/`AAAA` adds | 0 address adds = delete registration. The hostname's KEY is the FCFS anchor. |
| **Service Description** (0..n) | `Delete All RRsets` on the service‑instance name · 0..1 `KEY` add · 0..1 `SRV` add · 1..n `TXT` adds (if SRV present) | KEY may be omitted → inherits the Host Description KEY. SRV target **must** equal the Host Description hostname. |
| **Service Discovery** (0..n) | exactly 1 `PTR` add **or** exactly 1 `PTR` delete, target = a service‑instance name that has a Service Description in the same update | One instruction per subtype. |

Hard requirements:

- **Exactly one hostname** in the whole update (>1 ⇒ not an SRP update).
- **No prerequisites** (any prerequisite ⇒ not an SRP update).
- **Must** carry an 8‑byte Update‑Lease option with `LEASE ≤ KEY-LEASE`
  (missing, or `KEY-LEASE < LEASE` ⇒ not an SRP update).
- **All KEY RRs identical** and equal to the SIG(0) signing key; KEY `flags` field
  **all zeroes** from requesters; registrar **must** store flags as received.
- **TTL consistency** within every RRset in the update (§4) — reject with `REFUSED`
  if violated; registrar may clamp TTLs to `[min,max]` and `≤ lease`.
- Any add/delete that is not part of a recognised instruction ⇒ **not an SRP
  update** ⇒ registrar `MAY` process as plain RFC 2136 (if it does that at all),
  otherwise **must** reject with `REFUSED`.

### 2.2 Validation & FCFS (§3.3.2, §3.3.3)

1. Message is a syntactically valid RFC 2136 UPDATE.
2. Classify every instruction; confirm the whole‑update requirements (§2.1).
3. **FCFS name check**: for the hostname and each service‑instance name, if the
   name already exists in the zone, its stored `KEY` **must** match the update's
   KEY for that name (explicit or inherited). Mismatch ⇒ **`YXDOMAIN`** ("pick a
   new name").
4. **SIG(0) check**: verify the signature against the KEY in the Host Description.
   Fail ⇒ **`REFUSED`**.
5. Apply as a normal RFC 2136 update. After applying, every updated Service
   Description must carry a KEY equal to the Host Description KEY.
6. Response RCODE ∈ {`NOERROR`, `SERVFAIL`, `REFUSED`, `YXDOMAIN`}; response
   **must** echo the granted `LEASE`/`KEY-LEASE`.

### 2.3 Maintenance (§5.1)

- Lease time governs the **hostname**. When the hostname lease expires, the
  hostname **and every service that targets it** are removed together.
- Registrar also tracks a **per‑service‑instance** lease (a requester may
  re‑register a host with a different service set and forget the old one).
- KEY records survive on the **KEY‑LEASE** schedule (longer — typically 14 days)
  even after the data lease expires: this is what reserves the name.
- A Service Discovery PTR is removed whenever its target service instance is
  removed (it has no KEY of its own).
- Requester computes expiry from *send* time, registrar from *receive* time;
  refresh at 80% + 0–5% jitter (RFC 9664 §5.2).

### 2.4 Transport & crypto (§3.1.3, §6, §7)

- Non‑constrained networks: **TCP required** (anti off‑path spoofing); registrar
  relying on the handshake **must not** accept TCP Fast Open payloads.
- Registrar **must** offer **DNS‑over‑TLS** (opportunistic; no key auth).
- Constrained (CNN) requesters may use UDP **iff** the network does source‑address
  filtering; they target `default.service.arpa.`.
- Registrar **must** implement **ECDSAP256SHA256 (algorithm 13)** for validation;
  should implement other alg ≥ 13; requesters must not assume alg < 13.
- Registrar `SHOULD` reject updates from source addresses outside its admin domain.

### 2.5 Optional registrar behaviour (§3.2.3.1, §3.3.6, §7)

Rewrite `default.service.arpa.` → a real zone; auto‑populate reverse PTR;
restrict to pre‑registered keys; maintain a prohibited‑name dictionary; withhold
KEY records from queries for privacy.

---

## 3. Gap analysis — current implementation vs. SRP

| Area | Current `UpdateHandler` behaviour | SRP requirement | Verdict |
|---|---|---|---|
| **Message model** | Individual KEY RRs + non‑KEY RRs; dispatch on a `LEASE`/`KEY-LEASE` 4‑case matrix (A/B/C/D) | Instruction grammar (Host/Service Description, Service Discovery) with cross‑RR constraints | **New parser + validator** |
| **Allowed RR types** | Anything except a configurable blacklist | Only `KEY`, `A`, `AAAA`, `SRV`, `TXT`, `PTR` in prescribed positions | **New (stricter) filter** |
| **Deletes** | RFC 2136 RR‑delete (class NONE) and a cascade delete via Case C | `Delete All RRsets From A Name` (`*dns.ANY`, class `ANY`) is the core primitive; also `Delete An RR From An RRset` for PTRs | **New — `Delete All RRsets` not handled today** (`extractUpdateRecords` would drop a `*dns.ANY` into "other" and mis‑process it) |
| **Signer ↔ record hierarchy** | `extractAndValidateSig0` requires the signer be **at or above the zone**; `validateSignerHierarchyForUpdateRecords` requires every update RR owner be **at or below the signer**. Works because the current client sends the *key name* as the zone. | Signer (hostname KEY) is **below** the zone; it registers a **sibling** PTR at `_svc._tcp.<zone>`. | **Directly contradicts current checks** — SRP update would be rejected by both. Confirms sibling handler. |
| **Duplicate protection** | `filterDuplicateRegistrations` / `authoritativeHasRR` **fail the request** if an identical RR already exists at authoritative DNS (protocol.md item 6) | SRP explicitly **replaces** (`Delete All RRsets` then add); "already there" is normal | **Must not run** for SRP |
| **Name ownership** | `ParentKeyName` in the lease tree; a signer may only touch its own subtree | FCFS: any name whose stored KEY == the update's KEY may be updated; mismatch ⇒ `YXDOMAIN` | **New FCFS engine** (the tree can still store it) |
| **`KEY-LEASE == 0`** | Legal (Case B = non‑KEY‑only) | Illegal for a registration (`LEASE ≤ KEY-LEASE`, both non‑zero) | Different rule set |
| **RCODEs** | `NOERROR` / `FORMERR` / `REFUSED` / `SERVFAIL` | adds **`YXDOMAIN`** | New response path |
| **TTL consistency** | not enforced | enforced (§4) | New check |
| **Response** | echoes granted `LEASE`/`KEY-LEASE` ✅ | same | **Reusable** |
| **Lease store / expiry / cascade / reconciliation / file persistence** | `pkg/lease` tree, per‑node timers, `processExpiredLease`, `startLeaseReconciliation`, `FileLeaseStore` | host→service cascade, KEY survives data lease, per‑instance lease, PTR cleanup | **~80% reusable** (see §4.4) |
| **Upstream forward + re‑sign** | `UpstreamCoordinator` resolves SOA MNAME, re‑signs with proxy key, forwards | Registrar is authoritative or a hidden primary; test setups forward to RFC 2136 (Appx A/B) | **Reusable, but see the `service.arpa` problem in §5.4** |
| **SIG(0) verify (crypto)** | `pkg/sig0`; custom ED25519 (alg 15) path + `dns.CryptoSIG0` for others | alg 13 is the MUST | `dns.CryptoSIG0` already maps alg 13 → SHA‑256; **needs a real test**, low risk |
| **Transport** | UDP + TCP via `codeberg.org/miekg/dns` server | TCP‑required; TLS‑required | TCP enforce = easy; **TLS = new** |
| **Admin/dump endpoint, config loader, logging** | present | — | **Reusable** |

---

## 4. Proposed architecture

### 4.1 Package layout

```
pkg/srp/                     NEW — pure logic, no network, no DNS I/O
  instruction.go             instruction types + classifier (message -> []Instruction)
  validate.go                §3.3.1 / §3.3.2 whole-update validation, TTL consistency
  fcfs.go                    §3.3.3 name/key conflict evaluation (pure, takes a store view)
  update.go                  SRP-update builder (used by the client)
  response.go                RCODE mapping + granted-lease echo
  names.go                   service-instance / host / PTR name helpers, subtype handling
  srp_test.go ...            table-driven, mirrors handlers/opcode5_behavior_test.go

internal/updatecore/         NEW — shared plumbing lifted out of UpdateHandler
  upstream.go                SOA/NS resolution, constructUpstreamUpdate/Delete, re-sign
  authlookup.go              authoritative RR lookup helpers
  (UpstreamCoordinator interface moves here or stays in handlers and is imported)

handlers/
  srp_handler.go             NEW — implements handlers.Handler for opcode 5 (SRP path)
  srp_setup.go               NEW — config parsing for the srp block
  opcode5*.go                unchanged behaviour; refactored to call internal/updatecore

server/
  router.go                  small change: opcode 5 -> a dispatcher (see 4.2)

cmd/
  sig0lease-srp/main.go      NEW — SRP requester CLI  (decision D8)

client/
  srp/                       NEW — requester helpers: discovery, refresh scheduler,
                             conflict-retry loop  (wraps pkg/srp + client.Client)
```

Nothing in `pkg/lease`, `pkg/sig0`, `pkg/keyrec`, `pkg/dnscompat`, `forward`,
`config`, `logging` needs to change structurally (a few additive helpers only).

### 4.2 Routing / dispatch

The router currently maps `opcode 5 → "update_handler"` (one module per opcode).
SRP and the generic sig0lease mechanism both arrive as opcode‑5 UPDATE with an
Update‑Lease option. Options:

**Recommended — a thin opcode‑5 dispatcher** (`server` or a `handlers.CompositeUpdateHandler`):

1. `pkg/srp.Classify(msg)` →
   - `IsSRPUpdate` → **SRP handler**
   - `IsLeaseUpdate` (Update‑Lease option, not SRP‑shaped) → **generic `UpdateHandler`**
   - neither → forward upstream (existing behaviour)
2. Classification is cheap (the message is already fully unpacked by
   `fullUnpackHandler`) and is exactly the discrimination RFC 9665 §3.3.2
   describes ("not an SRP update ⇒ ...").
3. Config decides whether the generic path is even enabled, and on which zones
   each path is allowed (decision D10).

This keeps each handler's `Handle()` single‑purpose and testable, and makes the
"SRP‑or‑plain‑2136" fork a first‑class, logged decision.

### 4.3 What the SRP handler does (happy path)

```
Handle(ctx, w, r):
  1. classify -> instructions           (pkg/srp)         ; REFUSED if not SRP-shaped
  2. whole-update validation            (pkg/srp)         ; REFUSED / FORMERR
     - single hostname, no prereqs, lease present & LEASE<=KEY-LEASE
     - TTL consistency
     - KEY equality across instructions
  3. source-address check (optional)                      ; REFUSED
  4. FCFS name check vs lease store + authoritative        ; YXDOMAIN on key mismatch
  5. SIG(0) verify against Host Description KEY            ; REFUSED
  6. (optional) default.service.arpa. -> real zone rewrite
  7. build upstream UPDATE = the same adds/deletes, re-signed with proxy key
     (internal/updatecore) ; forward to authoritative
  8. on upstream NOERROR: stage lease-store mutations
     - host KEY node (KEY-LEASE schedule)
     - service-instance KEY nodes, parent = host node (KEY-LEASE schedule)
     - SRV/TXT/PTR as non-KEY children of the service node (LEASE schedule)
     - A/AAAA as non-KEY children of the host node (LEASE schedule)
     - subtype PTRs: atomic replace of the whole subtype set (§3.3.4)
  9. schedule expiry timers (reuse scheduleLeaseExpiry)
 10. response: NOERROR + echo granted LEASE/KEY-LEASE  (reuse buildSuccessResponse)
```

Reused almost verbatim from `UpdateHandler`: steps 7, 9, 10, the deferred‑mutation
pattern (never touch the store before upstream confirms), `processExpiredLease`,
`startLeaseReconciliation`, `FileLeaseStore`, the dump endpoint.

### 4.4 Lease‑store mapping (reuse `pkg/lease`)

The existing tree already models most of SRP:

| SRP concept | `pkg/lease` node | Schedule |
|---|---|---|
| Hostname + its KEY | KEY `Record`, root of the zone subtree | `KeyLeaseDuration` |
| `A`/`AAAA` for the host | `NonKEYRecord`, `ParentKeyName` = host node | `LeaseDuration` |
| Service instance + its KEY | KEY `Record`, `ParentKeyName` = host node | `KeyLeaseDuration` |
| `SRV`/`TXT` for the instance | `NonKEYRecord`, parent = service node | `LeaseDuration` |
| Service Discovery `PTR` | `NonKEYRecord`, parent = service node | `LeaseDuration` |

Why it fits:
- Same key at two names (`host` and `demo._ipps._tcp...`) = two distinct nodes
  (node key is name+algo+keytag). ✅
- Host‑expiry cascade to services = `DeleteSubtree` / `ListSubtreeKeys` cascade
  that `processExpiredLease` already does. ✅
- KEY node outliving its non‑KEY children (FCFS name reservation) = already the
  model (KEY `ExpiresAt` vs child `ExpiresAt`). ✅

Gaps to close (all additive):
1. **PTR‑at‑expiry rule** — when a service node is removed, its Service Discovery
   PTRs must go too. If PTRs are children of the service node this is free; if a
   PTR RRset lives at `_svc._tcp.<zone>` shared by multiple instances, deletion
   must be "delete *this* PTR RR", not "delete the RRset". `RecordKey` already
   keys non‑KEY nodes per‑RR, so multiple PTRs coexist; need a cascade hook
   "on service node delete, also delete non‑KEY PTR nodes whose RDATA targets it"
   regardless of tree position. Cleanest: **make the PTR a child of the service
   node** and rely on the existing subtree cascade.
2. **Subtype atomicity (§3.3.4)** — "whatever is in this update is the entire
   truth for this service+subtypes". Needs a per‑update "replace set" operation
   on the service node's PTR children rather than incremental upsert.
3. **`RegisterWithParent` currently rejects a non‑KEY as a parent** — fine, we
   never need that; but a service *KEY* under a host *KEY* is allowed. ✅
4. **Snapshot format** — adding PTR/subtype semantics may bump
   `leaseSnapshotVersion` from 2 → 3 (the loader already hard‑fails on version
   mismatch, so no silent data loss).

**Decision D3** covers "reuse vs. new store".

---

## 5. Decisions to make

### D1 — Sibling SRP handler vs. extend `UpdateHandler`

| Option | Pros | Cons |
|---|---|---|
| **A. New `handlers/srp_handler.go` + `pkg/srp` (recommended)** | Clean separation of two genuinely different auth/validation models; each `Handle()` stays testable; SRP conformance not muddied by sig0lease‑specific rules; can ship without touching the working RFC 9664 path | Some duplicated glue unless we do the `internal/updatecore` refactor; two code paths to maintain |
| B. Add an "SRP mode" branch inside `UpdateHandler` | One handler | The case matrix, hierarchy checks, duplicate rejection, and `KEY-LEASE==0` semantics all need per‑mode conditionals; high risk of regressing the 9664 path; `Handle()` is already 760 lines |
| C. SRP handler *wraps* `UpdateHandler` and pre‑transforms the message | Reuses forwarding | The transform is most of the work anyway, and the wrapped handler still enforces incompatible checks |

**Recommendation: A**, plus lift shared plumbing into `internal/updatecore` so "build
on the existing proxy" is real reuse, not copy‑paste.

### D2 — Opcode‑5 dispatch

| Option | Pros | Cons |
|---|---|---|
| **A. Classifier/dispatcher in front of opcode 5 (recommended)** | Matches RFC 9665 §3.3.2 wording; keeps handlers single‑purpose; the SRP‑vs‑2136 decision is logged | Small `router.go` change; need a `Classify` that is conservative (never misfile a plain update as SRP) |
| B. SRP handler runs first, returns `StatusNotRelevant` when not SRP‑shaped, generic handler second | No router data‑model change | Router today is 1 module per opcode; still needs a change to chain two; ordering is implicit |
| C. Route by zone (config: "these zones are SRP zones") | Simple; operators think in zones anyway | A zone can legitimately carry both (SRP for `_svc._tcp` names, plain leases elsewhere); still need shape classification as a backstop |

**Recommendation: A**, with zone allow‑lists from config feeding the dispatcher
(so C's operator model is available too).

### D3 — Reuse `pkg/lease` store vs. new SRP store

| Option | Pros | Cons |
|---|---|---|
| **A. Reuse `pkg/lease` with additive PTR/subtype helpers (recommended)** | Expiry timers, cascade, reconciliation, file persistence, dump endpoint all come for free; one store to reason about; §4.4 shows the mapping works | Must add PTR‑cascade + subtype‑replace; snapshot bump to v3; some SRP‑specific invariants live in the handler not the store |
| B. New `pkg/srp/store` purpose‑built for host/service/PTR | Data model matches SRP 1:1 | Re‑implements timers, cascade, reconciliation, persistence — a lot of the hardest, most‑tested code in the repo |
| C. Reuse the *interface* (`lease.LeaseStorage`), new implementation | Backend swap is already a config option | Same re‑implementation cost as B |

**Recommendation: A.** Prototype the mapping in Phase 1 against the RFC's own
example zone (Appx C) before committing.

### D4 — Authoritative model

| Option | Pros | Cons |
|---|---|---|
| **A. Keep "resolve SOA MNAME, re‑sign with proxy key, forward" (recommended for parity)** | Identical to the working 9664 path; matches RFC 9665 Appx A/B test topology; proxy needs no zone data of its own | The `default.service.arpa.` resolution problem (D5); proxy KEY is a single high‑value credential; upstream/local divergence risk already documented for 9664 |
| B. SRP proxy is itself authoritative for the SRP zone (serve the RRs from the lease store) | No re‑sign, no forward, no divergence; natural fit for `default.service.arpa.` | Large new surface: a real authoritative responder, zone transfer / NOTIFY story, DNSSEC signing; out of scope for a first cut |
| C. Static per‑zone "SRP upstream target" in config (skip SOA discovery) | Sidesteps D5 for `default.service.arpa.`; deterministic in labs | Operator must keep it correct; doesn't generalise to hidden‑primary fleets |

**Recommendation: A for real zones, C as an explicit per‑zone override** (covers
`default.service.arpa.` and CI without building an authoritative server). Revisit B
only if a standalone registrar becomes a goal.

### D5 — `default.service.arpa.` handling

`default.service.arpa.` has no public delegation, so `DefaultUpstreamCoordinator`'s
`resolveSOAMasterServer` (via `8.8.8.8`) cannot find where to forward.

| Option | Pros | Cons |
|---|---|---|
| **A. Config‑driven rewrite `default.service.arpa.` → `<real-zone>` before forwarding (recommended)** | This is the RFC's own suggested mechanism (§3.1.2); real zone is publicly resolvable; one knob | Name rewriting in RRs (PTR targets, SRV targets, owner names) is fiddly and must be consistent; response names must be rewritten back |
| B. Static upstream target for `default.service.arpa.` (D4‑C), no rewrite | Simplest for a closed network | The zone is only locally meaningful; useless for cross‑network discovery |
| C. Only support explicitly‑configured real SRP zones in v1; `default.service.arpa.` later | Smallest v1 | CNN requesters (which *only* use `default.service.arpa.`) unsupported at first |

**Recommendation: C for v1** (support configured real zones — e.g.
`srp.example.com.`), **A in a fast follow**. Document that CNN/`default.service.arpa.`
lands with the rewrite feature.

### D6 — Transport hardening

| Sub‑decision | Recommendation |
|---|---|
| Enforce **TCP‑required** for SRP on non‑CNN zones | **Yes** — reject a UDP SRP update with `REFUSED` unless the zone is flagged `allow_udp` (CNN). Cheap: `w.RemoteAddr()` network is known. |
| Reject **TCP Fast Open** payloads | The `codeberg.org/miekg/dns` server does not expose TFO; document as "not enabled, therefore compliant", add a test asserting no early‑data path. |
| **DNS‑over‑TLS** (registrar MUST offer) | **Phase 6, separate.** `server.serveNetwork` would gain a `"tls"` case with a `tls.Config` (cert from config). Opportunistic only — no client‑key pinning. Non‑trivial but self‑contained. |
| **Source‑address allow‑list** (§6.1 SHOULD) | Optional config `srp.allowed_source_prefixes`; default off (log only). |
| Anycast `2001:1::3` | Out of scope (deployment concern, not proxy logic). |

### D7 — Signature algorithm

- **Add explicit ECDSAP256SHA256 (alg 13) coverage** in `pkg/sig0` tests
  (sign + verify round trip, and verify‑only against a known vector). The
  `dns.CryptoSIG0` base path already handles it; the custom wrapper only forks
  for alg 15. **Low risk, must be proven.**
- Keep ED25519 (alg 15) — used by `sig0namectl` and the existing keystore.
- `keyrec.LoadKeyFromFile` uses `dnsKey.NewPrivate` which handles the ECDSA
  DNSSEC private‑key format — confirm with a P‑256 test key.
- Requester side: generate P‑256 keys by default for SRP (`dns` has
  `GenerateKey` / keygen for alg 13).

### D8 — Client: new binary vs. extend `sig0lease-client`

| Option | Pros | Cons |
|---|---|---|
| **A. New `cmd/sig0lease-srp`, sharing `client/`, `pkg/srp`, `pkg/keyrec` (recommended)** | SRP requester UX is service‑oriented (`--service _ipps._tcp --instance "Printer" --host h --port 631 --txt path=/`), not RR‑oriented; clean help text; doesn't destabilise the existing test‑oriented CLI | Second binary to build/ship (Makefile already cross‑compiles both; adding a third is trivial) |
| B. `sig0lease-client srp register ...` subcommand | One binary | The existing CLI's arg parsing is positional/ad‑hoc; bolting a different arg model on is awkward; conflates "protocol test tool" with "SRP requester" |
| C. Library only (`client/srp`), no CLI | Consumers embed it (the project's stated goal is a library module) | No manual/integration testing entry point; every test needs a Go harness |

**Recommendation: A** — and make `cmd/sig0lease-srp` a thin shell over
`client/srp` so the library‑module goal is still met.

### D9 — Optional registrar features (all default‑off, config‑gated)

| Feature | Recommendation |
|---|---|
| Prohibited‑name dictionary (§6.3) | Phase 4, easy, `REFUSED` (not `YXDOMAIN`) so the requester doesn't just append a number. |
| Pre‑registered‑keys‑only mode (§3.3.6) | Phase 4, reuses keystore loading. |
| Reverse‑PTR auto‑population (§3.3.6) | Phase 4+, needs credentials/authority for the reverse zone — likely out of scope. |
| Withhold KEY from queries (§7 privacy) | Only relevant if D4‑B (authoritative). With the forward model the KEY lands in the real zone; **document this as a known privacy limitation.** |

### D10 — Coexistence of SRP and the generic sig0lease mechanism

RFC 9665 §6.2 warns that mixing SRP and other authenticated updates on the same
names lets a non‑SRP update override an SRP promise.

**Recommendation:** config declares, per zone, which of `{srp, lease}` paths are
enabled. Default: a zone is SRP‑only *or* lease‑only, not both. Same‑zone
coexistence allowed only with an explicit opt‑in and a documented warning.

---

## 6. Likely problem areas (call these out early)

1. **`Delete All RRsets From A Name` parsing.** Represented as `*dns.ANY{Hdr:{Class:
   ClassANY}}` in the fork. `handlers.extractUpdateRecords` does not recognise it —
   the SRP classifier needs its own extraction that understands
   ANY/ANY, class‑NONE (RR delete), and class‑INET (add) per RFC 2136 §2.5. Write
   a focused parser + tests first (spike).
2. **`service.arpa` is locally served** — SOA/NS discovery via public resolvers
   fails (D5). Blocks CNN support until the rewrite exists.
3. **Signer/zone hierarchy checks** in `extractAndValidateSig0` and
   `validateSignerHierarchyForUpdateRecords` reject SRP updates outright. Must be
   bypassed for the SRP path (they don't apply — FCFS is the model).
4. **Duplicate‑registration rejection** (`filterDuplicateRegistrations`,
   `authoritativeHasRR`) is antithetical to SRP's replace semantics. The SRP
   forward path must not run it.
5. **Compressed SRV target names** (§3.2.5.4) — registrar MUST accept them.
   Confirm the fork's unpacker decompresses names inside SRV RDATA in an UPDATE
   message (test with a hand‑built compressed message; the README already
   documents fork quirks around `Pack/Unpack`).
6. **KEY `flags` handling.** Requesters send flags = 0; registrar must store as
   received. Existing keystore keys are often flags 256/257. Client must emit a
   flags‑0 KEY for SRP; registrar must not "correct" it.
7. **TTL consistency + clamping interaction.** New §4 check must run *before*
   `LeasePolicy` TTL clamping, and clamping must keep RRset TTLs equal.
8. **ECDSA P‑256 SIG(0)** — believed fine via `dns.CryptoSIG0`, unproven in this
   codebase. Blocking test in Phase 0.
9. **`YXDOMAIN` response path** — new; `makeErrorResponse` supports arbitrary
   rcodes already, but the client must interpret it as "rename & retry", not
   "hard fail".
10. **Subtype atomicity** (§3.3.4) — "the update is the whole truth for this
    service"; needs replace‑set semantics, not incremental upsert, on PTR
    children.
11. **Per‑service‑instance lease tracking** (§5.1) — a re‑registration that drops
    a service must still expire the dropped instance on its own old timer.
12. **Multi‑message updates** (§3.2.3.3) — requester must serialise; registrar
    must not interleave. Minor, but the client's refresh scheduler must respect it.
13. **`SendUpdate` zone‑equality guard** — `constructUpstreamUpdate` builds the
    upstream message with the *zone* in the question; the SRP zone (real, or
    post‑rewrite) must match what `resolveAuthoritativeZone` returns.
14. **Interop reality check** — validate against a known SRP implementation
    (OpenThread `srp-mdns-proxy`, Apple's `srputil`, or `dnssdutil`) rather than
    only against our own client.

---

## 7. Testing strategy

- **`pkg/srp` unit tests** — table‑driven, one row per RFC 9665 §3.3.1/§3.3.2
  clause: valid SRP updates, near‑misses that must be rejected ("looks like SRP
  but the PTR target has no Service Description"), TTL inconsistency, KEY
  mismatch, missing lease, `KEY-LEASE < LEASE`, >1 hostname, prerequisites
  present. Mirror `handlers/opcode5_behavior_test.go` style.
- **FCFS tests** — new name; same‑key refresh; different‑key ⇒ `YXDOMAIN`;
  name held by KEY‑lease after data lease expiry.
- **Handler tests** — mock `UpstreamCoordinator` (pattern already in the tests),
  assert forwarded message shape, RCODE mapping, lease‑store mutations, deferred‑
  mutation ordering (nothing written before upstream `NOERROR`).
- **Lifecycle tests** — host‑expiry cascades to services + PTRs; service‑instance
  expiry removes just that instance + its PTRs; KEY survives to KEY‑LEASE.
- **Crypto tests** — alg 13 sign/verify; alg 13 keystore load; flags‑0 KEY.
- **Integration script** — `tests/test_srp.sh` alongside `tests/test_update.sh`,
  against BIND 9 authoritative for a real zone (e.g. `srp.dev.zenr.io.`): full
  register → resolve via `dig` → refresh → conflict (`YXDOMAIN`) → remove‑one →
  remove‑all → expiry. Reuse `tests/utils.sh` and the lease‑dump helpers.
- **Interop (stretch)** — one recorded transaction from a third‑party SRP client
  replayed against our registrar, and our client against a third‑party registrar.

---

## 8. Phased roadmap

| Phase | Deliverable | Gate |
|---|---|---|
| **0 — Spikes** | (a) `Delete All RRsets` / instruction parser proof; (b) alg‑13 SIG(0) round‑trip test; (c) confirm compressed‑SRV unpack; (d) confirm `default.service.arpa.` forwarding is blocked as expected | De‑risks the unknowns before committing to the design |
| **1 — `pkg/srp` core** | instruction model + classifier + `Classify()` + whole‑update validator + TTL check; full unit tests; no network | `pkg/srp` validates the RFC's Appx C example and a corpus of near‑misses |
| **2 — FCFS + store mapping** | `pkg/srp/fcfs.go`; PTR‑as‑service‑child + subtype‑replace additions to `pkg/lease`; snapshot v3 | Lifecycle unit tests green |
| **3 — SRP handler + routing** | `internal/updatecore` refactor; `handlers/srp_handler.go`; dispatcher in `router.go`; `srp` config block; forward + re‑sign + RCODE mapping (incl. `YXDOMAIN`) | Handler tests green against mock upstream |
| **4 — Registrar options** | prohibited‑name dictionary; pre‑registered‑keys mode; source‑address allow‑list; TCP‑required enforcement | Config‑gated, default‑off, tested |
| **5 — Client** | `client/srp` (builder + discovery + refresh scheduler + conflict retry + initial random delay); `cmd/sig0lease-srp` | End‑to‑end against the Phase 3 registrar |
| **6 — `default.service.arpa.` rewrite** | zone‑rewrite in the forward path (RRs + response); CNN/`allow_udp` zones | CNN requester round‑trips |
| **7 — DoT + interop** | `"tls"` listener in `server`; opportunistic TLS; interop pass with a third‑party implementation | Registrar "MUST offer TLS" satisfied |

Phases 1–3 are the critical path to a usable SRP registrar for **configured real
zones**. Phase 5 makes it end‑to‑end testable without a third‑party client.
Phases 6–7 close the remaining MUSTs.

---

## 9. Open questions for the team

1. **Target deployment** — real zones only (e.g. `srp.example.com.`), or is
   CNN / `default.service.arpa.` a v1 requirement? (Drives D5 priority.)
2. **Standalone registrar** ever a goal (D4‑B), or is the forward‑to‑RFC‑2136
   model the permanent architecture?
3. **DoT** — required for the first milestone, or acceptable as Phase 7? (RFC
   says registrar MUST offer it; a lab/internal deployment may accept the gap
   temporarily.)
4. **Same‑zone coexistence** of SRP and the generic sig0lease mechanism —
   needed, or is "one zone, one protocol" acceptable? (D10.)
5. **Client packaging** — is the library (`client/srp`) the primary deliverable
   with the CLI as a test tool, or is the CLI a shipped product?
6. **Interop target** — which third‑party SRP implementation do we test against?
