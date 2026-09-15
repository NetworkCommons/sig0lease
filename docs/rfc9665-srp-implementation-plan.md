# RFC 9665 (DNS-SD Service Registration Protocol) — Implementation Plan

Status: **Phase 7 done (2026-09-14)** — DNS-over-TLS (RFC 7858) is implemented:
`server/transport_tls.go`'s `serveDoT`, wired in as a `"tls"` entry in `server.networks`
plus a new `server.tls: {address, cert, key}` config block. Transport-level, like every
other listener the server already runs, so it benefits every handler (base RFC 9664, SRP,
plain forwarding) rather than being SRP-specific — opportunistic only, no client-certificate
authentication, matching what the plan called for. Reuses the existing `serveNetwork`
plumbing unchanged (added a `tlsConfig *tls.Config` parameter, nil for plain udp/tcp) rather
than duplicating the listener-lifecycle/graceful-shutdown logic. Live-smoke-tested against
the real `cmd/sig0lease` binary — a real `openssl`-generated cert, queried with real
`dig +tls`: genuine TLS handshake, correct forwarded answer back over the wire, not just a
unit test. `TestServeDoT_RoundTrips`/`TestServeDoT_MissingTLSConfig` plus 4 `config.Validate`
cases, all green. §13 has the full writeup — this was the plan's last remaining phase; all
seven are now done.

Phase 6 — the `default.service.arpa.` zone-rewrite (D5) is
implemented: a new `rewrite_default_service_arpa` config flag lets a zone accept requests
addressed to `default.service.arpa.` (every real SRP client hardcodes it, having no other
way to discover a zone) in addition to its own configured `upstream_zone`, rewriting every
name in the update before FCFS/forwarding so the rest of the pipeline, the local lease-store
tree, and the authoritative server all work with exactly one real name per host, regardless
of which zone the client actually addressed. Required reordering the handler's own pipeline
(SIG(0) verify now runs before FCFS, not after — see §4.3's revised step list for why) and a
`pkg/updatecore`-adjacent name-rewrite pass in `handlers/srp_handler.go`
(`rewriteDefaultServiceARPA`/`rewriteZoneSuffix`). Live-validated against real BIND 9 using
the actual, unmodified mDNSResponder `srp-client` binary (not just unit tests): registered
against a proxy configured for `srp.test.`, `dig`-confirmed the data landed under
`srp.test.` and nothing orphaned at `default.service.arpa.`. Six new tests (three
handler-level, two pure-function, one FCFS-unification proof). §13 has the full writeup.
Phase 5 — both primary interop directions confirmed live against the
local `mDNSResponder/ServiceRegistration` build (§12.3), on top of a scratch
`default.service.arpa.` BIND 9 zone: the real, unmodified `srp-client` registered
successfully against our registrar (`rcode=0`, dig-confirmed at authoritative — including
that the real independent alg-13 (ECDSAP256SHA256) signature the Phase 0/1 risk was
originally about verified correctly, and flags=513 passed through unmodified exactly
matching the Phase 1 captured-message finding, now reproduced live rather than from a fixed
capture); and `client/srp` (our own Phase 4 requester) sent a real registration to the real
`srp-mdns-proxy`, whose own log explicitly recorded `srp_evaluate: ... validates` with
every field (lease values, host address, instance name/type/port) matching exactly what was
sent — full SRP-protocol-level interop confirmed both ways. That second test's very last
step (publishing to local mDNS) hit an environment-only wall unrelated to protocol
correctness — no `mdnsd` daemon in this sandbox for `srp-mdns-proxy` to connect to — noted,
not chased further (§13's Phase 5 entry has the full detail). OpenThread simulation
(secondary cross-check) not attempted as network-level interop — mDNSResponder alone
already satisfies the "Interop pass" gate as the plan's own named primary; real interop would
need a full Thread Border Router, a separate heavier project (§14). A real OpenThread
cross-implementation fixture was extracted anyway (no network needed for this) —
`pkg/srp/srp_test.go`'s `TestValidate_RealOpenThreadCapture` and `pkg/sig0/ecdsa_test.go`'s
`TestECDSAP256KnownAnswerFromOpenThread`. The OpenThread build-and-self-test CI job
(`tests/test_openthread.sh`) was tried and then **removed** (2026-09-14, interop coverage
expansion entry) — it never exercised our own code, only OpenThread's own test suite.
**Interop coverage substantially widened** (2026-09-14): `tests/test_mdnsresponder_interop.sh`
(new, permanent, checked-in) now covers plain registration, `--host-only`, and all three
subtype variants against our registrar (Direction 1), plus both Register *and* Deregister
(new `client/srp.Client.Deregister`, requesting `LEASE=0` — needed for real interop with
`srp-mdns-proxy`'s own removal-recognition logic) against the real `srp-mdns-proxy`
(Direction 2) — Deregister returns a genuine end-to-end NOERROR, no environment caveat
needed. `srp-client`'s own `--remove-added-service`/`--delete-registrations` flags were tried
live and found to hang forever, a confirmed real bug in that binary's own reconnect logic,
documented rather than silently skipped. §13's interop-coverage-expansion entry has the full
detail, including three real bugs found and fixed while building the test itself. Phase 4 (`client/srp`, `pkg/srp/{update,response}.go`,
`cmd/sig0lease-srp`, one real dnscompat-import bug found via live testing) and Phase 3
(`handlers/srp_handler.go`, D2 dispatch, 20 handler tests, `tests/test_srp.sh`, five real
bugs found and fixed at the edges of the lease/expiry model) remain done from before —
§13 has the full list for each. Phases 0-7 all green (`go test ./...`); alg-13 SIG(0) fixed
and regression-tested (Phase 1) · no further phase currently planned — all seven done ·
Scope: `./main`
(proxy + client) ·
Builds on: the RFC 9664 Update-Lease implementation in `handlers/opcode5*`, `pkg/lease`,
`pkg/sig0`.

Revision history:
- 2026-09-02 — initial draft
- 2026-09-10 — decisions D1–D10 + AD1/AD2 locked; three rounds of review Q&A folded in
  (§11). FCFS is a tri-state query with `srp.refuse_on_foreign_data` defaulting **on** (§3.3);
  worked lease-store tree example (§4.4); test environment resolved with local BIND as the
  CI gate (§14).
- 2026-09-11 — Option A (`srp.dev.zenr.io.` under `zenr.io.`) confirmed working and
  promoted to a deliverable alongside Option C (§14). §4.5 corrected twice: (a) A/AAAA and
  SRV/TXT need wipe-then-reinsert, not plain upsert; (b) simplified further — the local
  mutation for a service node's SRV/TXT/PTR is the *same* uniform wipe-then-reinsert as
  A/AAAA (no new store method at all, §4.4); the only new logic is a pre-wipe diff that
  builds the *upstream* delete for a dropped PTR, since delete-all never reaches it there.
  `client/srp` is now explicitly required to always restate Service Discovery (§4.5, §10).
- 2026-09-11 (later) — the local `mDNSResponder/ServiceRegistration` checkout promoted to
  **primary** interop target, replacing OpenThread simulation in that slot (OpenThread
  stays as secondary) — it's checked out deliberately for this development, builds with one
  `make`, and its own `srp-dns-proxy.c` independently validates D4's forward-to-RFC-2136
  registrar model. New §12.3; updated §2, §10, §13.
- 2026-09-11 (Phase 0) — spikes (a)-(d) and infra item (g) run. mDNSResponder built
  clean (two small upstream-bug patches, §12.3); delete-all-RRsets shape and compressed
  SRV-target decompression both confirmed against a real captured `srp-client` update,
  not just synthetic messages; `default.service.arpa.` confirmed safe by construction
  (code reading, no bug found); alg-13 confirmed working for our own sign+verify round
  trip **but verifying a real independent implementation's signature currently fails** —
  a genuine open risk carried into Phase 1, not yet root-caused (§10 item 8). (e) test
  refactor landed (`tests/lib/*.sh`), including a real pre-existing `test_forward.sh` cwd
  bug found and fixed along the way (§12.1); (f) `pkg/updatecore/ttl.go` built, tested, and
  wired into the base handler. Full validation: `go test ./...` green (incl. new
  `pkg/updatecore` tests), and the complete `test_update.sh` suite green end-to-end against
  the real `dev.zenr.io.` zone, both before and after the refactor (matched A/B comparison)
  — **Phase 0 complete.**
- 2026-09-11 (Phase 1) — root-caused **and fixed** the alg-13 verify risk carried out of
  Phase 0: `codeberg.org/miekg/dns`'s `CryptoSIG0.Sign`/`Verify` hash the SIG RR's full
  wire encoding instead of RDATA-only, violating RFC 2931 §3 — confirmed by instrumenting
  a local copy of the library and independently against `mDNSResponder`'s own C source
  (§10 item 8). User decided: generalize the fix to ED25519 + ECDSAP256SHA256 +
  ECDSAP384SHA384 (D7-B), document but don't report upstream yet (§8, and
  `README_proxy.md`'s new "miekg/dns Shortcomings" subsection). Implemented in
  `pkg/sig0/signer.go`, regression-tested (`pkg/sig0/ecdsa_test.go`, including a
  known-answer test pinned to the real `mDNSResponder` capture), full suite green, real-zone
  ED25519 smoke test green.
- 2026-09-11 (Phase 1 core) — built `pkg/srp`: `Classify()` (instruction model +
  classifier, algorithm closely follows `srp-parse.c`) and `Validate()` (structural checks
  + TTL-reject via `pkg/updatecore` + lease-option + KEY-identity). Full table-driven
  tests, including RFC 9665 Appendix C's own worked example (Figure 2 — a genuine example
  zone file, not just a BIND config sample as earlier assumed) and the real captured
  `mDNSResponder` message. Caught and fixed a real bug in an early draft via the
  real-capture test: KEY flags must never be checked by the registrar, only stored as
  received (§10 item 6, §12.2). Two documented, tested divergences from `srp-parse.c`:
  multiple TXT adds allowed (RFC text says 1..n); no base-type-precedes requirement on a
  subtype PTR *delete* (only on an add). `go vet`/`go test ./...` green throughout. Also
  refined this same day, on the user's request for clarification: the real captured
  `mDNSResponder` KEY's non-zero flags (`0x0201`/513) decode via RFC 2535 §3.1.2's field
  layout to `NAMTYP=10` (non-zone/host entity) + a non-zero `SIG` field ("valid to sign
  dynamic update [RFC 2137]") — the traditional pre-RFC-9665 encoding for a host
  update-signing key, evidently carried over rather than randomness (§10 item 6).
- 2026-09-11 (Phase 2) — `pkg/srp/fcfs.go`: `Evaluate()` implements the S3.3.3 tri-state
  FCFS table via an injected `StoreView` + `AuthoritativeKeyQuery` (no network I/O in this
  package); `Names()`/`KeyFor()` read a `ClassifiedUpdate` for the names FCFS must check
  and the KEY that governs each (S3.2.5.1 inheritance). `pkg/lease/srp_shape_test.go`
  prototypes the S4.4 lease-tree mapping in code, against the *unmodified* store: builds
  the full worked-example tree (host → service KEY node → SRV/TXT/2 PTRs), confirms
  cascade, partial-cascade (service-instance expiry leaves the KEY node + host untouched),
  wipe-then-reinsert dropping a subtype cleanly, and two instances safely sharing a PTR
  owner name (RFC 2136 RDATA-inclusive `RecordKey` identity). Result: **no new `pkg/lease`
  methods, no new `NodeKind`, no snapshot version bump** — revises §4.4's earlier "likely
  v3" hedge now that there's an actual implementation to check it against. Full
  `go test ./...` green throughout, `pkg/lease`'s pre-existing suite unaffected.
- 2026-09-11/12 (Phase 3) — **done.** `pkg/updatecore` extraction (`Coordinator`: SOA/NS
  resolution + D4 static-upstream override + `SendUpdate` + the new tri-state
  `QueryKeyAtName`, ported from `handlers.DefaultUpstreamCoordinator`); `handlers/srp_handler.go`
  + `srp_setup.go` (the S4.3 ten-step happy path); D2 ordered `processing_rules.modules`
  dispatch in `server/router.go`/`config/config.go`/`cmd/sig0lease/main.go`. The wrapper type
  was later removed at user request (a thin indirection layer that made call sites harder to
  read) — `handlers/opcode5.go` and `srp_handler.go` both hold/construct `*updatecore.Coordinator`
  directly now; `SRPHandler.coordinator` is typed as a narrow `srpCoordinator` interface
  purely so tests can substitute a fake.
  **Five real bugs found and fixed, all via live testing (both the real `dev.zenr.io.` zone
  and, once built, the new local BIND 9 harness) — not one was caught by writing code against
  the plan alone, each needed a real authoritative server's actual behavior to surface:**
  1. **KEY inheritance lost the instance's owner name** (`pkg/srp.KeyFor`): a service
     instance with no explicit KEY got back the Host Description's KEY record *verbatim*,
     including the host's own owner name. Since `pkg/lease.NodeKey` is name-scoped, this
     silently collided the instance's lease-store node with the host's own — a live refresh
     of that instance came back REFUSED. Fixed via a `keyAtName` helper (copy the key,
     rewrite just the owner name) per S3.2.5.1's "as if... given for" language.
  2. **`processExpiredNode` deleted only the KEY record, orphaning everything else**: on
     KEY-LEASE expiry it sent a single-RR delete for the KEY alone, never the node's A/AAAA
     or SRV/TXT — those got wiped locally (`DeleteSubtree`) but never touched upstream,
     leaving them permanently stale at the authoritative server. Fixed: a Delete All RRsets
     at the node's own name, plus explicit deletes for every PTR the node holds (a PTR's
     owner name is the shared service *type*, never reached by that delete-all).
  3. **`processExpiredNode` never checked the upstream response's RCODE**: only a
     transport-level error from `SendUpdate` was treated as failure, so a REFUSED/SERVFAIL
     response still fell through to `DeleteSubtree`, removing the node locally even though
     upstream still had it — the deferred-mutation invariant applies to deletes too, not
     just adds. Fixed to check the RCODE exactly like `Handle()`'s own forward step already
     did, leaving the node in place (to be retried by the 30s reconciliation pass) on a
     rejection.
  4. **A host's own successful expiry could cascade-discard a child instance's still-pending
     cleanup**: a host and its instances normally share lease durations and so expire within
     milliseconds of each other via independent timers. If a child's own expiry attempt was
     transiently REFUSED (see #3) and the host's own attempt then succeeded moments later,
     `DeleteSubtree(hostNodeKey)`'s local cascade silently removed the still-unresolved child
     too — permanently losing track of it; no later reconciliation pass could ever find it
     again. Fixed: the expiring node's upstream delete now covers its whole subtree (host +
     every instance + their PTRs), so by the time the local cascade runs, everything really
     has just been deleted upstream too (a harmless no-op for anything already clean).
  5. **`ptrDeleteDiff` skipped removal-shaped instances entirely** (live-update path, not
     expiry), on the mistaken assumption that "the instance's own delete-all already covers
     everything" — it doesn't reach the PTR, owned at the different, shared service-type
     name. A client explicitly removing one service instance left that instance's PTR(s)
     permanently orphaned upstream. Fixed by removing the skip; the existing diff-against-
     nothing logic already does the right thing once every instance (removal-shaped
     included) is considered.
  Also observed (not a code bug, left as an operational note): BIND 9 can transiently REFUSE
  one of two near-simultaneous same-key UPDATE transactions to the same zone (the trigger for
  #3/#4) — root cause not chased further since the fix above makes this correctly self-heal
  within one reconciliation interval; `tests/test_srp.sh`'s expiry test tolerates up to 40s
  for exactly this reason.
  Deliverables: 20 handler-level unit tests (`handlers/srp_handler_test.go`) against a fake
  `srpCoordinator` — happy path, the KEY-inheritance regression (pinned independently of the
  bug's original symptom), FCFS conflict/foreign-data, deferred-mutation ordering, transport
  hardening, SIG(0) rejection paths, instance removal + PTR cleanup, PTR-diff on subtype
  drop, and all five expiry scenarios above; `tests/test_srp.sh` + `tests/lib/bind9.sh` +
  `tests/bind9/{named.conf.in,srp.test.zone.in}` + `tests/keystore-srp-bind9/` +
  `tests/srp_client_tester/` (a minimal Go SRP UPDATE client — client/srp and
  cmd/sig0lease-srp are Phase 4, not built yet — mirroring `tests/blacklisted_tester.go`'s
  own precedent for a test-only Go helper) implementing the plan's own S12.2 checklist:
  register → dig → refresh → conflict (YXDOMAIN) → remove-one → remove-all → expiry, green
  end-to-end against a real local BIND 9 twice in a row. Full `go test ./...` green
  throughout (the only failures are pre-existing, unrelated `pkg/sig0` tests that need
  `CLIENT_KEYSTORE_DIR` set in the shell).
- 2026-09-14 (Phase 4) — **done.** `pkg/srp/update.go`: `BuildUpdate(spec)` constructs an
  unsigned SRP UPDATE (Host Description + Service Description(s) + Service Discovery + 8-byte
  lease option) from a declarative `UpdateSpec`/`InstanceSpec` -- pure logic, no network, and
  always restates every instruction fully (S3.2's "no lightweight refresh"). Deliberately
  encodes multiple TXT strings as ONE `dns.TXT` RR's multi-string RDATA, not multiple separate
  TXT RR adds -- confirmed the right choice, not just a valid one: mDNSResponder's own
  registrar rejects a second, separate TXT add outright (`TestClassify_MultipleTXTAdds`'s own
  doc comment), so this is also the interop-safe encoding. `pkg/srp/response.go`:
  `InterpretResponse`/`GrantedLease`, the registrar-response counterpart to `pkg/srp`'s own
  RCODE production. `pkg/keyrec/generate.go`: `GenerateKey`/`(*LoadedKey).SaveToFile`, reusing
  the same `dns.DNSKEY.Generate`/`PrivateKeyString` round-trip `LoadKeyFromFile` itself reads.
  `client/srp/` (package `srp`, distinct from `pkg/srp`'s own, disambiguated by import alias
  at call sites): `discovery.go` (`Discover`, a real `_dnssd-srp._tcp.<domain>.` SRV lookup --
  RFC 9665's own discovery convention, confirmed against the plan's own Appendix C zone
  skeleton reference and validated live, not just unit-tested); `timing.go` (`refreshDelay`
  implementing RFC 9664 S5.2's 80%-of-lease-plus-0-5%-jitter clock, `initialDelay` for the
  roadmap's 0-3s startup jitter); `client.go` (`Client`/`Config`: `Register` -- one build-
  sign-send-interpret cycle; `registerWithRenameRetry` -- on `OutcomeConflict`, renames BOTH
  the host label and every instance label together with the same incrementing suffix, since
  the RCODE alone never says which name conflicted (S3.3.3 checks every name in the update),
  so retrying with fresh names for everything is the only response that's safe regardless of
  which one actually collided; `Run` -- the full lifecycle: initial delay, register-with-
  retry, sleep the S5.2 clock off the *granted* lease (not the requested one), repeat until
  `ctx` is canceled). Every timing/network dependency (`Rng`, `Sleep`, `Send`, `Query`) is
  injectable via `Config`, so the full retry/scheduling state machine is unit-tested
  deterministically with no real waiting and no real network. `cmd/sig0lease-srp`: a thin CLI
  (D8 -- "the library is the deliverable... not a shipped product"), `-once` for a single
  `Register()` call or the default full `Run()` lifecycle, `-instance`/`-txt`/`-subtype`
  repeatable flags matched by label, `-keystore` to load-or-generate-and-persist an identity.
  **One real bug, found via live testing (not unit tests -- the unit test suite's fake
  transport never exercises real wire (un)packing at all):** `client/srp` built and sent a
  perfectly valid signed UPDATE, but choked trying to read back the registrar's own success
  response (`"dns: no option unpack defined"`) -- `pkg/dnscompat`'s EDNS0 code 2
  (UPDATE-LEASE) registration was never imported anywhere in the new Phase 4 code, so the
  granted-lease option in the response came back as a type this fork's `Unpack` didn't
  recognize. `cmd/sig0lease/main.go` and `cmd/sig0lease-client/main.go` already each do this
  blank-import themselves (an established, if easy-to-forget, per-binary convention in this
  codebase) -- fixed by adding it to `client/srp/client.go` itself instead (so any future
  caller of the *library*, not just this CLI, gets correct behavior automatically), plus
  redundantly in `cmd/sig0lease-srp/main.go` too for consistency with the existing
  convention. Confirmed fixed by re-running the exact failing live sequence afterward.
  **Live end-to-end validation** (real local BIND 9 + the real Phase 3 registrar, not mocks):
  fresh registration (dig-confirmed at authoritative); a genuine refresh (same identity, same
  keystore, no re-registration of the underlying record); a real FCFS conflict correctly
  returning YXDOMAIN; the *full* rename-retry lifecycle via `Run()` (two real YXDOMAIN
  conflicts observed in the registrar's own log, then a successful registration under
  `host-2` -- not simulated); live `_dnssd-srp._tcp.srp.test.` SRV discovery (added to
  `tests/bind9/srp.test.zone.in`, matching the plan's own Appendix C zone skeleton reference,
  resolved against the local BIND 9 via `-resolver`) correctly finding and using the
  registrar; and the unattended S5.2 refresh clock directly observed firing 4 times on its
  own over ~13s with a 5s lease, at ~4.06-4.12s intervals -- within the expected 4.0-4.25s
  window (80% of 5s, +0-5% jitter) with no further input after the process started. The real
  zone was left pristine afterward (confirmed via `dig`), matching every other live-zone test
  this session. Full `go test ./...` green throughout, including the new `client/srp` and
  `pkg/srp` update/response suites (29 new tests total: 8 `pkg/srp` builder + 3 `pkg/srp`
  response + 18 `client/srp`).
- 2026-09-14 (Phase 5) — **done.** Both primary interop directions run live against the
  local `mDNSResponder/ServiceRegistration` build (§12.3, confirmed buildable since Phase
  0). A scratch BIND 9 zone for `default.service.arpa.` was built for this (self-signing
  key, `update-policy { grant default.service.arpa. zonesub ANY; }`) -- both mDNSResponder
  binaries hardcode that exact zone name client-side (`srp-client.c`: `zone_name =
  "default.service.arpa"`; `srp-mdns-proxy.c`: `srp_proxy_init("local")` rewrites an
  incoming `default.service.arpa.` Zone Section to `local.` internally, per
  `srp-parse.c:337`'s `dns_names_equal_text(update_zone, "default.service.arpa.")` check),
  so no Phase 6 zone-rewrite feature was needed to reach either binary -- the SRP handler's
  own `upstream_zone` config was just pointed at `default.service.arpa.` directly for this
  test, with a D4 static `upstream` override at the scratch BIND 9.
  1. **`srp-client` (real, unmodified) against our registrar — full success.** `srp-client
     --server <ip>%<port> --host-name interop1 --lease-time 30 --log-stderr` produced
     `rcode = 0` / `Register Reply for interop1: 0` in the client's own log, and `dig`
     against the scratch BIND 9 confirmed the full registration landed: A record (the
     client's real interface address, auto-detected), KEY record (algorithm 13 /
     ECDSAP256SHA256, **flags 513** -- exactly reproducing the Phase 1 finding from the
     fixed captured-message fixture, now confirmed live against a fresh signature rather
     than a frozen capture), and a complete auto-generated Service Description + Service
     Discovery (`interop1._ipps._tcp.default.service.arpa.`, SRV/TXT/PTR all present).
     This is also the live resolution of the Phase 0/1 open risk in its original form:
     "verifying a real independent implementation's alg-13 signature" -- the fixed code
     was already regression-tested against the frozen capture, but this is the first time
     it was exercised against that same real implementation generating a **fresh** signature
     live, not a replayed fixture.
  2. **`client/srp` (ours) against `srp-mdns-proxy` (real, unmodified) — full SRP-protocol
     success; blocked only at the unrelated final mDNS-publish step.** `sig0lease-srp
     -domain=default.service.arpa. -host=ourclient1 -addr=192.0.2.111 -udp
     -instance=Gizmo:_http._tcp:8080 ...` against `srp-mdns-proxy`'s own ephemeral UDP port
     (it binds `port=0` -- OS-assigned -- discovered via `ss -tulnp`, not a fixed port; real
     deployments rely on mDNS advertisement of that port, orthogonal to `client/srp`'s own
     unicast `_dnssd-srp._tcp` SRV discovery, so this test used an explicit `-server`).
     `srp-mdns-proxy`'s own log recorded `srp_evaluate: update for ourclient1.local. #0,
     xid 86f4 validates, key lease 1209600, host lease 30, message lease 0` -- their
     independent implementation's own validator explicitly confirming our message
     structurally and cryptographically correct -- followed by `srp_update_start` lines
     showing the exact address, instance name, type, and port all parsed correctly. The
     RCODE that ultimately came back to our client was SERVFAIL, but only because the
     *next* step -- `srp-mdns-proxy` connecting to a local `mDNSResponder`/Bonjour daemon
     via `/var/run/mdnsd` to actually publish the now-validated registration onto the local
     network -- failed with `connect() ... Errno:2 No such file or directory`: this sandbox
     has no such daemon running, an environment gap unrelated to either implementation's
     SRP-protocol correctness (even Apple's own `srp-client` would hit the identical wall
     if pointed at `srp-mdns-proxy` here). Not chased further -- installing/running a real
     system mDNS daemon in this sandbox was judged out of scope for what the interop gate
     actually needs to demonstrate (wire-protocol compatibility, which is what the
     `srp_evaluate: ... validates` line already proves).
  OpenThread simulation (plan's named secondary cross-check) was not attempted this
  session -- mDNSResponder is the plan's own named primary, and both its directions are now
  confirmed, satisfying the Phase 5 "Interop pass" gate without it. Both interop zones (the
  real `default.service.arpa.` scratch zone, and the mDNSResponder repo's own working tree)
  were left pristine afterward: the scratch zone's records deleted via a signed cleanup
  UPDATE and confirmed empty via `dig`; `git status` on `mDNSResponder/` shows only the
  same two Phase 0 patch files modified, no other changes retained (the generated
  `com.apple.srp-client.host-key` test identity file removed).
- 2026-09-14 (post-Phase-5 follow-up) — **OpenThread added to CI, as a build-and-self-test
  gate, not network-level interop.** User asked for OpenThread in CI plus an architecture
  diagram clarifying the whole interop picture (published as an Artifact, "SRP Interop
  Map"). Cloned `openthread/openthread` fresh (not pre-positioned the way mDNSResponder
  was) and investigated whether the same interop pattern used against mDNSResponder's
  binaries would transfer.
  **It doesn't, for a real architectural reason, confirmed empirically rather than assumed:**
  mDNSResponder's `srp-client`/`srp-mdns-proxy` are standalone tools that open an ordinary
  UDP socket to an arbitrary address. OpenThread's SRP client/server are CLI commands
  (`srp client`/`srp server`) *inside* a full simulated Thread mesh node (`ot-cli-ftd`) --
  reaching them means bringing up a whole Thread network first (`dataset init new`, commit,
  `ifconfig up`, `thread start`, wait for leader election). Brought a node up and checked
  the host's own network stack directly (`ip link show` / `ip -6 addr show`): no interface,
  anywhere, ever carries the node's Thread mesh-local address. The simulation platform's
  "radio" is a closed bus between `ot-cli-ftd` processes on one host, with no TUN device or
  route anything outside can address -- confirmed by direct inspection, not inferred from
  documentation. Real bridging to ordinary IP traffic is a Thread Border Router's job
  (`openthread/ot-br-posix`, ROUTED via a TUN interface + infrastructure-interface
  bridging), a separate and materially heavier project than what a "secondary cross-check"
  warrants on its own.
  Given this, asked the user to choose between (a) build-and-self-test only, (b) the full
  Border Router undertaking, or (c) skip OpenThread for now. **User chose (a).**
  Implemented: `script/cmake-build simulation -DOT_SRP_SERVER=ON -DOT_SRP_CLIENT=ON
  -DOT_ECDSA=ON -DBUILD_TESTING=ON` (needed `cmake`/`ninja` installed, and OpenThread's own
  git submodules -- including mbedtls's own *nested* submodule -- recursively initialized;
  `-DOT_ECDSA=ON` specifically was a real, non-obvious requirement: omitting it fails far
  into the build with "'Ecdsa' in namespace 'ot::Crypto' does not name a type" inside
  `srp_client.hpp`/`srp_server.hpp`, since SRP's alg-13 signing pulls in ECDSA support that
  isn't implied by `OT_SRP_SERVER`/`OT_SRP_CLIENT` alone). `tests/lib/openthread.sh` +
  `tests/test_openthread.sh` (new, following the plan's own `lib/*.sh` + orchestration-script
  split): builds the simulation platform, then runs `ctest -R srp` from `build/simulation`
  (not `build/` itself -- that's where ctest's generated test files actually live) --
  `ot-test-srp_server`, `ot-test-srp_adv_proxy`, `ot-test-ncp-srp_server` all pass, in under
  half a second, and a second invocation of the whole script (ninja's incremental rebuild)
  completes in ~2s. `OPENTHREAD_DIR` is overridable, defaulting to a sibling checkout next
  to `mDNSResponder/`, matching that same "checked out deliberately, not vendored, not
  auto-cloned by the test script" convention (plan S12.3). §14's "OpenThread interop in CI"
  bullet and Option C's own text both corrected -- the plan previously assumed (without
  having actually built OpenThread) that "the OpenThread interop job reuses the same
  [BIND 9] server"; that assumption is now known to be architecturally impossible and has
  been corrected in place, not just appended to.
- 2026-09-14 (fixture-extraction follow-up) — **added a real OpenThread cross-implementation
  fixture**, closing the gap the build-and-self-test-only CI job leaves (it never exercises
  our own code). User asked what value OpenThread actually adds if it's only testing itself;
  agreed the self-test job alone proves nothing about `pkg/srp`, and instead extracted one
  real wire-format SRP registration message from OpenThread's own SRP client. Method: rather
  than the pcap+`tshark` route `tests/scripts/thread-cert`'s own verify scripts use (`tshark`
  isn't installed in this sandbox), added a temporary one-line hex-dump right before
  `mSocket.SendTo` in `src/core/net/srp_client.cpp`, dumping the complete signed update
  message once. Ran it via `openthread/tests/nexus/test_srp_client_change_lease` — a real
  two-node client/server exchange inside OpenThread's in-process "nexus" test platform (its
  own authoritative build entry point is `tests/nexus/build.sh`, not `script/cmake-build`,
  which doesn't support `nexus`; needed a `-DOT_PROJECT_CONFIG=tests/nexus/openthread-core-
  nexus-config.h`-driven config, not a hand-assembled flag list — reusing the `simulation`
  platform's flags directly on `nexus` fails with unrelated missing-symbol errors). Captured
  a clean 365-byte message (`my-host.default.service.arpa.` host, one `my-service._ipps._tcp`
  instance on port 12345), reverted the instrumentation (`git checkout` on the one modified
  file — checkout left pristine), and added two regression tests from it: `pkg/srp/srp_test.go`'s
  `TestValidate_RealOpenThreadCapture` (structural — `Validate` accepts the real message
  shape, mirroring `TestValidate_RealMDNSResponderCapture`) and `pkg/sig0/ecdsa_test.go`'s
  `TestECDSAP256KnownAnswerFromOpenThread` (cryptographic — `VerifySignature` accepts
  OpenThread's real ECDSA P-256 SIG(0) signature, keytag 55321, mirroring
  `TestECDSAP256KnownAnswerFromMDNSResponder`). Notable finding: OpenThread's client
  independently chose the same KEY flags=513 convention mDNSResponder uses — third-party
  evidence this is the real-world norm, not an mDNSResponder-specific quirk. `go build/vet/
  test ./...` green throughout.
  **Separately identified, not yet closed**: neither Phase 5 interop test exercised anything
  but a plain registration — `client/srp` has no deregistration/removal operation at all
  (`Register`/`Run` only), and the real `srp-client` binary's own removal/subtype flags
  (`--remove-added-service`, `--delete-registrations`, `--test-subtypes`, etc., seen in
  `srp-ioloop.c`) were never exercised against our registrar. Delete/expiry/PTR-cleanup
  *is* covered (Phase 3, `handlers/srp_handler_test.go` + `tests/test_srp.sh`), but only
  against BIND 9 directly — never cross-validated against a real independent
  implementation's parser in either direction. Flagged for the user; not yet prioritized.
- 2026-09-14 (interop coverage expansion) — **the gap above is closed.** User asked to
  (a) cover as much of the interop message space as possible, (b) remove the OpenThread
  build-and-self-test CI job (per the still-open question from the previous entry — settled
  as "drop it"), and (c) clarified how the OpenThread fixture hex-dump was actually injected
  plus whether checking out mDNSResponder/OpenThread locally needs to be a more formal,
  documented arrangement (answered in chat; no repo change from that part — see the session
  transcript, not repeated here).
  **Removed**: `tests/test_openthread.sh`, `tests/lib/openthread.sh` (the
  `TestValidate_RealOpenThreadCapture`/`TestECDSAP256KnownAnswerFromOpenThread` fixture tests
  from the entry above are unaffected — they're regression tests in our own packages, not
  OpenThread self-tests, and stay).
  **Added `client/srp.Client.Deregister`** (`client/srp/client.go`): withdraws a whole
  identity in one message (host addresses zeroed, every instance restated as a bare
  Delete-All via `InstanceSpec.Remove`), sharing a new `buildSignSend` helper with `Register`.
  Also requests `LEASE=0` — RFC 9665's own S3.3.1.3 removal signal is purely structural (zero
  address Adds), but live testing against `srp-mdns-proxy` found its `srp-parse.c` additionally
  requires `host_lease==0` before it recognizes a zero-address host update as a removal at all
  (`"SRP update does not include a host description"` otherwise) — sending `LEASE=0` is still
  fully RFC-conformant and is what real-world interop actually needs. Wired a `-deregister`
  CLI flag into `cmd/sig0lease-srp` (D8 dev/test tool). New unit test
  `TestClient_Deregister_SendsRemovalShapedUpdate`.
  **New `tests/test_mdnsresponder_interop.sh`** (+ `tests/lib/mdnsresponder.sh`,
  `tests/bind9/default.service.arpa.zone.in`, a second zone clause in `named.conf.in`, and a
  new self-signed key at `tests/keystore-srp-bind9-default-arpa/`) — promotes Phase 5's
  one-off manual interop session into a permanent, repeatable, checked-in test, covering far
  more of the message space than plain registration:
  - **Direction 1** (real `srp-client` → our registrar): plain registration, `--host-only`,
    and all three subtype variants (`--test-subtypes`, `--test-diff-subtypes`,
    `--test-renew-subtypes`) — all pass, dig-verified at authoritative. `--remove-added-service`
    and `--delete-registrations` were tried live and found to hang forever — confirmed (fresh
    host names each time, ruling out server-side state) a real bug in `srp-client`'s own
    reconnect-on-second-message logic (`srp_connect_udp called with non-null I/O context`,
    error -65549), independent of anything on our side; documented in the script rather than
    silently skipped, and not chased further.
  - **Direction 2** (our client → real `srp-mdns-proxy`): Register (confirmed via
    `srp-mdns-proxy`'s own `srp_evaluate: ... validates` log line, same SERVFAIL-at-the-mDNS-
    bridge-step caveat as Phase 5) and now Deregister too — which needs no mDNS daemon and
    returns a **genuine end-to-end NOERROR**, srp-mdns-proxy's own log confirming the delete.
  None of `srp-client`'s test modes self-terminate on success (an earlier assumption, from a
  loose reading of the Phase 5 notes, that plain registration exits on its own was wrong —
  every mode just schedules its RFC 9664 refresh wakeup and keeps running); the script runs
  each in the background against a log-line pattern, then kills it.
  **Three real bugs found and fixed while building this**, all via live testing, none in the
  registrar or the message construction:
  1. `srp-client` persists its generated identity key to `com.apple.srp-client.host-key`
     *relative to its own CWD*, reused across separate invocations sharing a CWD regardless
     of `--host-name` — fixed by running each invocation from a fresh `mktemp -d` scratch
     directory.
  2. A `timeout`-wrapped `srp-client` that ignores/outlives a plain `SIGTERM` can survive past
     its wrapper's own return, left running in the background indefinitely, retransmitting
     and colliding with later runs reusing the same host name and port (`"foreign data
     present, no KEY"` REFUSED on an otherwise-fresh zone) — fixed by using `kill -9` for
     every ephemeral test-client PID, never plain `kill`.
  3. **The actual root cause of a long, misleading debugging chase**: the script never
     `source`d `tests/lib/dns.sh`, so every `dig_d1` call was silently invoking a
     nonexistent `dig_query_short` (`"command not found"`) inside a `[ -n "$(...)" ]` test —
     an error `set -e` doesn't catch there. Every dig-based assertion returned false-empty
     regardless of the real state, which (combined with bugs 1 and 2 muddying the picture
     with genuine but coincidental other failures first) took a full instrumented trace
     (`set -x`) plus a temporary debug log line in `handlers/srp_handler.go` (reverted after)
     to finally catch — BIND 9's own log had the correct data the entire time. One-line fix:
     add the missing `source`.
  `go build/vet/test ./...` green throughout; `tests/test_mdnsresponder_interop.sh run`
  passes cleanly and repeatably (confirmed twice in a row). Both third-party checkouts
  (`mDNSResponder/`, `openthread/`) left in their expected pre-existing state (`git status`
  clean apart from the same two long-standing Phase 0 patch files in `mDNSResponder/`).
  Also published `tests/README.md`, documenting both external checkouts' setup (clone
  commands, pinned commits, the two mDNSResponder patches, the full OpenThread fixture
  re-extraction recipe) in one place, requested by the user for anyone else picking up this
  repo. The user also asked whether a real independent client's *removal* message could be
  cross-validated against our registrar the same way registration was, given `srp-client`'s
  removal flags are broken: answered precisely (Direction 2's Deregister proves the removal
  message shape against a real *parser*, but not PTR/A/KEY cleanup at a real zone, since
  `srp-mdns-proxy` doesn't write to one; Phase 3 proves cleanup at a real zone, but only via
  our own client tooling, never a genuinely independent one) and proposed a hybrid
  workaround (extract `srp-client`'s own generated key, build the removal message with our
  own code); **user declined it as not worth doing** — correctly, since it wouldn't have
  validated `srp-client`'s own removal-construction logic anyway, only ours with real key
  material. No code change from that discussion.
- 2026-09-14 (Phase 6 — done) — **`default.service.arpa.` zone-rewrite (D5) implemented**,
  closing the plan's last open phase. New `rewrite_default_service_arpa` bool on
  `srp_handler` config (`handlers/srp_setup.go`): when set, `zoneEnabled` additionally
  accepts `default.service.arpa.` alongside the configured `upstream_zone`.
  **The real design work was in the pipeline, not the config flag.** The original draft
  (§4.3) put FCFS ahead of both SIG(0) verify and the rewrite stub. Implementing the
  rewrite for real showed that ordering can't work: the rewrite mutates `r.Ns` in place, so
  it must run *after* SIG(0) verify (which covers the original, unrewritten bytes) but
  *before* FCFS -- FCFS's own live upstream query and the entire local lease-store tree
  need names shaped like they'd exist at the real zone, not `default.service.arpa.`, which
  doesn't exist anywhere upstream and would make every live FCFS query come back NXDOMAIN
  regardless of real prior state. So SIG(0) verify (was step 5) and FCFS (was step 4)
  swapped places; §4.3 corrected in place, with the reasoning kept rather than just the new
  order. An earlier design alternative -- rewrite only at the two upstream-facing call
  sites (FCFS's live query, the final forward), leaving the local store keyed by the
  client's original default.service.arpa. names -- was considered and rejected: it would
  let a constrained client and a direct client naming the same logical host collide
  upstream without FCFS ever seeing it, since the two would occupy different local-store
  keys right up until the second one's write silently overwrote the first at the
  authoritative server.
  New `rewriteDefaultServiceARPA`/`rewriteZoneSuffix` (`handlers/srp_handler.go`): rewrite
  every name in `r.Ns` -- each RR's own owner name (generic via `Header()`, no type switch
  needed) plus the two name-typed RDATA fields SRP itself ever produces, `SRV.Target` and
  `PTR.Ptr` -- from `default.service.arpa.` to `upstreamZone`, then re-run `Validate` to
  get a `cu` reflecting the rewritten names. `r.Question` is deliberately left alone --
  `makeErrorResponse`/`buildSuccessResponse` both echo it verbatim, so the response still
  shows the client exactly the zone name it itself sent, RFC 2136 request/response
  symmetry intact.
  Six new tests: `TestSRPHandle_DefaultServiceARPA_RejectedWhenRewriteDisabled` (the
  pre-Phase-6 default is unchanged), `TestSRPHandle_DefaultServiceARPA_
  RewrittenToUpstreamZone` (upstream forward, local store, *and* the response Zone Section
  all checked), `TestSRPHandle_DefaultServiceARPA_UnifiesFCFSWithRealZoneClient` (the
  correctness property the whole design exists for -- a real-zone registration and a
  `default.service.arpa.`-addressed one for the "same" host, different keys, correctly
  collide as YXDOMAIN instead of silently diverging), plus `TestRewriteZoneSuffix` and
  `TestRewriteDefaultServiceARPA_OwnerAndTargetNames` (pure-function coverage of the rewrite
  itself, including a case-insensitive-match/case-preserving-replacement case).
  **Live-validated against real BIND 9 using the actual, unmodified mDNSResponder
  `srp-client` binary** -- not just unit tests: pointed it at a proxy configured with
  `upstream_zone: srp.test.` and `rewrite_default_service_arpa: true` (srp-client itself
  can only ever address `default.service.arpa.`, having no other way to discover a zone --
  exactly the real-world scenario this phase exists for). `dig` at `srp.test.` after
  registration showed the A/KEY/SRV records correctly landed there, SRV target correctly
  rewritten to point at the `srp.test.`-suffixed host name; `dig` at
  `phase6demo.default.service.arpa.` came back empty -- nothing orphaned at the zone the
  client actually sent. `go build/vet/test ./...` green throughout, including the full
  pre-existing handler suite (the pipeline reorder changed nothing any existing test
  depended on).
  User asked two follow-up questions afterward: (1) what "rewrite only at the upstream
  boundary" (the rejected alternative design) actually meant -- answered with a concrete
  example (two clients, "Alice" direct and "Bob" via default.service.arpa., both naming the
  same real host): under the rejected design, FCFS would compare "printer.srp.dev.zenr.io."
  against "printer.default.service.arpa." as two unrelated local-store keys, so Bob's
  registration would sail through FCFS and silently overwrite Alice's real DNS record once
  forwarded -- the actual implemented design avoids this because both names are already
  identical, rewritten, by the time FCFS ever runs. (2) whether Phase 7 (DoT) was still in
  the plan -- confirmed yes (§13's roadmap table already listed it, not yet done); the
  status line's own prior "no further phase currently planned" claim was wrong, made
  without checking the full roadmap table first.
- 2026-09-14 (Phase 7 — done) — **DNS-over-TLS (RFC 7858) implemented**, the plan's actual
  last remaining phase. New `server.tls: {address, cert, key}` config block
  (`config/config.go`'s `TLSConfig`) plus a `"tls"` entry in `server.networks`; `Validate`
  requires all three fields present and `address` a valid `host:port` whenever "tls" is
  enabled. `server/transport_tls.go`'s `serveDoT` (`server.go`'s `Serve()` loop gets a new
  `case "tls"`) loads the certificate via `tls.LoadX509KeyPair`, sets `NextProtos:
  dns.NextProtos` (the fork's own exported `{"dot"}` — RFC 7858 S3.2's required ALPN
  identifier, confirmed by reading the fork's own `dns.Server.TLSConfig` doc comment rather
  than assumed), and calls `serveNetwork("tcp", tlsAddr, tlsConfig, handler)` -- the
  underlying `dns.Server` has no separate `"tls"` `Net` value of its own; per its own doc
  comment, a `"tcp"` server with a non-nil `TLSConfig` is what starts a TLS listener.
  `serveNetwork` itself only needed one new parameter (`tlsConfig *tls.Config`, nil for
  plain udp/tcp) -- the existing listener-lifecycle logic (start/ready notification/
  graceful-shutdown-on-ctx-done) is unchanged and fully reused, not duplicated.
  Six new tests: `TestServeDoT_RoundTrips` (a real `tls.Config`-equipped `dns.Client`,
  freshly-generated self-signed cert, full TLS handshake, correctly-routed response) and
  `TestServeDoT_MissingTLSConfig` (fail-closed if ever reached without `server.tls` set,
  the case `config.Validate` is supposed to prevent) in `server/`; four `config.Validate`
  cases in a new `config/config_test.go` (the package had none before) covering "tls"
  enabled with no `server.tls` block, each of address/cert/key missing individually, and
  the fully-configured accept case.
  **Live-smoke-tested against the real `cmd/sig0lease` binary, not just unit tests**: a
  real `openssl`-generated self-signed P-256 certificate, `server.tls.address: ":18171"`
  alongside plain `udp`/`tcp` on `:18170`, queried with the real `dig +tls` client (this
  sandbox's own `dig` -- BIND 9.20 -- supports `+tls` directly) — genuine TLS handshake
  completed, correct forwarded answer (`example.com.` A records via the configured upstream)
  came back over the wire. `go build/vet/test ./...` green throughout; `gofmt -l` clean.
  **All seven phases in the plan are now done.**

---

## 1. Executive summary

RFC 9665 (SRP) is **not a new wire option**. It is a profile of DNS UPDATE: a tightly
constrained message shape (three kinds of "instruction"), a specific authentication model
("First Come, First Served" naming with SIG(0)), and a set of maintenance rules — all
layered on the RFC 9664 Update-Lease option we already support.

The proxy today implements a *general-purpose* SIG(0)-authenticated leased-UPDATE mechanism
(the "sig0lease" protocol, see `protocol.md`). SRP is **more restrictive** than that
mechanism in almost every dimension, and a few of its assumptions directly contradict
checks the current handler enforces.

**The plumbing is reusable; the policy is not.** `pkg/lease`, `pkg/sig0`, `pkg/keyrec`,
`forward` and `pkg/dnscompat` all carry over. The request-handling logic — classifier,
validator, FCFS model, response codes — does not. SRP is implemented as a **sibling
handler**, not a layer on top of `UpdateHandler`, plus a `pkg/updatecore` package holding
the genuinely shared forwarding plumbing both handlers use.

---

## 2. Decisions locked (2026-09-10)

| # | Decision |
|---|---|
| **D1** | New `handlers/srp_handler.go` + `pkg/srp` as a sibling to `UpdateHandler`. Shared forwarding plumbing goes to a new **`pkg/updatecore`** package (not `internal/`, not left inline in `handlers/`). |
| **D2** | Router dispatches an opcode to an **ordered list of handlers**, each tried until one returns `Processed`/`Error`; all `NotRelevant` ⇒ fall through to upstream forwarding (today's behaviour). Reuses the existing `HandlerResult.Status` mechanism. `processing_rules` gains an ordered `modules` list. |
| **D3** | Reuse the `pkg/lease` tree with additive PTR/subtype helpers. Prototype the mapping against RFC 9665 Appendix C in Phase 1 before committing. *(Done. Phase 1 used Appendix C's worked example for the `pkg/srp` classifier's fixtures, §12.2. Phase 2's `pkg/lease/srp_shape_test.go` prototyped the tree mapping itself, in code, against §4.4's own worked example — confirmed zero new store methods and zero snapshot-format changes needed, see §4.4 item 3.)* |
| **D4** | Keep "resolve SOA MNAME, re-sign with proxy key, forward" as the default. Add a **per-zone static `upstream` override** (skips SOA/NS discovery) from day one. **Option B (standalone authoritative registrar) is permanently out of scope.** |
| **D5** | v1 supports **explicitly-configured real SRP zones only** (e.g. `srp.example.com.`). `default.service.arpa.` / constrained-host support is deferred to its own late phase (needs the zone-rewrite feature). *(Done, Phase 6, 2026-09-14 — `rewrite_default_service_arpa` config flag, opt-in per zone. §4.3/§13.)* |
| **D6** | Enforce TCP-required for SRP on non-CNN zones. Source-address allow-list: **wire the hook, leave it a dormant stub** (parse config, call site present, empty list = allow all). |
| **D7** | Add explicit **ECDSAP256SHA256 (algorithm 13)** support + tests to the proxy — for **both** the base RFC 9664 handler and SRP. (Believed already functional via `dns.CryptoSIG0`; needs proving + a P-256 test key + `keyrec` round-trip confirmation.) |
| **D8** | New `cmd/sig0lease-srp` binary, a thin shell over a new `client/srp` library. The library is the deliverable; the CLI is a dev/test tool, **not a shipped product** for now. |
| **D9** | All optional registrar features **struck**: no prohibited-name dictionary, no pre-registered-keys mode, no reverse-PTR auto-population. "Withhold KEY from queries" is desirable but **not achievable** under the forward model (the KEY lands in the real zone) — documented as a known privacy limitation (§9). |
| **D10** | **One zone, one protocol.** The dispatcher enables exactly one of `{srp, lease}` per zone. Different-key clashes are already prevented by the existing ownership checks; same-zone cross-protocol manipulation is prevented by disjoint zones; a third party with direct authenticated access to the authoritative zone is a deployment concern — documented recommendation: grant authoritative-zone update access to the proxy key only. |
| **AD1** | Proposed routing/dispatch shape accepted (see D2). |
| **AD2** | Optional SRP happy-path steps (source-address check, `default.service.arpa.` rewrite) ship as **commented stubs** so they are easy to find later. *(The rewrite stub is now real, Phase 6 — D6's source-address allow-list stays a stub.)* |

Open-question answers: real zones only; standalone registrar never a goal; DoT deferred
until core functionality is proven; "one zone, one protocol" accepted; CLI not a shipped
product; interop primary = the **local `mDNSResponder/ServiceRegistration` checkout**
(already in the workspace, deliberately — `srp-client`, `srp-mdns-proxy`, `srp-dns-proxy`,
buildable with one `make`, see §12.3), secondary = OpenThread simulation (the RFC's
credited second independent implementation), plus BIND 9 for the RFC 9665 Appendix A/B
path. **Avahi is not an interop target** — it is mDNS/multicast only and implements no
SRP client or registrar.

Base-handler improvements that fall out of the above and benefit RFC 9664 too:
**TTL-consistency handling** (§6, Q3), **alg-13 support** (D7), **DoT as a `server`
transport** (§7, Q6).

---

## 3. What RFC 9665 actually requires

### 3.1 The SRP Update message (§3.2.1, §3.3.1)

A single DNS UPDATE containing **only** the following, grouped into "instructions":

| Instruction | Contents | Notes |
|---|---|---|
| **Host Description** (exactly 1) | `Delete All RRsets` on the hostname · exactly 1 `KEY` add · 0..n `A`/`AAAA` adds | 0 address adds = delete registration. The hostname's KEY is the FCFS anchor. |
| **Service Description** (0..n) | `Delete All RRsets` on the service-instance name · 0..1 `KEY` add · 0..1 `SRV` add · 1..n `TXT` adds (if SRV present) | KEY may be omitted → inherits the Host Description KEY. SRV target **must** equal the Host Description hostname. |
| **Service Discovery** (0..n) | exactly 1 `PTR` add **or** exactly 1 `PTR` delete, target = a service-instance name that has a Service Description in the same update | One instruction per subtype. |

Hard requirements:

- **Exactly one hostname** in the whole update (>1 ⇒ not an SRP update).
- **No prerequisites** (any prerequisite ⇒ not an SRP update).
- **Must** carry an 8-byte Update-Lease option with `LEASE ≤ KEY-LEASE`
  (missing, or `KEY-LEASE < LEASE` ⇒ not an SRP update).
- **All KEY RRs identical** and equal to the SIG(0) signing key (§3.2.5.1); KEY `flags`
  field **all zeroes** from requesters; registrar **must** store flags as received.
- **TTL consistency** within every RRset in the update (§4) — reject with `REFUSED` if
  violated (this is a MUST — no normalization on the SRP path). Registrar may clamp TTLs
  to `[min,max]` and `≤ lease`, and must use one TTL across any RRset it adds to.
- Any add/delete that is not part of a recognised instruction ⇒ **not an SRP update** ⇒
  registrar `MAY` process as plain RFC 2136 (if it does that at all), otherwise **must**
  reject with `REFUSED`.

### 3.2 There is no lightweight refresh

Every SRP update carries a complete Host Description (`Delete All RRsets` + KEY add) and
its own `LEASE`/`KEY-LEASE`. A "refresh" is simply re-sending the registration (RFC 9664
§5.1). An update need not re-state *every* service — services it omits keep their previous
lease and expire on their own per-instance schedule (§5.1). Consequences:

- The registrar never needs to "adopt" an existing lease with a reconstructed duration —
  it always uses the current request's lease times (policy-clamped).
- `RenewLease` (leaves tree position untouched) is the operation for a name the update
  re-states; omitted service nodes are simply not touched.

### 3.3 Validation & FCFS (§3.3.2, §3.3.3)

1. Message is a syntactically valid RFC 2136 UPDATE.
2. **Structural validation** — classify every instruction; confirm the whole-update
   requirements in §3.1, including: every KEY RR identical and equal to the signing key,
   single hostname, no prerequisites, lease present with `LEASE ≤ KEY-LEASE`, TTL
   consistency.
3. **FCFS name check** — for the hostname and each service-instance name, look up the
   lease store; if the store has no entry, do **one live `KEY`-at-name query**. The query
   result is tri-state (a new `authoritativeKeyState` helper keeps the RCODE that today's
   `queryAuthoritativeRRs` discards):

   | query result | meaning | action |
   |---|---|---|
   | `NXDOMAIN` | name does not exist | proceed (first come) |
   | `NOERROR`, no KEY in the answer | name exists, has RRsets, **no KEY** — foreign / orphaned data | `srp.refuse_on_foreign_data` (**default `true`**): **`REFUSED`**; `false`: proceed (delete-all-then-add clobbers it) |
   | `NOERROR`, KEY present, RDATA matches the update's KEY (explicit or inherited) | same owner | proceed |
   | `NOERROR`, KEY present, RDATA differs | different owner | **`YXDOMAIN`** |

   The `NODATA` row should essentially never fire for a name a valid SRP update touches
   (`LEASE ≤ KEY-LEASE` means the KEY always outlives the data), so hitting it means
   genuine foreign data, external tampering, or a half-failed delete cascade — `REFUSED`
   plus a loud log is the right call. `default.service.arpa.` empty-non-terminal names are
   a known minor imprecision (we only run this check on hostnames and service *instance*
   names, never service *type* names, so it is unlikely to bite). This is the **same
   query** as the pre-forward cost in §5 — reading its RCODE is free.
4. **SIG(0) verify** against the KEY in the Host Description (§3.3.3) — always present in
   the request, so no three-stage signer resolution is needed. Fail ⇒ **`REFUSED`**.
5. Apply as a normal RFC 2136 update (via the forward path, §5). After applying, every
   updated Service Description must carry a KEY equal to the Host Description KEY.
6. Response RCODE ∈ {`NOERROR`, `SERVFAIL`, `REFUSED`, `YXDOMAIN`}; response **must** echo
   the granted `LEASE`/`KEY-LEASE`.

**Authorization for SRP is steps 2 + 3, nothing more.** Once structural validation
confirms every KEY in the update equals the signing key, per-name FCFS is the entire
ownership check — there is no per-record parent/key walk. PTRs are authorized transitively
(§3.3.1.1: each PTR targets a service instance with a Service Description in the same
update, and that instance is FCFS-checked). See §4.4 and §11 Q7.

### 3.4 Maintenance (§5.1)

- Lease time governs the **hostname**. When the hostname lease expires, the hostname
  **and every service that targets it** are removed together.
- Registrar also tracks a **per-service-instance** lease (a requester may re-register a
  host with a different service set and forget the old one).
- KEY records survive on the **KEY-LEASE** schedule (typically 14 days) even after the
  data lease expires — this reserves the name.
- A Service Discovery PTR is removed whenever its target service instance is removed.
- Requester computes expiry from *send* time, registrar from *receive* time. Baseline
  refresh clock: **80% of the lease + a 0–5% random offset** (RFC 9664 **§5.2** — a MUST).
  The 75%/50% thresholds in §5.2.1 are a *separate* mechanism for opportunistically
  *coalescing* multiple registrations into one refresh, not the base clock.

### 3.5 Transport & crypto (§3.1.3, §6, §7)

- Non-constrained networks: **TCP required** (anti off-path spoofing); registrar relying
  on the handshake **must not** accept TCP Fast Open payloads.
- Registrar **must** offer **DNS-over-TLS** (opportunistic; no key auth). *Done, Phase 7,
  2026-09-14 — a `server` transport (§7), benefiting every handler.*
- Constrained (CNN) requesters may use UDP **iff** the network does source-address
  filtering; they target `default.service.arpa.`. *Deferred per D5.*
- Registrar **must** implement **ECDSAP256SHA256 (algorithm 13)** for validation (D7).
- Registrar `SHOULD` reject updates from source addresses outside its admin domain (D6 —
  stubbed).

---

## 4. Proposed architecture

### 4.1 Package layout

```
pkg/srp/                     NEW — pure logic, no network, no DNS I/O
  instruction.go   [Phase 1 DONE] instruction types + Classify() (message -> ClassifiedUpdate)
  validate.go      [Phase 1 DONE] §3.3.1 / §3.3.2 structural validation, TTL consistency
  names.go         [Phase 1 DONE] canonical-name + DNS-SD subtype helpers
  srp_test.go      [Phase 1 DONE] table-driven — RFC 9665 Appendix C + real mDNSResponder
                   capture as positive fixtures, an 11-case near-miss table, 6 Validate-
                   level rejection cases
  fcfs.go          [Phase 2 DONE] §3.3.3 FCFS: Evaluate() (tri-state, takes an injected
                   StoreView + AuthoritativeKeyQuery, no network I/O of its own), plus
                   Names()/KeyFor() helpers over a ClassifiedUpdate
  fcfs_test.go     [Phase 2 DONE] table-driven — store hit, all 5 tri-state live-query
                   rows, error propagation, Names/KeyFor
  update.go                  SRP-update builder (used by the client) — Phase 4
  response.go                RCODE mapping + granted-lease echo — Phase 3

pkg/updatecore/              NEW — shared forwarding plumbing
  upstream.go                SOA/NS resolution, per-zone static-upstream override,
                             constructUpstreamUpdate/Delete, re-sign
  authlookup.go              authoritative RR lookup helpers
  ttl.go                     RRset TTL consistency: check (SRP) | normalize-to-min (base)

handlers/
  srp_handler.go             NEW — implements handlers.Handler for opcode 5 (SRP path)
  srp_setup.go               NEW — config parsing for the srp block
  opcode5*.go                unchanged behaviour; refactored onto pkg/updatecore

server/
  router.go                  opcode -> ordered []handler; try until one handles it
  transport_tls.go           NEW (later) — "tls" listener case, opportunistic DoT

cmd/sig0lease-srp/main.go    NEW — thin SRP requester CLI
client/srp/                  NEW — discovery, refresh scheduler (§5.2), conflict-retry loop
```

`pkg/lease`, `pkg/sig0`, `pkg/keyrec`, `pkg/dnscompat`, `forward`, `config`, `logging`
gain only additive helpers.

### 4.2 Routing / dispatch (D2)

`processing_rules` grows an ordered `modules` list per opcode:

```yaml
processing_rules:
  - opcode: 5
    modules: [srp_handler, update_handler]   # tried in order
```

`router.go`: `opcodeMap` becomes `map[uint8][]string`. `Route()` calls each handler for
the opcode in turn; the first returning `StatusProcessed` or `StatusError` wins; if all
return `StatusNotRelevant`, it falls through to `forwardToUpstream` (today's behaviour).

- `SRPHandler.Handle()` returns `NotRelevant` when `pkg/srp.Classify(msg)` says the
  message isn't SRP-shaped.
- `UpdateHandler.Handle()` already returns `NotRelevant` when there is no Update-Lease
  option.
- Per-zone `{srp|lease}` enablement (D10) is enforced in each handler's early checks: a
  handler returns `NotRelevant` for a zone it isn't enabled on.

### 4.3 SRP handler happy path

**Step order revised 2026-09-14 (Phase 6):** the original draft below put FCFS (then step 4)
ahead of SIG(0) verify (then step 5) and the rewrite (then step 6, a stub). Actually
implementing the rewrite showed that ordering doesn't work: the rewrite has to run *after*
SIG(0) verify (it mutates `r.Ns`, and the signature covers the original bytes) but *before*
FCFS (FCFS's own upstream `KEY`-at-name query, and the whole local lease-store tree, need to
see the same name a real client sitting on a real zone would use — not
`default.service.arpa.`, which doesn't exist anywhere upstream). So SIG(0) verify and FCFS
swapped places. Corrected in place below, not just appended to — see §13's Phase 6 entry for
the full reasoning and the live validation.

```
Handle(ctx, w, r):
  1. classify -> instructions            (pkg/srp)      ; NotRelevant if not SRP-shaped
  2. structural validation               (pkg/srp)      ; REFUSED / FORMERR
     single hostname · no prereqs · lease present & LEASE<=KEY-LEASE
     TTL consistency (reject) · every KEY identical & == signing key
  3. transport check: TCP required unless zone is allow_udp   ; REFUSED
     source-address allow-list                                ; STUB (AD2/D6)
  4. SIG(0) verify against the Host Description KEY (§3.3.3)   ; REFUSED
  5. default.service.arpa. -> real-zone rewrite, if this zone opted in
     (rewrite_default_service_arpa) -- rewrites every name r.Ns carries (owner names,
     SRV.Target, PTR.Ptr) to upstream_zone, in place, then re-validates to get a cu
     reflecting the rewritten names. r.Question (and so the eventual response) is left
     untouched -- the client still sees exactly the zone name it sent.               ; done
  6. FCFS name check: lease store, then one KEY-at-name query per uncovered name --
     always against upstream_zone-shaped names by this point, whether the client
     addressed upstream_zone directly or default.service.arpa.  ; YXDOMAIN on key mismatch
  7. build upstream UPDATE = the same adds/deletes, re-signed with proxy key
     (pkg/updatecore) ; forward to authoritative (SOA MNAME, or per-zone static upstream)
     -- before wiping anything locally, pkg/srp reads the service node's CURRENT PTR
     set from the store and diffs it against this update's named Service Discovery
     PTRs: anything dropped becomes an explicit Delete An RR From An RRSet in THIS
     outgoing message (upstream never delete-alls the PTR's owner name -- see §4.5)
  8. on upstream NOERROR: stage lease-store mutations -- uniformly wipe + reinsert the
     non-KEY children of every node touched by a Delete All RRsets in this update
     (RemoveNonKEYRecords then UpsertNonKEYRecords -- both already exist, no new store
     method needed):
     - host KEY node (KEY-LEASE)
     - service-instance KEY nodes, parent = host node (KEY-LEASE)
     - host A/AAAA: wipe + reinsert (mirrors the Host Description's Delete All RRsets)
     - service SRV/TXT **and** PTRs (base + subtypes) together: wipe + reinsert the
       WHOLE service subtree (mirrors the Service Description's Delete All RRsets;
       §3.3.4 atomicity falls out for free -- only PTRs named in this update survive)
     - omitted service nodes: untouched (expire on their own per-instance timer)
  9. schedule expiry timers (reuse scheduleLeaseExpiry)
 10. response: NOERROR + echo granted LEASE/KEY-LEASE (reuse buildSuccessResponse)
```

Reused from `UpdateHandler`: steps 7, 9, 10, the deferred-mutation pattern (never touch
the store before upstream confirms), `processExpiredLease`, `startLeaseReconciliation`,
`FileLeaseStore`, the dump endpoint.

### 4.4 Lease-store mapping (D3)

| SRP concept | `pkg/lease` node | schedule |
|---|---|---|
| Hostname + its KEY | KEY `Record`, root of the zone subtree | `KeyLeaseDuration` |
| `A`/`AAAA` for the host | `NonKEYRecord`, parent = host node | `LeaseDuration` |
| Service instance (+ inherited/explicit KEY) | KEY `Record`, parent = host node | `KeyLeaseDuration` |
| `SRV`/`TXT` for the instance | `NonKEYRecord`, parent = service node | `LeaseDuration` |
| Service Discovery `PTR` | `NonKEYRecord`, parent = **service** node | `LeaseDuration` |

Worked example — zone `srp.example.com.`, host `myhost` (A+AAAA), one service instance
`Printer._ipps._tcp` (SRV+TXT) with a `_print` subtype, one key (alg 13, keytag 34567),
`LEASE` 7200s, `KEY-LEASE` 1209600s:

```
srp.example.com.                                             ← zone root (rootsByZone)
│
▼ KEY node   "myhost.srp.example.com.+013+34567"             ← Host Description
  KeyRR: myhost.srp.example.com. IN KEY 0 3 13 <P>
  ParentKeyName ""                                           ← root of the zone subtree
  KeyLeaseDuration 1209600  ExpiresAt T0+14d                 ← name-reservation clock
  LeaseDuration    7200     ExpiresAt T0+2h                  ← host-data clock
  │
  ├─▶ non-KEY  "myhost… AAAA 2001:db8::1"   parent = myhost.…+013+34567   LEASE 7200
  ├─▶ non-KEY  "myhost… A 192.0.2.1"        parent = myhost.…+013+34567   LEASE 7200
  │
  └─▶ KEY node   "printer._ipps._tcp.srp.example.com.+013+34567"   ← Service Description
        KeyRR: Printer._ipps._tcp.srp.example.com. IN KEY 0 3 13 <P>   (same P)
        ParentKeyName  myhost.srp.example.com.+013+34567     ← parent = host node
        KeyLeaseDuration 1209600  ExpiresAt T0+14d
        LeaseDuration    7200     ExpiresAt T0+2h            ← per-instance lease (§5.1)
        │
        ├─▶ non-KEY  "printer._ipps._tcp… SRV 0 0 631 myhost.srp.example.com."
        │              parent = printer._ipps._tcp.…+013+34567   LEASE 7200
        ├─▶ non-KEY  "printer._ipps._tcp… TXT \"rp=ipp/print\""
        │              parent = printer._ipps._tcp.…+013+34567   LEASE 7200
        ├─▶ non-KEY  "_ipps._tcp.srp.example.com. PTR Printer._ipps._tcp.srp.example.com."
        │              parent = printer._ipps._tcp.…+013+34567   LEASE 7200
        │              ▲ owner name is the service TYPE; node is parented to the INSTANCE
        └─▶ non-KEY  "_print._sub._ipps._tcp.srp.example.com. PTR Printer._ipps._tcp…"
                       parent = printer._ipps._tcp.…+013+34567   LEASE 7200   ← subtype PTR
```

- Two KEY nodes, **one key** — `<P>` is byte-identical; the node keys differ only because
  `NodeKey` is name-scoped.
- Signer node = `NodeKeyFromSIG("myhost.srp.example.com", 13, 34567)` = the host KEY node.
- A later update's FCFS: look up `myhost…` → KEY matches; look up `printer._ipps._tcp…` →
  KEY matches. Done — nothing walks from the SRV node upward.
- Cascade: host KEY expiry (T0+14d) → `DeleteSubtree` on the host node → all 8 nodes gone.
  Host-data lease (T0+2h) → the two address nodes only. Service-instance lease (T0+2h) →
  SRV, TXT, **and both PTR nodes**; the service KEY node survives to T0+14d (name still
  reserved); host untouched.
- A second instance `Front Desk._ipps._tcp` → another KEY node under `myhost`, its own
  SRV/TXT, and its own PTR node at owner `_ipps._tcp.srp.example.com.` — same owner as
  Printer's PTR, different RDATA → different `RecordKey` → a distinct node under the
  Front Desk instance. Two PTR RRs coexist at that owner name, each independently leased.

**Authorization vs. cascade.** For the base handler, `ParentKeyName` is *both* the
authorization primitive (only your immediate parent node may modify you) *and* cascade
grouping. **For SRP, `ParentKeyName` is cascade/grouping only** — authorization is
structural validation + per-name FCFS (§3.3.3). This is safe because §3.2.5.1 guarantees
one key across the whole update, so the service-instance KEY node and the host KEY node
hold byte-identical KEY RDATA even though their node keys differ (node keys are
name-scoped). Any residual "does this key govern this name" question is answered by FCFS.

Why the tree fits: host-expiry cascade to services + PTRs = `DeleteSubtree` /
`ListSubtreeKeys` (already in `processExpiredLease`); a KEY node already outlives its
non-KEY children (FCFS name reservation); per-service-instance lease = each instance
node's own `ExpiresAt`; multiple PTRs at one owner name coexist because non-KEY identity
includes RDATA.

Accepted stretch points (Q7): a "KEY node" no longer strictly means "a key was
registered here" (an inherited-KEY service instance is a KEY node holding the host key);
`ParentKeyName` is overloaded across the two handlers (documented); PTR-under-instance
placement is slightly artificial; the same key at N names is N nodes with duplicated key
material. None fatal; the alternative (a bespoke SRP store) re-implements timers, cascade,
reconciliation and persistence — the most-tested code in the repo.

**Additive store work turns out to be almost nothing — no new store methods.** `pkg/lease`
already has everything this needs:
1. **PTR-at-expiry** — PTRs are children of the service node, so the existing subtree
   cascade (`DeleteSubtree` / `ListSubtreeKeys`) removes them when the instance goes; free.
2. **Wipe-then-reinsert, uniformly, for every node a `Delete All RRsets` touches** — the
   host's A/AAAA and the service's SRV/TXT **and PTRs together** are all children of a
   node whose Host/Service Description carries an unconditional delete-all (§3.3.1.2/.3).
   The local mirror is `RemoveNonKEYRecords(nodeKey)` (wipes every non-KEY child — already
   exists, unchanged) followed by `UpsertNonKEYRecords(nodeKey, records, lease, zone)`
   (already exists, unchanged) for whatever the update actually contains. A plain Upsert
   alone would leave a stale node behind if the set actually changed (same RRType,
   different RDATA → different `RecordKey` → Upsert never touches the old one) — the wipe
   is what makes this correct. Applying the *same* wipe+reinsert to the service node's SRV,
   TXT, *and* PTR children together also gives §3.3.4's subtype atomicity for free: only
   PTRs named in this update survive the reinsert. No separate "subtype sync" operation
   needed — see §4.5 for why the earlier draft's split was unnecessary.
3. **Snapshot — confirmed 2026-09-11 (Phase 2): no version bump needed.** The tentative
   "likely `2 → 3`" here was hedged pending an actual implementation to check it against;
   `pkg/lease/srp_shape_test.go` (Phase 2) builds the full worked-example tree — host KEY
   node, service KEY node parented to it, SRV/TXT/two-PTR non-KEY children, cascade and
   partial-cascade behavior, wipe-then-reinsert, two instances sharing a PTR owner name —
   using only the existing, unmodified `NodeSnapshot`/`LeaseTreeSnapshot` shape. Nothing
   about SRP's use of the tree needs a new field, a new `NodeKind`, or any other change a
   v2-format snapshot couldn't already represent — `ParentKeyName` meaning
   "cascade/grouping only" rather than "cascade + authorization" for SRP (§4.4's own
   "Authorization vs. cascade" note) is a *handler-level interpretation*, invisible to the
   stored bytes themselves. `leaseSnapshotVersion` stays `2`; revisit only if a later
   phase's actual handler wiring turns up a real need, not preemptively.

The one piece of real *new* logic is not a store method: **before wiping**, `pkg/srp` must
read the service node's current PTR children and diff them against this update's named
Service Discovery instructions, so the *outgoing* upstream message can carry an explicit
`Delete An RR From An RRSet` for anything being dropped — upstream, unlike the local
store, was never told to delete-all the PTR's owner name (§4.5). That diff lives in the
forward-message-construction step (§4.3 step 7), not in `pkg/lease`.

### 4.5 Worked update walkthrough

Starting state is the §4.4 tree at time **T0**: KEY nodes expire at T0+14d, all non-KEY
data at T0+2h.

**A refresh arrives at T0 + 90 min** — client re-sends the identical SRP update, `LEASE
7200`, `KEY-LEASE 1209600`, signed with key **P**:

| step | what happens |
|---|---|
| classify | valid SRP: 1 Host Desc, 1 Service Desc, 2 Service Discovery |
| structural validation | single hostname; no prereqs; `7200 ≤ 1209600`; TTLs consistent; **Host Desc KEY == Service Desc KEY == signing key P** |
| **FCFS** | the checked names are **the Host Description name and each Service Description name — nothing else**.<br>• `FindByName("myhost.srp.example.com")` → host KEY node; compare `KeyRR` RDATA to the update's Host Desc KEY → **P == P** *(store hit — no authoritative query)*<br>• `FindByName("Printer._ipps._tcp.srp.example.com")` → service KEY node; compare RDATA to the Service Desc KEY (or the inherited Host Desc KEY) → **P == P** *(no query)*<br>The SRV/TXT/PTRs are never looked up — they have no KEY and no independent owner. |
| SIG(0) | verify the message against Host Description KEY P |
| forward | `pkg/srp` first reads the service node's *current* PTR children (base + `_print` subtype, both present) and diffs against this update's named Service Discovery instructions (both named again) → nothing to drop; build the upstream UPDATE = `Delete All RRsets` + adds at `myhost`/`Printer._ipps._tcp` + the 2 PTR adds, re-sign with `Kdev.zenr.io.+015+35317`, send to the SOA MNAME → `NOERROR` |
| **store mutations** *(deferred until NOERROR)* | `RenewLease(hostKeyRR, 1209600, 1209600)` → host KEY node `ExpiresAt` = now+14d<br>`RenewLease(serviceKeyRR, 1209600, 1209600)` → service KEY node `ExpiresAt` = now+14d<br>host: `RemoveNonKEYRecords(hostNodeKey)` then `UpsertNonKEYRecords(hostNodeKey, [A, AAAA], 7200, zone)` → `ExpiresAt` = now+2h<br>service: `RemoveNonKEYRecords(serviceNodeKey)` (wipes SRV+TXT+**both PTRs**) then `UpsertNonKEYRecords(serviceNodeKey, [SRV, TXT, PTR_base, PTR_sub], 7200, zone)` → `ExpiresAt` = now+2h — same two calls as the host, just given a bigger record set<br>`RenewLease` **does not touch `ParentKeyName` or tree position** |
| timers | `scheduleLeaseExpiry` on both KEY node keys |

Net effect: every `ExpiresAt` slides forward (KEY nodes → T0+90min+14d, data → T0+90min+2h);
tree shape unchanged.

**A different key Q ≠ P sends the same update:** structural validation passes (all KEYs
in the update == Q, internally consistent), then FCFS's *first* check —
`FindByName("myhost.srp.example.com")` → RDATA P ≠ Q → **`YXDOMAIN`**, stop. Nothing
forwarded, no store change. It never reaches the SRV/TXT.

**A refresh that omits the `_print` subtype:** FCFS identical (P matches both names). At
message-construction time, `pkg/srp` reads the service node's current PTR children (base +
`_print`) and diffs against this update's named Service Discovery instructions (base
only) — `_print` is missing from the new set, so the forwarded UPDATE gets an explicit
`Delete An RR From An RRset` for `_print._sub._ipps._tcp PTR` added to it (upstream's
delete-all never reached that name — see the note below). After `NOERROR`, the local
mutation is the *same* uniform wipe+reinsert as the full-refresh case, just with a smaller
record set: `RemoveNonKEYRecords(serviceNodeKey)` wipes SRV+TXT+both PTRs,
`UpsertNonKEYRecords(serviceNodeKey, [SRV, TXT, PTR_base], …)` reinserts only what's named
— the dropped subtype simply isn't in the reinsert. No separate "subtype sync" step.

> **Why the diff step exists at all, if the local mutation is uniform.** The Host/Service
> Description's `Delete All RRsets` genuinely wipes everything at the hostname / instance
> name before the adds land — a real delete-then-insert, unconditionally, every update —
> which is exactly why the *local* mutation can be the same uniform wipe-then-reinsert for
> A/AAAA, SRV/TXT, and PTR alike (§4.4). But **upstream**, that delete-all's reach stops at
> the instance name. A PTR's owner name (`_ipps._tcp.srp.example.com.`, or a subtype under
> it) is a *different* name, shared by every other instance of the same service type (Front
> Desk's PTR lives there too) — it can never be delete-all'd without destroying other
> instances' discoverability. A PTR only ever moves via an individual `Add To An RRSet` /
> `Delete An RR From An RRSet` (§3.3.1.1). So nothing in the wire protocol tells the
> authoritative server to drop a subtype PTR on its own; the *outgoing* message has to
> carry that instruction explicitly, and building it requires knowing what the previous
> set was — hence the diff, at message-construction time, before the store gets touched.
>
> This also settles whether Service Discovery is ever legitimately absent from an update.
> There's no incremental-modify primitive anywhere in SRP — every instruction type is an
> unconditional delete-all-then-reinsert (Host Description, Service Description) or an
> explicit per-record add/delete (Service Discovery); nothing is phrased as "patch this one
> field." A client's natural model is therefore "resend my complete current state," and
> that's what real SRP clients (OpenThread, Apple) do. So rather than defending the
> registrar against a hypothetical Service-Discovery-less refresh, `client/srp` (Phase 4) is
> simply required to always restate Service Discovery for any service that should remain
> discoverable — matching typical implementation practice, and matching how §3.2.5.5.2
> already treats PTR lifecycle as tied to the service instance's existence rather than to
> whether any particular message re-declares it.

**Why nothing walks up from the SRV node.** The base handler, touching an SRV record,
does `LookupNonKEYRecord(srv)` → read `ParentKeyName` → check `signerNode == ParentKeyName`
— it *must*, because its updates are unstructured (arbitrary RRs at arbitrary names). An
SRP update can't contain such a record: by the time FCFS finishes, the handler knows every
KEY in the update is P, both KEY-bearing names are owned by P (or free), every SRV/TXT is
inside a Service Description for one of those names, and every PTR targets an instance with
a Service Description in the same update (§3.3.1.1). Checking the two KEY-bearing names is
sufficient; walking each SRV/TXT/PTR would only re-derive that.

---

## 5. Upstream forward + re-sign (reused mechanism)

What the proxy does today, and what SRP reuses unchanged:

1. **Client → proxy:** a SIG(0)-signed UPDATE, signed with the *client's* key.
2. **Proxy verifies** the client SIG(0) and runs all policy (SRP: structural + FCFS).
3. **Proxy builds a new UPDATE** with only the accepted records — adds, and RFC 2136
   deletes (class `NONE` / TTL 0, or `Delete All RRsets` = class `ANY`) — with the
   effective upstream zone in the question section. TTL/lease clamping happens here.
4. **Proxy resolves the target server:** `resolveSOAMasterServer` (SOA → MNAME), with
   `resolveAuthoritativeZone` (NS) confirming the zone cut. **Or**, if the zone has a
   static `upstream` configured (D4), both lookups are skipped.
5. **Proxy signs the new message with its own key** (`findAuthorizedProxyKeyForZone`,
   from `keystore/server/`).
6. **Proxy sends** to the target (UDP, TCP fallback).
7. **Authoritative server verifies the *proxy's* SIG(0)** — the proxy's key must be in
   that zone's `allow-update` / `update-policy`. Clients are never known upstream.
8. **Proxy commits lease-store mutations only on `NOERROR`** (deferred-mutation pattern).

Why re-sign: the authoritative server doesn't trust the client's key; the proxy modified
the message so the client's signature wouldn't validate anyway; the proxy is the security
boundary and vouches upstream with its own credential. This is exactly RFC 9665's
registrar / hidden-primary model (§3, Appendix B).

**Pre-forward DNS queries.** The base handler does several today: signer-KEY resolution
(sometimes), a duplicate/missing-at-FQDN check per KEY and per non-KEY record, an NS
lookup, an SOA lookup. SRP does **fewer** — it drops the duplicate checks (delete-all-
then-add), keeping only the FCFS `KEY`-at-name query (per name not covered by the lease
store) plus zone resolution. With a per-zone static `upstream`, an SRP forward can be
**lease-store-only, zero pre-forward queries**.

**Credential notes (D4):** the authoritative zone grants update rights to a *single*
proxy key — compromise of that key bypasses all proxy-side policy, so scope it to the SRP
subdomain (prefer `update-policy` over a broad `allow-update`). The proxy keeps two
databases (lease store + authoritative zone) with no distributed transaction; the
divergence windows and mitigations (deferred mutations, 30 s reconciliation,
missing-at-FQDN recovery) are the same ones documented for the RFC 9664 path.

---

## 6. TTL consistency (base handler + SRP)

Shared helper in `pkg/updatecore/ttl.go`, two modes:

- **SRP path — `check`:** if any RRset in the update has inconsistent TTLs, reject with
  `REFUSED` (RFC 9665 §4 — a MUST; requesters must send consistent TTLs).
- **Base RFC 9664 path — `normalize`:** rewrite each inconsistent RRset to the **lowest
  TTL** in the set (**RFC 2181 §5.2** — treat a mixed-TTL RRset as if all TTLs were the
  minimum). Runs *before* `LeasePolicy` clamping.
- **Both, on output:** when adding to an already-existing RRset at the authoritative
  server, force the new RR's TTL to the existing RRset's TTL (RFC 9665 §4; correct for
  the base handler too).

This is a genuine base-handler correctness fix, not SRP-only.

---

## 7. Transport hardening

| Item | Plan |
|---|---|
| **TCP-required** for SRP on non-CNN zones | Reject a UDP SRP update with `REFUSED` unless the zone is flagged `allow_udp`. `w.RemoteAddr()` network is known. |
| **TCP Fast Open** payloads | `codeberg.org/miekg/dns` exposes no TFO path; document as "not enabled, therefore compliant", add a test asserting no early-data acceptance. |
| **DNS-over-TLS** | **Done, Phase 7, 2026-09-14.** `server/transport_tls.go`'s `serveDoT` — a `"tls"` entry in `server.networks` (RFC 7858, `tls.Config` from a new `server.tls: {address, cert, key}` block; `address` is its own, since DoT conventionally listens on a separate port, RFC 7858 default 853, alongside plain DNS on 53). Transport-level, so it benefits **every** handler including base RFC 9664 and plain forwarding — reuses `serveNetwork` with `network="tcp"` and a non-nil `tls.Config` (the underlying `dns.Server` has no separate "tls" `Net` value of its own; a `"tcp"` server with `TLSConfig` set is what triggers a TLS listener). Opportunistic only, no key pinning. |
| **Source-address allow-list** (§6.1) | `srp.allowed_source_prefixes []string` → `[]netip.Prefix`; check point after classification; empty = allow all; `// TODO(srp)` + a no-op-when-unset test. **Stub only** (D6). |
| Anycast `2001:1::3` | Out of scope (deployment concern). |

---

## 8. Signature algorithm (D7)

- ~~ECDSAP256SHA256 (alg 13) is almost certainly already functional~~ **Superseded
  2026-09-11 — it is not.** `dns.CryptoSIG0.Sign`/`Verify` (everything but ED25519
  delegates here) hash the SIG RR's full wire encoding instead of RDATA-only, violating
  RFC 2931 §3 — confirmed root cause, see §10 item 8. Fixed for ED25519 only, by
  accident of a from-scratch reimplementation, not by design.
- `keyrec.LoadKeyFromFile` → `dnsKey.NewPrivate` has a P-256 branch (key *loading* is
  unaffected — this bug is purely in hash-input construction, not key parsing).

### Decision — made and implemented 2026-09-11

The user chose **D7-B (generalize)** and **not** to report upstream for now, but to
document the bug thoroughly so filing an issue later is easy.

| Option | Decision |
|---|---|
| **D7-A — alg-13-only patch** | Not taken. |
| **D7-B — generalize the fix** | **Taken.** `pkg/sig0/signer.go`'s `sig0SignerImpl` no longer delegates to `dns.CryptoSIG0.Sign`/`Verify` for ED25519, ECDSAP256SHA256, **or** ECDSAP384SHA384 — a shared `rdataOnlyPrefix(sig *dns.SIG) []byte` helper builds the correct RFC 2931 §3 hash input once, and each of those three algorithms signs/verifies against it directly (ECDSA via `crypto/ecdsa`, raw `r‖s` output per RFC 6605 §4, never ASN.1 DER). RSA (1/5/8/10) still delegates to the buggy library path — deliberately deferred, no RSA keys/vectors exist in this codebase to validate a from-scratch implementation against, so a claimed fix there would trade a known gap for an unverified one. |
| **Report upstream** | **Not now** — documented instead, so it's easy later: RFC 2931 §3 quote, exact library code path, and a reproducible known-answer case, all in `README_proxy.md`'s new "SIG(0) hashes the full SIG RR instead of RDATA-only" section. |

**Validated:** `pkg/sig0/ecdsa_test.go` — generate-sign-wire-round-trip-verify and
tampered-message-rejected tests for both ECDSAP256SHA256 and ECDSAP384SHA384, plus
`TestECDSAP256KnownAnswerFromMDNSResponder`, a permanent regression test pinned to the
actual captured `mDNSResponder` `srp-client` message (§10 item 1) — this is the "known-
answer verify" this section originally called for, now real rather than aspirational.
Existing ED25519 tests (`pkg/sig0/unit_test.go`) still green (the ED25519 code path is
unchanged logic, only refactored to call the new shared helper). Full suite (`go test
./...`, `go vet ./...`) green; a real-zone `test_update.sh` smoke run (`RR_TYPES=KEY`)
after this change stayed green too, confirming the ED25519 refactor didn't disturb the
path the base RFC 9664 handler actually exercises today.

- `client/srp` generates P-256 keys by default; the client must emit a **flags-0** KEY
  for SRP (§3.2.5.1), and the registrar must store flags as received.
- Keep ED25519 (alg 15) — used by `sig0namectl` and the existing keystore.

---

## 9. Struck / limited features (D9)

| Feature | Status |
|---|---|
| Prohibited-name dictionary (§6.3) | **Not implemented.** |
| Pre-registered-keys-only mode (§3.3.6) | **Not implemented.** |
| Reverse-PTR auto-population (§3.3.6) | **Not implemented** (needs authority for the reverse zone). |
| Withhold KEY from queries (§7 privacy) | **Not achievable** under the forward model — the KEY is written into the real authoritative zone, which the proxy does not serve. Documented limitation; would only be possible under a standalone authoritative registrar (D4-B, permanently out of scope). |

---

## 10. Likely problem areas

1. **`Delete All RRsets From A Name` parsing — confirmed 2026-09-11 (Phase 0 spike).**
   `*dns.ANY{Hdr: Header{Class: ClassANY}}` in the fork (this fork's `Header` carries no
   `Rrtype` field at all — RR type is the Go type itself, via `dns.RRToType(rr)`). Proven
   two ways: (1) a synthetic message built with all three RFC 2136 delete shapes —
   `*dns.ANY`/class ANY (delete-all-name), a concrete typed RR (e.g. `*dns.TXT`) with
   class ANY + zero RDATA (delete-one-rrset), class NONE + full RDATA (delete-one-RR) —
   round-tripped through a real `Pack()`/`Unpack()` correctly as three distinct,
   distinguishable shapes; (2) a **real captured update from `mDNSResponder`'s
   `srp-client`** (see §12.3) used only the delete-all-name shape (`*dns.ANY`) in
   practice, at both the Host Description and Service Description names — confirming real
   clients rely on delete-all, not the other two RFC 2136 delete forms, for SRP's
   mutation model (§3.2, §4.5). `handlers.extractUpdateRecords` still doesn't recognise
   any of the three specially (it just buckets `*dns.ANY` into "other") — the SRP
   classifier needs its own extraction understanding all three, confirmed buildable
   against this fork's actual (Rrtype-less) RR representation.
2. **`service.arpa` is locally served** — SOA/NS discovery via public resolvers fails.
   Handled by D5 (deferred) + the per-zone static `upstream` override for labs/CI.
   **Phase 0 spike (2026-09-11) confirms today's base handler is already safe by
   construction against a `default.service.arpa.`-addressed (or any other foreign-zone)
   request, by code reading rather than a new test:** `Handle()` never compares the
   request's own question-section zone to anything — it is entirely single-zone by
   config (`h.upstreamZone`, set once in `Setup()`), the forwarded upstream message is
   *always* addressed to `h.upstreamZone` regardless of what zone the client's question
   section named (`newUnsignedUpstreamUpdate(h.upstreamZone)` / D4), and
   `extractAndValidateSig0` checks the signer against `h.upstreamZone`'s hierarchy, not
   the client's stated zone. So a rogue or simply-misdirected `default.service.arpa.`
   update can be neither forwarded to the wrong place nor accepted on a foreign signer's
   say-so — it is rejected at the signer-hierarchy check. For SRP specifically this
   generalizes to the already-planned per-zone `{srp|lease}` `NotRelevant` gate (§4.2,
   D10): each handler still only ever forwards to its own configured zone, and simply
   also needs to *decline* (not error on) a zone it isn't configured for, so the router's
   ordered-handler fallthrough (D2) works correctly rather than every handler treating
   every zone as an error case.
3. **Signer/zone hierarchy checks** in `extractAndValidateSig0` and
   `validateSignerHierarchyForUpdateRecords` reject SRP updates. The SRP path doesn't call
   them — it verifies against the Host Description KEY and authorizes via FCFS.
4. **Duplicate-registration rejection** (`filterDuplicateRegistrations`,
   `authoritativeHasRR`) is antithetical to SRP's replace semantics — not on the SRP path.
5. **Compressed SRV target names** (§3.2.5.4) — registrar MUST accept them. **Confirmed
   2026-09-11 (Phase 0 spike), against a real message, not a synthetic one:** the SRV
   record in the captured `srp-client` update (see item 1 and §12.3) had RDLENGTH=8 —
   priority(2)+weight(2)+port(2)+**a 2-byte compression pointer**(2) — i.e. the target
   name was genuinely wire-compressed (verified in the raw hex dump: `c0 26` pointing back
   to the Host Description's owner-name bytes), not written out literally. `Unpack()`
   decompressed it correctly (`SRV target="spiketest.default.service.arpa."`, exact
   match). Note this fork's own `Pack()` does *not* reliably compress RDATA names itself
   (a synthetic message built and packed by our own code left a repeated literal name
   rather than emitting a pointer) — irrelevant to this MUST (which is about *accepting*
   compressed input, not producing it), but worth remembering if `pkg/updatecore` ever
   needs to reproduce a specific wire size.
6. **KEY `flags` handling — confirmed 2026-09-11, and a real bug in an early `pkg/srp`
   draft caught by it.** Requesters MUST send flags 0; the registrar MUST accept and
   store flags **as received, without checking or modifying them** (§3.3.3, quoted
   verbatim) — this is one-directional, and the registrar side is a MUST-NOT-check, not a
   parallel MUST-be-zero. `pkg/srp/validate.go`'s first draft rejected non-zero flags
   (reading the requester-side MUST as if it also bound the registrar); this was caught
   immediately by `TestValidate_RealMDNSResponderCapture` — the real captured
   `mDNSResponder` `srp-client` message carries flags `513` (`0x0201`), not 0: a literal
   miss of the requester-side MUST, but not a careless one. Decoded against RFC 2535
   §3.1.2's field layout (`A/C|Z|XT|Z|Z|NAMTYP|Z|Z|Z|Z|SIG`), `0x0201` is `NAMTYP=10`
   ("a key associated with the non-zone entity... used in connection with DNS request and
   transaction authentication services") with a non-zero `SIG` field ("the key can
   validly sign things as specified in DNS dynamic update [RFC 2137]") — the traditional
   pre-RFC-9665 encoding for "this is a host key valid for signing dynamic updates,"
   evidently carried over from that older convention rather than RFC 9665's later
   flags-must-be-zero simplification. The fix (drop the registrar-side check entirely,
   per the §3.3.3 text) is exactly what the RFC requires regardless of why the flags
   aren't zero. Existing keystore keys are often 256/257 — `client/srp` (a later phase)
   must still build a flags-0 KEY for outgoing SRP requests, independent of what the
   registrar accepts from others.
7. **TTL consistency + clamping ordering** — the §4 check runs *before* `LeasePolicy`
   clamping; clamping keeps RRset TTLs equal (§6).
8. **ECDSA P-256 SIG(0) — root-caused and fixed 2026-09-11 (Phase 1). A genuine bug in
   `codeberg.org/miekg/dns` v0.6.82, already silently worked around for ED25519 but not
   for any other algorithm; fixed locally and generalized, not reported upstream (§8).**
   Full story:
   - **Our own alg-13 round trip passes; verifying a real captured `srp-client` signature
     failed** (`"dns: bad signature"`) — reported in the Phase 0 spike (§10 item 8,
     earlier revision). Root-caused by instrumenting a local copy of the `dns` module
     (`replace` directive, reverted after) to print the exact bytes both `Sign` and
     `Verify` hash.
   - **Root cause: `dns.CryptoSIG0.Sign`/`Verify` (`sig0_signer.go`) hash the SIG RR's
     *full wire encoding* — NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA (via
     `packRR(s, sbuf, 0, nil)`) — instead of RDATA-only.** RFC 2931 §3 is explicit:
     *"data = RDATA | request − SIG(0) ... RDATA is the RDATA of the SIG(0) being
     calculated less the signature itself"* — no NAME/TYPE/CLASS/TTL/RDLENGTH prefix.
     Confirmed independently against `mDNSResponder`'s own C source
     (`ServiceRegistration/towire.c: dns_sig0_signature_to_wire_`, §12.3): it hashes
     `rr`/`rdlen` = a pointer/length pointing *after* the RR header, i.e. RDATA-only —
     matching the RFC, not the Go fork. Trimming the fork's `sbuf` down to RDATA-only (11
     bytes: 1 name + 2 type + 2 class + 4 TTL + 2 rdlength) and re-hashing makes the
     captured real signature verify successfully (`ecdsa.Verify` → `true`) — a direct,
     reproduced confirmation, not a guess.
   - **Why the existing ED25519 path was never affected.** `pkg/sig0/signer.go`'s
     `sig0SignerImpl.Sign`/`Verify` already special-cases `algorithm == 15` (comment:
     *"CryptoSIG0.Sign would fail because AlgorithmToHash doesn't have it"*) and builds
     its own `sigData` prefix by hand — which, on inspection, is *already RDATA-only*
     (TypeCovered/Algorithm/Labels/OrigTTL/Expiration/Inception/KeyTag/SignerName, no RR
     header). Whoever wrote that code got RFC 2931 right, whether or not they knew they
     were also routing around this exact library bug — the effect is that ED25519 (what
     every existing test exercises) has always been correct, while every other algorithm
     that falls through to `s.base.Sign`/`s.base.Verify` (ECDSAP256SHA256, and by the same
     code path presumably ECDSAP384SHA384 and the RSA family, RFC 9664 alg constants
     1/5/8/10/13/14 — untested here) inherits the bug. This is exactly why the base
     RFC 9664 handler's existing test suite, real-zone integration tests included, never
     surfaced it: nothing before this session had ever driven a non-ED25519 signature
     through it against a real, independent verifier.
   - **Decided and fixed (§8):** generalize the fix (D7-B) to ED25519 + ECDSAP256SHA256 +
     ECDSAP384SHA384; do not report upstream now, but document the reproduction thoroughly
     so it's easy to do later. Both done — see §8.
9. **`YXDOMAIN` response path** — new; `makeErrorResponse` takes arbitrary rcodes, but
   `client/srp` must read it as "rename & retry", not "hard fail".
10. **Subtype atomicity** (§3.3.4) — falls out for free from the same wipe-then-reinsert
    used for A/AAAA/SRV/TXT, applied to the service node's PTR children too; the real work
    is the pre-wipe diff that builds the *upstream* delete for a dropped subtype, since
    upstream never delete-alls the PTR's owner name (§4.5). `client/srp` must always
    restate Service Discovery for services that should stay discoverable (§4.5).
11. **Per-service-instance lease tracking** (§5.1) — an update that drops a service must
    leave that instance expiring on its own old timer.
12. **`SendUpdate` zone-equality guard** — the upstream message's question-section zone
    must match what `resolveAuthoritativeZone` / the static `upstream` config says.
13. **Interop reality check** — validate against the local `mDNSResponder/
    ServiceRegistration` build (`srp-client`/`srp-mdns-proxy`/`srp-dns-proxy`, §12.3) and
    OpenThread `srp_server`/`srp_client` (Phase 5+), not only our own client.

---

## 11. Resolved review questions

Condensed record of the three Q&A rounds; full reasoning is in the session.

- **Q1 (duplicate protection / foreign data).** SRP does no duplicate check on non-KEY
  RRs (delete-all-then-add is safe). The KEY check *is* FCFS, now a **tri-state** query
  (§3.3 table): `NXDOMAIN` → first come; `NODATA` (name exists, no KEY) → `REFUSED` by
  default (`srp.refuse_on_foreign_data`, **default `true`** per the reviewer's instinct) —
  with it `false`, delete-all-then-add clobbers the foreign RRset (an identical RR is
  re-added onto our lease clock = soft hijack; a different RR is replaced); `KEY` present
  → match proceeds, mismatch `YXDOMAIN`. No "adopt an existing lease with a reconstructed
  duration" — every SRP update carries its own complete lease statement, so a
  match-with-empty-store is just a fresh registration with this request's lease times.
- **Q2 (hierarchy).** Two distinct checks in today's code: (1)
  `validateSignerHierarchyForUpdateRecords` is a *DNS-name* check and rejects SRP's
  sibling PTR — replaced for SRP by the §3.3.1.1 linkage rule; (2) tree-parent ownership —
  not used for SRP authorization at all (see Q7).
- **Q3 (TTL).** §6 — SRP rejects (`REFUSED`, RFC 9665 §4); base normalizes to the minimum
  (RFC 2181 §5.2).
- **Q4 (pre-forward queries).** §5 — base does several; SRP does the FCFS `KEY`-at-name
  query only (per name uncovered by the store) plus zone resolution; zero with a static
  `upstream`. The FCFS query and the Q1 table are the same query.
- **Q7 (authorization).** For SRP, authorization = structural validation (all KEYs
  identical & == signing key, §3.2.5.1) + per-name FCFS (§3.3.3). No per-record
  parent/key walk — the service-instance node and host node hold the same key by
  construction, and the node-key mismatch is a cosmetic artifact of name-scoped identity.
  `ParentKeyName` is cascade/grouping only on the SRP path; unchanged (authz + cascade) on
  the base path. SIG(0) verification is against the Host Description KEY (§3.3.3), no
  three-stage resolution.
- **Q8.** Shared plumbing → `pkg/updatecore` (public, repo convention), not `internal/`.
- **Q9 (RFC §3.2.3.3).** "the SRP registrar MUST defer sending" reads as an editorial
  slip for "requester"; moot for us (we forward to a plain RFC 2136 server, never chain
  to another SRP registrar, and process one update at a time).
- **Refresh clock.** RFC 9664 §5.2 (80% + 0–5% jitter) is the base clock; §5.2.1
  (75%/50%) is the separate coalescing mechanism.

---

## 12. Testing strategy

### 12.1 Test-script refactor (Phase 0 — done 2026-09-11 — prerequisite for `test_srp.sh`)

```
tests/
  lib/
    common.sh      # log_*, double-source guard, return-not-exit, no `set -e` at lib scope
    dns.sh         # dig_query_short, rr_at_authoritative, wait_for_rr_state, add_rr/delete_rr
    proxy.sh       # build_binaries, prepare_lease_config, start/stop proxy
    client.sh      # run_client + wrappers
    leasestore.sh  # lease_dump, lease_store_has_rr, lease_store_*_expires_at,
                   # proxy_consistent_with_authoritative
  test_update.sh   # orchestration only — sources lib/* — behaviour identical to today
  test_srp.sh      # NEW — orchestration only
  test_forward.sh  # source line updated to lib/*
  reset.sh         # source line updated to lib/*
```

Rules for `lib/`:
- No `set -euo pipefail` at library scope (runner scripts set it, or `$-` is saved/restored).
- Functions `return 1` on failure — never `exit`.
- Idempotent double-source guard per file.
- **`lease_dump [proxy_addr] [level]`** — `proxy_addr` defaults to
  `${PROXY_URL:-127.0.0.1:8053}`, `level` defaults to `info`; **no required env vars**.
  Same for `lease_store_has_rr` etc. (optional proxy-addr first arg).
- Logging degrades gracefully when `$LOG_FILE` / `$DEBUG` are unset.
- `utils.sh` is deleted — its contents move into the right `lib/*.sh` file; no shim.

**Done 2026-09-11.** `lib/{common,proxy,client,dns,leasestore}.sh` built as specified above
(`test_srp.sh` itself is not — no SRP handler exists yet to orchestrate against). Three
things worth recording:
- **`CLIENT_KEYSTORE_DIR` really was hard-required just to *source* the old `utils.sh`**,
  even for a script (`test_forward.sh`) that never touches client keys — confirmed by
  reading the code, not just inferred. Fixed via `require_client_keystore_dir()`, called
  lazily only by the functions that actually need it.
- **`lease_dump [proxy_addr] [level]` and friends** (`lease_store_has_rr` etc.) gained the
  planned optional leading `proxy_addr`, but not via raw positional shifting — an
  arg-sniffing heuristic (":" present ⇒ treat as an address) keeps every existing call
  site working unchanged, with one documented caveat: a hypothetical future
  `lease_store_rr_expires_at` needle containing a literal ":" (e.g. an AAAA address) would
  be misread as a leading address. No current call site does this.
  `lease_dump`'s own dispatch is simpler (0/1/2 args, level recognized by value from
  `{info,debug}`) since it's the one function the plan gave an explicit signature for.
- **Found and fixed a real, pre-existing bug while validating the refactor**:
  `test_forward.sh` did `cd "$(dirname "$0")/."`, landing in `tests/`, while
  `config.yaml`'s `keystore_dir: "./keystore/server"` is relative to `main/` — so the
  proxy it started could never find its own signing key. This predates the refactor
  (confirmed via `git show`); fixed to `cd "$TESTS_DIR/.."`, matching `test_update.sh`'s
  own (no-`cd`, invoke-from-`main/`) convention.

**Validation.** The full `test_update.sh run` suite (all RR types, all cases) was run
against the real `dev.zenr.io.` zone (§14 option A) both before and after the refactor,
from a scratch copy of the pre-refactor `utils.sh`/`test_update.sh` pulled via `git show
HEAD:...`, to distinguish a real regression from environment flakiness. One initial run
under the refactored code did fail (Test 3, a tight two-key expiry timing window with only
a 2s buffer against a live, real-internet-latency DNS server) — but two further matched
A/B comparisons (old code vs. new code, same restricted `RR_TYPES=KEY`, back to back on a
freshly-cleaned zone) both passed cleanly, and a final full unrestricted run of the
refactored suite passed end-to-end with the zone left pristine. Conclusion: a one-off
real-network timing flake, not a refactor regression — and a concrete demonstration of
exactly why §14 promotes local BIND 9 (option C) to the required CI gate rather than
relying on the shared real zone alone.

### 12.2 Coverage

- **`pkg/srp` unit tests — done 2026-09-11 (Phase 1).** Table-driven, one row per RFC 9665
  §3.3.1/§3.3.2 clause: near-misses that must be rejected (no Host Description, >1
  hostname, SRV target ≠ host, SRV without TXT, orphan PTR target, subtype PTR without a
  preceding base-type PTR, duplicate delete-all, unrecognized RR type, KEY for an
  unrelated name), plus `Validate`-level checks (TTL inconsistency, KEY mismatch, missing
  lease option, `KEY-LEASE < LEASE`, prerequisites present, >1 Zone Section entry).
  Positive cases: **RFC 9665 Appendix C's own worked example** (Figure 2's example zone
  file, reconstructed as the update that produces it — the fixture's KEY material is the
  RFC's own, and the test asserts our `KeyTag()` matches the RFC-stated 14495 as a
  correctness cross-check) and the **real captured `mDNSResponder` `srp-client` message**
  (§10 item 1) via `Validate`, not just `Classify`. Two deliberate divergences from
  `srp-parse.c` are documented inline and tested: multiple TXT adds are allowed (RFC text
  says 1..n; Apple's own registrar rejects a second TXT outright) and a subtype PTR
  *delete* doesn't require a preceding base-type PTR add the way an *add* does. One real
  bug caught by testing against the real capture: an early draft rejected non-zero KEY
  flags, which is backwards — see §10 item 6.
- **FCFS tests** — new name; same-key re-registration; different-key ⇒ `YXDOMAIN`; name
  held by KEY-lease after data-lease expiry; hijack-via-bundled-host ⇒ `YXDOMAIN` (**done
  2026-09-14**: `handlers/srp_handler_test.go`'s `TestSRPHandle_HijackViaBundledHost_Refused`
  -- an attacker bundles a fake Host Description for someone else's already-registered host,
  signed by their own key, with a service instance riding along; rejected at the bundled
  host claim, before SIG(0)/forwarding ever run, leaving the victim's own registration
  completely untouched).
- **Handler tests — done 2026-09-12.** A fake `srpCoordinator` (not `UpstreamCoordinator` --
  a narrower interface scoped to what `Handle()` actually uses, see `handlers/srp_handler.go`);
  20 tests in `handlers/srp_handler_test.go` asserting forwarded message shape, RCODE
  mapping, lease-store mutations, and deferred-mutation ordering (nothing written before
  upstream `NOERROR`, including on the delete side).
- **Lifecycle tests — done 2026-09-12** (folded into the handler tests above, since expiry
  turned out to need five separate regression tests to pin each bug found): host-expiry
  covers its whole subtree (services + PTRs), not just itself; a REFUSED/SERVFAIL upstream
  delete leaves local state untouched rather than removing it optimistically; service-
  instance removal (both live-update and expiry paths) cleans up its PTR(s) at the shared
  service-type name.
- **Crypto tests** — alg-13 sign/verify; alg-13 keystore load; flags-0 KEY. (Covered by
  Phase 0/1's existing `pkg/sig0` suite; no SRP-specific addition needed.)
- **Integration — done 2026-09-12.** `tests/test_srp.sh` + `tests/lib/bind9.sh` against a
  **local BIND 9** (§14 option C): register → `dig` → refresh → conflict (`YXDOMAIN`) →
  remove-one → remove-all (host address data, KEY persists -- see the S12.2 note on SRP
  having no direct RFC-9664-Case-C analog) → expiry. Green twice in a row end-to-end.
  A second job against the real `srp.dev.zenr.io.` path (§14 option A) as an occasional
  real-internet smoke test is not yet built.
- **Interop** — the local `mDNSResponder/ServiceRegistration` build (primary — see §12.3),
  OpenThread simulation `srp_server` / `srp_client` (secondary), BIND 9 for the Appendix
  A/B path. OpenThread runs in the Linux CI sandbox (confirmed acceptable).

### 12.3 Local Apple mDNSResponder reference

Setup steps (clone command, pinned commit, the two patches, OpenThread's own fixture-
re-extraction recipe) are written up once in `tests/README.md` — read that before touching
either checkout; this section stays the narrative/reasoning record.

`mDNSResponder/` is checked out at the workspace root **deliberately, to serve this
development** (not incidental). `ServiceRegistration/` contains Apple's own SRP
implementation, built with a single `make` in that directory (`os` auto-detected from
`uname -s`; the Linux target needs `mbedtls` dev libraries: `apt-get install
libmbedtls-dev` pulls in `libmbedcrypto`/`libmbedx509` too).

**Confirmed 2026-09-11: builds and runs, with two small upstream fixes.** `make` (the
default `all` target) now succeeds end-to-end after two minimal, self-contained patches to
this checkout (`mDNSResponder` is its own git repo at tag `mDNSResponder-2881.0.25`, so both
are trivially diffable/revertable and are not part of `main`'s source):

1. `srp-replication.c` calls a function, `srpl_current_domain()`, that is declared nowhere
   in this snapshot (`-Werror=implicit-function-declaration`) — added as a small static
   helper using the exact domain-list lookup idiom already used elsewhere in the same file
   (`srpl_shutdown()`), so `srp-mdns-proxy.c` — which invokes it as a "dummy domain"
   fallback in `srpl_associate_incoming_with_instance()` — compiles again.
2. `srp-mdns-proxy.c` calls `srp_log_ref_check()` / `srp_log_ref_final()` directly at
   several object-finalization sites; both are declared in `srp.h` (next to the
   `RELEASE_BASE`/`RETAIN_HERE_LOG` reference-counting macros) but never defined anywhere in
   this open-source snapshot, so the link failed. Added as no-op stubs in `srp-log.c`
   (`srp_log_ref_check` returns `true` — the "not faulted" case the caller's fault-check
   macro expects; `srp_log_ref_final` is a pure debug-logging hook).

Neither gap is SRP-specific — both are pre-existing holes in this snapshot's own reference-
counting/replication debug instrumentation, unrelated to anything this plan changes.

| Binary | Role | Built by default? | Confirmed running |
|---|---|---|---|
| `srp-client` | SRP **requester** reference implementation | yes (`make all`) | yes |
| `srp-mdns-proxy` | SRP **registrar** ("Advertising Proxy") — validates FCFS, applies leases, then bridges registrations to local mDNS rather than a real zone | yes | yes |
| `keydump`, `dnssd-proxy` | supporting tools | yes | yes |
| `srp-dns-proxy` | SRP **registrar** ("Update Proxy") — listens for SRP updates, translates to plain RFC 2136 DNS UPDATE, forwards to a backend authoritative server | **no** — Makefile rule exists (`make build/srp-dns-proxy`), just not in `all` | **no — does not build** in this snapshot: several call sites (`srp_update_start`, `srp_proxy_listen`, `ioloop_connect`, `ioloop_events`) no longer match current function signatures elsewhere in the tree. This is materially more drift than the two gaps above — plausibly why Apple excludes it from `all` — and not a reasonable Phase 0 fix-up; left as source-level reference only (see below) unless a later phase specifically needs the running binary. |

**`srp-dns-proxy.c` is independent external validation of D4.** Its own header comment:
*"This is a DNSSD Service Registration Protocol gateway. The purpose of this is to make it
possible for SRP clients to update DNS servers that don't support SRP. The way it works is
that this gateway listens on port ANY:53 and forwards... to any port (usually 53) on a
different host."* That is precisely the "resolve, re-sign, forward to a plain RFC 2136
backend" registrar model D4 already committed to, from a completely independent
implementation — further reason D4-B (standalone authoritative registrar) stays out of
scope, and a good architectural cross-reference for §5.

Uses, beyond interop testing:
- **Implementation reference during Phase 1–3** — `srp-parse.c` (instruction
  classification/validation — cross-check `pkg/srp`'s classifier against it), `srp-mdns-
  proxy.c` (FCFS + lease handling), `srp-dns-proxy.c` (SRP → RFC 2136 UPDATE construction,
  the closest architectural sibling to `pkg/updatecore`'s forward path).
- **Interop, Phase 5** — `srp-client` against our registrar; `srp-mdns-proxy` against
  `client/srp` (validates wire-protocol/FCFS/lease correctness even though its backend
  differs from ours — it bridges to mDNS, not a real zone). `srp-dns-proxy` does not build
  in this snapshot (see above) so it is not a running interop counterpart; its source stays
  useful as the closest architectural reference for `pkg/updatecore`'s forward path.

Zero setup cost (already checked out, one `make` command) is why this outranks OpenThread
as primary interop — OpenThread remains valuable as the RFC's credited *second*
independent implementation, worth keeping as a secondary cross-check.

---

## 13. Phased roadmap

| Phase | Deliverable | Gate |
|---|---|---|
| **0 — Spikes + infra** | **All of (a)-(g) done 2026-09-11.** See §10 items 1/2/5/8, §12.1, and §12.3 for full results. (a) delete-all-RRsets shape confirmed against both a synthetic message and a real `srp-client` capture; (b) alg-13: our own round trip passes, **but verifying a real independent implementation's signature currently fails — open risk carried into Phase 1**, see §10 item 8; (c) compressed SRV target confirmed against a real capture; (d) confirmed safe by construction (code reading); (e) `tests/lib/` refactor landed, env-var-free `lease_dump`/`lease_store_*`, one real pre-existing bug found and fixed along the way (§12.1); (f) `pkg/updatecore/ttl.go` (`CheckConsistentTTLs`/`NormalizeTTLs`) built, unit-tested, and wired into the base handler; (g) `mDNSResponder/ServiceRegistration` builds and `srp-client`/`srp-mdns-proxy` run, after two small upstream-bug patches (§12.3) | Unknowns de-risked (one turned up a real open risk — alg-13 cross-impl verify — rather than a clean pass, which is itself the gate doing its job); `test_update.sh` (full RR-type matrix, real zone) green end-to-end on the refactored libs, `go test ./...` green including the new `pkg/updatecore` tests |
| **1 — `pkg/srp` core — done 2026-09-11** | instruction model (`HostDescription`/`ServiceInstance`/`ServiceDiscovery`) + `Classify()` + `Validate()` (structural + TTL-reject + lease-option + KEY-identity checks); full unit tests; no network; classification algorithm closely follows `srp-parse.c`'s scan-then-reconcile structure (§12.3), divergences documented inline | **Met**: `TestClassify_RFC9665AppendixCExample`/`TestValidate_RFC9665AppendixCExample` (RFC's own worked example) + `TestValidate_RealMDNSResponderCapture` (real capture) + an 11-case near-miss table + 6 `Validate`-level rejection cases, all green |
| **2 — FCFS + store — done 2026-09-11** | `pkg/srp/fcfs.go` (`Evaluate()` + `Names()`/`KeyFor()`); `pkg/lease/srp_shape_test.go` prototyping the S4.4 worked-example tree against the *existing, unmodified* store — confirmed no new methods, no `NodeKind`, no snapshot version bump needed | **Met**: full FCFS tri-state table green (`pkg/srp/fcfs_test.go`); tree-shape/cascade/wipe-reinsert/shared-PTR-owner-name tests green (`pkg/lease/srp_shape_test.go`); full `go test ./...` green throughout, `pkg/lease`'s pre-existing suite unaffected |
| **3 — Handler + routing — done 2026-09-12** | `pkg/updatecore` extraction; `handlers/srp_handler.go`; ordered-`modules` dispatch in `router.go`; `srp` config block (incl. per-zone static `upstream`, `allow_udp`, stub `allowed_source_prefixes`); forward + re-sign + RCODE mapping incl. `YXDOMAIN`; TCP-required enforcement; commented stubs for source check + `default.service.arpa.` rewrite; five real bugs found and fixed via live testing (KEY inheritance, expiry cleanup completeness/RCODE-checking/subtree-coverage, removal-path PTR cleanup — full detail in the revision history above) | **Met**: 20 handler tests green against a fake `srpCoordinator`; `tests/test_srp.sh` green end-to-end against a real local BIND 9, twice in a row |
| **4 — Client — done 2026-09-14** | `client/srp` (builder + discovery + §5.2 refresh scheduler + `YXDOMAIN` rename-retry + initial 0–3 s random delay); `cmd/sig0lease-srp`; one real bug found and fixed via live testing (missing `pkg/dnscompat` import — full detail in the revision history above) | **Met**: 29 new unit tests green; live end-to-end against a real local BIND 9 + the Phase 3 registrar — fresh registration, refresh, conflict, rename-retry, live SRV discovery, and an unattended §5.2 refresh clock all directly observed, not just inferred |
| **5 — Interop — done 2026-09-14** | `mDNSResponder/ServiceRegistration` (`srp-client` against our registrar, `srp-mdns-proxy` against `client/srp` — both confirmed buildable and running in Phase 0; `srp-dns-proxy` does not build in this snapshot, source-reference only), primary; OpenThread simulation build in CI as a secondary cross-check, not attempted | **Met**: both primary directions confirmed live — `srp-client` fully round-tripped against our registrar (dig-confirmed at authoritative, including a live alg-13 signature verify against a real implementation and the flags=513 passthrough); `client/srp` against `srp-mdns-proxy` confirmed at the full SRP-protocol level (`srp_evaluate: ... validates`, exact field match) with the one remaining failure isolated to an unrelated, environment-only local-mDNS-daemon gap — full detail in the revision history above |
| **6 — `default.service.arpa.` — done 2026-09-14** | zone-rewrite (`rewrite_default_service_arpa` config flag); every name in the update rewritten to `upstream_zone` before FCFS/forwarding, response still echoes `default.service.arpa.` | **Met**: unit + handler tests (`TestSRPHandle_DefaultServiceARPA_*`, `TestRewriteZoneSuffix`, `TestRewriteDefaultServiceARPA_OwnerAndTargetNames`) plus a live round-trip against real BIND 9 using the actual, unmodified mDNSResponder `srp-client` (which only ever knows `default.service.arpa.`) — registered against a proxy configured for `srp.test.`, `dig`-confirmed the data landed under `srp.test.` (not `default.service.arpa.`), full detail in §13's revision history |
| **7 — DoT — done 2026-09-14** | `server/transport_tls.go` (`serveDoT`); a `"tls"` entry in `server.networks` + a new `server.tls: {address, cert, key}` config block; opportunistic only, no client-cert auth; transport-level so it benefits every handler (base RFC 9664, SRP, plain forwarding alike) | **Met**: `TestServeDoT_RoundTrips`/`TestServeDoT_MissingTLSConfig` (server package) + 4 `config.Validate` cases (config package), all green; live-smoke-tested against the real `cmd/sig0lease` binary with a real `openssl`-generated cert, queried with real `dig +tls` — genuine TLS handshake, correct forwarded answer back over the wire, full detail in §13's revision history |

Phases 1–3 are the critical path to a usable SRP registrar for configured real zones.
Phase 4 makes it end-to-end testable. Phases 6–7 close the remaining MUSTs.

---

## 14. Test environment

All three review-round open questions are resolved:

- **OpenThread interop in CI** — **tried, then removed; superseded by a real
  cross-implementation fixture instead (revised 2026-09-14 twice: first after actually
  building it, see §13's post-Phase-5 entry; then again after the user questioned its value,
  see §13's interop-coverage-expansion entry).** OpenThread's SRP client/server are CLI
  commands inside a full simulated Thread mesh node, and the simulation platform's "radio" is
  a closed bus between `ot-cli-ftd` processes on one host with no TUN device or route
  anything outside can reach (confirmed empirically, not assumed) — genuine network-level
  interop would need a Thread Border Router (`openthread/ot-br-posix`) bridging Thread mesh
  traffic to the host network, a separate, heavier project, left for if it's ever wanted. A
  build-and-self-test CI job (`tests/test_openthread.sh`) was built as a lesser substitute,
  but only ever ran OpenThread's *own* internal test suite — zero exercise of our own code —
  and was removed once that was pointed out. What replaced it: a real wire-format SRP message
  extracted directly from OpenThread's own SRP client (`pkg/srp/srp_test.go`'s
  `TestValidate_RealOpenThreadCapture`, `pkg/sig0/ecdsa_test.go`'s
  `TestECDSAP256KnownAnswerFromOpenThread`) — genuine cross-implementation signal, no network
  or Border Router needed.
- **`v2 → v3` snapshot** — **hard-fail confirmed.** An old snapshot is rejected at load;
  the operator re-registers. Matches the current loader; no migration path.
- **Test zone** — **both C and A are deliverables.** C gates every PR; A is the shared
  environment other developers point `dig` at. `tests/test_srp.sh` runs against both. B is
  only if zone isolation is later wanted.

### Option C — local BIND 9 (the CI gate)

`tests/test_srp.sh` runs against BIND 9 in the CI container, authoritative for
`srp.dev.zenr.io.` (or `default.service.arpa.` — locally-served by design, and the D4
static `upstream` bypasses the SOA-discovery problem D5 defers, so CNN-zone-shaped names
are testable before the Phase 6 rewrite). `allow-update { key test-srp; };`, the RFC 9665
Appendix C zone skeleton, `srp` config with `upstream: 127.0.0.1:5300`. Deterministic, no
external dependency. `tests/test_mdnsresponder_interop.sh` also serves this same BIND 9
instance for its Direction-1 scenarios (a second `default.service.arpa.` zone clause,
forced by mDNSResponder's own hardcoded client-side zone string — see
`tests/bind9/default.service.arpa.zone.in`'s own doc comment), covering plain registration,
host-only, and all three subtype variants against the real `srp-client`; its Direction-2
scenarios (our own client against the real `srp-mdns-proxy`) don't touch BIND 9 at all.

### Option A — the shared, developer-visible environment (deliverable)

No delegation. Use names under `srp.dev.zenr.io.` inside the existing `zenr.io.` zone at
`ns1.free2air.org`; the existing proxy key `Kdev.zenr.io.+015+35317` already has SIG(0)
update rights over the `dev.zenr.io.` subtree there (**confirmed working** by a manual
`nsupdate` smoke check). Point `upstream_zone` at `dev.zenr.io.`. Other developers inspect
registrations here with plain `dig @ns1.free2air.org`. No further provisioning needed.

### Option B — a real delegated `srp.dev.zenr.io.` zone (only if isolation is wanted)

1. `dnssec-keygen -a ECDSAP256SHA256 -n HOST -T KEY srp.dev.zenr.io.` (alg 13, D7) → `keystore/server/`.
2. Authoritative server for `srp.dev.zenr.io.` with `update-policy` granting that key
   rights over the zone; Appendix C zone skeleton (SOA, NS, optional `_dnssd-srp._tcp` SRV).
3. Delegation in `dev.zenr.io.`: `srp.dev.zenr.io. IN NS <ns>.` via `nsupdate` signed with
   the existing `Kdev.zenr.io.` key. The **DS-update key is only needed here for a
   DNSSEC-secure delegation** — a test zone can use an **insecure delegation (NS only)**.
4. `srp` config: `upstream_zone: srp.dev.zenr.io.`, optionally the D4 static `upstream:`.
