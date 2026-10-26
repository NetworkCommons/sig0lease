# Proxy (RFC 9664 lease-UPDATE)

Proxy is a DNS proxy for SIG(0)-authenticated UPDATE-LEASE registration flows, according to
[RFC 9664](https://datatracker.ietf.org/doc/rfc9664/) and [RFC 2931](https://datatracker.ietf.org/doc/rfc2931/).
It accepts DNS UPDATE packets, validates the downstream SIG(0) signature, applies the
lease/update policy, and forwards the resulting UPDATE to the authoritative server selected for
the zone. The code also supports standard DNS routing for packets that are not relevant to this
flow.

The proxy also implements [RFC 9665](https://datatracker.ietf.org/doc/rfc9665/) (DNS-SD Service
Registration Protocol, SRP) as a **sibling** request path, sharing this document's SIG(0)
signing, lease store, upstream forward/re-sign, and DNS-over-TLS transport, but with its own,
more constrained message shape and authorization model — see `docs/siglease_rfc9665.md` for
that protocol. Everywhere below, a callout marks the parts genuinely shared between the two.

## What It Does

The project is intended to provide a light, explicit control point for lease registration
traffic:

- Receive DNS queries over UDP and TCP.
- Route the registration opcode to the update handler and forward unrelated traffic upstream.
- Process DNS UPDATE requests carrying an UPDATE-LEASE EDNS option.
- Verify downstream SIG(0) signatures before the proxy accepts the request.
- Re-sign the upstream UPDATE with the proxy's zone key before forwarding.
- Forward unhandled opcodes to the configured upstream resolver path.

*(Shared with RFC 9665 SRP: SIG(0) verification/re-signing and upstream forwarding follow the
same pattern described in "Upstream Forwarding and Write Ordering" below; SRP's message shape
and authorization are different, see `docs/siglease_rfc9665.md`.)*

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

To print each enabled handler's lease store and exit, add `--dump` (a summary) or
`--dump-debug` (every record):

```bash
./bin/<your OS>/sig0lease --dump ./config.yaml
```

A dump writes nothing: it reads a file store's snapshot as it is, without saving it back or
creating its directory, so it is safe beside a running proxy. It still runs each handler's
`Setup`, so it needs the same keystore as the proxy itself.

Run the client against a proxy. Its commands take `<command> [flags] [args]`, the flags first,
spelled as `sig0lease-srp-client`'s (`cmd/internal/cli`): `-server`, `-transport tcp|udp|tls`
(default `tcp`), `-keystore`, `-k`, `-lease`, `-key-lease`, `-ttl`. `sig0lease-client help`
lists them all. A keystore is required, given with `-keystore <dir>` or `CLIENT_KEYSTORE_DIR`
(the flag wins if both are given; `sig0lease-srp-client` and `sig0lease-agent` follow the same
convention):

```bash
./bin/<your OS>/sig0lease-client register -server 127.0.0.1:8053 -keystore /path/to/keystore \
  -lease 300 -key-lease 3600 -same-key Ktest.dev.zenr.io.+015+05044 'client.test.dev.zenr.io. 300 IN TXT "hello"'
```

By default a key must already exist under that keyname in the keystore
(`register`/`refresh`/`register-tamper` all error out rather than creating one). Pass `-k 13`
(ECDSAP256SHA256) or `-k 15` (ED25519) to generate one on first use instead — with `-k`, the
keyname argument is read as an owner name (e.g. `test.dev.zenr.io.`) rather than an exact key
filename, and any existing key for that name is reused regardless of its algorithm:

```bash
./bin/<your OS>/sig0lease-client register -server 127.0.0.1:8053 -keystore /path/to/keystore \
  -lease 0 -key-lease 3600 -same-key -k 13 test.dev.zenr.io.
```

## Client Use Cases

The client binary supports these commands:

- `name` - keep one name registered through the `client/rfc9664` library, as `sig0lease-srp-client` keeps a host through `client/srp`: the name, one label below the zone, with its own key, its addresses (`-addr`) and records (`-record`, written as in a `sig0lease-agent` template), refreshed on the lease clock until stopped. `-once`, `-withdraw` and `-deregister [-keep-names]` send one request instead (Cases A, D, and C or D).
- `register`, `refresh` - send exactly the signed UPDATE-LEASE request described: the KEY and other records given (`rr-spec`), the signer's KEY where `-signer` puts it, the Zone Section `-zone` names (default: the signing key's name). The test suite uses them to send the shapes the proxy must refuse.
- `register-tamper` - sign the request, then flip one payload bit to confirm the proxy rejects a bad SIG(0).
- `verify` - query whether a registration is currently active.
- `list-keys` - list available keystore entries.

Examples:

```bash
sig0lease-client name -server 127.0.0.1:8053 -zone dev.zenr.io. -name mysite -k 13 \
  -addr 192.0.2.10 -record '_dnslink TXT "dnslink=/ipfs/bafy..."'
sig0lease-client register -server 127.0.0.1:8053 -lease 300 -key-lease 3600 -same-key \
  Ktest.dev.zenr.io.+015+05044 'client.test.dev.zenr.io. 300 IN TXT "hello"'
sig0lease-client register-tamper -server 127.0.0.1:8053 -lease 0 -key-lease 3600 -same-key Ktest.dev.zenr.io.+015+05044
sig0lease-client verify -server 127.0.0.1:8053 test.dev.zenr.io.
sig0lease-client list-keys -keystore /path/to/keystore
```

## Proxy Use Cases

The proxy is designed to support two practical scenarios:

- Registration: a client submits an authenticated UPDATE-LEASE request and the proxy forwards a signed UPDATE to the authoritative server.
- Pass-through routing: non-registration traffic is forwarded according to the configured opcode routing and upstream settings.

## UPDATE-LEASE Case Matrix

Clients include an UPDATE-LEASE option (EDNS option code 2) in their UPDATE packets. Two
encodings are supported:

- **8-byte variant (default):** 4 bytes encode the LEASE value (lease duration for non-KEY RRs), followed by 4 bytes encoding the KEY-LEASE value (lease duration for KEY RRs). Both are big-endian `uint32` values.
- **4-byte variant (legacy):** 4 bytes encode a single LEASE value used for both KEY and non-KEY RRs. macOS's mDNSResponder sends it. Accepted only with `prefer_4byte_variant: true` on the handler, and `REFUSED` otherwise. When accepted, the one value is the KEY-LEASE if the Update section has KEY RRs, and the LEASE if it has other records, and 0 for a kind it lacks: Case A with both kinds, B with non-KEY records only, D with KEYs only, C for 0 (`requestedLeases`). After clamping, the KEYs get the granted LEASE, since RFC 9664 S4 has them expire together. The reply carries that one value in the 4-byte variant, the only one mDNSResponder reads (`grantedLeaseOption`). The proxy refuses to start with `prefer_4byte_variant: true` and `min_key_lease_sec` above `max_rr_lease_sec`, since no single lease would then fit both bounds.

A bad option is answered with a header RCODE: `FORMERR` for a length other than 4 or 8 or a LEASE above the KEY-LEASE, `REFUSED` for a 4-byte option without `prefer_4byte_variant`. A duration outside the lease policy is not an error: it is raised to the minimum or cut to the maximum ("Lease Clamping, TTLs and Response Echo" below). Extended RCODEs (16 and up, their high bits carried in the OPT RR) are avoided because a requester that reads only the header, as mDNSResponder does, takes them for NOERROR.

LEASE and KEY-LEASE together select one of four behavioral cases, detailed rule-by-rule in
"Behavior Specification" below:

| Case | KEY-LEASE | LEASE | Behavior |
|---|---|---|---|
| A | Non-zero | Non-zero | Full registration/refresh of a KEY RR and its non-KEY RRs together. |
| B | 0 | Non-zero | Non-KEY-only registration/refresh; the signing KEY must already be managed. |
| C | 0 | 0 | Delete: removes whichever of the named KEY/non-KEY RRs are actually locally managed. |
| D | Non-zero | 0 | KEY-only registration/refresh, with optional deletion of accompanying non-KEY RRs. |

Both the request-side decoding (`handlers/opcode5_lease_option.go`) and the response/client-side decoding (`client/lease_response.go`) share one low-level decoder (`pkg/lease.FindOption` + `pkg/lease.DecodeOption`/`FindAndDecode`) so there is a single place that knows how to locate and parse the option, whether it appears as a bare `ERFC3597` RR or nested inside an `OPT` record's options.

## Behavior Specification

This is the exact rule set the update handler implements — the numbered items below are cited
by number elsewhere in this codebase (e.g. a code comment reading "item 6" or "5.1.4" refers to
the corresponding entry here), so the numbering is kept stable.

### Behavior Specifications

1. Signature verification
   1. UPDATE requests must carry a valid SIG(0).
   2. An UPDATE request contains RRs to be updated. The name of those records determines the FQDN. The signer key must be at or above this FQDN. In the following we say that a key is "at-FQDN" when it is registered at or above that FQDN.
   3. The key can be present in the request as KEY RR, either in the Update section, or in the Additional section.
   4. If the key is not present in the request, lease-store key material is used as fallback.
   5. If lease-store does not contain the key, verification uses authoritative DNS as the last source for signer key resolution.
   6. If authoritative DNS is reachable but returns no matching signer KEY, the request fails.
      6.a. If the authoritative DNS cannot be reached for signer-key lookup, the request fails. This is because we are modifying records for a DNS that does not respond.
   7. According to RFC 2136, the Update Section contains RRs to be added to or deleted from the zone. Thus if a KEY RR is not been registered or refreshed, it should not be in the Authority/Update section of a signed lease-update request.
   8. Multiple KEY RRs can be present in a request in the Update section.
2. When a signed registration comes in, the proxy first needs to verify the signature. This can be done either because the signing RR KEY is in the message (either in the Update or Additional section), or because the KEY is online (its name is already present at the FQDN or above of the records contained in the lease update request), or because the KEY is in the LeaseStore. Any of this can be used to verify the signature.
3. You can sign a lease-update request with a key, but the request is to register or refresh a different RR KEY (which is not a signing KEY in this context). In this case only the latter is in the Update section.
4. If verification is passed, it means that we could find the signing key. We found it either:
   1. In-LeaseStore AND at-FQDN -> this is a key we are managing
   2. In-LeaseStore AND NOT at-FQDN -> we assume the key has been removed externally from our proxy, so we need to register it with the remaining lease time from the lease-store. This implies that we need to add this KEY RR to the RRs to be registered.
   3. NOT In-LeaseStore AND at-FQDN -> the key is already registered, but we assume this has happened outside the lease mechanism (permanent update) and not under our control
   4. NOT In-LeaseStore AND NOT at-FQDN -> the key must be in the request (either Update or Additional section), otherwise we would never get here since we would not have had any KEY to verify the signature.
5. From now on we look at the Update section and the RR records it contains. If the Update section contains a KEY RR, this does not need to be the key that signed the request. Looking at the request lease-times:
   1. KEY-LEASE != 0, LEASE != 0: This is a registration or a refresh of KEY and non-KEY RRs.
      1. The KEY RR and non-KEY RRs (at least one) must be present in the request, otherwise this is an error
      2. If the KEY RR is already present in the LeaseStore, this is a refresh of the KEY, otherwise a registration
      3. For any of the non-KEY RRs that is present in the LeaseStore, this is a refresh
      4. If a non-KEY RRs is not present in the LeaseStore, it needs to be recorded together with the key that registers it, because we need to remove it when that key expires. In this case, the key that registers it is the key that signed the request.
      5. This key must either be in the LeaseStore, or if not in the LeaseStore it must be in the Update section. It cannot be only in the Additional section, because the user intention must be to register a key, and not just use it to sign a request, so it must be part of the Update section.
      6. There might be more than one KEY RRs in the Update section, so it is important to determine which KEY RR is the signing key.
   2. KEY-LEASE == 0, LEASE != 0: this is a registration/refresh of non-KEY RRs
      1. non-KEY RRs (at least one) must be present in the request, otherwise this is an error
      2. For any of the non-KEY RRs that are not present in the LeaseStore, this is a registration, otherwise a refresh
      3. Signing KEY must already exist in the LeaseStore, and must not be present in the Update section (given KEY-LEASE == 0, this is not a registration of the key, the key must already be registered). If it is not already at the FQDN at the authoritative DNS, it needs to be registered again (see 4.2).
   3. KEY-LEASE == 0, LEASE == 0:
      1. If KEY RR present -> delete KEY
      2. If non-KEY RRs present -> delete non-KEY RRs
      3. Both present -> delete both
      4. Neither present -> error
      5. Authorization for delete is ownership, not just at-FQDN: a KEY or non-KEY RR may only be deleted by its immediate parent (the KEY that registered it), or, for a KEY RR, by itself, whether it registered itself or another KEY registered it; the delete takes along everything it registered. A signer that is at-FQDN but not the immediate parent cannot delete the record directly, even though it could sign the request; the record is treated the same as if it did not exist, and no error results.
   4. KEY-LEASE != 0, LEASE == 0:
      1. KEY RR must be present -> register or refresh KEY
      2. If non-KEY RRs present -> delete non-KEY RRs
6. If the proxy attemps to register a record that already exists at the DNS server, the request must fail also in the parts that would be successful if performed alone, because the consistency of the LeaseStore cannot be guaranteed, especially in case of already existing KEY RR.
   1. This implies that the proxy needs to verify whether in case of a registration, an identical record is already at the FQDN.
7. For all attempts of deleting records, if the record does not exist in the lease-store, we assume the record is either outside our control, or it has been removed after expiry. The request does not fail but the user needs to be informed about this. If the record exists in the lease-store but not at the DNS, do not fail the request but signal the situation. Missing local records do not force whole-request failure.
8. Every name in the Update section must be in the handler's zone, and not in a zone another handler of the same proxy serves below it: the deepest zone wins. Otherwise the request is refused. So must the SIG(0) signer's name.
9. With `fcfs_naming` on, a KEY holds its name: a KEY registered anew is refused if a different KEY is at its name or at a name above it, unless the key holding that name registers it. A KEY may register itself only one label below the zone; deeper names are registered by the key holding the name above.
10. The Zone Section must enclose every name in the Update section (RFC 2136 §3.4.1.3); otherwise the answer is `NOTZONE`. It may be the zone apex, the handler's zone, a name above the records, such as the signer's, or the root, and plays no other part.

### Storage Model

1. KEY lease storage
- KEY lease state is tracked per canonical key name in the lease manager.
- Given keys can be registered by other keys, a key can be linked to the key that registered it.

2. Non-KEY lease storage
- Non-KEY records are tracked individually and are linked to their key owner.
- This link is used to clear each records registered with a particular key when this key expires.
- Record identity is as defined in comparison rules in RFC 2136 Section 1.1 (NAME, CLASS, TYPE, RDLENGTH, RDATA equal; TTL excluded), with SOA and CNAME further narrowed to NAME+CLASS+TYPE per that same section, since only one such RR can exist at a name.
  - Exception: WKS records are compared on the full RDATA string, including the services bitmask, because the underlying DNS library has no WKS RDATA parser to split ADDRESS+PROTOCOL from the mask as the RFC specifies. This is a known, narrow deviation (see `RecordKey` in `pkg/lease/state.go` and `rrEqual` in `handlers/opcode5_update_helpers.go`), not a design choice -- WKS is effectively obsolete in current DNS use, so the practical impact is minimal.
- It is not possible for 2 different keys to register identical RRs.
- Records that differ in any field are treated as distinct records.

When a key expires, it can trigger a chain deletion, for example in the case key A registered key B that registered records C,D,E and key A expires. A,B,C,D and E are all deleted.

## Implementation Notes

The rules above are what the handler enforces; this section covers how, in terms of the actual
code — file/function references, config keys, and detail (storage backends, lease clamping, the
deferred-mutation write ordering) that goes beyond the rule statement itself.

### Signer Resolution (Three-Stage Fallback)

Before processing the case matrix, the proxy validates the SIG(0) signature on the UPDATE packet (`UpdateHandler.extractAndValidateSig0`). The signer's name must be one the handler serves (Behavior Specification item 8), and the signer key must be at or above the FQDN of every record in the Update section. Candidate signer key material is tried in order:

1. **Request-provided:** a KEY RR matching the SIG(0) signer identity (name, algorithm, key tag) present in the Update or Additional section.
2. **Lease store:** a KEY previously registered under that identity.
3. **Authoritative DNS:** a KEY RR published at the signer's name, queried live.

The first candidate that cryptographically verifies the signature is used. If verification succeeds via stage 3 only (not request-provided, not lease-managed), the signer is "online-only" — its material was neither proven fresh in this request nor already under lease management.

*(SRP does not use this three-stage resolution — it always verifies against the Host
Description KEY, always present in the request. See `docs/siglease_rfc9665.md` §5.)*

### Online-Only Signers and `allow_online_key_registration`

An online-only signer can always be used to authenticate a request — SIG(0) verification does not depend on the flag. What the signer is subsequently *allowed to do* does:

- **Deletes (Case C)** are ownership-based, independent of this flag (see Behavior Specification item 5.3.5 above). Such a signer can still remove the data, but only indirectly, by deleting the record's true parent, which cascades (see "Upstream Forwarding and Write Ordering" below).
- **Authoring new lease-store state** — a new KEY RR, or non-KEY RRs owned by the signer — requires the signer to be either already lease-managed, itself present in the Update section (a normal self-registration), or, if `allow_online_key_registration: true` is configured for the handler, an online-only signer. This is one policy (`UpdateHandler.signerAuthorizedForNewRegistration`) applied identically to KEY and non-KEY registration in Case A and Case D; it is not KEY-RR-specific. Default is `false` (fail closed).

When an online-only signer registers a *different* KEY RR than itself (e.g. delegating a new child key it will never itself be lease-managed under), any non-KEY RRs in the same request are still attached to the **signer's own node** per the rule below — including when that node has no backing KEY record (a signer that is deliberately never self-registered). The lease store permits this "phantom owner" for non-KEY records the same way it already permits a KEY RR's `ParentKeyName` to reference a node that has no record of its own.

### Non-KEY RR Ownership

Non-KEY RRs registered in Case A always belong to the signer of the request (Behavior Specification item 5.1.4) — never to some other KEY RR that happens to be registered in the same packet — regardless of whether the signer is itself present in the Update section. If the signer is present, this happens naturally as part of that KEY's own registration/refresh; if not (the signer is only authorizing a different KEY's registration), the data is attached to the signer's node in a separate step after the per-KEY loop.

Additional rules:

- The signer KEY used for SIG(0) verification and a KEY RR being registered/refreshed in the Update section can be different keys.
- Multiple KEY RRs can be present in the Update section; each is dispatched independently.
- A KEY used only for signing should be in the Additional section; a KEY in the Update section is interpreted as intended for lease register/refresh/delete.
- **Key lease ownership:** when a KEY RR is registered (Case A or D), its public key becomes the "owner" for the non-KEY RRs registered alongside it and for other KEY RRs registered under it. This is tracked via `ParentKeyName` in the lease tree.

### Zones Served: the Deepest Zone Wins

A proxy can run both handlers, each with its own zone (`upstream_zone`). The zones may nest: the live deployment has SRP's `srp.dev.zenr.io.` inside this handler's `dev.zenr.io.`. A name belongs to the handler whose zone is closest above it, as a delegated subzone does in DNS (Behavior Specification item 8). After setting the handlers up, `cmd/sig0lease` tells each one the zones the others serve below its own (`handlers.SeparateZones`), and refuses to start when two handlers serve the same zone.

Each handler refuses an UPDATE that names anything outside its zone, or inside a zone another handler serves, with `REFUSED` and Extended DNS Error 18 (`leaseHandler.refuseNamesNotServed`). This handler checks before the case dispatch and its node locks; SRP checks after its `default.service.arpa` rewrite has made the names final. Before this check only the authoritative server's update-policy kept the handlers apart. This handler could add a second KEY at a name SRP holds First-Come First-Served, or records SRP's lease store knows nothing about, whenever its signing key was allowed to write below its zone.

### The Zone Section

Both handlers read the Zone Section the same way (`handlers.refuseOutsideZoneSection`): it must enclose every name in the Update section, as RFC 2136 §3.4.1.3 requires, or the answer is `NOTZONE`; anything but one entry is `FORMERR`. Nothing else reads it. Which handler takes an UPDATE, and what it may change, go by the names: this handler's zone check (above), the signer's name and the SIG(0) checks; SRP takes an update by its host name (`docs/siglease_rfc9665.md` §3). The UPDATE sent upstream names the handler's own zone, and its lookups ask that zone's server.

A requester may therefore send the zone apex, as RFC 2136 asks and as `nsupdate` and other stock clients do, the handler's `upstream_zone` (`client/rfc9664`, `client/srp`), or any name above its records, such as its key's name (`sig0lease-client`'s default). Until 2026-10, this handler required the Zone Section at or below the signer's name, from the first design, in which each client had its own "downstream zone" named like its key; that refused the zone apex, and checked a field the requester chooses freely, so it constrained nothing the per-name checks did not.

### First-Come First-Served Naming (`fcfs_naming`)

Without this option, the handler follows RFC 9664 alone: a signer writes at and below its own name (Behavior Specification item 1.2), and a new key may register itself at any name, including at or below another key's name. That suits a zone whose names one operator hands out. A zone that unrelated requesters share, such as the live `dev.zenr.io.`, needs a name to stay with the key that took it first. With `fcfs_naming: true` (default `false`; on in this repo's `config.yaml`) the handler applies RFC 9665's First-Come First-Served Naming (§3.2.4.1) to KEYs (Behavior Specification item 9). The check runs on every KEY a request registers anew in Case A or D (`UpdateHandler.refuseNewKey`, `fcfsNewKey`):

- **One label below the zone.** A KEY may register itself only directly below the zone (`alice.dev.zenr.io.`), not at the apex, which is the zone operator's (the proxy's own KEY is there), nor deeper (`bob.alice.dev.zenr.io.`). Anything else is refused with `REFUSED` and Extended DNS Error 18, before any name is checked. A deeper name is registered by the key holding the name above it, so every held name has its holder above it, and goes with it: deleting or expiring a KEY takes along every KEY it registered. Without this rule, bob could register himself at `bob.alice.dev.zenr.io.` while `alice.dev.zenr.io.` is free. A newcomer could then take `alice.dev.zenr.io.` and, as a signer above bob's name, add records at bob's names (Behavior Specification item 1.2). Checking below the newcomer's name cannot stop that: no DNS query lists the names below a name, so only keys in this proxy's lease store would be found.
- **Names checked.** For a KEY registering itself: its own name. For a KEY its signer registers: the names from the KEY's name up to but not including the signer's name, which the signer holds. A holder may therefore register further KEYs at its own name and below it, which is how a second key gets a name another key holds. A KEY below a name a different key holds is refused, even when the signer is above that key: only the holder registers below its name.
- **Each name** is checked as SRP checks one (`srp.Evaluate`, with `refuse_on_foreign_data` off). The lease store comes first and is trusted when it has KEYs at the name; otherwise the handler queries the authoritative server for KEYs there. A name passes when every KEY at it is the new one. A name with any other KEY, alone or next to the new one, is held, as RFC 9665 §3.3.3 says ("If any existing KEY record ... does not match"). The request is then answered `YXDOMAIN` with Extended DNS Error 18 ("name held by a different key"), and nothing is sent upstream. A failed lookup is `SERVFAIL`, as in the other authoritative checks.
- **Atomic with the write.** Each free name adds an RFC 2136 "RRset does not exist" prerequisite for KEY at that name to the upstream UPDATE. If a KEY lands there between the check and the write, the authoritative server refuses the UPDATE (`YXRRSET`) and the handler answers `YXDOMAIN` with nothing changed. This covers two requests claiming one name at once, through this proxy or another: the node locks don't serialize them, because they lock different keys.
- **Not checked:** refreshes and records. A KEY already in the lease store keeps what it holds, and non-KEY records are written by a signer at and below its own name.
- **Keys from before.** The rules hold for what is registered while `fcfs_naming` is on. A KEY registered deeper before it was turned on, or written to the zone without this proxy, can still have a free name above it.

### Registration and Refresh Details

- **Refresh ownership check:** before treating a KEY RR as a refresh of an existing lease, `UpdateHandler.validateRefreshOwnership` compares the *actual* stored KEY RDATA (flags, protocol, algorithm, public key) against the one in the request. The lease store's node key is a composite of name + algorithm + key tag, which is not collision-free (the key tag is a 16-bit checksum); this check is what makes ownership verification exact rather than relying on the composite key alone.
- **Missing-at-FQDN recovery:** if a signer's managed KEY is found to be missing at the authoritative DNS (Cases A, B, D), the proxy re-registers it with whatever lease time remains in the local store, rather than granting a fresh full-duration lease or failing the request outright.
- **Duplicate registration rejection** (Behavior Specification item 6): applies uniformly to every case that can register something new — Cases A and D for KEY RRs, Cases A and B for non-KEY RRs. In Case A it applies to a refresh's non-KEY RRs too, since a refresh may add records new to its key (`filterDuplicateRegistrations`, run for every KEY in the request before the forward).
- **Delete semantics** (Behavior Specification items 5.3.5 and 7): a delete attempt deliberately doesn't distinguish "doesn't exist" from "exists but you don't own it," so it cannot be used to probe for the existence of records outside the signer's own subtree. Only records the signer is actually authorized to delete are included in the upstream delete request.

### Upstream Forwarding and Write Ordering

*(Shared mechanism: RFC 9665 SRP uses this same forward/re-sign/deferred-mutation path — see
`docs/siglease_rfc9665.md` §5 for what's different about how SRP gets there.)*

The proxy never mutates the local lease store before the corresponding upstream UPDATE has been confirmed successful:

1. All case-matrix outcomes are staged as deferred mutations.
2. The proxy signs and forwards the resulting change to the authoritative server (add-style for Cases A/B/D, a combined RFC 2136 delete for Case C).
3. Only if the upstream server returns `NOERROR` are the staged local mutations applied.
4. If the upstream server rejects the update (or is unreachable), the proxy returns an error to the client and the local lease store is left exactly as it was before the request — there is nothing to roll back, because nothing was written yet.
5. Once the upstream server has applied the update, a staged mutation must not fail. Every check that could refuse one — a record the store holds under another key (`filterDuplicateRegistrations`; SRP's FCFS), a node to renew that is not in the store — runs before the forward, while the request holds its node locks. A failure is therefore a bug, and both handlers panic, as a lease expiry does when its store write fails after its upstream delete: DNS has changed, so answering an error would leave published records that no lease ends, and answering success would hide the bug.

This means the local lease store's view of the world and the authoritative DNS server's view can never diverge as a direct result of a single request's outcome. Case C's delete additionally cascades: deleting a KEY takes its whole subtree along, as its expiry does (`subtreeLeases`, see "Storage Backends and Expiry"). The request's one UPDATE deletes the named records and, record by record, every KEY and record at and below each named KEY; nothing is forgotten locally before it is confirmed, and if it is not, the request fails with nothing changed. Every UPDATE either handler sends is built, signed and read the same way (`upstreamTarget.send`): a transport error, no answer, or any RCODE but NOERROR is a failure.

Two operations on the same lease-store nodes never interleave across that upstream round trip: see "Node Locks" below.

### Node Locks

*(Shared mechanism: the SRP handler uses the same lock table, locking names instead — see
`docs/siglease_rfc9665.md` §5.)*

Every operation that changes the lease store checks local and often remote state, sends one UPDATE upstream, and only then changes the store. The store's own mutex makes each single store call atomic, not that sequence, so without more two operations on the same nodes would interleave across the network round trips:

- two signers registering one RR would both pass the "already registered under another owner" check and both be accepted upstream; the loser would get `SERVFAIL` after its write landed, in Case A with its KEY left registered;
- a Case C delete would read a KEY's subtree before a registration under that KEY attached its record, and miss it: the record would stay published after the delete that should have taken it, under a KEY that no longer exists, until its own LEASE ran out;
- a lease expiry's upstream delete and a refresh's upstream add would race, with no way to know which one the authoritative server applied last.

So each handler has a lock table, `pkg/lease.NodeLocks` (`pkg/lease/nodelock.go`). An operation takes the locks of every node it may touch, all of them at once or none, holds them from its first check to its local apply, and releases them. Lock ids are the store's own keys: `NodeKey` for a KEY node, `RecordKey` for a non-KEY record.

| Operation | Locks |
|---|---|
| Case A, B, D (may register) | the signer's node, each named KEY, each named non-KEY record |
| Case C (delete) | each named KEY with its whole current subtree, each named non-KEY record |
| Expiry of a node | the node and its whole current subtree |

A refresh needs only the node it refreshes, a registration also the node it attaches to (its parent), and a delete the node with its subtree. Whether an RR in Cases A, B and D is a refresh or a registration is only learned from the checks the lock protects, so these cases always lock the registration-shaped set. Its parent is always the signer's node: a new KEY is registered under its signer (`registerKeyLease`), and non-KEY records always belong to the signer ("Non-KEY RR Ownership" above). Holding the signer's node is what keeps a delete or an expiry of the signer, which locks the signer's subtree, from running while something is being attached under it. Case C is known from `LEASE=0, KEY-LEASE=0` before any check, so its set is delete-shaped from the start (`UpdateHandler.requestLockSet`).

- **When a request locks.** In `Handle`, right after SIG(0) verification and before the case dispatch, so an unverified request never holds a lock; the locks are released on every return path, after the local apply. Signer resolution reads the store before that, and the checks that decide anything run under the locks.
- **One pass reads a whole subtree.** `Acquire` and `TryAcquire` take the lock set as a callback and call it with the table's mutex held, on every attempt; a delete-shaped set reads the subtree there (`ListSubtreeKeys`). Nothing can attach a node under a subtree member meanwhile, because attaching takes the parent's lock, which is either the subtree's root or a member just read, and no lock is taken or released while the table's mutex is held. So the subtree read is exact, with no repeated expansion. A waiting request calls the callback again after every release, so it takes the subtree as it is then, including children attached while it waited. Lock order is always the table's mutex, then the store's; the store never calls the table.
- **No deadlock.** A set is taken whole under one mutex, so nobody ever holds part of a set, and nobody waits while holding a node lock: a waiting request holds nothing, and expiries never wait. The upstream in-flight limit (`authoritative.max_inflight_updates`) is a wait inside `SendUpdate`, after the node locks: requests holding node locks may wait in it, but nothing holding one of its slots waits for a node lock, so the two cannot form a cycle.
- **Requests wait, up to their deadline.** A request whose locks are not all free waits, holding nothing, and tries again whenever a lock is released. It does not fail fast because of retransmissions: a client that times out resends its request with the same message ID and takes the first reply with that ID, so an immediate `SERVFAIL` to the resent request would beat the original's `NOERROR`, and the client would report a failure for a registration that happened. Waiting, the resent request runs after the original, as a refresh of what it just did. The wait is bounded by the request's deadline, which the router sets around the handlers: `server.request_timeout`, default 15s, must be positive (`Router.Route`). The deadline bounds the upstream exchanges too, so a request holds its locks at most that long, and a request waiting behind it does not give up before it has answered. 15s is above the worst case of one authoritative UPDATE, a UDP attempt and then TCP at the dns library's default timeouts (about 11s). A request still waiting at its deadline gets `SERVFAIL`, and the proxy logs the contended ids (`lease-store node lock contention on …`). Resent requests are not dropped as duplicates of one in flight: that is only possible over UDP (over TCP, the original's reply goes on a connection the resending client has abandoned), and waiting covers both transports.
- **Expiries back off instead.** A timer has nobody waiting on its answer. A lease event (`leaseExpirer.run`, the same in both handlers) takes its node and subtree with `TryAcquire`; if any is held, it does nothing and is retried exactly like a failed attempt (`expiryTimers.finish`, after 1s, doubling up to 16s). Each expiry attempt has its own deadline, `expiryTimeout` (10s).
- **The table.** A lock is an id in a set, not a mutex per id: nothing outlives its holder, so the table doesn't grow with every id ever seen (every A/AAAA address, including rotating IPv6 privacy addresses, and every TXT revision). Ids are deduplicated and sorted, so errors and `IDs()` are deterministic. Releasing a set twice panics: it would free ids another operation may have taken since.
- **One lease store per handler.** The RFC 9664 and SRP handlers each have their own store and lock table, and must never share a store. Each handler's `Start` and reconciliation pass arm expiry timers for nodes in its store, so with one store each would expire the other's nodes, by the wrong rules and with the wrong signing key; and SRP allows one KEY per name, while RFC 9664 allows several. `cmd/sig0lease` (`checkSeparateLeaseStores`) refuses to start, before any `Setup`, when the two handlers' `storage.path` name one file, also through a symlink, a hard link or a different letter case once the file exists. A Go program embedding the handlers and passing one `lease_manager` object to both is not checked.
- **Limits.** The table is in memory, so nothing here makes several proxy processes sharing state safe; the FCFS prerequisites, SRP's and this handler's with `fcfs_naming`, are the only protection across processes. The deadline can cut an upstream UPDATE short: if the authoritative server applied it but its reply did not arrive in time, the request answers `SERVFAIL` and applies nothing locally, as for any upstream timeout.
- **Tests.** `pkg/lease/nodelock_test.go` covers the table: mutual exclusion, all or none, waiting and the deadline, re-reading a subtree that grew while waiting, releasing twice. `handlers/node_locks_test.go` holds one operation inside its upstream send while a second runs against the same nodes: two signers registering one TXT get one `NOERROR` and one duplicate `REFUSED`, with one UPDATE sent; a Case C delete during a registration under its KEY cascades into the new record; an expiry while a request holds its node sends nothing and re-arms its timer. Each fails with the locks disabled.

### Lease Clamping, TTLs and Response Echo

Before forwarding, the proxy clamps LEASE and KEY-LEASE to `LeasePolicy` bounds (`min_key_lease_sec`/`max_key_lease_sec`/`min_rr_lease_sec`/`max_rr_lease_sec`): a duration below its minimum is raised to it and one above its maximum cut to it, and 0, a delete, is left alone. Both handlers parse and clamp with the same code (`handlers/lease_policy.go`), so neither refuses a request for its duration; the proxy refuses to start with a policy whose non-KEY bounds are looser than its KEY bounds (`min_rr_lease_sec` above `min_key_lease_sec`, or `max_rr_lease_sec` unset or above a set `max_key_lease_sec`): clamping the two values separately would then grant a LEASE longer than the KEY-LEASE. The *actual* durations used after clamping — not the client's originally-requested values — are echoed back to the client in the response's UPDATE-LEASE option, so the client can detect when the proxy granted less than what was requested. Both handlers build that response with `handlers.leaseResponse`: it copies none of the request's sections (RFC 2136 §3.8) and carries exactly one OPT RR (RFC 6891 §6.1.1). Copying the request's header used to add a second OPT RR beside the one holding the lease, which strict parsers such as mDNSResponder's `srp-client` reject. `client.EffectiveLeaseDuration(resp, requestedLease, requestedKeyLease)` returns both the effective LEASE and KEY-LEASE from a response.

This handler's status notes (for example `record not found for delete: ...`) travel in that same OPT RR, one Extended DNS Error option (RFC 8914, INFO-CODE 0 "Other") per note, with the note as EXTRA-TEXT; `dnsmsg.EDEs(resp)` returns them and `sig0lease-client` prints them under "Extended DNS Errors", as it does an error reply's (see "Error Replies" below). They used to be TXT records in the answer slot, next to an echo of the KEY RRs processed, but in an UPDATE reply that slot is the Prerequisite section, which a reply may only copy from the request. The KEY echo is gone; to see a registered KEY, query it (`sig0lease-client verify`) or `dig` it at the authoritative server.

TTLs are not leases, and the proxy does not forward the requester's. A requester may send its
lease as the TTL, which would let resolvers cache a record for as long as its lease.
(`sig0lease-client` does not: the KEY RRs it builds from the signing key carry `-ttl`, default
300, and rr-spec records carry the TTL written in them.) Once
SIG(0) verification passes, both handlers set every record they write upstream to
`record_ttl_sec` (default 300, `handlers/record_ttl.go`), cut to the granted KEY-LEASE on KEYs
and to the granted LEASE on everything else. The records are changed in place, so the lease
store keeps the TTLs the zone gets, and every RRset in a request leaves with one TTL (RFC 2181
§5.2) whatever the requester sent. A KEY re-registered from the lease store in Case B, where the
request carries no KEY-LEASE, is cut to the remaining lease it is re-registered with. RFC 9664
says nothing about TTLs; the rule follows RFC 9665 §4 and §5.1, where the SRP handler applies
the same setting (see `docs/siglease_rfc9665.md` §6).

### Error Replies

Every error reply either handler sends, like a success reply, copies none of the request's sections, and carries one Extended DNS Error (RFC 8914) in its OPT RR when the request had one: an INFO-CODE for the kind of refusal, and the reason as EXTRA-TEXT (`handlers.makeErrorResponse`, `dnsmsg.AddEDE`). The codes follow RFC 8914's definitions, one per kind of refusal whatever the RCODE:

| INFO-CODE | Refusals |
|---|---|
| 18 Prohibited | an unauthorized or unproven signer, records outside its subtree, a record held by another key (`REFUSED`), a name held by another key (`YXDOMAIN`: SRP's FCFS, this handler's `fcfs_naming`), a name outside the handler's zone or in another handler's (`REFUSED`), a KEY registering itself other than one label below the zone with `fcfs_naming` (`REFUSED`), a blacklisted type, foreign data at an SRP name |
| 21 Not Supported | a "." in a label, the 4-byte variant while `prefer_4byte_variant` is off, UDP while SRP's `allow_udp` is off |
| 22 No Reachable Authority | the authoritative server could not be queried or did not accept the UPDATE (`SERVFAIL`); also a query the proxy could not forward |
| 0 Other | anything else: a malformed request, a busy lease store, an internal error |

The reason text can tell a requester about the proxy's state, such as whether a key is in its lease store, so it stays only with `server.diagnostics: true`; otherwise the router removes it and keeps the code (`Router.ownErrorReply`), which RFC 8914 §3 requires every client to accept. `sig0lease-client` and `sig0lease-srp-client` print each Extended DNS Error after the status, and the test suites check refusals by them, with diagnostics on.

The RCODE tells the requester whether to retry: `FORMERR` for a request that is not a valid lease request -- a bad option, or records that don't fit the lease case it asks for, in every case alike; `REFUSED` for a valid one this proxy won't do; `SERVFAIL` when it could not finish, including a failed authoritative lookup inside a check that would otherwise refuse (the signer's KEY, a duplicate check: `authoritativeLookupError`), since the request itself may be fine. The SRP handler answers only the RCODEs RFC 9665 §3.3.5 allows, so a malformed SRP update is `REFUSED`.

### Blacklisted RR Types

The proxy maintains a configurable list of blacklisted RR types (`handlers.update.blacklisted_types` in `config.yaml`). Any UPDATE packet attempting to register one of these RR types is refused: `REFUSED` (RFC 2136 §2.2, "for policy or security reasons") with Extended DNS Error 18 (Prohibited). The request is well-formed, so not `FORMERR`.

### Storage Backends and Expiry

Building on the "Storage Model" rules above: the lease store is a tree rooted at each configured zone. Children of a root must be KEY nodes; a KEY node can itself be the parent of other KEY nodes (registered by it) or non-KEY nodes (data it owns). Expiry of a KEY node cascades to its entire subtree.

- `BaseRecord` fields (type, expiry, lease duration, registration time, parent) are shared by KEY (`Record`) and non-KEY (`NonKEYRecord`) nodes.
- **Deletion is always physical, never a soft flag.** A record is either present in the store (active) or absent (gone) — there is no intermediate "marked deleted" state to track or eventually reap.
- **Expiry is handler-driven, not store-driven.** A lease event (`leaseExpirer`, shared by both handlers), triggered by a per-node `time.AfterFunc` timer (`scheduleLeaseExpiry`, re-armed after every mutation and after every expiry event), is the only code path that removes an expired KEY or non-KEY record, and it always sends the corresponding upstream delete first. The store itself never deletes anything on its own initiative, because it has no way to also notify the authoritative server.
- **Each node's timer fires at its next lease event**, the earliest of its non-KEY records' LEASE and its own KEY-LEASE (`nextLeaseEvent`). One lease event is one UPDATE that deletes, record by record (`Delete An RR From An RRset`), everything the event ends. If only records' LEASE has run out, those records go, while the KEY and anything else not yet due stay. When the KEY expires, it takes its whole subtree along: every KEY and record at and below it, whatever their own leases. Nothing is forgotten locally before that UPDATE is confirmed. If it is rejected or fails to send, nothing is forgotten and the whole event is retried after a backoff of 1s, doubling up to 16s (`expiryRetryDelay`); success returns the node to its normal lease-event schedule. The proxy has no function without an upstream it can sign for, so a handler missing its upstream coordinator or signing key (a state `Setup()` refuses to produce, and `cmd/sig0lease` exits when `Setup()` fails) panics rather than expiring, retrying, or forgetting anything (`requireUpstream`). The engine, the timer table (`expiryTimers`) and `nextLeaseEvent` are shared with the RFC 9665 `SRPHandler`, so both handlers age the lease store the same way (see `docs/siglease_rfc9665.md`, "How expiry runs").
- **Start and the reconciliation backstop:** `Setup` loads the store and arms nothing, so `--dump`, which runs `Setup` alone, never expires anything. When the proxy starts serving, each handler's `Start` arms a timer for every lease owner in the store and starts the reconciliation pass. An owner is each KEY node, and each owner of non-KEY records, also one with no KEY record of its own, such as a signer that registered data without being lease-managed itself (`LeaseStorage.ListOwners`). Every 30 seconds the pass (`rearmMissingTimers`) looks for an owner that has no timer (a node waiting on a retry already has one). Every path that writes a lease arms its node's timer before releasing the node's locks, so an owner whose locks are held is skipped until the next pass, and an owner with no timer whose locks are free lost its timer to a bug: the pass logs it as an error and arms the timer. For an already-expired node it routes it through the same lease event (`leaseExpirer`) almost immediately — there is exactly one deletion implementation, not a second one that might skip the upstream call. The dumps list owners the same way, an owner without a KEY record as `KEY=absent`.

**Storage backend abstraction.** All of the above is defined against a single interface, `lease.LeaseStorage` (`pkg/lease/state.go`) — KEY lifecycle, tree/hierarchy, non-KEY record sets, and snapshot import/export/persistence all live on this one interface, and every backend must implement all of it. There is no narrower interface for a partial implementation to fall back to, and the handler never type-asserts down to a subset: a backend either supports the full feature set or `Setup()` fails to configure it at all. *(This same interface, and both backends below, are reused as-is by the RFC 9665 SRP handler, confirmed generic across both handlers' differently-shaped KEY trees with zero production-code changes needed.)*

Two backends are selectable via `handlers.update.storage` in `config.yaml` (see the Configuration section below):

- **`type: memory`** (default) — `InMemoryLeaseStore`. Zero persistence: a process restart drops all lease state, and clients simply re-register (the "Signer Resolution" three-stage fallback above still lets an unrelated signer authenticate against live authoritative DNS even with an empty store; only lease bookkeeping, not authentication, is lost).
- **`type: file`** — `FileLeaseStore` (`pkg/lease/file_store.go`), which wraps an `InMemoryLeaseStore` and adds human-readable JSON persistence via the existing `ExportSnapshot`/`ImportSnapshot`/`SaveSnapshot`/`LoadSnapshot` mechanism: loaded once at `Setup()` (a corrupt existing file is a hard `Setup()` error, never a silent "start empty"), saved periodically on `save_interval`, and flushed once more on `Shutdown()`. Both handlers' `Shutdown()` is the same code (`leaseRuntime`). Once it begins, no lease event or reconciliation pass starts. A lease event runs within 10s (`expiryTimeout`) and a pass within 10s (`reconcilePassTimeout`), each under a context `Shutdown` cancels, so it does not wait those out: it cancels the work still running and waits for it to return, which takes at most about one DNS exchange, since the DNS library does not interrupt a read already waiting for a reply (2s). Then it stops every expiry timer, including the retry a cancelled lease event armed, and only then stops the store, so nothing changes the store after that last save. A cancelled lease event forgets nothing: the store changes only once the upstream delete is confirmed, so its leases are in that save and expire after a restart. The file is readable but not hand-editable: it stores every record in wire format (`rr_wire`, shown as text in `rr_display`) next to the SHA-256 of the snapshot, and `LoadSnapshot` refuses any file that isn't byte-for-byte what the proxy wrote, so an edited file is also a hard `Setup()` error. Each save writes a new temporary file in the same directory, syncs it and renames it over the snapshot, so a crash mid-save leaves the previous snapshot intact rather than a torn file that would fail that check.

### Reference to Source Files

- `handlers/opcode5_handle.go` — `Handle()`, the full case dispatch, `buildSuccessResponse`.
- `handlers/lease_handler.go` — `leaseHandler`, the part both handlers are made of alike: the handler basics, the `leaseRuntime`, the configuration both read the same way (`setup`: upstream zone, keystore and signing key, coordinator, lease policy, record TTL, lease store), `Start`, which arms the timers of the leases `setup` loaded and starts the reconciliation pass, `upstream`, where both send their UPDATEs, `SeparateZones` and `refuseNamesNotServed` ("Zones Served"), and `fcfsConflictResult`, the `YXDOMAIN` reply both handlers' FCFS checks send. Each handler's `Setup` reads only its own options and then calls `setup`.
- `handlers/lease_runtime.go` — `leaseRuntime`, which `leaseHandler` embeds: the lease store, expiry timers and node locks, `scheduleLeaseExpiry`, the timer callback, the 30-second reconciliation pass, and `Shutdown`. Each handler supplies only how its lease event runs and what its pass adds (SRP's service enumeration).
- `handlers/opcode5_lease.go` — lease-store read/write helpers, `authorizeKeyRefresh`, and the expiry machinery shared with `SRPHandler`: `leaseExpirer`, `subtreeLeases`, `expiryTimers`, `expiryRetryDelay`, `nextLeaseEvent`.
- `handlers/handlers.go` — `upstreamTarget.send`, through which both handlers send every UPDATE; `LeaseStoreFromConfig`.
- `handlers/opcode5_update_helpers.go` — SIG(0) resolution (`extractAndValidateSig0`), upstream message construction, duplicate-registration checks, `fcfs_naming` (`refuseNewKey`, `fcfsNewKey`).
- `handlers/opcode5_lease_option.go` — UPDATE-LEASE option parsing and request-side policy validation.
- `handlers/opcode5_setup.go` — `Setup()`: this handler's own options (`prefer_4byte_variant`, `allow_online_key_registration`, `fcfs_naming`, `blacklisted_types`), then `leaseHandler.setup`. The storage-backend selection that `setup` shares with `cmd/sig0lease` is `LeaseStoreFromConfig` in `handlers/handlers.go`.
- `pkg/lease/state.go` — the unified `LeaseStorage` interface and `InMemoryLeaseStore`, the tree-structured in-memory implementation.
- `pkg/lease/file_store.go` — `FileLeaseStore`, the periodic/shutdown-flush JSON-snapshot-backed implementation.
- `pkg/lease/nodelock.go` — `NodeLocks`, the lock table both handlers use so that operations on the same lease-store nodes never interleave ("Node Locks").
- `pkg/lease/lease.go` — `LeaseOption` encode/decode and the shared `FindOption`/`DecodeOption`/`FindAndDecode` helpers.
- `client/lease_response.go` — client-side decoding of the server's granted LEASE/KEY-LEASE.
- `client/rfc9664/client.go` — the library requester: `Register` (Case A), `Withdraw` (Case D with the records listed), `Deregister` (Case D keeping the name, Case C freeing it) and `Run`, which keeps the name registered on the lease clock (`client/lifecycle.go`). A `YXDOMAIN` (`fcfs_naming`: another key holds the name) is an error `Run` tries again with backoff; it never renames.
- `client/rfc9664/name.go` — `Name`, one name kept registered as its records change, on `client.Keeper` (`client/keeper.go`, which `client/srp`'s `Host` uses too): it withdraws the records it no longer has, those an earlier run's `NameStore` kept included, before registering the rest. `Release` frees a name that is not running. `sig0lease-agent` registers its `names:` with it (`docs/sig0lease-agent.md`).

## Configuration

`config.yaml` controls:

- listening address and enabled transport networks;
- `server.request_timeout` (default 15s, must be positive): how long the handlers may work on one request, including waiting for a lease-store node another request is using (see "Node Locks");
- `server.diagnostics` (default `false`; keep it off in production): with it on, error replies carry the reason as their Extended DNS Error's text (see "Error Replies"), and the proxy answers the lease-store dump query, `__dump.sig0lease.internal.` TXT for a summary or `__dump.sig0lease.internal.debug.` TXT for every record (`dig @<proxy> -p <port> __dump.sig0lease.internal. TXT`). With it off, error replies carry only the code, and the dump query is answered `REFUSED` with Extended DNS Error 18 (Prohibited). The test suites turn it on in the configs they write;
- default upstream resolvers;
- handler-specific settings such as the upstream zone, an optional static `upstream` server for it, keystore directory, lease policy bounds, blacklisted RR types, `allow_online_key_registration`, `fcfs_naming` (see "First-Come First-Served Naming"), and the lease storage backend (`storage.type: memory|file`, see "Storage Backends and Expiry" above) for the update handler;
- opcode-to-module routing (an ordered list per opcode — see `docs/siglease_rfc9665.md` §3 for
  how SRP's handler fits into the same list). Each handler serves its own zone, and the deepest
  zone wins where they nest; two handlers on one zone stop the proxy at startup (see "Zones
  Served");
- `authoritative.max_inflight_updates` (default 1, `0` for no limit): how many UPDATEs the proxy
  has in flight to one authoritative server at a time, across all handlers. Every forwarded
  UPDATE is SIG(0)-signed, and BIND 9.20 refuses SIG(0) requests beyond its `sig0checks-quota`
  (default 1) instead of queueing them, so set this to the upstream server's quota — see
  `docs/siglease_rfc9665.md` §6, "Concurrent UPDATEs".

The update handler uses the configured zone to discover the authoritative server for the effective zone, then sends the rewritten UPDATE there. A static `upstream: "host:port"` replaces that discovery for the configured zone and every name below it, including the zones the requests name (`make test-update-local` uses it to point the handler at a local BIND 9).

## DNS-over-TLS

The server can offer DNS-over-TLS ([RFC 7858](https://datatracker.ietf.org/doc/rfc7858/)) as a
third listener alongside plain UDP/TCP — transport-level, so it benefits every handler
(RFC 9664, RFC 9665 SRP, and plain forwarding alike), not something protocol-specific.
Opportunistic only: no client-certificate authentication.

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

The proxy uses this one certificate for as long as it runs; nothing generates one for it. A
self-signed certificate is enough, since no client checks it (see below). Create it once and
keep it, for example:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/CN=proxy.example"
```

Generating a new certificate at every start would work for today's clients, but a long-lived
one keeps the option of key pinning (RFC 7858 §4.2), where a client is configured with the
proxy's key in advance, and pinning needs a key that does not change. RFC 9665 §6.5 mentions
pinning for SRP registrars and leaves it out of scope; it is not implemented here.

Both clients can send over DoT, with `-transport tls`: `sig0lease-client` to the `-server` DoT
address, `sig0lease-srp-client` too (with `-server`, give the DoT address; without it, discovery uses the
`_dnssd-srp-tls._tcp` record, see `docs/siglease_rfc9665.md`). Both use RFC 7858 §4.1's
Opportunistic Privacy profile, the only one RFC 9665 §7 uses for SRP: the client encrypts but
does not check the server's certificate, so it is protected against passive eavesdroppers but
not against an active attacker in the path. Neither client falls back to plain TCP or UDP when
TLS fails.

The transport is tested at three levels. `server/transport_tls_test.go` sends a query from
`client.New(..., "tls", ...)` to the real DoT listener. `PROXY_PROTOCOL=tls` runs the whole
`tests/test_update.sh` suite over DoT, against a listener the script turns on in its scratch
config with a throwaway certificate. `tests/test_srp.sh`'s TEST 9 discovers the registrar
through `_dnssd-srp-tls._tcp` and registers over DoT.

## Project Layout

- `cmd/sig0lease/` - proxy entrypoint
- `cmd/sig0lease-client/` - client entrypoint (RFC 9664: raw updates for the tests, and `name`
  over `client/rfc9664`)
- `cmd/internal/cli/` - the flags, key lookup and reply printing both client commands share
- `client/` - what the RFC 9664 and SRP requesters share (granted leases, transports, refresh
  clock, `Keeper`); `client/rfc9664` is the RFC 9664 library requester, `client/srp` the SRP
  one, `client/agent` the template agent on both
- `config/` - YAML config loading and validation
- `forward/` - upstream forwarding logic
- `handlers/` - opcode handlers and result types, including `srp_handler.go` (the RFC 9665
  SRP registrar path, a sibling to the RFC 9664 update handler, never a mode on it — see
  `docs/siglease_rfc9665.md`)
- `pkg/keyrec/` - keystore loading helpers (`LoadedKey`, `LoadKeyFromFile`, `FindKeysByZone`,
  `GenerateKey`)
- `pkg/lease/` - lease store, tree model, and UPDATE-LEASE option encoding/decoding (shared
  by both the RFC 9664 and RFC 9665 paths)
- `pkg/sig0/` - SIG(0) signing and verification helpers (shared by both paths)
- `pkg/updatecore/` - upstream forward/re-sign plumbing shared by both the RFC 9664 and
  RFC 9665 (SRP) handlers (SOA-based discovery, static `upstream` override, TTL
  consistency checks)
- `server/` - UDP/TCP/TLS (DNS-over-TLS, RFC 7858) listener and request dispatch

See `docs/siglease_rfc9665.md` for the full RFC 9665 SRP design (package layout, client
library/CLI, config, and known limitations) — it's the source of truth for anything SRP that
isn't covered above.

## Validation
(requires client key, see this [README](../keystore/README.md))
```bash
CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-unit
CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-update   # RFC 9664 lease flow, live against a real BIND 9
make test-update-local                                         # same RFC 9664 suite against a disposable local BIND 9
make test-srp                                                  # RFC 9665 SRP flow, see docs/siglease_rfc9665.md
make test-agent                                                # sig0lease-agent, see docs/sig0lease-agent.md
make test-mdnsresponder-interop                                 # RFC 9665 SRP interop, see docs/siglease_rfc9665.md
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

sig0lease adds a compatibility package at [pkg/dnscompat/updatelease.go](../pkg/dnscompat/updatelease.go) that registers EDNS code `2` with an `ERFC3597` constructor at process startup. This allows strict unpacking to succeed without adding parser fallback logic.

### UPDATE-LEASE unpacked form is not an OPT wrapper

After unpack, the library represents code `2` as a direct `*dns.ERFC3597` RR in the `Pseudo` section rather than as an `OPT` containing nested options in the shape the project initially expected.

### Applied patch

The update handler now checks both `Pseudo` and `Extra`, and it accepts either:

- direct `*dns.ERFC3597` records with EDNS code `2`, or
- `*dns.OPT` records containing an `ERFC3597` option.

### Multi-question messages don't round-trip through Pack/Unpack

`Msg.Question` is typed `[]RR`, but its doc comment says it "holds a single 'RR'" -- and in v0.6.82 that's enforced by a bug rather than by the type system. Setting `len(m.Question) > 1` and calling `Pack()` writes `QDCOUNT` from `len(m.Question)`, but the packing loop only serializes the first Question RR's bytes onto the wire. The result is an internally inconsistent message: the header claims N questions, the body contains one. Unpacking that message anywhere (including round-tripping it back through the same library) fails with:

`dns unpack: overflow name`

This is a library packing bug, not a sig0lease protocol issue -- real DNS traffic essentially never sets QDCOUNT > 1 anyway, and this project's own `acceptMsg` (see [server/server.go](../server/server.go)) rejects any message where `len(m.Question) != 1` with FORMERR, matching the library's own `DefaultMsgAcceptFunc`. No compatibility patch was written for it. It surfaced while writing [server/transport_equivalence_test.go](../server/transport_equivalence_test.go), which needed a genuine two-question wire message to test that FORMERR-rejection branch; that specific case had to be dropped since the library can't produce valid bytes for it, and the message-with-zero-questions case was kept in its place to cover the same `acceptMsg` branch.

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

### A label containing a dot doesn't survive Unpack/Pack

A DNS label may hold any octet, a dot included (RFC 2181 S11), and RFC 6763 S4.1.1 allows one in a DNS-SD instance name such as `Printer v2.1`. The library can't carry such a label in a name string. `Unpack` copies the label's octets into the string as they are, so the wire label `Printer v2.1` comes out as `Printer v2.1._ipp._tcp.example.`, which reads as the labels `Printer v2` and `1`. `Pack` splits at every dot, even one after a backslash, so it sends that string back out as those two labels: `\.` is not an escape either. The library escapes dots only in mailbox fields (SOA RNAME, RP, MINFO, MB, MG, MR). This is still the case in v0.6.117. `github.com/miekg/dns` v1 handled it with the RFC 1035 S5.1 escapes: its `UnpackDomainName` writes `\.` and its `PackDomainName` reads it.

For the proxy this meant that an update carrying such a label, validly signed, was accepted and forwarded upstream under a different name than the one the client asked for.

### Applied handling

- Both handlers call `refuseDottedLabels` ([handlers/handlers.go](../handlers/handlers.go)) as soon as they take a request. It scans the request's wire bytes with `dnsname.DottedWireLabel` ([pkg/dnsname/wire.go](../pkg/dnsname/wire.go)) and answers REFUSED, naming the label. Plain forwarding sends the original bytes unchanged, so it needs no check.
- `client/srp.NewClient` refuses a host, instance or subtype label that contains a dot (`dnsname.CheckLabel`). That is the only way this library lets it keep the label boundary, which RFC 6763 S4.3 requires.
- `TestLibraryReadsEveryDotAsLabelBoundary` ([pkg/dnsname/labels_test.go](../pkg/dnsname/labels_test.go)) pins the library behavior, so an upgrade that changes it is noticed. See the next section.
- [miekg-dns-escaped-names.patch](miekg-dns-escaped-names.patch) is a proposed upstream fix, against v0.6.117. It is not applied here. It makes `Unpack` escape `.` and `\` inside a label and `Pack` honor `\X` and `\DDD`, and its notes point to the v1 functions that already did this.

### When the library starts escaping dots

`TestLibraryReadsEveryDotAsLabelBoundary` fails the first time `go test ./...` runs against a library version that escapes dots inside labels, whether through the patch above or some other change, and its failure message points here. It is the only test that fails: that was checked by porting the patch onto v0.6.82 and running the whole suite against it. Everything else keeps passing because the refusal above still catches every dotted label, so a green run apart from this test does not mean nothing else needs changing.

A release carrying the change will be newer than v0.6.117, which already removed `OPT.SetUDPSize` (used in [pkg/updatecore/forward.go](../pkg/updatecore/forward.go), [pkg/dnsmsg/update.go](../pkg/dnsmsg/update.go) and others). Expect it to come as part of a larger upgrade; see [upgrade-miekg-dns.md](upgrade-miekg-dns.md).

Then work through these steps in order. **Do steps 1 and 2 before step 5**: both compare names as plain strings, and today the refusal is what keeps escaped names away from them.

1. **`isNameAtOrAbove`** ([handlers/opcode5_update_helpers.go](../handlers/opcode5_update_helpers.go)) is the signer-hierarchy check: a SIG(0) signer may only update names at or below its own. It tests `strings.HasSuffix(base, "."+c)`. With escapes, the owner `x\.victim.example.`, which is the single label `x.victim` under `example.`, passes that test for the signer `victim.example.`, and that signer could then write outside its own subtree. Compare label by label instead.
2. **`rewriteZoneSuffix`** ([handlers/srp_handler.go](../handlers/srp_handler.go)) treats the byte before `default.service.arpa.` as a label boundary if it is a dot. An escaped dot passes, so `x\.default.service.arpa.`, which is the label `x.default` under `service.arpa.`, would be rewritten into the upstream zone. Also require that the dot is not escaped.
3. **[pkg/dnsname/labels.go](../pkg/dnsname/labels.go)**: make `Labels` and `CutFirstLabel` split only at unescaped dots, skipping `\X` and `\DDD`. Replace `CheckLabel`'s refusal of a dot with a function that escapes `.` and `\` (RFC 6763 S4.3); the 63-octet limit then counts unescaped octets. Rewrite the file's opening comment, which describes today's library.
4. **[client/srp/client.go](../client/srp/client.go)**: escape host, instance and subtype labels with that function when joining them into names, instead of refusing a dotted one. Escape backslashes too: today they work as plain characters, but the library would then read them as escapes.
5. **Remove the refusal**: `refuseDottedLabels` in [handlers/handlers.go](../handlers/handlers.go), its calls in [handlers/opcode5_handle.go](../handlers/opcode5_handle.go) and [handlers/srp_handler.go](../handlers/srp_handler.go), and [pkg/dnsname/wire.go](../pkg/dnsname/wire.go) with its tests.
6. **Tests**:
   - Make `TestLibraryReadsEveryDotAsLabelBoundary` pin the new behavior: a dotted label unpacks escaped and packs back as one label.
   - Turn the refusal tests into tests that the name is registered, and forwarded upstream, as the single label it is: `TestHandle_DottedLabel_Refused`, `TestSRPHandle_DottedInstanceLabel_Refused`, `TestNewClient_RejectsLabelThatIsNotOneDNSLabel`, and the "instance label containing a dot rejected" case of `TestValidate_ServiceNames` in [pkg/srp/srp_test.go](../pkg/srp/srp_test.go).
   - Update the cases that spell a dotted label the way today's library presents it, unescaped: `TestCheckLabel` in [pkg/dnsname/labels_test.go](../pkg/dnsname/labels_test.go), and the "dot in the instance label" case of `TestServiceTypeFromInstanceName` in [pkg/dnssd/enumeration_test.go](../pkg/dnssd/enumeration_test.go).
   - Add tests for steps 1 and 2 with an escaped dot.
7. **Docs**: rewrite this section and the one above, drop item 7 from "Applied Compatibility Patches" below, and delete [miekg-dns-escaped-names.patch](miekg-dns-escaped-names.patch).

### The library does not build for WebAssembly

`server.go` calls `srv.listenUDP`, which only `server_recvmmsg.go` (build tag `unix`) and `server_no_recvmmsg.go` (`windows`) define. On any other platform the package does not compile, `GOOS=js GOARCH=wasm` (a browser) and `GOOS=wasip1 GOARCH=wasm` included:

`./server.go:180:7: srv.listenUDP undefined (type *Server has no field or method listenUDP)`

Every package of ours imports the library, so none of them builds for WebAssembly either, although a client never starts a server. This is still the case in v0.6.117.

### Proposed handling

- [miekg-dns-wasm-build.patch](miekg-dns-wasm-build.patch) is a proposed upstream fix, against v0.6.117; it also applies to v0.6.82. It is not applied here. It changes the build tag of `server_no_recvmmsg.go` from `windows` to `!unix`: that file reads one message at a time through `net.PacketConn` and needs nothing from Windows. Builds for unix do not change.
- With it, `pkg/...`, `client` and `client/srp` build for `js/wasm` and `wasip1/wasm`. A small program that registers through `client/srp` is 10.5 MB, 2.6 MB gzipped.
- Until a release carries it, build for WebAssembly against a patched copy of the library. From `main/`, leaving `go.mod` and `go.sum` as they are:

```sh
V=$(go list -m -f '{{.Version}}' codeberg.org/miekg/dns)
W=$(mktemp -d)
cp -r "$(go env GOMODCACHE)/codeberg.org/miekg/dns@$V" "$W/dns" && chmod -R u+w "$W/dns"
git -C "$W/dns" apply "$PWD/docs/miekg-dns-wasm-build.patch"
cp go.mod go.sum "$W/"
go mod edit -modfile="$W/go.mod" -replace codeberg.org/miekg/dns="$W/dns"
GOOS=js GOARCH=wasm go build -modfile="$W/go.mod" ./client/srp ./client ./pkg/...
```

- Once `go.mod` requires a release with the change, delete this section and the patch.

## Applied Compatibility Patches

The following project-side patches are currently in place:

1. `pkg/dnscompat` imports `codeberg.org/miekg/dns` and registers code `2` as `ERFC3597` on startup.
2. `cmd/sig0lease/main.go` imports the compatibility package so the proxy process gets the patch before reading packets.
3. `cmd/sig0lease-client/main.go` imports the same compatibility package so client-side pack/unpack behavior stays consistent.
4. `pkg/lease.FindOption` recognizes UPDATE-LEASE whether it arrives as a direct `ERFC3597` record or under an `OPT` wrapper, for both request and response parsing.
5. `server/server.go` wraps the handler chain in `fullUnpackHandler`, which calls `r.Unpack()` before dispatch so every request (UDP and TCP) reaches the router fully decoded, per the `dns.Handler` contract (see above).
6. `pkg/sig0/signer.go` replaces `dns.CryptoSIG0.Sign`/`Verify` for ED25519, ECDSAP256SHA256, and ECDSAP384SHA384 with an RFC-2931-correct, RDATA-only hash-input implementation (`rdataOnlyPrefix`), fixing a library bug that hashes the full SIG RR wire encoding instead.
7. `handlers.refuseDottedLabels` answers REFUSED to an update carrying a label with a dot in it, which the library would forward as several labels; `client/srp.NewClient` refuses such a label (see above).

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
