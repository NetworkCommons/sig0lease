# sig0lease Implementation Status

## Current State

sig0lease is operational for the SIG(0)-authenticated UPDATE-LEASE registration path:

- the client can build and send a signed DNS UPDATE carrying the lease option;
- the proxy can unpack and route the packet;
- the update handler validates the downstream SIG(0) signature;
- the proxy re-signs the upstream UPDATE with its configured zone key;
- the authoritative server for the target zone accepts the forwarded UPDATE;
- tampered packets are rejected.

The current focus is correctness and compatibility, not feature breadth.

## Design Decisions

### 1. Opcode-based routing

The proxy dispatches on DNS opcode and lets handlers decide whether a packet is relevant. The codebase previously included a diagnostic STATUS handler for opcode 2, but that surface has been removed so the proxy stays focused on UPDATE-LEASE registration and upstream forwarding.

### 2. Strict signature handling

SIG(0) verification is strict. The proxy does not accept unsigned or unverified UPDATE packets for the registration flow. A packet is either valid and processed, or rejected.

### 3. No parse fallback

The proxy avoids parser recovery paths that would hide malformed messages. If the wire format cannot be decoded correctly, the packet is dropped rather than normalized or guessed.

### 4. Explicit key boundaries

The client keystore and the proxy keystore are separate concerns. The client must provide `KEYSTORE_DIR` explicitly, and the proxy uses its configured handler keystore path. This prevents accidental trust boundary collapse.

### 5. Authoritative routing via the effective zone

The proxy does not forward UPDATEs to a generic resolver path when it can resolve the authoritative server for the effective zone. It uses zone discovery and then targets the zone’s SOA MNAME.

## miekg/dns Shortcomings

The project uses `codeberg.org/miekg/dns v0.6.82`, but several sharp edges had to be patched or worked around.

### A. UPDATE-LEASE unpack mismatch

The library exposes `CodeUPDATELEASE`, but in v0.6.82 the EDNS option unpack dispatcher does not include a `*UPDATELEASE` case. That causes parsing to fail with:

`dns: no option unpack defined`

This is not a protocol problem in sig0lease; it is a library dispatch gap.

### Applied patch

sig0lease adds a compatibility package at [pkg/dnscompat/updatelease.go](pkg/dnscompat/updatelease.go) that registers EDNS code `2` with an `ERFC3597` constructor at process startup. This allows strict unpacking to succeed without adding parser fallback logic.

### B. UPDATE-LEASE unpacked form is not an OPT wrapper

After unpack, the library represents code `2` as a direct `*dns.ERFC3597` RR in the `Pseudo` section rather than as an `OPT` containing nested options in the shape the project initially expected.

### Applied patch

The update handler now checks both `Pseudo` and `Extra`, and it accepts either:

- direct `*dns.ERFC3597` records with EDNS code `2`, or
- `*dns.OPT` records containing an `ERFC3597` option.

### C. Strict parser behavior exposes wire-format differences

Because parsing is strict, any representation mismatch becomes visible quickly instead of being silently normalized. That is good for correctness, but it also means the code must match the library’s actual unpacked shapes precisely.

## Applied Compatibility Patches

The following project-side patches are currently in place:

1. `pkg/dnscompat` imports `codeberg.org/miekg/dns` and registers code `2` as `ERFC3597` on startup.
2. `cmd/sig0lease/main.go` imports the compatibility package so the proxy process gets the patch before reading packets.
3. `cmd/sig0lease-client/main.go` imports the same compatibility package so client-side pack/unpack behavior stays consistent.
4. `handlers/opcode5.go` recognizes UPDATE-LEASE whether it arrives as a direct `ERFC3597` record or under an `OPT` wrapper.

## Open Issues

1. The proxy still forwards non-registration UPDATE traffic to the authoritative path rather than implementing a full SRP policy engine.
2. The config and handler model are still oriented around the current registration flow; more protocol-specific workflows will need clearer abstractions if they are added later.
3. Some comments and terminology still mention “fallback” in older places and should be normalized to the stricter behavior model.

## Next Steps

1. Add focused tests for the UPDATE-LEASE decode shape so the `ERFC3597` compatibility path is locked in.
2. Add a regression test for the live registration flow that asserts the proxy responds with `NOERROR` on a valid signed request.
3. Add a regression test for tampered registration that asserts `REFUSED` or the expected signature-failure response.
4. Audit remaining comments and debug logs for old “fallback” terminology.

## Verification Status

Validated locally:

- proxy build succeeds;
- client build succeeds;
- valid registration succeeds against a live proxy;
- tampered registration is rejected;
- the proxy logs show strict unpack, strict SIG(0) verification, and authoritative forwarding.
