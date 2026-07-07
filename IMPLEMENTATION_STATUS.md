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

The client keystore and the proxy keystore are separate concerns. The client must provide `CLIENT_KEYSTORE_DIR` explicitly, and the proxy uses its configured handler keystore path. This prevents accidental trust boundary collapse.

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

## Current Limitations (Phase 1)

1. `KEY-LEASE` is not used for policy decisions in the registration flow.
The client currently sends an 8-byte lease option with `KEY-LEASE` set to `0`, and the handler logic effectively enforces behavior from `LEASE` only. This limits lifetime-policy expressiveness where key lifetime and lease lifetime should be controlled separately.

2. The handler processes a single client `KEY` RR per request.
In the current flow, the update handler extracts the first `KEY` RR and proceeds. Multi-key updates in one transaction are not implemented as a first-class feature.

3. Upstream forwarding reuses the client `KEY` RR without rewrite.
The forwarded UPDATE uses the client-provided `KEY` RR as-is. This phase does not yet apply rewrite policy (for example, owner-name mapping or TTL normalization) before sending to the authoritative server.

## Unused / Unreachable Code Inventory

This inventory is based on `deadcode ./...` run from the module root on 2026-07-07.

Scope note:
- `deadcode` reports symbols unreachable from current entrypoints in this module.
- Exported library APIs can still be intentionally public even when unreachable from local binaries/tests.

Confirmed in handler chain module:
- `handlers.Chain` is currently unreachable from active server routing paths.
- `handlers.HandlerFunc` is only used as the type of `handlers.Chain`, and has no other current references.

Current unreachable functions by package:

1. `client/client.go`
`Client.QueryWithTimeout`, `Client.QueryMultiple`, `MakeQuery`, `MakeUpdateQuery`, `Client.QueryWithOpcode`.

2. `client/sig0.go`
`MakeRegistrationRequest`, `MakeRefreshRequest`.

3. `dnsmsg/dnsmsg.go`
`ProcessOpcode`, `MakeResponse`, `SetReply`, `ExtractQuestionInfo`, `MakeStatusResponse`.

4. `forward/forward.go`
`extractDomain`, `Resolver.SetServers`.

5. (Left for future use/completeness) `handlers/handlers.go`
`Chain`, `NewBaseHandler`.

6. `pkg/keyrec/keyrec.go`
`KeyRecord.Parse`, `FromKEY`, `KeyRecord.ToKEY`, `calculateKeyTag`, `KeyRecord.KeyTag`, `KeyRecord.AlgorithmName`, `KeyRecord.String`.

7. `pkg/lease/lease.go`
`LeaseOption.Decode`.

8. `pkg/sig0/signer.go`
`NewSigner`, `Signer.StartUpdate`, `Signer.UpdateRR`, `Signer.RemoveRR`, `Signer.UpdateParsedRR`, `Signer.RemoveParsedRR`, `Signer.SignUpdate`.

9. `pkg/srp/client/client.go`
`New`, `NewWithDefaults`, `Client.Register`, `Client.Update`, `Client.Delete`, `Client.Send`, `Client.signMessage`, `Client.sendUpdate`, `Client.RegisterService`, `Client.RegisterServiceWithTXT`, `Client.DeleteService`, `Client.CreateUpdateMessage`, `Client.VerifyResponse`, `ensureFQDN`.

10. `pkg/srp/instruction/instruction.go`
`New`, `Instruction.SetService`, `Instruction.SetTXT`, `Instruction.SetDNSKEY`, `Instruction.IsServiceDelete`, `ServiceDelete`, `NewService`, `Instruction.Validate`, `Service.Validate`, `validateDNSKEY`, `Instruction.Encode`, `Instruction.Decode`, `encodeTXT`, `decodeTXT`, `encodeDNSKEY`, `decodeDNSKEY`, `Instruction.ToRR`, `Instruction.ParseRR`.

11. `pkg/srp/server/server.go`
`NewDefaultKeyStore`, `DefaultKeyStore.AddKey`, `DefaultKeyStore.GetKey`, `DefaultKeyStore.GetKeysByZone`, `DefaultKeyStore.VerifySignature`, `New`, `NewWithKeyStore`, `Server.Process`, `Server.validateMessage`, `Server.verifySIG0`, `Server.findSIG0`, `Server.findDNSKEY`, `Server.processPrerequisites`, `Server.processInstructions`, `Server.parseInstruction`, `Server.buildResponse`, `Server.createSOA`, `Server.errorResponse`, `Server.ProcessUpdateMessage`, `Server.GetZone`, `Server.RegisterKey`, `Server.KeyStore`, `ensureFQDN`.

12. `server/server.go`
`Server.GetResolver`.

## Next Steps

1. Add focused tests for the UPDATE-LEASE decode shape so the `ERFC3597` compatibility path is locked in.
2. Implement explicit `KEY-LEASE` handling semantics in the handler (validation, storage, and refresh policy), then add integration coverage.
3. Support the registration of more RR types with a registered key, and check that the lease expiry is different for keys and other records.
3. Decide and document behavior for requests containing multiple `KEY` RRs (reject with clear rcode vs explicit batch support).
4. Define upstream rewrite policy for `KEY` RR forwarding (owner-name mapping and TTL policy) and enforce it in the handler.

## Verification Status

Validated locally:

- proxy build succeeds;
- client build succeeds;
- valid registration succeeds against a live proxy;
- tampered registration is rejected;
- the proxy logs show strict unpack, strict SIG(0) verification, and authoritative forwarding.
