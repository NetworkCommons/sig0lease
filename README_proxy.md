# Proxy

Proxy is a DNS proxy for SIG(0)-authenticated UPDATE-LEASE registration flows, according to [RFC 9664](https://datatracker.ietf.org/doc/rfc9664/) and [RFC 2931](https://datatracker.ietf.org/doc/rfc2931/). It accepts DNS UPDATE packets, validates the downstream SIG(0) signature, applies the lease/update policy, and forwards the resulting UPDATE to the authoritative server selected for the zone.

The code also supports standard DNS routing for packets that are not relevant to this flow.


## What It Does

The project is intended to provide a light, explicit control point for lease registration traffic:

- Receive DNS queries over UDP and TCP.
- Route the registration opcode to the update handler and forward unrelated traffic upstream.
- Process DNS UPDATE requests carrying an UPDATE-LEASE EDNS option.
- Verify downstream SIG(0) signatures before the proxy accepts the request.
- Re-sign the upstream UPDATE with the proxy’s zone key before forwarding.
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

## Configuration

`config.yaml` controls:

- listening address and enabled transport networks;
- default upstream resolvers;
- handler-specific settings such as the upstream zone and keystore directory for the update handler;
- opcode-to-module routing.

The update handler uses the configured zone to discover the authoritative server for the effective zone, then sends the rewritten UPDATE there.

## Project Layout

- `cmd/sig0lease/` - proxy entrypoint
- `cmd/sig0lease-client/` - client entrypoint
- `config/` - YAML config loading and validation
- `forward/` - upstream forwarding logic
- `handlers/` - opcode handlers and result types
- `pkg/keyrec/` - KEY RR parsing and keystore helpers
- `pkg/lease/` - UPDATE-LEASE option encoding helpers
- `pkg/sig0/` - SIG(0) signing and verification helpers
- `server/` - UDP/TCP listener and request dispatch

## Validation
(requires client key, see this [README](./keystore/README.md))
```bash
CLIENT_KEYSTORE_DIR=${PWD}/keystore/client make test-full
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

## Applied Compatibility Patches

The following project-side patches are currently in place:

1. `pkg/dnscompat` imports `codeberg.org/miekg/dns` and registers code `2` as `ERFC3597` on startup.
2. `cmd/sig0lease/main.go` imports the compatibility package so the proxy process gets the patch before reading packets.
3. `cmd/sig0lease-client/main.go` imports the same compatibility package so client-side pack/unpack behavior stays consistent.
4. `handlers/opcode5.go` recognizes UPDATE-LEASE whether it arrives as a direct `ERFC3597` record or under an `OPT` wrapper.

# Implementation Status

## Current Protocol Behavior

1. Signature verification
- UPDATE requests must carry a valid SIG(0).
- According to RFC 2136, a KEY RR does not need to always be present in the Authority/Update section of a signed lease-update request
- The signer key must be at or above the leased FQDN hierarchy.
- Verification uses authoritative DNS as the primary source for signer key resolution.
- If authoritative DNS cannot be reached for signer-key lookup, the request fails.
- If authoritative DNS is reachable but returns no matching signer KEY, lease-store key material is used as fallback.
- If the lease-store does not contain the key, the key must be present in the request as KEY RR.
- Multiple KEY RRs can be present in a request.

2. When a signed registration comes in, the proxy first needs to verify the signature. This can be done either because the signing RR KEY is in the message, or because the KEY is online (its name is already present in the zone), or because the KEY is in the lease store. Any of this can be used to verify the signature.
3. You can sign a lease-update request with a key, but the request is to register or refresh a different RR KEY (which is not a signing KEY in this context).
4. If verification is passed, it means that we could find the signing key. We found it either:
   1. In-LeaseStore AND at-FQDN -> this is a key we are managing
   2. In-LeaseStore AND NOT at-FQDN -> we assume the key has been removed externally from our proxy, so we need to register it with the remaining lease time
   3. NOT In-LeaseStore AND at-FQDN -> the key is already registered, but we assume this has happened outside the lease mechanism (permanent update) and not under our control
   4. NOT In-LeaseStore AND NOT at-FQDN -> the key must be in the request, otherwise we would never get here since we would not have had any KEY to verify the signature.
5. From now on if the request contains a KEY RR, this does not need to be the key that signed the request. Looking at the request lease-times:
   1. KEY-LEASE != 0, LEASE != 0: This is a registration or a refresh of KEY and non-KEY RRs.
      1. The KEY RR and non-KEY RRs (at least one) must be present in the request, otherwise this is an error
      2. If the KEY RR is already present in the LeaseStore, this is a refresh of the KEY, otherwise a registration
      3. For any of the non-KEY RRs that are not present in the LeaseStore, this is a registration, otherwise a refresh
      4. Because non-KEY RRs are present in the lease-store under the key that registered them, if there is no KEY then there are no non-KEY RRs.
   2. KEY-LEASE == 0, LEASE != 0: this is a registration/refresh of non-KEY RRs
      1. non-KEY RRs (at least one) must be present in the request, otherwise this is an error
      2. For any of the non-KEY RRs that are not present in the LeaseStore, this is a registration, otherwise a refresh
      3. Signing KEY must already exist authoritatively at the lease FQDN. It can be present in the request, but given KEY-LEASE == 0, this is not a registration of the key, therefore the key must be already registered.
   3. KEY-LEASE == 0, LEASE == 0:
      1. If KEY RR present -> delete KEY
      2. If non-KEY RRs present -> delete non-KEY RRs
      3. Both present -> delete both
      4. Neither present -> error
   4. KEY-LEASE != 0, LEASE == 0:
      1. KEY RR must be present -> register or refresh KEY
      2. If non-KEY RRs present -> delete non-KEY RRs
6. For all attempts of registration of an already existing identical record, the registration of the record is skipped (it has already been registered outside our code)
   1. If a record is already present authoritatively and not currently managed in active lease state, that specific registration is skipped.
   2. Remaining records in the same request continue processing.
   3. This implies that the proxy needs to verify whether in case of a registration, an identical record is already at the FQDN.
7. For all attempts of deleting records, if the record does not exist in the lease-store, we assume the record is either outside our control, or it has been cleaned after expiry. The request does not fail but the user needs to be informed about this. If the record exists in the lease-store but not at the DNS, do not fail the request but signal the situation. Missing local records do not force whole-request failure.

## Storage Model

1. KEY lease storage
- KEY lease state is tracked per canonical key name in the lease manager.

2. Non-KEY lease storage
- Non-KEY records are tracked individually under each key owner.
- Record identity includes full RR presentation (including TTL).
- Records that differ in any field are treated as distinct records.

## Authoritative Forwarding

1. Target resolution
- The proxy resolves the effective authoritative zone and SOA MNAME and forwards UPDATE there.

2. Upstream signing
- Forwarded UPDATE messages are signed with the proxy upstream key.

## Test Layout

1. Unit tests
- Unit tests remain next to packages (for example in handlers and pkg).

2. Integration tests
- Integration scripts and integration helpers are under tests.

## Client Behavior

1. Lease adoption from server response
- Client expiry calculations now adopt server-returned UPDATE-LEASE values when present.
- If no lease option is returned, client falls back to requested lease duration.
