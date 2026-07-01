# sig0lease

sig0lease is a DNS proxy for SIG(0)-authenticated UPDATE-LEASE registration flows. It accepts DNS UPDATE packets, validates the downstream SIG(0) signature, applies the lease/update policy, and forwards the resulting UPDATE to the authoritative server selected for the zone.

## What It Does

The project is intended to provide a small, explicit control point for DNS-SD style registration traffic:

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
./bin/darwin/sig0lease ./config.yaml
```

Run the client against a proxy:

```bash
make run-client ADDR=127.0.0.1:8053 CMD="register test.dev.zenr.io. test.dev.zenr.io."
```

The client requires an explicit keystore directory:

```bash
KEYSTORE_DIR=/path/to/keystore ./bin/darwin/sig0lease-client 127.0.0.1:8053 register test.dev.zenr.io. test.dev.zenr.io.
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

```bash
go test ./server ./handlers ./client ./pkg/lease
go build ./cmd/sig0lease ./cmd/sig0lease-client
```

For a complete behavior check, run the registration and tamper flows against a live proxy instance.

## Protocol Notes

This repository focuses on the UPDATE-LEASE + SIG(0) path defined by RFC 9664 / RFC 2931, with the proxy forwarding the resulting UPDATE to the authoritative server for the target zone. The code also supports standard DNS routing for packets that are not relevant to this flow.

The current implementation depends on `codeberg.org/miekg/dns`, but several library edge cases required compatibility shims. See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for details.

## Related Documentation

- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)
