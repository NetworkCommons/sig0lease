# sig0lease

A modular DNS proxy server implementing the Service Registration Protocol (SRP) for secure dynamic DNS-SD updates, using SIG(0) authentication.

## Features

- Accepts DNS queries on UDP and TCP (port 8053 by default)
- Routes queries based on DNS opcode to processing modules
- Configurable opcode-to-module mapping via YAML config
- Sig(0) signing for DNS update requests
- Forwarding of unhandled opcodes to upstream resolvers
- Concurrent upstream queries with first-response-wins

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌───────────────┐
│   DNS       │     │  Router (based   │     │               │
│  Client     │────►│  on opcode)      │────►│  Processing   │
└─────────────┘     └──────────────────┘     │    Modules    │
                                             │  (SIG(0), etc)│
                                             └───────────────┘
                                                     │
                                              ┌──────┴──────┐
                                              │ Forwarding  │
                                              │ to Upstream │
                                              └─────────────┘
```

## Directory Structure

- `cmd/sig0lease/` - Main binary entry point
- `pkg/` - Library modules
  - `sig0/` - SIG(0) signing and verification (RFC 2931)
  - `lease/` - Update Lease EDNS option (RFC 9664)
  - `keyrec/` - KEY record handling (RFC 2539, RFC 4034)
  - `srp/` - Service Registration Protocol (RFC 9665)
- `config/` - Configuration handling with YAML support
- `forward/` - Upstream forwarding logic
- `handlers/` - Processing modules interface and stubs
- `logging/` - Structured logging

## Usage

### Build

```bash
make build
```

### Run with Config File

```bash
./bin/<your OS>/sig0lease ./config.yaml
```

If no config file is provided, default settings are used:
- Listen on port **8053** (UDP/TCP) - non-privileged by default
- Forward to `8.8.8.8:53` for unhandled opcodes

## Processing Modules

Modules implement the `handlers.Handler` interface:

```go
type Handler interface {
    Name() string
    CanHandle(opcode uint8) bool
    Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) *HandlerResult
    Setup(cfg map[string]any) error
}
```

### Handler Response Types

Handlers return a `HandlerResult` with a status code indicating how the router should process the packet:

- **StatusProcessed (0)** - Handler successfully processed the packet; return response to client
- **StatusNotRelevant (1)** - Packet is valid but not relevant to this protocol (e.g., UPDATE without UPDATE-LEASE EDNS option); router forwards to default upstream resolver
- **StatusError (2)** - Handler encountered an error during processing; return error response to client

This pattern allows handlers to signal whether a packet is relevant to their protocol without throwing exceptions, enabling clean fallback forwarding for packets that don't match the expected protocol structure.

### Available Modules

- `status_handler` - Handles opcode 2 (STATUS queries)  
- `update_handler` - Handles opcode 5 (UPDATE queries with sig0lease authentication per RFC 9664)

## Testing

```bash
# Fast unit tests (no live integration environment)
make test

# Keystore-dependent unit tests
make test-unit

# Full integration test (starts proxy and uses sig0lease-client)
make test-integration

# Single e2e registration using built client binary
make test-register ADDR=127.0.0.1:8053 ZONE=dev.zenr.io. KEYNAME=test.dev.zenr.io.
```

Manual smoke test:

```bash
# Start the proxy
make run-server

# Send one registration through the client binary
make run-client ADDR=127.0.0.1:8053 CMD="register dev.zenr.io. test.dev.zenr.io."
```

For standard port 53, run with sudo or change config to `:53`.

## Standards Compliance

This proxy implements:
- **RFC 9664** - Update Lease EDNS(0) option
- **RFC 2539, RFC 4034** - KEY records for DNSSEC
- **RFC 2931** - SIG(0) request/response signing
- **RFC 9665** - Service Registration Protocol (SRP)

## Future Enhancements

- Implement actual SRP processing logic in modules
- Support DNS over HTTPS (DoH) upstream forwarding
- Support DNS over TLS (DoT) upstream forwarding
- Cache layer integration for response caching
- Statistics and metrics collection (prometheus compatible)
