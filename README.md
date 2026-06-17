# sig0lease Proxy

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

- `cmd/sig0lease_proxy/` - Main binary entry point
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
go build ./cmd/sig0lease_proxy
```

### Run with Config File

```bash
./sig0lease-proxy config.yaml
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
    Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (*dns.Msg, error)
    Setup(cfg map[string]any) error
}
```

### Available Modules

- `status_handler` - Handles opcode 2 (STATUS queries)
- `update_handler` - Handles opcode 5 (UPDATE queries for RFC 2136 dynamic DNS)

## Testing with dig

```bash
# Start the proxy (non-privileged port 8053 by default)
./sig0lease-proxy config.yaml

# Test normal DNS query (opcode 0 - QUERY) on port 8053
dig @localhost -p 8053 example.com

# For standard port 53, run with sudo or change config to :53
```

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