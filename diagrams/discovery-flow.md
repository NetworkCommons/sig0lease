# Registrar Discovery Flow

## Overview
This diagram shows how the SRP client discovers the registrar per RFC 9665 3.1 and RFC 8765.

```mermaid
sequenceDiagram
    participant Client as SRP Client
    participant Resolver as DNS Resolver
    participant ZoneAuthority as Zone Authority

    Note over Client: RFC 9665 3.1 Registrar Discovery

    %% Step 1: Discover Zone Apex
    Client->>Resolver: Query SOA for hostname e.g. myhost.example.com.

    Resolver->>ZoneAuthority: Query SOA
    ZoneAuthority-->>Resolver: SOA record plus MNAME authoritative server

    Resolver-->>Client: SOA response

    %% Step 2: Walk parent zones to find zone apex
    Client->>Client: Extract zone from SOA Given myhost.example.com. Zone equals example.com.

    Note over Client Resolver: RFC 8765 6.1 Zone Discovery via SOA

    %% Step 3: Query SRP Registrar SRV record
    Client->>Resolver: Query SRV for _dnssd-srp._tcp.zone e.g. _dnssd-srp._tcp.example.com.

    Resolver->>ZoneAuthority: Query SRV
    alt SRP registrar configured
        ZoneAuthority-->>Resolver: SRV record Priority equals 0 Weight equals 0 Port equals 5357 Target equals srp.example.com.
    else No SRP registrar
        ZoneAuthority-->>Resolver: NXDOMAIN or empty response
        Resolver-->>Client: No registrar found
        Client->>Client: Error No SRP registrar for this zone
        Note right of Client: May fall back to manual configuration
    end

    Resolver-->>Client: SRV records

    %% Step 4: TLS variant optional
    alt TLS enabled
        Client->>Resolver: Query SRV for _dnssd-srp-tls._tcp.zone e.g. _dnssd-srp-tls._tcp.example.com.

        Resolver->>ZoneAuthority: Query SRV
        ZoneAuthority-->>Resolver: SRV records with TLS-enabled registrar

        Resolver-->>Client: SRV records

        Client->>Client: Connect to SRP registrar via TLS port from SRV record
    else Non-TLS plain TCP
        Client->>Client: Connect to SRP registrar via plain TCP port 5357 from SRV record
    end

    %% Step 5: Connection established
    Note over Client ZoneAuthority: TCP connection ready for SRP updates RFC 9665 7 TLS or plain TCP
```

## DNS Records Used in Discovery

```mermaid
graph LR
    subgraph "Discovery Query Sequence"
        Q1[Query SOA for hostname]
        Q2[Walk parent zones via SOA MNAME]
        Q3[Query SRV _dnssd-srp._tcp.zone]
        Q4[Optionally Query SRV _dnssd-srp-tls._tcp.zone]
    end

    subgraph "Response Records"
        R1[SOA record Zone apex plus MNAME]
        R2[SRV records Registrar location]
    end

    Q1 --> R1
    Q3 --> R2
    Q4 --> R2

    style Q1 fill:#e1f5ff
    style Q3 fill:#ffe1e1
```

## Multiple Registrars Load Balancing

```mermaid
sequenceDiagram
    participant Client as SRP Client
    participant Resolver as DNS Resolver

    Client->>Resolver: Query SRV for _dnssd-srp._tcp.example.com.

    Resolver-->>Client: 3 SRV records:
        Note right of Resolver: 1. Priority equals 0 Port equals 5357 Target equals srp1.example.com<br/>2. Priority equals 0 Port equals 5357 Target equals srp2.example.com<br/>3. Priority equals 0 Port equals 5357 Target equals srp3.example.com

    alt Client uses random selection
        Client->>Resolver: Query A AAAA for srp1.example.com random choice
        Resolver-->>Client: IP address(es)

        Client->>srp1.example.com: Connect to registrar 1
    else Client prefers first
        Client->>Resolver: Query A AAAA for srp1.example.com
        Resolver-->>Client: IP address(es)

        alt Connection fails
            Client->>Resolver: Query A AAAA for srp2.example.com
            Resolver-->>Client: IP address(es)
            Client->>srp2.example.com: Failover to registrar 2
        end
    end
```

## Zone Discovery Alternatives

```mermaid
flowchart TD
    Start[Client wants to register service] --> Method{Discovery Method}

    Method -->|Auto via SOA| AutoSOA[Query SOA for hostname walk zone]
    Method -->|Manual config| Manual[Config specifies zone apex directly]

    subgraph "Auto Discovery RFC 8765"
        AS1[Query SOA myhost.example.com]
        AS2[Extract MNAME from SOA]
        AS3[Verify via reverse lookup]
        AS4[Use zone apex as SRP zone]
    end

    subgraph "Manual Configuration"
        MC1[Config file: zone equals example.com.]
        MC2[Config file: registrar equals srp.example.com colon 5357]
    end

    AutoSOA --> AS1 --> AS2 --> AS3 --> AS4
    Manual --> MC1 --> MC2

    AS4 --> Connect[Connect to registrar]
    MC2 --> Connect

    style AutoSOA fill:#d4edda
    style Manual fill:#f8d7da
```

## Error Cases in Discovery

```mermaid
flowchart TD
    Start[Start discovery] --> Q1[Query SOA]

    Q1 -->|Success| ExtractZone[Extract zone apex]
    Q1 -->|NXDOMAIN| Err1[No such domain Return error]
    Q1 -->|SERVFAIL| Err2[DNS server failure Retry or error]

    ExtractZone --> Q2[Query SRV _dnssd-srp._tcp.zone]

    Q2 -->|Success with records| ParseSRV[Parse SRV records]
    Q2 -->|NXDOMAIN| Err3[No SRP registrar configured Use manual config fallback]
    Q2 -->|Empty response| Err4[Zone has no SRP registrar]

    ParseSRV --> ResolveAddr[Resolve target hostname to IP]
    ResolveAddr --> Connect[TCP connect to registrar]

    Connect -->|Success| Ready[Registrar ready]
    Connect -->|Connection refused| Err5[Registrar not listening Check port firewall]
    Connect -->|TLS handshake fail| Err6[TLS error Try non-TLS or fix certs]

    style Err1 fill:#f8d7da
    style Err2 fill:#f8d7da
    style Err3 fill:#f8d7da
    style Err4 fill:#f8d7da
    style Err5 fill:#f8d7da
    style Err6 fill:#f8d7da
    style Ready fill:#d4edda
```

## Integration with miekg dns

```mermaid
sequenceDiagram
    participant Client as sig0lease discovery module
    participant Miekg as miekg/dns library

    Client->>Miekg: &dns.Msg{ Question: []dns.Question{ {Name: "." Qtype: dns.TypeSOA} } } ExchangeContext ctx addr

    Miekg-->>Client: *dns.Msg with SOA record

    Client->>Miekg: Parse SOA via dns.IsSoa msg.Answer[0]

    Client->>Miekg: &dns.Msg{ Question: []dns.Question{ {Name: "_dnssd-srp._tcp.example.com." Qtype: dns.TypeSRV} } } ExchangeContext ctx addr

    Miekg-->>Client: *dns.Msg with SRV records

    Client->>Miekg: Extract SRV via dns.SRV from answer
```
