# Test Harness Architecture

## Overview
This diagram shows the end-to-end test infrastructure for testing against a real BIND 9 server.

```mermaid
flowchart TD
    subgraph "Test Framework Go testing"
        T1[Test case e2e test.go]
        T2[Setup harness]
        T3[Run test scenario]
        T4[Assert results via dig query]
        T5[Tear down harness]
    end

    subgraph "Test Harness internal testharness"
        H1[bind.go Start stop BIND 9]
        H2[zone_writer.go Create zone files]
        H3[dig.go Query DNS results]
        H4[keygen.go Generate test keys]
        H5[port_mgr.go Port allocation]
    end

    subgraph "Test Data"
        D1[testdata keys *.pem]
        D2[testdata zones *.zone]
    end

    T1 --> T2
    T2 --> H1
    T2 --> H2
    T2 --> H4

    H1 -->|spawns| BIND9[BIND 9 process]
    H2 -->|creates zone files in temp dir| BIND9
    H4 -->|generates| TestKey[ED25519 key pair per RFC 8032]

    TestKey --> D1
    BIND9 -->|listens on| BindPort[Port from port_mgr]
    BindPort --> T3

    T3 --> DnsQuery[DNS query to test service]
    DnsQuery --> H3
     H3 -->|uses codeberg.org/miekg/dns v2 or exec dig| BIND9
    H3 -->|returns records| T4

    T4 --> Assert{Assertions}
    Assert -->|Records match| Pass1[PASS]
    Assert -->|TTL correct| Pass2[PASS]
    Assert -->|Lease OPT correct| Pass3[PASS]

    T5 -->|kills BIND 9 process| CleanUp[Clean up temp dir]
```

## Test Flow Example

```mermaid
sequenceDiagram
    participant Test as Test Case
    participant Harness as Test Harness
    participant Bind as BIND 9
    participant Dig as dig nslookup

    Note over Test: Work Package 1 milestone testing

    Test->>Harness: StartBIND9 zone file
    Harness->>Harness: Generate temp directory
    Harness->>Harness: Write zone file plus config
    Harness->>Bind: Spawn named c temp bind.conf
    Bind-->>Harness: PID port 5300 plus
    Harness-->>Test: Server struct with Addr Port

    Test->>Test: Load test keys from testdata/
    Test->>Test: Build SRP update message

     Test->>Bind: DNS Update via codeberg.org/miekg/dns v2
    Bind->>Bind: Validate SIG0 signature
    Bind->>Bind: Check zone file rules
    Bind-->>Test: Response with RCODE

    Test->>Dig: dig @127.0.0.1 port myhost.default.service.arpa. AAAA
    Dig->>Bind: Query via UDP TCP
    Bind-->>Dig: AAAA record for host

    alt Expected record exists
        Test->>Test: Assert records match
        Test->>Harness: Stop
        Harness->>Bind: Kill named process
        Harness->>Harness: Remove temp directory
        Test-->>TestRunner: PASS
    else Assertion failed
        Test-->>TestRunner: FAIL
    end
```

## Unit Tests vs E2E Tests

```mermaid
flowchart TD
    subgraph "Unit Tests pkg test.go"
        direction LR
        UT1[No external processes]
        UT2[Test individual packages]
        UT3[Fast execution less than 1s each]
        UT4[In-memory data structures]
    end

    subgraph "E2E Tests star e2e test.go"
        direction LR
        ET1[Start BIND 9 process]
        ET2[Test full integration]
        ET3[Slower seconds per test]
        ET4[Real DNS wire format]
    end

    UT1 --> UnitGroup[Run in go test dot dot]
    ET1 --> E2EGroup[Run with tags e2e]

    UnitGroup --> Coverage[80 percent code coverage target]
    E2EGroup --> Integration[Validate against RFC requirements]

    style UT1 fill:#d4edda
    style ET1 fill:#f8d7da
```

## Test Data Structure

```
testdata/
 ├── keys/                     ED25519 key pairs per RFC 8032
 │   ├── host1.pem            Private key plus public key for FCFS tests
 │   └── host2.pem            Second host key for conflict tests
├── zones/                    BIND 9 zone files
│   ├── default.service.arpa.zone
│   └── reverse.zone         Reverse mapping optional
└── bind.conf                Minimal BIND config
    options {
        directory /tmp/test-bind
        listen on port 5300 any
        allow-query any
        allow-update key test-key
    }
    zone "default.service.arpa." {
        type master
        file default.service.arpa.zone
    }
```

## Key Test Scenarios

```mermaid
flowchart TD
    Start[Test Suite] --> TC1[Test: Valid Registration]
    TC1 --> TC2[Test: Name Conflict YXDOMAIN]
    TC2 --> TC3[Test: Missing Update Lease]
    TC3 --> TC4[Test: Invalid Signature]
    TC4 --> TC5[Test: TTL Inconsistency]
    TC5 --> TC6[Test: Lease Expiry and GC]
    TC6 --> TC7[Test: Remove-All LEASE equals 0]
    TC7 --> TC8[Test: Multiple Services per Host]
    TC8 --> Done

    style TC1 fill:#d4edda
    style TC2 fill:#fff3cd
    style TC3 fill:#f8d7da
    style TC4 fill:#f8d7da
```

## Mock vs Real BIND 9 Tests

```mermaid
flowchart TD
    subgraph "Mock DNS Server fast isolated"
        M1[dns.Server with custom Handler]
        M2[In-memory zone storage]
        M3[Programmable responses]
    end

    subgraph "Real BIND 9 integration slower"
        R1[Spawn named process]
        R2[Actual BIND 9 DNS server]
        R3[Real zone file operations]
    end

    M1 --> M2
    R1 --> R2
    R2 --> R3

    subgraph "When to use"
        direction TB
        UseMock[Unit tests property based testing]
        UseBIND[E2E validation RFC compliance checks]
    end

    style M1 fill:#cce5ff
    style R1 fill:#f8d7da
```

## CI CD Integration

```mermaid
flowchart LR
    subgraph "Development"
        Dev[Test locally go test dot dot]
    end

    subgraph "CI Pipeline"
        CI1[go mod verify]
        CI2[Unit tests go test race]
        CI3[E2E tests go test tags e2e]
        CI4[Coverage report]
    end

    subgraph "Code Quality Gate"
        CQ1[Coverage greater than 80 percent]
        CQ2[E2E all pass]
        CQ3[Race detector clean]
    end

    Dev --> CI1
    CI1 --> CI2
    CI2 --> CI3
    CI3 --> CI4
    CI4 --> CQ1
    CQ1 -->|Yes| CQ2
    CQ2 -->|Yes| CQ3
    CQ3 -->|Yes| Merge[Ready for merge]

    style Dev fill:#d4edda
    style CQ1 fill:#fff3cd
    style Merge fill:#d4edda
```
