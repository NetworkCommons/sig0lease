# sig0lease Architecture Components

## Overview
This diagram shows the package structure and component relationships.

```mermaid
graph TB
    subgraph "cmd/sig0lease-server"
        ServerCLI[server main.go]
        Config[config.go YAML TOML]
    end

    subgraph "pkg/ library"

        subgraph "pkg/lease"
            LeaseOpt[LeaseOption type]
            EncodeDecode[encode decode functions]
        end

        subgraph "pkg/keyrec"
            KeyRecord[KeyRecord type]
            KeyEncode[key rec encode decode]
        end

        subgraph "pkg/sig0"
            Signer[Signer with KeyStore]
            Verifier[Verify signature]
            AlgoMap[algorithm mappings]
        end

        subgraph "pkg/srp/server"
            SRPSrv[SRP Server]
            Validate[instruction validation]
            LeaseMgr[lease management]
            FCFS[FCFS naming]
        end

        subgraph "pkg/srp/client"
            SRPClient[SRP Client]
            Refresh[refresh loop]
        end

        subgraph "pkg/dnsif"
            UpdateClient[UpdateClient interface]
            subgraph "pkg/dnsif/bind9"
                BindImpl[BIND 9 implementation]
            end
        end

        subgraph "pkg/discovery"
            ZoneDiscover[SOA zone discovery]
            RegistrarDiscover[SRV registrar lookup]
        end
    end

    subgraph "External Systems"
        BIND9[BIND 9 DNS Server]
        ClientApp[Client Application uses pkg as library]
    end

    SRPSrv --> Validate
    SRPSrv --> LeaseMgr
    SRPSrv --> FCFS
    SRPClient --> Refresh

    SRPSrv -->|implements UpdateClient| BindImpl
    SRPClient -->|uses| UpdateClient

    ClientApp -->|SRP requests| SRPClient
    SRPClient -->|TCP connection| ServerCLI
    ServerCLI -->|forward updates| BIND9
    BindImpl -->|DNS update messages| BIND9

    LeaseMgr -.->|stores state in memory| SRPSrv
    FCFS -.->|maintains name state| SRPSrv

    style LeaseOpt fill:#e1f5ff
    style KeyRecord fill:#e1f5ff
    style Signer fill:#ffe1e1
    style Verifier fill:#ffe1e1
    style SRPSrv fill:#e1ffe1
    style SRPClient fill:#e1ffe1
    style UpdateClient fill:#fff5e1

     note1[RFC 9664 Update Lease RFC 9665 SRP Protocol RFC 2931 SIG0 ED25519 RFC 8032 RFC 8945 TSIG]
    note1 -.->|documented in| ServerCLI
```

## Component Responsibilities Matrix

```mermaid
graph LR
    A[pkg lease] --> B[9664 4]
    C[pkg keyrec] --> D[2539, 4034]
    E[pkg sig0 signer] --> F[2931]
    G[pkg srp server] --> H[9665 3.2-3.3]
    I[pkg srp client] --> J[9665 3.2.5]

    style A fill:#e1f5ff
    style E fill:#ffe1e1
```

## Data Flow: Full Registration

```mermaid
flowchart TD
    Start[Client Application] --> Build1[Build DNS Update Message]

    Build1 --> AddLease[Add Update Lease OPT pkg lease]
    AddLease --> AddKey[Add KEY RR pkg keyrec]
    AddKey --> AddPtr[Add PTR RR pkg srp instruction]
    AddPtr --> AddSrvTxt[Add SRV TXT RRs pkg srp instruction]

    AddSrvTxt --> Sign1[Sign Message pkg sig0 signer]

    Sign1 --> ClientSend[Send to SRP Server TCP connection]
    ClientSend --> ServerRecv[Server receives message]

    ServerRecv --> ValidateSig[Validate SIG0 TSIG pkg sig0 verifier]
    ValidateSig --> ParseUpdate[Parse DNS Update pkg srp server]

    ParseUpdate --> ValidateInst[Validate Instructions pkg srp server validate.go]
    ValidateInst --> CheckLease[Check Update Lease pkg lease validation]

    CheckLease --> FCFSName[FCFS Name Generation pkg srp names]

    FCFSName --> ForwardToUpdate[Forward to DNS Server dnsif updateclient.go]
    ForwardToUpdate --> BindImpl[Bind9 implementation dnsif bind9]

    BindImpl --> DnsUpdate[Send DNS Update to BIND 9]
    DnsUpdate --> RecvResponse[Receive Response RCODE]

    RecvResponse --> AddLeaseOpt[Add granted lease to response OPT]
    AddLeaseOpt --> SendResp[Send response to client]

    SendResp --> ClientRecv[Client receives NOERROR plus leases]
    ClientRecv --> ScheduleRefresh[Schedule refresh at 80 percent plus jitter]
```

## Thread Model

```mermaid
graph LR
    subgraph "Main thread"
        Main[Server startup config load]
        AcceptLoop[Accept loop blocking]
    end

    subgraph "Worker pool"
        Worker1[Handler goroutine]
        Worker2[Handler goroutine]
        Worker3[Handler goroutine]
        Worker4[Handler goroutine]
    end

    subgraph "Background tasks"
        GC[Garbage collection loop periodic scan leases]
        RefreshMgr[Refresh scheduler handles timer events]
    end

    Main --> AcceptLoop
    AcceptLoop -->|spawns per connection| Worker1
    AcceptLoop -->|spawns per connection| Worker2
    AcceptLoop -->|spawns per connection| Worker3
    AcceptLoop -->|spawns per connection| Worker4

    Worker1 --> GC
    Worker2 --> GC
    Worker3 --> RefreshMgr
    Worker4 --> RefreshMgr
```
