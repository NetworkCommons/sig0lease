# SRP Instruction Validation Logic

## Overview
This diagram shows the instruction validation flow per RFC 9665 3.3.

```mermaid
flowchart TD
    Start[Receive DNS Update Message] --> CheckSection[Check Sections]

    subgraph "Message Structure Check"
        direction LR
        CheckSection --> HasZone[Has Zone Section with SOA]
        HasZone -->|No| Err1[RCODE REFUSED Not a valid SRP update]
        HasZone -->|Yes| CheckUpdate[Check Update Section]
    end

    subgraph "Update Section Validation"
        direction LR
        CheckUpdate --> HasInstructions[Has Update RRs]

        HasInstructions -->|No| Err2[RCODE REFUSED Empty update]

        HasInstructions -->|Yes| ParseInst[Parse Instructions]

        ParseInst --> IdentifyType{Identify Instruction Type}

        subgraph "Instruction Types"
            direction TB
            IdentifyType -->|ServiceDiscovery| SDCheck
            IdentifyType -->|ServiceDescription| SDCheck
            IdentifyType -->|HostDescription| HDCheck
        end

        subgraph "Validation Rules per RFC 9665"
            direction LR
            SDCheck[ServiceDiscovery 3.3.1.1]
            SDCheck[ServiceDescription 3.3.1.2]
            HDCheck[HostDescription 3.3.1.3]
        end

        SDCheck --> SDRule1[Exactly 1 PTR RR]
        SDCheck --> SDRule2[DeleteAll RRs optional KEY required TXT]

        HDCheck --> HDRule1[DeleteAll RRs exactly 1 KEY optional A AAAA]

        SDRule1 -->|Valid?| ValidSD
        SDRule2 -->|Valid?| ValidSD
        HDRule1 -->|Valid?| ValidHD

        ValidSD --> CheckAll[Check All Instructions]
        ValidHD --> CheckAll

        CheckAll --> NoPreReq[No Prerequisite RRs RFC 9665 3.2.3]
        NoPreReq -->|Has prerequisites| Err3[RCODE REFUSED SRP has no prerequisites]

        NoPreReq --> HasLease[Has Update Lease OPT RFC 9665 3.3.2]
        HasLease -->|No| Err4[RCODE REFUSED Update Lease required]

        HasLease --> CheckOrder[LEASE less than or equal to KEY-LEASE]
        CheckOrder -->|No| Err5[RCODE REFUSED Invalid lease order]

        CheckOrder --> ValidSIG{Valid SIG0 TSIG RFC 9665 3.3.3}
        ValidSIG -->|No| Err6[RCODE REFUSED Signature invalid]

        ValidSIG --> FCFSName[FCFS Name Generation]
        FCFSName --> CheckConflict{Name Conflict YXDOMAIN check}

        CheckConflict -->|Yes| Err7[RCODE YXDOMAIN plus recommended name in Additional]
        CheckConflict -->|No| ForwardToUpdate[Forward to DNS Server]

        ForwardToUpdate --> DnsUpdate[Send DNS Update]
        DnsUpdate --> Rcode{Response RCODE}
        Rcode -->|NOERROR| Success[Return NOERROR plus leases in OPT]
        Rcode -->|Other| Err8[Map RCODE return to client]
    end

    style Start fill:#e1f5ff
    style Err1 fill:#f8d7da
    style Err2 fill:#f8d7da
    style Err3 fill:#f8d7da
    style Err4 fill:#f8d7da
    style Err5 fill:#f8d7da
    style Err6 fill:#f8d7da
    style Err7 fill:#f8d7da
    style Success fill:#d4edda
```

## Instruction Type Details

### ServiceDiscovery RFC 9665 3.3.1.1

```mermaid
flowchart LR
    Start[ServiceDiscovery Instruction] --> Check1[Zone Section SOA for zone]
    Check1 --> Check2[Update Section Exactly 1 PTR RR]

    Check2 --> PTRFormat[PTR Format service._tcp.zone to instance._type.]

    PTRFormat --> Check3[No other RRs in Update Section]

    Check3 --> Valid[Valid ServiceDiscovery]
    Check3 -->|Extra RRs| Invalid[RCODE REFUSED Do not add other RR types]

    style Valid fill:#d4edda
    style Invalid fill:#f8d7da
```

### ServiceDescription RFC 9665 3.3.1.2

```mermaid
flowchart LR
    Start[ServiceDescription Instruction] --> DeleteAll[DeleteAll RRs for service name]

    DeleteAll --> CheckKey{KEY RR Present Optional}
    CheckKey -->|Yes| KeyFormat[KEY with flags equals 0 protocol equals 3 DH key]
    CheckKey -->|No| CheckSrv

    KeyFormat --> CheckSrv{SRV RR Present}

    CheckSrv -->|Yes| SrvCheck[SRV target matches hostname]
    CheckSrv -->|No| CheckTxt

    SrvCheck --> CheckTxt[TXT RR present or delete all]

    CheckTxt --> Valid[Valid ServiceDescription]

    style Valid fill:#d4edda
```

### HostDescription RFC 9665 3.3.1.3

```mermaid
flowchart LR
    Start[HostDescription Instruction] --> DeleteAll[DeleteAll RRs for hostname]

    DeleteAll --> CheckKey[Exactly 1 KEY RR required]

    CheckKey -->|Missing| Invalid1[RCODE REFUSED Host Description requires KEY]
    CheckKey -->|Multiple| Invalid2[RCODE REFUSED Exactly one KEY per HostDescription]
    CheckKey -->|Valid count| KeyFormat[KEY with flags equals 0 protocol equals 3]

    KeyFormat --> CheckAddr{A AAAA RRs Optional}
    CheckAddr -->|Yes| AddrCheck[IP address format valid]
    CheckAddr -->|No| Valid

    AddrCheck --> Valid[Valid HostDescription]

    style Valid fill:#d4edda
    style Invalid1 fill:#f8d7da
    style Invalid2 fill:#f8d7da
```

## TTL Consistency Check RFC 9665 4

```mermaid
flowchart TD
    Start[Validate TTLs] --> GroupByOwner[Group RRs by owner name]

    GroupByOwner --> CheckTTL{All RRs in set have same TTL}

    CheckTTL -->|Yes| NextSet[Next RR Set]
    CheckTTL -->|No| Err[TTL inconsistency detected RCODE REFUSED per RFC 9665 4]

    NextSet -->|More sets| CheckTTL
    NextSet -->|Done| Valid[TTL consistency verified]

    style Err fill:#f8d7da
    style Valid fill:#d4edda

    note1[Example TTL mismatch PTR for service._tcp: 7200 7200 3600 REFUSED inconsistent]
    note1 -.-> Err
```

## Name Conflict Detection FCFS

```mermaid
flowchart TD
    Start[Check FCFS name] --> CheckMemory{Name in memory store}

    CheckMemory -->|Yes| CheckKey{Same public key RFC 9665 3.2.4.1}
    CheckMemory -->|No| NameAvailable

    CheckKey -->|Yes| AlreadyOwned[Update allowed same owner]
    CheckKey -->|No| YXDomain

    NameAvailable --> GenerateName[Generate name preferred.default.service.arpa.]

    YXDomain --> TryAlt[Try alternate name preferred-N.default.service.arpa.]
    TryAlt --> CheckMem2{New name in store}

    CheckMem2 -->|Yes| Increment
    CheckMem2 -->|No| NameAssigned

    Increment[Increment N] --> CheckMem2

    GenerateName --> Assign[Assign name to update]
    AlreadyOwned --> Assign
    NameAssigned --> Assign

    Assign --> Proceed[Proceed with update]

    style YXDomain fill:#f8d7da
    style NameAvailable fill:#d4edda
```

## Complete Validation Pipeline

```mermaid
flowchart TD
    subgraph "Server Receive Phase"
        direction LR
        Rcv[TCP receive buffer] --> Parse[Parse DNS message]
        Parse --> ExtractLease[Extract Update Lease OPT]
    end

    subgraph "Signature Validation"
        direction TB
        VerifySig[Verify SIG0 TSIG Using miekg dns SIG0Verify]
        VerifySig -->|Success| ValOpt[Validate lease options]
        VerifySig -->|Fail| ErrAuth[RCODE REFUSED]
    end

    subgraph "Instruction Processing"
        direction LR
        ValOpt --> ParseInst[Parse instructions]
        ParseInst --> ValidateEach[Validate each instruction type]

        ValidateEach --> TTLCheck[TTL consistency check]
        TTLCheck --> FCFS[FCFS name generation]
    end

    subgraph "Forward to DNS"
        direction LR
        FCFS --> CheckZone[Zone exists]
        CheckZone -->|No| ErrZone[RCODE NOTZONE]

        CheckZone --> ForwardUpdate[Forward to BIND 9 via dnsif]
        ForwardUpdate --> RcvRcode[Receive RCODE from BIND]
    end

    subgraph "Response Building"
        direction LR
        RcvRcode --> AddLeaseOpt[Add granted leases to OPT]
        AddLeaseOpt --> SendResp[Send response to client]
    end

    style ErrAuth fill:#f8d7da
    style ErrZone fill:#f8d7da
    style SendResp fill:#d4edda
```
