# SRP Lease Refresh Flow

## Overview
This diagram shows the lease refresh mechanism per RFC 9664 5 and RFC 9665 5.

```mermaid
sequenceDiagram
    participant Client as SRP Client
    participant Server as SRP Proxy Server
    participant DNS as Authoritative DNS

    Note over Client: RFC 9664 5.2 Refresh at 80 percent of LEASE plus jitter 0-5 percent

    %% Initial Registration setup context
    Client->>Server: Full Registration as in registration flow diagram
    Server-->>Client: Granted LEASE equals 7200 KEY-LEASE equals 1209600

    Client->>Client: Schedule refresh timer<br/>t equals 80 percent times 7200 plus random 0-5 percent<br/>t equals 5760 plus approximately 288 seconds

    Note over Client: Wait for refresh timer to expire...

    %% Refresh Trigger
    Client->>Client: Timer expired Start refresh sequence

    %% Step 1: Build Refresh Message
    Client->>Client: Construct DNS Update Message<br/>Zone Section SOA record for zone<br/>Update Section No RRs leaving existing records<br/>Additional EDNS Update Lease OPT LEASE equals current lease value KEY-LEASE equals current key lease value

    %% Step 2: Sign and Send
    alt SIG0 Authentication
        Client->>Client: Compute SIG0
        Client->>Server: DNS Update plus SIG0
    else TSIG Authentication
        Client->>Client: Compute TSIG
        Client->>Server: DNS Update plus TSIG
    end

    %% Step 3: Server Processing
    Server->>Server: Validate signature
    alt Invalid
        Server-->>Client: RCODE REFUSED
    else Valid
        Server->>Server: Extract Update Lease OPT
        Server->>Server: Check current lease status
        alt Record expired lease exceeded
            Note right of Server: Records not found or expired<br/>Treat as new registration
            Server->>DNS: Forward update records removed
            DNS-->>Server: RCODE equals NOERROR
            Server->>Server: Generate new leases
            Server-->>Client: RCODE equals NOERROR plus New LEASE KEY-LEASE OPT
        else Record valid
            Server->>Server: Update lease timers in memory
            Note right of Server: Extend to new grant from client<br/>or same values if coalescing

            alt Coalesce with pending refresh
                Note over Client Server: Multiple clients Refreshing same records may be coalesced RFC 9664 5.2.1
            end

            Server-->>Client: RCODE equals NOERROR plus Updated LEASE KEY-LEASE OPT
            Client->>Client: Reschedule next refresh 80 percent of NEW lease plus jitter
        end
    end
```

## Coalesced Refreshes Multiple Clients

```mermaid
sequenceDiagram
    participant Client1 as SRP Client 1
    participant Client2 as SRP Client 2
    participant Server as SRP Proxy Server

    Note over Client1 Server: Same service instance registered by multiple hosts

    Client1->>Server: T equals 0s Refresh request for service._tcp
    Client2->>Server: T equals 1s Refresh request for service._tcp

    alt Coalescing enabled
        Server->>Server: Queue refresh requests
        Note over Server: Wait for coalesce window e.g. 500ms<br/>Merge identical refreshes

        Server->>DNS: Single DNS Update merged
        DNS-->>Server: Response
        Server-->>Client1: Response with granted lease
        Server-->>Client2: Response with granted lease
    else Coalescing disabled
        Server->>DNS: Update for Client1
        DNS-->>Server: Response
        Server-->>Client1: Response

        Server->>DNS: Update for Client2
        DNS-->>Server: Response
        Server-->>Client2: Response
    end
```

## Remove-All LEASE equals 0 Flow

```mermaid
sequenceDiagram
    participant Client as SRP Client
    participant Server as SRP Proxy Server
    participant DNS as Authoritative DNS

    Note over Client Server: RFC 9665 3.2.5.5.1 Remove All

    Client->>Client: Build Update Message<br/>Update Lease OPT LEASE equals 0 immediate removal KEY-LEASE equals 0 or reduced value<br/>Update Section DeleteAll for hostname service records

    Client->>Server: DNS Update plus SIG0
    Server->>Server: Validate signature
    alt Invalid
        Server-->>Client: RCODE REFUSED
    else Valid
        Server->>DNS: Forward remove-all update
        DNS-->>Server: RCODE equals NOERROR
        Server->>Server: Remove from lease tracking table
        Server-->>Client: RCODE equals NOERROR
        Note right of Client Server: All service records for this hostname<br/>removed from DNS zone
    end
```

## Lease Expiration and Garbage Collection

```mermaid
sequenceDiagram
    participant Server as SRP Proxy Server
    participant DNS as Authoritative DNS

    Note over Server: Background garbage collection per RFC 9664 7

    Server->>Server: Scan lease tracking table
    alt Record with expired LEASE
        Server->>DNS: Send delete update for service records
        DNS-->>Server: RCODE equals NOERROR
        Server->>Server: Remove from memory tracking
        Note right of Server: Service no longer serves
    else Record with expired KEY-LEASE but valid LEASE
        Server->>DNS: Delete KEY record only
        DNS-->>Server: RCODE equals NOERROR
        Server->>Server: Mark as pending removal
    end

    Note over Server: TTL Consistency RFC 9665 4
    Server->>Server: Verify all records in zone have matching TTLs<br/>Mismatch REFUSED on next update attempt
```
