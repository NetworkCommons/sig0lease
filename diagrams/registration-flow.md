# SRP Registration Flow - Client to Server to DNS

## Overview
This diagram shows the complete SRP registration flow per RFC 9665 3.2.5 (Client) and 3.3 (Server Validation).

```mermaid
sequenceDiagram
    participant Client as SRP Client pkg srp client
    participant Server as SRP Proxy Server pkg srp server
    participant DNS as Authoritative DNS BIND 9 dnsif bind9

    Note over Client Server: RFC 9665 3.2.5 Registration
    Note over Server DNS: RFC 2136 DNS Update

    %% Connection Setup
    Client->>Server: TCP Connect to SRP port RFC 9665 7

    %% Step 1: Build Update Message
    Client->>Client: Construct DNS Update Message<br/>Zone Section SOA record for zone<br/>Update Section PTR RR ServiceDiscovery<br/>KEY RR HostDescription<br/>SRV TXT RRs ServiceDescription
    Client->>Client: Add EDNS Update Lease OPT LEASE equals requested lease time

    %% Step 2: Sign Message
    alt SIG0 Authentication RFC 2931
        Client->>Client: Compute SIG0 over message
        Note right of Client: Hash SHA256 RFC 8624<br/>Algorithm ED25519 per RFC 8032 for sig0namectl compatibility
        Client->>Server: DNS Update Message plus SIG0 RR
    else TSIG Authentication RFC 8945
        Client->>Client: Compute TSIG HMAC SHA256 over message
        Client->>Server: DNS Update Message plus TSIG RR
    end

    %% Step 3: Server Validation
    Server->>Server: 1. Parse DNS Update Message
    Server->>Server: 2. Validate SIG0 TSIG Signature
    alt Invalid Signature
        Server-->>Client: RCODE REFUSED plus Error message
        Client->>Client: Handle error may retry
    else Valid Signature
        Server->>Server: 3. Check Update Lease OPT present
        alt No Update Lease
            Server-->>Client: RCODE REFUSED
        else Lease Present
            Server->>Server: 4. Validate LEASE less than or equal to KEY-LEASE RFC 9665 3.3.2
            alt Invalid order
                Server-->>Client: RCODE REFUSED
            else Valid order
                Server->>Server: 5. Validate Instructions RFC 9665 3.3.1<br/>ServiceDiscovery Exactly 1 PTR RR<br/>ServiceDescription DeleteAll plus KEY SRV TXT<br/>HostDescription DeleteAll plus exactly 1 KEY

                alt Validation Failed
                    Server-->>Client: RCODE REFUSED
                else All Valid
                    Server->>Server: 6. Check Prerequisites empty RFC 9665 3.2.3 SRP has none

                    %% Step 4: FCFS Name Generation
                    Server->>Server: 7. Generate Finalize hostname FCFS per RFC 9665 3.2.4.1

                    alt Name Conflict YXDOMAIN
                        Server-->>Client: RCODE YXDOMAIN plus Recommended name in Additional
                        Client->>Client: Retry with alternate name
                    else No Conflict
                        %% Step 5: Forward to DNS Server
                        Server->>DNS: Send DNS Update signed
                         Note right of Server DNS: Uses codeberg.org/miekg/dns v2 Client.SendUpdate

                        DNS-->>Server: Response RCODE

                        alt DNS Update Failed
                            Server-->>Client: RCODE REFUSED
                        else Success
                            %% Step 6: Send Response with Lease OPT
                            Server->>Server: Set granted LEASE and KEY-LEASE may differ from requested
                            Server->>Server: Add Update Lease OPT to response
                            Server-->>Client: RCODE NOERROR plus Granted leases in OPT

                            %% Step 7: Client Schedules Refresh
                            Client->>Client: Schedule refresh at<br/>80 percent of LEASE plus jitter 0-5 percent RFC 9664 5.2
                        end
                    end
                end
            end
        end
    end
```

## Message Structure Reference

```
DNS Update Message RFC 1035 RFC 2136:
+---------------------+
| Header              | ID flags opcode equals UPDATE
+---------------------+
| Question Section    | Zone apex SOA query
+---------------------+
| Answer Section      | empty for updates
+---------------------+
| Authority Section   | empty for updates
+---------------------+
| Additional Section  | - Update Lease OPT EDNS0 opt equals 2<br/>- SIG0 or TSIG RR
+---------------------+

Update Section RRs:
- ServiceDiscovery: PTR instance._service._tcp.zone
- HostDescription: KEY [A] [AAAA]
- ServiceDescription: DeleteAll, [KEY], SRV, TXT
```

## Error Codes per RFC

| RCODE | Meaning | When it occurs |
|-------|---------|----------------|
| REFUSED | Server failure or invalid request | Invalid signature missing lease validation error |
| YXDOMAIN | Name exists when it should not | FCFS conflict detection |
| NOTAUTH | Not authoritative | Server not auth for zone |
