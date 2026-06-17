# Authentication Paths SIG0 vs TSIG

## Overview
This diagram compares the two authentication paths per RFC 2931 and RFC 8945.

```mermaid
flowchart TD
    Start[DNS Update Message] --> ChooseAuth{Authentication Method}

    %% SIG0 Path
    ChooseAuth -->|SIG0| Sig0Start[Signal RFC 2931]
    Sig0Start --> Sig0KeyStore[Retrieve key from KeyStore]

    subgraph "SIG0 Details"
        direction TB
        Sig0Sign[Compute signature over message plus SIG RR header]
        Sig0Add[Insert SIG RR in Additional section]
        Sig0Verify[Verify Recompute hash compare signatures]
    end

    ChooseAuth -->|TSIG| TsigStart[Signal RFC 8945]
    TsigStart --> TsigKeyStore[Retrieve shared secret key]

    subgraph "TSIG Details"
        direction TB
        TsigHash[Compute HMAC SHA256 over message plus MAC in header]
        TsigAdd[Insert TSIG RR with MAC]
        TsigVerify[Verify Recompute HMAC compare MACs]
    end

    %% SIG0 Algorithm Requirements RFC 9665 6.6
    Sig0KeyStore --> ED2551[ED25519 REQUIRED MUST implement RFC 8032 RFC 9665 for sig0namectl compatibility]
    Sig0KeyStore --> OtherAlgos[Other algorithms Optional SHOULD support]

    %% BIND 9 Support
    Sig0Add --> BindSupportSIG0[BIND 9 supports SIG0 Yes via update-policy rules]
    TsigAdd --> BindSupportTsig[BIND 9 supports TSIG Yes via key plus allow-update-key]

    %% Error Handling
    Sig0Verify -->|Success| ProcessUpdate[Process DNS Update]
    Sig0Verify -->|Failure| RejectSig0[RCODE REFUSED]

    TsigVerify -->|Success| ProcessUpdate
    TsigVerify -->|Failure| RejectTsig[RCODE NOTAUTH]

    style ChooseAuth fill:#fff4e6
    style ED25519 fill:#d4edda
    style BindSupportSIG0 fill:#cce5ff
    style BindSupportTsig fill:#cce5ff
```

## Message Structure Comparison

```mermaid
graph LR
    subgraph "SIG0 RFC 2931"
        S1[DNS Header]
        S2[Question Section]
        S3[Answer Section empty for updates]
        S4[Authority Section empty for updates]
        S5[Additional Section]
        S6[SIG RR in Additional]
    end

    subgraph "TSIG RFC 8945"
        T1[DNS Header]
        T2[Question Section]
        T3[Answer Section]
        T4[Authority Section]
        T5[Additional Section]
        T6[TSIG RR in Additional]
    end

    S5 --> S6
    T5 --> T6

    noteSIG[SIG0 signs Entire DNS message Includes all sections Uses Hash algorithm SHA256 Public private key pair]
    noteTsig[TSIG uses HMAC SHA256 Shared secret key Signs Message plus MAC field Includes timestamps]

    noteSIG -.-> S6
    noteTsig -.-> T6
```

## Key Management Comparison

```mermaid
flowchart TD
    subgraph "SIG0 Per Client Keys"
        K1[Each client has own key pair]
        K2[Public key in DNS KEY RR private key with client]
        K3[Server validates using zones public keys]
    end

    subgraph "TSIG Shared Secrets"
        K4[Shared secret between client server]
        K5[Key named stored on both sides]
        K6[BIND 9 configured in named.conf]
    end

    K1 --> K2
    K2 --> K3
    K4 --> K5
    K5 --> K6

    style K1 fill:#d4edda
    style K4 fill:#f8d7da
```

## Code Flow sig0lease Implementation

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant Bind as BIND 9

    Note over C S: Choosing authentication method
    C->>S: Config specifies auth_method SIG0 or TSIG

    alt SIG0 mode recommended per RFC 9665
        Note over C: Use codeberg.org/miekg/dns v2 CryptoSIG0 interface with ED25519 per RFC 8032

        C->>C: Load private key from PEM file
        C->>C: Build DNS Update message
        C->>Bind: Send update may pass through S as proxy
        Bind-->>C: RCODE response
    else TSIG mode fallback
        Note over C: Use codeberg.org/miekg/dns v2 TSIG with HMAC SHA256

        C->>C: Compute HMAC SHA256 over message
        C->>Bind: Send update with TSIG RR
        Bind-->>C: RCODE response plus TSIG in reply
    end
```

## Security Properties Comparison

| Property | SIG0 | TSIG |
|----------|------|------|
| Key type | Asymmetric ECDSA RSA | Symmetric shared secret |
| Key distribution | Public key in DNS private key with client | Shared out-of-band |
| Replay protection | Validity window plus signature | Timestamps plus MAC |
| Non-repudiation | Yes signature cant be forged | No shared secret |
| BIND 9 config | update-policy local or named rules | key name secret |
| RFC requirement | RFC 9665 6.6 MUST implement ED25519 per RFC 8032 for sig0namectl compatibility | RFC 8945 Optional |

## Recommended Approach for sig0lease

Per the project docs and RFC requirements:

1. **Primary**: SIG0 with ED25519 per RFC 8032
   - Required by RFC 9665 §6.6 for sig0namectl compatibility
   - Better security properties asymmetric non-repudiation
   - Public keys can be distributed via DNS

   Note: ED25519 (algorithm 15) is used instead of ECDSAP256SHA256 (algorithm 13)

2. **Fallback Alternative**: TSIG with HMAC SHA256
   - Supported for compatibility
   - Simpler key management in some deployments
   - Referenced in RFC 9665 7 TLS alternatives

3. **Implementation pattern**:
```go
// Use miekg/dns CryptoSIG0 interface
signer := &dns.CryptoSIG0{
    CryptoSigner: privateKey,
    PublicKey:    keyRecord,
}

err := dns.SIG0Sign(msg, signer, &dns.SIG0Option{})
```
