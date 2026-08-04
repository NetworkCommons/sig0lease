# Documentation Improvement Proposal

## 1 Protocol Definition

The UPDATE-LEASE extension to DNS (RFC 9664, draft version) is implemented via a custom EDNS option
(code 2, registered as ERFC3597) that carries lease information inside DNS UPDATE packets
(RFC 2136). This section describes how the proxy interprets these packets and what actions it takes.

### 1.1 UPDATE-LEASE EDNS Option Encoding

Clients include an UPDATE-LEASE option (EDNS option code 2) in their UPDATE packets. Two encodings
are supported:

- **8-byte variant (default):** 4 bytes encode the LEASE value (lease duration for non-KEY RRs),
  followed by 4 bytes encoding the KEY-LEASE value (lease duration for KEY RRs). Both are
  big-endian uint32 values. This is the default encoding and is used unless the configuration sets
  `prefer_4byte_variant` to true.
- **4-byte variant (optional, legacy):** 4 bytes encode only one LEASE value for both KEY and non-KEY RRs.
  This variant is provided for backward compatibility and it is off by default.

The values **LEASE** and **KEY-LEASE** control which records are affected by an UPDATE packet:

- **LEASE:** Controls the lease duration for non-KEY RRs (A, AAAA, TXT, MX, NS, CNAME, SRV, etc.).
  A value of 0 is a special case meaning "no data RR lease" (used in delete semantics, see Case C).
  Values must be ≥ {config}.min_rr_lease_sec (30 seconds recommended) or 0; values below 30 (but non-zero) are rejected.
- **KEY-LEASE:** Controls the lease duration for KEY RRs (RFC 2539 KEY records). A value of 0 is
  a special case meaning "no KEY lease" (used in delete semantics). Values must be ≥ {config}.min_key_lease_sec (30 seconds recommended) or 0.

The proxy determines which of four behavioral cases applies by inspecting the LEASE and KEY-LEASE
values:

| Case | KEY-LEASE | LEASE | Behavior | Description |
|---|---|---|---|---|
| A | Non-zero | Non-zero | Full Registration | Registers or refreshes both KEY RRs and non-KEY RRs together. This is the standard use case for registering a name with both cryptographic identity and data. |
| B | 0 | Non-zero | Data-Only Registration | Registers or refreshes non-KEY RRs only. The KEY RR is not registered (but must already exist from a prior registration). |
| C | 0 | 0 | Delete | Deletes KEY RRs, non-KEY RRs, or both, depending on what exists. This is the primary delete semantics. |
| D | Non-zero | 0 | KEY-Only Registration | Registers or refreshes KEY RRs only. Optionally deletes non-KEY RRs. This allows a client to register cryptographic identity without any associated data. |

For the delete matrix (Case C), if neither KEY nor non-KEY records are present in the Update section,
the request is treated as invalid.

The proxy iterates over all KEY RRs in the request (there may be multiple per FQDN) and dispatches
each to the appropriate case based on the KEY-LEASE and LEASE values from the UPDATE-LEASE option.

Additional constraints from prior protocol notes:

- The signer KEY used for SIG(0) verification and the KEY RR being registered/refreshed in the Update section can be different keys.
- Multiple KEY RRs can be present in the Update section.
- A KEY used only for signing should be in the Additional section; a KEY in the Update section is interpreted as a KEY intended for lease register/refresh/delete behavior.
- Prior strict matrix notes define Case A (KEY-LEASE!=0 and LEASE!=0) as requiring both a KEY RR and at least one non-KEY RR in Update.
- Prior strict matrix notes define Case B (KEY-LEASE==0 and LEASE!=0) as requiring at least one non-KEY RR, with signing KEY already managed; the signing KEY should not appear in Update for this case.

**Key lease ownership:** When a KEY RR is registered (Cases A and D), the KEY's public key material
becomes the "owner" key for all non-KEY AND KEY RRs registered by that same UPDATE packet (Case A) or
subsequently (Case B for just non-KEY RRs). This linkage is maintained in the lease store: each KEY lease record points
to a LeaseRecord, which tracks all KEY and non-KEY RRs registered under that KEY's name. The owner key is always the signing key (see further), and other KEY RRs if present become linked to that key. A key that has an owner key can be also the owner 
of other KEY or non-KEY RRs.

### 1.2 Key Retrieval and Authentication (Three-Stage Fallback)

When a request is received, the proxy first validates that the requester is authorized to modify a zone by verifying the SIG(0)
signature on the UPDATE packet. This validation uses a three-source key lookup chain to find the signing key:

- The signer key must be at or above the FQDN being modified (hierarchy check).

1. **Request KEY RR:** The proxy first checks if the UPDATE packet itself contains a KEY RR in
  the Update section (RFC 2136), or in the Additional section (RFC 2931). If found, the public key material from this KEY RR is used directly for signature verification.
2. **Authoritative DNS:** If no KEY RR is in the packet, the proxy queries the authoritative DNS
  server for the KEY RR at the requested name (falling back through parent zones if needed).
3. **Lease Store:** If authoritative DNS is reachable but no matching signer KEY is returned, the proxy looks up the KEY in
  its local lease store (which may have been populated by a previous registration).

Each stage's failure causes the proxy to attempt the next stage. If all three stages fail, the
UPDATE is rejected as unauthorized.

Additional constraints from prior protocol notes:

- If authoritative DNS cannot be reached for signer-key lookup, the request fails.
- If lease-store lookup also fails, signer key material must be present in the request (Update or Additional section), otherwise signature validation cannot succeed.

Post-verification signer state interpretation from prior notes:

- In-LeaseStore and at-FQDN: signer key is a managed key.
- In-LeaseStore and not at-FQDN: signer key is treated as externally removed and may need re-registration with remaining lease.
- Not In-LeaseStore and at-FQDN: signer key is treated as present outside lease management (permanent/out-of-band update).
- Not In-LeaseStore and not at-FQDN: signer key must come from the request itself, otherwise verification would not have succeeded.

The proxy supports multiple SIG(0) algorithms, including ED25519 (algorithm 15), which requires
a custom implementation bypassing the standard `dns.CryptoSIG0` path (since ED25519 does not
satisfy the hash function requirement of CryptoSIG0).


### 1.3 TTL Clamping

Before forwarding UPDATE packets to the authoritative server, the proxy clamps the TTL (Time-to-Live)
values on all records (both KEY and non-KEY RRs) to configured bounds:

- **LeasePolicy.MinKeyLease / MaxKeyLease:** Min and max TTL bounds for KEY RRs.
- **LeasePolicy.MinRRLease / MaxRRLease:** Min and max TTL bounds for non-KEY RRs.

If a record's TTL falls outside the configured range, the proxy adjusts it to the nearest boundary.
This prevents clients from requesting excessively high or low TTL values.

The same configured policy bounds are also applied to local non-zero LEASE and KEY-LEASE values before
writing lease state in the proxy store, so local lease timing and forwarded request policy share the
same bounded durations.

### 1.4 Blacklisted RR Types

The proxy maintains a configurable list of blacklisted RR types. Any UPDATE packet attempting to
register one of these RR types is rejected. The blacklist is parsed from the proxy's YAML
configuration file (under `handlers.update.blacklisted_types`).

### 1.5 Upstream Forwarding and Rollback

After validating and processing the UPDATE packet, the proxy:

1. Re-signs the UPDATE with its own SIG(0) key (the proxy's zone key for the zone) using the
   requester's KEY RRs to construct the authoritative section.
2. Forwards the signed UPDATE to the authoritative nameserver via UDP (with TCP fallback if
   needed for large responses).

**Rollback on failure:** If the upstream server rejects the UPDATE (returning a RCODE other than
NOERROR), the proxy rolls back **all** leases registered during this UPDATE — both KEY and non-KEY
records — and reports the failure to the client. This ensures the proxy's lease store never
contains orphaned or conflicting records that were never confirmed by the authoritative server.

If the proxy attemps to register a record that already exists in the DNS zone, the request must fail also in the parts that would be successful if performed alone, because the consistency of the LeaseStore cannot be guaranteed, especially in case of a KEY RR that already exists in the zone.
This implies that the proxy needs to verify whether in case of a registration, an identical record is already at the same FQDN.

For all attempts of deleting records, if the record does not exist in the lease-store, we assume the record is either outside our control, or it has been removed after expiry. The request does not fail but the user needs to be informed about this. If the record exists in the lease-store but not at the DNS, the request does not fail but the proxy must signal the situation. Missing local records do not force whole-request failure.

## 2 "Storage Model"

The proxy maintains lease information in a key-value store, which can be in-memory (currently) or on a database (in the future). The structure is a tree, rooted in a permanent fictitious node with the name of the zone. A tree should be created for each zone that the proxy administers, and all root nodes should be recorded as a dict zone-name -> root node. The children of the root node must necessarily be KEY nodes, and a KEY node can have for a parent another KEY node if it has been registered by that key. Only KEY nodes can have children.

The expiry of a KEY node at any level in this hierarchy triggers the expiry of all children recursively.

### 2.1 Storage Architecture

There should be two types of records, KEY and non-KEY, both as subclasses of a base record type.

BaseRecord

| Field | Type | Description |
|---|---|---|
| `Type` | `time.Time` | Type of the RR. |
| `ExpiresAt` | `time.Time` | When this lease expires (computed as `RegisteredAt + LeaseDuration`). |
| `LeaseDuration` | `uint32` | The lease duration in seconds, as provided by the client (or clamped by the proxy's LeasePolicy). |
| `RegisteredAt` | `time.Time` | When this lease was registered (wall clock time at registration). |
| `Parent` | `BaseRecord` | Pointer to the parent for completeness. |

KEYRecord in addition has
| `KeyRR` | `*dns.KEY` | The KEY RR (RFC 2539) registered for this lease. Contains the cryptographic public key used for authentication. |
| `Children` | List of `BaseRecord` | Pointer to the children. |


NonKEYRecord RRs
| Field | Type | Description |
|---|---|---|
| `RR` | `dns.RR` | The non-KEY resource record (A, AAAA, TXT, etc.). |

To facilitate lease management, a map can be created to quickly find records, such as `map[string]*BaseRecord` to map from RFC 2136 record keys (NAME + CLASS + TYPE + optional RDLENGTH+RDATA) to per-record entries.

Additional storage constraints:

- KEY lease state is tracked per canonical key name in the lease manager.
- Non-KEY records are tracked individually and linked to their owning key.
- Record identity follows RFC 2136 Section 1.1 comparison rules.
- Two different keys cannot register identical RRs as separate managed records.
- Records that differ in any comparison field are treated as distinct records.


# Flow Diagram (Textual)

Consider adding a brief flow diagram showing the processing pipeline:

```
Client UPDATE packet (with UPDATE-LEASE EDNS option)
  ↓
Validate SIG(0) signature
  ↓
Parse LEASE and KEY-LEASE values
  ↓
Extract KEY RRs and non-KEY RRs from UPDATE
  ↓
Determine behavioral case (A / B / C / D)
  ↓
Clamp TTL values (LeasePolicy)
  ↓
Check blacklisted RR types
  ↓
Register/update/delete in local lease store
  ↓
Sign and forward to authoritative server (SIG(0))
  ↓
  ┌───────────────────────────┐
  │ Upstream succeeds?        │
  │   Yes → Send success      │
  │          (with status notes │
  │           as TXT records)  │
  │   No  → Rollback all       │
  │         local leases       │
  │         Report error        │
  └───────────────────────────┘
  ↓
  Schedule chain deletion timer
  (on earliest lease expiry)
```

# Reference to Source Files

The implementation for all behaviors described in this section is located in
`handlers/opcode5.go` (file: `opcode5.go`, functions: `UpdateHandler.Handle()`,
`UpdateHandler.applyLeasePolicy()`, `UpdateHandler.extractUpdateRecords()`,
`UpdateHandler.constructUpstreamUpdate()`, `UpdateHandler.processExpiredLease()`).

The implementation for the storage model is located in `pkg/lease/state.go` (file: `state.go`,
structs: `Record`, `Manager`, `InMemoryManager`), and `handlers/opcode5.go` (file:
`opcode5.go`, struct: `DataLeaseRecord`, helper: `dataRecordEntry`).
