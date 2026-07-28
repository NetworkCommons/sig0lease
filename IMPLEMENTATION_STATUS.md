# sig0lease Implementation Status

## Scope

sig0lease handles SIG(0)-authenticated DNS UPDATE requests with UPDATE-LEASE semantics and forwards accepted changes to the authoritative server for the configured upstream zone.

## Current Protocol Behavior

1. Signature verification
- UPDATE requests must carry a valid SIG(0).
- The signer key must be at or above the leased FQDN hierarchy.
- Verification uses authoritative DNS as the primary source for signer key resolution.
- If authoritative DNS cannot be reached for signer-key lookup, the request fails.
- If authoritative DNS is reachable but returns no matching signer KEY, lease-store key material may be used as fallback.

2. KEY RR in UPDATE section
- KEY RR in the UPDATE section is optional.
- If KEY RR is present, it must be complete (no header-only KEY accepted).
- Multiple KEY RRs in one request are rejected.

3. Lease matrix handling
- KEY-LEASE != 0, LEASE != 0:
  - KEY RR and at least one non-KEY RR are required.
  - KEY and non-KEY records are handled as registration-or-refresh per record.
- KEY-LEASE == 0, LEASE != 0:
  - At least one non-KEY RR is required.
  - KEY must already exist authoritatively at the lease FQDN.
- KEY-LEASE == 0, LEASE == 0:
  - Deletes requested KEY and/or non-KEY records.
  - Empty delete requests are rejected.
- KEY-LEASE != 0, LEASE == 0:
  - KEY RR is required.
  - KEY is registered/refreshed; non-KEY records are treated as delete intent.

4. Duplicate registration policy
- Duplicate registration attempts are handled per record (partial success mode).
- If a record is already present authoritatively and not currently managed in active lease state, that specific registration is skipped.
- Remaining records in the same request continue processing.

5. Delete behavior
- Delete operations are idempotent at proxy state level.
- Missing local records do not force whole-request failure.

## Storage Model

1. KEY lease storage
- KEY lease state is tracked per canonical key name in the lease manager.

2. Non-KEY lease storage
- Non-KEY records are tracked individually under each key owner.
- Record identity includes full RR presentation (including TTL).
- Records that differ in any field are treated as distinct records.

## Authoritative Forwarding

1. Target resolution
- The proxy resolves the effective authoritative zone and SOA MNAME and forwards UPDATE there.

2. Upstream signing
- Forwarded UPDATE messages are signed with the proxy upstream key.

## Test Layout

1. Unit tests
- Unit tests remain next to packages (for example in handlers and pkg).

2. Integration tests
- Integration scripts and integration helpers are under tests.
- The blacklisted type helper is now at tests/blacklisted_tester.go.

## Client Behavior

1. Lease adoption from server response
- Client expiry calculations now adopt server-returned UPDATE-LEASE values when present.
- If no lease option is returned, client falls back to requested lease duration.

## Cleanup Scope (Current PR)

1. Removed obsolete top-level DNS message helpers
- Deleted legacy top-level dnsmsg package (`dnsmsg/dnsmsg.go`).
- Active code uses pkg/dnsmsg instead.

2. Removed obsolete test utility command
- Deleted cmd/simpledig.
- Integration scripts now use system dig directly.

3. Reduced client surface to active usage
- Removed unused query helper APIs from client/client.go.
- Kept the minimal Query path used by current proxy/client workflows.

4. Unified SIG(0) signing API
- Replaced client-level SIG(0) signer wrapper usage with direct pkg/sig0 signing calls.
- Removed redundant signer wrapper implementation from client/sig0.go.
