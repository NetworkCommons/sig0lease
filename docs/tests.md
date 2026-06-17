# sig0lease — Test Plan

This document describes the unit tests and end-to-end (integration) tests for the sig0lease project. Tests are organized by package to match the architecture in `architecture.md`. Each test entry cites the RFC section it validates.

---

## 1. Unit Tests

Unit tests exercise individual packages in isolation, using in-memory objects and pre-generated keys from `testdata/keys/`. No external processes (BIND 9, DNS resolvers) are started.

### 1.1 `pkg/lease` — Update Lease Option

| # | Test name | What it validates | RFC reference |
|---|-----------|-------------------|---------------|
| L-01 | `TestEncode4Byte` | Encode LEASE=7200 to OPT RR (4-byte variant). Verify option-code=2, length=4, bytes match big-endian u32. | 9664 §4, Table 1 |
| L-02 | `TestEncode8Byte` | Encode LEASE=7200 + KEY-LEASE=1209600 (14 days). Verify option-code=2, length=8, both fields correct. | 9664 §4 |
| L-03 | `TestDecode4Byte` | Decode a 4-byte LEASE option from a crafted OPT RR → verify struct matches. | 9664 §4 |
| L-04 | `TestDecode8Byte` | Decode an 8-byte LEASE + KEY-LEASE option. | 9664 §4 |
| L-05 | `TestDecode_Truncated` | Feed fewer bytes than OPTION-LENGTH declares → expect error. | 9664 §4 (format) |
| L-06 | `TestDecode_WrongOptionCode` | OPTION-CODE ≠ 2 → expect error or skip. | 9664 §3 (EDNS mechanism) |
| L-07 | `TestLeaseKeyOrdering` | `Validate(LEASE, KEY-LEASE)` with LEASE > KEY-LEASE → expect invalid per RFC 9665 §3.3.2. | 9665 §3.3.2 |
| L-08 | `TestLeaseMinValues` | LEASE=0 and KEY-LEASE=0 → valid encode but should be flagged by server as below minimum. | 9664 §8 (min 30s) |

**Framework**: `testing` with property-based fuzzing via `quick.Check` or `github.com/stretchr/testify/require` for assertions.

### 1.2 `pkg/keyrec` — KEY Record

| # | Test name | What it validates | RFC reference |
|---|-----------|-------------------|---------------|
| K-01 | `TestRoundTrip` | Create KeyRecord, encode to `*dns.KEY`, decode back → identical fields. | 2539, 4034 §4 |
| K-02 | `TestZeroFlagsSRP` | Flags=0 encodes correctly; flags≠0 is valid wire format but flagged for SRP use. | 9665 §3.2.5.1 |
| K-03 | `TestNilPublicKey` | Decode with empty PublicKey → expect error or nil check on access. | 2539 §3 |
| K-04 | `TestAlgorithmMapping` | Algorithm=15 (ED25519 per RFC 8032) maps to correct digest type. | 8624 §3.1 |

### 1.3 `pkg/sig0` — SIG(0) Signing & Verification

| # | Test name | What it validates | RFC reference |
|---|-----------|-------------------|---------------|
| S-01 | `TestSignVerifyRoundTrip` | Sign a DNS message with host1's key → verify succeeds with public key. | 2931 §4 |
| S-02 | `TestVerifyWrongKey` | Verify with host2's public key → expect error. | 2931 §5 |
| S-03 | `TestVerifyTamperedMsg` | Sign message, modify one RRSIG-bearing RR after signing → verify fails. | 2931 §5 |
| S-04 | `TestVerifyExpiredSIG` | Set SIG validity window in the past → verify rejects. | 2931 §5 (time window) |
| S-05 | `TestVerifyPreValidSIG` | Set SIG validFrom > time of verification → reject as not-yet-valid. | 2931 §5 |
| S-06 | `TestAlgorithm_ED25519` | Algorithm=15 (ED25519 per RFC 8032) always accepted (MUST for sig0namectl compatibility). | 9665 §6.6 |
| S-07 | `TestTSIG_HMAC_SHA256` | Sign/verify using TSIG with HMAC-SHA256 as alternative auth path. | 8945 |
| S-08 | `TestVerify_MACMismatch` | Verify with truncated/wrong MAC → expect failure. | 2931 §5 |

**Key material**: Use `testdata/keys/host1.pem` / `testdata/keys/host2.pem`. Each file contains a PKCS#8 ECDSA P-256 private key; extract the public key via `x509.ParsePKIXPublicKey()`.

### 1.4 `pkg/srp/instruction` — Instruction Construction

| # | Test name | What it validates | RFC reference |
|---|-----------|-------------------|---------------|
| I-01 | `TestHostDescription_Valid` | Build HostDescription with one KEY + one AAAA → assemble into DNS Update msg. Verify Zone section is correct. | 9665 §3.3.1.3 |
| I-02 | `TestServiceDiscovery_Valid` | Build ServiceDiscovery with one PTR → verify RR type and owner name format `_svc._tcp.<zone>`. | 9665 §3.3.1.1 |
| I-03 | `TestServiceDescription_Valid_NoSRV` | Build ServiceDescription without SRV (delete-only or existing-key path). | 9665 §3.3.1.2 |
| I-04 | `TestServiceDescription_Valid_WithSRV` | Build with SRV + TXT, verify SRV target matches hostname from HostDescription. | 9665 §3.3.1.2 |
| I-05 | `TestMissingKEY_Rejected` | Attempt to build HostDescription without KEY → expect error. | 9665 §3.3.1.3 (exactly one KEY) |
| I-06 | `TestExtraRRType_Rejected` | Build update with CNAME RR in ServiceDescription → expect rejection. | 9665 §3.3.1.2 ("do not add other RR types") |
| I-07 | `TestPrerequisitePresent_Rejected` | Attempt to construct update with prerequisite RRs → reject (SRP has no prerequisites). | 9665 §3.2.3, §3.3.2 |
| I-08 | `TestCompression_SRVTarget` | Build SRV record with compressed target → verify wire format is valid per RFC 9665 §3.2.5.4. | 9665 §3.2.5.4 |
| I-09 | `TestMultiplePTRs` | Build update with PTR for same service type + different subtypes → all valid ServiceDiscovery Instructions. | 9665 §3.3.1.1 (subtype) |

### 1.5 `pkg/srp/names` — FCFS Naming

| # | Test name | What it validates | RFC reference |
|---|-----------|-------------------|---------------|
| N-01 | `TestPreferredAvailable` | Preferred name "myhost" in empty store → returns "myhost.default.service.arpa." with no conflict. | 9665 §3.2.4.1 |
| N-02 | `TestConflictIncrement` | Name taken → returns "myhost-1.default.service.arpa." (or next available). | 9665 §3.2.5.2 |
| N-03 | `TestConflictMultiple` | Names "myhost", "myhost-1" taken → returns "myhost-2". | 9665 §3.2.5.2 |
| N-04 | `TestRefusedStopsIncrement` | Name blocked by dictionary (returns Refused RCODE) → expect error without infinite loop. | 9665 §6.3 (dictionary recommendation) |

### 1.6 `pkg/srp/server` — SRP Server Validation

| # | Test name | What it validates | RFC reference |
|---|-----------|-------------------|---------------|
| V-01 | `TestValidRegistration_NoError` | Full valid update → RCODE=NoError, response contains Update Lease option with granted lease. | 9665 §3.3.2, §3.3.5 |
| V-02 | `TestNameConflict_YXDomain` | Duplicate name with different KEY → YXDomain RCODE. | 9665 §3.3.3 |
| V-03 | `TestMissingUpdateLease_Refused` | Update without EDNS Update Lease option → Refused RCODE. | 9665 §3.3.2 ("MUST include") |
| V-04 | `TestLEASE_GT_KEYLEASE_Refused` | LEASE > KEY-LEASE in Update Lease → reject as invalid SRP update. | 9665 §3.3.2 |
| V-05 | `TestSIG_VerificationFail_Refused` | Update signed with wrong key → Refused RCODE. | 9665 §3.3.3 ("reject … with Refused") |
| V-06 | `TestTTLInconsistency_Refused` | PTR RRset with inconsistent TTLs across records within same instruction → Refused. | 9665 §4 |
| V-07 | `TestNoHostDescription_Refused` | Update missing Host Description Instruction → not a valid SRP update → Refused or NotAuth. | 9665 §3.3.2 ("MUST contain exactly one") |
| V-08 | `TestTSIG_Accepted` | Valid TSIG-authenticated update → NoError (alternative auth path). | 8945 (TSIG) |
| V-09 | `TestLease_ExpiryAndGC` | Insert record with short lease, fast-forward time → record garbage collected and no longer served. | 9664 §7 |
| V-10 | `TestRemoveAll_LifetimeZero` | Update with LEASE=0 for one HostDescription → all services + PTRs removed for that hostname. | 9665 §3.2.5.5.1 |

### 1.7 `pkg/srp/client` — SRP Client Behavior

| # | Test name | What it validates | RFC reference |
|---|-----------|-------------------|---------------|
| C-01 | `TestRegister_HappyPath` | Register service → send valid update, parse NoError response, extract granted leases. | 9665 §3.2.5 |
| C-02 | `TestRegister_RefreshSchedule` | Verify refresh timer fires at correct time: 80% of lease + jitter(0–5%). | 9664 §5.2 |
| C-03 | `TestYXDomain_RetryName` | Server returns YXDomain → client generates alternate name, retries registration. | 9665 §3.2.5.2 |
| C-04 | `TestServerUnresponsive_Retry` | No response within timeout → retry with backoff (RFC 9664 §5.2/§6 guidance). | 9664 §5.2, §6 |
| C-05 | `TestCoalesceRefreshes` | Multiple registrations coalesced into single refresh request. | 9664 §5.2.1 |
| C-06 | `TestHonourServerLease` | Server grants shorter/longer lease → client uses granted values for next refresh schedule. | 9664 §4.2, §5.2 |

### 1.8 `pkg/discovery` — Registrar Discovery

| # | Test name | What it validates | RFC reference |
|---|-----------|-------------------|---------------|
| D-01 | `TestSOAZoneApex` | Walk parent zones via SOA query → discover zone apex for "myhost.example.com." → "example.com.". | 8765 §6.1 |
| D-02 | `TestSRVDiscovery_dnssdSrp` | Query `_dnssd-srp._tcp.<zone>.` → returns registrar address:port. | 9665 §3.1.1 |
| D-03 | `TestSRVDiscovery_dnssdSrpTls` | Query `_dnssd-srp-tls._tcp.<zone>.` → TLS-enabled registrar found. | 9665 §3.1.1 |

---

## 2. End-to-End (Integration) Tests

These tests spin up a real BIND 9 authoritative server (via `os/exec`) configured with the zone files from `testdata/zones/`. They verify the full SRP lifecycle: registrar discovery, service registration, lease refresh, conflict detection, and cleanup.

### 2.1 Setup / Teardown

Each integration test group:
1. **Before**: Write `testdata/bind.conf` + zone files to a temp directory. Spawn `named -c <tmpdir>/bind.conf -g &`.
2. **After**: Kill `named`, remove temp directory.
3. BIND 9 is started with the `default.service.arpa.` zone authoritative, configured to accept DNS updates (via `allow-update` or TSIG key).

### 2.2 E2E Test Cases

| # | Test name | What it validates | RFC reference |
|---|-----------|-------------------|---------------|
| E-01 | `TestFullRegistrationLifecycle` | Client registers `_ipps._tcp` service → BIND has AAAA + SRV + TXT + KEY + PTR records. Verify via dig/nslookup. | 9665 §3, RFC 6763 |
| E-02 | `TestLeaseRefresh_Succeeds` | Wait to 80% lease mark → client sends Refresh → BIND still serves the service. | 9664 §5 |
| E-03 | `TestLeaseExpiry_GarbageCollection` | Wait past lease duration → records are removed or not served. Verify via dig returning NXDOMAIN/nodata. | 9664 §7, 9665 §5.1 |
| E-04 | ` testNameConflict_FCFS` | Host A registers "myhost" → Host B tries same name with different key → BIND returns YXDomain (or update rejected by server validation). | 9665 §3.2.4.1, §3.3.3 |
| E-05 | `TestSIG0AuthPath` | Full register + refresh using SIG(0) / ED25519 per RFC 8032 → all operations succeed. | 2931, 9665 §6.6 |
| E-06 | `TestTSIGAuthPath` | Full register + refresh using TSIG / HMAC-SHA256 → all operations succeed on BIND side. | 8945 |
| E-07 | `TestRemoveAllServices` | Client sends LEASE=0 update → all service RRs for hostname disappear from BIND zone. | 9665 §3.2.5.5.1 |
| E-08 | `TestSubtypeManagement_Atomic` | Register service with subtypes A, B, C → send update without subtype B → subtype B removed atomically. | 9665 §3.3.4 |
| E-09 | `TestMultipleServices_OneHostname` | Client registers `_ssh._tcp`, `_ipps._tcp`, `_rfb._tcp` in one update → all three service instances + PTRs present. | 9665 §3.2.3 (combine multiple services) |
| E-10 | `TestKeyLeaseLonger_KeysPersist` | KEY-LEASE=14 days, LEASE=7200 → after LEASE expires but before KEY-LEASE, KEY records remain in zone. | 9665 §3.2.5.3, §3.2.5.5 |

### 2.3 E2E Assertions

For each test, assertions are performed against the running BIND 9 server using `dig` (or Go DNS queries to the authoritative port):

| Assertion type | Method |
|---|---|
| Record existence | `dig @127.0.0.1 -p <port> <name> <type>` → AXFR or specific query returns expected RRset |
| Record absence | Same command → NXDOMAIN or NOERROR + empty ANSWER section |
| RCODE check | Check the Response RCODE field in the DNS response message |
| Update Lease in response | Parse OPT RR from BIND's update response → extract LEASE/KEY-LEASE fields |

### 2.4 Test Harness Code Structure

```
agent/
└── internal/
    └── testharness/              # E2E infrastructure (not a pkg — internal to tests)
        ├── bind.go               # Start/stop BIND 9 with temp config
        ├── zone_writer.go        # Write zone files to temp dir
        ├── dig.go                # Execute dig or query via miekg/dns client
        └── keygen.go             # Generate test keys at startup (or read from testdata)
```

These are `*_test.go` files that live in the relevant packages but use the harness helpers:

```go
// pkg/srp/server/e2e_test.go  (inside package — gets internal access)
func TestFullLifecycle(t *testing.T) {
    s := testharness.StartBIND9(t, "testdata/zones/default-service.arpa.zone")
    defer s.Stop()

    c := client.New("127.0.0.1:"+s.Port(), keyStoreFromTestdata("host1"))
    svc := &dns.SRV{...} // construct service description
    err := c.Register(context.Background(), "myhost", []*dns.Service{svc})
    require.NoError(t, err)

    // Assert records exist in BIND zone
    assertRecordExists(t, s.Addr, "myhost.default.service.arpa.", dns.TypeAAAA)
}
```

---

## 3. Test Coverage Goals

| Tier | Goal | Notes |
|------|------|-------|
| Unit tests (all packages) | ≥ 80% line coverage | Protocol correctness is critical; missing coverage = undefined behavior risk |
| E2E tests (key scenarios from §2.2) | All E-01 through E-10 pass | Each test exercises a distinct RFC clause or protocol path |
| Fuzzing (optional, long-term) | `pkg/lease` and `pkg/sig0` via go-fuzz or quickcheck | Catch wire-format edge cases |

---

## 4. Test Data

All static fixtures live in `testdata/`:

| Path | Content |
|------|---------|
| `testdata/keys/host1.pem`, `host2.pem` | ECDSA P-256 key pairs (PKCS#8 private + PKIX public). Generated once via `openssl ecparam -genkey -name prime256v1`. |
| `testdata/zones/default-service.arpa.zone` | BIND zone file for the test SRP domain. Pre-populated with SOA, NS, _dnssd-srp SRV records. |
| `testdata/zones/reverse.zone` | PTR reverse mapping zone (optional, for §6.3 of RFC 9665). |
| `testdata/bind.conf` | Minimal BIND 9 config: `options { listen-on port 53; }; zone "default.service.arpa." { type master; file "..."; allow-update { key ...; }; };` |
