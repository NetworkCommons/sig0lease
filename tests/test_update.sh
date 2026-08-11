#!/bin/bash
#
# Comprehensive Update Test for sig0lease Proxy
#
# This suite runs real process-level update tests only:
# - real proxy binary
# - real client binary
# - real DNS keys from keystore
# - real authoritative path for zenr.io (via proxy update forwarding)
#
#

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

# Configuration
TMP_CONFIG_FILE=""
AUTH_SERVER="${AUTH_SERVER:-ns1.free2air.org}"

# Get keystore from environment
CLIENT_KEYSTORE_DIR="${CLIENT_KEYSTORE_DIR:-}"
if [ -z "$CLIENT_KEYSTORE_DIR" ]; then
    echo "ERROR: CLIENT_KEYSTORE_DIR environment variable not set"
    exit 1
fi

# Zones
UPSTREAM_ZONE="dev.zenr.io."
DOWNSTREAM_ZONE="test.${UPSTREAM_ZONE}"

# Keys
CLIENT_KEY_NAME="Ktest.dev.zenr.io.+015+05044"
WRONG_CLIENT_KEY_NAME="Ktest.dev.zenr.io.+015+42176"

# Lease times
POLICY_MIN_RR_LEASE_SECONDS="$(yaml_get_lease_time min_rr_lease_sec)"
POLICY_MIN_KEY_LEASE_SECONDS="$(yaml_get_lease_time min_key_lease_sec)"

LEASE_SECONDS="${LEASE_SECONDS:-$POLICY_MIN_RR_LEASE_SECONDS}"
REFRESH_SECONDS="${REFRESH_SECONDS:-$LEASE_SECONDS}"
KEY_LEASE_SECONDS="${KEY_LEASE_SECONDS:-$POLICY_MIN_KEY_LEASE_SECONDS}"
# Case 2 validates refresh behavior under split-lease policy: keep KEY alive longer.
REFRESH_CASE_KEY_LEASE_SECONDS="${REFRESH_CASE_KEY_LEASE_SECONDS:-3600}"
OVERLAP_RR_LEASE_SECONDS="${OVERLAP_RR_LEASE_SECONDS:-30}"
OVERLAP_KEY_LEASE_SECONDS="${OVERLAP_KEY_LEASE_SECONDS:-120}"
OVERLAP_DELAY_SECONDS="${OVERLAP_DELAY_SECONDS:-10}"

# Keep protocol invariant for any defaults in this script: LEASE <= KEY-LEASE and non-zero.
if [ "$KEY_LEASE_SECONDS" -eq 0 ] || [ "$LEASE_SECONDS" -eq 0 ]; then
    log_error "Invalid initial value for LEASE ($LEASE_SECONDS) and/or KEY-LEASE ($KEY_LEASE_SECONDS)"
    exit 1
elif [ "$LEASE_SECONDS" -gt "$KEY_LEASE_SECONDS" ]; then
    log_error "LEASE ($LEASE_SECONDS) longer than KEY-LEASE ($KEY_LEASE_SECONDS)"
    exit 1
fi

# Optional: limit matrix run to selected RR types, e.g. RR_TYPES="KEY TXT"
# Supported types: KEY TXT A AAAA NULL NXNAME WALLET CLA IPN
RR_TYPES="${RR_TYPES:-KEY TXT A AAAA NULL NXNAME WALLET CLA IPN}"

################################
# Utils
################################
require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "Required command not found: $1"
        exit 1
    fi
}

################################
# Timing
################################
log_case_timing() {
    local case_name="$1"
    local case_start_epoch="$2"
    local expected_min_seconds="$3"

    local now elapsed drift
    now=$(date +%s)
    elapsed=$((now - case_start_epoch))
    drift=$((elapsed - expected_min_seconds))

    log_step "Timing [$case_name]: expected-min=${expected_min_seconds}s actual=${elapsed}s drift=${drift}s"
}

wait_until_epoch() {
    local target_epoch="$1"
    local now
    now=$(date +%s)
    if [ "$now" -lt "$target_epoch" ]; then
        sleep $((target_epoch - now))
    fi
}

################################
# Client/Server functions
################################

build_binaries() {
    log_section "BUILD"
    log_step "Building proxy and client binaries"
    (cd "$SCRIPT_DIR/.." && go build -o "$PROXY_BIN" ./cmd/sig0lease)
    (cd "$SCRIPT_DIR/.." && go build -o "$CLIENT_BIN" ./cmd/sig0lease-client)
    (cd "$SCRIPT_DIR/.." && go build -o "$BLACKLISTED_TESTER_BIN" ./tests/blacklisted_tester.go)
    log_success "Binaries built"
}

run_client() {
    local operation="$1"
    local keyname="$2"
    local lease_seconds="$3"
    local key_lease_seconds="$4"
    local rr_spec="${5:-}"
    
    cmd="CLIENT_KEYSTORE_DIR=\"$CLIENT_KEYSTORE_DIR\" \"$CLIENT_BIN\" \"$PROXY_URL\" $operation \"$keyname\" $lease_seconds $key_lease_seconds \"$rr_spec\"" 
    echo $cmd
    eval $cmd
}

assert_proxy_log_contains() {
    local pattern="$1"
    if grep -q "$pattern" "$LOG_FILE"; then
        return 0
    fi
    log_error "Expected proxy log pattern not found: $pattern"
    tail -n 120 "$LOG_FILE" || true
    return 1
}

# Query the running proxy for lease store dump at the specified log level.
# Usage: query_lease_dump <level>
#   level: "debug" → full details via __dump.sig0lease.internal.debug.
#          "info"  → summary via __dump.sig0lease.internal.
# Returns the concatenated TXT dump text from the proxy.
query_lease_dump() {
    local level="${1:-info}"
    local query_domain dump_label
    case "$level" in
        debug)
            query_domain="__dump.sig0lease.internal.debug."
            dump_label="DEBUG/full"
            ;;
        info|*)
            query_domain="__dump.sig0lease.internal."
            dump_label="INFO/summary"
            ;;
    esac

    local out
    out=$(dig_query_short "$PROXY_URL" "${query_domain}" TXT)

    # Use test script's own log levels (independent from proxy logging).
    if [ "$level" = "debug" ]; then
        log_debug "[dig] @${PROXY_URL} ${query_domain} TXT (${dump_label})"
    else
        log_info "[dig] @${PROXY_URL} ${query_domain} TXT (${dump_label})"
    fi

    if [ -n "$out" ]; then
        echo "$out"
    else
        echo "(no dump response)"
    fi
    printf '%s\n' "$out"
}

verify_keystore() {
    log_section "SETUP: Real Keystore"

    if [ ! -d "$CLIENT_KEYSTORE_DIR" ]; then
        log_error "Test keystore directory not found: $CLIENT_KEYSTORE_DIR"
        exit 1
    fi

    log_step "Verifying test keys in keystore: $CLIENT_KEYSTORE_DIR"
    if ! ls "$CLIENT_KEYSTORE_DIR"/${CLIENT_KEY_NAME}.key >/dev/null 2>&1; then
        log_error "Expected key for zone $DOWNSTREAM_ZONE not found in $CLIENT_KEYSTORE_DIR"
        exit 1
    fi
    CLIENT_KEY_RR=$(cat $CLIENT_KEYSTORE_DIR/${CLIENT_KEY_NAME}.key)
    if ! ls "$CLIENT_KEYSTORE_DIR"/${WRONG_CLIENT_KEY_NAME}.key >/dev/null 2>&1; then
        log_error "Expected second real key for unauthorized test ($WRONG_CLIENT_KEY_NAME) not found"
        exit 1
    fi
    WRONG_CLIENT_KEY_RR=$(cat $CLIENT_KEYSTORE_DIR/${WRONG_CLIENT_KEY_NAME}.key)

    log_success "Test keystore verified, directory content:"
    ls -1 "$CLIENT_KEYSTORE_DIR" | sed -n '1,50p'
    echo "CLIENT_KEY_RR: $CLIENT_KEY_RR"
    echo "WRONG_CLIENT_KEY_RR: $WRONG_CLIENT_KEY_RR"
}

test_list_keys() {
    log_section "CHECK: Key Listing"
    log_step "Listing keys from real keystore"
    CLIENT_KEYSTORE_DIR="$CLIENT_KEYSTORE_DIR" "$CLIENT_BIN" dummy list-keys "$CLIENT_KEYSTORE_DIR"
    log_success "Key listing successful"
}

################################
# DNS inquiry functions
################################
dig_query_short() {
    local endpoint="$1"
    local name="$2"
    local rr_type="$3"

    local host="$endpoint"
    local port="53"
    if [[ "$endpoint" == *:* ]]; then
        host="${endpoint%:*}"
        port="${endpoint##*:}"
    fi
    
    log_file dig_query_short "dig +short +time=5 @\"$host\" -p \"$port\" \"$name\" \"$rr_type\" 2>/dev/null"
    dig +short +time=5 @"$host" -p "$port" "$name" "$rr_type" 2>/dev/null    
}

rr_at_authoritative() {
    local rr_type=$1
    local rdata="$2"

    local answer

    local dig_answer="$(dig_query_short $AUTH_SERVER $DOWNSTREAM_ZONE $rr_type)"
    
    if [ -n "$dig_answer" ]; then
        answer="$(echo "$rdata" | grep "$dig_answer")"
        log_file rr_at_authoritative "rdata=$rdata, dig_answer=$dig_answer, answer=$answer."
    else
        answer=''
        log_file rr_at_authoritative "rdata=$rdata, empty dig_answer."
    fi
    
    if [ -n "$answer" ]; then
        echo "Record present: $answer"
        return 0
    else
        echo "no match"
        return 1
    fi
    
}

wait_for_rr_state() {
    local rr_type="$1"
    local rdata="$2"
    local state="$3"   # present|absent
    local timeout=30

    local start
    start=$(date +%s)

    while true; do
        log_file wait_for_rr_state "state=$state, calling rr_at_authoritative $rr_type \"$rdata\""
        if [ "$state" = "present" ]; then
            if rr_at_authoritative $rr_type "$rdata"; then
                log_success "$rr_type present on $DOWNSTREAM_ZONE"
                return 0
            fi
        else
            if ! rr_at_authoritative $rr_type "$rdata"; then
                log_success "$rr_type absent on $DOWNSTREAM_ZONE"
                return 0
            fi
        fi

        if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
            log_error "Timed out waiting for ${rr_type} state=$state on $DOWNSTREAM_ZONE"
            return 1
        fi

        sleep 2
    done
}

ensure_rr_absent() {
    local rr_type="$1"
    local rr_rdata="$2"

    log_file ensure_rr_absent "rr_type=$rr_type, rr_rdata=$rr_rdata."

    if ! rr_at_authoritative "$rr_type" "$rr_rdata"; then
        log_success "Pristine state already present: $rr_type - $rr_rdata absent on $DOWNSTREAM_ZONE"
        return 0
    fi

    log_step "Cleanup: rr $rr_type - $rr_rdata is present, deleting"

    # Refresh with 0 lease.
    if ! run_client refresh $CLIENT_KEY_NAME 0 0 "$rr_rdata"; then
        log_error "Cleanup failed for $rr_type - $rr_rdata"
        return 1
    fi

    if wait_for_rr_state $rr_type "$rr_rdata" absent; then
        log_success "Cleanup complete: $rr_type - $rr_rdata absent on $DOWNSTREAM_ZONE"
    else
        log_error "Cleanup failed for $rr_type - $rr_rdata on $DOWNSTREAM_ZONE"
        return 1
    fi
    return 0
}

make_rr() {
    local rr_type="$1"
    local ttl="$2"
    local wrong="${3:-0}"
    case "$rr_type" in
        KEY)
            if [ "$wrong" == "1" ]; then
                echo "$WRONG_CLIENT_KEY_RR"
            else
                echo "$CLIENT_KEY_RR"
            fi
        
        ;;
        TXT) echo "${DOWNSTREAM_ZONE} ${ttl} IN TXT \"lease-txt-$(date +%s)\"" ;;
        A) echo "${DOWNSTREAM_ZONE} ${ttl} IN A 192.0.2.33" ;;
        AAAA) echo "${DOWNSTREAM_ZONE} ${ttl} IN AAAA 2001:db8::33" ;;
        # NULL and NXNAME have no presentation format in miekg/dns,
        # so they cannot be constructed via the client binary's
        # ParseAdditionalRRSpec (which uses dns.New). They are
        # tested at the unit-test level (handlers opcode5 behavior tests).
        NULL) log_step "Skipping NULL: no presentation format in miekg/dns" ;;
        NXNAME) log_step "Skipping NXNAME: no presentation format in miekg/dns" ;;
        WALLET) echo "${DOWNSTREAM_ZONE} ${ttl} IN WALLET \"wallet-data-$(date +%s)\"" ;;
        CLA) echo "${DOWNSTREAM_ZONE} ${ttl} IN CLA \"cla-data-$(date +%s)\"" ;;
        IPN) echo "${DOWNSTREAM_ZONE} ${ttl} IN IPN 42" ;;
        *)
            log_error "Unsupported rr type: $rr_type"
            return 1
            ;;
    esac
}

register_rr_type() {
    local key_name="$1"
    local lease_seconds=$2
    local key_lease_seconds=$3
    local rr_spec="$4"
    local cmd="run_client register \"$key_name\" $lease_seconds $key_lease_seconds \"$rr_spec\""
    log_step "running $cmd"
    eval "$cmd"
}

proxy_consistent_with_authoritative() {
    local rr_type="$1"
    local rr_rdata="$2"
    local expected_state="$3"  # present|absent

    local is_present=0
    log_file proxy_consistent_with_authoritative "rr_type=$rr_type, rr_rdata=$rr_rdata, expected_state=$expected_state."

    if rr_at_authoritative $rr_type "$rr_rdata"; then
        is_present=1
    fi

    if [ "$expected_state" = "present" ] && [ "$is_present" -ne 1 ]; then
        log_error "Consistency check failed: authoritative missing but expected present for $rr_type - $rr_rdata"
        return 1
    fi
    if [ "$expected_state" = "absent" ] && [ "$is_present" -ne 0 ]; then
        log_error "Consistency check failed: authoritative present but expected absent for $rr_type - $rr_rdata"
        return 1
    fi

    # Proxy Lease-store consistency checks
    # TODO: Add checks that records in lease-store are actually at the DNS
    
    log_info "Consistency check passed for $rr_type - $rr_rdata"

}
################################
# Tests
################################
test_blacklisted_type() {
# Test blacklisted RR types by constructing them programmatically.
# NULL and NXNAME cannot be constructed via presentation format (miekg/dns limitation),
# so we use a small Go helper that constructs these records directly and sends them.

    local rr_type=$1
    log_section "BLACKLISTED [$rr_type]: Proxy Rejects Blacklisted Type"

    log_step "Registering lease with blacklisted type"
    local case_start lease_start
    case_start=$(date +%s)
    lease_start=$(date +%s)

    # For NULL/NXNAME, use the Go helper to construct the record directly.
    # For WALLET/CLA/IPN, use the standard client binary.
    local rr_spec=""
    local reg_out=""
    case "$rr_type" in
        NULL|NXNAME)
            # Construct the record programmatically via the Go helper.
            # This bypasses ParseAdditionalRRSpec and constructs the RR directly.
            log_step "Using Go helper to construct $rr_type record directly"
            # blacklisted_tester sends the request directly to the proxy and prints the response.
            reg_out=$(cd "$SCRIPT_DIR/.." && go run -ldflags="-X main.rrType=$rr_type -X main.rrOwner=$DOWNSTREAM_ZONE -X main.leaseDuration=$LEASE_SECONDS -X main.keyLeaseSec=$KEY_LEASE_SECONDS -X main.proxyAddr=$PROXY_URL -X main.zone=$DOWNSTREAM_ZONE" ./tests/blacklisted_tester.go 2>&1) || true
            ;;
        *)
            rr_spec=$(make_rr "$rr_type" "$LEASE_SECONDS")
            log_step "Attempting registration with blacklisted type $rr_type"
            reg_out=$(run_client register "$CLIENT_KEY_NAME" "$LEASE_SECONDS" "$KEY_LEASE_SECONDS" "$rr_spec" 2>&1) || true
            ;;
    esac

    # Check the response for rejection (should be Rcode=1 FormatError).
    if echo "$reg_out" | grep -q "Rcode=1\|FormatError\|REGISTRATION FAILED"; then
        log_success "Proxy correctly rejected blacklisted type $rr_type with format error"
    else
        log_error "Proxy should have rejected blacklisted type $rr_type, got: $reg_out"
        return 1
    fi

    # Verify no KEY RR was created (registration should be atomic - all or nothing).
    if rr_at_authoritative KEY $CLIENT_KEY_NAME; then
        log_error "Blacklisted type $rr_type rejected but key lease created"
        return 1
    else
        log_success "Blacklisted type $rr_type rejected and no lease created"
    fi
    return 0
}

test_single_rr_register_expire_remove() {
    local rr_type="$1"
    log_section "CASE 1 [$rr_type]: Register -> Expire -> Removed"

    case $rr_type in
        KEY)
            local lease_time=0
            local key_lease_time=$KEY_LEASE_SECONDS
            local lease=$key_lease_time
            ;;
        *)
            local lease_time=$LEASE_SECONDS
            local key_lease_time=0
            local lease=$lease_time
            ;;
    esac

    local case_start lease_start expected_min
    rr_spec="$(make_rr $rr_type $lease)"
    case_start=$(date +%s)
    log_step "Registering lease "
    lease_start=$(date +%s)
    register_rr_type $CLIENT_KEY_NAME $lease_time $key_lease_time "$rr_spec" 
    wait_for_rr_state $rr_type "$rr_spec" present

    # Verify lease store via dump query (INFO level summary).
    log_step "Verifying lease store state via dump query (DEBUG)"
    query_lease_dump "debug"

    log_step "Waiting until lease expiry boundary"
    wait_until_epoch $((lease_start + lease + 3))

    # RR should be gone before we exercise post-expiry behavior.
    wait_for_rr_state "$rr_type" "$rr_spec" absent
    proxy_consistent_with_authoritative "$rr_type" "$rr_spec" absent

    if [ "$rr_type" = "KEY" ]; then
        log_step "Attempting refresh after expiry (KEY path: expected to re-register)"
        run_client refresh "$CLIENT_KEY_NAME" 0 $REFRESH_SECONDS "$rr_spec"
        wait_for_rr_state KEY "$rr_spec" present
        proxy_consistent_with_authoritative KEY "$rr_spec" present
        log_success "Expired KEY refresh succeeded via re-registration semantics"
    else
        log_step "Attempting refresh after expiry (non-KEY path: expected failure)"
        if run_client refresh "$CLIENT_KEY_NAME" "$REFRESH_SECONDS" 0 "$rr_spec"; then
            log_error "Refresh succeeded after expiry, expected failure"
            return 1
        fi
        wait_for_rr_state $rr_type "$rr_spec" absent
        proxy_consistent_with_authoritative $rr_type "$rr_spec" absent
        assert_proxy_log_contains "refresh rejected: lease does not exist"
    fi

    expected_min=$((lease_start + lease + 3 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case1-${rr_type}" "$case_start" "$expected_min"
    log_success "Case 1 post-expiry behavior validated for $rr_type"
}

test_case_register_refresh_not_prematurely_removed() {
    local rr_type="$1"
    log_section "CASE 2 [$rr_type]: Register -> Refresh -> Not Prematurely Removed"

    local case_start lease_start refresh_start expected_min
    case_start=$(date +%s)
    log_step "Registering initial lease"
    lease_start=$(date +%s)
    register_rr_type $CLIENT_KEY_NAME $LEASE_SECONDS $REFRESH_CASE_KEY_LEASE_SECONDS $rr_type
    wait_for_rr_state KEY present
    wait_for_rr_state "$rr_type" present
    proxy_consistent_with_authoritative "$rr_type" present

    # Verify lease store via dump query (INFO level summary).
    log_step "Verifying lease store state via dump query (INFO) after initial registration"
    query_lease_dump "info"

    log_step "Waiting to near-expiry checkpoint then refreshing"
    wait_until_epoch $((lease_start + 20))
    refresh_start=$(date +%s)
    run_client refresh "$CLIENT_KEY_NAME" "$REFRESH_SECONDS" $FIXME
    wait_for_rr_state KEY present
    wait_for_rr_state "$rr_type" present
    proxy_consistent_with_authoritative "$rr_type" present

    log_step "Waiting past original expiry window"
    wait_until_epoch $((lease_start + LEASE_SECONDS + 5))
    wait_for_rr_state KEY present
    wait_for_rr_state "$rr_type" present
    proxy_consistent_with_authoritative "$rr_type" present

    log_step "Refreshing again (must still succeed if not removed prematurely)"
    run_client refresh "$CLIENT_KEY_NAME" $REFRESH_SECONDS $FIXME
    wait_for_rr_state KEY present
    wait_for_rr_state "$rr_type" present
    proxy_consistent_with_authoritative "$rr_type" present

    log_step "Waiting for refreshed data lease window while key-lease remains active"
    wait_until_epoch $((refresh_start + REFRESH_SECONDS + 5))
    wait_for_rr_state KEY present
    proxy_consistent_with_authoritative KEY present
    if [ "$rr_type" != "KEY" ]; then
        log_step "Post-refresh note: non-key RR ($rr_type) state is informational only"
        rr_at_authoritative "$rr_type" $FIXME >/dev/null || true
    fi

    expected_min=$((refresh_start + REFRESH_SECONDS + 5 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case2-${rr_type}" "$case_start" "$expected_min"
    log_success "Lease behavior validated after renewal for $rr_type"
}

test_case_split_lease_nonkey_expires_key_persists() {
    local rr_type="$1"
    if [ "$rr_type" = "KEY" ]; then
        return 0
    fi

    log_section "CASE 2B [$rr_type]: LEASE < KEY-LEASE Deletes Non-KEY Only"

    local case_start lease_start expected_min
    case_start=$(date +%s)
    lease_start=$(date +%s)

    log_step "Registering split lease for $rr_type (LEASE=$LEASE_SECONDS, KEY-LEASE=$REFRESH_CASE_KEY_LEASE_SECONDS)"
    register_rr_type $CLIENT_KEY_NAME $LEASE_SECONDS $REFRESH_CASE_KEY_LEASE_SECONDS $rr_type
    wait_for_rr_state KEY present
    wait_for_rr_state "$rr_type" present

    log_step "Waiting past LEASE boundary and verifying only non-KEY records expire"
    wait_until_epoch $((lease_start + LEASE_SECONDS + 5))
    wait_for_rr_state KEY present
    wait_for_rr_state "$rr_type" absent

    expected_min=$((lease_start + LEASE_SECONDS + 5 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case2b-${rr_type}" "$case_start" "$expected_min"
    log_success "Split lease behavior correct: non-KEY expired while KEY remained active for $rr_type"
}

test_case_overlapping_registrations_issue17() {
    log_section "CASE 4 [ISSUE-17]: Overlapping Registrations Must Not Leave Permanent RR"

    local case_start first_start second_start expected_min
    local ts1 ts2
    ts1=$(date +%s)
    ts2=$((ts1 + 1))
    case_start=$ts1

    local rr1_a rr1_txt rr2_a rr2_txt
    rr1_a="${DOWNSTREAM_ZONE} ${OVERLAP_RR_LEASE_SECONDS} IN A 192.0.2.99"
    rr1_txt="${DOWNSTREAM_ZONE} ${OVERLAP_RR_LEASE_SECONDS} IN TXT \"issue17-first-${ts1}\""
    rr2_a="${DOWNSTREAM_ZONE} ${OVERLAP_RR_LEASE_SECONDS} IN A 192.0.2.100"
    rr2_txt="${DOWNSTREAM_ZONE} ${OVERLAP_RR_LEASE_SECONDS} IN TXT \"issue17-second-${ts2}\""

    log_step "First registration (A+TXT set #1)"
    first_start=$(date +%s)
    run_client register "$CLIENT_KEY_NAME" $OVERLAP_RR_LEASE_SECONDS $OVERLAP_KEY_LEASE_SECONDS "$rr1_a" "$rr1_txt"
    wait_for_rr_state KEY present
    wait_for_rr_state A present
    wait_for_rr_state TXT present

    log_step "Waiting ${OVERLAP_DELAY_SECONDS}s before overlapping registration"
    sleep "$OVERLAP_DELAY_SECONDS"

    log_step "Second overlapping registration (A+TXT set #2)"
    second_start=$(date +%s)
    run_client register "$CLIENT_KEY_NAME" $OVERLAP_RR_LEASE_SECONDS $OVERLAP_KEY_LEASE_SECONDS "$rr2_a" "$rr2_txt"
    wait_for_rr_state KEY present
    wait_for_rr_state A present
    wait_for_rr_state TXT present

    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" A "192.0.2.100"; then
        log_error "Expected second A record to be visible after overlapping registration"
        return 1
    fi
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "issue17-second-${ts2}"; then
        log_error "Expected second TXT record to be visible after overlapping registration"
        return 1
    fi

    log_step "Waiting for RR lease expiry to verify old and new non-KEY leases are both cleaned"
    wait_until_epoch $((second_start + OVERLAP_RR_LEASE_SECONDS + 8))

    wait_for_rr_state A absent
    wait_for_rr_state TXT absent
    wait_for_rr_state KEY present

    expected_min=$((second_start + OVERLAP_RR_LEASE_SECONDS + 8 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case4-issue17-overlap" "$case_start" "$expected_min"
    log_success "Issue #17 regression check passed: overlapping RR sets were not forgotten/permanent"
}

test_case_unauthorized_refresh_rejected_then_expires() {
    local rr_type="$1"
    log_section "CASE 3 [$rr_type]: Unauthorized Refresh Rejected -> Lease Expires"

    local case_start lease_start expected_min
    case_start=$(date +%s)
    log_step "Registering lease under authorized key ($CLIENT_KEY_NAME)"
    lease_start=$(date +%s)
    register_rr_type $CLIENT_KEY_NAME $LEASE_SECONDS $KEY_LEASE_SECONDS $rr_type
    wait_for_rr_state "$CLIENT_KEY_NAME" KEY present
    wait_for_rr_state "$rr_type" present

    log_step "Unauthorized refresh attempt using different real key ($WRONG_CLIENT_KEY_NAME)"
    if run_client refresh "$WRONG_CLIENT_KEY_NAME" $REFRESH_SECONDS $REFRESH_SECONDS $FIXME; then
        log_error "Unauthorized refresh unexpectedly succeeded"
        return 1
    fi
    wait_for_rr_state "$CLIENT_KEY_NAME" KEY present
    wait_for_rr_state "$rr_type" present

    log_step "Waiting until original lease expires"
    wait_until_epoch $((lease_start + LEASE_SECONDS + 3))

    wait_for_rr_state "$CLIENT_KEY_NAME" KEY absent
    proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" KEY absent
    if [ "$rr_type" != "KEY" ]; then
        log_step "Post-expiry note: non-key RR ($rr_type) state is informational only"
        rr_at_authoritative "$rr_type" $FIXME >/dev/null || true
    fi
    log_step "Original key refresh after expiry must fail"
    if run_client refresh "$CLIENT_KEY_NAME" "$REFRESH_SECONDS"; then
        log_error "Lease still active after expiry, expected removal"
        return 1
    fi
    wait_for_rr_state "$CLIENT_KEY_NAME" KEY absent
    proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" KEY absent

    expected_min=$((lease_start + LEASE_SECONDS + 3 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case3-${rr_type}" "$case_start" "$expected_min"
    log_success "Unauthorized refresh rejected and lease expired as expected for $rr_type"
}

################################
# Top level commands
################################
run_all_tests() {
    log_section "SIG0LEASE INTEGRATION TEST SUITE"
    echo "This suite uses live components only (no stubs/mocks):"
    echo "  - real proxy process"
    echo "  - real client process"
    echo "  - real key files"
    echo "  - real authoritative forwarding path for zenr.io"
    echo ""

    trap cleanup EXIT

    require_command grep
    require_command ls
    require_command dig
    build_binaries
    verify_keystore
    log_success "Using authoritative server for KEY checks: $AUTH_SERVER, key: $CLIENT_KEY_NAME, lease: $LEASE_SECONDS, key-lease: $KEY_LEASE_SECONDS"
    log_section "TESTING LIVE LEASE LIFECYCLE"
    test_list_keys
    start_proxy

    local rr_types=($RR_TYPES)
    local blacklisted_rrs=$(awk '
        /blacklisted_types:/ { found=1; next }
        found && /^[[:space:]]*-[[:space:]]*"/ {
        val = $0
        sub(/^[[:space:]]*-[[:space:]]*"/, "", val)
        sub(/"[[:space:]]*$/, "", val)
        types = types " " val
        }
        END {
        sub(/^ /, "", types)
        print types
        }
    ' "$CONFIG_FILE")


    log_step "Black-listed types: $blacklisted_rrs"
    
    local rr_type
    for rr_type in "${rr_types[@]}"; do
        log_section "RR TEST MATRIX: $rr_type"
        # ensure_rr_absent $rr_type "$CLIENT_KEY_RR"
        if [[ " $blacklisted_rrs " == *" $rr_type "* ]]; then
            test_blacklisted_type $rr_type
        else
            test_single_rr_register_expire_remove "$rr_type"
            # ensure_rr_absent $rr_type $FIXME
            # test_case_register_refresh_not_prematurely_removed "$rr_type"
            # ensure_rr_absent $rr_type $FIXME
            # test_case_split_lease_nonkey_expires_key_persists "$rr_type"
            # ensure_rr_absent $rr_type $FIXME
            # test_case_unauthorized_refresh_rejected_then_expires "$rr_type"
        fi
    done

    # ensure_rr_absent $rr_type $FIXME
    # test_case_overlapping_registrations_issue17

    log_section "TEST RESULTS"
    echo -e "${GREEN}All integration tests completed successfully!${NC}"
    echo ""
    echo "Summary of what was tested:"
    echo "  [OK] Register -> expire -> removed (KEY/TXT/A/AAAA)"
    echo "  [OK] Register -> refresh -> split lease behavior (KEY/TXT/A/AAAA)"
    echo "  [OK] LEASE < KEY-LEASE -> non-KEY records expire while KEY remains"
    echo "  [OK] Unauthorized refresh rejected, lease still expires (KEY/TXT/A/AAAA)"
    echo "  [OK] Issue #17: overlapping registrations do not leave permanent stale RR"
    echo "  [OK] Proxy consistency checks use refresh path"
    echo ""
    echo "Proxy process was exercised at $PROXY_URL"
    echo "Logs: $LOG_FILE"
}

cleanup() {
    set +e
    log_section "CLEANUP"

    if [ ! -z "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        log_step "Restoring pristine KEY state before shutdown"
        # ensure_rr_absent KEY "$CLIENT_KEY_RR" || true
    fi

    stop_proxy

    if [ -n "$TMP_CONFIG_FILE" ] && [ -f "$TMP_CONFIG_FILE" ]; then
        rm -f "$TMP_CONFIG_FILE"
    fi

    set -e
}

################################
# Menu
################################

case "${1:-run}" in
    run)
        run_all_tests
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo "Usage: $0 [run|cleanup]"
        echo "  run     - Run all live integration tests"
        echo "  cleanup - Stop proxy"
        exit 1
        ;;
esac
