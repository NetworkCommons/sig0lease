#!/bin/bash
#
# Comprehensive Integration Test for sig0lease Proxy
#
# This suite intentionally runs real process-level integration tests only:
# - real proxy binary
# - real client binary
# - real DNS keys from keystore
# - real authoritative path for zenr.io (via proxy update forwarding)
#
# Usage: tests/test_integration.sh [start|stop|clean]
#

set -euo pipefail


# Configuration
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_BIN="${SCRIPT_DIR}/../bin/${OS}/sig0lease"
CLIENT_BIN="${SCRIPT_DIR}/../bin/${OS}/sig0lease-client"
CONFIG_FILE="${SCRIPT_DIR}/../config.yaml"
LOG_FILE="/tmp/sig0lease_proxy.log"
TMP_CONFIG_FILE=""
AUTH_SERVER="${AUTH_SERVER:-ns1.free2air.org}"
MIN_LEASE_SECONDS=30

# Get keystore from environment or config file
TEST_KEYSTORE="${KEYSTORE_DIR:-}"
if [ -z "$TEST_KEYSTORE" ]; then
    echo "ERROR: KEYSTORE_DIR environment variable not set"
    exit 1
fi

PROXY_ADDR="${PROXY_ADDR:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8053}"
PROXY_URL="$PROXY_ADDR:$PROXY_PORT"

# Real zones/keys
DOWNSTREAM_ZONE="test.dev.zenr.io."
UPSTREAM_ZONE="dev.zenr.io."
CLIENT_KEY_NAME="test.dev.zenr.io."
WRONG_CLIENT_KEY_NAME="farback.dev.zenr.io."
LEASE_SECONDS=30
REFRESH_SECONDS=30

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_section() {
    echo -e "\n${BLUE}===================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================================${NC}\n"
}

log_step() {
    echo -e "${YELLOW}→ $1${NC}"
}

log_success() {
    echo -e "${GREEN}[OK] $1${NC}"
}

log_error() {
    echo -e "${RED}[FAIL] $1${NC}"
}

cleanup() {
    set +e
    log_section "CLEANUP"

    if [ ! -z "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        log_step "Restoring pristine KEY state before shutdown"
        ensure_key_absent "$CLIENT_KEY_NAME" || true
    fi

    if [ ! -z "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        log_step "Stopping sig0lease proxy (PID: $PROXY_PID)"
        kill "$PROXY_PID" || true
        sleep 1
        log_success "Proxy stopped"
    fi

    if [ -n "$TMP_CONFIG_FILE" ] && [ -f "$TMP_CONFIG_FILE" ]; then
        rm -f "$TMP_CONFIG_FILE"
    fi

    set -e
}

stop_proxy() {
    if [ ! -z "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" || true
        sleep 1
    fi
    PROXY_PID=""
}

restart_proxy() {
    stop_proxy
    start_proxy
}

run_client() {
    KEYSTORE_DIR="$TEST_KEYSTORE" "$CLIENT_BIN" "$@"
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "Required command not found: $1"
        exit 1
    fi
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

query_key_at_authoritative() {
    local name="$1"
    local cmd="dig +time=3 +tries=1 +short @${AUTH_SERVER} ${name} KEY"
    local out
    out=$(dig +time=3 +tries=1 +short @"$AUTH_SERVER" "$name" KEY)
    log_step "[dig] $cmd" >&2
    if [ -n "$out" ]; then
        echo "$out" >&2
    else
        echo "(no records)" >&2
    fi
    printf '%s\n' "$out"
}

key_is_present() {
    local name="$1"
    local answer
    answer=$(query_key_at_authoritative "$name" | tail -n 1 || true)
    [ -n "$answer" ]
}

wait_for_key_state() {
    local name="$1"
    local state="$2"   # present|absent
    local timeout="$3"

    local start
    start=$(date +%s)

    while true; do
        local answer
        answer=$(query_key_at_authoritative "$name" | tail -n 1 || true)

        if [ "$state" = "present" ]; then
            if [ -n "$answer" ]; then
                log_success "KEY present for $name on $AUTH_SERVER"
                return 0
            fi
        else
            if [ -z "$answer" ]; then
                log_success "KEY absent for $name on $AUTH_SERVER"
                return 0
            fi
        fi

        if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
            log_error "Timed out waiting for KEY state=$state for $name on $AUTH_SERVER"
            echo "Last answer:"
            echo "$answer"
            return 1
        fi

        sleep 2
    done
}

assert_proxy_consistent_with_authoritative() {
    local key_name="$1"
    local expected_state="$2"  # present|absent

    local is_present=0
    if key_is_present "$key_name"; then
        is_present=1
    fi

    if [ "$expected_state" = "present" ] && [ "$is_present" -ne 1 ]; then
        log_error "Consistency check failed: authoritative missing KEY but expected present for $key_name"
        return 1
    fi
    if [ "$expected_state" = "absent" ] && [ "$is_present" -ne 0 ]; then
        log_error "Consistency check failed: authoritative KEY present but expected absent for $key_name"
        return 1
    fi

    # Proxy consistency checks:
    # - for present: non-mutating check via verify command output
    # - for absent: refresh must be rejected (strong lease-manager check)
    if [ "$expected_state" = "present" ]; then
        local verify_out
        verify_out=$(run_client "$PROXY_URL" verify "$DOWNSTREAM_ZONE" "$key_name" 2>&1 || true)
        if ! echo "$verify_out" | grep -q "Rcode=0"; then
            log_error "Consistency check failed: proxy verify did not return NOERROR while authoritative KEY is present for $key_name"
            echo "$verify_out"
            return 1
        fi
        log_success "Consistency check OK: proxy reachable/NOERROR and authoritative KEY present for $key_name"
    else
        if run_client "$PROXY_URL" refresh "$DOWNSTREAM_ZONE" "$key_name" "$REFRESH_SECONDS" >/dev/null 2>&1; then
            log_error "Consistency check failed: proxy refresh accepted but authoritative KEY is absent for $key_name"
            return 1
        fi
        log_success "Consistency check OK: proxy refresh rejected and authoritative KEY absent for $key_name"
    fi
}

wait_until_epoch() {
    local target_epoch="$1"
    local now
    now=$(date +%s)
    if [ "$now" -lt "$target_epoch" ]; then
        sleep $((target_epoch - now))
    fi
}

wait_until_lease_expired() {
    local lease_start_epoch="$1"
    local lease_seconds="$2"
    local grace_seconds="$3"
    wait_until_epoch $((lease_start_epoch + lease_seconds + grace_seconds))
}

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

ensure_key_absent() {
    local key_name="$1"

    if ! key_is_present "$key_name"; then
        log_success "Pristine state already present: $key_name absent on $AUTH_SERVER"
        return 0
    fi

    log_step "Cleanup: key $key_name is present, forcing short lease then waiting expiry"
    local cleanup_start
    cleanup_start=$(date +%s)

    # Re-register with minimum supported lease so cleanup reaches absence quickly.
    if ! run_client "$PROXY_URL" register "$DOWNSTREAM_ZONE" "$key_name" "$MIN_LEASE_SECONDS" 3600 >/dev/null 2>&1; then
        log_error "Cleanup registration failed for $key_name"
        return 1
    fi

    wait_until_lease_expired "$cleanup_start" "$MIN_LEASE_SECONDS" 3
    wait_for_key_state "$key_name" absent 90
    log_success "Cleanup complete: $key_name absent on $AUTH_SERVER"
}

setup_keystore() {
    log_section "SETUP: Real Keystore"

    if [ ! -d "$TEST_KEYSTORE" ]; then
        log_error "Test keystore directory not found: $TEST_KEYSTORE"
        exit 1
    fi

    log_step "Verifying test keys in keystore: $TEST_KEYSTORE"
    if ! ls "$TEST_KEYSTORE"/Ktest.dev.zenr.io.+015+*.key >/dev/null 2>&1; then
        log_error "Expected key for zone $DOWNSTREAM_ZONE not found in $TEST_KEYSTORE"
        exit 1
    fi
    if ! ls "$TEST_KEYSTORE"/Kfarback.dev.zenr.io.+015+*.key >/dev/null 2>&1; then
        log_error "Expected second real key for unauthorized test ($WRONG_CLIENT_KEY_NAME) not found"
        exit 1
    fi

    log_success "Test keystore verified"
    ls -1 "$TEST_KEYSTORE" | sed -n '1,50p'
}

start_proxy() {
    log_section "START: Proxy Process"

    if ! [ -x "$PROXY_BIN" ]; then
        log_error "Proxy binary not found or not executable: $PROXY_BIN"
        exit 1
    fi

    log_step "Preparing runtime config for listen address $PROXY_ADDR:$PROXY_PORT"

    TMP_CONFIG_FILE="$(mktemp /tmp/sig0lease-config.XXXXXX)"
    cp "$CONFIG_FILE" "$TMP_CONFIG_FILE"
    sed -i.bak "s|^  address:.*$|  address: \"$PROXY_ADDR:$PROXY_PORT\"|" "$TMP_CONFIG_FILE"
    rm -f "$TMP_CONFIG_FILE.bak"

    log_step "Starting proxy on $PROXY_URL with config: $TMP_CONFIG_FILE"

    "$PROXY_BIN" "$TMP_CONFIG_FILE" > "$LOG_FILE" 2>&1 &
    PROXY_PID=$!

    sleep 2

    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        log_error "Proxy failed to start. Check logs:"
        cat "$LOG_FILE"
        if grep -q "address already in use" "$LOG_FILE"; then
            log_error "Port $PROXY_PORT is already in use. Re-run with a free port: PROXY_PORT=18053 tests/test_integration.sh run"
        fi
        exit 1
    fi

    log_success "Proxy started successfully (PID: $PROXY_PID)"
    log_success "Proxy log: tail -f $LOG_FILE"
}

build_binaries() {
    log_section "BUILD"
    log_step "Building proxy and client binaries"
    (cd "$SCRIPT_DIR/.." && go build -o "$PROXY_BIN" ./cmd/sig0lease)
    (cd "$SCRIPT_DIR/.." && go build -o "$CLIENT_BIN" ./cmd/sig0lease-client)
    log_success "Binaries built"
}

test_list_keys() {
    log_section "CHECK: Key Listing"
    log_step "Listing keys from real keystore"
    run_client dummy list-keys "$TEST_KEYSTORE"
    log_success "Key listing successful"
}

test_case_register_expire_remove() {
    log_section "CASE 1: Register -> Expire -> Removed"

    local case_start lease_start expected_min
    case_start=$(date +%s)
    log_step "Registering lease ($LEASE_SECONDS seconds)"
    lease_start=$(date +%s)
    run_client "$PROXY_URL" register "$DOWNSTREAM_ZONE" "$CLIENT_KEY_NAME" "$LEASE_SECONDS" 3600
    wait_for_key_state "$CLIENT_KEY_NAME" present 30
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" present

    log_step "Waiting until lease expiry boundary"
    wait_until_lease_expired "$lease_start" "$LEASE_SECONDS" 3

    log_step "Attempting refresh after expiry (must fail)"
    if run_client "$PROXY_URL" refresh "$DOWNSTREAM_ZONE" "$CLIENT_KEY_NAME" "$REFRESH_SECONDS"; then
        log_error "Refresh succeeded after expiry, expected failure"
        return 1
    fi
    wait_for_key_state "$CLIENT_KEY_NAME" absent 45
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" absent

    assert_proxy_log_contains "refresh rejected: lease does not exist"
    expected_min=$((lease_start + LEASE_SECONDS + 3 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case1" "$case_start" "$expected_min"
    log_success "Expired lease no longer refreshable"
}

test_case_register_refresh_not_prematurely_removed() {
    log_section "CASE 2: Register -> Refresh -> Not Prematurely Removed"

    local case_start lease_start refresh_start expected_min
    case_start=$(date +%s)
    log_step "Registering initial lease"
    lease_start=$(date +%s)
    run_client "$PROXY_URL" register "$DOWNSTREAM_ZONE" "$CLIENT_KEY_NAME" "$LEASE_SECONDS" 3600
    wait_for_key_state "$CLIENT_KEY_NAME" present 30
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" present

    log_step "Waiting to near-expiry checkpoint then refreshing"
    wait_until_epoch $((lease_start + 20))
    refresh_start=$(date +%s)
    run_client "$PROXY_URL" refresh "$DOWNSTREAM_ZONE" "$CLIENT_KEY_NAME" "$REFRESH_SECONDS"
    wait_for_key_state "$CLIENT_KEY_NAME" present 20
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" present

    log_step "Waiting past original expiry window"
    wait_until_lease_expired "$lease_start" "$LEASE_SECONDS" 5
    wait_for_key_state "$CLIENT_KEY_NAME" present 30
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" present

    log_step "Refreshing again (must still succeed if not removed prematurely)"
    run_client "$PROXY_URL" refresh "$DOWNSTREAM_ZONE" "$CLIENT_KEY_NAME" "$REFRESH_SECONDS"
    wait_for_key_state "$CLIENT_KEY_NAME" present 20
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" present

    log_step "Waiting for refreshed lease to expire and restoring absence"
    wait_until_lease_expired "$refresh_start" "$REFRESH_SECONDS" 5
    wait_for_key_state "$CLIENT_KEY_NAME" absent 90
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" absent

    expected_min=$((refresh_start + REFRESH_SECONDS + 5 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case2" "$case_start" "$expected_min"
    log_success "Lease remained active after renewal"
}

test_case_unauthorized_refresh_rejected_then_expires() {
    log_section "CASE 3: Unauthorized Refresh Rejected -> Lease Expires"

    local case_start lease_start expected_min
    case_start=$(date +%s)
    log_step "Registering lease under authorized key ($CLIENT_KEY_NAME)"
    lease_start=$(date +%s)
    run_client "$PROXY_URL" register "$DOWNSTREAM_ZONE" "$CLIENT_KEY_NAME" "$LEASE_SECONDS" 3600
    wait_for_key_state "$CLIENT_KEY_NAME" present 30
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" present

    log_step "Unauthorized refresh attempt using different real key ($WRONG_CLIENT_KEY_NAME)"
    if run_client "$PROXY_URL" refresh "$DOWNSTREAM_ZONE" "$WRONG_CLIENT_KEY_NAME" "$REFRESH_SECONDS"; then
        log_error "Unauthorized refresh unexpectedly succeeded"
        return 1
    fi
    wait_for_key_state "$CLIENT_KEY_NAME" present 20
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" present

    log_step "Waiting until original lease expires"
    wait_until_lease_expired "$lease_start" "$LEASE_SECONDS" 3

    wait_for_key_state "$CLIENT_KEY_NAME" absent 45
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" absent
    log_step "Original key refresh after expiry must fail"
    if run_client "$PROXY_URL" refresh "$DOWNSTREAM_ZONE" "$CLIENT_KEY_NAME" "$REFRESH_SECONDS"; then
        log_error "Lease still active after expiry, expected removal"
        return 1
    fi
    wait_for_key_state "$CLIENT_KEY_NAME" absent 45
    assert_proxy_consistent_with_authoritative "$CLIENT_KEY_NAME" absent

    expected_min=$((lease_start + LEASE_SECONDS + 3 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case3" "$case_start" "$expected_min"
    log_success "Unauthorized refresh rejected and lease expired as expected"
}

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
    setup_keystore
    log_success "Using authoritative server for KEY checks: $AUTH_SERVER"
    log_section "TESTING LIVE LEASE LIFECYCLE"
    test_list_keys
    start_proxy
    ensure_key_absent "$CLIENT_KEY_NAME"
    test_case_register_expire_remove
    ensure_key_absent "$CLIENT_KEY_NAME"
    test_case_register_refresh_not_prematurely_removed
    ensure_key_absent "$CLIENT_KEY_NAME"
    test_case_unauthorized_refresh_rejected_then_expires

    log_section "TEST RESULTS"
    echo -e "${GREEN}All integration tests completed successfully!${NC}"
    echo ""
    echo "Summary of what was tested:"
    echo "  [OK] Register -> expire -> removed"
    echo "  [OK] Register -> refresh -> not prematurely removed"
    echo "  [OK] Unauthorized refresh rejected, lease still expires"
    echo ""
    echo "Proxy process was exercised at $PROXY_URL"
    echo "Logs: $LOG_FILE"
}

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
