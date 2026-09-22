#!/bin/bash
#
# RFC 9665 SRP integration test for sig0lease (plan S12.2/S14 Option C).
#
# Runs the real proxy process (srp_handler only) against a real, disposable local BIND 9
# instance authoritative for srp.test. -- register -> dig -> refresh -> conflict (YXDOMAIN)
# -> remove-one -> remove-all -> expiry. Uses tests/srp_client_tester (a minimal Go test
# client -- client/srp and cmd/sig0lease-srp-client are Phase 4, not built yet), not stubs/mocks.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/dns.sh"
source "$SCRIPT_DIR/lib/bind9.sh"

SRP_ZONE="srp.test."
SRP_PROXY_ADDR="127.0.0.1"
SRP_PROXY_PORT="${SRP_PROXY_PORT:-8159}"
SRP_PROXY_URL="${SRP_PROXY_ADDR}:${SRP_PROXY_PORT}"
SRP_KEYSTORE_DIR="${TESTS_DIR}/keystore-srp-bind9"
SRP_LEASE_SECONDS="${SRP_LEASE_SECONDS:-5}"
SRP_KEY_LEASE_SECONDS="${SRP_KEY_LEASE_SECONDS:-1209600}"
SRP_EXPIRY_LEASE_SECONDS=1
SRP_EXPIRY_TIMEOUT=40 # covers the 30s reconciliation-retry path (see processExpiredNode's
                       # RCODE-check fix: a transiently-REFUSED expiry-delete self-heals on
                       # the next reconciliation pass rather than corrupting local state)

SRP_PROXY_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease"
SRP_CLIENT_BIN="${TESTS_DIR}/../bin/${OS}/srp_client_tester"
SRP_PROXY_LOG="/tmp/sig0lease_srp_proxy.log"
SRP_TMP_CONFIG=""
SRP_PROXY_PID=""
SRP_KEY_DIR=""

PERFORMED_TESTS=""

build_srp_binaries() {
    log_section "BUILD"
    (cd "$TESTS_DIR/.." && go build -o "$SRP_PROXY_BIN" ./cmd/sig0lease)
    (cd "$TESTS_DIR/.." && go build -o "$SRP_CLIENT_BIN" ./tests/srp_client_tester)
    log_success "Binaries built"
}

prepare_srp_config() {
    SRP_TMP_CONFIG="$(mktemp /tmp/sig0lease-srp-client-config.XXXXXX.yaml)"
    cat > "$SRP_TMP_CONFIG" <<EOF
server:
  address: ":${SRP_PROXY_PORT}"
  networks:
    - udp
    - tcp
upstreams:
  - address: "8.8.8.8:53"
    protocol: "udp"
    timeout: "5s"
handlers:
  srp_handler:
    upstream_zone: "${SRP_ZONE}"
    keystore_dir: "${SRP_KEYSTORE_DIR}"
    upstream: "${BIND9_ADDR}:${BIND9_PORT}"
    allow_udp: true
    lease_policy:
      min_key_lease_sec: 1
      max_key_lease_sec: 1209600
      min_rr_lease_sec: 1
      max_rr_lease_sec: 7200
processing_rules:
  - opcode: 5
    modules: ["srp_handler"]
EOF
}

start_srp_proxy() {
    log_section "START: SRP proxy"
    prepare_srp_config

    if ! [ -x "$SRP_PROXY_BIN" ]; then
        log_error "Proxy binary not found: $SRP_PROXY_BIN"
        return 1
    fi

    "$SRP_PROXY_BIN" "$SRP_TMP_CONFIG" > "$SRP_PROXY_LOG" 2>&1 &
    SRP_PROXY_PID=$!
    sleep 1

    if ! kill -0 "$SRP_PROXY_PID" 2>/dev/null; then
        log_error "SRP proxy failed to start. Log:"
        cat "$SRP_PROXY_LOG"
        return 1
    fi
    log_success "SRP proxy started (PID $SRP_PROXY_PID) on $SRP_PROXY_URL, log: $SRP_PROXY_LOG"
}

stop_srp_proxy() {
    if [ -n "${SRP_PROXY_PID:-}" ] && kill -0 "$SRP_PROXY_PID" 2>/dev/null; then
        log_step "Stopping SRP proxy (PID: $SRP_PROXY_PID)"
        kill "$SRP_PROXY_PID" || true
        sleep 1
    fi
    SRP_PROXY_PID=""
    if [ -n "$SRP_TMP_CONFIG" ] && [ -f "$SRP_TMP_CONFIG" ]; then
        rm -f "$SRP_TMP_CONFIG"
    fi
}

# run_srp_client <identity-name> [extra srp_client_tester flags...] -- identity-name selects
# a per-test persistent key file under a scratch dir (fresh on first use, reused after);
# pass a never-before-used name to get a fresh identity, the same name again to reuse one
# (refresh / conflict scenarios).
run_srp_client() {
    local identity="$1"; shift
    "$SRP_CLIENT_BIN" -server="$SRP_PROXY_URL" -zone="$SRP_ZONE" \
        -keyfile="${SRP_KEY_DIR}/${identity}.key" "$@"
}

# dig_srp <name> <type> -- query BIND directly (not through the proxy), short form.
dig_srp() {
    dig_query_short "${BIND9_ADDR}:${BIND9_PORT}" "$1" "$2"
}

wait_for_srp_state() {
    local name="$1" rr_type="$2" state="$3" timeout="${4:-10}"
    local start
    start=$(date +%s)
    while true; do
        local got
        got="$(dig_srp "$name" "$rr_type")"
        if [ "$state" = "present" ] && [ -n "$got" ]; then
            return 0
        fi
        if [ "$state" = "absent" ] && [ -z "$got" ]; then
            return 0
        fi
        if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
            log_error "Timed out waiting for $name/$rr_type state=$state (last dig: '$got')"
            return 1
        fi
        sleep 1
    done
}

################################
# Tests
################################

test_register_and_dig() {
    local log_msg="TEST 1: Register -> dig at authoritative"
    log_section "$log_msg"

    local out
    out="$(run_srp_client id1 -host=host1.srp.test. -inst=Widget._http._tcp.srp.test. \
        -lease="$SRP_LEASE_SECONDS" -keylease="$SRP_KEY_LEASE_SECONDS")"
    echo "$out"
    echo "$out" | grep -q "Status: NOERROR (Rcode=0)" || { log_error "registration did not return NOERROR"; return 1; }

    [ -n "$(dig_srp host1.srp.test. A)" ] || { log_error "host A record not found at authoritative"; return 1; }
    [ -n "$(dig_srp host1.srp.test. KEY)" ] || { log_error "host KEY record not found at authoritative"; return 1; }
    [ -n "$(dig_srp Widget._http._tcp.srp.test. SRV)" ] || { log_error "instance SRV not found at authoritative"; return 1; }
    [ -n "$(dig_srp _http._tcp.srp.test. PTR)" ] || { log_error "PTR not found at authoritative"; return 1; }

    # RFC 6763 S9: the proxy must also maintain the Service Type Enumeration record so
    # "browse everything" tools (which query this name first, not a specific type's own
    # browsing PTR) can find what's registered -- see reconcileServiceEnumeration.
    wait_for_srp_state _services._dns-sd._udp.srp.test. PTR present 10 || { log_error "S9 enumeration record not found at authoritative"; return 1; }
    dig_srp _services._dns-sd._udp.srp.test. PTR | grep -qi "_http._tcp.srp.test." \
        || { log_error "S9 enumeration record does not list _http._tcp.srp.test."; return 1; }

    log_success "Register landed at authoritative: host A/KEY, instance SRV/TXT, PTR, and S9 enumeration all present"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_refresh() {
    local log_msg="TEST 2: Refresh (same identity) -> NOERROR"
    log_section "$log_msg"

    local out
    out="$(run_srp_client id1 -host=host1.srp.test. -inst=Widget._http._tcp.srp.test. \
        -lease="$SRP_LEASE_SECONDS" -keylease="$SRP_KEY_LEASE_SECONDS")"
    echo "$out"
    echo "$out" | grep -q "Status: NOERROR (Rcode=0)" || { log_error "refresh did not return NOERROR"; return 1; }

    log_success "Refresh accepted"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_conflict() {
    local log_msg="TEST 3: Conflict (different identity, same host) -> YXDOMAIN"
    log_section "$log_msg"

    local out
    out="$(run_srp_client id2-conflict -host=host1.srp.test. -inst=Gadget._http._tcp.srp.test. \
        -lease="$SRP_LEASE_SECONDS" -keylease="$SRP_KEY_LEASE_SECONDS")" || true
    echo "$out"
    echo "$out" | grep -q "Status: YXDOMAIN (Rcode=6)" || { log_error "expected YXDOMAIN for a conflicting registration"; return 1; }

    # The rejected identity's own instance name must never have landed.
    [ -z "$(dig_srp Gadget._http._tcp.srp.test. SRV)" ] || { log_error "conflicting instance unexpectedly landed at authoritative"; return 1; }
    # The original registration must be untouched.
    [ -n "$(dig_srp host1.srp.test. A)" ] || { log_error "original host A record disappeared after a rejected conflicting registration"; return 1; }

    log_success "Conflicting registration correctly rejected (YXDOMAIN); original registration untouched"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_remove_one_instance() {
    local log_msg="TEST 4: Remove one service instance, host stays"
    log_section "$log_msg"

    local out
    out="$(run_srp_client id1 -host=host1.srp.test. -inst=Widget._http._tcp.srp.test. -inst-remove \
        -lease="$SRP_LEASE_SECONDS" -keylease="$SRP_KEY_LEASE_SECONDS")"
    echo "$out"
    echo "$out" | grep -q "Status: NOERROR (Rcode=0)" || { log_error "instance removal did not return NOERROR"; return 1; }

    wait_for_srp_state Widget._http._tcp.srp.test. SRV absent 10 || return 1
    [ -n "$(dig_srp host1.srp.test. A)" ] || { log_error "host A record disappeared after removing just the instance"; return 1; }

    # RFC 6763 S9: Widget was the only _http._tcp instance registered so far, so removing it
    # must clear the type out of the enumeration record too, not just leave it stale.
    wait_for_srp_state _services._dns-sd._udp.srp.test. PTR absent 10 \
        || { log_error "S9 enumeration record still lists a type with no live instances"; return 1; }

    log_success "Service instance removed; host registration untouched; S9 enumeration record cleared"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_remove_all() {
    # RFC 9665's Host Description Instruction signals "delete this host's registration" by
    # a Delete All RRsets with ZERO Add operations (S3.3.1.3) -- i.e. no A/AAAA adds, which
    # is a structural signal, not a LEASE=0 one (that's RFC 9664 Case C; SRP has no direct
    # analog -- a KEY registration otherwise persists to its own KEY-LEASE, tested
    # separately by test_expiry). So "remove all" here means the host's address data is
    # withdrawn while its KEY registration (the reserved name) remains live.
    local log_msg="TEST 5: Remove all host address data (bare host update, no A/AAAA adds)"
    log_section "$log_msg"

    local out
    out="$(run_srp_client id1 -host=host1.srp.test. -addr="" \
        -lease="$SRP_LEASE_SECONDS" -keylease="$SRP_KEY_LEASE_SECONDS")"
    echo "$out"
    echo "$out" | grep -q "Status: NOERROR (Rcode=0)" || { log_error "host address removal did not return NOERROR"; return 1; }

    wait_for_srp_state host1.srp.test. A absent 10 || return 1
    [ -n "$(dig_srp host1.srp.test. KEY)" ] || { log_error "host KEY unexpectedly disappeared -- only its address data should be withdrawn"; return 1; }

    log_success "Host address data withdrawn (A gone); KEY registration (reserved name) persists"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_expiry() {
    local log_msg="TEST 6: Expiry (LEASE=KEY-LEASE=${SRP_EXPIRY_LEASE_SECONDS}s) cleans up upstream"
    log_section "$log_msg"

    local out
    out="$(run_srp_client id3-expiry -host=host3.srp.test. -inst=Sprocket._http._tcp.srp.test. \
        -lease="$SRP_EXPIRY_LEASE_SECONDS" -keylease="$SRP_EXPIRY_LEASE_SECONDS")"
    echo "$out"
    echo "$out" | grep -q "Status: NOERROR (Rcode=0)" || { log_error "fresh registration for expiry test did not return NOERROR"; return 1; }
    [ -n "$(dig_srp host3.srp.test. A)" ] || { log_error "host A record not found right after registration"; return 1; }

    # RFC 6763 S9: Sprocket is a fresh _http._tcp instance (the type dropped out of the
    # enumeration record when TEST 4 removed the last one) -- registering it must bring the
    # type back.
    wait_for_srp_state _services._dns-sd._udp.srp.test. PTR present 10 \
        || { log_error "S9 enumeration record did not pick the type back up after a fresh registration"; return 1; }

    log_step "Waiting up to ${SRP_EXPIRY_TIMEOUT}s for upstream expiry cleanup (self-heals via the 30s reconciliation pass if a delete is transiently rejected -- see processExpiredNode's RCODE check)"
    wait_for_srp_state host3.srp.test. A absent "$SRP_EXPIRY_TIMEOUT" || return 1
    wait_for_srp_state host3.srp.test. KEY absent "$SRP_EXPIRY_TIMEOUT" || return 1
    wait_for_srp_state Sprocket._http._tcp.srp.test. SRV absent "$SRP_EXPIRY_TIMEOUT" || return 1
    wait_for_srp_state _http._tcp.srp.test. PTR absent "$SRP_EXPIRY_TIMEOUT" || return 1

    # Sprocket was again the only live _http._tcp instance, so its expiry must clear the
    # enumeration record one more time.
    wait_for_srp_state _services._dns-sd._udp.srp.test. PTR absent "$SRP_EXPIRY_TIMEOUT" \
        || { log_error "S9 enumeration record still lists a type with no live instances after expiry"; return 1; }

    log_success "Expiry cleaned up host A/KEY, instance SRV, the shared-type PTR, and the S9 enumeration record at authoritative"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

################################
# Top level
################################
run_all_tests() {
    log_section "SIG0LEASE SRP (RFC 9665) INTEGRATION TEST SUITE"
    echo "Real components only: real proxy process (srp_handler), real client helper,"
    echo "real local BIND 9 authoritative for ${SRP_ZONE} (plan S14 Option C)."
    echo ""

    trap cleanup EXIT

    require_command dig
    require_command named
    require_command go

    SRP_KEY_DIR="$(mktemp -d /tmp/sig0lease-srp-client-identities.XXXXXX)"

    build_srp_binaries
    start_bind9
    start_srp_proxy

    test_register_and_dig
    test_refresh
    test_conflict
    test_remove_one_instance
    test_remove_all
    test_expiry

    log_section "TEST RESULTS"
    echo -e "${GREEN}All SRP integration tests completed successfully!${NC}"
    echo -e "$PERFORMED_TESTS"
    echo ""
    echo "SRP proxy log: $SRP_PROXY_LOG"
    echo "BIND log: ${BIND9_RUNDIR}/named.stdout.log"
}

cleanup() {
    set +e
    log_section "CLEANUP"
    stop_srp_proxy
    stop_bind9
    [ -n "$SRP_KEY_DIR" ] && rm -rf "$SRP_KEY_DIR"
    set -e
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
        exit 1
        ;;
esac
