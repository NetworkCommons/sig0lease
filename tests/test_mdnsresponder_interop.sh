#!/bin/bash
#
# RFC 9665 SRP interop test against the real, unmodified mDNSResponder/ServiceRegistration
# binaries (plan S12.3, S14 Option C's named primary cross-check) -- both directions, and as
# many distinct SRP message shapes as the reference implementation's own test tooling can
# actually produce against a live registrar (not just plain registration).
#
# Direction 1: the real srp-client against OUR registrar (srp_handler, upstream_zone =
# default.service.arpa., forwarding to a local scratch BIND 9 -- see lib/bind9.sh). Exercises
# plain registration, host-only (no service instance), and three subtype variants
# (test-subtypes/test-diff-subtypes/test-renew-subtypes). srp-client's own
# --remove-added-service/--delete-registrations flags are NOT run here: both were found,
# empirically, to hang forever against ANY real registrar (confirmed independent of our own
# code -- see test_removal_flags_are_upstream_broken's doc comment below for the exact
# evidence), a real bug/limitation in srp-client's own reconnect-on-second-message logic, not
# something this test suite can route around.
#
# Direction 2: OUR client (client/srp, via cmd/sig0lease-srp) against the real
# srp-mdns-proxy -- both Register and, importantly, Deregister (this project's own new
# removal capability, added specifically to extend interop coverage past plain registration).
# srp-mdns-proxy's own log line (srp_evaluate: ... validates) is the actual interop signal
# checked, not just the RCODE -- Register's RCODE is SERVFAIL in this sandbox only because
# srp-mdns-proxy's last step (bridging to a local mDNS daemon at /var/run/mdnsd) has nothing
# to connect to here; that's an environment gap unrelated to protocol correctness, unlike
# Deregister, which needs no such daemon and returns a genuine NOERROR end-to-end.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/dns.sh"
source "$SCRIPT_DIR/lib/bind9.sh"
source "$SCRIPT_DIR/lib/mdnsresponder.sh"

D1_ZONE="default.service.arpa."
D1_PROXY_ADDR="127.0.0.1"
D1_PROXY_PORT="${D1_PROXY_PORT:-18159}"
D1_PROXY_URL="${D1_PROXY_ADDR}:${D1_PROXY_PORT}"
D1_KEYSTORE_DIR="${TESTS_DIR}/keystore-srp-bind9-default-arpa"

D1_PROXY_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease"
D2_CLIENT_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease-srp"
D1_PROXY_LOG="/tmp/sig0lease_d1_proxy.log"
D1_TMP_CONFIG=""
D1_PROXY_PID=""

D2_MDNS_PROXY_LOG="/tmp/srp-mdns-proxy_interop.log"
D2_MDNS_PROXY_PID=""
D2_MDNS_PROXY_PORT=""
D2_KEY_DIR=""

PERFORMED_TESTS=""

build_interop_binaries() {
    log_section "BUILD"
    (cd "$TESTS_DIR/.." && go build -o "$D1_PROXY_BIN" ./cmd/sig0lease)
    (cd "$TESTS_DIR/.." && go build -o "$D2_CLIENT_BIN" ./cmd/sig0lease-srp)
    build_mdnsresponder
    log_success "Binaries ready"
}

################################
# Direction 1: real srp-client -> our registrar
################################

prepare_d1_config() {
    D1_TMP_CONFIG="$(mktemp /tmp/sig0lease-d1-config.XXXXXX.yaml)"
    cat > "$D1_TMP_CONFIG" <<EOF
server:
  address: ":${D1_PROXY_PORT}"
  networks:
    - udp
    - tcp
upstreams:
  - address: "8.8.8.8:53"
    protocol: "udp"
    timeout: "5s"
handlers:
  srp_handler:
    upstream_zone: "${D1_ZONE}"
    keystore_dir: "${D1_KEYSTORE_DIR}"
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

start_d1_proxy() {
    log_section "START: our registrar for ${D1_ZONE} (Direction 1)"
    prepare_d1_config

    "$D1_PROXY_BIN" "$D1_TMP_CONFIG" > "$D1_PROXY_LOG" 2>&1 &
    D1_PROXY_PID=$!
    sleep 1

    if ! kill -0 "$D1_PROXY_PID" 2>/dev/null; then
        log_error "Direction-1 proxy failed to start. Log:"
        cat "$D1_PROXY_LOG"
        return 1
    fi
    log_success "Direction-1 proxy started (PID $D1_PROXY_PID) on $D1_PROXY_URL"
}

stop_d1_proxy() {
    if [ -n "${D1_PROXY_PID:-}" ] && kill -0 "$D1_PROXY_PID" 2>/dev/null; then
        kill "$D1_PROXY_PID" || true
        sleep 1
    fi
    D1_PROXY_PID=""
    [ -n "$D1_TMP_CONFIG" ] && [ -f "$D1_TMP_CONFIG" ] && rm -f "$D1_TMP_CONFIG"
}

dig_d1() {
    dig_query_short "${BIND9_ADDR}:${BIND9_PORT}" "$1" "$2"
}

# dig_d1_wait <name> <type> -- like dig_d1, but retries briefly: srp-client's own success log
# line (what run_srp_client_bg_wait polls for) is written a few instructions before the
# proxy's own upstream write to BIND 9 is guaranteed queryable, so a dig immediately after
# killing the client can race a write that's still in flight. Confirmed live (not assumed) --
# an immediate dig_d1 for d1-register's A record intermittently came back empty even though
# the proxy's own log showed "Handler processed packet successfully" a moment earlier.
dig_d1_wait() {
    local name="$1" rr_type="$2"
    local start
    start=$(date +%s)
    local got
    while true; do
        got="$(dig_d1 "$name" "$rr_type")"
        if [ -n "$got" ]; then
            echo "$got"
            return 0
        fi
        if [ $(( $(date +%s) - start )) -ge 5 ]; then
            return 0
        fi
        sleep 0.2
    done
}

# run_srp_client_bg_wait <logfile> <host-label> <expect-pattern> <extra srp-client flags...>
# -- shared driver for every D1 scenario. None of srp-client's test modes self-terminate on
# success (confirmed empirically for all of plain registration, --host-only, and all three
# subtype variants -- an earlier assumption, based on a loose reading of the Phase 5 notes,
# that plain registration exits on its own was wrong): each just schedules its RFC 9664 S5.2
# refresh wakeup and keeps running like a real device would. So every scenario here runs in
# the background, waits for its own success-indicating log line, then gets killed -- there is
# no exit code to check.
#
# Runs from a fresh per-call scratch directory (a subshell's own cd, not the script's own):
# srp-client persists its generated identity key to "com.apple.srp-client.host-key" *relative
# to its CWD*, and reuses it across separate invocations sharing a CWD regardless of
# --host-name. Confirmed live to cause real failures -- a stale key from one host name's run
# leaking into a later, different host name's run intermittently produced a registration with
# no address data at all. A fresh CWD per call is the fix, not just a coincidence.
run_srp_client_bg_wait() {
    local logfile="$1" label="$2" pattern="$3"; shift 3
    local scratch
    scratch="$(mktemp -d /tmp/sig0lease-srpclient.XXXXXX)"
    # exec, not a plain call: makes the binary replace the subshell process image, so $! (and
    # the later `kill "$pid"`) reliably targets the actual srp-client process, not a subshell
    # wrapper that may or may not propagate the signal to its child.
    (cd "$scratch" && exec "$MDNSRESPONDER_SRP_CLIENT_BIN" --server "${D1_PROXY_ADDR}%${D1_PROXY_PORT}" --log-stderr \
        --host-name "$label" --lease-time 3600 "$@") > "$logfile" 2>&1 &
    local pid=$!
    local start
    start=$(date +%s)
    while ! grep -q "$pattern" "$logfile" 2>/dev/null; do
        if [ $(( $(date +%s) - start )) -ge 10 ]; then
            kill -9 "$pid" 2>/dev/null || true
            log_error "Timed out waiting for ${label}'s expected log line: $pattern"
            cat "$logfile"
            return 1
        fi
        sleep 0.2
    done
    kill -9 "$pid" 2>/dev/null || true
}

test_d1_register() {
    local log_msg="D1-TEST 1: Plain registration (srp-client) -> dig at authoritative"
    log_section "$log_msg"

    run_srp_client_bg_wait /tmp/d1-register.log d1-register "Register Reply for d1-register: 0" || return 1

    [ -n "$(dig_d1_wait d1-register.default.service.arpa. A)" ] || { log_error "host A record not found"; return 1; }
    [ -n "$(dig_d1_wait d1-register.default.service.arpa. KEY)" ] || { log_error "host KEY record not found"; return 1; }
    [ -n "$(dig_d1_wait d1-register._ipps._tcp.default.service.arpa. SRV)" ] || { log_error "instance SRV not found"; return 1; }
    [ -n "$(dig_d1_wait _ipps._tcp.default.service.arpa. PTR)" ] || { log_error "PTR not found"; return 1; }

    log_success "Plain registration landed: host A/KEY, instance SRV, PTR all present"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_d1_host_only() {
    local log_msg="D1-TEST 2: Host-only registration (--host-only, no service instance)"
    log_section "$log_msg"

    run_srp_client_bg_wait /tmp/d1-hostonly.log d1-hostonly "udp_response: Got a response" --host-only || return 1

    [ -n "$(dig_d1_wait d1-hostonly.default.service.arpa. KEY)" ] || { log_error "host KEY record not found"; return 1; }
    [ -z "$(dig_d1 d1-hostonly._ipps._tcp.default.service.arpa. SRV)" ] || { log_error "unexpected service instance for --host-only"; return 1; }

    log_success "Host-only registration landed: KEY present, no service instance created"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_d1_subtypes() {
    local log_msg="D1-TEST 3: Subtype registration (--test-subtypes, two instances: one with a subtype, one plain)"
    log_section "$log_msg"

    run_srp_client_bg_wait /tmp/d1-subtypes.log d1-subtypes "Second Register Reply for d1-subtypes: 0" --test-subtypes || return 1

    [ -n "$(dig_d1_wait subtype._sub._ipps._tcp.default.service.arpa. PTR)" ] || { log_error "subtype PTR not found"; return 1; }
    [ -n "$(dig_d1_wait d1-subtypes._ipps._tcp.default.service.arpa. SRV)" ] || { log_error "base-type instance not found"; return 1; }
    [ -n "$(dig_d1_wait othersub._sub._ipps._tcp.default.service.arpa. PTR)" ] || { log_error "second instance's subtype PTR not found"; return 1; }
    [ -n "$(dig_d1_wait foo-d1-subtypes._ipps._tcp.default.service.arpa. SRV)" ] || { log_error "second (foo-prefixed) instance not found"; return 1; }

    log_success "Both instances (with and without a distinguishing prefix) and both PTRs landed correctly"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_d1_diff_subtypes() {
    local log_msg="D1-TEST 4: Two distinct subtypes on two instances (--test-diff-subtypes)"
    log_section "$log_msg"

    run_srp_client_bg_wait /tmp/d1-diffsubtypes.log d1-diffsubtypes "Second Register Reply for d1-diffsubtypes: 0" --test-diff-subtypes || return 1

    [ -n "$(dig_d1_wait subtype._sub._ipps._tcp.default.service.arpa. PTR)" ] || { log_error "first subtype PTR not found"; return 1; }
    [ -n "$(dig_d1_wait othersub._sub._second._tcp.default.service.arpa. PTR)" ] || { log_error "second subtype PTR not found"; return 1; }

    log_success "Both distinct-subtype instances landed correctly"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_d1_renew_subtypes() {
    local log_msg="D1-TEST 5: Subtype renewal (--test-renew-subtypes, subtype changes subtype -> othersub)"
    log_section "$log_msg"

    run_srp_client_bg_wait /tmp/d1-renewsubtypes.log d1-renewsubtypes "Second Register Reply for d1-renewsubtypes: 0" --test-renew-subtypes || return 1

    # Verified live: the renewal fully replaces d1-renewsubtypes's own subtype PTR (this
    # project's own wipe-then-reinsert model, S4.5) -- checking against this instance's own
    # target specifically, not the owner name's overall emptiness, since D1-TEST 3/4 register
    # their own instances under the same "subtype" owner name and are still live at this
    # point in the same BIND 9 zone.
    # Not dig_d1_wait: that owner name (othersub._sub._ipps._tcp...) already has an unrelated
    # entry from D1-TEST 3's own "foo-d1-subtypes" instance, so a bare non-empty check would
    # pass immediately without actually waiting for *this* instance's own write to land --
    # wait for the specific target substring instead.
    local old_ptr new_ptr start
    old_ptr="$(dig_d1 subtype._sub._ipps._tcp.default.service.arpa. PTR | grep "d1-renewsubtypes" || true)"
    start=$(date +%s)
    while true; do
        new_ptr="$(dig_d1 othersub._sub._ipps._tcp.default.service.arpa. PTR | grep "d1-renewsubtypes" || true)"
        [ -n "$new_ptr" ] && break
        [ $(( $(date +%s) - start )) -ge 5 ] && break
        sleep 0.2
    done
    [ -z "$old_ptr" ] || { log_error "old subtype PTR for d1-renewsubtypes still present after renewal"; return 1; }
    [ -n "$new_ptr" ] || { log_error "renewed (othersub) subtype PTR for d1-renewsubtypes not found"; return 1; }

    log_success "Subtype renewal landed correctly: old subtype PTR gone, new one present"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

# Not a pass/fail test -- documents a real, confirmed-live finding rather than silently
# skipping these two flags. Both --remove-added-service and --delete-registrations trigger a
# SECOND message on the same already-connected UDP context (srp_deregister_instance /
# srp_deregister respectively), and srp-client's own reconnect logic then fails with
# "srp_connect_udp called with non-null I/O context" / "error -65549 connecting udp context",
# retrying forever without ever sending the removal. Reproduced against our registrar with
# fresh host names each time (ruling out proxy-side state) -- a genuine bug/limitation in
# srp-client's own test tooling, not something this project's registrar or client causes or
# can route around. Real removal interop (Direction 2's Deregister test below) still fully
# covers the removal *message shape* -- just driven by our own client instead of theirs,
# since theirs can't currently produce one against a live server.
note_removal_flags_broken_upstream() {
    log_section "D1-NOTE: --remove-added-service / --delete-registrations not run"
    echo "Both were tried live against this same registrar and found to hang forever --"
    echo "confirmed a bug in srp-client's own UDP reconnect logic (see this script's own"
    echo "top-of-file comment and note_removal_flags_broken_upstream's doc comment), not"
    echo "anything on our end. See the RFC 9665 plan doc's revision history for full detail."
}

################################
# Direction 2: our client -> real srp-mdns-proxy
################################

start_d2_mdns_proxy() {
    log_section "START: real srp-mdns-proxy (Direction 2)"

    "$MDNSRESPONDER_SRP_MDNS_PROXY_BIN" --log-stderr > "$D2_MDNS_PROXY_LOG" 2>&1 &
    D2_MDNS_PROXY_PID=$!
    sleep 1

    if ! kill -0 "$D2_MDNS_PROXY_PID" 2>/dev/null; then
        log_error "srp-mdns-proxy failed to start. Log:"
        cat "$D2_MDNS_PROXY_LOG"
        return 1
    fi

    require_command ss
    D2_MDNS_PROXY_PORT="$(ss -tulnp 2>/dev/null | grep "srp-mdns-proxy" | grep -oE ':[0-9]+' | head -1 | tr -d ':')"
    if [ -z "$D2_MDNS_PROXY_PORT" ]; then
        log_error "Could not discover srp-mdns-proxy's ephemeral UDP port"
        return 1
    fi
    log_success "srp-mdns-proxy started (PID $D2_MDNS_PROXY_PID) on 127.0.0.1:${D2_MDNS_PROXY_PORT}"
}

stop_d2_mdns_proxy() {
    if [ -n "${D2_MDNS_PROXY_PID:-}" ] && kill -0 "$D2_MDNS_PROXY_PID" 2>/dev/null; then
        kill "$D2_MDNS_PROXY_PID" || true
        sleep 1
    fi
    D2_MDNS_PROXY_PID=""
}

test_d2_register() {
    local log_msg="D2-TEST 1: Register (our client) -> srp-mdns-proxy validates it"
    log_section "$log_msg"

    # || true: the CLI itself exits 1 on a non-Success outcome, and SERVFAIL (not Success) is
    # the expected result here -- see the comment below. The real pass/fail signal is
    # srp-mdns-proxy's own log line, checked next.
    local out
    out="$("$D2_CLIENT_BIN" -domain=default.service.arpa. -host=d2-register -addr=192.0.2.111 -udp \
        -server="127.0.0.1:${D2_MDNS_PROXY_PORT}" -instance=Gizmo:_http._tcp:8080 -once \
        -keystore="${D2_KEY_DIR}/d2-register" 2>&1 || true)"
    echo "$out"

    # SERVFAIL here is expected and NOT a failure: it's srp-mdns-proxy's own last step
    # (bridging to a local mDNS daemon at /var/run/mdnsd) hitting an environment gap, not a
    # protocol problem -- see this script's top comment. The actual interop signal is
    # srp-mdns-proxy's own log line below.
    grep -q "srp_evaluate: update for d2-register.local. #0, .*validates" "$D2_MDNS_PROXY_LOG" \
        || { log_error "srp-mdns-proxy's own log did not confirm the update validates"; tail -n 40 "$D2_MDNS_PROXY_LOG"; return 1; }

    log_success "srp-mdns-proxy's independent parser validated our Register message"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_d2_deregister() {
    local log_msg="D2-TEST 2: Deregister (our client, LEASE=0) -> genuine NOERROR end-to-end"
    log_section "$log_msg"

    local out
    out="$("$D2_CLIENT_BIN" -domain=default.service.arpa. -host=d2-register -addr=192.0.2.111 -udp \
        -server="127.0.0.1:${D2_MDNS_PROXY_PORT}" -instance=Gizmo:_http._tcp:8080 -deregister \
        -keystore="${D2_KEY_DIR}/d2-register" 2>&1)"
    echo "$out"
    echo "$out" | grep -q "Status: NOERROR (Rcode=0)" || { log_error "deregister did not return NOERROR"; return 1; }

    grep -q "delete for presumably previously-registered instance which is being withdrawn: Gizmo._http._tcp.default.service.arpa." "$D2_MDNS_PROXY_LOG" \
        || { log_error "srp-mdns-proxy's own log did not confirm the instance delete"; tail -n 40 "$D2_MDNS_PROXY_LOG"; return 1; }

    log_success "Deregister fully succeeded end-to-end, srp-mdns-proxy's own log confirms the delete"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

################################
# Top level
################################
run_all_tests() {
    log_section "MDNSRESPONDER INTEROP TEST SUITE (RFC 9665 plan S12.3/S14 Option C)"
    echo "Real components only: real proxy process, real client library, and the real,"
    echo "unmodified mDNSResponder/ServiceRegistration srp-client/srp-mdns-proxy binaries."
    echo ""

    trap cleanup EXIT

    require_command dig
    require_command named
    require_command go
    require_command timeout

    D2_KEY_DIR="$(mktemp -d /tmp/sig0lease-d2-identities.XXXXXX)"

    build_interop_binaries
    start_bind9
    start_d1_proxy
    start_d2_mdns_proxy

    test_d1_register
    test_d1_host_only
    test_d1_subtypes
    test_d1_diff_subtypes
    test_d1_renew_subtypes
    note_removal_flags_broken_upstream

    test_d2_register
    test_d2_deregister

    log_section "TEST RESULTS"
    echo -e "${GREEN}All mDNSResponder interop tests completed successfully!${NC}"
    echo -e "$PERFORMED_TESTS"
    echo ""
    echo "Direction-1 proxy log: $D1_PROXY_LOG"
    echo "srp-mdns-proxy log: $D2_MDNS_PROXY_LOG"
    echo "BIND log: ${BIND9_RUNDIR}/named.stdout.log"
}

cleanup() {
    set +e
    log_section "CLEANUP"
    stop_d1_proxy
    stop_d2_mdns_proxy
    stop_bind9
    pkill -f "$MDNSRESPONDER_SRP_CLIENT_BIN" 2>/dev/null
    [ -n "$D2_KEY_DIR" ] && rm -rf "$D2_KEY_DIR"
    rm -rf /tmp/sig0lease-srpclient.*
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
