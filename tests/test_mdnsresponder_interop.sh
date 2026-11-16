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
# Direction 2: OUR client (client/srp, via cmd/sig0lease-srp-client) against the real
# srp-mdns-proxy -- both Register and, importantly, Deregister (this project's own new
# removal capability, added specifically to extend interop coverage past plain registration).
# srp-mdns-proxy hands what it accepts to the mDNS daemon, so both calls must return NOERROR,
# its log must confirm the update, and mDNSResponder's dns-sd must then find (and, after
# Deregister, no longer find) the service on the local link.
#
# Direction 3: an application advertises a service through the mDNS daemon (dns-sd -P), and OUR
# sig0lease-agent, whose template has an mdns mirror that learns it from the daemon's client
# socket like any DNS-SD application, registers it with OUR registrar (the Direction-1 proxy),
# so it must appear at BIND. When the application stops advertising, and when the agent stops,
# the records must go again.
#
# The mDNS daemon (lib/mdnsresponder.sh): on Linux, mDNSResponder's own mdnsd, built from the
# same checkout and started here, which needs root; on macOS, the system's mDNSResponder with
# /usr/bin/dns-sd, as in the Mac demo, and no root. Either way Directions 2 and 3 advertise their
# test services on the local network while they run.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/proxy.sh"
source "$SCRIPT_DIR/lib/dns.sh"
source "$SCRIPT_DIR/lib/bind9.sh"
source "$SCRIPT_DIR/lib/mdnsresponder.sh"

D1_ZONE="default.service.arpa."
D1_PROXY_ADDR="127.0.0.1"
D1_PROXY_PORT="${D1_PROXY_PORT:-18159}"
D1_PROXY_URL="${D1_PROXY_ADDR}:${D1_PROXY_PORT}"
D1_KEYSTORE_DIR="${TESTS_DIR}/keystore-srp-bind9-default-arpa"
D1_MAX_RR_LEASE_SECONDS=7200 # the D1 proxy's max_rr_lease_sec; D1-TEST 1 asks for more

D2_CLIENT_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease-srp-client"
# The Direction-1 proxy's config and log (lib/proxy.sh's proxy_run_prepare).
D1_RUN_DIR="$PROXY_RUN_ROOT/mdnsresponder-interop"
D1_TMP_CONFIG="$D1_RUN_DIR/config.yaml"
D1_PROXY_LOG="$D1_RUN_DIR/proxy.log"
D1_PROXY_PID=""

D2_MDNS_PROXY_LOG="/tmp/srp-mdns-proxy_interop.log"
D2_MDNS_PROXY_PID=""
D2_MDNS_PROXY_PORT=""
D2_KEY_DIR=""

D3_HOST="d3-host"
D3_ADDR="192.0.2.33"
D3_INSTANCE="Mirror Demo"
D3_INSTANCE_DNS='Mirror\032Demo' # D3_INSTANCE as dig takes and prints it
D3_ADVERT_LOG="/tmp/sig0lease_d3_advert.log"
D3_ADVERT_PID=""
D3_AGENT_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease-agent"
D3_AGENT_LOG="/tmp/sig0lease_d3_agent.log"
D3_AGENT_PID=""
D3_AGENT_DIR="" # the agent's template, and its keystore under it

PERFORMED_TESTS=""

build_interop_binaries() {
    log_section "BUILD"
    (cd "$TESTS_DIR/.." && go build -o "$PROXY_BIN" ./cmd/sig0lease)
    (cd "$TESTS_DIR/.." && go build -o "$D2_CLIENT_BIN" ./cmd/sig0lease-srp-client)
    (cd "$TESTS_DIR/.." && go build -o "$D3_AGENT_BIN" ./cmd/sig0lease-agent)
    build_mdnsresponder
    log_success "Binaries ready"
}

################################
# Direction 1: real srp-client -> our registrar
################################

prepare_d1_config() {
    cat > "$D1_TMP_CONFIG" <<EOF
server:
  address: ":${D1_PROXY_PORT}"
  diagnostics: true
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
      max_rr_lease_sec: ${D1_MAX_RR_LEASE_SECONDS}
authoritative:
  max_inflight_updates: ${BIND9_SIG0_QUOTA}
processing_rules:
  - opcode: 5
    modules: ["srp_handler"]
EOF
}

start_d1_proxy() {
    log_section "START: our registrar for ${D1_ZONE} (Direction 1)"
    prepare_d1_config
    proxy_launch "$D1_TMP_CONFIG" "$D1_PROXY_PORT" "$D1_PROXY_LOG" || return 1
    D1_PROXY_PID="$LAUNCHED_PROXY_PID"
    log_success "Direction-1 proxy listening (PID $D1_PROXY_PID) on $D1_PROXY_URL, config $D1_TMP_CONFIG"
}

stop_d1_proxy() {
    proxy_stop "$D1_PROXY_PID"
    D1_PROXY_PID=""
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
    # the later stop_process) reliably targets the actual srp-client process, not a subshell
    # wrapper that may or may not propagate the signal to its child.
    (cd "$scratch" && exec "$MDNSRESPONDER_SRP_CLIENT_BIN" --server "${D1_PROXY_ADDR}%${D1_PROXY_PORT}" --log-stderr \
        --host-name "$label" --lease-time 3600 "$@") > "$logfile" 2>&1 &
    local pid=$!
    local start
    start=$(date +%s)
    while ! grep -q "$pattern" "$logfile" 2>/dev/null; do
        if [ $(( $(date +%s) - start )) -ge 10 ]; then
            stop_process "$pid" KILL || true
            log_error "Timed out waiting for ${label}'s expected log line: $pattern"
            cat "$logfile"
            return 1
        fi
        sleep 0.2
    done
    stop_process "$pid" KILL || true
}

test_d1_register() {
    local log_msg="D1-TEST 1: Plain registration (srp-client) -> dig at authoritative, granted lease adopted"
    log_section "$log_msg"

    # Asks for more than the proxy grants (a later --lease-time overrides the driver's 3600).
    # srp-client logs the lease it will refresh on before its Register Reply line: "set to"
    # when it read the proxy's Update Lease option, "defaults to" its own request when it did
    # not -- which it did for as long as our replies echoed the Zone section (RFC 2136 S3.8,
    # handlers.updateResponse).
    run_srp_client_bg_wait /tmp/d1-register.log d1-register "Register Reply for d1-register: 0" \
        --lease-time $(( D1_MAX_RR_LEASE_SECONDS * 2 )) || return 1
    grep -q "Lease time set to ${D1_MAX_RR_LEASE_SECONDS}\$" /tmp/d1-register.log \
        || { log_error "srp-client did not adopt the lease the proxy granted (${D1_MAX_RR_LEASE_SECONDS}s):"; grep "Lease time" /tmp/d1-register.log; return 1; }

    [ -n "$(dig_d1_wait d1-register.default.service.arpa. A)" ] || { log_error "host A record not found"; return 1; }
    [ -n "$(dig_d1_wait d1-register.default.service.arpa. KEY)" ] || { log_error "host KEY record not found"; return 1; }
    [ -n "$(dig_d1_wait d1-register._ipps._tcp.default.service.arpa. SRV)" ] || { log_error "instance SRV not found"; return 1; }
    [ -n "$(dig_d1_wait _ipps._tcp.default.service.arpa. PTR)" ] || { log_error "PTR not found"; return 1; }

    log_success "Plain registration landed: host A/KEY, instance SRV, PTR all present; srp-client refreshes on the granted ${D1_MAX_RR_LEASE_SECONDS}s"
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

    # Its SRP listener takes a free UDP port. Its DNS proxy, where it starts, listens on 53: on
    # macOS it does (an unprivileged process may bind 53 there); on Linux it stops before, for
    # want of a TLS key.
    local ports
    ports="$(listening_ports udp "$D2_MDNS_PROXY_PID" | { grep -vx 53 || true; })"
    if [ -z "$ports" ] || [ "$ports" != "${ports%%$'\n'*}" ]; then
        log_error "Expected one UDP port besides 53 for srp-mdns-proxy's SRP listener, found: ${ports:-none}"
        return 1
    fi
    D2_MDNS_PROXY_PORT="$ports"
    log_success "srp-mdns-proxy started (PID $D2_MDNS_PROXY_PID) on 127.0.0.1:${D2_MDNS_PROXY_PORT}"
}

stop_d2_mdns_proxy() {
    if [ -n "${D2_MDNS_PROXY_PID:-}" ] && kill -0 "$D2_MDNS_PROXY_PID" 2>/dev/null; then
        stop_process "$D2_MDNS_PROXY_PID" || true
    fi
    D2_MDNS_PROXY_PID=""
}

test_d2_register() {
    local log_msg="D2-TEST 1: Register (our client) -> srp-mdns-proxy -> mDNS daemon, found with dns-sd"
    log_section "$log_msg"

    # -k=13 generates this identity's key on first use (sig0lease-srp-client no longer
    # auto-generates a missing key by default -- see the -k flag doc); the deregister
    # call below reuses the same key without needing -k again.
    local out
    out="$("$D2_CLIENT_BIN" -domain=default.service.arpa. -host=d2-register -addr=192.0.2.111 -transport=udp \
        -server="127.0.0.1:${D2_MDNS_PROXY_PORT}" -instance=Gizmo:_http._tcp:8080 -txt=Gizmo:path=/d2 -once \
        -keystore="${D2_KEY_DIR}/d2-register" -k=13 2>&1)" || { echo "$out"; log_error "register did not succeed"; return 1; }
    echo "$out"
    echo "$out" | grep -q "Status: NOERROR (Rcode=0)" || { log_error "register did not return NOERROR"; return 1; }

    grep -q "srp_evaluate: update for d2-register.local. #0, .*validates" "$D2_MDNS_PROXY_LOG" \
        || { log_error "srp-mdns-proxy's own log did not confirm the update validates"; tail -n 40 "$D2_MDNS_PROXY_LOG"; return 1; }

    # srp-mdns-proxy publishes under local.; mDNSResponder's own browser must see it there.
    local browse resolve
    browse="$(dnssd_for 3 -B _http._tcp local.)"
    echo "$browse"
    echo "$browse" | grep -qE "Add .* _http\._tcp\. +Gizmo\$" \
        || { log_error "dns-sd -B did not find Gizmo._http._tcp.local."; return 1; }
    resolve="$(dnssd_for 3 -L Gizmo _http._tcp local.)"
    echo "$resolve"
    echo "$resolve" | grep -q "can be reached at d2-register.local.:8080" \
        || { log_error "dns-sd -L did not resolve Gizmo to d2-register.local.:8080"; return 1; }
    echo "$resolve" | grep -q "path=/d2" || { log_error "dns-sd -L did not show Gizmo's TXT path=/d2"; return 1; }

    log_success "srp-mdns-proxy validated our Register (NOERROR) and the mDNS daemon advertises Gizmo: dns-sd finds and resolves it"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_d2_deregister() {
    local log_msg="D2-TEST 2: Deregister (our client, LEASE=0) -> genuine NOERROR end-to-end"
    log_section "$log_msg"

    local out
    out="$("$D2_CLIENT_BIN" -domain=default.service.arpa. -host=d2-register -addr=192.0.2.111 -transport=udp \
        -server="127.0.0.1:${D2_MDNS_PROXY_PORT}" -instance=Gizmo:_http._tcp:8080 -deregister \
        -keystore="${D2_KEY_DIR}/d2-register" 2>&1)"
    echo "$out"
    echo "$out" | grep -q "Status: NOERROR (Rcode=0)" || { log_error "deregister did not return NOERROR"; return 1; }

    grep -q "delete for presumably previously-registered instance which is being withdrawn: Gizmo._http._tcp.default.service.arpa." "$D2_MDNS_PROXY_LOG" \
        || { log_error "srp-mdns-proxy's own log did not confirm the instance delete"; tail -n 40 "$D2_MDNS_PROXY_LOG"; return 1; }

    # A browse started right away may first report Gizmo from the daemon's cache, then its
    # removal about a second later: what counts is the last event dns-sd reports for it.
    local browse last
    browse="$(dnssd_for 4 -B _http._tcp local.)"
    echo "$browse"
    last="$(echo "$browse" | grep -E "(Add|Rmv) .* _http\._tcp\. +Gizmo\$" | tail -n 1)"
    if echo "$last" | grep -q "Add"; then
        log_error "dns-sd -B still finds Gizmo._http._tcp.local. after Deregister"
        return 1
    fi

    log_success "Deregister fully succeeded end-to-end: srp-mdns-proxy confirms the delete and dns-sd no longer finds Gizmo"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

################################
# Direction 3: the mDNS daemon's advertisement -> sig0lease-agent's mdns mirror -> our registrar
################################

# dig_d1_until <seconds> <name> <type> <present|absent> -- polls BIND until <name> <type> has
# an answer (present) or none (absent), and prints the last answer. The mirror needs a few
# seconds per change: resolve and address lookups, its 1s settle time, and the client's
# initial 0-3s delay before a registration.
dig_d1_until() {
    local seconds="$1" name="$2" rr_type="$3" want="$4"
    local start got
    start=$(date +%s)
    while true; do
        got="$(dig_d1 "$name" "$rr_type")"
        if { [ "$want" = present ] && [ -n "$got" ]; } || { [ "$want" = absent ] && [ -z "$got" ]; }; then
            echo "$got"
            return 0
        fi
        if [ $(( $(date +%s) - start )) -ge "$seconds" ]; then
            echo "$got"
            return 1
        fi
        sleep 0.5
    done
}

# start_d3_advert advertises D3_INSTANCE through the mDNS daemon as an application would.
# dns-sd -P is a proxy registration: it names its own host, d3-host.local., and address, so
# what the mirror finds does not depend on this machine's interfaces.
start_d3_advert() {
    dnssd_start -P "$D3_INSTANCE" _http._tcp local. 8080 "${D3_HOST}.local." "$D3_ADDR" "path=/d3" \
        > "$D3_ADVERT_LOG" 2>&1
    D3_ADVERT_PID=$DNSSD_PID
    local start
    start=$(date +%s)
    while ! grep -q "Got a reply for service ${D3_INSTANCE}._http._tcp.local.: Name now registered and active" "$D3_ADVERT_LOG" 2>/dev/null; do
        if [ $(( $(date +%s) - start )) -ge 10 ]; then
            log_error "dns-sd -P did not get ${D3_INSTANCE} registered:"
            cat "$D3_ADVERT_LOG"
            return 1
        fi
        sleep 0.2
    done
}

stop_d3_advert() {
    if [ -n "${D3_ADVERT_PID:-}" ] && kill -0 "$D3_ADVERT_PID" 2>/dev/null; then
        stop_process "$D3_ADVERT_PID" || true
    fi
    D3_ADVERT_PID=""
}

# start_d3_agent runs sig0lease-agent on a template with no hosts of its own and one mdns
# mirror, of D3_HOST's _http._tcp services.
start_d3_agent() {
    cat > "$D3_AGENT_DIR/agent.yaml" <<EOF
keystore: keys
registrars:
  - protocol: srp
    domain: ${D1_ZONE}
    server: ${D1_PROXY_URL}
    mirrors:
      - type: mdns
        socket: ${MDNSRESPONDER_MDNSD_SOCKET}
        hosts: [${D3_HOST}.local.]
        services: [_http._tcp]
EOF
    "$D3_AGENT_BIN" run "$D3_AGENT_DIR/agent.yaml" > "$D3_AGENT_LOG" 2>&1 &
    D3_AGENT_PID=$!
    sleep 0.5
    if ! kill -0 "$D3_AGENT_PID" 2>/dev/null; then
        log_error "sig0lease-agent exited at once:"
        cat "$D3_AGENT_LOG"
        return 1
    fi
}

# stop_d3_agent stops the agent the way Ctrl-C does and returns its exit status.
stop_d3_agent() {
    local status=0
    if [ -n "${D3_AGENT_PID:-}" ] && kill -0 "$D3_AGENT_PID" 2>/dev/null; then
        stop_process "$D3_AGENT_PID" || status=$?
    fi
    D3_AGENT_PID=""
    return "$status"
}

test_d3_mirror() {
    local log_msg="D3-TEST 1: a service advertised through the mDNS daemon is mirrored by sig0lease-agent's mdns mirror into the zone"
    log_section "$log_msg"

    start_d3_advert || return 1
    start_d3_agent || return 1

    local srv a txt ptr
    srv="$(dig_d1_until 20 "${D3_INSTANCE_DNS}._http._tcp.${D1_ZONE}" SRV present)" \
        || { log_error "no SRV for ${D3_INSTANCE} at BIND; agent log:"; cat "$D3_AGENT_LOG"; return 1; }
    echo "SRV: $srv"
    [ "$srv" = "0 0 8080 ${D3_HOST}.${D1_ZONE}" ] || { log_error "SRV is \"$srv\", want \"0 0 8080 ${D3_HOST}.${D1_ZONE}\""; return 1; }
    a="$(dig_d1 "${D3_HOST}.${D1_ZONE}" A)"
    [ "$a" = "$D3_ADDR" ] || { log_error "A ${D3_HOST}.${D1_ZONE} is \"$a\", want $D3_ADDR"; return 1; }
    txt="$(dig_d1 "${D3_INSTANCE_DNS}._http._tcp.${D1_ZONE}" TXT)"
    [ "$txt" = '"path=/d3"' ] || { log_error "TXT is $txt, want \"path=/d3\""; return 1; }
    ptr="$(dig_d1 "_http._tcp.${D1_ZONE}" PTR)"
    echo "$ptr" | grep -qxF "${D3_INSTANCE_DNS}._http._tcp.${D1_ZONE}" \
        || { log_error "PTR _http._tcp.${D1_ZONE} does not list ${D3_INSTANCE}: $ptr"; return 1; }

    log_success "the daemon's ${D3_INSTANCE} is at BIND as ${D3_HOST}.${D1_ZONE}:8080, address $D3_ADDR, TXT path=/d3"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_d3_withdraw() {
    local log_msg="D3-TEST 2: the application stops advertising -> the agent deregisters the host"
    log_section "$log_msg"

    stop_d3_advert
    dig_d1_until 20 "${D3_INSTANCE_DNS}._http._tcp.${D1_ZONE}" SRV absent > /dev/null \
        || { log_error "SRV for ${D3_INSTANCE} still at BIND after dns-sd -P stopped; agent log:"; cat "$D3_AGENT_LOG"; return 1; }
    dig_d1_until 5 "${D3_HOST}.${D1_ZONE}" A absent > /dev/null \
        || { log_error "A ${D3_HOST}.${D1_ZONE} still at BIND after the host was deregistered"; return 1; }
    grep -q "${D3_HOST}: deregistered \"${D3_INSTANCE}\" _http._tcp; names kept for its key\$" "$D3_AGENT_LOG" \
        || { log_error "the agent did not log the deregistration:"; cat "$D3_AGENT_LOG"; return 1; }

    log_success "the instance and its host left the zone when the daemon stopped advertising them"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_d3_stop() {
    local log_msg="D3-TEST 3: the agent stops (SIGTERM) -> it deregisters what it registered and exits 0"
    log_section "$log_msg"

    start_d3_advert || return 1
    dig_d1_until 20 "${D3_INSTANCE_DNS}._http._tcp.${D1_ZONE}" SRV present > /dev/null \
        || { log_error "the agent did not register ${D3_INSTANCE} again; agent log:"; cat "$D3_AGENT_LOG"; return 1; }
    stop_d3_agent || { log_error "the agent exited non-zero; log:"; cat "$D3_AGENT_LOG"; return 1; }
    dig_d1_until 5 "${D3_INSTANCE_DNS}._http._tcp.${D1_ZONE}" SRV absent > /dev/null \
        || { log_error "SRV for ${D3_INSTANCE} still at BIND after the agent stopped"; return 1; }
    dig_d1_until 5 "${D3_HOST}.${D1_ZONE}" A absent > /dev/null \
        || { log_error "A ${D3_HOST}.${D1_ZONE} still at BIND after the agent stopped"; return 1; }
    stop_d3_advert

    log_success "stopping the agent removed ${D3_INSTANCE} and ${D3_HOST} from the zone"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

################################
# Top level
################################
run_all_tests() {
    log_section "MDNSRESPONDER INTEROP TEST SUITE (RFC 9665 plan S12.3/S14 Option C)"
    echo "Real components only: real proxy process, real client library, and the real,"
    echo "unmodified mDNSResponder srp-client/srp-mdns-proxy binaries and mDNS daemon."
    echo ""

    trap cleanup EXIT

    require_command dig
    require_command named
    require_command go

    proxy_run_prepare "$D1_RUN_DIR" "$D1_PROXY_PORT"
    D2_KEY_DIR="$(mktemp -d /tmp/sig0lease-d2-identities.XXXXXX)"
    D3_AGENT_DIR="$(mktemp -d /tmp/sig0lease-d3-agent.XXXXXX)"

    build_interop_binaries
    start_bind9
    start_d1_proxy
    start_mdns_daemon
    start_d2_mdns_proxy

    test_d1_register
    test_d1_host_only
    test_d1_subtypes
    test_d1_diff_subtypes
    test_d1_renew_subtypes
    note_removal_flags_broken_upstream

    test_d2_register
    test_d2_deregister

    test_d3_mirror
    test_d3_withdraw
    test_d3_stop

    bind9_report_rejections || return 1
    BIND9_REJECTIONS_REPORTED=1

    log_section "TEST RESULTS"
    echo -e "${GREEN}All mDNSResponder interop tests completed successfully!${NC}"
    echo -e "$PERFORMED_TESTS"
    echo ""
    if [ "$PROXY_LAUNCH" = auto ]; then
        echo "Direction-1 proxy log: $D1_PROXY_LOG"
    fi
    echo "Direction-1 proxy config: $D1_TMP_CONFIG"
    echo "srp-mdns-proxy log: $D2_MDNS_PROXY_LOG"
    echo "sig0lease-agent log: $D3_AGENT_LOG"
    if [ -n "$MDNSD_LOG" ]; then echo "mdnsd log: $MDNSD_LOG"; fi
    echo "BIND log: ${BIND9_RUNDIR}/named.log"
}

cleanup() {
    set +e
    log_section "CLEANUP"
    # See test_srp.sh's cleanup: a failed run still shows why named rejected anything.
    [ -z "${BIND9_REJECTIONS_REPORTED:-}" ] && bind9_report_rejections
    stop_d3_agent
    stop_d3_advert
    stop_d1_proxy
    stop_d2_mdns_proxy
    stop_mdns_daemon
    stop_bind9
    pkill -f "$MDNSRESPONDER_SRP_CLIENT_BIN" 2>/dev/null
    [ -n "$D2_KEY_DIR" ] && rm -rf "$D2_KEY_DIR"
    [ -n "$D3_AGENT_DIR" ] && rm -rf "$D3_AGENT_DIR"
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
