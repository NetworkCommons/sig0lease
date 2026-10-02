# tests/lib/bind9.sh -- start/stop a local, disposable BIND 9 instance for test_srp.sh's
# CI gate (plan S14 Option C): authoritative for srp.test., accepting SIG(0)-signed dynamic
# updates from the proxy's own test keystore key (tests/keystore-srp-bind9/). Also serves
# default.service.arpa. (tests/keystore-srp-bind9-default-arpa/'s key) on the same
# instance/port, for tests/test_mdnsresponder_interop.sh -- BIND routes purely by zone name,
# so one named process covers both without any port/instance duplication. See lib/common.sh
# for the "no set -e, return not exit" rules this file follows.

if [ -n "${_SIG0LEASE_LIB_BIND9_SOURCED:-}" ]; then
    return 0 2>/dev/null || true
fi
_SIG0LEASE_LIB_BIND9_SOURCED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$LIB_DIR/common.sh"

BIND9_TEMPLATE_DIR="${TESTS_DIR}/bind9"
BIND9_ZONE="srp.test."
BIND9_ADDR="127.0.0.1"
BIND9_PORT="${BIND9_PORT:-5300}"
# named's sig0checks-quota, and the proxy's matching authoritative.max_inflight_updates in the
# suites' generated configs. 1 is BIND 9.20's own default.
BIND9_SIG0_QUOTA="${BIND9_SIG0_QUOTA:-1}"
# Port that srp.test.'s _dnssd-srp._tcp SRV record advertises for the registrar. test_srp.sh
# sets it to its proxy's port, before calling start_bind9.
BIND9_SRP_REGISTRAR_PORT="${BIND9_SRP_REGISTRAR_PORT:-8159}"
BIND9_RUNDIR=""
BIND9_PID=""

# start_bind9 fills in the named.conf.in/srp.test.zone.in templates (checked into the repo)
# into a fresh scratch runtime directory -- never running named against the source tree's
# own copy, since dynamic updates rewrite the zone file and bump its SOA serial in place.
start_bind9() {
    log_section "START: local BIND 9 (srp.test.)"

    require_command named
    require_command named-checkconf

    BIND9_RUNDIR="$(mktemp -d /tmp/sig0lease-bind9.XXXXXX)"
    sed "s#@RUNDIR@#${BIND9_RUNDIR}#g; s#@SIG0_QUOTA@#${BIND9_SIG0_QUOTA}#g" "${BIND9_TEMPLATE_DIR}/named.conf.in" > "${BIND9_RUNDIR}/named.conf"
    sed "s#@SRP_REGISTRAR_PORT@#${BIND9_SRP_REGISTRAR_PORT}#g" "${BIND9_TEMPLATE_DIR}/srp.test.zone.in" > "${BIND9_RUNDIR}/srp.test.zone"
    cp "${BIND9_TEMPLATE_DIR}/default.service.arpa.zone.in" "${BIND9_RUNDIR}/default.service.arpa.zone"

    # Output kept for failures only: on success it is just BIND's "option 'sig0checks-quota'
    # is experimental" notice.
    if ! named-checkconf "${BIND9_RUNDIR}/named.conf" > "${BIND9_RUNDIR}/named-checkconf.log" 2>&1; then
        log_error "named.conf failed validation:"
        cat "${BIND9_RUNDIR}/named-checkconf.log"
        return 1
    fi

    # -f, not -g: -g forces all logging to stderr and ignores named.conf's logging block, so
    # named.log stayed empty and nothing below info level was ever recorded. -d 1 is the debug
    # level named.conf.in's "severity dynamic" channel follows -- see its comment for why 1.
    # Started from BIND9_RUNDIR because with -d, named writes its pre-config startup output to
    # named.run in the current directory; exec keeps $! the named process itself.
    (cd "$BIND9_RUNDIR" && exec named -c "${BIND9_RUNDIR}/named.conf" -f -d 1) > "${BIND9_RUNDIR}/named.stdout.log" 2>&1 &
    BIND9_PID=$!

    local start
    start=$(date +%s)
    while true; do
        if dig +short +time=1 +tries=1 "@${BIND9_ADDR}" -p "${BIND9_PORT}" "${BIND9_ZONE}" SOA >/dev/null 2>&1 \
            && [ -n "$(dig +short +time=1 +tries=1 "@${BIND9_ADDR}" -p "${BIND9_PORT}" "${BIND9_ZONE}" SOA 2>/dev/null)" ]; then
            break
        fi
        if ! kill -0 "$BIND9_PID" 2>/dev/null; then
            log_error "named exited during startup. Log:"
            cat "${BIND9_RUNDIR}/named.stdout.log" "${BIND9_RUNDIR}/named.log" 2>/dev/null || true
            return 1
        fi
        if [ $(( $(date +%s) - start )) -ge 10 ]; then
            log_error "Timed out waiting for named to answer for ${BIND9_ZONE}"
            cat "${BIND9_RUNDIR}/named.stdout.log" "${BIND9_RUNDIR}/named.log" 2>/dev/null || true
            return 1
        fi
        sleep 0.2
    done

    if [ -z "$(dig +short +time=1 +tries=1 "@${BIND9_ADDR}" -p "${BIND9_PORT}" default.service.arpa. SOA 2>/dev/null)" ]; then
        log_error "named came up but did not load default.service.arpa. -- check the log:"
        cat "${BIND9_RUNDIR}/named.log" || true
        return 1
    fi

    log_success "named started (PID $BIND9_PID), serving ${BIND9_ZONE} on ${BIND9_ADDR}:${BIND9_PORT}"
    log_success "named log: ${BIND9_RUNDIR}/named.log"
}

# bind9_report_rejections lists every request named rejected during this run, with named's
# own reason, from named.log. Only request-handling categories are matched, so startup noise
# such as the config category's "rndc.key: permission denied" is not mistaken for a
# rejection. A SIG(0) quota refusal (named.conf.in's logging comment) is reported but
# tolerated: the proxy retries it. Any other rejection -- an update-policy denial, an invalid
# signature, a failed update -- returns 1, even if a later retry hid it from the test's own
# checks.
bind9_report_rejections() {
    local log="${BIND9_RUNDIR}/named.log"
    [ -f "$log" ] || return 0

    local rejections quota others
    rejections="$(grep -E ' (client|update|update-security|security): .*(quota reached|denied|invalid signature|update failed|update unsuccessful|refused)' "$log" || true)"
    if [ -z "$rejections" ]; then
        log_success "named rejected no requests during this run"
        return 0
    fi
    quota="$(echo "$rejections" | grep -c 'SIG(0) checks quota reached' || true)"
    others="$(echo "$rejections" | grep -v 'SIG(0) checks quota reached' || true)"

    log_section "BIND REJECTIONS (${log})"
    if [ "$quota" -gt 0 ]; then
        # named rate-limits this message to about one line a second (measured: a burst of 13
        # quota refusals logged one line), so the count is of moments, not refused requests.
        echo "REFUSED under the SIG(0) checks quota, logged ${quota} time(s) -- each line can stand for several refused requests: a SIG(0) request arrived while named was verifying another (sig0checks-quota); the proxy retries these"
    fi
    if [ -n "$others" ]; then
        log_error "named rejected requests for other reasons:"
        echo "$others"
        return 1
    fi
    return 0
}

stop_bind9() {
    if [ -n "${BIND9_PID:-}" ] && kill -0 "$BIND9_PID" 2>/dev/null; then
        log_step "Stopping named (PID: $BIND9_PID)"
        kill "$BIND9_PID" || true
        sleep 1
        kill -0 "$BIND9_PID" 2>/dev/null && kill -9 "$BIND9_PID" 2>/dev/null || true
        log_success "named stopped"
    fi
    BIND9_PID=""
}
