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
BIND9_RUNDIR=""
BIND9_PID=""

# start_bind9 copies the named.conf.in/srp.test.zone.in templates (checked into the repo)
# into a fresh scratch runtime directory -- never running named against the source tree's
# own copy, since dynamic updates rewrite the zone file and bump its SOA serial in place.
start_bind9() {
    log_section "START: local BIND 9 (srp.test.)"

    require_command named
    require_command named-checkconf

    BIND9_RUNDIR="$(mktemp -d /tmp/sig0lease-bind9.XXXXXX)"
    sed "s#@RUNDIR@#${BIND9_RUNDIR}#g" "${BIND9_TEMPLATE_DIR}/named.conf.in" > "${BIND9_RUNDIR}/named.conf"
    cp "${BIND9_TEMPLATE_DIR}/srp.test.zone.in" "${BIND9_RUNDIR}/srp.test.zone"
    cp "${BIND9_TEMPLATE_DIR}/default.service.arpa.zone.in" "${BIND9_RUNDIR}/default.service.arpa.zone"

    if ! named-checkconf "${BIND9_RUNDIR}/named.conf"; then
        log_error "named.conf failed validation"
        return 1
    fi

    named -c "${BIND9_RUNDIR}/named.conf" -g > "${BIND9_RUNDIR}/named.stdout.log" 2>&1 &
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
            cat "${BIND9_RUNDIR}/named.stdout.log" || true
            return 1
        fi
        if [ $(( $(date +%s) - start )) -ge 10 ]; then
            log_error "Timed out waiting for named to answer for ${BIND9_ZONE}"
            cat "${BIND9_RUNDIR}/named.stdout.log" || true
            return 1
        fi
        sleep 0.2
    done

    if [ -z "$(dig +short +time=1 +tries=1 "@${BIND9_ADDR}" -p "${BIND9_PORT}" default.service.arpa. SOA 2>/dev/null)" ]; then
        log_error "named came up but did not load default.service.arpa. -- check the log:"
        cat "${BIND9_RUNDIR}/named.stdout.log" || true
        return 1
    fi

    log_success "named started (PID $BIND9_PID), serving ${BIND9_ZONE} on ${BIND9_ADDR}:${BIND9_PORT}"
    log_success "named log: ${BIND9_RUNDIR}/named.stdout.log"
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
