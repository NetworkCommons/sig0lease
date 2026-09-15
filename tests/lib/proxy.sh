# tests/lib/proxy.sh -- build, start, stop, and inspect the proxy process
# itself, plus the scratch-config machinery that lets a test run its own
# proxy with lease-policy minimums floored for fast tests. See lib/common.sh
# for the "no set -e, return not exit" rules this file follows.

if [ -n "${_SIG0LEASE_LIB_PROXY_SOURCED:-}" ]; then
    return 0 2>/dev/null || true
fi
_SIG0LEASE_LIB_PROXY_SOURCED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$LIB_DIR/common.sh"

CLIENT_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease-client"
BLACKLISTED_TESTER_BIN="${TESTS_DIR}/../bin/${OS}/blacklisted_tester"

build_binaries() {
    log_section "BUILD"
    log_step "Building proxy and client binaries"
    (cd "$TESTS_DIR/.." && go build -o "$PROXY_BIN" ./cmd/sig0lease)
    (cd "$TESTS_DIR/.." && go build -o "$CLIENT_BIN" ./cmd/sig0lease-client)
    (cd "$TESTS_DIR/.." && go build -o "$BLACKLISTED_TESTER_BIN" ./tests/blacklisted_tester.go)
    log_success "Binaries built"
}

yaml_get_lease_time() {
    local key="$1"

    local value=""

    if command -v yq >/dev/null 2>&1; then
        value="$(yq -r ".handlers.update.lease_policy.${key} // \"\"" "$LEASE_CONFIG_FILE" 2>/dev/null || true)"
    else
        echo "please install yq!"
        return 1
    fi

    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo "Invalid value for ${key}: $value"
        return 1
    fi
}

# Check if a proxy/service is ALREADY listening on PROXY_PORT. Sets the
# global PORT_HEX as a side effect (consumed later by start_proxy's
# post-launch listener check).
is_port_in_use() {
    PORT_HEX=$(printf '%04X' "$PROXY_PORT")

    if [ "${OS}" = "darwin" ]; then
        lsof -nP -iTCP:"${PROXY_PORT}" -sTCP:LISTEN >/dev/null 2>&1 || \
            lsof -nP -iUDP:"${PROXY_PORT}" >/dev/null 2>&1
    elif command -v ss >/dev/null 2>&1; then
        ss -tuln 2>/dev/null | grep -qE ":${PROXY_PORT}\\b"
    elif [ -f /proc/net/tcp ] || [ -f /proc/net/udp ]; then
        grep ":${PORT_HEX} " /proc/net/tcp 2>/dev/null | grep -q " 0A " || \
            grep ":${PORT_HEX} " /proc/net/udp 2>/dev/null | grep -q " 07 "
    else
        return 1
    fi
}

# prepare_lease_config decides, once, whether this run will start its own
# proxy or reuse one already listening on PROXY_PORT, and sets
# LEASE_CONFIG_FILE accordingly:
#   - starting our own proxy: writes a scratch TMP_CONFIG_FILE with
#     min_key_lease_sec/min_rr_lease_sec forced down to
#     TEST_MIN_LEASE_SECONDS, so lease-cycle tests don't wait out the real
#     policy minimums.
#   - reusing an already-running proxy: we don't control that process's
#     config, so LEASE_CONFIG_FILE falls back to the real CONFIG_FILE
#     (whatever policy it's actually enforcing).
# Idempotent: safe to call from multiple entry points (e.g. a caller that
# needs lease values before start_proxy runs, and start_proxy itself).
prepare_lease_config() {
    if [ "$LEASE_CONFIG_PREPARED" = true ]; then
        return 0
    fi
    LEASE_CONFIG_PREPARED=true

    if is_port_in_use; then
        REUSED_PROXY=true
        LEASE_CONFIG_FILE="$CONFIG_FILE"
        return 0
    fi

    log_step "Preparing runtime config for listen address $PROXY_ADDR:$PROXY_PORT"

    TMP_CONFIG_FILE="$(mktemp /tmp/sig0lease-config.XXXXXX)"
    cp "$CONFIG_FILE" "$TMP_CONFIG_FILE"
    sed -i.bak \
        -e "s|^  address:.*$|  address: \"$PROXY_ADDR:$PROXY_PORT\"|" \
        -e "s|^      min_key_lease_sec:.*$|      min_key_lease_sec: ${TEST_MIN_LEASE_SECONDS}|" \
        -e "s|^      min_rr_lease_sec:.*$|      min_rr_lease_sec: ${TEST_MIN_LEASE_SECONDS}|" \
        "$TMP_CONFIG_FILE"
    rm -f "$TMP_CONFIG_FILE.bak"

    LEASE_CONFIG_FILE="$TMP_CONFIG_FILE"
}

start_proxy() {
    log_section "START: Proxy Process"

    prepare_lease_config

    # If already running, reuse it and skip startup
    if [ "$REUSED_PROXY" = true ]; then
        log_success "Reusing proxy already listening on ${PROXY_ADDR}:${PROXY_PORT}"
        return 0
    fi

    if ! [ -x "$PROXY_BIN" ]; then
        log_error "Proxy binary not found or not executable: $PROXY_BIN"
        return 1
    fi

    log_step "Starting proxy on $PROXY_URL with config: $TMP_CONFIG_FILE"

    "$PROXY_BIN" "$TMP_CONFIG_FILE" > "$LOG_FILE" 2>&1 &
    PROXY_PID=$!

    sleep 2

    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        log_error "Proxy failed to start. Check logs:"
        cat "$LOG_FILE"
        if grep -q "address already in use" "$LOG_FILE"; then
            log_error "Port $PROXY_PORT is already in use. Re-run with a free port: PROXY_PORT=18053 tests/test_update.sh run"
        fi
        return 1
    fi
    # Verify our proxy PID owns at least one listener on the target port.
    is_listening=true

    if [ "${OS}" = "darwin" ]
    then
        if ! lsof -nP -a -p "$PROXY_PID" -iTCP:"${PROXY_PORT}" -sTCP:LISTEN >/dev/null 2>&1 && \
        ! lsof -nP -a -p "$PROXY_PID" -iUDP:"${PROXY_PORT}" >/dev/null 2>&1
        then
            is_listening=false
        fi
    elif command -v ss >/dev/null 2>&1
    then
        if ! ss -tulnp 2>/dev/null | grep -E ":${PROXY_PORT}\\b" | grep -q "pid=${PROXY_PID},"
        then
            is_listening=false
        fi
    elif [ -f /proc/net/tcp ] || [ -f /proc/net/udp ]
    then
        # Fallback for container environments without lsof/ss:
        # Check /proc/net/tcp (state 0A = LISTEN) and /proc/net/udp for the port.
        if ! grep ":${PORT_HEX} " /proc/net/tcp 2>/dev/null | grep -q " 0A " && \
           ! grep ":${PORT_HEX} " /proc/net/udp 2>/dev/null | grep -q " 07 "
        then
            is_listening=false
        fi
    else
        log_error "Cannot verify proxy listening: no lsof, ss, or /proc/net available"
        return 1
    fi

    if [ "${is_listening}" = false ]
    then
        log_error "Proxy PID $PROXY_PID is not listening on port ${PROXY_PORT}"
        kill "$PROXY_PID" 2>/dev/null || true
        return 1
    fi


    log_success "Proxy started successfully on ${PROXY_ADDR}:${PROXY_PORT} (PID: $PROXY_PID)"
    log_success "Proxy log: tail -f $LOG_FILE"
}

stop_proxy() {
    if [ ! -z "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        log_step "Stopping sig0lease proxy (PID: $PROXY_PID)"
        kill "$PROXY_PID" || true
        sleep 1
        log_success "Proxy stopped"
    fi
    PROXY_PID=""
}

restart_proxy() {
    stop_proxy
    start_proxy
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
