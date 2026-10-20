# tests/lib/proxy.sh -- build, start, stop, and inspect the proxy process
# itself: the launch every suite shares (proxy_run_prepare, proxy_launch,
# proxy_stop), plus the config machinery that lets a test run the proxy on
# config.yaml with lease-policy minimums floored for fast tests. See
# lib/common.sh for the "no set -e, return not exit" rules this file follows.

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
        value="$(yq -r ".handlers.update.lease_policy.${key} // \"\"" "$PROXY_CONFIG_FILE" 2>/dev/null || true)"
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

################################
# Proxy lifecycle, shared by every suite
################################

# proxy_launch_mode_valid -- fails unless PROXY_LAUNCH (lib/common.sh) is auto or manual.
proxy_launch_mode_valid() {
    case "$PROXY_LAUNCH" in
        auto|manual) ;;
        *)
            log_error "Unknown PROXY_LAUNCH=$PROXY_LAUNCH (want auto or manual)"
            return 1
            ;;
    esac
}

# wait_for_port_free <port> -- waits up to PROXY_LAUNCH_TIMEOUT seconds for nothing to listen
# on <port>.
wait_for_port_free() {
    local port="$1" waited=0
    while is_listening "$port"; do
        if [ "$waited" -ge "$PROXY_LAUNCH_TIMEOUT" ]; then
            log_error "Port $port is still in use after ${PROXY_LAUNCH_TIMEOUT}s"
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

# proxy_run_prepare <dir> <port> -- readies <dir>, a suite's fixed directory under
# PROXY_RUN_ROOT, for a proxy that will listen on <port>. Nothing may listen there yet: with
# PROXY_LAUNCH=auto that fails the run; with manual it waits for you to stop the proxy, which
# would otherwise save its leases into this run's files as it stops. Then <dir> is emptied for
# the config and files the suite writes next.
proxy_run_prepare() {
    local dir="$1" port="$2"
    proxy_launch_mode_valid || return 1
    case "$dir" in
        "$PROXY_RUN_ROOT"/?*) ;;
        *)
            log_error "Proxy run directory $dir is not under $PROXY_RUN_ROOT"
            return 1
            ;;
    esac
    if is_listening "$port"; then
        if [ "$PROXY_LAUNCH" = auto ]; then
            log_error "Port $port is already in use. Stop what listens there, or run with PROXY_LAUNCH=manual to test a proxy you start yourself"
            return 1
        fi
        log_step "PROXY_LAUNCH=manual: something listens on port $port (PID $(listening_pid "$port")). Stop it before this run clears $dir; waiting up to ${PROXY_LAUNCH_TIMEOUT}s"
        wait_for_port_free "$port" || return 1
    fi
    rm -rf "$dir"
    mkdir -p "$dir"
}

# proxy_launch <config> <port> <log> -- has the proxy started on <config>, waits for it to
# listen on <port>, and sets LAUNCHED_PROXY_PID. With PROXY_LAUNCH=auto this script starts
# PROXY_BIN from the current directory, appending its output to <log>. With manual it asks you
# to start it -- from main/, e.g. in your debugger -- waits up to PROXY_LAUNCH_TIMEOUT seconds
# for a process other than the one proxy_stop left running to listen on <port>, and checks
# that it was started with <config>.
LAUNCHED_PROXY_PID=""
PROXY_STALE_PID="" # manual: the proxy proxy_stop left running, which proxy_launch must not take
proxy_launch() {
    local config="$1" port="$2" log="$3" pid waited=0
    LAUNCHED_PROXY_PID=""
    proxy_launch_mode_valid || return 1

    if [ "$PROXY_LAUNCH" = auto ]; then
        if ! [ -x "$PROXY_BIN" ]; then
            log_error "Proxy binary not found or not executable: $PROXY_BIN"
            return 1
        fi
        log_step "Starting proxy on port $port with config $config"
        "$PROXY_BIN" "$config" >> "$log" 2>&1 &
        pid=$!
        until is_listening "$port" "$pid"; do
            if ! kill -0 "$pid" 2>/dev/null || [ "$waited" -ge 10 ]; then
                log_error "The proxy (PID $pid) did not listen on port $port. Its log, $log:"
                cat "$log"
                stop_process "$pid" || true
                return 1
            fi
            sleep 1
            waited=$((waited + 1))
        done
        LAUNCHED_PROXY_PID="$pid"
        return 0
    fi

    if [ -n "$PROXY_STALE_PID" ] && [ "$(listening_pid "$port")" = "$PROXY_STALE_PID" ]; then
        log_step "PROXY_LAUNCH=manual: restart the proxy (PID $PROXY_STALE_PID) with config $config, so it reads it anew. Waiting up to ${PROXY_LAUNCH_TIMEOUT}s"
    else
        log_step "PROXY_LAUNCH=manual: start the proxy from main/ with config $config (VS Code: see tests/README.md). Waiting up to ${PROXY_LAUNCH_TIMEOUT}s for it on port $port"
    fi
    while :; do
        pid="$(listening_pid "$port")" || return 1
        if [ -n "$pid" ] && [ "$pid" != "$PROXY_STALE_PID" ]; then
            break
        fi
        if [ "$waited" -ge "$PROXY_LAUNCH_TIMEOUT" ]; then
            log_error "No new proxy listened on port $port within ${PROXY_LAUNCH_TIMEOUT}s"
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
    if ! ps -o args= -p "$pid" | grep -qF -- "$config"; then
        log_error "The process listening on port $port was not started with $config: PID $pid, $(ps -o args= -p "$pid")"
        return 1
    fi
    LAUNCHED_PROXY_PID="$pid"
    PROXY_STALE_PID=""
}

# proxy_stop <pid> -- stops <pid>, a proxy proxy_launch started, with PROXY_LAUNCH=auto. With
# manual it leaves the proxy you started running, and the next proxy_launch, if any, asks you to
# restart it.
proxy_stop() {
    local pid="$1"
    [ -n "$pid" ] || return 0
    if [ "$PROXY_LAUNCH" = manual ]; then
        log_step "PROXY_LAUNCH=manual: leaving the proxy you started (PID $pid) running"
        PROXY_STALE_PID="$pid"
        return 0
    fi
    if kill -0 "$pid" 2>/dev/null; then
        log_step "Stopping proxy (PID: $pid)"
        stop_process "$pid" || true
    fi
}

################################
# config.yaml-based runs (test_update.sh, test_forward.sh)
################################

# prepare_lease_config writes, once, PROXY_RUN_DIR/config.yaml (PROXY_CONFIG_FILE): a copy of
# config.yaml listening on PROXY_ADDR:PROXY_PORT, with server.diagnostics on (the reasons in
# error replies and the lease-store dump the suites check) and min_key_lease_sec/
# min_rr_lease_sec forced down to TEST_MIN_LEASE_SECONDS, so lease-cycle tests don't wait out
# the real policy minimums. With PROXY_PROTOCOL=tls it also turns on config.yaml's
# commented-out DoT listener at PROXY_TLS_URL, with a throwaway certificate in
# PROXY_RUN_DIR/tls. Idempotent: safe to call from multiple entry points (e.g. a caller that
# needs lease values before start_proxy runs, and start_proxy itself).
prepare_lease_config() {
    if [ "$LEASE_CONFIG_PREPARED" = true ]; then
        return 0
    fi
    LEASE_CONFIG_PREPARED=true

    if [ -z "$PROXY_RUN_DIR" ]; then
        log_error "PROXY_RUN_DIR is not set: the orchestration script names its run directory under $PROXY_RUN_ROOT"
        return 1
    fi
    proxy_run_prepare "$PROXY_RUN_DIR" "$PROXY_PORT" || return 1
    PROXY_CONFIG_FILE="$PROXY_RUN_DIR/config.yaml"
    PROXY_LOG_FILE="$PROXY_RUN_DIR/proxy.log"

    log_step "Preparing runtime config $PROXY_CONFIG_FILE for listen address $PROXY_ADDR:$PROXY_PORT"

    cp "$CONFIG_FILE" "$PROXY_CONFIG_FILE"
    sed -i.bak \
        -e "s|^  address:.*$|  address: \"$PROXY_ADDR:$PROXY_PORT\"|" \
        -e "s|^  diagnostics:.*$|  diagnostics: true|" \
        -e "s|^      min_key_lease_sec:.*$|      min_key_lease_sec: ${TEST_MIN_LEASE_SECONDS}|" \
        -e "s|^      min_rr_lease_sec:.*$|      min_rr_lease_sec: ${TEST_MIN_LEASE_SECONDS}|" \
        "$PROXY_CONFIG_FILE"
    rm -f "$PROXY_CONFIG_FILE.bak"
    if ! grep -qx '  diagnostics: true' "$PROXY_CONFIG_FILE"; then
        log_error "Could not turn on server.diagnostics in $PROXY_CONFIG_FILE: $CONFIG_FILE no longer has the \"  diagnostics:\" line this edits"
        return 1
    fi

    if [ "$PROXY_PROTOCOL" = "tls" ]; then
        local tls_dir="$PROXY_RUN_DIR/tls"
        mkdir "$tls_dir"
        make_tls_cert "$tls_dir" || return 1
        sed -i.bak \
            -e "s|^    # - tls .*$|    - tls|" \
            -e "s|^  # tls:$|  tls:|" \
            -e "s|^  #   address:.*$|    address: \"$PROXY_TLS_URL\"|" \
            -e "s|^  #   cert:.*$|    cert: \"$tls_dir/cert.pem\"|" \
            -e "s|^  #   key:.*$|    key: \"$tls_dir/key.pem\"|" \
            "$PROXY_CONFIG_FILE"
        rm -f "$PROXY_CONFIG_FILE.bak"
        if ! grep -q '^    - tls$' "$PROXY_CONFIG_FILE" || ! grep -q '^  tls:$' "$PROXY_CONFIG_FILE" \
            || ! grep -qF "address: \"$PROXY_TLS_URL\"" "$PROXY_CONFIG_FILE" \
            || ! grep -qF "$tls_dir/cert.pem" "$PROXY_CONFIG_FILE" \
            || ! grep -qF "$tls_dir/key.pem" "$PROXY_CONFIG_FILE"; then
            log_error "Could not turn on the DoT listener in $PROXY_CONFIG_FILE: $CONFIG_FILE no longer has the commented-out \"- tls\" and \"tls:\" lines this edits"
            return 1
        fi
    fi
}

start_proxy() {
    log_section "START: Proxy Process"

    prepare_lease_config || return 1
    proxy_launch "$PROXY_CONFIG_FILE" "$PROXY_PORT" "$PROXY_LOG_FILE" || return 1
    PROXY_PID="$LAUNCHED_PROXY_PID"

    log_success "Proxy listening on ${PROXY_ADDR}:${PROXY_PORT} (PID: $PROXY_PID), config $PROXY_CONFIG_FILE"
    if [ "$PROXY_LAUNCH" = auto ]; then
        log_success "Proxy log: tail -f $PROXY_LOG_FILE"
    fi
}

stop_proxy() {
    proxy_stop "${PROXY_PID:-}"
    PROXY_PID=""
}
