# !/usr/bin/env bash

# Configuration
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
PROXY_BIN="${SCRIPT_DIR}/../bin/${OS}/sig0lease"
CLIENT_BIN="${SCRIPT_DIR}/../bin/${OS}/sig0lease-client"
CONFIG_FILE="${SCRIPT_DIR}/../config.yaml"
LOG_FILE="/tmp/sig0lease_proxy.log"

PROXY_ADDR="${PROXY_ADDR:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8053}"
PROXY_URL="$PROXY_ADDR:$PROXY_PORT"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROXY_PID=""

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
            log_error "Port $PROXY_PORT is already in use. Re-run with a free port: PROXY_PORT=18053 tests/test_update.sh run"
        fi
        exit 1
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
    else
        if ! ss -tulnp 2>/dev/null | grep -E ":${PROXY_PORT}\\b" | grep -q "pid=${PROXY_PID},"
        then
            is_listening=false
        fi
    fi

    if [ "${is_listening}" = false ]
    then
        echo -e "${RED}ERROR: Proxy PID $PROXY_PID is not listening on port ${PROXY_PORT}${NC}"
        kill "$PROXY_PID" 2>/dev/null || true
        exit 1
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
