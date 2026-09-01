# !/usr/bin/env bash

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
PROXY_BIN="${SCRIPT_DIR}/../bin/${OS}/sig0lease"
CONFIG_FILE="${SCRIPT_DIR}/../config.yaml"
LOG_FILE="/tmp/sig0lease_proxy.log"
CLIENT_LOG_FILE="/tmp/sig0lease_client.log"

PROXY_ADDR="${PROXY_ADDR:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8053}"
PROXY_URL="$PROXY_ADDR:$PROXY_PORT"
# Transport run_client (tests/test_update.sh) uses to reach PROXY_URL.
# Defaults to udp; set PROXY_PROTOCOL=tcp to run the whole suite over TCP
# instead (passes --tcp through to sig0lease-client).
PROXY_PROTOCOL="${PROXY_PROTOCOL:-udp}"

AUTH_SERVER="${AUTH_SERVER:-ns1.free2air.org}"
PROXY_KEYSTORE_DIR="./keystore/server"
PROXY_KEY_NAME="${PROXY_KEYSTORE_DIR}/Kdev.zenr.io.+015+35317.key"

# Configuration
TMP_CONFIG_FILE=""
LEASE_CONFIG_FILE="$CONFIG_FILE"
LEASE_CONFIG_PREPARED=false
REUSED_PROXY=false
# Floor used for min_key_lease_sec/min_rr_lease_sec in the scratch config
# prepare_lease_config() writes, so lease-cycle tests don't wait out the
# real (production) policy minimums.
TEST_MIN_LEASE_SECONDS="${TEST_MIN_LEASE_SECONDS:-10}"

# Get keystore from environment
CLIENT_KEYSTORE_DIR="${CLIENT_KEYSTORE_DIR:-}"
if [ -z "$CLIENT_KEYSTORE_DIR" ]; then
    echo "ERROR: CLIENT_KEYSTORE_DIR environment variable not set"
    exit 1
fi

# Keys
CLIENT_KEY_NAME="Ktest.dev.zenr.io.+015+05044"
WRONG_CLIENT_KEY_NAME="Ktest.dev.zenr.io.+015+42176"



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

log_file() {
    local function=$1
    local message="$2"

    echo -e "$(date "+%Y-%m-%d %H:%M:%S") $function - $message" >> $CLIENT_LOG_FILE
}

yaml_get_lease_time() {
    local key="$1"

    local value=""

    if command -v yq >/dev/null 2>&1; then
        value="$(yq -r ".handlers.update.lease_policy.${key} // \"\"" "$LEASE_CONFIG_FILE" 2>/dev/null || true)"
    else
        echo "please install jq!"
        exit 1
    fi

    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo "Invalid value for ${key}: $value"
        exit 1
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
        exit 1
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
        exit 1
    fi

    if [ "${is_listening}" = false ]
    then
        log_error "Proxy PID $PROXY_PID is not listening on port ${PROXY_PORT}"
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

delete_rr(){
    local record="$1"
    local payload

    echo "Deleting $record"
    if [ "$record" = "key" ]; then
        # Read the secret string straight out of the private file
        payload="$(cat $CLIENT_KEYSTORE_DIR/$CLIENT_KEY_NAME.key | sed 's/test.dev.zenr.io. IN \(.*\)/\1/g')"
    else
        payload="$record"
    fi
    echo "payload is $payload"

    cat <<EOF | nsupdate -k $PROXY_KEY_NAME
    server $AUTH_SERVER
    zone zenr.io
    update delete test.dev.zenr.io $payload
    send
EOF
}

# add_rr publishes a record directly at the authoritative server, bypassing
# the proxy entirely. Used to simulate a key or record that exists online but
# was never registered through the proxy (e.g. an "online-only" signer, or a
# pre-existing authoritative record for duplicate-registration tests).
#
# Usage: add_rr <record> [ttl]
#   record: "key" for the well-known client test KEY, or an explicit
#           "<TYPE> <rdata...>" payload (e.g. "TXT \"hello\"")
#   ttl:    TTL in seconds for the added record (default 60)
#
# Requires a modern nsupdate with ED25519 SIG(0)/TSIG support (BIND 9.10.6,
# the version macOS ships at /usr/bin/nsupdate, predates RFC 8080 and cannot
# sign/verify this project's ED25519 keys correctly -- install a current
# nsupdate via `brew install bind` and make sure /opt/homebrew/bin precedes
# /usr/bin in PATH).
add_rr(){
    local record="$1"
    local ttl="${2:-60}"
    local payload

    echo "Adding $record (ttl=$ttl)"
    if [ "$record" = "key" ]; then
        # Read the secret string straight out of the private file
        payload="$(cat $CLIENT_KEYSTORE_DIR/$CLIENT_KEY_NAME.key | sed 's/test.dev.zenr.io. IN \(.*\)/\1/g')"
    else
        payload="$record"
    fi
    echo "payload is $payload"

    cat <<EOF | nsupdate -k $PROXY_KEY_NAME
    server $AUTH_SERVER
    zone zenr.io
    update add test.dev.zenr.io $ttl $payload
    send
EOF
}