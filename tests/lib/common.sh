# tests/lib/common.sh
#
# Shared configuration, logging, and small generic helpers, sourced by every
# other tests/lib/*.sh file and by the orchestration scripts (test_update.sh,
# test_srp.sh, test_forward.sh, reset.sh).
#
# No `set -e`/`set -euo pipefail` here, or in any tests/lib/*.sh file: bash's
# `source` runs in the current shell, so a lib-level `set -e` would silently
# change the *sourcing* script's own shell options too. The orchestration
# script owns that decision. Library functions signal failure via `return 1`,
# never `exit` -- so a future caller that wants to catch a failure and
# continue (rather than abort the whole process) safely can. An orchestration
# script that wants today's fail-fast behavior still gets it for free by
# calling a lib function as a bare statement under its own `set -e` (a
# non-zero return from a simple command, or from a command substitution on
# the right-hand side of a plain assignment, both trigger errexit in bash).

# Idempotent double-source guard.
if [ -n "${_SIG0LEASE_LIB_COMMON_SOURCED:-}" ]; then
    return 0 2>/dev/null || true
fi
_SIG0LEASE_LIB_COMMON_SOURCED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$LIB_DIR/.." && pwd)"
# Kept as SCRIPT_DIR too: existing orchestration scripts and callers refer to
# $SCRIPT_DIR (the tests/ directory) rather than $TESTS_DIR.
SCRIPT_DIR="$TESTS_DIR"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
PROXY_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease"
CONFIG_FILE="${TESTS_DIR}/../config.yaml"
CLIENT_LOG_FILE="/tmp/sig0lease_client.log"

# Who starts the proxy a suite tests (lib/proxy.sh's proxy_launch): auto, the default, starts
# it from PROXY_BIN; manual waits up to PROXY_LAUNCH_TIMEOUT seconds for one you start
# yourself, e.g. in a debugger, with the config the suite wrote. Every suite writes its
# proxy's config, DoT certificate, lease files and log into its own fixed directory under
# PROXY_RUN_ROOT, emptied at the start of each run and kept after it, so a debugger launch
# configuration can name the config (tests/README.md lists one per suite).
PROXY_LAUNCH="${PROXY_LAUNCH:-auto}"
PROXY_LAUNCH_TIMEOUT="${PROXY_LAUNCH_TIMEOUT:-600}"
PROXY_RUN_ROOT="/tmp/sig0lease-debug"

PROXY_ADDR="${PROXY_ADDR:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8053}"
PROXY_URL="$PROXY_ADDR:$PROXY_PORT"
# Transport run_client (tests/lib/client.sh) uses to reach the proxy.
# Defaults to udp; set PROXY_PROTOCOL=tcp to run the whole suite over TCP
# instead (passes --tcp through to sig0lease-client), or PROXY_PROTOCOL=tls
# for DNS-over-TLS (--tls), sent to PROXY_TLS_URL: the proxy's DoT listener,
# which prepare_lease_config turns on in the scratch config it writes.
PROXY_PROTOCOL="${PROXY_PROTOCOL:-udp}"
PROXY_TLS_PORT="${PROXY_TLS_PORT:-8853}"
PROXY_TLS_URL="$PROXY_ADDR:$PROXY_TLS_PORT"

AUTH_SERVER="${AUTH_SERVER:-ns1.free2air.org}"
# The zone AUTH_SERVER is authoritative for, which lib/dns.sh's direct nsupdate changes
# (add_rr/delete_rr) name, signed with PROXY_KEY_NAME. test_update.sh's local mode replaces
# AUTH_SERVER, AUTH_ZONE and PROXY_KEY_NAME with the local BIND 9's.
AUTH_ZONE="zenr.io."
PROXY_KEYSTORE_DIR="./keystore/server"
PROXY_KEY_NAME="${PROXY_KEYSTORE_DIR}/Kdev.zenr.io.+015+35317.key"

# Configuration: prepare_lease_config's copy of config.yaml, and its log, in PROXY_RUN_DIR --
# PROXY_RUN_ROOT/<suite>, which the orchestration script sets.
PROXY_RUN_DIR=""
PROXY_CONFIG_FILE=""
PROXY_LOG_FILE=""
LEASE_CONFIG_PREPARED=false
# Floor used for min_key_lease_sec/min_rr_lease_sec in the scratch config
# prepare_lease_config() writes, so lease-cycle tests don't wait out the
# real (production) policy minimums.
TEST_MIN_LEASE_SECONDS="${TEST_MIN_LEASE_SECONDS:-10}"

# CLIENT_KEYSTORE_DIR is deliberately *not* required just to source this
# file (or any lib/*.sh file) -- only functions that actually touch client
# key material (run_client, verify_keystore, make_rr's KEY case,
# add_rr/delete_rr's "key" shorthand) need it, and each of those calls
# require_client_keystore_dir itself. This is what lets e.g. test_forward.sh
# (which never touches client keys) source the whole lib tree without ever
# setting it -- previously utils.sh hard-required it unconditionally at
# source time, which test_forward.sh had no way to satisfy on its own.
CLIENT_KEYSTORE_DIR="${CLIENT_KEYSTORE_DIR:-}"

# Keys
CLIENT_KEY_NAME="${CLIENT_KEY_NAME:-Ktest.dev.zenr.io.+015+05044}"
WRONG_CLIENT_KEY_NAME="${WRONG_CLIENT_KEY_NAME:-Ktest.dev.zenr.io.+015+42176}"

# require_client_keystore_dir -- the lazy counterpart to utils.sh's old
# source-time hard requirement. Call this at the top of any function that
# actually needs $CLIENT_KEYSTORE_DIR.
require_client_keystore_dir() {
    if [ -z "$CLIENT_KEYSTORE_DIR" ]; then
        log_error "CLIENT_KEYSTORE_DIR environment variable not set"
        return 1
    fi
    return 0
}

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

    echo -e "$(date "+%Y-%m-%d %H:%M:%S") $function - $message" >> "$CLIENT_LOG_FILE"
}

################################
# Utils
################################
require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "Required command not found: $1"
        return 1
    fi
}

# listening_ports <tcp|udp> [<pid>] -- prints, one per line, the ports of every listening TCP
# socket or bound UDP socket, or only of process <pid>'s. lsof on macOS; on Linux ss or, in
# containers without it, /proc/net.
listening_ports() {
    local proto="$1" pid="${2:-}"
    if [ "${OS}" = "darwin" ]; then
        local args=(-nP -Fn -i"$(echo "$proto" | tr '[:lower:]' '[:upper:]')")
        [ "$proto" = tcp ] && args+=(-sTCP:LISTEN)
        [ -n "$pid" ] && args+=(-a -p "$pid")
        # Name lines are n<address>:<port>; a connected socket's also names its peer (->).
        { lsof "${args[@]}" 2>/dev/null || true; } | sed -n -e '/->/d' -e 's/^n.*:\([0-9][0-9]*\)$/\1/p'
    elif command -v ss >/dev/null 2>&1; then
        # The local address is the first field that ends in :<port>; the peer's is *:* or similar.
        { ss -ln"${proto:0:1}"p 2>/dev/null || true; } \
            | { if [ -n "$pid" ]; then grep "pid=${pid}," || true; else cat; fi; } \
            | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /:[0-9]+$/) { sub(/.*:/, "", $i); print $i; next } }'
    elif [ -d /proc/net ]; then
        # Columns: sl, local address (hex address:hex port), remote address, state (0A is TCP
        # LISTEN, 07 an unconnected UDP socket), ..., socket inode (10th), matched against
        # <pid>'s file descriptors.
        local files state inodes=""
        if [ "$proto" = tcp ]; then files="/proc/net/tcp /proc/net/tcp6"; state=0A; else files="/proc/net/udp /proc/net/udp6"; state=07; fi
        [ -n "$pid" ] && inodes=" $(ls -l "/proc/$pid/fd" 2>/dev/null | sed -n 's/.*socket:\[\([0-9]*\)\].*/\1/p' | tr '\n' ' ')"
        # shellcheck disable=SC2086 # files is a list
        cat $files 2>/dev/null \
            | awk -v st="$state" -v pid="$pid" -v inodes="$inodes" \
                '$4 == st && (pid == "" || index(inodes, " " $10 " ")) { sub(/.*:/, "", $2); print $2 }' \
            | while read -r hex; do printf '%d\n' "0x$hex"; done
    else
        log_error "Cannot list listening ports: no lsof, ss or /proc/net"
        return 1
    fi
}

# listening_pid <port> -- the PID of the process listening on <port> over UDP, or else TCP, or
# nothing: lsof on macOS; on Linux ss or, in containers without it, /proc (the socket's inode
# in /proc/net, then the process holding it).
listening_pid() {
    local port="$1"
    if [ "${OS}" = "darwin" ]; then
        { lsof -nP -t -iUDP:"$port" 2>/dev/null; lsof -nP -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null; } | head -n 1
    elif command -v ss >/dev/null 2>&1; then
        # The local address is the field that ends in :<port>; ss -p names the owner pid=<pid>.
        { ss -lnup 2>/dev/null; ss -lntp 2>/dev/null; } | awk -v want=":${port}\$" '
            { for (i = 1; i <= NF; i++) if ($i ~ want && match($0, /pid=[0-9]+/)) { print substr($0, RSTART + 4, RLENGTH - 4); exit } }'
    elif [ -d /proc/net ]; then
        local inode fd
        inode="$(cat /proc/net/udp /proc/net/udp6 2>/dev/null \
            | awk -v hex="$(printf ':%04X' "$port")" '$4 == "07" && substr($2, length($2) - 4) == hex { print $10; exit }')"
        [ -n "$inode" ] || return 0
        for fd in /proc/[0-9]*/fd/*; do
            if [ "$(readlink "$fd" 2>/dev/null)" = "socket:[$inode]" ]; then
                fd="${fd#/proc/}"
                echo "${fd%%/*}"
                return 0
            fi
        done
    else
        log_error "Cannot find the process listening on port $port: no lsof, ss or /proc/net"
        return 1
    fi
}

# is_listening <port> [<pid>] -- whether anything, or process <pid>, listens on <port> over TCP
# or UDP.
is_listening() {
    local port="$1" pid="${2:-}" ports
    ports="$(listening_ports tcp "$pid" && listening_ports udp "$pid")" || return 1
    grep -qx "$port" <<< "$ports"
}

# stop_process <pid> [<signal>] -- sends <signal> (default TERM) to <pid>, a background job of
# this shell, waits for it to exit and returns its exit status (128+n when signal n ended it).
# The wait, with stderr off, is also what keeps bash from printing its own notice for a job a
# signal ended ("line N: <pid> Killed: 9 ..."), which it otherwise does at whatever line it is
# on when it notices.
stop_process() {
    local pid="$1" signal="${2:-TERM}"
    { kill -s "$signal" "$pid"; wait "$pid"; } 2>/dev/null
}

# make_tls_cert <dir> -- writes a fresh self-signed ECDSA P-256 certificate (cert.pem) and its
# private key (key.pem) into dir, for a test proxy's DNS-over-TLS listener (server.tls). The
# project's clients use opportunistic DoT and never check the certificate, so a throwaway one
# per run is enough. Plain ecparam/req subcommands, which OpenSSL and macOS's LibreSSL both
# have.
make_tls_cert() {
    local dir="$1"
    require_command openssl || return 1
    if ! openssl ecparam -name prime256v1 -genkey -noout -out "$dir/key.pem"; then
        log_error "openssl could not generate the DoT listener's key in $dir"
        return 1
    fi
    if ! openssl req -new -x509 -key "$dir/key.pem" -out "$dir/cert.pem" -days 1 -subj "/CN=sig0lease-test"; then
        log_error "openssl could not generate the DoT listener's certificate in $dir"
        return 1
    fi
}

################################
# Timing
################################
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

wait_until_epoch() {
    local target_epoch="$1"
    local now
    now=$(date +%s)
    if [ "$now" -lt "$target_epoch" ]; then
        sleep $((target_epoch - now))
    fi
}
time_tag(){
    echo $(date +%d_%m_%Y_%H_%M_%S_%N)
}
