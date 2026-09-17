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
LOG_FILE="/tmp/sig0lease_proxy.log"
CLIENT_LOG_FILE="/tmp/sig0lease_client.log"

PROXY_ADDR="${PROXY_ADDR:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8053}"
PROXY_URL="$PROXY_ADDR:$PROXY_PORT"
# Transport run_client (tests/lib/client.sh) uses to reach PROXY_URL.
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
