#!/bin/bash

# DNS Proxy Test Script
# Start proxy, run tests, then shut down

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/proxy.sh"

# Pre-existing bug fixed here: this used to `cd "$(dirname "$0")/."`, which
# lands in tests/ (wherever this script file lives) -- but config.yaml's
# keystore_dir is "./keystore/server", relative to main/, so a proxy started
# from tests/ silently failed to find its signing key ("no proxy
# authorization key found for zone ... or any parent"). $TESTS_DIR/.. (from
# lib/common.sh) is the robust equivalent of test_update.sh's convention of
# not cd'ing at all and relying on being invoked from main/ -- this makes
# test_forward.sh work the same way regardless of invocation cwd.
cd "$TESTS_DIR/.." || exit 1

DOWNSTREAM_ZONE="test.dev.zenr.io."

log_section "DNS Proxy forward functionality test"

# Build the binaries if they don't exist. Relative to main/ (this script's
# cwd as of the fix above), matching $PROXY_BIN/$CLIENT_BIN from lib/*.sh.
if [ ! -f "bin/${OS}/sig0lease" ]; then
    log_step "Building proxy binaries..."
    go build -o "bin/${OS}/sig0lease" ./cmd/sig0lease
fi

log_step "Building client binaries..."
go build -o "bin/${OS}/sig0lease-client" ./cmd/sig0lease-client

# Start proxy in background
start_proxy

FAILED_TESTS=""

# expect_answer <label> <dig arguments...> -- one query through the proxy (+short); the test
# passes only if the answer has at least one record. dig's own error lines (timeouts, no
# servers reached, ID mismatch) start with ";;" and do not count as records.
expect_answer() {
    local label="$1"; shift
    log_step "$label"
    local out records
    out="$(dig @"${PROXY_ADDR}" -p "${PROXY_PORT}" +short +time=3 +tries=2 "$@" 2>&1)" || true
    echo "$out" | head -5
    records="$(echo "$out" | grep -v -e '^;;' -e '^$' || true)"
    if [ -n "$records" ]; then
        log_success "$label"
    else
        log_error "$label: no answer"
        FAILED_TESTS="$FAILED_TESTS\n  $label"
    fi
    echo ""
}

expect_answer "Test 1: A record lookup for google.com" google.com A
expect_answer "Test 2: AAAA record lookup for ipv6.google.com" ipv6.google.com AAAA
expect_answer "Test 3: MX records for gmail.com" gmail.com MX
expect_answer "Test 4: TXT records for google.com" google.com TXT
expect_answer "Test 5: Name servers for example.com" example.com NS
expect_answer "Test 6: Reverse lookup for 8.8.8.8" -x 8.8.8.8
expect_answer "Test 7: A record lookup for google.com over TCP" +tcp google.com A

# Test 8: an error reply reaches the client with the query's ID. A reply with another ID is one
# dig ignores ("ID mismatch") while it keeps waiting, so it ends in a timeout instead of the
# NXDOMAIN the upstream resolver sends.
label="Test 8: NXDOMAIN reply for a nonexistent name keeps the query's ID"
log_step "$label"
out="$(dig @"${PROXY_ADDR}" -p "${PROXY_PORT}" +time=3 +tries=2 nonexistent-domain-12345.example. A 2>&1)" || true
echo "$out" | grep -E "status:|mismatch|timed out|no servers" || true
if echo "$out" | grep -q "status: NXDOMAIN" && ! echo "$out" | grep -qiE "mismatch|timed out|no servers"; then
    log_success "$label"
else
    log_error "$label: expected an NXDOMAIN reply with the query's ID"
    FAILED_TESTS="$FAILED_TESTS\n  $label"
fi
echo ""

# Cleanup
stop_proxy

if [ -n "$FAILED_TESTS" ]; then
    log_section "Forward tests FAILED"
    echo -e "Failed:$FAILED_TESTS"
    exit 1
fi
log_section "Testing forward functionality Complete!"
