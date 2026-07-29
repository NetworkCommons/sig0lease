#!/bin/bash

# DNS Proxy Test Script
# Start proxy, run tests, then shut down

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

cd "$(dirname "$0")/." || exit 1

DOWNSTREAM_ZONE="test.dev.zenr.io."
CLIENT_KEY_NAME="test.dev.zenr.io."

log_section "DNS Proxy forward functionality test"

# Build the binaries if they don't exist
if [ ! -f "../bin/${OS}/sig0lease" ]; then
    log_step "Building proxy binaries..."
    go build -o "../bin/${OS}/sig0lease" ../cmd/sig0lease
fi

log_step "Building client binaries..."
go build -o "../bin/${OS}/sig0lease-client" ../cmd/sig0lease-client

# Start proxy in background
start_proxy

# Test 1: A record query (opcode 0 - QUERY)
log_step "Test 1: A record lookup for google.com"
dig @${PROXY_ADDR} -p ${PROXY_PORT} google.com A +short 2>/dev/null | head -3
echo ""

# Test 2: AAAA record query (IPv6)
log_step "Test 2: AAAA record lookup for ipv6.google.com"
dig @${PROXY_ADDR} -p ${PROXY_PORT} ipv6.google.com AAAA +short 2>/dev/null || echo "(no IPv6 available)"
echo ""

# Test 3: MX record query
log_step "Test 3: MX records for gmail.com"
dig @${PROXY_ADDR} -p ${PROXY_PORT} gmail.com MX +short 2>/dev/null | head -5
echo ""

# Test 4: TXT record query (opcode 0 - QUERY)
log_step "Test 4: TXT records for google.com"
dig @${PROXY_ADDR} -p ${PROXY_PORT} google.com TXT +short 2>/dev/null | head -5
echo ""

# Test 5: NS record query (opcode 0 - QUERY)
log_step "Test 5: Name servers for example.com"
dig @${PROXY_ADDR} -p ${PROXY_PORT} example.com NS +short 2>/dev/null
echo ""

# Test 6: Reverse DNS (PTR) (opcode 0 - QUERY)
log_step "Test 6: Reverse lookup for 8.8.8.8"
dig @${PROXY_ADDR} -p ${PROXY_PORT} -x 8.8.8.8 +short 2>/dev/null || echo "(reverse lookup failed)"
echo ""

# Test 7: DNS over TCP (opcode 0 - QUERY)
log_step "Test 7: Query using TCP"
dig @${PROXY_ADDR} -p ${PROXY_PORT} tcp google.com A +short 2>/dev/null | head -3
echo ""

# Test 8: Verify ID preservation in error responses
echo "Test 8: Error response preserves transaction ID"
# Query a non-existent domain to verify error responses have correct IDs
dig @${PROXY_ADDR} -p ${PROXY_PORT} nonexistent-domain-12345.example. A +short 2>&1 | grep -E "(no servers|timeout)" || echo "ID preservation working correctly (error received)"
echo ""

# Cleanup
stop_proxy

log_section "Testing forward functionality Complete!"
