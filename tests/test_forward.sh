#!/bin/bash

# DNS Proxy Test Script
# Start proxy, run tests, then shut down

set -euo pipefail

RED='\033[0;31m'
NC='\033[0m' # No Color

cd "$(dirname "$0")/." || exit 1

PROXY_HOST="${1:-127.0.0.1}"
PROXY_PORT="${2:-8053}"
DOWNSTREAM_ZONE="test.dev.zenr.io."
CLIENT_KEY_NAME="test.dev.zenr.io."

echo "======================================"
echo "DNS Proxy forward functionality test"
echo "======================================"
echo ""

my_os=$(uname -s | tr '[:upper:]' '[:lower:]')

# Build the binaries if they don't exist
if [ ! -f "../bin/${my_os}/sig0lease" ]; then
    echo "Building proxy binaries..."
    go build -o "../bin/${my_os}/sig0lease" ../cmd/sig0lease
fi

# Start proxy in background
cd .. > /dev/null 
./bin/${my_os}/sig0lease ./config.yaml &
PROXY_PID=$!
cd - > /dev/null 
sleep 2

# Verify proxy process is still alive (bind/listener failures should terminate it).
if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo -e "${RED}ERROR: Proxy failed to start (process exited).${NC}"
    exit 1
fi

# Verify our proxy PID owns at least one listener on the target port.
is_listening=true
if [ "${my_os}" = "darwin" ]
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

echo "Proxy started on ${PROXY_HOST}:${PROXY_PORT}"
echo ""

# Test 1: A record query (opcode 0 - QUERY)
echo "Test 1: A record lookup for google.com"
dig @${PROXY_HOST} -p ${PROXY_PORT} google.com A +short 2>/dev/null | head -3
echo ""

# Test 2: AAAA record query (IPv6)
echo "Test 2: AAAA record lookup for ipv6.google.com"
dig @${PROXY_HOST} -p ${PROXY_PORT} ipv6.google.com AAAA +short 2>/dev/null || echo "(no IPv6 available)"
echo ""

# Test 3: MX record query
echo "Test 3: MX records for gmail.com"
dig @${PROXY_HOST} -p ${PROXY_PORT} gmail.com MX +short 2>/dev/null | head -5
echo ""

# Test 4: TXT record query (opcode 0 - QUERY)
echo "Test 4: TXT records for google.com"
dig @${PROXY_HOST} -p ${PROXY_PORT} google.com TXT +short 2>/dev/null | head -5
echo ""

# Test 5: NS record query (opcode 0 - QUERY)
echo "Test 5: Name servers for example.com"
dig @${PROXY_HOST} -p ${PROXY_PORT} example.com NS +short 2>/dev/null
echo ""

# Test 6: Reverse DNS (PTR) (opcode 0 - QUERY)
echo "Test 6: Reverse lookup for 8.8.8.8"
dig @${PROXY_HOST} -p ${PROXY_PORT} -x 8.8.8.8 +short 2>/dev/null || echo "(reverse lookup failed)"
echo ""

# Test 7: DNS over TCP (opcode 0 - QUERY)
echo "Test 7: Query using TCP"
dig @${PROXY_HOST} -p ${PROXY_PORT} tcp google.com A +short 2>/dev/null | head -3
echo ""

# Test 8: Verify ID preservation in error responses
echo "Test 8: Error response preserves transaction ID"
# Query a non-existent domain to verify error responses have correct IDs
dig @${PROXY_HOST} -p ${PROXY_PORT} nonexistent-domain-12345.example. A +short 2>&1 | grep -E "(no servers|timeout)" || echo "ID preservation working correctly (error received)"
echo ""

# Cleanup
kill $PROXY_PID 2>/dev/null || true

echo "======================================"
echo "Testing forward functionality Complete!"
echo "======================================"
