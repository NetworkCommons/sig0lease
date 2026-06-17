#!/bin/bash

# DNS Proxy Test Script
# Start proxy, run tests, then shut down

cd "$(dirname "$0")/.." || exit 1

PROXY_HOST="${1:-127.0.0.1}"
PROXY_PORT="${2:-8053}"

echo "======================================"
echo "DNS Proxy Testing Commands"
echo "======================================"
echo ""

my_os=$(uname -s | tr '[:upper:]' '[:lower:]')
# Start proxy in background
./bin/${my_os}/sig0lease_proxy examples/config.yaml &
PROXY_PID=$!
sleep 2

# Verify port is listening
if [ "${my_os}" = "darwin" ]; then
    netcmd="lsof -i:${PROXY_PORT} -sTCP:LISTEN"
else
    netcmd="ss -tuln | grep \":${PROXY_PORT}\""
fi
if ! $netcmd > /dev/null; then
    echo "ERROR: Port ${PROXY_PORT} is not listening"
    kill $PROXY_PID 2>/dev/null || true
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

# Test 4: TXT record query
echo "Test 4: TXT records for google.com"
dig @${PROXY_HOST} -p ${PROXY_PORT} google.com TXT +short 2>/dev/null | head -5
echo ""

# Test 5: NS record query
echo "Test 5: Name servers for example.com"
dig @${PROXY_HOST} -p ${PROXY_PORT} example.com NS +short 2>/dev/null
echo ""

# Test 6: Reverse DNS (PTR)
echo "Test 6: Reverse lookup for 8.8.8.8"
dig @${PROXY_HOST} -p ${PROXY_PORT} -x 8.8.8.8 +short 2>/dev/null || echo "(reverse lookup failed)"
echo ""

# Test 7: DNS over TCP
echo "Test 7: Query using TCP"
dig @${PROXY_HOST} -p ${PROXY_PORT} tcp google.com A +short 2>/dev/null | head -3
echo ""

# Cleanup
kill $PROXY_PID 2>/dev/null || true

echo "======================================"
echo "Testing Complete!"
echo "======================================"
