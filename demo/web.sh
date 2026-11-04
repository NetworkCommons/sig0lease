#!/bin/bash
# demo/web.sh -- D6 of docs/demo.md: the browser page (make web), served by this machine, with a
# DNS client in it that sends everything to this machine's proxy over DNS-over-HTTPS. Phones on
# the network open it, watch the SRP domain's services come and go, and claim names with a
# message, each with a key the phone's browser makes and keeps.
# It builds the proxy and the page, starts the proxy with a copy of config.yaml that turns on its
# DoH listener, in plain HTTP (a page served over plain HTTP may reach it, and a browser refuses
# a self-signed certificate), serves the page, prints its address and a QR code of it, and
# waits: Enter, or Ctrl-C, stops the page and the proxy. The logs and the copy of the config
# go to a temporary directory, printed at the start.
#   ADDRESS   the address phones reach this machine at; default, the one it reaches the internet
#             from
#   PORT      the page's port; default 8090 (D3's gateway has 8080)
#   DOH_PORT  the proxy's DoH port; default 8443
#   NS, ZONE, DOMAIN as for watch.sh.
# A name a page claims stays the phone's while the page is open, and for half an hour after:
# stopping the proxy does not free it.

cd "$(dirname "$0")/.." || exit 1
. demo/lib.sh
B="./bin/$(uname -s | tr A-Z a-z)"
ns="${NS:-ns1.free2air.org}"
zone="${ZONE:-dev.zenr.io}"
domain="${DOMAIN:-srp.dev.zenr.io}"
port="${PORT:-8090}"
doh_port="${DOH_PORT:-8443}"

for tool in go python3 dig curl qrencode; do
    command -v "$tool" > /dev/null || { echo "$tool is not installed (docs/demo.md, D6)" >&2; exit 1; }
done

# lan_address -- the address this machine reaches the internet from.
lan_address() {
    if [ "$(uname -s)" = Darwin ]; then
        ipconfig getifaddr "$(route -n get default | awk '/interface:/ { print $2 }')"
    else
        ip -4 route get 1.1.1.1 | awk '{ for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1) }'
    fi
}
address="${ADDRESS:-$(lan_address)}"
if [ -z "$address" ]; then
    echo "Could not tell this machine's address; set ADDRESS" >&2
    exit 1
fi

echo "Building the proxy and the page."
make -s build web || exit 1

set -m
log="$(mktemp -d "${TMPDIR:-/tmp}/sig0lease-web.XXXXXX")" || exit 1
proxy= page=

finish() {
    trap '' INT
    echo
    echo "Stopping."
    stop page
    stop proxy
    echo "Logs: $log"
}
trap finish EXIT
trap 'exit 130' INT TERM

# The proxy's config: config.yaml with its commented-out doh listener on, without the cert and
# key lines, so in plain HTTP.
sed -e 's|^    # - doh .*$|    - doh|' \
    -e "/^  # doh:\$/,/^  #   key:/{
s|^  # doh:\$|  doh:|
s|^  #   address:.*\$|    address: \":$doh_port\"|
}" config.yaml > "$log/config.yaml"
if ! grep -q '^    - doh$' "$log/config.yaml" || ! grep -q '^  doh:$' "$log/config.yaml" ||
    ! grep -qF "address: \":$doh_port\"" "$log/config.yaml"; then
    echo "Could not turn on the doh listener in $log/config.yaml: config.yaml no longer has the commented-out \"- doh\" and \"doh:\" lines this edits" >&2
    exit 1
fi

# doh_answers -- whether the proxy answers a query over DoH (RFC 8484 S4.1's GET): the root's NS
# records, which it asks of its upstreams.
doh_answers() { curl -sf -o /dev/null "http://127.0.0.1:$doh_port/dns-query?dns=AAABAAABAAAAAAAAAAACAAE"; }
page_served() { curl -sf -o /dev/null "http://127.0.0.1:$port/"; }

url="http://$address:$port/?doh=http://$address:$doh_port&zone=$zone&domain=$domain&ns=$ns"
cat << EOF
The page, served by this machine at $address, and its proxy on the live $zone zone.
Logs: $log
EOF

step "1. Start the proxy and serve the page."
start proxy proxy.log "$B/sig0lease" "$log/config.yaml"
start page page.log python3 -m http.server "$port" -d bin/web
wait_until "the proxy answers over DoH" doh_answers
wait_until "the page is served" page_served

echo
echo "The page: $url"
qrencode -t ANSIUTF8 "$url"
cat << EOF

What anyone can run, for a name claimed on the page:
  dig +short TXT <name>.$zone @$ns
and for the services it shows:
  demo/watch.sh
EOF

step "2. Stop the page and the proxy."
