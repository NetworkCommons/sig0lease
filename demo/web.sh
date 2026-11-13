#!/bin/bash
# demo/web.sh -- D6 of docs/demo.md: the browser page (make web), served by this machine, with a
# DNS client in it that sends everything to this machine's proxy over DNS-over-HTTPS. Phones on
# the network open it, watch the SRP domain's services come and go, and claim names with a
# message, each with a key the phone's browser makes and keeps.
# It builds the proxy, the agent and the page, starts the proxy with its config (demo/lib.sh,
# proxy_config) with the DoH listener on, in plain HTTP (a page served over plain HTTP may reach
# it, and a browser refuses a self-signed certificate), D1's site and agent (demo/demo.yaml), whose
# "<name> http" the page shows, and serves the page, and prints its address and a QR code of it.
# The next n keys stop the site and start it again, for the phones to see "<name> http" leave
# and come back. The last n, or Ctrl-C, stops the agent first, so it frees its names, then
# the page, the site and the proxy. The logs and the copy of the config go to a temporary
# directory, printed at the start.
#   ADDRESS   the address phones reach this machine at; default, the one it reaches the internet
#             from
#   PORT      the page's port; default 8090 (D3's gateway has 8080)
#   DOH_PORT  the proxy's DoH port; default 8443
#   NS, UPDATE_DOMAIN, SRP_DOMAIN, NAME  as for watch.sh; UPDATE_DOMAIN and SRP_DOMAIN are also
#             where the agent registers, and what the proxy serves (demo/lib.sh).
#   REGISTRAR, TRANSPORT  the registrar the agent uses instead of a proxy this script starts
#             (demo/lib.sh). The page then asks the registrar's web server, over DNS-over-HTTPS:
#   DOH       the page's DoH server, as a URL with no path; default https://<REGISTRAR's host>,
#             or REGISTRAR itself when it is an https URL
# A name a page claims stays the phone's while the page is open, and for half an hour after:
# stopping the proxy does not free it.

cd "$(dirname "$0")/.." || exit 1
. demo/lib.sh
B="./bin/$(uname -s | tr A-Z a-z)"
name="${NAME:-demo}"
instance="$name\\032http"         # "demo http", as browsing lists it
port="${PORT:-8090}"
doh_port="${DOH_PORT:-8443}"
if [ -n "${DOH:-}" ] && ! remote; then
    echo "DOH is the registrar's DoH server, for REGISTRAR, which is not set: the page asks this machine's proxy, on DOH_PORT" >&2
    exit 1
fi

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

check_proxy_ports "$doh_port"

build web

set -m
log="$(mktemp -d "${TMPDIR:-/tmp}/sig0lease-web.XXXXXX")" || exit 1
proxy= site= agent= page=

finish() {
    trap '' INT
    echo
    echo "Stopping."
    stop agent
    stop page
    stop site
    stop proxy
    echo "Logs: $log"
}
trap finish EXIT
trap 'exit 130' INT TERM

# The page's DoH server: this machine's proxy, or the registrar's web server.
if ! remote; then
    doh="http://$address:$doh_port"
else
    case "$REGISTRAR" in
    https://*) doh="${DOH:-$REGISTRAR}" ;;
    *) doh="${DOH:-https://${REGISTRAR%:*}}" ;;
    esac
fi

# The proxy's config: the demo's (proxy_config), with config.yaml's commented-out doh listener
# on, without the cert and key lines, so in plain HTTP.
proxy_config
remote || { sed -e 's|^    # - doh .*$|    - doh|' \
    -e "/^  # doh:\$/,/^  #   key:/{
s|^  # doh:\$|  doh:|
s|^  #   address:.*\$|    address: \":$doh_port\"|
}" "$log/config.yaml" > "$log/config.yaml.new" && mv "$log/config.yaml.new" "$log/config.yaml"; } || exit 1
if ! remote && { ! grep -q '^    - doh$' "$log/config.yaml" || ! grep -q '^  doh:$' "$log/config.yaml" ||
    ! grep -qF "address: \":$doh_port\"" "$log/config.yaml"; }; then
    echo "Could not turn on the doh listener in $log/config.yaml: config.yaml no longer has the commented-out \"- doh\" and \"doh:\" lines this edits" >&2
    exit 1
fi

template demo/demo.yaml "$log/demo.yaml"

# soa_query -- a query for UPDATE_DOMAIN's SOA, in DNS wire format (ID 0, RD), base64url-encoded
# as RFC 8484 S4.1's GET takes it.
soa_query() {
    local label wire='\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    for label in ${update_domain//./ }; do
        wire+="$(printf '\\x%02x' "${#label}")$label"
    done
    printf "$wire"'\x00\x00\x06\x00\x01' | base64 | tr '+/' '-_' | tr -d '=\n'
}

# doh_answers -- whether the page's DoH server answers the SOA query with RCODE 0 (the low 4 bits
# of the reply's fourth byte): the proxy relays the zone's authoritative server's answer.
doh_answers() {
    local rcode
    rcode="$(curl -sf "$doh/dns-query?dns=$(soa_query)" | od -An -tu1 -j3 -N1)"
    [ -n "$rcode" ] && [ $(( rcode & 15 )) -eq 0 ]
}
page_served() { curl -sf -o /dev/null "http://127.0.0.1:$port/"; }

url="http://$address:$port/?doh=$doh&update_domain=$update_domain&srp_domain=$srp_domain&ns=$ns"
cat << EOF
The page, served by this machine at $address, on the live zone, in $update_domain and
$srp_domain: it asks $doh over DNS-over-HTTPS. Logs: $log
EOF

step "1. Start ${our_proxy}the site and the agent, and serve the page."
start_proxy
start_site
start agent agent.log "$B/sig0lease-agent" run -probe-interval 5s "$log/demo.yaml"
start page page.log python3 -m http.server "$port" -d bin/web
wait_until "$doh answers over DoH" doh_answers
wait_until "the page is served" page_served
wait_until "\"$name http\" is listed" listed "$instance"

echo
echo "The page: $url"
qrencode -t ANSIUTF8 "$url"
cat << EOF

What anyone can run, for a name claimed on the page:
  dig +short TXT <name>.$update_domain @$ns
and for the services it shows:
  NS=$ns UPDATE_DOMAIN=$update_domain SRP_DOMAIN=$srp_domain NAME=$name demo/watch.sh
EOF

step "2. Stop the site: after three failed probes the agent withdraws \"$name http\", and the phones show it leave."
stop site
wait_until "\"$name http\" is gone" not listed "$instance"
step "   Start the site again: once a probe passes, \"$name http\" is back on the phones."
start_site
wait_until "\"$name http\" is listed" listed "$instance"

last="the page, the site and the proxy"
remote && last="the page and the site"
step "Last, stop the agent, which frees its names (on_stop: release), then $last."
stop agent
wait_until "\"$name http\" is gone" not listed "$instance"
