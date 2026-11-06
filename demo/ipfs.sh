#!/bin/bash
# demo/ipfs.sh member|community -- D3 of docs/demo.md: a community folder over IPFS, kept by two
# kubo nodes (IPFS Desktop runs one) in a private swarm, which find each other at the addresses
# the agent publishes for them.
#   member     A, a member: the agent gives the folder FOLDER in this machine's node's files as
#              the site of <MEMBER>.<zone> (its _dnslink record), and the node's addresses at that
#              name (_dnsaddr).
#   community  B, the always-on community node: the agent follows <MEMBER>.<zone>: the node pins
#              each version of its site, and <SITE>.<zone> gives it once pinned. The node's
#              addresses go at <SITE>.<zone>, and its gateway is the SRP instance
#              "<HOST> ipfs-gateway". Once <SITE>.<zone> has the site, the gateway's address for
#              phones is printed, with a QR code.
# It checks that the node answers and has a swarm key, builds the proxy and the agent, starts
# them, waits until the zone's authoritative server has the records, and waits: Enter, or
# Ctrl-C, stops the agent, which frees the names, then the proxy. The logs and the agent's
# template go to a temporary directory, printed at the start.
#   MEMBER     the member's label; default a
#   SITE       the community's site's label; default site
#   HOST       the community node's host in the SRP domain; default b
#   FOLDER     the member's folder in its node's files; default /community
#   IPFS_API   the node's RPC API; default http://127.0.0.1:5001
#   IPFS_PATH  the node's repository, which holds its swarm key; default ~/.ipfs, IPFS Desktop's
#   GATEWAY    the community node's gateway port; default 8080
#   ADDRESS    the community node's address to publish; default, all of this machine's (auto)
#   NS, ZONE   as for watch.sh; ZONE is also where the agent registers, and srp.<ZONE> its SRP
#              domain.
#   REGISTRAR, TRANSPORT  the registrar the agent uses instead of a proxy this script starts
#              (demo/lib.sh).
# The member starts first: the community node's agent follows a site that is there, and its node
# reaches the member's at the addresses published for it.

cd "$(dirname "$0")/.." || exit 1
. demo/lib.sh
B="./bin/$(uname -s | tr A-Z a-z)"
ns="${NS:-ns1.free2air.org}"
zone="${ZONE:-dev.zenr.io}"
role="${1:-}"
member="${MEMBER:-a}"
site="${SITE:-site}"
host="${HOST:-b}"
folder="${FOLDER:-/community}"
api="${IPFS_API:-http://127.0.0.1:5001}"
repo="${IPFS_PATH:-$HOME/.ipfs}"
gateway="${GATEWAY:-8080}"

case "$role" in
member) tools=(go dig curl) ;;
community) tools=(go dig curl qrencode) ;;
*) echo "Usage: $0 member|community (docs/demo.md, D3)" >&2; exit 1 ;;
esac
for tool in "${tools[@]}"; do
    command -v "$tool" > /dev/null || { echo "$tool is not installed (docs/demo.md, D3)" >&2; exit 1; }
done
for label in "$member" "$site" "$host"; do
    if ! [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]; then
        echo "$label is not a DNS label: lower-case letters, digits and inner hyphens" >&2
        exit 1
    fi
done
if [ ! -f "$repo/swarm.key" ]; then
    echo "$repo has no swarm.key: the demo's nodes are a private swarm (docs/demo.md, D3: Needs)" >&2
    exit 1
fi
if ! curl -sf -o /dev/null -X POST "$api/api/v0/id"; then
    echo "No IPFS node answers at $api: start IPFS Desktop, or ipfs daemon" >&2
    exit 1
fi
check_proxy_ports

build

set -m
log="$(mktemp -d "${TMPDIR:-/tmp}/sig0lease-ipfs.XXXXXX")" || exit 1
proxy= agent=

finish() {
    trap '' INT
    echo
    echo "Stopping."
    stop agent
    stop proxy
    echo "Logs: $log"
}
trap finish EXIT
trap 'exit 130' INT TERM

registrar() {
    cat << EOF
  - protocol: $1
    $2
    server: 127.0.0.1:8053
    lease: 10m
    on_stop: release
EOF
}
{
    cat << EOF
# D3's template for the $role (docs/demo.md), written by demo/ipfs.sh.
keystore: $PWD/demo/keys-ipfs-$role
registrars:
EOF
    if [ "$role" = member ]; then
        registrar rfc9664 "zone: $zone."
        cat << EOF
    names:
      - name: $member
        ipfs: {api: "$api", publish: {mfs: "$folder"}}
EOF
    else
        registrar srp "domain: srp.$zone."
        cat << EOF
    hosts:
      - name: $host
        addresses: [${ADDRESS:-auto}]
        services:
          - {type: ipfs-gateway, port: $gateway}
EOF
        registrar rfc9664 "zone: $zone."
        cat << EOF
    names:
      - name: $site
        ipfs: {api: "$api", follow: $member.$zone}
EOF
    fi
} > "$log/ipfs.yaml"
template "$log/ipfs.yaml" "$log/ipfs.yaml"

cat << EOF
D3's $role, its node at $api, published on the live $zone zone $via.
Logs: $log
Answers are asked of $ns, the zone's authoritative server.
EOF

step "1. Start ${our_proxy:+the proxy and }the agent."
start_proxy
start agent agent.log "$B/sig0lease-agent" run -probe-interval 5s "$log/ipfs.yaml"
if [ "$role" = member ]; then
    wait_until "$member.$zone has the folder's site" answers TXT "_dnslink.$member.$zone"
    wait_until "$member.$zone has the node's addresses" answers TXT "_dnsaddr.$member.$zone"
    cat << EOF

What anyone can run:
  dig +short TXT _dnslink.$member.$zone
  dig +short TXT _dnsaddr.$member.$zone
A file put in $folder, in IPFS Desktop's Files, changes the site within about 15 s.
EOF
else
    wait_until "$site.$zone has the site $member.$zone gives, pinned" answers TXT "_dnslink.$site.$zone"
    wait_until "$site.$zone has the node's addresses" answers TXT "_dnsaddr.$site.$zone"
    wait_until "\"$host ipfs-gateway\" is registered" answers SRV "$host\\ ipfs-gateway._http._tcp.srp.$zone"
    address="$(ask A "$host.srp.$zone" | head -n 1)"
    url="http://$address:$gateway/ipns/$site.$zone/"
    cat << EOF

What anyone can run:
  dig +short TXT _dnslink.$site.$zone
  dns-sd -B _http._tcp,_ipfs srp.$zone       # a Mac: the IPFS gateways
The community's site: http://$host.srp.$zone:$gateway/ipns/$site.$zone/
  by address, for phones whose resolver hides private addresses: $url
EOF
    qrencode -t ANSIUTF8 "$url"
fi

step "2. Stop the agent${our_proxy:+ and the proxy}."
