#!/bin/bash
# demo/ipfs.sh member|community -- D3 of docs/demo.md: a community folder over IPFS, kept by two
# kubo nodes (IPFS Desktop runs one) in a private swarm, which find each other at the addresses
# the agent publishes for them.
#   member     A, a member: the agent gives the folder FOLDER in this machine's node's files as
#              the site of <MEMBER>.<UPDATE_DOMAIN> (its _dnslink record), and the node's
#              addresses at that name (_dnsaddr).
#   community  B, the always-on community node: the agent follows <MEMBER>.<UPDATE_DOMAIN>: the
#              node pins each version of its site, and <SITE>.<UPDATE_DOMAIN> gives it once
#              pinned. The node's addresses go at <SITE>.<UPDATE_DOMAIN>, and its gateway is the
#              SRP instance "<HOST> ipfs-gateway", in SRP_DOMAIN. Once <SITE>.<UPDATE_DOMAIN> has
#              the site, the gateway's address for phones is printed, with a QR code.
# It checks that the node answers and has a swarm key, builds the proxy and the agent, starts
# them, waits until the zone's authoritative server has the records, and waits: Enter, or
# Ctrl-C, stops the agent, which frees the names, then the proxy. The logs and the agent's
# template go to a temporary directory, printed at the start.
#   MEMBER     the member's label; default a
#   SITE       the community's site's label; default site
#   HOST       the community node's host in SRP_DOMAIN; default b
#   FOLDER     the member's folder in its node's files; default /community
#   IPFS_API   the node's RPC API; default http://127.0.0.1:5001
#   IPFS_PATH  the node's repository, which holds its swarm key; default ~/.ipfs, IPFS Desktop's
#   GATEWAY    the community node's gateway port; default 8080
#   ADDRESS    the community node's address to publish; default, all of this machine's (auto)
#   NS, UPDATE_DOMAIN, SRP_DOMAIN  as for watch.sh; UPDATE_DOMAIN and SRP_DOMAIN are also where
#              the agent registers, and what the proxy serves (demo/lib.sh).
#   REGISTRAR, TRANSPORT  the registrar the agent uses instead of a proxy this script starts
#              (demo/lib.sh).
# The member starts first: the community node's agent follows a site that is there, and its node
# reaches the member's at the addresses published for it.

cd "$(dirname "$0")/.." || exit 1
. demo/lib.sh
B="./bin/$(uname -s | tr A-Z a-z)"
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

# registrar <protocol> [<line>] -- a registrar through this machine's proxy, with <line> (an srp
# registrar's domain) if given.
registrar() {
    echo "  - protocol: $1"
    [ -z "${2:-}" ] || echo "    $2"
    cat << EOF
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
        registrar rfc9664
        cat << EOF
    names:
      - name: $member.$update_domain.
        ipfs: {api: "$api", publish: {mfs: "$folder"}}
EOF
    else
        registrar srp "domain: $srp_domain."
        cat << EOF
    hosts:
      - name: $host
        addresses: [${ADDRESS:-auto}]
        services:
          - {type: ipfs-gateway, port: $gateway}
EOF
        registrar rfc9664
        cat << EOF
    names:
      - name: $site.$update_domain.
        ipfs: {api: "$api", follow: $member.$update_domain}
EOF
    fi
} > "$log/ipfs.yaml"
template "$log/ipfs.yaml" "$log/ipfs.yaml"
proxy_config

cat << EOF
D3's $role, its node at $api, published in the live zone, in $update_domain, $via.
Logs: $log
Answers are asked of $ns, the zone's authoritative server.
EOF

step "1. Start ${our_proxy:+the proxy and }the agent."
start_proxy
start agent agent.log "$B/sig0lease-agent" run -probe-interval 5s "$log/ipfs.yaml"
if [ "$role" = member ]; then
    wait_until "$member.$update_domain has the folder's site" answers TXT "_dnslink.$member.$update_domain"
    wait_until "$member.$update_domain has the node's addresses" answers TXT "_dnsaddr.$member.$update_domain"
    cat << EOF

What anyone can run:
  dig +short TXT _dnslink.$member.$update_domain
  dig +short TXT _dnsaddr.$member.$update_domain
A file put in $folder, in IPFS Desktop's Files, changes the site within about 15 s.
EOF
else
    wait_until "$site.$update_domain has the site $member.$update_domain gives, pinned" answers TXT "_dnslink.$site.$update_domain"
    wait_until "$site.$update_domain has the node's addresses" answers TXT "_dnsaddr.$site.$update_domain"
    wait_until "\"$host ipfs-gateway\" is registered" answers SRV "$host\\ ipfs-gateway._http._tcp.$srp_domain"
    address="$(ask A "$host.$srp_domain" | head -n 1)"
    url="http://$address:$gateway/ipns/$site.$update_domain/"
    cat << EOF

What anyone can run:
  dig +short TXT _dnslink.$site.$update_domain
  dns-sd -B _http._tcp,_ipfs $srp_domain       # a Mac: the IPFS gateways
The community's site: http://$host.$srp_domain:$gateway/ipns/$site.$update_domain/
  by address, for phones whose resolver hides private addresses: $url
EOF
    qrencode -t ANSIUTF8 "$url"
fi

step "2. Stop the agent${our_proxy:+ and the proxy}."
