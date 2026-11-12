#!/bin/bash
# demo/ipfs.sh member|community -- D3 of docs/demo.md: a community folder over IPFS, kept by its
# members' kubo nodes (IPFS Desktop runs one) and a community node, in a private swarm.
#   community  the always-on community node: its agent lists the community's members, the
#              instances of _ipfs-member._tcp under the subtype <SITE> in SRP_DOMAIN whose
#              swarm-mac= the swarm key makes (docs/sig0lease-agent.md), and keeps a folder
#              with an entry for each, the member's folder once its node pinned it all,
#              which <SITE>.<UPDATE_DOMAIN> gives (its _dnslink record). An entry whose member is
#              not listed for REVOKE_AFTER is removed. The node's addresses go at
#              <SITE>.<UPDATE_DOMAIN>, where members' nodes find it, and its gateway is the SRP
#              instance "<HOST> ipfs-gateway", in SRP_DOMAIN: its address for phones is printed,
#              with a QR code. The members' comings and goings are printed as they happen.
#   member     a member: the agent registers this machine as the host <MEMBER> in SRP_DOMAIN,
#              with the instance <MEMBER> of _ipfs-member._tcp, the node's swarm port, under the
#              subtype <SITE>, its TXT record giving the folder FOLDER in the node's files and
#              the swarm-mac= the swarm key makes of it and the member's KEY; the member's key
#              holds the label, an hour after it stops too, so that it comes back as the same
#              member. The script waits until the community's folder has the member's.
# It checks that the node answers and has a swarm key, and for a member that its peer list has
# the community node, builds the proxy and the agent, starts them, waits until the zone's
# authoritative server has the records, and waits: Enter, or Ctrl-C, stops the agent, then the
# proxy. The community node's agent frees its names; a member's keeps its label. The logs and
# the agent's template go to a temporary directory, printed at the start.
#   MEMBER     the member's label: letters, digits and hyphens; default this machine's name
#   SITE       the community's label; default site
#   HOST       the community node's host in SRP_DOMAIN; default community
#   REVOKE_AFTER  community only: how long a member may be unlisted before its entry is removed;
#              default 10m
#   FOLDER     the member's folder in its node's files; default /community
#   IPFS_API   the node's RPC API; default http://127.0.0.1:5001
#   IPFS_PATH  the node's repository, which holds its swarm key, which the agent reads too;
#              default ~/.ipfs, IPFS Desktop's
#   GATEWAY    the community node's gateway port; default 8080
#   ADDRESS    the address to publish for the community node's or the member's host; default,
#              all of this machine's (auto)
#   NS, UPDATE_DOMAIN, SRP_DOMAIN  as for watch.sh; UPDATE_DOMAIN and SRP_DOMAIN are also where
#              the agent registers, and what the proxy serves (demo/lib.sh).
#   REGISTRAR, TRANSPORT  the registrar the agent uses instead of a proxy this script starts
#              (demo/lib.sh).
#   COMMUNITY_GATEWAY  member only: the registrar's community node, which is the community node
#              (deploy/README.md, "The community node"), as the https URL of its gateway with no
#              path, such as https://<registrar>:8444 for staging's. Once the community's folder
#              has the member's, its address there is printed, with a QR code.
# The community node starts first: members' nodes connect to it, at the addresses its name
# gives, and it fetches their folders over those connections; it never connects to theirs.

cd "$(dirname "$0")/.." || exit 1
. demo/lib.sh
B="./bin/$(uname -s | tr A-Z a-z)"
role="${1:-}"
member="${MEMBER:-$(hostname -s | tr A-Z a-z)}"
site="${SITE:-site}"
host="${HOST:-community}"
revoke_after="${REVOKE_AFTER:-10m}"
folder="${FOLDER:-/community}"
api="${IPFS_API:-http://127.0.0.1:5001}"
repo="${IPFS_PATH:-$HOME/.ipfs}"
gateway="${GATEWAY:-8080}"
community_gateway="${COMMUNITY_GATEWAY:-}"
community_gateway="${community_gateway%/}"
type=_ipfs-member._tcp

case "$role" in
member) tools=(go dig curl ${community_gateway:+qrencode}) labels=("$member" "$site") ;;
community) tools=(go dig curl qrencode) labels=("$site" "$host") ;;
*) echo "Usage: $0 member|community (docs/demo.md, D3)" >&2; exit 1 ;;
esac
if [ -n "$community_gateway" ]; then
    if [ "$role" != member ]; then
        echo "COMMUNITY_GATEWAY names the registrar's community node, which is the community node: run only members (docs/demo.md, D3)" >&2
        exit 1
    fi
    if ! [[ "$community_gateway" =~ ^https://[^/]+$ ]]; then
        echo "COMMUNITY_GATEWAY is the https URL of the registrar's gateway, with no path, such as https://<registrar>:8444: not $COMMUNITY_GATEWAY" >&2
        exit 1
    fi
fi
for tool in "${tools[@]}"; do
    command -v "$tool" > /dev/null || { echo "$tool is not installed (docs/demo.md, D3)" >&2; exit 1; }
done
for label in "${labels[@]}"; do
    if ! [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]; then
        hint=
        [ "$label" != "$member" ] || [ -n "${MEMBER:-}" ] || hint=": it is this machine's name; give the member's label as MEMBER"
        echo "$label is not a DNS label: lower-case letters, digits and inner hyphens$hint" >&2
        exit 1
    fi
done
if [ ! -f "$repo/swarm.key" ]; then
    echo "$repo has no swarm.key: the demo's nodes are a private swarm (docs/demo.md, D3: Once)" >&2
    exit 1
fi
swarm_key="$(cd "$repo" && pwd)/swarm.key"
if ! id="$(curl -sf -X POST "$api/api/v0/id")"; then
    echo "No IPFS node answers at $api: start IPFS Desktop, or ipfs daemon" >&2
    exit 1
fi
id="$(sed -n 's/.*"ID":"\([^"]*\)".*/\1/p' <<< "$id")"
if [ "$role" = member ]; then
    # The swarm port, which the member's instance gives and the agent probes over TCP.
    swarm="$(curl -sf -X POST "$api/api/v0/config?arg=Addresses.Swarm" | grep -o '/tcp/[0-9]*' | head -n 1)"
    swarm="${swarm#/tcp/}"
    if [ -z "$swarm" ]; then
        echo "The node at $api has no TCP swarm address (Addresses.Swarm): the member's instance gives its TCP port" >&2
        exit 1
    fi
    if ! curl -sf -X POST "$api/api/v0/bootstrap/list" | grep -qF "\"/dnsaddr/$site.$update_domain/p2p/"; then
        echo "The node's peer list has no /dnsaddr/$site.$update_domain/p2p/<ID>: the community node, which the member's node connects to; add it (docs/demo.md, D3: Once)" >&2
        exit 1
    fi
fi
check_proxy_ports

build

set -m
log="$(mktemp -d "${TMPDIR:-/tmp}/sig0lease-ipfs.XXXXXX")" || exit 1
proxy= agent= events=

finish() {
    trap '' INT
    echo
    echo "Stopping."
    [ -z "$events" ] || kill -- "-$events" 2> /dev/null
    stop agent
    stop proxy
    echo "Logs: $log"
}
trap finish EXIT
trap 'exit 130' INT TERM

# label -- the member's label: MEMBER, or the one the agent renamed it to, another key holding
# MEMBER (its log says "renamed: now ...").
label() {
    local renamed
    renamed="$(sed -n "s/.*renamed: now .*\"$member\" $type as \"\([^\"]*\)\".*/\1/p" "$log/agent.log" | tail -n 1)"
    echo "${renamed:-$member}"
}

# listed -- whether the member is listed under the community's subtype.
listed() { ask PTR "$site._sub.$type.$srp_domain" | grep -qixF "$(label).$type.$srp_domain."; }

# cid <answers> -- the CID of a "dnslink=/ipfs/<CID>" TXT record among the answers.
cid() { sed -n 's/.*"dnslink=\/ipfs\/\([^"/]*\)".*/\1/p' <<< "$1" | head -n 1; }

# in_site -- whether the community's folder has the member's entry, giving the folder the
# member's TXT record gives, as this machine's node reads the community's folder.
in_site() {
    local mine dir entry
    mine="$(cid "$(ask TXT "$(label).$type.$srp_domain")")"
    dir="$(cid "$(ask TXT "_dnslink.$site.$update_domain")")"
    [ -n "$mine" ] && [ -n "$dir" ] || return 1
    entry="$(curl -sf --max-time 5 -X POST "$api/api/v0/files/stat?arg=/ipfs/$dir/$(label)&hash=true")" || return 1
    [ "$(sed -n 's/.*"Hash":"\([^"]*\)".*/\1/p' <<< "$entry")" = "$mine" ]
}

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
    if [ "$role" = member ]; then
        cat << EOF
# D3's template for the member $member (docs/demo.md), written by demo/ipfs.sh.
keystore: $PWD/demo/keys-ipfs-member-$member
registrars:
EOF
        registrar srp "domain: $srp_domain."
        cat << EOF
    hosts:
      - name: $member
        addresses: [${ADDRESS:-auto}]
        lease: 2m                     # gone from the listing within 2 minutes if it vanishes
        key_lease: 1h                 # its label stays its own for an hour after it stops
        on_stop: keep
        services:
          - type: ipfs-member
            instance: $member
            port: $swarm
            subtypes: [$site]
            ipfs: {api: "$api", swarm_key: "$swarm_key", publish: {mfs: "$folder"}}
EOF
    else
        cat << EOF
# D3's template for the community node (docs/demo.md), written by demo/ipfs.sh.
keystore: $PWD/demo/keys-ipfs-community
registrars:
EOF
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
        ipfs:
          api: "$api"
          swarm_key: "$swarm_key"
          follow: {type: ipfs-member, domain: $srp_domain, revoke_after: $revoke_after}
EOF
    fi
} > "$log/ipfs.yaml"
template "$log/ipfs.yaml" "$log/ipfs.yaml"
proxy_config

what="the community node"
[ "$role" = community ] || what="the member $member"
cat << EOF
D3's $what, its node at $api, published in the live zone, in $update_domain, $via.
Logs: $log
Answers are asked of $ns, the zone's authoritative server.
EOF

step "1. Start ${our_proxy:+the proxy and }the agent."
start_proxy
start agent agent.log "$B/sig0lease-agent" run -probe-interval 5s "$log/ipfs.yaml"
if [ "$role" = member ]; then
    wait_until "$member is listed, a member of $site" listed
    wait_until "the community's folder has $(label)'s, pinned by the community node" in_site
    cat << EOF

What anyone can run:
  dig +short PTR $site._sub.$type.$srp_domain      # the members
  dig +short TXT $(label).$type.$srp_domain        # this member's folder, and its swarm-mac=
The community's folder: /ipns/$site.$update_domain/, this member's in it: /ipns/$site.$update_domain/$(label)/
A file put in $folder, in IPFS Desktop's Files, changes this member's folder within about 15 s,
and the community's once its node pinned it. Stopped, the member's entry stays for the community
node's REVOKE_AFTER, and its label for an hour: run again within it to come back as the member.
EOF
    if [ -n "$community_gateway" ]; then
        url="$community_gateway/ipns/$site.$update_domain/$(label)/"
        echo
        echo "This member's folder, from anywhere: $url"
        qrencode -t ANSIUTF8 "$url"
    fi
else
    wait_until "$site.$update_domain has the community's folder" answers TXT "_dnslink.$site.$update_domain"
    wait_until "$site.$update_domain has the node's addresses" answers TXT "_dnsaddr.$site.$update_domain"
    wait_until "\"$host ipfs-gateway\" is registered" answers SRV "$host\\ ipfs-gateway._http._tcp.$srp_domain"
    address="$(ask A "$host.$srp_domain" | head -n 1)"
    url="http://$address:$gateway/ipns/$site.$update_domain/"
    cat << EOF

Each member's peer list names this node: ipfs bootstrap add /dnsaddr/$site.$update_domain/p2p/$id
What anyone can run:
  dig +short PTR $site._sub.$type.$srp_domain      # the members
  dig +short TXT _dnslink.$site.$update_domain     # the community's folder
  dns-sd -B _http._tcp,_ipfs $srp_domain       # a Mac: the IPFS gateways
The community's folder, one folder per member: http://$host.$srp_domain:$gateway/ipns/$site.$update_domain/
  by address, for phones whose resolver hides private addresses: $url
EOF
    qrencode -t ANSIUTF8 "$url"
    echo
    echo "Members, as they come and go (REVOKE_AFTER $revoke_after):"
    (tail -n +1 -f "$log/agent.log" | grep --line-buffered -E ": [^ ]+ is (a member|listed again|not listed|another key's now)|: (un)?pinned |: [^ ]+'s entry gives |: found |: [^ ]+: not a member|: swarm key") &
    events=$!
fi

step "2. Stop the agent${our_proxy:+ and the proxy}."
