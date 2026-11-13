#!/bin/bash
# demo/ipfs-local.sh start|stop -- the three kubo nodes of D3's local test (docs/demo.md, D3,
# "Local test"), on this machine: the community node's and the members alice's and carol's, each
# with a repository of its own, $IPFS_REPOS/.ipfs-<node>, apart from IPFS Desktop's ~/.ipfs.
#   start  sets up and starts each node that does not run, as docs/demo.md describes: its
#          repository (ipfs init), D3's settings and the node's ports, the community's swarm key
#          (made once, in the community node's repository, and copied to the members'), and the
#          community node in the members' peer lists. The node runs in the background, logging to
#          daemon.log in its repository. Then each member gets its folder, /community, with a
#          first file, if it has none, and the commands that run the test are printed. A node
#          that runs is left as it is.
#   stop   stops the three nodes. Their repositories stay, for the next start.
#   UPDATE_DOMAIN, SITE  as for demo/ipfs.sh: the community's name, <SITE>.<UPDATE_DOMAIN>,
#          which the members' peer lists give
#   IPFS_REPOS  the directory of the repositories; default the home directory

cd "$(dirname "$0")/.." || exit 1
. demo/lib.sh
action="${1:-}"
case "$action" in
start|stop) ;;
*) echo "Usage: $0 start|stop (docs/demo.md, D3, \"Local test\")" >&2; exit 1 ;;
esac
if remote; then
    echo "D3's local test uses no registrar: paste the laptop's block, whose REGISTRAR is empty (docs/demo.md, \"Running a demo\")" >&2
    exit 1
fi
for tool in ipfs curl openssl; do
    command -v "$tool" > /dev/null || { echo "$tool is not installed (docs/demo.md, D3)" >&2; exit 1; }
done
site="${SITE:-site}"
repos="${IPFS_REPOS:-$HOME}"
nodes=(community alice carol)

# repo <node> -- the node's repository.
repo() { echo "$repos/.ipfs-$1"; }

# shown <node> -- the node's repository as the printed commands give it.
shown() { if [ "$repos" = "$HOME" ]; then echo "~/.ipfs-$1"; else repo "$1"; fi; }

# ports <node> -- the node's API, swarm and gateway ports, and the address its gateway listens
# on: the community node's on all of this machine's, for the phones.
ports() {
    case "$1" in
    community) echo 5002 4002 8081 0.0.0.0 ;;
    alice) echo 5003 4003 8082 127.0.0.1 ;;
    carol) echo 5004 4004 8083 127.0.0.1 ;;
    esac
}

# on <node> <arguments...> -- runs ipfs with the node's repository.
on() {
    local n="$1"
    shift
    IPFS_PATH="$(repo "$n")" ipfs "$@"
}

# peer_id <node> -- the node's peer ID, from its repository's config.
peer_id() { sed -n 's/^ *"PeerID": "\([^"]*\)".*/\1/p' "$(repo "$1")/config" 2> /dev/null; }

# runs <node> -- whether the node answers at its API port.
runs() {
    local api
    read -r api _ <<< "$(ports "$1")"
    curl -sf --max-time 2 -X POST "http://127.0.0.1:$api/api/v0/id" | grep -qF "\"ID\":\"$(peer_id "$1")\""
}

# set_up <node> -- makes the node's repository if there is none, and gives the node D3's settings
# and its ports (docs/demo.md, D3, "How a node is set up").
set_up() {
    local n="$1" api swarm gateway at
    read -r api swarm gateway at <<< "$(ports "$n")"
    if [ ! -f "$(repo "$n")/config" ]; then
        on "$n" init -e > /dev/null || exit 1
        echo "  $n: a new repository, $(repo "$n"), node $(peer_id "$n")"
    fi
    on "$n" config profile apply autoconf-off > /dev/null &&
        on "$n" config Routing.Type dht &&
        on "$n" config --json AutoTLS.Enabled false &&
        on "$n" config --json Swarm.Transports.Network.Websocket false &&
        on "$n" config --json Discovery.MDNS.Enabled false &&
        on "$n" config Addresses.API "/ip4/127.0.0.1/tcp/$api" &&
        on "$n" config Addresses.Gateway "/ip4/$at/tcp/$gateway" &&
        on "$n" config --json Addresses.Swarm "[\"/ip4/0.0.0.0/tcp/$swarm\", \"/ip4/0.0.0.0/udp/$swarm/quic-v1\"]" ||
        exit 1
}

if [ "$action" = stop ]; then
    for n in "${nodes[@]}"; do
        if ! runs "$n"; then
            echo "  $n's node does not run"
            continue
        fi
        on "$n" shutdown || exit 1
        for _ in $(seq 30); do
            runs "$n" || break
            sleep 1
        done
        if runs "$n"; then
            echo "$n's node still runs 30 s after ipfs shutdown; $(repo "$n")/daemon.log says why" >&2
            exit 1
        fi
        echo "  $n's node stopped"
    done
    exit 0
fi

key="$(repo community)/swarm.key"
started=()
for n in "${nodes[@]}"; do
    if runs "$n"; then
        if [ "$n" != community ] && ! cmp -s "$key" "$(repo "$n")/swarm.key"; then
            echo "$n's node runs with a swarm key other than the community's: stop it ($0 stop), then start again" >&2
            exit 1
        fi
        echo "  $n's node runs: left as it is"
        continue
    fi
    read -r api swarm gateway _ <<< "$(ports "$n")"
    for port in "$api" "$swarm" "$gateway"; do
        if in_use "$port"; then
            echo "Port $port, $n's node's, is in use by another program: stop it first" >&2
            exit 1
        fi
    done
    set_up "$n"
    if [ "$n" = community ]; then
        if [ ! -f "$key" ]; then
            printf '/key/swarm/psk/1.0.0/\n/base16/\n%s\n' "$(openssl rand -hex 32)" > "$key" || exit 1
            echo "  a new swarm key for the community, $key"
        fi
    else
        cp "$key" "$(repo "$n")/swarm.key" || exit 1
        on "$n" bootstrap rm --all > /dev/null &&
            on "$n" bootstrap add "/dnsaddr/$site.$update_domain/p2p/$(peer_id community)" > /dev/null ||
            exit 1
    fi
    nohup env IPFS_PATH="$(repo "$n")" ipfs daemon < /dev/null >> "$(repo "$n")/daemon.log" 2>&1 &
    started+=("$n")
done
for n in "${started[@]}"; do
    for _ in $(seq 60); do
        runs "$n" && break
        sleep 1
    done
    if ! runs "$n"; then
        echo "$n's node did not start; $(repo "$n")/daemon.log:" >&2
        tail -n 5 "$(repo "$n")/daemon.log" >&2
        exit 1
    fi
    echo "  $n's node runs, logging to $(repo "$n")/daemon.log"
done
for n in alice carol; do
    on "$n" files stat /community > /dev/null 2>&1 && continue
    cid="$(printf "%s's first file in the community's folder, from demo/ipfs-local.sh\n" "$n" | on "$n" add -Q)" &&
        on "$n" files mkdir /community &&
        on "$n" files cp "/ipfs/$cid" "/community/$n.txt" || exit 1
    echo "  $n's folder, /community, with $n.txt"
done

sites="${SITE:+SITE=$site }"
cat << EOF

The three nodes run. Each in a terminal of its own (docs/demo.md, D3, "Local test", "Run"):
  UPDATE_DOMAIN=$update_domain NAME=$site demo/watch.sh
  UPDATE_DOMAIN=$update_domain ${sites}REVOKE_AFTER=2m IPFS_PATH=$(shown community) IPFS_API=http://127.0.0.1:5002 GATEWAY=8081 demo/ipfs.sh community
  REGISTRAR=127.0.0.1:8053 UPDATE_DOMAIN=$update_domain ${sites}MEMBER=alice IPFS_PATH=$(shown alice) IPFS_API=http://127.0.0.1:5003 demo/ipfs.sh member
  REGISTRAR=127.0.0.1:8053 UPDATE_DOMAIN=$update_domain ${sites}MEMBER=carol IPFS_PATH=$(shown carol) IPFS_API=http://127.0.0.1:5004 demo/ipfs.sh member
A file into alice's folder:
  export IPFS_PATH=$(shown alice)
  ipfs files cp /ipfs/\$(ipfs add -Q photo.jpg) /community/photo.jpg
Afterwards: demo/ipfs-local.sh stop
EOF
