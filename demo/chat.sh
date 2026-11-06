#!/bin/bash
# demo/chat.sh [label...] -- D5 of docs/demo.md: an XMPP server (Prosody) for each label, serving
# guests at <label>.dev.zenr.io and their rooms at rooms.<label>.dev.zenr.io, and the agent
# publishing each name's addresses, SRV records and TLSA record through the proxy on this
# machine. The servers find each other by the SRV records and authenticate each other by the
# TLSA records alone (DANE): their certificates are self-signed. Phones open the page a server
# serves, log in as its guests and meet in one room.
# It builds the proxy and the clients, starts the proxy, the servers and the agent, waits until
# the zone's authoritative server has the records, prints each page's address and a QR code of
# it, and waits: Enter, or Ctrl-C, stops the agent first, so that it frees the names,
# then the servers and the proxy. The logs and the agent's template go to a temporary directory,
# printed at the start.
#
# The demo runs it on two machines, with a label each (default chat); a rehearsal, on one
# machine with two labels.
#   ROOM     the room every page joins; default meet@rooms.<first label>.dev.zenr.io. On the
#            second machine, the first one's.
#   PROSODY  docker: the prosodyim/prosody:13.0 image (default on macOS); native: Prosody 13
#            with luaunbound, installed (default elsewhere).
#   ADDRESS  the address to publish for the servers; default, all of this machine's (auto).
#   NS, ZONE as for watch.sh; ZONE is also where the agent registers.
#   REGISTRAR, TRANSPORT  the registrar the agent uses instead of a proxy this script starts
#            (demo/lib.sh).
# Each label's certificate and key stay in demo/chat/servers/<label>.<zone>/ from one run to
# the next, and so does its TLSA record.

cd "$(dirname "$0")/.." || exit 1
. demo/lib.sh
B="./bin/$(uname -s | tr A-Z a-z)"
ns="${NS:-ns1.free2air.org}"
zone="${ZONE:-dev.zenr.io}"
labels=("$@")
[ ${#labels[@]} -gt 0 ] || labels=(chat)
room="${ROOM:-meet@rooms.${labels[0]}.$zone}"
image=prosodyim/prosody:13.0

for label in "${labels[@]}"; do
    if ! [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]; then
        echo "$label is not a DNS label: lower-case letters, digits and inner hyphens" >&2
        exit 1
    fi
done
if [ -z "${PROSODY:-}" ]; then
    if [ "$(uname -s)" = Darwin ]; then PROSODY=docker; else PROSODY=native; fi
fi
case "$PROSODY" in
docker) need=docker ;;
native) need=prosody ;;
*) echo "PROSODY is docker or native, not $PROSODY" >&2; exit 1 ;;
esac
for tool in "$need" openssl dig curl qrencode; do
    command -v "$tool" > /dev/null || { echo "$tool is not installed (docs/demo.md, D5)" >&2; exit 1; }
done

check_proxy_ports
build

# Each program runs in its own process group (set -m), so Ctrl-C reaches only this script, which
# then stops them in order: the proxy has to outlive the agent's deregistrations.
set -m
log="$(mktemp -d "${TMPDIR:-/tmp}/sig0lease-chat.XXXXXX")" || exit 1
proxy= agent=

finish() {
    trap '' INT
    echo
    echo "Stopping."
    stop agent
    for i in "${!labels[@]}"; do stop "server_$i"; done
    stop proxy
    echo "Logs: $log"
}
trap finish EXIT
trap 'exit 130' INT TERM

# The servers' ports: the first label's are XMPP's own, the next ones' 10 above the previous.
c2s_port() { echo $(( 5222 + 10 * $1 )); }
s2s_port() { echo $(( 5269 + 10 * $1 )); }
http_port() { echo $(( 5280 + 10 * $1 )); }
server_dir() { echo "$PWD/demo/chat/servers/${labels[$1]}.$zone"; }

# cert <dir> <domain> -- a self-signed certificate (cert.pem) for the domain and rooms.<domain>,
# and its key (key.pem), unless dir has them. Prosody checks a certificate's names even when its
# TLSA record matches. The key is readable by all: in the container, the prosody user reads it.
cert() {
    [ -s "$1/cert.pem" ] && [ -s "$1/key.pem" ] && return 0
    mkdir -p "$1" || return 1
    printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' 'x509_extensions = ext' \
        '[dn]' "CN = $2" '[ext]' "subjectAltName = DNS:$2, DNS:rooms.$2" > "$log/openssl.cnf"
    openssl ecparam -name prime256v1 -genkey -noout -out "$1/key.pem" &&
        openssl req -new -x509 -config "$log/openssl.cnf" -key "$1/key.pem" -days 3650 -out "$1/cert.pem" &&
        chmod 644 "$1/key.pem"
}

# spki <certificate> -- the SHA-256 of its public key: a TLSA 3 1 1 record's data.
spki() { openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 | awk '{print $NF}'; }

# tlsa <name> -- the TLSA record at name as "3 1 1 <data>", the data in one lower-case piece.
tlsa() { ask TLSA "$1" | awk '{ d = ""; for (i = 4; i <= NF; i++) d = d $i; print $1, $2, $3, tolower(d) }'; }
is() { [ "$("${@:2}")" = "$1" ]; }

page() { curl -sf -o /dev/null "http://127.0.0.1:$1/"; }

# server <i> -- starts label i's Prosody, as PROSODY says, with demo/chat/prosody.cfg.lua.
server() {
    local domain="${labels[$1]}.$zone" dir c2s s2s http
    dir="$(server_dir "$1")" c2s="$(c2s_port "$1")" s2s="$(s2s_port "$1")" http="$(http_port "$1")"
    if [ "$PROSODY" = docker ]; then
        start "server_$1" "${labels[$1]}-prosody.log" docker run --rm --name "sig0lease-$domain" \
            -p "$c2s:$c2s" -p "$s2s:$s2s" -p "$http:$http" \
            -e CHAT_DOMAIN="$domain" -e CHAT_DIR=/chat/server -e CHAT_WWW=/chat/www \
            -e CHAT_C2S="$c2s" -e CHAT_S2S="$s2s" -e CHAT_HTTP="$http" \
            -v "$PWD/demo/chat/prosody.cfg.lua:/etc/prosody/prosody.cfg.lua:ro" \
            -v "$dir:/chat/server:ro" -v "$PWD/demo/chat/www:/chat/www:ro" "$image"
    else
        mkdir -p "$dir/data" || exit 1
        start "server_$1" "${labels[$1]}-prosody.log" env CHAT_DOMAIN="$domain" CHAT_DIR="$dir" \
            CHAT_WWW="$PWD/demo/chat/www" CHAT_DATA="$dir/data" \
            CHAT_C2S="$c2s" CHAT_S2S="$s2s" CHAT_HTTP="$http" \
            CHAT_RUN_AS_ROOT="$( [ "$(id -u)" = 0 ] && echo yes)" \
            prosody --config "$PWD/demo/chat/prosody.cfg.lua" -F
    fi
}

{
    cat << EOF
# D5's template (docs/demo.md), written by demo/chat.sh: the XMPP servers' names, each with its
# addresses, the SRV records of its services and the TLSA record of its certificate.
keystore: $PWD/demo/keys-chat
registrars:
  - protocol: rfc9664
    zone: $zone.
    server: 127.0.0.1:8053
    lease: 10m
    on_stop: release
    names:
EOF
    for i in "${!labels[@]}"; do
        cat << EOF
      - name: ${labels[$i]}
        addresses: [${ADDRESS:-auto}]
        services:
          - {type: xmpp-client, port: $(c2s_port "$i")}
          - {type: xmpp-server, port: $(s2s_port "$i"), subdomains: [rooms], tlsa: $(server_dir "$i")/cert.pem}
EOF
    done
} > "$log/chat.yaml"
template "$log/chat.yaml" "$log/chat.yaml"

cat << EOF
XMPP servers for ${labels[*]/%/.$zone}, run by $PROSODY Prosody, published on the live $zone zone
$via. Logs: $log
Answers are asked of $ns, the zone's authoritative server.
EOF

step "1. Start ${our_proxy}the servers and the agent."
for i in "${!labels[@]}"; do
    # Prosody goes on running without a port it cannot have.
    for port in "$(c2s_port "$i")" "$(s2s_port "$i")" "$(http_port "$i")"; do
        if in_use "$port"; then
            echo "Port $port, for ${labels[$i]}.$zone's server, is in use: another XMPP server? (On Debian: sudo systemctl stop prosody)" >&2
            exit 1
        fi
    done
    cert "$(server_dir "$i")" "${labels[$i]}.$zone" || exit 1
done
start_proxy
for i in "${!labels[@]}"; do server "$i"; done
for i in "${!labels[@]}"; do wait_until "${labels[$i]}.$zone serves its page" page "$(http_port "$i")"; done
start agent agent.log "$B/sig0lease-agent" run -probe-interval 5s "$log/chat.yaml"
for i in "${!labels[@]}"; do
    domain="${labels[$i]}.$zone"
    wait_until "$domain has its SRV records" answers SRV "_xmpp-server._tcp.$domain"
    wait_until "rooms.$domain has its SRV records" answers SRV "_xmpp-server._tcp.rooms.$domain"
    wait_until "$domain has its TLSA record" is "3 1 1 $(spki "$(server_dir "$i")/cert.pem")" tlsa "_$(s2s_port "$i")._tcp.$domain"
done

echo
echo "What anyone can run:"
for i in "${!labels[@]}"; do
    domain="${labels[$i]}.$zone"
    echo "  dig +short SRV _xmpp-server._tcp.$domain"
    echo "  dig +short SRV _xmpp-server._tcp.rooms.$domain"
    echo "  dig +short TLSA _$(s2s_port "$i")._tcp.$domain"
done
echo "Every page joins $room."
for i in "${!labels[@]}"; do
    domain="${labels[$i]}.$zone"
    address="$(ask A "$domain" | head -n 1)"
    url="http://$address:$(http_port "$i")/?domain=$domain&room=$room"
    echo
    echo "$domain's page: http://$domain:$(http_port "$i")/?room=$room"
    echo "  by address, for phones whose resolver hides private addresses: $url"
    qrencode -t ANSIUTF8 "$url"
done

step "Last, stop the agent, the servers${our_proxy:+ and the proxy}: the agent frees the names (on_stop: release)."
