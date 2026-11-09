#!/bin/bash
#
# sig0lease-agent end-to-end test.
#
# Runs the real agent (cmd/sig0lease-agent) on a template, against the real proxy (srp_handler,
# and the RFC 9664 handler for the names) and a real, disposable local BIND 9 authoritative for
# srp.test. and update.test. (lib/srp.sh, as test_srp.sh): validate and plan -> run registers
# the template's hosts and services -> a
# probed service that stops answering is withdrawn, and registered again when it answers ->
# template edits are applied, an invalid one is ignored -> a name another key holds is renamed;
# a restart frees the rename's names and asks for the name again, renamed again while the other
# key holds it, its own once that key frees it -> stopping deregisters everything, keeping the
# names for the agent's keys (on_stop: keep) -> a host removed from the template frees its names, and with
# on_stop: release so does stopping -> a host removed while the agent was stopped has its names
# freed at the next start -> an RFC 9664 name is registered with its records, one another key
# holds is tried again rather than renamed, stopping keeps the name and removing it frees it ->
# with Prosody installed, two XMPP servers on ports only their names' SRV records give federate
# through what the agent publishes, a stopped one's records are withdrawn and come back ->
# with kubo installed, a name publishes a node's folder and addresses, and another follows it,
# its node pinning each version before the name gives it.
# The probed service is python3's http.server; the other key is sig0lease-srp-client's, and
# sig0lease-client's for a name.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
# The proxy's config, DoT certificate and log, and here the agent's directory and logs too.
SRP_RUN_DIR="$PROXY_RUN_ROOT/agent"
SRP_UPDATE_HANDLER=true
source "$SCRIPT_DIR/lib/srp.sh"

AGENT_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease-agent"
SRP_CLIENT_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease-srp-client"
CLIENT_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease-client"
AGENT_DIR="$SRP_RUN_DIR/agent" # the template, and the keystore the template names (keys/)
AGENT_TEMPLATE="$AGENT_DIR/agent.yaml"
AGENT_LOG="$SRP_RUN_DIR/agent.log"
AGENT_PID=""
# Fast enough for a test: a stopped service is withdrawn after 3 probes a second apart.
AGENT_FLAGS=(-poll-interval=1s -probe-interval=1s)
AGENT_HTTP_PORT="${AGENT_HTTP_PORT:-18180}"
AGENT_HTTP_DIR="$SRP_RUN_DIR/www"
AGENT_HTTP_LOG="$SRP_RUN_DIR/http.log"
AGENT_HTTP_PID=""
HOLDER_KEY_DIR="$SRP_RUN_DIR/holder" # the other key, holding taken.srp.test., and held.update.test.'s
NAME_ZONE="$BIND9_UPDATE_ZONE"         # the RFC 9664 handler's zone
# The template's rfc9664 registrar, as write_template appends it: none until AGENT-TEST 9.
NAMES_REGISTRAR=""
CHANGE_TIMEOUT=20 # seconds for a change to reach BIND: probes, settle time, the client's 0-3s delay
# AGENT-TEST 10's two Prosody servers, a and b in NAME_ZONE, each in XMPP_DIR/<server> and
# federating on its own port: not XMPP's 5269, so that only their SRV records tell where.
XMPP_DIR="$SRP_RUN_DIR/xmpp"
XMPP_A_PORT="${XMPP_A_PORT:-15269}"
XMPP_B_PORT="${XMPP_B_PORT:-25269}"
PROSODY_PID_a=""
PROSODY_PID_b=""
# AGENT-TEST 11's two kubo nodes, a and b, each in IPFS_DIR/<node>, in a private swarm of
# their own: no other node has its key.
IPFS_DIR="$SRP_RUN_DIR/ipfs"
IPFS_A_API_PORT="${IPFS_A_API_PORT:-15001}"
IPFS_A_SWARM_PORT="${IPFS_A_SWARM_PORT:-14001}"
IPFS_B_API_PORT="${IPFS_B_API_PORT:-25001}"
IPFS_B_SWARM_PORT="${IPFS_B_SWARM_PORT:-24001}"
IPFS_PID_a=""
IPFS_PID_b=""

PERFORMED_TESTS=""

build_agent_binaries() {
    log_section "BUILD"
    (cd "$TESTS_DIR/.." && go build -o "$PROXY_BIN" ./cmd/sig0lease)
    (cd "$TESTS_DIR/.." && go build -o "$AGENT_BIN" ./cmd/sig0lease-agent)
    (cd "$TESTS_DIR/.." && go build -o "$SRP_CLIENT_BIN" ./cmd/sig0lease-srp-client)
    (cd "$TESTS_DIR/.." && go build -o "$CLIENT_BIN" ./cmd/sig0lease-client)
    log_success "Binaries built"
}

# write_template [srp registrar line...] -- writes the agent's template: the keystore, the srp
# registrar every test uses with any further lines given, then stdin (its hosts:, and anything
# after it, written as at the top level), then NAMES_REGISTRAR. Written to a temporary file
# and moved, as the agent may read it at any moment.
write_template() {
    {
        cat <<EOF
keystore: keys
registrars:
  - protocol: srp
    domain: ${SRP_ZONE}
    server: ${SRP_PROXY_URL}
    transport: tcp
    resolvers: ["${BIND9_ADDR}:${BIND9_PORT}"]
    lease: 1h
    key_lease: 336h
EOF
        [ $# -eq 0 ] || printf '    %s\n' "$@"
        sed 's/^/    /'
        printf '%s' "$NAMES_REGISTRAR"
    } > "$AGENT_TEMPLATE.tmp" && mv "$AGENT_TEMPLATE.tmp" "$AGENT_TEMPLATE"
}

# names_registrar <names: lines> -- the rfc9664 registrar through the proxy, with the names given
# (written as at the top level, each in full, in NAME_ZONE), for NAMES_REGISTRAR.
names_registrar() {
    cat <<EOF
  - protocol: rfc9664
    server: ${SRP_PROXY_URL}
    transport: tcp
EOF
    sed 's/^/    /' <<< "$1"
}

# The agent's first template: one host, a probed web service and an unprobed printer.
write_first_template() {
    write_template <<EOF
hosts:
  - name: agent1
    addresses: [127.0.0.1]
    services:
      - {type: http, instance: Web, port: ${AGENT_HTTP_PORT}, txt: {path: /}, probe: {http: /health}}
      - {type: ipp, instance: Printer, probe: none}
EOF
}

start_http() {
    if is_listening "$AGENT_HTTP_PORT"; then
        log_error "Port $AGENT_HTTP_PORT, for the probed web service, is already in use; set AGENT_HTTP_PORT"
        return 1
    fi
    python3 -m http.server --bind 127.0.0.1 --directory "$AGENT_HTTP_DIR" "$AGENT_HTTP_PORT" >> "$AGENT_HTTP_LOG" 2>&1 &
    AGENT_HTTP_PID=$!
    local start
    start=$(date +%s)
    until is_listening "$AGENT_HTTP_PORT"; do
        if [ $(( $(date +%s) - start )) -ge 10 ] || ! kill -0 "$AGENT_HTTP_PID" 2>/dev/null; then
            log_error "python3 -m http.server did not start:"
            cat "$AGENT_HTTP_LOG"
            return 1
        fi
        sleep 0.2
    done
}

stop_http() {
    if [ -n "${AGENT_HTTP_PID:-}" ] && kill -0 "$AGENT_HTTP_PID" 2>/dev/null; then
        stop_process "$AGENT_HTTP_PID" || true
    fi
    AGENT_HTTP_PID=""
}

start_agent() {
    "$AGENT_BIN" run "${AGENT_FLAGS[@]}" "$AGENT_TEMPLATE" >> "$AGENT_LOG" 2>&1 &
    AGENT_PID=$!
    sleep 0.5
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        log_error "sig0lease-agent exited at once:"
        cat "$AGENT_LOG"
        return 1
    fi
}

# stop_agent stops the agent the way Ctrl-C does and returns its exit status.
stop_agent() {
    local status=0
    if [ -n "${AGENT_PID:-}" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        stop_process "$AGENT_PID" || status=$?
    fi
    AGENT_PID=""
    return "$status"
}

# agent_log_has <text> -- whether the agent logged a line containing text.
agent_log_has() {
    grep -qF -- "$1" "$AGENT_LOG"
}

# wait_log <text> [count, default 1] -- waits for the agent to have logged count lines
# containing text.
wait_log() {
    local start
    start=$(date +%s)
    until [ "$(grep -cF -- "$1" "$AGENT_LOG")" -ge "${2:-1}" ]; do
        if [ $(( $(date +%s) - start )) -ge "$CHANGE_TIMEOUT" ]; then
            log_error "the agent did not log \"$1\":"; cat "$AGENT_LOG"; return 1
        fi
        sleep 0.5
    done
}

# claim_as_holder <host> -- the other key registers host (sig0lease-srp-client -once), printing
# the registrar's answer; exits non-zero unless it is NOERROR.
claim_as_holder() {
    "$SRP_CLIENT_BIN" -server="$SRP_PROXY_URL" -domain="$SRP_ZONE" -keystore="$HOLDER_KEY_DIR" -k=13 -once \
        -host="$1" -addr=192.0.2.70
}

# release_as_holder <host> -- the other key frees host (sig0lease-srp-client -deregister,
# KEY-LEASE 0), as claim_as_holder.
release_as_holder() {
    "$SRP_CLIENT_BIN" -server="$SRP_PROXY_URL" -domain="$SRP_ZONE" -keystore="$HOLDER_KEY_DIR" -k=13 -deregister \
        -host="$1"
}

# claim_name_as_holder <label> -- the other key registers <label>.NAME_ZONE with a TXT record
# "holder" (sig0lease-client name -once, on client/rfc9664 as the agent's names are), printing
# the proxy's answer; exits non-zero unless it is NOERROR.
claim_name_as_holder() {
    "$CLIENT_BIN" name -server="$SRP_PROXY_URL" -name="$1.$NAME_ZONE" -keystore="$HOLDER_KEY_DIR" -k=13 -once \
        -record='@ TXT "holder"'
}

# wait_state <name> <type> <present|absent> -- wait_for_srp_state with CHANGE_TIMEOUT, showing
# the agent's log when it times out.
wait_state() {
    wait_for_srp_state "$1" "$2" "$3" "$CHANGE_TIMEOUT" || { echo "agent log:"; cat "$AGENT_LOG"; return 1; }
}

# start_prosody <server> <port> -- runs Prosody for <server>.NAME_ZONE in XMPP_DIR/<server>,
# federating on 127.0.0.1:<port> alone, with a throwaway certificate (make_tls_cert, kept
# across restarts), resolving every name through the local BIND, and for a the group chat
# service rooms.a. Server-to-server connections are encrypted and authenticated by dialback,
# Prosody's defaults with a certificate no authority signed; DANE needs DNSSEC, which the local
# BIND does not sign.
start_prosody() {
    local server="$1" port="$2" dir="$XMPP_DIR/$1" host="$1.${NAME_ZONE%.}" rooms=""
    if is_listening "$port"; then
        log_error "Port $port, for Prosody $host, is already in use; set XMPP_A_PORT or XMPP_B_PORT"
        return 1
    fi
    mkdir -p "$dir/data"
    [ -f "$dir/cert.pem" ] || make_tls_cert "$dir" || return 1
    if [ "$server" = a ]; then
        rooms="$(printf 'Component "rooms.%s" "muc"\n    modules_enabled = { "ping" }' "$host")"
    fi
    cat > "$dir/prosody.cfg.lua" <<CFG
-- AGENT-TEST 10's Prosody for $host (tests/test_agent.sh).
pidfile = "$dir/prosody.pid"
data_path = "$dir/data"
admin_socket = "$dir/prosody.sock"
log = { debug = "$dir/prosody.log" }
run_as_root = true -- the suite may run as root, as in a container
interfaces = { "127.0.0.1" }
c2s_ports = { }
s2s_ports = { $port }
modules_enabled = { "disco", "tls", "dialback", "ping", "admin_shell" }
certificates = "$dir" -- where Prosody looks for certificates by host name; ssl gives the one to use
ssl = { certificate = "$dir/cert.pem", key = "$dir/key.pem" }
-- libunbound answers every name in test. NXDOMAIN itself (RFC 6761 S6.2) unless told otherwise.
unbound = {
    resolvconf = false, hoststxt = false, forward = { "${BIND9_ADDR}@${BIND9_PORT}" },
    options = { ["local-zone"] = "test. transparent" },
}
VirtualHost "$host"
$rooms
CFG
    prosody --config "$dir/prosody.cfg.lua" -F >> "$dir/prosody.out" 2>&1 &
    eval "PROSODY_PID_$server=$!"
    local start pid
    start=$(date +%s)
    until is_listening "$port"; do
        pid="$(eval echo "\$PROSODY_PID_$server")"
        if [ $(( $(date +%s) - start )) -ge 10 ] || ! kill -0 "$pid" 2>/dev/null; then
            log_error "Prosody $host did not start:"
            cat "$dir/prosody.out"
            tail -20 "$dir/prosody.log" 2>/dev/null
            return 1
        fi
        sleep 0.2
    done
}

# stop_prosody <server> -- stops the Prosody start_prosody runs for <server>.
stop_prosody() {
    local pid
    pid="$(eval echo "\$PROSODY_PID_$1")"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        stop_process "$pid" || true
    fi
    eval "PROSODY_PID_$1=''"
}

# xmpp_ping <from server> <to host> -- has the Prosody of <from server> ping <to host>
# (XEP-0199) over a server-to-server connection, printing the answer; exits non-zero unless a
# pong comes back.
xmpp_ping() {
    local out
    out="$(prosodyctl --config "$XMPP_DIR/$1/prosody.cfg.lua" shell "xmpp:ping('$1.${NAME_ZONE%.}', '$2', 15)" 2>&1)"
    echo "$out"
    grep -q "^OK: pong from $2 " <<< "$out"
}

# spki_sha256 <certificate file> -- the SHA-256 of the certificate's public key, in lower-case
# hex: the data of a TLSA 3 1 1 record for it.
spki_sha256() {
    openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 | awk '{print $NF}'
}

# dig_tlsa <name> -- the TLSA record at name as "<usage> <selector> <type> <data>", the data in
# lower-case hex in one piece (dig splits it).
dig_tlsa() {
    dig_srp "$1" TLSA | awk '{ d = ""; for (i = 4; i <= NF; i++) d = d $i; print $1, $2, $3, tolower(d) }'
}

# start_kubo <node> <api port> <swarm port> -- runs a kubo node in IPFS_DIR/<node>, made the
# first time with kubo's test profile (no bootstrap peers, no mDNS, no AutoConf), in the private
# swarm of IPFS_DIR/swarm.key (LIBP2P_FORCE_PNET: kubo refuses to start without it), its RPC API
# on 127.0.0.1:<api port>, and listening for other nodes on <swarm port> at every address: the
# agent publishes only the addresses that mean something off the link.
start_kubo() {
    local node="$1" api="$2" swarm="$3" dir="$IPFS_DIR/$1" port
    for port in "$api" "$swarm"; do
        if is_listening "$port"; then
            log_error "Port $port, for kubo $node, is already in use; set IPFS_A_API_PORT, IPFS_A_SWARM_PORT, IPFS_B_API_PORT or IPFS_B_SWARM_PORT"
            return 1
        fi
    done
    if [ ! -f "$IPFS_DIR/swarm.key" ]; then
        mkdir -p "$IPFS_DIR"
        printf '/key/swarm/psk/1.0.0/\n/base16/\n%s\n' "$(openssl rand -hex 32)" > "$IPFS_DIR/swarm.key"
    fi
    if [ ! -d "$dir" ]; then
        IPFS_PATH="$dir" ipfs init --profile test > "$dir.log" 2>&1 || { cat "$dir.log"; return 1; }
        IPFS_PATH="$dir" ipfs config Addresses.API "/ip4/127.0.0.1/tcp/$api"
        IPFS_PATH="$dir" ipfs config --json Addresses.Swarm "[\"/ip4/0.0.0.0/tcp/$swarm\"]"
        cp "$IPFS_DIR/swarm.key" "$dir/swarm.key"
    fi
    IPFS_PATH="$dir" LIBP2P_FORCE_PNET=1 ipfs daemon >> "$dir.log" 2>&1 &
    eval "IPFS_PID_$node=$!"
    local start pid
    start=$(date +%s)
    until ipfs_on "$node" id > /dev/null 2>&1; do
        pid="$(eval echo "\$IPFS_PID_$node")"
        if [ $(( $(date +%s) - start )) -ge 20 ] || ! kill -0 "$pid" 2>/dev/null; then
            log_error "kubo $node did not start:"
            cat "$dir.log"
            return 1
        fi
        sleep 0.2
    done
}

# stop_kubo <node> -- stops the kubo start_kubo runs for <node>.
stop_kubo() {
    local pid
    pid="$(eval echo "\$IPFS_PID_$1")"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        stop_process "$pid" || true
    fi
    eval "IPFS_PID_$1=''"
}

# ipfs_on <node> <ipfs arguments...> -- runs an ipfs command against the running kubo <node>.
ipfs_on() {
    local port="$IPFS_A_API_PORT"
    [ "$1" = a ] || port="$IPFS_B_API_PORT"
    shift
    ipfs --api "/ip4/127.0.0.1/tcp/$port" "$@"
}

# wait_txt <name> <text> -- waits for the TXT records at name to be text, as dig +short prints
# them.
wait_txt() {
    local start got
    start=$(date +%s)
    until got="$(dig_srp "$1" TXT)" && [ "$got" = "$2" ]; do
        if [ $(( $(date +%s) - start )) -ge "$CHANGE_TIMEOUT" ]; then
            log_error "TXT $1 is \"$got\", want \"$2\"; agent log:"; cat "$AGENT_LOG"; return 1
        fi
        sleep 0.5
    done
}

################################
# Tests
################################

test_validate_and_plan() {
    local log_msg="AGENT-TEST 1: validate lists every problem; plan shows the template and writes nothing"
    log_section "$log_msg"

    write_template <<EOF
hosts:
  - name: -bad
    addresses: []
    services:
      - {type: sssh}
EOF
    local out
    if out="$("$AGENT_BIN" validate "$AGENT_TEMPLATE" 2>&1)"; then
        log_error "validate accepted a broken template:"; echo "$out"; return 1
    fi
    echo "$out"
    for want in 'name "-bad"' 'addresses: at least one' 'unknown type "sssh"' '3 problem(s)'; do
        grep -qF -- "$want" <<< "$out" || { log_error "validate did not report: $want"; return 1; }
    done

    write_first_template
    out="$("$AGENT_BIN" validate "$AGENT_TEMPLATE")"
    echo "$out"
    grep -qF "is valid: 1 registrar(s); 1 host(s), 2 service(s), 0 mirror(s); 0 name(s)" <<< "$out" || { log_error "validate did not accept the template"; return 1; }
    out="$("$AGENT_BIN" plan "$AGENT_TEMPLATE")"
    echo "$out"
    grep -qF "host agent1.${SRP_ZONE}" <<< "$out" || { log_error "plan does not show agent1"; return 1; }
    grep -qF "service \"Web\" _http._tcp port ${AGENT_HTTP_PORT}, type http, probe http /health" <<< "$out" \
        || { log_error "plan does not show Web as the template gives it"; return 1; }
    grep -qF "key:       none yet" <<< "$out" || { log_error "plan does not say the key is to be created"; return 1; }
    [ ! -e "$AGENT_DIR/keys" ] || { log_error "plan created $AGENT_DIR/keys"; return 1; }

    log_success "validate reported every problem at once; plan described the template and created nothing"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_run_registers() {
    local log_msg="AGENT-TEST 2: run registers the host and its services once their probes pass"
    log_section "$log_msg"

    start_http
    start_agent
    wait_state "Web._http._tcp.${SRP_ZONE}" SRV present || return 1
    wait_state "Printer._ipp._tcp.${SRP_ZONE}" SRV present || return 1

    [ "$(dig_srp "agent1.${SRP_ZONE}" A)" = "127.0.0.1" ] || { log_error "A agent1.${SRP_ZONE} is not 127.0.0.1"; return 1; }
    [ -n "$(dig_srp "agent1.${SRP_ZONE}" KEY)" ] || { log_error "no KEY at agent1.${SRP_ZONE}"; return 1; }
    [ "$(dig_srp "Web._http._tcp.${SRP_ZONE}" SRV)" = "0 0 ${AGENT_HTTP_PORT} agent1.${SRP_ZONE}" ] \
        || { log_error "Web's SRV is not 0 0 ${AGENT_HTTP_PORT} agent1.${SRP_ZONE}"; return 1; }
    [ "$(dig_srp "Web._http._tcp.${SRP_ZONE}" TXT)" = '"path=/"' ] || { log_error "Web's TXT is not path=/"; return 1; }
    [ "$(dig_srp "Printer._ipp._tcp.${SRP_ZONE}" SRV)" = "0 0 631 agent1.${SRP_ZONE}" ] \
        || { log_error "Printer's SRV is not the ipp preset's port 631"; return 1; }
    [ "$(dig_srp "Printer._ipp._tcp.${SRP_ZONE}" TXT)" = '"rp=ipp/print" "txtvers=1"' ] \
        || { log_error "Printer's TXT is not the ipp preset's"; return 1; }
    agent_log_has 'agent1: "Web" _http._tcp: probe http /health passes' || { log_error "the agent did not log Web's probe passing"; return 1; }

    log_success "agent1 is at BIND with its address, KEY, Web (probed over HTTP) and Printer (the ipp preset)"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_probe_withdraws_and_restores() {
    local log_msg="AGENT-TEST 3: a service that stops answering is withdrawn, and registered again when it answers"
    log_section "$log_msg"

    stop_http
    wait_state "Web._http._tcp.${SRP_ZONE}" SRV absent || return 1
    [ -n "$(dig_srp "Printer._ipp._tcp.${SRP_ZONE}" SRV)" ] || { log_error "Printer went with Web"; return 1; }
    agent_log_has 'agent1: "Web" _http._tcp: probe failed 3 times in a row, withdrawing it' \
        || { log_error "the agent did not log the withdrawal"; return 1; }

    start_http
    wait_state "Web._http._tcp.${SRP_ZONE}" SRV present || return 1

    log_success "Web left the zone when http.server stopped, and came back when it started; Printer stayed"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_template_changes() {
    local log_msg="AGENT-TEST 4: a template edit is applied; an invalid one is logged and ignored"
    log_section "$log_msg"

    write_template <<EOF
hosts:
  - name: agent1
    addresses: [127.0.0.1]
    services:
      - {type: http, instance: Web, port: ${AGENT_HTTP_PORT}, txt: {path: /}, probe: {http: /health}}
      - {type: ssh, instance: Shell, port: 2222, probe: none}
EOF
    wait_state "Shell._ssh._tcp.${SRP_ZONE}" SRV present || return 1
    wait_state "Printer._ipp._tcp.${SRP_ZONE}" SRV absent || return 1
    [ "$(dig_srp "Shell._ssh._tcp.${SRP_ZONE}" SRV)" = "0 0 2222 agent1.${SRP_ZONE}" ] \
        || { log_error "Shell's SRV does not have the overridden port 2222"; return 1; }
    agent_log_has "template: agent1.${SRP_ZONE} changed" || { log_error "the agent did not log the change"; return 1; }

    write_template <<EOF
hosts:
  - name: agent1
    addresses: [127.0.0.1]
    services:
      - {type: telnet}
EOF
    wait_log "keeping the template as it was" || return 1
    sleep 3 # several polls
    [ "$(grep -cF "keeping the template as it was" "$AGENT_LOG")" = 1 ] || { log_error "the invalid template was logged more than once"; return 1; }
    [ -n "$(dig_srp "Shell._ssh._tcp.${SRP_ZONE}" SRV)" ] && [ -n "$(dig_srp "Web._http._tcp.${SRP_ZONE}" SRV)" ] \
        || { log_error "the invalid template changed what is registered"; return 1; }

    log_success "Shell was added and Printer withdrawn; the invalid template was logged once and changed nothing"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_rename_starts_over() {
    local log_msg="AGENT-TEST 5: a name another key holds is renamed; a restart frees the rename's names and asks for the name again: renamed again while the other key holds it, its own once that key frees it"
    log_section "$log_msg"

    claim_as_holder taken || { log_error "the other key could not register taken.${SRP_ZONE}"; return 1; }

    write_template <<EOF
hosts:
  - name: agent1
    addresses: [127.0.0.1]
    services:
      - {type: http, instance: Web, port: ${AGENT_HTTP_PORT}, txt: {path: /}, probe: {http: /health}}
      - {type: ssh, instance: Shell, port: 2222, probe: none}
  - name: taken
    addresses: [192.0.2.77]
EOF
    wait_state "taken-2.${SRP_ZONE}" A present || return 1
    [ "$(dig_srp "taken-2.${SRP_ZONE}" A)" = "192.0.2.77" ] || { log_error "taken-2 does not have the template's address"; return 1; }
    [ "$(dig_srp "taken.${SRP_ZONE}" A)" = "192.0.2.70" ] || { log_error "the other key's taken.${SRP_ZONE} changed"; return 1; }
    agent_log_has "taken: renamed: now host taken-2" || { log_error "the agent did not log the rename"; return 1; }
    grep -qF '"host": "taken-2"' "$AGENT_DIR/keys/sig0lease-agent-state.json" || { log_error "the state file does not record taken held as taken-2"; return 1; }

    stop_agent || { log_error "the agent exited non-zero"; cat "$AGENT_LOG"; return 1; }
    wait_state "taken-2.${SRP_ZONE}" A absent || return 1
    [ -n "$(dig_srp "taken-2.${SRP_ZONE}" KEY)" ] || { log_error "taken-2's KEY went on stopping: on_stop: keep did not keep it"; return 1; }
    local out renames registered
    out="$("$AGENT_BIN" plan "$AGENT_TEMPLATE")"
    grep -qF "renamed:   an earlier run's rename holds host taken-2.${SRP_ZONE}; run frees its names and asks for these again" <<< "$out" \
        || { log_error "plan does not say taken-2 will be freed:"; echo "$out"; return 1; }
    renames="$(grep -cF "taken: renamed: now host taken-2" "$AGENT_LOG")"
    start_agent
    wait_log "taken: renamed: now host taken-2" $(( renames + 1 )) || return 1
    agent_log_has "taken: freeing host taken-2, held from an earlier run, to ask for the requested names again" \
        || { log_error "the restarted agent did not log freeing taken-2"; return 1; }
    wait_state "taken-2.${SRP_ZONE}" A present || return 1

    stop_agent || { log_error "the agent exited non-zero"; cat "$AGENT_LOG"; return 1; }
    wait_state "taken-2.${SRP_ZONE}" A absent || return 1
    release_as_holder taken || { log_error "the other key could not free taken.${SRP_ZONE}"; return 1; }
    wait_state "taken.${SRP_ZONE}" KEY absent || return 1
    registered="$(grep -cF "taken: registered" "$AGENT_LOG")"
    start_agent
    wait_log "taken: registered" $(( registered + 1 )) || return 1
    [ "$(dig_srp "taken.${SRP_ZONE}" A)" = "192.0.2.77" ] || { log_error "taken.${SRP_ZONE} does not have the template's address"; return 1; }
    wait_state "taken-2.${SRP_ZONE}" KEY absent || return 1
    if grep -qF '"host": "taken-2"' "$AGENT_DIR/keys/sig0lease-agent-state.json"; then
        log_error "the state file still records taken-2"; return 1
    fi

    log_success "taken became taken-2 beside the other key's taken; a restart freed taken-2 and was renamed taken-2 again; once the other key freed taken, the next restart freed taken-2 and got taken"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_stop_keeps_names() {
    local log_msg="AGENT-TEST 6: the agent stops (SIGTERM) -> it deregisters everything, keeps the names for its keys (on_stop: keep), and exits 0"
    log_section "$log_msg"

    wait_state "Shell._ssh._tcp.${SRP_ZONE}" SRV present || return 1
    stop_agent || { log_error "the agent exited non-zero; log:"; cat "$AGENT_LOG"; return 1; }
    for name in "Web._http._tcp" "Shell._ssh._tcp"; do
        wait_state "${name}.${SRP_ZONE}" SRV absent || return 1
    done
    for host in agent1 taken; do
        wait_state "${host}.${SRP_ZONE}" A absent || return 1
    done
    for name in agent1 taken "Web._http._tcp" "Shell._ssh._tcp"; do
        [ -n "$(dig_srp "${name}.${SRP_ZONE}" KEY)" ] || { log_error "${name}.${SRP_ZONE}'s KEY went: its name was not kept"; return 1; }
    done
    agent_log_has "agent1: deregistered \"Web\" _http._tcp, \"Shell\" _ssh._tcp; names kept for its key" \
        || { log_error "the agent did not log agent1 deregistering and keeping its names:"; cat "$AGENT_LOG"; return 1; }
    local out
    if out="$(claim_as_holder agent1)"; then
        echo "$out"; log_error "the other key took agent1.${SRP_ZONE}, which the agent's key holds"; return 1
    fi
    echo "$out"
    grep -q "Status: YXDOMAIN" <<< "$out" || { log_error "the other key's claim of agent1 was not refused with YXDOMAIN"; return 1; }

    log_success "stopping the agent removed agent1, taken and their services, kept their KEYs, so the other key could not take agent1"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_names_freed() {
    local log_msg="AGENT-TEST 7: restarted, the agent gets its names back; a host removed from the template frees its names, and with on_stop: release so does stopping"
    log_section "$log_msg"

    local renames registered
    renames="$(grep -cF "renamed: now" "$AGENT_LOG")"
    start_agent
    wait_state "agent1.${SRP_ZONE}" A present || return 1
    wait_state "taken.${SRP_ZONE}" A present || return 1
    [ "$(grep -cF "renamed: now" "$AGENT_LOG")" = "$renames" ] || { log_error "the restarted agent renamed a host"; return 1; }

    registered="$(grep -cF "agent1: registered" "$AGENT_LOG")"
    write_template "on_stop: release" <<EOF
hosts:
  - name: agent1
    addresses: [127.0.0.1]
    services:
      - {type: http, instance: Web, port: ${AGENT_HTTP_PORT}, txt: {path: /}, probe: {http: /health}}
      - {type: ssh, instance: Shell, port: 2222, probe: none}
EOF
    wait_state "taken.${SRP_ZONE}" KEY absent || return 1
    agent_log_has "template: taken.${SRP_ZONE} removed; freeing its names" || { log_error "the agent did not log taken's removal"; return 1; }
    agent_log_has "template: the srp registrar for ${SRP_ZONE} changed" || { log_error "the agent did not log the registrar's change"; return 1; }
    wait_log "agent1: registered" $(( registered + 1 )) || return 1

    stop_agent || { log_error "the agent exited non-zero; log:"; cat "$AGENT_LOG"; return 1; }
    for name in agent1 "Web._http._tcp" "Shell._ssh._tcp"; do
        wait_state "${name}.${SRP_ZONE}" KEY absent || return 1
    done
    claim_as_holder agent1 || { log_error "the other key could not take agent1.${SRP_ZONE}, which the agent released"; return 1; }

    log_success "agent1 and taken came back unrenamed; removing taken freed it, and stopping with on_stop: release freed agent1 for the other key"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_freed_after_restart() {
    local log_msg="AGENT-TEST 8: a host removed from the template while the agent was stopped has its names, its instances' too, freed at the next start"
    log_section "$log_msg"

    write_template <<EOF
hosts:
  - name: stay
    addresses: [127.0.0.1]
  - name: gone
    addresses: [192.0.2.80]
    services:
      - {type: ssh, instance: Old, port: 2222, probe: none}
EOF
    start_agent
    wait_state "Old._ssh._tcp.${SRP_ZONE}" SRV present || return 1
    wait_state "stay.${SRP_ZONE}" A present || return 1
    stop_agent || { log_error "the agent exited non-zero; log:"; cat "$AGENT_LOG"; return 1; }
    wait_state "gone.${SRP_ZONE}" A absent || return 1
    for name in gone "Old._ssh._tcp"; do
        [ -n "$(dig_srp "${name}.${SRP_ZONE}" KEY)" ] || { log_error "${name}.${SRP_ZONE}'s KEY went on stopping: its name was not kept"; return 1; }
    done

    write_template <<EOF
hosts:
  - name: stay
    addresses: [127.0.0.1]
EOF
    local out
    out="$("$AGENT_BIN" plan "$AGENT_TEMPLATE")"
    grep -qF "host gone.${SRP_ZONE}: holds names from an earlier run that the template no longer registers; run frees them" <<< "$out" \
        || { log_error "plan does not say gone's names will be freed:"; echo "$out"; return 1; }
    start_agent
    for name in gone "Old._ssh._tcp"; do
        wait_state "${name}.${SRP_ZONE}" KEY absent || return 1
    done
    wait_state "stay.${SRP_ZONE}" A present || return 1
    agent_log_has "state: gone.${SRP_ZONE} holds names the template no longer registers; freeing them" \
        || { log_error "the agent did not log freeing gone's names"; return 1; }
    if grep -qF "\"gone.${SRP_ZONE}\"" "$AGENT_DIR/keys/sig0lease-agent-state.json"; then
        log_error "the state file still has gone"; return 1
    fi

    log_success "gone's KEY and its instance Old's went at the restart, which registered stay; the state file forgot gone"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_rfc9664_names() {
    local log_msg="AGENT-TEST 9: an RFC 9664 name is registered with its records; one another key holds is tried again, not renamed; stopping keeps the name, removing it frees it"
    log_section "$log_msg"

    claim_name_as_holder held || { log_error "the other key could not register held.${NAME_ZONE}"; return 1; }
    local stay
    stay="$(cat <<EOF
hosts:
  - name: stay
    addresses: [127.0.0.1]
EOF
)"
    NAMES_REGISTRAR="$(names_registrar "$(cat <<EOF
names:
  - name: site.${NAME_ZONE}
    addresses: [127.0.0.1]
    records:
      - '_dnslink TXT "dnslink=/ipfs/bafy"'
      - "www CNAME site.${NAME_ZONE}"
  - name: held.${NAME_ZONE}
    records: ['@ TXT "agent"']
EOF
)")"
    write_template <<< "$stay"
    wait_state "_dnslink.site.${NAME_ZONE}" TXT present || return 1
    [ "$(dig_srp "site.${NAME_ZONE}" A)" = "127.0.0.1" ] || { log_error "A site.${NAME_ZONE} is not 127.0.0.1"; return 1; }
    [ "$(dig_srp "www.site.${NAME_ZONE}" CNAME)" = "site.${NAME_ZONE}" ] || { log_error "www.site.${NAME_ZONE} is not a CNAME to site"; return 1; }
    [ -n "$(dig_srp "site.${NAME_ZONE}" KEY)" ] || { log_error "no KEY at site.${NAME_ZONE}"; return 1; }
    wait_log "held.${NAME_ZONE} is held by another key (YXDOMAIN)" || return 1
    [ "$(dig_srp "held.${NAME_ZONE}" TXT)" = '"holder"' ] || { log_error "the other key's held.${NAME_ZONE} changed"; return 1; }
    if agent_log_has "held-2"; then
        log_error "the agent renamed held"; return 1
    fi

    NAMES_REGISTRAR="$(names_registrar "$(cat <<EOF
names:
  - name: site.${NAME_ZONE}
    addresses: [127.0.0.1]
    records: ["www CNAME site.${NAME_ZONE}"]
EOF
)")"
    write_template <<< "$stay"
    wait_state "_dnslink.site.${NAME_ZONE}" TXT absent || return 1
    [ "$(dig_srp "site.${NAME_ZONE}" A)" = "127.0.0.1" ] || { log_error "site's address went with _dnslink"; return 1; }
    agent_log_has "site.${NAME_ZONE}: withdrew _dnslink.site.${NAME_ZONE} TXT" || { log_error "the agent did not log the withdrawal"; return 1; }

    stop_agent || { log_error "the agent exited non-zero; log:"; cat "$AGENT_LOG"; return 1; }
    wait_state "site.${NAME_ZONE}" A absent || return 1
    wait_state "www.site.${NAME_ZONE}" CNAME absent || return 1
    [ -n "$(dig_srp "site.${NAME_ZONE}" KEY)" ] || { log_error "site.${NAME_ZONE}'s KEY went on stopping: the name was not kept"; return 1; }

    NAMES_REGISTRAR=""
    write_template <<< "$stay"
    start_agent
    wait_state "site.${NAME_ZONE}" KEY absent || return 1
    agent_log_has "state: site.${NAME_ZONE} holds names the template no longer registers; freeing them" \
        || { log_error "the agent did not log freeing site"; return 1; }
    [ "$(dig_srp "held.${NAME_ZONE}" TXT)" = '"holder"' ] || { log_error "the other key's held.${NAME_ZONE} went"; return 1; }

    log_success "site came with its address, KEY, _dnslink TXT and www CNAME; held stayed the other key's, retried and not renamed; stopping kept site's KEY, and removing site freed it"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_xmpp_federation() {
    local log_msg="AGENT-TEST 10: two XMPP servers (Prosody) federate through the SRV records the agent publishes for their names, with a TLSA record each; a server that stops has them withdrawn, and they come back when it starts"
    log_section "$log_msg"
    if ! command -v prosody >/dev/null || ! command -v prosodyctl >/dev/null; then
        log_step "Prosody is not installed: AGENT-TEST 10 skipped"
        PERFORMED_TESTS="$PERFORMED_TESTS\n  [SKIPPED: no prosody] $log_msg"
        return 0
    fi
    require_command openssl || return 1

    start_prosody a "$XMPP_A_PORT" || return 1
    start_prosody b "$XMPP_B_PORT" || return 1
    local z="${NAME_ZONE}" stay
    stay="$(cat <<HOSTS
hosts:
  - name: stay
    addresses: [127.0.0.1]
HOSTS
)"
    NAMES_REGISTRAR="$(names_registrar "$(cat <<NAMES
names:
  - name: a.${z}
    addresses: [127.0.0.1]
    services:
      - {type: xmpp-server, port: ${XMPP_A_PORT}, subdomains: [rooms], tlsa: ${XMPP_DIR}/a/cert.pem}
  - name: b.${z}
    addresses: [127.0.0.1]
    services:
      - {type: xmpp-server, port: ${XMPP_B_PORT}, tlsa: ${XMPP_DIR}/b/cert.pem}
NAMES
)")"
    write_template <<< "$stay"
    wait_state "_xmpp-server._tcp.a.${z}" SRV present || return 1
    wait_state "_xmpp-server._tcp.b.${z}" SRV present || return 1
    local want got
    for want in "_xmpp-server._tcp.a.${z}|0 0 ${XMPP_A_PORT} a.${z}" "_xmpp-server._tcp.rooms.a.${z}|0 0 ${XMPP_A_PORT} a.${z}" \
        "_xmpp-server._tcp.b.${z}|0 0 ${XMPP_B_PORT} b.${z}"; do
        got="$(dig_srp "${want%%|*}" SRV)"
        [ "$got" = "${want#*|}" ] || { log_error "SRV ${want%%|*} is \"$got\", want \"${want#*|}\""; return 1; }
    done
    for want in "a|${XMPP_A_PORT}" "b|${XMPP_B_PORT}"; do
        got="$(dig_tlsa "_${want#*|}._tcp.${want%%|*}.${z}")"
        [ "$got" = "3 1 1 $(spki_sha256 "$XMPP_DIR/${want%%|*}/cert.pem")" ] \
            || { log_error "TLSA _${want#*|}._tcp.${want%%|*}.${z} is \"$got\", want 3 1 1 and ${want%%|*}'s certificate's key"; return 1; }
    done

    xmpp_ping a "b.${z%.}" || { log_error "a could not reach b"; return 1; }
    xmpp_ping b "rooms.a.${z%.}" || { log_error "b could not reach rooms.a"; return 1; }

    stop_prosody b
    wait_state "_xmpp-server._tcp.b.${z}" SRV absent || return 1
    wait_state "_${XMPP_B_PORT}._tcp.b.${z}" TLSA absent || return 1
    [ "$(dig_srp "b.${z}" A)" = "127.0.0.1" ] || { log_error "b's address went with its service"; return 1; }
    wait_log "b.${z}: _xmpp-server._tcp: probe failed 3 times in a row, withdrawing it" || return 1
    [ -n "$(dig_srp "_xmpp-server._tcp.a.${z}" SRV)" ] || { log_error "a's SRV went with b's"; return 1; }

    start_prosody b "$XMPP_B_PORT" || return 1
    wait_state "_xmpp-server._tcp.b.${z}" SRV present || return 1
    wait_state "_${XMPP_B_PORT}._tcp.b.${z}" TLSA present || return 1
    xmpp_ping b "a.${z%.}" || { log_error "b, started again, could not reach a"; return 1; }

    NAMES_REGISTRAR=""
    write_template <<< "$stay"
    wait_state "a.${z}" KEY absent || return 1
    wait_state "b.${z}" KEY absent || return 1
    [ -z "$(dig_srp "_xmpp-server._tcp.a.${z}" SRV)" ] || { log_error "a's SRV stayed after a was removed"; return 1; }

    log_success "a and b federated on ports only their SRV records gave (a to b, b to rooms.a), with TLSA records for their certificates; b stopped lost its SRV and TLSA records, kept its address, and got them back started again"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_ipfs() {
    local log_msg="AGENT-TEST 11: a name publishes a kubo node's folder and addresses; another follows it, its node pinning each version before the name gives it; a node that stops has its addresses withdrawn, and its folder kept"
    log_section "$log_msg"
    if ! command -v ipfs >/dev/null; then
        log_step "kubo (ipfs) is not installed: AGENT-TEST 11 skipped"
        PERFORMED_TESTS="$PERFORMED_TESTS\n  [SKIPPED: no ipfs] $log_msg"
        return 0
    fi
    require_command openssl || return 1

    start_kubo a "$IPFS_A_API_PORT" "$IPFS_A_SWARM_PORT" || return 1
    start_kubo b "$IPFS_B_API_PORT" "$IPFS_B_SWARM_PORT" || return 1
    echo "first" | ipfs_on a files write --create --parents /community/hello.txt
    local first
    first="$(ipfs_on a files stat --hash /community)"
    local z="${NAME_ZONE}" stay
    stay="$(cat <<HOSTS
hosts:
  - name: stay
    addresses: [127.0.0.1]
HOSTS
)"
    NAMES_REGISTRAR="$(names_registrar "$(cat <<NAMES
names:
  - name: a.${z}
    ipfs: {api: "http://127.0.0.1:${IPFS_A_API_PORT}", publish: {mfs: /community}}
  - name: site.${z}
    ipfs: {api: "http://127.0.0.1:${IPFS_B_API_PORT}", follow: a.${z}}
NAMES
)")"
    write_template <<< "$stay"
    wait_txt "_dnslink.a.${z}" "\"dnslink=/ipfs/${first}\"" || return 1
    wait_state "_dnsaddr.a.${z}" TXT present || return 1

    # b reaches a at an address a's _dnsaddr records give, as /dnsaddr/a.<zone> would have it
    # do; kubo reads those through the system's resolver, which does not know the local BIND.
    local ma connected=""
    for ma in $(dig_srp "_dnsaddr.a.${z}" TXT | tr -d '"' | sed 's/^dnsaddr=//'); do
        if ipfs_on b swarm connect "$ma" > /dev/null 2>&1; then connected="$ma"; break; fi
    done
    [ -n "$connected" ] || { log_error "b reached a at none of _dnsaddr.a's addresses: $(dig_srp "_dnsaddr.a.${z}" TXT)"; return 1; }

    wait_txt "_dnslink.site.${z}" "\"dnslink=/ipfs/${first}\"" || return 1
    [ "$(ipfs_on b --offline cat "/ipfs/${first}/hello.txt")" = first ] || { log_error "b does not hold a's folder"; return 1; }
    [ "$(ipfs_on b pin ls --type=recursive --names "/ipfs/${first}")" = "${first} recursive sig0lease-agent site.${z}" ] \
        || { log_error "b's pin of a's folder: $(ipfs_on b pin ls --type=recursive --names)"; return 1; }

    echo "second" | ipfs_on a files write --create /community/second.txt
    local second
    second="$(ipfs_on a files stat --hash /community)"
    wait_txt "_dnslink.a.${z}" "\"dnslink=/ipfs/${second}\"" || return 1
    wait_txt "_dnslink.site.${z}" "\"dnslink=/ipfs/${second}\"" || return 1
    [ "$(ipfs_on b --offline cat "/ipfs/${second}/second.txt")" = second ] || { log_error "b does not hold a's new folder"; return 1; }
    wait_log "site.${z}: unpinned ${first}, a site before" || return 1
    if ipfs_on b pin ls --type=recursive "/ipfs/${first}" > /dev/null 2>&1; then
        log_error "b still pins the first folder"; return 1
    fi

    stop_kubo a
    wait_state "_dnsaddr.a.${z}" TXT absent || return 1
    wait_log "a.${z}: its node does not answer" || return 1
    [ "$(dig_srp "_dnslink.a.${z}" TXT)" = "\"dnslink=/ipfs/${second}\"" ] || { log_error "a's _dnslink went with its node"; return 1; }
    [ "$(dig_srp "_dnslink.site.${z}" TXT)" = "\"dnslink=/ipfs/${second}\"" ] || { log_error "site's _dnslink changed when a's node stopped"; return 1; }

    NAMES_REGISTRAR=""
    write_template <<< "$stay"
    wait_state "a.${z}" KEY absent || return 1
    wait_state "site.${z}" KEY absent || return 1
    [ -z "$(dig_srp "_dnslink.site.${z}" TXT)" ] || { log_error "site's _dnslink stayed after site was removed"; return 1; }
    stop_kubo b

    log_success "a gave its folder and addresses; b, reaching a at one of them, pinned each version before site gave it, and unpinned the one before; a's node stopped lost its addresses and kept its folder"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

################################
# Top level
################################
run_all_tests() {
    log_section "SIG0LEASE-AGENT INTEGRATION TEST SUITE"
    echo "Real components only: real agent (sig0lease-agent), real proxy process (srp_handler and"
    echo "update_handler), real local BIND 9 authoritative for ${SRP_ZONE} and ${NAME_ZONE}, python3's"
    echo "http.server as the probed service, Prosody, if installed, as two XMPP servers, and kubo, if"
    echo "installed, as two IPFS nodes."
    echo ""

    trap cleanup EXIT

    require_command dig
    require_command named
    require_command go
    require_command python3

    srp_run_prepare
    mkdir -p "$AGENT_DIR" "$AGENT_HTTP_DIR" "$HOLDER_KEY_DIR"
    echo ok > "$AGENT_HTTP_DIR/health"

    build_agent_binaries
    start_bind9
    start_srp_proxy

    test_validate_and_plan
    test_run_registers
    test_probe_withdraws_and_restores
    test_template_changes
    test_rename_starts_over
    test_stop_keeps_names
    test_names_freed
    test_freed_after_restart
    test_rfc9664_names
    test_xmpp_federation
    test_ipfs

    bind9_report_rejections || return 1
    BIND9_REJECTIONS_REPORTED=1

    log_section "TEST RESULTS"
    echo -e "${GREEN}All sig0lease-agent integration tests completed successfully!${NC}"
    echo -e "$PERFORMED_TESTS"
    echo ""
    if [ "$PROXY_LAUNCH" = auto ]; then
        echo "SRP proxy log: $SRP_PROXY_LOG"
    fi
    echo "SRP proxy config: $SRP_TMP_CONFIG"
    echo "Agent log: $AGENT_LOG"
    echo "Agent template and keystore: $AGENT_DIR"
    echo "BIND log: ${BIND9_RUNDIR}/named.log"
}

cleanup() {
    set +e
    log_section "CLEANUP"
    [ -z "${BIND9_REJECTIONS_REPORTED:-}" ] && bind9_report_rejections
    stop_agent
    stop_http
    stop_prosody a
    stop_prosody b
    stop_kubo a
    stop_kubo b
    stop_srp_proxy
    stop_bind9
    set -e
}

case "${1:-run}" in
    run)
        run_all_tests
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo "Usage: $0 [run|cleanup]"
        exit 1
        ;;
esac
