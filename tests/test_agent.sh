#!/bin/bash
#
# sig0lease-agent end-to-end test.
#
# Runs the real agent (cmd/sig0lease-agent) on a template, against the real proxy (srp_handler,
# and the RFC 9664 handler for the names) and a real, disposable local BIND 9 authoritative for
# srp.test. and update.test. (lib/srp.sh, as test_srp.sh): validate and plan -> run registers
# the template's hosts and services -> a
# probed service that stops answering is withdrawn, and registered again when it answers ->
# template edits are applied, an invalid one is ignored -> a name another key holds is renamed,
# and the rename kept across a restart -> stopping deregisters everything, keeping the names for
# the agent's keys (on_stop: keep) -> a host removed from the template frees its names, and with
# on_stop: release so does stopping -> a host removed while the agent was stopped has its names
# freed at the next start -> an RFC 9664 name is registered with its records, one another key
# holds is tried again rather than renamed, stopping keeps the name and removing it frees it.
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

# names_registrar <names: lines> -- the rfc9664 registrar for NAME_ZONE through the proxy,
# with the names given (written as at the top level), for NAMES_REGISTRAR.
names_registrar() {
    cat <<EOF
  - protocol: rfc9664
    zone: ${NAME_ZONE}
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

# claim_name_as_holder <label> -- the other key registers <label>.NAME_ZONE with a TXT record
# "holder" through the RFC 9664 handler (sig0lease-client), with a key it generates; exits
# non-zero unless the proxy answers NOERROR.
claim_name_as_holder() {
    local name="$1.${NAME_ZONE}" key
    key="$(dnssec-keygen -q -K "$HOLDER_KEY_DIR" -a ECDSAP256SHA256 -n HOST -T KEY "$name")" || return 1
    "$CLIENT_BIN" "$SRP_PROXY_URL" register "$key" 3600 1209600 --same-key \
        "$name 300 IN TXT \"holder\"" --tcp --keystore="$HOLDER_KEY_DIR"
}

# wait_state <name> <type> <present|absent> -- wait_for_srp_state with CHANGE_TIMEOUT, showing
# the agent's log when it times out.
wait_state() {
    wait_for_srp_state "$1" "$2" "$3" "$CHANGE_TIMEOUT" || { echo "agent log:"; cat "$AGENT_LOG"; return 1; }
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

test_rename_kept() {
    local log_msg="AGENT-TEST 5: a name another key holds is renamed, and the new name kept across a restart"
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
    grep -qF '"host": "taken-2"' "$AGENT_DIR/keys/sig0lease-agent-state.json" || { log_error "the state file does not keep taken-2"; return 1; }

    stop_agent || { log_error "the agent exited non-zero"; cat "$AGENT_LOG"; return 1; }
    wait_state "taken-2.${SRP_ZONE}" A absent || return 1
    local out renames
    renames="$(grep -cF "renamed: now" "$AGENT_LOG")"
    start_agent
    wait_state "taken-2.${SRP_ZONE}" A present || return 1
    [ "$(grep -cF "renamed: now" "$AGENT_LOG")" = "$renames" ] || { log_error "the restarted agent renamed again"; return 1; }
    agent_log_has "taken: registering the host alone at [192.0.2.77] (renamed: host taken-2)" \
        || { log_error "the restarted agent's log does not say taken registers as taken-2"; return 1; }
    out="$("$AGENT_BIN" plan "$AGENT_TEMPLATE")"
    grep -qF "host taken.${SRP_ZONE}, registered as taken-2.${SRP_ZONE}" <<< "$out" || { log_error "plan does not show the rename:"; echo "$out"; return 1; }

    log_success "taken became taken-2 beside the other key's taken, and stayed taken-2 after a restart"
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
    for host in agent1 taken-2; do
        wait_state "${host}.${SRP_ZONE}" A absent || return 1
    done
    for name in agent1 taken-2 "Web._http._tcp" "Shell._ssh._tcp"; do
        [ -n "$(dig_srp "${name}.${SRP_ZONE}" KEY)" ] || { log_error "${name}.${SRP_ZONE}'s KEY went: its name was not kept"; return 1; }
    done
    agent_log_has "agent1: deregistered \"Web\" _http._tcp, \"Shell\" _ssh._tcp; names kept for its key" \
        || { log_error "the agent did not log agent1 deregistering and keeping its names:"; cat "$AGENT_LOG"; return 1; }
    [ "$(dig_srp "taken.${SRP_ZONE}" A)" = "192.0.2.70" ] || { log_error "the other key's taken.${SRP_ZONE} went too"; return 1; }
    local out
    if out="$(claim_as_holder agent1)"; then
        echo "$out"; log_error "the other key took agent1.${SRP_ZONE}, which the agent's key holds"; return 1
    fi
    echo "$out"
    grep -q "Status: YXDOMAIN" <<< "$out" || { log_error "the other key's claim of agent1 was not refused with YXDOMAIN"; return 1; }

    log_success "stopping the agent removed agent1, taken-2 and their services, kept their KEYs, so the other key could not take agent1"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_names_freed() {
    local log_msg="AGENT-TEST 7: restarted, the agent gets its names back; a host removed from the template frees its names, and with on_stop: release so does stopping"
    log_section "$log_msg"

    local renames registered
    renames="$(grep -cF "renamed: now" "$AGENT_LOG")"
    start_agent
    wait_state "agent1.${SRP_ZONE}" A present || return 1
    wait_state "taken-2.${SRP_ZONE}" A present || return 1
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
    wait_state "taken-2.${SRP_ZONE}" KEY absent || return 1
    agent_log_has "template: taken.${SRP_ZONE} removed; freeing its names" || { log_error "the agent did not log taken's removal"; return 1; }
    agent_log_has "template: the srp registrar for ${SRP_ZONE} changed" || { log_error "the agent did not log the registrar's change"; return 1; }
    wait_log "agent1: registered" $(( registered + 1 )) || return 1

    stop_agent || { log_error "the agent exited non-zero; log:"; cat "$AGENT_LOG"; return 1; }
    for name in agent1 "Web._http._tcp" "Shell._ssh._tcp"; do
        wait_state "${name}.${SRP_ZONE}" KEY absent || return 1
    done
    claim_as_holder agent1 || { log_error "the other key could not take agent1.${SRP_ZONE}, which the agent released"; return 1; }

    log_success "agent1 and taken-2 came back unrenamed; removing taken freed taken-2, and stopping with on_stop: release freed agent1 for the other key"
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
  - name: site
    addresses: [127.0.0.1]
    records:
      - '_dnslink TXT "dnslink=/ipfs/bafy"'
      - "www CNAME site.${NAME_ZONE}"
  - name: held
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
  - name: site
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

################################
# Top level
################################
run_all_tests() {
    log_section "SIG0LEASE-AGENT INTEGRATION TEST SUITE"
    echo "Real components only: real agent (sig0lease-agent), real proxy process (srp_handler and"
    echo "update_handler), real local BIND 9 authoritative for ${SRP_ZONE} and ${NAME_ZONE}, python3's"
    echo "http.server as the probed service."
    echo ""

    trap cleanup EXIT

    require_command dig
    require_command named
    require_command go
    require_command python3
    require_command dnssec-keygen

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
    test_rename_kept
    test_stop_keeps_names
    test_names_freed
    test_freed_after_restart
    test_rfc9664_names

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
