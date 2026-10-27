#!/bin/bash
# demo/run.sh -- D1 of docs/demo.md in one terminal. It starts the proxy, the site and the agent
# (demo/demo.yaml), runs D1's steps, each after Enter, and after each one waits until the zone's
# authoritative server answers with the change, printing how long that took. The last Enter, or
# Ctrl-C, stops the agents first, so they deregister what they published, then the site and the
# proxy. The logs, and the agent's copy of the template that step 3 edits, go to a temporary
# directory, printed at the start. Run it after make build build-client.
#
# NS, DOMAIN, ZONE and NAME change what it asks, as for watch.sh.

cd "$(dirname "$0")/.." || exit 1
B="./bin/$(uname -s | tr A-Z a-z)"
ns="${NS:-ns1.free2air.org}"
domain="${DOMAIN:-srp.dev.zenr.io}"
zone="${ZONE:-dev.zenr.io}"
name="${NAME:-demo}"
instance="$name\\032http"         # "demo http", as browsing lists it
renamed="$name\\032http-2"        # the second key's

for bin in sig0lease sig0lease-agent; do
    if [ ! -x "$B/$bin" ]; then
        echo "no $B/$bin: run make build build-client first" >&2
        exit 1
    fi
done

# Each program runs in its own process group (set -m), so Ctrl-C reaches only this script, which
# then stops them in order: the proxy has to outlive the agents' deregistrations.
set -m
log="$(mktemp -d "${TMPDIR:-/tmp}/sig0lease-demo.XXXXXX")" || exit 1
proxy= site= agent= other=

# start <var> <log> <command...> -- runs the command in the background, its pid in <var>.
start() {
    local var="$1" out="$log/$2" pid
    shift 2
    "$@" < /dev/null >> "$out" 2>&1 &
    pid=$!
    sleep 1
    if ! kill -0 "$pid" 2> /dev/null; then
        echo "$1 stopped at once; $out:"
        tail -n 5 "$out"
        exit 1
    fi
    printf -v "$var" %s "$pid"
}

# stop <var> -- sends SIGTERM to the program whose pid is in <var>, and waits for it to exit.
stop() {
    local pid="${!1}"
    [ -n "$pid" ] || return 0
    kill "$pid" 2> /dev/null
    wait "$pid" 2> /dev/null
    printf -v "$1" %s ""
}

finish() {
    trap '' INT
    echo
    echo "Stopping."
    stop other
    stop agent
    stop site
    stop proxy
    echo "Logs: $log"
}
trap finish EXIT
trap 'exit 130' INT TERM

# step <text> -- prints the step and waits for Enter.
step() {
    printf '\n%s\n[Enter] ' "$1"
    read -r _ || echo
}

ask() { dig +short +time=2 +tries=1 "@$ns" "$@"; }
answers() { [ -n "$(ask "$@")" ]; }
listed() { ask PTR "_http._tcp.$domain" | grep -qF "$1._http._tcp.$domain."; }
not() { ! "$@"; }

# wait_until <what> <command...> -- runs the command every second until it succeeds, and prints
# how long that took; after 90 s it gives up, showing the agents' last log lines.
wait_until() {
    local what="$1" t0
    shift
    t0=$(date +%s)
    printf '  waiting until %s ... ' "$what"
    until "$@"; do
        if [ $(( $(date +%s) - t0 )) -ge 90 ]; then
            echo "not after 90 s; the agents' last log lines:"
            tail -n 5 "$log"/*agent.log
            exit 1
        fi
        sleep 1
    done
    echo "$(( $(date +%s) - t0 )) s"
}

sed "s|^keystore: keys |keystore: $PWD/demo/keys |" demo/demo.yaml > "$log/demo.yaml"
if ! grep -qF "keystore: $PWD/demo/keys " "$log/demo.yaml"; then
    echo "demo/demo.yaml has no 'keystore: keys' line to point at $PWD/demo/keys" >&2
    exit 1
fi

cat << EOF
This machine publishes itself on the live $zone zone, through its own proxy.
Logs: $log
Answers are asked of $ns, the zone's authoritative server.

What anyone can run meanwhile:
  dig +short TXT $name.$zone
  dig +short $name.$zone
  dns-sd -B _http._tcp $domain                (a Mac)
  avahi-browse -d $domain. -r _http._tcp      (Linux)
and, on this network, open http://$name.$domain:8000/
EOF

step "1. Start the proxy, the site and the agent."
start proxy proxy.log "$B/sig0lease"
start site site.log python3 -m http.server 8000 -d demo/site
start agent agent.log "$B/sig0lease-agent" run -probe-interval 5s "$log/demo.yaml"
wait_until "\"$name http\" is listed" listed "$instance"
wait_until "$name.$zone has its records" answers TXT "$name.$zone"
echo
demo/watch.sh once

step "2. Stop the site: after three failed probes the agent withdraws \"$name http\"."
stop site
wait_until "\"$name http\" is gone" not listed "$instance"
step "   Start the site again: once a probe passes, \"$name http\" is back."
start site site.log python3 -m http.server 8000 -d demo/site
wait_until "\"$name http\" is listed" listed "$instance"

step "3. Add a record to the template, hello.$name TXT: the agent reads it every 10 s."
sed "s|# - 'hello TXT|- 'hello TXT|" "$log/demo.yaml" > "$log/demo.yaml.new"
if cmp -s "$log/demo.yaml" "$log/demo.yaml.new"; then
    echo "demo/demo.yaml has no commented hello record to add" >&2
    exit 1
fi
mv "$log/demo.yaml.new" "$log/demo.yaml"
wait_until "hello.$name.$zone has its TXT" answers TXT "hello.$name.$zone"
echo "  dig +short TXT hello.$name.$zone: $(ask TXT "hello.$name.$zone")"

step "4. A second key wants the same names (demo/conflict.yaml)."
start other other-agent.log "$B/sig0lease-agent" run -probe-interval 5s demo/conflict.yaml
wait_until "its host is renamed: \"$name http-2\" is listed" listed "$renamed"
wait_until "it is refused $name.$zone" grep -q "held by another key" "$log/other-agent.log"
echo
demo/watch.sh once
step "   Stop the second agent: it frees what it got (on_stop: release), and leaves $name alone."
stop other
wait_until "\"$name http-2\" is gone" not listed "$renamed"
echo "  dig +short TXT $name.$zone: $(ask TXT "$name.$zone")"

step "5. Stop the agent: it deregisters what it published; demo/keys keep the names."
stop agent
wait_until "\"$name http\" is gone" not listed "$instance"
