#!/bin/bash
# demo/run.sh -- D1 of docs/demo.md in one terminal, and D2 on a Mac. It starts the proxy, the
# site and the agent (demo/demo.yaml), runs the steps, each after Enter, and after each one waits
# until the zone's authoritative server answers with the change, printing how long that took.
# The last Enter, or Ctrl-C, stops the agents first, so they deregister what they published, then
# the site and the proxy. The logs, and the agent's copy of the template that step 3 edits, go to
# a temporary directory, printed at the start. On a Mac it writes demo/mac.yaml, D2's template,
# when there is none. It builds the proxy and the clients first (make build build-client).
#
# NS, DOMAIN, ZONE and NAME change what it asks, as for watch.sh.

cd "$(dirname "$0")/.." || exit 1
. demo/lib.sh
B="./bin/$(uname -s | tr A-Z a-z)"
ns="${NS:-ns1.free2air.org}"
domain="${DOMAIN:-srp.dev.zenr.io}"
zone="${ZONE:-dev.zenr.io}"
name="${NAME:-demo}"
instance="$name\\032http"         # "demo http", as browsing lists it
renamed="$name\\032http-2"        # the second key's

echo "Building the proxy and the clients."
make -s build build-client || exit 1

# D2's template names this Mac, so it is not in the repository.
machost=
if [ "$(uname -s)" = Darwin ]; then
    machost="$(scutil --get LocalHostName)" || exit 1
    if [ ! -e demo/mac.yaml ]; then
        cat > demo/mac.yaml << EOF
# This Mac's template (docs/demo.md, D2), written by demo/run.sh: the mDNS mirror publishes the
# sharing services macOS advertises for $machost.local.
keystore: keys-mac
registrars:
  - protocol: srp
    domain: $domain.
    server: 127.0.0.1:8053
    lease: 10m
    on_stop: release
    mirrors:
      - type: mdns
        hosts: [$machost.local.]
        services: [_ssh._tcp, _smb._tcp, _rfb._tcp]
EOF
    fi
fi

# Each program runs in its own process group (set -m), so Ctrl-C reaches only this script, which
# then stops them in order: the proxy has to outlive the agents' deregistrations.
set -m
log="$(mktemp -d "${TMPDIR:-/tmp}/sig0lease-demo.XXXXXX")" || exit 1
proxy= site= agent= other= mirror=

finish() {
    trap '' INT
    echo
    echo "Stopping."
    stop other
    stop mirror
    stop agent
    stop site
    stop proxy
    echo "Logs: $log"
}
trap finish EXIT
trap 'exit 130' INT TERM

listed() { ask PTR "_http._tcp.$domain" | grep -qF "$1._http._tcp.$domain."; }

# mirrored <type> -- whether an instance of <type> on this Mac's host is listed.
mirrored() {
    local instance
    for instance in $(ask PTR "$1.$domain"); do
        ask SRV "$instance" | grep -qiF " $machost.$domain." && return 0
    done
    return 1
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

if [ -n "$machost" ]; then
    step "5. This Mac's own services: a second agent (demo/mac.yaml) publishes what macOS advertises on the local network for $machost.local: Remote Login, File Sharing, Screen Sharing."
    start mirror mac-agent.log "$B/sig0lease-agent" run demo/mac.yaml
    wait_until "its Screen Sharing is listed" mirrored _rfb._tcp
    echo
    demo/watch.sh once
    step "   Turn Screen Sharing off (System Settings > General > Sharing)."
    wait_until "it is gone" not mirrored _rfb._tcp
    step "   Turn it on again."
    wait_until "it is listed" mirrored _rfb._tcp
fi

step "Last, stop the agents: they deregister what they published and free their names (on_stop: release)."
stop mirror
stop agent
wait_until "\"$name http\" is gone" not listed "$instance"
