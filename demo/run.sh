#!/bin/bash
# demo/run.sh -- D1 of docs/demo.md in one terminal, and D2 on a Mac. It starts the proxy, the
# site and the agent (demo/demo.yaml), runs the steps, each after Enter, and after each one waits
# until the zone's authoritative server answers with the change, printing how long that took.
# The last Enter, or Ctrl-C, stops the agents first, so they deregister what they published, then
# the site and the proxy. Step 3 asks for the text of the record it adds, and adds the time to it.
# The logs, and the agent's copy of the template that step 3 edits, go to a temporary directory,
# printed at the start. On a Mac it writes demo/mac.yaml, D2's template,
# when there is none. It builds the proxy and the clients first (make build build-client).
#
# NS and NAME change what it asks, as for watch.sh. UPDATE_DOMAIN and SRP_DOMAIN are where the
# agents register (demo/lib.sh, template), and what the proxy serves (proxy_config). REGISTRAR
# sends the agents' updates to that registrar instead, and starts no proxy (demo/lib.sh).

cd "$(dirname "$0")/.." || exit 1
. demo/lib.sh
B="./bin/$(uname -s | tr A-Z a-z)"
name="${NAME:-demo}"
instance="$name\\032http"         # "demo http", as browsing lists it
renamed="$name\\032http-2"        # the second key's

check_proxy_ports
build

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
    domain: $srp_domain.
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

# mirrored <type> -- whether an instance of <type> on this Mac's host is listed.
mirrored() {
    local instance
    for instance in $(ask PTR "$1.$srp_domain"); do
        ask SRV "$instance" | grep -qiF " $machost.$srp_domain." && return 0
    done
    return 1
}

proxy_config
template demo/demo.yaml "$log/demo.yaml"
template demo/conflict.yaml "$log/conflict.yaml"
[ -z "$machost" ] || template demo/mac.yaml "$log/mac.yaml"

cat << EOF
This machine publishes itself in the live zone, in $update_domain and $srp_domain, $via.
Logs: $log
Answers are asked of $ns, the zone's authoritative server.

What anyone can run meanwhile:
  dig +short TXT $name.$update_domain
  dig +short $name.$update_domain
  dns-sd -B _http._tcp $srp_domain                (a Mac)
  avahi-browse -d $srp_domain. -r _http._tcp      (Linux)
and, on this network, open http://$name.$srp_domain:8000/
EOF

step "1. Start ${our_proxy}the site and the agent."
start_proxy
start_site
start agent agent.log "$B/sig0lease-agent" run -probe-interval 5s "$log/demo.yaml"
wait_until "\"$name http\" is listed" listed "$instance"
wait_until "$name.$update_domain has its records" answers TXT "$name.$update_domain"
echo
demo/watch.sh once

step "2. Stop the site: after three failed probes the agent withdraws \"$name http\"."
stop site
wait_until "\"$name http\" is gone" not listed "$instance"
step "   Start the site again: once a probe passes, \"$name http\" is back."
start_site
wait_until "\"$name http\" is listed" listed "$instance"

# Step 3's record: the template's commented-out hello record, its text the one typed (by
# default its own, taken as typed), with the time.
default="$(sed -n "s|^ *# - 'hello TXT \"\(.*\)\"'\$|\1|p" "$log/demo.yaml")"
if [ -z "$default" ]; then
    echo "demo/demo.yaml has no commented-out hello record to add" >&2
    exit 1
fi
printf '\n%s\n' "3. Add a record to the template, hello.$name TXT, with your text and the time: the agent reads it every 10 s."
while :; do
    printf '[Its text, or Enter for "%s"] ' "$default"
    IFS= read -r text || echo
    stamp="$(date '+%F %T %Z')"
    record="${text:-$default} ($stamp)"
    bytes="$(printf %s "$record" | wc -c)"
    [ "$bytes" -gt 255 ] || break
    echo "  With the time, that is $bytes bytes; a TXT string holds 255 at most."
done
# The template's line: the text in the record's presentation format, \ and " escaped, in YAML
# single quotes, ' doubled, in place of the commented-out record.
txt="${record//\\/\\\\}"
txt="${txt//\"/\\\"}"
spec="hello TXT \"$txt\""
line="- '${spec//\'/\'\'}'"
L="$line" awk '
    !done && /^ *# - '\''hello TXT / { sub(/# - .*/, ""); print $0 ENVIRON["L"]; done = 1; next }
    { print }' "$log/demo.yaml" > "$log/demo.yaml.new" && mv "$log/demo.yaml.new" "$log/demo.yaml" || exit 1
echo "  $line"
stamped() { ask TXT "hello.$name.$update_domain" | grep -qF "($stamp)"; }
wait_until "hello.$name.$update_domain has your text" stamped
echo "  dig +short TXT hello.$name.$update_domain: $(ask TXT "hello.$name.$update_domain")"

step "4. A second key wants the same names (demo/conflict.yaml)."
start other other-agent.log "$B/sig0lease-agent" run -probe-interval 5s "$log/conflict.yaml"
wait_until "its host is renamed: \"$name http-2\" is listed" listed "$renamed"
wait_until "it is refused $name.$update_domain" grep -q "held by another key" "$log/other-agent.log"
echo
demo/watch.sh once
step "   Stop the second agent: it frees what it got (on_stop: release), and leaves $name alone."
stop other
wait_until "\"$name http-2\" is gone" not listed "$renamed"
echo "  dig +short TXT $name.$update_domain: $(ask TXT "$name.$update_domain")"

if [ -n "$machost" ]; then
    step "5. This Mac's own services: a second agent (demo/mac.yaml) publishes what macOS advertises on the local network for $machost.local: Remote Login, File Sharing, Screen Sharing."
    start mirror mac-agent.log "$B/sig0lease-agent" run "$log/mac.yaml"
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
