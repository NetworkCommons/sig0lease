# demo/lib.sh -- what the demo's scripts (run.sh, chat.sh, web.sh, ipfs.sh) share, sourced by
# them. They set B, the binaries' directory, log, the directory for the programs' logs, ns, the
# server ask() asks, zone, the RFC 9664 zone, and domain, the SRP domain, if they have one, before
# using these.
#
# REGISTRAR, when set, is the registrar the agents send their updates to, in place of the proxy
# each demo otherwise starts on this machine, at 127.0.0.1:8053: a shared one, as the public
# registrar (docs/demo.md, "Against a shared registrar"). It is what the agents' templates take
# as server: host:port, or an https URL with TRANSPORT=doh. TRANSPORT, with REGISTRAR only, is how
# they reach it: tcp (the agents' default), udp, tls or doh.

if [ -n "${TRANSPORT:-}" ] && [ -z "${REGISTRAR:-}" ]; then
    echo "TRANSPORT is how the agents reach REGISTRAR, which is not set: this machine's proxy takes the agents' default, tcp" >&2
    exit 1
fi

# remote -- whether the demo uses REGISTRAR, and starts no proxy.
remote() { [ -n "${REGISTRAR:-}" ]; }

# via -- how the demo's updates reach the zone, for the scripts' messages; our_proxy -- "the
# proxy, " when the demo starts one, for the steps that list what they start and stop.
if remote; then
    via="through the registrar at $REGISTRAR" our_proxy=
else
    via="through this machine's proxy" our_proxy="the proxy, "
fi

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

# step <text> -- prints the step and waits for Enter.
step() {
    printf '\n%s\n[Enter] ' "$1"
    read -r _ || echo
}

# in_use <port> -- whether something on this machine accepts connections on the port.
in_use() { (exec 3<> "/dev/tcp/127.0.0.1/$1") 2> /dev/null; }

# check_proxy_ports [port...] -- exits unless port 8053, where the demo's proxy listens, and the
# other ports given are free on this machine. Each demo starts its own proxy, with the config it
# needs, so it does not run beside another proxy: another demo's, or one whose config it cannot
# know. With REGISTRAR, it starts none, and this checks nothing.
check_proxy_ports() {
    local port
    remote && return 0
    for port in 8053 "$@"; do
        if in_use "$port"; then
            echo "Port $port, for this demo's proxy, is in use: another demo, or another proxy, runs on this machine. Stop it first: each demo starts its own proxy (docs/demo.md)." >&2
            exit 1
        fi
    done
}

# build [web] -- builds the clients, the proxy unless REGISTRAR is set, and with web the page.
build() {
    local targets=(build-client) what="the clients"
    if ! remote; then
        targets=(build "${targets[@]}") what="the proxy and $what"
    fi
    if [ "${1:-}" = web ]; then
        targets+=(web) what="$what, and the page"
    fi
    echo "Building $what."
    make -s "${targets[@]}" || exit 1
}

# start_proxy [config] -- starts this demo's proxy, with config.yaml or the config given; with
# REGISTRAR, nothing.
start_proxy() {
    remote && return 0
    start proxy proxy.log "$B/sig0lease" "$@"
}

# template <file> <copy> -- copies an agent template for this run (the copy may be the file): a
# relative keystore made absolute, as the agent takes it relative to the template's directory;
# each srp registrar's domain the demo's (DOMAIN), and each rfc9664 name, given in full on one
# "- name:" line, its first label in the demo's ZONE; and with REGISTRAR each registrar's server,
# this machine's proxy (127.0.0.1:8053), replaced by REGISTRAR, with TRANSPORT.
template() {
    local dir
    dir="$(cd "$(dirname "$1")" && pwd)" || exit 1
    awk -v dir="$dir" -v server="${REGISTRAR:-}" -v transport="${TRANSPORT:-}" \
        -v zone="${zone:-}" -v domain="${domain:-}" '
        BEGIN { sub(/[.]$/, "", zone); sub(/[.]$/, "", domain) }
        /^keystore: [^\/ #]/ { sub(/^keystore: /, "keystore: " dir "/") }
        /^ *- protocol: / { names = /protocol: rfc9664/ }
        zone != "" && names && match($0, /^ *- name: [^ .#]+[.][^ #]*/) {
            head = substr($0, 1, RSTART + RLENGTH - 1)
            label = head
            sub(/^ *- name: /, "", label)
            sub(/[.].*/, "", label)
            sub(/name: .*/, "name: " label "." zone ".", head)
            $0 = head substr($0, RSTART + RLENGTH)
        }
        domain != "" && /^ *domain: / { sub(/domain: [^ #]*/, "domain: " domain ".") }
        server != "" && /^ *server: 127\.0\.0\.1:8053/ {
            indent = $0
            sub(/[^ ].*/, "", indent)
            print indent "server: " server
            if (transport != "") print indent "transport: " transport
            next
        }
        { print }' "$1" > "$2.new" && mv "$2.new" "$2" || exit 1
    if ! grep -q '^keystore: /' "$2" || { remote && grep -q '127\.0\.0\.1:8053' "$2"; }; then
        echo "Could not copy $1 to $2 for this run: a template needs a keystore line, and each registrar the server: 127.0.0.1:8053 that REGISTRAR replaces" >&2
        exit 1
    fi
}

ask() { dig +short +time=2 +tries=1 "@$ns" "$@"; }
answers() { [ -n "$(ask "$@")" ]; }
not() { ! "$@"; }

# wait_until <what> <command...> -- runs the command every second until it succeeds, and prints
# how long that took; after 90 s it gives up, showing every log's last lines.
wait_until() {
    local what="$1" t0
    shift
    t0=$(date +%s)
    printf '  waiting until %s ... ' "$what"
    until "$@"; do
        if [ $(( $(date +%s) - t0 )) -ge 90 ]; then
            echo "not after 90 s; the logs' last lines:"
            tail -n 5 "$log"/*.log
            exit 1
        fi
        sleep 1
    done
    echo "$(( $(date +%s) - t0 )) s"
}

# D1's site, which D6 (web.sh) starts too: demo/demo.yaml's host registers it as "<name> http",
# in the SRP domain, while it answers. listed uses domain, which the script sets.
start_site() { start site site.log python3 -m http.server 8000 -d demo/site; }

# listed <instance> -- whether browsing the domain's HTTP services lists the instance.
listed() { ask PTR "_http._tcp.$domain" | grep -qF "$1._http._tcp.$domain."; }
