# demo/lib.sh -- what the demo's scripts (run.sh, chat.sh, web.sh, ipfs.sh, ipfs-local.sh,
# watch.sh) share, sourced by them. It sets ns, update_domain and srp_domain, below; the scripts
# set B, the binaries' directory, and log, the directory for the programs' logs, before using the
# rest.
#
# REGISTRAR, when set, is the registrar the agents send their updates to, in place of the proxy
# each demo otherwise starts on this machine, at 127.0.0.1:8053: a shared one, as the public
# registrar (docs/demo.md, "Running a demo"). It is what the agents' templates take
# as server: host:port, or an https URL with TRANSPORT=doh. TRANSPORT, with REGISTRAR only, is how
# they reach it: tcp (the agents' default), udp, tls or doh.

if [ -n "${TRANSPORT:-}" ] && [ -z "${REGISTRAR:-}" ]; then
    echo "TRANSPORT is how the agents reach REGISTRAR, which is not set: this machine's proxy takes the agents' default, tcp" >&2
    exit 1
fi

# remote -- whether the demo uses REGISTRAR, and starts no proxy.
remote() { [ -n "${REGISTRAR:-}" ]; }

# NS, ns: the server ask() asks, the zone's authoritative one; default ns1.free2air.org.
# UPDATE_DOMAIN and SRP_DOMAIN, update_domain and srp_domain: the two subtrees of the zone where
# the demo's names go (docs/demo.md, "Where the names go"): names a key holds, with any records
# (RFC 9664, the proxy's update_handler), and hosts with the services they register (RFC 9665,
# srp_handler). Without REGISTRAR, they are what the proxy the demo starts serves (proxy_config),
# UPDATE_DOMAIN by default local.dev.zenr.io, apart from the registrar's names. With REGISTRAR,
# they are the registrar's, and UPDATE_DOMAIN has to be given. SRP_DOMAIN is srp.<UPDATE_DOMAIN>
# by default.
ns="${NS:-ns1.free2air.org}"
if remote && [ -z "${UPDATE_DOMAIN:-}" ]; then
    echo "UPDATE_DOMAIN is where REGISTRAR takes the demo's names, and SRP_DOMAIN its hosts, if not srp.<UPDATE_DOMAIN>: give them (docs/demo.md, \"Running a demo\")" >&2
    exit 1
fi
update_domain="${UPDATE_DOMAIN:-local.dev.zenr.io}"
update_domain="${update_domain%.}"
srp_domain="${SRP_DOMAIN:-srp.$update_domain}"
srp_domain="${srp_domain%.}"

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

# step <text> -- prints the step and waits for the key n (next). Any other key, Enter too, only
# starts a new line: Enter makes room in what the demo prints, without moving on.
step() {
    local key
    printf '\n%s\n[n: next] ' "$1"
    while IFS= read -r -s -n 1 key; do
        echo
        [ "$key" != n ] || return 0
    done
    echo
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

# proxy_config -- writes $log/config.yaml, the config of the proxy the demo starts: config.yaml,
# with srp_handler's upstream_zone SRP_DOMAIN and update_handler's UPDATE_DOMAIN. The proxy signs
# its updates for each with the key in keystore/server at the closest name at or above it, and
# does not start without one. With REGISTRAR, nothing.
proxy_config() {
    remote && return 0
    awk -v srp="$srp_domain." -v update="$update_domain." '
        /^[^ #]/ { handlers = /^handlers:/ }
        handlers && /^  [a-z_]+:/ { block = $1 }
        handlers && /^    upstream_zone:/ && (block == "srp_handler:" || block == "update:") {
            sub(/upstream_zone: .*/, "upstream_zone: \"" (block == "update:" ? update : srp) "\"")
            n++
        }
        { print }
        END { exit n != 2 }' config.yaml > "$log/config.yaml" || {
        echo "Could not give the proxy the demo's subtrees in $log/config.yaml: config.yaml no longer has one upstream_zone line in handlers.srp_handler and one in handlers.update" >&2
        exit 1
    }
}

# start_proxy -- starts this demo's proxy, with $log/config.yaml (proxy_config); with REGISTRAR,
# nothing.
start_proxy() {
    remote && return 0
    start proxy proxy.log "$B/sig0lease" "$log/config.yaml"
}

# template <file> <copy> -- copies an agent template for this run (the copy may be the file): a
# relative keystore made absolute, as the agent takes it relative to the template's directory;
# each srp registrar's domain SRP_DOMAIN, and each rfc9664 name, given in full on one "- name:"
# line, its first label in UPDATE_DOMAIN; and with REGISTRAR each registrar's server, this
# machine's proxy (127.0.0.1:8053), replaced by REGISTRAR, with TRANSPORT.
template() {
    local dir
    dir="$(cd "$(dirname "$1")" && pwd)" || exit 1
    awk -v dir="$dir" -v server="${REGISTRAR:-}" -v transport="${TRANSPORT:-}" \
        -v update="$update_domain" -v srp="$srp_domain" '
        /^keystore: [^\/ #]/ { sub(/^keystore: /, "keystore: " dir "/") }
        /^ *- protocol: / { names = /protocol: rfc9664/ }
        names && match($0, /^ *- name: [^ .#]+[.][^ #]*/) {
            head = substr($0, 1, RSTART + RLENGTH - 1)
            label = head
            sub(/^ *- name: /, "", label)
            sub(/[.].*/, "", label)
            sub(/name: .*/, "name: " label "." update ".", head)
            $0 = head substr($0, RSTART + RLENGTH)
        }
        /^ *domain: / { sub(/domain: [^ #]*/, "domain: " srp ".") }
        server != "" && /^ *server: 127\.0\.0\.1:8053/ {
            indent = $0
            sub(/[^ ].*/, "", indent)
            print indent "server: " server
            if (transport != "") print indent "transport: " transport
            next
        }
        { print }' "$1" > "$2.new" && mv "$2.new" "$2" || exit 1
    # With REGISTRAR, every server in the copy has to be it: REGISTRAR replaces only this
    # machine's proxy, and may be that very address (a proxy started by hand, docs/demo.md D3).
    if ! grep -q '^keystore: /' "$2" ||
        { remote && awk -v s="$REGISTRAR" '/^ *server:/ && $2 != s { bad = 1 } END { exit !bad }' "$2"; }; then
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
# in SRP_DOMAIN, while it answers. It serves $log/site, a copy of demo/site whose page lists the
# run's host and name, $name.$srp_domain and $name.$update_domain (name: the caller's NAME, by
# default demo), where demo/site/index.html, written like demo/demo.yaml for runs by hand, has
# demo.srp.dev.zenr.io and demo.dev.zenr.io.
start_site() {
    mkdir -p "$log/site" || exit 1
    awk -v host="$name.$srp_domain" -v nm="$name.$update_domain" '
        { h += gsub(/<code>demo[.]srp[.]dev[.]zenr[.]io<[/]code>/, "<code>" host "</code>")
          n += gsub(/<code>demo[.]dev[.]zenr[.]io<[/]code>/, "<code>" nm "</code>")
          print }
        END { exit !(h == 1 && n == 1) }' demo/site/index.html > "$log/site/index.html" || {
        echo "Could not give the site's page this run's names: demo/site/index.html no longer has <code>demo.srp.dev.zenr.io</code> and <code>demo.dev.zenr.io</code> once each" >&2
        exit 1
    }
    start site site.log python3 -m http.server 8000 -d "$log/site"
}

# listed <instance> -- whether browsing SRP_DOMAIN's HTTP services lists the instance.
listed() { ask PTR "_http._tcp.$srp_domain" | grep -qF "$1._http._tcp.$srp_domain."; }
