# demo/lib.sh -- what the demo's scripts (run.sh, chat.sh, web.sh, ipfs.sh) share, sourced by
# them. They set log, the directory for the programs' logs, and ns, the server ask() asks, before
# using these.

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
# know.
check_proxy_ports() {
    local port
    for port in 8053 "$@"; do
        if in_use "$port"; then
            echo "Port $port, for this demo's proxy, is in use: another demo, or another proxy, runs on this machine. Stop it first: each demo starts its own proxy (docs/demo.md)." >&2
            exit 1
        fi
    done
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
