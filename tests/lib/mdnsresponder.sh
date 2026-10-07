# tests/lib/mdnsresponder.sh -- build (if needed) and locate the real, unmodified
# mDNSResponder/ServiceRegistration srp-client and srp-mdns-proxy binaries, plus the
# mDNSPosix daemon (mdnsd) and its dns-sd tool, for tests/test_mdnsresponder_interop.sh's
# network-level interop gate against the RFC 9665 plan's own named primary cross-check
# (plan S12.3, S14 Option C). See lib/common.sh for the "no set -e, return not exit" rules
# this file follows.

if [ -n "${_SIG0LEASE_LIB_MDNSRESPONDER_SOURCED:-}" ]; then
    return 0 2>/dev/null || true
fi
_SIG0LEASE_LIB_MDNSRESPONDER_SOURCED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$LIB_DIR/common.sh"

# MDNSRESPONDER_DIR: a sibling checkout of
# https://github.com/apple/mDNSResponder (ServiceRegistration/ is the SRP-relevant
# subtree) -- checked out deliberately to serve this development, the same convention
# plan S12.3 documents; not vendored into this repo, not auto-cloned by this script (a
# missing checkout fails clearly below rather than silently fetching one).
MDNSRESPONDER_DIR="${MDNSRESPONDER_DIR:-$TESTS_DIR/../../mDNSResponder}"
MDNSRESPONDER_SRCDIR="$MDNSRESPONDER_DIR/ServiceRegistration"
MDNSRESPONDER_BUILD_DIR="$MDNSRESPONDER_SRCDIR/build"
MDNSRESPONDER_SRP_CLIENT_BIN="$MDNSRESPONDER_BUILD_DIR/srp-client"
MDNSRESPONDER_SRP_MDNS_PROXY_BIN="$MDNSRESPONDER_BUILD_DIR/srp-mdns-proxy"
MDNSRESPONDER_POSIX_DIR="$MDNSRESPONDER_DIR/mDNSPosix"
MDNSRESPONDER_LIB_DIR="$MDNSRESPONDER_POSIX_DIR/build/prod" # libdns_sd.so, which dns-sd links against
MDNSRESPONDER_MDNSD_BIN="$MDNSRESPONDER_LIB_DIR/mdnsd"
MDNSRESPONDER_DNSSD_BIN="$MDNSRESPONDER_DIR/Clients/build/dns-sd"
# mdnsd's client socket. A compile-time path (MDNS_UDS_SERVERPATH), the same in mdnsd, dns-sd and
# srp-mdns-proxy, which hands every registration it accepts to the daemon listening there.
MDNSRESPONDER_MDNSD_SOCKET="/var/run/mdnsd"
MDNSD_LOG="/tmp/mdnsd_interop.log"
MDNSD_PID=""

# build_mdnsresponder builds srp-client and srp-mdns-proxy via ServiceRegistration's own
# Makefile (one `make`, Linux target auto-detected), and mdnsd and dns-sd via mDNSPosix's
# (`make os=linux Daemon Clients`), whichever are missing. Requires mbedtls dev libs to
# already be installed (not this script's job to install them).
build_mdnsresponder() {
    log_section "BUILD: mDNSResponder (srp-client, srp-mdns-proxy, mdnsd, dns-sd)"

    if [ ! -d "$MDNSRESPONDER_SRCDIR" ]; then
        log_error "mDNSResponder checkout not found at $MDNSRESPONDER_DIR"
        log_error "Clone it first: git clone https://github.com/apple/mDNSResponder.git \"$MDNSRESPONDER_DIR\""
        log_error "Or point MDNSRESPONDER_DIR at an existing checkout."
        return 1
    fi
    require_command make

    if [ -x "$MDNSRESPONDER_SRP_CLIENT_BIN" ] && [ -x "$MDNSRESPONDER_SRP_MDNS_PROXY_BIN" ]; then
        log_success "Already built: $MDNSRESPONDER_SRP_CLIENT_BIN, $MDNSRESPONDER_SRP_MDNS_PROXY_BIN"
    else
        log_step "Building (make, from $MDNSRESPONDER_SRCDIR)"
        if ! (cd "$MDNSRESPONDER_SRCDIR" && make >/tmp/mdnsresponder-build.log 2>&1); then
            log_error "mDNSResponder build failed -- log:"
            tail -n 80 /tmp/mdnsresponder-build.log || true
            return 1
        fi
        log_success "Built: $MDNSRESPONDER_SRP_CLIENT_BIN, $MDNSRESPONDER_SRP_MDNS_PROXY_BIN"
    fi

    if [ -x "$MDNSRESPONDER_MDNSD_BIN" ] && [ -x "$MDNSRESPONDER_DNSSD_BIN" ]; then
        log_success "Already built: $MDNSRESPONDER_MDNSD_BIN, $MDNSRESPONDER_DNSSD_BIN"
        return 0
    fi
    log_step "Building (make os=linux Daemon Clients, from $MDNSRESPONDER_POSIX_DIR)"
    if ! (cd "$MDNSRESPONDER_POSIX_DIR" && make os=linux Daemon Clients >/tmp/mdnsposix-build.log 2>&1); then
        log_error "mDNSPosix build failed -- log:"
        tail -n 80 /tmp/mdnsposix-build.log || true
        return 1
    fi
    log_success "Built: $MDNSRESPONDER_MDNSD_BIN, $MDNSRESPONDER_DNSSD_BIN"
}

# start_mdnsd starts mDNSResponder's own daemon, in the foreground (-debug) so its log lands
# in MDNSD_LOG, and waits for its client socket. Needs root: mdnsd creates
# MDNSRESPONDER_MDNSD_SOCKET under /var/run and binds UDP 5353. Refuses to run beside a daemon
# already listening on that socket rather than test against something it did not start.
start_mdnsd() {
    log_section "START: mdnsd (mDNSResponder's daemon)"

    if [ "$(id -u)" -ne 0 ]; then
        log_error "mdnsd needs root: it creates $MDNSRESPONDER_MDNSD_SOCKET and binds UDP 5353"
        return 1
    fi
    require_command ss
    if ss -xl 2>/dev/null | grep -qF "$MDNSRESPONDER_MDNSD_SOCKET "; then
        log_error "An mDNS daemon is already listening on $MDNSRESPONDER_MDNSD_SOCKET -- stop it first"
        return 1
    fi
    rm -f "$MDNSRESPONDER_MDNSD_SOCKET" # a stale socket file, from a daemon that is gone

    "$MDNSRESPONDER_MDNSD_BIN" -debug > "$MDNSD_LOG" 2>&1 &
    MDNSD_PID=$!
    local start
    start=$(date +%s)
    while [ ! -S "$MDNSRESPONDER_MDNSD_SOCKET" ]; do
        if ! kill -0 "$MDNSD_PID" 2>/dev/null || [ $(( $(date +%s) - start )) -ge 5 ]; then
            log_error "mdnsd did not come up. Log:"
            tail -n 40 "$MDNSD_LOG" || true
            return 1
        fi
        sleep 0.2
    done
    log_success "mdnsd started (PID $MDNSD_PID), socket $MDNSRESPONDER_MDNSD_SOCKET, log: $MDNSD_LOG"
}

stop_mdnsd() {
    if [ -n "${MDNSD_PID:-}" ] && kill -0 "$MDNSD_PID" 2>/dev/null; then
        kill "$MDNSD_PID" || true
        sleep 1
        rm -f "$MDNSRESPONDER_MDNSD_SOCKET"
    fi
    MDNSD_PID=""
}

# dnssd_for <seconds> <dns-sd arguments...> runs mDNSResponder's dns-sd against the running
# mdnsd for <seconds> and prints what it printed. dns-sd never exits on its own; stdbuf keeps
# its output line-buffered so none of it is lost when timeout stops it.
dnssd_for() {
    local seconds="$1"; shift
    LD_LIBRARY_PATH="$MDNSRESPONDER_LIB_DIR" timeout "$seconds" stdbuf -oL "$MDNSRESPONDER_DNSSD_BIN" "$@" 2>&1 || true
}
