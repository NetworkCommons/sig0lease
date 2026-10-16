# tests/lib/mdnsresponder.sh -- build (if needed) and locate the real, unmodified
# mDNSResponder/ServiceRegistration srp-client and srp-mdns-proxy binaries, and the mDNS daemon
# and dns-sd tool beside them, for tests/test_mdnsresponder_interop.sh's network-level interop
# gate against the RFC 9665 plan's own named primary cross-check (plan S12.3, S14 Option C).
# On Linux the daemon and dns-sd are mDNSPosix's mdnsd and dns-sd, built from the same checkout
# and started here; on macOS they are the system's own mDNSResponder and /usr/bin/dns-sd. See
# lib/common.sh for the "no set -e, return not exit" rules this file follows.

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
# One build per OS, like bin/<os>/: a checkout shared between a Linux machine and a Mac keeps
# both. Relative to MDNSRESPONDER_SRCDIR, as ServiceRegistration's Makefile takes them.
MDNSRESPONDER_BUILD_SUBDIR="build/$OS"
MDNSRESPONDER_OBJ_SUBDIR="objects/$OS"
MDNSRESPONDER_BUILD_DIR="$MDNSRESPONDER_SRCDIR/$MDNSRESPONDER_BUILD_SUBDIR"
MDNSRESPONDER_SRP_CLIENT_BIN="$MDNSRESPONDER_BUILD_DIR/srp-client"
MDNSRESPONDER_SRP_MDNS_PROXY_BIN="$MDNSRESPONDER_BUILD_DIR/srp-mdns-proxy"
MDNSRESPONDER_POSIX_DIR="$MDNSRESPONDER_DIR/mDNSPosix"
MDNSD_PID=""
# MDNSRESPONDER_MAKE_OS: ServiceRegistration's Makefile target. MDNSRESPONDER_MDNSD_SOCKET: the
# daemon's client socket. A compile-time path (MDNS_UDS_SERVERPATH), the same in the daemon,
# dns-sd and srp-mdns-proxy, which hands every registration it accepts to the daemon listening
# there.
case "$OS" in
    linux)
        MDNSRESPONDER_MAKE_OS="linux"
        MDNSRESPONDER_LIB_DIR="$MDNSRESPONDER_POSIX_DIR/build/prod" # libdns_sd.so, which dns-sd links against
        MDNSRESPONDER_MDNSD_BIN="$MDNSRESPONDER_LIB_DIR/mdnsd"
        MDNSRESPONDER_DNSSD_BIN="$MDNSRESPONDER_DIR/Clients/build/dns-sd"
        MDNSRESPONDER_MDNSD_SOCKET="/var/run/mdnsd"
        MDNSD_LOG="/tmp/mdnsd_interop.log"
        ;;
    darwin)
        # x-mbedtls: macOS with mbedtls in place of the Security framework, so srp-client keeps
        # its key in a file in its working directory, as on Linux, rather than in one login
        # keychain item every run would share (tests/mdnsresponder-build.patch).
        MDNSRESPONDER_MAKE_OS="x-mbedtls"
        MDNSRESPONDER_LIB_DIR=""
        MDNSRESPONDER_MDNSD_BIN=""
        MDNSRESPONDER_DNSSD_BIN="/usr/bin/dns-sd"
        MDNSRESPONDER_MDNSD_SOCKET="/var/run/mDNSResponder"
        MDNSD_LOG=""
        ;;
    *)
        MDNSRESPONDER_MAKE_OS=""
        ;;
esac

# build_mdnsresponder builds srp-client and srp-mdns-proxy with ServiceRegistration's own
# Makefile into MDNSRESPONDER_BUILD_DIR and, on Linux, mdnsd and dns-sd with mDNSPosix's
# (`make os=linux Daemon Clients`), whichever are missing. Requires mbedtls to already be
# installed (not this script's job): its dev package on Linux, Homebrew's mbedtls@3 on macOS
# (mbedtls 4 dropped APIs ServiceRegistration uses, such as mbedtls/ecp.h).
build_mdnsresponder() {
    log_section "BUILD: mDNSResponder (srp-client, srp-mdns-proxy)"

    if [ -z "$MDNSRESPONDER_MAKE_OS" ]; then
        log_error "No mDNSResponder build for $OS: the interop suite runs on Linux and macOS"
        return 1
    fi
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
        local make_vars=("os=$MDNSRESPONDER_MAKE_OS" "BUILDDIR=$MDNSRESPONDER_BUILD_SUBDIR" "OBJDIR=$MDNSRESPONDER_OBJ_SUBDIR")
        if [ "$OS" = darwin ]; then
            require_command brew
            local mbedtls_prefix
            mbedtls_prefix="$(brew --prefix mbedtls@3)"
            if [ ! -f "$mbedtls_prefix/include/mbedtls/version.h" ]; then
                log_error "mbedtls 3 not found at $mbedtls_prefix: brew install mbedtls@3"
                return 1
            fi
            make_vars+=("MBEDTLS_PREFIX=$mbedtls_prefix")
        fi
        log_step "Building (make ${make_vars[*]}, from $MDNSRESPONDER_SRCDIR)"
        if ! (cd "$MDNSRESPONDER_SRCDIR" && make "${make_vars[@]}" setup \
                "$MDNSRESPONDER_BUILD_SUBDIR/srp-client" "$MDNSRESPONDER_BUILD_SUBDIR/srp-mdns-proxy" \
                >/tmp/mdnsresponder-build.log 2>&1); then
            log_error "mDNSResponder build failed -- log:"
            tail -n 80 /tmp/mdnsresponder-build.log || true
            return 1
        fi
        log_success "Built: $MDNSRESPONDER_SRP_CLIENT_BIN, $MDNSRESPONDER_SRP_MDNS_PROXY_BIN"
    fi

    [ "$OS" = linux ] || return 0
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

# start_mdns_daemon makes sure an mDNS daemon listens on MDNSRESPONDER_MDNSD_SOCKET. On macOS
# that is the system's mDNSResponder, which always runs: nothing to start, and no root needed.
# On Linux it starts mDNSResponder's own daemon, in the foreground (-debug) so its log lands in
# MDNSD_LOG, and waits for its client socket. That needs root: mdnsd creates
# MDNSRESPONDER_MDNSD_SOCKET under /var/run and binds UDP 5353. It refuses to run beside a
# daemon already listening on that socket rather than test against something it did not start.
start_mdns_daemon() {
    if [ "$OS" = darwin ]; then
        log_section "mDNS daemon: the system's mDNSResponder"
        if [ ! -S "$MDNSRESPONDER_MDNSD_SOCKET" ]; then
            log_error "The system's mDNSResponder is not listening on $MDNSRESPONDER_MDNSD_SOCKET"
            return 1
        fi
        log_success "Using the system daemon, socket $MDNSRESPONDER_MDNSD_SOCKET"
        return 0
    fi

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

# stop_mdns_daemon stops the daemon start_mdns_daemon started, if it started one.
stop_mdns_daemon() {
    if [ -n "${MDNSD_PID:-}" ] && kill -0 "$MDNSD_PID" 2>/dev/null; then
        stop_process "$MDNSD_PID" || true
        rm -f "$MDNSRESPONDER_MDNSD_SOCKET"
    fi
    MDNSD_PID=""
}

# dnssd_start <dns-sd arguments...> starts dns-sd against the daemon in the background, writing
# to this shell's output, and sets DNSSD_PID. dns-sd never exits on its own, and flushes its
# output after each batch of results, so all it found is written by the time it is stopped.
dnssd_start() {
    LD_LIBRARY_PATH="$MDNSRESPONDER_LIB_DIR" "$MDNSRESPONDER_DNSSD_BIN" "$@" &
    DNSSD_PID=$!
}

# dnssd_for <seconds> <dns-sd arguments...> runs dns-sd for <seconds> and prints what it printed.
dnssd_for() {
    local seconds="$1"; shift
    dnssd_start "$@" 2>&1
    sleep "$seconds"
    stop_process "$DNSSD_PID" || true
}
