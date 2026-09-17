# tests/lib/mdnsresponder.sh -- build (if needed) and locate the real, unmodified
# mDNSResponder/ServiceRegistration srp-client and srp-mdns-proxy binaries, for
# tests/test_mdnsresponder_interop.sh's network-level interop gate against the RFC 9665
# plan's own named primary cross-check (plan S12.3, S14 Option C). See lib/common.sh for the
# "no set -e, return not exit" rules this file follows.

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

# build_mdnsresponder builds srp-client and srp-mdns-proxy via the checkout's own Makefile
# (one `make`, Linux target auto-detected) if either binary is missing. Requires mbedtls dev
# libs to already be installed (not this script's job to install them).
build_mdnsresponder() {
    log_section "BUILD: mDNSResponder/ServiceRegistration (srp-client, srp-mdns-proxy)"

    if [ ! -d "$MDNSRESPONDER_SRCDIR" ]; then
        log_error "mDNSResponder checkout not found at $MDNSRESPONDER_DIR"
        log_error "Clone it first: git clone https://github.com/apple/mDNSResponder.git \"$MDNSRESPONDER_DIR\""
        log_error "Or point MDNSRESPONDER_DIR at an existing checkout."
        return 1
    fi
    require_command make

    if [ -x "$MDNSRESPONDER_SRP_CLIENT_BIN" ] && [ -x "$MDNSRESPONDER_SRP_MDNS_PROXY_BIN" ]; then
        log_success "Already built: $MDNSRESPONDER_SRP_CLIENT_BIN, $MDNSRESPONDER_SRP_MDNS_PROXY_BIN"
        return 0
    fi

    log_step "Building (make, from $MDNSRESPONDER_SRCDIR)"
    if ! (cd "$MDNSRESPONDER_SRCDIR" && make >/tmp/mdnsresponder-build.log 2>&1); then
        log_error "mDNSResponder build failed -- log:"
        tail -n 80 /tmp/mdnsresponder-build.log || true
        return 1
    fi
    log_success "Built: $MDNSRESPONDER_SRP_CLIENT_BIN, $MDNSRESPONDER_SRP_MDNS_PROXY_BIN"
}
