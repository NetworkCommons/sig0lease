# tests/lib/client.sh -- everything that drives the sig0lease-client binary
# against the proxy, plus keystore setup/verification. See lib/common.sh for
# the "no set -e, return not exit" rules this file follows.

if [ -n "${_SIG0LEASE_LIB_CLIENT_SOURCED:-}" ]; then
    return 0 2>/dev/null || true
fi
_SIG0LEASE_LIB_CLIENT_SOURCED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$LIB_DIR/common.sh"

CLIENT_BIN="${TESTS_DIR}/../bin/${OS}/sig0lease-client"

# run_client <operation> <keyname> <lease> <key-lease> [rr-spec...] [--signer=update|additional|none]
# Accepts zero or more trailing rr-specs and/or a --signer= flag, passed
# through to the client binary as separate argv entries (no eval/string
# concatenation, so rr-specs containing spaces/quotes are safe).
# Transport is controlled by PROXY_PROTOCOL (see lib/common.sh; defaults to
# udp, same udp-unless-told-otherwise mechanism as PROXY_ADDR/PROXY_PORT) --
# every call site gets --tcp for free when PROXY_PROTOCOL=tcp, no call site
# needs to pass it itself.
run_client() {
    require_client_keystore_dir || return 1

    local operation="$1"
    local keyname="$2"
    local lease_seconds="$3"
    local key_lease_seconds="$4"
    shift 4
    local extra=("$@")
    if [ "$PROXY_PROTOCOL" = "tcp" ]; then
        extra+=(--tcp)
    fi

    log_file run_client "operation=$operation keyname=$keyname lease=$lease_seconds key_lease=$key_lease_seconds extra=${extra[*]:-}"
    echo "CLIENT_KEYSTORE_DIR=\"$CLIENT_KEYSTORE_DIR\" \"$CLIENT_BIN\" \"$PROXY_URL\" $operation \"$keyname\" $lease_seconds $key_lease_seconds ${extra[*]:-}"
    CLIENT_KEYSTORE_DIR="$CLIENT_KEYSTORE_DIR" "$CLIENT_BIN" "$PROXY_URL" "$operation" "$keyname" "$lease_seconds" "$key_lease_seconds" "${extra[@]}"
}

# verify_keystore checks that the two well-known test keys this suite relies
# on (CLIENT_KEY_NAME, WRONG_CLIENT_KEY_NAME) are present in
# $CLIENT_KEYSTORE_DIR, and sets CLIENT_KEY_RR / WRONG_CLIENT_KEY_RR (the raw
# "<name> IN KEY ..." lines) for callers that need the rdata. References
# $DOWNSTREAM_ZONE only for its log message -- set by the orchestration
# script, not this library.
verify_keystore() {
    require_client_keystore_dir || return 1
    log_section "SETUP: Real Keystore"

    if [ ! -d "$CLIENT_KEYSTORE_DIR" ]; then
        log_error "Test keystore directory not found: $CLIENT_KEYSTORE_DIR"
        return 1
    fi

    log_step "Verifying test keys in keystore: $CLIENT_KEYSTORE_DIR"
    if ! ls "$CLIENT_KEYSTORE_DIR"/${CLIENT_KEY_NAME}.key >/dev/null 2>&1; then
        log_error "Expected key for zone $DOWNSTREAM_ZONE not found in $CLIENT_KEYSTORE_DIR"
        return 1
    fi
    CLIENT_KEY_RR=$(cat $CLIENT_KEYSTORE_DIR/${CLIENT_KEY_NAME}.key)

    if ! ls "$CLIENT_KEYSTORE_DIR"/${WRONG_CLIENT_KEY_NAME}.key >/dev/null 2>&1; then
        log_error "Expected second real key for unauthorized test ($WRONG_CLIENT_KEY_NAME) not found"
        return 1
    fi
    WRONG_CLIENT_KEY_RR=$(cat $CLIENT_KEYSTORE_DIR/${WRONG_CLIENT_KEY_NAME}.key)

    log_success "Test keystore verified, directory content:"
    ls -1 "$CLIENT_KEYSTORE_DIR" | sed -n '1,50p'
    echo "CLIENT_KEY_RR: $CLIENT_KEY_RR"
    echo "WRONG_CLIENT_KEY_RR: $WRONG_CLIENT_KEY_RR"
}

test_list_keys() {
    require_client_keystore_dir || return 1
    log_section "CHECK: Key Listing"
    log_step "Listing keys from real keystore"
    CLIENT_KEYSTORE_DIR="$CLIENT_KEYSTORE_DIR" "$CLIENT_BIN" dummy list-keys "$CLIENT_KEYSTORE_DIR"
    log_success "Key listing successful"
}
