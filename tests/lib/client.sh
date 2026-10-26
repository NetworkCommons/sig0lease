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

# run_client <operation> <keyname> <lease> <key-lease> [rr-spec...] [-signer=update|additional|none]
# Accepts zero or more trailing rr-specs and/or client flags (an argument starting with "-"),
# in any order: it passes the flags before keyname, as the client wants them, and every
# argument as a separate argv entry (no eval/string concatenation, so rr-specs containing
# spaces/quotes are safe).
# Transport is controlled by PROXY_PROTOCOL (see lib/common.sh; defaults to udp, same
# udp-unless-told-otherwise mechanism as PROXY_ADDR/PROXY_PORT) -- every call site gets
# -transport for it, and the proxy's DoT address (PROXY_TLS_URL) when PROXY_PROTOCOL=tls; no
# call site needs to pass either itself.
run_client() {
    require_client_keystore_dir || return 1

    local operation="$1"
    local keyname="$2"
    local lease_seconds="$3"
    local key_lease_seconds="$4"
    shift 4
    local server="$PROXY_URL"
    case "$PROXY_PROTOCOL" in
        udp|tcp) ;;
        tls) server="$PROXY_TLS_URL" ;;
        *)
            log_error "Unknown PROXY_PROTOCOL=$PROXY_PROTOCOL (want udp, tcp or tls)"
            return 1
            ;;
    esac
    local flags=(-server "$server" -transport "$PROXY_PROTOCOL" -lease "$lease_seconds" -key-lease "$key_lease_seconds")
    local specs=() arg
    for arg in "$@"; do
        case "$arg" in
            -*) flags+=("$arg") ;;
            *) specs+=("$arg") ;;
        esac
    done

    log_file run_client "operation=$operation keyname=$keyname flags=${flags[*]} rr-specs=${specs[*]:-}"
    echo "CLIENT_KEYSTORE_DIR=\"$CLIENT_KEYSTORE_DIR\" \"$CLIENT_BIN\" $operation ${flags[*]} \"$keyname\" ${specs[*]:-}"
    CLIENT_KEYSTORE_DIR="$CLIENT_KEYSTORE_DIR" "$CLIENT_BIN" "$operation" "${flags[@]}" "$keyname" ${specs[@]+"${specs[@]}"}
}

# assert_client_reply <client output> <rcode> <info-code> <reason> -- checks the reply
# sig0lease-client (or blacklisted_tester) printed: Status <rcode>, e.g. REFUSED, and an
# Extended DNS Error (RFC 8914) with <info-code> whose text contains <reason>. The text is the
# proxy's own reason for the refusal, sent because the suites' configs turn on
# server.diagnostics.
assert_client_reply() {
    local out="$1" rcode="$2" info_code="$3" reason="$4"
    if ! grep -q "Status: ${rcode} (Rcode=" <<< "$out"; then
        log_error "Expected a $rcode reply, got:"
        echo "$out"
        return 1
    fi
    if ! grep "EDE ${info_code} (" <<< "$out" | grep -qF -- "$reason"; then
        log_error "Expected Extended DNS Error $info_code with \"$reason\", got:"
        echo "$out"
        return 1
    fi
}

# verify_keystore checks that the two well-known test keys this suite relies
# on (CLIENT_KEY_NAME, WRONG_CLIENT_KEY_NAME) are present in
# $CLIENT_KEYSTORE_DIR, both at $DOWNSTREAM_ZONE (set by the orchestration
# script) with different key tags, and sets CLIENT_KEY_RR / WRONG_CLIENT_KEY_RR
# (the raw "<name> IN KEY ..." lines) for callers that need the rdata.
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

    # The unauthorized-signer tests (TEST 3) need a second key at the same name: the proxy
    # refuses a key at another name earlier, for signing records outside its own subtree,
    # and never reaches the refusals those tests check.
    if [ "$CLIENT_KEY_NAME" = "$WRONG_CLIENT_KEY_NAME" ]; then
        log_error "CLIENT_KEY_NAME and WRONG_CLIENT_KEY_NAME are the same key: $CLIENT_KEY_NAME"
        return 1
    fi
    local name rr owner
    for name in "$CLIENT_KEY_NAME" "$WRONG_CLIENT_KEY_NAME"; do
        rr="$(cat "$CLIENT_KEYSTORE_DIR/${name}.key")"
        owner="$(awk '{ print tolower($1); exit }' <<< "$rr")"
        if [ "$owner" != "$(tr '[:upper:]' '[:lower:]' <<< "$DOWNSTREAM_ZONE")" ]; then
            log_error "Key $name is at $owner, not at $DOWNSTREAM_ZONE: both client keys must be at $DOWNSTREAM_ZONE. Make a second one with: dnssec-keygen -K $CLIENT_KEYSTORE_DIR -a ED25519 -n HOST -T KEY $DOWNSTREAM_ZONE"
            return 1
        fi
    done

    log_success "Test keystore verified, directory content:"
    ls -1 "$CLIENT_KEYSTORE_DIR" | sed -n '1,50p'
    echo "CLIENT_KEY_RR: $CLIENT_KEY_RR"
    echo "WRONG_CLIENT_KEY_RR: $WRONG_CLIENT_KEY_RR"
}

test_list_keys() {
    require_client_keystore_dir || return 1
    log_section "CHECK: Key Listing"
    log_step "Listing keys from real keystore"
    "$CLIENT_BIN" list-keys -keystore "$CLIENT_KEYSTORE_DIR"
    log_success "Key listing successful"
}
