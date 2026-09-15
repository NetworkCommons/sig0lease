# tests/lib/dns.sh -- querying the authoritative server directly (bypassing
# the proxy) and RR-spec/rdata string helpers. See lib/common.sh for the "no
# set -e, return not exit" rules this file follows.
#
# rr_at_auth_contains, rr_at_authoritative, and wait_for_rr_state read the
# global $DOWNSTREAM_ZONE, set by the orchestration script (test_update.sh /
# test_srp.sh), not by this library -- matching how they've always worked.

if [ -n "${_SIG0LEASE_LIB_DNS_SOURCED:-}" ]; then
    return 0 2>/dev/null || true
fi
_SIG0LEASE_LIB_DNS_SOURCED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$LIB_DIR/common.sh"

delete_rr(){
    local record="$1"
    local payload

    echo "Deleting $record"
    if [ "$record" = "key" ]; then
        require_client_keystore_dir || return 1
        # Read the secret string straight out of the private file
        payload="$(cat $CLIENT_KEYSTORE_DIR/$CLIENT_KEY_NAME.key | sed 's/test.dev.zenr.io. IN \(.*\)/\1/g')"
    else
        payload="$record"
    fi
    echo "payload is $payload"

    cat <<EOF | nsupdate -k $PROXY_KEY_NAME
    server $AUTH_SERVER
    zone zenr.io
    update delete test.dev.zenr.io $payload
    send
EOF
}

# add_rr publishes a record directly at the authoritative server, bypassing
# the proxy entirely. Used to simulate a key or record that exists online but
# was never registered through the proxy (e.g. an "online-only" signer, or a
# pre-existing authoritative record for duplicate-registration tests).
#
# Usage: add_rr <record> [ttl]
#   record: "key" for the well-known client test KEY, or an explicit
#           "<TYPE> <rdata...>" payload (e.g. "TXT \"hello\"")
#   ttl:    TTL in seconds for the added record (default 60)
#
# Requires a modern nsupdate with ED25519 SIG(0)/TSIG support (BIND 9.10.6,
# the version macOS ships at /usr/bin/nsupdate, predates RFC 8080 and cannot
# sign/verify this project's ED25519 keys correctly -- install a current
# nsupdate via `brew install bind` and make sure /opt/homebrew/bin precedes
# /usr/bin in PATH).
add_rr(){
    local record="$1"
    local ttl="${2:-60}"
    local payload

    echo "Adding $record (ttl=$ttl)"
    if [ "$record" = "key" ]; then
        require_client_keystore_dir || return 1
        # Read the secret string straight out of the private file
        payload="$(cat $CLIENT_KEYSTORE_DIR/$CLIENT_KEY_NAME.key | sed 's/test.dev.zenr.io. IN \(.*\)/\1/g')"
    else
        payload="$record"
    fi
    echo "payload is $payload"

    cat <<EOF | nsupdate -k $PROXY_KEY_NAME
    server $AUTH_SERVER
    zone zenr.io
    update add test.dev.zenr.io $ttl $payload
    send
EOF
}

################################
# DNS inquiry functions
################################
dig_query_short() {
    local endpoint="$1"
    local name="$2"
    local rr_type="$3"

    local host="$endpoint"
    local port="53"
    if [[ "$endpoint" == *:* ]]; then
        host="${endpoint%:*}"
        port="${endpoint##*:}"
    fi

    log_file dig_query_short "dig +short +time=5 @\"$host\" -p \"$port\" \"$name\" \"$rr_type\" 2>/dev/null"
    dig +short +time=5 @"$host" -p "$port" "$name" "$rr_type" 2>/dev/null
}

# rr_at_auth_contains <name> <rr_type> <needle>
# Queries <name>/<rr_type> at the authoritative server and checks whether
# <needle> appears anywhere in the (possibly multi-record) answer. Unlike
# rr_at_authoritative (which matches a specific rr-spec's rdata against a
# single-line dig answer), this checks presence of a substring across all
# returned records -- used where multiple records of the same type/name can
# coexist (e.g. overlapping registrations).
rr_at_auth_contains() {
    local name="$1"
    local rr_type="$2"
    local needle="$3"

    local dig_answer
    dig_answer="$(dig_query_short "$AUTH_SERVER" "$name" "$rr_type")"
    log_file rr_at_auth_contains "name=$name rr_type=$rr_type needle=$needle dig_answer=$dig_answer"

    if echo "$dig_answer" | grep -qF -- "$needle"; then
        return 0
    fi
    return 1
}
# Matches a specific rr-spec's rdata against a single-line dig answer
rr_at_authoritative() {
    local rr_type=$1
    local rdata="$2"

    local answer

    local dig_answer="$(dig_query_short $AUTH_SERVER $DOWNSTREAM_ZONE $rr_type)"

    if [ -n "$dig_answer" ]; then
        # -F: match dig_answer's line(s) as literal fixed strings, not a
        # regex. Each newline-separated line still acts as its own
        # alternative to grep against $rdata (multi-record answers), but a
        # "." in an A/AAAA answer can no longer wildcard-match, and a stray
        # regex metachar in a TXT/WALLET/CLA payload (e.g. an unbalanced
        # "[") can no longer make grep itself error out instead of just
        # not matching.
        answer="$(echo "$rdata" | grep -F -- "$dig_answer")"
        log_file rr_at_authoritative "rdata=$rdata, dig_answer=$dig_answer, answer=$answer."
    else
        answer=''
        log_file rr_at_authoritative "rdata=$rdata, empty dig_answer."
    fi

    if [ -n "$answer" ]; then
        echo "Record present: $answer"
        return 0
    else
        echo "no match"
        return 1
    fi

}

wait_for_rr_state() {
    local rr_type="$1"
    local rdata="$2"
    local state="$3"   # present|absent
    local timeout=30

    local start
    start=$(date +%s)

    while true; do
        log_file wait_for_rr_state "state=$state, calling rr_at_authoritative $rr_type \"$rdata\""
        if [ "$state" = "present" ]; then
            if rr_at_authoritative $rr_type "$rdata"; then
                log_success "$rr_type present on $DOWNSTREAM_ZONE"
                auth_present=1
                break
            fi
        else
            if ! rr_at_authoritative $rr_type "$rdata"; then
                log_success "$rr_type absent on $DOWNSTREAM_ZONE"
                auth_present=0
                break
            fi
        fi

        if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
            log_error "Timed out waiting for ${rr_type} state=$state on $DOWNSTREAM_ZONE"
            return 1
        fi

        sleep 2
    done

    proxy_consistent_with_authoritative $rr_type "$rdata" "$state" $auth_present
}

ensure_rr_absent() {
    local rr_type="$1"
    local rr_rdata="$2"

    log_file ensure_rr_absent "rr_type=$rr_type, rr_rdata=$rr_rdata."

    if ! rr_at_authoritative "$rr_type" "$rr_rdata"; then
        log_success "Pristine state already present: $rr_type - $rr_rdata absent on $DOWNSTREAM_ZONE"
        return 0
    fi

    log_step "Cleanup: rr $rr_type - $rr_rdata is present, deleting"

    # Refresh with 0 lease.
    if ! run_client refresh $CLIENT_KEY_NAME 0 0 "$rr_rdata"; then
        log_error "Cleanup failed for $rr_type - $rr_rdata"
        return 1
    fi

    if wait_for_rr_state $rr_type "$rr_rdata" absent; then
        log_success "Cleanup complete: $rr_type - $rr_rdata absent on $DOWNSTREAM_ZONE"
    else
        log_error "Cleanup failed for $rr_type - $rr_rdata on $DOWNSTREAM_ZONE"
        return 1
    fi
    return 0
}

################################
# RR builder functions
################################
# get_rdata <rr-spec> -- the rdata-bearing tail of an rr-spec, with
# tabs and runs of spaces collapsed to single spaces: everything after
# "<name> [ttl] IN ". This lets one rr-spec form (space-separated, TTL
# optional -- what make_rr and the *.key files produce) be matched against a
# lease-store dump line (dns.RR.String(), tab-separated) or a dig answer.
#   "test.dev.zenr.io. IN KEY 256 3 15 AAA.."   -> 'KEY 256 3 15 AAA..'
#   "test.dev.zenr.io. 30 IN TXT \"lease-x\""   -> 'TXT "lease-x"'
get_rdata() {
    printf '%s' "$1" | tr '\t' ' ' \
        | sed -E 's/  +/ /g; s/^ +//; s/ +$//; s/^[^ ]+ ([0-9]+ )?IN //'
}
