#!/bin/bash
#
# Comprehensive Update Test for sig0lease Proxy
#
# This suite runs real process-level update tests only:
# - real proxy binary
# - real client binary
# - real DNS keys from keystore
# - real authoritative path for zenr.io (via proxy update forwarding)
#
#

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

CLIENT_BIN="${SCRIPT_DIR}/../bin/${OS}/sig0lease-client"
BLACKLISTED_TESTER_BIN="${SCRIPT_DIR}/../bin/${OS}/blacklisted_tester"

# Zones
UPSTREAM_ZONE="dev.zenr.io."
DOWNSTREAM_ZONE="test.${UPSTREAM_ZONE}"

# Lease times
POLICY_MIN_RR_LEASE_SECONDS="$(yaml_get_lease_time min_rr_lease_sec)"
POLICY_MIN_KEY_LEASE_SECONDS="$(yaml_get_lease_time min_key_lease_sec)"

LEASE_SECONDS="${LEASE_SECONDS:-$POLICY_MIN_RR_LEASE_SECONDS}"
REFRESH_SECONDS="${REFRESH_SECONDS:-$LEASE_SECONDS}"
KEY_LEASE_SECONDS="${KEY_LEASE_SECONDS:-$POLICY_MIN_KEY_LEASE_SECONDS}"
# Case 2 validates refresh behavior under split-lease policy: keep KEY alive longer.
REFRESH_CASE_KEY_LEASE_SECONDS="${REFRESH_CASE_KEY_LEASE_SECONDS:-3600}"
OVERLAP_RR_LEASE_SECONDS="${OVERLAP_RR_LEASE_SECONDS:-30}"
OVERLAP_KEY_LEASE_SECONDS="${OVERLAP_KEY_LEASE_SECONDS:-120}"
OVERLAP_DELAY_SECONDS="${OVERLAP_DELAY_SECONDS:-10}"

# Keep protocol invariant for any defaults in this script: LEASE <= KEY-LEASE and non-zero.
if [ "$KEY_LEASE_SECONDS" -eq 0 ] || [ "$LEASE_SECONDS" -eq 0 ]; then
    log_error "Invalid initial value for LEASE ($LEASE_SECONDS) and/or KEY-LEASE ($KEY_LEASE_SECONDS)"
    exit 1
elif [ "$LEASE_SECONDS" -gt "$KEY_LEASE_SECONDS" ]; then
    log_error "LEASE ($LEASE_SECONDS) longer than KEY-LEASE ($KEY_LEASE_SECONDS)"
    exit 1
fi

# Optional: limit matrix run to selected RR types, e.g. RR_TYPES="KEY TXT"
# Supported types: KEY TXT A AAAA NULL NXNAME WALLET CLA IPN
RR_TYPES="${RR_TYPES:-KEY TXT A AAAA NULL NXNAME WALLET CLA IPN}"

################################
# Utils
################################
require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "Required command not found: $1"
        exit 1
    fi
}

################################
# Timing
################################
log_case_timing() {
    local case_name="$1"
    local case_start_epoch="$2"
    local expected_min_seconds="$3"

    local now elapsed drift
    now=$(date +%s)
    elapsed=$((now - case_start_epoch))
    drift=$((elapsed - expected_min_seconds))

    log_step "Timing [$case_name]: expected-min=${expected_min_seconds}s actual=${elapsed}s drift=${drift}s"
}

wait_until_epoch() {
    local target_epoch="$1"
    local now
    now=$(date +%s)
    if [ "$now" -lt "$target_epoch" ]; then
        sleep $((target_epoch - now))
    fi
}

################################
# Client/Server functions
################################

build_binaries() {
    log_section "BUILD"
    log_step "Building proxy and client binaries"
    (cd "$SCRIPT_DIR/.." && go build -o "$PROXY_BIN" ./cmd/sig0lease)
    (cd "$SCRIPT_DIR/.." && go build -o "$CLIENT_BIN" ./cmd/sig0lease-client)
    (cd "$SCRIPT_DIR/.." && go build -o "$BLACKLISTED_TESTER_BIN" ./tests/blacklisted_tester.go)
    log_success "Binaries built"
}

# run_client <operation> <keyname> <lease> <key-lease> [rr-spec...] [--signer=update|additional|none]
# Accepts zero or more trailing rr-specs and/or a --signer= flag, passed
# through to the client binary as separate argv entries (no eval/string
# concatenation, so rr-specs containing spaces/quotes are safe).
run_client() {
    local operation="$1"
    local keyname="$2"
    local lease_seconds="$3"
    local key_lease_seconds="$4"
    shift 4
    local extra=("$@")

    log_file run_client "operation=$operation keyname=$keyname lease=$lease_seconds key_lease=$key_lease_seconds extra=${extra[*]:-}"
    echo "CLIENT_KEYSTORE_DIR=\"$CLIENT_KEYSTORE_DIR\" \"$CLIENT_BIN\" \"$PROXY_URL\" $operation \"$keyname\" $lease_seconds $key_lease_seconds ${extra[*]:-}"
    CLIENT_KEYSTORE_DIR="$CLIENT_KEYSTORE_DIR" "$CLIENT_BIN" "$PROXY_URL" "$operation" "$keyname" "$lease_seconds" "$key_lease_seconds" "${extra[@]}"
}

assert_proxy_log_contains() {
    local pattern="$1"
    if grep -q "$pattern" "$LOG_FILE"; then
        return 0
    fi
    log_error "Expected proxy log pattern not found: $pattern"
    tail -n 120 "$LOG_FILE" || true
    return 1
}

# Query the running proxy for lease store dump at the specified log level.
# Usage: query_lease_dump <level>
#   level: "debug" → full details via __dump.sig0lease.internal.debug.
#          "info"  → summary via __dump.sig0lease.internal.
# Returns the concatenated TXT dump text from the proxy.
query_lease_dump() {
    local level="${1:-info}"
    local query_domain dump_label
    case "$level" in
        debug)
            query_domain="__dump.sig0lease.internal.debug."
            dump_label="DEBUG/full"
            ;;
        info|*)
            query_domain="__dump.sig0lease.internal."
            dump_label="INFO/summary"
            ;;
    esac

    local out
    out=$(dig_query_short "$PROXY_URL" "${query_domain}" TXT)

    # Use test script's own log levels (independent from proxy logging).
    if [ "$level" = "debug" ]; then
        log_debug "[dig] @${PROXY_URL} ${query_domain} TXT (${dump_label})"
    else
        log_info "[dig] @${PROXY_URL} ${query_domain} TXT (${dump_label})"
    fi

    if [ -n "$out" ]; then
        echo "$out"
    else
        echo "(no dump response)"
    fi
    printf '%s\n' "$out"
}

# unescape_dump_text <raw> -- reconstructs a lease-store dump's real text
# (newlines/tabs) from dig +short's DNS presentation-format output. dig
# renders embedded control bytes as literal \DDD (decimal, per RFC 1035
# <character-string> escaping) and splits a dump longer than one TXT string
# across multiple RRs/output lines. Strips the per-line quoting, joins the
# chunks back together, then decodes the \DDD escapes -- otherwise any
# line-anchored parsing (awk /^.../) of query_lease_dump's output silently
# matches nothing, since there are no real newlines in dig's raw output.
# Uses printf (not echo) to feed input through, since some shells' builtin
# echo reinterprets backslash escapes itself before sed/perl ever see them.
unescape_dump_text() {
    local raw="$1"
    printf '%s\n' "$raw" | sed 's/^"//; s/"$//' | tr -d '\n' | perl -pe 's/\\(\d{3})/chr($1)/ge; s/\\"/"/g; s/\\\\/\\/g'
}

verify_keystore() {
    log_section "SETUP: Real Keystore"

    if [ ! -d "$CLIENT_KEYSTORE_DIR" ]; then
        log_error "Test keystore directory not found: $CLIENT_KEYSTORE_DIR"
        exit 1
    fi

    log_step "Verifying test keys in keystore: $CLIENT_KEYSTORE_DIR"
    if ! ls "$CLIENT_KEYSTORE_DIR"/${CLIENT_KEY_NAME}.key >/dev/null 2>&1; then
        log_error "Expected key for zone $DOWNSTREAM_ZONE not found in $CLIENT_KEYSTORE_DIR"
        exit 1
    fi
    CLIENT_KEY_RR=$(cat $CLIENT_KEYSTORE_DIR/${CLIENT_KEY_NAME}.key)
    if ! ls "$CLIENT_KEYSTORE_DIR"/${WRONG_CLIENT_KEY_NAME}.key >/dev/null 2>&1; then
        log_error "Expected second real key for unauthorized test ($WRONG_CLIENT_KEY_NAME) not found"
        exit 1
    fi
    WRONG_CLIENT_KEY_RR=$(cat $CLIENT_KEYSTORE_DIR/${WRONG_CLIENT_KEY_NAME}.key)

    log_success "Test keystore verified, directory content:"
    ls -1 "$CLIENT_KEYSTORE_DIR" | sed -n '1,50p'
    echo "CLIENT_KEY_RR: $CLIENT_KEY_RR"
    echo "WRONG_CLIENT_KEY_RR: $WRONG_CLIENT_KEY_RR"
}

test_list_keys() {
    log_section "CHECK: Key Listing"
    log_step "Listing keys from real keystore"
    CLIENT_KEYSTORE_DIR="$CLIENT_KEYSTORE_DIR" "$CLIENT_BIN" dummy list-keys "$CLIENT_KEYSTORE_DIR"
    log_success "Key listing successful"
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

rr_at_authoritative() {
    local rr_type=$1
    local rdata="$2"

    local answer

    local dig_answer="$(dig_query_short $AUTH_SERVER $DOWNSTREAM_ZONE $rr_type)"
    
    if [ -n "$dig_answer" ]; then
        answer="$(echo "$rdata" | grep "$dig_answer")"
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
                return 0
            fi
        else
            if ! rr_at_authoritative $rr_type "$rdata"; then
                log_success "$rr_type absent on $DOWNSTREAM_ZONE"
                return 0
            fi
        fi

        if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
            log_error "Timed out waiting for ${rr_type} state=$state on $DOWNSTREAM_ZONE"
            return 1
        fi

        sleep 2
    done
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

make_rr() {
    local rr_type="$1"
    local ttl="$2"
    local wrong="${3:-0}"
    case "$rr_type" in
        KEY)
            # The raw key file line has no TTL field ("<name> IN KEY ...");
            # inject the requested ttl so this is a well-formed rr-spec.
            if [ "$wrong" == "1" ]; then
                echo "$WRONG_CLIENT_KEY_RR" | sed "s/ IN / ${ttl} IN /"
            else
                echo "$CLIENT_KEY_RR" | sed "s/ IN / ${ttl} IN /"
            fi
        ;;
        TXT) echo "${DOWNSTREAM_ZONE} ${ttl} IN TXT \"lease-txt-$(date +%s)\"" ;;
        A) echo "${DOWNSTREAM_ZONE} ${ttl} IN A 192.0.2.33" ;;
        AAAA) echo "${DOWNSTREAM_ZONE} ${ttl} IN AAAA 2001:db8::33" ;;
        # NULL and NXNAME have no presentation format in miekg/dns,
        # so they cannot be constructed via the client binary's
        # ParseAdditionalRRSpec (which uses dns.New). They are
        # tested at the unit-test level (handlers opcode5 behavior tests).
        NULL) log_step "Skipping NULL: no presentation format in miekg/dns" ;;
        NXNAME) log_step "Skipping NXNAME: no presentation format in miekg/dns" ;;
        WALLET) echo "${DOWNSTREAM_ZONE} ${ttl} IN WALLET \"wallet-data-$(date +%s)\"" ;;
        CLA) echo "${DOWNSTREAM_ZONE} ${ttl} IN CLA \"cla-data-$(date +%s)\"" ;;
        IPN) echo "${DOWNSTREAM_ZONE} ${ttl} IN IPN 42" ;;
        *)
            log_error "Unsupported rr type: $rr_type"
            return 1
            ;;
    esac
}

# build_case_a_specs <rr_type> <ttl> -- sets the global array CASE_A_SPECS to
# the rr-specs needed for a valid Case A (KEY-LEASE!=0 and LEASE!=0)
# registration/refresh of <rr_type>. Case A always requires an explicit KEY
# rr-spec in the Update section (even for a pure refresh of an
# already-managed key) alongside at least one non-KEY rr-spec, so this always
# includes a KEY rr-spec paired with either a companion TXT record (if
# rr_type is itself KEY) or the type's own spec.
build_case_a_specs() {
    local rr_type="$1"
    local ttl="$2"
    local key_spec
    key_spec="$(make_rr KEY "$ttl")"
    if [ "$rr_type" = "KEY" ]; then
        CASE_A_SPECS=("$key_spec" "$(make_rr TXT "$ttl")")
    else
        CASE_A_SPECS=("$key_spec" "$(make_rr "$rr_type" "$ttl")")
    fi
}

# register_rr_type <key_name> <lease> <key_lease> <rr_spec...>
register_rr_type() {
    local key_name="$1"
    local lease_seconds="$2"
    local key_lease_seconds="$3"
    shift 3
    log_step "registering key=$key_name lease=$lease_seconds key_lease=$key_lease_seconds rr_specs=$*"
    run_client register "$key_name" "$lease_seconds" "$key_lease_seconds" "$@"
}

proxy_consistent_with_authoritative() {
    local rr_type="$1"
    local rr_rdata="$2"
    local expected_state="$3"  # present|absent

    local is_present=0
    log_file proxy_consistent_with_authoritative "rr_type=$rr_type, rr_rdata=$rr_rdata, expected_state=$expected_state."

    if rr_at_authoritative $rr_type "$rr_rdata"; then
        is_present=1
    fi

    if [ "$expected_state" = "present" ] && [ "$is_present" -ne 1 ]; then
        log_error "Consistency check failed: authoritative missing but expected present for $rr_type - $rr_rdata"
        return 1
    fi
    if [ "$expected_state" = "absent" ] && [ "$is_present" -ne 0 ]; then
        log_error "Consistency check failed: authoritative present but expected absent for $rr_type - $rr_rdata"
        return 1
    fi

    # Proxy Lease-store consistency checks
    # TODO: Add checks that records in lease-store are actually at the DNS
    
    log_info "Consistency check passed for $rr_type - $rr_rdata"

}
################################
# Tests
################################
test_blacklisted_type() {
# Test blacklisted RR types by constructing them programmatically.
# NULL and NXNAME cannot be constructed via presentation format (miekg/dns limitation),
# so we use a small Go helper that constructs these records directly and sends them.

    local rr_type=$1
    log_section "BLACKLISTED [$rr_type]: Proxy Rejects Blacklisted Type"

    log_step "Registering lease with blacklisted type"
    local case_start lease_start
    case_start=$(date +%s)
    lease_start=$(date +%s)

    # For NULL/NXNAME, use the Go helper to construct the record directly.
    # For WALLET/CLA/IPN, use the standard client binary.
    local rr_spec=""
    local reg_out=""
    case "$rr_type" in
        NULL|NXNAME)
            # Construct the record programmatically via the Go helper.
            # This bypasses ParseAdditionalRRSpec and constructs the RR directly.
            log_step "Using Go helper to construct $rr_type record directly"
            # blacklisted_tester sends the request directly to the proxy and prints the response.
            reg_out=$(cd "$SCRIPT_DIR/.." && go run -ldflags="-X main.rrType=$rr_type -X main.rrOwner=$DOWNSTREAM_ZONE -X main.keyName=$CLIENT_KEY_NAME -X main.leaseDurationStr=$LEASE_SECONDS -X main.keyLeaseSecStr=$KEY_LEASE_SECONDS -X main.proxyAddr=$PROXY_URL -X main.zone=$DOWNSTREAM_ZONE" ./tests/blacklisted_tester.go 2>&1) || true
            ;;
        *)
            rr_spec=$(make_rr "$rr_type" "$LEASE_SECONDS")
            log_step "Attempting registration with blacklisted type $rr_type"
            # Both LEASE and KEY-LEASE nonzero (Case A) requires a companion
            # KEY rr-spec in the Update section, or the client rejects the
            # request itself before it ever reaches the proxy.
            reg_out=$(run_client register "$CLIENT_KEY_NAME" "$LEASE_SECONDS" "$KEY_LEASE_SECONDS" "$(make_rr KEY "$KEY_LEASE_SECONDS")" "$rr_spec" 2>&1) || true
            ;;
    esac

    # Check the response for rejection (should be Rcode=1 FormatError).
    if echo "$reg_out" | grep -q "Rcode=1\|FormatError\|REGISTRATION FAILED"; then
        log_success "Proxy correctly rejected blacklisted type $rr_type with format error"
    else
        log_error "Proxy should have rejected blacklisted type $rr_type, got: $reg_out"
        return 1
    fi

    # Verify no KEY RR was created (registration should be atomic - all or nothing).
    if rr_at_authoritative KEY $CLIENT_KEY_NAME; then
        log_error "Blacklisted type $rr_type rejected but key lease created"
        return 1
    else
        log_success "Blacklisted type $rr_type rejected and no lease created"
    fi
    return 0
}

test_single_rr_register_expire_remove() {
    local rr_type="$1"
    log_section "CASE 1 [$rr_type]: Register -> Expire -> Removed"

    local rr_spec lease case_start lease_start expected_min

    case $rr_type in
        KEY)
            local lease_time=0
            local key_lease_time=$KEY_LEASE_SECONDS
            lease=$key_lease_time
            rr_spec="$(make_rr $rr_type $lease)"
            ;;
        *)
            # A non-KEY-only registration is Case B (data-only), which
            # requires the signer to already be lease-managed -- not true at
            # this point in a fresh run. So register via Case A (KEY+data
            # together, both timers equal so they expire together) instead,
            # mirroring the build_case_a_specs pattern used by Cases 2/2B/3.
            local lease_time=$LEASE_SECONDS
            local key_lease_time=$LEASE_SECONDS
            lease=$lease_time
            build_case_a_specs "$rr_type" "$lease"
            rr_spec="${CASE_A_SPECS[1]}"
            ;;
    esac

    case_start=$(date +%s)
    log_step "Registering lease "
    lease_start=$(date +%s)
    if [ "$rr_type" = "KEY" ]; then
        register_rr_type $CLIENT_KEY_NAME $lease_time $key_lease_time "$rr_spec"
    else
        register_rr_type $CLIENT_KEY_NAME $lease_time $key_lease_time "${CASE_A_SPECS[@]}"
        wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    fi
    wait_for_rr_state $rr_type "$rr_spec" present

    # Verify lease store via dump query (INFO level summary).
    log_step "Verifying lease store state via dump query (DEBUG)"
    query_lease_dump "debug"

    log_step "Waiting until lease expiry boundary"
    wait_until_epoch $((lease_start + lease + 3))

    # RR should be gone before we exercise post-expiry behavior.
    wait_for_rr_state "$rr_type" "$rr_spec" absent
    proxy_consistent_with_authoritative "$rr_type" "$rr_spec" absent

    if [ "$rr_type" = "KEY" ]; then
        log_step "Attempting refresh after expiry (KEY path: expected to re-register)"
        run_client refresh "$CLIENT_KEY_NAME" 0 $REFRESH_SECONDS "$rr_spec"
        wait_for_rr_state KEY "$rr_spec" present
        proxy_consistent_with_authoritative KEY "$rr_spec" present
        log_success "Expired KEY refresh succeeded via re-registration semantics"
    else
        # Both KEY and data expired together above, so the signer is no
        # longer lease-managed: a data-only (Case B) refresh attempt must be
        # refused for that reason, not because "the lease does not exist"
        # (that message is Case D's validateRefreshOwnership path, which
        # this request never reaches). Assert on the client-visible Rcode
        # plus the actual Case B rejection text, not a guessed string.
        log_step "Attempting refresh after expiry (non-KEY path: expected failure, signer no longer managed)"
        local post_expiry_out
        if post_expiry_out=$(run_client refresh "$CLIENT_KEY_NAME" "$REFRESH_SECONDS" 0 "$rr_spec" 2>&1); then
            log_error "Refresh succeeded after expiry, expected failure"
            echo "$post_expiry_out"
            return 1
        fi
        if ! echo "$post_expiry_out" | grep -q "Rcode=5\|REFUSED"; then
            log_error "Expected REFUSED (Rcode=5) for post-expiry data-only refresh, got:"
            echo "$post_expiry_out"
            return 1
        fi
        wait_for_rr_state $rr_type "$rr_spec" absent
        proxy_consistent_with_authoritative $rr_type "$rr_spec" absent
        # "requires signing KEY to already be managed" is the *response*
        # message text (never passed to h.logger), not what actually lands
        # in the proxy's own log -- assert on the real logged reason instead.
        assert_proxy_log_contains "signing key not found in lease store"
    fi

    expected_min=$((lease_start + lease + 3 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case1-${rr_type}" "$case_start" "$expected_min"
    log_success "Case 1 post-expiry behavior validated for $rr_type"
}

test_case_register_refresh_not_prematurely_removed() {
    local rr_type="$1"
    log_section "CASE 2 [$rr_type]: Register -> Refresh -> Not Prematurely Removed (Case A)"

    local case_start lease_start refresh_start expected_min data_spec data_type
    case_start=$(date +%s)
    build_case_a_specs "$rr_type" "$LEASE_SECONDS"
    data_spec="${CASE_A_SPECS[1]}"
    # build_case_a_specs pairs a KEY registration with a TXT companion (Case
    # A needs a non-KEY record too), so data_spec's actual RR type is TXT
    # when rr_type is KEY -- never $rr_type itself in that case.
    if [ "$rr_type" = "KEY" ]; then
        data_type="TXT"
    else
        data_type="$rr_type"
    fi
    log_step "Registering initial lease (LEASE=$LEASE_SECONDS, KEY-LEASE=$REFRESH_CASE_KEY_LEASE_SECONDS)"
    lease_start=$(date +%s)
    register_rr_type "$CLIENT_KEY_NAME" "$LEASE_SECONDS" "$REFRESH_CASE_KEY_LEASE_SECONDS" "${CASE_A_SPECS[@]}"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$data_type" "$data_spec" present
    proxy_consistent_with_authoritative "$data_type" "$data_spec" present

    # Verify lease store via dump query (INFO level summary).
    log_step "Verifying lease store state via dump query (INFO) after initial registration"
    query_lease_dump "info"

    log_step "Waiting to near-expiry checkpoint then refreshing"
    wait_until_epoch $((lease_start + 20))
    refresh_start=$(date +%s)
    run_client refresh "$CLIENT_KEY_NAME" "$REFRESH_SECONDS" "$REFRESH_CASE_KEY_LEASE_SECONDS" "${CASE_A_SPECS[@]}"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$data_type" "$data_spec" present
    proxy_consistent_with_authoritative "$data_type" "$data_spec" present

    log_step "Waiting past original expiry window"
    wait_until_epoch $((lease_start + LEASE_SECONDS + 5))
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$data_type" "$data_spec" present
    proxy_consistent_with_authoritative "$data_type" "$data_spec" present

    log_step "Refreshing again (must still succeed if not removed prematurely)"
    run_client refresh "$CLIENT_KEY_NAME" "$REFRESH_SECONDS" "$REFRESH_CASE_KEY_LEASE_SECONDS" "${CASE_A_SPECS[@]}"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$data_type" "$data_spec" present
    proxy_consistent_with_authoritative "$data_type" "$data_spec" present

    log_step "Waiting for refreshed data lease window while key-lease remains active"
    wait_until_epoch $((refresh_start + REFRESH_SECONDS + 5))
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    proxy_consistent_with_authoritative KEY "$CLIENT_KEY_RR" present
    if [ "$rr_type" != "KEY" ]; then
        log_step "Post-refresh note: non-key RR ($rr_type) state is informational only"
        rr_at_authoritative "$data_type" "$data_spec" >/dev/null || true
    fi

    expected_min=$((refresh_start + REFRESH_SECONDS + 5 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case2-${rr_type}" "$case_start" "$expected_min"
    log_success "Lease behavior validated after renewal for $rr_type"
}

test_case_split_lease_nonkey_expires_key_persists() {
    local rr_type="$1"
    if [ "$rr_type" = "KEY" ]; then
        return 0
    fi

    log_section "CASE 2B [$rr_type]: LEASE < KEY-LEASE Deletes Non-KEY Only"

    local case_start lease_start expected_min rr_spec
    case_start=$(date +%s)
    lease_start=$(date +%s)
    # Both LEASE and KEY-LEASE are nonzero here (Case A), which requires a
    # companion KEY rr-spec in the Update section -- a data-only rr-spec
    # alone is rejected client-side before anything is even sent ("keyRRs
    # not present but keyLeaseDuration != 0").
    build_case_a_specs "$rr_type" "$LEASE_SECONDS"
    rr_spec="${CASE_A_SPECS[1]}"

    log_step "Registering split lease for $rr_type (LEASE=$LEASE_SECONDS, KEY-LEASE=$REFRESH_CASE_KEY_LEASE_SECONDS)"
    register_rr_type "$CLIENT_KEY_NAME" "$LEASE_SECONDS" "$REFRESH_CASE_KEY_LEASE_SECONDS" "${CASE_A_SPECS[@]}"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$rr_type" "$rr_spec" present

    log_step "Waiting past LEASE boundary and verifying only non-KEY records expire"
    wait_until_epoch $((lease_start + LEASE_SECONDS + 5))
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$rr_type" "$rr_spec" absent

    expected_min=$((lease_start + LEASE_SECONDS + 5 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case2b-${rr_type}" "$case_start" "$expected_min"
    log_success "Split lease behavior correct: non-KEY expired while KEY remained active for $rr_type"
}

test_case_overlapping_registrations_issue17() {
    log_section "CASE 4 [ISSUE-17]: Overlapping Registrations Must Not Leave Permanent RR"

    local case_start first_start second_start expected_min
    local ts1 ts2
    ts1=$(date +%s)
    ts2=$((ts1 + 1))
    case_start=$ts1

    local rr1_a rr1_txt rr2_a rr2_txt
    rr1_a="${DOWNSTREAM_ZONE} ${OVERLAP_RR_LEASE_SECONDS} IN A 192.0.2.99"
    rr1_txt="${DOWNSTREAM_ZONE} ${OVERLAP_RR_LEASE_SECONDS} IN TXT \"issue17-first-${ts1}\""
    rr2_a="${DOWNSTREAM_ZONE} ${OVERLAP_RR_LEASE_SECONDS} IN A 192.0.2.100"
    rr2_txt="${DOWNSTREAM_ZONE} ${OVERLAP_RR_LEASE_SECONDS} IN TXT \"issue17-second-${ts2}\""

    log_step "First registration (A+TXT set #1)"
    first_start=$(date +%s)
    run_client register "$CLIENT_KEY_NAME" $OVERLAP_RR_LEASE_SECONDS $OVERLAP_KEY_LEASE_SECONDS "$(make_rr KEY "$OVERLAP_KEY_LEASE_SECONDS")" "$rr1_a" "$rr1_txt"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" A "192.0.2.99"; then
        log_error "Expected first A record to be visible after first registration"
        return 1
    fi
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "issue17-first-${ts1}"; then
        log_error "Expected first TXT record to be visible after first registration"
        return 1
    fi

    log_step "Waiting ${OVERLAP_DELAY_SECONDS}s before overlapping registration"
    sleep "$OVERLAP_DELAY_SECONDS"

    log_step "Second overlapping registration (A+TXT set #2)"
    second_start=$(date +%s)
    run_client register "$CLIENT_KEY_NAME" $OVERLAP_RR_LEASE_SECONDS $OVERLAP_KEY_LEASE_SECONDS "$(make_rr KEY "$OVERLAP_KEY_LEASE_SECONDS")" "$rr2_a" "$rr2_txt"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present

    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" A "192.0.2.100"; then
        log_error "Expected second A record to be visible after overlapping registration"
        return 1
    fi
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "issue17-second-${ts2}"; then
        log_error "Expected second TXT record to be visible after overlapping registration"
        return 1
    fi

    log_step "Waiting for RR lease expiry to verify old and new non-KEY leases are both cleaned"
    wait_until_epoch $((second_start + OVERLAP_RR_LEASE_SECONDS + 8))

    if rr_at_auth_contains "$DOWNSTREAM_ZONE" A "192.0.2.99" || rr_at_auth_contains "$DOWNSTREAM_ZONE" A "192.0.2.100"; then
        log_error "A record(s) from overlapping registrations were not cleaned up"
        return 1
    fi
    if rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "issue17-first-${ts1}" || rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "issue17-second-${ts2}"; then
        log_error "TXT record(s) from overlapping registrations were not cleaned up"
        return 1
    fi
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present

    expected_min=$((second_start + OVERLAP_RR_LEASE_SECONDS + 8 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case4-issue17-overlap" "$case_start" "$expected_min"
    log_success "Issue #17 regression check passed: overlapping RR sets were not forgotten/permanent"
}

test_case_unauthorized_refresh_rejected_then_expires() {
    local rr_type="$1"
    log_section "CASE 3 [$rr_type]: Unauthorized Refresh Rejected -> Lease Expires"

    local case_start lease_start expected_min data_spec data_type
    case_start=$(date +%s)
    build_case_a_specs "$rr_type" "$LEASE_SECONDS"
    data_spec="${CASE_A_SPECS[1]}"
    # build_case_a_specs pairs a KEY registration with a TXT companion, so
    # data_spec's actual RR type is TXT when rr_type is KEY (see Case 2).
    if [ "$rr_type" = "KEY" ]; then
        data_type="TXT"
    else
        data_type="$rr_type"
    fi
    log_step "Registering lease under authorized key ($CLIENT_KEY_NAME)"
    lease_start=$(date +%s)
    register_rr_type "$CLIENT_KEY_NAME" "$LEASE_SECONDS" "$KEY_LEASE_SECONDS" "${CASE_A_SPECS[@]}"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$data_type" "$data_spec" present

    log_step "Unauthorized refresh attempt using different real key ($WRONG_CLIENT_KEY_NAME)"
    local unauth_out
    # Both LEASE and KEY-LEASE nonzero (Case A) requires a companion KEY
    # rr-spec in the Update section. Include the *original* (CLIENT_KEY_NAME)
    # KEY rdata here -- not WRONG's -- signed by WRONG_CLIENT_KEY_NAME: this
    # reproduces the exact scenario the proxy is meant to reject (a
    # transaction signature from a different, unmanaged key over data it
    # doesn't own), matching the resolved HANDOFF experiment.
    if unauth_out=$(run_client refresh "$WRONG_CLIENT_KEY_NAME" "$REFRESH_SECONDS" "$REFRESH_SECONDS" "$(make_rr KEY "$REFRESH_SECONDS")" "$data_spec" 2>&1); then
        log_error "Unauthorized refresh unexpectedly succeeded"
        echo "$unauth_out"
        return 1
    fi
    # WRONG_CLIENT_KEY_NAME is a distinct, never-registered key (different
    # keytag), not a forged copy of the managed key -- so the proxy rejects
    # it via the online-signer-authorization path ("signer not authorized
    # for new registration"), not a KEY-identity "key mismatch" path (that
    # path is for a colliding name+algo+keytag whose public key bytes
    # differ, which does not apply here). Assert on the client-visible
    # Rcode rather than a proxy-internal log string, which is more robust
    # to log wording changes.
    if ! echo "$unauth_out" | grep -q "Rcode=5\|REFUSED"; then
        log_error "Expected REFUSED (Rcode=5) for unauthorized refresh, got:"
        echo "$unauth_out"
        return 1
    fi
    assert_proxy_log_contains "signer not authorized for new registration"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$data_type" "$data_spec" present

    log_step "Waiting until original lease expires"
    wait_until_epoch $((lease_start + LEASE_SECONDS + 3))

    wait_for_rr_state KEY "$CLIENT_KEY_RR" absent
    proxy_consistent_with_authoritative KEY "$CLIENT_KEY_RR" absent
    if [ "$rr_type" != "KEY" ]; then
        log_step "Post-expiry note: non-key RR ($rr_type) state is informational only"
        rr_at_authoritative "$data_type" "$data_spec" >/dev/null || true
    fi

    expected_min=$((lease_start + LEASE_SECONDS + 3 - case_start))
    if [ "$expected_min" -lt 0 ]; then
        expected_min=0
    fi
    log_case_timing "case3-${rr_type}" "$case_start" "$expected_min"
    log_success "Unauthorized refresh rejected and lease expired as expected for $rr_type"
}

# test_case_abcd_lease_policy_matrix walks deliberately through all four
# lease-policy dispatch cases in handlers/opcode5_handle.go, in the order
# A -> D -> B -> C, using a single KEY (CLIENT_KEY_NAME) and two TXT records
# so each transition's effect on the other records is directly observable:
#   A: KEY-LEASE!=0, LEASE!=0 -- full registration (KEY + txt_a together)
#   D: KEY-LEASE!=0, LEASE=0  -- key-only refresh, must not disturb txt_a
#   B: KEY-LEASE=0,  LEASE!=0 -- data-only registration of txt_b under the
#      already-managed key, coexisting with txt_a
#   C: KEY-LEASE=0,  LEASE=0  -- delete matrix: first a non-KEY-only delete
#      (txt_b only), then a KEY delete that cascades and removes txt_a too
test_case_abcd_lease_policy_matrix() {
    log_section "CASE A/B/C/D: Explicit Lease-Policy Matrix"

    local case_start
    case_start=$(date +%s)

    local needle_a needle_b txt_a txt_b
    needle_a="caseA-$(date +%s)"
    txt_a="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle_a}\""

    log_step "Case A (KEY-LEASE!=0, LEASE!=0): full registration of KEY+TXT"
    register_rr_type "$CLIENT_KEY_NAME" "$LEASE_SECONDS" "$REFRESH_CASE_KEY_LEASE_SECONDS" "$(make_rr KEY "$REFRESH_CASE_KEY_LEASE_SECONDS")" "$txt_a"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle_a"; then
        log_error "Case A: expected TXT record not found at authoritative"
        return 1
    fi
    proxy_consistent_with_authoritative KEY "$CLIENT_KEY_RR" present
    query_lease_dump "info"
    log_success "Case A: KEY+TXT registered together"

    log_step "Case D (KEY-LEASE!=0, LEASE=0): key-only refresh must leave data untouched"
    run_client refresh "$CLIENT_KEY_NAME" 0 "$REFRESH_CASE_KEY_LEASE_SECONDS" "$(make_rr KEY "$REFRESH_CASE_KEY_LEASE_SECONDS")"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle_a"; then
        log_error "Case D: key-only refresh unexpectedly disturbed the Case A TXT record"
        return 1
    fi
    log_success "Case D: key-only refresh left Case A's TXT record untouched"

    needle_b="caseB-$(date +%s)"
    txt_b="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle_b}\""
    log_step "Case B (KEY-LEASE=0, LEASE!=0): data-only registration under the already-managed signer"
    run_client refresh "$CLIENT_KEY_NAME" "$LEASE_SECONDS" 0 "$txt_b"
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle_a"; then
        log_error "Case B: original Case A TXT record disappeared"
        return 1
    fi
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle_b"; then
        log_error "Case B: new data-only TXT record not found at authoritative"
        return 1
    fi
    query_lease_dump "debug"
    log_success "Case B: data-only registration added a second TXT record alongside the first"

    log_step "Case C (KEY-LEASE=0, LEASE=0): non-KEY-only delete removes just txt_b"
    run_client refresh "$CLIENT_KEY_NAME" 0 0 "$txt_b"
    if rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle_b"; then
        log_error "Case C: targeted TXT delete did not remove txt_b"
        return 1
    fi
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle_a"; then
        log_error "Case C: non-KEY-only delete unexpectedly removed txt_a too"
        return 1
    fi
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    log_success "Case C: non-KEY-only delete removed txt_b while KEY and txt_a remained"

    log_step "Case C (KEY-LEASE=0, LEASE=0): KEY delete cascades and removes remaining data"
    run_client refresh "$CLIENT_KEY_NAME" 0 0 "$(make_rr KEY 0)"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" absent
    if rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle_a"; then
        log_error "Case C: KEY delete did not cascade-remove remaining txt_a"
        return 1
    fi
    log_success "Case C: KEY delete cascaded and removed the remaining data lease"

    log_case_timing "case-abcd-matrix" "$case_start" 0
    log_success "Lease-policy Case A/B/C/D matrix (A -> D -> B -> C) validated end-to-end"
}

# test_case_signer_location_matrix exercises all four ways the proxy can
# resolve a SIG(0) signer's KEY material (handlers/opcode5_update_helpers.go
# extractAndValidateSig0's three-stage fallback, split into four physical
# placements): Update section, Additional section, lease store (omitted from
# the request, already registered), and authoritative DNS (omitted, published
# online via add_rr, never registered through the proxy at all).
#
# Steps 1-3 reuse CLIENT_KEY_NAME across a self-registration (Update) and two
# data-only refreshes (Additional, then lease-store), since Case B forbids a
# KEY rr-spec in the Update section entirely -- the only way to prove
# Additional/omitted signer resolution. Step 4 uses WRONG_CLIENT_KEY_NAME,
# published directly at authoritative and never registered through the
# proxy, to reach the authoritative-only fallback stage.
test_case_signer_location_matrix() {
    log_section "SIGNER LOCATION MATRIX: Update / Additional / Lease-Store / Online-Only"

    local case_start
    case_start=$(date +%s)

    local needle1 needle2 needle3 txt1 txt2 txt3
    needle1="signerloc-update-$(date +%s)"
    txt1="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle1}\""

    log_step "Signer location 1/4: Update section (self-registration, Case A)"
    register_rr_type "$CLIENT_KEY_NAME" "$LEASE_SECONDS" "$REFRESH_CASE_KEY_LEASE_SECONDS" "$(make_rr KEY "$REFRESH_CASE_KEY_LEASE_SECONDS")" "$txt1" --signer=update
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle1"; then
        log_error "Signer-location[update]: expected TXT record not found"
        return 1
    fi
    log_success "Signer-location[update]: signer KEY resolved from the Update section"

    needle2="signerloc-additional-$(date +%s)"
    txt2="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle2}\""
    log_step "Signer location 2/4: Additional section (data-only refresh, Case B)"
    run_client refresh "$CLIENT_KEY_NAME" "$LEASE_SECONDS" 0 "$txt2" --signer=additional
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle2"; then
        log_error "Signer-location[additional]: expected TXT record not found"
        return 1
    fi
    log_success "Signer-location[additional]: signer KEY resolved from the Additional section"

    needle3="signerloc-leasestore-$(date +%s)"
    txt3="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle3}\""
    log_step "Signer location 3/4: omitted from request, resolved via lease store (Case B)"
    run_client refresh "$CLIENT_KEY_NAME" "$LEASE_SECONDS" 0 "$txt3" --signer=none
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle3"; then
        log_error "Signer-location[lease-store]: expected TXT record not found"
        return 1
    fi
    log_success "Signer-location[lease-store]: signer KEY resolved from the lease store (omitted from request)"

    log_step "Signer location 4/4: omitted from request, resolved via authoritative DNS (online-only, never registered through the proxy)"
    local wrong_key_payload probe_needle probe_txt probe_out
    wrong_key_payload="$(cat "$CLIENT_KEYSTORE_DIR/${WRONG_CLIENT_KEY_NAME}.key" | sed 's/test.dev.zenr.io. IN \(.*\)/\1/g')"
    add_rr "$wrong_key_payload" 60
    probe_needle="signerloc-online-$(date +%s)"
    probe_txt="${DOWNSTREAM_ZONE} 60 IN TXT \"${probe_needle}\""
    # This is a Case C request (LEASE=0, KEY-LEASE=0) for a record the
    # online-only signer does not own, so it resolves to a harmless no-op
    # (Rcode=Success, "record not found for delete" note) once SIG(0)
    # authenticates -- it is not gated by AllowOnlineKeyRegistration, which
    # only applies to *new registrations* (Case A/D), not Case C deletes.
    if ! probe_out=$(run_client refresh "$WRONG_CLIENT_KEY_NAME" 0 0 "$probe_txt" --signer=none 2>&1); then
        log_error "Signer-location[online-only]: request signed by an online-only, never-registered key was unexpectedly rejected"
        echo "$probe_out"
        delete_rr "$wrong_key_payload"
        return 1
    fi
    delete_rr "$wrong_key_payload"
    if rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$probe_needle"; then
        log_error "Signer-location[online-only]: Case C no-op unexpectedly created a TXT record"
        return 1
    fi
    log_success "Signer-location[online-only]: signer KEY resolved from authoritative DNS (never lease-managed)"

    log_case_timing "signer-location-matrix" "$case_start" 0
    log_success "Signer-location matrix validated: Update, Additional, lease-store, and online-only all resolve correctly"
}

# test_case_multi_rr_combination_registration registers several distinct
# non-KEY RR types together in a single Update (Case A), verifies all land
# correctly, then verifies they all expire together at the LEASE boundary
# while the KEY (registered with a longer key-lease) persists. Deliberately
# excludes NULL/NXNAME (no presentation format, see make_rr) and CLA/IPN
# (blacklisted by this repo's config.yaml), leaving a combination of
# distinct, constructible, non-blacklisted types.
test_case_multi_rr_combination_registration() {
    log_section "MULTI-RR: Register Several RR Types Together in One Update"

    local case_start lease_start
    case_start=$(date +%s)

    # Parallel indexed arrays (combo_types[i] <-> combo_specs[i]), not an
    # associative array: this script's #!/bin/bash shebang resolves to
    # macOS's bundled bash 3.2, which has no `declare -A` support.
    local combo_types=(TXT A AAAA WALLET)
    local combo_specs=() specs=() i t spec
    specs=("$(make_rr KEY "$REFRESH_CASE_KEY_LEASE_SECONDS")")
    for i in "${!combo_types[@]}"; do
        spec="$(make_rr "${combo_types[$i]}" "$LEASE_SECONDS")"
        specs+=("$spec")
        combo_specs[$i]="$spec"
    done

    log_step "Registering KEY + ${combo_types[*]} together in a single Update"
    lease_start=$(date +%s)
    register_rr_type "$CLIENT_KEY_NAME" "$LEASE_SECONDS" "$REFRESH_CASE_KEY_LEASE_SECONDS" "${specs[@]}"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    for i in "${!combo_types[@]}"; do
        t="${combo_types[$i]}"
        if ! wait_for_rr_state "$t" "${combo_specs[$i]}" present; then
            log_error "Multi-RR: $t record not present after combined registration"
            return 1
        fi
        proxy_consistent_with_authoritative "$t" "${combo_specs[$i]}" present
    done
    query_lease_dump "debug"
    log_success "All ${#combo_types[@]} non-KEY types plus KEY landed correctly from a single Update"

    log_step "Waiting past LEASE boundary: non-KEY records should expire, KEY (longer key-lease) persists"
    wait_until_epoch $((lease_start + LEASE_SECONDS + 5))
    for i in "${!combo_types[@]}"; do
        t="${combo_types[$i]}"
        if ! wait_for_rr_state "$t" "${combo_specs[$i]}" absent; then
            log_error "Multi-RR: $t record still present after LEASE expiry"
            return 1
        fi
    done
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present

    log_case_timing "multi-rr-combination" "$case_start" "$((LEASE_SECONDS + 5))"
    log_success "Multi-RR combination registration validated: all types landed together and expired together"
}

# test_case_refresh_extends_data_not_key_lease inspects actual lease
# timestamps via the DEBUG dump (not just presence/absence) to confirm a
# data-only refresh (Case B) advances the data record's ExpiresAt while
# leaving the KEY's own ExpiresAt untouched.
test_case_refresh_extends_data_not_key_lease() {
    log_section "REFRESH: Extends Data Lease Without Extending Key Lease"

    local case_start
    case_start=$(date +%s)

    local needle txt_spec
    needle="refresh-lease-check-$(date +%s)"
    txt_spec="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle}\""

    log_step "Registering KEY (long key-lease) + TXT (short lease)"
    register_rr_type "$CLIENT_KEY_NAME" "$LEASE_SECONDS" "$REFRESH_CASE_KEY_LEASE_SECONDS" "$(make_rr KEY "$REFRESH_CASE_KEY_LEASE_SECONDS")" "$txt_spec"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle"; then
        log_error "Refresh-lease-check: TXT record not found after initial registration"
        return 1
    fi

    local dump_before key_expires_before data_expires_before
    dump_before="$(unescape_dump_text "$(query_lease_dump "debug")")"
    key_expires_before="$(printf '%s' "$dump_before" | awk '/^  Key: /{inkey=1} inkey && /ExpiresAt:/{print $2; exit}')"
    data_expires_before="$(printf '%s' "$dump_before" | awk -v needle="$needle" '
        /RR:/ && index($0, needle) { found=1; next }
        found && /ExpiresAt:/ { print $2; exit }
    ')"
    log_step "Before refresh: KEY ExpiresAt=$key_expires_before  Data ExpiresAt=$data_expires_before"
    if [ -z "$key_expires_before" ] || [ -z "$data_expires_before" ]; then
        log_error "Refresh-lease-check: could not parse ExpiresAt values from debug dump"
        echo "$dump_before"
        return 1
    fi

    sleep 3

    log_step "Refreshing data only (Case B: KEY-LEASE=0), same TXT rdata, extending LEASE"
    run_client refresh "$CLIENT_KEY_NAME" "$LEASE_SECONDS" 0 "$txt_spec"

    local dump_after key_expires_after data_expires_after
    dump_after="$(unescape_dump_text "$(query_lease_dump "debug")")"
    key_expires_after="$(printf '%s' "$dump_after" | awk '/^  Key: /{inkey=1} inkey && /ExpiresAt:/{print $2; exit}')"
    data_expires_after="$(printf '%s' "$dump_after" | awk -v needle="$needle" '
        /RR:/ && index($0, needle) { found=1; next }
        found && /ExpiresAt:/ { print $2; exit }
    ')"
    log_step "After refresh: KEY ExpiresAt=$key_expires_after  Data ExpiresAt=$data_expires_after"

    if [ "$key_expires_after" != "$key_expires_before" ]; then
        log_error "Refresh-lease-check: KEY ExpiresAt changed from a data-only (Case B) refresh: $key_expires_before -> $key_expires_after"
        return 1
    fi
    if [[ ! "$data_expires_after" > "$data_expires_before" ]]; then
        log_error "Refresh-lease-check: Data ExpiresAt did not advance after refresh: $data_expires_before -> $data_expires_after"
        return 1
    fi

    log_case_timing "refresh-lease-check" "$case_start" 3
    log_success "Refresh extended the data lease ($data_expires_before -> $data_expires_after) without touching the key lease ($key_expires_before)"
}

# test_case_dump_vs_dig_consistency cross-checks the lease-store dump (both
# INFO and DEBUG levels) against live `dig` results at the authoritative
# server, through both registration (both present/active) and expiry (both
# absent) -- proving the dump reflects real DNS state, not just internal
# bookkeeping.
test_case_dump_vs_dig_consistency() {
    log_section "DUMP vs DIG: Lease-Store Dump Cross-Checked Against Authoritative"

    local case_start lease_start
    case_start=$(date +%s)

    local needle txt_spec node_key
    needle="dumpcheck-$(date +%s)"
    txt_spec="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle}\""
    node_key="${DOWNSTREAM_ZONE%.}.+015+05044"

    log_step "Registering KEY + TXT for dump/dig cross-check"
    lease_start=$(date +%s)
    register_rr_type "$CLIENT_KEY_NAME" "$LEASE_SECONDS" "$KEY_LEASE_SECONDS" "$(make_rr KEY "$KEY_LEASE_SECONDS")" "$txt_spec"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    if ! rr_at_auth_contains "$DOWNSTREAM_ZONE" TXT "$needle"; then
        log_error "Dump/dig check: TXT record not found at authoritative after registration"
        return 1
    fi

    log_step "Cross-checking INFO dump against authoritative state (both present)"
    local info_dump
    info_dump="$(query_lease_dump info)"
    if ! echo "$info_dump" | grep "Key: ${node_key}" | grep -q "KEY=active"; then
        log_error "Dump/dig check: INFO dump does not show KEY=active for $node_key"
        echo "$info_dump"
        return 1
    fi
    if ! echo "$info_dump" | grep "Key: ${node_key}" | grep -q "Data=1"; then
        log_error "Dump/dig check: INFO dump does not show Data=1 for $node_key"
        echo "$info_dump"
        return 1
    fi

    log_step "Cross-checking DEBUG dump contains the exact registered TXT rdata"
    local debug_dump
    debug_dump="$(query_lease_dump debug)"
    if ! echo "$debug_dump" | grep -q "$needle"; then
        log_error "Dump/dig check: DEBUG dump does not contain the registered TXT record"
        echo "$debug_dump"
        return 1
    fi

    log_step "Waiting past LEASE expiry to cross-check absence in both dump and dig"
    wait_until_epoch $((lease_start + LEASE_SECONDS + 5))
    wait_for_rr_state TXT "$txt_spec" absent

    info_dump="$(query_lease_dump info)"
    if echo "$info_dump" | grep "Key: ${node_key}" | grep -q "Data=1"; then
        log_error "Dump/dig check: INFO dump still shows Data=1 after authoritative TXT expired"
        echo "$info_dump"
        return 1
    fi
    debug_dump="$(query_lease_dump debug)"
    if echo "$debug_dump" | grep -q "$needle"; then
        log_error "Dump/dig check: DEBUG dump still shows the expired TXT record"
        echo "$debug_dump"
        return 1
    fi

    log_case_timing "dump-vs-dig-consistency" "$case_start" "$((lease_start + LEASE_SECONDS + 5 - case_start))"
    log_success "Lease-store dump (INFO and DEBUG) stayed consistent with authoritative DNS through registration and expiry"
}

################################
# Top level commands
################################
run_all_tests() {
    log_section "SIG0LEASE INTEGRATION TEST SUITE"
    echo "This suite uses live components only (no stubs/mocks):"
    echo "  - real proxy process"
    echo "  - real client process"
    echo "  - real key files"
    echo "  - real authoritative forwarding path for zenr.io"
    echo ""

    trap cleanup EXIT

    require_command grep
    require_command ls
    require_command dig
    build_binaries
    verify_keystore
    log_success "Using authoritative server for KEY checks: $AUTH_SERVER, key: $CLIENT_KEY_NAME, lease: $LEASE_SECONDS, key-lease: $KEY_LEASE_SECONDS"
    log_section "TESTING LIVE LEASE LIFECYCLE"
    test_list_keys
    start_proxy

    local rr_types=($RR_TYPES)
    local blacklisted_rrs=$(awk '
        /blacklisted_types:/ { found=1; next }
        found && /^[[:space:]]*-[[:space:]]*"/ {
        val = $0
        sub(/^[[:space:]]*-[[:space:]]*"/, "", val)
        sub(/"[[:space:]]*$/, "", val)
        types = types " " val
        }
        END {
        sub(/^ /, "", types)
        print types
        }
    ' "$CONFIG_FILE")


    log_step "Black-listed types: $blacklisted_rrs"
    
    local rr_type
    for rr_type in "${rr_types[@]}"; do
        log_section "RR TEST MATRIX: $rr_type"
        # Reset via the shared client KEY, not a per-type rdata: deleting the
        # KEY lease (Case C) cascades and removes every data lease under it
        # (see handlers/opcode5_handle.go Case C subtree cleanup), so this is
        # the correct pristine-state reset regardless of $rr_type.
        ensure_rr_absent KEY "$CLIENT_KEY_RR"
        if [[ " $blacklisted_rrs " == *" $rr_type "* ]]; then
            test_blacklisted_type $rr_type
        else
            test_single_rr_register_expire_remove "$rr_type"
            ensure_rr_absent KEY "$CLIENT_KEY_RR"
            test_case_register_refresh_not_prematurely_removed "$rr_type"
            ensure_rr_absent KEY "$CLIENT_KEY_RR"
            test_case_split_lease_nonkey_expires_key_persists "$rr_type"
            ensure_rr_absent KEY "$CLIENT_KEY_RR"
            test_case_unauthorized_refresh_rejected_then_expires "$rr_type"
        fi
    done

    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    test_case_overlapping_registrations_issue17

    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    test_case_abcd_lease_policy_matrix
    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    test_case_signer_location_matrix
    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    test_case_multi_rr_combination_registration
    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    test_case_refresh_extends_data_not_key_lease
    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    test_case_dump_vs_dig_consistency
    ensure_rr_absent KEY "$CLIENT_KEY_RR"

    log_section "TEST RESULTS"
    echo -e "${GREEN}All integration tests completed successfully!${NC}"
    echo ""
    echo "Summary of what was tested:"
    echo "  [OK] Register -> expire -> removed (KEY/TXT/A/AAAA)"
    echo "  [OK] Register -> refresh -> split lease behavior (KEY/TXT/A/AAAA)"
    echo "  [OK] LEASE < KEY-LEASE -> non-KEY records expire while KEY remains"
    echo "  [OK] Unauthorized refresh rejected, lease still expires (KEY/TXT/A/AAAA)"
    echo "  [OK] Issue #17: overlapping registrations do not leave permanent stale RR"
    echo "  [OK] Proxy consistency checks use refresh path"
    echo "  [OK] Explicit Case A/B/C/D lease-policy matrix"
    echo "  [OK] Signer-location matrix (Update/Additional/lease-store/online-only)"
    echo "  [OK] Multi-RR combination registration in a single Update"
    echo "  [OK] Refresh extends data lease without extending key lease (dump-verified)"
    echo "  [OK] Lease-store dump (INFO/DEBUG) cross-checked against dig at authoritative"
    echo ""
    echo "Proxy process was exercised at $PROXY_URL"
    echo "Logs: $LOG_FILE"
}

cleanup() {
    set +e
    log_section "CLEANUP"

    if [ ! -z "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        log_step "Restoring pristine KEY state before shutdown"
        ensure_rr_absent KEY "$CLIENT_KEY_RR" || true
    fi

    stop_proxy

    if [ -n "$TMP_CONFIG_FILE" ] && [ -f "$TMP_CONFIG_FILE" ]; then
        rm -f "$TMP_CONFIG_FILE"
    fi

    set -e
}

################################
# Menu
################################

case "${1:-run}" in
    run)
        run_all_tests
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo "Usage: $0 [run|cleanup]"
        echo "  run     - Run all live integration tests"
        echo "  cleanup - Stop proxy"
        exit 1
        ;;
esac
