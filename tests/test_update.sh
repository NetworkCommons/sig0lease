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

# Decide up front whether we'll run our own proxy (against a scratch config
# with min_*_lease_sec floored to TEST_MIN_LEASE_SECONDS) or reuse one
# already listening (whose real policy we read from CONFIG_FILE instead) --
# must happen before the yaml_get_lease_time calls below, since they read
# whichever file this settles on.
prepare_lease_config

# Lease times
POLICY_MIN_RR_LEASE_SECONDS="$(yaml_get_lease_time min_rr_lease_sec)"
POLICY_MIN_KEY_LEASE_SECONDS="$(yaml_get_lease_time min_key_lease_sec)"

LEASE_SECONDS="${LEASE_SECONDS:-$POLICY_MIN_RR_LEASE_SECONDS}"
KEY_LEASE_SECONDS="${KEY_LEASE_SECONDS:-$POLICY_MIN_KEY_LEASE_SECONDS}"
# Case 2 validates refresh behavior under split-lease policy: keep KEY alive longer.
# Scaled off the policy minimum (120x) so it stays well beyond any test's own
# runtime without actually being waited out -- ratio matches the original
# fixed defaults (3600s at the real policy min of 30s).
LONG_KEY_LEASE_SECONDS="${LONG_KEY_LEASE_SECONDS:-$((POLICY_MIN_KEY_LEASE_SECONDS * 120))}"
# Floored at 5s: below that, the gap between the two overlapping
# registrations in test 5 stops leaving enough room for the first
# registration's effects to be observed before the second one lands.
OVERLAP_DELAY_SECONDS="${OVERLAP_DELAY_SECONDS:-$(( POLICY_MIN_RR_LEASE_SECONDS / 3 > 5 ? POLICY_MIN_RR_LEASE_SECONDS / 3 : 5 ))}"
BUFFER=2
# Grace window proxy_consistent_with_authoritative gives the internal lease
# store to converge with authoritative DNS: the proxy publishes/reaps
# asynchronously (local removal happens only after the upstream delete
# succeeds), so a bare snapshot right after wait_for_rr_state can still be
# mid-flight. Only actually waited out on the failure path.
LEASE_STORE_SETTLE_SECONDS="${LEASE_STORE_SETTLE_SECONDS:-$(( POLICY_MIN_RR_LEASE_SECONDS / 2 < 5 ? POLICY_MIN_RR_LEASE_SECONDS / 2 : 5 ))}"

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

PERFORMED_TESTS=""

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
time_tag(){
    echo $(date +%d_%m_%Y_%H_%M_%S_%N)
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
# Transport is controlled by PROXY_PROTOCOL (see utils.sh; defaults to udp,
# same udp-unless-told-otherwise mechanism as PROXY_ADDR/PROXY_PORT) --
# every call site gets --tcp for free when PROXY_PROTOCOL=tcp, no call site
# needs to pass it itself.
run_client() {
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

assert_proxy_log_contains() {
    local pattern="$1"
    if grep -q "$pattern" "$LOG_FILE"; then
        return 0
    fi
    log_error "Expected proxy log pattern not found: $pattern"
    tail -n 120 "$LOG_FILE" || true
    return 1
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
# Lease Dump functions
################################

# lease_dump <level> -- query the running proxy's internal lease-store dump
# endpoint and print it as readable, line-oriented text.
#
# dig +short hands back the dump in DNS <character-string> presentation form --
# embedded control bytes rendered as literal \DDD (decimal, per RFC 1035), and
# a dump longer than one 240-byte TXT string split across several TXT RRs /
# output lines. lease_dump strips the per-line quoting, rejoins the chunks, and
# decodes the \DDD / \" / \\ escapes, so the result has real newlines and tabs
# and can be printed as-is OR fed straight to grep/awk (and to the
# lease_store_* helpers below).
#
#   level: "debug" -> full per-record dump via __dump.sig0lease.internal.debug.
#          "info"  -> one-line-per-key summary via __dump.sig0lease.internal.
#
# The "[dig] @..." progress line goes to stderr, so stdout is pure dump text.
# printf (not echo) feeds the pipeline, since some shells' builtin echo would
# reinterpret the backslash escapes before sed/perl ever see them.
lease_dump() {
    local level="${1:-info}"
    local query_domain dump_label
    case "$level" in
        debug)
            query_domain="__dump.sig0lease.internal.debug."
            dump_label="DEBUG/full"
            ;;
        info|*)
            level="info"
            query_domain="__dump.sig0lease.internal."
            dump_label="INFO/summary"
            ;;
    esac

    local raw
    raw=$(dig_query_short "$PROXY_URL" "${query_domain}" TXT)

    # Test script's own log level, independent from proxy logging; to stderr
    # so a `foo="$(lease_dump ...)"` capture stays clean.
    printf '  [%s] [dig] @%s %s TXT (%s)\n' \
        "$(printf '%s' "$level" | tr '[:lower:]' '[:upper:]')" \
        "$PROXY_URL" "$query_domain" "$dump_label" >&2

    if [ -z "$raw" ]; then
        echo "(no dump response)"
        return 0
    fi

    printf '%s\n' "$raw" | sed 's/^"//; s/"$//' | tr -d '\n' \
        | perl -pe 's/\\(\d{3})/chr($1)/ge; s/\\"/"/g; s/\\\\/\\/g'
}

# lease_store_has_rr <rr_type> <rr-spec> [debug-dump] -- succeeds (0) when the
# proxy's INTERNAL lease store currently holds a live record matching
# <rr-spec>, read from the DEBUG lease-store dump. This is the internal-state
# counterpart to rr_at_authoritative (which checks the authoritative DNS).
# Pass a pre-fetched `lease_dump debug` as the 3rd arg to avoid re-querying.
#   KEY   -> matched on "KeyRR:" lines; a key block flagged "IsExpired: true"
#            (expired but not yet reaped) counts as absent.
#   other -> matched on the non-KEY "RR:" lines.
# Echoes a one-line present/absent result (silence it with >/dev/null).
lease_store_has_rr() {
    local rr_type="$1" rr_spec="$2" dump="${3:-}"
    [ -n "$dump" ] || dump="$(lease_dump debug)"

    local disc norm present
    disc="$(get_rdata "$rr_spec")"
    norm="$(printf '%s\n' "$dump" | tr '\t' ' ' | sed -E 's/  +/ /g')"
    present=1

    if [ "$rr_type" = "KEY" ]; then
        # `expd` not `exp` -- `exp` is an awk builtin (mawk rejects it as an lvalue).
        printf '%s\n' "$norm" | awk -v disc="$disc" '
            /^ *Key: /                    { if (m && !expd) f=1; m=0; expd=0 }
            /KeyRR: / && index($0, disc)  { m=1 }
            /IsExpired: true/             { expd=1 }
            END { if (m && !expd) f=1; exit f ? 0 : 1 }
        ' || present=0
    else
        printf '%s\n' "$norm" | grep -E '^ *RR: ' | grep -Fq -- " $disc" || present=0
    fi

    if [ "$present" -eq 1 ]; then
        echo "lease-store: $rr_type present -- $disc"
        return 0
    fi
    echo "lease-store: $rr_type absent -- $disc"
    return 1
}

# lease_store_key_expires_at <key-rdata|""> [debug-dump] -- print the KEY
# lease's ExpiresAt (RFC3339) from a DEBUG dump. Empty first arg -> the first
# KEY block; otherwise the block whose KeyRR matches the given rdata/rr-spec.
lease_store_key_expires_at() {
    local want="$1" dump="${2:-}"
    [ -n "$dump" ] || dump="$(lease_dump debug)"
    local disc=""
    [ -n "$want" ] && disc="$(get_rdata "$want")"
    printf '%s\n' "$dump" | tr '\t' ' ' | sed -E 's/  +/ /g' | awk -v disc="$disc" '
        /^ *Key: /                        { inkey = (disc == "") }
        disc != "" && /KeyRR: / && index($0, disc) { inkey = 1 }
        inkey && /ExpiresAt: /            { print $2; exit }
    '
}

# lease_store_rr_expires_at <needle> [debug-dump] -- print the non-KEY
# record's ExpiresAt (RFC3339) for the record whose "RR:" line contains
# <needle>, from a DEBUG dump.
lease_store_rr_expires_at() {
    local needle="$1" dump="${2:-}"
    [ -n "$dump" ] || dump="$(lease_dump debug)"
    printf '%s\n' "$dump" | tr '\t' ' ' | sed -E 's/  +/ /g' | awk -v needle="$needle" '
        /^ *RR: / && index($0, needle) { found = 1; next }
        found && /ExpiresAt: /          { print $2; exit }
    '
}

# lease_store_summary_line <node_key> [info-dump] -- the INFO-summary line for
# <node_key> ("Key: <nodekey>  KEY=<..>  NonKEY=<n>  Status=<..>"), or empty.
lease_store_summary_line() {
    local node_key="$1" dump="${2:-}"
    [ -n "$dump" ] || dump="$(lease_dump info)"
    printf '%s\n' "$dump" | grep -F -- "Key: ${node_key} " || true
}

# proxy_consistent_with_authoritative <rr_type> <rr-spec> <expected_state>
#   expected_state: present | absent
#
# Asserts that the record is in <expected_state> at BOTH the authoritative
# DNS and the proxy's INTERNAL lease store -- and that the two agree with
# each other. The lease store is read from the DEBUG dump via
# lease_store_has_rr (the same reconstruction/matching the dump-inspection
# tests use). Since the proxy publishes and reaps asynchronously (a record is
# only dropped locally once its upstream delete has actually landed), the
# lease-store side is polled for up to LEASE_STORE_SETTLE_SECONDS to converge
# before the check is enforced -- so a call right after wait_for_rr_state
# does not race the proxy's own bookkeeping.
proxy_consistent_with_authoritative() {
    local rr_type="$1"
    local rr_rdata="$2"
    local expected_state="$3"  # present|absent
    local auth_present="$4"

    log_file proxy_consistent_with_authoritative "rr_type=$rr_type, rr_rdata=$rr_rdata, expected_state=$expected_state."

    local want_present=0
    [ "$expected_state" = "present" ] && want_present=1

    # # Authoritative DNS -- the source of truth these tests drive toward.
    # local auth_present=0
    # if rr_at_authoritative "$rr_type" "$rr_rdata" >/dev/null; then
    #     auth_present=1
    # fi

    # Internal lease store, given a short window to catch up.
    local store_present deadline
    deadline=$(( $(date +%s) + LEASE_STORE_SETTLE_SECONDS ))
    while :; do
        store_present=0
        if lease_store_has_rr "$rr_type" "$rr_rdata" >/dev/null; then
            store_present=1
        fi
        [ "$store_present" -eq "$want_present" ] && break
        [ "$(date +%s)" -ge "$deadline" ] && break
        sleep 1
    done

    local ok=1
    if [ "$auth_present" -ne "$want_present" ]; then
        log_error "Consistency check: authoritative state ($auth_present) != expected $expected_state for $rr_type - $rr_rdata"
        ok=0
    fi
    if [ "$store_present" -ne "$want_present" ]; then
        log_error "Consistency check: internal lease store state ($store_present) != expected $expected_state for $rr_type - $rr_rdata"
        ok=0
    fi
    if [ "$auth_present" -ne "$store_present" ]; then
        log_error "Consistency check: internal lease store ($store_present) and authoritative ($auth_present) disagree for $rr_type - $rr_rdata"
        ok=0
    fi

    if [ "$ok" -ne 1 ]; then
        log_step "Lease-store DEBUG dump at failure:"
        lease_dump debug || true
        return 1
    fi

    log_success "Consistency check passed ($expected_state at authoritative and internal lease store) for $rr_type - $rr_rdata"
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
        TXT) echo "${DOWNSTREAM_ZONE} ${ttl} IN TXT \"lease-txt-$(time_tag)\"" ;;
        A) echo "${DOWNSTREAM_ZONE} ${ttl} IN A 192.0.2.33" ;;
        AAAA) echo "${DOWNSTREAM_ZONE} ${ttl} IN AAAA 2001:db8::33" ;;
        # NULL and NXNAME have no presentation format in miekg/dns,
        # so they cannot be constructed via the client binary's
        # ParseAdditionalRRSpec (which uses dns.New). They are
        # tested at the unit-test level (handlers opcode5 behavior tests).
        NULL) log_step "Skipping NULL: no presentation format in miekg/dns" ;;
        NXNAME) log_step "Skipping NXNAME: no presentation format in miekg/dns" ;;
        WALLET) echo "${DOWNSTREAM_ZONE} ${ttl} IN WALLET \"wallet-data-$(time_tag)\"" ;;
        CLA) echo "${DOWNSTREAM_ZONE} ${ttl} IN CLA \"cla-data-$(time_tag)\"" ;;
        IPN) echo "${DOWNSTREAM_ZONE} ${ttl} IN IPN 42" ;;
        *)
            log_error "Unsupported rr type: $rr_type"
            return 1
            ;;
    esac
}

# build_key_nonkey_rr <rr_type> <ttl> -- sets the global array KEY_NONKEY_RRs to
# the rr-specs needed for a valid Case A (KEY-LEASE!=0 and LEASE!=0)
# registration/refresh of <rr_type>. Case A always requires an explicit KEY
# rr-spec in the Update section (even for a pure refresh of an
# already-managed key) alongside at least one non-KEY rr-spec, so this always
# includes a KEY rr-spec paired with either a companion TXT record (if
# rr_type is itself KEY) or the type's own spec.
build_key_nonkey_rr() {
    local rr_type="$1"
    local ttl="$2"
    local key_spec
    key_spec="$(make_rr KEY "$ttl")"
    if [ "$rr_type" = "KEY" ]; then
        KEY_NONKEY_RRs=("$key_spec" "$(make_rr TXT "$ttl")")
    else
        KEY_NONKEY_RRs=("$key_spec" "$(make_rr "$rr_type" "$ttl")")
    fi
}

################################
# Tests
################################
test_blacklisted_type() {
# Test blacklisted RR types by constructing them programmatically.
# NULL and NXNAME cannot be constructed via presentation format (miekg/dns limitation),
# so we use a small Go helper that constructs these records directly and sends them.

    local rr_type=$1
    
    local log_msg="TEST 4: Proxy Rejects Blacklisted Type ($rr_type)"
    log_section "$log_msg"

    log_step "Registering lease with blacklisted type"
    local lease_start

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
            rr_spec=$(make_rr "$rr_type" $LEASE_SECONDS)
            log_step "Attempting registration with blacklisted type $rr_type"
            # Both LEASE and KEY-LEASE nonzero (Case A) requires a companion
            # KEY rr-spec in the Update section, or the client rejects the
            # request itself before it ever reaches the proxy.
            reg_out=$(run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS $KEY_LEASE_SECONDS "$(make_rr KEY $KEY_LEASE_SECONDS)" "$rr_spec" 2>&1) || true
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
    if rr_at_authoritative KEY $CLIENT_KEY_RR; then
        log_error "Blacklisted type $rr_type rejected but key lease created"
        return 1
    else
        log_success "Blacklisted type $rr_type rejected and no lease created"
    fi
    
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_single_rr_register_expire_remove() {
    local rr_type="$1"

    local log_msg="TEST 1: Register -> Expire -> Removed ($rr_type)"
    log_section "$log_msg"

    local rr_spec lease lease_start expected_min

    case $rr_type in
        KEY)
            local lease_time=0
            local key_lease_time=$KEY_LEASE_SECONDS
            lease=$key_lease_time
            rr_spec="$(make_rr $rr_type $lease)"
            ;;
        *)
            # A non-KEY-only registration is Case B, which requires the
            # signer to already be lease-managed -- not true at this point in
            # a fresh run. So register via Case A (KEY+non-KEY records
            # together, both timers equal so they expire together) instead,
            # mirroring the build_key_nonkey_rr pattern used by Cases 2/2B/3.
            local lease_time=$LEASE_SECONDS
            local key_lease_time=$LEASE_SECONDS
            lease=$lease_time
            build_key_nonkey_rr "$rr_type" "$lease"
            rr_spec="${KEY_NONKEY_RRs[1]}"
            ;;
    esac

    log_step "Registering lease "
    lease_start=$(date +%s)
    if [ "$rr_type" = "KEY" ]; then
        run_client register $CLIENT_KEY_NAME $lease_time $key_lease_time "$rr_spec"
    else
        run_client register $CLIENT_KEY_NAME $lease_time $key_lease_time "${KEY_NONKEY_RRs[@]}"
        wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    fi
    wait_for_rr_state $rr_type "$rr_spec" present

    # Verify lease store via dump query (INFO level summary).
    log_step "Verifying lease store state via dump query (DEBUG)"
    lease_dump debug

    log_step "Waiting until lease expiry boundary"
    wait_until_epoch $((lease_start + lease + BUFFER))

    # RR should be gone before we exercise post-expiry behavior.
    wait_for_rr_state "$rr_type" "$rr_spec" absent

    if [ "$rr_type" = "KEY" ]; then
        log_step "Attempting refresh after expiry (KEY path: expected to re-register)"
        run_client refresh "$CLIENT_KEY_NAME" 0 $LEASE_SECONDS "$rr_spec"
        wait_for_rr_state KEY "$rr_spec" present
        log_success "Expired KEY refresh succeeded via re-registration semantics"
    else
        # Both KEY and data expired together above, so the signer is no
        # longer lease-managed: a non-KEY-only (Case B) refresh attempt must be
        # refused for that reason, not because "the lease does not exist"
        # (that message is Case D's validateRefreshOwnership path, which
        # this request never reaches). Assert on the client-visible Rcode
        # plus the actual Case B rejection text, not a guessed string.
        log_step "Attempting refresh after expiry (non-KEY path: expected failure, signer no longer managed)"
        local post_expiry_out
        if post_expiry_out=$(run_client refresh "$CLIENT_KEY_NAME" $LEASE_SECONDS 0 "$rr_spec" 2>&1); then
            log_error "Refresh succeeded after expiry, expected failure"
            echo "$post_expiry_out"
            return 1
        fi
        if ! echo "$post_expiry_out" | grep -q "Status: REFUSED (Rcode=5)"; then
            log_error "Expected REFUSED (Rcode=5) for post-expiry non-KEY-only refresh, got:"
            echo "$post_expiry_out"
            return 1
        fi
        wait_for_rr_state $rr_type "$rr_spec" absent
        # "requires signing KEY to already be managed" is the *response*
        # message text (never passed to h.logger), not what actually lands
        # in the proxy's own log -- assert on the real logged reason instead.
        assert_proxy_log_contains "signing key not found in lease store"
    fi

    expected_min=$((lease + BUFFER))

    log_case_timing "case1-${rr_type}" "$lease_start" "$expected_min"
    log_success "Case 1 post-expiry behavior validated for $rr_type"
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_case_register_refresh_not_prematurely_removed() {
    local rr_type="$1"

    local log_msg="TEST 2: Register -> Refresh -> Not Prematurely Removed (Case A) ($rr_type)"
    log_section "$log_msg"

    local lease_start refresh_start expected_min data_spec data_type

    build_key_nonkey_rr "$rr_type" $LEASE_SECONDS
    data_spec="${KEY_NONKEY_RRs[1]}"
    # build_key_nonkey_rr pairs a KEY registration with a TXT companion (Case
    # A needs a non-KEY record too), so data_spec's actual RR type is TXT
    # when rr_type is KEY -- never $rr_type itself in that case.
    if [ "$rr_type" = "KEY" ]; then
        data_type="TXT"
    else
        data_type="$rr_type"
    fi
    log_step "Registering initial lease (LEASE=$LEASE_SECONDS, KEY-LEASE=$LONG_KEY_LEASE_SECONDS)"
    lease_start=$(date +%s)
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS $LONG_KEY_LEASE_SECONDS "${KEY_NONKEY_RRs[@]}"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$data_type" "$data_spec" present

    # Verify lease store via dump query (INFO level summary).
    log_step "Verifying lease store state via dump query (INFO) after initial registration"
    lease_dump info

    log_step "Waiting to near-expiry checkpoint then refreshing $data_type"
    wait_until_epoch $((lease_start + (LEASE_SECONDS * 2 / 3)))
    refresh_start=$(date +%s)
    # Only the non-KEY RR in the payload
    run_client refresh "$CLIENT_KEY_NAME" $LEASE_SECONDS 0 "${KEY_NONKEY_RRs[1]}"
    if ! rr_at_authoritative KEY "$CLIENT_KEY_RR"; then
        log_error "KEY not found after non-KEY refresh"
        return 1
    fi
    if ! rr_at_authoritative "$data_type" "$data_spec"; then
        log_error ""$data_type" not found after refresh"
        return 1
    fi

    log_step "Waiting past original expiry window"
    wait_until_epoch $((lease_start + LEASE_SECONDS + BUFFER))

    if ! rr_at_authoritative KEY "$CLIENT_KEY_RR"; then
        log_error "KEY not found after non-KEY lease time expiry"
        return 1
    fi
    if ! rr_at_authoritative "$data_type" "$data_spec"; then
        log_error ""$data_type" not found after initial lease time expiry (refresh ignored)"
        return 1
    fi

    log_step "Waiting for refreshed non-KEY lease window while key-lease remains active"
    wait_until_epoch $((refresh_start + LEASE_SECONDS + BUFFER))
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$data_type" "$data_spec" absent

    expected_min=$((LEASE_SECONDS * (1 + 2 / 3) + BUFFER))

    log_case_timing "case2-${rr_type}" "$lease_start" "$expected_min"
    log_success "Lease behavior validated after renewal for $rr_type"
    
    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_case_overlapping_registrations() {
    
    local log_msg="TEST 5: Overlapping Registrations Must Not Leave Permanent RR"
    log_section "$log_msg"

    local first_start second_start expected_min
    local ts1
    ts1=$(time_tag)

    local rr1_a rr1_txt rr2_a rr2_txt
    rr1_a="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN A 192.0.2.99"
    rr1_txt="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"overlapping_registrations-first-${ts1}_1\""
    sleep 1
    rr2_a="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN A 192.0.2.100"
    rr2_txt="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"overlapping_registrations-second-${ts1}_2\""

    log_step "First registration (A+TXT set #1)"
    first_start=$(date +%s)
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS $LONG_KEY_LEASE_SECONDS "$(make_rr KEY $LONG_KEY_LEASE_SECONDS)" "$rr1_a" "$rr1_txt"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    if ! rr_at_authoritative A "$rr1_a"; then
        log_error "Expected first A record to be visible after first registration"
        return 1
    fi
    if ! rr_at_authoritative TXT "$rr1_txt"; then
        log_error "Expected first TXT record to be visible after first registration"
        return 1
    fi

    log_step "Waiting ${OVERLAP_DELAY_SECONDS}s before overlapping registration"
    sleep "$OVERLAP_DELAY_SECONDS"

    log_step "Second overlapping registration (A+TXT set #2)"
    second_start=$(date +%s)
    # We do not need to send the KEY again, by now it is known by the Proxy
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS 0  "$rr2_a" "$rr2_txt"

    if ! wait_for_rr_state A "$rr2_a" present; then
        log_error "Expected second A record to be visible after overlapping registration"
        return 1
    fi
    if ! wait_for_rr_state TXT "$rr2_txt" present; then
        log_error "Expected second TXT record to be visible after overlapping registration"
        return 1
    fi

    log_step "Waiting for RR lease expiry to verify old and new non-KEY leases are both cleaned"
    wait_until_epoch $((second_start + LEASE_SECONDS + BUFFER))

    if ! wait_for_rr_state A "$rr1_a" absent || ! wait_for_rr_state A "$rr2_a" absent; then
        log_error "A record(s) from overlapping registrations were not cleaned up"
        return 1
    fi
    if ! wait_for_rr_state A "$rr1_txt" absent || ! wait_for_rr_state A "$rr2_txt" absent; then
        log_error "TXT record(s) from overlapping registrations were not cleaned up"
        return 1
    fi
    
    expected_min=$((OVERLAP_DELAY_SECONDS + LEASE_SECONDS + BUFFER))

    log_case_timing "case4-overlap" "$first_start" "$expected_min"
    log_success "Regression check passed: overlapping RR sets were not forgotten/permanent"

    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

test_case_unauthorized_refresh_rejected_then_expires() {
    local rr_type="$1"
    
    local log_msg="TEST 3: Unauthorized Refresh Rejected -> Lease Expires ($rr_type)"
    log_section "$log_msg"

    local lease_start expected_min data_spec data_type

    build_key_nonkey_rr "$rr_type" $LEASE_SECONDS
    data_spec="${KEY_NONKEY_RRs[1]}"
    # build_key_nonkey_rr pairs a KEY registration with a TXT companion, so
    # data_spec's actual RR type is TXT when rr_type is KEY (see Case 2).
    if [ "$rr_type" = "KEY" ]; then
        data_type="TXT"
    else
        data_type="$rr_type"
    fi
    log_step "Registering lease under authorized key ($CLIENT_KEY_NAME)"
    lease_start=$(date +%s)
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS $KEY_LEASE_SECONDS "${KEY_NONKEY_RRs[@]}"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state "$data_type" "$data_spec" present

    log_step "Unauthorized refresh attempt using unregistered different key ($WRONG_CLIENT_KEY_NAME)"
    local unauth_out
    # Both LEASE and KEY-LEASE nonzero (Case A) requires a companion KEY
    # rr-spec in the Update section. Include the *original* (CLIENT_KEY_NAME)
    # KEY rdata here -- not WRONG's -- signed by WRONG_CLIENT_KEY_NAME: this
    # reproduces the exact scenario the proxy is meant to reject (a
    # transaction signature from a different, unmanaged key over data it
    # doesn't own), matching the resolved HANDOFF experiment.
    if unauth_out=$(run_client refresh "$WRONG_CLIENT_KEY_NAME" $LEASE_SECONDS 0 "$data_spec" 2>&1); then
        log_error "Unauthorized refresh unexpectedly succeeded"
        return 1
    fi

    # WRONG_CLIENT_KEY_NAME is a distinct, never-registered key (different
    # keytag), so the proxy rejects it via the online-signer-authorization 
    # path ("signer not authorized for new registration").
    # Assert on the client-visible Rcode.
    if ! echo "$unauth_out" | grep -q "Status: REFUSED (Rcode=5)"; then
        log_error "Expected REFUSED (Rcode=5) for unauthorized refresh, got:"
        echo "$unauth_out"
        return 1
    fi

    assert_proxy_log_contains "signing key not found in lease store"

    # Now register WRONG_CLIENT_KEY_NAME to test a non-owner rejection
    # for the refresh operation
    log_step "Register different key ($WRONG_CLIENT_KEY_NAME)"
    local wrong_key_rr
    wrong_key_rr="$(make_rr KEY $LEASE_SECONDS 1)"
    run_client register "$WRONG_CLIENT_KEY_NAME" 0 $LEASE_SECONDS  "$wrong_key_rr"
    wait_for_rr_state KEY "$wrong_key_rr" present
    
    log_step "Refresh RR with different non-owner key ($WRONG_CLIENT_KEY_NAME)"
    local nonowner_out
    if nonowner_out=$(run_client refresh "$WRONG_CLIENT_KEY_NAME" $LEASE_SECONDS 0 "$data_spec" 2>&1); then
        log_error "Non-owner refresh unexpectedly succeeded"
        echo "$nonowner_out"
        return 1
    fi
    # WRONG_CLIENT_KEY_NAME is not the owner of the previously registered RR
    # so the proxy rejects it.
    # Assert on the client-visible Rcode.
    if ! echo "$nonowner_out" | grep -q "Status: REFUSED (Rcode=5)"; then
        log_error "Expected REFUSED (Rcode=5) for unauthorized refresh, got:"
        echo "$nonowner_out"
        return 1
    fi

    assert_proxy_log_contains "duplicate registration rejected:"

    log_step "Waiting until original lease expires"
    wait_until_epoch $((lease_start + KEY_LEASE_SECONDS + BUFFER))

    wait_for_rr_state KEY "$CLIENT_KEY_RR" absent
    wait_for_rr_state KEY "$WRONG_CLIENT_KEY_RR" absent
    wait_for_rr_state "$data_type" "$data_spec" absent
    
    expected_min=$((KEY_LEASE_SECONDS + BUFFER))

    log_case_timing "case3-${rr_type}" "$lease_start" "$expected_min"
    log_success "Unauthorized refresh rejected and lease expired as expected for $rr_type"

    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

# test_case_abcd_lease_policy_matrix walks deliberately through all four
# lease-policy dispatch cases in handlers/opcode5_handle.go, in the order
# A -> D -> B -> C, using a single KEY (CLIENT_KEY_NAME) and two TXT records
# so each transition's effect on the other records is directly observable:
#   A: KEY-LEASE!=0, LEASE!=0 -- full registration (KEY + txt_a together)
#   D: KEY-LEASE!=0, LEASE=0  -- key-only refresh, must not disturb txt_a
#   B: KEY-LEASE=0,  LEASE!=0 -- non-KEY-only registration of txt_b under the
#      already-managed key, coexisting with txt_a
#   C: KEY-LEASE=0,  LEASE=0  -- delete matrix: first a non-KEY-only delete
#      (txt_b only), then a KEY delete that cascades and removes txt_a too
test_case_abcd_lease_policy_matrix() {
    
    local log_msg="CASE A/B/C/D: Explicit Lease-Policy Matrix"
    log_section "$log_msg"

    local case_start
    case_start=$(date +%s)

    local needle_a needle_b txt_a txt_b
    needle_a="caseA-$(time_tag)"
    txt_a="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle_a}\""

    log_step "Case A (KEY-LEASE!=0, LEASE!=0): full registration of KEY+TXT"
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS $LONG_KEY_LEASE_SECONDS "$(make_rr KEY $LONG_KEY_LEASE_SECONDS)" "$txt_a"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    wait_for_rr_state TXT "$txt_a" present

    lease_dump info
    log_success "Case A: KEY+TXT registered together"

    log_step "Case D (KEY-LEASE!=0, LEASE=0): key-only refresh must leave data untouched"
    run_client refresh "$CLIENT_KEY_NAME" 0 $LONG_KEY_LEASE_SECONDS "$(make_rr KEY $LONG_KEY_LEASE_SECONDS)"

    if ! rr_at_authoritative KEY "$CLIENT_KEY_RR"; then
        log_error "Case D: key-only refresh but key absent at authoritative"
        return 1
    fi
    if ! rr_at_authoritative TXT "$txt_a"; then
        log_error "Case D: key-only refresh unexpectedly disturbed the Case A TXT record"
        return 1
    fi
    log_success "Case D: key-only refresh left Case A's TXT record untouched"

    needle_b="caseB-$(time_tag)"
    txt_b="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle_b}\""
    log_step "Case B (KEY-LEASE=0, LEASE!=0): non-KEY-only registration under the already-managed signer"
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS 0 "$txt_b"
    
    if ! wait_for_rr_state TXT "$txt_b" present; then
        log_error "Case B: new non-KEY-only TXT record not found at authoritative"
        return 1
    fi
    if ! rr_at_authoritative TXT "$txt_a"; then
        log_error "Case B: original Case A TXT record disappeared"
        return 1
    fi
    lease_dump debug
    log_success "Case B: non-KEY-only registration added a second TXT record alongside the first"

    log_step "Case C (KEY-LEASE=0, LEASE=0): non-KEY-only delete removes just txt_b"
    run_client refresh "$CLIENT_KEY_NAME" 0 0 "$txt_b"

    if ! wait_for_rr_state TXT "$txt_b" absent; then
        log_error "Case C: targeted TXT delete did not remove txt_b"
        return 1
    fi
    if ! rr_at_authoritative KEY "$CLIENT_KEY_RR"; then
        log_error "Case C: targeted TXT delete removed KEY"
        return 1
    fi
    if ! rr_at_authoritative TXT "$txt_a"; then
        log_error "Case C: non-KEY-only delete unexpectedly removed txt_a too"
        return 1
    fi
    
    log_success "Case C: non-KEY-only delete removed txt_b while KEY and txt_a remained"

    log_step "Case C (KEY-LEASE=0, LEASE=0): KEY delete cascades and removes remaining data"
    run_client refresh "$CLIENT_KEY_NAME" 0 0 "$(make_rr KEY 0)"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" absent
    if rr_at_authoritative TXT "$txt_a"; then
        log_error "Case C: KEY delete did not cascade-remove remaining txt_a"
        return 1
    fi
    log_success "Case C: KEY delete cascaded and removed the remaining non-KEY lease"

    log_case_timing "case-abcd-matrix" "$case_start" 0
    log_success "Lease-policy Case A/B/C/D matrix (A -> D -> B -> C) validated end-to-end"

    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

# test_case_signer_location_matrix exercises all four ways the proxy can
# resolve a SIG(0) signer's KEY material (handlers/opcode5_update_helpers.go
# extractAndValidateSig0's three-stage fallback, split into four physical
# placements): Update section, Additional section, lease store (omitted from
# the request, already registered), and authoritative DNS (omitted, published
# online via add_rr, never registered through the proxy at all).
#
# Steps 1-3 reuse CLIENT_KEY_NAME across a self-registration (Update) and two
# non-KEY-only refreshes (Additional, then lease-store), since Case B forbids a
# KEY rr-spec in the Update section entirely (KEY-LEASE == 0) -- a way to prove
# Additional/omitted signer resolution (an alternative would have been case D - delete 
# non-KEY RR, with no KEY in the Update section). Step 4 uses WRONG_CLIENT_KEY_NAME,
# published directly at authoritative and never registered through the
# proxy, to reach the authoritative-only fallback stage.
test_case_signer_location_matrix() {
    
    local log_msg="CASE SIGNER LOCATION MATRIX: Update / Additional / Lease-Store / Online-Only"
    log_section "$log_msg"

    local case_start
    case_start=$(date +%s)

    local needle1 needle2 needle3 txt1 txt2 txt3
    needle1="signerloc-update-$(time_tag)"
    txt1="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle1}\""

    log_step "Signer location 1/4: Update section (self-registration, Case A)"
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS $LONG_KEY_LEASE_SECONDS "$(make_rr KEY $LONG_KEY_LEASE_SECONDS)" "$txt1" --signer=update
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    if ! rr_at_authoritative TXT "$txt1"; then
        log_error "Signer-location[update]: expected TXT record not found"
        return 1
    fi
    log_success "Signer-location[update]: signer KEY resolved from the Update section"

    needle2="signerloc-additional-$(time_tag)"
    txt2="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle2}\""
    
    log_step "Signer location 2/4: Additional section (non-KEY-only refresh, Case B)"
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS 0 "$txt2" --signer=additional
    if ! wait_for_rr_state TXT "$txt2" present; then
        log_error "Signer-location[additional]: expected TXT record not found"
        return 1
    fi
    log_success "Signer-location[additional]: signer KEY resolved from the Additional section"

    needle3="signerloc-leasestore-$(time_tag)"
    txt3="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle3}\""
    
    log_step "Signer location 3/4: omitted from request, resolved via lease store (Case B)"
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS 0 "$txt3" --signer=none
    if ! wait_for_rr_state TXT "$txt3" present; then
        log_error "Signer-location[lease-store]: expected TXT record not found"
        return 1
    fi
    log_success "Signer-location[lease-store]: signer KEY resolved from the lease store (omitted from request)"

    log_step "Signer location 4/4: omitted from request, resolved via authoritative DNS (online-only, never registered through the proxy)"
    local wrong_key_payload probe_needle probe_txt_rr probe_out
    wrong_key_payload="$(get_rdata "${WRONG_CLIENT_KEY_RR}")"
    # Add the key directly to the Authoritative DNS
    add_rr "$wrong_key_payload" 60
    
    probe_needle="signerloc-online-$(time_tag)"
    probe_txt_rr="${DOWNSTREAM_ZONE} 60 IN TXT \"${probe_needle}\""
    # This is a Case C request (LEASE=0, KEY-LEASE=0) for a record the
    # online-only signer does not own, so it resolves to a harmless no-op
    # (Rcode=Success, "record not found for delete" note) once SIG(0)
    # authenticates -- it is not gated by AllowOnlineKeyRegistration, which
    # only applies to *new registrations* (Case A/D), not Case C deletes.
    if ! probe_out=$(run_client refresh "$WRONG_CLIENT_KEY_NAME" 0 0 "$probe_txt_rr" --signer=none 2>&1); then
        log_error "Signer-location[online-only]: request signed by an online-only, never-registered key was unexpectedly rejected"
        echo "$probe_out"
        delete_rr "$wrong_key_payload"
        return 1
    fi
    delete_rr "$wrong_key_payload"
    if rr_at_authoritative TXT "$probe_txt_rr"; then
        log_error "Signer-location[online-only]: Case C no-op unexpectedly created a TXT record"
        return 1
    fi
    log_success "Signer-location[online-only]: signer KEY resolved from authoritative DNS (never lease-managed)"

    log_case_timing "signer-location-matrix" "$case_start" 0
    log_success "Signer-location matrix validated: Update, Additional, lease-store, and online-only all resolve correctly"

    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

# test_case_multi_rr_combination_registration registers several distinct
# non-KEY RR types together in a single Update (Case A), verifies all land
# correctly, then verifies they all expire together at the LEASE boundary
# while the KEY (registered with a longer key-lease) persists. Deliberately
# excludes NULL/NXNAME (no presentation format, see make_rr) and CLA/IPN
# (blacklisted by this repo's config.yaml), leaving a combination of
# distinct, constructible, non-blacklisted types.
test_case_multi_rr_combination_registration() {

    local log_msg="CASE MULTI-RR: Register Several RR Types Together in One Update"
    log_section "$log_msg"

    local lease_start

    # Parallel indexed arrays (combo_types[i] <-> combo_specs[i]), not an
    # associative array for compatibility with older versions of /bin/bash
    # which have no `declare -A` support.
    local combo_types=(TXT A AAAA WALLET)
    local combo_specs=() specs=() i t spec
    specs=("$(make_rr KEY $LONG_KEY_LEASE_SECONDS)")
    for i in "${!combo_types[@]}"; do
        spec="$(make_rr "${combo_types[$i]}" $LEASE_SECONDS)"
        specs+=("$spec")
        combo_specs[$i]="$spec"
    done

    log_step "Registering KEY + ${combo_types[*]} together in a single Update"
    lease_start=$(date +%s)
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS $LONG_KEY_LEASE_SECONDS "${specs[@]}"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    for i in "${!combo_types[@]}"; do
        t="${combo_types[$i]}"
        if ! wait_for_rr_state "$t" "${combo_specs[$i]}" present; then
            log_error "Multi-RR: $t record not present after combined registration"
            return 1
        fi
    done
    lease_dump debug
    log_success "All ${#combo_types[@]} non-KEY types plus KEY landed correctly from a single Update"

    log_step "Waiting past LEASE boundary: non-KEY records should expire, KEY (longer key-lease) persists"
    wait_until_epoch $((lease_start + LEASE_SECONDS + BUFFER))
    for i in "${!combo_types[@]}"; do
        t="${combo_types[$i]}"
        if ! wait_for_rr_state "$t" "${combo_specs[$i]}" absent; then
            log_error "Multi-RR: $t record still present after LEASE expiry"
            return 1
        fi
    done

    if ! rr_at_authoritative KEY "$CLIENT_KEY_RR"; then
        log_error "Multi-RR: KEY expected present but absent at authoritative"
        return 1
    fi

    log_case_timing "multi-rr-combination" "$lease_start" "$((LEASE_SECONDS + BUFFER))"
    log_success "Multi-RR combination registration validated: all types landed together and expired together"

    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

# test_case_refresh_extends_nonkey_not_key_lease inspects actual lease
# timestamps via the DEBUG dump (not just presence/absence) to confirm a
# non-KEY-only refresh (Case B) advances the non-KEY record's ExpiresAt while
# leaving the KEY's own ExpiresAt untouched.
test_case_refresh_extends_nonkey_not_key_lease() {

    local log_msg="CASE REFRESH: Extends Non-KEY Lease Without Extending Key Lease"
    log_section "$log_msg"

    local case_start
    case_start=$(date +%s)

    local needle txt_spec_rr
    needle="refresh-lease-check-$(time_tag)"
    txt_spec_rr="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle}\""

    log_step "Registering KEY (long key-lease) + TXT (short lease)"
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS $LONG_KEY_LEASE_SECONDS "$(make_rr KEY $LONG_KEY_LEASE_SECONDS)" "$txt_spec_rr"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    if ! rr_at_authoritative TXT "$txt_spec_rr"; then
        log_error "Refresh-lease-check: TXT record not found after initial registration"
        return 1
    fi

    local dump_before key_expires_before nonkey_expires_before
    dump_before="$(lease_dump debug)"
    key_expires_before="$(lease_store_key_expires_at "" "$dump_before")"
    nonkey_expires_before="$(lease_store_rr_expires_at "$needle" "$dump_before")"
    log_step "Before refresh: KEY ExpiresAt=$key_expires_before  Non-KEY ExpiresAt=$nonkey_expires_before"
    if [ -z "$key_expires_before" ] || [ -z "$nonkey_expires_before" ]; then
        log_error "Refresh-lease-check: could not parse ExpiresAt values from debug dump"
        echo "$dump_before"
        return 1
    fi

    sleep $BUFFER

    log_step "Refreshing non-KEY-only (Case B: KEY-LEASE=0), same TXT rdata, extending LEASE"
    run_client refresh "$CLIENT_KEY_NAME" $LEASE_SECONDS 0 "$txt_spec_rr"

    local dump_after key_expires_after nonkey_expires_after
    dump_after="$(lease_dump debug)"
    key_expires_after="$(lease_store_key_expires_at "" "$dump_after")"
    nonkey_expires_after="$(lease_store_rr_expires_at "$needle" "$dump_after")"
    log_step "After refresh: KEY ExpiresAt=$key_expires_after  Non-KEY ExpiresAt=$nonkey_expires_after"

    if [ "$key_expires_after" != "$key_expires_before" ]; then
        log_error "Refresh-lease-check: KEY ExpiresAt changed from a non-KEY-only (Case B) refresh: $key_expires_before -> $key_expires_after"
        return 1
    fi
    if [[ ! "$nonkey_expires_after" > "$nonkey_expires_before" ]]; then
        log_error "Refresh-lease-check: Non-KEY ExpiresAt did not advance after refresh: $nonkey_expires_before -> $nonkey_expires_after"
        return 1
    fi

    log_case_timing "refresh-lease-check" "$case_start" $BUFFER
    log_success "Refresh extended the non-KEY lease ($nonkey_expires_before -> $nonkey_expires_after) without touching the key lease ($key_expires_before)"

    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
}

# test_case_dump_vs_dig_consistency cross-checks the lease-store dump (both
# INFO and DEBUG levels) against live `dig` results at the authoritative
# server, through both registration (both present/active) and expiry (both
# absent) -- proving the dump reflects real DNS state, not just internal
# bookkeeping.
test_case_dump_vs_dig_consistency() {

    local log_msg="CASE DUMP vs DIG: Lease-Store Dump Cross-Checked Against Authoritative"
    log_section "$log_msg"

    local lease_start

    local needle txt_spec node_key
    needle="dumpcheck-$(time_tag)"
    txt_spec_rr="${DOWNSTREAM_ZONE} ${LEASE_SECONDS} IN TXT \"${needle}\""
    node_key="${CLIENT_KEY_NAME#K}"

    log_step "Registering KEY + TXT for dump/dig cross-check"
    lease_start=$(date +%s)
    run_client register "$CLIENT_KEY_NAME" $LEASE_SECONDS $KEY_LEASE_SECONDS "$(make_rr KEY $KEY_LEASE_SECONDS)" "$txt_spec_rr"
    wait_for_rr_state KEY "$CLIENT_KEY_RR" present
    if ! rr_at_authoritative TXT "$txt_spec_rr"; then
        log_error "Dump/dig check: TXT record not found at authoritative after registration"
        return 1
    fi

    log_step "Cross-checking INFO summary line against authoritative state (both present)"
    local info_dump summary_line
    info_dump="$(lease_dump info)"
    summary_line="$(lease_store_summary_line "$node_key" "$info_dump")"
    if ! printf '%s\n' "$summary_line" | grep -q "KEY=active"; then
        log_error "Dump/dig check: INFO summary does not show KEY=active for $node_key"
        echo "$info_dump"
        return 1
    fi
    if ! printf '%s\n' "$summary_line" | grep -q "NonKEY=1"; then
        log_error "Dump/dig check: INFO summary does not show NonKEY=1 for $node_key"
        echo "$info_dump"
        return 1
    fi

    log_step "Cross-checking DEBUG dump holds the exact registered TXT rdata"
    local debug_dump
    debug_dump="$(lease_dump debug)"
    if ! lease_store_has_rr TXT "$txt_spec_rr" "$debug_dump"; then
        log_error "Dump/dig check: DEBUG dump does not contain the registered TXT record"
        echo "$debug_dump"
        return 1
    fi

    log_step "Waiting past LEASE expiry to cross-check absence in both dump and dig"
    wait_until_epoch $((lease_start + LEASE_SECONDS + BUFFER))
    wait_for_rr_state TXT "$txt_spec_rr" absent

    info_dump="$(lease_dump info)"
    summary_line="$(lease_store_summary_line "$node_key" "$info_dump")"
    if printf '%s\n' "$summary_line" | grep -q "NonKEY=1"; then
        log_error "Dump/dig check: INFO summary still shows NonKEY=1 after authoritative TXT expired"
        echo "$info_dump"
        return 1
    fi
    debug_dump="$(lease_dump debug)"
    if lease_store_has_rr TXT "$txt_spec_rr" "$debug_dump"; then
        log_error "Dump/dig check: DEBUG dump still shows the expired TXT record"
        echo "$debug_dump"
        return 1
    fi

    log_case_timing "dump-vs-dig-consistency" "$lease_start" "$(( LEASE_SECONDS + BUFFER ))"
    log_success "Lease-store dump (INFO and DEBUG) stayed consistent with authoritative DNS through registration and expiry"

    PERFORMED_TESTS="$PERFORMED_TESTS\n  [OK] $log_msg"
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
    echo "  - real authoritative forwarding path for $UPSTREAM_ZONE"
    echo ""

    trap cleanup EXIT

    require_command grep
    require_command ls
    require_command dig
    build_binaries
    verify_keystore
    log_success "Using authoritative server for KEY checks: $AUTH_SERVER, key: $CLIENT_KEY_NAME, lease: $LEASE_SECONDS, key-lease: $KEY_LEASE_SECONDS"
    test_list_keys
    start_proxy

    log_section "TESTING LIVE LEASE LIFECYCLE"    

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
        # KEY lease (Case C) cascades and removes every non-KEY lease under it
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
            
            test_case_unauthorized_refresh_rejected_then_expires "$rr_type"
            ensure_rr_absent KEY "$CLIENT_KEY_RR"
        fi
    done

    
    test_case_overlapping_registrations
    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    
    test_case_abcd_lease_policy_matrix
    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    
    test_case_signer_location_matrix
    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    
    test_case_multi_rr_combination_registration
    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    
    test_case_refresh_extends_nonkey_not_key_lease
    ensure_rr_absent KEY "$CLIENT_KEY_RR"
    
    test_case_dump_vs_dig_consistency
    ensure_rr_absent KEY "$CLIENT_KEY_RR"

    log_section "TEST RESULTS"
    echo -e "${GREEN}All integration tests completed successfully!${NC}"
    echo ""
    echo "Summary of what was tested:"
    echo -e "$PERFORMED_TESTS"
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
        ensure_rr_absent KEY "$WRONG_CLIENT_KEY_RR" || true
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
