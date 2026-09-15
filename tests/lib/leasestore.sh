# tests/lib/leasestore.sh -- inspecting the proxy's internal lease-store dump
# endpoint, and cross-checking it against authoritative DNS. See
# lib/common.sh for the "no set -e, return not exit" rules this file follows.

if [ -n "${_SIG0LEASE_LIB_LEASESTORE_SOURCED:-}" ]; then
    return 0 2>/dev/null || true
fi
_SIG0LEASE_LIB_LEASESTORE_SOURCED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$LIB_DIR/common.sh"
# shellcheck source=./dns.sh
source "$LIB_DIR/dns.sh"   # get_rdata, dig_query_short

# Grace window proxy_consistent_with_authoritative gives the internal lease
# store to converge with authoritative DNS (see that function below). Given
# an inline default here, not just in the orchestration script, so this file
# is self-sufficient with no required env vars; test_update.sh overrides it
# with a value scaled off its own lease-policy minimums.
LEASE_STORE_SETTLE_SECONDS="${LEASE_STORE_SETTLE_SECONDS:-5}"

################################
# Lease Dump functions
################################

# _default_proxy_url -- PROXY_URL if lib/common.sh has already computed it
# (the normal case), otherwise the same 127.0.0.1:8053 fallback it would
# have used, so lease_dump has no required env vars even if this file is
# somehow sourced without common.sh's defaulting having run.
_default_proxy_url() {
    echo "${PROXY_URL:-127.0.0.1:8053}"
}

# lease_dump [proxy_addr] [level] -- query a running proxy's internal
# lease-store dump endpoint and print it as readable, line-oriented text.
#
#   proxy_addr: "host:port" of the proxy to query. Defaults to
#               ${PROXY_URL:-127.0.0.1:8053} when omitted.
#   level:      "debug" -> full per-record dump via __dump.sig0lease.internal.debug.
#               "info"  -> one-line-per-key summary via __dump.sig0lease.internal.
#               Defaults to "info".
#
# Both arguments are optional and order-preserving with the pre-existing
# single-argument callers (`lease_dump`, `lease_dump debug`, `lease_dump
# info`): with exactly one argument, "info"/"debug" is recognized as level
# (proxy_addr defaults); anything else is taken as proxy_addr (level
# defaults to "info"). This keeps every existing call site working
# unchanged while adding the ability to dump a non-default proxy instance.
#
# dig +short hands back the dump in DNS <character-string> presentation form --
# embedded control bytes rendered as literal \DDD (decimal, per RFC 1035), and
# a dump longer than one 240-byte TXT string split across several TXT RRs /
# output lines. lease_dump strips the per-line quoting, rejoins the chunks, and
# decodes the \DDD / \" / \\ escapes, so the result has real newlines and tabs
# and can be printed as-is OR fed straight to grep/awk (and to the
# lease_store_* helpers below).
#
# The "[dig] @..." progress line goes to stderr, so stdout is pure dump text.
# printf (not echo) feeds the pipeline, since some shells' builtin echo would
# reinterpret the backslash escapes before sed/perl ever see them.
lease_dump() {
    local proxy_addr level
    case $# in
        0)
            proxy_addr="$(_default_proxy_url)"
            level="info"
            ;;
        1)
            case "$1" in
                info|debug)
                    proxy_addr="$(_default_proxy_url)"
                    level="$1"
                    ;;
                *)
                    proxy_addr="$1"
                    level="info"
                    ;;
            esac
            ;;
        *)
            proxy_addr="$1"
            level="${2:-info}"
            ;;
    esac

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
    raw=$(dig_query_short "$proxy_addr" "${query_domain}" TXT)

    # Test script's own log level, independent from proxy logging; to stderr
    # so a `foo="$(lease_dump ...)"` capture stays clean.
    printf '  [%s] [dig] @%s %s TXT (%s)\n' \
        "$(printf '%s' "$level" | tr '[:lower:]' '[:upper:]')" \
        "$proxy_addr" "$query_domain" "$dump_label" >&2

    if [ -z "$raw" ]; then
        echo "(no dump response)"
        return 0
    fi

    printf '%s\n' "$raw" | sed 's/^"//; s/"$//' | tr -d '\n' \
        | perl -pe 's/\\(\d{3})/chr($1)/ge; s/\\"/"/g; s/\\\\/\\/g'
}

# _lease_store_split_addr <args...> -- sets the globals _LSS_ADDR (the
# proxy_addr) and _LSS_ARGS (the remaining arguments, as an array) as a side
# effect, rather than returning them, to avoid a process-substitution +
# `read`-to-EOF pattern whose final `read` failing (an entirely expected
# "no more args" outcome here, e.g. no pre-fetched dump was passed) would
# read as this whole statement failing -- fatal under a caller's `set -e`
# even though nothing has actually gone wrong.
#
# If the first argument contains a ':', it's taken as an optional leading
# proxy_addr (every real proxy_addr in this codebase is a "host:port"
# string, e.g. $PROXY_URL) and shifted off; otherwise proxy_addr defaults and
# every argument is passed through unchanged.
#
# Caveat: this is a narrow, deliberately cheap heuristic, not a real parser.
# It is safe for every argument these functions are actually called with
# today (RR-type keywords, KEY rdata, node-keys, and the plain
# "refresh-lease-check-<timestamp>" needles this suite generates all lack a
# ':'), but a hypothetical future needle that itself contains a ':' (e.g.
# searching lease_store_rr_expires_at for an AAAA record's literal address)
# would be mis-detected as a leading proxy_addr. If that ever comes up, pass
# the proxy_addr explicitly as a real leading argument to sidestep the
# heuristic rather than relying on default-detection.
_LSS_ADDR=""
_LSS_ARGS=()
_lease_store_split_addr() {
    if [ $# -gt 0 ] && [[ "$1" == *:* ]]; then
        _LSS_ADDR="$1"
        shift
        _LSS_ARGS=("$@")
    else
        _LSS_ADDR="$(_default_proxy_url)"
        _LSS_ARGS=("$@")
    fi
}

# lease_store_has_rr [proxy_addr] <rr_type> <rr-spec> [debug-dump] -- succeeds
# (0) when the proxy's INTERNAL lease store currently holds a live record
# matching <rr-spec>, read from the DEBUG lease-store dump. This is the
# internal-state counterpart to rr_at_authoritative (which checks the
# authoritative DNS). Pass a pre-fetched `lease_dump debug` as the last arg
# to avoid re-querying.
#   KEY   -> matched on "KeyRR:" lines; a key block flagged "IsExpired: true"
#            (expired but not yet reaped) counts as absent.
#   other -> matched on the non-KEY "RR:" lines.
# Echoes a one-line present/absent result (silence it with >/dev/null).
lease_store_has_rr() {
    _lease_store_split_addr "$@"
    local proxy_addr="$_LSS_ADDR" rr_type="${_LSS_ARGS[0]:-}" rr_spec="${_LSS_ARGS[1]:-}" dump="${_LSS_ARGS[2]:-}"
    [ -n "$dump" ] || dump="$(lease_dump "$proxy_addr" debug)"

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

# lease_store_key_expires_at [proxy_addr] <key-rdata|""> [debug-dump] --
# print the KEY lease's ExpiresAt (RFC3339) from a DEBUG dump. Empty
# key-rdata arg -> the first KEY block; otherwise the block whose KeyRR
# matches the given rdata/rr-spec.
lease_store_key_expires_at() {
    _lease_store_split_addr "$@"
    local proxy_addr="$_LSS_ADDR" want="${_LSS_ARGS[0]:-}" dump="${_LSS_ARGS[1]:-}"
    [ -n "$dump" ] || dump="$(lease_dump "$proxy_addr" debug)"
    local disc=""
    [ -n "$want" ] && disc="$(get_rdata "$want")"
    printf '%s\n' "$dump" | tr '\t' ' ' | sed -E 's/  +/ /g' | awk -v disc="$disc" '
        /^ *Key: /                        { inkey = (disc == "") }
        disc != "" && /KeyRR: / && index($0, disc) { inkey = 1 }
        inkey && /ExpiresAt: /            { print $2; exit }
    '
}

# lease_store_rr_expires_at [proxy_addr] <needle> [debug-dump] -- print the
# non-KEY record's ExpiresAt (RFC3339) for the record whose "RR:" line
# contains <needle>, from a DEBUG dump.
lease_store_rr_expires_at() {
    _lease_store_split_addr "$@"
    local proxy_addr="$_LSS_ADDR" needle="${_LSS_ARGS[0]:-}" dump="${_LSS_ARGS[1]:-}"
    [ -n "$dump" ] || dump="$(lease_dump "$proxy_addr" debug)"
    printf '%s\n' "$dump" | tr '\t' ' ' | sed -E 's/  +/ /g' | awk -v needle="$needle" '
        /^ *RR: / && index($0, needle) { found = 1; next }
        found && /ExpiresAt: /          { print $2; exit }
    '
}

# lease_store_summary_line [proxy_addr] <node_key> [info-dump] -- the
# INFO-summary line for <node_key> ("Key: <nodekey>  KEY=<..>  NonKEY=<n>
# Status=<..>"), or empty.
lease_store_summary_line() {
    _lease_store_split_addr "$@"
    local proxy_addr="$_LSS_ADDR" node_key="${_LSS_ARGS[0]:-}" dump="${_LSS_ARGS[1]:-}"
    [ -n "$dump" ] || dump="$(lease_dump "$proxy_addr" info)"
    printf '%s\n' "$dump" | grep -F -- "Key: ${node_key} " || true
}

# proxy_consistent_with_authoritative <rr_type> <rr-spec> <expected_state> <auth_present>
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
