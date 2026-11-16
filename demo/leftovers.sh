#!/bin/bash
# demo/leftovers.sh [-n server] [-c config]... [-p host:port]... [-r] [domain] -- lists every
# record set under domain (default srp.dev.zenr.io) on the zone's authoritative server, and says
# for each one whether a lease store holds it. One that no store holds is a leftover: a test, an
# earlier run or another client wrote it, and nothing will remove it (docs/dns-sd-records.md,
# "When the proxy stops"). It finds the names by walking the zone's NSEC chain, stepping over
# child zones. It only reads: dig queries, and the stores through the proxy's read-only dump.
#
#   domain        the subtree to list, itself included (default srp.dev.zenr.io)
#   -n server     the server to ask (default: the zone's primary, its SOA MNAME)
#   -c config     read the lease stores (snapshot files) of this proxy config, with
#                 "sig0lease --dump-debug config"; relative storage paths are taken from the
#                 repository's top directory, where this runs. Repeatable. Default config.yaml,
#                 if there is no -c, -p or -r.
#   -p host:port  read the lease stores of the proxy running there, with its dump query
#                 (needs diagnostics: true in its config). Repeatable.
#   -r            also read the stores of the registrar discovery finds for domain: the first
#                 _dnssd-srp._tcp SRV from domain up to the zone apex, with its dump query.
#
# A store it cannot read stops it: a missing store would turn everything it holds into
# leftovers. A store not consulted does the same, so it prints which ones it consulted.
# SIG0LEASE names the proxy binary for -c (default ./bin/<os>/sig0lease, from make build).
# Leftover KEY records whose public key is in a keystore here (keystore/*, demo/keys*) name
# that key file: it is the key that can remove them.

here="$PWD"
cd "$(dirname "$0")/.." || exit 1
B="./bin/$(uname -s | tr A-Z a-z)"
proxy_bin="${SIG0LEASE:-$B/sig0lease}"

die() { echo "leftovers.sh: $*" >&2; exit 1; }
usage() { sed -n '2,3p' "$0" | sed 's/^# //' >&2; exit 2; }

server= discover= configs=() proxies=()
while getopts n:c:p:rh opt; do
    case "$opt" in
        n) server="$OPTARG" ;;
        c) case "$OPTARG" in /*) configs+=("$OPTARG") ;; *) configs+=("$here/$OPTARG") ;; esac ;;
        p) proxies+=("$OPTARG") ;;
        r) discover=1 ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ $# -le 1 ] || usage
domain="${1:-srp.dev.zenr.io}"
case "$domain" in *.) ;; *) domain="$domain." ;; esac
if [ ${#configs[@]} -eq 0 ] && [ ${#proxies[@]} -eq 0 ] && [ -z "$discover" ]; then
    configs=("$PWD/config.yaml")
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/sig0lease-leftovers.XXXXXX")" || exit 1
trap 'rm -rf "$tmp"' EXIT

# Names are compared in one form: every escape decoded (\DDD as dig prints them, \X as the
# proxy's dump does), ASCII letters lower-cased, and every octet but a letter, a digit, "_" and
# "-" written as \DDD. ENVIRON passes names to awk, since -v would decode their backslashes.
CANON='
BEGIN { for (i = 1; i < 256; i++) ord[sprintf("%c", i)] = i }
function encn(n) {
    if (n >= 65 && n <= 90) return sprintf("%c", n + 32)
    if ((n >= 97 && n <= 122) || (n >= 48 && n <= 57) || n == 95 || n == 45) return sprintf("%c", n)
    return sprintf("\\%03d", n)
}
function canon(s,    out, i, n, c, d) {
    out = ""
    n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "\\") {
            d = substr(s, i + 1, 3)
            if (d ~ /^[0-9][0-9][0-9]$/) { out = out encn(d + 0); i += 3 }
            else { i++; out = out encn(ord[substr(s, i, 1)]) }
        } else if (c == ".") out = out "."
        else out = out encn(ord[c])
    }
    if (out !~ /\.$/) out = out "."
    return out
}'
canon() { K="$1" LC_ALL=C awk "$CANON"' BEGIN { print canon(ENVIRON["K"]) }'; }

# query <name> <type> -- the answer and authority records the server gives, DNSSEC included;
# stops on anything but NOERROR or NXDOMAIN.
query() {
    local out status
    out="$(dig +norec +dnssec +noall +comments +answer +authority +time=3 +tries=2 "@$server" "$1" "$2" 2>&1)" ||
        die "dig $1 $2 @$server failed: $out"
    status="$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<< "$out" | head -n 1)"
    case "$status" in
        NOERROR|NXDOMAIN) ;;
        *) die "$server answered $1 $2 with ${status:-no status}: $out" ;;
    esac
    grep -v -e '^;' -e '^$' <<< "$out" || true
}

# rrs <type> <records> -- each record of that type: canonical owner, owner as dig prints it, and
# its data, tab-separated.
rrs() {
    T="$1" LC_ALL=C awk "$CANON"' $4 == ENVIRON["T"] {
        d = $5; for (i = 6; i <= NF; i++) d = d " " $i
        print canon($1) "\t" $1 "\t" d }' <<< "$2"
}

# owned <canonical name> -- the lines on stdin whose first field is that name.
owned() { K="$1" awk -F'\t' '$1 == ENVIRON["K"]'; }

# The zone apex and the server.
if [ -z "$server" ]; then
    soa="$(dig +noall +answer +authority SOA "$domain" | awk '$4 == "SOA" { print $1, $5; exit }')"
    [ -n "$soa" ] || die "no SOA found for $domain through this machine's resolver: give the server with -n"
    server="${soa#* }"
fi
out="$(query "$domain" SOA)" || exit 1
soa="$(rrs SOA "$out")"
[ -n "$soa" ] || die "$server gives no SOA for $domain: it is not authoritative for it"
apex="$(cut -f2 <<< "$soa" | head -n 1)"
D="$(canon "$domain")"
A="$(canon "$apex")"
under() { case "$1" in "$D"|*".$D") return 0 ;; esac; return 1; }

# The lease stores: one line per record set a store holds (canonical owner, type, store number),
# from the "KeyRR:" and "RR:" lines of both handlers' debug dumps, each a record as the proxy
# prints it, tab-separated.
: > "$tmp/held"
: > "$tmp/stores"
nstores=0
add_store() { # <description> <dump text>
    local n
    nstores=$((nstores + 1))
    LABEL="[$nstores]" LC_ALL=C awk "$CANON"' {
        line = $0; sub(/^[ \t]*/, "", line)
        if (line !~ /^(KeyRR|RR): /) next
        sub(/^(KeyRR|RR): /, "", line)
        split(line, f, "\t")
        print canon(f[1]) "\t" toupper(f[4]) "\t" ENVIRON["LABEL"] }' <<< "$2" | sort -u > "$tmp/one"
    n="$(wc -l < "$tmp/one" | tr -d ' ')"
    cat "$tmp/one" >> "$tmp/held"
    echo "  [$nstores] $1: $n record set(s)" >> "$tmp/stores"
}
# dump_query <host> <port> -- the debug dump a running proxy answers, decoded from its TXT records.
dump_query() {
    local out
    out="$(dig +tcp +short +time=3 +tries=2 -p "$2" "@$1" __dump.sig0lease.internal.debug TXT 2>&1)" ||
        die "dump query to $1 port $2 failed: $out"
    grep -q '^"' <<< "$out" ||
        die "$1 port $2 gives no dump${out:+ ($out)}: not running there, or diagnostics off"
    LC_ALL=C awk '{
        n = length($0); inq = 0
        for (i = 1; i <= n; i++) {
            c = substr($0, i, 1)
            if (!inq) { if (c == "\"") inq = 1; continue }
            if (c == "\"") { inq = 0; continue }
            if (c == "\\") {
                d = substr($0, i + 1, 3)
                if (d ~ /^[0-9][0-9][0-9]$/) { printf "%c", d + 0; i += 3 } else { i++; printf "%s", substr($0, i, 1) }
                continue
            }
            printf "%s", c
        } }' <<< "$out"
}
for config in "${configs[@]}"; do
    [ -x "$proxy_bin" ] || die "no proxy binary at $proxy_bin to read $config: run make build, or set SIG0LEASE"
    [ -f "$config" ] || die "no config at $config"
    out="$(DEBUG_LEVEL=error "$proxy_bin" --dump-debug "$config" 2>&1)" ||
        die "$proxy_bin --dump-debug $config failed: $out"
    add_store "snapshots of ${config#"$PWD/"} (sig0lease --dump-debug)" "$out"
done
for p in "${proxies[@]}"; do
    case "$p" in *:*) ;; *) die "-p $p: give host:port" ;; esac
    out="$(dump_query "${p%:*}" "${p##*:}")" || exit 1
    add_store "proxy at $p (dump query)" "$out"
done
if [ -n "$discover" ]; then
    n="$domain" srv=
    while [ -n "$n" ]; do
        out="$(query "_dnssd-srp._tcp.$n" SRV)" || exit 1
        srv="$(rrs SRV "$out" | cut -f3 | sort -n | head -n 1)"
        [ -n "$srv" ] && break
        [ "$(canon "$n")" = "$A" ] && break
        n="${n#*.}"
    done
    [ -n "$srv" ] || die "-r: no _dnssd-srp._tcp SRV from $domain up to $apex"
    set -- $srv
    # The target's address, from the server when the target is in its zone.
    if case "$(canon "$4")" in "$A"|*".$A") true ;; *) false ;; esac; then
        out="$(query "$4" A)" || exit 1
        addr="$(rrs A "$out" | cut -f3 | head -n 1)"
    else
        addr="$(dig +short "$4" A | tail -n 1)"
    fi
    [ -n "$addr" ] || die "-r: _dnssd-srp._tcp.$n names $4, which has no address"
    out="$(dump_query "$addr" "$3")" || exit 1
    add_store "registrar $4 port $3, from _dnssd-srp._tcp.$n (dump query)" "$out"
fi

# The walk: every name under domain that has records, with its types (RRSIG and NSEC left
# out), in the zone's order. Each name's NSEC record names the next. At a child zone's apex the
# server answers with the child's own NSEC, which goes on inside the child zone; the parent's
# NSEC at the cut, which the name just after the child zone's subtree ("<label>\000.<rest>")
# returns, goes on past it.
: > "$tmp/names"
after_subtree() { K="$1" awk 'BEGIN {
    s = ENVIRON["K"]; n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "\\") { i++; if (substr(s, i, 1) ~ /[0-9]/) i += 2; continue }
        if (c == ".") { print substr(s, 1, i - 1) "\\000" substr(s, i); exit }
    } }'; }
out="$(query "$domain" NSEC)" || exit 1
nsec="$(rrs NSEC "$out")" || exit 1
cur= curc=
if [ -n "$(owned "$D" <<< "$nsec")" ]; then
    cur="$domain" curc="$D"
else
    # No records at domain itself (an empty non-terminal, or nothing at all): the NSEC that
    # proves it names the first name after it.
    while IFS=$'\t' read -r oc od data; do
        next="${data%% *}"
        nc="$(canon "$next")"
        if under "$nc"; then cur="$next" curc="$nc"; break; fi
    done <<< "$nsec"
fi
count=0
while [ -n "$cur" ] && under "$curc"; do
    if cut -f1 "$tmp/names" | grep -Fxq -- "$curc"; then
        [ "$curc" = "$A" ] && break # the chain is back at the apex
        die "the NSEC chain goes back to $cur"
    fi
    count=$((count + 1))
    [ $count -le 100000 ] || die "more than 100000 names under $domain"
    out="$(query "$cur" NSEC)" || exit 1
    line="$(rrs NSEC "$out" | owned "$curc" | head -n 1)" || exit 1
    types= child=
    if [ -n "$line" ]; then
        data="$(cut -f3 <<< "$line")"
        next="${data%% *}"
        for t in ${data#* }; do
            case "$t" in RRSIG|NSEC) ;; *) types="$types $t" ;; esac
        done
        types="${types# }"
        case " $types " in *" NS "*|*" SOA "*) [ "$curc" != "$A" ] && child=1 ;; esac
        case " $types " in *" SOA "*) [ -n "$child" ] && line= ;; esac # the child's own NSEC
    elif [ -n "$(rrs NS "$out" | owned "$curc")" ]; then
        child=1 # a referral to a child zone this server does not serve
    else
        die "$server gives no NSEC for $cur: the zone is not NSEC-signed (NSEC3 is not walked here)"
    fi
    if [ -n "$child" ] && [ -z "$line" ]; then
        out="$(query "$(after_subtree "$cur")" A)" || exit 1
        line="$(rrs NSEC "$out" | owned "$curc" | head -n 1)" || exit 1
        [ -n "$line" ] || die "$server gives no parent-side NSEC for the child zone at $cur"
        data="$(cut -f3 <<< "$line")"
        next="${data%% *}"
    fi
    [ -n "$child" ] && types="child zone"
    printf '%s\t%s\t%s\n' "$curc" "$cur" "$types" >> "$tmp/names"
    cur="$next"
    curc="$(canon "$next")"
done

# Public keys in the keystores here, to name the key file of a leftover KEY.
: > "$tmp/keys"
for f in keystore/*/*.key demo/keys*/*.key; do
    [ -f "$f" ] || continue
    awk -v f="$f" '!/^;/ { for (i = 1; i <= NF; i++) if ($i == "KEY") { k = ""; for (j = i + 4; j <= NF; j++) k = k $j; print k "\t" f; exit } }' "$f" >> "$tmp/keys"
done

# Each record set, in one of four groups; PTRs whose target under domain has no records, and
# child zones, in two more.
for g in held meta srv left dangling missing child; do : > "$tmp/g.$g"; done
# records <name> <type> -- the record set's data, one record per line.
records() {
    local out
    out="$(query "$1" "$2")" || exit 1
    rrs "$2" "$out" | owned "$(canon "$1")" | cut -f3
}
joined() { awk 'NR > 1 { printf " | " } { printf "%s", $0 } END { if (NR) print "" }'; }
row() { printf '  %-52s %-6s %s\n' "$2" "$3" "$4" >> "$tmp/g.$1"; }
# domain_enumeration <canonical name> -- whether it is one of RFC 6763 S11's five names.
domain_enumeration() {
    case "$1" in b._dns-sd._udp.*|db._dns-sd._udp.*|lb._dns-sd._udp.*|r._dns-sd._udp.*|dr._dns-sd._udp.*) return 0 ;; esac
    return 1
}
type_enumeration() { case "$1" in _services._dns-sd._udp.*) return 0 ;; esac; return 1; }
registrar_srv() { case "$1" in _dnssd-srp._tcp.*|_dnssd-srp-tls._tcp.*) return 0 ;; esac; return 1; }
# The targets of the registrar SRV records: their addresses are the operator's too.
: > "$tmp/targets"
while IFS=$'\t' read -r nc nd types; do
    registrar_srv "$nc" || continue
    case " $types " in *" SRV "*) ;; *) continue ;; esac
    rdata="$(records "$nd" SRV)" || exit 1
    while read -r _ _ _ target; do
        [ -n "$target" ] && canon "$target" >> "$tmp/targets"
    done <<< "$rdata"
done < "$tmp/names"
registrar_address() { grep -Fxq -- "$1" "$tmp/targets"; }
while IFS=$'\t' read -r nc nd types; do
    if [ "$types" = "child zone" ]; then
        row child "$nd" "" "a zone of its own, not walked"
        continue
    fi
    for t in $types; do
        if [ "$nc" = "$A" ]; then # the zone's own records, which no client writes
            case "$t" in SOA|NS|DNSKEY|CDS|CDNSKEY|NSEC3PARAM|ZONEMD|TYPE65534) continue ;; esac
        fi
        rdata="$(records "$nd" "$t")" || exit 1
        stores="$(owned "$nc" < "$tmp/held" | awk -F'\t' -v t="$t" '$2 == t { print $3 }' | sort -u | paste -s -d ' ' -)"
        if [ -n "$stores" ]; then
            row held "$nd" "$t" "$stores"
        elif [ "$t" = PTR ] && { domain_enumeration "$nc" || type_enumeration "$nc"; }; then
            row meta "$nd" "$t" "$(joined <<< "$rdata")"
        elif { [ "$t" = SRV ] && registrar_srv "$nc"; } ||
            { { [ "$t" = A ] || [ "$t" = AAAA ]; } && registrar_address "$nc"; }; then
            row srv "$nd" "$t" "$(joined <<< "$rdata")"
        elif [ "$t" = KEY ]; then
            # flags, protocol, algorithm, and the key file that holds the same public key
            detail="$(while read -r flags proto alg key; do
                key="${key// /}"
                file="$(awk -F'\t' -v k="$key" '$1 == k { print $2; exit }' "$tmp/keys")"
                echo "$flags $proto $alg${file:+ (key $file)}"
            done <<< "$rdata" | joined)"
            row left "$nd" "$t" "$detail"
        else
            row left "$nd" "$t" "$(joined <<< "$rdata")"
        fi
        if [ "$t" = PTR ] && ! domain_enumeration "$nc"; then
            while read -r target; do
                tc="$(canon "$target")"
                under "$tc" || continue
                cut -f1 "$tmp/names" | grep -Fxq -- "$tc" || row dangling "$nd" PTR "$target"
            done <<< "$rdata"
        fi
    done
done < "$tmp/names"

# Record sets a store holds under domain that the zone does not have: the store and the zone
# disagree, and the store would delete, on expiry, what is not there.
cut -f1,3 "$tmp/names" | awk -F'\t' '{ n = split($2, t, " "); for (i = 1; i <= n; i++) print $1 "\t" t[i] }' > "$tmp/zone"
while IFS=$'\t' read -r nc t store; do
    under "$nc" || continue
    grep -Fxq -- "$nc"$'\t'"$t" "$tmp/zone" || row missing "$nc" "$t" "$store"
done < "$tmp/held"

section() { # <group> <title>
    [ -s "$tmp/g.$1" ] || return 0
    echo
    echo "$2"
    cat "$tmp/g.$1"
}
echo "Record sets under $domain (zone $apex), asked of $server, $(date '+%Y-%m-%d %H:%M %Z'):"
echo "$(wc -l < "$tmp/names" | tr -d ' ') name(s) with records.$(under "$A" && echo " The apex's SOA, NS and DNSSEC records are left out.")"
echo
echo "Lease stores consulted (a store not listed here counts as holding nothing):"
cat "$tmp/stores"
section held "Held by a lease store:"
section meta "RFC 6763 §9/§11 records (never in a lease store; an srp_handler writes them for its own zone):"
section srv "Registrar SRV records and their targets' addresses (the operator writes these, docs/dns-sd-records.md):"
section left "Leftovers (no consulted lease store holds them):"
section dangling "PTRs to a name under $domain that has no records:"
section missing "In a lease store but not in the zone (names as the comparison writes them):"
section child "Child zones:"
[ -s "$tmp/g.left" ] || { echo; echo "No leftovers."; }
