#!/bin/bash
# demo/watch.sh [seconds|once] -- what anyone can see of the demo (docs/demo.md), asked of the
# zone's authoritative server every few seconds (default 2), with dig only: the service types and
# instances browsing finds in the SRP domain, and the records the demo names have. Ctrl-C stops
# it.
#
# NS, UPDATE_DOMAIN and SRP_DOMAIN change what it asks, as for the other scripts (demo/lib.sh);
# NAME, the names' labels, default demo, may list several, as D3's "a site".

. "$(dirname "$0")/lib.sh"
read -r -a names <<< "${NAME:-demo}"
every="${1:-2}"

# line <label> <answers> -- one record set, if there is one.
line() {
    [ -z "$2" ] || printf '  %-22s %s\n' "$1" "$(printf '%s' "$2" | tr '\n' ' ')"
}

show() {
    echo "$(date +%H:%M:%S), asked of $ns"
    echo
    echo "Browsing $srp_domain (RFC 6763, registered over RFC 9665):"
    local type instance label srv target found=
    for type in $(ask PTR "_services._dns-sd._udp.$srp_domain" | sort); do
        echo "  ${type%".$srp_domain."}"
        for instance in $(ask PTR "$type" | sort); do
            found=1
            label="${instance%".$type"}"
            srv="$(ask SRV "$instance")"
            target="${srv##* }"
            printf '    %-28s %s port %s  %s\n' "${label//\\032/ }" "$target" "$(cut -d' ' -f3 <<< "$srv")" "$(ask TXT "$instance" | tr '\n' ' ')"
            printf '    %-28s %s\n' "" "$( (ask A "$target"; ask AAAA "$target") | tr '\n' ' ')"
        done
    done
    [ -n "$found" ] || echo "  (no instances)"
    local name records
    for name in "${names[@]}"; do
        echo
        echo "Name $name.$update_domain (RFC 9664):"
        records="$(
            line "KEY" "$(ask KEY "$name.$update_domain" | cut -c1-40)"
            line "A, AAAA" "$(ask A "$name.$update_domain"; ask AAAA "$name.$update_domain")"
            line "TXT" "$(ask TXT "$name.$update_domain")"
            line "_dnslink TXT" "$(ask TXT "_dnslink.$name.$update_domain")"
            line "_dnsaddr TXT" "$(ask TXT "_dnsaddr.$name.$update_domain")"
            line "hello TXT" "$(ask TXT "hello.$name.$update_domain")"
        )"
        echo "${records:-  (no records)}"
    done
}

if [ "$every" = once ]; then
    show
    exit
fi
while :; do
    out="$(show)"
    printf '\033[H\033[2J%s\n' "$out"
    sleep "$every"
done
