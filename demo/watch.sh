#!/bin/bash
# demo/watch.sh [seconds|once] -- what anyone can see of the demo (docs/demo.md), asked of the
# zone's authoritative server every few seconds (default 2), with dig only: the service types and
# instances browsing finds in the SRP domain, and the demo name's records. Ctrl-C stops it.
#
# NS, DOMAIN, ZONE and NAME change what it asks; defaults: ns1.free2air.org, srp.dev.zenr.io,
# dev.zenr.io, demo.

ns="${NS:-ns1.free2air.org}"
domain="${DOMAIN:-srp.dev.zenr.io}"
zone="${ZONE:-dev.zenr.io}"
name="${NAME:-demo}"
every="${1:-2}"

ask() { dig +short +time=2 +tries=1 "@$ns" "$@"; }

# line <label> <answers> -- one record set, "-" when there is none.
line() {
    local answers
    answers="$(printf '%s' "$2" | tr '\n' ' ')"
    printf '  %-22s %s\n' "$1" "${answers:--}"
}

show() {
    echo "$(date +%H:%M:%S), asked of $ns"
    echo
    echo "Browsing $domain (RFC 6763, registered over RFC 9665):"
    local type instance label srv target found=
    for type in $(ask PTR "_services._dns-sd._udp.$domain" | sort); do
        echo "  ${type%".$domain."}"
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
    echo
    echo "Name $name.$zone (RFC 9664):"
    line "KEY" "$(ask KEY "$name.$zone" | cut -c1-40)"
    line "A, AAAA" "$(ask A "$name.$zone"; ask AAAA "$name.$zone")"
    line "TXT" "$(ask TXT "$name.$zone")"
    line "_dnslink TXT" "$(ask TXT "_dnslink.$name.$zone")"
    line "hello TXT" "$(ask TXT "hello.$name.$zone")"
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
