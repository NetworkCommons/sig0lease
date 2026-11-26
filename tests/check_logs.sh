#!/bin/bash
#
# Collects the logs to check for problems around a demo: the registrar's proxy (sig0lease@stable)
# and nginx, and the BIND of ns1, the authoritative server of zenr.io. It needs
# ssh aliases for registrar and free2air, and writes every result to LOGFILE, each after a TEST line.
#
# Every test looks at the same time window, SINCE to UNTIL, in the syntax of GNU date -d, which
# the registrar reads (its clock is on UTC): "00:00" is today's midnight UTC, "1 hour ago",
# "yesterday 18:00", "2026-11-26 05:00 UTC". GNU date reads "today" as now, not midnight.
#
#   tests/check_logs.sh                                  # today, from 00:00 UTC
#   SINCE="1 hour ago" tests/check_logs.sh
#   SINCE="2026-11-26 05:00 UTC" UNTIL="2026-11-26 05:20 UTC" tests/check_logs.sh
#
# Each host compares the window with its logs' own times (ns1's are CET). A log whose rotation has
# already dropped part of the window is listed under LOGS THAT START AFTER SINCE.

SINCE=${SINCE:-00:00}
UNTIL=${UNTIL:-now}

# The window in seconds since the epoch, read by the registrar's GNU date (the Mac's has no -d).
FROM=$(ssh registrar "date -d '$SINCE' +%s") || { echo "The registrar could not read SINCE=$SINCE" >&2; exit 1; }
TO=$(ssh registrar "date -d '$UNTIL' +%s") || { echo "The registrar could not read UNTIL=$UNTIL" >&2; exit 1; }
[ "$FROM" -le "$TO" ] || { echo "SINCE=$SINCE is later than UNTIL=$UNTIL" >&2; exit 1; }

LOGFILE=$(mktemp) || exit 1
echo "Logging to ${LOGFILE}"

# Shell functions both hosts run before their tests (each host gets FROM and TO as $1 and $2).
HELPERS=$(cat <<'EOF'
FROM=$1 TO=$2
FROMKEY=$(date -d "@$FROM" +%Y%m%d%H%M%S) || exit 1
TOKEY=$(date -d "@$TO" +%Y%m%d%H%M%S) || exit 1

# An awk function, key(mode), that turns a log line's time into YYYYMMDDhhmmss, or "" when the
# line has none. Modes: nginx-access ("[26/Nov/2026:00:43:44 +0000]" in field 4), nginx-error
# ("2026/11/26 10:00:01 ..."), bind ("26-Nov-2026 06:04:47.123 ...").
KEY='
BEGIN { n = split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " "); for (i = 1; i <= n; i++) mon[m[i]] = sprintf("%02d", i) }
function key(mode,   t, k) {
  if (mode == "nginx-access") {
    t = substr($4, 2)
    k = substr(t, 8, 4) mon[substr(t, 4, 3)] substr(t, 1, 2) substr(t, 13, 2) substr(t, 16, 2) substr(t, 19, 2)
  } else if (mode == "nginx-error") {
    k = $1 $2; gsub(/[\/:]/, "", k)
  } else {
    k = substr($1, 8, 4) mon[substr($1, 4, 3)] substr($1, 1, 2) substr($2, 1, 2) substr($2, 4, 2) substr($2, 7, 2)
  }
  return (length(k) == 14 && k !~ /[^0-9]/) ? k : ""
}
'

# logs FILE...: the lines of those files (gzipped or not) written to since SINCE, oldest file first.
logs() {
  local f
  for f in $(ls -1tr "$@"); do
    [ "$(stat -c %Y "$f")" -ge "$FROM" ] && zcat -f "$f"
  done
}

# window MODE: the lines on stdin whose time lies between SINCE and UNTIL.
window() {
  awk -v mode="$1" -v from="$FROMKEY" -v to="$TOKEY" "$KEY"'{ k = key(mode); if (k != "" && k >= from && k <= to) print }'
}

# gone LABEL MODE FILE...: LABEL and the time of the oldest line those files still hold, when that
# time is later than SINCE.
gone() {
  local label=$1 mode=$2
  shift 2
  zcat -f "$(ls -1tr "$@" | head -1)" | head -1 | awk -v mode="$mode" -v label="$label" -v from="$FROMKEY" "$KEY"'{
    k = key(mode)
    if (k == "") printf "%-18s its oldest line has no time: %s\n", label, $0
    else if (k > from) printf "%-18s from %s-%s-%s %s:%s:%s\n", label, substr(k, 1, 4), substr(k, 5, 2), substr(k, 7, 2), substr(k, 9, 2), substr(k, 11, 2), substr(k, 13, 2)
  }'
}
EOF
)

# --- The registrar: the proxy's journal and nginx's logs (UTC) ---
{ echo "$HELPERS"; cat <<'EOF'
NGINX=/var/log/nginx

echo "WINDOW $(date -u -d "@$FROM" '+%F %T') .. $(date -u -d "@$TO" '+%F %T') UTC"

echo "LOGS THAT START AFTER SINCE (registrar)"
# nginx's logs rotate daily and keep 14 days; stable's 443 and staging's 8444 share them.
out=$(gone access.log nginx-access $NGINX/access.log*; gone error.log nginx-error $NGINX/error.log*)
echo "${out:-none}"

echo "TEST 1: the proxy's ERROR and WARN lines"
journalctl -u sig0lease@stable --since "@$FROM" --until "@$TO" --no-pager | grep -E -- '-- (ERROR|WARN) --'

echo "TEST 2: the proxy's ERROR and WARN lines, counted per message"
journalctl -u sig0lease@stable --since "@$FROM" --until "@$TO" -o cat | grep -E -- '-- (ERROR|WARN) --' | sed -E 's/^.* -- (ERROR|WARN) -- /\1 /' | sort | uniq -c | sort -rn

echo "TEST 3: nginx's errors, counted per message"
# Rate-limit refusals, failed connections to the proxy, DNS-over-TLS connection limits.
logs $NGINX/error.log* | window nginx-error | sed -E 's/^[0-9/]+ [0-9:]+ //; s/[0-9]+#[0-9]+: (\*[0-9]+ )?//; s/excess: [0-9.]+/excess: N/; s/, client: .*//' | sort | uniq -c | sort -rn

echo "TEST 4: DNS-over-HTTPS requests stable's rate limit refused"
logs $NGINX/error.log* | window nginx-error | grep -c 'limiting requests.*sig0lease_doh_stable'

echo "TEST 5: the HTTP status codes of the DNS-over-HTTPS (/dns-query) requests, counted"
logs $NGINX/access.log* | window nginx-access | awk '$7 ~ "^/dns-query" {print $9}' | sort | uniq -c | sort -rn

echo "TEST 6: the requests nginx answered with status 400 or above"
logs $NGINX/access.log* | window nginx-access | awk '$9 >= 400'

echo "TEST 7: the DNS-over-HTTPS requests per client address"
logs $NGINX/access.log* | window nginx-access | awk '$7 ~ "^/dns-query" {print $1}' | sort | uniq -c | sort -rn

echo "TEST 8: the DNS-over-HTTPS requests per hour (UTC)"
logs $NGINX/access.log* | window nginx-access | awk '$7 ~ "^/dns-query" {print substr($4, 2, 14) "h"}' | uniq -c

echo "TEST 9: the DNS-over-HTTPS requests per client address, page (referer without its query string) and browser"
logs $NGINX/access.log* | window nginx-access | awk -F'"' '$2 ~ "^[A-Z]+ /dns-query" {split($1, a, " "); sub(/\?.*/, "", $4); print a[1] "  " $4 "  " $6}' | sort | uniq -c | sort -rn
EOF
} | ssh registrar bash -s -- "$FROM" "$TO" >> "${LOGFILE}" 2>&1

# --- ns1's BIND: /var/log/named, one file per category, rotated by size (CET) ---
{ echo "$HELPERS"; cat <<'EOF'
NAMED=/var/log/named

echo "WINDOW (ns1) $(date -d "@$FROM" '+%F %T') .. $(date -d "@$TO" '+%F %T %Z')"

echo "LOGS THAT START AFTER SINCE (ns1)"
# queries.log* hold only minutes when the registrar sends a lot of queries.
out=$(for f in $NAMED/*.log; do gone "${f##*/}" bind "$f"*; done)
echo "${out:-none}"

echo "TEST 10: database.log's lines per date and hour (CET)"
# BIND's "too many records (must not exceed 100)" goes there.
logs $NAMED/database.log* | window bind | cut -c1-14 | uniq -c

echo "TEST 11: database.log's lines, counted per message, quoted names replaced by NAME"
logs $NAMED/database.log* | window bind | sed -E 's/^[^ ]+ [^ ]+ //; s/\x27[^\x27]*\x27/NAME/g' | sort | uniq -c

echo "TEST 12: the UPDATEs' log lines, counted per action, service instance names replaced by INSTANCE"
logs $NAMED/update.log* | window bind | sed -E 's/^[^ ]+ [^ ]+ //; s/client @0x[0-9a-f]+ //; s/#[0-9]+/#P/; s/\x27[^\x27]*\._[a-z0-9-]+\._(tcp|udp)\.[^\x27]*\x27/INSTANCE/g' | sort | uniq -c | sort -rn

echo "TEST 13: the queries per client address (the registrar is 2a01:4f8:1c0c:714d::1)"
logs $NAMED/queries.log* | window bind | awk '{sub(/#.*/, "", $5); print $5}' | sort | uniq -c | sort -rn

echo "TEST 14: failure, refusal and rate-limit lines about the registrar or dev.zenr.io in all logs, counted per date, hour and message"
logs $NAMED/*.log $NAMED/*.log.[0-9] | window bind | grep -E '2a01:4f8:1c0c:714d::1|dev\.zenr\.io' | grep -v ' query: ' | grep -i -E 'too many|fail|denied|refus|error|limit' | sed -E 's/^([0-9]{2}-[A-Za-z]{3}-[0-9]{4}) ([0-9]{2}):[0-9:.]+ /\1 \2h /; s/client @0x[0-9a-f]+ //; s/#[0-9]+/#P/; s/\x27[^\x27]*\x27/NAME/g' | sort | uniq -c
EOF
} | ssh free2air bash -s -- "$FROM" "$TO" >> "${LOGFILE}" 2>&1

echo "Done: ${LOGFILE}"
