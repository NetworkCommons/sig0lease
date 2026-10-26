# tests/lib/srp.sh -- the SRP registrar the local-BIND SRP suites run (test_srp.sh,
# test_agent.sh): the real proxy, with srp_handler on lib/bind9.sh's srp.test. (and, with
# SRP_UPDATE_HANDLER=true, the RFC 9664 handler on its update.test.), plus queries straight to
# that BIND. A suite sets SRP_RUN_DIR, where the proxy's config, log, lease file and
# DNS-over-TLS certificate go, before sourcing this file. See lib/common.sh for the "no set -e,
# return not exit" rules this file follows.

if [ -n "${_SIG0LEASE_LIB_SRP_SOURCED:-}" ]; then
    return 0 2>/dev/null || true
fi
_SIG0LEASE_LIB_SRP_SOURCED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$LIB_DIR/common.sh"
# shellcheck source=./proxy.sh
source "$LIB_DIR/proxy.sh"
# shellcheck source=./dns.sh
source "$LIB_DIR/dns.sh"
# shellcheck source=./bind9.sh
source "$LIB_DIR/bind9.sh"

SRP_ZONE="srp.test."
SRP_PROXY_ADDR="127.0.0.1"
SRP_PROXY_PORT="${SRP_PROXY_PORT:-8159}"
SRP_PROXY_URL="${SRP_PROXY_ADDR}:${SRP_PROXY_PORT}"
BIND9_SRP_REGISTRAR_PORT="$SRP_PROXY_PORT" # the zone's _dnssd-srp._tcp SRV points here
SRP_PROXY_TLS_PORT="${SRP_PROXY_TLS_PORT:-8160}" # the proxy's DNS-over-TLS listener
BIND9_SRP_REGISTRAR_TLS_PORT="$SRP_PROXY_TLS_PORT" # the zone's _dnssd-srp-tls._tcp SRV points here
SRP_KEYSTORE_DIR="$BIND9_SRP_KEYSTORE_DIR"
SRP_REFUSE_ON_FOREIGN_DATA=true # the default; test_srp.sh's test_foreign_data_takeover restarts the proxy with false
# true: the proxy also runs the RFC 9664 handler (update) on update.test., with fcfs_naming as
# config.yaml has it, for test_agent.sh's names.
SRP_UPDATE_HANDLER="${SRP_UPDATE_HANDLER:-false}"

: "${SRP_RUN_DIR:?set SRP_RUN_DIR before sourcing lib/srp.sh}"
SRP_TMP_CONFIG="$SRP_RUN_DIR/config.yaml"
SRP_PROXY_LOG="$SRP_RUN_DIR/proxy.log"
SRP_TLS_DIR="$SRP_RUN_DIR/tls" # the DoT listener's throwaway certificate (make_tls_cert)
SRP_PROXY_PID=""

prepare_srp_config() {
    local update_handler="" modules='"srp_handler"'
    if [ "$SRP_UPDATE_HANDLER" = true ]; then
        update_handler="$(cat <<EOF
  update:
    upstream_zone: "${BIND9_UPDATE_ZONE}"
    keystore_dir: "${BIND9_UPDATE_KEYSTORE_DIR}"
    upstream: "${BIND9_ADDR}:${BIND9_PORT}"
    fcfs_naming: true
    lease_policy:
      min_key_lease_sec: 1
      max_key_lease_sec: 1209600
      min_rr_lease_sec: 1
      max_rr_lease_sec: 7200
    storage:
      type: file
      path: "${SRP_RUN_DIR}/lease_snapshot.json"
EOF
)"
        modules='"srp_handler", "update_handler"'
    fi
    cat > "$SRP_TMP_CONFIG" <<EOF
server:
  address: ":${SRP_PROXY_PORT}"
  diagnostics: true
  networks:
    - udp
    - tcp
    - tls
  tls:
    address: ":${SRP_PROXY_TLS_PORT}"
    cert: "${SRP_TLS_DIR}/cert.pem"
    key: "${SRP_TLS_DIR}/key.pem"
upstreams:
  - address: "8.8.8.8:53"
    protocol: "udp"
    timeout: "5s"
handlers:
  srp_handler:
    upstream_zone: "${SRP_ZONE}"
    keystore_dir: "${SRP_KEYSTORE_DIR}"
    upstream: "${BIND9_ADDR}:${BIND9_PORT}"
    allow_udp: true
    refuse_on_foreign_data: ${SRP_REFUSE_ON_FOREIGN_DATA}
    lease_policy:
      min_key_lease_sec: 1
      max_key_lease_sec: 1209600
      min_rr_lease_sec: 1
      max_rr_lease_sec: 7200
${update_handler}
authoritative:
  max_inflight_updates: ${BIND9_SIG0_QUOTA}
processing_rules:
  - opcode: 5
    modules: [${modules}]
EOF
}

# srp_run_prepare readies SRP_RUN_DIR for the proxy: its config, log and certificate.
srp_run_prepare() {
    proxy_run_prepare "$SRP_RUN_DIR" "$SRP_PROXY_PORT" || return 1
    mkdir "$SRP_TLS_DIR" && make_tls_cert "$SRP_TLS_DIR"
}

start_srp_proxy() {
    log_section "START: SRP proxy"
    prepare_srp_config
    # Appended to its log: test_srp.sh's test_foreign_data_takeover restarts the proxy.
    proxy_launch "$SRP_TMP_CONFIG" "$SRP_PROXY_PORT" "$SRP_PROXY_LOG" || return 1
    SRP_PROXY_PID="$LAUNCHED_PROXY_PID"
    log_success "SRP proxy listening (PID $SRP_PROXY_PID) on $SRP_PROXY_URL, DNS-over-TLS on port $SRP_PROXY_TLS_PORT, config $SRP_TMP_CONFIG"
}

stop_srp_proxy() {
    proxy_stop "$SRP_PROXY_PID"
    SRP_PROXY_PID=""
}

# dig_srp <name> <type> -- query BIND directly (not through the proxy), short form.
dig_srp() {
    dig_query_short "${BIND9_ADDR}:${BIND9_PORT}" "$1" "$2"
}

# wait_for_srp_state <name> <type> <present|absent> [timeout seconds, default 10]
wait_for_srp_state() {
    local name="$1" rr_type="$2" state="$3" timeout="${4:-10}"
    local start
    start=$(date +%s)
    while true; do
        local got
        got="$(dig_srp "$name" "$rr_type")"
        if [ "$state" = "present" ] && [ -n "$got" ]; then
            return 0
        fi
        if [ "$state" = "absent" ] && [ -z "$got" ]; then
            return 0
        fi
        if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
            log_error "Timed out waiting for $name/$rr_type state=$state (last dig: '$got')"
            return 1
        fi
        sleep 1
    done
}
