#!/bin/bash
# - bring up proxy manually with ./proxy.sh
# - run this script
DIR=$(uname | tr '[:upper:]' '[:lower:]')
##
GITDIR="$(git rev-parse --show-toplevel)"
KEYLEASE=250
LEASE=130
HOSTNAME="vpn"
DOMAIN="srp.dev.zenr.io"

SERVER_LISTENPORT=51820
#
# Register VPN 'Server'

SERVER_SERVICE_NAME="vpnserver"
SD_TYPE="_wg._udp"
HOST_IP="128.140.34.230"

SERVER_PUBKEY="dLAovvPP0LQ8ZBgbAw4tkVb3wuqZyS9HFFutsAz+ezA="

CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -server=127.0.0.1:8053 \
  -host="${HOSTNAME}" \
  -addr="${HOST_IP}" \
  -instance=${SERVER_SERVICE_NAME}:${SD_TYPE}:${SERVER_LISTENPORT} \
  -txt=${SERVER_SERVICE_NAME}:"txtver=1 PublicKey=${SERVER_PUBKEY} " \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 \
  -once

KEYLEASE=250
LEASE=130
HOSTNAME="vpnclient"
DOMAIN="srp.dev.zenr.io"
HOST_IP="10.10.10.10"
SD_TYPE="_${SERVER_SERVICE_NAME}._wg._udp"
SERVICE_NAME="vpnclient"
CLIENT_PUBKEY="mul5zgBo+f14SCYvsj6F1CJgZlO/LFm3dWJrRnCHZzQ="
#
# Register VPN 'Client'

CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -server=127.0.0.1:8053 \
  -host="${HOSTNAME}" \
  -addr="${HOST_IP}" \
  -instance=${SERVICE_NAME}:${SD_TYPE}:0 \
  -txt=${SERVICE_NAME}:"txtver=1 Peer=VPNServer PublicKey=${CLIENT_PUBKEY}" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 \
  -once

