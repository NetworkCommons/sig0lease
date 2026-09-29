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

#
# Register VPN 'Server'

SERVICE_NAME="VPNServer"
SD_TYPE="_wg._udp"
HOST_IP="138.201.89.108"


CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -server=127.0.0.1:8053 \
  -host="${HOSTNAME}" \
  -addr="${HOST_IP}" \
  -instance=${SERVICE_NAME}:${SD_TYPE}:668 \
  -txt=${SERVICE_NAME}:"txtver=1 PublicKey=IstwnIfVuvgfb7LzaE3YLb24FAT2oUEhVcsZILDhHXk=" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 \
  -once

KEYLEASE=250
LEASE=130
HOSTNAME="vpnclient"
DOMAIN="srp.dev.zenr.io"
HOST_IP="10.10.10.10"
SERVICE_NAME="vpnclient"
SD_TYPE="_VPNServer._wg._udp"

#
# Register VPN 'Client'

CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -server=127.0.0.1:8053 \
  -host="${HOSTNAME}" \
  -addr="${HOST_IP}" \
  -instance=${SERVICE_NAME}:${SD_TYPE}:0 \
  -txt=${SERVICE_NAME}:"txtver=1 Peer=VPNServer PublicKey=<client-public-key>" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 \
  -once


