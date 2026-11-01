#!/usr/bin/bash

# - bring up proxy manually with ./proxy.sh
# - run this script
DIR=$(uname | tr '[:upper:]' '[:lower:]')
##
GITDIR="$(git rev-parse --show-toplevel)"
DIG_OPTIONS=${DIG_OPTIONS:-"+noall +answer @ns1.free2air.org"}

# set DNS RFC9664 lease test defaults
KEYLEASE=${KEYLEASE:-"250"}
LEASE=${LEASE:-"130"}

# set srp registration domain
DOMAIN=${DOMAIN:-"dev.zenr.io"}

# set wg Service Host description defaults
SERVER_HOSTNAME=${SERVER_HOSTNAME:-"vpn"}
SERVER_HOST_IP=${SERVER_HOST_IP:-"128.140.34.230"}

# server wg Service Description defaults
SERVER_SERVICE_NAME=${SERVER_SERVICE_NAME:-"wgservice"}
SERVER_SD_TYPE="_wg._udp"

# Set SRP Service Advertisement Details
SERVER_LISTENPORT=${SERVER_LISTENPORT:-"51820"} # SRV port
SERVER_NETWORK=${SERVER_NETWORK:-"192.168.179.0/24"}
SERVER_PUBKEY=${SERVER_PUBKEY:-"dLAovvPP0LQ8ZBgbAw4tkVb3wuqZyS9HFFutsAz+ezA="}

# debug: set CLIENT_SERVICE_NAME on command line
if [ "$#" -eq 1 ]; then
  CLIENT_SERVICE_NAME=${1:-"myclientservice"}
fi
# debug: set CLIENT_SERVICE_NAME on command line
# debug: set service instance name on command line
if [ "$#" -eq 2 ]; then
  CLIENT_SERVICE_NAME=${1:-"myclientservice"}
  SERVER_SERVICE_NAME=${2:-"wgservice"}
fi


CLIENT_HOSTNAME="myclient"
CLIENT_HOST_IP="10.10.10.10"
CLIENT_SD_TYPE="_wgpeer._udp"
CLIENT_SERVICE_NAME=${CLIENT_SERVICE_NAME:-"wgclientservice"}
CLIENT_SUBTYPE=${SERVER_SERVICE_NAME}
CLIENT_PUBKEY="mul5zgBo+f14SCYvsj6F1CJgZlO/LFm3dWJrRnCHZzQ="
#
# Request to use VPN service instance ${SERVER_SERVICE_NAME}
#
echo "****"
echo "**** Step 2: REQUEST: CLIENT Browses & Requests to be a VPN client: ${CLIENT_HOSTNAME} for SD VPN service: ${SERVER_SERVICE_NAME} with service type: ${CLIENT_SD_TYPE} and subtype: ${CLIENT_SUBTYPE}"
echo "****"

CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -host="${CLIENT_HOSTNAME}" \
  -addr="${CLIENT_HOST_IP}" \
  -instance=${CLIENT_SERVICE_NAME}:${CLIENT_SD_TYPE}:0 \
  -subtype="${CLIENT_SERVICE_NAME}:${CLIENT_SUBTYPE}" \
  -txt=${CLIENT_SERVICE_NAME}:"txtvers=1" \
  -txt=${CLIENT_SERVICE_NAME}:"pk=${CLIENT_PUBKEY}" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 \
  -once

echo
echo "*** 2.Requested (WG Client)"
echo
echo "== Browse ${SERVER_SD_TYPE} Service Instances Results"
SERVICE_INSTANCES=`dig ${DIG_OPTIONS} ${SERVER_SD_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
echo "${SERVICE_INSTANCES}"
echo
echo "== Published Request with ${SERVER_SERVICE_NAME}._sub.${CLIENT_SERVICE_NAME}.${CLIENT_SD_TYPE}.${DOMAIN}"
CLIENT_REQUEST=`dig ${DIG_OPTIONS} ${SERVER_SERVICE_NAME}._sub.${CLIENT_SD_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
echo "${CLIENT_REQUEST}"
echo


exit

