#!/bin/bash
# - bring up proxy manually with ./proxy.sh
# - run this script
DIR=$(uname | tr '[:upper:]' '[:lower:]')
##
GITDIR="$(git rev-parse --show-toplevel)"
DIG_OPTIONS="+noall +answer @ns1.free2air.org"

KEYLEASE=250
LEASE=130
SERVER_HOSTNAME="vpn"
DOMAIN="srp.dev.zenr.io"

SERVER_LISTENPORT=51820
#
#

 echo "****"
 echo "**** Step -1: DEBUG: Send non-SRP request with ${SERVER_HOSTNAME}.${DOMAIN} KEY first"
 echo "****"

# when commented this script errors on final sig0lease-client invocation
# when uncommented, this causes all client invocations to succeed (at least while the lease is active?)
CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/linux/sig0lease-client 127.0.0.1:8053 register ${SERVER_HOSTNAME}.${DOMAIN} ${LEASE} ${KEYLEASE}  "${SERVER_HOSTNAME}.${DOMAIN}. 30 IN TXT \"well well well\""  " ${SERVER_HOSTNAME}.${DOMAIN}. 30 IN TXT \"second well\"" "${SERVER_HOSTNAME}.${DOMAIN}. 30 IN TXT \"third well\"" --k=15 --same-key



SERVER_SERVICE_NAME="myserver"
SD_TYPE="_wg._udp"
HOST_IP="128.140.34.230"

SERVER_PUBKEY="dLAovvPP0LQ8ZBgbAw4tkVb3wuqZyS9HFFutsAz+ezA="

echo "****"
echo "**** Step 0: Register a VPN 'Server' for SD with service type _wg"
echo "****"

CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -server=127.0.0.1:8053 \
  -host="${SERVER_HOSTNAME}" \
  -addr="${HOST_IP}" \
  -instance=${SERVER_SERVICE_NAME}:${SD_TYPE}:${SERVER_LISTENPORT} \
  -txt=${SERVER_SERVICE_NAME}:"txtver=1 PublicKey=${SERVER_PUBKEY}" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 \
  -once



KEYLEASE=250
LEASE=130
CLIENT_HOSTNAME="myclient"
DOMAIN="srp.dev.zenr.io"
HOST_IP="10.10.10.10"
SD_TYPE="_wgpeer._udp"
CLIENT_SERVICE_NAME="myclient"
SUBTYPE=${SERVER_SERVICE_NAME}
CLIENT_PUBKEY="mul5zgBo+f14SCYvsj6F1CJgZlO/LFm3dWJrRnCHZzQ="
#
# Register VPN 'Client'

echo "****"
echo "**** Step 1: Register a VPN client: ${HOST_NAME} for SD VPN service: ${SERVER_SERVICE_NAME} with service type: ${SD_TYPE} and subtype: ${SUBTYPE}"
echo "****"

CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -server=127.0.0.1:8053 \
  -host="${CLIENT_HOSTNAME}" \
  -addr="${HOST_IP}" \
  -instance=${CLIENT_SERVICE_NAME}:${SD_TYPE}:0 \
  -subtype="${CLIENT_SERVICE_NAME}:${SUBTYPE}" \
  -txt=${CLIENT_SERVICE_NAME}:"txtver=1 PublicKey=${CLIENT_PUBKEY}" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 \
  -once

echo "****"
echo "**** Step 2: VPN server instance: ${SERVER_SERVICE_NAME} scans for client request PTR records of ${SERVER_SERVICE_NAME}.sub.${SD_TYPE}.${DOMAIN}"
echo "****"

# wait ...
sleep 1
echo "dig ${DIG_OPTIONS} ${SERVER_SERVICE_NAME}._sub.${SD_TYPE}.${DOMAIN} PTR"
dig ${DIG_OPTIONS} ${SERVER_SERVICE_NAME}._sub.${SD_TYPE}.${DOMAIN} PTR
dig +short ${DIG_OPTIONS} ${SERVER_SERVICE_NAME}._sub.${SD_TYPE}.${DOMAIN} PTR


echo "****"
echo "**** Step 3: VPN server instance: ${SERVER_SERVICE_NAME} scans for client service instance PublicKEY A/V pair in TXT RR"
echo "****"

CLIENT_SERVICE="$(dig +short ${DIG_OPTIONS} ${SERVER_SERVICE_NAME}._sub.${SD_TYPE}.${DOMAIN} PTR)"
echo "Server discovers client long service name: ${CLIENT_SERVICE}"
CLIENT_TXT="$(dig +short ${DIG_OPTIONS} ${CLIENT_SERVICE} TXT)"
echo "Server discovers Client Service PublicKey: ${CLIENT_TXT}"


echo "****"
echo "**** Step 4: VPN server instance: ${SERVER_SERVICE_NAME} sets TXT record for client details (IP Address/Netmask)"
echo "****"

CLIENT_SERVICE_NAME="${CLIENT_SERVICE%%'.'*}"
echo "Server derives short client instance name: ${CLIENT_SERVICE_NAME} from full client name: ${CLIENT_SERVICE}"

echo "Server knows its own service: ${SERVER_SERVICE_NAME}.${SD_TYPE}.${DOMAIN}"

echo "Server can construct specific configuration TXT record (outside of SRP for now): ${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}.${SD_TYPE}.${DOMAIN}"
SERVER_HOSTNAME="vpn"
echo "${GITDIR}/bin/${DIR}/sig0lease-client 127.0.0.1:8053 register ${SERVER_HOSTNAME}.${DOMAIN} ${LEASE} ${KEYLEASE} \"${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}.${SERVER_HOSTNAME}.${DOMAIN} 120 IN TXT \\\"Addr=10.10.10.10\\\"\""

# this looks suss
# CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-client 127.0.0.1:8053 register ${SERVER_HOSTNAME}.${DOMAIN}. ${LEASE} ${KEYLEASE} "${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}.${SERVER_HOSTNAME}.${DOMAIN} 120 IN TXT \"Addr=10.10.10.10\"" --k=15  --same-key

# let's remove the SERVER_SERVICE_NAME ...
CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-client 127.0.0.1:8053 register ${SERVER_HOSTNAME}.${DOMAIN}. ${LEASE} ${KEYLEASE} "${CLIENT_SERVICE_NAME}.${SERVER_HOSTNAME}.${DOMAIN} 120 IN TXT \"Addr=10.10.10.10\"" --k=15  --same-key

echo "TXT record should be at ${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}.${SERVER_HOSTNAME}.${DOMAIN}"

dig @ns1.free2air.org ${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}.${SERVER_HOSTNAME}.${DOMAIN} TXT

## Following gives error:
## -- INFO -- "SRP UPDATE for zone srp.dev.zenr.io.: host=myclient.myserver.srp.dev.zenr.io. instances=1 discovery=2"
## -- "SRP handler: FCFS conflict for myclient._wgpeer._udp.srp.dev.zenr.io. -- name held by a different key"

# CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
#   -domain="${DOMAIN}" \
#   -server=127.0.0.1:8053 \
#   -host="${CLIENT_HOSTNAME}.${SERVER_SERVICE_NAME}" \
#   -addr="${HOST_IP}" \
#   -instance=${CLIENT_SERVICE_NAME}:${SD_TYPE}:0 \
#   -subtype="${CLIENT_SERVICE_NAME}:${SUBTYPE}" \
#   -txt=${CLIENT_SERVICE_NAME}:"txtver=1 Address=WOOHOO" \
#   -lease=${LEASE} -keylease=${KEYLEASE} \
#   -keystore="${GITDIR}/keystore/client" -k=15 \
#   -once
