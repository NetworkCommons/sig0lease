#!/bin/bash
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
DOMAIN=${DOMAIN:-"srp.dev.zenr.io"}

# set wg Service Host description defaults
SERVER_HOSTNAME=${SERVER_HOSTNAME:-"vpn"}
SERVER_HOST_IP=${SERVER_HOST_IP:-"128.140.34.230"}

# server wg Service Description defaults
SERVER_SERVICE_NAME="myserver"
SERVER_SD_TYPE="_wg._udp"

# Set SRP Service Advertisement Details
SERVER_LISTENPORT=${SERVER_LISTENPORT:-"51820"} # SRV port
SERVER_NETWORK=${SERVER_NETWORK:-"192.168.179.0/24"}
SERVER_PUBKEY=${SERVER_PUBKEY:-"dLAovvPP0LQ8ZBgbAw4tkVb3wuqZyS9HFFutsAz+ezA="}


echo "****"
echo "**** Step 1: ADVERTISE: SERVER advertises a VPN Server with instance name ${SERVER_SERVICE_NAME}.${SERVER_SD_TYPE} over SD"
echo "****"

CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -server=127.0.0.1:8053 \
  -host="${SERVER_HOSTNAME}" \
  -addr="${SERVER_HOST_IP}" \
  -instance=${SERVER_SERVICE_NAME}:${SERVER_SD_TYPE}:${SERVER_LISTENPORT} \
  -txt="${SERVER_SERVICE_NAME}:txtvers=1" \
  -txt="${SERVER_SERVICE_NAME}:pk=${SERVER_PUBKEY}" \
  -txt="${SERVER_SERVICE_NAME}:net=${SERVER_NETWORK}" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 \
  -once


echo
echo "*** 1. Advertised (WG Server)"
echo
SERVICE_DISCOVERY=`dig ${DIG_OPTIONS} ${SERVER_SD_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
echo "=== Service Discovery Instruction Results"
echo ${SERVICE_DISCOVERY}
echo
echo "=== Service Description Instruction Results"
SERVICE_DESCRIPTION=`dig ${DIG_OPTIONS} ${SERVER_SERVICE_NAME}.${SERVER_SD_TYPE}.${DOMAIN} ANY | grep -v RRSIG | grep -v NSEC`
echo "${SERVICE_DESCRIPTION}"
echo
echo "=== Host Description Instruction Results"
HOST_DESCRIPTION=`dig ${DIG_OPTIONS} ${SERVER_HOSTNAME}.${DOMAIN} ANY | grep -v RRSIG | grep -v NSEC`
echo "${HOST_DESCRIPTION}"
echo



CLIENT_HOSTNAME="myclient"
CLIENT_HOST_IP="10.10.10.10"
CLIENT_SD_TYPE="_wgpeer._udp"
CLIENT_SERVICE_NAME="myclient"
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
  -server=127.0.0.1:8053 \
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






CONFIG_HOSTNAME=${SERVER_HOSTNAME}
CONFIG_HOST_IP=${SERVER_HOST_IP}
CONFIG_SD_TYPE="_wgcfg._udp"
CONFIG_LISTENPORT="${SERVER_LISTENPORT}"
CONFIG_SERVICE_NAME="${SERVER_SERVICE_NAME}-${CLIENT_SERVICE_NAME}"
CONFIG_SUBTYPE="${CLIENT_SERVICE_NAME}"
CLIENT_VPN_IP="192.168.178.254"
CLIENT_VPN_SUBNET_LEN="24"

echo "****"
echo "**** Step 3: ANSWER: SERVER watches ${SERVER_SERVICE_NAME}._sub.${CLIENT_SD_TYPE} For each new request, apply server admit policy, allocates client IP addresses and adds peer to wg configuration. If approved, the server registers ${SERVER_SERVICE_NAME}-${CLIENT_SERVICE_NAME}.${CONFIG_SD_TYPE} "
echo "****    (Initial Default server admit policy is allow all unless VPN network is already fully allocated)"
echo "****"

CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -server=127.0.0.1:8053 \
  -host="${CONFIG_HOSTNAME}" \
  -addr="${CONFIG_HOST_IP}" \
  -instance=${CONFIG_SERVICE_NAME}:${CONFIG_SD_TYPE}:${CONFIG_LISTENPORT} \
  -subtype="${CONFIG_SERVICE_NAME}:${CONFIG_SUBTYPE}" \
  -txt=${CONFIG_SERVICE_NAME}:"txtvers=1" \
  -txt=${CONFIG_SERVICE_NAME}:"peer=${CLIENT_PUBKEY}" \
  -txt=${CONFIG_SERVICE_NAME}:"addr=${CLIENT_VPN_IP}" \
  -txt=${CONFIG_SERVICE_NAME}:"allowed=${CLIENT_VPN_IP}/${CLIENT_VPN_SUBNET_LEN}" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 \
  -once

#sleep 2
echo
echo "*** 3. Answered (WG Server)"
echo

CONFIG_CMD="dig ${DIG_OPTIONS} ${CONFIG_SUBTYPE}._sub.${CONFIG_SD_TYPE}.${DOMAIN} PTR"
CONFIG_REQUEST=`${CONFIG_CMD}`
echo ${CONFIG_CMD}
echo ${CONFIG_REQUEST}
echo 





echo "****"
echo "**** Step 4: CONFIGURE: CLIENT  watches ${CLIENT_SERVICE_NAME}._sub.${CONFIG_SD_TYPE}. It looks for entry where SRV target host is ${SERVER_HOSTNAME} and whose TXT peer= is its own key. It the sets: address addr peer key pk of WG server, endpoint= SRV target and port, AllowedIPs to allowed="
echo "****"




exit











CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -server=127.0.0.1:8053 \
  -host="${CLIENT_HOSTNAME}" \
  -addr="${CLIENT_HOST_IP}" \
  -instance=${CLIENT_SERVICE_NAME}:${CLIENT_SD_TYPE}:0 \
  -subtype="${CLIENT_SERVICE_NAME}:${CLIENT_SUBTYPE}" \
  -txt=${CLIENT_SERVICE_NAME}:"txtvers=1 PublicKey=${CLIENT_PUBKEY}" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 \
  -once


echo
echo "*** 3. Answer (WG Server)"
echo

while true;
do
  clear
  echo "*** Advertise (WG Server) The server registers ${SERVER_INSTANCE}._wg._udp."
  echo
  SERVICE_DISCOVERY=`dig ${DIG_OPTIONS} ${SERVER_SD_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
  echo "=== Service Discovery Instruction Results"
  echo ${SERVICE_DISCOVERY}
  echo
  echo "=== Service Description Instruction Results"
  SERVICE_DESCRIPTION=`dig ${DIG_OPTIONS} ${SERVER_SERVICE_NAME}.${SERVER_SD_TYPE}.${DOMAIN} ANY | grep -v RRSIG | grep -v NSEC`
  echo "${SERVICE_DESCRIPTION}"
  echo
  echo "=== Host Description Instruction Results"
  HOST_DESCRIPTION=`dig ${DIG_OPTIONS} ${SERVER_HOSTNAME}.${DOMAIN} ANY | grep -v RRSIG | grep -v NSEC`
  echo "${HOST_DESCRIPTION}"
  echo
  echo "*** Request (WG Client)"
  echo
  echo "== Browse ${SERVER_SD_TYPE} Service Instances"
  SERVICE_INSTANCES=`dig ${DIG_OPTIONS} ${SERVER_SD_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
  echo "${SERVICE_INSTANCES}"
  echo
  echo "== Publish Request with ${SERVER_SERVICE_NAME}._sub.${CLIENT_SERVICE_NAME}.${CLIENT_SD_TYPE}.${DOMAIN}"
  CLIENT_REQUEST=`dig ${DIG_OPTIONS} ${SERVER_SERVICE_NAME}._sub.${CLIENT_SD_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
  echo "${CLIENT_REQUEST}"
  echo
  echo "*** Answer (WG Server)"
  echo
  echo "==  Server watches client requests for ${SERVER_SERVICE_NAME}._sub.${CLIENT_SD_TYPE}.${DOMAIN}"

  CLIENT_INSTANCE=`dig ${DIG_OPTIONS} ${SERVER_SERVICE_NAME}._sub.${CLIENT_SD_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
  echo "${CLIENT_INSTANCE}"

  echo ${CLIENT_INSTANCE} | wc -l

  sleep 2
done

exit
















echo "****"
echo "**** Step 3: VPN server instance: ${SERVER_SERVICE_NAME} scans for client request PTR records of ${SERVER_SERVICE_NAME}.sub.${SD_TYPE}.${DOMAIN}"
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

# this fails with  Step -1 commented out?
CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-client 127.0.0.1:8053 register ${SERVER_HOSTNAME}.${DOMAIN}. ${LEASE} ${KEYLEASE} "${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}.${SERVER_HOSTNAME}.${DOMAIN} 120 IN TXT \"Addr=10.10.10.10\"" --k=15  --same-key

echo "TXT record should be at ${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}.${SERVER_HOSTNAME}.${DOMAIN}"

dig @ns1.free2air.org ${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}.${SERVER_HOSTNAME}.${DOMAIN} TXT

