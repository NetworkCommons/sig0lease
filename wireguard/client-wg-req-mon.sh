#!/usr/bin/bash

# - bring up proxy manually with ./proxy.sh
# - run this script
DIR=$(uname | tr '[:upper:]' '[:lower:]')
##
GITDIR="$(git rev-parse --show-toplevel)"

# includes ...
source get_mname.sh
source get_WG_attribute.sh
source ./env-client

DIG_OPTIONS=${DIG_OPTIONS:-"+noall +answer @${MNAME}"}

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


CLIENT_HOSTNAME="$(hostname -s)"
CLIENT_SERVICE_NAME="${CLIENT_HOSTNAME}"

# debug: set CLIENT_SERVICE_NAME on command line
if [ "$#" -eq 1 ]; then
  CLIENT_SERVICE_NAME=${1:-"myclientservice"}
fi

# debug: set CLIENT_SERVICE_NAME on command line
# debug: set service instance name on command line

if [ "$#" -eq 2 ]; then
  CLIENT_SERVICE_NAME=${1:-"${CLIENT_HOSTNAME}-wgcs"}
  SERVER_SERVICE_NAME=${2:-"wgservice"}
fi


CLIENT_HOST_IP="10.10.10.10"
CLIENT_SD_TYPE="_wgpeer._udp"
CLIENT_SERVICE_NAME=${CLIENT_SERVICE_NAME:-"${CLIENT_HOSTNAME}-wgclientservice"}
CLIENT_SUBTYPE=${SERVER_SERVICE_NAME}

# Does keypair for [client instance]-[server instance] exist?
#
# if not, create it
#
KEYPAIR_PATH=${KEYPAIR_PATH:-"/etc/wireguard"}
PUBKEY_FILENAME="${KEYPAIR_PATH}/publickey-${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}"
PRIVATEKEY_FILENAME="${KEYPAIR_PATH}/privatekey-${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}"

echo "wg genkey | tee \"${PRIVATEKEY_FILENAME}\" | wg pubkey > \"${PUBKEY_FILENAME}\""
wg genkey | tee "${PRIVATEKEY_FILENAME}" | wg pubkey > "${PUBKEY_FILENAME}"
CLIENT_PUBKEY="$(cat ${PUBKEY_FILENAME})"
echo "Generated keypair public key: ${CLIENT_PUBKEY} in ${KEYPAIR_PATH}"

#
# Request to use VPN service instance ${SERVER_SERVICE_NAME}
#
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



# SERVICE_INSTANCES=`dig ${DIG_OPTIONS} ${SERVER_SD_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
# echo "${SERVICE_INSTANCES}"
# echo

echo "== Published Request with ${SERVER_SERVICE_NAME}._sub.${CLIENT_SERVICE_NAME}.${CLIENT_SD_TYPE}.${DOMAIN}"
CLIENT_REQUEST=`dig ${DIG_OPTIONS} ${SERVER_SERVICE_NAME}._sub.${CLIENT_SD_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
echo "${CLIENT_REQUEST}"
echo

n=10
echo "Waiting ${n} seconds for a response ..."
sleep ${n}

# Look for config _wgcfg._udp type
#
#echo "DEBUG: get_WGCFG_attribute ${CLIENT_SERVICE_NAME} ${SERVER_SERVICE_NAME} ${DOMAIN} addr"

IP_ADDR="$(get_WGCFG_attribute ${CLIENT_SERVICE_NAME} ${SERVER_SERVICE_NAME} ${DOMAIN} addr)"
echo "IP = ${IP_ADDR}"
PEER="$(get_WGCFG_attribute ${CLIENT_SERVICE_NAME} ${SERVER_SERVICE_NAME} ${DOMAIN} pk)"
echo "PEER = ${PEER}"
ALLOWED="$(get_WGCFG_attribute ${CLIENT_SERVICE_NAME} ${SERVER_SERVICE_NAME} ${DOMAIN} allowed)"
#ALLOWED="10.0.0.0/24"
echo "ALLOWED = ${ALLOWED}"
#
# SERVER_HOSTNAME & SERVER_LISTENPORT should be fetched from the _wg._udp service type SRV record

echo "ip link add dev ${VPN_INTERFACE} type wireguard"
echo "ip address add dev ${VPN_INTERFACE} ${IP_ADDR}/27"
echo "ip link set up dev ${VPN_INTERFACE}"
echo "wg set ${VPN_INTERFACE} listen-port 51820 private-key /etc/wireguard/privatekey-${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}"

ip link add dev ${VPN_INTERFACE} type wireguard
ip address add dev ${VPN_INTERFACE} ${IP_ADDR}/27
ip link set up dev ${VPN_INTERFACE}
wg set ${VPN_INTERFACE} listen-port 51820 private-key /etc/wireguard/privatekey-${CLIENT_SERVICE_NAME}.${SERVER_SERVICE_NAME}

echo "wg set ${VPN_INTERFACE} peer ${PEER} allowed-ips ${ALLOWED} endpoint ${SERVER_HOSTNAME}.${DOMAIN}:${SERVER_LISTENPORT}"
wg set ${VPN_INTERFACE} peer ${PEER} allowed-ips ${ALLOWED} endpoint ${SERVER_HOSTNAME}.${DOMAIN}:${SERVER_LISTENPORT}
exit

