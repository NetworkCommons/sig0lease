#!/bin/bash

# BASH Wireguard service (_wg._udp) client request monitoring

# Server steps:
#
# 1.  (1) Advertise:  The server registers  S._wg._udp. under domain to ensure the service is still publishe
# 2.  (3) The server watches S._sub._wgpeer._udp. For each new request it decides whether to admit the client (policy to be defined). If it admits the client, it allocates an address and adds the peer to its interface. It then registers S-Ci._wgcfg._udp with subtype Ci. A refused client gets the same record with status=refused and no addr or allowed.

# set defaults of any required ENV var that isn't set

# dig util options
DIG_OPTIONS=${DIG_OPTIONS:-"+noall +answer +short @ns1.free2air.org"}

source ./env

# set service domain
DOMAIN=${DOMAIN:-"dev.zenr.io"}



echo "****"
echo "**** Step 1: ADVERTISE: SERVER advertises a VPN Server with instance name ${SERVER_SERVICE_NAME}.${SERVER_SD_TYPE} over SD"
echo "****"

CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -host="${SERVER_HOSTNAME}" \
  -addr="${SERVER_HOST_IP}" \
  -instance=${SERVER_SERVICE_NAME}:${SERVER_SD_TYPE}:${SERVER_LISTENPORT} \
  -txt="${SERVER_SERVICE_NAME}:txtvers=1" \
  -txt="${SERVER_SERVICE_NAME}:pk=${SERVER_PUBKEY}" \
  -txt="${SERVER_SERVICE_NAME}:net=${SERVER_NETWORK}" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 -once 
# \ -once



# set client request service type for request
REQ_SERVICE_TYPE=${REQ_SERVICE_TYPE:-"_wgpeer._udp"}

# service name to monitor requests for
REQ_SERVICE_NAME=${SERVER_SERVICE_NAME:-"myservice"}

# service name to provide config to ...
ANS_SERVICE_TYPE=${ANS_SERVICE_TYPE:-"_wgcfg._udp"}




echo "2.  The server watches S._sub._wgpeer._udp. For each new request it decides whether to admit the client (policy to be defined). If it admits the client, it allocates an address and adds the peer to its interface. It then registers S-Ci._wgcfg._udp with subtype Ci. A refused client gets the same record with status=refused and no addr or allowed."
echo

while true
do
    CLIENT_REQUESTS=`dig ${DIG_OPTIONS} ${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
    echo "*ALL* SERVICE CLIENT_REQUESTS WITHIN DOMAIN ${DOMAIN}:"
    echo "${CLIENT_REQUESTS}"
    echo
    # 
    
    echo "SERVICE subtype '${REQ_SERVICE_NAME}' CLIENT_REQUESTS :" 
    CLIENT_REQUESTS_SUB=`dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}._sub.${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
    
    # substitute new line for space in list for looping ...
    CLIENT_LOOP="${CLIENT_REQUESTS_SUB//$'\n'/ }"
    
    # loop over client requests and collect those without corresponding _wgcfg entries for ${REQ_SERVICE_NAME}
    for Ci in $(echo ${CLIENT_LOOP})
    do
      Ci_REQ="$(dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}.${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC)"
    # echo "Ci_REQ: dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}.${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC"
      Ci_TXT="$(dig ${DIG_OPTIONS} ${Ci} TXT)"
      Ci_SRV="$(dig ${DIG_OPTIONS} ${Ci} SRV)"
      Ci_CFG="$(dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}-${Ci%%.*}.${ANS_SERVICE_TYPE}.${DOMAIN} TXT | grep -v RRSIG | grep -v NSEC)"
    # echo "${Ci}: SRV:${Ci_SRV} TXT:${Ci_REQ} (len:${#Ci_REQ})" 
      echo "${Ci}: SRV: ${Ci_SRV} TXT: ${Ci_TXT} (len:${#Ci_TXT})" 
    # echo "${Ci}: ${Ci_CFG} (len:${#Ci_CFG})" 
    done
    echo
    echo "====="
    echo
    
    SERVER_ANSWERS_DIG="dig ${DIG_OPTIONS} ${ANS_SERVICE_TYPE}.${DOMAIN} PTR"
    echo "SERVER_ANSWERS_DIG: ${SERVER_ANSWERS_DIG}"
    echo "---"
    echo $(${SERVER_ANSWERS_DIG} | grep -v RRSIG | grep -v NSEC)
    echo "---"
    sleep 2
    clear
    date
done


# echo "SERVER_ANSWERS:"
# 
# # set server answer service type for answer
# ANS_SERVICE_SUBTYPE=${ANS_SERVICE_SUBTYPE:-"${REQ_SERVICE_NAME}._sub"}
# 
# 
# CLIENT_SERVICE_NAME="bar"
# SERVER_ANSWER_TXT=`dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}-${CLIENT_SERVICE_NAME}.${ANS_SERVICE_TYPE}.${DOMAIN} TXT | grep -v RRSIG | grep -v NSEC`
# echo "${CLIENT_SERVICE_NAME}:${SERVER_ANSWER_TXT}"
# 
# CLIENT_SERVICE_NAME="foo"
# SERVER_ANSWER_TXT=`dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}-${CLIENT_SERVICE_NAME}.${ANS_SERVICE_TYPE}.${DOMAIN} TXT | grep -v RRSIG | grep -v NSEC`
# echo "${CLIENT_SERVICE_NAME}:${SERVER_ANSWER_TXT}"
# 


