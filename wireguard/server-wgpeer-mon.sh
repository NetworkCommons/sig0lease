#!/bin/bash

# BASH Wireguard service (_wg._udp) client request monitoring

# Server steps:
#
# 1.  (1) Advertise:  The server registers  S._wg._udp. under domain to ensure the service is still publishe
# 2.  (3) The server watches S._sub._wgpeer._udp. For each new request it decides whether to admit the client (policy to be defined). If it admits the client, it allocates an address and adds the peer to its interface. It then registers S-Ci._wgcfg._udp with subtype Ci. A refused client gets the same record with status=refused and no addr or allowed.

# set defaults of any required ENV var that isn't set

source ./env

clear

# Step 1: ADVERTISE: SERVER advertises a VPN Server with instance name ${SERVER_SERVICE_NAME}.${SERVER_SD_TYPE} over SD"
#
CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
  -domain="${DOMAIN}" \
  -host="${SERVER_HOSTNAME}" \
  -addr="${SERVER_HOST_IP}" \
  -instance=${SERVER_SERVICE_NAME}:${SERVER_SD_TYPE}:${SERVER_LISTENPORT} \
  -txt="${SERVER_SERVICE_NAME}:txtvers=1" \
  -txt="${SERVER_SERVICE_NAME}:peer=${SERVER_PUBKEY}" \
  -txt="${SERVER_SERVICE_NAME}:net=${SERVER_NETWORK}" \
  -lease=${LEASE} -keylease=${KEYLEASE} \
  -keystore="${GITDIR}/keystore/client" -k=15 -once 

# Step 3: ANSWER: The server watches S._sub._wgpeer._udp. For each new request it decides whether to admit the client (policy to be defined).
# If it admits the client, it allocates an address and adds the peer to its interface. It then registers S-Ci._wgcfg._udp with subtype Ci. 
# (not yet implemented) A refused client gets the same record with status=refused and no addr or allowed.
echo

while true
do

    echo "=== Browse Domains"
    dig ${BROWSE_DIG_OPTIONS} b._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} db._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} lb._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} r._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} dr._dns-sd._udp.${DOMAIN}. PTR

    echo
    echo "=== ACTIVE SERVICE TYPES IN ${DOMAIN}"
    dig ${SHORT_DIG_OPTIONS} _services._dns-sd._udp.${DOMAIN}. PTR | grep -v RRSIG | grep -v NSEC
    echo


    echo "=== ACTIVE Wireguard Service Instances"
    WG_SERVICE_INSTANCES=`dig ${SHORT_DIG_OPTIONS} _wg._udp.${DOMAIN}. PTR | grep -v RRSIG | grep -v NSEC`
    echo ${WG_SERVICE_INSTANCES}
    echo


    CLIENT_REQUESTS=`dig ${SHORT_DIG_OPTIONS} ${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
    echo "== *ALL* WIREGUARD SERVICE CLIENT_REQUESTS WITHIN DOMAIN ${DOMAIN}:"
    echo "${CLIENT_REQUESTS}"
    echo
    # 
    
    echo "** SERVICE subtype '${REQ_SERVICE_NAME}' CLIENT_ANSWERS"

    CLIENT_REQUESTS_SUB=`dig ${SHORT_DIG_OPTIONS} ${REQ_SERVICE_NAME}._sub.${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
    CLIENT_LOOP="${CLIENT_REQUESTS_SUB//$'\n'/ }" # substitute new line for space in list for looping ...
    
    # loop over client requests and collect those without corresponding _wgcfg entries for ${REQ_SERVICE_NAME}
    if (( ${#CLIENT_LOOP} > 0 )); then
      for Ci in $(echo ${CLIENT_LOOP})
      do
        Ci_REQ="$(dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}.${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC)"
        Ci_TXT="$(dig ${DIG_OPTIONS} ${Ci} TXT)"
        Ci_SRV="$(dig ${DIG_OPTIONS} ${Ci} SRV)"
        # first line with sub - its a pointer
        # Ci_CFG="$(dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}-${Ci%%.*}.${Ci%%.*}._sub.${ANS_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC)"
        Ci_CFG="$(dig ${SHORT_DIG_OPTIONS} ${REQ_SERVICE_NAME}-${Ci%%.*}.${ANS_SERVICE_TYPE}.${DOMAIN} TXT | grep -v RRSIG | grep -v NSEC)"
        # echo "** DEBUG: ${Ci}: SRV: ${Ci_SRV} TXT: ${Ci_TXT} (len:${#Ci_TXT}) : CFG: ${Ci_CFG}"

        if (( ${#Ci_CFG} == 0 )); then
          echo "${Ci%%.*} needs a config"
          # TEST DATA (DEBUG)
          WG_CLIENT_IP="172.16.0.254"
          WG_CLIENT_NET="172.16.0.0/24"
          CLIENT_KEYSTORE_DIR="${GITDIR}/keystore/client" ${GITDIR}/bin/${DIR}/sig0lease-srp-client \
            -domain="${DOMAIN}" \
            -host="${SERVER_HOSTNAME}" \
            -addr="${SERVER_HOST_IP}" \
            -instance="${SERVER_SERVICE_NAME}-${Ci%%.*}:${ANS_SERVICE_TYPE}:${SERVER_LISTENPORT}" \
            -subtype="${SERVER_SERVICE_NAME}-${Ci%%.*}:${Ci%%.*}" \
            -txt="${SERVER_SERVICE_NAME}-${Ci%%.*}:txtvers=1" \
            -txt="${SERVER_SERVICE_NAME}-${Ci%%.*}:pk=${SERVER_PUBKEY}" \
            -txt="${SERVER_SERVICE_NAME}-${Ci%%.*}:addr=${WG_CLIENT_IP}" \
            -txt="${SERVER_SERVICE_NAME}-${Ci%%.*}:allowed=${WG_CLIENT_NET}" \
            -lease=${LEASE} -keylease=${KEYLEASE} \
            -keystore="${GITDIR}/keystore/client" -k=15 -once
        fi
        # echo "** SERVICE subtype '${REQ_SERVICE_NAME}' CLIENT_CONFIG for ${Ci%%.*}"
        echo "${Ci%%.*}: Ci_CFG: ${Ci_CFG} (len:${#Ci_CFG})"
        # fi

      done
    fi

    echo
    echo "====="
    sleep 5
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


