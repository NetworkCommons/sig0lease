#!/bin/bash

# BASH Wireguard service (_wg._udp) client request monitoring

# Server steps:
#
# 1.  (1) Advertise:  The server registers  S._wg._udp. under domain to ensure the service is still publishe
# 2.  (3) The server watches S._sub._wgpeer._udp. For each new request it decides whether to admit the client (policy to be defined). If it admits the client, it allocates an address and adds the peer to its interface. It then registers S-Ci._wgcfg._udp with subtype Ci. A refused client gets the same record with status=refused and no addr or allowed.

# set defaults of any required ENV var that isn't set

# BROWSE dig options
BROWSE_DIG_OPTIONS=${BROWSE_DIG_OPTIONS:-"+noall +answer @ns1.free2air.org"}
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
  -txt="${SERVER_SERVICE_NAME}:peer=${SERVER_PUBKEY}" \
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

    echo "=== Browse Domains"
    dig ${BROWSE_DIG_OPTIONS} b._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} db._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} lb._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} r._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} dr._dns-sd._udp.${DOMAIN}. PTR

    echo
    echo "=== ACTIVE SERVICE TYPES IN ${DOMAIN}"
    dig ${DIG_OPTIONS} +short @ns1.free2air.org _services._dns-sd._udp.${DOMAIN}. PTR | grep -v RRSIG | grep -v NSEC
    echo


    echo "=== ACTIVE Wireguard Service Instances"
    dig ${DIG_OPTIONS} +short @ns1.free2air.org _wg._udp.${DOMAIN}. PTR | grep -v RRSIG | grep -v NSEC
    echo


    CLIENT_REQUESTS=`dig ${DIG_OPTIONS} ${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
    echo "*ALL* WIREGUARD SERVICE CLIENT_REQUESTS WITHIN DOMAIN ${DOMAIN}:"
    echo "${CLIENT_REQUESTS}"
    echo
    # 
    
    echo "SERVICE subtype '${REQ_SERVICE_NAME}' CLIENT_REQUESTS :" 
    CLIENT_REQUESTS_SUB=`dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}._sub.${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
    
    # substitute new line for space in list for looping ...

    CLIENT_LOOP="${CLIENT_REQUESTS_SUB//$'\n'/ }"
    
    # loop over client requests and collect those without corresponding _wgcfg entries for ${REQ_SERVICE_NAME}


    if (( ${#CLIENT_LOOP} > 0 )); then
      for Ci in $(echo ${CLIENT_LOOP})
      do
        Ci_REQ="$(dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}.${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC)"
        Ci_TXT="$(dig ${DIG_OPTIONS} ${Ci} TXT)"
        Ci_SRV="$(dig ${DIG_OPTIONS} ${Ci} SRV)"
        #Ci_CFG="$(dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}-${Ci%%.*}.${Ci%%.*}._sub.${ANS_SERVICE_TYPE}.${DOMAIN} TXT | grep -v RRSIG | grep -v NSEC)"
        Ci_CFG="$(dig ${DIG_OPTIONS} ${REQ_SERVICE_NAME}-${Ci%%.*}.${ANS_SERVICE_TYPE}.${DOMAIN} TXT | grep -v RRSIG | grep -v NSEC)"
        echo "${Ci}: SRV: ${Ci_SRV} TXT: ${Ci_TXT} (len:${#Ci_TXT}) : CFG: ${Ci_CFG}"

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
        else
          echo
          echo "SERVICE subtype '${REQ_SERVICE_NAME}' CLIENT_CONFIG"
          echo "Ci_CFG: ${Ci_CFG} (len:${#Ci_CFG})"
        fi

      done
    fi
    echo
    echo "====="
    echo
    
    echo "---"
    sleep 10
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


