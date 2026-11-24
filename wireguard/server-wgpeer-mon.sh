#!/bin/bash

# BASH Wireguard service (_wg._udp) client request monitoring

# Server steps:
#
# 1.  (1) Advertise:  The server registers  S._wg._udp. under domain to ensure the service is still publishe
# 2.  (3) Answer: The server watches S._sub._wgpeer._udp. For each new request it decides whether to admit the client (policy to be defined).
#         If it admits the client, it allocates an address and adds the peer to its interface. It then registers S-Ci._wgcfg._udp with subtype Ci.
#         A refused client gets the same record with status=refused and no addr or allowed.

# includes
source get_mname.sh
source get_WG_attribute.sh

# set defaults of any required ENV var that isn't set

source ./env

VPN_SERVER_IP=${VPN_SERVER_IP:-"$(ip -f inet -o addr show ${VPN_INTERFACE} | cut -d\  -f 7 | cut -d/ -f 1)"}

## Prepare VPN IP pool
# set IP Allocation array for clients
VPN_IP_LIST="$(cidrl ${SERVER_NETWORK} | head -n-1 | tail -n+2)"
# take IP address VPN_INTERFACE out of list for VPN_CLIENT_POOL
IP_FREE_ARRAY=(${VPN_IP_LIST})
IP_FREE_ARRAY=("${IP_FREE_ARRAY[@]/$VPN_SERVER_IP}")

i=0
while (( i < ${#IP_FREE_ARRAY[@]} ))
        do
                # echo "${i} len: ${#IP_FREE_ARRAY[i]}"
                if ! [[ -n ${IP_FREE_ARRAY[i]} ]]; then
                        unset IP_FREE_ARRAY[i]
                fi
                ((i++))
        done
# renormalise IP_FREE_ARRAY
for i in "${!IP_FREE_ARRAY[@]}"; do
        NEW_FREE_ARRAY+=( "${IP_FREE_ARRAY[i]}" )
done
IP_FREE_ARRAY=("${NEW_FREE_ARRAY[@]}")
unset NEW_FREE_ARRAY

echo "VPN Server IP: ${VPN_SERVER_IP}"
echo "VPN Free Array: ${IP_FREE_ARRAY[@]} (${#IP_FREE_ARRAY[@]} free addresses)"
sleep 5
if [[ -n ${TEST_IP_FREE_ARRAY} ]]; then
	exit
fi




clear

while true
do
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

    echo
    echo "=== Browse Domains"
    dig ${BROWSE_DIG_OPTIONS} b._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} db._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} lb._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} r._dns-sd._udp.${DOMAIN}. PTR
    dig ${BROWSE_DIG_OPTIONS} dr._dns-sd._udp.${DOMAIN}. PTR

    echo
    echo "=== Advertised SD Service Types IN ${DOMAIN}"
    dig ${BROWSE_DIG_OPTIONS} _services._dns-sd._udp.${DOMAIN}. PTR | grep -v RRSIG | grep -v NSEC
    echo


    echo "=== Advertised SD Wireguard Service Instances (_wg._udp) in ${DOMAIN}"
    #WG_SERVICE_INSTANCES=`dig ${BROWSE_DIG_OPTIONS} _wg._udp.${DOMAIN}. PTR | grep -v RRSIG | grep -v NSEC`
    WG_SERVICE_INSTANCES=`dig ${SHORT_DIG_OPTIONS} _wg._udp.${DOMAIN}. PTR | grep -v RRSIG | grep -v NSEC`
    for wgs in "${WG_SERVICE_INSTANCES}"
    do
        #echo "${wgs}"
        dig ${BROWSE_DIG_OPTIONS} $wgs SRV
        dig ${BROWSE_DIG_OPTIONS} $wgs TXT
        echo
    done

 #    echo "== *ALL* WIREGUARD SERVICE CLIENT_REQUESTS for all instances in ${DOMAIN}"
 #    CLIENT_REQUESTS=`dig ${SHORT_DIG_OPTIONS} ${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
 #    echo "${CLIENT_REQUESTS}"
 #    echo

    echo "== WIREGUARD SERVICE CLIENT_REQUESTS (_wgpeer._udp) for my Service Instance (subtype) '${SERVER_SERVICE_NAME}' in ${DOMAIN}"
    CLIENT_REQUESTS_SUB=`dig ${SHORT_DIG_OPTIONS} ${REQ_SERVICE_NAME}._sub.${REQ_SERVICE_TYPE}.${DOMAIN} PTR | grep -v RRSIG | grep -v NSEC`
    CLIENT_LOOP="${CLIENT_REQUESTS_SUB//$'\n'/ }" # substitute new line for space in list for looping ...
    #echo "CLIENT_LOOP=${CLIENT_LOOP}"
    for client in $(echo ${CLIENT_LOOP})
      do
          # echo "get_WGPEER_attribute ${client%%.*} ${SERVER_SERVICE_NAME} ${DOMAIN} pk"
          CLIENT_PUBLIC_KEY="$(get_WGPEER_attribute ${client%%.*} ${SERVER_SERVICE_NAME} ${DOMAIN} pk)"
          echo -e " ${client%%.*}:\tCi_REQ: client pk = ${CLIENT_PUBLIC_KEY}"
      done
    #

    echo
    echo
    echo "** WIREGUARD SERVICE INSTANCE '${REQ_SERVICE_NAME}' CLIENT_ANSWERS (_wgcfg._udp) with subtype CLIENT in ${DOMAIN}"

    # loop over client requests and collect those without corresponding _wgcfg entries for ${REQ_SERVICE_NAME}
    if (( ${#CLIENT_LOOP} > 0 )); then
      for Ci in $(echo ${CLIENT_LOOP})
      do
        Ci_TXT="$(dig ${DIG_OPTIONS} ${Ci} TXT)"
        Ci_SRV="$(dig ${DIG_OPTIONS} ${Ci} SRV)"
        Ci_CFG="$(dig ${SHORT_DIG_OPTIONS} ${REQ_SERVICE_NAME}-${Ci%%.*}.${ANS_SERVICE_TYPE}.${DOMAIN} TXT | grep -v RRSIG | grep -v NSEC)"

        if (( ${#Ci_CFG} == 0 )); then
          echo "${Ci%%.*} needs a config"
	  if (( ${#IP_FREE_ARRAY[@]} > 0 )); then
            WG_CLIENT_IP="${IP_FREE_ARRAY[0]}"
            IP_FREE_ARRAY=("${IP_FREE_ARRAY[@]/$WG_CLIENT_IP}")
	    unset IP_FREE_ARRAY[0]
	    NEW_FREE_ARRAY=()
            # renormalise IP_FREE_ARRAY
            for i in "${!IP_FREE_ARRAY[@]}"
	    do
              NEW_FREE_ARRAY+=( "${IP_FREE_ARRAY[i]}" )
            done
            IP_FREE_ARRAY=("${NEW_FREE_ARRAY[@]}")
            unset NEW_FREE_ARRAY

	    echo "Allocated: ${WG_CLIENT_IP}"
	    echo "Next free: ${IP_FREE_ARRAY[0]}"
	    echo

	    # DEBUG bad IP Alloc
	    if ((${#WG_CLIENT_IP} < 8)); then
              echo "IP alloc ${WG_CLIENT_IP} incorrectly formed"
	      echo "Attempting again on next run ..."
	      echo "IP_FREE_ARRAY[@]"
	      echo "${IP_FREE_ARRAY[@]}"
	      break
	    fi

	    # TEST DATA (DEBUG)
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
        fi
        echo -e " ${Ci%%.*}:\tCi_CFG: ${Ci_CFG}"
      done
    fi

    echo
    echo "====="
    sleep 10
    clear
    date
done

