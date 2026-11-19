#!/bin/bash
#
# get_WG_attributes - get a specified TXT record attribute of a specifed _wg._udp instance
# 
# get_WG_attr <instance_name> <domain>  

source ./env

function get_WG_attribute() {
    # get specified attribute value from TXT of a WG DNS-SD service instance
    #
    # PARAMS
    #   1 WG Instance Name
    #   2 DOMAIN
    #   3 attribute key
    #
    # RETURNS
    #   value of specified attribute key in TXT RR for WG Instance Name
    #
    # Example test uses:
    #
    # TEST_GET_WG_ATTRIBUTE="True" ./get_WG_attribute.sh wgservice _wg._udp dev.zenr.io txtvers
    # Service Instance 'wgservice' of type '_wg._udp' in domain dev.zenr.io has TXT RR attribute 'txtvers' value of '1'
    # 
    # TEST_GET_WG_ATTRIBUTE="True" ./get_WG_attribute.sh wgservice _wg._udp dev.zenr.io pk
    # Service Instance 'wgservice' of type '_wg._udp' in domain dev.zenr.io has TXT RR attribute 'peer' value of 'dLAovvPP0LQ8ZBgbAw4tkVb3wuqZyS9HFFutsAz+ezA='
    # 
    #
    SD_TYPE="_wg._udp"
    TXT_RR="`dig +short @${MNAME} ${1}.${SD_TYPE}.${2}. txt`"

    attribute=${3:-"net"}

    temp="${TXT_RR##*\"${attribute}=}" # strip up to and including '"'+attribute+'='
    res="${temp%%\"*}"   # strip everything after endquote matching beginning '"' from above
    echo "${res}"
}


function get_WGPEER_attribute() {
    # get specified attribute value from TXT of a WGPEER DNS-SD service instance
    #
    # PARAMS
    #   1 WGPEER instance name
    #   2 WG service instance name (used as subtype)
    #   3 DOMAIN
    #   4 TXT Attribute key value to enumerate
    # 
    # Example test uses:
    #
    # $ TEST_GET_WGPEER_ATTRIBUTE="True" ./get_WG_attribute.sh blackbox wgservice dev.zenr.io  pk
    # Service Instance 'blackbox' of type '_wgpeer._udp' in domain dev.zenr.io has TXT RR attribute 'txtvers' value of '1'
    #
    # $ TEST_GET_WGPEER_ATTRIBUTE="True" ./get_WG_attribute.sh blackbox wgservice dev.zenr.io  pk
    # Service Instance 'blackbox' of type '_wgpeer._udp' in domain dev.zenr.io has TXT RR attribute 'pk' value of 'mul5zgBo+f14SCYvsj6F1CJgZlO/LFm3dWJrRnCHZzQ='
    #
    #   WG service instance name (S subtype)
    local wgpeer_instance="${1}" # WGPEER instance name
    local wg_instance="${2}"     # WG service instance name (used as wgpeer subtype)
    local domain="${3}"          # FQDN common to _wg and _wgpeer instances
    local attribute="${4}"       # TXT key attribute to evaluate & return value

    SD_TYPE="_wgpeer._udp"
    SD_SUBTYPE="${wg_instance}._sub"

    PTR_RR="`dig +short @${MNAME} ${SD_SUBTYPE}.${SD_TYPE}.${domain}. ptr`"
    
    WGPEER_RR_ARRAY=(${PTR_RR})

    i=0
    WGPEER_RR=""
    while (( i < ${#WGPEER_RR_ARRAY[@]} ))
    do
	# echo "$i. ${WGPEER_RR_ARRAY[i]} : `dig +short @${MNAME} ${WGPEER_RR_ARRAY[i]} TXT` : ${wgpeer_instance}.${SD_TYPE}.${domain}."
 	if [[ "${WGPEER_RR_ARRAY[i]}" == "${wgpeer_instance}.${SD_TYPE}.${domain}." ]]; then
            WGPEER_RR="${WGPEER_RR_ARRAY[i]}"
	    break;
	fi
        ((i++))
    done
    # echo "===== ${WGPEER_RR}"

    TXT_RR="`dig +short @${MNAME} ${WGPEER_RR} TXT`"
    # echo "***** ${TXT_RR}"

    temp="${TXT_RR##*\"${attribute}=}" # strip up to and including '"'+attribute+'='
    res="${temp%%\"*}"   # strip everything after endquote matching beginning '"' from above
    echo "${res}"
}

function get_WGCFG_attribute() {
    # get specified attribute value from TXT of a WGPEER DNS-SD service instance
    #
    # PARAMS
    #   1 WG instance name
    #   2 WGPEER instance name (used as subtype)
    #   3 DOMAIN
    #   4 TXT Attribute key value to enumerate
    # 
    local wgpeer_instance="${1}" # WGPEER client instance name
    local wg_instance="${2}"     # WG server instance name
    local wgcfg_instance="${wg_instance}-${wgpeer_instance}" # WGCFG cfg instance name

    local domain="${3}"          # FQDN common to _wg and _wgpeer instances
    local attribute="${4}"       # TXT key attribute to evaluate & return value



    SD_TYPE="_wgcfg._udp"
    SD_SUBTYPE="${wgpeer_instance}._sub" # WGCFG subtype is CLIENT Ci

    PTR_RR="`dig +short @${MNAME} ${SD_SUBTYPE}.${SD_TYPE}.${domain}. ptr`"
    PTR_RR_STR="dig +short @${MNAME} ${SD_SUBTYPE}.${SD_TYPE}.${domain}. ptr"

    TXT_RR="`dig +short @${MNAME} ${PTR_RR} TXT`"

    temp="${TXT_RR##*\"${attribute}=}" # strip up to and including '"'+attribute+'='
    res="${temp%%\"*}"   # strip everything after endquote matching beginning '"' from above
    echo "${res}"
}

if [[ -n ${TEST_GET_WG_ATTRIBUTE} ]]; then
    instance=${1:-"wgservice"}
    service_type="_wg._udp"
    domain=${3:-"srp.dev.zenr.io"}
    attr=${4:-"net"}
    echo " get_WG_attribute <wg instance name> <domain> <TXT RR attribute>"
    echo " Service Instance '${instance}' of type '${service_type}' in domain ${domain} has TXT RR attribute '${attr}' value of '$(get_WG_attribute ${instance} ${domain} ${attr})'"
fi

if [[ -n ${TEST_GET_WGPEER_ATTRIBUTE} ]]; then
    instance=${1:-"redbox"}
    service_type="_wgpeer._udp"
    wg_instance="wgservice"
    domain=${3:-"srp.dev.zenr.io"}
    attr=${4:-"pk"}
    echo " get_WG_attribute <wgpeer instance name> <wg instance name> <domain> <TXT RR attribute>"
    echo " Service Instance '${instance}' of type '${service_type}' in domain ${domain} has TXT RR attribute '${attr}' value of '$(get_WGPEER_attribute ${instance} ${wg_instance} ${domain} ${attr})'"
    echo
fi

if [[ -n ${TEST_GET_WGCFG_ATTRIBUTE} ]]; then
    service_type="_wgcfg._udp"
    wg_instance=${1:-"wgservice"}
    wgpeer_instance=${2:-"bluebox"}
    wgcfg_instance="${wg_instance}-${wgpeer_instance}"
    domain=${3:-"srp.dev.zenr.io"}
    attr=${4:-"addr"}
    echo " get_WGCFG_attribute <wgpeer instance name> <wg instance name> <domain> <TXT RR attribute>"
    echo " Service Instance '${wgcfg_instance}' of type '${service_type}' in domain '${domain}' has TXT RR attribute '${attr}' value of '$(get_WGCFG_attribute ${wgpeer_instance} ${wg_instance} ${domain} ${attr})'"
fi

