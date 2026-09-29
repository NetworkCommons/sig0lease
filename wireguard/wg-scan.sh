#!/bin/bash
DIG_OPTIONS="+noall +answer"

DOMAIN="srp.dev.zenr.io"
HOSTNAME="demo"
SD_INSTANCE="DemoDaemon"

if (( $# == 0)); then
 SD_TYPE="${SD_TYPE:-_http._tcp}"
else
  SD_TYPE="${SD_TYPE:-${1}}"
fi


while true
 clear
 do date

 echo "******************************"

 DOMAIN="srp.dev.zenr.io"
 HOSTNAME="vpn"
 SD_INSTANCE="VPNServer"
 SD_TYPE="_wg._udp"
 
echo "=== Browse Domains"
 dig ${DIG_OPTIONS} @ns1.free2air.org b._dns-sd._udp.${DOMAIN}. PTR
 dig ${DIG_OPTIONS} @ns1.free2air.org db._dns-sd._udp.${DOMAIN}. PTR
 dig ${DIG_OPTIONS} @ns1.free2air.org lb._dns-sd._udp.${DOMAIN}. PTR
 dig ${DIG_OPTIONS} @ns1.free2air.org r._dns-sd._udp.${DOMAIN}. PTR
 dig ${DIG_OPTIONS} @ns1.free2air.org dr._dns-sd._udp.${DOMAIN}. PTR



 echo
 echo "*** ACTIVE SERVICE TYPES IN ${DOMAIN}"
 dig ${DIG_OPTIONS} +short @ns1.free2air.org _services._dns-sd._udp.${DOMAIN}. PTR | grep -v RRSIG | grep -v NSEC
          
 echo
 echo "*** HOST ${HOSTNAME}.${DOMAIN}"
 dig ${DIG_OPTIONS} @ns1.free2air.org ${HOSTNAME}.${DOMAIN}. any | grep -v RRSIG | grep -v NSEC

 echo
 echo "*** SERVICE TYPE ${SD_TYPE}"
 dig ${DIG_OPTIONS} @ns1.free2air.org ${SD_TYPE}.${DOMAIN}. ptr | grep -v RRSIG | grep -v NSEC

 echo
 echo "*** SERVICE INSTANCE ${SD_INSTANCE}"
 dig ${DIG_OPTIONS} @ns1.free2air.org ${SD_INSTANCE}.${SD_TYPE}.${DOMAIN} any | grep -v RRSIG | grep -v NSEC
 echo
 echo "******"

 HOSTNAME="vpnclient"
 SD_TYPE="_VPNServer._wg._udp"
 SD_INSTANCE="VPNClient"
 echo
 echo "*** HOST ${HOSTNAME}.${DOMAIN}"
 dig ${DIG_OPTIONS} @ns1.free2air.org ${HOSTNAME}.${DOMAIN}. any | grep -v RRSIG | grep -v NSEC

 echo
 echo "*** SERVICE TYPE ${SD_TYPE}"
 dig ${DIG_OPTIONS} @ns1.free2air.org ${SD_TYPE}.${DOMAIN}. ptr | grep -v RRSIG | grep -v NSEC

 echo
 echo "*** SERVICE INSTANCE ${SD_INSTANCE}.${SD_TYPE}.${DOMAIN}"
 dig ${DIG_OPTIONS} @ns1.free2air.org ${SD_INSTANCE}.${SD_TYPE}.${DOMAIN} any | grep -v RRSIG | grep -v NSEC
 echo
 echo "******"



avahi-browse -bartd ${DOMAIN} 
 sleep 2
done

