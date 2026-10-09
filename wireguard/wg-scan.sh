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
 HOSTNAME="myclient"
 SD_INSTANCE="myvpn"
 SD_TYPE="_wg._udp"
 SD_SUBTYPE="myserver"
echo "=== Browse Domains"
 dig ${DIG_OPTIONS} @ns1.free2air.org b._dns-sd._udp.${DOMAIN}. PTR
 dig ${DIG_OPTIONS} @ns1.free2air.org db._dns-sd._udp.${DOMAIN}. PTR
 dig ${DIG_OPTIONS} @ns1.free2air.org lb._dns-sd._udp.${DOMAIN}. PTR
 dig ${DIG_OPTIONS} @ns1.free2air.org r._dns-sd._udp.${DOMAIN}. PTR
 dig ${DIG_OPTIONS} @ns1.free2air.org dr._dns-sd._udp.${DOMAIN}. PTR



 echo
 echo "*** ACTIVE SERVICE TYPES IN ${DOMAIN}"
 dig ${DIG_OPTIONS} +short @ns1.free2air.org _services._dns-sd._udp.${DOMAIN}. PTR | grep -v RRSIG | grep -v NSEC
 echo "*** ACTIVE SUBTYPE ${SD_SUBTYPE} IN ${SD_SUBTYPE}.${SD_TYPE}.${DOMAIN} (static test)"
 dig ${DIG_OPTIONS} +short @ns1.free2air.org ${SD_SUBTYPE}.${SD_TYPE}.${DOMAIN} PTR
 dig ${DIG_OPTIONS} +short @ns1.free2air.org ${SD_SUBTYPE}._sub.${SD_TYPE}.${DOMAIN} PTR
          
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

 HOSTNAME="myclient"
 SD_TYPE="_VPNServer._sub._wg._udp"
 SD_INSTANCE="myclient"
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
 sleep 5
done

