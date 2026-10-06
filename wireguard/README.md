This directory contains experimental ideation scripts to test

- DNS-SD service type for publishing wireguard services:
	- _wg._udp for wireguard servers
	- _'service-name'._wg.udp for potential clients to request configuation from server

- DNS_SD service type for Wireguard client/server configuration:
	- _wgpeer._udp for client/server configuration information
	- each client and each server defines its own subtype in a configuration sequence

Configuration Sequence

1. Wireguard Server registers 'service-name'._wg._udp as above
	- SRV contains FQDN and UDP port number of service-name Wireguard instance
	- TXT contains public key of Wireguard service

2. Wireguard server utility monitors _'service-name'._sub._wgpeer._udp for client connection configuration requests


3. Wireguard client utility registers 'myclient'._'service-name'._sub._wgpeer._udp as request to connect to <service-name>
	- SRV contains client FQDN and UDP port of 0
	- TXT contains public key of Wireguard client

4. Wireguard server utility now has sufficient information to configure the Wireguard server instance for <myclient> connectivity

5. Wireguard client utility monitors 'service-name'._'myclient'._sub._wgpeer._udp for specifc configuration details
	- SRV contains FQDN and UDP port number of service-name Wireguard instance
	- TXT contains further client specific configuration from Wireguard serverr: eg. Allocated IP Address, Netmask, Routes

6. Wireguard client utility now has sufficient information to configure itself for the 'service-name' Wireguard server instance connectivity

