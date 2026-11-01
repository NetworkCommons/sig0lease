Wireguard Client Flow

Browse _wg._udp and select a Service named S
Read Server Service Wireguard key from TXT RR, remote endpoint FQDN and port from SRV, read IP address resolution of SRV FQDN for A/AAAA records
Register Application Lease to use service and receive client Ci specific configuration details from S with Ci.S._sub._wgpeer._udp registration TXT RR must contain client Wireguard key as pk=public wg key
While Application Lease is active
	for each Ci._sub.wgcfg._udp where SRV target is S and TXT record AV assignment "peer=" holds the client's WG key
		if Ci._sub.wgcfg._udp TXT status=refused or if TXT AV addr= is an IP address outside net read in S._wg._udp TXT RR then END REQUEST
		else set WG int address addr, WG peer key pk & Wireguard remote endpoint as SRV FQDN & port with TXT AV var allowed= as network routes to check and set

(When Wireguard service is no longer wanted, Application Lease Ci._S._sub._wgpeer._udp is removed by client Ci)
