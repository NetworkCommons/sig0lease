Wireguard Server Flow

Register Service Lease with Service name S under S._wg.udp
While Service Lease is active
	for each Client Request Ci under S._sub._wgpeer._udp
		if no S-Ci._Ci._sub._wgcfg._udp TXT exists (ie, is this a request without an answer)
			apply approval policy
			if not approved, register S-Ci.Ci._sub._wgcfg._udp with TXT including "status=refused"
			if approved, register Si-Ci.Ci._sub._wgcfg._udp with TXT including "addr=" and "allowed=" (allocated IP address and allowed routes)

(When Client Request under Ci.S._sub._wgpeer._udp RR is removed, server disconnects Ci and removes its WG config) 
