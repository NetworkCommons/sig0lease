package dnscompat

import "codeberg.org/miekg/dns"

func init() {
	// codeberg.org/miekg/dns v0.6.82 maps code 2 (UPDATE-LEASE) to *dns.UPDATELEASE,
	// but unpackOptionCode has no *UPDATELEASE case and fails with
	// "dns: no option unpack defined". Force ERFC3597 for code 2 so strict
	// message parsing works without fallback behavior.
	dns.CodeToRR[2] = func() dns.EDNS0 {
		return &dns.ERFC3597{EDNS0Code: 2}
	}
}
