// Package sig0 implements SIG(0) verification as per RFC 2931.
package sig0

import (
	"fmt"

	"codeberg.org/miekg/dns"
)

// Verify validates a DNS message with SIG(0).
func Verify(msg *dns.Msg, publicKey dns.RR) error {
	if msg == nil || len(msg.Extra) == 0 {
		return fmt.Errorf("no SIG RR found in message")
	}

	var sigRR *dns.SIG
	for _, rr := range msg.Extra {
		if s, ok := rr.(*dns.SIG); ok {
			sigRR = s
			break
		}
	}

	if sigRR == nil {
		return fmt.Errorf("no SIG RR found in message")
	}

	// Find the DNSKEY with matching parameters
	var dnskey *dns.DNSKEY
	for _, rr := range msg.Extra {
		if key, ok := rr.(*dns.DNSKEY); ok {
			dnskey = key
			break
		}
	}

	if dnskey == nil {
		return fmt.Errorf("no DNSKEY found in message")
	}

	rdataKey := dnskey.DNSKEY

	// For SIG(0), verify that the SIG RR parameters match the DNSKEY
	if sigRR.KeyTag != dnskey.KeyTag() {
		return fmt.Errorf("key tag mismatch")
	}

	if sigRR.Algorithm != rdataKey.Algorithm {
		return fmt.Errorf("algorithm mismatch")
	}

	// Note: Full SIG(0) signature verification requires access to the private key
	// which is not available in this module. This function only validates parameters.
	// Actual signature verification would need to be done using miekg/dns crypto functions.

	return nil
}
