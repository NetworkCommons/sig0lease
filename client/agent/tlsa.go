package agent

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"codeberg.org/miekg/dns"
)

// TLSARecord reads the PEM certificate file, the first certificate in it being the server's
// own (as in the chain files TLS servers read), and returns the TLSA record at owner matching
// its public key: usage 3 (DANE-EE: this server's own key, no certificate authority, the
// certificate's names and dates not checked), selector 1 (the SubjectPublicKeyInfo) and
// matching type 1 (its SHA-256), the form RFC 7671 S5.1 recommends. It still matches when the
// certificate is renewed with the same key.
func TLSARecord(owner, file string) (*dns.TLSA, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	for rest := data; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return nil, fmt.Errorf("certificate %s: no PEM CERTIFICATE block", file)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %s: %w", file, err)
		}
		rr := &dns.TLSA{Hdr: dns.Header{Name: owner, Class: dns.ClassINET}}
		if err := rr.Sign(3, 1, 1, cert); err != nil {
			return nil, fmt.Errorf("certificate %s: %w", file, err)
		}
		return rr, nil
	}
}
