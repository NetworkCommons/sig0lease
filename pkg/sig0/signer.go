// Package sig0 implements SIG(0) request/response signing as per RFC 2931.
// Uses codeberg.org/miekg/dns SIG(0) facilities for proper cryptographic signing.
// Provenance: RFC 2931 (Transaction Signatures with SIG(0))
//
// # A note on codeberg.org/miekg/dns's SIG(0) hashing bug
//
// codeberg.org/miekg/dns v0.6.82's dns.CryptoSIG0.Sign/Verify compute the SIG(0) hash
// input as the SIG RR's *full wire encoding* (owner name + TYPE + CLASS + TTL + RDLENGTH,
// followed by RDATA) -- but RFC 2931 S3 is explicit that the signed "data" is
// "RDATA | message", where RDATA is only the SIG's RDATA fields (with the Signature
// field itself omitted), never that RR envelope. This was root-caused by instrumenting a
// local copy of the library and independently confirmed against mDNSResponder's own C
// implementation (ServiceRegistration/towire.c: dns_sig0_signature_to_wire_, which hashes
// a `rr`/`rdlen` pointing at RDATA only) -- see README_proxy.md's "miekg/dns Shortcomings"
// section for the full writeup and reproduction.
//
// sig0SignerImpl below replaces dns.CryptoSIG0.Sign/Verify with a from-scratch,
// RFC-correct implementation for every algorithm this package validates (ED25519,
// ECDSAP256SHA256, ECDSAP384SHA384) via the shared rdataOnlyPrefix helper, rather than
// only working around the bug for one algorithm as a previous version of this file did by
// accident (its ED25519 special case built an RDATA-only prefix by hand for unrelated
// reasons -- CryptoSIG0.Sign has no Ed25519 case at all -- and so had always been correct,
// while every other algorithm silently inherited the library's bug). RSA algorithms
// (RSAMD5/RSASHA1/RSASHA256/RSASHA512) still delegate to the buggy dns.CryptoSIG0 path:
// nothing in this codebase uses or tests them, and implementing RSA sign/verify from
// scratch without any test vectors to validate against would trade a known, documented gap
// for an unverified one.
package sig0

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // registers crypto.SHA256 for ECDSAP256SHA256, independent of whether codeberg.org/miekg/dns has already done so transitively
	_ "crypto/sha512" // registers crypto.SHA384 for ECDSAP384SHA384, same reasoning
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

// sig0SignerImpl replaces dns.CryptoSIG0's Sign/Verify for every algorithm listed in the
// switch statements below (see the package doc comment for why), and falls back to
// dns.CryptoSIG0 itself for anything else. Implements the full dns.SIG0Signer interface.
type sig0SignerImpl struct {
	base      dns.CryptoSIG0
	algorithm uint8 // Algorithm for dispatch (0 means use base CryptoSIG0)
}

// rdataOnlyPrefix builds the RFC 2931 S3 "RDATA" term of the SIG(0) signed data --
// "data = RDATA | message" -- as the wire encoding of the SIG's RDATA fields
// (TypeCovered, Algorithm, Labels, OrigTTL, Expiration, Inception, KeyTag, SignerName)
// with the Signature field entirely omitted, and critically WITHOUT the owner
// name/TYPE/CLASS/TTL/RDLENGTH envelope that would precede RDATA in a full RR encoding
// (that envelope is exactly what dns.CryptoSIG0 mistakenly includes). SignerName is
// written uncompressed, per RFC 2931/4034 canonical-form convention for signed data.
func rdataOnlyPrefix(sig *dns.SIG) []byte {
	buf := make([]byte, 0, 32+len(sig.SignerName))
	buf = append(buf, 0, 0) // TypeCovered: always 0 for a transaction SIG(0)
	buf = append(buf, sig.Algorithm)
	buf = append(buf, sig.Labels)
	buf = appendUint32(buf, sig.OrigTTL)
	buf = appendUint32(buf, sig.Expiration)
	buf = appendUint32(buf, sig.Inception)
	buf = appendUint16(buf, sig.KeyTag)
	buf = appendDomainName(buf, sig.SignerName)
	return buf
}

func appendUint32(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendUint16(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

// ecdsaCurve reports the elliptic curve and per-coordinate byte width RFC 6605 S4
// specifies for a DNSSEC/SIG(0) ECDSA algorithm: the KEY RR's PublicKey (and a
// signature's r/s components) are each exactly coordSize bytes, concatenated with no
// leading 0x04 point-format byte and no ASN.1 wrapping.
func ecdsaCurve(algorithm uint8) (curve elliptic.Curve, coordSize int, hash crypto.Hash, ok bool) {
	switch algorithm {
	case dns.ECDSAP256SHA256:
		return elliptic.P256(), 32, crypto.SHA256, true
	case dns.ECDSAP384SHA384:
		return elliptic.P384(), 48, crypto.SHA384, true
	default:
		return nil, 0, 0, false
	}
}

// ecdsaPublicKeyFromKEY parses a KEY RR's PublicKey field into an *ecdsa.PublicKey per
// RFC 6605 S4 (raw X||Y, both left-padded to coordSize bytes).
func ecdsaPublicKeyFromKEY(k *dns.KEY, curve elliptic.Curve, coordSize int) (*ecdsa.PublicKey, error) {
	if k == nil {
		return nil, fmt.Errorf("nil KEY RR")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in KEY public key: %w", err)
	}
	if len(raw) != 2*coordSize {
		return nil, fmt.Errorf("wrong ECDSA public key length for algorithm %d: got %d bytes, want %d", k.Algorithm, len(raw), 2*coordSize)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(raw[:coordSize]),
		Y:     new(big.Int).SetBytes(raw[coordSize:]),
	}, nil
}

// signECDSA implements Sign for ECDSAP256SHA256/ECDSAP384SHA384: hash
// rdataOnlyPrefix(sig)||p with the algorithm's hash function, sign with the private key,
// and encode r||s as two coordSize-byte big-endian integers (RFC 6605 S4) -- never ASN.1
// DER, which is what crypto.Signer.Sign would produce for an *ecdsa.PrivateKey and is not
// the wire format DNS SIG(0)/DNSSEC signatures use.
func (s sig0SignerImpl) signECDSA(sig *dns.SIG, p []byte, curve elliptic.Curve, coordSize int, hash crypto.Hash) ([]byte, error) {
	priv, ok := s.base.Signer().(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ECDSA signing requires an *ecdsa.PrivateKey, got %T", s.base.Signer())
	}
	h := hash.New()
	h.Write(rdataOnlyPrefix(sig))
	h.Write(p)
	r, sVal, err := ecdsa.Sign(rand.Reader, priv, h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign failed: %w", err)
	}
	out := make([]byte, 2*coordSize)
	r.FillBytes(out[:coordSize])
	sVal.FillBytes(out[coordSize:])
	return out, nil
}

// verifyECDSA implements Verify for ECDSAP256SHA256/ECDSAP384SHA384, the mirror of
// signECDSA.
func (s sig0SignerImpl) verifyECDSA(sig *dns.SIG, p []byte, curve elliptic.Curve, coordSize int, hash crypto.Hash) error {
	pub, err := ecdsaPublicKeyFromKEY(s.base.PublicKey, curve, coordSize)
	if err != nil {
		return fmt.Errorf("ECDSA SIG(0) verify: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig.Signature))
	if err != nil {
		return fmt.Errorf("invalid base64 signature: %w", err)
	}
	if len(raw) != 2*coordSize {
		return fmt.Errorf("wrong ECDSA signature length: got %d bytes, want %d", len(raw), 2*coordSize)
	}
	h := hash.New()
	h.Write(rdataOnlyPrefix(sig))
	h.Write(p)
	r := new(big.Int).SetBytes(raw[:coordSize])
	sVal := new(big.Int).SetBytes(raw[coordSize:])
	if !ecdsa.Verify(pub, h.Sum(nil), r, sVal) {
		return fmt.Errorf("ECDSA SIG(0) verification failed")
	}
	return nil
}

// Sign implements the full dns.SIG0Signer interface with SIG0Option parameter.
func (s sig0SignerImpl) Sign(sig *dns.SIG, p []byte, _ dns.SIG0Option) ([]byte, error) {
	switch s.algorithm {
	case 15: // ED25519
		// ED25519 does its own hashing internally, so it signs
		// rdataOnlyPrefix(sig) || p directly rather than a digest of it --
		// dns.CryptoSIG0.Sign has no ED25519 case at all (AlgorithmToHash has
		// no entry for it), so this was already necessarily a from-scratch
		// implementation; it has always built an RDATA-only prefix.
		ed25519Key, ok := s.base.Signer().(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ED25519 signer is not an ed25519.PrivateKey")
		}
		toSign := append(rdataOnlyPrefix(sig), p...)
		return ed25519Key.Sign(rand.Reader, toSign, crypto.Hash(0))

	default:
		if curve, coordSize, hash, ok := ecdsaCurve(s.algorithm); ok {
			return s.signECDSA(sig, p, curve, coordSize, hash)
		}
	}

	// RSA family (and anything else): still delegates to dns.CryptoSIG0, which hashes
	// the full RR encoding instead of RDATA-only -- a known instance of the same bug,
	// not patched here. See the package doc comment.
	return s.base.Sign(sig, p)
}

// Verify implements the full dns.SIG0Signer interface with SIG0Option parameter.
func (s sig0SignerImpl) Verify(sig *dns.SIG, p []byte, _ dns.SIG0Option) error {
	switch s.algorithm {
	case 15: // ED25519
		pubKeyB64 := s.base.PublicKey.PublicKey
		pubKeyBinary, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return fmt.Errorf("failed to decode base64 public key: %w", err)
		}
		if len(pubKeyBinary) != 32 {
			return fmt.Errorf("invalid ED25519 public key length after base64 decode: %d (expected 32)", len(pubKeyBinary))
		}
		ed25519Pub := ed25519.PublicKey(pubKeyBinary)

		toVerify := append(rdataOnlyPrefix(sig), p...)

		sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
		if err != nil {
			return fmt.Errorf("failed to decode signature: %w", err)
		}
		if !ed25519.Verify(ed25519Pub, toVerify, sigBytes) {
			return fmt.Errorf("ED25519 signature verification failed")
		}
		return nil

	default:
		if curve, coordSize, hash, ok := ecdsaCurve(s.algorithm); ok {
			return s.verifyECDSA(sig, p, curve, coordSize, hash)
		}
	}

	// RSA family (and anything else): see Sign above.
	return s.base.Verify(sig, p)
}

// Key returns the KEY RR
func (s sig0SignerImpl) Key() *dns.KEY {
	return s.base.Key()
}

// Signer returns the crypto signer
func (s sig0SignerImpl) Signer() crypto.Signer {
	return s.base.Signer()
}

// Helper to append domain name in DNS wire format
func appendDomainName(buf []byte, name string) []byte {
	name = canonicalDomainName(name)
	if name == "." {
		return append(buf, 0)
	}
	name = name[:len(name)-1] // strip trailing dot; root terminator is appended below

	// Split the domain name into labels
	// This is a simple implementation for DNS names
	i := 0
	for i < len(name) {
		// Find the next label
		j := i
		for j < len(name) && name[j] != '.' {
			j++
		}

		label := name[i:j]
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)

		if j == len(name) {
			break
		}
		i = j + 1
	}

	// Always terminate with root label.
	buf = append(buf, 0)

	return buf
}

func canonicalDomainName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" || name == "." {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// SignMessage signs any DNS message with SIG(0) using shared logic for both client and server paths.
func SignMessage(msg *dns.Msg, keyRR *dns.KEY, privateKey crypto.PrivateKey) (*dns.Msg, error) {
	if msg == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}
	if keyRR == nil {
		return nil, fmt.Errorf("KEY RR cannot be nil")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	cryptoSigner, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer interface")
	}

	now := uint32(time.Now().Unix())
	sigRR := new(dns.SIG)
	sigRR.Hdr.Name = "."
	sigRR.Hdr.Class = dns.ClassANY
	sigRR.Hdr.TTL = 0
	sigRR.Algorithm = keyRR.Algorithm
	sigRR.Inception = now - 300
	sigRR.Expiration = now + 300
	sigRR.KeyTag = keyRR.KeyTag()
	sigRR.SignerName = keyRR.Hdr.Name

	msg.Pseudo = append(msg.Pseudo, sigRR)

	baseSigner := dns.CryptoSIG0{
		CryptoSigner: cryptoSigner,
		PublicKey:    keyRR,
	}
	wrappedSigner := sig0SignerImpl{
		base:      baseSigner,
		algorithm: keyRR.Algorithm,
	}

	options := dns.SIG0Option{}
	if err := dns.SIG0Sign(msg, wrappedSigner, &options); err != nil {
		return nil, err
	}

	return msg, nil
}

// VerifySignature verifies a SIG(0) signature on a message.
// This is useful for servers to verify client-signed requests.
// Provenance: RFC 2931 SIG(0) verification + codeberg/miekg/dns SIG0Verify()
func VerifySignature(msg *dns.Msg, keyRR *dns.KEY) error {
	if msg == nil {
		return fmt.Errorf("message cannot be nil")
	}
	if keyRR == nil {
		return fmt.Errorf("KEY RR cannot be nil")
	}

	// Create CryptoSIG0 verifier (without private key for verification)
	baseVerifier := dns.CryptoSIG0{
		PublicKey: keyRR,
	}
	cryptoVerifier := sig0SignerImpl{
		base:      baseVerifier,
		algorithm: keyRR.Algorithm, // Pass algorithm for ED25519/ECDSA dispatch
	}

	// Verify the signature using SIG0Verify from codeberg/miekg/dns
	options := dns.SIG0Option{} // Empty options struct for SIG0Verify
	err := dns.SIG0Verify(msg, keyRR, cryptoVerifier, &options)
	if err != nil {
		return fmt.Errorf("SIG(0) verification failed: %w", err)
	}

	return nil
}
