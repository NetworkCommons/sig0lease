package agent

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"codeberg.org/miekg/dns"
)

// swarmMACKey is the TXT key whose value proves that a community's member holds the
// community's swarm key: the MAC of its KEY and of the folder its TXT record gives (mac).
const swarmMACKey = "swarm-mac"

// swarmKey is the key a member makes its swarm-mac= with, and a community checks it with:
// derived from the community's swarm key (readSwarmKey), which the nodes of its private swarm
// share and no other node has.
type swarmKey []byte

// readSwarmKey reads the swarm key file at path, as kubo reads it (go-libp2p's pnet V1 PSK):
// "/key/swarm/psk/1.0.0/", then "/base16/", "/base64/" or "/bin/", then the 32-byte key so
// encoded. It returns the key derived from it with HKDF-SHA256, so that the swarm key itself,
// which libp2p encrypts the swarm's connections with, is used for nothing else.
func readSwarmKey(path string) (swarmKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("swarm key: %w", err)
	}
	psk, err := decodeSwarmKey(data)
	if err != nil {
		return nil, fmt.Errorf("swarm key %s: %w", path, err)
	}
	k, err := hkdf.Key(sha256.New, psk, nil, "sig0lease "+swarmMACKey, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("swarm key %s: %w", path, err)
	}
	return k, nil
}

// decodeSwarmKey returns the 32-byte key of a swarm key file's contents.
func decodeSwarmKey(data []byte) ([]byte, error) {
	header, rest, _ := bytes.Cut(data, []byte("\n"))
	if strings.TrimSpace(string(header)) != "/key/swarm/psk/1.0.0/" {
		return nil, fmt.Errorf("its first line is not /key/swarm/psk/1.0.0/, as a swarm key's is")
	}
	encoding, rest, _ := bytes.Cut(rest, []byte("\n"))
	var psk []byte
	var err error
	switch e := strings.TrimSpace(string(encoding)); e {
	case "/base16/":
		psk, err = hex.DecodeString(strings.TrimSpace(string(rest)))
	case "/base64/":
		psk, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(rest)))
	case "/bin/":
		psk = rest
	default:
		return nil, fmt.Errorf("its encoding %q is not /base16/, /base64/ or /bin/", e)
	}
	if err != nil {
		return nil, fmt.Errorf("its key: %w", err)
	}
	if len(psk) != 32 {
		return nil, fmt.Errorf("its key is %d bytes, not 32", len(psk))
	}
	return psk, nil
}

// mac returns the swarm-mac= value of a member whose KEY is key and whose TXT record gives the
// folder cid: the HMAC-SHA256, under k, of the fields the registrar tells keys apart by
// (protocol, algorithm, public key: pkg/srp.KeysAllMatch) and of cid, base64url-encoded. The
// registrar puts at an instance's name only the KEY of the key that signed the update, so a
// swarm-mac= copied to an instance another key holds does not match it there.
func (k swarmKey) mac(key *dns.KEY, cid string) string {
	return base64.RawURLEncoding.EncodeToString(k.sum(key, cid))
}

func (k swarmKey) sum(key *dns.KEY, cid string) []byte {
	h := hmac.New(sha256.New, k)
	fmt.Fprintf(h, "%d %d %s %s", key.Protocol, key.Algorithm, key.PublicKey, cid)
	return h.Sum(nil)
}

// verify reports whether mac is the swarm-mac= k makes for key and cid.
func (k swarmKey) verify(key *dns.KEY, cid, mac string) bool {
	got, err := base64.RawURLEncoding.DecodeString(mac)
	return err == nil && hmac.Equal(got, k.sum(key, cid))
}
