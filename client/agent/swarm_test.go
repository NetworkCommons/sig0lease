package agent

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
)

// A swarm key file is read as kubo reads it: its key in base16, base64 or as bytes, the same
// key each way; any other file is refused.
func TestReadSwarmKey(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	dir := t.TempDir()
	read := func(name, contents string) (swarmKey, error) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return readSwarmKey(path)
	}
	head := "/key/swarm/psk/1.0.0/\n"
	var keys []swarmKey
	for _, f := range []string{
		head + "/base16/\n3031323334353637383961626364656630313233343536373839616263646566\n",
		head + "/base64/\n" + base64.StdEncoding.EncodeToString(psk) + "\n",
		head + "/bin/\n" + string(psk),
	} {
		k, err := read("swarm.key", f)
		if err != nil {
			t.Fatalf("%q: %v", f, err)
		}
		keys = append(keys, k)
	}
	if len(keys[0]) != 32 || string(keys[0]) != string(keys[1]) || string(keys[0]) != string(keys[2]) {
		t.Fatalf("keys %x, want one 32-byte key three times", keys)
	}
	if string(keys[0]) == string(psk) {
		t.Fatal("the key is the swarm key itself, want one derived from it")
	}

	for _, c := range []struct{ contents, want string }{
		{"/key/swarm/psk/2.0.0/\n/base16/\n00\n", "its first line is not /key/swarm/psk/1.0.0/"},
		{head + "/base32/\nAA\n", `its encoding "/base32/" is not /base16/, /base64/ or /bin/`},
		{head + "/base16/\nzz\n", "its key: encoding/hex: invalid byte"},
		{head + "/base16/\n0011\n", "its key is 2 bytes, not 32"},
	} {
		if _, err := read("bad.key", c.contents); err == nil || !strings.Contains(err.Error(), "swarm key "+filepath.Join(dir, "bad.key")+": "+c.want) {
			t.Errorf("%q: %v, want %q", c.contents, err, c.want)
		}
	}
	if _, err := readSwarmKey(filepath.Join(dir, "none")); err == nil || !strings.HasPrefix(err.Error(), "swarm key: open ") {
		t.Errorf("a missing file: %v", err)
	}
}

// A swarm-mac= checks with the swarm key that made it, for the KEY and the folder it was made
// for, whatever the KEY's owner name and flags, which the registrar does not tell keys apart by;
// another KEY, folder or swarm key, or a malformed one, does not check.
func TestSwarmMAC(t *testing.T) {
	_, k := testSwarm(t)
	other := swarmKey(strings.Repeat("x", 32))
	key := func(name, pub string, flags uint16) *dns.KEY {
		rr := &dns.KEY{}
		rr.Hdr = dns.Header{Name: name, Class: dns.ClassINET}
		rr.Flags, rr.Protocol, rr.Algorithm, rr.PublicKey = flags, 3, dns.ECDSAP256SHA256, pub
		return rr
	}
	alice := key("alice.srp.test.", "a2V5IG9mIGFsaWNl", 0)
	mac := k.mac(alice, "QmA1")
	// As docs/sig0lease-agent.md gives it, computed with Python's hmac and hashlib: HKDF-SHA256
	// of the swarm key, no salt, info "sig0lease swarm-mac"; then HMAC-SHA256 of
	// "<protocol> <algorithm> <public key> <CID>", base64url with no padding.
	if want := "B_Qu1gcqWf2KqbGahHAxrwY4Wcq5xQ_Arw2SSrOoGYg"; mac != want {
		t.Fatalf("mac = %s, want %s", mac, want)
	}
	if !k.verify(key("alice-2._ipfs-member._tcp.srp.test.", "a2V5IG9mIGFsaWNl", 256), "QmA1", mac) {
		t.Fatal("the swarm-mac= does not check for the same key at another name")
	}
	for what, ok := range map[string]bool{
		"another key":        k.verify(key("alice.srp.test.", "a2V5IG9mIHRydWR5", 0), "QmA1", mac),
		"another folder":     k.verify(alice, "QmA2", mac),
		"another swarm key":  other.verify(alice, "QmA1", mac),
		"not base64url":      k.verify(alice, "QmA1", mac+"!"),
		"empty":              k.verify(alice, "QmA1", ""),
		"another swarm-mac=": k.verify(alice, "QmA1", other.mac(alice, "QmA1")),
	} {
		if ok {
			t.Errorf("%s: the swarm-mac= checks", what)
		}
	}
}
