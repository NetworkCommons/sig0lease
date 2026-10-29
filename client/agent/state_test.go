package agent

import (
	"path/filepath"
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
)

// The state file keeps a host while its names are held, with the labels they are held under
// if a rename changed any, and is read back as written.
func TestHostStore(t *testing.T) {
	dir := t.TempDir()
	s, err := openHostStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	v := s.view(sourceHosts, savedRegistrar{Domain: "srp.test.", Transport: baseclient.NetworkTLS})
	if err := v.Hold("a.srp.test.", &clientsrp.Labels{Host: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := v.Hold("b.srp.test.", &clientsrp.Labels{Host: "b-2"}); err != nil {
		t.Fatal(err)
	}
	if err := v.Hold("c.srp.test.", nil); err != nil {
		t.Fatal(err)
	}

	again, err := openHostStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := again.entries()
	if e := got["a.srp.test."]; !e.Held || e.Labels != nil || e.Source != sourceHosts || e.Registrar.Transport != baseclient.NetworkTLS {
		t.Errorf("a = %+v, want held, no labels written, from hosts, over tls", e)
	}
	if l := again.labels("a.srp.test."); l == nil || l.Host != "a" {
		t.Errorf("a's labels = %+v, want host a", l)
	}
	if l := again.labels("b.srp.test."); l == nil || l.Host != "b-2" {
		t.Errorf("b's labels = %+v, want host b-2", l)
	}
	if _, ok := got["c.srp.test."]; ok || len(got) != 2 {
		t.Errorf("entries = %v, want a and b only", got)
	}

	// Freed, a and b hold nothing: they go, b's rename with it.
	v = again.view(sourceHosts, savedRegistrar{Domain: "srp.test.", Transport: baseclient.NetworkTLS})
	if err := v.Hold("a.srp.test.", nil); err != nil {
		t.Fatal(err)
	}
	if err := v.Hold("b.srp.test.", nil); err != nil {
		t.Fatal(err)
	}
	if err := again.forget("x.srp.test."); err != nil {
		t.Fatal(err)
	}
	third, err := openHostStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := third.entries(); len(got) != 0 {
		t.Errorf("entries = %v, want none", got)
	}
	if l := third.labels("b.srp.test."); l != nil {
		t.Errorf("b's labels after it was freed = %+v, want none", l)
	}
}

// A name's entry keeps its records while it has some or is held, and reads them back.
func TestHostStore_Names(t *testing.T) {
	dir := t.TempDir()
	s, err := openHostStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	v := s.names(savedRegistrar{Domain: "dev.test.", Server: "192.0.2.1:53", Transport: baseclient.NetworkTCP})
	site, err := dns.New(`site.dev.test. 300 IN TXT "a b"`)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Save("site.dev.test.", true, []dns.RR{site}); err != nil {
		t.Fatal(err)
	}
	again, err := openHostStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := again.entry("site.dev.test."); !e.Held || e.Source != sourceNames {
		t.Errorf("entry = %+v, want held, from names", e)
	}
	got := again.names(savedRegistrar{}).Load("site.dev.test.")
	if len(got) != 1 || got[0].String() != site.String() {
		t.Errorf("Load = %v, want %v", got, site)
	}

	// Kept for its key, the name has no records; freed, it goes.
	if err := v.Save("site.dev.test.", true, nil); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.entry("site.dev.test."); !e.Held || e.Records != nil {
		t.Errorf("entry kept = %+v, want held without records", e)
	}
	if err := v.Save("site.dev.test.", false, nil); err != nil {
		t.Fatal(err)
	}
	if got := s.entries(); len(got) != 0 {
		t.Errorf("entries after freeing = %v, want none", got)
	}
}

// A host or name is wanted where it was registered: from the template's keystore, in its
// domain or zone, through its registrar, as one of its hosts or names or, if a mirror
// registered it, as one a mirror of that type selects.
func TestWanted(t *testing.T) {
	t.Setenv("CLIENT_KEYSTORE_DIR", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	plan, err := Parse([]byte(`
keystore: keys
registrars:
  - protocol: srp
    domain: srp.test.
    server: 127.0.0.1:8159
    hosts: [{name: box, addresses: [192.0.2.1]}]
    mirrors: [{type: mdns, hosts: [MyMac.local.]}]
  - protocol: rfc9664
    zone: dev.test.
    server: 127.0.0.1:8159
    names: [{name: site, addresses: [192.0.2.1]}]
`), path)
	if err != nil {
		t.Fatal(err)
	}
	keystore := filepath.Join(dir, "keys")
	here := savedRegistrarOf(plan.Registrars[0])
	other := here
	other.Server = "127.0.0.1:9999"
	zone := savedRegistrarOf(plan.Registrars[1])
	for _, tt := range []struct {
		host     string
		e        savedHost
		keystore string
		want     bool
	}{
		{"box.srp.test.", savedHost{Source: sourceHosts, Registrar: here}, keystore, true},
		{"BOX.srp.test.", savedHost{Source: "mdns", Registrar: here}, keystore, true},
		{"gone.srp.test.", savedHost{Source: sourceHosts, Registrar: here}, keystore, false},
		{"mymac.srp.test.", savedHost{Source: "mdns", Registrar: here}, keystore, true},
		{"mymac.srp.test.", savedHost{Source: sourceHosts, Registrar: here}, keystore, false},
		{"other.srp.test.", savedHost{Source: "mdns", Registrar: here}, keystore, false},
		{"box.srp.test.", savedHost{Source: sourceHosts, Registrar: other}, keystore, false},
		{"box.srp.test.", savedHost{Source: sourceHosts, Registrar: here}, filepath.Join(dir, "old"), false},
		{"site.dev.test.", savedHost{Source: sourceNames, Registrar: zone}, keystore, true},
		{"gone.dev.test.", savedHost{Source: sourceNames, Registrar: zone}, keystore, false},
		{"site.dev.test.", savedHost{Source: sourceHosts, Registrar: zone}, keystore, false},
		{"box.srp.test.", savedHost{Source: sourceNames, Registrar: here}, keystore, false},
	} {
		if got := wanted(plan, tt.keystore, tt.host, tt.e); got != tt.want {
			t.Errorf("wanted(%s, %+v, %s) = %v, want %v", tt.host, tt.e, tt.keystore, got, tt.want)
		}
	}

	s, err := openHostStore(keystore)
	if err != nil {
		t.Fatal(err)
	}
	s.hosts = map[string]savedHost{
		"box.srp.test.":  {Source: sourceHosts, Registrar: here, Held: true},
		"gone.srp.test.": {Source: sourceHosts, Registrar: here, Held: true},
		"old.srp.test.":  {Source: sourceHosts, Registrar: here, Held: true, Labels: &savedLabels{Host: "old-2"}},
	}
	if got := s.unwanted(plan); !slices.Equal(got, []string{"gone.srp.test.", "old.srp.test."}) {
		t.Errorf("unwanted = %v, want gone and old", got)
	}
}
