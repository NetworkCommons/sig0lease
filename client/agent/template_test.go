package agent

import (
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/mdnsresponder"
	"github.com/NetworkCommons/sig0lease/client/rfc9664"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// envKeystore is the keystore a template without keystore: gets in mustParse.
const envKeystore = "/var/lib/agent"

// mustParse parses yaml with CLIENT_KEYSTORE_DIR set to envKeystore, problems with it unset, so
// the environment the tests run in changes neither.
func mustParse(t *testing.T, yaml string) *Plan {
	t.Helper()
	t.Setenv(keyrec.KeystoreEnv, envKeystore)
	p, err := Parse([]byte(yaml), "/etc/agent/t.yaml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func problems(t *testing.T, yaml string) []string {
	t.Helper()
	t.Setenv(keyrec.KeystoreEnv, "")
	_, err := Parse([]byte(yaml), "t.yaml")
	var v *ValidationError
	if !errors.As(err, &v) {
		t.Fatalf("Parse = %v, want a ValidationError", err)
	}
	return v.Problems
}

func wantProblem(t *testing.T, got []string, sub string) {
	t.Helper()
	if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, sub) }) {
		t.Errorf("no problem containing %q in:\n  %s", sub, strings.Join(got, "\n  "))
	}
}

// srpYAML is a template with one srp registrar for srp.test., fields its further lines
// (indented as the registrar's), and rest after it.
func srpYAML(fields, rest string) string {
	return "registrars:\n  - protocol: srp\n    domain: srp.test.\n" + fields + rest
}

// The example template in the repository stays valid.
func TestLoad_ExampleTemplate(t *testing.T) {
	p, err := Load(filepath.Join("..", "..", "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Registrars) != 2 || len(p.Registrars[0].Hosts) != 2 || len(p.Registrars[0].Mirrors) != 1 || len(p.Registrars[1].Names) != 3 || len(p.Registrars[1].Names[1].Services) != 2 || p.Registrars[1].Names[2].IPFS == nil {
		t.Fatalf("example: %+v, want an srp registrar with 2 hosts and a mirror, and an rfc9664 one with a name, an XMPP server's and an IPFS node's", p.Registrars)
	}
}

// The demo's templates (docs/demo.md) stay valid: each an srp registrar with host demo and an
// rfc9664 one with name demo.dev.zenr.io., both through the proxy on the same machine.
func TestLoad_DemoTemplates(t *testing.T) {
	for _, file := range []string{"demo.yaml", "conflict.yaml"} {
		p, err := Load(filepath.Join("..", "..", "demo", file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if len(p.Registrars) != 2 || len(p.Registrars[0].Hosts) != 1 || p.Registrars[0].Hosts[0].Name != "demo" ||
			len(p.Registrars[1].Names) != 1 || p.Registrars[1].Names[0].Name != "demo.dev.zenr.io." ||
			p.Registrars[0].Server != "127.0.0.1:8053" || p.Registrars[1].Server != "127.0.0.1:8053" {
			t.Fatalf("%s: %+v, want host demo and name demo.dev.zenr.io., through 127.0.0.1:8053", file, p.Registrars)
		}
	}
}

func TestParse_RegistrarDefaults(t *testing.T) {
	r := mustParse(t, "registrars: [{protocol: srp, domain: srp.test}]\n").Registrars[0]
	if r.Protocol != SRP || r.Domain != "srp.test." || r.Transport != baseclient.NetworkTCP || r.Server != "" || r.Resolvers != nil || r.Lifetime != (Lifetime{Lease: 3600, KeyLease: 1209600, KeepNames: true}) {
		t.Fatalf("registrar = %+v", r)
	}
	r = mustParse(t, "registrars: [{protocol: srp, domain: srp.test., lease: 90m, key_lease: 2h, on_stop: release, transport: tls, server: 192.0.2.1:853}]\n").Registrars[0]
	if r.Lifetime != (Lifetime{Lease: 5400, KeyLease: 7200}) || r.Transport != baseclient.NetworkTLS || r.Server != "192.0.2.1:853" {
		t.Fatalf("registrar = %+v", r)
	}
	r = mustParse(t, "registrars: [{protocol: rfc9664, server: 192.0.2.1:53}]\n").Registrars[0]
	if r.Protocol != RFC9664 || r.Domain != "" || r.Transport != baseclient.NetworkTCP || r.Lifetime != (Lifetime{Lease: 3600, KeyLease: 1209600, KeepNames: true}) {
		t.Fatalf("rfc9664 registrar = %+v", r)
	}
}

// A host or name takes its registrar's lease, key_lease and on_stop, and overrides any it gives.
func TestParse_HostOverridesTheLifetime(t *testing.T) {
	p := mustParse(t, srpYAML("    lease: 1h\n    key_lease: 336h\n", `    hosts:
      - {name: a, addresses: [192.0.2.1]}
      - {name: b, addresses: [192.0.2.2], lease: 2m, key_lease: 10m, on_stop: release}
      - {name: c, addresses: [192.0.2.3], on_stop: release}
  - protocol: rfc9664
    server: 192.0.2.1:53
    lease: 2h
    names:
      - {name: d.dev.test, addresses: [192.0.2.4]}
      - {name: e.dev.test, addresses: [192.0.2.5], on_stop: release}
`))
	hosts, names := p.Registrars[0].Hosts, p.Registrars[1].Names
	for i, want := range []Lifetime{
		{Lease: 3600, KeyLease: 1209600, KeepNames: true},
		{Lease: 120, KeyLease: 600},
		{Lease: 3600, KeyLease: 1209600},
	} {
		if got := hosts[i].Lifetime; got != want {
			t.Errorf("host %s: %+v, want %+v", hosts[i].Name, got, want)
		}
	}
	for i, want := range []Lifetime{
		{Lease: 7200, KeyLease: 1209600, KeepNames: true},
		{Lease: 7200, KeyLease: 1209600},
	} {
		if got := names[i].Lifetime; got != want {
			t.Errorf("name %s: %+v, want %+v", names[i].Name, got, want)
		}
	}
	got := problems(t, srpYAML("    on_stop: forget\n", `    hosts:
      - {name: a, addresses: [192.0.2.1], lease: 400h}
      - {name: b, addresses: [192.0.2.2], on_stop: maybe, key_lease: soon}
`))
	wantProblem(t, got, `registrars[0] (srp srp.test.): on_stop "forget": want keep or release`)
	wantProblem(t, got, "hosts[0] (a): lease is longer than key_lease")
	wantProblem(t, got, `hosts[1] (b): on_stop "maybe": want keep or release`)
	wantProblem(t, got, "hosts[1] (b): key_lease")
}

// The keystore follows the clients' convention (keyrec.KeystoreDir): the template's keystore:,
// relative to the template's directory, wins over CLIENT_KEYSTORE_DIR, and one is required.
func TestParse_Keystore(t *testing.T) {
	if got := mustParse(t, "keystore: keys\n"+srpYAML("", "")).Keystore; got != "/etc/agent/keys" {
		t.Errorf("keystore: keys = %s, want /etc/agent/keys", got)
	}
	if got := mustParse(t, srpYAML("", "")).Keystore; got != envKeystore {
		t.Errorf("no keystore: = %s, want %s", got, envKeystore)
	}
	wantProblem(t, problems(t, srpYAML("", "")), "keystore directory is required: give keystore: or set CLIENT_KEYSTORE_DIR")
}

// A service takes its type's fields, and overrides any it gives: port, TXT keys (merged),
// subtypes and probe (replaced).
func TestParse_ServiceOverridesItsType(t *testing.T) {
	p := mustParse(t, srpYAML("", `    hosts:
      - name: box
        addresses: [192.0.2.1, auto]
        services:
          - type: ssh
          - type: ssh
            instance: Admin
            port: 2222
            probe: none
          - type: ipfs-gateway
            txt: {path: /ipns/, open: null}
            subtypes: []
          - type: http
            probe: {http: /health}
`))
	h := p.Registrars[0].Hosts[0]
	if !h.Auto || !slices.Equal(h.Addresses, []netip.Addr{netip.MustParseAddr("192.0.2.1")}) {
		t.Fatalf("addresses: auto %v, %v", h.Auto, h.Addresses)
	}
	s := h.Services
	if in := s[0].Instance; in.Label != "box ssh" || in.ServiceType != "_ssh._tcp" || in.Port != 22 || s[0].Probe.Kind != ProbeTCP {
		t.Errorf("ssh = %+v %v", in, s[0].Probe)
	}
	if in := s[1].Instance; in.Label != "Admin" || in.Port != 2222 || s[1].Probe.Kind != ProbeNone {
		t.Errorf("overridden ssh = %+v %v", in, s[1].Probe)
	}
	if in := s[2].Instance; in.ServiceType != "_http._tcp" || in.Port != 8080 || !slices.Equal(in.TXT, []string{"open", "path=/ipns/"}) || len(in.Subtypes) != 0 {
		t.Errorf("ipfs-gateway = %+v", in)
	}
	if s[3].Probe != (Probe{Kind: ProbeHTTP, Path: "/health"}) {
		t.Errorf("http probe = %+v", s[3].Probe)
	}
}

func TestParse_TemplateTypes(t *testing.T) {
	p := mustParse(t, `
types:
  gemini: {service: _gemini._tcp, port: 1965, txt: {v: "1"}, probe: {tcp: true}}
  bare: {service: _bare._udp}
`+srpYAML("", `    hosts:
      - name: box
        addresses: [192.0.2.1]
        services:
          - type: gemini
          - type: bare
            port: 9
`))
	s := p.Registrars[0].Hosts[0].Services
	if in := s[0].Instance; in.ServiceType != "_gemini._tcp" || in.Port != 1965 || !slices.Equal(in.TXT, []string{"v=1"}) || s[0].Probe.Kind != ProbeTCP {
		t.Errorf("gemini = %+v %v", in, s[0].Probe)
	}
	if in := s[1].Instance; in.ServiceType != "_bare._udp" || in.Port != 9 || s[1].Probe.Kind != ProbeNone {
		t.Errorf("bare = %+v %v", in, s[1].Probe)
	}
}

// A backslash in a TXT value is sent as itself (dnsmsg.EscapeTXT).
func TestParse_TXTIsEscaped(t *testing.T) {
	p := mustParse(t, srpYAML("", `    hosts:
      - name: box
        addresses: [192.0.2.1]
        services:
          - {type: http, txt: {p: 'a\b'}}
`))
	if got := p.Registrars[0].Hosts[0].Services[0].Instance.TXT; !slices.Equal(got, []string{`p=a\\b`}) {
		t.Fatalf("TXT = %q", got)
	}
}

// A name's records are relative to it, "@" the name itself, and its addresses separate.
func TestParse_Names(t *testing.T) {
	p := mustParse(t, `
registrars:
  - protocol: rfc9664
    server: 192.0.2.1:53
    names:
      - name: mysite.dev.test.
        addresses: [auto, 2001:db8::1]
        records:
          - '_dnslink TXT "dnslink=/ipfs/bafy"'
          - "@ MX 10 mail.example."
          - "www CNAME mysite.dev.test."
      - name: other.dev.test.
        records: ["@ TXT hello"]
`)
	n := p.Registrars[0].Names
	if !n[0].Auto || !slices.Equal(n[0].Addresses, []netip.Addr{netip.MustParseAddr("2001:db8::1")}) {
		t.Fatalf("addresses: auto %v, %v", n[0].Auto, n[0].Addresses)
	}
	var got []string
	for _, rr := range n[0].Records {
		got = append(got, rfc9664.Describe(rr))
	}
	want := []string{`_dnslink.mysite.dev.test. TXT "dnslink=/ipfs/bafy"`, "mysite.dev.test. MX 10 mail.example.", "www.mysite.dev.test. CNAME mysite.dev.test."}
	if !slices.Equal(got, want) {
		t.Fatalf("records = %q, want %q", got, want)
	}
	if n[1].Auto || n[1].Addresses != nil || len(n[1].Records) != 1 {
		t.Fatalf("other = %+v", n[1])
	}
}

// An rfc9664 registrar's resolvers, with no name that follows a community, do nothing: a
// warning, not a problem, so that removing the last follower leaves the template valid.
func TestParse_UnusedResolvers(t *testing.T) {
	p := mustParse(t, `
registrars:
  - protocol: rfc9664
    server: 192.0.2.1:53
    resolvers: [192.0.2.53:53]
    names:
      - {name: a.dev.test., ipfs: {publish: {mfs: /community}}}
`)
	want := []string{"registrars[0] (rfc9664 192.0.2.1:53): resolvers: unused: none of its names follows a community (ipfs: {follow:})"}
	if !slices.Equal(p.Warnings, want) {
		t.Errorf("warnings = %q, want %q", p.Warnings, want)
	}
}

// A name's ipfs: publishes a path in its node's files or follows a community, or gives the
// node's addresses alone; the node's RPC API defaults to kubo's. A community is the instances
// of a type, by its service type, listed under a subtype, by default the name's first label,
// in an SRP domain, checked with a swarm key file, relative to the template; a name's site has
// none. The registrar's resolvers are what a follower asks for what the registrar does not
// serve.
func TestParse_NameIPFS(t *testing.T) {
	p := mustParse(t, `
registrars:
  - protocol: rfc9664
    server: 192.0.2.1:53
    resolvers: [192.0.2.53:53]
    names:
      - {name: a.dev.test., ipfs: {publish: {mfs: /community}}}
      - {name: site.dev.test., ipfs: {api: "http://127.0.0.1:5002", swarm_key: swarm.key, follow: {type: ipfs-member, domain: srp.test, revoke_after: 10m}}}
      - {name: b.dev.test., ipfs: {}}
      - {name: club.dev.test., ipfs: {swarm_key: /var/kubo/swarm.key, follow: {type: ipfs-member, subtype: friends, domain: srp.test., revoke_after: 90s}}}
`)
	r := p.Registrars[0]
	if !slices.Equal(r.Resolvers, []string{"192.0.2.53:53"}) {
		t.Errorf("resolvers = %v, want 192.0.2.53:53", r.Resolvers)
	}
	if w := p.Warnings; w != nil {
		t.Errorf("warnings = %q, want none: a name follows a community", w)
	}
	n := r.Names
	for i, want := range []IPFS{
		{API: "http://127.0.0.1:5001", Publish: "/community"},
		{API: "http://127.0.0.1:5002", SwarmKey: "/etc/agent/swarm.key", Follow: &Follow{ServiceType: "_ipfs-member._tcp", Subtype: "site", Domain: "srp.test.", RevokeAfter: 10 * time.Minute}},
		{API: "http://127.0.0.1:5001"},
		{API: "http://127.0.0.1:5001", SwarmKey: "/var/kubo/swarm.key", Follow: &Follow{ServiceType: "_ipfs-member._tcp", Subtype: "friends", Domain: "srp.test.", RevokeAfter: 90 * time.Second}},
	} {
		if n[i].IPFS == nil || !reflect.DeepEqual(*n[i].IPFS, want) {
			t.Errorf("%s's ipfs = %+v, want %+v", n[i].Name, n[i].IPFS, want)
		}
	}
	if got := n[1].IPFS.Follow.Members(); got != "site._sub._ipfs-member._tcp.srp.test." {
		t.Errorf("Members() = %q", got)
	}

	got := problems(t, `
keystore: keys
registrars:
  - protocol: rfc9664
    server: 192.0.2.1:53
    names:
      - {name: both.dev.test., ipfs: {swarm_key: k, publish: {mfs: /x}, follow: {type: ipfs-member, domain: srp.test, revoke_after: 1m}}}
      - {name: badapi.dev.test., ipfs: {api: "https://127.0.0.1:5001/api"}}
      - {name: badmfs.dev.test., ipfs: {publish: {mfs: community}}}
      - {name: badtype.dev.test., ipfs: {swarm_key: k, follow: {type: nosuch, domain: srp.test, revoke_after: 1m}}}
      - {name: badsub.dev.test., ipfs: {swarm_key: k, follow: {type: ipfs-member, subtype: "my site", domain: srp.test, revoke_after: 1m}}}
      - {name: nodomain.dev.test., ipfs: {swarm_key: k, follow: {type: ipfs-member, revoke_after: 1m}}}
      - {name: norevoke.dev.test., ipfs: {swarm_key: k, follow: {type: ipfs-member, domain: srp.test}}}
      - {name: badrevoke.dev.test., ipfs: {swarm_key: k, follow: {type: ipfs-member, domain: srp.test, revoke_after: "-1m"}}}
      - {name: twice.dev.test., records: ['_dnslink TXT "dnslink=/ipfs/x"'], ipfs: {publish: {mfs: /x}}}
      - {name: addrs.dev.test., records: ['_dnsaddr TXT "dnsaddr=/ip4/192.0.2.1/tcp/4001/p2p/x"'], ipfs: {}}
      - {name: nokey.dev.test., ipfs: {follow: {type: ipfs-member, domain: srp.test, revoke_after: 1m}}}
      - {name: sitekey.dev.test., ipfs: {swarm_key: k, publish: {mfs: /x}}}
`)
	for _, want := range []string{
		"names[0] (both.dev.test.): ipfs: publish: and follow: are two sites for one name; give one",
		`names[1] (badapi.dev.test.): ipfs: api: "https://127.0.0.1:5001/api": want http://host:port`,
		`names[2] (badmfs.dev.test.): ipfs: publish: mfs: "community": want a path in the node's files`,
		`names[3] (badtype.dev.test.): ipfs: follow: type "nosuch": want the type the members' services are`,
		`names[4] (badsub.dev.test.): ipfs: follow: subtype "my site": want a label of letters, digits and hyphens`,
		"names[5] (nodomain.dev.test.): ipfs: follow: domain is required",
		"names[6] (norevoke.dev.test.): ipfs: follow: revoke_after is required",
		`names[7] (badrevoke.dev.test.): ipfs: follow: revoke_after "-1m": want a duration`,
		"names[8] (twice.dev.test.): ipfs: registers the TXT records at _dnslink.twice.dev.test., which records[0] registers too",
		"names[9] (addrs.dev.test.): ipfs: registers the TXT records at _dnsaddr.addrs.dev.test., which records[0] registers too",
		"names[10] (nokey.dev.test.): ipfs: swarm_key is required with follow:",
		"names[11] (sitekey.dev.test.): ipfs: swarm_key: a community's (follow:) or a member's",
	} {
		wantProblem(t, got, want)
	}
	if len(got) != 12 {
		t.Errorf("%d problems, want 12:\n%s", len(got), strings.Join(got, "\n"))
	}
	wantProblem(t, problems(t, srpYAML("", "    mirrors: [{type: ipfs, all_hosts: true}]\n")), `"ipfs" is not a complex type that makes hosts (known: mdns)`)
	wantProblem(t, problems(t, srpYAML("", "    hosts: [{name: box, addresses: [auto], services: [{type: ipfs}]}]\n")), "ipfs is a complex type, not a service's; use it as an rfc9664 registrar's name's ipfs:, or an srp host's service's")
}

// A host's service's ipfs: gives a folder of its node's files in its TXT record, with the
// swarm-mac= of its swarm key file, relative to the template; it publishes with publish: alone,
// and its TXT record's dnslink and swarm-mac are its own. A name's service has none.
func TestParse_ServiceIPFS(t *testing.T) {
	p := mustParse(t, srpYAML("", `    hosts:
      - name: alice
        addresses: [auto]
        services:
          - {type: ipfs-member, instance: alice, subtypes: [site], ipfs: {swarm_key: swarm.key, publish: {mfs: /community}}}
`))
	s := p.Registrars[0].Hosts[0].Services[0]
	want := clientsrp.InstanceConfig{Label: "alice", ServiceType: "_ipfs-member._tcp", Subtypes: []string{"site"}, Port: 4001, TXT: []string{}}
	if !reflect.DeepEqual(s.Instance, want) || s.Probe != (Probe{Kind: ProbeTCP}) || !reflect.DeepEqual(s.IPFS, &IPFS{API: "http://127.0.0.1:5001", Publish: "/community", SwarmKey: "/etc/agent/swarm.key"}) {
		t.Errorf("service = %+v, ipfs %+v; want %+v, a tcp probe, the folder /community, the swarm key /etc/agent/swarm.key", s, s.IPFS, want)
	}

	got := problems(t, srpYAML("", `    hosts:
      - name: alice
        addresses: [auto]
        services:
          - {type: ipfs-member, ipfs: {}}
          - {type: ipfs-member, instance: two, ipfs: {swarm_key: k, follow: {type: ipfs-member, domain: srp.test, revoke_after: 1m}}}
          - {type: ipfs-member, instance: three, txt: {DNSLink: x}, ipfs: {swarm_key: k, publish: {mfs: /c}}}
          - {type: ipfs-member, instance: four, txt: {Swarm-MAC: x}, ipfs: {swarm_key: k, publish: {mfs: /c}}}
`))
	for _, want := range []string{
		"services[0]: ipfs: publish: is required",
		"services[0]: ipfs: swarm_key is required",
		"services[1]: ipfs: follow: is a name's",
		"services[2]: txt DNSLink: ipfs: gives the TXT record's dnslink",
		"services[3]: txt Swarm-MAC: ipfs: gives the TXT record's swarm-mac",
	} {
		wantProblem(t, got, want)
	}
	wantProblem(t, problems(t, `
keystore: keys
registrars:
  - protocol: rfc9664
    server: 192.0.2.1:53
    names: [{name: a.dev.test., addresses: [192.0.2.1], services: [{type: http, ipfs: {publish: {mfs: /c}}}]}]
`), "services[0]: ipfs: a host's service has it, not a name's")
}

// A name's service is the SRV records that find it at the name and its subdomains, pointing
// at the name; with tlsa, also a TLSA record at the name's port, from a certificate relative to
// the template.
func TestParse_NameServices(t *testing.T) {
	n := mustParse(t, `
registrars:
  - protocol: rfc9664
    server: 192.0.2.1:53
    names:
      - name: a.dev.test.
        addresses: [auto]
        services:
          - type: xmpp-client
          - type: xmpp-server
            port: 15269
            subdomains: [rooms]
            tlsa: certs/a.crt
            probe: none
`).Registrars[0].Names[0]
	if len(n.Services) != 2 {
		t.Fatalf("services = %+v, want 2", n.Services)
	}
	c, s := n.Services[0], n.Services[1]
	if c.Instance.ServiceType != "_xmpp-client._tcp" || c.Instance.Port != 5222 || c.Probe.Kind != ProbeTCP || c.TLSA != "" || c.Instance.Label != "" {
		t.Errorf("xmpp-client = %+v, want the preset's service, port and probe", c)
	}
	if s.Instance.Port != 15269 || s.Probe.Kind != ProbeNone || s.TLSA != "/etc/agent/certs/a.crt" {
		t.Errorf("xmpp-server = %+v, want port 15269, no probe, tlsa relative to the template", s)
	}
	var got []string
	for _, rr := range s.SRV("a.dev.test.") {
		got = append(got, rfc9664.Describe(rr))
	}
	want := []string{"_xmpp-server._tcp.a.dev.test. SRV 0 0 15269 a.dev.test.", "_xmpp-server._tcp.rooms.a.dev.test. SRV 0 0 15269 a.dev.test."}
	if !slices.Equal(got, want) {
		t.Errorf("SRV = %q, want %q", got, want)
	}
	if o := s.TLSAOwner("a.dev.test."); o != "_15269._tcp.a.dev.test." {
		t.Errorf("TLSAOwner = %s, want _15269._tcp.a.dev.test.", o)
	}

	got = problems(t, `
keystore: keys
registrars:
  - protocol: srp
    domain: srp.test.
    hosts:
      - name: box
        addresses: [auto]
        services: [{type: ssh, subdomains: [x], tlsa: c.pem}]
  - protocol: rfc9664
    server: 192.0.2.1:53
    names:
      - name: bare.dev.test.
        records: ['@ TXT x']
        services: [{type: xmpp-client}]
      - name: hostish.dev.test.
        addresses: [auto]
        services:
          - {type: xmpp-client, instance: Chat, txt: {a: b}, subtypes: [_x]}
          - {type: ipp}
          - {type: xmpp-server, subdomains: [rooms, Rooms, -bad]}
      - name: twice.dev.test.
        addresses: [auto]
        records: ['_xmpp-client._tcp SRV 0 0 5222 twice.dev.test.']
        services:
          - {type: xmpp-client}
          - {type: xmpp-server, tlsa: a.pem}
          - {type: xmpp-server, subdomains: [rooms], tlsa: b.pem}
          - {type: https, port: 5269, tlsa: c.pem}
`)
	for _, want := range []string{
		"hosts[0] (box): services[0]: subdomains: a name's service has it, not a host's",
		"hosts[0] (box): services[0]: tlsa: a name's service has it, not a host's",
		"names[0] (bare.dev.test.): services: their SRV records point at the name, which needs addresses:",
		"names[1] (hostish.dev.test.): services[0]: instance: a host's service has it, not a name's",
		"names[1] (hostish.dev.test.): services[0]: txt: a host's service has it",
		"names[1] (hostish.dev.test.): services[0]: subtypes: a host's service has it",
		"names[1] (hostish.dev.test.): services[1]: type ipp has TXT keys or subtypes, which a name's service cannot carry",
		"names[1] (hostish.dev.test.): services[2]: subdomains: Rooms twice",
		`names[1] (hostish.dev.test.): services[2]: subdomains: "-bad": want a name relative to the name`,
		"names[2] (twice.dev.test.): services[0]: registers the SRV records at _xmpp-client._tcp.twice.dev.test., which records[0] registers too",
		"names[2] (twice.dev.test.): services[2]: registers the SRV records at _xmpp-server._tcp.twice.dev.test., which services[1] registers too",
		"names[2] (twice.dev.test.): services[3]: registers the TLSA records at _5269._tcp.twice.dev.test., which services[1] registers too",
	} {
		wantProblem(t, got, want)
	}
}

// Over DoH a registrar is a URL, and an SRP one must be given: nothing discovers it.
func TestParse_DoHServer(t *testing.T) {
	r := mustParse(t, "registrars: [{protocol: srp, domain: srp.test., transport: doh, server: \"http://192.0.2.1:8080\"}]\n").Registrars[0]
	if r.Transport != baseclient.NetworkDoH || r.Server != "http://192.0.2.1:8080" {
		t.Fatalf("got transport %s server %q", r.Transport, r.Server)
	}
	got := problems(t, `
registrars:
  - {protocol: srp, domain: a.test., transport: doh}
  - {protocol: srp, domain: b.test., transport: doh, server: "192.0.2.1:8080"}
  - {protocol: rfc9664, transport: doh, server: "https://proxy.example/dns-query", names: [{name: x.c.test., addresses: [192.0.2.1]}]}
  - {protocol: srp, domain: d.test., server: "https://proxy.example"}
`)
	for _, want := range []string{
		"registrars[0] (srp a.test.): server is required with transport doh",
		`registrars[1] (srp b.test.): server: "192.0.2.1:8080": want an http or https URL`,
		`registrars[2] (rfc9664 https://proxy.example/dns-query): server: "https://proxy.example/dns-query": want an http or https URL`,
		`registrars[3] (srp d.test.): server: "https://proxy.example": want host:port`,
	} {
		wantProblem(t, got, want)
	}
}

// Every problem is reported at once.
func TestParse_ReportsEveryProblem(t *testing.T) {
	got := problems(t, `
types:
  ssh: {service: _ssh._tcp}
  mdns: {service: _x._tcp}
  Bad: {service: _x._tcp}
  noproto: {service: _x}
registrars:
  - protocol: srp
    transport: quic
    server: nope
    lease: 30h
    key_lease: 2h
    hosts:
      - name: Box
        addresses: []
        services:
          - type: sssh
          - type: mdns
      - name: box
        addresses: [ff02::1, 0.0.0.0, "fe80::1%eth0", 10.0.0.1, 10.0.0.1, nope]
        services:
          - {type: ssh, instance: shared}
          - {type: http, port: 70000}
          - {type: http, txt: {"a=b": x}}
          - {type: http, probe: {http: health}}
      - name: -x
        addresses: [auto]
        services:
          - {type: ssh, instance: shared}
          - {type: ssh, instance: "a.b"}
    mirrors:
      - {type: mdns, hosts: [box.local.], all_hosts: true}
      - {type: ssh}
  - protocol: rfc9664
    resolvers: [nope]
    hosts: []
    names:
      - name: a
        addresses: [auto]
      - name: empty.dev.test.
      - name: bad.dev.test.
        records:
          - "x.dev.test. TXT abs"
          - "@ A 192.0.2.1"
          - "@ KEY 512 3 13 c29tZW9uZSBlbHNl"
          - "@ MX ten mail.example."
          - "@ NOPE x"
          - "x TXT twice"
          - "x TXT twice"
      - name: Bad.dev.test.
        addresses: [192.0.2.1]
  - protocol: dhcp
`)
	for _, want := range []string{
		"srp registrar's, not an rfc9664 one's",
		"registrars[0]: domain is required",
		"keystore directory is required",
		`transport "quic"`,
		`server: "nope"`,
		"lease is longer than key_lease",
		"types: ssh: ssh is a preset",
		"types: mdns: mdns is a built-in complex type",
		"types: Bad: a type name is lower-case",
		"types: noproto: service:",
		"hosts[0] (Box): addresses: at least one",
		`unknown type "sssh"`,
		"mdns is a complex type, not a service's; use it under an srp registrar's mirrors:",
		"a second host named box",
		"ff02::1 cannot be published",
		"0.0.0.0 cannot be published",
		"fe80::1%eth0 cannot be published",
		"10.0.0.1 twice",
		`"nope" is neither auto nor an IP address`,
		"port 70000",
		`txt key "a=b"`,
		`name "-x"`,
		`instance "shared" _ssh._tcp is also on host box`,
		`instance "a.b"`,
		"give hosts: or all_hosts: true, not both or neither",
		"box.local. would be registered as box",
		`"ssh" is not a complex type`,
		"registrars[1]: server is required",
		`registrars[1]: resolvers: "nope": want host:port`,
		"hosts: is an srp registrar's",
		`names[0] (a): name "a" has one label: give the name in full`,
		"names[1] (empty.dev.test.): nothing to register",
		"records[0]: \"x.dev.test. TXT abs\": owner x.dev.test.: relative to the name",
		"records[1]: \"@ A 192.0.2.1\": an address of the name itself: give it with the name's addresses",
		"records[2]: \"@ KEY",
		"records[3]: \"@ MX ten mail.example.\"",
		"records[4]: \"@ NOPE x\"",
		`records[6]: "x TXT twice" twice`,
		"a second name Bad.dev.test.",
		`registrars[2]: protocol "dhcp": want srp or rfc9664`,
	} {
		wantProblem(t, got, want)
	}
}

// Registrars are one per srp domain or rfc9664 proxy, a name is given once, an rfc9664 name
// stays out of the srp domains, and a mirror type is mirrored once.
func TestParse_RegistrarsTogether(t *testing.T) {
	got := problems(t, `
registrars:
  - protocol: srp
    domain: srp.dev.test.
    mirrors: [{type: mdns, all_hosts: true}]
  - protocol: srp
    domain: SRP.dev.test
    mirrors: [{type: mdns, all_hosts: true}]
  - protocol: rfc9664
    server: 192.0.2.1:53
    names:
      - {name: srp.dev.test., records: ["@ TXT covers"]}
      - {name: fine.dev.test., records: ["@ TXT fine"]}
      - {name: inside.srp.dev.test., records: ["@ TXT inside"]}
      - {name: twice.dev.test., records: ["@ TXT one"]}
  - protocol: rfc9664
    server: 192.0.2.1:53
  - protocol: rfc9664
    server: 192.0.2.2:53
    names:
      - {name: Twice.dev.test., records: ["@ TXT two"]}
`)
	for _, want := range []string{
		"registrars[1] (srp SRP.dev.test.): a second srp registrar for SRP.dev.test.",
		"registrars[1] (srp SRP.dev.test.): a second mdns mirror",
		"registrars[2] (rfc9664 192.0.2.1:53): name srp.dev.test.: in the srp domain srp.dev.test., or above it",
		"registrars[2] (rfc9664 192.0.2.1:53): name inside.srp.dev.test.: in the srp domain srp.dev.test.",
		"registrars[3] (rfc9664 192.0.2.1:53): a second rfc9664 registrar at 192.0.2.1:53",
		"registrars[4] (rfc9664 192.0.2.2:53): a second name Twice.dev.test.",
	} {
		wantProblem(t, got, want)
	}
	if slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, "fine") }) {
		t.Errorf("a name outside the srp domains reported: %q", got)
	}
	wantProblem(t, problems(t, "registrars: []\n"), "registrars: at least one")
}

func TestParse_DomainLabels(t *testing.T) {
	for _, d := range []string{".", "a..b.", "_srp.example.", "-a.example."} {
		wantProblem(t, problems(t, "registrars: [{protocol: srp, domain: \""+d+"\"}]\n"), "registrars[0]: domain")
	}
	mustParse(t, "registrars: [{protocol: srp, domain: default.service.arpa}]\n")
}

// An rfc9664 name is given in full, of host name labels: the Zone Section is its parent.
func TestParse_NameLabels(t *testing.T) {
	for d, want := range map[string]string{
		".":             "has one label",
		"mysite":        "has one label",
		"a..b.":         "label is empty",
		"_srp.example.": "want labels of letters, digits and hyphens",
		"-a.example.":   "want labels of letters, digits and hyphens",
	} {
		got := problems(t, "registrars: [{protocol: rfc9664, server: 192.0.2.1:53, names: [{name: \""+d+"\", addresses: [auto]}]}]\n")
		wantProblem(t, got, "registrars[0] (rfc9664 192.0.2.1:53): names[0] ("+d+"): name \""+d+"\"")
		wantProblem(t, got, want)
	}
	if n := mustParse(t, "registrars: [{protocol: rfc9664, server: 192.0.2.1:53, names: [{name: mysite.dev.test, addresses: [auto]}]}]\n").Registrars[0].Names[0]; n.Name != "mysite.dev.test." {
		t.Errorf("name = %q, want mysite.dev.test.", n.Name)
	}
}

func TestParse_ProbeSyntax(t *testing.T) {
	reg := srpYAML("", "")
	wantProblem(t, problems(t, reg+"types: {x: {service: _x._tcp, probe: {http: health}}}\n"), "probe")
	wantProblem(t, problems(t, reg+"types: {x: {service: _x._tcp, probe: always}}\n"), "types: x: probe")
	wantProblem(t, problems(t, reg+"types: {x: {service: _x._tcp, probe: {tcp: true, http: /}}}\n"), "probe")
	wantProblem(t, problems(t, reg+"types: {x: {service: _x._tcp, probe: {tcp: false}}}\n"), "probe")
	wantProblem(t, problems(t, reg+"types: {x: {service: _x._tcp, probe: {udp: true}}}\n"), "probe")
}

// A field the format does not have is an error, not ignored.
func TestParse_UnknownField(t *testing.T) {
	wantProblem(t, problems(t, srpYAML("    lease_time: 1h\n", "")), "lease_time")
	wantProblem(t, problems(t, srpYAML("", "    hosts: [{name: box, addresses: [auto], services: [{type: ssh, prot: 2}]}]\n")), "prot")
	wantProblem(t, problems(t, "registrar: {domain: srp.test.}\n"), "registrar")
}

func TestParse_LeaseInWholeSeconds(t *testing.T) {
	wantProblem(t, problems(t, srpYAML("    lease: 1500ms\n", "")), "whole seconds")
	wantProblem(t, problems(t, srpYAML("    lease: soon\n", "")), "registrars[0] (srp srp.test.): lease")
}

// A type with no port needs the service to give one.
func TestParse_PortRequired(t *testing.T) {
	wantProblem(t, problems(t, "types: {x: {service: _x._tcp}}\n"+srpYAML("", "    hosts: [{name: box, addresses: [auto], services: [{type: x}]}]\n")), "type x has no port")
}

func TestParse_MirrorDefaults(t *testing.T) {
	p := mustParse(t, srpYAML("", "    mirrors: [{type: mdns, all_hosts: true}]\n"))
	if m := p.Registrars[0].Mirrors[0]; m.Socket != mdnsresponder.DefaultSocketPath() || !m.AllHosts || m.ServiceTypes != nil {
		t.Fatalf("mirror = %+v", m)
	}
	if r, m, ok := p.Mirror("mdns"); !ok || r.Domain != "srp.test." || m.Type != "mdns" {
		t.Fatalf("Mirror(mdns) = %v, %+v, %v", r, m, ok)
	}
	wantProblem(t, problems(t, srpYAML("", "    mirrors: [{type: mdns, all_hosts: true}, {type: mdns, all_hosts: true}]\n")), "a second mdns mirror")
}

func TestTypes_ListsPresetsAndComplexTypes(t *testing.T) {
	var names []string
	for _, ti := range Types() {
		names = append(names, ti.Name)
		if (ti.Name == "mdns" || ti.Name == "ipfs") && !ti.Complex {
			t.Errorf("%s is not listed as a complex type", ti.Name)
		}
	}
	for _, want := range []string{"ssh", "sftp-ssh", "http", "https", "ipfs-gateway", "activitypub", "ipp", "xmpp-client", "xmpp-server", "mdns", "ipfs"} {
		if !slices.Contains(names, want) {
			t.Errorf("Types() lacks %s: %v", want, names)
		}
	}
}
