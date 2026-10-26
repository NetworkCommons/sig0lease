package agent

import (
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/mdnsresponder"
	"github.com/NetworkCommons/sig0lease/client/rfc9664"
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
	if len(p.Registrars) != 2 || len(p.Registrars[0].Hosts) != 2 || len(p.Registrars[0].Mirrors) != 1 || len(p.Registrars[1].Names) != 1 {
		t.Fatalf("example: %+v, want an srp registrar with 2 hosts and a mirror, and an rfc9664 one with a name", p.Registrars)
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
	r = mustParse(t, "registrars: [{protocol: rfc9664, zone: dev.test, server: 192.0.2.1:53}]\n").Registrars[0]
	if r.Protocol != RFC9664 || r.Domain != "dev.test." || r.Transport != baseclient.NetworkTCP || r.Lifetime != (Lifetime{Lease: 3600, KeyLease: 1209600, KeepNames: true}) {
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
    zone: dev.test.
    server: 192.0.2.1:53
    lease: 2h
    names:
      - {name: d, addresses: [192.0.2.4]}
      - {name: e, addresses: [192.0.2.5], on_stop: release}
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

// A backslash in a TXT value is sent as itself (clientsrp.EscapeTXT).
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
    zone: dev.test.
    server: 192.0.2.1:53
    names:
      - name: mysite
        addresses: [auto, 2001:db8::1]
        records:
          - '_dnslink TXT "dnslink=/ipfs/bafy"'
          - "@ MX 10 mail.example."
          - "www CNAME mysite.dev.test."
      - name: other
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
    zone: x.test.
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
    zone: dev.test.
    resolvers: [192.0.2.1:53]
    hosts: []
    names:
      - name: a.b
        addresses: [auto]
      - name: empty
      - name: bad
        records:
          - "x.dev.test. TXT abs"
          - "@ A 192.0.2.1"
          - "@ KEY 512 3 13 c29tZW9uZSBlbHNl"
          - "@ MX ten mail.example."
          - "@ NOPE x"
          - "x TXT twice"
          - "x TXT twice"
      - name: bad
        addresses: [192.0.2.1]
  - protocol: dhcp
`)
	for _, want := range []string{
		"srp registrar's, not an rfc9664 one's",
		"zone: is an rfc9664 registrar's, not an srp one's",
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
		"mdns is a complex type that makes its own hosts; use it under an srp registrar's mirrors:",
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
		"registrars[1] (rfc9664 dev.test.): server is required",
		"resolvers: is an srp registrar's",
		"hosts: is an srp registrar's",
		`names[0] (a.b): name "a.b": one label`,
		"names[1] (empty): nothing to register",
		"records[0]: \"x.dev.test. TXT abs\": owner x.dev.test.: relative to the name",
		"records[1]: \"@ A 192.0.2.1\": an address of the name itself: give it with the name's addresses",
		"records[2]: \"@ KEY",
		"records[3]: \"@ MX ten mail.example.\"",
		"records[4]: \"@ NOPE x\"",
		`records[6]: "x TXT twice" twice`,
		"a second name bad",
		`registrars[2]: protocol "dhcp": want srp or rfc9664`,
	} {
		wantProblem(t, got, want)
	}
}

// Registrars are one per domain or zone, an rfc9664 name stays out of the srp domains, and a
// mirror type is mirrored once.
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
    zone: dev.test.
    server: 192.0.2.1:53
    names:
      - {name: srp, records: ["@ TXT covers"]}
      - {name: fine, records: ["@ TXT fine"]}
  - protocol: rfc9664
    zone: srp.dev.test.
    server: 192.0.2.1:53
    names:
      - {name: inside, records: ["@ TXT inside"]}
`)
	for _, want := range []string{
		"registrars[1] (srp SRP.dev.test.): a second srp registrar for SRP.dev.test.",
		"registrars[1] (srp SRP.dev.test.): a second mdns mirror",
		"registrars[2] (rfc9664 dev.test.): name srp.dev.test.: in the srp domain srp.dev.test., or above it",
		"registrars[3] (rfc9664 srp.dev.test.): name inside.srp.dev.test.: in the srp domain srp.dev.test.",
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
		wantProblem(t, problems(t, "registrars: [{protocol: rfc9664, server: 192.0.2.1:53, zone: \""+d+"\"}]\n"), "registrars[0]: zone")
	}
	mustParse(t, "registrars: [{protocol: srp, domain: default.service.arpa}]\n")
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
		if ti.Name == "mdns" && !ti.Complex {
			t.Error("mdns is not listed as a complex type")
		}
	}
	for _, want := range []string{"ssh", "sftp-ssh", "http", "https", "ipfs-gateway", "activitypub", "ipp", "mdns"} {
		if !slices.Contains(names, want) {
			t.Errorf("Types() lacks %s: %v", want, names)
		}
	}
}
