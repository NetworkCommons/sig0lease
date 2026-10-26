// Package agent is sig0lease-agent: one long-running client per machine that keeps what a
// template (YAML) describes registered: hosts and their services through SRP registrars (RFC
// 9665), and names and their records through this project's proxy (RFC 9664).
//
// A template lists its registrars, each with a protocol. An srp one holds hosts -- each one SRP
// identity with its own key -- and each host's services. A service is an instance of a service
// type: a built-in preset ("ssh", "http", ...), or a type the template defines with the same
// fields. A service whose probe fails is withdrawn and registered again once it passes.
// Complex types are code, not data: a template uses them but cannot define them; "mdns", under
// an srp registrar's mirrors:, mirrors what a running mDNSResponder sees (client/mdnsbridge).
// An rfc9664 one holds names, each with its own key, its addresses and its records
// (client/rfc9664). See docs/sig0lease-agent.md.
package agent

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/mdnsresponder"
	"github.com/NetworkCommons/sig0lease/client/rfc9664"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/dnssd"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"gopkg.in/yaml.v3"
)

//go:embed presets.yaml
var presetsYAML []byte

// defaultLifetime is a registrar's when the template leaves its lease, key_lease or on_stop
// out: an hour, RFC 9665 S3.4's "typically 14 days" for the key, and the names kept.
var defaultLifetime = Lifetime{Lease: 3600, KeyLease: 14 * 24 * 3600, KeepNames: true}

// complexTypes are the types implemented in code, with what each does.
var complexTypes = map[string]string{
	"mdns": "mirrors the services a running mDNSResponder sees, one SRP host per mDNS host; under an srp registrar's mirrors:",
}

// Plan is a valid template: everything the agent registers.
type Plan struct {
	Keystore   string      // absolute: one key per host and name, and the agent's state file
	Registrars []Registrar // in the template's order
}

// Mirror returns the template's mirror of type t, and the registrar it registers through.
func (p *Plan) Mirror(t string) (Registrar, Mirror, bool) {
	for _, r := range p.Registrars {
		for _, m := range r.Mirrors {
			if m.Type == t {
				return r, m, true
			}
		}
	}
	return Registrar{}, Mirror{}, false
}

// Protocol is what a registrar is registered with.
type Protocol string

const (
	SRP     Protocol = "srp"     // RFC 9665 (client/srp): hosts with their services, and mirrors
	RFC9664 Protocol = "rfc9664" // RFC 9664 through this project's proxy (client/rfc9664): names
)

// Registrar is where and how its hosts or names register.
type Registrar struct {
	Protocol  Protocol
	Domain    string             // SRP: the domain; RFC 9664: the zone. Fully qualified.
	Server    string             // "host:port"; SRP only: "" to discover the registrar
	Transport baseclient.Network //
	Resolvers []string           // SRP: for discovery and KEY lookups; nil: client/srp's default
	Lifetime                     // every host's or name's, unless it gives its own; the mirrors' hosts'
	Hosts     []Host             // SRP
	Mirrors   []Mirror           // SRP
	Names     []Name             // RFC 9664
}

// Owner returns the name a host or name labelled label registers through r, fully qualified.
func (r Registrar) Owner(label string) string { return label + "." + r.Domain }

// connection is r without what it registers: what its hosts, names and mirrors register
// through, and their default lifetime.
func (r Registrar) connection() Registrar {
	r.Hosts, r.Mirrors, r.Names = nil, nil, nil
	return r
}

// same reports whether r and o are the template's same registrar: the same protocol and domain.
func (r Registrar) same(o Registrar) bool {
	return r.Protocol == o.Protocol && dnsname.EqualFold(r.Domain, o.Domain)
}

func (r Registrar) String() string { return fmt.Sprintf("%s registrar for %s", r.Protocol, r.Domain) }

// Lifetime is how long a host's registration lasts: its records, its key, and whether its
// names outlive the agent stopping.
type Lifetime struct {
	Lease     uint32 // seconds
	KeyLease  uint32 // seconds
	KeepNames bool   // on_stop: keep; release frees them (clientsrp.HostConfig.KeepNames)
}

func (l Lifetime) String() string {
	names := "freed"
	if l.KeepNames {
		names = "kept"
	}
	return fmt.Sprintf("%s, key %s; names %s on stop", time.Duration(l.Lease)*time.Second, time.Duration(l.KeyLease)*time.Second, names)
}

// Host is one SRP identity: a name, its addresses and its services.
type Host struct {
	Name      string
	Auto      bool         // this machine's addresses too, as they change
	Addresses []netip.Addr // literal addresses
	Services  []Service
	Lifetime  // the registrar's, with what the host overrides
}

// Service is one instance of a service type on a host.
type Service struct {
	Type     string // the type's name: a preset or one the template defines
	Instance clientsrp.InstanceConfig
	Probe    Probe
}

// ProbeKind is how a service is checked.
type ProbeKind int

const (
	ProbeNone ProbeKind = iota // never checked: always registered
	ProbeTCP                   // a TCP connection to the port succeeds
	ProbeHTTP                  // an HTTP GET of Path answers 2xx or 3xx
)

// Probe checks that a service answers, at one of its host's addresses and its port.
type Probe struct {
	Kind ProbeKind
	Path string // ProbeHTTP's path
}

func (p Probe) String() string {
	switch p.Kind {
	case ProbeTCP:
		return "tcp"
	case ProbeHTTP:
		return "http " + p.Path
	default:
		return "none"
	}
}

// Name is one RFC 9664 name: a label right below its registrar's zone, held by its own key,
// with its addresses and records.
type Name struct {
	Name      string       // the label
	Auto      bool         // this machine's addresses too, as they change
	Addresses []netip.Addr // literal addresses
	Records   []dns.RR     // at or below the name, fully qualified; no address of the name
	Lifetime               // the registrar's, with what the name overrides
}

// Mirror is a complex type that makes its own hosts.
type Mirror struct {
	Type         string // "mdns"
	Socket       string
	Hosts        []string // mDNS hosts, as given
	AllHosts     bool
	ServiceTypes []string // empty: every type the daemon sees
}

// TypeInfo describes a service type for listings.
type TypeInfo struct {
	Name    string
	Complex bool
	// Summary is the type's fields, as a template would write them, or what a complex type does.
	Summary string
}

// ValidationError lists every problem a template has.
type ValidationError struct {
	Path     string
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("template %s has %d problem(s):\n  %s", e.Path, len(e.Problems), strings.Join(e.Problems, "\n  "))
}

// The template's YAML.
type templateDoc struct {
	Keystore   string             `yaml:"keystore"`
	Types      map[string]typeDoc `yaml:"types"`
	Registrars []registrarDoc     `yaml:"registrars"`
}

// registrarDoc is either protocol's: domain, resolvers, hosts and mirrors are srp's, zone and
// names rfc9664's.
type registrarDoc struct {
	Protocol  string      `yaml:"protocol"`
	Domain    string      `yaml:"domain"`
	Zone      string      `yaml:"zone"`
	Server    string      `yaml:"server"`
	Transport string      `yaml:"transport"`
	Resolvers []string    `yaml:"resolvers"`
	Lease     string      `yaml:"lease"`
	KeyLease  string      `yaml:"key_lease"`
	OnStop    string      `yaml:"on_stop"`
	Hosts     []hostDoc   `yaml:"hosts"`
	Mirrors   []mirrorDoc `yaml:"mirrors"`
	Names     []nameDoc   `yaml:"names"`
}

// typeDoc is a data service type, and serviceDoc a service's overrides of one; a field left
// out is nil.
type typeDoc struct {
	Service  string             `yaml:"service"`
	Port     *int               `yaml:"port"`
	TXT      map[string]*string `yaml:"txt"`
	Subtypes []string           `yaml:"subtypes"`
	Probe    *probeDoc          `yaml:"probe"`
}

type serviceDoc struct {
	Type     string             `yaml:"type"`
	Instance string             `yaml:"instance"`
	Port     *int               `yaml:"port"`
	TXT      map[string]*string `yaml:"txt"`
	Subtypes []string           `yaml:"subtypes"`
	Probe    *probeDoc          `yaml:"probe"`
}

type hostDoc struct {
	Name      string       `yaml:"name"`
	Addresses []string     `yaml:"addresses"`
	Services  []serviceDoc `yaml:"services"`
	Lease     string       `yaml:"lease"`
	KeyLease  string       `yaml:"key_lease"`
	OnStop    string       `yaml:"on_stop"`
}

type nameDoc struct {
	Name      string   `yaml:"name"`
	Addresses []string `yaml:"addresses"`
	Records   []string `yaml:"records"`
	Lease     string   `yaml:"lease"`
	KeyLease  string   `yaml:"key_lease"`
	OnStop    string   `yaml:"on_stop"`
}

type mirrorDoc struct {
	Type     string   `yaml:"type"`
	Socket   string   `yaml:"socket"`
	Hosts    []string `yaml:"hosts"`
	AllHosts bool     `yaml:"all_hosts"`
	Services []string `yaml:"services"`
}

// probeDoc is "none", {tcp: true} or {http: <path>}. A malformed one is kept as a problem,
// to be reported with the template's others.
type probeDoc struct {
	probe   Probe
	problem string
}

func (p *probeDoc) UnmarshalYAML(n *yaml.Node) error {
	ok := false
	switch n.Kind {
	case yaml.ScalarNode:
		ok = n.Value == "none"
		p.probe = Probe{Kind: ProbeNone}
	case yaml.MappingNode:
		if len(n.Content) != 2 {
			break
		}
		k, v := n.Content[0].Value, n.Content[1]
		var on bool
		switch {
		case k == "tcp" && v.Decode(&on) == nil && on:
			ok, p.probe = true, Probe{Kind: ProbeTCP}
		case k == "http" && v.Kind == yaml.ScalarNode && strings.HasPrefix(v.Value, "/"):
			ok, p.probe = true, Probe{Kind: ProbeHTTP, Path: v.Value}
		}
	}
	if !ok {
		p.problem = fmt.Sprintf("probe (line %d): want none, {tcp: true} or {http: <path starting with />}", n.Line)
	}
	return nil
}

// check reports p's problem, if any, under where.
func (p *probeDoc) check(where string, problems *[]string) {
	if p != nil && p.problem != "" {
		*problems = append(*problems, fmt.Sprintf("%s: %s", where, p.problem))
	}
}

// typeDef is a validated data service type.
type typeDef struct {
	service  string
	port     int // 0: none
	txt      map[string]*string
	subtypes []string
	probe    Probe
}

var presets = mustParsePresets()

func mustParsePresets() map[string]typeDef {
	var docs map[string]typeDoc
	if err := decodeStrict(presetsYAML, &docs); err != nil {
		panic(fmt.Sprintf("agent: presets.yaml: %v", err))
	}
	var problems []string
	defs := parseTypes(docs, nil, &problems)
	if len(problems) > 0 {
		panic(fmt.Sprintf("agent: presets.yaml: %s", strings.Join(problems, "; ")))
	}
	return defs
}

func decodeStrict(data []byte, v any) error {
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(v); err != nil && !errors.Is(err, io.EOF) { // an empty document
		return err
	}
	return nil
}

var typeNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// hostNameRE is a host name label (RFC 952, RFC 1123 S2.1): letters, digits and hyphens, not
// starting or ending with a hyphen. BIND refuses an address record with any other owner name
// by default (check-names), so a host label is checked here, not only as a DNS label.
var hostNameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// parseTypes validates docs, data service types. builtin are names a type may not take.
func parseTypes(docs map[string]typeDoc, builtin map[string]typeDef, problems *[]string) map[string]typeDef {
	defs := map[string]typeDef{}
	for _, name := range sortedKeys(docs) {
		d := docs[name]
		where := fmt.Sprintf("types: %s", name)
		switch {
		case !typeNameRE.MatchString(name):
			*problems = append(*problems, fmt.Sprintf("%s: a type name is lower-case letters, digits and hyphens", where))
			continue
		case complexTypes[name] != "":
			*problems = append(*problems, fmt.Sprintf("%s: %s is a built-in complex type; pick another name", where, name))
			continue
		}
		if _, ok := builtin[name]; ok {
			*problems = append(*problems, fmt.Sprintf("%s: %s is a preset; use it as it is (a service may override its fields), or pick another name", where, name))
			continue
		}
		def := typeDef{service: d.Service, txt: d.TXT, subtypes: d.Subtypes}
		if err := dnssd.ValidateServiceType(d.Service); err != nil {
			*problems = append(*problems, fmt.Sprintf("%s: service: %v", where, err))
		}
		if d.Port != nil {
			def.port = checkPort(*d.Port, where, problems)
		}
		checkTXT(d.TXT, where, problems)
		checkSubtypes(d.Subtypes, where, problems)
		d.Probe.check(where, problems)
		if d.Probe != nil {
			def.probe = d.Probe.probe
		}
		defs[name] = def
	}
	return defs
}

func checkPort(port int, where string, problems *[]string) int {
	if port < 1 || port > 65535 {
		*problems = append(*problems, fmt.Sprintf("%s: port %d is not 1 to 65535", where, port))
		return 0
	}
	return port
}

// checkTXT checks TXT keys and values (RFC 6763 S6.4, S6.5): a key is printable US-ASCII
// without "=", and each "key=value" string fits in 255 octets.
func checkTXT(txt map[string]*string, where string, problems *[]string) {
	for _, k := range sortedKeys(txt) {
		ok := k != ""
		for i := 0; i < len(k); i++ {
			if k[i] < 0x20 || k[i] > 0x7e || k[i] == '=' {
				ok = false
			}
		}
		if !ok {
			*problems = append(*problems, fmt.Sprintf("%s: txt key %q: a key is printable US-ASCII without \"=\"", where, k))
		}
		if s := txtString(k, txt[k]); len(s) > 255 {
			*problems = append(*problems, fmt.Sprintf("%s: txt %s: %d octets, at most 255", where, k, len(s)))
		}
	}
}

func checkSubtypes(subtypes []string, where string, problems *[]string) {
	for _, st := range subtypes {
		if err := dnsname.CheckLabel(st); err != nil {
			*problems = append(*problems, fmt.Sprintf("%s: subtype: %v", where, err))
		}
	}
}

// txtString is one TXT string: "key=value", or the key alone for a boolean attribute.
func txtString(k string, v *string) string {
	if v == nil {
		return k
	}
	return k + "=" + *v
}

// Load reads and validates the template at path.
func Load(path string) (*Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// Parse validates data, the template read from path; a relative keystore is relative to
// path's directory, and with none CLIENT_KEYSTORE_DIR is used (keyrec.KeystoreDir).
func Parse(data []byte, path string) (*Plan, error) {
	var doc templateDoc
	if err := decodeStrict(data, &doc); err != nil {
		return nil, &ValidationError{Path: path, Problems: []string{err.Error()}}
	}
	var problems []string
	plan := &Plan{Keystore: parseKeystore(doc.Keystore, filepath.Dir(path), &problems)}

	types := parseTypes(doc.Types, presets, &problems)
	for name, def := range presets {
		types[name] = def
	}

	if len(doc.Registrars) == 0 {
		problems = append(problems, "registrars: at least one, with protocol: srp or rfc9664")
	}
	for i, rd := range doc.Registrars {
		if r, ok := parseRegistrar(rd, types, fmt.Sprintf("registrars[%d]", i), &problems); ok {
			plan.Registrars = append(plan.Registrars, r)
		}
	}
	checkRegistrars(plan.Registrars, &problems)

	if len(problems) > 0 {
		return nil, &ValidationError{Path: path, Problems: problems}
	}
	return plan, nil
}

func parseKeystore(given, dir string, problems *[]string) string {
	if given != "" && !filepath.IsAbs(given) {
		given = filepath.Join(dir, given)
	}
	ks, err := keyrec.KeystoreDir(given, "give keystore:")
	if err != nil {
		*problems = append(*problems, err.Error())
		return ""
	}
	abs, err := filepath.Abs(ks)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("keystore %q: %v", ks, err))
	}
	return abs
}

// parseRegistrar validates d, the registrar at where, with what it registers; ok is false
// for a protocol it does not know, whose fields cannot be told apart.
func parseRegistrar(d registrarDoc, types map[string]typeDef, where string, problems *[]string) (r Registrar, ok bool) {
	r = Registrar{Protocol: Protocol(d.Protocol), Server: d.Server, Resolvers: d.Resolvers}
	misplaced := func(field string, given bool, theirs Protocol) {
		if given {
			*problems = append(*problems, fmt.Sprintf("%s: %s: is an %s registrar's, not an %s one's", where, field, theirs, r.Protocol))
		}
	}
	switch r.Protocol {
	case SRP:
		r.Domain = parseDomain(d.Domain, "domain", where, problems)
	case RFC9664:
		r.Domain = parseDomain(d.Zone, "zone", where, problems)
	default:
		*problems = append(*problems, fmt.Sprintf("%s: protocol %q: want srp or rfc9664", where, d.Protocol))
		return Registrar{}, false
	}
	if r.Domain != "" {
		where += fmt.Sprintf(" (%s %s)", r.Protocol, r.Domain)
	}
	if r.Protocol == SRP {
		misplaced("zone", d.Zone != "", RFC9664)
		misplaced("names", d.Names != nil, RFC9664)
	} else {
		misplaced("domain", d.Domain != "", SRP)
		misplaced("resolvers", d.Resolvers != nil, SRP)
		misplaced("hosts", d.Hosts != nil, SRP)
		misplaced("mirrors", d.Mirrors != nil, SRP)
		if d.Server == "" {
			*problems = append(*problems, where+": server is required: RFC 9664 has no registrar discovery")
		}
	}
	r.Transport = baseclient.NetworkTCP
	if d.Transport != "" {
		var err error
		if r.Transport, err = baseclient.ParseNetwork(d.Transport); err != nil {
			*problems = append(*problems, where+": transport "+err.Error())
		}
	}
	if d.Server != "" {
		checkHostPort(d.Server, where+": server", problems)
	}
	for _, res := range d.Resolvers {
		checkHostPort(res, where+": resolvers", problems)
	}
	r.Lifetime = parseLifetime(d.Lease, d.KeyLease, d.OnStop, defaultLifetime, where, problems)
	if r.Protocol == SRP {
		parseHosts(&r, d.Hosts, types, where, problems)
		for i, md := range d.Mirrors {
			if m, ok := parseMirror(md, r.Hosts, fmt.Sprintf("%s: mirrors[%d]", where, i), problems); ok {
				r.Mirrors = append(r.Mirrors, m)
			}
		}
	} else {
		labels := map[string]bool{}
		for i, nd := range d.Names {
			nwhere := fmt.Sprintf("%s: names[%d]", where, i)
			if nd.Name != "" {
				nwhere += " (" + nd.Name + ")"
			}
			if labels[dnsname.Fold(nd.Name)] {
				*problems = append(*problems, fmt.Sprintf("%s: a second name %s", nwhere, nd.Name))
			}
			labels[dnsname.Fold(nd.Name)] = true
			r.Names = append(r.Names, parseName(nd, r, nwhere, problems))
		}
	}
	return r, true
}

// parseDomain reads an srp registrar's domain or an rfc9664 one's zone, field.
func parseDomain(given, field, where string, problems *[]string) string {
	if given == "" {
		*problems = append(*problems, fmt.Sprintf("%s: %s is required", where, field))
		return ""
	}
	// Every host's and name's name ends in it, so its labels are host name labels too.
	domain := strings.TrimSuffix(given, ".") + "."
	labels := dnsname.Labels(domain)
	labels = labels[:len(labels)-1] // the root's
	if len(labels) == 0 || slices.ContainsFunc(labels, func(l string) bool { return !hostNameRE.MatchString(l) }) {
		*problems = append(*problems, fmt.Sprintf("%s: %s %q: want labels of letters, digits and hyphens, as in a host name", where, field, given))
	}
	return domain
}

// parseHosts validates an srp registrar's hosts into r.
func parseHosts(r *Registrar, docs []hostDoc, types map[string]typeDef, where string, problems *[]string) {
	hostNames := map[string]bool{}
	instances := map[string]string{} // folded instance name -> the host it is on
	for i, hd := range docs {
		hwhere := fmt.Sprintf("%s: hosts[%d]", where, i)
		if hd.Name != "" {
			hwhere += " (" + hd.Name + ")"
		}
		h := Host{Name: hd.Name}
		switch {
		case !hostNameRE.MatchString(hd.Name):
			*problems = append(*problems, fmt.Sprintf("%s: name %q: a host name is letters, digits and hyphens, not starting or ending with a hyphen, at most 63", hwhere, hd.Name))
		case hostNames[dnsname.Fold(hd.Name)]:
			*problems = append(*problems, fmt.Sprintf("%s: a second host named %s", hwhere, hd.Name))
		}
		hostNames[dnsname.Fold(hd.Name)] = true
		if len(hd.Addresses) == 0 {
			*problems = append(*problems, fmt.Sprintf("%s: addresses: at least one, \"auto\" or an IP address (SRP cannot register a host without one)", hwhere))
		}
		h.Auto, h.Addresses = parseAddresses(hd.Addresses, hwhere, problems)
		h.Lifetime = parseLifetime(hd.Lease, hd.KeyLease, hd.OnStop, r.Lifetime, hwhere, problems)
		for j, sd := range hd.Services {
			s, ok := parseService(sd, hd.Name, types, fmt.Sprintf("%s: services[%d]", hwhere, j), problems)
			if !ok {
				continue
			}
			key := dnsname.Fold(s.Instance.Label + "." + s.Instance.ServiceType)
			if on, dup := instances[key]; dup {
				*problems = append(*problems, fmt.Sprintf("%s: services[%d]: instance %q %s is also on host %s: an instance name is one per domain", hwhere, j, s.Instance.Label, s.Instance.ServiceType, on))
				continue
			}
			instances[key] = hd.Name
			h.Services = append(h.Services, s)
		}
		r.Hosts = append(r.Hosts, h)
	}
}

// parseName validates an rfc9664 registrar's name d, registered through r.
func parseName(d nameDoc, r Registrar, where string, problems *[]string) Name {
	n := Name{Name: d.Name}
	if !hostNameRE.MatchString(d.Name) {
		*problems = append(*problems, fmt.Sprintf("%s: name %q: one label of letters, digits and hyphens, not starting or ending with a hyphen, at most 63, right below the zone", where, d.Name))
	}
	n.Auto, n.Addresses = parseAddresses(d.Addresses, where, problems)
	owner := r.Owner(d.Name)
	seen := map[string]bool{}
	for j, spec := range d.Records {
		rr, err := parseRecord(spec, owner)
		if err != nil {
			*problems = append(*problems, fmt.Sprintf("%s: records[%d]: %v", where, j, err))
			continue
		}
		key := leasepkg.RecordKey(rr)
		if seen[key] {
			*problems = append(*problems, fmt.Sprintf("%s: records[%d]: %q twice", where, j, spec))
			continue
		}
		seen[key] = true
		n.Records = append(n.Records, rr)
	}
	if !n.Auto && len(n.Addresses) == 0 && len(d.Records) == 0 {
		*problems = append(*problems, where+": nothing to register: give addresses:, records: or both")
	}
	n.Lifetime = parseLifetime(d.Lease, d.KeyLease, d.OnStop, r.Lifetime, where, problems)
	return n
}

// parseRecord reads spec, "<owner> <type> <data>" with the owner "@" for owner itself, or
// relative to it, as one of owner's records (rfc9664.CheckRecords).
func parseRecord(spec, owner string) (dns.RR, error) {
	spec = strings.TrimSpace(spec)
	rel, rest, _ := strings.Cut(spec, " ")
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return nil, fmt.Errorf("%q: want <owner> <type> <data>, the owner @ for the name or relative to it", spec)
	}
	if strings.HasSuffix(rel, ".") {
		return nil, fmt.Errorf("%q: owner %s: relative to the name (@ for the name itself), not fully qualified", spec, rel)
	}
	fq := owner
	if rel != "@" {
		fq = rel + "." + owner
	}
	rr, err := dns.New(fq + " " + rest)
	if err != nil {
		return nil, fmt.Errorf("%q: %v", spec, err)
	}
	if err := rfc9664.CheckRecords(owner, []dns.RR{rr}); err != nil {
		return nil, fmt.Errorf("%q: %v", spec, err)
	}
	switch rr.(type) {
	case *dns.A, *dns.AAAA:
		if dnsname.EqualFold(fq, owner) {
			return nil, fmt.Errorf("%q: the name's addresses go in addresses:", spec)
		}
	}
	return rr, nil
}

// checkRegistrars reports what registrars cannot all have: two for the same domain or zone,
// an rfc9664 name in an srp domain or above one, and two mirrors of one type.
func checkRegistrars(registrars []Registrar, problems *[]string) {
	mirrors := map[string]bool{}
	for i, r := range registrars {
		where := fmt.Sprintf("registrars[%d] (%s %s)", i, r.Protocol, r.Domain)
		for _, o := range registrars[:i] {
			if r.same(o) {
				*problems = append(*problems, fmt.Sprintf("%s: a second %s", where, r))
			}
		}
		for _, m := range r.Mirrors {
			if mirrors[m.Type] {
				*problems = append(*problems, fmt.Sprintf("%s: a second %s mirror: one daemon, one mirror", where, m.Type))
			}
			mirrors[m.Type] = true
		}
		for _, n := range r.Names {
			name := r.Owner(n.Name)
			for _, o := range registrars {
				if o.Protocol == SRP && o.Domain != "" && (dnsname.IsAtOrBelow(name, o.Domain) || dnsname.IsAtOrBelow(o.Domain, name)) {
					*problems = append(*problems, fmt.Sprintf("%s: name %s: in the srp domain %s, or above it; the proxy serves a name through one handler", where, name, o.Domain))
				}
			}
		}
	}
}

// parseLifetime reads lease, key_lease and on_stop, each def's where left out.
func parseLifetime(lease, keyLease, onStop string, def Lifetime, where string, problems *[]string) Lifetime {
	l := Lifetime{
		Lease:    parseLease(lease, def.Lease, where+": lease", problems),
		KeyLease: parseLease(keyLease, def.KeyLease, where+": key_lease", problems),
	}
	if l.Lease > l.KeyLease && l.KeyLease != 0 {
		*problems = append(*problems, where+": lease is longer than key_lease: the records would outlive the key they belong to")
	}
	switch onStop {
	case "":
		l.KeepNames = def.KeepNames
	case "keep":
		l.KeepNames = true
	case "release":
	default:
		*problems = append(*problems, fmt.Sprintf("%s: on_stop %q: want keep or release", where, onStop))
	}
	return l
}

func checkHostPort(s, where string, problems *[]string) {
	_, port, err := net.SplitHostPort(s)
	if err == nil {
		_, err = strconv.ParseUint(port, 10, 16)
	}
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("%s: %q: want host:port", where, s))
	}
}

// parseLease reads a Go duration ("1h", "336h") in whole seconds; def, in seconds, if s is empty.
func parseLease(s string, def uint32, where string, problems *[]string) uint32 {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		*problems = append(*problems, fmt.Sprintf("%s: %v", where, err))
		return 0
	}
	if d < time.Second || d%time.Second != 0 || d/time.Second > math.MaxUint32 {
		*problems = append(*problems, fmt.Sprintf("%s: %s: want whole seconds, at least 1s", where, d))
		return 0
	}
	return uint32(d / time.Second)
}

func parseAddresses(addrs []string, where string, problems *[]string) (auto bool, out []netip.Addr) {
	for _, a := range addrs {
		if a == "auto" {
			if auto {
				*problems = append(*problems, fmt.Sprintf("%s: addresses: auto twice", where))
			}
			auto = true
			continue
		}
		ip, err := netip.ParseAddr(a)
		switch {
		case err != nil:
			*problems = append(*problems, fmt.Sprintf("%s: addresses: %q is neither auto nor an IP address", where, a))
		case ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast():
			*problems = append(*problems, fmt.Sprintf("%s: addresses: %s cannot be published as a host's address", where, a))
		case slices.Contains(out, ip):
			*problems = append(*problems, fmt.Sprintf("%s: addresses: %s twice", where, a))
		default:
			out = append(out, ip)
		}
	}
	return auto, out
}

func parseService(d serviceDoc, hostName string, types map[string]typeDef, where string, problems *[]string) (Service, bool) {
	if d.Type == "" {
		*problems = append(*problems, fmt.Sprintf("%s: type is required", where))
		return Service{}, false
	}
	if complexTypes[d.Type] != "" {
		*problems = append(*problems, fmt.Sprintf("%s: %s is a complex type that makes its own hosts; use it under an srp registrar's mirrors:", where, d.Type))
		return Service{}, false
	}
	def, ok := types[d.Type]
	if !ok {
		*problems = append(*problems, fmt.Sprintf("%s: unknown type %q (known: %s)", where, d.Type, strings.Join(sortedKeys(types), ", ")))
		return Service{}, false
	}
	n := len(*problems)
	port := def.port
	if d.Port != nil {
		port = checkPort(*d.Port, where, problems)
	} else if port == 0 {
		*problems = append(*problems, fmt.Sprintf("%s: type %s has no port, so the service needs one", where, d.Type))
	}
	txt := map[string]*string{}
	for k, v := range def.txt {
		txt[k] = v
	}
	for k, v := range d.TXT {
		txt[k] = v
	}
	checkTXT(d.TXT, where, problems)
	subtypes := def.subtypes
	if d.Subtypes != nil {
		subtypes = d.Subtypes
		checkSubtypes(subtypes, where, problems)
	}
	probe := def.probe
	d.Probe.check(where, problems)
	if d.Probe != nil {
		probe = d.Probe.probe
	}
	label := d.Instance
	if label == "" {
		label = hostName + " " + d.Type
	}
	if err := dnsname.CheckLabel(label); err != nil {
		*problems = append(*problems, fmt.Sprintf("%s: instance %q: %v", where, label, err))
	}
	if len(*problems) > n {
		return Service{}, false
	}
	strs := make([]string, 0, len(txt))
	for _, k := range sortedKeys(txt) {
		strs = append(strs, clientsrp.EscapeTXT(txtString(k, txt[k])))
	}
	return Service{
		Type: d.Type,
		Instance: clientsrp.InstanceConfig{
			Label:       label,
			ServiceType: def.service,
			Subtypes:    slices.Clone(subtypes),
			Port:        uint16(port),
			TXT:         strs,
		},
		Probe: probe,
	}, true
}

func parseMirror(d mirrorDoc, hosts []Host, where string, problems *[]string) (Mirror, bool) {
	if d.Type == "" {
		*problems = append(*problems, fmt.Sprintf("%s: type is required", where))
		return Mirror{}, false
	}
	if complexTypes[d.Type] == "" {
		*problems = append(*problems, fmt.Sprintf("%s: %q is not a complex type that makes hosts (known: %s); a service type goes in a host's services:", where, d.Type, strings.Join(sortedKeys(complexTypes), ", ")))
		return Mirror{}, false
	}
	m := Mirror{Type: d.Type, Socket: d.Socket, Hosts: d.Hosts, AllHosts: d.AllHosts, ServiceTypes: d.Services}
	if m.Socket == "" {
		m.Socket = mdnsresponder.DefaultSocketPath()
	}
	n := len(*problems)
	if d.AllHosts == (len(d.Hosts) > 0) {
		*problems = append(*problems, fmt.Sprintf("%s: give hosts: or all_hosts: true, not both or neither", where))
	}
	for _, mh := range d.Hosts {
		label := strings.TrimSuffix(strings.TrimSuffix(mh, "."), ".local")
		switch {
		case !hostNameRE.MatchString(label):
			*problems = append(*problems, fmt.Sprintf("%s: hosts: %q: want an mDNS host name, such as mymac.local.", where, mh))
		case slices.ContainsFunc(hosts, func(h Host) bool { return dnsname.EqualFold(h.Name, label) }):
			*problems = append(*problems, fmt.Sprintf("%s: hosts: %s would be registered as %s, which hosts: already registers", where, mh, label))
		}
	}
	for _, t := range d.Services {
		if err := dnssd.ValidateServiceType(t); err != nil {
			*problems = append(*problems, fmt.Sprintf("%s: services: %v", where, err))
		}
	}
	return m, len(*problems) == n
}

// Types lists the types a template can use: the presets and the complex types, by name.
func Types() []TypeInfo {
	var out []TypeInfo
	for _, name := range sortedKeys(presets) {
		def := presets[name]
		parts := []string{"service: " + def.service, fmt.Sprintf("port: %d", def.port)}
		if len(def.txt) > 0 {
			var strs []string
			for _, k := range sortedKeys(def.txt) {
				strs = append(strs, txtString(k, def.txt[k]))
			}
			parts = append(parts, "txt: "+strings.Join(strs, " "))
		}
		if len(def.subtypes) > 0 {
			parts = append(parts, "subtypes: "+strings.Join(def.subtypes, " "))
		}
		parts = append(parts, "probe: "+def.probe.String())
		out = append(out, TypeInfo{Name: name, Summary: strings.Join(parts, ", ")})
	}
	for _, name := range sortedKeys(complexTypes) {
		out = append(out, TypeInfo{Name: name, Complex: true, Summary: complexTypes[name]})
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
