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
// An rfc9664 one holds names, each given in full, with its own key, its addresses, its records and its
// services, which SRV records find at the name (RFC 2782), with a TLSA record for a TLS one
// (DANE) (client/rfc9664); "ipfs", a name's ipfs:, publishes an IPFS node at the name: its
// addresses, and a folder of its files or one holding the folders of a community's members
// (client/kubo); a host's service's ipfs: gives a folder of its node's files in its TXT record.
// See docs/sig0lease-agent.md.
package agent

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/kubo"
	"github.com/NetworkCommons/sig0lease/client/mdnsresponder"
	"github.com/NetworkCommons/sig0lease/client/rfc9664"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/dnssd"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	"gopkg.in/yaml.v3"
)

//go:embed presets.yaml
var presetsYAML []byte

// defaultLifetime is a registrar's when the template leaves its lease, key_lease or on_stop
// out: an hour, RFC 9665 S3.4's "typically 14 days" for the key, and the names kept.
var defaultLifetime = Lifetime{Lease: 3600, KeyLease: 14 * 24 * 3600, KeepNames: true}

// complexType is a type implemented in code: what it does, and where a template uses it.
type complexType struct {
	does   string
	where  string
	mirror bool // under an srp registrar's mirrors:
}

// complexTypes are the types implemented in code, by name.
var complexTypes = map[string]complexType{
	"mdns": {
		does:   "mirrors the services a running mDNSResponder sees, one SRP host per mDNS host",
		where:  "under an srp registrar's mirrors:",
		mirror: true,
	},
	"ipfs": {
		does:  "publishes a kubo node's addresses at the name (_dnsaddr), and as the name's site (_dnslink) a folder of its files, or one with an entry for each member of a community, the folder its TXT record gives once the node has pinned it; on a host's service, the TXT record gives a folder of the node's files (dnslink=)",
		where: "as an rfc9664 registrar's name's ipfs:, or an srp host's service's",
	},
}

// Plan is a valid template: everything the agent registers.
type Plan struct {
	Keystore   string      // absolute: one key per host and name, and the agent's state file
	Registrars []Registrar // in the template's order
	Warnings   []string    // what the template gives that does nothing in it (unused)
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
	Domain    string             // SRP only: the domain, fully qualified
	Server    string             // "host:port", a URL with NetworkDoH; SRP only: "" to discover the registrar
	Transport baseclient.Network //
	// Resolvers are asked, as "host:port" over UDP, by SRP for discovery and KEY lookups, and by
	// RFC 9664's names for a followed site the registrar refuses as not its own. nil: client/srp's
	// default ones.
	Resolvers []string
	Lifetime           // every host's or name's, unless it gives its own; the mirrors' hosts'
	Hosts     []Host   // SRP
	Mirrors   []Mirror // SRP
	Names     []Name   // RFC 9664
}

// Owner returns the name a host labelled label registers through r, an SRP registrar, fully
// qualified. An RFC 9664 name is given in full (Name.Name).
func (r Registrar) Owner(label string) string { return label + "." + r.Domain }

// connection is r without what it registers: what its hosts, names and mirrors register
// through, and their default lifetime.
func (r Registrar) connection() Registrar {
	r.Hosts, r.Mirrors, r.Names = nil, nil, nil
	return r
}

// same reports whether r and o are the template's same registrar: the same protocol and, for
// SRP, the same domain, for RFC 9664 the same proxy. An RFC 9664 registrar names no zone: which
// names a key may register is the proxy's to say, and a requester cannot look its zone up.
func (r Registrar) same(o Registrar) bool {
	return r.Protocol == o.Protocol && dnsname.EqualFold(r.Domain, o.Domain) && (r.Protocol == SRP || r.Server == o.Server)
}

// place is what tells r apart in the template: an SRP registrar's domain, an RFC 9664 one's proxy.
func (r Registrar) place() string {
	if r.Protocol == RFC9664 {
		return r.Server
	}
	return r.Domain
}

func (r Registrar) String() string {
	if r.Protocol == RFC9664 {
		return fmt.Sprintf("%s registrar at %s", r.Protocol, r.Server)
	}
	return fmt.Sprintf("%s registrar for %s", r.Protocol, r.Domain)
}

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

// Service is one instance of a service type. On a host it is a DNS-SD instance. On a name it
// is the SRV records that find the service at the name and at its Subdomains, each pointing at
// the name and the service's port (RFC 2782), and with TLSA the record that lets a client check
// the service's certificate through DNSSEC (DANE, RFC 6698).
type Service struct {
	Type     string                   // the type's name: a preset or one the template defines
	Instance clientsrp.InstanceConfig // a name's: its ServiceType and Port alone
	Probe    Probe
	// A host's only: the node whose folder (IPFS.Publish) its TXT record gives, as
	// "dnslink=/ipfs/<CID>", which a community's node follows (IPFS.Follow); nil: none. The
	// instance is registered once the folder is read.
	IPFS *IPFS
	// A name's only. Subdomains are names below the name, relative to it, that the service is
	// also offered for; TLSA is the certificate file, absolute, whose key a TLSA record at
	// "_<port>._<proto>.<name>" gives (TLSARecord), or "".
	Subdomains []string
	TLSA       string
}

func (s Service) String() string {
	if s.Instance.Label == "" {
		return s.Instance.ServiceType
	}
	return fmt.Sprintf("%q %s", s.Instance.Label, s.Instance.ServiceType)
}

// SRV returns the SRV records that find s, a service of name (fully qualified), at name and
// at each of its subdomains: pointing at name and s's port, priority and weight 0 (RFC 2782:
// there is one target).
func (s Service) SRV(name string) []dns.RR {
	owners := []string{name}
	for _, sub := range s.Subdomains {
		owners = append(owners, sub+"."+name)
	}
	out := make([]dns.RR, len(owners))
	for i, o := range owners {
		out[i] = &dns.SRV{
			Hdr: dns.Header{Name: s.Instance.ServiceType + "." + o, Class: dns.ClassINET},
			SRV: rdata.SRV{Port: s.Instance.Port, Target: name},
		}
	}
	return out
}

// TLSAOwner returns where s's TLSA record is, s being a service of name with a TLSA: the SRV
// records' target and port, "_<port>._<proto>.<name>" (RFC 6698 S3, RFC 7673 S3).
func (s Service) TLSAOwner(name string) string {
	_, proto, _ := strings.Cut(s.Instance.ServiceType, ".")
	return fmt.Sprintf("_%d.%s.%s", s.Instance.Port, proto, name)
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

// Name is one RFC 9664 name, held by its own key, with its addresses, records and services.
type Name struct {
	Name      string       // the name, fully qualified
	Auto      bool         // this machine's addresses too, as they change
	Addresses []netip.Addr // literal addresses
	Records   []dns.RR     // at or below the name, fully qualified; no address of the name
	Services  []Service    // none registers what Records, another service or IPFS registers
	IPFS      *IPFS        // nil: none
	Lifetime               // the registrar's, with what the name overrides
}

// IPFS is the kubo node a name publishes (client/kubo): its addresses, as the name's _dnsaddr
// TXT records, which a node given /dnsaddr/<name> connects to, and a site, as its _dnslink TXT
// record (DNSLink), which IPFS gateways and nodes open by the name: a path in the node's files
// (Publish), or a folder with the folders of a community's members, each once the node holds
// all of it (Follow). With neither, the name publishes the node's addresses alone. A host's
// service publishes a path in the node's files alone, in its TXT record (Service.IPFS).
//
// A community and its members share a swarm key (SwarmKey): a member's TXT record gives, with
// its folder, the swarm-mac= that key makes of its KEY and its folder (swarmKey.mac), and the
// community counts as members only the instances whose swarm-mac= it makes too.
type IPFS struct {
	API      string  // the node's RPC API, "http://host:port"
	Publish  string  // a path in the node's files (MFS), such as /community
	Follow   *Follow // nil: none
	SwarmKey string  // the swarm key file, absolute: a community's and a member's; "" a name's site
}

// Follow is the community whose members' folders a name's node keeps: the instances of a
// service type in an SRP domain listed under a subtype of it (RFC 6763 S7.1), each a member's
// node giving its folder in its TXT record (Service.IPFS). Each member is its Instance label,
// held by the member's key (RFC 9665's First-Come First-Served naming): the node pins each
// folder a member gives, and the name's site is a folder with an entry per member, by its
// label, giving the member's folder last pinned. A member gone from the listing for
// RevokeAfter, or whose label another key holds, has its entry removed and its folder unpinned.
type Follow struct {
	ServiceType string        // such as _ipfs-member._tcp
	Subtype     string        // a label: the name's first one unless the template gives it
	Domain      string        // the SRP domain, fully qualified
	RevokeAfter time.Duration // more than 0
}

// Members returns the name whose PTR records list the members' instances:
// "<subtype>._sub.<service type>.<domain>".
func (f Follow) Members() string {
	return f.Subtype + "._sub." + dnssd.BrowsingOwnerName(f.ServiceType, f.Domain)
}

// dnsaddrOwner and dnslinkOwner return where a name publishes its node's addresses and its
// site, name being fully qualified.
func dnsaddrOwner(name string) string { return "_dnsaddr." + name }
func dnslinkOwner(name string) string { return "_dnslink." + name }

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

// registrarDoc is either protocol's: domain, hosts and mirrors are srp's, names rfc9664's.
type registrarDoc struct {
	Protocol  string      `yaml:"protocol"`
	Domain    string      `yaml:"domain"`
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

// serviceDoc is a host's or a name's service: instance, txt and subtypes are a host's,
// subdomains and tlsa a name's.
type serviceDoc struct {
	Type       string             `yaml:"type"`
	Instance   string             `yaml:"instance"`
	Port       *int               `yaml:"port"`
	TXT        map[string]*string `yaml:"txt"`
	Subtypes   []string           `yaml:"subtypes"`
	Probe      *probeDoc          `yaml:"probe"`
	IPFS       *ipfsDoc           `yaml:"ipfs"`
	Subdomains []string           `yaml:"subdomains"`
	TLSA       string             `yaml:"tlsa"`
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
	Name      string       `yaml:"name"`
	Addresses []string     `yaml:"addresses"`
	Records   []string     `yaml:"records"`
	Services  []serviceDoc `yaml:"services"`
	IPFS      *ipfsDoc     `yaml:"ipfs"`
	Lease     string       `yaml:"lease"`
	KeyLease  string       `yaml:"key_lease"`
	OnStop    string       `yaml:"on_stop"`
}

type ipfsDoc struct {
	API      string `yaml:"api"`
	SwarmKey string `yaml:"swarm_key"`
	Publish  *struct {
		MFS string `yaml:"mfs"`
	} `yaml:"publish"`
	Follow *struct {
		Type        string `yaml:"type"`
		Subtype     string `yaml:"subtype"`
		Domain      string `yaml:"domain"`
		RevokeAfter string `yaml:"revoke_after"`
	} `yaml:"follow"`
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
		case complexTypes[name].does != "":
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

// Parse validates data, the template read from path; a relative keystore or tlsa is relative
// to path's directory, and with no keystore CLIENT_KEYSTORE_DIR is used (keyrec.KeystoreDir).
func Parse(data []byte, path string) (*Plan, error) {
	var doc templateDoc
	if err := decodeStrict(data, &doc); err != nil {
		return nil, &ValidationError{Path: path, Problems: []string{err.Error()}}
	}
	var problems []string
	dir := filepath.Dir(path)
	plan := &Plan{Keystore: parseKeystore(doc.Keystore, dir, &problems)}

	types := parseTypes(doc.Types, presets, &problems)
	for name, def := range presets {
		types[name] = def
	}

	if len(doc.Registrars) == 0 {
		problems = append(problems, "registrars: at least one, with protocol: srp or rfc9664")
	}
	for i, rd := range doc.Registrars {
		if r, ok := parseRegistrar(rd, types, dir, fmt.Sprintf("registrars[%d]", i), &problems); ok {
			plan.Registrars = append(plan.Registrars, r)
		}
	}
	checkRegistrars(plan.Registrars, &problems)

	if len(problems) > 0 {
		return nil, &ValidationError{Path: path, Problems: problems}
	}
	plan.Warnings = unused(plan.Registrars)
	return plan, nil
}

// unused returns a warning for each field the registrars give that does nothing in this
// template: the resolvers of an rfc9664 registrar none of whose names follows a community.
// Such a field is no problem: removing the last name that uses it would otherwise make the
// template invalid until the field went too.
func unused(registrars []Registrar) []string {
	var warnings []string
	for i, r := range registrars {
		follows := slices.ContainsFunc(r.Names, func(n Name) bool { return n.IPFS != nil && n.IPFS.Follow != nil })
		if r.Protocol == RFC9664 && len(r.Resolvers) > 0 && !follows {
			warnings = append(warnings, fmt.Sprintf("registrars[%d] (%s %s): resolvers: unused: none of its names follows a community (ipfs: {follow:})", i, r.Protocol, r.place()))
		}
	}
	return warnings
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

// parseRegistrar validates d, the registrar at where, with what it registers, in the template
// in dir; ok is false for a protocol it does not know, whose fields cannot be told apart.
func parseRegistrar(d registrarDoc, types map[string]typeDef, dir, where string, problems *[]string) (r Registrar, ok bool) {
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
	default:
		*problems = append(*problems, fmt.Sprintf("%s: protocol %q: want srp or rfc9664", where, d.Protocol))
		return Registrar{}, false
	}
	if r.place() != "" {
		where += fmt.Sprintf(" (%s %s)", r.Protocol, r.place())
	}
	if r.Protocol == SRP {
		misplaced("names", d.Names != nil, RFC9664)
	} else {
		misplaced("domain", d.Domain != "", SRP)
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
	switch {
	case d.Server != "":
		if err := r.Transport.CheckServer(d.Server); err != nil {
			*problems = append(*problems, where+": server: "+err.Error())
		}
	case d.Server == "" && r.Protocol == SRP && r.Transport == baseclient.NetworkDoH:
		*problems = append(*problems, where+": server is required with transport doh: no registrar is discovered over DoH")
	}
	for _, res := range d.Resolvers {
		if err := baseclient.CheckHostPort(res); err != nil {
			*problems = append(*problems, where+": resolvers: "+err.Error())
		}
	}
	r.Lifetime = parseLifetime(d.Lease, d.KeyLease, d.OnStop, defaultLifetime, where, problems)
	if r.Protocol == SRP {
		parseHosts(&r, d.Hosts, types, dir, where, problems)
		for i, md := range d.Mirrors {
			if m, ok := parseMirror(md, r.Hosts, fmt.Sprintf("%s: mirrors[%d]", where, i), problems); ok {
				r.Mirrors = append(r.Mirrors, m)
			}
		}
	} else {
		for i, nd := range d.Names {
			nwhere := fmt.Sprintf("%s: names[%d]", where, i)
			if nd.Name != "" {
				nwhere += " (" + nd.Name + ")"
			}
			r.Names = append(r.Names, parseName(nd, r, types, dir, nwhere, problems))
		}
	}
	return r, true
}

// parseDomain reads an srp registrar's domain, field.
func parseDomain(given, field, where string, problems *[]string) string {
	if given == "" {
		*problems = append(*problems, fmt.Sprintf("%s: %s is required", where, field))
		return ""
	}
	// Every host's name ends in it, so its labels are host name labels too.
	domain := strings.TrimSuffix(given, ".") + "."
	if !hostLabels(domain) {
		*problems = append(*problems, fmt.Sprintf("%s: %s %q: want labels of letters, digits and hyphens, as in a host name", where, field, given))
	}
	return domain
}

// hostLabels reports whether every label of name, fully qualified, is a host name label
// (dnsname.IsHostLabel), and it has one at least.
func hostLabels(name string) bool {
	labels := dnsname.Labels(name)
	labels = labels[:len(labels)-1] // the root's
	return len(labels) > 0 && !slices.ContainsFunc(labels, func(l string) bool { return !dnsname.IsHostLabel(l) })
}

// parseHosts validates an srp registrar's hosts into r; dir is the template's directory.
func parseHosts(r *Registrar, docs []hostDoc, types map[string]typeDef, dir, where string, problems *[]string) {
	hostNames := map[string]bool{}
	instances := map[string]string{} // folded instance name -> the host it is on
	for i, hd := range docs {
		hwhere := fmt.Sprintf("%s: hosts[%d]", where, i)
		if hd.Name != "" {
			hwhere += " (" + hd.Name + ")"
		}
		h := Host{Name: hd.Name}
		switch {
		case !dnsname.IsHostLabel(hd.Name):
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
			s, ok := parseService(sd, hd.Name, false, dir, types, fmt.Sprintf("%s: services[%d]", hwhere, j), problems)
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

// parseName validates an rfc9664 registrar's name d, registered through r, in the template in
// dir.
func parseName(d nameDoc, r Registrar, types map[string]typeDef, dir, where string, problems *[]string) Name {
	n := Name{Name: dnsutil.Fqdn(d.Name)}
	owner := n.Name
	if err := rfc9664.CheckName(d.Name); err != nil {
		*problems = append(*problems, fmt.Sprintf("%s: %v", where, err))
	} else if !hostLabels(owner) {
		*problems = append(*problems, fmt.Sprintf("%s: name %q: want labels of letters, digits and hyphens, not starting or ending with a hyphen, at most 63 each, as in a host name", where, d.Name))
	}
	n.Auto, n.Addresses = parseAddresses(d.Addresses, where, problems)
	n.Records = rfc9664.ParseRecords(owner, d.Records, func(j int, err error) {
		*problems = append(*problems, fmt.Sprintf("%s: records[%d]: %v", where, j, err))
	})
	if !n.Auto && len(n.Addresses) == 0 && len(d.Records) == 0 && d.IPFS == nil {
		*problems = append(*problems, where+": nothing to register: give addresses:, records:, ipfs: or several")
	}
	if len(d.Services) > 0 && !n.Auto && len(n.Addresses) == 0 {
		*problems = append(*problems, where+": services: their SRV records point at the name, which needs addresses:")
	}

	// Each record has one source: a record, or one service.
	by := map[string]string{} // owner and type, folded -> what registers them
	slot := func(name string, t uint16) string { return dnsname.Fold(name) + " " + dns.TypeToString[t] }
	for j, rr := range n.Records {
		by[slot(rr.Header().Name, dns.RRToType(rr))] = fmt.Sprintf("records[%d]", j)
	}
	if d.IPFS != nil {
		n.IPFS = parseIPFS(*d.IPFS, owner, types, dir, where+": ipfs", problems)
		if n.IPFS.Follow == nil && n.IPFS.SwarmKey != "" {
			*problems = append(*problems, where+": ipfs: swarm_key: a community's (follow:) or a member's (a host's service's ipfs:); a name's site is no member")
		}
		owners := []string{dnsaddrOwner(owner)}
		if n.IPFS.Publish != "" || n.IPFS.Follow != nil {
			owners = append(owners, dnslinkOwner(owner))
		}
		for _, o := range owners {
			if other, dup := by[slot(o, dns.TypeTXT)]; dup {
				*problems = append(*problems, fmt.Sprintf("%s: ipfs: registers the TXT records at %s, which %s registers too", where, o, other))
			}
			by[slot(o, dns.TypeTXT)] = "ipfs"
		}
	}
	for j, sd := range d.Services {
		swhere := fmt.Sprintf("%s: services[%d]", where, j)
		s, ok := parseService(sd, d.Name, true, dir, types, swhere, problems)
		if !ok {
			continue
		}
		slots := map[string]uint16{}
		for _, rr := range s.SRV(owner) {
			slots[rr.Header().Name] = dns.TypeSRV
		}
		if s.TLSA != "" {
			slots[s.TLSAOwner(owner)] = dns.TypeTLSA
		}
		for _, name := range sortedKeys(slots) {
			if other, dup := by[slot(name, slots[name])]; dup {
				*problems = append(*problems, fmt.Sprintf("%s: registers the %s records at %s, which %s registers too", swhere, dns.TypeToString[slots[name]], name, other))
				ok = false
			}
		}
		if !ok {
			continue
		}
		for name, t := range slots {
			by[slot(name, t)] = fmt.Sprintf("services[%d]", j)
		}
		n.Services = append(n.Services, s)
	}
	n.Lifetime = parseLifetime(d.Lease, d.KeyLease, d.OnStop, r.Lifetime, where, problems)
	return n
}

// parseIPFS validates d, the ipfs: of the name owner, at where; types are the template's, the
// one a community's members are instances of among them, and a relative swarm_key is relative
// to dir. A community (follow:) needs swarm_key; what else does is the caller's to check.
func parseIPFS(d ipfsDoc, owner string, types map[string]typeDef, dir, where string, problems *[]string) *IPFS {
	ip := &IPFS{API: d.API, SwarmKey: d.SwarmKey}
	if ip.SwarmKey != "" && !filepath.IsAbs(ip.SwarmKey) {
		ip.SwarmKey = filepath.Join(dir, ip.SwarmKey)
	}
	if ip.API == "" {
		ip.API = kubo.DefaultAPI
	}
	if err := kubo.CheckAPI(ip.API); err != nil {
		*problems = append(*problems, fmt.Sprintf("%s: api: %v", where, err))
	}
	if d.Publish != nil {
		ip.Publish = d.Publish.MFS
		if !strings.HasPrefix(ip.Publish, "/") {
			*problems = append(*problems, fmt.Sprintf("%s: publish: mfs: %q: want a path in the node's files, such as /community", where, ip.Publish))
		}
	}
	if fd := d.Follow; fd != nil {
		where := where + ": follow"
		f := &Follow{Subtype: fd.Subtype}
		if def, ok := types[fd.Type]; ok {
			f.ServiceType = def.service
		} else {
			*problems = append(*problems, fmt.Sprintf("%s: type %q: want the type the members' services are, a preset or one the template defines, such as ipfs-member", where, fd.Type))
		}
		if f.Subtype == "" {
			f.Subtype, _, _ = dnsname.CutFirstLabel(owner)
		} else if !dnsname.IsHostLabel(f.Subtype) {
			*problems = append(*problems, fmt.Sprintf("%s: subtype %q: want a label of letters, digits and hyphens", where, fd.Subtype))
		}
		f.Domain = parseDomain(fd.Domain, "domain", where, problems)
		if fd.RevokeAfter == "" {
			*problems = append(*problems, where+": revoke_after is required: how long a member may be gone before its entry is removed, such as 10m")
		} else if f.RevokeAfter, _ = time.ParseDuration(fd.RevokeAfter); f.RevokeAfter <= 0 {
			*problems = append(*problems, fmt.Sprintf("%s: revoke_after %q: want a duration, such as 10m", where, fd.RevokeAfter))
		}
		ip.Follow = f
	}
	if d.Publish != nil && d.Follow != nil {
		*problems = append(*problems, where+": publish: and follow: are two sites for one name; give one")
	}
	if d.Follow != nil && d.SwarmKey == "" {
		*problems = append(*problems, where+": swarm_key is required with follow: the swarm key file its node and the members' share, such as the swarm.key in its node's repository, which the members' swarm-mac= are checked with")
	}
	return ip
}

// checkRegistrars reports what registrars cannot all have: two for the same domain or proxy,
// an rfc9664 name given twice, or in an srp domain or above one, and two mirrors of one type.
func checkRegistrars(registrars []Registrar, problems *[]string) {
	mirrors := map[string]bool{}
	names := map[string]bool{}
	for i, r := range registrars {
		where := fmt.Sprintf("registrars[%d] (%s %s)", i, r.Protocol, r.place())
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
			name := n.Name
			if names[dnsname.Fold(name)] {
				*problems = append(*problems, fmt.Sprintf("%s: a second name %s", where, name))
			}
			names[dnsname.Fold(name)] = true
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

// parseService validates d, a service of the host or name labelled label (onName): a DNS-SD
// instance on a host, the SRV records that find it on a name (Service). A relative tlsa or
// swarm_key is relative to dir, the template's directory.
func parseService(d serviceDoc, label string, onName bool, dir string, types map[string]typeDef, where string, problems *[]string) (Service, bool) {
	if d.Type == "" {
		*problems = append(*problems, fmt.Sprintf("%s: type is required", where))
		return Service{}, false
	}
	if ct := complexTypes[d.Type]; ct.does != "" {
		*problems = append(*problems, fmt.Sprintf("%s: %s is a complex type, not a service's; use it %s", where, d.Type, ct.where))
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
	probe := def.probe
	d.Probe.check(where, problems)
	if d.Probe != nil {
		probe = d.Probe.probe
	}
	// The fields of the other kind of service.
	type field struct {
		name  string
		given bool
	}
	theirs := []field{{"subdomains", d.Subdomains != nil}, {"tlsa", d.TLSA != ""}}
	why := "a name's service has it, not a host's: SRP registers a host's services in the domain's service types"
	if onName {
		theirs = []field{{"instance", d.Instance != ""}, {"txt", d.TXT != nil}, {"subtypes", d.Subtypes != nil}, {"ipfs", d.IPFS != nil}}
		why = "a host's service has it, not a name's, which SRV records alone find"
	}
	for _, f := range theirs {
		if f.given {
			*problems = append(*problems, fmt.Sprintf("%s: %s: %s", where, f.name, why))
		}
	}
	if onName {
		return parseNameService(d, def, uint16(port), probe, dir, where, problems, n)
	}
	txt := map[string]*string{}
	for k, v := range def.txt {
		txt[k] = v
	}
	for k, v := range d.TXT {
		txt[k] = v
	}
	checkTXT(d.TXT, where, problems)
	var ip *IPFS
	if d.IPFS != nil {
		ip = parseIPFS(*d.IPFS, label, types, dir, where+": ipfs", problems)
		switch {
		case ip.Follow != nil:
			*problems = append(*problems, where+": ipfs: follow: is a name's; a host's service gives a folder of its node's files, with publish:")
		case ip.Publish == "":
			*problems = append(*problems, where+": ipfs: publish: is required: the folder of its node's files that its TXT record gives")
		}
		if ip.SwarmKey == "" {
			*problems = append(*problems, where+": ipfs: swarm_key is required: the swarm key file of the community's private swarm, such as the swarm.key in its node's repository, whose swarm-mac= its TXT record gives")
		}
		for _, k := range sortedKeys(txt) {
			if strings.EqualFold(k, "dnslink") || strings.EqualFold(k, swarmMACKey) {
				*problems = append(*problems, fmt.Sprintf("%s: txt %s: ipfs: gives the TXT record's %s", where, k, strings.ToLower(k)))
			}
		}
	}
	subtypes := def.subtypes
	if d.Subtypes != nil {
		subtypes = d.Subtypes
		checkSubtypes(subtypes, where, problems)
	}
	instance := d.Instance
	if instance == "" {
		instance = label + " " + d.Type
	}
	if err := dnsname.CheckLabel(instance); err != nil {
		*problems = append(*problems, fmt.Sprintf("%s: instance %q: %v", where, instance, err))
	}
	if len(*problems) > n {
		return Service{}, false
	}
	strs := make([]string, 0, len(txt))
	for _, k := range sortedKeys(txt) {
		strs = append(strs, dnsmsg.EscapeTXT(txtString(k, txt[k])))
	}
	return Service{
		Type: d.Type,
		Instance: clientsrp.InstanceConfig{
			Label:       instance,
			ServiceType: def.service,
			Subtypes:    slices.Clone(subtypes),
			Port:        uint16(port),
			TXT:         strs,
		},
		Probe: probe,
		IPFS:  ip,
	}, true
}

// parseNameService finishes parseService for a name's service d, of type def, on port with
// probe; n is the count of problems before parseService began. A name's service is SRV records
// alone: it has no TXT or subtypes, nor may its type.
func parseNameService(d serviceDoc, def typeDef, port uint16, probe Probe, dir, where string, problems *[]string, n int) (Service, bool) {
	if len(def.txt) > 0 || len(def.subtypes) > 0 {
		*problems = append(*problems, fmt.Sprintf("%s: type %s has TXT keys or subtypes, which a name's service cannot carry: SRV records alone find it", where, d.Type))
	}
	seen := map[string]bool{}
	for _, sub := range d.Subdomains {
		labels := strings.Split(sub, ".")
		switch {
		case slices.ContainsFunc(labels, func(l string) bool { return !dnsname.IsHostLabel(l) }):
			*problems = append(*problems, fmt.Sprintf("%s: subdomains: %q: want a name relative to the name, of labels of letters, digits and hyphens, such as rooms", where, sub))
		case seen[dnsname.Fold(sub)]:
			*problems = append(*problems, fmt.Sprintf("%s: subdomains: %s twice", where, sub))
		}
		seen[dnsname.Fold(sub)] = true
	}
	tlsa := d.TLSA
	if tlsa != "" && !filepath.IsAbs(tlsa) {
		tlsa = filepath.Join(dir, tlsa)
	}
	if len(*problems) > n {
		return Service{}, false
	}
	return Service{
		Type:       d.Type,
		Instance:   clientsrp.InstanceConfig{ServiceType: def.service, Port: port},
		Probe:      probe,
		Subdomains: slices.Clone(d.Subdomains),
		TLSA:       tlsa,
	}, true
}

func parseMirror(d mirrorDoc, hosts []Host, where string, problems *[]string) (Mirror, bool) {
	if d.Type == "" {
		*problems = append(*problems, fmt.Sprintf("%s: type is required", where))
		return Mirror{}, false
	}
	if !complexTypes[d.Type].mirror {
		var mirrors []string
		for _, name := range sortedKeys(complexTypes) {
			if complexTypes[name].mirror {
				mirrors = append(mirrors, name)
			}
		}
		*problems = append(*problems, fmt.Sprintf("%s: %q is not a complex type that makes hosts (known: %s); a service type goes in a host's services:", where, d.Type, strings.Join(mirrors, ", ")))
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
		case !dnsname.IsHostLabel(label):
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
		ct := complexTypes[name]
		out = append(out, TypeInfo{Name: name, Complex: true, Summary: ct.does + "; " + ct.where})
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
