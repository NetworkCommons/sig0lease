package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"

	"codeberg.org/miekg/dns"
	baseclient "github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/mdnsbridge"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/sealedfile"
)

// StateFile is the agent's state, in the keystore: every host it registered, mirrored ones
// included, by requested host name, while its names may be held for its key, and under which
// labels if a rename changed any, and every name, while it may be held or has records
// registered. With it the agent frees the names of hosts and names the template no longer
// registers, even after a restart (agent.release), a host restarted frees the names a rename
// held before asking for its own again (clientsrp.StartHost), and a name's records the
// template no longer has are withdrawn.
const StateFile = "sig0lease-agent-state.json"

// sourceHosts is the source (savedHost.Source) of the template's own SRP hosts, and
// sourceNames of its RFC 9664 names; a mirror's hosts have the mirror's type.
const (
	sourceHosts = "hosts"
	sourceNames = "names"
)

// hostStore keeps StateFile. Every host shares it, through a hostView.
type hostStore struct {
	keystore string
	path     string
	mu       sync.Mutex
	hosts    map[string]savedHost
}

// The state file's JSON: hosts holds the names' entries too.
type stateDoc struct {
	Hosts map[string]savedHost `json:"hosts"`
}

// savedHost is one host's or name's entry, kept while its names are held or it has records
// registered.
type savedHost struct {
	// Source is what registers it: sourceHosts or sourceNames, or the type of the mirror that
	// does. sourceNames is an RFC 9664 name, the others SRP hosts.
	Source string `json:"source"`
	// Registrar is where it was last registered: what freeing its names needs.
	Registrar savedRegistrar `json:"registrar"`
	// Held: a registration succeeded, and no deregistration has freed the names since.
	Held bool `json:"held"`
	// Labels are the labels a held host's names are held under, if a rename changed any.
	Labels *savedLabels `json:"labels,omitempty"`
	// Records are a name's records registered, in presentation format.
	Records []string `json:"records,omitempty"`
}

// savedRegistrar is the part of a registrar that says where names are held, and how to reach
// it.
type savedRegistrar struct {
	Domain    string             `json:"domain"`
	Server    string             `json:"server,omitempty"`
	Transport baseclient.Network `json:"transport"`
	Resolvers []string           `json:"resolvers,omitempty"`
}

type savedLabels struct {
	Host      string          `json:"host"`
	Instances []savedInstance `json:"instances,omitempty"`
}

type savedInstance struct {
	Label       string `json:"label"`
	ServiceType string `json:"service_type"`
	As          string `json:"as"`
}

func savedRegistrarOf(r Registrar) savedRegistrar {
	// An rfc9664 registrar has no resolvers (Parse).
	return savedRegistrar{Domain: r.Domain, Server: r.Server, Transport: r.Transport, Resolvers: r.Resolvers}
}

// sameRegistration reports whether names registered through r are held where names
// registered through o are: the same domain, through the same registrar.
func (r savedRegistrar) sameRegistration(o savedRegistrar) bool {
	return dnsname.EqualFold(r.Domain, o.Domain) && r.Server == o.Server && r.Transport == o.Transport
}

// openHostStore reads the state file in keystore; none yet is an empty store. It writes
// nothing.
func openHostStore(keystore string) (*hostStore, error) {
	s := &hostStore{keystore: keystore, path: filepath.Join(keystore, StateFile), hosts: map[string]savedHost{}}
	var doc stateDoc
	switch err := sealedfile.Read(s.path, &doc); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("agent state %s: %w (the agent's state must not be edited by hand)", s.path, err)
	default:
		for host, e := range doc.Hosts {
			if _, err := parseRecords(e.Records); err != nil {
				return nil, fmt.Errorf("agent state %s: %s: %w", s.path, host, err)
			}
		}
		if doc.Hosts != nil {
			s.hosts = doc.Hosts
		}
	}
	return s, nil
}

// parseRecords reads records saved in presentation format.
func parseRecords(saved []string) ([]dns.RR, error) {
	var out []dns.RR
	for _, r := range saved {
		rr, err := dns.New(r)
		if err != nil {
			return nil, fmt.Errorf("record %q: %w", r, err)
		}
		out = append(out, rr)
	}
	return out, nil
}

// view is the clientsrp.HostStore of the hosts source registers through r.
func (s *hostStore) view(source string, r savedRegistrar) hostView {
	return hostView{s: s, source: source, registrar: r}
}

// names is the rfc9664.NameStore of the names registered through r.
func (s *hostStore) names(r savedRegistrar) nameView {
	return nameView{s: s, registrar: r}
}

// entries returns every host's entry, by requested host name.
func (s *hostStore) entries() map[string]savedHost {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.hosts)
}

func (s *hostStore) entry(host string) (savedHost, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.hosts[host]
	return e, ok
}

// labels returns the labels host's names are held under, or nil if none are held.
func (s *hostStore) labels(host string) *clientsrp.Labels {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.hosts[host]
	if !e.Held {
		return nil
	}
	if e.Labels == nil {
		label, _, _ := dnsname.CutFirstLabel(host)
		return &clientsrp.Labels{Host: label, Instances: map[clientsrp.InstanceName]string{}}
	}
	l := clientsrp.Labels{Host: e.Labels.Host, Instances: map[clientsrp.InstanceName]string{}}
	for _, i := range e.Labels.Instances {
		l.Instances[clientsrp.InstanceName{Label: i.Label, ServiceType: i.ServiceType}] = i.As
	}
	return &l
}

// update applies change to host's entry, recording it as registered by source through
// registrar, and writes the file if that changed anything. An entry left neither held nor
// with records is dropped.
func (s *hostStore) update(host, source string, registrar savedRegistrar, change func(*savedHost)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.hosts[host]
	e := old
	e.Source, e.Registrar = source, registrar
	change(&e)
	empty := !e.Held && e.Records == nil
	switch {
	case empty && !had:
		return nil
	case empty:
		delete(s.hosts, host)
	case had && reflect.DeepEqual(e, old):
		return nil
	default:
		s.hosts[host] = e
	}
	return sealedfile.Write(s.path, stateDoc{Hosts: s.hosts})
}

// forget drops host's entry.
func (s *hostStore) forget(host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[host]; !ok {
		return nil
	}
	delete(s.hosts, host)
	return sealedfile.Write(s.path, stateDoc{Hosts: s.hosts})
}

// hostView is the clientsrp.HostStore of the hosts one source registers through one
// registrar: what it records, it records as theirs.
type hostView struct {
	s         *hostStore
	source    string
	registrar savedRegistrar
}

func (v hostView) Load(host string) *clientsrp.Labels { return v.s.labels(host) }

// Hold records l as the labels host's names are held under, written only if a rename
// changed any; nil: none are held.
func (v hostView) Hold(host string, l *clientsrp.Labels) error {
	var saved *savedLabels
	if label, _, _ := dnsname.CutFirstLabel(host); l != nil && l.Renamed(label) {
		saved = &savedLabels{Host: l.Host}
		for n, as := range l.Instances {
			if as != n.Label {
				saved.Instances = append(saved.Instances, savedInstance{Label: n.Label, ServiceType: n.ServiceType, As: as})
			}
		}
		slices.SortFunc(saved.Instances, func(a, b savedInstance) int {
			return strings.Compare(a.ServiceType+"\x00"+a.Label, b.ServiceType+"\x00"+b.Label)
		})
	}
	return v.s.update(host, v.source, v.registrar, func(e *savedHost) { e.Held, e.Labels = l != nil, saved })
}

// nameView is the rfc9664.NameStore of the names registered through one registrar.
type nameView struct {
	s         *hostStore
	registrar savedRegistrar
}

func (v nameView) Load(name string) []dns.RR {
	e, _ := v.s.entry(name)
	records, err := parseRecords(e.Records)
	if err != nil {
		// openHostStore parsed every entry's, and Save writes only what the library prints.
		panic(fmt.Sprintf("agent state: %s: %v", name, err))
	}
	return records
}

func (v nameView) Save(name string, held bool, records []dns.RR) error {
	var saved []string
	for _, rr := range records {
		saved = append(saved, rr.String())
	}
	return v.s.update(name, sourceNames, v.registrar, func(e *savedHost) { e.Held, e.Records = held, saved })
}

// wanted reports whether plan registers the host or name e records, owner, as it was
// registered: from keystore, through the same registration (sameRegistration), and as one of
// the registrar's names, one of its hosts or, if a mirror registered it, a host a mirror of
// that type selects.
func wanted(plan *Plan, keystore, owner string, e savedHost) bool {
	if keystore != plan.Keystore {
		return false
	}
	label, _, _ := dnsname.CutFirstLabel(owner)
	for _, r := range plan.Registrars {
		if !e.Registrar.sameRegistration(savedRegistrarOf(r)) {
			continue
		}
		switch {
		case e.Source == sourceNames:
			if r.Protocol == RFC9664 && slices.ContainsFunc(r.Names, func(n Name) bool { return dnsname.EqualFold(n.Name, label) }) {
				return true
			}
		case r.Protocol != SRP:
		case slices.ContainsFunc(r.Hosts, func(h Host) bool { return dnsname.EqualFold(h.Name, label) }):
			return true
		case e.Source != sourceHosts && slices.ContainsFunc(r.Mirrors, func(m Mirror) bool {
			return m.Type == e.Source && mdnsbridge.Selects(m.Hosts, m.AllHosts, label)
		}):
			return true
		}
	}
	return false
}

// unwanted returns, sorted, the hosts and names s records that plan does not register (wanted).
func (s *hostStore) unwanted(plan *Plan) []string {
	var out []string
	for host, e := range s.entries() {
		if !wanted(plan, s.keystore, host, e) {
			out = append(out, host)
		}
	}
	slices.Sort(out)
	return out
}
