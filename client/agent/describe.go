package agent

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"strings"

	"github.com/NetworkCommons/sig0lease/client/rfc9664"
	clientsrp "github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// Describe writes what Run would register for plan. It reads, and changes nothing: this
// machine's addresses for auto (interfaces, InterfaceAddresses if nil), the keys the
// keystore holds, and in StateFile the names that Run frees: those an earlier run's renames
// hold (clientsrp.StartHost), and those of hosts and names the template no longer registers
// (agent.release).
func Describe(w io.Writer, plan *Plan, interfaces func() ([]netip.Addr, error), logger *logging.Logger) error {
	if interfaces == nil {
		interfaces = InterfaceAddresses
	}
	store, err := openHostStore(plan.Keystore)
	if err != nil {
		return err
	}
	p := func(format string, args ...any) { fmt.Fprintf(w, format+"\n", args...) }
	key := func(owner string) error {
		keys, err := keyrec.FindKeysByZone(plan.Keystore, owner, logger)
		switch {
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			return err
		case len(keys) == 0:
			p("  key:       none yet; run creates an ECDSA P-256 key")
		default:
			p("  key:       %s", keys[0])
		}
		return nil
	}
	addresses := func(auto bool, literal []netip.Addr) {
		var addrs []string
		for _, a := range literal {
			addrs = append(addrs, a.String())
		}
		if auto {
			machine, err := machineAddresses(interfaces)
			switch {
			case err != nil:
				addrs = append(addrs, fmt.Sprintf("auto (cannot read this machine's: %v)", err))
			case len(machine) == 0:
				addrs = append(addrs, "auto (this machine has none to publish now)")
			default:
				addrs = append(addrs, fmt.Sprintf("auto (now %s)", joinAddrs(machine)))
			}
		}
		if len(addrs) > 0 {
			p("  addresses: %s", strings.Join(addrs, ", "))
		}
	}

	p("keystore:  %s", plan.Keystore)
	for _, r := range plan.Registrars {
		p("")
		switch r.Protocol {
		case SRP:
			p("srp domain %s", r.Domain)
			if r.Server != "" {
				p("  registrar: %s over %s", r.Server, r.Transport)
			} else {
				p("  registrar: discovered (%s SRV), over %s", clientsrp.DiscoveryService(r.Transport), r.Transport)
			}
			if len(r.Resolvers) > 0 {
				p("  resolvers: %s", strings.Join(r.Resolvers, ", "))
			}
		case RFC9664:
			p("rfc9664 zone %s", r.Domain)
			p("  proxy:     %s over %s", r.Server, r.Transport)
		}
		p("  leases:    %s", r.Lifetime)

		for _, h := range r.Hosts {
			owner := r.Owner(h.Name)
			p("")
			p("host %s", owner)
			held := store.labels(owner)
			if held != nil && held.Renamed(h.Name) {
				p("  renamed:   an earlier run's rename holds host %s; run frees its names and asks for these again", r.Owner(held.Host))
			} else {
				held = nil
			}
			if err := key(owner); err != nil {
				return err
			}
			addresses(h.Auto, h.Addresses)
			if h.Lifetime != r.Lifetime {
				p("  leases:    %s", h.Lifetime)
			}
			if len(h.Services) == 0 {
				p("  no services: the host alone")
			}
			for _, s := range h.Services {
				in := s.Instance
				line := fmt.Sprintf("  service %q %s port %d, type %s, probe %s", in.Label, in.ServiceType, in.Port, s.Type, s.Probe)
				if held != nil {
					if as, ok := held.Instances[clientsrp.InstanceName{Label: in.Label, ServiceType: in.ServiceType}]; ok && as != in.Label {
						line += fmt.Sprintf(", held as %q from that rename", as)
					}
				}
				p("%s", line)
				if len(in.TXT) > 0 {
					p("    txt:      %s", strings.Join(in.TXT, " "))
				}
				if len(in.Subtypes) > 0 {
					p("    subtypes: %s", strings.Join(in.Subtypes, " "))
				}
			}
		}

		for _, m := range r.Mirrors {
			p("")
			hosts := "every host on the link"
			if !m.AllHosts {
				hosts = strings.Join(m.Hosts, ", ")
			}
			types := "every type"
			if len(m.ServiceTypes) > 0 {
				types = strings.Join(m.ServiceTypes, ", ")
			}
			p("mirror %s: %s, services of %s, from the daemon at %s", m.Type, hosts, types, m.Socket)
		}

		for _, n := range r.Names {
			owner := r.Owner(n.Name)
			p("")
			p("name %s", owner)
			if err := key(owner); err != nil {
				return err
			}
			addresses(n.Auto, n.Addresses)
			for _, rr := range n.Records {
				p("  record:    %s", rfc9664.Describe(rr))
			}
			if n.Lifetime != r.Lifetime {
				p("  leases:    %s", n.Lifetime)
			}
		}
	}

	for _, owner := range store.unwanted(plan) {
		if e, _ := store.entry(owner); e.Held {
			kind := "host"
			if e.Source == sourceNames {
				kind = "name"
			}
			p("")
			p("%s %s: holds names from an earlier run that the template no longer registers; run frees them", kind, owner)
		}
	}
	return nil
}

func joinAddrs(addrs []netip.Addr) string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}
