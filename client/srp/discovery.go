package srp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
)

// SRVQuery is the shape of a live SRV lookup, injected so Discover is testable without real
// network I/O. Returns the answer's SRV records (possibly none), in whatever order the
// server returned them.
type SRVQuery func(ctx context.Context, name string) ([]*dns.SRV, error)

// defaultBootstrapResolvers mirrors pkg/updatecore.Coordinator's own default -- the same
// public resolver pair used elsewhere in this codebase to resolve records this project
// doesn't itself serve.
var defaultBootstrapResolvers = []string{"8.8.8.8:53", "8.8.4.4:53"}

// LiveSRVQuery returns an SRVQuery that performs a real SRV lookup against resolvers
// (falling back to defaultBootstrapResolvers if empty), trying each in turn until one
// answers with NOERROR.
func LiveSRVQuery(resolvers []string) SRVQuery {
	if len(resolvers) == 0 {
		resolvers = defaultBootstrapResolvers
	}
	return func(ctx context.Context, name string) ([]*dns.SRV, error) {
		req := dns.NewMsg(name, dns.TypeSRV)
		if req == nil {
			return nil, fmt.Errorf("srp/client: failed to build SRV query for %s", name)
		}

		var lastErr error
		for _, resolver := range resolvers {
			resp, err := dns.Exchange(ctx, req, "udp", resolver)
			if err != nil {
				lastErr = err
				continue
			}
			if resp == nil || resp.Rcode != dns.RcodeSuccess {
				continue
			}
			var out []*dns.SRV
			for _, rr := range resp.Answer {
				if srv, ok := rr.(*dns.SRV); ok {
					out = append(out, srv)
				}
			}
			return out, nil
		}
		if lastErr != nil {
			return nil, fmt.Errorf("srp/client: SRV query for %s failed against all resolvers: %w", name, lastErr)
		}
		return nil, nil
	}
}

// Discover finds the SRP registrar for domain via a `_dnssd-srp._tcp.<domain>.` SRV lookup
// -- ordinary DNS-SD service discovery (RFC 6763), applied to bootstrap SRP itself, per RFC
// 9665's own discovery convention (see RFC 9665 Appendix C's zone skeleton's optional
// `_dnssd-srp._tcp` SRV record). Returns "host:port" for the best (lowest-priority,
// highest-weight-among-ties) answer. A caller with an explicit registrar address configured
// should skip this entirely (see Config.RegistrarAddr) -- discovery is the fallback, not the
// only path, matching cmd/sig0lease-srp-client's own "dev/test tool" framing.
func Discover(ctx context.Context, query SRVQuery, domain string) (string, error) {
	if query == nil {
		return "", fmt.Errorf("srp/client: Discover called with a nil SRVQuery")
	}
	name := "_dnssd-srp._tcp." + ensureFQDN(domain)

	srvs, err := query(ctx, name)
	if err != nil {
		return "", fmt.Errorf("srp/client: discovery failed for %s: %w", domain, err)
	}
	if len(srvs) == 0 {
		return "", fmt.Errorf("srp/client: no SRP registrar found via %s", name)
	}

	best := srvs[0]
	for _, s := range srvs[1:] {
		if s.Priority < best.Priority || (s.Priority == best.Priority && s.Weight > best.Weight) {
			best = s
		}
	}
	target := strings.TrimSuffix(best.Target, ".")
	return net.JoinHostPort(target, strconv.Itoa(int(best.Port))), nil
}

func ensureFQDN(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
