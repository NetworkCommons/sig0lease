// Package updatecore holds forwarding plumbing shared by the RFC 9664 update-lease
// handler and the RFC 9665 SRP handler (see main/docs/rfc9665-srp-implementation-plan.md
// S4.1, D1/D8). It is a public package, not internal/, matching this repo's convention.
package updatecore

import (
	"context"
	"fmt"
	"net"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// Coordinator resolves the authoritative server for a zone (SOA MNAME, or a configured
// per-zone static override, D4) and performs the two things both handlers need against
// it: sending a signed UPDATE, and a live KEY-at-name query (S3.3.3 FCFS).
//
// This is the extraction of what was previously handlers.DefaultUpstreamCoordinator's
// entire body. Both handlers/opcode5.go (RFC 9664) and handlers/srp_handler.go (RFC 9665)
// construct and hold a *Coordinator directly -- there is no per-package wrapper type.
type Coordinator struct {
	logger *logging.Logger
	// bootstrapResolvers are the resolvers used to look up SOA/NS records to find the
	// authoritative server for a zone not covered by staticUpstream.
	bootstrapResolvers []string
	// staticUpstream maps a normalized (lower-cased, no trailing dot) zone name to a
	// static "host:port" override (D4): when a zone matches (exactly -- no parent-zone
	// fallback, unlike SOA/NS resolution), both SOA and NS discovery are skipped
	// entirely for it. nil or a zone with no entry falls through to normal resolution.
	staticUpstream map[string]string
}

// defaultBootstrapResolvers is used only when no bootstrap resolver list was configured
// at all -- the same pair config.NewDefaultConfig uses for generic upstreams, so
// out-of-the-box behavior for a caller that sets nothing is unchanged from before this
// extraction.
var defaultBootstrapResolvers = []string{"8.8.8.8:53", "8.8.4.4:53"}

// NewCoordinator creates a Coordinator. bootstrapResolvers falls back to
// defaultBootstrapResolvers when empty. staticUpstream may be nil (no overrides).
func NewCoordinator(logger *logging.Logger, bootstrapResolvers []string, staticUpstream map[string]string) *Coordinator {
	resolvers := bootstrapResolvers
	if len(resolvers) == 0 {
		resolvers = defaultBootstrapResolvers
	}
	normalized := make(map[string]string, len(staticUpstream))
	for zone, addr := range staticUpstream {
		normalized[normalizeZone(zone)] = addr
	}
	return &Coordinator{
		logger:             logger,
		bootstrapResolvers: resolvers,
		staticUpstream:     normalized,
	}
}

func normalizeZone(zone string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
}

// ResolveSOAMasterServer returns the "host:port" of zone's SOA MNAME (walking up to
// parent zones if the exact name has none) and the effective zone that answered, or --
// if zone exactly matches a configured static upstream (D4) -- that override address
// with zone itself as the effective zone, skipping the lookup entirely.
func (c *Coordinator) ResolveSOAMasterServer(ctx context.Context, zone string) (server, effectiveZone string, err error) {
	if addr, ok := c.staticUpstream[normalizeZone(zone)]; ok {
		return addr, ensureFQDN(zone), nil
	}

	trimmed := strings.TrimSuffix(zone, ".")
	if trimmed == "" {
		return "", "", fmt.Errorf("upstream zone is empty")
	}

	for candidate := trimmed; candidate != ""; candidate = parentZone(candidate) {
		candidateFQDN := candidate + "."
		req := dns.NewMsg(candidateFQDN, dns.TypeSOA)
		if req == nil {
			continue
		}

		for _, bootstrapServer := range c.bootstrapResolvers {
			resp, err := dns.Exchange(ctx, req, "udp", bootstrapServer)
			if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
				continue
			}

			for _, rr := range resp.Answer {
				soa, ok := rr.(*dns.SOA)
				if !ok {
					continue
				}
				mname := strings.TrimSuffix(soa.Ns, ".")
				if mname == "" {
					break
				}
				c.logger.Debugf("Selected SOA MNAME %s for effective zone %s (via bootstrap resolver %s)", mname, candidateFQDN, bootstrapServer)
				return net.JoinHostPort(mname, "53"), candidateFQDN, nil
			}
		}
	}

	return "", "", fmt.Errorf("no SOA master server found for %q", zone)
}

// ResolveAuthoritativeZone finds the zone cut (the name that actually has NS records)
// for zone or one of its parents -- or, for a zone matching a static upstream override
// (D4), zone itself, with no NS lookup at all (the operator has already asserted the
// zone cut by configuring the override).
func (c *Coordinator) ResolveAuthoritativeZone(ctx context.Context, zone string) (string, error) {
	if _, ok := c.staticUpstream[normalizeZone(zone)]; ok {
		return ensureFQDN(zone), nil
	}

	trimmed := strings.TrimSuffix(zone, ".")
	if trimmed == "" {
		return "", fmt.Errorf("upstream zone is empty")
	}

	for candidate := trimmed; candidate != ""; candidate = parentZone(candidate) {
		candidateFQDN := candidate + "."
		req := dns.NewMsg(candidateFQDN, dns.TypeNS)
		if req == nil {
			continue
		}

		for _, bootstrapServer := range c.bootstrapResolvers {
			resp, err := dns.Exchange(ctx, req, "udp", bootstrapServer)
			if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
				continue
			}
			for _, rr := range resp.Answer {
				if _, ok := rr.(*dns.NS); ok {
					c.logger.Debugf("Selected authoritative zone %s via NS lookup (bootstrap resolver %s)", candidateFQDN, bootstrapServer)
					return candidateFQDN, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no authoritative zone with NS records found for %q", zone)
}

func ensureFQDN(zone string) string {
	zone = strings.TrimSpace(zone)
	if zone == "" || strings.HasSuffix(zone, ".") {
		return zone
	}
	return zone + "."
}

func parentZone(zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return ""
	}
	idx := strings.Index(zone, ".")
	if idx < 0 {
		return ""
	}
	return zone[idx+1:]
}

func canonicalName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// SendUpdate sends updateMsg (already built and signed) to upstreamZone's authoritative
// server, resolved via ResolveSOAMasterServer (so a static override, D4, is honored),
// trying UDP then falling back to TCP.
func (c *Coordinator) SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error) {
	if upstreamZone == "" {
		return nil, fmt.Errorf("upstream zone is required")
	}
	if updateMsg == nil {
		return nil, fmt.Errorf("update message is nil")
	}
	if len(updateMsg.Question) != 1 {
		return nil, fmt.Errorf("update message must contain exactly one question")
	}
	msgZone := updateMsg.Question[0].Header().Name
	c.logger.Debugf("Message zone: %s", msgZone)
	// Compare canonically: callers pass zone strings from several sources (config,
	// resolved via live NS lookup with a trailing dot, or normalizeZone()'d lease-store
	// values without one) that name the same zone but aren't byte-identical.
	if canonicalName(msgZone) != canonicalName(upstreamZone) {
		return nil, fmt.Errorf("update zone mismatch: message zone %q, expected upstream zone %q", msgZone, upstreamZone)
	}

	soaServer, authZone, err := c.ResolveSOAMasterServer(ctx, upstreamZone)
	if err != nil {
		return nil, fmt.Errorf("SOA master resolution failed for zone %q: %w", upstreamZone, err)
	}
	c.logger.Debugf("Resolved SOA master for zone %s (effective zone %s): %s", upstreamZone, authZone, soaServer)

	resp, udpErr := dns.Exchange(ctx, updateMsg, "udp", soaServer)
	if udpErr == nil {
		c.logger.Debugf("Authoritative UPDATE over UDP succeeded: server=%s rcode=%d", soaServer, resp.Rcode)
		return resp, nil
	}

	c.logger.Debugf("Authoritative UPDATE over UDP failed: server=%s err=%v; retrying TCP", soaServer, udpErr)
	resp, tcpErr := dns.Exchange(ctx, updateMsg, "tcp", soaServer)
	if tcpErr == nil {
		c.logger.Debugf("Authoritative UPDATE over TCP succeeded: server=%s rcode=%d", soaServer, resp.Rcode)
		return resp, nil
	}

	return nil, fmt.Errorf("authoritative update failed to SOA master %s (udp: %v, tcp: %v)", soaServer, udpErr, tcpErr)
}

// QueryKeyAtName is the real implementation of AuthoritativeKeyQuery (S3.3.3 FCFS):
// one live QTYPE=KEY query at name against zoneHint's resolved authoritative server
// (ResolveSOAMasterServer, honoring a static override), reporting the tri-state result
// pkg/srp needs. This is also the pre-forward cost S5 describes -- the same query
// backs both the FCFS check (S3.3) and, when reused by a caller, the "does this name
// already have a KEY" question the base handler asks elsewhere.
func (c *Coordinator) QueryKeyAtName(ctx context.Context, zoneHint, name string) (AuthoritativeKeyState, []*dns.KEY, error) {
	soaServer, _, err := c.ResolveSOAMasterServer(ctx, zoneHint)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve authoritative server for %s: %w", zoneHint, err)
	}

	req := dns.NewMsg(name, dns.TypeKEY)
	if req == nil {
		return 0, nil, fmt.Errorf("failed to build KEY query for %s", name)
	}
	req.RecursionDesired = false

	// A truncated UDP answer must not be trusted as-is: an empty (or partial) Answer
	// section on a TC=1 response would otherwise be read as AuthNoKey/AuthNXDomain --
	// letting FCFS treat an already-owned name as free -- even though the name really
	// does have KEY data, just more than fit in the UDP response. This fork's
	// dns.Exchange does not retry or fall back to TCP on truncation on its own (see its
	// own doc comment), so that fallback has to happen here, same as SendUpdate already
	// does for a transport-level UDP failure.
	resp, udpErr := dns.Exchange(ctx, req, "udp", soaServer)
	if udpErr != nil || (resp != nil && resp.Truncated) {
		tcpResp, tcpErr := dns.Exchange(ctx, req, "tcp", soaServer)
		if tcpErr != nil {
			return 0, nil, fmt.Errorf("KEY query for %s failed (udp: %v, tcp: %v)", name, udpErr, tcpErr)
		}
		resp = tcpResp
	}
	if resp == nil {
		return 0, nil, fmt.Errorf("KEY query for %s returned a nil response", name)
	}

	switch resp.Rcode {
	case dns.RcodeNameError:
		return AuthNXDomain, nil, nil

	case dns.RcodeSuccess:
		var keys []*dns.KEY
		for _, rr := range resp.Answer {
			if k, ok := rr.(*dns.KEY); ok {
				keys = append(keys, k)
			}
		}
		if len(keys) == 0 {
			return AuthNoKey, nil, nil
		}
		return AuthKeyPresent, keys, nil

	default:
		return 0, nil, fmt.Errorf("KEY query for %s returned unexpected rcode %d (%s)", name, resp.Rcode, dns.RcodeToString[resp.Rcode])
	}
}

// FindAuthorizedProxyKey loads the proxy's own SIG(0) signing key for zone from
// keystoreDir, walking up to parent zones if the exact zone has no key -- extracted from
// what was previously (*handlers.UpdateHandler).findAuthorizedProxyKeyForZone, now a
// standalone function so handlers/srp_handler.go can use it without depending on
// *handlers.UpdateHandler.
func FindAuthorizedProxyKey(keystoreDir, zone string, logger *logging.Logger) (*keyrec.LoadedKey, string, error) {
	zone = normalizeZone(zone)
	if zone == "" {
		return nil, "", fmt.Errorf("zone is empty")
	}

	for candidate := zone; candidate != ""; candidate = parentZone(candidate) {
		keyNames, err := keyrec.FindKeysByZone(keystoreDir, candidate+".", logger)
		if len(keyNames) == 0 {
			continue
		}
		if len(keyNames) > 1 {
			return nil, "", fmt.Errorf("More than one proxy authorization key found for zone %s", candidate)
		}

		k, err := keyrec.LoadKeyFromFile(keystoreDir, keyNames[0])
		if err != nil {
			return nil, "", fmt.Errorf("error loading proxy authorization key %s", keyNames[0])
		}
		return k, candidate + ".", nil
	}

	return nil, "", fmt.Errorf("no proxy authorization key found for zone %q or any parent", zone+".")
}
