// Package updatecore holds forwarding plumbing shared by the RFC 9664 update-lease
// handler and the RFC 9665 SRP handler (see docs/siglease_rfc9665.md's upstream forward
// section). It is a public package, not internal/, matching this repo's convention.
package updatecore

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/NetworkCommons/sig0lease/logging"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/dnszone"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// Coordinator resolves the authoritative server for a zone (SOA MNAME, or a configured
// static upstream) and performs the two things both handlers need against
// it: sending a signed UPDATE, and a live KEY-at-name query (S3.3.3 FCFS).
//
// This is the extraction of what was previously handlers.DefaultUpstreamCoordinator's
// entire body. Both handlers/opcode5.go (RFC 9664) and handlers/srp_handler.go (RFC 9665)
// construct and hold a *Coordinator directly -- there is no per-package wrapper type.
type Coordinator struct {
	logger *logging.Logger
	// bootstrapResolvers are the resolvers asked for a name's SOA to find the zone holding
	// it and that zone's primary server (discoverZone), for names static does not cover;
	// query asks them.
	bootstrapResolvers []string
	query              dnszone.Query
	// zones keeps what discoverZone found, each SOA for its TTL; now is its clock.
	zones zoneCache
	now   func() time.Time
	// static, when set, replaces discovery for its zone and every name below it.
	static *StaticUpstream
}

// StaticUpstream is a configured authoritative server for one zone: for Zone and every
// name at or below it, the Coordinator sends to Addr and takes Zone as the zone, with no
// discovery. Configuring it is the operator's assertion that Addr serves Zone and that no
// zone cut lies below Zone -- the handlers' "upstream" setting.
type StaticUpstream struct {
	Zone string // e.g. "srp.test."
	Addr string // "host:port"
}

// NewCoordinator creates a Coordinator. static may be nil (discovery for every name). With
// no bootstrapResolvers, discovery fails: only names at or below static's zone can be served.
func NewCoordinator(logger *logging.Logger, bootstrapResolvers []string, static *StaticUpstream) *Coordinator {
	if static != nil && !strings.HasSuffix(static.Zone, ".") {
		static = &StaticUpstream{Zone: static.Zone + ".", Addr: static.Addr}
	}
	return &Coordinator{
		logger:             logger,
		bootstrapResolvers: bootstrapResolvers,
		query:              dnszone.Resolvers(bootstrapResolvers),
		now:                time.Now,
		static:             static,
	}
}

// covers reports whether the static upstream applies to name: one is configured and name
// is its zone or below it.
func (c *Coordinator) covers(name string) bool {
	return c.static != nil && dnsname.IsAtOrBelow(name, c.static.Zone)
}

// discoverZone returns the SOA of the zone holding name: its owner is the zone's apex, its
// MNAME the zone's primary server. It asks the bootstrap resolvers (dnszone.Apex, RFC 8765
// S6.1): one SOA query for name, whose answer carries the SOA in the Answer section when name
// is the apex and in the Authority section otherwise, unless the resolver leaves it out
// (Google Public DNS does at times for srp.dev.zenr.io., a name inside zenr.io.); then the
// parent names are asked in turn, up to the apex. A root SOA (name is in no delegated zone),
// an SOA of a zone not holding name, or one naming no primary server is no answer.
//
// Every query the handlers relay and every UPDATE they send starts here, so the SOA found is
// kept for its TTL -- the zone's negative-caching TTL when it came in the Authority section
// -- and discoverZone answers from it, with no query, until that runs out. A failure is
// never kept: the next call asks again.
func (c *Coordinator) discoverZone(ctx context.Context, name string) (*dns.SOA, error) {
	fqdn := dnsutil.Fqdn(name)
	key := dnsname.Normalize(fqdn)
	if key == "" {
		return nil, fmt.Errorf("upstream zone is empty")
	}
	if soa := c.zones.get(key, c.now()); soa != nil {
		return soa, nil
	}
	soa, err := dnszone.Apex(ctx, c.query, fqdn)
	if err != nil {
		return nil, fmt.Errorf("no zone SOA found for %q via bootstrap resolvers %v: %w", fqdn, c.bootstrapResolvers, err)
	}
	if dnsname.Normalize(soa.Ns) == "" {
		return nil, fmt.Errorf("no zone SOA found for %q via bootstrap resolvers %v: the SOA of %s names no primary server (MNAME %q)", fqdn, c.bootstrapResolvers, soa.Hdr.Name, soa.Ns)
	}
	c.logger.Debugf("Zone of %s is %s, primary server %s, kept for %d s (via bootstrap resolvers %v)", fqdn, soa.Hdr.Name, soa.Ns, soa.Hdr.TTL, c.bootstrapResolvers)
	c.zones.put(key, soa, c.now())
	return soa, nil
}

// zoneCache keeps discoverZone's answers, by the name asked (normalized), each until its
// SOA's TTL runs out. The handlers ask only for their upstream_zone, so it holds one entry
// per handler; put drops whatever has run out all the same.
type zoneCache struct {
	mu      sync.Mutex
	entries map[string]cachedZone
}

type cachedZone struct {
	soa     *dns.SOA
	expires time.Time
}

// get returns the SOA kept for name, or nil when there is none or its TTL has run out by now.
func (z *zoneCache) get(name string, now time.Time) *dns.SOA {
	z.mu.Lock()
	defer z.mu.Unlock()
	e, ok := z.entries[name]
	if !ok || !now.Before(e.expires) {
		return nil
	}
	return e.soa
}

// put keeps soa for name for its TTL from now (not at all for a TTL of 0), and drops every
// entry that has run out.
func (z *zoneCache) put(name string, soa *dns.SOA, now time.Time) {
	z.mu.Lock()
	defer z.mu.Unlock()
	for k, e := range z.entries {
		if !now.Before(e.expires) {
			delete(z.entries, k)
		}
	}
	if soa.Hdr.TTL == 0 {
		return
	}
	if z.entries == nil {
		z.entries = make(map[string]cachedZone)
	}
	z.entries[name] = cachedZone{soa: soa, expires: now.Add(time.Duration(soa.Hdr.TTL) * time.Second)}
}

// ResolveSOAMasterServer returns the "host:port" of the primary server (SOA MNAME, port 53)
// of the zone holding zone, and that zone (discoverZone) -- or, when the static upstream
// covers zone, its address and zone, with no lookup.
func (c *Coordinator) ResolveSOAMasterServer(ctx context.Context, zone string) (server, effectiveZone string, err error) {
	if c.covers(zone) {
		return c.static.Addr, c.static.Zone, nil
	}
	soa, err := c.discoverZone(ctx, zone)
	if err != nil {
		return "", "", err
	}
	return net.JoinHostPort(strings.TrimSuffix(soa.Ns, "."), "53"), soa.Hdr.Name, nil
}

// ResolveAuthoritativeZone returns the apex of the zone holding zone -- the zone an UPDATE
// for names under zone must name (discoverZone) -- or, when the static upstream covers
// zone, its zone, with no lookup.
func (c *Coordinator) ResolveAuthoritativeZone(ctx context.Context, zone string) (string, error) {
	if c.covers(zone) {
		return c.static.Zone, nil
	}
	soa, err := c.discoverZone(ctx, zone)
	if err != nil {
		return "", err
	}
	return soa.Hdr.Name, nil
}

func parentZone(zone string) string {
	_, parent, _ := dnsname.CutFirstLabel(strings.TrimSuffix(zone, "."))
	return parent
}

// SendUpdate sends updateMsg (already built and signed) to upstreamZone's authoritative
// server, resolved via ResolveSOAMasterServer (so a static override is honored),
// trying UDP then falling back to TCP. Each change of an update the server accepts is
// logged at INFO (logAppliedChanges).
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
	// resolved via a live SOA lookup with a trailing dot, or dnsname.Normalize()'d lease-store
	// values without one) that name the same zone but aren't byte-identical.
	if dnsname.Normalize(msgZone) != dnsname.Normalize(upstreamZone) {
		return nil, fmt.Errorf("update zone mismatch: message zone %q, expected upstream zone %q", msgZone, upstreamZone)
	}

	soaServer, authZone, err := c.ResolveSOAMasterServer(ctx, upstreamZone)
	if err != nil {
		return nil, fmt.Errorf("SOA master resolution failed for zone %q: %w", upstreamZone, err)
	}
	c.logger.Debugf("Resolved SOA master for zone %s (effective zone %s): %s", upstreamZone, authZone, soaServer)

	// Held across both attempts below, so the server never sees more of this process's
	// UPDATEs at once than SetMaxInflightUpdates allows.
	release, err := inflightUpdates.acquire(ctx, soaServer)
	if err != nil {
		return nil, err
	}
	defer release()

	resp, udpErr := dns.Exchange(ctx, updateMsg, "udp", soaServer)
	if udpErr == nil {
		c.logger.Debugf("Authoritative UPDATE over UDP succeeded: server=%s rcode=%d", soaServer, resp.Rcode)
		c.logAppliedChanges(updateMsg, resp, soaServer)
		return resp, nil
	}

	c.logger.Debugf("Authoritative UPDATE over UDP failed: server=%s err=%v; retrying TCP", soaServer, udpErr)
	resp, tcpErr := dns.Exchange(ctx, updateMsg, "tcp", soaServer)
	if tcpErr == nil {
		c.logger.Debugf("Authoritative UPDATE over TCP succeeded: server=%s rcode=%d", soaServer, resp.Rcode)
		c.logAppliedChanges(updateMsg, resp, soaServer)
		return resp, nil
	}

	return nil, fmt.Errorf("authoritative update failed to SOA master %s (udp: %v, tcp: %v)", soaServer, udpErr, tcpErr)
}

// logAppliedChanges logs at INFO each add and delete in updateMsg's Update section, once
// the authoritative server has accepted it (NOERROR). Every proxy write to DNS passes
// through SendUpdate -- client updates under both RFCs, lease expiry, and the RFC 6763 S9
// Service Type Enumeration record -- so these lines are the record of what the proxy
// changed in DNS. A rejected update changed nothing; its caller logs the rejection.
func (c *Coordinator) logAppliedChanges(updateMsg, resp *dns.Msg, server string) {
	if resp.Rcode != dns.RcodeSuccess {
		return
	}
	zone := updateMsg.Question[0].Header().Name
	for _, rr := range updateMsg.Ns {
		c.logger.Infof("DNS update applied: zone=%s server=%s %s", zone, server, describeUpdateChange(rr))
	}
}

// describeUpdateChange renders an Update-section RR as the change it makes (RFC 2136
// S2.5): an add carries the zone's class, a delete of one RR class NONE, and a delete of
// an RRset, or of every RRset at a name, class ANY.
func describeUpdateChange(rr dns.RR) string {
	hdr := rr.Header()
	rrType := dnsutil.TypeToString(dns.RRToType(rr))
	switch hdr.Class {
	case dns.ClassNONE:
		return fmt.Sprintf("deleted %s %s %s", hdr.Name, rrType, rr.Data().String())
	case dns.ClassANY:
		if dns.RRToType(rr) == dns.TypeANY {
			return "deleted all RRsets at " + hdr.Name
		}
		return fmt.Sprintf("deleted RRset %s %s", hdr.Name, rrType)
	default:
		return fmt.Sprintf("added %s %d %s %s %s", hdr.Name, hdr.TTL, dnsutil.ClassToString(hdr.Class), rrType, rr.Data().String())
	}
}

// QueryAuthoritative sends req, with its RD bit cleared, to zoneHint's authoritative server
// (ResolveSOAMasterServer, honoring a static override) over UDP, falling back to TCP on a UDP
// failure or a truncated answer. A truncated UDP answer must not be trusted as-is: its empty (or partial) Answer
// section would otherwise read as "no such records" -- letting FCFS treat an already-owned
// name as free, say -- even though the name really has more data than fit in the UDP
// response. This fork's dns.Exchange neither retries nor falls back to TCP on truncation on
// its own (see its doc comment), so it has to happen here. what names the query in errors.
func (c *Coordinator) QueryAuthoritative(ctx context.Context, zoneHint string, req *dns.Msg, what string) (*dns.Msg, error) {
	soaServer, _, err := c.ResolveSOAMasterServer(ctx, zoneHint)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve authoritative server for %s: %w", zoneHint, err)
	}
	req.RecursionDesired = false

	resp, udpErr := dns.Exchange(ctx, req, "udp", soaServer)
	if udpErr != nil || (resp != nil && resp.Truncated) {
		tcpResp, tcpErr := dns.Exchange(ctx, req, "tcp", soaServer)
		if tcpErr != nil {
			return nil, fmt.Errorf("%s failed (udp: %v, tcp: %v)", what, udpErr, tcpErr)
		}
		resp = tcpResp
	}
	if resp == nil {
		return nil, fmt.Errorf("%s returned a nil response", what)
	}
	return resp, nil
}

// QueryKeyAtName is the real implementation of AuthoritativeKeyQuery (S3.3.3 FCFS):
// one live QTYPE=KEY query at name against zoneHint's resolved authoritative server
// (ResolveSOAMasterServer, honoring a static override), reporting the tri-state result
// pkg/srp needs. This is also the pre-forward cost S5 describes -- the same query
// backs both the FCFS check (S3.3) and, when reused by a caller, the "does this name
// already have a KEY" question the base handler asks elsewhere.
func (c *Coordinator) QueryKeyAtName(ctx context.Context, zoneHint, name string) (AuthoritativeKeyState, []*dns.KEY, error) {
	req := dns.NewMsg(name, dns.TypeKEY)
	if req == nil {
		return 0, nil, fmt.Errorf("failed to build KEY query for %s", name)
	}
	resp, err := c.QueryAuthoritative(ctx, zoneHint, req, "KEY query for "+name)
	if err != nil {
		return 0, nil, err
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

// QueryRRs returns the rrType records at name from zoneHint's authoritative server -- none
// for NXDOMAIN -- with the same query/fallback shape as QueryKeyAtName. Used by the RFC 9664
// handler's checks of what is already published (signer KEYs, duplicate registrations), and by
// the SRP handler's RFC 6763 S9 and S11 reconciliation (the PTRs at a browsing or
// domain-enumeration name).
func (c *Coordinator) QueryRRs(ctx context.Context, zoneHint, name string, rrType uint16) ([]dns.RR, error) {
	what := fmt.Sprintf("%s query for %s", dns.TypeToString[rrType], name)
	req := dns.NewMsg(name, rrType)
	if req == nil {
		return nil, fmt.Errorf("failed to build %s", what)
	}
	resp, err := c.QueryAuthoritative(ctx, zoneHint, req, what)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("%s returned unexpected rcode %d (%s)", what, resp.Rcode, dns.RcodeToString[resp.Rcode])
	}

	rrs := make([]dns.RR, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		if rr != nil && rr.Header() != nil && dns.RRToType(rr) == rrType {
			rrs = append(rrs, rr)
		}
	}
	return rrs, nil
}

// FindAuthorizedProxyKey loads the proxy's own SIG(0) signing key for zone from
// keystoreDir, walking up to parent zones if the exact zone has no key -- extracted from
// what was previously (*handlers.UpdateHandler).findAuthorizedProxyKeyForZone, now a
// standalone function so handlers/srp_handler.go can use it without depending on
// *handlers.UpdateHandler.
func FindAuthorizedProxyKey(keystoreDir, zone string, logger *logging.Logger) (*keyrec.LoadedKey, string, error) {
	zone = dnsname.Normalize(zone)
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
