// Package dnssd holds pure logic for RFC 6763 (DNS-Based Service Discovery) concerns that
// sit alongside, but outside, RFC 9665's own Service Registration Protocol -- currently just
// S9's Service Type Enumeration meta-record. An SRP client's Service Description never
// carries this record itself (S9 predates SRP and isn't part of what a client restates), so
// a registrar that wants registered services to be discoverable by "browse everything" tools
// -- not just a targeted per-type browse -- has to maintain it independently. See
// handlers.SRPHandler.reconcileServiceEnumeration for how this package's pure functions are
// combined with live lease-store state and turned into an upstream UPDATE.
package dnssd

import (
	"sort"
	"strings"

	"codeberg.org/miekg/dns"
)

// EnumerationOwnerName returns the RFC 6763 S9 Service Type Enumeration PTR owner name for
// zone: "_services._dns-sd._udp.<zone>". Fixed at "._udp" regardless of whether the
// individual service types being enumerated are themselves "._tcp" -- S9 defines exactly one
// enumeration name per zone, not one per protocol. zone must already be dot-terminated (this
// package does no normalization of its own, matching the rest of this codebase's convention
// of trusting an already-canonical zone at this layer).
func EnumerationOwnerName(zone string) string {
	return "_services._dns-sd._udp." + zone
}

// BrowsingOwnerName returns the RFC 6763 S4.1 per-type Service Instance Enumeration PTR
// owner name for svcType in zone: "<svcType>.<zone>" (e.g. "_http._tcp.example.com."). This
// is the name a normal DNS-SD browse queries directly; SRPHandler also uses it as a live
// ground-truth check before removing svcType from the S9 enumeration record -- see
// reconcileServiceEnumeration's doc comment.
func BrowsingOwnerName(svcType, zone string) string {
	return svcType + "." + zone
}

// RFC 6763 S11 defines five domain-enumeration meta-record prefixes, each rooted at
// "<prefix>._dns-sd._udp.<domain>.": these are a different, earlier query than S9 type
// enumeration -- a browse tool that implements full domain enumeration asks one or more of
// these FIRST, to learn which domain to browse/register in at all, and only then queries
// EnumerationOwnerName (or a specific type's BrowsingOwnerName) against whatever it got back
// -- it never queries those on the originally-entered name directly. A zone with services
// registered via SRP but none of these records is therefore invisible to such a tool even
// though its S9/S4.1 records are otherwise perfectly correct. See
// SRPHandler.reconcileServiceEnumeration for why this registrar publishes a trivial
// self-pointing answer for each (this zone IS its own recommended browsing/registration
// domain, D10: one zone per handler instance) once it has at least one live registration.
const (
	BrowseDomainPrefix              = "b"  // list of domains recommended for browsing
	DefaultBrowseDomainPrefix       = "db" // single recommended default browsing domain
	LegacyBrowseDomainPrefix        = "lb" // "legacy"/"automatic" browsing domain(s)
	RegistrationDomainPrefix        = "r"  // list of domains recommended for registering via Dynamic Update
	DefaultRegistrationDomainPrefix = "dr" // single recommended default registration domain
)

// DomainEnumerationOwnerName returns the RFC 6763 S11 domain-enumeration meta-record owner
// name for one of the *DomainPrefix constants above, in zone: "<prefix>._dns-sd._udp.<zone>".
func DomainEnumerationOwnerName(prefix, zone string) string {
	return prefix + "._dns-sd._udp." + zone
}

// DiffSelfPointingDomainRecord returns the single add or delete instruction needed to bring
// one RFC 6763 S11 domain-enumeration PTR (named by prefix, self-pointing: "this zone IS its
// own recommended browsing/registration domain") from wasPresent to isPresent, or nil if no
// change is needed. Unlike DiffEnumerationRecords, which diffs a whole set of service types,
// every S11 record this registrar ever publishes has the same trivial rdata (the zone itself)
// regardless of which of the five prefixes it is, so there's nothing to diff beyond the
// presence flag itself.
func DiffSelfPointingDomainRecord(prefix, zone string, wasPresent, isPresent bool, ttl uint32) []dns.RR {
	if wasPresent == isPresent {
		return nil
	}
	owner := DomainEnumerationOwnerName(prefix, zone)
	if isPresent {
		rr := &dns.PTR{Hdr: dns.Header{Name: owner, Class: dns.ClassINET, TTL: ttl}}
		rr.Ptr = zone
		return []dns.RR{rr}
	}
	rr := &dns.PTR{Hdr: dns.Header{Name: owner, Class: dns.ClassNONE, TTL: 0}}
	rr.Ptr = zone
	return []dns.RR{rr}
}

// ServiceTypeFromInstanceName extracts the two-label DNS-SD service type (e.g. "_http._tcp")
// from a Service Instance Name shaped "<Instance>.<type>.<proto>.<Domain>." -- RFC 6763 S4.1
// is explicit that the Instance portion always occupies exactly one label, so the type is
// always the second and third labels regardless of how many labels <Domain> itself has. ok is
// false if name has fewer labels than that shape requires.
func ServiceTypeFromInstanceName(name string) (svcType string, ok bool) {
	labels := splitLabels(canonicalName(name))
	// instance, type, proto, trailing empty root label from the split.
	if len(labels) < 4 {
		return "", false
	}
	return labels[1] + "." + labels[2], true
}

// DiffEnumerationRecords returns targeted add/delete instructions to bring zone's Service
// Type Enumeration record from previous to current (both deduplicated, case-insensitively,
// before comparing) -- an RFC 2136 S2.5.1 Add to an RRset for each type newly present in
// current, and an S2.5.4 Delete An RR From An RRSet (single-RR, not a delete-all) for each
// type that was in previous but has dropped out of current. Each add points at "<type>.<zone>"
// -- the canonical two-label service type plus the same domain, per S9's own worked example
// ("_http._tcp.<Domain>"). Returns nil if previous and current describe the same set (no
// update needed at all).
//
// This is deliberately NOT a delete-all-then-reinsert of the whole record: this handler's
// own local knowledge of "what's currently live" is authoritative only for what it has
// itself seen (RFC 9665 clients restate everything on every refresh, so a long-running
// process's local view converges quickly) -- but a delete-all is authoritative over
// everything at that name, including entries a DIFFERENT proxy process, or an earlier run of
// this same one before a restart, wrote for a type this process hasn't relearned about yet.
// A delete-all would silently erase those on every reconcile until every such type's owner
// happens to re-register through the current process -- observed live against a real,
// multi-run shared zone: a second proxy process, restarted after a first had registered one
// service type, wiped that type's still-live entry the moment it reconciled its own (empty)
// view of the world. Targeted single-RR deletes only ever remove a (type, previous) pair
// this function was explicitly told was previously true, so a fresh process's first-ever
// call (previous typically empty) can only ever ADD, never destroy another process's data.
func DiffEnumerationRecords(zone string, previous, current []string, ttl uint32) []dns.RR {
	owner := EnumerationOwnerName(zone)
	prevSet := dedupedSet(previous)
	currSet := dedupedSet(current)

	var records []dns.RR
	for t := range currSet {
		if !prevSet[t] {
			rr := &dns.PTR{Hdr: dns.Header{Name: owner, Class: dns.ClassINET, TTL: ttl}}
			rr.Ptr = t + "." + zone
			records = append(records, rr)
		}
	}
	for t := range prevSet {
		if !currSet[t] {
			rr := &dns.PTR{Hdr: dns.Header{Name: owner, Class: dns.ClassNONE, TTL: 0}}
			rr.Ptr = t + "." + zone
			records = append(records, rr)
		}
	}

	// Deterministic wire order for reproducible tests -- adds and deletes here always
	// target disjoint (type, class) pairs (a type is never both added and deleted in the
	// same call), so their relative order has no effect on the resulting RFC 2136 state.
	sort.Slice(records, func(i, j int) bool {
		return records[i].(*dns.PTR).Ptr < records[j].(*dns.PTR).Ptr
	})
	return records
}

// dedupedSet lower-cases and de-duplicates types into a set, dropping empty entries.
func dedupedSet(types []string) map[string]bool {
	set := make(map[string]bool, len(types))
	for _, t := range types {
		t = canonicalName(t)
		if t != "" {
			set[t] = true
		}
	}
	return set
}

// canonicalName lower-cases a DNS name for comparison/map-keying purposes, leaving the
// trailing dot intact. Duplicated from pkg/srp's identical helper rather than shared --
// see this file's deleteAllRR doc comment for why.
func canonicalName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// splitLabels splits a canonical (already-lowercased, dot-terminated) DNS name into its
// labels, including a trailing empty string for the root label -- e.g.
// "widget._http._tcp.example.com." -> ["widget","_http","_tcp","example","com",""]. A
// presentation-format split (on literal "."), not wire-aware -- fine here since every name
// this package handles has already round-tripped through the dns library's own name
// decompression into presentation form. Duplicated from pkg/srp's identical helper rather
// than shared -- see this file's deleteAllRR doc comment for why.
func splitLabels(name string) []string {
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}
