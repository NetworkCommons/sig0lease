# DNS-SD discovery records

This page lists every record a DNS-SD or SRP client looks up to find services or a registrar.
For each one it says where the record must be for a client to find it, and who writes it in
this deployment. Mostly the answer is not "the zone the proxy serves": a client only looks
there once it already knows that zone's name.

The records are defined in RFC 6763 (DNS-SD), RFC 9665 (SRP) and RFC 8765 (DNS Push); all
three are in `sig0lease_docs/standards`.

## Four kinds of domain

A client goes through up to four domains on its way to a service or a registrar:

- **Starting domain.** A domain the client knows before any discovery. RFC 6763 §11 names four
  sources: the DHCP Domain option (15) and Domain Search option (119), the IPv6 Router
  Advertisement DNSSL option, and the reverse-mapping name of the client's subnet (for
  192.168.12.34/16, `0.0.168.192.in-addr.arpa.`). Then there is `local.` (multicast). macOS
  uses every domain in the resolver's search list (`mDNSCore/uDNS.c`, `SearchList`).
- **Browsing domain.** Where the per-type PTRs are (RFC 6763 §4.1). Here: `srp.dev.zenr.io.`
- **Registration domain.** The domain an SRP client names its host and services under (RFC 9665
  §3.1.1). Here it is the same as the browsing domain: the `srp_handler`'s `upstream_zone`,
  `srp.dev.zenr.io.`
- **Zone apex.** The owner of the SOA record of the zone that holds a name. A client finds it
  with SOA queries, removing one label at a time (RFC 8765 §6.1). Here: `zenr.io.` There is no
  zone cut at `dev.zenr.io.` or `srp.dev.zenr.io.` (`dig SOA srp.dev.zenr.io.` returns the
  `zenr.io.` SOA in the authority section).

A client that is told the browsing or registration domain directly (`-domain`,
`dns-sd -B _http._tcp srp.dev.zenr.io`) skips the starting domain.

## The records

`<S>` is a starting domain, `<B>` a browsing domain, `<R>` a registration domain, and `<Z>` a
zone apex.

| Name | Type → points at | Defined in | Belongs at | Written here by | With nothing registered | When the proxy stops |
|---|---|---|---|---|---|---|
| `b._dns-sd._udp.<S>` | PTR → domains to browse (a list) | RFC 6763 §11 | the starting domain | proxy: one PTR to itself at `upstream_zone`, while `advertise_browse_domain` (default on) | present | stays |
| `db._dns-sd._udp.<S>` | PTR → the default browsing domain (one) | RFC 6763 §11 | the starting domain | same as `b` | present | stays |
| `lb._dns-sd._udp.<S>` | PTR → domains to browse automatically, without a domain from the user (a list) | RFC 6763 §11 | the starting domain | same as `b` | present | stays |
| `r._dns-sd._udp.<S>` | PTR → domains to register in (a list) | RFC 6763 §11, used by RFC 9665 §3.1.1 | the starting domain | proxy: one PTR to itself at `upstream_zone`, while `advertise_registration_domain` (default off) | present when on | stays |
| `dr._dns-sd._udp.<S>` | PTR → the default registration domain (one) | RFC 6763 §11, used by RFC 9665 §3.1.1 | the starting domain | same as `r` | present when on | stays |
| `_services._dns-sd._udp.<B>` | PTR → `<type>.<B>`, one per service type | RFC 6763 §9 | the browsing domain | proxy, from the lease store (`reconcileServiceEnumeration`) | absent | stays |
| `<type>.<B>`, e.g. `_http._tcp.<B>` | PTR → `<instance>.<type>.<B>` | RFC 6763 §4.1 | the browsing domain | the SRP client (forwarded by the proxy) | absent | stays until the lease expires on a running proxy |
| `<sub>._sub.<type>.<B>` | PTR → `<instance>.<type>.<B>` | RFC 6763 §7.1 | the browsing domain | the SRP client | absent | same |
| `<instance>.<type>.<B>` | SRV → host and port, TXT | RFC 6763 §5, §6 | the browsing domain | the SRP client | absent | same |
| `<host>.<R>` | A/AAAA, KEY | RFC 9665 §3.2.1 | the registration domain | the SRP client | absent | same (the KEY's own lease is longer) |
| `_dnssd-srp._tcp.<Z>` | SRV → registrar host and port | RFC 9665 §3.1.1, §10.4 | the zone apex; also below it for this repo's clients (see below) | the operator, by hand; the proxy never writes it | present | stays |
| `_dnssd-srp-tls._tcp.<Z>` | SRV → registrar host and DNS-over-TLS port | RFC 9665 §3.1.1, §10.4 | same as above | same as above | present | stays |
| `_dns-update._udp.<Z>` | SRV → an RFC 2136 primary | RFC 9665 App. B | the zone apex | the operator, if at all; the proxy never writes it | — | — |
| `_dns-push-tls._tcp.<Z>` | SRV → a DNS Push server | RFC 8765 §6.1 | the zone apex | the operator, if at all; the proxy has no DNS Push | — | — |

"Present" or "absent" with nothing registered: a DNS name has no "PTR pointing at nothing".
A name with no PTR answers NODATA (or NXDOMAIN if nothing at all is below it). The §11 records
say where to browse or register, which stays true with nothing registered. An empty browsing
domain just gives an empty browse. The §9 record lists types that are registered, so with no
types it has no PTRs. Like any record, all of these persist after the proxy stops (see
[When the proxy stops](#when-the-proxy-stops)).

`b`, `lb` and `r` can hold several PTRs, so another domain's PTR can sit next to ours. RFC 6763
§11 defines `db` and `dr` as a single default, and two PTRs there make the client pick one.

Apple's `dnssd-proxy` (mDNSResponder's `ServiceRegistration/dnssd-proxy.c`, in
`dnssd_hardwired_setup_for_served_domain`) answers "no such record" for `_dns-update._udp`,
`_dns-update-tls._tcp`, `_dns-llq._udp`, `_dns-llq-tls._tcp` and `_dns-query-tls._udp` at the
domain it serves. It does the same for `lb`, `b` and `db`, "to avoid the response like
`lb._dns-sd._udp.openthread.thread.home.arpa. PTR openthread.thread.home.arpa.`", which is
exactly the self-pointing record this proxy publishes; the code gives no reason beyond that
comment. Instead it answers `lb` at a starting domain, the reverse-mapping name of each of its
subnets: `lb._dns-sd._udp.<subnet>.in-addr.arpa. PTR <served domain>`
(`dnssd_hardwired_lbdomains_setup`). The proxy is itself a unicast DNS server (port 53, plus
DNS over TLS for DNS Push). It claims all of `in-addr.arpa.` and `ip6.arpa.` and answers this
record from an in-memory list. Nothing is written to a zone or sent over mDNS, so only clients
that use the proxy's host as their resolver see it. The refusal only concerns names that an
Apple `dnssd-proxy` answers for, typically a Thread border router's own domain. It has no effect
on records in a zone that an ordinary authoritative server answers, such as `zenr.io.`. A
self-pointing `lb` does no harm to a Mac: demo D4 (`docs/demo.md`) uses it on macOS 26.7.

## Browsing: which records a client asks for, and where

A DNS-SD client such as macOS `dns-sd -B _http._tcp` (no domain given) does this:

1. For each starting domain `<S>`, it asks for `lb._dns-sd._udp.<S>`. mDNSResponder asks at every
   search domain other than `local.`. It asks `lb` while an application browses with no domain,
   `b`/`db`/`lb` while one lists browsing domains (`dns-sd -F`), and `r`/`dr` while one lists
   registration domains (`dns-sd -E`) (`mDNSShared/uds_daemon.c`, `uDNS_StartWABQueries`).
2. It browses every domain `<B>` those PTRs name: `<type>.<B>` PTR, or
   `_services._dns-sd._udp.<B>` first to see which types exist.
3. It resolves each instance's SRV and TXT, then the host's A/AAAA.

So a §11 record helps a client whose starting domain is the record's own domain. The proxy
publishes its records at its own zone, pointing at its own zone, and that only helps a client
that already has `srp.dev.zenr.io.` as a starting domain, as demo D4 sets up with
`networksetup -setsearchdomains Wi-Fi srp.dev.zenr.io`.

The main use of §11 is a record at a domain many clients start from, pointing at ours. A laptop
on a network whose DHCP hands out `zenr.io` as the search domain asks
`lb._dns-sd._udp.zenr.io.`. For the laptop to find the services registered through this proxy,
that name needs a PTR to `srp.dev.zenr.io.`, next to whatever PTRs others put there (`b` and
`lb` can hold several). The zone's operator would add:

```
lb._dns-sd._udp.zenr.io.  PTR  srp.dev.zenr.io.
b._dns-sd._udp.zenr.io.   PTR  srp.dev.zenr.io.
```

The same goes for a network's reverse-mapping domain (RFC 6763 §11's
`lb._dns-sd._udp.0.0.168.192.in-addr.arpa.`). For a private subnet such as 192.168.0.0/16 no
public server holds that name, so only a resolver on the client's own network can answer it.
Apple's `dnssd-proxy` works this way (see the note under "The records"): clients that use it as
their resolver get `lb` for each of its subnets' reverse names, answered from memory. For this
proxy, that would be a resolver on the client's network answering
`lb._dns-sd._udp.<subnet>.in-addr.arpa. PTR srp.dev.zenr.io.`. Without one, the pointer has to
be in a zone the client already searches: `zenr.io.` above, or `srp.dev.zenr.io.` itself, as in
demo D4.

The proxy writes §11 records only at its own `upstream_zone`, so of these pointers it writes only
the one at `srp.dev.zenr.io.` itself. The two at `zenr.io.` are for that zone's operator to add,
and the reverse-mapping answer for whoever runs the network's resolver.

## Registration: which records an SRP client asks for, and where

RFC 9665 §3.1.1, for a full-featured host:

1. Get a registration domain `<R>`: configured, or the default from `dr._dns-sd._udp.<S>`, or
   one the user picks from `r._dns-sd._udp.<S>`.
2. Find the zone apex `<Z>` of the zone that holds names under `<R>` with SOA queries (RFC 8765
   §6.1).
3. Ask for `_dnssd-srp._tcp.<Z>` SRV (`_dnssd-srp-tls._tcp.<Z>` with TLS). Its target and port are
   the registrar.

The SRV is at the apex `<Z>`, not at `<R>`, unless the registration domain is itself a zone apex.
For `srp.dev.zenr.io.` the apex is `zenr.io.`, so a client that follows the RFC asks for
`_dnssd-srp._tcp.zenr.io.` and nothing else: an SRV at `srp.dev.zenr.io.` is not seen by such a
client. There are two ways to give it an SRV it finds:

- **An SRV at the apex:** `_dnssd-srp._tcp.zenr.io. SRV 0 0 8053 <registrar host>.` The apex is
  shared, though: one SRV name serves every registration domain in `zenr.io.`. It would also send
  `dev.zenr.io.` clients to this registrar, and RFC 9665 has no way to give two domains in one
  zone different registrars. Several SRV records at that name are alternatives for the same
  service, not one per domain.
- **A zone cut at `srp.dev.zenr.io.`:** delegate it as its own zone (SOA and NS), so that it is
  its own apex and its `_dnssd-srp._tcp` SRV is at the apex. This needs the `zenr.io.` operator
  and a server that serves the new zone.

This repo's SRP clients (`sig0lease-srp-client` and the agent's SRP templates) do more than
the RFC by default: they look for the SRV at the registration domain first, then at each parent
name up to the apex, and the first one found wins (`client/srp/discovery.go`,
`DiscoveryClosest`, issue #46). `sig0lease-srp-client -discovery=apex` keeps the RFC's
apex-only lookup. For
`srp.dev.zenr.io.` they look at `srp.dev.zenr.io.`, `dev.zenr.io.`, then `zenr.io.`. An SRV at
`dev.zenr.io.`, published for a registrar that serves `dev.zenr.io.`, is found before one at the
apex, so these clients would register with that registrar. The demos give the registrar
explicitly (`server: 127.0.0.1:8053` in `demo/*.yaml`, `-server` in `docs/srp-live-demo.md`):
the demo proxy runs on the presenter's machine and no SRV names it. Publishing
`_dnssd-srp._tcp.srp.dev.zenr.io.`, for a proxy clients can reach, would make this repo's clients
find it, but not a client that follows only the RFC.

Constrained hosts (RFC 9665 §3.1.2) look up none of this. They register under
`default.service.arpa.` with a registrar address from the network, and the proxy rewrites the
names to `upstream_zone` (`docs/siglease_rfc9665.md` §9).

## What the proxy writes, and when

Under its `upstream_zone`, the `srp_handler` writes:

- **The five §11 names**, each a PTR to `upstream_zone` itself. `b`/`db`/`lb` are there while
  `srp_handler.advertise_browse_domain` is set (default `true`), and `r`/`dr` while
  `srp_handler.advertise_registration_domain` is set (default `false`: `r`/`dr` invite direct
  RFC 2136 registration, a policy choice). The config is compared with the zone on every
  reconciliation pass (every 30 s, the first 30 s after start), one PTR query per name, and the
  proxy adds or deletes its PTR where they differ. A PTR at those names that points at another
  domain is left alone. Turning a setting off and starting the proxy deletes what an earlier run
  published within 30 s (`SRPHandler.reconcileDomainEnumeration`, `docs/siglease_rfc9665.md`
  §10).
- **`_services._dns-sd._udp.<upstream_zone>`**, one PTR per service type registered through it
  (`SRPHandler.reconcileServiceEnumeration`, `docs/siglease_rfc9665.md` §10).
- **What SRP clients register**: host A/AAAA and KEY, instance SRV/TXT, and the per-type and
  subtype PTRs.

It does not write the `_dnssd-srp._tcp`/`_dnssd-srp-tls._tcp` SRV or the registrar's own
address record (no code does; the operator publishes them), §11 records at any other domain, or
`_dns-update._udp`.

## When the proxy stops

Stopping the proxy removes nothing:

- The §11 records stay. They say the domain is one to browse (or register) in, which a restart
  does not change.
- Records registered by clients stay. Their leases stay in the lease-store snapshot, and the
  next run removes any that expired in the meantime. If the proxy never runs again, nothing
  removes them.
- The `_dnssd-srp._tcp` SRV stays. The operator wrote it, and a stop is not a decommissioning.
  Removing it on every stop would also send clients elsewhere, or nowhere, during a restart. A
  crash would skip any removal anyway.

To take the deployment down for good:

1. Start the proxy with both `advertise_browse_domain` and `advertise_registration_domain` set
   to `false`, and let it run past one pass (30 s). That deletes the five §11 records.
2. Let the leases expire with the proxy running, or have the clients deregister. The §9 record
   goes with the last registered type.
3. Remove the `_dnssd-srp._tcp` SRV (and `-tls`) by hand.

`demo/leftovers.sh` lists what is left under the domain and which store, if any, still holds
each name.

Two proxies on one zone with the same settings agree on the §11 records: each compares the zone
with the same config, so whichever pass comes first makes a change and the other then finds
nothing to do. With different settings they would undo each other's records on every pass.
Several proxies on one zone are not supported anyway (`docs/siglease_rfc9665.md` §11): each
process has its own lease store and its own in-memory name locks.

## Checking the zone

What the zone holds changes with every run and every operator edit, so this page does not list
it. To see the discovery records a client meets from `srp.dev.zenr.io.` up to the apex, asking
the zone's primary server:

```bash
ns=$(dig +short SOA zenr.io. | cut -d' ' -f1)
for d in zenr.io dev.zenr.io srp.dev.zenr.io; do
  for p in b db lb r dr; do echo "$p._dns-sd._udp.$d: $(dig +short @"$ns" $p._dns-sd._udp.$d PTR)"; done
  for s in _dnssd-srp._tcp _dnssd-srp-tls._tcp; do echo "$s.$d: $(dig +short @"$ns" $s.$d SRV)"; done
done
```

`demo/leftovers.sh` lists every record under a domain and which lease store, if any, holds it.
