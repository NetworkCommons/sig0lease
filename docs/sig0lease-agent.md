# sig0lease-agent

`sig0lease-agent` is the client a machine runs to keep its services and names in DNS. It reads
a template, a YAML file listing registrars and what each registers, and registers:

- hosts and their services through an SRP registrar (RFC 9665), such as this project's proxy
  with `srp_handler`: names people find by browsing (DNS-SD);
- names and their records through this project's proxy with `update_handler` (RFC 9664 with
  `fcfs_naming`): names people type or link, such as a web address, a DNSLink path or a Matrix
  ID.

It then keeps the registrations alive, follows the template as it changes, and deregisters
everything when it stops. Services are described by type: a template names a built-in preset
(`ssh`, `http`, ...) or a type it defines itself, and overrides whatever fields it needs.

`sig0lease-srp-client` and `sig0lease-client name` keep one host or one name registered, on
the same libraries, as their flags say; the agent keeps a template's worth, and follows it.

Code: `client/agent` (template, run loop, probes, state), `cmd/sig0lease-agent`; each host is
a `client/srp` `Host`, each name a `client/rfc9664` `Name` (both on `client.Keeper`), the
`mdns` mirror is `client/mdnsbridge`. Tests: `go test -race ./client/agent` and `make
test-agent` (`tests/test_agent.sh`, against the proxy and a local BIND 9).

## Commands

| Command | Does |
|---|---|
| `sig0lease-agent validate <template>` | Checks the template and lists every problem at once; exit 1 if there is any. |
| `sig0lease-agent plan <template>` | Validates, then shows what `run` would register, registrar by registrar: hosts with their addresses (`auto` resolved now) and services with their TXT, subtypes and probes; names with their addresses and records; which keys exist, hosts renamed earlier, and the hosts and names holding names from an earlier run that `run` frees. Writes nothing. |
| `sig0lease-agent run [-poll-interval=10s] [-probe-interval=30s] <template>` | Validates (and refuses to start on any problem), then registers and keeps registered until Ctrl-C or SIGTERM, which deregister everything. |
| `sig0lease-agent types` | Lists the presets, with their fields, and the complex types. |
| `sig0lease-agent mdns-list <template>` | Shows what the mDNS daemon sees, `*` marking what the template's `mdns` mirror would register. Registers nothing. |

## The template

`agent.yaml` at the top of the repository is a complete example. A smaller one:

```yaml
keystore: keys

registrars:
  - protocol: srp
    domain: srp.dev.zenr.io.
    server: 127.0.0.1:8053
    hosts:
      - name: myhost
        addresses: [auto]
        services:
          - type: ssh               # "myhost ssh" _ssh._tcp port 22, probed over TCP
          - type: http
            port: 8080
            probe: {http: /health}

  - protocol: rfc9664
    zone: dev.zenr.io.
    server: 127.0.0.1:8053
    names:
      - name: mysite                # mysite.dev.zenr.io.
        addresses: [auto]
        records: ['_dnslink TXT "dnslink=/ipns/k51..."']
```

Every field name is checked: one the format does not have is an error, not ignored.

### keystore and types

| Field | Default | Meaning |
|---|---|---|
| `keystore` | `CLIENT_KEYSTORE_DIR` | The directory holding one key per host and name, and the agent's state. A relative path is relative to the template's directory. Left out, the agent uses `CLIENT_KEYSTORE_DIR`, as `sig0lease-client` and `sig0lease-srp-client` do without `-keystore`; with neither, the template is invalid. |
| `types` | none | The template's own service types (see "types" below), for every srp registrar's hosts. |

### registrars

A list, each entry with a `protocol`: `srp` registers hosts, their services and mirrors;
`rfc9664` registers names. Both take:

| Field | Default | Meaning |
|---|---|---|
| `server` | srp: discovery; rfc9664: required | The registrar's `host:port`. srp, empty: found through the `_dnssd-srp._tcp` SRV record (`_dnssd-srp-tls._tcp` with `tls`), closest to `domain` (`docs/siglease_rfc9665.md` §3). RFC 9664 has no discovery. |
| `transport` | `tcp` | `tcp`, `udp` or `tls` (DNS over TLS, opportunistic: the certificate is not checked). |
| `lease` | `1h` | How long the records last unless refreshed. A Go duration, in whole seconds. |
| `key_lease` | `336h` | How long each host's or name's names stay reserved for its key (RFC 9665 §3.4). At least `lease`. |
| `on_stop` | `keep` | What stopping does to the names. `keep`: the records go, the KEYs stay, so the names remain reserved for the agent's keys for `key_lease` (RFC 9665 §3.2.5.5.1; RFC 9664's Case D). `release`: the KEYs go too, and the names are free at once. |

An `srp` registrar also takes:

| Field | Default | Meaning |
|---|---|---|
| `domain` | required | The registration domain. Hosts become `<name>.<domain>`. |
| `resolvers` | `8.8.8.8:53`, `8.8.4.4:53` | Used for discovery, and after a conflict to find which names another key holds. |
| `hosts`, `mirrors` | none | What it registers (below). |

An `rfc9664` registrar also takes:

| Field | Default | Meaning |
|---|---|---|
| `zone` | required | The proxy's zone (`update_handler`'s `upstream_zone`). Names become `<name>.<zone>`. |
| `names` | none | What it registers (below). |

A domain or zone may have one registrar of each protocol, and an rfc9664 name may not be in an
srp domain, or above one: the proxy serves a name through one handler. A registrar may grant
other leases than asked: this project's proxy raises one below its `lease_policy` minimum and
cuts one above its maximum. The agent refreshes on what it grants.

### hosts

Under an `srp` registrar. A host is one SRP identity: one key, one name, its addresses and its
services, sent in one registration.

| Field | Meaning |
|---|---|
| `name` | The host label: letters, digits and hyphens, not starting or ending with a hyphen (RFC 952, RFC 1123; BIND refuses other host names by default). Unique in its registrar, ignoring case. |
| `addresses` | At least one: `auto`, IP addresses, or both. `auto` is this machine's addresses, without loopback and link-local ones, read again at every poll: a change is registered. A literal address may be any but unspecified, multicast or zoned (loopback is allowed, for tests). |
| `services` | The host's services. None: the host is registered alone, with its addresses. |
| `lease`, `key_lease`, `on_stop` | As in the registrar, for this host only. Left out: the registrar's. |

A host's key is created on its first run, as ECDSA P-256 (`K<name>.<domain>.+013+<tag>` in
the keystore), and used from then on: the registrar gives a name to the key that first
registered it, so while a host is registered its key holds its name.

### services

| Field | Meaning |
|---|---|
| `type` | Required: a preset or one of the template's `types:`. |
| `instance` | The instance name. Default `"<host> <type>"`, e.g. `myhost ssh`. Free text, without `.`. |
| `port`, `txt`, `subtypes`, `probe` | Override the type's. |

A service takes every field of its type and overrides what it gives. `txt` merges key by key
over the type's, and `key: null` sends the key alone, as a boolean attribute (RFC 6763 §6.4);
`subtypes` and `probe` replace the type's. An instance name and service type pair may appear
once in a registrar, since it names one instance in the domain.

### types

The presets (`sig0lease-agent types` lists them; they are `client/agent/presets.yaml`):

| Type | Service | Port | TXT, subtypes | Probe |
|---|---|---|---|---|
| `ssh` | `_ssh._tcp` | 22 | | TCP |
| `sftp-ssh` | `_sftp-ssh._tcp` | 22 | | TCP |
| `http` | `_http._tcp` | 80 | | TCP |
| `https` | `_https._tcp` | 443 | | TCP |
| `ipfs-gateway` | `_http._tcp` | 8080 | `path=/ipfs/`, subtype `_ipfs` | TCP |
| `activitypub` | `_activitypub._tcp` | 443 | | TCP |
| `ipp` | `_ipp._tcp` | 631 | `txtvers=1`, `rp=ipp/print` | TCP |

A template's own `types:` take the same fields: `service` (required, `_<name>._tcp` or
`_<name>._udp`), `port`, `txt`, `subtypes` and `probe`. A type without a port needs each of its
services to give one; a type without a probe is never probed. A type may not take a preset's
name (override the preset in the service instead) or a complex type's.

Complex types are code, not data: a template uses them but cannot define them. They make hosts
of their own, so they go under an srp registrar's `mirrors:`, not in a host's services. There is
one, `mdns`.

### Probes

| `probe:` | Passes when |
|---|---|
| `none` | Never probed: always registered. |
| `{tcp: true}` | A TCP connection to the port succeeds. |
| `{http: /path}` | A plain HTTP `GET` of the path answers 2xx or 3xx. A redirect is not followed. |

A probe tries the host's addresses in turn and passes at the first that answers, each attempt
taking at most 5 seconds. A probed service is registered only once a probe passes. It is probed
every 30 seconds (`run -probe-interval`); after 3 failures in a row it is withdrawn, and at the
next pass registered again. The agent logs the first failure, each failure that counts towards
a withdrawal, the withdrawal and the return.

### mirrors: `mdns`

Under an `srp` registrar:

```yaml
    mirrors:
      - type: mdns
        hosts: [mymac.local.]          # or all_hosts: true
        services: [_ssh._tcp, _rfb._tcp]
        socket: /var/run/mDNSResponder # default: this one on macOS, /var/run/mdnsd elsewhere
```

The `mdns` mirror asks a running mDNSResponder, over its client socket, what is advertised on
the link, and registers each selected mDNS host (`mymac.local.` becomes `mymac.<domain>`) with
its addresses and instances, each with its own key in the keystore. An instance the daemon
reports gone is withdrawn; a host with none left is deregistered. It does not follow subtypes,
nor a host's address or TXT changes after its instances first appear. `hosts:` or
`all_hosts: true` is required, not both: copying a whole network into a public zone has to be
asked for. A mirrored host may not be one its registrar's `hosts:` registers: naming one is an
error, and with `all_hosts` they are skipped. One `mdns` mirror per template. Its hosts take
their registrar's `lease`, `key_lease` and `on_stop`.

If the daemon is not there, or refuses (macOS asks the user whether the terminal may find
devices on the local network), the mirror stops, deregisters its hosts, and is started again at
every poll; the failure is logged once.

### names

Under an `rfc9664` registrar. A name is one label right below the zone, held by its own key,
with its addresses and records, registered in one RFC 9664 update signed with that key: the
KEY and the records, on the registrar's leases (the handler's Case A).

| Field | Meaning |
|---|---|
| `name` | The label: letters, digits and hyphens, as a host's. The proxy's `fcfs_naming` lets a key register itself only one label below the zone. Unique in its registrar, ignoring case. |
| `addresses` | `auto`, IP addresses, or both, as a host's: registered as A and AAAA records at the name. Optional. |
| `records` | `"<owner> <type> <data>"`, the owner `@` for the name itself or relative to it (`_dnslink`, `www`), the data in zone-file format. At or below the name, class IN, no KEY or SIG, no A or AAAA at the name (`addresses:` has those). Each once. |
| `lease`, `key_lease`, `on_stop` | As in the registrar, for this name only. Left out: the registrar's. |

A name needs an address or a record. With only `auto` and no address to publish, the agent
registers nothing for it until the machine has one. A name's records the template or the
machine no longer has are withdrawn (Case D: LEASE 0 with them listed, the KEY refreshed) before
the rest is registered again; a record's TTL is the client's 300 seconds, which the proxy may
override (`record_ttl_sec`).

## Running

`run` reads the template again every 10 seconds (`-poll-interval`). A valid change is applied:

- a host or name added is registered; one removed is deregistered as on stopping, then its
  names are freed, whatever `on_stop` says (see "The state file");
- a host or name whose `lease`, `key_lease` or `on_stop` changed is deregistered as on
  stopping, then registered again;
- a host changed is registered again with its new addresses and services, withdrawing the
  services it no longer has; a service whose port and probe are unchanged keeps its probe
  state, any other is registered once a probe passes. A name changed withdraws the records it
  no longer has, then registers the others;
- a registrar whose `server`, `transport`, `resolvers`, `lease`, `key_lease` or `on_stop`
  changed deregisters what it registers, then registers it again; a new `server` or
  `transport` also frees the names held through the old one. Another registrar's hosts and
  names are not touched. A registrar with a new `domain` or `zone` is a new registrar: the old
  one's hosts and names are removed, as above;
- a changed `keystore` deregisters everything, frees the names held with the old keys, then
  registers everything again with the new ones;
- a changed mirror is restarted; the hosts it no longer selects, or all of a removed mirror's,
  have their names freed.

An invalid change is logged, once, with every problem, and the agent goes on with the template
as it was until the file is valid again. Each host's log lines start with its label, each
name's with the name.

Ctrl-C or SIGTERM deregisters every host and name, the mirror's hosts included, and exits 0.
With `on_stop: keep`, the default, the deregistration asks for the `key_lease`: the records go
but the KEYs stay (RFC 9665 §3.2.5.5.1; for a name, Case D with its records), so no other key
can take the names, and the next start gets them back. With `release` it asks for a KEY lease
of 0, a permanent removal (for a name, Case C: the KEY alone, which takes its records): the
names are free, first come, first served. A host name another key takes in the meantime is
renamed on the next start; a name is tried again (below). The mirror's hosts follow their
registrar's `on_stop`, also when the daemon stops advertising them.

## Names another key holds

When an SRP registrar refuses a registration with `YXDOMAIN`, the agent looks up the KEY at the
host name and at each instance name, through `resolvers:`, and renames only the names another
key holds: `myhost` becomes `myhost-2`, then `myhost-3`; an instance likewise. It registers again
under the new names and logs `renamed: now host myhost-2`. If no name turns out to be held, it
logs an error and tries again later; it does not guess.

Renames are kept in the state file (below) and used from the next start on, so a renamed host
does not ask for, and lose, its first name every time. `plan` shows them.

An RFC 9664 name is not renamed: RFC 9665 §3.2.5.2's other choice, giving up, applies. Hosts
and services are found by browsing, so a renamed one is still found; a name is typed or
stored in links, IPNS paths and user IDs, which nothing would point at `mysite-2`. The agent
logs `mysite.dev.zenr.io. is held by another key (YXDOMAIN)` and tries the name again, with a
backoff from 5 seconds up to 5 minutes, then on every refresh. If the holder is an old key of
the agent's own (a keystore deleted or replaced), the name registers by itself once that key's
lease ends. Meanwhile nothing at the name is the agent's: a template change withdraws nothing
from it, and stopping deregisters nothing (the agent logs `another key holds the name`).

## The state file

`sig0lease-agent-state.json`, in the keystore, records each host the agent registered, the
mirror's included, while its names may be held for its key or it was renamed, and each name
while it may be held or has records registered: where it was registered (domain or zone,
registrar, transport, resolvers), what registers it (`hosts:`, a mirror, or `names:`), whether
its names are held, the names a host was renamed to, and a name's records. It is written
atomically and checksummed, with the same code as the proxy's lease snapshots
(`pkg/sealedfile`): a file edited by hand stops the agent at start.

A name's records let a start withdraw those the template lost while the agent was not running
cleanly, such as after a crash, when the stop did not delete them: they are withdrawn before the
name is registered again.

At every start, and after every template change, the agent frees the names of the hosts and
names the file records that the template no longer registers, then forgets them: hosts and
names removed while it was stopped as well as while it ran, hosts a mirror no longer selects,
and hosts and names registered in another domain or zone, through another registrar or from
another keystore. A host gets one deregistration of the host alone with a KEY lease of 0; the
registrar removes the host's service instances with it (RFC 9665 §3.2.5.5.1, "even if the SRP
requester doesn't list them"). A name gets its KEY alone with both leases 0 (Case C), which
deletes every record the key registered. `plan` lists them. A release that fails is logged and
tried again at the next start or template change; until then the names stay held until their
key lease ends. A mirrored host that only stopped being advertised keeps its names, as
`on_stop` says.

To ask for the template's names again, stop the agent and delete the file. The agent then no
longer knows the hosts and names it registered before: the names of those the template no
longer has stay held until their key lease ends.

A keystore changed while the agent was stopped is not seen either. The state file is in the
keystore, and a start reads only the one in the keystore the template names now, so the hosts
and names recorded in the old one are never freed: their names stay held until their key lease
ends (14 days by default). The hosts the template still registers get new keys in the new
keystore, while the old keys still hold their names, so they are renamed (`myhost-2`); the new
state file keeps the rename, also once the old keys' lease has ended, until the file is deleted.
The names the template still registers are tried again until the old keys' lease ends. To
change keystores, change `keystore:` while the agent runs, which frees the hosts and names with
the old keys before registering with the new ones, or move the directory itself, keys and state
file together.

Run one agent per keystore.

## Not yet

- RFC 9664 names need this project's proxy: the lease is RFC 9664's, but a name held by its key
  (`fcfs_naming`) is the proxy's.
- Code handlers for types needing more than data (IPFS DNSLink from a running node, Matrix and
  XMPP SRV), and DNS-over-HTTPS, are later steps.
- Probes are plain TCP and HTTP; names have none.
