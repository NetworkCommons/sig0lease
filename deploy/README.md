# Deploying the community registrar

The community registrar is a public machine that runs the proxy, for anyone to register through,
with the demo's page (docs/demo.md, D6) in front. It runs two instances of it:

- **stable**, the one the zones' discovery records name, which the community uses;
- **staging**, where a release runs first, before it is promoted to stable.

An instance may also have a community node: D3's (docs/demo.md), always on, with its gateway
behind the registrar's web server ("The community node"). Staging has one.

[`ansible/`](ansible) deploys them from the operator's machine, over ssh: nothing is installed on
the registrar to deploy it, and its name is in no file of this repository.

| | stable | staging |
|---|---|---|
| Zones: RFC 9664, SRP | `dev.zenr.io.`, `srp.dev.zenr.io.` | `stg.zenr.io.`, `srp.stg.zenr.io.` |
| Plain DNS, UDP and TCP | 8053 | 8054 |
| DNS-over-TLS | 853 | 8853 |
| The page, and DNS-over-HTTPS at `/dns-query` | `https://<registrar>/` | `https://<registrar>:8444/` |
| Community node: swarm port, TCP and QUIC; the site at its gateway | none | 4002; `https://<registrar>:8444/ipns/site.stg.zenr.io/` |

These, the proxy's DNS-over-HTTPS listener behind nginx and the name of its key are each
instance's settings in `registrar_instances` ([group_vars/all.yml](ansible/group_vars/all.yml)).
Every zone the registrar serves is set there; none comes from `config.yaml`. Each instance's
zones lie outside the other's: with one inside the other, a name could be registered through
both, and each instance would delete records the other still renews.

| On the registrar | What it is |
|---|---|
| `sig0lease@stable.service`, `sig0lease@staging.service` | each instance's proxy, as a user of its own, `sig0lease-<instance>`: plain DNS at the instance's port, for everyone; DNS-over-HTTPS in plain HTTP on 127.0.0.1, for nginx only |
| `/opt/sig0lease/<instance>/releases/<time>-<commit>/` | a release: the proxy (`sig0lease`), the agent a community node runs (`sig0lease-agent`), the page (`web/`), `config.base.yaml` (the repository's `config.yaml` at the commit) and `config.yaml` (the instance's config, made from it); `/opt/sig0lease/<instance>/current` links to the one the instance runs |
| `/etc/sig0lease/<instance>/keystore/` | the instance's key, from `keystore/server` on the operator's machine, and nothing else, readable by the instance's user only ("The zones' keys") |
| `/var/lib/sig0lease/<instance>/` | the instance's lease stores, readable by the instance's user only |
| nginx | port 80: Let's Encrypt's challenges, and a redirect to stable's HTTPS. For each instance that has a release, at its ports: HTTPS, with the page, opened on the instance's zones, and `/dns-query`, passed to the instance's DNS-over-HTTPS, with a request rate per source address; DNS-over-TLS, its TLS ended here and the DNS-over-TCP inside passed to the instance's plain DNS port, with a number of connections per source address |
| `kubo@<instance>.service`, `sig0lease-agent@<instance>.service` | an instance's community node, as users of their own, `kubo-<instance>` and `sig0lease-agent-<instance>`: kubo, from `/opt/kubo/<version>/`, with its repository in `/var/lib/kubo/<instance>/`; the release's agent, with its template, `/etc/sig0lease/<instance>/community.yaml`, the swarm key, `/etc/sig0lease/<instance>/swarm.key`, and its keystore, `/var/lib/sig0lease-agent/<instance>/` ("The community node") |
| certbot | the registrar's certificate, renewed by `certbot.timer`; nginx reloads it. Its Let's Encrypt account has the address in `nginx_acme_email` ([roles/nginx/defaults/main.yml](ansible/roles/nginx/defaults/main.yml)) |

An instance's config is `config.base.yaml` with the changes in `sig0lease_config_overrides`
([roles/sig0lease/defaults/main.yml](ansible/roles/sig0lease/defaults/main.yml)): the instance's
zones and listeners, and where its key and lease stores are. Everything else is `config.yaml`'s:
the lease policy, `server.diagnostics` and `server.forward` off. Change `config.yaml`, the
overrides or `registrar_instances`, and deploy.

## The operator's machine, once

- Ansible (`brew install ansible` on a Mac; the playbooks were checked with ansible-core 2.18),
  Go, git and dig.
- An ssh alias `registrar` in `~/.ssh/config`, whose `HostName` is the registrar's DNS name,
  for which its certificate is issued:

  ```
  Host registrar
      HostName <the registrar's DNS name>
      User root
  ```

  `ssh registrar true` must work without a password prompt.
- In `keystore/server`, each instance's key ("The zones' keys").
- In `keystore/ipfs/<instance>/swarm.key`, the swarm key of each instance that has a community
  node ("The community node").

## The zones' keys

Each instance has one key, the one in `keystore/server` at the name its `key` in
`registrar_instances` gives: `dev.zenr.io.` for stable, `stg.zenr.io.` for staging. Its zones are
at that name or below it.

Every deploy and promote copies that key, and no other, into the instance's keystore on the
registrar, and removes whatever else is there, a key it replaces included. Before it builds or
switches anything, the play stops if `keystore/server` has no key at that name, or more than one,
or if one of the instance's zones is not at that name or below it. An instance loads its key when
it starts: a deploy restarts staging, a promote restarts stable.

## Releasing

```bash
make deploy      # this checkout, built and installed on staging
make promote     # the release staging runs, moved to stable
```

`make deploy`:

1. On this machine: makes staging's config and finds its key and its swarm key, then builds the proxy and the agent for the registrar's Linux from
   the checkout, refusing uncommitted changes (`make deploy ARGS="-e
   sig0lease_allow_dirty=true"` deploys them, as a release whose name ends in `-dirty`), and the
   page (`make web`).
2. On the registrar: installs nginx and gets the certificate the first time, prepares and starts
   staging's community node ("The community node"), and gives staging its user, directories, key
   and service. Unless staging runs the same release already (below), it installs the release in
   staging beside the ones before it, points staging's `current` at it, and restarts staging and
   its community node's agent.
3. Checks, on the registrar: staging runs the release; each of its zones is answered from its
   authoritative server over UDP, TCP, DNS-over-TLS and DNS-over-HTTPS; any other name is
   refused; its community node runs, its agent is the release's, the community's site name gives
   the node's addresses and the community's folder, and nginx serves the node's gateway. When a check fails, staging goes back to the release before (on its first release,
   it stops), and the play fails with the failed release's journal.
4. Checks from this machine that staging's plain DNS port answers and its page is served. A
   failure here leaves the release running: something between the two machines blocks them.

Staging runs the same release already when the release it runs holds the same files, byte for
byte (the proxy, the page, `config.base.yaml`, and staging's config made from it), and its proxy
started after the last change to anything it starts with: that release's program and config,
`current`, staging's key and the service unit; and its community node's agent, after the release's
agent, its template and its unit. `make deploy` then says so, and installs, restarts
and checks nothing (`make deploy-check` runs step 3's checks). Otherwise it says what differs.
The same code and Go build the same proxy and page, byte for byte, so a commit that changes
neither, nor `config.yaml`, deploys nothing. Neither records the commit: the release's name does.

`make deploy` installs on staging only. Try the release there: the demos take staging's zones
(docs/demo.md, "Running a demo"), and its page is at `https://<registrar>:8444/`.

```bash
REGISTRAR=<registrar>:8054 UPDATE_DOMAIN=stg.zenr.io SRP_DOMAIN=srp.stg.zenr.io demo/run.sh
REGISTRAR=<registrar>:8054 UPDATE_DOMAIN=stg.zenr.io SRP_DOMAIN=srp.stg.zenr.io DOH=https://<registrar>:8444 demo/web.sh
REGISTRAR=<registrar>:8054 UPDATE_DOMAIN=stg.zenr.io SRP_DOMAIN=srp.stg.zenr.io COMMUNITY_GATEWAY=https://<registrar>:8444 demo/ipfs.sh member
```

`demo/web.sh` takes staging's DNS-over-HTTPS with `DOH`: without it, the page asks
`https://<registrar>/`, which is stable's.

Then `make promote`:

1. Checks staging's release again, as in step 3.
2. Copies its files into stable's releases, makes stable's config from the release's own
   `config.base.yaml`, points stable's `current` at it, and restarts stable. Nothing is built:
   stable runs the very files staging was checked with.
3. Checks stable as in steps 3 and 4, going back to stable's release before when a check fails.

When stable runs the same release already, as `make deploy` tells for staging, `make promote`
says so after step 1, and installs, restarts and checks nothing.

Each instance keeps the 5 releases before the one it runs.

- `make deploy-check INSTANCE=stable`: the checks of step 3, on the release stable runs; changes
  nothing. `INSTANCE` is `staging` or `stable`, default `staging`.
- `make deploy-rollback INSTANCE=stable`: stable back to the release before the one it runs,
  then its checks.
- `make deploy ARGS="--tags nginx"`: nginx and the certificate only.

## The community node

An instance with `community` in its `registrar_instances` entry has a community node: D3's
(docs/demo.md), on the registrar, always on and reachable from anywhere. Staging has one; stable
has none.

- **kubo**, in a private swarm of its own, at the instance's swarm port, open to the internet. A
  member's node, behind its home's NAT, connects to it: the node never needs to reach a member's.
  Its config is what `ipfs init --profile server,autoconf-off` makes, with D3's settings for a
  member's node and the instance's listeners (`community_kubo_overrides`,
  [roles/community/defaults/main.yml](ansible/roles/community/defaults/main.yml)). kubo is its
  GitHub release, checked against its SHA-512 sum, at the version set there.
- **The agent**, the release's `sig0lease-agent`, which registers through the instance's proxy
  and asks it for the members: the instances of `_ipfs-member._tcp` that members register in the
  instance's `srp_handler` zone under the subtype `<site>` (staging:
  `site._sub._ipfs-member._tcp.srp.stg.zenr.io`). It has the node pin each folder a member gives,
  whole, and keeps a folder with an entry for each member, its folder once pinned, which
  `<site>.<update zone>` (`site.stg.zenr.io`) gives, with the node's addresses, which the
  members' nodes connect to. A member not listed for `revoke_after` (staging: 10 minutes) has its
  entry removed and its folder unpinned. It keeps its names when it stops, for a restart, and
  its folder: after one, each entry stays until its member is listed again, or `revoke_after`.
- **The gateway**, behind nginx at the instance's HTTPS port, at
  `https://<registrar>:8444/ipns/site.stg.zenr.io/` for staging. nginx passes on only that site
  and `/ipfs/`, the CIDs its pages link to, with a request rate per source address; the gateway
  serves only what the node holds (`Gateway.NoFetch`), and reads the site's name through the
  instance's proxy, which answers from the zone's authoritative server, not from a resolver's
  cache.

The swarm key is the community's secret: the node and its members' nodes have it, and nothing
else. A member's agent proves it has it: its instance's TXT record gives, with its folder, a
`swarm-mac=` made with the key, which the community node's agent checks before it pins anything
(docs/sig0lease-agent.md). Make it once, on this machine, and give it to the members by hand,
never in DNS or the repository:

```bash
mkdir -p keystore/ipfs/staging
printf '/key/swarm/psk/1.0.0/\n/base16/\n%s\n' "$(openssl rand -hex 32)" > keystore/ipfs/staging/swarm.key
```

The play stops before it builds anything when such an instance has no swarm key there. Every
deploy and promote copies it into the node's repository, readable by the node's user only, and
next to the agent's template, readable by the agent's user only (the agent reads it at each
check), and installs kubo, the users, the node's config and the agent's template, then starts
the node, restarting it when any of those changed. The agent comes with the release: its activation
restarts the agent, and the release's checks cover the node (step 3).

A member's node finds the community node at `/dnsaddr/site.stg.zenr.io/p2p/<the node's ID>`:
`dig +short TXT _dnsaddr.site.stg.zenr.io` gives the ID at the end of each address. docs/demo.md,
D3, "The registrar's community node", runs members alone.

Stable gets one with a `community` entry of its own and a swarm key, at the next promote.

## Lease stores across releases

Each instance keeps its lease stores, in `/var/lib/sig0lease/<instance>/`; only releases move
between instances. A name registered through staging therefore stays on staging, and promoting
leaves stable's names as they were.

A proxy stopped for a new release saves its stores, and the new release loads them. A release
that cannot read them, because their format changed (the project keeps no compatibility with
older lease-store files), stops before writing to them: its checks fail, and the instance goes
back to the release before, on the untouched stores. Staging meets such a release first, with
its own stores. Such a release cannot be promoted as it is: stable's names are removed from the
zones first, and stable starts with empty stores, as at the first promote.

## Discovery records

An SRP client given no registrar finds one in DNS (RFC 9665; docs/siglease_rfc9665.md,
"Discovery"): it asks for `_dnssd-srp._tcp` (over DNS-over-TLS, `_dnssd-srp-tls._tcp`) at its
domain and at each name above it, the closest record winning. One record per transport at
stable's RFC 9664 zone names stable for both its zones:

```
_dnssd-srp._tcp.dev.zenr.io.         SRV 0 0 8053 <registrar>.
_dnssd-srp-tls._tcp.dev.zenr.io.     SRV 0 0 853  <registrar>.
```

The deploy does not write them: they are written once, with the zones' key, and change only with
stable's zones or ports. `dig +short _dnssd-srp._tcp.dev.zenr.io SRV` shows one.

Staging has none: it is reached by its address only. A client of its zones is given that
address, as the demos are with `REGISTRAR`; given none, it finds a registrar only if a record at
`zenr.io.` names one.

## The first promote

Until the first promote, the registrar's stable is a proxy started by hand on port 8053, serving
`dev.zenr.io.` with both handlers, and staging runs beside it.

The first promote stops before switching anything while another process holds port 8053, and
names it. With that proxy's operators:

1. Remove from the zones what it registered: stop its clients so that they deregister, or delete
   their records with the zones' key. `demo/leftovers.sh` lists what is in the zones that no
   lease store holds.
2. Stop it.
3. `make promote`. Stable's lease stores start empty; the old proxy's files are left where they
   are. Its SRP clients registered in `dev.zenr.io.`; stable's SRP domain is `srp.dev.zenr.io.`.

## Looking at it

```bash
ssh registrar journalctl -u sig0lease@stable -f      # stable's log
ssh registrar runuser -u sig0lease-stable -- /opt/sig0lease/stable/current/sig0lease --dump /opt/sig0lease/stable/current/config.yaml
```

`--dump` (`--dump-debug` for every record) reads the lease stores and changes nothing. The dump
query over DNS is refused, as `server.diagnostics` is off.

## What protects it

- Each proxy answers only for its zones (`server.forward` off): neither is an open resolver.
- Error replies carry the Extended DNS Error's code and no reason (`server.diagnostics` off).
- nginx limits each source address's DNS-over-HTTPS requests and DNS-over-TLS connections, per
  instance ([roles/nginx/defaults/main.yml](ansible/roles/nginx/defaults/main.yml)). Behind
  nginx, a proxy sees every such client as 127.0.0.1.
- Each proxy runs as a user of its own, with no capabilities, in systemd's sandbox: neither can
  read the other's key or lease stores, and each writes only its own stores. So does each
  community node's kubo and agent, which read neither the proxies' keys nor each other's.
- A community node's gateway serves only what the node holds; nginx passes on only the
  community's site and `/ipfs/`. kubo's RPC API listens on 127.0.0.1 without authentication: any
  user on the registrar can use it.
- The plain DNS ports themselves have no limit, and the machine no firewall from these roles: its
  other services belong to their own operators, and a firewall of its own (an nftables table
  beside theirs) is still to come. It would open, besides theirs and ssh: 80, 443, 853, 8053,
  8054, 8444 and 8853, and staging's community node's swarm port, 4002.
