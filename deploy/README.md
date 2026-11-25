# Deploying the community registrar

The community registrar is a public machine that runs the proxy, the web page
(`cmd/sig0lease-web`) and an IPFS community node. It runs two instances of them:

- **stable**, the one the discovery records name;
- **staging**, where `make deploy` installs a release, which `make promote` then moves to stable.

[`ansible/`](ansible) deploys them from the operator's machine, over ssh. The registrar's name is
in no file of this repository.

| | stable | staging |
|---|---|---|
| Zones: RFC 9664, SRP | `dev.zenr.io.`, `srp.dev.zenr.io.` | `stg.zenr.io.`, `srp.stg.zenr.io.` |
| Plain DNS, UDP and TCP | 8053 | 8054 |
| DNS-over-TLS | 853 | 8853 |
| The page, and DNS-over-HTTPS at `/dns-query` | `https://<registrar>/` | `https://<registrar>:8444/` |
| IPFS community node: swarm port, TCP and QUIC | 4001 | 4002 |
| Its site, at its gateway | `https://<registrar>/ipns/site.dev.zenr.io/` | `https://<registrar>:8444/ipns/site.stg.zenr.io/` |

Each instance's settings are in `registrar_instances`
([group_vars/all.yml](ansible/group_vars/all.yml)). An instance's proxy config is the repository's
`config.yaml` with the changes in `sig0lease_config_overrides`
([roles/sig0lease/defaults/main.yml](ansible/roles/sig0lease/defaults/main.yml)): its zones,
listeners, key and lease stores. Neither instance's zones may lie inside the other's: a name
registered through both would have a lease in each, and the first to end would delete records
the other still renews.

## On the registrar

| | What it is |
|---|---|
| `sig0lease@<instance>.service` | The instance's proxy, run as user `sig0lease-<instance>`. Its systemd unit file is `/etc/systemd/system/sig0lease@.service`, one for both instances. |
| `kubo@<instance>.service` | The instance's IPFS node: kubo, run as user `kubo-<instance>`, from `/opt/kubo/<version>/`, with its repository in `/var/lib/kubo/<instance>/`. kubo's own HTTP gateway serves the community's site. Unit file `/etc/systemd/system/kubo@.service`. |
| `sig0lease-agent@<instance>.service` | The node's agent: the release's `sig0lease-agent`, run as user `sig0lease-agent-<instance>`, with its template `/etc/sig0lease/<instance>/community.yaml` and its keystore `/var/lib/sig0lease-agent/<instance>/`. Through the instance's proxy, it registers the community's site name and keeps its folder up to date with the members' folders ([docs/sig0lease-agent.md](../docs/sig0lease-agent.md), "A name's IPFS node"). Unit file `/etc/systemd/system/sig0lease-agent@.service`. |
| `/opt/sig0lease/<instance>/releases/<time>-<commit>/` | A release: `sig0lease`, `sig0lease-agent`, the page (`web/`), `config.base.yaml` (the repository's `config.yaml`) and `config.yaml` (the instance's). `/opt/sig0lease/<instance>/current` links to the one the instance runs. |
| `/etc/sig0lease/<instance>/keystore/` | The instance's zone key, and nothing else. |
| `/var/lib/sig0lease/<instance>/` | The instance's two lease stores, one per handler. |
| nginx | Port 80: Let's Encrypt's challenges, and a redirect to HTTPS. At each instance's HTTPS port: the page, `/dns-query` passed to the proxy's DNS-over-HTTPS on 127.0.0.1, and `/ipns/<site>/` and `/ipfs/` passed to kubo's gateway on 127.0.0.1, each limited per source address. At each instance's DNS-over-TLS port: TLS ended, DNS passed to the proxy's plain DNS port. |
| certbot | The registrar's certificate, renewed by `certbot.timer`. The account's address is `nginx_acme_email` ([roles/nginx/defaults/main.yml](ansible/roles/nginx/defaults/main.yml)). |

Each user reads only its own instance's files: no proxy reads the other's key or lease stores, and
neither kubo nor the agent reads a proxy's key.

## The operator's machine, once

- Ansible (`brew install ansible` on a Mac; checked with ansible-core 2.18), Go, git and dig.
- An ssh alias `registrar` in `~/.ssh/config`, whose `HostName` is the registrar's DNS name, the
  name its certificate is issued for. `ssh registrar true` must work without a password prompt.

  ```
  Host registrar
      HostName <the registrar's DNS name>
      User root
  ```

- Each instance's zone key in `keystore/server`, and its swarm key in
  `keystore/ipfs/<instance>/swarm.key` (below).

## Keys

**Zone keys.** Each instance's `key` in `registrar_instances` names its key in `keystore/server`:
`dev.zenr.io.` for stable, `stg.zenr.io.` for staging. Its zones must be at that name or below it.
Every deploy and promote copies that key, and no other, into the instance's keystore, and removes
anything else there. The play stops before building anything if `keystore/server` has no key at
that name, or more than one, or if a zone is outside it.

**Swarm keys.** Each instance's IPFS node is in a private swarm, whose key is the community's
secret. Make it once per instance and give it to the members by hand, never in DNS or the
repository:

```bash
mkdir -p keystore/ipfs/<instance>
printf '/key/swarm/psk/1.0.0/\n/base16/\n%s\n' "$(openssl rand -hex 32)" > keystore/ipfs/<instance>/swarm.key
```

A member proves it has the key with a `swarm-mac=` in its instance's TXT record. The agent checks
it before pinning anything ([docs/sig0lease-agent.md](../docs/sig0lease-agent.md), "Who is a
member"). The play stops if the key is missing. Every deploy and promote copies it into kubo's
repository and next to the agent's template, each readable only by its own user. A changed key
restarts kubo. The agent reads it at each check, so it needs no restart.

## Releasing

```bash
make deploy      # this checkout, built and installed on staging
make promote     # the release staging runs, moved to stable
```

`make deploy`:

1. On this machine, it makes staging's config and finds its keys. It then builds the proxy, the
   agent and the page (`make web`) for the registrar's Linux. It refuses uncommitted changes:
   `make deploy ARGS="-e sig0lease_allow_dirty=true"` deploys them, as a release whose name ends
   in `-dirty`.
2. On the registrar, it sets up nginx and the certificate, staging's IPFS node, and staging's
   users, directories and keys. Unless staging already runs the same release (below), it installs
   the release beside the ones before it, points `current` at it, and restarts the proxy and the
   agent.
3. It checks staging on the registrar:
   - staging runs the release;
   - each zone is answered from its authoritative server over UDP, TCP, DNS-over-TLS and
     DNS-over-HTTPS;
   - any other name is refused;
   - kubo runs and the agent is the release's;
   - the site name gives the node's addresses and folder;
   - nginx serves the gateway.

   If any check fails, staging goes back to the release before (on its first release, it stops)
   and the play fails, printing the journal.
4. From this machine, it checks that staging's plain DNS port answers and its page is served. A
   failure here leaves the release running: something between the two machines blocks it.

`make promote`:

1. It checks staging's release again, as in step 3.
2. It copies the release's files into stable's releases, makes stable's config from the release's
   `config.base.yaml`, points `current` at the release, and restarts stable. Nothing is built:
   stable runs the very files staging was checked with.
3. It checks stable as in steps 3 and 4, going back to stable's release before if a check fails.

An instance already runs the same release when its current release holds the same files, byte for
byte, and nothing either service starts with has changed since it started. For the proxy, that
means `current`, the release's `sig0lease` and `config.yaml`, the keystore and
`sig0lease@.service`. For the agent, it means the release's `sig0lease-agent`, `community.yaml`
and `sig0lease-agent@.service`. Then `make deploy` or `make promote` says so and installs,
restarts and checks nothing. Otherwise it says what differs. The same commit and Go build the same
files, byte for byte, so a commit that changes no code they are built from, nor `config.yaml`,
deploys nothing.

Each instance keeps the 5 releases before the one it runs.

- `make deploy-check INSTANCE=stable`: step 3's checks on the release stable runs. It changes
  nothing. `INSTANCE` is `staging` or `stable`; the default is `staging`.
- `make deploy-rollback INSTANCE=stable`: stable goes back to the release before the one it runs,
  then is checked.
- `make deploy ARGS="--tags nginx"`: nginx and the certificate only.

## The IPFS community node

An instance with `community` in its `registrar_instances` entry runs one. Both instances do.

- **kubo** runs in the instance's private swarm. Its swarm port must be reachable from the
  internet, since the members' nodes connect to it. Its config is what
  `ipfs init --profile server,autoconf-off` makes, plus `community_kubo_overrides`
  ([roles/community/defaults/main.yml](ansible/roles/community/defaults/main.yml)). kubo is
  installed from its GitHub release, checked against the SHA-512 sum set there.
- **Its gateway** is kubo's own, on 127.0.0.1, behind nginx. nginx passes on only the site and
  `/ipfs/`. The gateway serves only what the node holds (`Gateway.NoFetch`).
- **The agent** registers `<site>.<update zone>` (`site.dev.zenr.io` on stable) and follows the
  members registered under the subtype `<site>` in the SRP zone. A member unlisted for
  `revoke_after` loses its entry. How it works is in
  [docs/sig0lease-agent.md](../docs/sig0lease-agent.md), "A name's IPFS node".

Every deploy and promote installs kubo, its config and unit, and the agent's template and unit.
kubo restarts when its config, unit or swarm key changed. The agent comes with the release and
restarts with it, or when its template or unit changed.

## Lease stores across releases

Each instance's two lease stores stay with the instance; only releases move between instances. A
name registered through staging stays on staging, and a promote leaves stable's names as they
were.

A proxy stopped for a new release saves its stores, and the new release loads them. If a release
cannot read them because their format changed (the project keeps no compatibility with older
lease-store files), it stops before writing to them. Its checks fail, and the instance goes back
to the release before, with the stores untouched. Such a release therefore fails at
`make deploy`, on staging, before it can reach stable. It can run on an instance only after that
instance's names are removed from the zones and its stores are deleted.

## Discovery records

An SRP client given no registrar finds stable through these records, written by hand with the
`dev.zenr.io.` key. The deploy does not write them, so change them when stable's ports or the
registrar's name change:

```
_dnssd-srp._tcp.dev.zenr.io.      SRV 0 0 8053 <registrar>.
_dnssd-srp-tls._tcp.dev.zenr.io.  SRV 0 0 853  <registrar>.
```

```bash
dig +short _dnssd-srp._tcp.dev.zenr.io SRV _dnssd-srp-tls._tcp.dev.zenr.io SRV
```

Staging has none: its clients are given its address.

## Looking at it

```bash
ssh registrar journalctl -u sig0lease@stable -f          # the proxy's log
ssh registrar journalctl -u kubo@stable -u sig0lease-agent@stable -f   # the IPFS node's
ssh registrar runuser -u sig0lease-stable -- /opt/sig0lease/stable/current/sig0lease --dump /opt/sig0lease/stable/current/config.yaml
```

`--dump` (`--dump-debug` for every record) reads the lease stores and changes nothing. The dump
query over DNS is refused, since `server.diagnostics` is off.

## What protects it

- Each proxy answers only for its zones (`server.forward` off): neither is an open resolver.
- Error replies carry the Extended DNS Error's code and no reason (`server.diagnostics` off).
- nginx limits each source address's DNS-over-HTTPS and gateway requests and its DNS-over-TLS
  connections, per instance ([roles/nginx/defaults/main.yml](ansible/roles/nginx/defaults/main.yml)).
  Behind nginx, a proxy sees every such client as 127.0.0.1.
- Each service runs as its own user, with no capabilities, in systemd's sandbox, and writes only
  its own directories.
- kubo's RPC API listens on 127.0.0.1 without authentication: any user on the registrar can use
  it.
- The plain DNS ports have no limit, and these roles set up no firewall, since the machine's other
  services belong to their own operators. A firewall of its own (an nftables table beside theirs)
  is still to come. Besides theirs and ssh, it would open 80, 443, 853, 8053, 8054, 8444, 8853,
  4001 and 4002.
