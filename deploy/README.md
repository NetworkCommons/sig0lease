# Deploying the community registrar

The community registrar is a public machine that runs the proxy, for anyone to register through,
with the demo's page (docs/demo.md, D6) in front. It runs two instances of it:

- **stable**, the one the zones' discovery records name, which the community uses;
- **staging**, where a release runs first, before it is promoted to stable.

[`ansible/`](ansible) deploys them from the operator's machine, over ssh: nothing is installed on
the registrar to deploy it, and its name is in no file of this repository.

| | stable | staging |
|---|---|---|
| Zones: RFC 9664, SRP | `dev.zenr.io.`, `srp.dev.zenr.io.` | `stg.zenr.io.`, `srp.stg.zenr.io.` |
| Plain DNS, UDP and TCP | 8053 | 8054 |
| DNS-over-TLS | 853 | 8853 |
| The page, and DNS-over-HTTPS at `/dns-query` | `https://<registrar>/` | `https://<registrar>:8444/` |

These, and the proxy's DNS-over-HTTPS listener behind nginx, are each instance's settings in
`registrar_instances` ([group_vars/all.yml](ansible/group_vars/all.yml)). Every zone the
registrar serves is set there; none comes from `config.yaml`. Each instance's zones lie outside
the other's: with one inside the other, a name could be registered through both, and each
instance would delete records the other still renews.

| On the registrar | What it is |
|---|---|
| `sig0lease@stable.service`, `sig0lease@staging.service` | each instance's proxy, as user `sig0lease`: plain DNS at the instance's port, for everyone; DNS-over-HTTPS in plain HTTP on 127.0.0.1, for nginx only |
| `/opt/sig0lease/<instance>/releases/<time>-<commit>/` | a release: the proxy (`sig0lease`), the page (`web/`), `config.base.yaml` (the repository's `config.yaml` at the commit) and `config.yaml` (the instance's config, made from it); `/opt/sig0lease/<instance>/current` links to the one the instance runs |
| `/etc/sig0lease/keystore/` | the zones' keys, from `keystore/server` on the operator's machine |
| `/var/lib/sig0lease/<instance>/` | the instance's lease stores |
| nginx | port 80: Let's Encrypt's challenges, and a redirect to stable's HTTPS. For each instance that has a release, at its ports: HTTPS, with the page, opened on the instance's zones, and `/dns-query`, passed to the instance's DNS-over-HTTPS, with a request rate per source address; DNS-over-TLS, its TLS ended here and the DNS-over-TCP inside passed to the instance's plain DNS port, with a number of connections per source address |
| certbot | the registrar's certificate, renewed by `certbot.timer`; nginx reloads it. Its Let's Encrypt account has the address in `nginx_acme_email` ([roles/nginx/defaults/main.yml](ansible/roles/nginx/defaults/main.yml)) |

An instance's config is `config.base.yaml` with the changes in `sig0lease_config_overrides`
([roles/sig0lease/defaults/main.yml](ansible/roles/sig0lease/defaults/main.yml)): the instance's
zones and listeners, and where its keys and lease stores are. Everything else is `config.yaml`'s:
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
- The zones' keys in `keystore/server`: `dev.zenr.io.`'s for stable, as for the demos, and
  `stg.zenr.io.`'s for staging.

## Releasing

```bash
make deploy      # this checkout, built and installed on staging
make promote     # the release staging runs, moved to stable
```

`make deploy`:

1. On this machine: makes staging's config, then builds the proxy for the registrar's Linux from
   the checkout, refusing uncommitted changes (`make deploy ARGS="-e
   sig0lease_allow_dirty=true"` deploys them, as a release whose name ends in `-dirty`), and the
   page (`make web`).
2. On the registrar: installs nginx and gets the certificate the first time, installs the release
   in staging beside the ones before it, points staging's `current` at it, and restarts staging.
3. Checks, on the registrar: staging runs the release; each of its zones is answered from its
   authoritative server over UDP, TCP, DNS-over-TLS and DNS-over-HTTPS; any other name is
   refused. When a check fails, staging goes back to the release before (on its first release,
   it stops), and the play fails with the failed release's journal.
4. Checks from this machine that staging's plain DNS port answers and its page is served. A
   failure here leaves the release running: something between the two machines blocks them.

`make deploy` installs on staging only. Try the release there: the demos take staging's zones
(docs/demo.md, "Against a shared registrar"), and its page is at `https://<registrar>:8444/`.

```bash
REGISTRAR=<registrar>:8054 ZONE=stg.zenr.io DOMAIN=srp.stg.zenr.io demo/run.sh
```

Then `make promote`:

1. Checks staging's release again, as in step 3.
2. Copies its files into stable's releases, makes stable's config from the release's own
   `config.base.yaml`, points stable's `current` at it, and restarts stable. Nothing is built:
   stable runs the very files staging was checked with.
3. Checks stable as in steps 3 and 4, going back to stable's release before when a check fails.

Each instance keeps the 5 releases before the one it runs.

- `make deploy-check INSTANCE=stable`: the checks of step 3, on the release stable runs; changes
  nothing. `INSTANCE` is `staging` or `stable`, default `staging`.
- `make deploy-rollback INSTANCE=stable`: stable back to the release before the one it runs,
  then its checks.
- `make deploy ARGS="--tags nginx"`: nginx and the certificate only.

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
ssh registrar runuser -u sig0lease -- /opt/sig0lease/stable/current/sig0lease --dump /opt/sig0lease/stable/current/config.yaml
```

`--dump` (`--dump-debug` for every record) reads the lease stores and changes nothing. The dump
query over DNS is refused, as `server.diagnostics` is off.

## What protects it

- Each proxy answers only for its zones (`server.forward` off): neither is an open resolver.
- Error replies carry the Extended DNS Error's code and no reason (`server.diagnostics` off).
- nginx limits each source address's DNS-over-HTTPS requests and DNS-over-TLS connections, per
  instance ([roles/nginx/defaults/main.yml](ansible/roles/nginx/defaults/main.yml)). Behind
  nginx, a proxy sees every such client as 127.0.0.1.
- The proxies run as their own user, with no capabilities, in systemd's sandbox: each writes only
  its own lease stores.
- The plain DNS ports themselves have no limit, and the machine no firewall from these roles: its
  other services belong to their own operators, and a firewall of its own (an nftables table
  beside theirs) is still to come. It would open, besides theirs and ssh: 80, 443, 853, 8053,
  8054, 8444 and 8853.
