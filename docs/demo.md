# Demos: publishing on the live zenr.io zone

The demos publish names, services and records in the live zone `zenr.io.`: a laptop's site and
services, an IPFS folder, chat servers, and names that phones claim from a web page, each held by
the phone's key (a KEY record) and carrying a message (a TXT record).
`sig0lease-agent`, or the DNS client in a web page (D6), sends each update through the sig0lease
proxy, which runs on the presenter's laptop (local proxy), or on an online server (the registrar). 
The proxy forwards each update to the real authoritative server of `zenr.io.`
(`ns1.free2air.org`). The audience looks from their own devices, with the DNS tools they already
have. Everything runs from the repository root, with the files in [`demo/`](../demo/).

Each demo runs in two ways: as a local test, where its script starts the proxy on the laptop, or
with the registrar, where it reuse the online running proxy ("Running a demo"). A demo's section has three parts:
"Common to both", then "Local test" and "With the registrar", which say what is particular to
each. D4 adds to D1 or D6 and has no such parts: it is the same both ways.

| Demo | What the audience sees | Needs |
|---|---|---|
| D1: the laptop publishes itself | its site among browse results and under a name; a service leaves when it stops and comes back; a record added to its template shows within 15 s; a second key gets `demo-2`, and is refused the name | the laptop |
| D2: the Mac's own services | turning on Remote Login or Screen Sharing puts it in the public zone | a Mac |
| D3: a community folder over IPFS | phones open the members' folders by name from the IPFS community node, which finds each member by browsing as it comes up, pins its folder before publishing it, keeps serving it while the member is away, and drops it once the member stays away; the nodes find each other by DNS alone, in a private swarm | the laptop with kubo, or, with the registrar, the members' machines with IPFS Desktop or kubo; phones |
| D4: native discovery | an audience Mac lists the laptop's services beside its `local.` ones | a Mac in the audience |
| D5: two communities meet in one chat room | phones log in as guests of two XMPP servers and talk in one room; the servers find each other by SRV records and trust each other's self-signed certificates by TLSA records (DANE) | one or two machines, each with Docker (a Mac) or Prosody 13 (Linux); phones |
| D6: the zone in a browser | phones watch the services come and go, and the zone's names with their records; they claim a name with a message, held by a key their browser makes, and every phone lists it; `dig` shows it within seconds | the laptop; phones |

The demos use this repository's programs and tools that come with the system, except IPFS
Desktop or kubo for D3, and for D5 the XMPP server Prosody and the XMPP chat client Converse.js,
written in JavaScript: the page each Prosody serves to the phones loads Converse.js from
`cdn.jsdelivr.net`, so the phones need the internet too.

## Running a demo

Each demo is a script in `demo/`. A script builds what it runs, starts it, and pauses before each
step until the key `n` (next); Enter only starts a new line, to make room in what it prints. Its
last `n`, or Ctrl-C, stops what it started, its agents first, which free the demo's names.

A script reads variables written before its command, as in `NAME=demo7 demo/run.sh`; its first
lines, comments, list the ones it reads, such as `NAME` or `ADDRESS`. Some variables tell every
script which registrar the agents use and where the demo's names go. They are defined here,
once: paste the block of your case, below, in each terminal, and the commands in this document
use them.

### Local test: the laptop's own proxy

```bash
REGISTRAR= DOH= UPDATE_DOMAIN=local.dev.zenr.io SRP_DOMAIN=srp.local.dev.zenr.io
```

Each script starts its own proxy, on 127.0.0.1:8053, with the config its demo needs, and refuses to
start while another proxy runs on the machine, another demo's included: run one demo at a time. The
proxy serves the block's subtrees, `local.dev.zenr.io` and `srp.local.dev.zenr.io` or any others
written in it, such as `stg.zenr.io` and `srp.stg.zenr.io`, and signs its updates for each with the
key in `keystore/server` at the closest name at or above it; it does not start without one. The proxy ends
a lease only while it runs, which is while the script that launched it is running.

### With the registrar

`<registrar>` is the host name of the server the registrar runs on. The registrar has two
instances, stable and staging, each with its own ports and subtrees: paste the line of the one
you use, after the first line.

```bash
REG=<registrar>
#Stable:
REGISTRAR=$REG:8053 DOH= UPDATE_DOMAIN=dev.zenr.io SRP_DOMAIN=srp.dev.zenr.io
#Staging:
REGISTRAR=$REG:8054 DOH=https://$REG:8444 UPDATE_DOMAIN=stg.zenr.io SRP_DOMAIN=srp.stg.zenr.io
```

- `REG` is only the registrar's host name, a shorthand from which the instance's line and this
  document's commands build addresses and URLs. No script reads it.
- `REGISTRAR` is what the scripts read: where the agents send their updates, written
  `<host>:<port>`, the host `$REG` and the instance's plain DNS port, 8053 or 8054, used over
  TCP. With it, a script starts no proxy, and checks no ports for one.
- `DOH` is for D6 only. The page in the browser can use only DNS-over-HTTPS, and `DOH` is the
  instance's DNS-over-HTTPS server. Stable's is `https://$REG`, on port 443, which `web.sh` takes
  when `DOH` is empty; staging's is on port 8444.
- `UPDATE_DOMAIN` and `SRP_DOMAIN` are the instance's subtrees ("Where the names go"): a script
  stops without `UPDATE_DOMAIN`.

The agents can also reach the registrar over UDP, DNS-over-TLS or DNS-over-HTTPS, which the
variable `TRANSPORT` chooses. DNS-over-TLS and DNS-over-HTTPS are on other ports of the instance
than plain DNS, so `REGISTRAR` changes with them. Write `TRANSPORT` and the `REGISTRAR` of your
instance before a command, in place of `REGISTRAR=$REGISTRAR`:

```bash
TRANSPORT=udp REGISTRAR=$REGISTRAR            # both: UDP, on the plain DNS port
TRANSPORT=tls REGISTRAR=$REG:853              # stable: DNS-over-TLS
TRANSPORT=tls REGISTRAR=$REG:8853             # staging
TRANSPORT=doh REGISTRAR=https://$REG          # stable: DNS-over-HTTPS
TRANSPORT=doh REGISTRAR=https://$REG:8444     # staging
```

such as `TRANSPORT=tls REGISTRAR=$REG:853 UPDATE_DOMAIN=$UPDATE_DOMAIN demo/run.sh`. Without
`TRANSPORT`, the agents use TCP.

Two things differ from a local test:

- Other people can use the same registrar, and the registrar gives each name in a demo to the first key that claims it,
  for as long as that key's lease lasts. One of the demo's names may already be taken by someone:
  you can check this (see "Before a demo"). The registrar's own lease limits apply to lease time.
- For security reasons, a shared registrar does not report its error reasons and its lease-store dump
  (`server.diagnostics` off): a refusal shows only its Extended DNS Error's code, and
  `demo/leftovers.sh -r` cannot read its stores.

### Reading the commands

A part of a command in `<…>` is optional: write it without `<` and `>`, or leave it out.

- `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN>` hands the script the block you pasted.
  Write it with the registrar's block, or with a local block whose subtrees are not
  `local.dev.zenr.io` and `srp.local.dev.zenr.io`; add `SRP_DOMAIN=$SRP_DOMAIN` to it when
  `SRP_DOMAIN` is not `srp.$UPDATE_DOMAIN`. Left out, the script runs the local test, in
  `local.dev.zenr.io` and `srp.local.dev.zenr.io`.
- Any other optional part, such as `<MEMBER=…>`, has nothing to do with the block: the demo's
  section says when to write it.

### Where the names go

The zone is `zenr.io.`. The demos' names go in two subtrees of it, one for each of the proxy's
handlers:

- `UPDATE_DOMAIN`: names a key holds, with any records (RFC 9664, `update_handler`), such as
  D1's `demo.$UPDATE_DOMAIN`.
- `SRP_DOMAIN`: hosts and the services these hosts register, which DNS-SD browses (RFC 9665,
  `srp_handler`), such as D1's `demo.$SRP_DOMAIN`; by default `SRP_DOMAIN`=`srp.$UPDATE_DOMAIN`. It may be
  elsewhere in the zone, but not at or above `UPDATE_DOMAIN`, because demo D6's page lists the names in
  `UPDATE_DOMAIN` outside `SRP_DOMAIN`.

With neither set, the scripts use `local.dev.zenr.io` and `srp.local.dev.zenr.io`, so that a
local test's names do not collide with the names people register through the registrar: the
local test's `site.local.dev.zenr.io`, for instance, is not `site.dev.zenr.io`, which the
registrar's IPFS community node holds.

`local.dev.zenr.io` is itself a name one label below the registrar's `dev.zenr.io`, where anyone
can claim a name through the registrar, and whoever held it could write records at every name
below it, the local tests' included. So that nobody can claim it, `local.dev.zenr.io` holds a KEY
that no demo writes, written there once by hand: the public key of `dev.zenr.io` itself. The
registrar refuses to give a name that holds another key. No script needs or checks this KEY; to
see it, compare:

```bash
dig +short KEY local.dev.zenr.io @ns1.free2air.org
dig +short KEY dev.zenr.io @ns1.free2air.org
```

The proxy's config and the agents' templates in the repository are written for `dev.zenr.io` and
`srp.dev.zenr.io`, for runs by hand (running the commands separately and not via a script): 
`config.yaml` serves `srp.dev.zenr.io.` and `dev.zenr.io.`, and
`demo/demo.yaml` registers the host `demo` in `srp.dev.zenr.io.` and the name `demo.dev.zenr.io.`,
at the laptop's proxy, `127.0.0.1:8053`. So that the same files serve any subtrees and any
registrar, a script never runs them as they are: it writes a copy of each into the run's log
directory, starts the proxy and the agents with the copies, and leaves `config.yaml` and the files
in `demo/` as they are, for runs by hand.

In the copy of `config.yaml`, which a script writes only when `REGISTRAR`is not specified, the following 
changes are made:

- `handlers.srp_handler.upstream_zone`, `srp_handler`'s subtree, is `SRP_DOMAIN`;
- `handlers.update.upstream_zone`, `update_handler`'s, is `UPDATE_DOMAIN`.

In the copy of a agent template:

- each srp registrar's `domain:` is `SRP_DOMAIN`;
- each RFC 9664 name keeps its first label, the part before the first dot, and the rest is
  `UPDATE_DOMAIN`: `demo.dev.zenr.io.` becomes `demo.$UPDATE_DOMAIN.`;
- with `REGISTRAR`, `server: 127.0.0.1:8053` is `REGISTRAR`.

In the copy of D1's site, `demo/site`, which `run.sh` and `web.sh` serve, the page lists the run's
host and name: `demo.srp.dev.zenr.io` is `$NAME.$SRP_DOMAIN`, and `demo.dev.zenr.io`
`$NAME.$UPDATE_DOMAIN`.

The copies stay beside the run's logs, so they show what the proxy, the agents and the site were
given.
Every script copies in this way each template it runs: `demo/demo.yaml`, `demo/conflict.yaml`,
`demo/mac.yaml`, and the ones `ipfs.sh` and `chat.sh` write.

## Before a demo

1. If running commands by hand (and not via a demo script), build, and name the binaries' directory. Each script builds what
   it runs itself:

   ```bash
   make build build-client
   B=./bin/$(uname -s | tr A-Z a-z)
   ```

2. Check that the network reaches the zone's server, over UDP and TCP: the proxy sends it the
   updates, and the scripts ask it whether each change is there.

   ```bash
   dig +short SOA zenr.io @ns1.free2air.org
   dig +tcp +short SOA zenr.io @ns1.free2air.org
   ```

3. Check that the demo's names are free, before each run: a script that stops frees them
   (`on_stop: release`), so someone else may take them in between. Run
   `<UPDATE_DOMAIN=$UPDATE_DOMAIN> NAME=… demo/watch.sh once` with the demo's `NAME`:

   | Demo | `NAME` | What it shows when the names are free |
   |---|---|---|
   | D1, D2, D6 | `demo`, the default | `(no records)` under `demo`, and no `demo` instance; the same with the registrar |
   | D3, local test | `site` | `(no records)` under `site`, and no instance with a label the run registers: `community ipfs-gateway`, `alice`, `carol` |
   | D3, with the registrar | `site` | `site` is the registrar's IPFS community node's, and stays so: its `KEY`; its `_dnslink TXT`, the community's folder (`QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn`, an empty folder, while no member was listed in the last 10 minutes); its `_dnsaddr TXT`, the node's addresses. Only the members' labels have to be free: no instance with a member's label |
   | D5 | `"chat-a chat-b"` | `(no records)` under each; the same with the registrar |

   If one is taken, write another label:

   - D1, D2 and D6: write it, say `demo7`, in place of `demo` in `demo/demo.yaml` and
     `demo/conflict.yaml`, twice in each: the host, `name: demo`, and the first label of the
     name, `name: demo.dev.zenr.io.` (only that label: the scripts replace the rest with
     `UPDATE_DOMAIN`, "Where the names go"). Then put `NAME=demo7` before the commands of
     `run.sh`, `web.sh` and `watch.sh`, such as `<REGISTRAR=$REGISTRAR
     UPDATE_DOMAIN=$UPDATE_DOMAIN> NAME=demo7 demo/run.sh`.
   - D3, local test: `site` as `SITE=…` before `demo/ipfs-local.sh start`, with the nodes
     stopped (`demo/ipfs-local.sh stop`): it writes the label into alice's and carol's peer lists
     as it starts their nodes, and prints the run's commands with it. A member's label as
     `MEMBER=…` in that member's `demo/ipfs.sh member` command, with its `IPFS_PATH` as it is.
     `community` as `HOST=…` before `demo/ipfs.sh community`.
   - D3, with the registrar: a member's label as `MEMBER=…`.
   - D5: as `chat.sh`'s arguments, in `ROOM`, and as `NAME`.

4. Consider recording a run: if the venue's network blocks port 53, the recording is the demo.

While a demo runs:

- A screen can show `<UPDATE_DOMAIN=$UPDATE_DOMAIN> NAME=… demo/watch.sh`, with the demo's
  labels as `NAME`: what anyone can see, asked of `ns1.free2air.org` every 2 s.
- Ask the audience to look only once a name is published: a resolver that was told "no such
  name" keeps that answer for up to 6 minutes (the zone's SOA TTL). `@ns1.free2air.org` always
  gives the current answer.
- Each script prints the commands anyone can run, with the subtrees written out.

## D1: the laptop publishes itself

### Common to both

**Needs**: the laptop.

**Run**:

```bash
<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> demo/run.sh
```

It starts the site and the agent, and after each step prints how long `ns1.free2air.org` took to
show it.

1. The agent registers the host `demo`, with its service `demo http`, and the name `demo`:
   `watch.sh` shows the instance `demo http` under `_http._tcp`, and the name's addresses and
   TXT.
2. The site stops. After three failed probes, about 15 s, `demo http` leaves the browse results;
   about 30 s on a Mac whose firewall is in stealth mode, where a stopped site's port does not
   refuse connections, so each probe waits its 5 s out. The site starts again: `demo http` is back
   within about 10 s.
3. A record is added to the agent's template: `run.sh` asks for its text, and adds the time to
   it. Within 15 s (the agent reads the template every 10 s):

   ```bash
   dig +short TXT hello.demo.$UPDATE_DOMAIN @ns1.free2air.org
   ```

4. Someone else wants the same names: a second agent, with `demo/conflict.yaml` and keys of its
   own. Its host is renamed `demo-2`, and its instance `demo http-2` shows beside yours. The name
   `demo` is refused, since your key holds it, and is not renamed. A host's services are found
   by browsing, whatever the host is called, so the agent can take another host name; but a name
   such as `demo.$UPDATE_DOMAIN` is what people type, and `demo-2` would reach nobody. The agent
   logs `held by another key` and asks again, after 5 s, then less and less often, up to every
   5 minutes: it gets the name once your key no longer holds it. When it stops, it frees what it
   got (`on_stop: release`) and leaves your name alone.

What the audience can run:

```bash
dig +short demo.$UPDATE_DOMAIN                      # any machine
dig +short TXT demo.$UPDATE_DOMAIN
dns-sd -B _http._tcp $SRP_DOMAIN                    # a Mac: browse
dns-sd -L "demo http" _http._tcp $SRP_DOMAIN        #        resolve one instance
avahi-browse -d $SRP_DOMAIN. -r _http._tcp          # Linux with avahi-daemon
```

and, on the same network as the laptop, open `http://demo.$SRP_DOMAIN:8000/`. The addresses
the agent publishes are the laptop's on that network.

### Local test

`run.sh` also starts the proxy, before the agent, and stops it last.

**By hand**, from the repository's top directory. The commands use the repository's files as
they are, so the names go in `dev.zenr.io` and `srp.dev.zenr.io`, not `local.dev.zenr.io`. Check
first that they are free: `UPDATE_DOMAIN=dev.zenr.io demo/watch.sh once`.

1. Start each of these in a terminal of its own:

   ```bash
   $B/sig0lease                                               # the proxy
   python3 -m http.server 8000 -d demo/site                   # the site
   $B/sig0lease-agent run -probe-interval 5s demo/demo.yaml   # the agent
   UPDATE_DOMAIN=dev.zenr.io demo/watch.sh                    # what anyone can see
   ```

2. Ctrl-C in the site's terminal, then start the site again.
3. In `demo/demo.yaml`, uncomment the `hello` record, change its text if you like, and save.
4. In a fifth terminal, start the second agent, then Ctrl-C:

   ```bash
   $B/sig0lease-agent run -probe-interval 5s demo/conflict.yaml
   ```

### With the registrar

Both agents, yours and step 4's, register through the registrar, which gives `demo` to the first
key that claims it: check that it is free ("Before a demo", step 3). Only `run.sh` runs D1 with
the registrar: `demo/demo.yaml` and `demo/conflict.yaml`, run by hand, name the laptop's proxy.

## D2: the Mac's own services

### Common to both

**Needs**: a Mac as the laptop. `demo/run.sh` writes the Mac's template, `demo/mac.yaml`, on its
first run there: it names this Mac, so it is not in the repository. On first use macOS asks
whether Terminal may find devices on the local network: allow it.

**Run**: D1's command on the Mac, whose step 5, after D1's four, starts a second agent with
`demo/mac.yaml`. In System Settings > General > Sharing, turn on Remote Login (`_ssh._tcp`) or
Screen Sharing (`_rfb._tcp`): a few seconds later the agent logs `registered`, and `watch.sh`
shows the Mac's instance. Turn it off and it goes. [srp-live-demo.md §7](srp-live-demo.md) has
the details and limits.

### Local test

By hand, beside D1's terminals 1 to 4: `$B/sig0lease-agent run demo/mac.yaml`.

### With the registrar

D1's command with its `<…>` part: the Mac's agent registers through the registrar too. Only
`run.sh` runs it so: `demo/mac.yaml`, run by hand, names the laptop's proxy.

## D3: a community folder over IPFS

Members keep a folder each in their IPFS node. An IPFS community node finds each member by browsing
as it comes up, pins its folder, and keeps a folder with an entry for each member, which its
gateway serves to phones. Two ways to run it:

- **Local test**: everything on the laptop: the IPFS community node and two members, alice and
  carol, as three kubo nodes that `demo/ipfs-local.sh` sets up and starts, and one proxy. Phones
  on the laptop's network open the gateway.
- **With the registrar**: the registrar's own IPFS community node, always on, with its gateway on the
  internet. Only the members run `demo/ipfs.sh member`, each on its own machine, with a kubo
  node: the one IPFS Desktop runs, or kubo on its own; phones open the folder from anywhere.

### Common to both

What the agents publish, which `<UPDATE_DOMAIN=$UPDATE_DOMAIN> NAME=site demo/watch.sh` shows:

| Record | Published by | Changes when |
|---|---|---|
| `alice._ipfs-member._tcp.$SRP_DOMAIN` SRV, and TXT `dnslink=/ipfs/<CID>` `swarm-mac=<MAC>` | each member, under its label | its folder changes; withdrawn while its node's swarm port does not answer, and when it stops |
| `site._sub._ipfs-member._tcp.$SRP_DOMAIN` PTR | each member | a member comes or goes |
| `_dnslink.site.$UPDATE_DOMAIN` TXT `dnslink=/ipfs/<CID>`, the community's folder | the IPFS community node | it has pinned a member's new folder, or removed a member's entry |
| `_dnsaddr.site.$UPDATE_DOMAIN` TXT `dnsaddr=/ip4/<address>/tcp/<port>/p2p/<ID>`, one for each of its node's addresses | the IPFS community node | its node's addresses change |
| `community ipfs-gateway._http._tcp.$SRP_DOMAIN` SRV `0 0 8081 community.$SRP_DOMAIN.`: the gateway phones open, as a service | the local test's IPFS community node; the registrar's gateway is at the registrar's own address | its gateway starts or stops answering |

`/ipns/site.$UPDATE_DOMAIN/alice/` is alice's folder. A member is its label, `MEMBER`, by default
the machine's name, which its key holds: a member that stops comes back to its label as the same
member. The IPFS community node keeps an absent member's entry for `REVOKE_AFTER`, then removes it and
unpins its folder. Only nodes with the community's swarm key are members: a member's TXT record
gives a `swarm-mac=` that the swarm key makes from its KEY and its folder's CID, and the IPFS
community node pins nothing whose `swarm-mac=` it cannot make ([sig0lease-agent.md](sig0lease-agent.md),
"Who is a member").

### How a node is set up

An IPFS node here is kubo, the `ipfs` program. IPFS Desktop is optional: an app that runs kubo
and shows its files and peers. All a node has is in
its repository, a directory: `~/.ipfs`, unless `IPFS_PATH` names another. `ipfs init` makes it,
with:

- the node's key pair, from whose public key comes the node's peer ID, `12D3KooW…`, which
  `ipfs id` shows;
- the node's settings, the file `config`;
- room for its blocks and its files.

`ipfs config`, with `IPFS_PATH` set to the repository, writes a setting into `config` while the
node is stopped; the node reads its settings when it starts.

Every node, the IPFS community node's and each member's, gets these settings:

- `ipfs config profile apply autoconf-off`. Otherwise kubo fills four settings, marked `auto`,
  from a list of public services it downloads (`https://conf.ipfs-mainnet.org/autoconf.json`):
  - `Bootstrap`: the public network's peers it connects to when it starts;
  - `DNS.Resolvers`: DNS-over-HTTPS resolvers for some top-level domains;
  - `Routing.DelegatedRouters`: HTTP services that tell which nodes have a block;
  - `Ipns.DelegatedPublishers`: HTTP services that publish IPNS names.

  `autoconf-off` stops the download and empties all four: the node asks no public service, knows
  no public peer, and resolves names through the machine's own resolver.
- `ipfs config Routing.Type dht`: the node finds which nodes have a block, and their addresses,
  only in the distributed hash table (DHT) that the nodes it connects to keep among themselves.
  The default, `auto`, also asks the delegated routers. In a private swarm the table holds only
  the swarm's nodes.
- `ipfs config --json AutoTLS.Enabled false`: otherwise the node uses kubo's AutoTLS. It
  registers with `registration.libp2p.direct`, a public web service on the internet run by
  kubo's developers (the setting `AutoTLS.RegistrationEndpoint`). That service gives the node a
  DNS name of its own, made from its peer ID, in the domain `libp2p.direct`, which the service
  runs, and a Let's Encrypt certificate for that name. Browsers need the name and the
  certificate to connect to the node, over secure WebSockets.
- `ipfs config --json Swarm.Transports.Network.Websocket false`: no WebSocket listener, the
  transport that certificate is for.
- `ipfs config --json Discovery.MDNS.Enabled false`: otherwise nodes on the same local network
  find each other by multicast DNS. Off, they find each other by DNS alone, as across the
  internet: through the IPFS community node's name.
- A swarm key, the file `swarm.key` in the repository, made once for the community and given to
  each member. It has three lines, two fixed ones and 32 random bytes in hex:

  ```
  /key/swarm/psk/1.0.0/
  /base16/
  <64 hex digits>
  ```

  `demo/ipfs-local.sh start` makes it with
  `printf '/key/swarm/psk/1.0.0/\n/base16/\n%s\n' "$(openssl rand -hex 32)" > swarm.key`.
  With it, the node connects only to nodes with the same key, a private
  swarm: every connection is encrypted with it, and a node without it cannot connect at all. At
  start the node says "Swarm is limited to private network of peers with the swarm key", then
  the key's fingerprint, the same on every node of the community. The key never goes into DNS or
  this repository.

Each node listens on three ports, each one a setting in its `config`, under `Addresses`. The
setting's value is a multiaddr, kubo's way of writing an address, which names each protocol with
its value: `/ip4/127.0.0.1/tcp/5001` is TCP port 5001 on the address 127.0.0.1, and
`/ip4/0.0.0.0/tcp/4001` TCP port 4001 on all of the machine's addresses.

- `Addresses.API`, port 5001 by default, on 127.0.0.1 only: the RPC API, over HTTP, which the
  `ipfs` command, IPFS Desktop and the agents use (`IPFS_API`, `http://127.0.0.1:<port>`).
  Whoever reaches it controls the node.
- `Addresses.Gateway`, port 8080 by default, on 127.0.0.1: the HTTP gateway, which serves
  `/ipfs/<CID>` and `/ipns/<name>` to browsers. The local test's IPFS community node has it on
  0.0.0.0, all of the machine's addresses, so that phones reach it, and registers it as the
  instance `community ipfs-gateway` in `$SRP_DOMAIN`.
- `Addresses.Swarm`, port 4001 by default, over TCP and QUIC (UDP), on all of the machine's
  addresses: where the node takes connections from other nodes. The IPFS community node's agent
  publishes its node's swarm addresses at `_dnsaddr.site.$UPDATE_DOMAIN`; a member's agent gives
  its node's TCP swarm port in the member's SRV record, and probes it.

A member's node also gets the IPFS community node in its peer list (`Bootstrap`): the nodes it
connects to when it starts, and again every 30 s while it has fewer than 4 connections.

```bash
ipfs bootstrap add /dnsaddr/site.$UPDATE_DOMAIN/p2p/<ID>
```

- `/dnsaddr/site.$UPDATE_DOMAIN` is an address to look up. The node asks DNS for the TXT records
  of `_dnsaddr.site.$UPDATE_DOMAIN`; each, `dnsaddr=<address>`, is an address of the IPFS
  community node, as the IPFS community node's agent publishes them.
- `/p2p/<ID>` is the IPFS community node's peer ID. The node keeps the addresses that end in it, and
  a connection to one succeeds only if the node there holds the private key the ID was made from.
  The ID names the node, not where it is: its addresses can change, its ID stays.

`demo/ipfs.sh member` also makes the IPFS community node a peering peer of the member's node, for as
long as the node runs (`ipfs swarm peering add`, at the addresses `_dnsaddr.site` gives). kubo
keeps a peering peer connected, and asks a peer outside the local network for blocks only if it
is a peering peer or has sent it some: without it, a member's node would never ask the
registrar's IPFS community node for the community's folder.

A member's folder is a directory in its node's files (MFS, the files IPFS Desktop's Files shows),
`/community` by default (`FOLDER`):

```bash
ipfs files mkdir /community
ipfs files cp /ipfs/$(ipfs add -Q photo.jpg) /community/photo.jpg
```

`ipfs add -Q` stores the file in the node and prints its CID, the hash of its content, by which
any node of the swarm fetches it; `ipfs files cp` puts it in the folder, under a name. The folder
has a CID of its own, which changes with each change, and the member's agent publishes it in the
member's TXT record.

### Local test

**Needs**: the laptop, with kubo's `ipfs` command, `openssl`, and `qrencode` (`brew install
qrencode` on a Mac, `sudo apt install qrencode` on Linux); phones on the laptop's network, which
reach its port 8081. IPFS Desktop is not used, and its node, `~/.ipfs`, is left as it is.

The three nodes, each with its repository in the home directory:

| Node | Repository | API | Swarm | Gateway |
|---|---|---|---|---|
| the IPFS community node | `~/.ipfs-community` | 127.0.0.1:5002 | 4002 | 0.0.0.0:8081, for the phones |
| alice | `~/.ipfs-alice` | 127.0.0.1:5003 | 4003 | 127.0.0.1:8082 |
| carol | `~/.ipfs-carol` | 127.0.0.1:5004 | 4004 | 127.0.0.1:8083 |

kubo's default ports, 5001, 4001 and 8080, stay IPFS Desktop's.

**Start the nodes**, with the laptop's block pasted:

```bash
UPDATE_DOMAIN=$UPDATE_DOMAIN demo/ipfs-local.sh start
```

For each node that does not run, `demo/ipfs-local.sh start`:

1. makes its repository, if there is none (`ipfs init`);
2. gives it the settings of "How a node is set up", and its ports, as in the table;
3. for the IPFS community node, makes the community's swarm key, `~/.ipfs-community/swarm.key`, if
   there is none; for alice and carol, copies it into their repositories;
4. for alice and carol, makes the IPFS community node their peer list's only entry,
   `/dnsaddr/site.$UPDATE_DOMAIN/p2p/<the IPFS community node's ID>`;
5. starts the node, `ipfs daemon`, in the background, logging to `daemon.log` in its repository,
   and waits until its API answers.

Then it gives alice and carol each a folder, `/community`, with a first file, `alice.txt` and
`carol.txt`, if they have none, and prints the commands of "Run". A node that runs is left as it
is: run again, `demo/ipfs-local.sh start` starts only the nodes that stopped. The members' nodes
log "failed to bootstrap (no peers found)" until the IPFS community node publishes its addresses:
`demo/ipfs.sh member` connects them, in "Run", step 3.

**Run**, with the laptop's block pasted in each terminal, each command in a terminal of its own:

1. A screen shows the community's records:

   ```bash
   UPDATE_DOMAIN=$UPDATE_DOMAIN NAME=site demo/watch.sh
   ```

2. Start the IPFS community node's agent, and the proxy (`n`):

   ```bash
   UPDATE_DOMAIN=$UPDATE_DOMAIN REVOKE_AFTER=2m IPFS_PATH=~/.ipfs-community IPFS_API=http://127.0.0.1:5002 GATEWAY=8081 demo/ipfs.sh community
   ```

   `_dnslink.site`, an empty folder, and `_dnsaddr.site` appear. `demo/ipfs.sh community` prints
   the gateway's address, `http://community.$SRP_DOMAIN:8081/ipns/site.$UPDATE_DOMAIN/`, with a
   QR code, then each member as it comes and goes.
3. Start alice's agent, then carol's (`n` in each); they use the IPFS community node's proxy:

   ```bash
   REGISTRAR=127.0.0.1:8053 UPDATE_DOMAIN=$UPDATE_DOMAIN MEMBER=alice IPFS_PATH=~/.ipfs-alice IPFS_API=http://127.0.0.1:5003 demo/ipfs.sh member
   ```

   ```bash
   REGISTRAR=127.0.0.1:8053 UPDATE_DOMAIN=$UPDATE_DOMAIN MEMBER=carol IPFS_PATH=~/.ipfs-carol IPFS_API=http://127.0.0.1:5004 demo/ipfs.sh member
   ```

   Each appears under `_ipfs-member._tcp`, and `demo/ipfs.sh member` makes the IPFS community node a
   peering peer of the member's node, at the addresses `_dnsaddr.site` gives ("connected to the
   IPFS community node at …, a peering peer of its node"). The IPFS community node says "alice is a
   member", then "pinned …, alice's folder" and "alice's entry gives …"; `demo/ipfs.sh member`
   waits until then.
4. Phones scan the QR code: a folder for each member, with its first file.
5. Put a photo in alice's folder, in a fifth terminal:

   ```bash
   PHOTO=<path to a photo>
   CID=$(IPFS_PATH=~/.ipfs-alice ipfs add -Q "$PHOTO")
   IPFS_PATH=~/.ipfs-alice ipfs files cp /ipfs/$CID /community/$(basename "$PHOTO")
   ```

   Within about 15 s alice's TXT record changes, and within about 15 s more `_dnslink.site`:
   each agent reads its node, and the IPFS community node lists the members, every 10 s. A phone's
   reload shows the photo within about a minute, once the gateway's cached `site`, 30 s, is over.
6. `https://dweb.link/ipns/site.$UPDATE_DOMAIN/`, a public gateway, reads the name but cannot
   find the folder: no node outside the private swarm has it.
7. alice leaves for a while: stop her node, in the fifth terminal:

   ```bash
   IPFS_PATH=~/.ipfs-alice ipfs shutdown
   ```

   alice's instance goes within about 15 s, when her agent's probe of the node's swarm port
   fails, and within about 10 s more the IPFS community node says "alice is not listed; its entry goes
   in 2m0s unless it is again"; phones still load alice's folder. Start her node again within
   those 2 minutes, which starts only the nodes that stopped:

   ```bash
   UPDATE_DOMAIN=$UPDATE_DOMAIN demo/ipfs-local.sh start
   ```

   "alice is listed again", and the entry stays.
8. carol leaves for good: `n` in carol's `demo/ipfs.sh member`. Two minutes later the IPFS
   community node says "carol is not listed for 2m0s: no longer a member", and carol's folder goes from the
   site and from its pins.
9. `n` in alice's `demo/ipfs.sh member`, then in the IPFS community node's `demo/ipfs.sh community`,
   last: it stops the proxy too.
10. Stop the three nodes:

    ```bash
    demo/ipfs-local.sh stop
    ```

A member that stops keeps its label for an hour, its key's lease, as long as the proxy runs. The
IPFS community node keeps the community's folder for the next run, in its files at
`/sig0lease-agent/site.$UPDATE_DOMAIN`, with the members' folders pinned under
`sig0lease-agent site.$UPDATE_DOMAIN.`; a member's key is in `demo/keys-ipfs-member-<MEMBER>`.
The repositories stay too, with the swarm key and the folders: the next
`demo/ipfs-local.sh start` starts the same nodes.

### With the registrar

Each of the registrar's instances runs an IPFS community node of its own (deploy/README.md, "The IPFS
community node"), always on, at a public address. It lists the members of `site` in
`$SRP_DOMAIN`, keeps the community's folder at `site.$UPDATE_DOMAIN`, and serves it on the
instance's HTTPS port, at `${DOH:-https://$REG}/ipns/site.$UPDATE_DOMAIN/`: `DOH` is set for
staging, `https://$REG:8444`, and empty for stable, which gives `https://$REG`. A member's node
connects to it, and it fetches the member's folder over that connection, so a member's node
behind the venue's NAT takes part as well. It may also dial a member's node, at addresses it
learned from an earlier connection. An absent member's entry stays for 10 minutes. A member that stops keeps its label for an hour, its key's
lease; one whose machine sleeps or leaves the network is no longer listed about 2 minutes later,
when its instance's lease ends.

**Needs**: on each member's machine, IPFS Desktop or kubo, and `qrencode`; a network that lets
the members' nodes reach the IPFS community node's swarm port, the port in the addresses
`dig +short TXT _dnsaddr.site.$UPDATE_DOMAIN @ns1.free2air.org` gives; the registrar's block
pasted.

**Once**, on each member's machine, whose node has its repository in `~/.ipfs`, IPFS Desktop's
and kubo's default, and kubo's default ports. With kubo alone and no `~/.ipfs` yet, make it
first: `ipfs init`.

1. Stop the node (quit IPFS Desktop, or `ipfs shutdown`), and give it the settings of "How a
   node is set up":

   ```bash
   ipfs config profile apply autoconf-off
   ipfs config Routing.Type dht
   ipfs config --json AutoTLS.Enabled false
   ipfs config --json Swarm.Transports.Network.Websocket false
   ipfs config --json Discovery.MDNS.Enabled false
   ```

2. Put the community's swarm key, which the registrar's operators give
   (`keystore/ipfs/<instance>/swarm.key` on the machine that deploys the node), in
   `~/.ipfs/swarm.key`. While it is there, the node is in the community's private swarm only.
3. Put the IPFS community node in its peer list, by its name and its peer ID. The peer ID is the
   part after `/p2p/` in each address `_dnsaddr.site` gives, the same in all of them:

   ```bash
   dig +short TXT _dnsaddr.site.$UPDATE_DOMAIN @ns1.free2air.org
   # "dnsaddr=/ip4/<address>/tcp/<port>/p2p/12D3KooW…"   <the ID> is 12D3KooW…, to the closing quote
   ipfs bootstrap add /dnsaddr/site.$UPDATE_DOMAIN/p2p/<the ID>
   ```

4. Start the node (IPFS Desktop, or `ipfs daemon` in a terminal of its own), and make its
   folder, `/community`, with a first file (IPFS Desktop: Files, New folder, then Import), or:

   ```bash
   PHOTO=<path to a photo>
   ipfs files mkdir /community
   ipfs files cp /ipfs/$(ipfs add -Q "$PHOTO") /community/$(basename "$PHOTO")
   ```

**Run**:

1. A screen shows `UPDATE_DOMAIN=$UPDATE_DOMAIN NAME=site demo/watch.sh`, and the peers of the
   node on alice's machine, which list the IPFS community node: IPFS Desktop's Peers, or
   `ipfs swarm peers`.
2. On alice's machine, then on each other member's (`n` in each):

   ```bash
   REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN <MEMBER=…> COMMUNITY_GATEWAY=${DOH:-https://$REG} demo/ipfs.sh member
   ```

   The member appears under `_ipfs-member._tcp`, and its node connects to the IPFS community node,
   as in the local test; the IPFS community node pins its folder, and `_dnslink.site` gives it,
   within seconds. `demo/ipfs.sh member` prints the address of the member's folder at the
   registrar, with a QR code.
3. Phones scan it, on any network: the folder's files. The community's folder is at
   `${DOH:-https://$REG}/ipns/site.$UPDATE_DOMAIN/`.
4. Put a photo in `/community` on alice's machine (IPFS Desktop: drag it into Files; or the
   `ipfs files cp` command of "Once", step 4): a phone's reload shows it within about a minute.
5. alice leaves: `n` in alice's `demo/ipfs.sh member`, or stop the node (quit IPFS Desktop, or
   `ipfs shutdown`). alice's instance
   goes; its entry stays for 10 minutes, and phones still load its folder; back within them, it
   carries on as the same member.

### Why DNSLink, not IPNS

An IPNS name is the hash of a key (`k51…`), published in IPFS's distributed hash table, which can
take from tens of seconds to minutes; IPFS's documentation calls DNSLink "currently much faster
than IPNS" ([docs.ipfs.tech/concepts/ipns](https://docs.ipfs.tech/concepts/ipns/)). A DNSLink
record has a name people can read, is DNSSEC-signed in this zone, and is at the zone's servers
seconds after the agent's update.

## D4: an audience Mac finds them without being told where

D4 is the same as a local test and with the registrar: it adds to D1 or D6, run either way.

**Needs**: a Mac whose owner may run `sudo`, in the audience or the laptop itself, and a demo
running whose agent registers `_http._tcp` services in `$SRP_DOMAIN`: D1 or D6.

**Run**, on that Mac:

```bash
sudo networksetup -setsearchdomains Wi-Fi $SRP_DOMAIN
dns-sd -B _http._tcp          # no domain: the local. and $SRP_DOMAIN. instances together
sudo networksetup -setsearchdomains Wi-Fi Empty                # undo
```

The proxy that serves `$SRP_DOMAIN`, the laptop's or the registrar, publishes
`lb._dns-sd._udp.$SRP_DOMAIN. PTR $SRP_DOMAIN.` (within 30 s of starting, and it stays when the
proxy stops); mDNSResponder looks for that record in each search domain and browses what it
names (RFC 6763 §11). This works with `dns-sd` on macOS 26.7; whether Finder and Screen Sharing
list the instances too has not been tried. Setting the search domain stands in for a pointer at
a domain the Mac already starts from, which needs the zone's operator or a resolver on the
network: `docs/dns-sd-records.md`, "Browsing".

## D5: two communities meet in one chat room

Two XMPP servers (Prosody), A and B, each serve a community: A's guests get addresses at
`chat-a.$UPDATE_DOMAIN` and its rooms are at `rooms.chat-a.$UPDATE_DOMAIN`; B's, at `chat-b`.
The agent publishes each server's addresses, the SRV records that tell other servers where it
listens (`_xmpp-server._tcp`, for the name and for `rooms`) and clients where to log in
(`_xmpp-client._tcp`), and a TLSA record with the hash of the server's key. The certificates are
self-signed: a server accepts another only when its key matches its TLSA record, which DNSSEC
vouches for (DANE). Nothing is configured between the two servers, and nobody makes an account.
It runs on one machine or on two, each with its own section below, with all its steps:

- **On one machine**: one `chat.sh` starts both servers and one agent; B gets the ports 10 above
  XMPP's: 5232, 5279 and 5290. The servers still find and authenticate each other only by their
  records.
- **On two machines**: A on one, B on the other, each started by its own `chat.sh`, with its own
  agent, on XMPP's ports: 5222, 5269 and 5280.

### Common to both

Each machine that runs `chat.sh` needs: on a Mac, Docker Desktop, then
`docker pull prosodyim/prosody:13.0`; on Linux, Prosody 13 (`apt install prosody` on Debian 13,
which brings luaunbound, then `sudo systemctl disable --now prosody`: the package's own server
would hold the ports), or Docker with `PROSODY=docker`. Also `qrencode`, as for D3. `chat.sh`
runs its servers in Docker on a Mac, and with the installed Prosody on Linux; `PROSODY=docker` or
`native` chooses.

Phones talk to their server over plain HTTP on the venue's network, so the guests' messages are
not encrypted there; the servers talk to each other over TLS. Each server keeps its certificate
and key in `demo/chat/servers/<name>/`, so its TLSA record is the same at every run; delete the
directory for a new key. A server whose key its TLSA record does not match is refused
("certificate does not match any DANE TLSA records" in the other server's log), as a test run
showed.

#### On one machine

**Needs**: the machine, with ports 5222, 5269, 5280, 5232, 5279 and 5290 open to the network;
phones on its network, which also reach the internet, for Converse.js.

**Run**:

1. Start both servers:

   ```bash
   <REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> demo/chat.sh chat-a chat-b
   ```

   It starts the servers and the agent, waits until `ns1.free2air.org` has the records, and
   prints the address of the page each server serves, and its QR code. Both pages join A's room,
   `meet@rooms.chat-a.$UPDATE_DOMAIN`. On a Mac, allow Docker's incoming connections when asked;
   on Linux, the firewall has to let in the six ports.
2. Show what the other server reads:

   ```bash
   dig +short SRV _xmpp-server._tcp.rooms.chat-a.$UPDATE_DOMAIN   # 0 0 5269 chat-a.<UPDATE_DOMAIN>.
   dig +dnssec TLSA _5269._tcp.chat-a.$UPDATE_DOMAIN @8.8.8.8    # the ad flag: validated
   ```

3. Half the room scans A's QR code, half B's. The page (Converse.js) logs each phone in as a
   guest of that server and joins `meet@rooms.chat-a.$UPDATE_DOMAIN`; the first one in creates the
   room. B's guests' messages reach A's room over a connection between the servers that each end
   authenticated by the other's TLSA record.
4. `n`, or Ctrl-C, in `chat.sh` stops the agent first, which frees the names, then the servers.

#### On two machines

**Needs**: two machines, A and B, each with ports 5222, 5269 and 5280 open to the network; phones
on their network, which also reach the internet, for Converse.js.

**Run**:

1. On A, start A's server:

   ```bash
   <REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> demo/chat.sh chat-a
   ```

   It starts the server and the agent, waits until `ns1.free2air.org` has the records, and prints
   the address of the page the server serves, and its QR code. On a Mac, allow Docker's incoming
   connections when asked; on Linux, the firewall has to let in the three ports.
2. On B, start B's server, whose page joins A's room:

   ```bash
   <REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> ROOM=meet@rooms.chat-a.$UPDATE_DOMAIN demo/chat.sh chat-b
   ```

   It does on B what step 1 does on A.
3. Show what the other server reads:

   ```bash
   dig +short SRV _xmpp-server._tcp.rooms.chat-a.$UPDATE_DOMAIN   # 0 0 5269 chat-a.<UPDATE_DOMAIN>.
   dig +dnssec TLSA _5269._tcp.chat-a.$UPDATE_DOMAIN @8.8.8.8    # the ad flag: validated
   ```

4. Half the room scans A's QR code, half B's. The page (Converse.js) logs each phone in as a
   guest of that server and joins `meet@rooms.chat-a.$UPDATE_DOMAIN`; the first one in creates the
   room. B's guests' messages reach A's room over a connection between the servers that each end
   authenticated by the other's TLSA record.
5. `n`, or Ctrl-C, in `chat.sh` on A and on B stops its agent first, which frees its name, then
   its server.

### Local test

Each `chat.sh` also starts a proxy on its machine, before its agent, and stops it last.

### With the registrar

The registrar gives `chat-a` and `chat-b` to the first key that claims them: check that they are
free ("Before a demo", step 3).

## D6: the zone in a browser

The page has a DNS client in it: this repository's client code, built for WebAssembly
(`make web`). It sends every question and every update over DNS-over-HTTPS, the one DNS
transport a browser has, to the proxy: the laptop's in a local test, the registrar otherwise. The
proxy answers the questions about its subtrees from the zone's own server: the page sees a change
as soon as `ns1.free2air.org` has it, not what a resolver cached. A question about a name outside
them, such as the address of a service's host elsewhere, the proxy refuses, as it is no
resolver, and the page asks Google's DNS-over-HTTPS resolver instead, over the internet. The
names in `UPDATE_DOMAIN`, which are typed rather than browsed, the page finds by the zone's NSEC
records (the zone is signed with NSEC): each one names the next name in the zone, and the types
of records at its own.

### Common to both

**Needs**: the laptop, with `qrencode`, as for D3; phones, or a browser on the laptop, from 2023
or later. What they must reach is in "Local test" and "With the registrar".

**Run**:

1. Start it:

   ```bash
   <REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN DOH=$DOH> demo/web.sh
   ```

   It builds the agent and the page, and starts a site and an agent that registers it as the
   service `demo http`, as in D1 (`demo/demo.yaml`), and the page, on port 8090. It prints the
   page's address and its QR code.
2. Phones scan the code. The page lists the services in `$SRP_DOMAIN`, read every 3
   seconds, and the names in `$UPDATE_DOMAIN` outside it, read every 10: each name a key holds,
   such as `demo.$UPDATE_DOMAIN`, with its records and those of the names below it, and the
   zone's other names, marked `no key`. At the next `n`, `web.sh` stops the site, and after
   three failed probes, about 15 s, the phones show `demo http` leave, struck through; at the
   one after, it starts the site again, and `demo http` comes back, lit up.
3. Someone picks a name and writes a message. The browser makes a key and keeps it, and the page
   claims `<name>.$UPDATE_DOMAIN` with the message as its TXT record. The badge turns `published`
   once the zone's server has it, within a few seconds, and anyone can check:

   ```bash
   dig +short TXT <name>.$UPDATE_DOMAIN @ns1.free2air.org
   ```

   Within 10 s every phone lists the name, marked `yours` on the phone that holds it. A second
   phone that claims the same name stays `waiting`, and shows the first one's message: another
   key holds the name.
4. "Release the name" deletes the message and frees the name. The last `n`, or Ctrl-C, in
   `web.sh` stops the agent, which frees `demo`, then the page and the site.

A name stays its phone's while the page is open: the message for 10 minutes after the page
closes (its lease), the name for 30 (its key's, the most the zone grants). Opened again within
that time, from the same browser, the page claims it again. Clearing the browser's data for the
site loses the key, and the name with it until those 30 minutes are over.

### Local test

`web.sh` also builds and starts the proxy, with its DNS-over-HTTPS listener on, port 8443, in
plain HTTP, which the page uses, and stops it last. The phones are on the laptop's network, and
reach its ports 8090 and 8443. On a Mac, allow `sig0lease`'s incoming connections when asked.
The page reaches the proxy over plain HTTP on the venue's network: every update is signed with
the phone's key, so nobody can forge one, but anyone there can read them.

### With the registrar

The page, still served by the laptop, sends its questions and updates over DNS-over-HTTPS to the
registrar, at `https://$REG/dns-query` (port 443): the phones need the laptop's port 8090 and the
internet, not the laptop's port 8443. `DOH` gives the registrar's DNS-over-HTTPS, without
`/dns-query`, when it is on another port, as staging's is. The registrar serves the page too, at
`https://$REG/`, and staging's, on its subtrees, at `https://$REG:8444/` (deploy/README.md).

## After a demo

- Ctrl-C the agents, then the site and the proxy. The records go at once, and so do the names
  (`on_stop: release`). For D3, `n` in each `demo/ipfs.sh`, the IPFS community node's last: a
  member keeps its label for an hour; after a local test, also `demo/ipfs-local.sh stop`. For D5,
  `n` in each `demo/chat.sh`; for D6, in `demo/web.sh` (the names the phones claimed stay theirs
  for up to 30 minutes).
- To hold the names for their keys after stopping instead, set `on_stop: keep` in the
  registrars of `demo/demo.yaml` and `demo/mac.yaml`: a host for 14 days and a name for 30
  minutes (the proxy's `config.yaml` caps an RFC 9664 key lease at 1800 s).
- Undo D4's search domain.

## When something fails

- Local test: a script stops at once: "Port 8053, for this demo's proxy, is in use". Another
  demo still runs, or a proxy started by hand (D1, "By hand"): stop it, then start the demo's
  script again.
- Local test: the proxy stops at once: "the lease store of `<handler>` holds `<name>`, which it
  does not serve" in `proxy.log`. Its lease stores, in `data/`, hold names from a run with other
  subtrees, which an earlier run did not free: D6's phones' claims stay up to 30 minutes, or a
  script was killed. Run a demo with those subtrees until their leases are over, then stop it.
- Local test: a script stops at once, as "TRANSPORT is how the agents reach REGISTRAR, which is
  not set", or "DOH is the registrar's DoH server, for REGISTRAR, which is not set": it got
  `TRANSPORT` or `DOH` without `REGISTRAR`, from the command or, exported, from the terminal
  (`env | grep -E '^(REGISTRAR|TRANSPORT|DOH)='`).
- Local test: the proxy logs errors reaching `ns1.free2air.org`: the network blocks port 53. Use
  a phone's hotspot, or the recording.
- The agent logs a name held by another key: choose another label ("Before a demo", step 3).
- D3: `demo/ipfs.sh member` waits until "alice is listed": the member's instance is registered
  once its node's swarm port answers the agent's probe at the addresses it publishes;
  `agent.log`, in the directory `demo/ipfs.sh member` printed, says why not. A label another key
  holds is renamed (`renamed: now host alice-2, "alice" _ipfs-member._tcp as "alice-2"`), and
  `demo/ipfs.sh member` follows: that is another member.
- D3: `demo/ipfs.sh member` says "could not connect to the IPFS community node …", and waits until the
  community's folder has the member's: its node does not reach the IPFS community node, and
  `ipfs swarm peers` on it lists nobody. Is its swarm key the community's (`ipfs daemon` logs the
  key's fingerprint)? With the registrar, does the network let it out to the IPFS community node's
  swarm port?
- D3: the IPFS community node says "…: not a member: …": an instance under `site`'s subtype whose
  label is not letters, digits and hyphens, whose name has no KEY or several, or whose
  `swarm-mac=` its swarm key does not make: that node's `swarm.key` is not the community's. The
  IPFS community node leaves it out.
- D3, local test: phones get no answer from the gateway, and `community ipfs-gateway` is not
  registered: the IPFS community node's gateway listens on 127.0.0.1 only (`Addresses.Gateway` in
  `~/.ipfs-community/config`, which `demo/ipfs-local.sh start` sets to 0.0.0.0, port 8081), or
  the laptop's firewall blocks port 8081.
- `watch.sh` shows a record and the audience does not: their resolver answered "no such name"
  before it was published. Ask `@ns1.free2air.org`, or wait up to 6 minutes.
- `demo http` is never registered: the probe asks the site at the published addresses
  (`$B/sig0lease-agent plan demo/demo.yaml` lists them); a firewall may block port 8000. On a Mac,
  allow `python3`'s incoming connections when asked.
- D5: B's guests cannot join A's room ("remote-server-timeout"). The servers' logs are in the
  directory `chat.sh` printed (`<name>-prosody.log`). "does not match any DANE TLSA records": the
  record is not for the key the server uses. Other DNSSEC failures: Prosody resolves from the
  DNS root itself, which a network blocking outgoing port 53 prevents; add
  `forward = { "9.9.9.9" }` to `unbound` in `demo/chat/prosody.cfg.lua`, a resolver that passes
  the signatures on, which Prosody still checks. Without DANE, `s2s_secure_auth = false` there
  lets the servers fall back to dialback.
- D5: a phone cannot open the page by name: the venue's resolver hides answers with private
  addresses. The address line `chat.sh` prints, and its QR code, need no name.
- D5: the records list a Docker or VPN address that other machines cannot reach: give the
  venue's with `ADDRESS=<address>`.
- D6, local test: the page says the DNS client did not start, or cannot read the services: the
  phone does not reach port 8443. On a Mac, allow `sig0lease`'s incoming connections when asked.
  If `web.sh` printed a Docker or VPN address, give the venue's with `ADDRESS=<address>`.
- D6: a claim stays `waiting` with no other message shown: the log under the page says why.
- D6: the page cannot read the names, as the zone "has no NSEC record": it is not signed with
  NSEC, as a shared registrar's zone may not be. The services and the claims still work.
