# Demos: publishing on the live zenr.io zone

The demos publish names, services and records in the live zone `zenr.io.`: a laptop's site and
services, an IPFS folder, chat servers, names that phones claim from a web page.
`sig0lease-agent`, or the DNS client in that page (D6), sends each update through the sig0lease
proxy, which the demo starts on the presenter's laptop (local proxy), or an online deployment of
it (the registrar). The proxy forwards each update to the real authoritative server of `zenr.io.`
(`ns1.free2air.org`). The audience looks from their own devices, with the DNS tools they already
have. Everything runs from the repository root, with the files in [`demo/`](../demo).

Each demo runs in two ways: as a local test, where its script starts the proxy on the laptop, or
with the registrar, where it starts none ("Running a demo"). A demo's section has three parts:
"Common to both", then "Local test" and "With the registrar", which say what is particular to
each. D4 adds to D1 or D6 and has no such parts: it is the same both ways.

| Demo | What the audience sees | Needs |
|---|---|---|
| D1: the laptop publishes itself | its site among browse results and under a name; a service leaves when it stops and comes back; a template edit shows within seconds; a second key gets `demo-2`, and is refused the name | the laptop |
| D2: the Mac's own services | turning on Remote Login or Screen Sharing puts it in the public zone | a Mac |
| D3: a community folder over IPFS | phones open the members' folders by name from the community node, which finds each member by browsing as it comes up, pins its folder before publishing it, keeps serving it while the member is away, and drops it once the member stays away; the nodes find each other by DNS alone, in a private swarm | the laptop with IPFS Desktop or kubo, or with the registrar, the members' machines; phones |
| D4: native discovery | an audience Mac lists the laptop's services beside its `local.` ones | a Mac in the audience |
| D5: two communities meet in one chat room | phones log in as guests of two laptops' XMPP servers and talk in one room; the servers find each other by SRV records and trust each other's self-signed certificates by TLSA records (DANE) | two machines, each with Docker (a Mac) or Prosody 13 (Linux); phones |
| D6: the zone in a browser | phones watch the services come and go, and the zone's names with their records; they claim a name with a message, held by a key their browser makes, and every phone lists it; `dig` shows it within seconds | the laptop; phones |

The demos use this repository's programs and tools that come with the system, except IPFS
Desktop or kubo for D3, and Prosody for D5, whose page loads Converse.js from `cdn.jsdelivr.net`.

## Running a demo

Each demo is a script in `demo/`. A script builds what it runs, starts it, and pauses before each
step until Enter. Its last Enter, or Ctrl-C, stops what it started, its agents first, which free
the demo's names. Its first lines list the other variables it reads, such as `NAME` or
`ADDRESS`, which go before the command the same way.

Variables tell a script which registrar the agents use and where the demo's names go. They are
defined here, once: paste the block of your case, below, in each terminal, and the commands in
this document use them.

### Local test: the laptop's own proxy

```bash
REGISTRAR= DOH= UPDATE_DOMAIN=local.dev.zenr.io SRP_DOMAIN=srp.local.dev.zenr.io
```

Each script starts its own proxy, on 127.0.0.1:8053, with the config its demo needs, and refuses to
start while another proxy runs on the machine, another demo's included: run one demo at a time. The
proxy serves the block's subtrees, `local.dev.zenr.io` and `srp.local.dev.zenr.io` or any others
written in it, such as `stg.zenr.io` and `srp.stg.zenr.io`, and signs its updates for each with the
key in `keystore/server` at the closest name at or above it; it does not start without one. It ends
a lease only while it runs, which is while its script does.

### With the registrar

The registrar's instance, where `<registrar>` is the registrar's host name, which its
operators give (it is in no file of this repository):

```bash
REG=<registrar>
#Stable:
REGISTRAR=$REG:8053 DOH= UPDATE_DOMAIN=dev.zenr.io SRP_DOMAIN=srp.dev.zenr.io
#Staging:
REGISTRAR=$REG:8054 DOH=https://$REG:8444 UPDATE_DOMAIN=stg.zenr.io SRP_DOMAIN=srp.stg.zenr.io
```

With `REGISTRAR`, the agents send their updates to that registrar: a script starts no proxy, and
checks no ports for one.

- `TRANSPORT`, before the command with `REGISTRAR`, is how the agents reach it: `tcp`, their
  default, `udp`, `tls` with the registrar's DNS-over-TLS port in `REGISTRAR` (staging's 8853,
  stable's 853), or `doh` with `REGISTRAR=https://$REG:8444` (stable: `https://$REG`).
- The registrar's stable instance, in place of staging's block:
  `REGISTRAR=$REG:8053 DOH= UPDATE_DOMAIN=dev.zenr.io SRP_DOMAIN=srp.dev.zenr.io` (its
  DNS-over-HTTPS is on port 443, `web.sh`'s default).
- `UPDATE_DOMAIN`, and `SRP_DOMAIN` unless it is `srp.$UPDATE_DOMAIN`, are the registrar's
  subtrees ("Where the names go"), which its operators give with its address: a script stops
  without `UPDATE_DOMAIN`.
- Other people use the same registrar, which gives each name to the first key that claims it,
  for as long as that key's lease lasts. One of the demo's names may already be someone else's:
  check them ("Before a demo"). The registrar's own lease limits apply.
- A shared registrar keeps its error reasons and its lease-store dump to itself
  (`server.diagnostics` off): a refusal shows only its Extended DNS Error's code, and
  `demo/leftovers.sh -r` cannot read its stores.

### Reading the commands

A part of a command in `<…>` is optional. The one with the pasted block's variables,
`<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN>`, hands the demo's script the block you
pasted: write it without `<` and `>` for the registrar's block, or for a local one with other
subtrees than `local.dev.zenr.io`. Left out, the demo's script uses the laptop's own proxy and
the subtrees `local.dev.zenr.io` and `srp.local.dev.zenr.io`. `SRP_DOMAIN=$SRP_DOMAIN` goes in it
too for subtrees whose `SRP_DOMAIN` is not `srp.$UPDATE_DOMAIN`. Any other, such as
`<MEMBER=…>`, is written or left out as its demo says, either way.

### Where the names go

The zone is `zenr.io.`. The demos' names go in two subtrees of it, one for each of the proxy's
handlers:

- `UPDATE_DOMAIN`: names a key holds, with any records (RFC 9664, `update_handler`), such as
  D1's `demo.$UPDATE_DOMAIN`.
- `SRP_DOMAIN`: hosts and the services they register, which DNS-SD browses (RFC 9665,
  `srp_handler`), such as D1's `demo.$SRP_DOMAIN`; by default `SRP_DOMAIN`=`srp.$UPDATE_DOMAIN`. It may be
  elsewhere in the zone, but not at or above `UPDATE_DOMAIN`: D6's page lists the names in
  `UPDATE_DOMAIN` outside `SRP_DOMAIN`.

With neither set, the scripts use `local.dev.zenr.io` and `srp.local.dev.zenr.io`, apart from
the registrar's subtrees, so that a local test's names are free of the names people register
through the registrar, its own community node's included. `local.dev.zenr.io` itself has a KEY
of the zone's operator. Without it, anyone registering through the registrar could take that
name, one label below the registrar's `dev.zenr.io`, and with it write records at every name a
laptop's proxy puts below it. Check that it has one: `dig +short KEY local.dev.zenr.io
@ns1.free2air.org`.

The proxy's config and the agents' templates in the repository are written for `dev.zenr.io` and
`srp.dev.zenr.io`, for runs by hand: `config.yaml` serves `srp.dev.zenr.io.` and `dev.zenr.io.`, and
`demo/demo.yaml` registers the host `demo` in `srp.dev.zenr.io.` and the name `demo.dev.zenr.io.`,
at the laptop's proxy, `127.0.0.1:8053`. So that the same files serve any subtrees and any
registrar, a script never runs them as they are: it writes a copy of each into the run's log
directory, starts the proxy and the agents with the copies, and leaves `config.yaml` and the files
in `demo/` as they are, for runs by hand.

In the copy of `config.yaml`, which a script writes only without `REGISTRAR`, as it then starts
the proxy:

- `handlers.srp_handler.upstream_zone`, `srp_handler`'s subtree, is `SRP_DOMAIN`;
- `handlers.update.upstream_zone`, `update_handler`'s, is `UPDATE_DOMAIN`.

In the copy of a template:

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

### Demos on two machines

D5 runs on two machines, A and B, on the same network, or on one machine. A Docker container as
one of them has not been tried: its agent would publish the container's own addresses, which
neither the other machine nor the phones reach, unless `ADDRESS` gives the host's and the
container publishes the demo's ports.

## Before a demo

1. Build, and name the binaries' directory, for the commands run by hand (each script builds what
   it runs itself):

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

   | Demo | `NAME` | What it shows when the names are free | If one is taken, write another label |
   |---|---|---|---|
   | D1, D2, D6 | `demo`, the default | `(no records)` under `demo`, and no `demo` instance; the same with the registrar | in `demo/demo.yaml` and `demo/conflict.yaml`, and as `NAME` (below) |
   | D3, local test | `site` | `(no records)` under `site`, no `community ipfs-gateway` instance, and no `alice` or `carol` instance | as `SITE=…` before the three commands, in the members' peer lists, and as `NAME`; a member's as `MEMBER=…`; the gateway's as `HOST=…` |
   | D3, with the registrar | `site` | `site` is the registrar's community node's, and stays so: its `KEY`; its `_dnslink TXT`, the community's folder (`QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn`, an empty folder, while no member was listed in the last 10 minutes); its `_dnsaddr TXT`, the node's addresses. Only the members' labels have to be free: no instance with a member's label | a member's as `MEMBER=…` |
   | D5 | `"chat-a chat-b"` | `(no records)` under each; the same with the registrar | as `chat.sh`'s arguments, in `ROOM`, and as `NAME` |

   For D1, D2 and D6, write the other label, say `demo7`, in place of `demo` in `demo/demo.yaml`
   and `demo/conflict.yaml`, twice in each: the host, `name: demo`, and the first label of the
   name, `name: demo.dev.zenr.io.` (only that label: the scripts replace the rest with
   `UPDATE_DOMAIN`, "Where the names go"). Then put `NAME=demo7` before the commands of `run.sh`,
   `web.sh` and `watch.sh`, such as `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN>
   NAME=demo7 demo/run.sh`.

4. Record a run: if the venue's network blocks port 53, the recording is the demo.

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

Members keep a folder each in their IPFS node. A community node finds each member by browsing
as it comes up, pins its folder, and keeps a folder with an entry for each member, which its
gateway serves to phones. Two ways to run it:

- **Local test**: everything on the laptop: the community node and two members, alice and
  carol, as three IPFS nodes, and one proxy. Phones on the laptop's network open the gateway.
- **With the registrar**: the registrar's own community node, always on, with its gateway on the
  internet. Only the members run `demo/ipfs.sh member`, on any machines; phones open the folder
  from anywhere.

### Common to both

What the agents publish, which `<UPDATE_DOMAIN=$UPDATE_DOMAIN> NAME=site demo/watch.sh` shows:

| Record | Published by | Changes when |
|---|---|---|
| `alice._ipfs-member._tcp.$SRP_DOMAIN` SRV, and TXT `dnslink=/ipfs/<CID>` `swarm-mac=<MAC>` | each member, under its label | its folder changes; withdrawn while its node's swarm port does not answer, and when it stops |
| `site._sub._ipfs-member._tcp.$SRP_DOMAIN` PTR | each member | a member comes or goes |
| `_dnslink.site.$UPDATE_DOMAIN` TXT | the community node | it has pinned a member's new folder, or removed a member's entry |
| `_dnsaddr.site.$UPDATE_DOMAIN` TXT | the community node | its node's addresses change |
| `community ipfs-gateway` in `$SRP_DOMAIN` | the local test's community node | its gateway starts or stops answering |

`/ipns/site.$UPDATE_DOMAIN/alice/` is alice's folder. A member is its label, `MEMBER`, by default
the machine's name, which its key holds: a member that stops comes back to its label as the same
member. The community node keeps an absent member's entry for `REVOKE_AFTER`, then removes it and
unpins its folder. Only nodes with the community's swarm key are members: a member's TXT record
gives a `swarm-mac=` that the swarm key makes from its KEY and its folder's CID, and the community
node pins nothing whose `swarm-mac=` it cannot make ([sig0lease-agent.md](sig0lease-agent.md),
"Who is a member").

Each IPFS node is configured once, stopped (quit IPFS Desktop, or stop `ipfs daemon`), with
`IPFS_PATH` set to its repository (left unset for `~/.ipfs`, IPFS Desktop's):

```bash
ipfs config profile apply autoconf-off               # no public peers, resolvers or routers
ipfs config Routing.Type dht
ipfs config --json AutoTLS.Enabled false
ipfs config --json Swarm.Transports.Network.Websocket false
ipfs config --json Discovery.MDNS.Enabled false      # nodes find each other by DNS alone
```

A node is in one private swarm, whose key is its repository's `swarm.key`: going from the local
test to the registrar's community node, or back, means replacing `~/.ipfs/swarm.key` and
restarting the node. The key never goes into DNS or this repository.

### Local test

**Needs**: the laptop, with kubo's `ipfs` command, and IPFS Desktop or `ipfs daemon` for alice's
node, `~/.ipfs`; `qrencode` (`brew install qrencode` on a Mac, `sudo apt install qrencode` on
Linux); phones on the laptop's network, which reach its port 8081.

**Once**:

1. Make the community node's and carol's repositories, and configure all three nodes as above:

   ```bash
   IPFS_PATH=~/.ipfs-community ipfs init
   IPFS_PATH=~/.ipfs-carol ipfs init
   ```

2. Give those two their own ports; the community node's gateway listens on the network, for
   the phones:

   ```bash
   IPFS_PATH=~/.ipfs-community ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8081
   IPFS_PATH=~/.ipfs-community ipfs config Addresses.API /ip4/127.0.0.1/tcp/5002
   IPFS_PATH=~/.ipfs-community ipfs config --json Addresses.Swarm '["/ip4/0.0.0.0/tcp/4002", "/ip4/0.0.0.0/udp/4002/quic-v1"]'
   IPFS_PATH=~/.ipfs-carol ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8082
   IPFS_PATH=~/.ipfs-carol ipfs config Addresses.API /ip4/127.0.0.1/tcp/5003
   IPFS_PATH=~/.ipfs-carol ipfs config --json Addresses.Swarm '["/ip4/0.0.0.0/tcp/4003", "/ip4/0.0.0.0/udp/4003/quic-v1"]'
   ```

3. Make the community's swarm key, and give it to all three:

   ```bash
   printf '/key/swarm/psk/1.0.0/\n/base16/\n%s\n' "$(openssl rand -hex 32)" > ~/.ipfs/swarm.key
   cp ~/.ipfs/swarm.key ~/.ipfs-community/
   cp ~/.ipfs/swarm.key ~/.ipfs-carol/
   ```

4. Put the community node in the members' peer lists, with the laptop's block pasted:

   ```bash
   id=$(IPFS_PATH=~/.ipfs-community ipfs id -f '<id>')
   ipfs bootstrap add /dnsaddr/site.$UPDATE_DOMAIN/p2p/$id
   IPFS_PATH=~/.ipfs-carol ipfs bootstrap add /dnsaddr/site.$UPDATE_DOMAIN/p2p/$id
   ```

5. Start the three nodes: IPFS Desktop, or `ipfs daemon`, for alice's, and each of these in a
   terminal of its own. Each says "Swarm is limited to private network of peers with the swarm
   key"; the members say "failed to bootstrap (no peers found)": `demo/ipfs.sh member` connects
   them to the community node, in "Run", step 3.

   ```bash
   IPFS_PATH=~/.ipfs-community ipfs daemon
   IPFS_PATH=~/.ipfs-carol ipfs daemon
   ```

6. Give each member its folder, `/community`, with a first file (IPFS Desktop: Files, New folder,
   then Import):

   ```bash
   ipfs files mkdir /community
   ipfs files cp /ipfs/$(ipfs add -Q photo.jpg) /community/photo.jpg
   IPFS_PATH=~/.ipfs-carol ipfs files mkdir /community
   IPFS_PATH=~/.ipfs-carol ipfs files cp /ipfs/$(IPFS_PATH=~/.ipfs-carol ipfs add -Q photo.jpg) /community/photo.jpg
   ```

**Run**, with the laptop's block pasted in each terminal:

1. A screen shows `NAME=site demo/watch.sh`.
2. Start the community node, which also starts the proxy:

   ```bash
   UPDATE_DOMAIN=$UPDATE_DOMAIN REVOKE_AFTER=2m IPFS_PATH=~/.ipfs-community IPFS_API=http://127.0.0.1:5002 GATEWAY=8081 demo/ipfs.sh community
   ```

   `_dnslink.site`, an empty folder, and `_dnsaddr.site` appear. It prints the gateway's
   address, `http://community.$SRP_DOMAIN:8081/ipns/site.$UPDATE_DOMAIN/`, with a QR code, then
   each member as it comes and goes.
3. Start the members, each in a terminal of its own; they use the community node's proxy:

   ```bash
   REGISTRAR=127.0.0.1:8053 UPDATE_DOMAIN=$UPDATE_DOMAIN MEMBER=alice demo/ipfs.sh member
   REGISTRAR=127.0.0.1:8053 UPDATE_DOMAIN=$UPDATE_DOMAIN MEMBER=carol IPFS_PATH=~/.ipfs-carol IPFS_API=http://127.0.0.1:5003 demo/ipfs.sh member
   ```

   Each appears under `_ipfs-member._tcp`, and `demo/ipfs.sh member` makes the community node a
   peering peer of the member's node, at the addresses `_dnsaddr.site` gives ("connected to the
   community node at …, a peering peer of its node"; IPFS Desktop's Peers lists it). The
   community node says "alice is a member", then "pinned …, alice's folder" and "alice's entry
   gives …"; `demo/ipfs.sh member` waits until then.
4. Phones scan the QR code: a folder for each member, with its files.
5. Drag a photo into `/community` on alice's node (IPFS Desktop, Files). Within about 15 s
   alice's TXT record changes, and within about 15 s more `_dnslink.site`: each agent reads its
   node, and the community node lists the members, every 10 s. A phone's reload shows the photo
   within about a minute, once the gateway's cached `site`, 30 s, is over.
6. `https://dweb.link/ipns/site.$UPDATE_DOMAIN/`, a public gateway, reads the name but cannot
   find the folder: no node outside the private swarm has it.
7. alice leaves for a while: quit IPFS Desktop (alice's instance goes within about 15 s), or
   Enter in alice's `ipfs.sh`. The community node says "alice is not listed; its entry goes in
   2m0s unless it is again", and phones still load alice's folder. Start it again within that
   time: "alice is listed again", and the entry stays.
8. carol leaves for good: Enter in carol's `ipfs.sh`. Two minutes later the community node says
   "carol is not listed for 2m0s: no longer a member", and carol's folder goes from the site and
   from its pins.
9. Enter in the community node's `ipfs.sh`, last: it stops the proxy too.

A member that stops keeps its label for an hour, its key's lease, as long as the proxy runs. The
community node keeps the community's folder for the next run, in its files at
`/sig0lease-agent/site.$UPDATE_DOMAIN`, with the members' folders pinned under
`sig0lease-agent site.$UPDATE_DOMAIN.`; a member's key is in `demo/keys-ipfs-member-<MEMBER>`.

### With the registrar

The registrar runs the community node (deploy/README.md, "The community node"), always on, at a
public address. It lists the members of `site` in `$SRP_DOMAIN`, keeps the community's folder
at `site.$UPDATE_DOMAIN`, and serves it at `${DOH:-https://$REG}/ipns/site.$UPDATE_DOMAIN/`. A
member's node, behind the venue's NAT, connects to it; it never connects to a member's. An absent
member's entry stays for 10 minutes. A member that stops keeps its label for an hour, its key's
lease; one whose machine sleeps or leaves the network is no longer listed about 2 minutes later,
when its instance's lease ends.

**Needs**: on each member's machine, IPFS Desktop or kubo, and `qrencode`; a network that lets
the members' nodes reach the community node's swarm port, the port in the addresses
`dig +short TXT _dnsaddr.site.$UPDATE_DOMAIN @ns1.free2air.org` gives; the registrar's block
pasted.

**Once**, on each member's machine:

1. Configure its node as above.
2. Put the community's swarm key, which the registrar's operators give
   (`keystore/ipfs/<instance>/swarm.key` on the machine that deploys the node), in
   `~/.ipfs/swarm.key`.
3. Put the community node in its peer list, by its name and the ID at the end of each address
   `_dnsaddr.site` gives:

   ```bash
   dig +short TXT _dnsaddr.site.$UPDATE_DOMAIN @ns1.free2air.org
   ipfs bootstrap add /dnsaddr/site.$UPDATE_DOMAIN/p2p/<the ID>
   ```

4. Start the node, and make its folder, `/community`, with a first file, as in the local test.

**Run**:

1. A screen shows `UPDATE_DOMAIN=$UPDATE_DOMAIN NAME=site demo/watch.sh`, and IPFS Desktop's
   Peers on alice's machine, which lists the community node.
2. On alice's machine, then on each other member's:

   ```bash
   REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN <MEMBER=…> COMMUNITY_GATEWAY=${DOH:-https://$REG} demo/ipfs.sh member
   ```

   The member appears under `_ipfs-member._tcp`, and its node connects to the community node,
   as in the local test; the community node pins its folder, and `_dnslink.site` gives it,
   within seconds. `demo/ipfs.sh member` prints the address of the member's folder at the
   registrar, with a QR code.
3. Phones scan it, on any network: the folder's files. The community's folder is at
   `${DOH:-https://$REG}/ipns/site.$UPDATE_DOMAIN/`.
4. Drag a photo into `/community` on alice's machine (IPFS Desktop, Files): a phone's reload
   shows it within about a minute.
5. alice leaves: Enter in alice's `ipfs.sh`, or quit IPFS Desktop. alice's instance goes; its
   entry stays for 10 minutes, and phones still load its folder; back within them, it carries on
   as the same member.

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

Two machines, A and B, each run an XMPP server (Prosody) for a community: A's guests get
addresses at `chat-a.$UPDATE_DOMAIN` and its rooms are at `rooms.chat-a.$UPDATE_DOMAIN`; B's, at
`chat-b`. The agent on each publishes its server's addresses, the SRV records that tell other
servers where it listens (`_xmpp-server._tcp`, for the name and for `rooms`) and clients where to
log in (`_xmpp-client._tcp`), and a TLSA record with the hash of the server's key. The
certificates are self-signed: a server accepts another only when its key matches its TLSA
record, which DNSSEC vouches for (DANE). Nothing is configured between the two servers, and
nobody makes an account.

### Common to both

**Needs**:

- Two machines, A and B, each with: on a Mac, Docker Desktop, then
  `docker pull prosodyim/prosody:13.0`; on Linux, Prosody 13 (`apt install prosody` on Debian
  13, which brings luaunbound, then `sudo systemctl disable --now prosody`: the package's own
  server would hold the ports), or Docker with `PROSODY=docker`. Also `qrencode`, as for D3.
- Ports 5222, 5269 and 5280 open to the network on each.
- Phones on the network, which also reach the internet, for Converse.js.

**Run**:

1. On A and B:

   ```bash
   <REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> demo/chat.sh chat-a
   <REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> ROOM=meet@rooms.chat-a.$UPDATE_DOMAIN demo/chat.sh chat-b
   ```

   Each starts its server (in Docker on a Mac, Prosody installed on Linux; `PROSODY=docker` or
   `native` chooses) and its agent, waits until `ns1.free2air.org` has the records, and prints
   the address of the page its server serves, and its QR code. On a Mac, allow Docker's incoming
   connections when asked; on Linux, the firewall has to let in ports 5222, 5269 and 5280.
2. Show what the other server reads:

   ```bash
   dig +short SRV _xmpp-server._tcp.rooms.chat-a.$UPDATE_DOMAIN   # 0 0 5269 chat-a.<UPDATE_DOMAIN>.
   dig +dnssec TLSA _5269._tcp.chat-a.$UPDATE_DOMAIN @8.8.8.8    # the ad flag: validated
   ```

3. Half the room scans A's QR code, half B's. The page (Converse.js) logs each phone in as a
   guest of that server and joins `meet@rooms.chat-a.$UPDATE_DOMAIN`; the first one in creates the
   room. B's guests' messages reach A's room over a connection between the servers that each end
   authenticated by the other's TLSA record.
4. Enter, or Ctrl-C, in `chat.sh` stops the agent first, which frees the names, then the server.

**On one machine**: `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> demo/chat.sh chat-a
chat-b`, which runs both servers, giving the second ports 10 above: 5232, 5279, 5290.

Phones talk to their server over plain HTTP on the venue's network, so the guests' messages are
not encrypted there; the servers talk to each other over TLS. Each server keeps its certificate
and key in `demo/chat/servers/<name>/`, so its TLSA record is the same at every run; delete the
directory for a new key. A server whose key its TLSA record does not match is refused
("certificate does not match any DANE TLSA records" in the other server's log), as a test run
showed.

### Local test

Each `chat.sh` also starts a proxy on its machine, before the agent, and stops it last; on one
machine, the one `chat.sh` starts one.

### With the registrar

Both agents register through the registrar, which gives `chat-a` and `chat-b` to the first key
that claims them: check that they are free ("Before a demo", step 3).

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
   zone's other names, marked `no key`. At the next Enter, `web.sh` stops the site, and after
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
4. "Release the name" deletes the message and frees the name. The last Enter, or Ctrl-C, in
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
  (`on_stop: release`). For D3, Enter in each `demo/ipfs.sh`, the community node's last: a
  member keeps its label for an hour; for D5, in each `demo/chat.sh`;
  for D6, in `demo/web.sh` (the names the phones claimed stay theirs for up to 30 minutes).
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
- D3: `demo/ipfs.sh member` says "could not connect to the community node …", and waits until the
  community's folder has the member's: its node does not reach the community node, and
  `ipfs swarm peers` on it lists nobody. Is its swarm key the community's (`ipfs daemon` logs the
  key's fingerprint)? With the registrar, does the network let it out to the community node's
  swarm port?
- D3: the community node says "…: not a member: …": an instance under `site`'s subtype whose
  label is not letters, digits and hyphens, whose name has no KEY or several, or whose
  `swarm-mac=` its swarm key does not make: that node's `swarm.key` is not the community's. The
  community node leaves it out.
- D3, local test: phones get no answer from the gateway, and `community ipfs-gateway` is not
  registered: the community node's gateway listens on 127.0.0.1 only (D3's "Once", step 2), or
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
