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
| D3: a community folder over IPFS | phones open the members' folders by name from the community node, which finds each member by browsing as it comes up, pins its folder before publishing it, keeps serving it while the member is away, and drops it once the member stays away; the nodes find each other by DNS alone, in a private swarm | machines with IPFS Desktop or kubo, a community node and members, or one machine; or members alone with the registrar's community node; phones |
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
REGISTRAR= DOH= UPDATE_DOMAIN=dev.zenr.io SRP_DOMAIN=srp.dev.zenr.io
```

Each script starts its own proxy, on 127.0.0.1:8053, with the config its demo needs, and refuses
to start while another proxy runs on the machine, another demo's included: run one demo at a
time. The proxy serves the subtrees `dev.zenr.io` and `srp.dev.zenr.io`, and signs its updates
for each with the key in `keystore/server` at the closest name at or above it; it does not start
without one. It ends a lease only while it runs, which is while its script does.

### With the registrar

The registrar's staging instance, where `<registrar>` is the registrar's host name, which its
operators give (it is in no file of this repository):

```bash
REG=<registrar>
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

### Commands

A part of a command in `<…>` is optional. The one with the pasted block's variables,
`<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN>`, is for the registrar: in a local test,
leave it out, and a script uses the laptop's own proxy and the subtrees `dev.zenr.io` and
`srp.dev.zenr.io`; with the registrar, write it without `<` and `>`, and it takes what the pasted
block gives. `SRP_DOMAIN=$SRP_DOMAIN` goes in it too for subtrees whose `SRP_DOMAIN` is not
`srp.$UPDATE_DOMAIN`. Any other, such as `<MEMBER=…>`, is written or left out as its demo says,
either way.

| Demo | Command |
|---|---|
| D1 | `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> demo/run.sh` |
| D2 | the same, on a Mac: its step 5 |
| D3, on the community node | `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> REVOKE_AFTER=2m demo/ipfs.sh community` |
| D3, on each member | `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> <MEMBER=…> demo/ipfs.sh member` |
| D3, with staging's community node | on each member only: `REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN <MEMBER=…> COMMUNITY_GATEWAY=https://$REG:8444 demo/ipfs.sh member` |
| D3, on one machine | D3's "On one machine" |
| D4 | D4's commands, on a Mac, while D1 or D6 runs |
| D5, on A | `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> demo/chat.sh chat-a` |
| D5, on B | `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> ROOM=meet@rooms.chat-a.$UPDATE_DOMAIN demo/chat.sh chat-b` |
| D5, on one machine | `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> demo/chat.sh chat-a chat-b` |
| D6 | `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN DOH=$DOH> demo/web.sh` |
| What anyone can see | `<UPDATE_DOMAIN=$UPDATE_DOMAIN> <NAME=…> demo/watch.sh`, `NAME` the demo's labels ("Before a demo") |

### Where the names go

The zone is `zenr.io.`. The demos' names go in two subtrees of it, one for each of the proxy's
handlers:

- `UPDATE_DOMAIN`: names a key holds, with any records (RFC 9664, `update_handler`), such as
  D1's `demo.$UPDATE_DOMAIN`.
- `SRP_DOMAIN`: hosts and the services they register, which DNS-SD browses (RFC 9665,
  `srp_handler`), such as D1's `demo.$SRP_DOMAIN`; by default `SRP_DOMAIN`=`srp.$UPDATE_DOMAIN`. It may be
  elsewhere in the zone, but not at or above `UPDATE_DOMAIN`: D6's page lists the names in
  `UPDATE_DOMAIN` outside `SRP_DOMAIN`.

With neither set, the scripts use `dev.zenr.io` and `srp.dev.zenr.io`. A script that starts the
proxy on the laptop gives it these two subtrees.

The templates in `demo/` are written for the default subtrees and the laptop's proxy:
`demo/demo.yaml` registers the host `demo` in `srp.dev.zenr.io.` and the name
`demo.dev.zenr.io.`, at `127.0.0.1:8053`. So that the same files serve any subtrees and any
registrar, a script never gives the agent a template as it is: it writes a copy of it into the
run's log directory, the agent runs that copy, and the files in `demo/` stay as they are, for
runs by hand. In the copy:

- each srp registrar's `domain:` is `SRP_DOMAIN`;
- each RFC 9664 name keeps its first label, the part before the first dot, and the rest is
  `UPDATE_DOMAIN`: `demo.dev.zenr.io.` becomes `demo.$UPDATE_DOMAIN.`;
- with `REGISTRAR`, `server: 127.0.0.1:8053` is `REGISTRAR`.

The copy stays beside the run's logs, so it shows what the agent was given. Every template a
script runs goes through this: `demo/demo.yaml`, `demo/conflict.yaml`, `demo/mac.yaml`, and the
ones `ipfs.sh` and `chat.sh` write.

### Demos on two machines

D3 runs on the community node and a machine for each member; D5 on two machines, A and B; all
on the same network. Each also runs on one machine, as its section says, and D3 with the
registrar's community node. A Docker container as one of these machines has not been tried: its
agent would publish the container's own addresses, which neither the other machines nor the
phones reach, unless `ADDRESS` gives the host's and the container publishes the demo's ports.

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
   (`on_stop: release`), so someone else may take them in between.
   `<UPDATE_DOMAIN=$UPDATE_DOMAIN> NAME=… demo/watch.sh once`, with the demo's labels as `NAME`,
   shows `(no records)` under each, and for D1, D2 and D6 no `demo` instance:

   | Demo | `NAME` | Another label |
   |---|---|---|
   | D1, D2, D6 | `demo`, the default | in `demo/demo.yaml` and `demo/conflict.yaml`, below |
   | D3 | `site` | `SITE`, on every script and in the members' peer lists; a member's label is `MEMBER` |
   | D5 | `"chat-a chat-b"` | `chat.sh`'s arguments, and `ROOM` |

   With staging's community node as D3's, `site` is the node's, and stays so.

   For D1, D2 and D6, write the other label, say `demo7`, in place of `demo` in `demo/demo.yaml`
   and `demo/conflict.yaml`, twice in each: the host, `name: demo`, and the first label of the
   name, `name: demo.dev.zenr.io.` (only that label: the scripts replace the rest with
   `UPDATE_DOMAIN`, "Where the names go"). Then put `NAME=demo7` before the commands of `run.sh`,
   `web.sh` and `watch.sh`, such as `<REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN>
   NAME=demo7 demo/run.sh`.

4. Record a run: if the venue's network blocks port 53, the recording is the demo.

While a demo runs:

- The projector shows `<UPDATE_DOMAIN=$UPDATE_DOMAIN> NAME=… demo/watch.sh`, with the demo's
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

**By hand**, in these terminals:

| | Command | What it is |
|---|---|---|
| 1 | `$B/sig0lease` | the proxy, on 127.0.0.1:8053, with `config.yaml`: `srp_handler` for `srp.dev.zenr.io.`, `update_handler` for `dev.zenr.io.`, signing upstream with `keystore/server` |
| 2 | `python3 -m http.server 8000 -d demo/site` | the site |
| 3 | `$B/sig0lease-agent run -probe-interval 5s demo/demo.yaml` | the agent: host `demo`, its services and the name `demo` |
| 4 | `demo/watch.sh` | what anyone can see |

The subtrees are then the ones `config.yaml` and `demo/demo.yaml` give, `dev.zenr.io` and
`srp.dev.zenr.io`. Step 1 is starting terminals 1 to 4; step 2, Ctrl-C in terminal 2, then
starting it again; step 3, uncommenting the `hello` record in `demo/demo.yaml`, with your text,
and saving it; step 4, in a fifth terminal, `$B/sig0lease-agent run -probe-interval 5s
demo/conflict.yaml`, then Ctrl-C.

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

The members, alice, carol and as many more as come, each keep a folder in their IPFS node; the
community node (a colleague's laptop here, a small always-on machine in real life) pins each
member's folder as soon as the member comes up, and keeps a folder with an entry for each
member, which it serves.

As a local test, the community node and the members are machines of the demo, each script
starting a proxy of its own, or one machine, with one proxy for all. With the registrar, the
community node is either still a machine of the demo, or the registrar's own, with its gateway
on the internet, and then only the members run a script ("With the registrar").

### Common to both

Each machine runs `demo/ipfs.sh`, which starts an agent; the agents publish:

| Record | Published by | Changes when |
|---|---|---|
| `alice._ipfs-member._tcp.$SRP_DOMAIN` SRV, and TXT `dnslink=/ipfs/<CID>` `swarm-mac=<MAC>` | each member, under its label (`alice`) | the member's folder changes, read from its node; withdrawn while its node's swarm port does not answer, and when it stops |
| `site._sub._ipfs-member._tcp.$SRP_DOMAIN` PTR | each member | a member comes or goes: the list of members |
| `_dnslink.site.$UPDATE_DOMAIN` | the community node | its node has pinned all of a member's new folder, or a member's entry is removed |
| `_dnsaddr.site.$UPDATE_DOMAIN` | the community node | its node's addresses change |
| `community ipfs-gateway` in `$SRP_DOMAIN` | the community node | its gateway starts or stops answering |

The community node's agent lists the members through its registrar, which answers from
`ns1.free2air.org`: it sees a member come, and pins its folder, as soon as the zone has it.
`/ipns/site.$UPDATE_DOMAIN/alice/` is `alice`'s folder.

A member is its label, `MEMBER`, by default the machine's name, which the member's key holds:
stopped, it keeps the label, and comes back to it as the same member ("Local test" and "With the
registrar" say for how long). The community node keeps an absent member's entry for `REVOKE_AFTER`,
by default 10 minutes, then removes it and unpins its folder. Another key at a member's label is
another member: the entry before goes at once.

Only nodes of the community's private swarm are members. Each member's TXT record gives, with
its folder, a `swarm-mac=` that the community's swarm key makes from the member's KEY and the
folder's CID; the community node pins nothing for an instance whose `swarm-mac=` its copy of
the key does not make. A `swarm-mac=` copied to another instance does not match the KEY there:
the registrar puts at a name only the KEY of the key that signed for it
([sig0lease-agent.md](sig0lease-agent.md), "Who is a member"). Each agent reads its node's
`swarm.key`, which `ipfs.sh` points it at.

**Needs**:

- The community node, and a machine for each member: alice, the presenter's laptop, and as many
  others as join. Each has IPFS Desktop, or kubo (`ipfs init`), and kubo's `ipfs` command, which
  works on IPFS Desktop's node too (its repository is `~/.ipfs`).
- On the community node, `qrencode`, which prints the QR code the phones scan: `brew install
  qrencode` on a Mac, `sudo apt install qrencode` on Linux.
- Phones on the network, which reach the community node's port 8080.

**Once**, on each node: quit IPFS Desktop, or stop `ipfs daemon`, then

```bash
ipfs config profile apply autoconf-off               # no public peers, resolvers or routers
ipfs config Routing.Type dht
ipfs config --json AutoTLS.Enabled false
ipfs config --json Swarm.Transports.Network.Websocket false
ipfs config --json Discovery.MDNS.Enabled false      # nodes found by DNS alone
ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080  # community node: the gateway, on the network
ipfs id -f '<id>\n'                                  # community node: its ID, for the peer lists
```

The community's nodes are a private swarm: every one of them has the community's key, and no
other node has it, so the folder reaches no other node. The key is one for the whole community,
however many nodes it has: the community node and every member's node. It is in each node's
repository, as `~/.ipfs/swarm.key`. Make it once, on any one node (with the registrar's community
node, the key is that node's: "With the registrar"):

```bash
printf '/key/swarm/psk/1.0.0/\n/base16/\n%s\n' "$(openssl rand -hex 32)" > ~/.ipfs/swarm.key
```

Copy the file to each other node's `~/.ipfs/swarm.key` by hand, and never into DNS or this Git
repository.

Each member's peer list is the community node's name, whose addresses its agent publishes:
`ipfs bootstrap add /dnsaddr/site.$UPDATE_DOMAIN/p2p/<the community node's ID>`, which the
community node's script prints. The community node's peer list stays empty: it never connects to
a member's node; each member's connects to it, and it fetches the member's folder over that
connection. Start the nodes again: `ipfs daemon` says "Swarm is limited to private network of
peers with the swarm key", and on a member, until the community node's agent publishes `site`,
"failed to bootstrap (no peers found)": it tries again by itself. On
each member, make the folder, `ipfs files mkdir /community` (IPFS Desktop: Files, New folder),
and put a first file in it: without an `index.html`, gateways show it as a list of files.

**Run**:

1. The projector shows `<UPDATE_DOMAIN=$UPDATE_DOMAIN> NAME=site demo/watch.sh`: browsing lists
   the members under `_ipfs-member._tcp`, each with its folder.
2. On the community node:

   ```bash
   <REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> REVOKE_AFTER=2m demo/ipfs.sh community
   ```

   `_dnslink.site`, an empty folder, and `_dnsaddr.site` appear. Its script prints the command
   for the members' peer lists, the address of its gateway, with a QR code,
   `http://community.$SRP_DOMAIN:8080/ipns/site.$UPDATE_DOMAIN/`, and then each member as it
   comes and goes. `REVOKE_AFTER=2m` removes an absent member within the demo.
3. On alice's machine, then on each other member's:

   ```bash
   <REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN> <MEMBER=…> demo/ipfs.sh member
   ```

   The member appears under `_ipfs-member._tcp`, and its node connects to the community node's
   (IPFS Desktop's Peers lists it, its only peer). The community node pins its folder and
   `_dnslink.site` changes: its script says "alice is a member", then "pinned …, alice's folder"
   and "alice's entry gives …", and the member's script stops waiting once the community's
   folder has the member's.
4. Phones scan the QR code: a folder for each member, with its files.
5. Drag a photo into `/community` on alice's machine (IPFS Desktop, Files). Within about 15 s
   `alice`'s TXT record changes; the community node pins the new folder, and `_dnslink.site`
   follows, again within about 15 s: each agent asks its node, and the community node's lists
   the members, every 10 s. A phone's reload shows the photo within about a minute: the
   community node's gateway asks for `site` again once its TTL, 30 s, is over.
6. `https://dweb.link/ipns/site.$UPDATE_DOMAIN/`, a public gateway, reads the name but cannot
   find the folder: no node outside the private swarm has it.
7. alice leaves for a while: quit IPFS Desktop on alice's machine (its instance goes within
   about 15 s, once its swarm port does not answer), or Enter in alice's `ipfs.sh`. The
   community node says "alice is not listed; its entry goes in 2m0s unless it is again", and
   phones still load `alice`'s folder from it. alice comes back within that time, IPFS Desktop
   started again or `ipfs.sh` run again: the community node says "alice is listed again", and
   the entry stays.
8. carol leaves for good: Enter in carol's `ipfs.sh`. Two minutes later the community node says
   "carol is not listed for 2m0s: no longer a member": `carol`'s folder goes from the site and
   from the community node's pins.

**On one machine**, the community node is a second node beside alice's, and a further member's,
carol's, a third, each with a repository of its own and other ports. In the community node's
terminal:

```bash
export IPFS_PATH=~/.ipfs-community                 # the community node, in this terminal only
ipfs init
# the configuration above, its gateway on 8081 instead of 8080, then:
ipfs config Addresses.API /ip4/127.0.0.1/tcp/5002
ipfs config --json Addresses.Swarm '["/ip4/0.0.0.0/tcp/4002", "/ip4/0.0.0.0/udp/4002/quic-v1"]'
cp ~/.ipfs/swarm.key ~/.ipfs-community/            # the community's key
ipfs daemon
```

carol's likewise, in a terminal of its own, with `IPFS_PATH=~/.ipfs-carol`, its gateway on 8082, the
API on 5003 and the swarm on 4003; and like alice's, the community node's name in its peer list and
the folder `/community`. The three scripts share one registrar, `REGISTRAR` ("Local test" and "With
the registrar" say which): each would otherwise start a proxy of its own, and refuses to start
beside another. Each in a terminal of its own:

```bash
REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN REVOKE_AFTER=2m \
    IPFS_PATH=~/.ipfs-community IPFS_API=http://127.0.0.1:5002 GATEWAY=8081 demo/ipfs.sh community
REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN MEMBER=alice demo/ipfs.sh member
REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN MEMBER=carol \
    IPFS_PATH=~/.ipfs-carol IPFS_API=http://127.0.0.1:5003 demo/ipfs.sh member
```

The gateway address the community node's script prints has port 8081.

The community node keeps the community's folder after the demo, in its files at
`/sig0lease-agent/site.$UPDATE_DOMAIN`, with its members' folders pinned under the name
`sig0lease-agent site.$UPDATE_DOMAIN.` (`ipfs pin ls --type=recursive --names`). The next start
gives that folder as `site`, and removes each entry whose member is not listed again within
`REVOKE_AFTER`. A member's key, which holds its label, is in the member's keystore,
`demo/keys-ipfs-member-<MEMBER>`.

Why a DNS record, and not IPNS, IPFS's own name for content that changes: an IPNS name is the
hash of a key (`k51…`), and its record, signed by that key, is published in IPFS's distributed
hash table, on the peers whose IDs are closest to the name, and over pubsub to the peers
subscribed to it, which kubo leaves off by default. Publishing or resolving it over the hash
table can take from tens of seconds to minutes: IPFS's documentation calls it slow, and DNSLink
"currently much faster than IPNS" ([docs.ipfs.tech/concepts/ipns](https://docs.ipfs.tech/concepts/ipns/)).
A DNSLink record has a name people can read, is DNSSEC-signed in this zone, and is at the zone's
servers seconds after the agent's update; a resolver that cached the old one keeps it for up to
its TTL.

### Local test

Each machine's `ipfs.sh` starts a proxy of its own; the community node's agent lists the members
through its own. A member's leases are its own proxy's, which ends them only while it runs: a
member that stops keeps its label until it runs again, however long that is, and one whose
machine sleeps or leaves the network stays listed, and keeps its entry, until the machine is
back.

On one machine, the three scripts share the proxy started by hand, which serves `config.yaml`'s
subtrees, the laptop block's: `$B/sig0lease`, in a terminal of its own, and in each of the three
terminals, after the laptop's block, `REGISTRAR=127.0.0.1:8053`.

### With the registrar

The agents' updates and the community node's reads go to the registrar, which runs all the time:
a member that stops keeps its label for an hour, its key's lease, and one whose machine sleeps or
leaves the network is no longer listed about 2 minutes later, when its lease ends; the community
node's `REVOKE_AFTER` counts from then.

Unless the registrar's own community node is used (below), the community node is still a machine of
the demo, with the commands of "Common to both", whose gateway the phones reach on the venue's
network. On staging, whose own community node holds `site`, it takes another label: `SITE=…` before
every command, the community node's and the members', on one machine too, and that label in the
members' peer lists and as `watch.sh`'s `NAME`. On one machine, the commands take the registrar's
block as it is.

#### The registrar's community node

The registrar's staging instance runs the community node itself (deploy/README.md, "The community
node"): a node that is always on, at a public address, in a private swarm of its own. It lists the
members of `site` in `srp.stg.zenr.io`, pins their folders and keeps the community's folder at
`site.stg.zenr.io`, and serves it at `https://<registrar>:8444/ipns/site.stg.zenr.io/`, so phones
open it from anywhere, over mobile data too. Only the members run a script: one machine is enough,
and any number can join. A member's node, behind the venue's NAT, connects to the community node;
the community node never connects to it. An absent member's entry stays for staging's
`revoke_after`, 10 minutes.

**Needs**:

- Each member, with IPFS Desktop or kubo, configured once as in "Common to both", and the folder
  `/community`. Its swarm key is the community's, which is the registrar's node's key: the
  registrar's operators give it (`keystore/ipfs/staging/swarm.key` on the machine that deploys
  the node). Its peer list names the community node: `ipfs bootstrap add
  /dnsaddr/site.stg.zenr.io/p2p/<the node's ID>`, where the ID is the one at the end of each
  address that `dig +short TXT _dnsaddr.site.stg.zenr.io @ns1.free2air.org` gives.
- On each member, `qrencode`, as for the community node in "Common to both".
- A network that lets the members' nodes reach the registrar's port 4002, TCP or UDP.
- Staging's block pasted ("Running a demo").

**Run**:

1. The projector shows `UPDATE_DOMAIN=$UPDATE_DOMAIN NAME=site demo/watch.sh`, and IPFS Desktop's
   Peers on alice's machine, which lists the community node. `site` gives the community's folder: an
   entry for each member listed in the last 10 minutes.
2. On alice's machine, then on each other member's:

   ```bash
   REGISTRAR=$REGISTRAR UPDATE_DOMAIN=$UPDATE_DOMAIN <MEMBER=…> COMMUNITY_GATEWAY=https://$REG:8444 demo/ipfs.sh member
   ```

   The member appears under `_ipfs-member._tcp`; the community node pins its folder, and
   `_dnslink.site` gives it, within seconds. The script then prints the address of the member's
   folder at the registrar, with a QR code; the community's is
   `https://$REG:8444/ipns/site.stg.zenr.io/`.
3. Phones scan it, on any network: the folder's files.
4. Drag a photo into `/community` on alice's machine (IPFS Desktop, Files): a phone's reload
   shows it within about a minute, as in step 5 of "Common to both".
5. alice leaves: Enter in alice's `ipfs.sh`, or quit IPFS Desktop. `alice`'s instance goes; its
   entry stays for 10 minutes, and phones still load its folder from the registrar; back within
   them, it carries on as the same member.

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
  (`on_stop: release`). For D3, Enter in each `demo/ipfs.sh`: a member keeps its label ("Local
  test" and "With the registrar" of D3 say for how long); for D5, in each `demo/chat.sh`;
  for D6, in `demo/web.sh` (the names the phones claimed stay theirs for up to 30 minutes).
- To hold the names for their keys after stopping instead, set `on_stop: keep` in the
  registrars of `demo/demo.yaml` and `demo/mac.yaml`: a host for 14 days and a name for 30
  minutes (the proxy's `config.yaml` caps an RFC 9664 key lease at 1800 s).
- Undo D4's search domain.

## When something fails

- Local test: a script stops at once: "Port 8053, for this demo's proxy, is in use". Another
  demo still runs, or the proxy of D1's terminal 1: stop it, then start the script again.
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
- D3: a member's script waits until "alice is listed": its instance is registered once its
  node's swarm port answers the agent's probe at the addresses it publishes; `agent.log`, in the
  directory the script printed, says why not. A label another key holds is renamed (`renamed:
  now host alice-2, "alice" _ipfs-member._tcp as "alice-2"`), and the script follows: that is
  another member.
- D3: a member's script waits until the community's folder has the member's: the community node
  does not reach it. `ipfs swarm peers` on the member lists nobody: do both `ipfs daemon` logs
  show the same swarm key fingerprint? Does its peer list name the community node, with its ID
  (the community node's script prints the command)? Its resolver may have answered "no such
  name" for `_dnsaddr.site` before the community node published it, and keeps that answer for up
  to 6 minutes: connect by hand, `ipfs swarm connect <address>`, with an address from
  `dig +short TXT _dnsaddr.site.$UPDATE_DOMAIN @ns1.free2air.org`. The community node's
  `agent.log` says what its agent waits for.
- D3: the community node says "…: not a member: …": an instance under `site`'s subtype whose
  label is not letters, digits and hyphens, whose name has no KEY or several, or whose
  `swarm-mac=` its swarm key does not make: that node's `swarm.key` is not the community's. The
  community node leaves it out.
- D3 with the registrar's community node: `ipfs.sh` waits until the community's folder has the
  member's: its node does not reach the community node. `ipfs swarm peers` on it lists nobody:
  is its swarm key the community's, the registrar node's (`ipfs daemon` says "Swarm is limited
  to private network")? Does its peer list name the node, with the ID `_dnsaddr.site` gives?
  Does the network let it out to the registrar's port 4002?
- D3: phones get no answer from the community node's gateway: it listens on 127.0.0.1 only
  (`Addresses.Gateway`, D3's "Once"), and then `community ipfs-gateway` is not registered either.
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
