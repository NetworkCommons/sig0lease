# Demo: a laptop publishes itself on the live zenr.io zone

The presenter's laptop runs the sig0lease proxy and `sig0lease-agent`. The agent publishes the
laptop's site, its services and a name through the proxy, which forwards each update to the real
authoritative server of `zenr.io.` (`ns1.free2air.org`). The audience looks from their own
devices, with the DNS tools they already have. Everything runs from `./main`, with the files in
[`demo/`](../demo).

Each demo's script starts its own proxy, with the config that demo needs, and refuses to start
while another proxy runs on the machine, another demo's included: run one demo at a time. With
`REGISTRAR` set, a script uses that registrar instead, and starts no proxy (see "Against a
shared registrar").

| Demo | What the audience sees | Needs |
|---|---|---|
| D1: the laptop publishes itself | its site among browse results and under a name; a service leaves when it stops and comes back; a template edit shows within seconds; a second key gets `demo-2`, and is refused the name | the laptop |
| D2: the Mac's own services | turning on Remote Login or Screen Sharing puts it in the public zone | a Mac |
| D3: a community folder over IPFS | phones open a member's folder by name from the community node, which pins each version before publishing it, and keeps serving it once the member leaves; the two nodes find each other by DNS alone, in a private swarm | two machines with IPFS Desktop or kubo; phones |
| D4: native discovery | an audience Mac lists the laptop's services beside its `local.` ones | a Mac in the audience |
| D5: two communities meet in one chat room | phones log in as guests of two laptops' XMPP servers and talk in one room; the servers find each other by SRV records and trust each other's self-signed certificates by TLSA records (DANE) | two machines, each with Docker (a Mac) or Prosody 13 (Linux); phones |
| D6: the zone in a browser | phones watch the services come and go, and claim a name with a message, held by a key their browser makes; `dig` shows it within seconds | the laptop; phones |

The demos use this repository's programs and tools that come with the system, except IPFS
Desktop or kubo for D3, and Prosody for D5, whose page loads Converse.js from `cdn.jsdelivr.net`.

## Preparation

What every demo needs. Each demo's section starts with what else it needs, what to set up for it
once, and how to rehearse it.

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

3. Choose the registrar the agents use: the proxy each script starts on the laptop, by default,
   or a shared one ("Against a shared registrar").

4. Record the rehearsal: if the venue's network blocks port 53, the recording is the demo.

A script that stops frees its demo's names (`on_stop: release` in every registrar of the demo's
templates), so someone else may take them between the rehearsal and the day: check them again
on the day, as each demo's section says.

### Demos on two machines

D3 and D5 run on two machines, A and B, on the same network. Each can be rehearsed on one
machine, as its section says: no second machine is needed for that. A Docker container as B has
not been tried: its agent would publish the container's own addresses, which neither A nor the
phones reach, unless `ADDRESS` gives the host's and the container publishes the demo's ports.

## Against a shared registrar

Every script takes `REGISTRAR`, the address of a registrar that serves the same zones, such as
the public one: the agents send their updates there, in place of the proxy the script otherwise
starts on the laptop, and the script starts no proxy and checks no ports for it. Its host name is
not in this repository; its operators give it.

```bash
REGISTRAR=<registrar>:8053 demo/run.sh
REGISTRAR=<registrar>:853 TRANSPORT=tls demo/ipfs.sh member     # over DNS-over-TLS
```

- `TRANSPORT` is how the agents reach it: `tcp`, their default, `udp`, `tls`, or `doh` with
  `REGISTRAR=https://<registrar>`.
- The scripts copy each template they run (`demo/demo.yaml`, `demo/conflict.yaml`,
  `demo/mac.yaml`, and the ones `ipfs.sh` and `chat.sh` write) into their log directory, with
  `server: 127.0.0.1:8053` replaced by `REGISTRAR`; the files in `demo/` stay as they are.
- D6: the page, still served by the laptop, asks the registrar's web server,
  `https://<registrar>/dns-query`, over DNS-over-HTTPS; `DOH=<url>` names another. The phones then
  need the internet, not the laptop's proxy.
- Other people use the same registrar: a name another key holds stays theirs ("When something
  fails"), and the registrar's own lease limits apply.
- A shared registrar keeps its error reasons and its lease-store dump to itself
  (`server.diagnostics` off): a refusal shows only its Extended DNS Error's code, and
  `demo/leftovers.sh -r` cannot read its stores.

## D1: the laptop publishes itself

**Needs**: the laptop. Check that the names are free, before the rehearsal and on the day:
`demo/watch.sh once` shows no `demo` instance, and `(no records)` under the name `demo`. If
another key holds them, change `name: demo` in `demo/demo.yaml` (both registrars) and run
`watch.sh` with `NAME=<the new label>`.

**Rehearsal**: `demo/run.sh`, as on the day.

One terminal is enough: `demo/run.sh` builds the proxy and the clients, starts the proxy, the
site and the agents, pauses before each step until Enter, and prints how long
`ns1.free2air.org` took to show it. The last Enter, or Ctrl-C, stops everything. To run D1 by
hand instead, use these terminals:

| | Command | What it is |
|---|---|---|
| 1 | `$B/sig0lease` | the proxy, on 127.0.0.1:8053: `srp_handler` for `srp.dev.zenr.io.`, `update_handler` for `dev.zenr.io.`, signing upstream with `keystore/server` |
| 2 | `python3 -m http.server 8000 -d demo/site` | the site |
| 3 | `$B/sig0lease-agent run -probe-interval 5s demo/demo.yaml` | the agent: host `demo`, its services and the name `demo` |
| 4 | `demo/watch.sh` | what anyone can see, asked of `ns1.free2air.org` every 2 s |

What the audience can run:

```bash
dig +short demo.dev.zenr.io                         # any machine
dig +short TXT demo.dev.zenr.io
dns-sd -B _http._tcp srp.dev.zenr.io                # a Mac: browse
dns-sd -L "demo http" _http._tcp srp.dev.zenr.io    #        resolve one instance
avahi-browse -d srp.dev.zenr.io. -r _http._tcp      # Linux with avahi-daemon
```

and, on the same network as the laptop, open `http://demo.srp.dev.zenr.io:8000/`. The addresses
the agent publishes are the laptop's on that network.

Ask the audience to look only once the name is published: a resolver that was told "no such
name" keeps that answer for up to 6 minutes (the zone's SOA TTL). `@ns1.free2air.org` always
gives the current answer.

1. Start terminals 1 to 4. The agent logs `registered` for host `demo` and name `demo`, and
   `watch.sh` shows the instance `demo http` under `_http._tcp`, and the name's addresses and
   TXT.
2. Stop the site (Ctrl-C in terminal 2). After three failed probes, about 15 s, `demo http`
   leaves the browse results; about 30 s on a Mac whose firewall is in stealth mode, where a
   stopped site's port does not refuse connections, so each probe waits its 5 s out. Start it
   again: it is back within about 10 s.
3. In `demo/demo.yaml`, uncomment the `hello` record and save. Within 15 s (the agent reads the
   template every 10 s):

   ```bash
   dig +short TXT hello.demo.dev.zenr.io @ns1.free2air.org
   ```

4. Someone else wants the same names. In a fifth terminal:

   ```bash
   $B/sig0lease-agent run -probe-interval 5s demo/conflict.yaml
   ```

   Its host is renamed `demo-2`, and its instance `demo http-2` shows beside yours. The name
   `demo` is refused, since your key holds it; the agent logs it and tries again later, without
   renaming: a name is typed, not browsed. Ctrl-C it: it frees what it got (`on_stop: release`)
   and leaves your name alone.

## D2: the Mac's own services

**Needs**: a Mac as the laptop, and D1's names free. The rehearsal on it writes the Mac's
template, `demo/mac.yaml`: it names this Mac, so it is not in the repository. On first use
macOS asks whether Terminal may find devices on the local network: allow it.

**Rehearsal**: `demo/run.sh` on the Mac, as on the day.

`demo/run.sh` does it on a Mac, as its step 5. By hand, beside D1's terminals 1 to 4, in another
terminal: `$B/sig0lease-agent run demo/mac.yaml`. In System Settings > General >
Sharing, turn on Remote Login (`_ssh._tcp`) or Screen Sharing (`_rfb._tcp`): a few seconds later
the agent logs `registered`, and `watch.sh` shows the Mac's instance. Turn it off and it goes.
[srp-live-demo.md §7](srp-live-demo.md) has the details and limits.

## D3: a community folder over IPFS

A, a member, keeps a folder in its IPFS node; B, the community node (a colleague's laptop here,
a small always-on machine in real life), keeps every version of it and serves it. Each runs
`demo/ipfs.sh`, which starts a proxy and an agent; the agent publishes:

| Record | Published by | Changes when |
|---|---|---|
| `_dnslink.a.dev.zenr.io` | A | A's folder changes: the folder's CID, read from A's node |
| `_dnsaddr.a.dev.zenr.io` | A | A's node's addresses change; withdrawn while the node is down |
| `_dnslink.site.dev.zenr.io` | B | B's node has pinned all of a new version of `a`'s folder |
| `_dnsaddr.site.dev.zenr.io` | B | B's node's addresses change |
| `b ipfs-gateway` in `srp.dev.zenr.io` | B | B's gateway starts or stops answering |

B's agent reads `a`'s folder through its proxy, which answers from `ns1.free2air.org`: B follows
each change as soon as the zone has it.

**Needs**:

- Two machines: A, the presenter's laptop, and B. Each has IPFS Desktop, or kubo (`ipfs init`),
  and kubo's `ipfs` command, which works on IPFS Desktop's node too (its repository is
  `~/.ipfs`).
- On B, `qrencode`, which prints the QR code the phones scan: `brew install qrencode` on a Mac,
  `sudo apt install qrencode` on Linux.
- Phones on the network, which reach B's port 8080.
- The names `a` and `site` free, before the rehearsal and on the day:
  `dig +short KEY a.dev.zenr.io @ns1.free2air.org` answers nothing, and so for `site`.

Once, on each node: quit IPFS Desktop, or stop `ipfs daemon`, then

```bash
ipfs config profile apply autoconf-off               # no public peers, resolvers or routers
ipfs config Routing.Type dht
ipfs config --json AutoTLS.Enabled false
ipfs config --json Swarm.Transports.Network.Websocket false
ipfs config --json Discovery.MDNS.Enabled false      # nodes found by DNS alone
ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080  # the gateway reachable on the network
ipfs id -f '<id>\n'                                  # the node's ID, for the other's peer list
```

The two nodes are a private swarm: they share a key no other node has, so the folder reaches no
other node. Make it on A and copy the file to B's `~/.ipfs/swarm.key`, by hand, never into DNS
or the repository:

```bash
printf '/key/swarm/psk/1.0.0/\n/base16/\n%s\n' "$(openssl rand -hex 32)" > ~/.ipfs/swarm.key
```

Each node's peer list is the other's name, whose addresses the agents publish:
`ipfs bootstrap add /dnsaddr/site.dev.zenr.io/p2p/<B's ID>` on A,
`ipfs bootstrap add /dnsaddr/a.dev.zenr.io/p2p/<A's ID>` on B. Start the nodes again:
`ipfs daemon` says "Swarm is limited to private network of peers with the swarm key", and,
until the agents publish those names, "failed to bootstrap (no peers found)": it tries again by
itself. On A, make the folder, `ipfs files mkdir /community` (IPFS Desktop: Files, New folder),
and put a first file in it: without an `index.html`, gateways show it as a list of files.

**Rehearsal**: on the two machines, `demo/ipfs.sh member` on A, then `demo/ipfs.sh community` on
B. On one machine, B's node is a second one beside A's, with a repository of its own and other
ports, and the two scripts share a proxy started by hand: each script otherwise starts its own,
and refuses to start beside another. This has not been tried yet. In B's terminal:

```bash
export IPFS_PATH=~/.ipfs-b                         # B's node, in this terminal only
ipfs init
# the configuration above, its gateway on 8081 instead of 8080, then:
ipfs config Addresses.API /ip4/127.0.0.1/tcp/5002
ipfs config --json Addresses.Swarm '["/ip4/0.0.0.0/tcp/4002", "/ip4/0.0.0.0/udp/4002/quic-v1"]'
cp ~/.ipfs/swarm.key ~/.ipfs-b/                    # A's key
ipfs bootstrap add /dnsaddr/a.dev.zenr.io/p2p/<A's ID>
ipfs daemon
```

and A's peer list gets B's ID as above. Then, each in a terminal of its own:

```bash
$B/sig0lease                                       # the proxy both use
REGISTRAR=127.0.0.1:8053 demo/ipfs.sh member
REGISTRAR=127.0.0.1:8053 IPFS_PATH=~/.ipfs-b IPFS_API=http://127.0.0.1:5002 GATEWAY=8081 \
    demo/ipfs.sh community
```

The gateway address B's script prints then has port 8081.

On the day:

1. The projector shows `NAME="a site" demo/watch.sh`, and IPFS Desktop's Peers on A, empty.
2. On A, `demo/ipfs.sh member`: `_dnslink.a` and `_dnsaddr.a` appear. Then on B,
   `demo/ipfs.sh community`: B's node reaches A's at `_dnsaddr.a`'s addresses (A's Peers now
   lists B, its only peer), pins the folder, and `_dnslink.site` appears. B's script then prints
   the address of B's gateway, with a QR code:
   `http://b.srp.dev.zenr.io:8080/ipns/site.dev.zenr.io/`.
3. Phones scan it: the folder's files.
4. Drag a photo into `/community` on A (IPFS Desktop, Files). Within about 15 s `_dnslink.a`
   changes; B pins the new version, and `_dnslink.site` follows, again within about 15 s: each
   agent asks its node, and B's asks for `a`, every 10 s. A phone's reload shows the photo
   within about a minute: B's gateway asks for `site` again once its TTL, 30 s, is over.
5. `https://dweb.link/ipns/site.dev.zenr.io/`, a public gateway, reads the name but cannot find
   the folder: no node outside the private swarm has it.
6. A leaves: Enter in A's `ipfs.sh`, and quit IPFS Desktop. `a`'s records go; `site` stays, and
   phones still load the folder from B.

B's node keeps the last version pinned after the demo, under the name
`sig0lease-agent site.dev.zenr.io.` (`ipfs pin ls --type=recursive --names`), and the next start
gives it as `site` until `a` publishes again.

Why a DNS record, and not IPNS, IPFS's own name for content that changes: an IPNS name is the
hash of a key (`k51…`), and its record, signed by that key, is published in IPFS's distributed
hash table, on the peers whose IDs are closest to the name, and over pubsub to the peers
subscribed to it, which kubo leaves off by default. Publishing or resolving it over the hash
table can take from tens of seconds to minutes: IPFS's documentation calls it slow, and DNSLink
"currently much faster than IPNS" ([docs.ipfs.tech/concepts/ipns](https://docs.ipfs.tech/concepts/ipns/)).
A DNSLink record has a name people can read, is DNSSEC-signed in this zone, and is at the zone's
servers seconds after the agent's update; a resolver that cached the old one keeps it for up to
its TTL.

## D4: an audience Mac finds them without being told where

**Needs**: a Mac in the audience, whose owner may run `sudo`, and a demo running whose agent
registers `_http._tcp` services in `srp.dev.zenr.io`: D1 or D6.

**Rehearsal**: on any Mac, the laptop itself included, while `demo/run.sh` runs.

On a Mac in the audience:

```bash
sudo networksetup -setsearchdomains Wi-Fi srp.dev.zenr.io
dns-sd -B _http._tcp          # no domain: the local. and srp.dev.zenr.io. instances together
sudo networksetup -setsearchdomains Wi-Fi Empty                # undo
```

The proxy publishes `lb._dns-sd._udp.srp.dev.zenr.io. PTR srp.dev.zenr.io.` (within 30 s of
starting, and it stays when the proxy stops); mDNSResponder looks for that record in each search
domain and browses what it names (RFC 6763 §11). This works with `dns-sd` on macOS 26.7; whether
Finder and Screen Sharing list the instances too has not been tried. Setting the search domain
stands in for a pointer at a domain the Mac already starts from, which needs the zone's operator
or a resolver on the network: `docs/dns-sd-records.md`, "Browsing".

## D5: two communities meet in one chat room

Two machines, A and B, each run an XMPP server (Prosody) for a community: A's guests get
addresses at `chat-a.dev.zenr.io` and its rooms are at `rooms.chat-a.dev.zenr.io`; B's, at
`chat-b`. The agent on each publishes its server's addresses, the SRV records that tell other
servers where it listens (`_xmpp-server._tcp`, for the name and for `rooms`) and clients where to
log in (`_xmpp-client._tcp`), and a TLSA record with the hash of the server's key. The
certificates are self-signed: a server accepts another only when its key matches its TLSA
record, which DNSSEC vouches for (DANE). Nothing is configured between the two servers, and
nobody makes an account.

**Needs**:

- Two machines, A and B, each with: on a Mac, Docker Desktop, then
  `docker pull prosodyim/prosody:13.0`; on Linux, Prosody 13 (`apt install prosody` on Debian
  13, which brings luaunbound, then `sudo systemctl disable --now prosody`: the package's own
  server would hold the ports), or Docker with `PROSODY=docker`. Also `qrencode`, as for D3.
- Ports 5222, 5269 and 5280 open to the network on each.
- Phones on the network, which also reach the internet, for Converse.js.
- The names `chat-a` and `chat-b` free, before the rehearsal and on the day:
  `dig +short KEY chat-a.dev.zenr.io @ns1.free2air.org` answers nothing, and so for `chat-b`.

**Rehearsal**: on one machine, `demo/chat.sh chat-a chat-b`, which gives the second server ports
10 above: 5232, 5279, 5290.

1. On A, `demo/chat.sh chat-a`; on B, `ROOM=meet@rooms.chat-a.dev.zenr.io demo/chat.sh chat-b`.
   Each starts its proxy, its server (in Docker on a Mac, Prosody installed on Linux;
   `PROSODY=docker` or `native` chooses) and its agent, waits until `ns1.free2air.org` has the
   records, and prints the address of the page its server serves, and its QR code. On a Mac,
   allow Docker's incoming connections when asked; on Linux, the firewall has to let in ports
   5222, 5269 and 5280.
2. Show what the other server reads:

   ```bash
   dig +short SRV _xmpp-server._tcp.rooms.chat-a.dev.zenr.io     # 0 0 5269 chat-a.dev.zenr.io.
   dig +dnssec TLSA _5269._tcp.chat-a.dev.zenr.io @8.8.8.8      # the ad flag: validated
   ```

3. Half the room scans A's QR code, half B's. The page (Converse.js) logs each phone in as a
   guest of that server and joins `meet@rooms.chat-a.dev.zenr.io`; the first one in creates the
   room. B's guests' messages reach A's room over a connection between the servers that each end
   authenticated by the other's TLSA record.
4. Enter, or Ctrl-C, in `chat.sh` stops the agent first, which frees the names, then the server
   and the proxy.

Phones talk to their server over plain HTTP on the venue's network, so the guests' messages are
not encrypted there; the servers talk to each other over TLS. Each server keeps its certificate
and key in `demo/chat/servers/<name>/`, so its TLSA record is the same at every run; delete the
directory for a new key. A server whose key its TLSA record does not match is refused
("certificate does not match any DANE TLSA records" in the other server's log), as the
rehearsal on `dev.zenr.io` checked.

## D6: the zone in a browser

The page has a DNS client in it: this repository's client code, built for WebAssembly
(`make web`). It sends every question and every update to the laptop's proxy over
DNS-over-HTTPS, the one DNS transport a browser has, and the proxy answers the questions about
its zones from the zone's own server: the page sees a change as soon as `ns1.free2air.org` has
it, not what a resolver cached. A question about a name outside the zones, such as the address
of a service's host elsewhere, the proxy refuses, as it is no resolver, and the page asks
Google's DNS-over-HTTPS resolver instead, over the internet.

**Needs**: the laptop, with `qrencode`, as for D3, and D1's names free; phones on the same
network, with a browser from 2023 or later, which reach the laptop's ports 8090 and 8443 (with
`REGISTRAR`, port 8090 and the internet). On a Mac, allow `sig0lease`'s incoming connections
when asked.

**Rehearsal**: `demo/web.sh`, and a phone on the same network, or a browser on the laptop, at
the address it prints.

1. `demo/web.sh` builds the proxy, the agent and the page, and starts: the proxy, with its
   DNS-over-HTTPS listener on (port 8443, plain HTTP); a site and an agent that registers it as
   the service `demo http`, as in D1 (`demo/demo.yaml`); and the page, on port 8090. It prints
   the page's address and its QR code.
2. Phones scan the code. The page lists the services in `srp.dev.zenr.io`, read every 3
   seconds. At the next Enter, `web.sh` stops the site, and after three failed probes, about
   15 s, the phones show `demo http` leave, struck through; at the one after, it starts the site
   again, and `demo http` comes back, lit up.
3. Someone picks a name and writes a message. The browser makes a key and keeps it, and the page
   claims `<name>.dev.zenr.io` with the message as its TXT record. The badge turns `published`
   once the zone's server has it, within a few seconds, and anyone can check:

   ```bash
   dig +short TXT <name>.dev.zenr.io @ns1.free2air.org
   ```

   A second phone that claims the same name stays `waiting`, and shows the first one's message:
   another key holds the name.
4. "Release the name" deletes the message and frees the name. The last Enter, or Ctrl-C, in
   `web.sh` stops the agent, which frees `demo`, then the page, the site and the proxy.

A name stays its phone's while the page is open: the message for 10 minutes after the page
closes (its lease), the name for 30 (its key's, the most the zone grants). Opened again within
that time, from the same browser, the page claims it again. Clearing the browser's data for the
site loses the key, and the name with it until those 30 minutes are over. The page reaches the
proxy over plain HTTP on the venue's network: every update is signed with the phone's key, so
nobody can forge one, but anyone there can read them.

## After the demo

- Ctrl-C the agents, then the site and the proxy. The records go at once, and so do the names
  (`on_stop: release`). For D3, Enter in each `demo/ipfs.sh`; for D5, in each `demo/chat.sh`;
  for D6, in `demo/web.sh` (the names the phones claimed stay theirs for up to 30 minutes).
- To hold the names for their keys after stopping instead, set `on_stop: keep` in the
  registrars of `demo/demo.yaml` and `demo/mac.yaml`: a host for 14 days and a name for 30
  minutes (the proxy's `config.yaml` caps an RFC 9664 key lease at 1800 s).
- Undo D4's search domain.

## When something fails

- A script stops at once: "Port 8053, for this demo's proxy, is in use". Another demo still runs,
  or the proxy of D1's terminal 1: stop it, then start the script again.
- The proxy logs errors reaching `ns1.free2air.org`: the network blocks port 53. Use a phone's
  hotspot, or the recording.
- The agent logs a name held by another key: change `name: demo` (D1, "Needs").
- D3: B's script waits for `site`: B's node does not reach A's. `ipfs swarm peers` on B lists
  nobody: both `ipfs daemon` logs show the same swarm key fingerprint? B's resolver may have
  answered "no such name" for `_dnsaddr.a` before A published it, and keeps that answer for up
  to 6 minutes: connect by hand, `ipfs swarm connect <address>`, with an address from
  `dig +short TXT _dnsaddr.a.dev.zenr.io @ns1.free2air.org`. The log in the directory B's script
  printed says what B's agent waits for (`agent.log`).
- D3: phones get no answer from B's gateway: it listens on 127.0.0.1 only (`Addresses.Gateway`,
  D3's "Needs"), and then `b ipfs-gateway` is not registered either.
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
- D6: the page says the DNS client did not start, or cannot read the services: the phone does
  not reach port 8443. On a Mac, allow `sig0lease`'s incoming connections when asked. If
  `web.sh` printed a Docker or VPN address, give the venue's with `ADDRESS=<address>`.
- D6: a claim stays `waiting` with no other message shown: the log under the page says why.
