# Demo: a laptop publishes itself on the live zenr.io zone

The presenter's laptop runs the sig0lease proxy and `sig0lease-agent`. The agent publishes the
laptop's site, its services and a name through the proxy, which forwards each update to the real
authoritative server of `zenr.io.` (`ns1.free2air.org`). The audience looks from their own
devices, with the DNS tools they already have. Everything runs from `./main`, with the files in
[`demo/`](../demo).

| Demo | What the audience sees | Needs |
|---|---|---|
| D1: the laptop publishes itself | its site among browse results and under a name; a service leaves when it stops and comes back; a template edit shows within seconds; a second key gets `demo-2`, and is refused the name | the laptop |
| D2: the Mac's own services | turning on Remote Login or Screen Sharing puts it in the public zone | a Mac |
| D3: a site by name over IPFS | `dweb.link/ipns/demo.dev.zenr.io/` serves the laptop's site | kubo (`ipfs`) |
| D4: native discovery | an audience Mac lists the laptop's services beside its `local.` ones | a Mac in the audience |
| D5: a chat server by name | to come: XMPP clients find a Prosody server through the name's SRV records | |

The demos use this repository's programs and tools that come with the system, except kubo for
D3.

## Before the day

1. Build, and name the binaries' directory:

   ```bash
   make build build-client
   B=./bin/$(uname -s | tr A-Z a-z)
   ```

2. Check that the network reaches the zone's server, over UDP and TCP:

   ```bash
   dig +short SOA zenr.io @ns1.free2air.org
   dig +tcp +short SOA zenr.io @ns1.free2air.org
   ```

3. Check that the names are free: `demo/watch.sh once` shows no `demo` instance and a `-` for the
   name's KEY. If another key holds them, change `name: demo` in `demo/demo.yaml` (both
   registrars) and run `watch.sh` with `NAME=<the new label>`.

4. Rehearse once, with the same `demo/keys` you will use on the day. Those keys then hold the
   names: the host for 14 days and the name for 30 minutes after the agent stops (the proxy's
   `config.yaml` caps an RFC 9664 key lease at 1800 s). Keep `demo/keys` until the demo.

5. For D3, once: `ipfs init`, then let kubo's gateway listen beyond 127.0.0.1, so the agent's
   probe and the audience on the same network reach it:

   ```bash
   ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080
   ```

6. For D2, write the Mac's template (it names this Mac, so it is not in the repository):

   ```bash
   cat > demo/mac.yaml <<EOF
   keystore: keys-mac
   registrars:
     - protocol: srp
       domain: srp.dev.zenr.io.
       server: 127.0.0.1:8053
       lease: 10m
       mirrors:
         - type: mdns
           hosts: [$(scutil --get LocalHostName).local.]
           services: [_ssh._tcp, _smb._tcp, _rfb._tcp]
   EOF
   ```

   On first use macOS asks whether Terminal may find devices on the local network: allow it.

7. Record the rehearsal: if the venue's network blocks port 53, the recording is the demo.

## The terminals

For D1 alone, one terminal is enough: `demo/run.sh` starts the proxy, the site and the agent,
pauses before each step until Enter, and prints how long `ns1.free2air.org` took to show it. The
last Enter, or Ctrl-C, stops everything. For the full demo, use these terminals:

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

## D1: the laptop publishes itself

1. Start terminals 1 to 4. The agent logs `registered` for host `demo` and name `demo`, and
   `watch.sh` shows the instance `demo http` under `_http._tcp`, and the name's addresses and
   TXT. `demo ipfs-gateway` waits for D3: its probe fails until kubo's gateway answers.
2. Stop the site (Ctrl-C in terminal 2). After three failed probes, about 15 s, `demo http`
   leaves the browse results. Start it again: it is back within about 10 s.
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

Keep the agent running for D2 and D3.

## D2: the Mac's own services

In another terminal: `$B/sig0lease-agent run demo/mac.yaml`. In System Settings > General >
Sharing, turn on Remote Login (`_ssh._tcp`) or Screen Sharing (`_rfb._tcp`): a few seconds later
the agent logs `registered`, and `watch.sh` shows the Mac's instance. Turn it off and it goes.
[srp-live-demo.md §7](srp-live-demo.md) has the details and limits.

## D3: the site by name, over IPFS

1. In another terminal: `ipfs daemon`. Once it runs, `demo ipfs-gateway` appears in the browse
   results: the agent's probe reaches kubo's gateway on port 8080.
2. Add the site, and publish its CID under the name:

   ```bash
   ipfs add -r -Q demo/site
   ```

   In `demo/demo.yaml`, uncomment the `_dnslink` record, put the CID in place of `CID`, and
   save. Within 10 s `watch.sh` shows `_dnslink TXT "dnslink=/ipfs/<CID>"`.
3. The audience opens `https://dweb.link/ipns/demo.dev.zenr.io/`: a public gateway reads the
   `_dnslink` record and fetches the site from the laptop over IPFS. The first fetch can take a
   minute, while the gateway finds the laptop. Also:

   ```bash
   ipfs cat /ipns/demo.dev.zenr.io/index.html          # anyone running kubo
   ```

   and, on the laptop's network, `http://demo.srp.dev.zenr.io:8080/ipns/demo.dev.zenr.io/`.

   Public gateways (`dweb.link`, `ipfs.io`) limit requests per address and answer HTTP 429
   past it; a room behind one address can reach that. The laptop's gateway and kubo have no
   such limit.

A changed site has a new CID, so the record changes too; gateways keep the old one for up to the
record's TTL, 5 minutes. For now the CID is copied by hand; the agent is to read it from kubo.

## D4: an audience Mac finds them without being told where

On a Mac in the audience:

```bash
sudo networksetup -setsearchdomains Wi-Fi srp.dev.zenr.io
dns-sd -B _http._tcp          # no domain: the local. and srp.dev.zenr.io. instances together
sudo networksetup -setsearchdomains Wi-Fi Empty                # undo
```

While the proxy holds a registration it publishes `lb._dns-sd._udp.srp.dev.zenr.io. PTR
srp.dev.zenr.io.`; mDNSResponder looks for that record in each search domain and browses what it
names (RFC 6763 §11). This works with `dns-sd` on macOS 26.7; whether Finder and Screen
Sharing list the instances too has not been tried.

## D5: a chat server by name

To come: Prosody (XMPP) on the laptop, the agent publishing the name's `_xmpp-client._tcp` and
`_xmpp-server._tcp` SRV records, and any XMPP client logging in to `alice@chat.dev.zenr.io`.

## After the demo

- Ctrl-C the agents, then the site, kubo and the proxy. The records go at once; the names stay
  with `demo/keys`, the host for 14 days and the name for 30 minutes.
- To leave the names free for someone else, set `on_stop: release` in both registrars of
  `demo/demo.yaml` before stopping the agent.
- Undo D4's search domain.

## When something fails

- The proxy logs errors reaching `ns1.free2air.org`: the network blocks port 53. Use a phone's
  hotspot, or the recording.
- The agent logs a name held by another key: change `name: demo` (step 3 of "Before the day").
- A public gateway answers HTTP 429: it is limiting the venue's address. Use the laptop's
  gateway on the same network.
- `watch.sh` shows a record and the audience does not: their resolver answered "no such name"
  before it was published. Ask `@ns1.free2air.org`, or wait up to 6 minutes.
- `demo http` is never registered: the probe asks the site at the published addresses
  (`$B/sig0lease-agent plan demo/demo.yaml` lists them); a firewall may block port 8000. On a Mac,
  allow `python3`'s incoming connections when asked.
