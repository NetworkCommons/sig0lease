# Live demo: registering a service via the SRP proxy on the real dev.zenr.io zone

This is a copy/paste walkthrough for showing how [RFC 9665](https://datatracker.ietf.org/doc/rfc9665/)
(DNS-SD Service Registration Protocol) actually works end to end: the SRP client signs a
registration, sends it to a local proxy, the proxy forwards and re-signs it upstream, and
the result lands on a **real, shared, already-provisioned authoritative DNS server**
(`ns1.free2air.org`, serving the `zenr.io.` zone) that anyone can `dig` against.

The repo's checked-in `config.yaml` has `srp_handler` enabled (alongside the
pre-existing RFC 9664 `update_handler`), pointed at `srp.dev.zenr.io.` using the proxy's
own signing key already present in `./keystore/server`
(`Kdev.zenr.io.+015+35317`, which already has SIG(0) update rights over `dev.zenr.io.` and
everything under it, `srp.dev.zenr.io.` included). No separate config needed.

## 0. Build

From the `./main` directory of this repo:

```bash
make build build-client
```

## 1. Start the proxy

```bash
./bin/$(uname)/sig0lease
```

Leave this running in its own terminal. It listens on `:8053` and logs both `srp_handler`
and `update_handler` registering for opcode 5 (UPDATE).

## 2. Register a host + service instance

In another terminal, from `./main`:

```bash
./bin/$(uname)/sig0lease-srp-client \
  -domain=srp.dev.zenr.io. \
  -host=demo \
  -addr=192.0.2.42 \
  -instance=DemoWidget:_http._tcp:8080 \
  -txt=DemoWidget:path=/demo \
  -server=127.0.0.1:8053 \
  -lease=60 -keylease=120 \
  -keystore=./keystore/client -k=15 \
  -once
```

- `-keystore=./keystore/client` points at the repo's existing client keystore directory
  (already used by the RFC 9664 client examples in `docs/siglease_rfc9664.md`).
- `-k=13` (ECDSAP256SHA256) or `-k=15` (ED25519) mints one new identity key there 
  (`Kdemo.srp.dev.zenr.io.+013+<keytag>` or `Kdemo.srp.dev.zenr.io.+015+<keytag>`,
  printed as `Key:` in the output) on the **first** run, if nothing named
  `demo.srp.dev.zenr.io.` exists yet; every run after that reuses the exact same file, 
  and `-k` is then a no-op. It's not committed to git — `keystore/client` is
  gitignored — so it's local, persistent-across-runs on whichever machine runs the demo.
  If a key for the domain (`demo.srp.dev.zenr.io.` in this case) already exists, no matter 
  the type (13 or 15), **no new key** is generated and the existing key is used. 
- `-lease`/`-keylease` are short on purpose for a demo (1/2 minutes) so a stale record
  cleans itself up if you forget to deregister (step 6).
- A real device would normally omit `-server` and let the client discover the registrar via
  `_dnssd-srp._tcp.<domain>.` SRV lookup; it's passed explicitly here since this points at a
  local proxy rather than a publicly discoverable one. Discovery needs an SRV record
  published for the zone and network reachability from wherever the client runs to the
  registrar, neither of which every environment running this walkthrough has, which is why
  `-server` is used throughout instead.

### 2b. Other registration shapes (optional)

The command above is the general case (host + one service instance); the client supports
narrower and wider shapes too, all against the same running proxy:

```bash
# Host-only: no service instance at all, just an address record for the host
./bin/$(uname)/sig0lease-srp-client -domain=srp.dev.zenr.io. -host=demo-host-only \
  -addr=192.0.2.43 -server=127.0.0.1:8053 -lease=60 -keylease=120 -keystore=./keystore/client -k=13 -once

# A DNS-SD subtype on the same instance (repeatable -subtype/-txt/-instance, matched by label)
./bin/$(uname)/sig0lease-srp-client -domain=srp.dev.zenr.io. -host=demo \
  -addr=192.0.2.42 -instance=DemoWidget:_http._tcp:8080 \
  -subtype=DemoWidget:_printer -server=127.0.0.1:8053 -lease=60 -keylease=120 -keystore=./keystore/client -once
```

Expected output ends with:

```
Status: NOERROR (Rcode=0)
Granted: LEASE=60 KEY-LEASE=120
```

## 3. See it on the real DNS server

From any machine with internet access — no local setup needed, just `dig`:

```bash
dig +noall +answer A   demo.srp.dev.zenr.io. @ns1.free2air.org
dig +noall +answer KEY demo.srp.dev.zenr.io. @ns1.free2air.org
dig +noall +answer SRV "DemoWidget._http._tcp.srp.dev.zenr.io." @ns1.free2air.org
dig +noall +answer TXT "DemoWidget._http._tcp.srp.dev.zenr.io." @ns1.free2air.org

# browse every instance currently registered under this service type
dig +noall +answer PTR "_http._tcp.srp.dev.zenr.io." @ns1.free2air.org

# browse every instance currently registered under this service subtype
dig +noall +answer PTR "_printer._sub._http._tcp.srp.dev.zenr.io." @ns1.free2air.org

# RFC 6763 S9: which service TYPES exist at all on this zone (the query a "browse
# everything" tool runs before it knows to ask for _http._tcp specifically)
# RFC 6763 §9 defines _services._dns-sd._udp.<Domain> as enumerating only base two-label <Service> names (e.g. _http._tcp),
# explicitly stating "only the first two labels are relevant for the purposes of service type enumeration."
# Subtypes (_printer._sub._http._tcp) aren't part of that meta-query — they're a separate, targeted browsing mechanism: 
# a client that already knows to look for _printer._sub._http._tcp queries that PTR name directly.
dig +noall +answer PTR "_services._dns-sd._udp.srp.dev.zenr.io." @ns1.free2air.org

# RFC 6763 S11: domain enumeration -- some browse tools query this ("is there a browsable
# domain here at all") before ever trying the S9 query above. db/lb are the same
# self-pointing answer under a different prefix; r/dr (registration-domain) are omitted
# here since they're opt-in (advertise_registration_domain) and off by default.
dig +noall +answer PTR "b._dns-sd._udp.srp.dev.zenr.io." @ns1.free2air.org
```

### 3b. Browse it with a real DNS-SD client

#### avahi-browse

`dig` above proves the records exist; `avahi-browse` proves a genuine third-party DNS-SD
client can discover them the way a real application would -- via `avahi-daemon`'s wide-area
(unicast DNS) support, not multicast. This needs your own machine's normal DNS resolver to
be able to reach `ns1.free2air.org` recursively (not something every sandboxed/restricted
network can do) -- check that first:

```bash
dig +short NS zenr.io.
```

If that returns `ns0.free2air.org.`/`ns1.free2air.org.`, wide-area resolution works here and
this will too. If it returns nothing, skip this step and rely on the `dig` commands above
instead -- this is exactly the situation in the sandbox this feature was originally built and
tested in, which is why the automated `tests/test_srp.sh` suite uses `dig @server` throughout
rather than depending on avahi/dns-sd.

```bash
# -d: the domain to browse (wide-area DNS-SD, not mDNS/.local)
# -r: resolve each instance found (SRV/TXT/address), not just list its name
avahi-browse -d srp.dev.zenr.io. -r _http._tcp

# -a browses every service TYPE first (RFC 6763 S9 -- see the dig PTR above), then each
# instance under every type found -- the closest real-client equivalent of "see everything
# registered on this zone" without already knowing _http._tcp in advance
avahi-browse -d srp.dev.zenr.io. -a -r
```
#### dns-sd

On Mac (and possibly other systems that have dns-sd) you can run this command:

```bash
# dns-sd -B <Type> <Domain> (Browse for service instances)
dns-sd -B _services._dns-sd._udp srp.dev.zenr.io
# Browse a particular instance
dns-sd -B _http._tcp srp.dev.zenr.io
```

## 4. Full lifecycle mode (optional)

Drop `-once` to watch the client run unattended: initial delay, then automatic refresh at
~80% of the granted lease (RFC 9664 §5.2), forever, until you `Ctrl-C`:

```bash
./bin/$(uname)/sig0lease-srp-client -domain=srp.dev.zenr.io. -host=demo -addr=192.0.2.42 \
  -instance=DemoWidget:_http._tcp:8080 -server=127.0.0.1:8053 \
  -lease=60 -keylease=120 -keystore=./keystore/client
```

## 5. Try a conflict (optional)

Register the same `-host` again, but with a *different* identity (a fresh, throwaway
keystore directory instead of reusing `./keystore/client`'s, so it's a genuinely different
key). It fails -- FCFS rejects a second identity trying to claim a name the first identity
already holds:

```bash
./bin/$(uname)/sig0lease-srp-client -domain=srp.dev.zenr.io. -host=demo -addr=192.0.2.99 \
  -server=127.0.0.1:8053 -lease=60 -keylease=120 -keystore=$(mktemp -d) -k=13 -once
```

Drop `-once` from that same command to see the other side of a conflict instead: the client
notices the `YXDOMAIN`, renames itself (`demo-2`, then `demo-3`, ...) and retries
automatically until a free name is found — the same unattended recovery a real device
relies on after a collision, rather than a hard failure.

## 6. Clean up

Explicitly withdraw the host and every instance in one message (`LEASE=0`), rather than
waiting for the short demo lease to expire:

```bash
./bin/$(uname)/sig0lease-srp-client \
  -domain=srp.dev.zenr.io. -host=demo \
  -instance=DemoWidget:_http._tcp:8080 \
  -server=127.0.0.1:8053 -keystore=./keystore/client \
  -deregister
```

Then confirm it's gone (the `dig`s from step 3 should return no answer), and `Ctrl-C` the
proxy.

## Background

- `docs/siglease_rfc9665.md` covers the CLI/config, protocol behavior, and known
  limitations in full.
- `docs/siglease_rfc9665.md`'s "Testing and interop" section documents this exact shared
  environment and how it differs from the CI-only local BIND 9 setup used by
  `make test-srp`.
