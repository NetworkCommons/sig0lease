# Test suite

Orchestration scripts live directly in `tests/`; shared helpers live in `tests/lib/`. Every
`test_*.sh` script follows the same shape: `source tests/lib/common.sh` (and whichever other
`lib/*.sh` files it needs), then `run|cleanup` as its only CLI surface. See `lib/common.sh`'s
own header comment for the "no `set -e` in library files, `return` not `exit`" convention
those files follow.

`test_srp.sh` is self-contained: real proxy process, real client (`cmd/sig0lease-srp-client`), a local
disposable BIND 9 (`lib/bind9.sh`, zone `srp.test.`) — nothing outside this repo required
beyond `go`, `named`/`named-checkconf`, `dig`, and `openssl` (for the throwaway certificate of
the proxy's DNS-over-TLS listener, which TEST 9 registers through). So is `test_update.sh`
with `AUTH_BACKEND=local` (below).

`test_update.sh` (by default) and `test_forward.sh` run against the **real DNS**, not a local
BIND 9. Both start the proxy from a copy of `main/config.yaml` (only the listen address and the
minimum leases are rewritten), so they also use its lease-store files under `data/`.

- `test_update.sh` updates the live `test.dev.zenr.io.` records: the proxy finds the
  authoritative server for `dev.zenr.io.` via an SOA lookup and signs with
  `keystore/server/Kdev.zenr.io.+015+35317`. The suite checks results with `dig` against
  `AUTH_SERVER` (default `ns1.free2air.org`) and adds/deletes some records there directly with
  `nsupdate` (needs a current BIND `nsupdate` with ED25519 support). Needs
  `CLIENT_KEYSTORE_DIR` (see the Makefile's `test-update` target). Overridable via env:
  `AUTH_SERVER`, `PROXY_ADDR`/`PROXY_PORT` (a proxy already listening there is reused instead
  of starting one), `PROXY_PROTOCOL`, `CLIENT_KEY_NAME`, `RR_TYPES` and the lease times. The
  config file, the zones and the proxy key are fixed. `PROXY_PROTOCOL` is `udp` (default),
  `tcp`, or `tls`: with `tls` the client sends DNS-over-TLS to `PROXY_ADDR:PROXY_TLS_PORT`
  (default 8853). A proxy the script starts gets that listener turned on in its scratch config,
  with a throwaway certificate (needs `openssl`); a reused proxy must already serve DoT there.

  With `AUTH_BACKEND=local` (`make test-update-local`) the same suite runs against the local
  BIND 9 of `lib/bind9.sh` instead. The scratch copy of `config.yaml` is then localized for
  that deployment (`localize_lease_config`): only what names a server, zone, key or file is
  replaced, so every other setting, including ones `config.yaml` gains later, carries over.
  The upstream resolvers become the local BIND 9; the RFC 9664 handler serves its own zone
  `update.test.` (key in `keystore-update-bind9/`), and the client registers under
  `test.update.test.`; `srp_handler` runs ahead of it, as in `config.yaml`, on `srp.test.`
  (key in `keystore-srp-bind9/`). Each handler reaches the BIND 9 through its static
  `upstream` (the commented-out `# upstream:` line of its section, turned on) and keeps its
  leases in a scratch file. The run fails if `config.yaml` has a handler section this doesn't
  localize, or if any zone, key, file or upstream server `config.yaml` names is left, so
  nothing outside the run is touched. (SOA discovery is therefore only exercised by the live
  run.) The two client keys are generated for the run with `dnssec-keygen`, so
  `CLIENT_KEYSTORE_DIR` is not needed (and is ignored), nor is network access. The proxy must
  be the script's own, not a reused one. At the end, as in `test_srp.sh`, any request `named`
  rejected other than a SIG(0) quota refusal fails the run, even if a retry later hid it from
  the suite's own checks.
- `test_forward.sh` needs internet access: it resolves public names (google.com, gmail.com,
  ...) through the proxy's configured upstream resolvers.

## External checkouts

Two scripts additionally depend on a **sibling checkout, outside this repo, checked out
deliberately rather than vendored or auto-cloned**: real reference implementations of SRP
from other projects, used because a real independent implementation is a much stronger
correctness signal than anything this repo could construct on its own. Both live as siblings
of `main/` (i.e. `../mDNSResponder`, `../openthread` relative to this file), overridable via
`MDNSRESPONDER_DIR` / `OPENTHREAD_DIR` env vars if you keep them somewhere else.

They're deliberately **not** vendored (no git submodule, no copy into this repo): both are
large, independently-maintained upstream trees: vendoring would bloat this repo, duplicate
their own git history, and drift from upstream fixes. The commit each was actually tested
against is pinned below instead — clone fresh and check out that commit (or a later one; SRP
is stable in both projects) rather than assuming `main`/`master` behaves identically forever.

### mDNSResponder (`ServiceRegistration/`) — required for `test_mdnsresponder_interop.sh`

Apple's own SRP client (`srp-client`) and registrar (`srp-mdns-proxy`) reference
implementation, plus its mDNS daemon (`mdnsd`) and browse tool (`dns-sd`) from `mDNSPosix/` and
`Clients/`. `tests/test_mdnsresponder_interop.sh` runs the real, unmodified binaries
against our own registrar and client — see that script's own top-of-file comment for what it
covers. `tests/lib/mdnsresponder.sh`'s `build_mdnsresponder` builds them automatically the
first time the interop script runs (subsequent runs reuse the existing build). The script must
run as root: it starts `mdnsd`, which creates `/var/run/mdnsd` and binds UDP 5353, and it
refuses to start if another mDNS daemon already listens on that socket.

```
git clone https://github.com/apple/mDNSResponder.git ../mDNSResponder
cd ../mDNSResponder && git checkout mDNSResponder-2881.0.25   # commit actually tested; a later tag should also work
```

Needs `mbedtls` dev libraries on Linux (`apt-get install libmbedtls-dev`) and requires two
small local patches to build in this snapshot — both are pre-existing gaps in this
checkout's own reference-counting/replication debug instrumentation, unrelated to SRP or to
anything in this repo, and already applied in the checkout this test suite expects (see the
docs/siglease_rfc9665.md's mDNSResponder reference section for the exact two-patch diff and reasoning if you need to
reapply them on a fresh clone: `srp-replication.c`'s missing `srpl_current_domain()`
declaration, and `srp-log.c`'s missing `srp_log_ref_check`/`srp_log_ref_final` definitions).

`make` (from `ServiceRegistration/`) builds `build/srp-client`, `build/srp-mdns-proxy`, and a
couple of supporting tools. `build/srp-dns-proxy` does **not** build in this snapshot
(unrelated drift, several call sites don't match current signatures elsewhere in the tree) —
source-level reference only, not exercised by any test here.

### OpenThread — only needed to *regenerate* a fixture, not for routine test runs

OpenThread's SRP client/server is the RFC's other credited independent implementation. It is
**not** used for network-level interop (its simulation platform has no host-reachable
network interface — see docs/siglease_rfc9665.md's OpenThread interop section for the full empirical
finding) and there is no automated script that touches this checkout. Instead, one real
signed SRP registration message was extracted from it once and is now a hardcoded fixture in
`pkg/srp/srp_test.go` (`TestValidate_RealOpenThreadCapture`) and
`pkg/sig0/ecdsa_test.go` (`TestECDSAP256KnownAnswerFromOpenThread`) — routine `go test ./...`
needs no OpenThread checkout at all.

You'd only need the checkout to redo or refresh that extraction (e.g. if `pkg/srp`'s message
shape assumptions ever need re-validating against a fresh OpenThread build). If so:

```
git clone https://github.com/openthread/openthread.git ../openthread
cd ../openthread && git checkout 67437ed96469acfd865a9437e7edfa6c3f5f0a60   # commit actually tested
git submodule update --init --recursive --depth 1        # mbedtls, and its own nested submodule
```

Then, temporarily, add a hex-dump of the outgoing message right before the client's send
call in `src/core/net/srp_client.cpp` (search for `mSocket.SendTo` — `info.mMessage` at that
point holds the complete signed update, identical to what goes out on the wire), build and
run the `nexus` test platform's own two-node client/server test:

```
top_builddir=build/nexus ./tests/nexus/build.sh
./build/nexus/tests/nexus/nexus_srp_client_change_lease
```

Copy the captured hex out of stdout, `git checkout src/core/net/srp_client.cpp` to revert
the instrumentation (leave the checkout pristine — it's a third-party tree, not part of this
repo), and update the two `capturedOpenThreadHex`/fixture constants above with the new bytes.

`tests/nexus/build.sh` is OpenThread's own authoritative build entry point for this platform
(not `script/cmake-build`, which has no `nexus` preset) — it configures via
`-DOT_PROJECT_CONFIG=tests/nexus/openthread-core-nexus-config.h`, not a hand-assembled cmake
flag list; reusing the `simulation` platform's own flags directly on `nexus` fails with
unrelated missing-symbol errors.
