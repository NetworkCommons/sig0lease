# Test suite

Orchestration scripts live directly in `tests/`; shared helpers live in `tests/lib/`. Every
`test_*.sh` script follows the same shape: `source tests/lib/common.sh` (and whichever other
`lib/*.sh` files it needs), then `run|cleanup` as its only CLI surface. See `lib/common.sh`'s
own header comment for the "no `set -e` in library files, `return` not `exit`" convention
those files follow.

Most of the suite (`test_update.sh`, `test_forward.sh`, `test_srp.sh`) is self-contained:
real proxy process, real client tooling, a local disposable BIND 9 (`lib/bind9.sh`) — nothing
outside this repo required beyond `go`, `named`/`named-checkconf`, and `dig`.

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
implementation. `tests/test_mdnsresponder_interop.sh` runs the real, unmodified binaries
against our own registrar and client — see that script's own top-of-file comment for what it
covers. `tests/lib/mdnsresponder.sh`'s `build_mdnsresponder` builds it automatically the
first time the interop script runs (subsequent runs reuse the existing build).

```
git clone https://github.com/apple/mDNSResponder.git ../mDNSResponder
cd ../mDNSResponder && git checkout mDNSResponder-2881.0.25   # commit actually tested; a later tag should also work
```

Needs `mbedtls` dev libraries on Linux (`apt-get install libmbedtls-dev`) and requires two
small local patches to build in this snapshot — both are pre-existing gaps in this
checkout's own reference-counting/replication debug instrumentation, unrelated to SRP or to
anything in this repo, and already applied in the checkout this test suite expects (see the
RFC 9665 plan doc's §12.3 for the exact two-patch diff and reasoning if you need to
reapply them on a fresh clone: `srp-replication.c`'s missing `srpl_current_domain()`
declaration, and `srp-log.c`'s missing `srp_log_ref_check`/`srp_log_ref_final` definitions).

`make` (from `ServiceRegistration/`) builds `build/srp-client`, `build/srp-mdns-proxy`, and a
couple of supporting tools. `build/srp-dns-proxy` does **not** build in this snapshot
(unrelated drift, several call sites don't match current signatures elsewhere in the tree) —
source-level reference only, not exercised by any test here.

### OpenThread — only needed to *regenerate* a fixture, not for routine test runs

OpenThread's SRP client/server is the RFC's other credited independent implementation. It is
**not** used for network-level interop (its simulation platform has no host-reachable
network interface — see the RFC 9665 plan doc's post-Phase-5 entry for the full empirical
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
