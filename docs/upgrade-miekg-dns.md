# Future PR: bump codeberg.org/miekg/dns to v0.6.104, update pkg/dnscompat and pkg/lease

Not done in this PR. This is a separate, self-contained follow-up. Everything below was
verified against real builds of the dependency in an isolated scratch module (not this
repo's go.mod/go.sum), so the facts are solid; the *decision* of how far to take it is not
made here.

## What's actually fixed upstream

The three shortcomings documented in `README_proxy.md` under "miekg/dns Shortcomings" were
tested against `codeberg.org/miekg/dns` versions v0.6.82 (pinned today) through v0.6.104
(latest at time of writing):

| Shortcoming | v0.6.82 | v0.6.95 | v0.6.104 |
|---|---|---|---|
| #1 UPDATE-LEASE unpack dispatcher gap (`"dns: no option unpack defined"`) | reproduces | reproduces | **fixed** |
| #2 unpacked form isn't OPT-wrapped | same cause as #1 | same | now unpacks as a real typed `*dns.UPDATELEASE{Lease, KeyLease}` RR |
| #3 multi-question round-trip (`"overflow name"`) | reproduces | silently truncates to 1 question (regression, not a fix) | reproduces again, same as v0.6.82 |

The #1/#2 fix landed exactly at v0.6.104 (bisected: v0.6.103 still fails, v0.6.104 passes).
v0.6.104's `go.mod` requires `go >= 1.27.0`, so this repo's own `go` directive/toolchain
needs to move too.

#3 needs no action: this project's own `acceptMsg` (`server/server.go`) already rejects any
message where `len(Question) != 1` with FORMERR before the bug would ever matter, and the
README already documents that reasoning. Don't chase it.

## The catch: the native UPDATELEASE type does not support the 4-byte variant

`pkg/lease.LeaseOption` supports both the 8-byte variant (LEASE + KEY-LEASE, always used for
encoding) and, on decode only, the legacy 4-byte variant (LEASE only), gated by
`prefer_4byte_variant` in config (`handlers/opcode5_lease_option.go`). `Encode4Byte` exists
but is currently dead code (nothing calls it) — only `Encode8Byte` is used, by both
`pkg/dnsmsg.NewLeaseUpdate` (client) and `handlers/opcode5_handle.go`'s response builder
(server).

The upstream native type is 8-byte only by construction:

```go
// v0.6.104 edns_types.go
type UPDATELEASE struct {
    Lease    uint32
    KeyLease uint32
}
// zednspack.go: unpack() unconditionally reads two uint32s (8 bytes), no length branch.
```

I verified directly: if `pkg/dnscompat`'s override (`dns.CodeToRR[2] = ...ERFC3597...`) is
removed so the library's own dispatch table is used, a message carrying a genuine 4-byte
UPDATE-LEASE option (4 bytes of data, not 8) fails with `dns unpack: overflow data` — and
that failure kills the *entire message unpack*, not just that option, i.e. strictly worse
than today's behavior for any real 4-byte-variant sender.

`pkg/dnscompat`'s current override works for both variants today only because it forces
`*dns.ERFC3597`, which stores the raw option bytes generically regardless of length —
`pkg/lease.decodeERFC` then branches on `len(data) == 4` vs `== 8`.

**Conclusion: do not simply delete `pkg/dnscompat` and switch `pkg/lease` over to
`*dns.UPDATELEASE` decoding.** That silently breaks `prefer_4byte_variant: true` in a way
that fails the whole request rather than falling back.

## Recommended paths (pick one, this is a product decision, not just a technical one)

**Option A — safe, minimal.** Bump the dependency for whatever else v0.6.82→v0.6.104 carries
(review the intervening CHANGELOG.md entries for anything else relevant), but leave
`pkg/dnscompat`'s override and `pkg/lease` exactly as they are. ERFC3597 still handles both
variants; nothing about the fixed dispatcher gap needs to be consumed. Update the comment in
`pkg/dnscompat/updatelease.go` to say the override is now a deliberate choice (keeps 4-byte
support working) rather than a required workaround for a still-broken library.

**Option B — bigger change.** If 4-byte-variant support (`prefer_4byte_variant`) is
confirmed genuinely unused/droppable (check with whoever owns that config flag — the code
comments call it "legacy"/"backward compatibility" but that's not the same as "safe to
delete"), then:
1. Remove `pkg/dnscompat/updatelease.go` and its blank imports in `cmd/sig0lease/main.go`
   and `cmd/sig0lease-client/main.go` (it's the only file in that package).
2. `pkg/lease.Encode`: replace the `hex.EncodeToString` + `ERFC3597{EDNS0Code: OPTION_CODE,
   Code: data}` construction with `opt.Options = append(opt.Options, &dns.UPDATELEASE{Lease:
   lo.Lease, KeyLease: keyLease})`.
3. `pkg/lease.Decode`/`decodeERFC`: add a case recognizing `*dns.UPDATELEASE` directly
   (`.Lease`/`.KeyLease` fields, no hex decode needed), and decide what happens to the
   4-byte path (drop it deliberately, with a config-time error if `prefer_4byte_variant` is
   still set, rather than a silent behavior change).
4. `pkg/lease.FindOption`: extend the `scan` closure to also match `*dns.UPDATELEASE` (it
   lands in `Pseudo`, confirmed empirically — same section ERFC3597 currently uses).
5. Update `pkg/lease`'s tests and `README_proxy.md`'s "miekg/dns Shortcomings" /
   "Applied Compatibility Patches" sections to reflect whichever option was taken.

## Testing either option

- `go build ./... && go test ./...`
- `CLIENT_KEYSTORE_DIR=... tests/test_update.sh` — the real integration suite against a live
  proxy and real authoritative test zone; confirms wire compatibility end-to-end, not just
  unit-level.
- If Option B: explicitly test a `prefer_4byte_variant: true` config path end-to-end (or
  confirm it's being deliberately removed) — this is exactly the case that silently breaks.

## Explicitly out of scope for this bump

The TCP `serveDNS` bug (a *different* library defect: `(*Server).serveDNS` in `server.go`
sets `r.Options = MsgOptionUnpack` but never calls `r.Unpack()` a second time before invoking
the handler, so `Ns`/`Extra`/`Pseudo` stay empty for every TCP-received message) is **not**
fixed by this bump — confirmed identical in `serveDNS` across v0.6.82 through v0.6.104. That
was fixed separately, in this repo, by replacing `serveTCP`'s use of `dns.Server` with a
custom accept loop mirroring `serveUDP` (see `server/server.go`). The two changes are
independent; don't conflate them.
