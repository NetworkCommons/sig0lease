# Per-Node Lease-Store Locking — Implementation Plan

Status: **draft for review** · Scope: `./main` (proxy only, `handlers/opcode5*` + a new
`pkg/lease` component) · Closes: the check-then-act race across the upstream network
round trip (tracked informally as issue **#6** during the lease-store tree-structure
rework).

---

## 1. Executive summary

Every UPDATE case (A/B/C/D) in `handlers/opcode5_handle.go` follows the same shape:

1. **Check** local state (`LookupByKEY`, `LookupBySIG`, `LookupNonKEYRecord`) and,
   sometimes, remote state (`authoritativeHasRR`, `authoritativeHasKeyAtName` — a real
   network round trip to the authoritative DNS server).
2. **Act upstream**: build and send one signed UPDATE to the authoritative server
   (`h.upstreamCoordinator.SendUpdate`, another network round trip).
3. **Act locally**: on upstream success, mutate the lease store (`pendingMutations`).

Nothing serializes two concurrent requests that touch the same identity between steps
1 and 3. The store's own `sync.RWMutex` (`InMemoryLeaseStore.mu`) only guarantees each
individual map operation is atomic — it says nothing about two *sequences* of
operations interleaving. The canonical failure case (raised by the user while
reviewing the old owner-nested non-KEY storage): two different KEY signers both submit
`UpsertNonKEYRecords` for the *same* TXT RR at nearly the same time; both pass the
"does this already exist under a different owner" check (step 1) before either has
written anything (step 3), and both succeed — the RR ends up double-owned.

The flat, globally-identity-keyed tree built in the ["Reshaping the lease store"]
data-model change (KEY and non-KEY nodes each keyed by their own composite identity,
`NodeKey`/`RecordKey`) is what makes a real fix possible: every node this scheme needs
to protect already has one unambiguous key, independent of who currently owns it.

This document proposes a **per-node-identity lock**, held for the full duration of a
request's check → upstream round trip → local-apply sequence, with three lock-set
rules the user specified:

| Operation  | Lock set                              |
|------------|----------------------------------------|
| Refresh    | `{node}`                                |
| Register   | `{node, parent}` (parent only if any)   |
| Delete     | `{node} ∪ subtree(node)` (children only if any — a non-KEY node never has any) |

Acquisition is **non-blocking** (`TryLock` on every id in the set) with **release-all
on any single failure** — never a blocking `Lock()`, and never a partial hold.

---

## 2. Design principles (already decided)

These were fixed by the user during the data-model discussion and are treated as
requirements here, not options:

1. **Lock identity = the node's own composite key alone** (`NodeKey(keyRR)` for KEY
   nodes, `RecordKey(rr)` for non-KEY nodes) — never keyed by owner. This is what lets
   the two-different-signers-same-TXT race resolve correctly: both requests' lock sets
   contain the *same* id for the RR itself, so whichever acquires it first excludes the
   other, even though the two requests have different candidate owners.
2. **A node can always be locked together with its children**, because a non-KEY node
   is, structurally, incapable of having any — the subtree-lock rule for delete is the
   same rule for both kinds of node, it just resolves to `{node}` for a leaf.
3. **Acquisition is non-blocking**, with full rollback on partial failure. This is what
   makes the scheme deadlock-free *by construction* (§5) rather than by careful lock
   ordering.
4. This is a **handler-level concern, not a storage-level one**. `pkg/lease/state.go`
   needs zero changes for this plan (see §7) — the thing being protected is the
   check → *network I/O* → apply sequence in `handlers/opcode5_handle.go`, which the
   store has no visibility into. Folding locking into `LeaseStorage` would mean every
   backend re-implements it and every caller has to know which subset of the interface
   is "the real" locking API — the kind of indirection already rejected once this
   session (`hasActiveNonKeyRecord`-style wrappers).

---

## 3. Why "always lock the superset" instead of branching on refresh-vs-register

The three rules above are stated in terms of what a KEY/RR operation is (refresh vs.
register vs. delete) — but in `Handle()`, whether a given identity turns out to be a
refresh or a fresh registration is itself learned only by `LookupByKEY`/
`LookupNonKEYRecord`, i.e. by the very check the lock exists to protect. The lock set
has to be computed *before* that check runs.

Resolution: for every KEY RR and every non-KEY RR appearing in the request, always
acquire the **register-shaped** superset, `{node, candidate-parent}`:

- KEY RR: candidate parent = the signer's own node id, if it differs from the KEY's own
  id (exactly the `signerNodeKey != keyNodeKey` test `registerKeyLease` already does at
  `handlers/opcode5_lease.go:93-99` — reused here, not reinvented, to pick the parent
  candidate).
- Non-KEY RR: candidate parent = the owner id it's scoped to in this request
  (`leasepkg.NodeKey(keyRR)` per-key in Case A, or `signerOwnerKey` in Case B/parts of
  A/D) — already computed by `groupOtherRecordsByTargetKey` before any case-specific
  logic runs.

If the identity turns out to be a genuine refresh, the parent lock was unnecessary —
but harmless: it only produces contention if something *else* is concurrently
registering/deleting under that same parent, which is precisely a case the store's
uniqueness invariant needs serialized anyway. This trades a small amount of
extra-conservative locking for not needing a second, narrower code path that can only
be evaluated after the fact.

Case C (delete) does not have this problem — the case is known unconditionally from
`LEASE=0, KEY-LEASE=0` before any per-record check, so its lock set is exactly rule 3
(`{node} ∪ subtree(node)`, no parent) from the start.

---

## 4. The subtree case: children can change while we're still acquiring

Rule 3's `subtree(node)` is dynamic — `ListSubtreeKeys` (`pkg/lease/state.go:424-446`)
walks `m.children` at the moment it's called. A naive "snapshot the subtree, then lock
every id in the snapshot" has its own TOCTOU gap: something could attach a new child
between the snapshot and the lock.

Closed by acquiring **root-first, then expanding**, relying on rule 2: *any* operation
that would attach a new child to a node must itself hold `{child, thatNode}` — so once
we hold `thatNode`'s lock, no new child can attach beneath it until we release.

```
acquireDeleteSet(root):
    if !tryLock(root): return nil, false
    held := {root}
    for pass := 1..maxSubtreePasses:
        current := ListSubtreeKeys(root)      // fresh read, root already ours
        missing := current − held
        if missing empty: return held, true
        for id in sorted(missing):
            if !tryLock(id):
                releaseAll(held)
                return nil, false
        held += missing
        // loop again: locking `missing` doesn't itself guarantee nothing
        // *else* attached in the meantime — re-scan to be sure
    releaseAll(held)
    return nil, false   // gave up after maxSubtreePasses — see §8
```

**Why this converges.** Once root is locked, any node that could still be missing from
`held` after a scan is one of two things: (a) a node that tried to attach *during* our
acquisition and lost the race on its parent's lock (impossible while we hold that
parent — it simply hasn't happened), or (b) a node that already existed before we
locked root and we just haven't scanned it yet. Only (b) is possible, and it's finite
and shrinks by at least one node per pass (the pass that discovers it locks it, pinning
it against further additions beneath it too) — so the loop terminates in at most
`depth(subtree)` passes. `maxSubtreePasses` is a circuit breaker for the pathological
case (e.g. something re-registering children faster than we can lock them), not part
of the correctness argument.

A single-node delete (KEY leaf, or any non-KEY record) takes the `missing` == ∅ branch
on the first pass — one `TryLock`, done.

---

## 5. Deadlock freedom

Every acquisition in this scheme is `TryLock`, never a blocking `Lock()`, and every
failure releases everything this attempt already holds before returning. No goroutine
ever blocks while holding one of these locks — so the circular-wait precondition for
deadlock cannot arise, regardless of what order different requests happen to attempt
their (possibly overlapping) id sets in. This holds independent of §4's retry-until-
converged loop, since each `tryLock` call inside it is itself non-blocking and the
whole loop backs out completely on any failure.

This is also why the ordering question ("should ids be locked in sorted order?") is
about determinism for debugging/logging, not correctness — unlike a blocking-lock
scheme, there is no lock-ordering invariant to maintain here.

---

## 6. What happens on acquisition failure

Recommended: **fail fast, no in-process retry.** If the full lock set can't be
acquired, release whatever was held and return `SERVFAIL` to the client immediately —
the same rcode already used for other transient-but-not-the-client's-fault failures in
`Handle()` (upstream errors, authoritative lookup failures). The client's own
retransmit/retry (already required for any DNS UPDATE client, and already present in
`client/client.go`) handles the retry; the proxy does not spend a goroutine or add
latency looping in place.

This is deliberately conservative and easy to change later — see the open decision in
§9 (bounded in-process retry with jittered backoff is a plausible enhancement if
fail-fast turns out to reject too eagerly under real contention, but nothing here
requires committing to it upfront).

Log a single line distinguishing this from other `SERVFAIL` causes (e.g.
`"lease-store node lock contention: <ids>"`), so operators can tell "the server is
overloaded/broken" apart from "two clients briefly collided on the same record," which
is expected, not a bug.

---

## 7. Relationship to `InMemoryLeaseStore.mu`

Two independent layers, never nested the wrong way:

- **`InMemoryLeaseStore.mu`** (`pkg/lease/state.go:229`) — unchanged by this plan.
  Keeps guarding exactly what it already guards: the atomicity of each individual store
  method's map mutation. Always the *innermost*, briefly-held lock; never held across
  network I/O today, and this plan doesn't change that.
- **The new node lock** — the *outer*, long-held coordination lock, acquired by the
  handler before it makes any store call or network call, released after the request's
  local-apply step. It never itself touches `m.mu` or any map — it's a pure identity
  → `sync.Mutex` table, living outside `InMemoryLeaseStore`.

Because the node lock never calls into the store while held in a way that would
recursively need the node lock again, and `m.mu` is never held across a node-lock
acquisition, there's no cross-layer cycle to reason about.

`pkg/lease/state.go` requires **zero changes** for this plan. `ListSubtreeKeys` (used
by §4) and `NodeKey`/`RecordKey` (used to compute lock ids) already exist and are
already exported.

---

## 8. New component: `pkg/lease/nodelock.go`

Lives in `pkg/lease` (not `handlers`) because node identity is a `pkg/lease` concept
and the RFC 9665/SRP plan (`docs/rfc9665-srp-implementation-plan.md`) already
anticipates a second, sibling handler reusing `pkg/lease` — this lock manager should be
equally reusable, not tied to `UpdateHandler`.

```go
package lease

// NodeLockManager hands out non-blocking, identity-keyed locks. It has no
// knowledge of KEY vs non-KEY, parents, or subtrees -- callers compute the id
// set (see LockSetForRegister/LockSetForDelete helpers below) and this type
// only ever does one thing: try to hold a set of string ids, all-or-nothing.
type NodeLockManager struct {
    mu    sync.Mutex
    locks map[string]*sync.Mutex
}

func NewNodeLockManager() *NodeLockManager

// TryAcquire attempts to lock every id in ids. On any single failure it
// releases everything already acquired by this call and returns ok=false --
// never a partial hold.
func (n *NodeLockManager) TryAcquire(ids []string) (set *NodeLockSet, ok bool)

// NodeLockSet is the held set from a successful TryAcquire. Release is safe
// to call exactly once; callers should defer it immediately after a
// successful TryAcquire.
type NodeLockSet struct { /* ... */ }
func (s *NodeLockSet) Release()

// LockSetForDelete implements §4's root-first-then-expand algorithm using
// store.ListSubtreeKeys. Takes the store as a parameter (an interface
// covering just ListSubtreeKeys) rather than embedding one, so it isn't
// coupled to a specific LeaseStorage implementation.
func (n *NodeLockManager) LockSetForDelete(store SubtreeLister, root string) (set *NodeLockSet, ok bool)
```

Notes on the sketch above (illustrative, not final):

- The per-id `*sync.Mutex` entries in `locks` are created lazily on first use and never
  removed — they're cheap (one uninitialized mutex per distinct identity ever seen) and
  removing them safely would need its own reference-counting scheme for no real benefit
  at this codebase's scale. Worth a one-line comment when implemented so a future reader
  doesn't "fix" it into a leak-prone eviction scheme.
- `TryAcquire` sorts `ids` before attempting, purely so two requests racing on an
  overlapping-but-not-identical set produce deterministic, reproducible logs/tests —
  not required for correctness (§5).
- `LockSetForDelete`'s `maxSubtreePasses` should be a small constant (e.g. 8) with a
  comment pointing at §4's convergence argument.

---

## 9. Handler integration

Everything below wraps the **existing** `Handle()` logic in
`handlers/opcode5_handle.go` unchanged — no case-internal branch needs to change, only
the top of the function.

Insertion point: right after `groupOtherRecordsByTargetKey` succeeds
(`handlers/opcode5_handle.go:92-97`) — the first point at which the case (A/B/C/D,
already known from `leaseDuration`/`keyLeaseDuration`) and the per-key-scoped non-KEY
groupings are both available — and *before* the `if keyLeaseDuration != 0 && ...`
dispatch at line 128, i.e. before the first `LookupByKEY`/`authoritativeHasRR` call
anywhere in any case:

```go
lockIDs := computeLockIDs(zone, updateKeyRRs, updateOtherRRs, updateOtherRRsByKeyOwner,
    signerID, leaseDuration, keyLeaseDuration)
lockSet, ok := h.acquireNodeLocks(lockIDs) // wraps NodeLockManager, handles the
                                            // delete/subtree expansion per id
if !ok {
    h.logger.Debugf("lease-store node lock contention: %v", lockIDs)
    msg := h.makeErrorResponse(r, dns.RcodeServerFailure, "lease store busy, try again")
    return NewErrorResult(msg, "node lock contention", fmt.Errorf("could not acquire node locks"))
}
defer lockSet.Release()
```

`computeLockIDs` mirrors the case dispatch condition exactly (same
`leaseDuration`/`keyLeaseDuration` tests as line 128/322/389/515) so it can never
disagree with which case actually runs afterward:

- **Case A/D-shaped** (any `keyLeaseDuration != 0`): for each `keyRR` in
  `updateKeyRRs`, register-set `{NodeKey(keyRR), signerNodeKey if ≠}` (§3); for each
  scoped non-KEY RR, register-set `{RecordKey(rr), owner}`.
- **Case B-shaped** (`keyLeaseDuration == 0, leaseDuration != 0`): for each RR in
  `updateOtherRRs`, register-set `{RecordKey(rr), signerOwnerKey}`.
- **Case C-shaped** (`leaseDuration == 0, keyLeaseDuration == 0`): for each `keyRR` in
  `updateKeyRRs`, delete-set `{NodeKey(keyRR)} ∪ subtree` (§4); for each RR in
  `updateOtherRRs`, delete-set `{RecordKey(rr)}` (leaf, no subtree expansion needed).
- **Case D's embedded non-KEY deletes**: same as Case C's non-KEY rule, added to the
  Case A/D-shaped set above for the KEY halves of the same request.

The single `defer lockSet.Release()` covers every return path for the rest of
`Handle()` — every case's early-error returns, the shared upstream-forwarding block
(lines 640-691), and the `pendingMutations` apply loop (lines 693-699) — so the lock is
held across exactly the check → upstream round trip → local-apply window this plan
exists to protect, and released automatically no matter which path out of the function
is taken.

`h.acquireNodeLocks` is a thin `UpdateHandler` method translating between
`computeLockIDs`'s output (which ids need plain `TryAcquire` vs. which need
`LockSetForDelete`'s subtree expansion) and `h.nodeLocks *leasepkg.NodeLockManager` — a
new field on `UpdateHandler` (`handlers/opcode5.go:253-274`), constructed the same
trivial way `leaseManager` already is in `NewUpdateHandler()`
(`handlers/opcode5.go:277-287`):

```go
nodeLocks: leasepkg.NewNodeLockManager(),
```

---

## 10. Non-goals / limitations

- **Single process only.** This is an in-memory lock table; it does nothing across
  multiple proxy instances. Every `LeaseStorage` backend today (`InMemoryLeaseStore`,
  `FileLeaseStore` embedding it) is already single-process, so this doesn't newly
  constrain anything, but it's worth stating: if the proxy is ever run as more than one
  replica against shared state, this scheme alone does not make that safe.
- **Not a replacement for `FileLeaseStore.saveMu`.** Periodic/shutdown snapshot saves
  are a separate concern (serializing `SaveSnapshot` calls against each other) and are
  unaffected by this plan.
- **Does not change persistence-hook semantics, response codes for existing error
  paths, or any case's business logic.** Purely an additional serialization layer
  around the existing check → upstream → apply sequence.
- **Does not itself fix `reconcileLeaseTimers`/`processExpiredLease`.** Those run on a
  timer, outside of any client request, and mutate the store directly. Whether they
  need to participate in this same lock table (so an expiring lease can't race a
  concurrent refresh of the same node) is called out as an open decision below —
  they're a different trigger (timer, not client request) but touch the same
  identities and the same store methods, so the same race is plausible there too.

---

## 11. Decisions needing sign-off

| # | Question | Recommendation |
|---|---|---|
| 1 | In-process retry on acquisition failure, or fail-fast (§6)? | Fail-fast: simpler, no backoff policy to tune, relies on the client's existing retry. Revisit only if real contention proves this too eager. |
| 2 | `maxSubtreePasses` constant (§4)? | 8 — generous for any realistic tree depth in this protocol, still a real circuit breaker. |
| 3 | Should `reconcileLeaseTimers`/`processExpiredLease` (`handlers/opcode5_lease.go:179-499`) acquire the same node locks before mutating expired nodes? | Yes, recommended — same identities, same store methods, same race shape, just a different trigger than a client request. Scope as a fast-follow once the request-path locking above is implemented and tested, rather than growing this change further before it's proven. |
| 4 | Expose lock-contention as a metric/counter, not just a log line? | Not yet — add if operational experience shows it's needed; no metrics infrastructure currently referenced in `handlers/opcode5*` to hang it on. |

---

## 12. Testing plan

- **`pkg/lease/nodelock_test.go`** (new, mirrors `state_tree_test.go`'s style):
  - Mutual exclusion: two goroutines `TryAcquire` the same id; exactly one succeeds.
  - Release-all on partial failure: goroutine A holds `{x, y}`; goroutine B attempts
    `{y, z}` and must fail *and* leave `z` unlocked (verified by a third `TryAcquire`
    on `z` succeeding immediately after B's failed attempt returns).
  - Subtree convergence (§4): a background goroutine repeatedly attaches new children
    under a node (simulating concurrent registration) while another goroutine calls
    `LockSetForDelete` on an ancestor; once the attacher itself starts blocking on
    `TryLock` for the parent, the deleter's call must complete and return a lock set
    that includes every node that was actually attached before the deleter first
    locked root. Run with `-race`.
- **`handlers/opcode5_behavior_test.go`** (extend): reproduce the exact scenario from
  the original bug report — two goroutines, two different KEY signers, each submitting
  `UpsertNonKEYRecords`-equivalent requests for the identical TXT RR via `Handle()`
  concurrently, gated by a `sync.WaitGroup`/barrier so both reach their local "does
  this exist under a different owner" check before either has committed. Assert
  exactly one succeeds and the other's response reflects a rejected/conflicting
  registration, not a silently double-owned record. Run with `-race`, and without this
  plan's change first (to confirm it reproduces the old bug), then with it (to confirm
  it's fixed) — matches how the earlier `RemoveSingleNonKEYRecord` idempotency bug was
  caught and verified in this codebase.

---

## 13. Implementation checklist

1. `pkg/lease/nodelock.go`: `NodeLockManager`, `NodeLockSet`, `TryAcquire`,
   `LockSetForDelete` (+ `SubtreeLister` interface covering just `ListSubtreeKeys`).
2. `pkg/lease/nodelock_test.go`: §12's unit tests, `-race` clean.
3. `handlers/opcode5.go`: add `nodeLocks *leasepkg.NodeLockManager` field, wire in
   `NewUpdateHandler()`.
4. `handlers/opcode5_handle.go`: `computeLockIDs` (§9) + `acquireNodeLocks` +
   the acquire/defer-release wrapper at the top of `Handle()`. No changes to any
   Case A/B/C/D internal logic.
5. `handlers/opcode5_behavior_test.go`: §12's concurrent-registration regression test.
6. Full suite (`go build ./...`, `go vet ./...`, `go test -race ./...`) green.
7. Revisit §11 item 3 (`reconcileLeaseTimers`/`processExpiredLease`) as a fast-follow.
