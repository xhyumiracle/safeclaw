# Delegation-log adversarial re-audit — findings + triage (Task #36)

> **STATUS (2026-08-05):** findings below pertain to the current (pre-refactor) build;
> the crypto model + fixes carry over. The identity/keyset SCHEMA is being normalized per
> `unified-identity-schema.md` (target SSOT). #37 (anchor-KEY rotation) stays a non-goal;
> creator-remove is DONE via `unified-identity-schema.md` §6, not via #37.

Two background adversarial auditors (core-crypto fold; cross-layer parity + flows) reviewed
the full delegation-log model. Consolidated below. Verdicts are MINE after verifying each has
a real failure path. Fixes are applied across all three layers (Rust daemon / Node backend /
TS frontend) unless marked FLAGGED.

## FIXED (this pass)

### H-1 — Granter/cred pubkey resolution was not self-certifying (X1 + X2 + C5). CONFIRMED HIGH.
Two symptoms, one root cause:
- **X1 (poison):** backend + frontend keyed the granter's verifying key by the row's
  *self-declared* `uik_user_id → uik_sig_pub`, with no `derive_id(sig_pub) == user_id` check
  (`uik_user_id`/`uik_sig_pub` are NOT stripped on member self-writes). A member could write a
  shadow row `{uik_user_id: G, uik_sig_pub: K_M}` to poison the map for owner G, so G's events
  (e.g. `remove X`) fail to verify on the backend but not the daemon → accept-vs-drop gap /
  removed-member resurrection on the backend's authorization set.
- **X2 (cascade):** offboard deletes the granter's cred row, and events carried only
  `granter_id` (no key) — the key was resolved from live cred rows. So after offboarding A,
  A's `A adds B` could no longer be verified → **B dropped (cascade)**, defeating the whole
  point of the log.
- **C5:** the checkpoint keyed the owner-set on the server-supplied `cred.user_id` without
  `derive_id(sig_pub)==user_id`, and could overwrite the genesis-root Owner entry.

**Fix (self-certifying inline key):** `DelegationEvent` now carries `granter_sig_pub` INLINE;
the fold requires `derive_id(granter_sig_pub) == granter_id` then verifies the sig under it —
no cred-row lookup at all. The event verifies itself, so it is immune to a poisoned cred row
AND survives the granter's cred-row deletion (NON-CASCADE holds). The checkpoint now skips
`root_id` and asserts `derive_id(cred.sig_pub) == cred.user_id` before honoring a grant. The
daemon additionally verifies each event's self-signature AT ADOPT (`adopt_delegation_meta`), so
a colluding server can no longer bloat the log with well-formed junk (closes **C4** DoS).
Regression tests: core `junk_same_seq_event_does_not_suppress_legit`,
`event_verifies_via_inline_key_without_cred_row`; backend §6/§7 (inline-key, forged-granter).

### H-2 — `last_seq` advanced before validation → junk suppresses a legit same-seq event (C1 + X4). CONFIRMED HIGH.
The fold ratcheted `last_seq` BEFORE the owner + signature checks, so a well-formed junk event
sharing a legit event's `seq` (sorted first) consumed the slot and made the dup-guard drop the
real one — a sticky, keyless-server revocation-void. And same-seq winners differed across the
three folds (server-controlled row order).
**Fix:** advance `last_seq` ONLY after an event passes owner + self-certifying-key + signature
checks; sort by `(seq, sig)` (deterministic, server-independent) in all three. Regression:
core `junk_same_seq_event_does_not_suppress_legit`; backend §8.

### M — approveV2Join log redundancy (X5). Fixed.
The add-event lived only on the joiner's row; a DIRECT keyset-delete (not the offboard flow,
which re-stamps first) could lose it → issuance-time-authority break for anyone the joiner
later added. `approveV2Join` now re-stamps the full log onto every existing row.

### H-3 — same-seq tiebreak was cross-impl INCONSISTENT (byte vs base64). CONFIRMED (verifier item 3), FIXED.
My own H-2 fix sorted same-seq events by `(seq, sig)`, but Rust compared the RAW signature
`Vec<u8>` while the backend/frontend compared the base64 STRING. Base64's alphabet is not
ASCII-monotonic, so the two orders disagree ~32% of the time (measured over 200k random pairs;
a concrete differing pair was reproduced) — which would REOPEN the accept-vs-drop gap H-2 set
out to close, for a benign same-seq collision (`nextDelegationSeq` hands two racing owners the
same `max+1`). **Fix:** the JS folds now decode `sig` to raw bytes and byte-compare
(`Buffer.compare` / `cmpB64Bytes`), matching Rust. Regression test: backend §9 grinds a pair
whose byte-order and base64-order winners DIFFER and asserts the fold applies the byte-order
winner (a regression to string-compare would flip it and fail). I caught this myself right
after spawning the verifier; the verifier independently confirmed it on the pre-fix code.

### Residual caveat on X2 (verifier) — checkpoint-seated owner bare-delete. NOTED, not a current hole.
The inline-key fix keeps EVENT-seated grants verifiable after a granter's row is deleted. It does
NOT cover an owner seated ONLY by a root-signed CHECKPOINT grant (which exists only AFTER a
compaction) whose row is then bare-deleted without a `remove` event / re-cut: that owner vanishes
from the checkpoint base, so events they signed cascade-drop. **Why not a current hole:** in the
shipped flows every non-root owner is EVENT-seated (`approveV2Join` grants via an event, sets no
`uik_role_sig`); the root is genesis-seated (checkpoint loop skips it). Checkpoint-seated owners
appear only once COMPACTION is exposed in the UI (not built — like transfer, a follow-up). Folded
into the compaction/transfer follow-up: a compaction that offboards must append a `remove` event
(preserving issuance-time authority), never bare-delete.

### Low / parity notes (verifier)
- Malformed `set` role token: JS coerces any non-`owner` to `member`; Rust would fail the serde
  parse of the whole `delegation_log`. Not security-relevant (a garbage-role event can't hold a
  valid sig). Asymmetry only.
- Frontend genesis-anchor fallback (`genesisPub ??= firstRow`) is server-order-dependent, but the
  frontend is a NON-enforcing render/fail-fast gate (daemon TOFU pin + backend `vaults.user_id`
  are the boundary), so not a security divergence.

## FLAGGED (not fixed this pass — reasons below)

### C2 / C6 — fresh-device membership/generation rollback vs a FULLY-colluding server.
A truly fresh device (empty local log) has no trusted reference, so a fully-colluding server
can serve it a stale owner-set (omit a `remove` event or a compaction cert) or an old
generation. This is **largely inherent to the cloud-blind model** (no second channel). The
append-only union ALREADY protects a *re-syncing* device (it holds the event locally and never
shrinks), which is the common case. **Spec correction:** §0 over-claimed that "the server-signed
sync envelope attests the current (role_epoch, log length/hash) head" — it does NOT: the
envelope rides `/blob` only and its `membership_epoch` is read but never ratcheted. Wiring a
server-signed membership head (over `role_epoch` + log hash) onto `/keys`, ratcheted against the
highest seen, is the proper mitigation (anti-equivocation + re-sync anti-rollback) and is a
**follow-up**, not shipped. Corrected the spec claim to match reality.

### C3 / X3 — succession re-fork + backend anchor under transfer. Tied to deferred transfer (#37).
- C3: `resolve_current_root` prefers the lowest-epoch hop and re-derives from genesis every
  fold, so a former root that kept its key could equivocate and grind a smaller `new_root_id`
  to re-fork the root. Transfer is not cryptographically final while the old root key survives.
- X3: the backend resolves the GENESIS anchor off the `vaults.user_id` row; after a
  creator-offboard that row is gone → backend fails closed while the daemon (TOFU pin) still
  resolves a root. Backend must pin the genesis anchor server-side (set-once column) to survive
  succession.
Both only bite the deferred two-party transfer (#37) — folded into that task's scope.

### Low / noted
`Number(seq)`/`Number(role_epoch)` lose precision above 2^53 (owner-only, latent) — the
`(seq,sig)` tiebreak makes ordering deterministic regardless, but a coordinated-seq scheme
would also want BigInt seqs. The same-seq drop is still a documented v1 limitation (loser
re-appends), now deterministic.

## User decisions (2026-08-04, awake review)

- **D6 SUPERSEDED — creator-leave is just a plain `remove` (Part 1, DONE).** The user
  pushed back that "creator离开" should be part of owner-增减, not a two-party dance. The
  root-permanent-immunity rule was over-engineering. FIXED across all 3 folds: the creator
  is seated at the fold base for ISSUANCE-TIME authority (so their grants verify) but is a
  NORMAL removable owner in the FINAL set; the only invariant is a **last-owner guard** (a
  remove/demote that would empty the owner-set is ignored). UI: the creator row now shows
  promote/demote/remove (guarded). The verification ANCHOR is a KEY (immutable pin), NOT a
  permanent owner-principal. Two-party succession now ONLY covers rotating the anchor KEY on
  creator-key COMPROMISE (rare — task #37). Core: `last_owner_cannot_be_removed` +
  `creator_removable_when_another_owner_exists`. Backend: §10/§11. Gates: core 371 · backend 25.
- **C2 anti-rollback — DONE (Part 2, owner-signed membership commitment).** User rejected the
  server-signed head (the server just signs the lie). Built per the user's design: the
  RekeyProof (owner-signed + generation-ratcheted) now commits a **delegation-log prefix**
  = `(membership_len N, membership_hash)` where `membership_hash = membership_commitment(first-N event sigs,
  (seq,sig) order)`. `rekey_sig_input` gained the two fields (golden vectors updated in all
  3 pins). The daemon's `resolve_membership_trust` gate (`membership_prefix_ok`) recomputes the
  prefix over the SERVED log and → `Untrusted` on mismatch, so the server can't serve the
  CURRENT generation with a rolled-back log (e.g. an omitted `remove`) — the practical
  attack. Low-frequency (only on re-key/offboard). The frontend mirrors the gate
  (defense-in-depth); the BACKEND is unchanged (it's the adversary for this threat and
  can't self-enforce; it only transports/strips the opaque proof). Residual fresh-device-
  vs-permanent-consistent-old-bubble is inherent to cloud-blind (documented; the bubble is
  fragile — new content is under the new K it can't open). Core fixture
  `membership_rollback_is_rejected`; parity `membership_commitment` vectors (empty + non-empty).
  Gates: core 372 · frontend 58 parity + tsc. **Task #39 DONE.**

## Gate status after fixes + Part 1 + Part 2
core `cargo test --lib` = **372 green**; backend `test/delegation-fold.test.mjs` = **25
assertions** + import self-check golden vectors; frontend UIK parity = **58** + `tsc` clean.
Cross-language golden vectors pinned for role_grant / delegation_event / root_succession /
derive_id / rekey_sig_input / membership_commitment.

## What's DONE vs what genuinely needs a decision (2026-08-04, "别再留 todo")
- **DONE (v1 delegation model complete):** full any-owner delegation log (add/promote/demote/
  remove), NON-CASCADE, self-certifying inline granter keys, validate-before-seq + byte-order
  tiebreak, sig-verify-at-adopt, **creator removable via plain remove + last-owner guard (Part
  1)**, **owner-signed membership anti-rollback (Part 2)**, UI (any-owner controls + non-cascade
  offboard review + creator-removable), 3-layer parity, re-audit + fixes. All green.
- **NOT v1 (documented future, not a loose end of this work):**
  - Anchor-KEY rotation on creator-key COMPROMISE (task #37): rotating the trust anchor itself
    is a hard org-recovery problem (can't trust a compromised key to authorize its own
    replacement) — genuinely needs a separate design + product decision. The COMMON case
    (creator leaves cleanly) is DONE (Part 1). C3/X3 only matter if anchor rotation is used.
  - Compaction exposure (role_epoch > 0) + its checkpoint-seated-owner offboard caveat — a
    log-length optimization, not needed for correctness; revisit when long-lived high-churn
    vaults need it.
  - Fresh-device-vs-fully-colluding-server first-sync rollback — inherent to cloud-blind.
