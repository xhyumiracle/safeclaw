# Credential pubkey atomicity — fix "unknown credential" on approve/unlock

Status: PROPOSED 2026-08-22. Fixes the structural gap behind `AppError::Unauthorized("unknown credential")` at approve/unlock/write time on migrated (fmt2) vaults.

## Problem

A WebAuthn credential is `{credential_id, pk=(x,y)}` plus, in v2, a K-seal
(`k_encapped`/`k_ct`) and wrap material (`wrap_salt`/`wc_check`/`wrapped_uik`).
To verify an approve/unlock/write assertion the daemon must resolve
`credential_id -> pk` and check the signature. In v2 (UIK/membership) the pk was
split AWAY from the credential's K-seal:

- Backend `credentials` row: has `x`,`y` (atomic at rest).
- Daemon v2 keyset `uik.creds[cid]` (`UikCred`): has the K-seal but NO `x`,`y`.
  Gap D bolted the pk into a SEPARATE registry, fed by a separate `/membership`
  sync ("own creds only"), which can be stale or empty.
- Offer material `grantPasskeyMaterial`: returns `credential_id` + wrap material,
  NO `x`,`y`.

Result: the OFFER set (member-identity credentials) can exceed the VERIFY set
(daemon registry that actually holds `x`,`y`). Tapping an offered-but-unregistered
credential -> `credential_lookup` miss -> `Unauthorized("unknown credential")`
(`protocol/grant.rs:143`). Worse, the relay poll ENDS on that 401
(`relay::client` "relay register/poll ended"), so the CLI hangs on
"Waiting for approval" with no signal.

v1/fmt1 was airtight (the `SealedCredential` row carried the pk). v2 regressed it.

## Invariant

**offered ≡ verifiable.** A credential's pk travels ATOMICALLY with the
credential across every hop: authoritative store -> membership serve -> daemon
keyset -> offer -> verify. No separate "did the pk sync yet" dependency.

## Decisions

- **D1 (core, the fix): fold `x`,`y` into `UikCred`.** Each v2 credential record
  carries its ES256 pubkey alongside its K-seal, synced as ONE unit via
  `/membership`. `credential_lookup` / grant verify read the pk from `uik.creds`.
  This removes the separate-registry dependency for v2. `serde(default)` on the
  new fields so existing on-disk keysets deserialize (pk empty) and backfill on
  the next membership pull — no disk-format break.
- **D2 (backend): serve + offer carry the pk.** `/membership` already selects
  `x`,`y` (Gap D); confirm it returns them for ALL member credentials (any of a
  person's passkeys can approve), not a subset. `grantPasskeyMaterial` adds
  `x`,`y` per credential so the offer and the daemon read the SAME record.
- **D3 (self-heal): re-pull before failing.** On a `credential_lookup` miss for a
  credential the cloud DID offer, trigger a fresh `/membership` pull and retry
  once before returning "unknown credential". Backfills daemons whose cursor did
  not advance (the Gap A class); matches the sync-watchdog self-heal ethos.
- **D4 (fail loud): the poll must not die on one 401.** `relay::client` must keep
  the op live on a redeem rejection and surface a clear, retryable error
  ("this passkey can't approve this vault, pick another") instead of ending the
  poll and hanging the CLI.
- **D5 (DB — the "merge x/y into one pk" question): KEEP `x`,`y` columns; do NOT
  migrate to a single `pk` blob.** Rationale below.

### D5 rationale (honest take, not just agreeing)

`x`,`y` are the two coordinates of one P-256 point — they ARE the pk, and the
`credentials` ROW already stores them together as one unit. The bug was never the
two-column shape; it was DROPPING the pk as the credential flowed to the daemon and
the offer. A single `pk` blob column does not structurally prevent "forgot to carry
it" (you can omit a `pk` column from a SELECT just as easily as omitting `x`,`y`).
Where unification actually prevents the bug is the TYPE level: the Rust `UikCred`
and the TS credential type bundle the pk so a credential record cannot be
constructed without it. A DB migration to `pk` = churn across every reader/writer
+ golden-vector rework, with no gain the type-level bundling doesn't already give.
So: agree with the PRINCIPLE (unify the pk), enforce it in the TYPE, keep the DB
columns.

## Non-goals

- DB schema merge of `x`/`y` into one column (D5).
- v1/fmt1 rework (already carries the pk in `SealedCredential`).

## Scope

- **core (Rust):** `UikCred` +`x`,`y` (`serde(default)`); `adopt_membership_triple`
  populates them; `credential_lookup` / `protocol/grant.rs` / `metadata.rs` v2 read
  the pk from `uik.creds`; golden vectors + fixtures; relay poll resilience (D4) +
  self-heal re-pull (D3).
- **backend (Node):** `grantPasskeyMaterial` +`x`,`y`; confirm `/membership`
  serves every member credential's pk.
- **frontend:** none expected (it offers + derives; the daemon verifies).
- **DB:** none.

## Rollout

Existing daemons backfill `uik.creds` pk on `sc upgrade` + next membership pull.
D3 self-heal covers vaults whose sync cursor did not advance. No migration; no
prod schema change.

## CONVERGED & BUILT 2026-08-22 (supersedes D1/D5 framing above)

Traced one level deeper before coding: `adopt_membership_triple` ALREADY co-adopts
each cred's x/y into the registry (Gap D), and `credential_lookup` reads it. So the
daemon's miss was NOT "the struct doesn't hold the pk" — it was **staleness**: a
backend x/y backfill on an already-synced membership does NOT bump `keyset_seq`, so
the daemon never re-pulls and its registry stays missing that cred, while the OFFER
(`grantPasskeyMaterial`, by identity membership) lists it anyway. Divergence →
"unknown credential" → relay poll ends on the 401 → CLI hangs.

Shipped fix (D1 atomic-struct refactor DROPPED — churn across 15+ callers + golden
vectors with no reliability gain; the registry already co-locates the pk):

- **D3 self-heal (load-bearing).** `sync::resync_membership_now` = FULL (`since=0`)
  `/membership` re-pull; `pull_membership` gains a `force_full` flag (a delta pull
  would reply "nothing new"). The approve handler, on a `credential_lookup` miss,
  re-pulls + re-reads once before validating — so a merely-unsynced valid passkey
  succeeds on the FIRST tap.
- **D2 offer==verify (backend).** `grantPasskeyMaterial` now also requires `x`/`y`
  non-null, so a pubkey-less cred (never verifiable) is never offered.
- **D4 fail-loud (core).** On an apply failure the relay client REJECTS the op
  (`apply_reject`) instead of ending the poll with `Err`, so `sc unlock` / `sc op
  wait` returns a definitive error instead of hanging on "Waiting for approval".

Verified: `cargo build --release` green; `cargo test --lib` 417 passed / 0 failed
(golden vectors untouched). Files: core `sync.rs`, `server/handlers/approve.rs`,
`relay/client.rs`; backend `vault-routes.mjs`.
