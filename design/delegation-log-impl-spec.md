# Delegation-log implementation spec (Task #30)

> **STATUS (2026-08-05): schema / naming / UIK-scope SUPERSEDED by
> `unified-identity-schema.md`** (target SSOT for the pre-prod refactor). The CRYPTO
> MODEL here (owner-set fold, delegation events, non-cascade, anchor pin, generation
> anti-rollback) CARRIES OVER. What changes: normalized tables instead of the one
> `vault_keys` blob; UIK per-person (not per-vault); NoUik deleted (personal unifies);
> `vaults.user_id` no longer an authority (Option B); field names → encrypt/wrap/seal.
> On any schema / naming / UIK-scope conflict, the unified doc wins.

Concrete build contract for reworking the **one-hop creator-signs-all** role model
into the **full multi-admin delegation-log** model of `identity-uik-aik.md §4.3`.
This spec RESOLVES §4.3's underspecification (it left "checkpoint signed by whom"
and "generation vs seq" open). Grounded in memory
`reference_delegation_sigchain_first_principles` + `project_team_edition_design`.

Status: team-edition UIK format is dev-only, never released → **we may change the
`KeysetUik` wire format freely** (no migration compat for team vaults). Personal v1
vaults (`uik == None`) are untouched (all deltas are additive to the v2 layer).

---

## 0. The resolved model (the design decision — FLAG FOR USER REVIEW)

Three requirements from §4.3 that a single flat root-signed grant-set CANNOT satisfy
together, forcing the log:

1. **Non-cascade removal** — removing A must not drop whoever A added (user, 08-04).
2. **Any-owner delegation** — any current owner may add/remove (SPKI delegation bit).
3. **Cloud-blind fresh-boot** — a fresh daemon verifies the owner-set from the pinned
   root without trusting the server and without replaying full history.

(1)+(2) require **issuance-time authority** ("A was an owner *when* A signed"), which
is a historical fact → an ordered LOG. (3) requires the fold's base to be
**root-signed** (depth-1 under the TOFU pin) so no history is needed below it.

**Resolution — TWO orthogonal monotonic counters (memory: "generation ⊥ chain"):**

- `generation` (**K-epoch**, EXISTING): the DP-S1 content-key rotation epoch. Bumped
  on K-rotation (eviction / passkey-leak). RekeyProof-gated. Guards K rollback +
  crypto-eviction. Authority to bump = **any owner** (RekeyProof signed by an owner).
- `role_epoch` (**role-checkpoint epoch**, NEW): the epoch at which the current
  ROOT-signed checkpoint of the owner-set was cut. Role grants are bound to THIS, not
  to `generation`. Bumped only on **compaction** (root re-cuts the flat checkpoint).

**Owner-set = fold( root-signed checkpoint @ role_epoch ) ∘ ( delegation_log ).**

- **Checkpoint** = the per-cred `role`/`role_sig` (EXISTING), now signed over
  `role_grant_input(vault, user, role, role_epoch)` (was `generation`; the byte layout
  is unchanged — only which counter is bound). Verified under the current root (see
  succession). Depth-1 → fresh-boot verifiable, no history.
- **Log** = `delegation_log: Vec<DelegationEvent>`, events since the checkpoint, each
  signed by **any principal who is an owner in the fold up to that event** (issuance-
  time authority). Ordered by `seq` (monotone within a `role_epoch`).
- **Fold** = base owner-set from the checkpoint, then apply log events in `seq` order;
  each event honored iff its `granter_id` ∈ owner-set-so-far. `remove` drops only its
  `subject` (NON-CASCADE). Result = current owner-set.

**Who can do what:**

- **add / promote / demote / remove (role authority)** = a signed `DelegationEvent`,
  by **ANY owner**. Immediately authoritative via the fold. No root, no re-key needed.
- **crypto-eviction (deny future K)** = K-rotation (`generation++` + RekeyProof + re-
  seal K to remaining `enc_pub`s). **ANY owner** (needs K, which every member has, +
  an owner signature). Decoupled from the role-remove event (which is instant); the
  removed person keeps K until the next K-rotation — same "offline lease window"
  honesty line we already ship.
- **compaction (log → checkpoint, root re-cut, `role_epoch++`)** = **ROOT only**
  (only the root can produce root-signed depth-1 grants a fresh daemon trusts under the
  pin). Compaction is periodic housekeeping to keep the log short; it gates NO security
  action. If the creator has left, succession has moved root to a successor who compacts.
- **root transfer / creator-offboard (succession)** = a `RootSuccession` event, the
  current root signs the next root's id. Daemon follows the short succession chain from
  the TOFU-pinned genesis root → current root.

**Rollback / anti-fork:** `role_epoch` + per-event `seq` are monotone; a lower value is
rejected. The append-only UNION adopt (never shrink the local log/chain) is what protects
a RE-SYNCING device from a server that serves a stale subset — it keeps the events/certs it
already holds. **CAVEAT (re-audit C2, NOT yet closed):** a truly FRESH device (empty local
log) has no trusted reference, so a fully-colluding server can serve it a stale owner-set
(omit a `remove` or a compaction cert). This is largely inherent to cloud-blind. The intended
mitigation — a server-signed membership head over `(role_epoch, log hash)` on `/keys`, ratcheted
against the highest seen (anti-equivocation + re-sync anti-rollback) — is a FOLLOW-UP and is
NOT implemented yet (the existing server envelope rides `/blob` only and its `membership_epoch`
is read but not ratcheted). See `delegation-log-review-findings.md`. The server is trusted to
withhold/delay, NEVER to forge authority (that's the root pin).

**Fail-closed:** unpinnable/absent root, broken succession chain, or an event whose
granter is not an owner-so-far ⇒ that event is dropped; a keyset whose checkpoint won't
verify under the (succession-resolved) root ⇒ `MembershipTrust::Untrusted` (drop all owner-
config, as today). Secrets/connections still fold (member-tier).

### DESIGN DECISIONS FLAGGED FOR USER (review in the morning)

- **D1. Two counters** (`generation` = K-epoch ⊥ `role_epoch` = role-checkpoint). Backed
  by your own "generation ⊥ chain 正交" note. Alternative (single counter) forces every
  role change to be a full re-key → collapses back to creator-only. Chose two.
- **D2. Compaction is root-only; add/remove are any-owner events.** Root-only compaction
  is FORCED by cloud-blind fresh-boot (only root-signed depth-1 is verifiable under the
  pin without history). It gates no security action (adds/removes/evictions are all any-
  owner). Honesty cost: the log grows until the root next compacts; a fresh daemon folds
  base+log (both present in the keyset), so correctness never depends on compaction.
- **D3. Role-remove (instant, event) is decoupled from K-eviction (next K-rotation).**
  Matches the existing offline-lease honesty ("kill/offboard 离线时延=租约窗口, 文案禁
  '即刻失效'"). An owner who wants immediate crypto-eviction does remove-event + K-rotate
  together (the console "offboard" button does both, as today).
- **D4. Root transfer via `RootSuccession` chain** (creator can leave). This is the most
  novel piece and the one most needing e2e validation.
- **D5 (REFINEMENT of D1/D2, decided in build). `role_epoch` is DERIVED from the
  root-signed succession chain, NOT stored as a separate scalar.** A pure compaction is
  a SELF-succession cert (`old_root == new_root`, same pubkey, epoch bumped), signed by
  the root. `resolve_current_root` now returns `(root, role_epoch)` — the epoch is
  whatever the chain walks to. **Why this is strictly better:** the spec's original plan
  (a stored `role_epoch` scalar) would let a colluding server forge `role_epoch: 999` to
  strip every non-root owner from the fold (a sticky DoS, the exact class F-1 fixed for
  `generation`), which CONTRADICTS D2's invariant "correctness never depends on
  compaction." Deriving it from a root-signed chain makes the epoch **un-forgeable by
  construction** — no separate proof artifact (`role_epoch_sig`) needed, one fewer field,
  one fewer parity surface. The two-counter model (D1) is unchanged: `generation`
  (stored scalar, RekeyProof-gated) ⊥ `role_epoch` (chain-derived). This eliminates the
  `KeysetUik.role_epoch` field entirely.

---

## 1. Core (Rust) — `safeclaw`

### 1.1 `identity.rs`
- `DS_DELEGATION: &[u8] = b"safeclaw/v1/delegation-event"`.
- `DS_ROOT_SUCCESSION: &[u8] = b"safeclaw/v1/root-succession"`.
- `delegation_event_input(vault_id, op, subject_id, role, granter_id, seq, role_epoch) -> Vec<u8>`
  = `lp(DS_DELEGATION) ‖ lp(vault) ‖ lp(op) ‖ lp(subject) ‖ lp(role) ‖ lp(granter) ‖ u64_be(seq) ‖ u64_be(role_epoch)`.
  `op ∈ {"set","remove"}`; `role` = lowercase token for `set`, empty for `remove`.
- `root_succession_input(vault_id, old_root_id, new_root_id, new_root_sig_pub, role_epoch) -> Vec<u8>`
  = `lp(DS_ROOT_SUCCESSION) ‖ lp(vault) ‖ lp(old_root) ‖ lp(new_root) ‖ lp(new_root_pub) ‖ u64_be(role_epoch)`.
- KEEP `role_grant_input` byte-identical; only the caller now passes `role_epoch` (not
  `generation`) as the trailing u64. Update the doc-comment to say "role_epoch".
- Golden vectors for both new inputs (pinned hex) — parity gate vs browser.

### 1.2 `storage/sealed_vault.rs`
- `struct DelegationEvent { op: String, subject_id: String, role: MemberRole, granter_id: String, seq: u64, role_epoch: u64, sig: Vec<u8> }` (serde; `sig` = `granter`'s Ed25519 over `delegation_event_input`).
- `struct RootSuccession { old_root_id, new_root_id, new_root_sig_pub: Vec<u8>, role_epoch: u64, sig: Vec<u8> }` (sig by `old_root`).
- `KeysetUik` gains (all `#[serde(default)]`, additive):
  - `role_epoch: u64` (checkpoint epoch; grants signed at this).
  - `delegation_log: Vec<DelegationEvent>`.
  - `root_succession: Vec<RootSuccession>` (chain from genesis `creator_sig_pub`).
- **`resolve_current_root(uik) -> Option<[u8;32]>`**: start at pinned `creator_sig_pub`;
  walk `root_succession` in order; each hop valid iff `sig` verifies under the *current*
  root pub over `root_succession_input(...)` AND `old_root_id == derive_id(current root)`
  AND `role_epoch` strictly increases. Return the last valid root pub. Any break ⇒ stop
  at last-good (fail-closed forward: an unverifiable succession does NOT advance root).
- **`owner_set_at` → generalize to `fold_owner_set(uik, vault_id) -> BTreeMap<String,MemberRole>`**:
  1. base: current root's id → Owner (genesis). Plus each cred whose `role_sig` verifies
     under the **current root** over `role_grant_input(vault, user, role, role_epoch)`.
  2. apply `delegation_log` in `seq` order (reject out-of-order / dup seq): resolve the
     `granter_id`'s sig_pub from the creds; event honored iff granter ∈ running owner-set
     AND granter is `Owner` AND `sig` verifies over `delegation_event_input`. `set` →
     insert subject→role; `remove` → drop subject. NON-CASCADE (touch only subject).
  3. **last-owner guard** in the fold: a `remove`/demote that would empty the owner-set is
     ignored (defense-in-depth; also enforced at write time).
- `resolve_membership_trust` → build `MembershipTrust::Verified(fold_owner_set(...))`; `Untrusted`
  when v2+creds present but `resolve_current_root` is `None`; `NoUik` when `uik==None`.
- `verify_rekey_proof`: unchanged shape; the owner check now reads the folded owner-set.
- Compaction helper `checkpoint_owner_set(uik, new_role_epoch, root_sk)`: fold → write
  flat `role_sig`s on creds (root-signed @ new_role_epoch) for survivors → drop removed
  creds → clear `delegation_log` → set `role_epoch = new_role_epoch`. (Rust side is
  verify/apply only; the SIGNING of a compaction is done by the root's client = console.)

### 1.3 `sync.rs`
- `KeyRowData` / keyset sync already carries `uik_*`; add carriage for `role_epoch`,
  `delegation_log` (JSON), `root_succession` (JSON). `adopt_*` two-pass unchanged in
  spirit; add: verify the delegation_log folds cleanly & `role_epoch`/succession are
  monotone before adopting (reject a rollback — same guard style as `adopt_rekey_meta`).
- `adopt_creator_pin` stays SET-ONCE on the **genesis** root; succession advances the
  *effective* root via the verified chain, never by overwriting the pin.

### 1.4 Fixtures (hard gates)
`fold_nonroot_owner_grant_accepts`, `fold_grant_by_non_owner_rejected`,
`remove_is_non_cascade` (A adds B, remove A, B still owner), `stale_granter_ok_after_removal`,
`delegation_log_out_of_order_rejected`, `role_epoch_rollback_rejected`,
`root_succession_transfers_root`, `forged_succession_does_not_advance_root`,
`last_owner_removal_ignored`, `checkpoint_compacts_log_preserves_ownerset`. Keep the
existing role/rekey fixtures green (they become the `role_epoch`==`generation` special case).

## 2. Backend (Node) — `safeclaw-pro-backend` `keyset-roles.mjs`
- Mirror `fold_owner_set` byte-for-byte (Node Ed25519 via SPKI DER prefix): resolve
  current root via succession, verify checkpoint grants @ `role_epoch`, fold
  `delegation_log`. `resolveKeysetRoles` returns `{owners, generation, role_epoch}`.
- **F-2 fix:** the anchor is the **succession-resolved current root**, NOT bound to
  `vaults.user_id`. Genesis root still = `derive_id(creator_sig_pub)`; follow succession.
- All owner-gates already route through `isSignedKeysetOwner`/`resolveKeysetRoles` → they
  inherit multi-owner automatically. `handleKeyPut` self-cid strip: also strip
  `uik_delegation_log`/`uik_root_succession`/`uik_role_epoch` from member self-writes.

## 3. Frontend (TS) — `safeclaw-pro-frontend`
- `lib/uik-crypto.ts`: `delegationEventInput`, `rootSuccessionInput`, `verifyDelegationEvent`,
  `verifyRootSuccession`; `role_grant_input` trailing u64 = `role_epoch`. Parity vectors.
- `lib/vault-grant.ts`: `foldOwnerSet` (mirror); `addOwnerEvent`/`removeOwnerEvent`/
  `setRoleEvent` (any owner appends a signed event, no re-key); `compactCheckpoint`
  (root-only, re-cut); `transferRoot`/`leaveAsCreator` (RootSuccession). `rekeyVault`
  gains any-owner (was creator-only) for K-eviction; compaction stays root-only.
- UI: **any owner** sees add/remove/role controls (was `isCreator`-gated). Offboard flow
  surfaces "A also added X, Y — remove them too?" (explicit non-cascade human review).
  A "Transfer ownership / leave" affordance for the root. Members tab shows per-member
  "added by" (from the fold provenance) for the review UX.

## 4. UI DESIGN REVIEW (user asked explicitly)
After functional build: review the team-edition console surfaces
(`components/saas-vault/*`, `/join/[token]`, team-dashboard) against the UI design specs
(`safeclaw-market/designs/team-edition-ui/*.png`, wave-59-63 view-as/deny-visible-locked/
matrix-dual-channel) AND aesthetic bar (global frontend-design skill: bold direction, no
generic AI look, brand lockup from `lib/brand.ts`). Report deltas; fix within design.

## 5. Sequencing (loop iterations)
1. spec (this) ✔ → 2. core: types + signing inputs + fold + succession + fixtures (green
core) → 3. backend mirror (node --check + self-check) → 4. frontend crypto + parity → 5.
frontend UI (any-owner controls + offboard review + transfer) → 6. UI design+aesthetic
review → 7. adversarial re-audit (subagents) → 8. final green-gate sweep + e2e handoff notes.
Reuse: role_sig / RekeyProof / generation / MembershipTrust / 6 backend gates / F5 as the base.

---

## 6. Build progress log (loop, 2026-08-04)

- **[DONE] Spec (§0-§5).** This file.
- **[DONE] Core `identity.rs`.** `DS_DELEGATION` + `DS_ROOT_SUCCESSION`;
  `delegation_event_input(vault, op, subject, role, granter, seq, role_epoch)`;
  `root_succession_input(vault, old_root, new_root, new_pub, role_epoch)`;
  `role_grant_input` trailing u64 renamed `generation` → `role_epoch` (bytes
  unchanged; golden vector `pinned_role_grant_input` still valid).
- **[DONE] Core `sealed_vault.rs`.** `DelegationEvent` + `RootSuccession` structs;
  `KeysetUik` +`role_epoch`/`delegation_log`/`root_succession` (all serde-default →
  gen-0 behavior preserved); `resolve_current_root` (succession walker, fail-closed
  forward); `owner_set_at` → `fold_owner_set` (checkpoint@role_epoch ∘ log, issuance-
  time authority, NON-CASCADE remove, ROOT immune to log events → owner-set never
  empties); `resolve_membership_trust` succession-aware (Untrusted when no resolvable
  root + creds present).
- **[DONE] Core `sync.rs`.** `adopt_rekey_meta` owner-check now folds at current
  role_epoch (`fold_owner_set`), not `owner_set_at(generation)` — K-epoch ⊥ role-epoch.
- **[DONE] Fixtures.** `role_grant_generation_bound` → `role_grant_role_epoch_bound`
  (proves gen-bump ⊥ owner-set; role_epoch-bump drops stale grant); +6 new:
  `delegation_event_grant_and_non_cascade`, `delegation_event_by_non_owner_rejected`,
  `delegation_log_dup_seq_replay_rejected`,
  `root_succession_transfers_root_and_offboards_creator`,
  `forged_succession_does_not_advance_root`, `root_immune_to_log_events`.
  **363 core tests green** (was 357).

### NEXT (in order)
- **[DONE] Core sync carriage + role_epoch derivation (D5).** `resolve_current_root`
  now returns `(root, role_epoch)`, order-robust search walk (reorder-DoS closed);
  removed the stored `KeysetUik.role_epoch` (compaction = self-succession). `KeyRowData`
  +`uik_delegation_log`/`uik_root_succession` (JSON, `b64_std` serde → the exact browser
  wire); `adopt_delegation_meta` = append-only UNION + dedup + well-formedness screen
  (rollback-safe BY CONSTRUCTION — the fold re-derives authority from signatures, so no
  verify-before-ratchet needed unlike `generation`); PASS-2a before the re-key gate;
  `key_row_data_for` re-emits both. Golden vectors `pinned_delegation_event_input` +
  `pinned_root_succession_input` (Rust pin). 2 new sync tests prove a fresh device folds
  the SAME owner-set from the carried log + compaction. **367 core tests green** (was 363).
- **[DONE] Backend mirror** (`keyset-roles.mjs`). `resolveKeysetRoles` now folds the
  FULL model: `resolveCurrentRoot` (succession/compaction chain walk, order-robust,
  derives root+role_epoch) → `foldOwnerSetFromRows` (pure, exported, unit-testable) =
  root-signed checkpoint @ derived epoch ∘ append-only delegation log (any-owner,
  NON-CASCADE, root-immune). Added `delegationEventInput`/`rootSuccessionInput`/
  `deriveUserId` (RFC4648 base32, matches Rust `derive_id` — pinned `pinned_derive_id`).
  F-2 anchor = genesis, current root = succession-resolved. Import-time self-check pins
  delegation + succession + derive_id golden vectors (fail-boot on drift). `handleKeyPut`
  member self-write strip extended to `uik_delegation_log`/`uik_root_succession`.
  New `test/delegation-fold.test.mjs`: **14 assertions green** (non-cascade, self-promote
  blocked, compaction derives epoch + drops stale grant, forged succession inert, real
  transfer offboards creator). Returns `{owners, hasUikMembership, generation, roleEpoch}`.
- **[DONE] Frontend crypto + orchestration.** `uik-crypto.ts`: `delegationEventInput`
  / `rootSuccessionInput` + `verifyDelegationEvent` / `verifyRootSuccession`.
  `vault-api.ts`: `DelegationEventWire` / `RootSuccessionWire` + the two `uik_*` fields.
  `vault-grant.ts`: `foldOwnerSet` (delegation-aware, order-robust `resolveCurrentRoot`
  from keys) replacing the generation-based `ownerIdsFromKeys`; builders
  `buildDelegationEvent` / `buildCompactionCert` / `buildTransferCert` +
  `nextDelegationSeq`. FLOWS reworked to the delegation model: `approveV2Join` adds via
  an any-owner `set` event (was creator-only checkpoint grant); `rekeyVault` is now
  PURE any-owner K-eviction (dropped creator-only gate + `roleChange` + the
  generation-bound role re-sign — grants bind role_epoch, untouched by K-rotation) and
  re-stamps the FULL log/succession on every re-sealed row (redundancy → non-cascade
  survives a row deletion); `changeRoleAndRekey`→`changeMemberRole` = a `set` event (NO
  re-key); `offboardMemberAndRekey` = `remove` event (instant, all-rows) THEN K-evict.
  New `appendDelegationEventToAllRows` (any-owner append + full-log re-stamp). Parity
  harness §12: delegation/succession/derive_id golden vectors + sign→verify roundtrips
  — **56/56 green**; `tsc --noEmit` clean (only pre-existing stale `.next` route stubs).
- **[DONE (transfer deferred)] Frontend UI** (`tab-members.tsx`). Gating reworked
  isCreator → **any-owner**: `canManage` = my `uik_user_id` ∈ `foldOwnerSet(keys)`
  (the same fold the daemon/backend enforce), not "am I the creator". Promote/demote
  title fixed ("a signed event — no re-key"). Offboard now surfaces a **non-cascade
  review**: if the member ever granted others, a confirm lists them and states they
  STAY. `tsc` clean. **Transfer/leave DEFERRED + FLAGGED (D6):** creator-offboard is a
  genuine TWO-PARTY handshake — the outgoing root signs a `RootSuccession` (epoch++),
  but the checkpoint must be RE-CUT by the INCOMING root (grants verify under the *new*
  root at the new epoch, and epoch-0 events are epoch-gated out), which the outgoing
  root can't do alone. The crypto is ready + tested (`buildTransferCert`, fold
  succession handling, fixtures + parity); the console UX (initiate → accept, like a
  GitHub org-ownership transfer) needs a product decision. Not needed for the main
  any-owner add/promote/demote/remove e2e.
- **[DONE] UI design + aesthetic review** (§4). **Assessment:** the team-edition console
  is aesthetically strong + internally consistent — one cohesive luxury-dark system
  (surface `#111113`, gold `#C9A96E` accent, mono ids, uppercase tracked micro-labels,
  thin `fontWeight:200` numerals, 12–14px rounded cards). `team-dashboard`'s alpha-graded
  gold heat-matrix + the `/join` page's warm human copy voice are highlights; no generic
  AI-slop. **Fixes applied within the design:** (1) replaced my offboard `window.confirm`
  (a raw browser dialog — jarring in this console) with an **inline danger-toned confirm
  panel** in the console's own voice (grantee chips + Cancel / Remove-anyway); (2)
  **em-dash iron-rule sweep** — removed all 11 user-facing em-dashes across tab-members,
  /join, team-dashboard, connection-form, tab-overview, connections-tab (console now
  0 user-facing em-dashes); (3) team-dashboard null placeholder `—` → `·` (matches its own
  zero-heat glyph). `tsc` clean. **Caveat (flag):** the design PNG mockups
  (`team-edition-ui/*.png`, wave-59-63) are NOT in this checkout (market `designs/` is
  empty — they live in your HQ repo), so this was reviewed against the brand lockup +
  frontend-design skill + aesthetic bar + memory copy conventions, NOT pixel-matched.
- **[DONE] Adversarial re-audit** (2 subagents: core-crypto fold; cross-layer parity + flows).
  Full triage in `delegation-log-review-findings.md`. **Two HIGH findings CONFIRMED + FIXED
  across all 3 layers:** (H-1) granter/cred pubkey resolution was not self-certifying (a member
  could poison the backend/frontend fold, and offboard-row-deletion broke non-cascade) → fixed
  by carrying `granter_sig_pub` INLINE (self-certifying `derive_id==granter_id`), checkpoint
  self-consistency + root-skip, and sig-verify-at-adopt (also closes a junk-growth DoS); (H-2)
  `last_seq` advanced before validation so a junk same-seq event suppressed a legit one → fixed
  by advancing only after owner+sig validation + a deterministic `(seq, sig)` sort. A THIRD
  independent verifier pass CONFIRMED both closed and caught a follow-on defect I'd introduced
  (H-3): the `(seq,sig)` tiebreak sorted on raw bytes in Rust but base64 STRINGS in JS (~32%
  disagree) → fixed to byte-compare everywhere, with a deterministic differing-pair regression
  test. **FLAGGED (not fixed):** C2/C6 fresh-device rollback vs a fully-colluding server (largely
  inherent; union covers re-sync; server-signed `/keys` head is a follow-up — spec §0 claim
  CORRECTED); C3/X3 succession re-fork + backend anchor under transfer → folded into #37; a
  compaction-only-owner bare-delete caveat → folded into the compaction follow-up. Full triage:
  `delegation-log-review-findings.md`. Post-fix gates: **core 370 · backend 22 · frontend 56 + tsc**.
- **[DONE] Final green-gate sweep.** core `cargo test --lib` = **368 green**; backend
  `test/delegation-fold.test.mjs` = **14 assertions** + import-time self-check golden
  vectors; frontend UIK parity harness = **56 green** + `tsc --noEmit` clean. All three
  layers agree byte-for-byte (pinned golden vectors: role_grant / delegation_event /
  root_succession / derive_id).

### E2E HANDOFF (dev)
- **Path:** create a SHARED team vault (creator = root/owner). Invite a member (owner or
  member role) via the `/join/<token>` link → they accept → creator approves in the
  Members tab (now an **any-owner delegation event**, not a creator-only grant).
  Promote/demote in the Members tab (**no re-key** — an instant signed event). Add a
  SECOND owner; have that owner add a THIRD member (proves **any-owner** delegation).
  Remove the first owner — the **inline non-cascade review** confirms the third member
  STAYS. Every owner-config write gates on the folded owner-set (daemon + backend agree).
- **Not in this build:** transfer / creator-offboard (D6, two-party — task #37).
  Compaction (`role_epoch` bump) is exercised by tests, not a manual UI action (it is
  housekeeping; the model is correct without it).
- **Gotchas:** team edition is DEV-ONLY and the `KeysetUik` wire format CHANGED (no
  migration compat) → recreate any existing dev team vault. Role grants now bind
  `role_epoch` (0 for an uncompacted vault), NOT `generation`. Everything is uncommitted.

### POST-REVIEW (2026-08-04, user awake — two more decisions, BOTH DONE)
- **Part 1 — creator removable (D6 SUPERSEDED).** The user rejected the two-party
  transfer as over-engineering: creator-leave is just a plain `remove` event. Dropped
  root-immunity; the creator is seated at the fold base for issuance-time authority but
  is a NORMAL removable owner in the final set, guarded by a **last-owner guard** (never
  empty the owner-set). The genesis KEY stays an immutable verification anchor; the
  creator PRINCIPAL is removable. UI shows promote/demote/remove on the creator row.
  3 layers + fixtures + UI, all green. Anchor-KEY rotation on creator-key COMPROMISE is a
  separate future org-recovery feature (not v1).
- **Part 2 — anti-rollback (C2 RESOLVED, owner-signed not server-signed).** The user
  rejected the server-signed head (server signs the lie). Built: the owner-signed,
  generation-ratcheted `RekeyProof` now commits the delegation-log PREFIX
  (`membership_len` + `membership_commitment`); the daemon's `resolve_membership_trust` refuses a
  keyset whose served prefix doesn't match → `Untrusted`, so the server can't serve the
  current generation with a rolled-back log. Low-frequency (re-key only). Frontend
  mirrors the gate; backend unchanged (it's the adversary here). Fresh-device-vs-
  permanent-bubble stays inherent. Full detail: `delegation-log-review-findings.md`.
  **Gates: core 372 · backend 25 · frontend 58 parity + tsc.**

### FLAGGED FOR USER (added this loop)
- **D6. Transfer/creator-offboard is inherently two-party (initiate + accept).** How
  should the console model the handshake? (a) outgoing root creates a pending transfer,
  incoming root accepts on their next unlock (re-cuts checkpoint); (b) require both
  online at once. Crypto done; UX is your call. The main delegation e2e doesn't need it.
- **Concurrent-add seq race (v1 limitation):** two owners appending at the same `seq`
  → the fold's monotone-seq guard keeps the first, drops the second (loser re-adds).
  Rare + recoverable; documented in `nextDelegationSeq`. Flagging in case you want a
  coordinated-seq scheme later.
