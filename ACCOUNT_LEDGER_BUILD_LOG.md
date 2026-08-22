# Account principal ledger + universal revocation-drop — BUILD LOG

Execution log for design **§15** (SSOT: `design/agent-device-identity-mtls.md` §15).
Branch: `feat/account-principal-ledger` (core). Backend/frontend branches added per phase.

## Goal (one line)
Owner-signed ADMIT + REVOKE of account principals (device/agent), enforced locally
while online: a revoked device/agent loses the ability to use secrets. Universal
(personal + team), not a team privilege.

## Invariants (non-negotiable)
- **Additive / dual-path / flag-gated.** Current §14 session-admission + the shipping
  launch flow never brick during the build. Enforcement flips are last + gated.
- **Destructive only on VERIFIED owner signature.** "Lock + wipe local" fires ONLY on a
  daemon-verified owner-signed removal, NEVER on a bare 401 (that class caused the
  transient-403 mass-outage incident; 401 keeps PARKING).
- **Delivery-before-hard-kill.** Publish the signed `revoke` (target still syncs it) →
  target verifies + self-drops → THEN hard-kill its device-key.
- Build on the feature branch; merge additive phases to `dev` + release rc only when green.

## Two layers (both owner-signed)
| Layer | Channel | Signer/anchor | Revoke → daemon |
|---|---|---|---|
| Account admission (device/agent) | NEW account principal ledger | owner **UIK**; anchor = the account's own UIK (self-certified: `derive_id(User,uik_pub)==account_id`) | device `−` → LOCK+WIPE all vaults + logout; agent `−` → global reject |
| Per-vault access | authorized-agents / passkey-membership (existing) | **K** per-vault | remove → drop that ONE vault |

## Phases
- **P1 core crypto foundation** — DONE (this branch). `identity.rs`: `DS_PRINCIPAL_EVENT`
  = `safeclaw/v1/principal-event`; `principal_event_input(account_id, op, principal_id,
  seq, owner_id)` (account-scoped analog of `delegation_event_input`); field-binding +
  lp-ambiguity + roundtrip + pinned golden-vector tests. 33 identity tests green.
  Anchor needs NO new primitive: `account_id == derive_id(User, owner_uik_pub)` already
  self-certifies the owner UIK (same trick as per-vault genesis anchor).
- **P2 backend** — DONE (backend `dev` commit `778bb63`; migration LIVE on dev DB
  `nyykwxuakkjydmjroyzb` + verified). Table `account_principal_events` (append-only,
  monotone `seq`, PK `(account_id,seq)` replay guard, RLS service-role-only) + rollback.
  `keyset-roles.mjs`: `principalEventInput()` Node mirror + boot golden-vector self-check
  (parity MATCH vs Rust pinned hex). `vault-routes.mjs`: `GET /api/vault/principals`
  (daemon/console pull; session OR device-key; serves raw signed events + account anchor
  pubkey) + `POST` (append; SESSION + verified owner-UIK signature, monotone-seq guard,
  self-cert anchor check). Additive/dormant: §14 roster stays authoritative; missing
  migration degrades to empty, never 500. LEFT: push backend `dev` to remote + Railway
  `dev-backend` redeploy (batched; endpoints dormant so no rush — needed before P4 e2e).
- **P3 frontend** — DONE (frontend `dev` commit `622670b`; tsc clean; parity 60/60).
  `uik-crypto.ts`: `principalEventInput` + `DS_PRINCIPAL_EVENT` (three-way Rust↔Node↔TS
  parity, pinned vector in `verify-uik-crypto.mts`). `vault-grant.ts`: `recoverOwnerUik`
  (account-scoped passkey tap → unwrap owner UIK, no vault, never mints) +
  `signAndPostPrincipalEvent` (seq=cursor+1, retry once on 409). `vault-api.ts`:
  get/post principal-ledger. `/pair` approve signs `admit` (one owner tap);
  access-client revoke signs `revoke` BEFORE the DELETE (delivery-before-hard-kill).
  Additive/dormant/best-effort: session approve + DELETE stay enforced; a cancelled tap
  never blocks them. P6 flips enforcement + makes the tap mandatory.
- **P4 core/daemon** — DONE (this branch; `cargo build` clean, 5 new tests green).
  New `src/principal_ledger.rs`: `fetch_ledger` (GET /api/vault/principals, device-key +
  DIK PoP), `fold_verified` (self-cert anchor check `derive_id(User, uik_pub)==account_id`;
  per-event owner-sig verify; skip-invalid; monotone-seq), and `principal_ledger_loop`
  (poll 120s → verify → flag-gated enforce). Verified self-revoke → `self_wipe_and_logout`:
  `drop_local_vault_locked` every vault (evict K + wipe blob, in-process) → delete
  device-key → `clear_pairing` → `process::exit`. Rollback-resistant: a verified
  self-revoke LATCHES to `principal_floor.json`; a pull whose max seq regresses is ignored
  (server can't un-revoke). Anchor bootstrap RESOLVED: `account_id` persisted at pairing
  (`put_cloud_coords` + login, both paths) IS the anchor (self-certifying). Flag
  `SAFECLAW_PRINCIPAL_ENFORCE` / `CliConfig.principal_enforce`, DEFAULT OFF. Agent revoke
  rides the existing /agents/hashes sync (backend drops the key). `sc logout` also clears
  `account_id`. Invariant held: destructive only on a VERIFIED sig, never a bare 401
  (a fetch failure parks).
- **P5 per-vault drop hardening** — MAPPED, NOT BUILT (a mini-wave; two legs, see below).
  Split into leg A (unambiguous, buildable) and leg B (blocked on a design question).
  - **Leg A — sign the vault-delete TOMBSTONE.** Today it is UNSIGNED server cleartext: a
    top-level `status:"deleted"` field the daemon acts on in 4 sites BEFORE any signature
    path (core `sync.rs`: `classify_pull_body:752`, `handle_blob_wake_body:2069`,
    `watch_loop` SSE arm `:1615`, + `pull_on_start`/`sync_vault_now`/`recover_after_conflict`).
    Backend sets it as a plain DB column (`vault-routes.mjs handleDeleteVault:1435-1439`) and
    serves it with NO env/sig (`:2200`). The server envelope (`DS_SERVER_ENVELOPE`) is
    SERVER-signed and does NOT cover `status` — so a NEW owner-signed field is needed
    (`DS_VAULT_TOMBSTONE`), verified against the vault genesis anchor via the SAME
    `resolve_current_root` / `fold_owner_set` machinery (`sealed_vault.rs:1774`). Full build:
    new primitive in identity.rs + Node mirror (keyset-roles.mjs) + FE mirror (uik-crypto.ts)
    + 3 golden vectors; FE delete ceremony signs it (owner passkey tap); backend stores+serves
    it; core verifies-before-destroy, DUAL-PATH (accept unsigned OR verified-signed; only
    REQUIRE signed behind a flag, so existing deletes never brick). Large but unambiguous.
  - **Leg B — membership-loss active-wipe — DONE (branch `573931a`; green).** Design fork
    RESOLVED by the user: the daemon's per-vault member identity = the account owner-UIK
    `us_` pinned at pairing (Fix-0). `PerItemVault::verified_membership(vault, us) ->
    Option<bool>` (`Some(false)` = a `Verified`, non-empty owner-fold that EXCLUDES us;
    `None` = NoUik/Untrusted/bootstrap → park). `sync.rs enforce_membership_presence` →
    `drop_local_vault_locked` + stop watcher, wired after the sse-wake + reconcile pulls.
    Flag-gated (default OFF). A rolled-back/dropped-grant triple → `Untrusted` → never a
    false wipe; a wrong wipe is recoverable (discovery won't re-add a non-member vault).
  - **Fix-0 — CRITICAL P4 anchor bug fixed (backend `27bd766` dev; core `422bbf5`).** P4
    pinned the Supabase account UUID and passed it to `fold_verified`, whose self-cert
    `derive_id(User,uik_pub)==anchor` never matches a UUID → P4 verified nothing in prod
    (parked, never enforced). Now: pairing delivers `account_uik_id` (`accountOwnerUik`);
    daemon pins `CliConfig.account_uik`; the ledger loop + leg B both anchor on that `us_`.
  - **(original leg-B blocker, now resolved) design question was:**
    Today a removed team member's daemon only "stops serving" weakly: `adopt_membership_triple`
    (`sync.rs:2844`) adopts only PRESENT members, never prunes an absent self, never wipes;
    stale K stays retained while unlocked + `vault.dat` stays on disk. The VERIFIED signal
    exists — `fold_owner_set` returns the full owner-verified member map and is `Untrusted`
    (fail-closed) on a rolled-back log — BUT: a shared vault's membership is keyed by the
    USER's UIK (`us_…`), while the daemon holds a DEVICE identity (`dev_…`). "Which `us_` is
    this daemon a member AS?" is not cleanly answered at the daemon layer (the daemon serves
    K to the local user/agent; the us_ is established client-side at unlock). Wiping on a
    wrong answer = destroying a LEGIT member's vault (data loss). RESOLVE WITH THE USER before
    building: does the daemon persist the `us_` it unlocked as, per vault? Only then can
    "self ∉ verified member set → wipe" fire safely. Personal (fmt1/NoUik) vaults have no
    triple, so their "access gone" rides leg A's tombstone, not membership.
- **P6 cutover** — flip enforcement (require signed admission; wipe-on-revoke on) + retire
  session-admission + adversarial review + e2e. Gated/census'd.

## Already shipped (rc.9, the small clear pieces, on dev)
`sc logout` stops the daemon on macOS too + wipes local `<state_dir>/vaults/` (commit 6efb795).

## Status (2026-08-22)
P1-P4 DONE + green + committed across all 3 repos: the CORE §15 invariant (owner-signed
admit/revoke ledger end-to-end; verified device self-revoke → lock+wipe+logout,
rollback-resistant, flag-gated default OFF). This fully covers the originating request
("owner revokes device → device can't use secrets, online case"). Commits: core P1 `1970d03`
+ P4 `a5704b3` (branch `feat/account-principal-ledger`); backend P2 `778bb63` (dev, migration
LIVE on dev DB); frontend P3 `622670b` (dev).
Also DONE since: **Fix-0** (P4 anchor bug → P4 now actually verifies in prod) + **P5 leg B**
(membership-loss active-wipe). Commits: backend `27bd766`; core `422bbf5` (Fix-0), `573931a`
(leg B).
LEFT:
- **P5 leg A** (sign delete tombstone) — DONE. `DS_VAULT_TOMBSTONE` + `vault_tombstone_input`
  ×3 langs (three-way parity, pinned vectors); FE delete ceremony signs it (PRF tap →
  owner UIK); backend stores (handleBlobDelete) + serves it (migration LIVE on dev); core
  `PerItemVault::tombstone_verified` + `tombstone_should_drop` gate at all 3 trust sites,
  dual-path (flag OFF = unchanged legacy drop; flag ON = drop only on a verified owner
  tombstone). Flag `SAFECLAW_REQUIRE_SIGNED_TOMBSTONE`, default OFF. Commits: core
  `6e94c03`, backend `978e348`, frontend `bc483af`. All green.
- **P6 cutover** — flip `SAFECLAW_PRINCIPAL_ENFORCE` on + mandatory /pair tap + retire §14
  session-admission + adversarial review. The FLIP is a launch decision (user-gated); the
  adversarial review + making the tap mandatory are buildable.
- Ship: push backend `dev` + Railway `dev-backend` redeploy (P2/P3 endpoints dormant so no
  rush); merge core branch `feat/account-principal-ledger` → core `dev` + cut an rc when P5/P6
  land. All current work is isolated on the branch / additive-dormant, so the user's fresh
  e2e on rc.9 is unaffected.

## P1-P5 ALL BUILT + green (2026-08-22). Resume pointer → P6 cutover (LAUNCH-GATED).
The whole §15 line is built additive/flag-gated across 3 repos; nothing enforces until the
flags flip. P6 = the deliberate cutover, sequenced:
1. **Ship what's built to dev + real e2e (do first):** push backend `dev` remote + Railway
   `dev-backend` redeploy; merge core `feat/account-principal-ledger` → core `dev` + cut an rc;
   push frontend `dev`. Then a fresh-account e2e with the flags STILL OFF (proves zero
   regression: admit/revoke ledger populates, deletes still work, nothing wipes).
2. **Adversarial review** (P6 deliverable, run 2026-08-22) — DONE. Found 1 HIGH + 2 LOW, ALL
   FIXED (commit `50425fa`); the crypto foundation, cross-lang parity, backend write-gate,
   tombstone verify, and flag-OFF non-regression were confirmed solid.
   - **F1 (HIGH, fixed):** the self-revoke latch was not monotone — a compromised server could
     un-revoke a device by omitting the revoke event while serving any newer event. Now
     monotone (`apply_fold_to_floor`, unit-tested with the exact attack); enforcement reads the
     LATCH every iteration, not the current pull.
   - **F2 (LOW, fixed):** self-wipe now evicts K from all vaults up-front (closes the serve window).
   - **F3 (LOW, fixed):** require-signed no longer strands legacy fmt1/NoUik deletes (legacy-drop
     fallback; only fmt2 requires a verified tombstone).
   - **KNOWN RESIDUAL F1c (documented, post-flip hardening):** a revoke the daemon has NEVER
     observed (server withholds on every poll) can't latch — needs an owner-signed ledger head
     (max-seq/count). Out of scope for the flag flip; do BEFORE relying on revoke against a
     fully-adversarial backend.
3. **Flip enforcement (USER decision — destructive for real users):** set
   `SAFECLAW_PRINCIPAL_ENFORCE=on` + `SAFECLAW_REQUIRE_SIGNED_TOMBSTONE=on` (env or
   `CliConfig.principal_enforce`/`require_signed_tombstone`) on daemons, staged/census'd. Only
   after e2e proves: verified device-revoke → wipe+logout; offboard → per-vault wipe; a forged
   delete → parked.
4. **Make the /pair admit tap mandatory + retire §14 session-only admission** (couple with the
   flip — the ledger becomes the authority). Small FE change (drop the best-effort try/catch
   around the admit sign) + backend: require a ledger `admit` alongside `/api/pair/approve`.
5. **Deferred non-goals (unchanged):** deliberately-offline device; token-path (`sc login
   --pair-token`) still vault-binds (new users don't hit it).

## (superseded) earlier resume pointer
Next: **P5 per-vault drop hardening** (SSOT §15 "per-vault drop", agent-device-identity-mtls.md:725-736).
Three gaps to close: (a) the vault-DELETE tombstone is currently UNSIGNED server cleartext —
`sync.rs` acts on `status:"deleted"` before any signed-envelope check; sign it (vault-owner K
or owner UIK) so a malicious server can't forge a delete; (b) upgrade daemon membership-loss
from "stop serving" to "actively LOCK + WIPE" the dropped vault (reuse `drop_local_vault_locked`);
(c) extend both to PERSONAL vaults (today's tombstone drop is the personal path; the signing +
active-wipe is the new part). Semantics: delete-vault = account-wide tombstone; offboard-member =
single-member removal; ONE daemon reaction = verify a vault-owner-signed "vault Y access gone" →
LOCK+WIPE vault Y locally. Keep the P4 invariant: destructive only on a VERIFIED signature.
Then **P6 cutover**: flip `SAFECLAW_PRINCIPAL_ENFORCE` default on + make the /pair admit tap
mandatory + retire §14 session-only admission + adversarial review + e2e.

--- (P4 done; historical note below) ---
P4 was: **core/daemon** (Rust, on this branch; the DESTRUCTIVE phase — flag-gated).
Add: (a) a daemon pull of `GET /api/vault/principals` (DIK PoP, like the VA2 vault
discovery loop in `sync.rs`); (b) verify each event's owner-UIK sig via
`identity::principal_event_input` against the account anchor learned at pairing
(`derive_id(User, owner_uik_pub) == account_id`), fold by monotone `seq` (reject a
ledger that drops a higher-seq revoke); (c) enforcement behind a flag: on a VERIFIED
`revoke` of THIS device's own `dev_…` → LOCK + WIPE all local vaults + logout (reuse
the `sc logout` wipe path). Agent `revoke` → drop from the local authorizing set.
INVARIANTS: destructive only on a daemon-VERIFIED owner signature, NEVER a bare 401
(401 keeps PARKING — the transient-403 incident). Delivery-before-hard-kill already
set up FE-side (revoke event posted before the key DELETE). Where the daemon learns
the account anchor UIK pubkey at pairing is the one open bootstrap question to resolve
against current pairing code. Keep additive: nothing enforces until the flag flips (P6).
