# Agent-authz cleartext id + `aux`→`agent` cutover + T2 close (LOCKED design)

Status: BUILT (2026-08-23, dev branches, UNPUSHED). Extends
`agent-device-identity-mtls.md` §11.1/§14. SSOT for the authorized-agents item
scheme, its server-side ownership gate (T2), and the one-shot forced-upgrade
migration.

Commits (local dev): daemon `8f142af` + pin `f6a07c9`; backend gate `adb579e`;
FE parity `a7de6d0` + lazy migration `d42bda1`. Verified: 46 daemon storage tests,
backend `node --check`, FE `tsc`, cross-lang AAD vector `9s_Kpu…` pinned both sides
(node reproduces the Rust secret vector → algorithm byte-identical). NOT
browser-e2e'd (VM can't run the console).

## ⚠️ DEPLOY ORDER (critical — daemon FIRST)

The new FE WRITES cleartext-native agent items; an OLD daemon decodes the 35-char
ag_id wire as base64url → fails → DROPS the row → the agent silently loses access.
So the daemon must read the new scheme BEFORE the FE writes it. Order:

1. Tag a core rc containing the daemon changes; the client `sc upgrade`s to it
   (NEW daemon reads cleartext-native + legacy → dual-read, still works with the
   old FE).
2. THEN deploy backend (the gate) + FE (native writes) to the same env.
3. Never leave "old daemon + new FE" reachable. For PROD, bump §12.9
   `MIN_DAEMON_VERSION` so old daemons are locked out (403) until upgraded — that
   IS the safe window; reuse it (dev tests it now, prod one-shots later).

## Why

Authorizing an agent on a vault = writing an `aux:agent` item; PRESENCE keyed by
`ag_id` = authorized (daemon fold is the wall). Two problems today:

1. **T2 gap (violates iron rule #1: no client-only enforcement).** The fold honors
   a row where `signer == owner` (self-service), but the daemon can't verify the
   signer actually OWNS that `ag_id`, and the backend is BLIND to which agent a row
   is for (`item_id = HMAC(K-derived, ns‖name)`, body E2E). So "a member may only
   authorize their OWN agents" is unenforced: a member can declare `owner = self`
   for any `ag_id`. The §15 ledger is account-scoped (a folding daemon can't see a
   co-member's ledger), so a ledger check can't close it. The ONLY party that can
   verify agent ownership cross-account is the BACKEND (`api_keys: identity_id →
   account_id`) — but it needs to SEE the `ag_id`.

2. **Two spellings.** The daemon writes legacy `ns=aux, name="agent/<ag_id>"`; it
   also has a native `ItemNs::Agent`; the FE writes the legacy spelling. Daemon
   folds both. Latent tech-debt; a planned "console-coordinated cutover".

`ag_id` is NOT secret (it appears in op_relay / audit / PoP). Blinding it is what
BLOCKS server enforcement. So exposing it is MORE consistent (restores server-side
enforcement of a critical judgment), at the cost of one addressing special-case.

## Target scheme

Authorized-agents items move to the native `agent` ns with a CLEARTEXT id:

- ns = `agent`, name = `<ag_id>`, **`item_id = <ag_id>` verbatim** (the id IS the
  ag_id). `ag_id` = `ag_` + base64url ⇒ already `[A-Za-z0-9_-]+`, passes the
  backend route regex as-is. (No `aux:agents:<id>` form — `:`/`.` are illegal in
  the route.) Secret/connection/etc. items stay HMAC-blinded, unchanged.
- **AAD + record-sig id bytes = `utf8(ag_id)`** on BOTH ends (variable length).
  This is the crux: the id is no longer 32 bytes.
- Sealed body unchanged: `AgentEntry { connections, owner, agent_pubkey }`, still
  self-cert `derive_id(Agent, agent_pubkey) == ag_id`, still UIK-signed (existing).

### AAD-binding: use (Y) fixed-32, NOT (X) variable-length (decided 2026-08-22)

The wire `item_id` (what the backend reads) MUST be the cleartext `ag_id`. But the
seal/record-sig AAD id bytes are a SEPARATE concern, and how we derive them decides
the blast radius:

- **(X) variable-length**: AAD = `utf8(ag_id)`. Conceptually "AAD = decode(wire)",
  but forces `ItemCtx.id: [u8;32]` → variable across the daemon — a sprawling,
  risky refactor touching every ItemCtx construction/use + the 32-byte row-PK
  decode assumptions (`sealed_vault.rs:2081/2477`).
- **(Y′) fixed-32, reuse the EXISTING HMAC (CHOSEN, refined 2026-08-23)**: wire
  `item_id = ag_id` (cleartext, backend-visible, 35 chars), but the seal/sig AAD id
  bytes = the UNCHANGED `item_id_bytes(K, "agent", ag_id)` HMAC (the same 32-byte
  derivation everything else uses — NOT a new hash). So `ItemCtx.id` stays
  `[u8;32]`, `seal_ctx()` unchanged, existing HMAC parity vectors already cover the
  AAD. The ONLY changes: (a) the WIRE id (row PK / URL) for an agent item = `ag_id`
  instead of `item_id_b64` (base64url of the HMAC); (b) on READ, reconstruct the
  AAD for an agent row by RECOMPUTING `item_id_bytes(K,"agent",ag_id)` from the
  `ag_id` in the wire id, instead of `decode(wire_id)`.

  **Recognition is collision-proof by LENGTH, no prefix guessing:** `ag_id` =
  `"ag_" + base32_nopad(sha256(pk)[:20])` = **35 chars, `[a-z2-7]`** (identity.rs
  derive_id). Blinded ids = **43-char base64url**. Disjoint sets. Rule everywhere
  (FE + daemon + backend): `wire_id.length == 35 && startsWith("ag_")` ⇒ agent
  (recompute HMAC AAD; backend reads the ag_id straight off the wire id); else ⇒
  blinded (decode as today). A 43-char blinded id that happens to start `ag_` is
  length 43 ⇒ never misclassified.

  This is strictly less invasive than (X)/(Y): no ItemCtx type change, no new hash,
  no new AAD parity vector (only a trivial "wire id for agent == ag_id" check).

Trade: (Y) decouples AAD-id from wire-id for the agent ns (a contained asymmetry)
in exchange for avoiding a sprawling variable-length refactor across seal/unseal on
both ends. Given this ships unattended-risk to a live dogfood env, (Y)'s smaller
blast radius wins. Record-sig binds the same `H(ag_id)` (FE + daemon identical).
The backend still reads the plaintext `ag_id` straight off the wire id — unchanged.

## Enforcement — two halves (defense in depth), together close T2

- **Daemon fold (id == name):** for an `agent`-ns item, REQUIRE the row PK ==
  `utf8(ag_id)` (the decrypted name). Drop on mismatch. ⇒ an agent-authz body
  cannot be smuggled at a blinded id to dodge the backend gate.
- **Backend gate (ownership), `handleItemPut`:** authoritative recognition is an
  `api_keys` lookup, NOT a prefix guess (a blinded id could start `ag_` by
  chance): `SELECT account_id FROM api_keys WHERE identity_id = <item_id> AND
  tier='agent'`. If a row exists → this write authorizes a real agent ⇒ gate:
  `row.account_id == writer.accountId` (owns it) OR `isSignedKeysetOwner(vid,
  writer)` (vault-owner override) ELSE 403 `agent_write_forbidden`. No api_keys
  row → normal item, no gate. Cheap `ag_`-prefix pre-filter to skip the lookup on
  ordinary writes (optimization only; the lookup is the truth). Fail-open on DB
  read error (billing/authz-gate posture, matches neighbours).

Together: to authorize `ag_Z` you MUST write at `item_id = ag_Z` (fold rule), and
writing there requires OWNING `ag_Z` (backend). T2 closed, server-side, SSOT (the
id is the ag_id), NO vault sig, NO new field.

## Code sites (from the 08-22 three-repo site map)

Daemon (`safeclaw/src`):
- `storage/item.rs:73-84` — `item_id_bytes`/`item_id`: branch the `agent` ns to
  `id = ag_id`, `idBytes = utf8(ag_id)` (skip HMAC). Keep HMAC for other ns.
- `storage/item.rs:174-224` — `ItemCtx.id: [u8;32]` → variable-length (`Vec<u8>`
  / `Box<[u8]>`); `item_id_b64`, `for_item`, `new` follow. `open_item`
  (`sealed_vault.rs:1496-1501`) round-trip follows.
- `storage/sealed_vault.rs:2081-2084` + `2477-2480` — relax the 32-byte row-PK
  decode for agent rows (variable length).
- `storage/sealed_vault.rs` — write path moves to `ns=agent` (`aux_blob_bodies`
  1600-1606, `seed_items_from_view` 1551-1560, `reconcile_from_view` 1654-1655 +
  tombstone 1718-1729). Fold keeps BOTH branches during transition (native 2113,
  legacy 2331). Add the **id==name** check in `fold_agent_record` (718-753).
- `identity.rs:359-379` — `record_signature_input` already `&[u8]` (no type
  change); it now signs `utf8(ag_id)` — daemon+FE must feed identical bytes.
- Parity tests `item.rs:470-475/541-546` — add a pinned cleartext-agent vector.

FE (`safeclaw-pro-frontend`):
- `lib/vault-items.ts:98-107` — `itemId`: agent branch → `id = ag_id`,
  `idBytes = utf8(ag_id)`.
- `lib/vault-items.ts:184` — `unsealItem` AAD reconstruction `b64UrlToBytes(id)`
  → utf8 for agent ids (LOAD-BEARING for the read-back join; wrong ⇒ row silently
  dropped ⇒ agent vanishes).
- `lib/vault-grant.ts:3577` (tombstone) + `:3098` (rekey) — same utf8 special-case.
- `lib/vault-grant.ts:854-856` — `flattenStateToItems` emit `ns=agent,name=<ag>`.
- `assertItemVectors`/`ITEM_ID_VECTOR` (`vault-items.ts:190-237`) +
  `scripts/verify-uik-crypto.mts` — add the pinned agent vector (mirror Rust).

Backend (`safeclaw-pro-backend/src`):
- `vault-routes.mjs:2830` `handleItemPut` — insert the gate near `team.isConfigId`
  (~2847), before `recordWriteGate`. api_keys lookup (owns) + `isSignedKeysetOwner`
  (`vault-routes.mjs:3988`) override.
- Route regex `vault-routes.mjs:5075` `[A-Za-z0-9_-]+` — already allows `ag_id`; no
  change (no `:`).
- ownership query precedent: `vault-routes.mjs:1863` / `vault.mjs:215`.

## Unified forced-upgrade + migration (0.9.x → new, one-shot, works immediately)

Ride ONE shared window (§12.9 `MIN_DAEMON_VERSION` floor). Reuse it for dev NOW and
the eventual prod 0.9.x hop — do NOT open a separate T2 window.

- **Dual-read = "upgrade and it just works":** the new daemon reads BOTH old
  blinded `aux/agent` AND new cleartext `agent` (daemon already dual-folds). So an
  upgraded user immediately sees existing authorizations — no re-authorize needed
  to be usable. Fold dedupes by `ag_id` (both spellings collapse into one
  `aux.agents[ag_id]`), so old+new coexisting is safe.
- **Opportunistic migration:** on unlock, each member's daemon re-seals ITS OWN
  agent items into the new cleartext scheme (+ tombstone the old blinded row). A
  member migrates only agents they own (the backend gate allows exactly that);
  co-members migrate theirs on their own upgrade. Converges as members upgrade.
- **T2 during transition:** NEW cleartext items are backend-gated (T2 enforced);
  OLD blinded items are grandfathered (today's behavior) until migrated. Strict
  improvement; converges to full enforcement once migration completes.
- **Retire legacy fold path:** LATER, after migration has converged (a follow-up),
  not in this change. Never before.
- **Dev now:** the rc carrying this upgrades the dev daemon → migrates the dev
  account's agent items → T2 gate active. Tested end-to-end with the owner's dev
  account (GATES already true on dev).
- **Prod later:** the SAME rc becomes the prod `MIN_DAEMON_VERSION` floor; 0.9.x
  daemons are forced to it once → dual-read → usable immediately → migrate in the
  background. NOTE: prod 0.9.50 → 0.10.x is a much larger release (per-item sync,
  identity wave, …); T2/cutover is designed to RIDE that window, it does not drive
  the whole prod release.

## Non-goals

- Not retiring the legacy `aux/agent` fold path in this change (needs converged
  migration first).
- Not de-blinding any other namespace (secrets stay blinded).
- Not driving the broader prod 0.10 release; only making T2 safe to ride it.

## Verification

- Rust `cargo check` + the new + existing item-id/sig parity tests.
- FE `tsc --noEmit` + `assertItemVectors` + `scripts/verify-uik-crypto.mts`.
- Backend `node --check`.
- Dev e2e (owner's dev account): pair an agent → batch-authorize → confirm new
  cleartext item written + backend 403 for a non-owned ag_id + old items still
  read + migrated on unlock.

## Risks

- Variable-length AAD/sig must be byte-identical FE↔daemon or agent rows silently
  drop (agent vanishes). Parity vectors guard this; add one before touching seal.
- A wrong fold `id==name` check drops legitimate agents. Test old+new coexist.
- Migration writes must pass the backend gate (owner writes own agents) — verify
  the daemon re-seal path authenticates as the owner account.
