# Unified membership — end-to-end `verify(anchor, members, proof)`

**Status: DESIGN LOCKED (2026-08-05, user-approved). SSOT for the implementation.**
Code comes AFTER this doc + a compact (§9 is the TODO). This doc is the ONLY current
design. Two earlier variants that lived in this file are **DEAD — do not resurrect**:
- the **4-table "normalized" schema** (vault_access / vault_delegation_events /
  vault_succession / uik_identities) — over-fragmented; replaced by the single
  `vault_membership` triple below.
- the **"wire-compat" row-translation strategy** (backend `demux` row→tables and
  `synthesize` tables→row so the daemon kept reading cid-keyed rows) — an unneeded
  translation layer. We go **end-to-end**: no row format anywhere.

--------------------------------------------------------------------------------
## 0. The model

Membership of a vault is ONE authorization triple:

```
verify(anchor, members, proof) = true
```

- **`anchor`** — the genesis root: the creator's UIK **signing pubkey**. Set once at
  vault birth, immutable. The whole fold roots here (it is a KEY, not a person — the
  creator can be removed and the anchor stays).
- **`members`** — the current membership, an object keyed by identity id:
  `{ "us_…": { role, k_encapped, k_ct, role_sig }, … }`. Each entry = a member's role
  + their K delivery (K sealed to their UIK enc-pub) + the root-signed checkpoint grant.
- **`proof`** — what authorizes `members`:
  `{ delegation_log[], succession[], generation, rekey_proof }`.

**`verify`** = the fold: walk `succession` from `anchor` → current root + `role_epoch`;
verify each `members[id].role_sig` under the current root; apply `delegation_log`
(any-owner events, issuance-time authority, NON-CASCADE, last-owner guard) → the
authorized owner-set; `generation` + `rekey_proof` are the K-rotation anti-rollback.

**END-TO-END.** Frontend, backend, daemon, and DB ALL speak this triple. There is **NO
row format and NO translation layer**.

--------------------------------------------------------------------------------
## 1. Threat-model conclusions (locked, 2026-08-05)

1. **The daemon's local TOFU pin of `anchor` is THE boundary vs a malicious server.**
   The daemon never trusts server-side role fields; it re-verifies `members`/`proof`
   against the anchor pinned locally on first unlock. A server that rewrites the DB
   (even a "set-once" column whose trigger it drops) is defeated by a pinned daemon.
   No server/DB constraint defends against a malicious server — only the off-server pin.
2. **The signature chain (`proof`) buys MULTI-ADMIN, not stronger server-resistance.**
   Any non-creator owner can provably manage membership. And creator-removal REQUIRES
   multi-admin, so the chain is not optional.
3. **The append-only signed head is the substrate for a future public-log root**
   (publish the head commitment + anchor to a CT-style log → closes fresh-device
   first-touch + non-equivocation). Future; not now.
4. **The proof IS the chain, packaged** — one self-contained object verified against
   the pinned anchor.

--------------------------------------------------------------------------------
## 2. Schema — 3 tables

```
vault_membership            -- one row per vault; the verify(anchor, members, proof) triple.
                            -- INDEPENDENT table (NOT merged into `vaults`): it is the crypto-
                            -- authorization layer, distinct from the product metadata in
                            -- `vaults`; and members/proof churn on every membership op, so they
                            -- stay off the hot `vaults` row.
  vault_id    PK
  anchor      text          -- root = creator's UIK sig pubkey (b64 raw-32), SET-ONCE
  members     jsonb         -- { "us_…": { role, k_encapped, k_ct, role_sig }, … }
  proof       jsonb         -- { delegation_log[], succession[], generation, rekey_proof }
  keyset_seq  bigint        -- monotone; drives the GET /membership since-delta
  updated_at  timestamptz

identities                  -- one per PRINCIPAL (user = UIK, agent = AIK)
  id          PK            -- us_… / ag_… = derive_id(sig_pub); self-certifying
  account_id  text          -- owning account
  kind        text          -- 'user' | 'agent'
  sig_pub     text          -- Ed25519 signing pubkey (b64 raw-32)
  enc_pub     text          -- X25519 encryption pubkey (b64 raw-32; users)

credentials                 -- one per DEVICE credential (was `passkeys`; `type` generalizes)
  cid         PK            -- credential id (globally unique)
  account_id  text          -- owning account
  type        text          -- 'passkey' (only type today); future: 'recovery_code', …
  identity_id text          -- which identity this credential unlocks
  wrapped_uik text          -- the UIK root WRAPPED under this credential's custody (W_c)
  wrap_salt   text          -- per-credential KDF salt for W_c (device scope, NOT per-vault)
  wc_check    text          -- optional W_c key-check value (cross-device)
  x, y, device_name, …      -- existing WebAuthn fields

vaults  (UNCHANGED product table)  -- keeps: format (1 = legacy v1; 2 = triple), kind,
  user_id (= created_by label, NOT an authority for shared vaults), label, status,
  version, membership_epoch. NO crypto columns (anchor/members/proof live in vault_membership).
```

Naming convention for key material (§5): **encrypt** (data under a key) / **wrap** (a key
under a symmetric key: UIK under custody) / **seal** (a key to a pubkey: K to a member's
UIK, HPKE — `k_encapped` + `k_ct`).

--------------------------------------------------------------------------------
## 3. Wire — `GET`/`PUT /membership` (end-to-end, no row)

```
GET /v/{vid}/membership?since=<seq>          (daemon + console read)
  → { keyset_seq }                            if keyset_seq <= since (nothing new)
  → { anchor, members, proof, keyset_seq,
      identities: { "us_…": { sig_pub, enc_pub }, … },   -- pubkeys for the members
      credential: { cid, wrapped_uik, wrap_salt, wc_check } }   -- the CALLER's OWN credential
  Daemon: own credential.wrapped_uik (custody→UIK) → open members[self].k_ct → K;
          verify(anchor, members, proof) → owner-set.

PUT /v/{vid}/membership   body { base_seq, anchor?, members, proof,
                                 identity?: { sig_pub, enc_pub },
                                 credential?: { wrapped_uik, wrap_salt, wc_check } }
  CAS on keyset_seq (base_seq must equal current, else 409 → caller re-reads + retries).
  Authorize: verify(anchor, members, proof) must hold AND the writer is either an OWNER
  (owner op) OR only touching their OWN members[self] entry (self-service K re-seal).
  `anchor` is SET-ONCE. Registers the writer's `identity` + `credential` if carried.
  On success bump keyset_seq.
```

The CAS (`base_seq`) is the concurrency guard (same shape as the item CAS): an owner
reads the triple, computes the new (members, proof) for their op, writes with the base;
a concurrent write makes one side 409 + retry. Keyset ops are low-frequency.

--------------------------------------------------------------------------------
## 4. What each layer does

- **Frontend (console):** every owner op (create / invite-approve / promote / demote /
  offboard / re-key) computes the new `(members, proof)` and `PUT`s the triple (CAS).
  Reads the triple from `GET` and folds it for display/authority.
- **Backend:** stores the triple verbatim; the WRITE gate authorizes via the fold
  (`keyset-roles.mjs` reads `vault_membership` — already done); serves the triple on GET;
  registers identities + credentials. NO row, NO demux/synthesize.
- **Daemon (Rust):** sync `GET`s the triple → builds its in-memory keyset from
  `(anchor, members, own credential)` and folds `(anchor, members, proof)`. The in-memory
  model shifts from **cid-keyed rows → id-keyed `members`** + the daemon's own credential
  for unlock. **Crypto fold + golden vectors UNCHANGED** — only the data plumbing changes.

--------------------------------------------------------------------------------
## 5. Naming convention (apply to all key-material fields)

`encrypt`/`ciphertext` = bulk data under a key (items under K). `wrap` = a key under a
symmetric key (UIK under custody W_c → `wrapped_uik`). `seal` = a key to a pubkey (K to a
member's UIK, HPKE → `k_encapped` + `k_ct`). Rule the name must convey: `seal` = "doable
with only a public key" (add a member offline); `wrap` = "needs the symmetric key".

--------------------------------------------------------------------------------
## 6. Option B (creator = normal member)

The creator is just an entry in `members` (role owner) — no `vaults.user_id`
special-casing for the crypto. `isOwnedVaultId` (backend data-access gate) resolves
**shared-vault** access from membership/fold, NOT `vaults.user_id`; **personal** vaults
keep the `vaults.user_id` fast path (creator = permanent sole owner). **DELETE the
reassign hack** (it was a lower-risk substitute I wrongly kept). Creator-removal = drop
their `members` entry + an owner-signed `remove` delegation event + re-key; last-owner
guard applies.

--------------------------------------------------------------------------------
## 7. Per-person UIK (get-or-create)

One UIK per person, stable `us_…` across vaults. On create: RECOVER the person's existing
UIK (unwrap `wrapped_uik` from an existing credential via their passkey) or MINT if first
vault. Add-device: seal the SAME UIK to the new credential during enrollment (honor
`cross-device-enroll-integrity.md`). Personal vaults are created as format=2 (owner-set
of one). Today the ceremony mints a fresh UIK per vault — this replaces that.

--------------------------------------------------------------------------------
## 8. Migration / census (no flag-day)

New vaults are born `format=2` (triple). Legacy `format=1` v1 vaults (personal, uik=None →
NoUik) keep working via the legacy path and migrate LAZILY: a per-user version census
flips a user's vaults to the triple only when ALL their devices are ≥ the release that
understands it (no cross-device lockout, no deadline; client-side re-wrap on next unlock).
DELETE the NoUik path + any legacy row/table + the `passkeys` compat view once the census
shows zero `format=1` left. Team vaults are all format=2, so the team e2e needs no census
(it creates fresh format=2 vaults). PROD personal migration is gated behind the deploy +
daemon rollout (user-controlled) — highest-stakes, client-side, K never leaves the device.

--------------------------------------------------------------------------------
## 8b. Implementation decisions (locked during build, 2026-08-05/06)

These fill gaps the design left open or correct one infeasibility — recorded so they are not
silently lost:
1. **Option B mechanism = creator gets a `memberships` owner row** at shared-vault create
   (revocable; offboard deletes it). `vaults.user_id` is now a pure created_by LABEL, not an
   authority. `vaultRoleFor`/`listMembers` scope the `user_id`→owner shortcut to PERSONAL
   vaults; the reassign hack is deleted; `isOwnedVaultId` shared access = memberships row OR
   crypto fold (`ownerViaFold`).
2. **Bootstrap ≠ create.** `handleCreateVault` cannot write the initial triple — the anchor is
   the creator's client-side UIK sig pub, unknown to the backend at create. The initial triple
   is written by the ceremony's FIRST `PUT /membership` (base_seq 0). (Supersedes the literal
   "create writes initial vault_membership" wording below.)
3. **Wire tweaks:** `PUT /membership`'s `credential` body carries `cid`; `GET` returns a
   `credentials[]` array (superset of the singular `credential`) so a multi-device daemon keys
   each of its cids.
4. **Identity account binding is SET-ONCE** (`registerIdentity`). `deriveUserId(sig_pub)` is
   public, so a plain `upsert(onConflict:id)` let any caller rebind a victim's `us_…` to their
   account by replaying the victim's public sig_pub — forging owner authority (`writerIds`) AND
   shared-vault data access (`ownerViaFold`). Fixed: bind only when new / already-ours / unclaimed;
   `writerIds` come from the DB, never a us_id the caller couldn't bind. (Found in self-review.)

--------------------------------------------------------------------------------
## 8c. Invite/join flow + seat semantics (2026-08-06, user-approved; RESOLVED)

Two 2026-08-06 records disagreed (this SSOT draft vs a forwarded decision summary). The
user resolved in favor of the hybrid below (2026-08-06). Superseded alternatives are kept
inline and marked ⛔ so the trail can't be re-litigated.

1. **Invite to a REGISTERED account = membership born at invite time.** The owner's
   client looks up the invitee's UIK `enc_pub` (email→UIK directory, §1.3) and seals K
   into `members` in the SAME `PUT /membership` as the invite op (§5: seal is
   public-key-only — no invitee action needed). "Accept" is roster/UX acknowledgment
   ONLY — no crypto, no owner re-confirm. The two-step "invite → approve" ceremony
   collapses to one step. **The current deposit+approve code (/join deposit → owner
   approve) is REPLACED by this on the registered path.**
2. **Invite to an UNREGISTERED email = REJECTED with an actionable error** + an optional
   "send a signup link" action (that link is NOT an invite). They register — registration
   MUST mint UIK + first credential (**credential-at-birth invariant**: no account with a
   UIK but zero credentials) — then the owner invites them normally (now registered →
   path 1). ⛔ SUPERSEDED: the earlier "unregistered = applicant + an owner device
   auto-completes the seal on next unlock" — dropped as unnecessary machinery (no
   applicant state, no auto-seal queue).
3. **`members` ⟺ K-holders ⟺ billable seats — ONE roster.** An entry in `members` means
   the person holds K, counts as a seat **from the invite moment**, and shrinking =
   offboard (+ re-key). Withdrawing an invited member = offboard + re-key (they already
   hold K). Credentials never affect seats (add-passkey/device is self-service). ⛔
   SUPERSEDED: "seat counts only after accept; withdraw needs no re-key" — it split the
   roster into K-holders ⊋ seats and left a K-retention gap (a sealed-but-withdrawn
   invitee keeps K without a re-key).
4. **First-touch directory trust** (email→UIK lookup served by the backend) stays the
   accepted §1.3 boundary; no extra flow in v1.
5. **Trial billing = Creem-native (card at first invite), NOT app-managed** (2026-08-06):
   the first invite opens a Creem checkout (card + 30-day trial, `units = seats`); Creem
   owns trial → auto-charge → dunning. We build only the freeze GATE that reads Creem's
   status. ⛔ SUPERSEDED: the app-managed "no card until trial end" trial — dropped (it
   duplicated Creem's lifecycle for a solo dev to maintain, and card-on-file converts far
   better; the only friction is the owner entering a card once at first invite).
6. **Billing account = an EXPLICIT, first-class record, DECOUPLED from ownership**
   (2026-08-06). Store `vaults.billing_account_id` (its OWN column — NOT derived from
   `vaults.user_id` or owner status); initially = creator. Because a creator can be
   offboarded (Option B), billing is decoupled by design: a removed creator STOPS being a
   member/seat but REMAINS the billing account — a pay-only account (sees billing / seats /
   card, never vault plaintext) until an explicit transfer. `subscriptions.account_id` =
   the billing account (one Creem customer per). **Seat formula follows precisely:
   billable = members EXCLUDING the billing account.** Billing account is in `members` ⇒
   their own seat is free (`members − 1`); billing account not in `members` (removed
   creator) ⇒ no free seat, all `members` billable — numerically identical to
   "(members − 1) × $18" in the normal case, just exact at the edge. **Display:** every
   owner sees who the billing account is + seat count + next charge; only the billing
   account sees/manages the card. **v1: no transfer** (the field is set at team start and
   stays); **v2: transfer = update `billing_account_id` + move seats to the new account's
   sub** — a seamless additive upgrade. If the billing account stops paying and won't
   transfer, the team freezes (v1 limitation; v2 transfer resolves it).

--------------------------------------------------------------------------------
## 9. STATUS — implementation (ET1-ET4 DONE + verified; 2026-08-06)

- **ET1 dev reconcile** ✓ — `cur→members`, `credentials.uik_wrapped→wrapped_uik`, dead
  `vaults` cols + `bump_keyset_seq` dropped. (DB-introspected.)
- **ET2 backend** ✓ — `GET/PUT /membership`, `/keys`+`/keys/{cid}` 409 for fmt≥2,
  demux/synthesize/anchor-pin removed, Option B, `registerIdentity` set-once, deposit registers
  joiner identity/credential, `handleUikMaterial`. (node --check + import golden self-checks.)
- **ET3 daemon** ✓ — `pull_keys` 409→`pull_membership`; `adopt_membership_triple` reuses the
  exact adopt helpers; fold/unlock/golden vectors untouched. cargo build + **373 tests** incl.
  `membership_triple_adopts_same_owner_set_as_keys_wire` (triple↔row parity).
- **ET4 frontend** ✓ — client `get/putMembership` + `rowsFromMembership`/`membershipFromRows`
  converters + `getKeys` 409→/membership read-shim; ceremonies (setup/approve/rekey/delegation)
  write the triple via `commitMembership`; **per-person UIK get-or-create** (`getOrCreatePersonUik`
  in setup + join); dead `wrappingKey` removed. tsc clean + **verify-uik-crypto 58/58**.

**Deferred (flagged, per the user's "先B" sequencing):**
- **ET5 census + NoUik/legacy deletion** = the PRE-PROD breaking batch. Team vaults are all
  fmt=2 so e2e does not need it; existing personal fmt=1 vaults keep the legacy `/keys` path
  until the census migrates them (client-side re-wrap on unlock, version-gated). Do NOT delete
  the NoUik runtime path before the census shows zero fmt=1.

**Legacy TODO wording (kept for reference; superseded where §8b notes):**

**Migrations / dev reconcile**
- [ ] One clean migration = the final schema (`2026-08-05-membership.sql`; the churn
      files 01–04 are deleted). Uses `if not exists`.
- [ ] Reconcile dev (it carries the churn): rename `vault_membership.cur` → `members`;
      DROP the dead `vaults` columns `genesis_anchor_pub` / `generation` / `rekey_proof`
      / `keyset_seq`; drop the unused `bump_keyset_seq` RPC (keep `bump_vault_membership_seq`).

**Backend**
- [ ] Route + handler `GET /v/{vid}/membership` (serve triple + identities + caller
      credential; since-delta on `keyset_seq`).
- [ ] Route + handler `PUT /v/{vid}/membership` (CAS on `base_seq`; authorize via the
      fold + owner/self rule; set-once anchor; register identity+credential; bump seq).
- [ ] `keyset-roles.mjs`: fold-mirror already reads `vault_membership`; rename `cur`→`members`.
- [ ] **RIP OUT**: `demuxKeysetRowToNormalized`, `synthesizeKeysFromNormalized`, the
      `format>=2` branches in `handleKeysGet`/`handleKeyPut`, and the `vault_keys` write
      for format=2 (Option-B item ②). `putKey`/`getKeys` stay ONLY for legacy format=1.
- [ ] Option B: `isOwnedVaultId` shared→membership; **delete the reassign hack** in
      `handleMemberRemove`; `handleCreateVault` writes the creator's initial
      `vault_membership` (anchor + `members[creator]`) at `format=2`.
- [ ] `offboardMember`: drop `members[id]` + bump seq (adapt the current partial version).

**Daemon (Rust)**
- [ ] Sync: replace the `/keys` pull with the `/membership` pull; build the keyset from
      the triple; drop `adopt_key_rows`/row parsing for format=2.
- [ ] In-memory model: id-keyed `members` (+ own credential for unlock) instead of
      cid-keyed `creds`. Fold input iterates `members`. **Crypto + golden vectors unchanged.**
- [ ] Unlock: own `credential.wrapped_uik` (custody→UIK) → `members[self].k_ct` → K.

**Frontend (console)**
- [ ] Ceremony (`vault-grant.ts`): write the triple via `PUT /membership` (compute
      members+proof + CAS) instead of `putKey` rows; fold from `GET /membership`.
- [ ] Per-person UIK get-or-create + add-device seal (§7).
- [ ] `encrypt`/`wrap`/`seal` naming.

**Finish**
- [ ] Census migration (§8) + delete NoUik/legacy at census→0.
- [ ] Unified adversarial re-audit of the fold; full green gates (core / backend / frontend).

--------------------------------------------------------------------------------
## 10. Non-goals
- Anchor-KEY rotation on creator-key compromise (org-recovery; separate).
- On-chain / SAS public-log root for first-touch (future; the head commitment is ready).
- Any change to sudp.

--------------------------------------------------------------------------------
## 11. Identity invariants — UIK/passkey co-birth + the two authority planes (2026-08-18, user-flagged)

### 11.1 A UIK and its first passkey are born together; zero passkeys is unreachable
- The PRIVATE UIK exists in storage ONLY as `credentials.wrapped_uik` = `Wrap_{W_c}(UIK)`.
  `identities` holds only the PUBLIC keys (`us_…` / `sig_pub` / `enc_pub`). There is no
  standalone / un-wrapped UIK anywhere.
- Mint is client-side, in the SAME gesture as the first passkey: `UikRoot.generate()` makes the
  UIK and the new passkey's PRF-derived `W_c` wraps it; both commit together (`registerIdentity`
  + the credential's `wrapped_uik`, `vault-routes.mjs` ~3987). There is no "mint UIK first, then
  decide whether to enroll a passkey" step.
- Locked consequences:
  - Signup mints NOTHING. A just-registered account has no UIK and no passkey; the UIK is
    minted lazily at the first vault ceremony.
  - "UIK present but zero passkeys" is NOT a representable state: losing every passkey loses the
    only wrap of the private UIK, so the UIK itself is gone. This is the first-principles reason
    the last-passkey delete is hard-blocked (`vault-grant.ts` ~2588, `cannot remove the last
    passkey`).
  - Edge: the identity insert and the credential wrap are two non-transactional writes (~3987
    then ~3989, logged non-fatal). A rare partial failure can leave a bare PUBLIC `identities`
    row with no wrapping credential, but the account still has that passkey (just not
    UIK-bearing = the "needs upgrade" state, losslessly re-bindable). It never yields a usable
    UIK without a passkey.

### 11.2 Two authority planes: owner-gated vault writes vs self-service identity ops
- **Vault plane (owner-gated):** membership / policy / roster / K rotation. Gated on the
  crypto-folded owner set because it changes OTHER people's access to shared secrets. This is the
  console banner's "membership writes are owner-only".
- **Identity plane (self-service, authority root = UIK possession):** a person managing THEIR OWN
  credentials and agents: add / upgrade / remove their own passkey, authorize / revoke their own
  agents. No owner approval, because it only extends access AMONG one person's own principals,
  all bound to the SAME UIK. This is the banner's "(or your own K re-seal)" carve-out.
- **Invariant that makes self-service sound:** a person is not a device, but a device's reach is a
  SUBSET of the person's reach. Adding / upgrading your own device grants it at most your EXISTING
  membership (the UIK is already the member); it never reaches a vault you are not in, and never
  grants a NEW person anything. So it needs no owner gate.
- **Corollary — passkey upgrade is a pure identity-plane op.** Binding the account UIK to a passkey
  writes one account-level row (`credentials.wrapped_uik`) and thereby unlocks EVERY UIK-member
  vault at once. It needs no vault SECRET (no K, no content).
- **Same solution as agent access.** Agent authorization is a UIK-signed grant (authz table,
  `agent-device-identity-mtls.md`). Passkey add / upgrade / remove share the identical authority
  root (a fresh UIK-possession PRF gesture) and belong on the same self-service surface
  (Account -> Passkeys / Account -> Agents), NOT behind any one vault's gate.

### 11.3 Passkey upgrade = account-level credential-wrap write (WRITE side DONE 2026-08-18)
- **The write is now dedicated + account-level.** `PUT /api/me/credential-wrap` attaches the UIK
  custody wrap to the caller's OWN credential (`wrapped_uik` + `wrap_salt` + `identity_id` via
  SET-ONCE `registerIdentity`), gated on ONE server-authoritative fact — the credential's `user_id`
  is this account. Same declare-intent / ownership model as the item write (`recordWriteGate`), NOT
  a triple diff. It does NOT touch the membership triple, needs NO owner rights, bumps NO
  `keyset_seq`. `upgradePasskey` step 4 calls it instead of a members-unchanged membership PUT.
  (BE a30682b / FE 3d59683.) This is why a plain MEMBER can now upgrade their own passkey.
  - Bug this closed: the old members-unchanged PUT was authorized either by owner rights or by
    `isSelfServiceOnlyWrite`'s byte-compare; a member hit "membership writes are owner-only". That
    compare is now canonical (11d05a7) and stays ONLY for the genuine K re-seal path (which DOES
    change `members[me].k`).
- **Remaining GAP (read side): UIK sourcing is still vault-coupled.** `upgradePasskey` still
  recovers the UIK by unlocking THIS vault's keyset row (`vault-grant.ts` ~1980-1994), so it needs
  the vault unlocked and UIK-bearing, and lives in the vault's Passkeys tab. Target: source the UIK
  from ANY unlocked UIK-bearing session (recover-from-self) and move the primary home to
  Account -> Passkeys. The write endpoint above is already account-level and ready for that.
