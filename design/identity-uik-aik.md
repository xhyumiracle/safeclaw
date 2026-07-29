# User & Agent Identity Keys (UIK / AIK) — RFC

Status: **proposal** (team-edition T2). Nothing here is implemented; T1 ships
the deposit ceremony + op-agent binding this builds on. Ground truth for the
pieces it composes: [protocol.md](protocol.md) (SUDP, key hierarchy),
[cross-device-enroll-integrity.md](cross-device-enroll-integrity.md) (Debt A/B),
[credential-broker.md](credential-broker.md) (op-binding). Design decisions and
their wave history live in `safeclaw-market/designs/team-edition.md` §7/§8; this
doc is the engineering spec that follows from them.

## 0. Why

Two questions T1 answers only operationally, not cryptographically:

- **"How do I know agent A's approval can't be abused by agent B?"** T1 binds an
  op to the requesting agent's api-key prefix (op-binding). That is a
  *bearer* — a leaked key impersonates the agent. AIK makes the agent a
  *keypair*: possession of a signing key, not a string.
- **"Who is allowed to change the rules?"** T1 gates config writes on a
  server-held owner list (`vault_config_ids`). A compromised or colluding cloud
  can rewrite that list. UIK makes the owner list a *signed* vault object: the
  server can refuse a write, but it can never *forge* one.

Both are the same move — replace a bearer/authority-by-server with a
public-key identity the holder proves by signing.

## 1. Two roles, kept separate

Per team-edition §7.11 (UIK dual role) and §C (AIK):

| | UIK (user) | AIK (agent) |
|---|---|---|
| unit | one per **account** | one per **agent** |
| unlock role | one wrap of `K` among peers (passkey / password+SecretKey / HSM) — **fully co-equal** with passkeys | none — an agent never unlocks a vault |
| identity role | account primary key; `user_id = derive(UIK.pub)`; **never deletable, exactly one** | agent id `= derive(AIK.pub)`; created by `sc agent add` |
| signs | config objects (owner list, policy, members) | proof-of-possession on each op (PoP) |
| custody | memory-derived seed + device keychain cache; **private key NEVER enters a shared vault's K domain** | in the agent's device's `sc` component (daemon locally; client/satellite remote); **never in agent env, never across machines** |

**Iron rule (UIK):** the UIK private key must never be sealed under a shared
vault's `K`. Any member who unlocks `K` would otherwise recover the owner's
signing key. UIK lives in the *personal* domain; its public key alone is
published into vault data.

## 2. Key construction (single-root derivation)

One secret per identity; everything else derives. Precedent: our own
`W_c` / item-id-key HKDF style + libsodium `crypto_kdf`.

```
seed            ← 32B CSPRNG (the ONE secret; custody protects this)
signing key     ← Ed25519 from seed          (identity: signs)
id              ← multibase(  "sc"‖ 'u'|'a' ‖ base32( SHA-256(pubkey)[:20] )  )
                  # pubkey-derived, self-certifying — ETH-address / SSH-fingerprint style
```

- **id is a fold of the public key**, so anyone can verify `id == derive(pub)`
  offline. No registry lookup to trust an id.
- `'u'` vs `'a'` discriminator byte keeps user and agent ids in disjoint
  spaces (a UIK id can never be presented as an AIK id).
- 20-byte truncation of SHA-256 (160 bits) — collision-resistant enough for an
  identifier, matches the ETH/SSH precedent this deliberately mirrors.

Interop note (survey, team-edition §C): the same pubkey-hash id construction
appears in IETF draft-duda and DID/ERC-8004 prototypes — cite them in the wire
spec and leave an OAuth `actor_token` mapping slot so an AIK id can ride
existing agent-actor headers.

## 3. AIK — agent proof-of-possession

### 3.1 Rotation without changing identity (bearer vs identity)

The daemon holds the AIK signing key. Agents authenticate to their local daemon
with a **bearer**, derived — not a second stored secret:

```
bearer  ← HKDF(seed, "sc/agent-bearer" ‖ epoch_be)
```

- `epoch` starts at 0; `sc agent rotate` bumps it. A leaked bearer is killed by
  `epoch+1` **without changing the id** (id folds the pubkey, not the bearer).
- Lifecycle is fully automatic: bearer is born with the agent, dies with it,
  self-heals on `sc run` (re-derives), and never appears in the console — the
  only user-facing concept is the agent.

### 3.2 What AIK adds over the T1 bearer prefix

T1: op bound to `sha256(api_key)` prefix — a **string** the daemon compares.
AIK: the daemon signs a PoP over the op with the agent's key; the op record
carries `agent_pub`, and the grant's β covers it (as the T1 scope already
carries `agent`). The gain is precisely **"un-clonable, not un-usable"**
(team-edition §C, wave 9): on the local execution surface the daemon holding the
key is ≈ a bearer (abuse is stopped by op-binding either way); the private key
resident in the daemon defeats *identity cloning* and *forged signed artifacts*
off-box — which a string prefix cannot.

### 3.3 Custody ladder (zero-payment first)

Per team-edition §16 + [[feedback_no_paid_signing_now]]:

1. **v1** — `~/.safeclaw/keyring` file, `0600`. Stops casual/accidental
   exfiltration. Same threat posture as `~/.ssh`.
2. **v2** — OS keychain (binary-scoped ACL) stops same-user *targeted* reads;
   same-binary self-attestation (`SO_PEERCRED`/`getpeereid`, SPIRE-style) so the
   daemon only serves the AIK to *itself* — **zero-payment, OS-native**, but
   *severable and low-priority* (wave 20 calibration: it only blocks a
   trace-less direct call to the control API, not a traced misuse of the real
   `sc`; the true wall is a sandbox).
3. **v3** — TPM/SE anchors only the daemon *root* key; per-agent keys stay
   software (few agents, cheap re-key).

The plateau we openly own (docs, not the web): same-user arbitrary code
execution reaches the file. That is `~/.ssh`'s posture too.

## 4. UIK — config signing (the real boundary)

### 4.1 Why signing, not a second symmetric key

A member's daemon **must read** policy to enforce it (the broker runs on the
member's machine). Symmetric "can read ⇒ holds key ⇒ can re-encrypt ⇒ can
forge." Only signatures give *read-not-write*: config is plaintext-readable
under `K`, but only the UIK holder can produce a valid signature over it; every
daemon verifies before applying.

### 4.2 Signed config objects

The six config singletons (§8.2) each carry a detached signature:

```
config_item.body        = { data: <subtree>, sig: Ed25519(UIK, canonical(data ‖ vault_id ‖ item_ns ‖ version)) }
```

- `vault_id ‖ item_ns ‖ version` in the signed message stops cross-vault and
  rollback replay (a v3 policy signature can't re-authorize a v5 body).
- **Tombstones must be signed too** — else "can't edit but can delete" reopens
  the hole. A config tombstone carries a sig over `(ns ‖ version ‖ "tombstone")`.

### 4.3 The owner list is itself a signed config object (`members:`)

The authority anchor can't come from the server (a colluding cloud swaps it).
`members:` = `{ user_id → role }`, signed by an owner. Trust chain:

- **genesis** — the vault creator's UIK signs the first `members:` (creator is
  owner; self-authorizing at birth, exactly like a git root commit).
- **change** — an existing owner signs the new `members:`. Verifiers accept a
  `members:` v(n+1) iff its signer's `user_id` is an owner in the verified
  v(n). Same old-key-signs-new lineage as AIK rotation.
- server `memberships` rows (T1) are demoted to an **operational projection**:
  used for gating/billing/UI while offline from the signed truth; a mismatch
  with the signed `members:` is an alarm, never authority.

### 4.4 What UIK does NOT protect

Signing protects config **integrity**, not confidentiality. A member holding `K`
can still *read* everything and *write member-tier items* (secrets,
connections) — that is the nature of a shared vault (team-edition §5.15b). UIK
draws the line at "who can change the rules," which is the only line a colluding
cloud could otherwise cross.

## 5. Ceremony reuse (single core)

Per team-edition §B (wave 45/48): the wrap-`K` authority — `deposit(target
pubkey + context) → approve(pin → wrap K → audit → close)` — is **one spec, two
runtimes** (console TS `approvePendingPasskeyInstall` + core Rust `approve.rs`),
pinned by shared golden test vectors. UIK enrollment (a new custody method for
an existing account) and AIK issuance are *qualification layers* over that same
core; they do not fork the crypto. Debt A/B hardening (deposit-target pubkey
pinning) lands once and both inherit it.

## 6. Phasing

- **T2.a** — id construction + `sc agent add` mints Ed25519, derives id;
  console shows the self-certifying id (`ag_…`), lineage, verify badge. AIK PoP
  on ops (grant β already carries `agent`; upgrade the string to a signature).
- **T2.b** — UIK enrollment as a custody method; config signing + verification
  in both runtimes; `members:` becomes the signed owner anchor; server config
  gate demoted to defense-in-depth.
- **T3** — HSM/TPM custody tier; four-eyes; SSO actor-token interop.

## 7. Migration & compatibility

- Additive: an unsigned config object stays valid until an account opts into
  UIK (a vault with no UIK published verifies nothing — T1 behavior). First UIK
  publish signs the current config; from then on unsigned writes to config items
  are rejected by up-to-date daemons.
- Mixed fleet: a pre-AIK daemon treats `agent_pub` as advisory (bearer prefix
  still enforced), so op-binding never regresses during rollout — same
  "not silent-brick" discipline as the addressing migration (§8.3).
