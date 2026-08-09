# Requestor Identity — mutual mTLS for Agent (AIK) & Device (DIK)

**Status: DESIGN LOCKED (2026-08-09, user-approved). SSOT for the identity-upgrade wave.**
One coherent wave: replace the two BEARER credentials (agent api-key, device pair token) with
possession-proven **keypair identities**, verified by **mutual mTLS**, symmetric in naming /
paths / lifecycle. No loose ends, no half-migration. Code AFTER this doc.

**Status update 2026-08-10:** the agent-authorization model was reworked to its simplest stable
form. **GROUND TRUTH = §11 (LOCKED 2026-08-10)** for authz + connect/install flows; §1/§4/§5/§6/§7/§8
still hold for mTLS / multi-agent / naming / migration / threat model; **§2/§3 admission framing is
SUPERSEDED by §11.** Diagram: `design/identity-protocol.svg`. Post-compact execution plan: §11.6 +
§9.

### Decision log (what · why · why-not · reversals — one line each)
- **AIK/DIK/UIK = Ed25519 keypairs, id = fold(pubkey)** · self-certifying, server can't swap a key behind an id · not bearers (injectable/replayable).
- **Auth = mutual mTLS both hops** (AIK client cert to daemon; DIK to cloud) · a big-co reviewer named requestor-identity-check = mTLS · not a bearer, not per-op signing.
- **hop-A needs the `sc` transport to present the cert** (generic HTTP clients can't client-cert an HTTPS proxy via env) · faithful to "sc transport does the mTLS" · NOT a data-path change the agent sees.
- **hop-B realized as a DIK-signed request** when the cloud sits behind TLS-terminating hosting · same mutual-auth outcome · literal TLS-client-cert not available there.
- **Authz = explicit in-vault authorized-agents TABLE, UIK-signed; daemon reads ONLY it** (§11) · one server-blind source, no trust in a server agent→account map · REVERSED two earlier tries: "presence = admitted grant" (Phase-1) and "membership-derived admission" (interim) — both needed a mode/join; the table is simpler + stable.
- **Dropped open/gated modes** · a permanent two-state toggle to solve a one-time migration is complexity-for-nothing · the table ships WITH AIK so the legacy api-key path is untouched → nothing bricks.
- **Account known-agents roster = management/discovery only, NOT authz** · keeps machine identity in one place (agent≡api-key) · does not entangle the daemon's authz decision.
- **Per-member authority = the authz item's UIK signature** (fold+server verify signer ∈ {agent owner, any owner}) · reuses existing owner-config signing · not new crypto, not a fragile new "ownership marker".
- **Authorization is Console-side, not in the agent prompt** · keeps the hard-won prompt lean · the vault(s) an agent lands on = which button the user clicked (§11.3).
- **One passkey authorizes across many vaults** · UIK is per-account and unseals every vault's K · avoids per-vault taps.

Grounded in the real (2026-08-09) architecture, verified in code:
- The only live local brokered path is the resident **MITM egress proxy** (the old `/use` HTTP
  route is retired). Agent auth today = api-key in the `CONNECT Proxy-Authorization` Basic
  password, checked LOCALLY against a synced hash-set (`api_key.rs` `check_token`). Never sent to cloud.
- There is **no cloud broker**; credential injection is local-daemon-only (daemon holds K).
- daemon↔cloud today = the **device pair token** (bearer, `.bearer_auth`) on all sync / op-relay
  / audit. The **cloud backend** checks it (`tier='device'`).
- Every agent talks to a **local** daemon (`127.0.0.1`); there is no remote-agent→cloud-broker path yet.

--------------------------------------------------------------------------------
## 0. The one idea

**"Who is the requestor" must be a cryptographically-verified identity (proof-of-possession),
not an ambient bearer string — checked with MUTUAL mTLS on every hop.** (This is the exact
gap a big-co reviewer named: do the requestor-identity check as mTLS mutual auth.)

Two symmetric identities, one model:

| | **UIK** (person) | **AIK** (agent) | **DIK** (device) |
|---|---|---|---|
| id | `us_…` | `ag_…` | `dev_…` |
| unit | one per account | one per agent | one per machine |
| holds K / unlocks | YES | **never** | **never** |
| proves itself to | (signs config/roles) | the **local daemon** (mTLS client) | the **cloud** (mTLS client) |
| verified by | the fold (daemon) | the **local daemon** | the **cloud backend** |
| authorized-set | membership triple | vault **authorized-agents** | account **authorized-devices** |
| revoke = | offboard + re-key | drop pubkey (**no re-key**) | drop pubkey (cut off cloud) |

`derive_id(kind, pubkey)` already emits `us_`/`ag_`; add `dev_`. All three ids are self-certifying
(id = fold of the pubkey) — no registry to trust, ssh-fingerprint / ETH-address style.

**No CA hierarchy.** Identity = a keypair; trust = the peer's pubkey is in an **authorized set**
(self-signed cert + pinned/authorized pubkey, ssh `authorized_keys` style). A real issuing
CA (SPIFFE-style) is an OPTIONAL later enterprise layer, not this wave.

--------------------------------------------------------------------------------
## 1. Mutual mTLS on both hops

**Hop A — agent ↔ local daemon (the egress proxy).**
- Upgrade the local proxy from `http://` to a **client-cert-requiring `https://` proxy**.
- **requestor → broker:** the agent's `sc` transport presents its **AIK** as the client cert.
  The daemon verifies pubkey → `ag_id` → ∈ this vault's authorized-agents, and **binds the
  tunnel to that `ag_id`** for its lifetime.
- **broker → requestor:** the proxy presents a leaf cert **minted from the daemon's EXISTING
  local CA** (the one `sc run` already installs into the agent's trust) — so no new server key,
  and the agent can't be tricked by an impostor proxy (matters in a shared hub).

**Hop B — daemon ↔ cloud.**
- The daemon authenticates with its **DIK** (mTLS client cert / signed request) instead of the
  bearer device token. The cloud verifies pubkey → `dev_id` → ∈ account's authorized-devices.
- **cloud → daemon:** the cloud is a public HTTPS endpoint with a standard CA server cert —
  the "cloud proves itself" half is already there, zero work.

**Session = the connection; session key = TLS's.** The unit is the TLS connection/tunnel; its
confidentiality is TLS's own session key, held by the two endpoints. **We invent NO session key.**
Identity is bound to the connection; anything created on it (an op) inherits the verified id.

--------------------------------------------------------------------------------
## 2. Authentication vs authorization (don't conflate)

- **Authentication (who) = mutual mTLS** (§1): AIK/DIK client cert + server cert.
- **Authorization (what):**
  - agent: **authorized-agents** (is this `ag_id` admitted to the vault?) + **connection mask**
    (which connections; deny-list so new connections stay open for an admitted agent).
  - device: **account scope** (is this `dev_id` an authorized device of the account?).
- "requestor identity check done right" = auth (mTLS) AND authz (the set + mask), together.

--------------------------------------------------------------------------------
## 3. Agent access = 2 layers, not 3 (first-principles, user-corrected)

> ⛔ **SUPERSEDED by §11 (LOCKED 2026-08-10).** The "presence = admitted grant" framing below
> (and the later interim "membership-derived admission") are replaced by an explicit **in-vault
> authorized-agents TABLE** (per item: `{ag_pubkey, owner us_, mask}`, UIK-signed) that is the
> daemon's ONLY authz source, plus an account **known-agents roster** that is management-only.
> Read §11. The paragraphs below are kept for lineage.

Durable truths kept from this section: an agent's reach is **always ⊆ its owner-member** (the mask
runs on that member's own daemon, which holds K, so an agent can never escalate); **revoke = drop
the authorization, NO re-key** (the agent never held K — contrast member offboard, which re-keys).

Lineage (why the rest was dropped, one line): the earlier "one grant object where *presence* =
admitted (fail-closed) + deny-list mask, v1 UNSIGNED" was superseded by §11 — it left the
"no-grant default" ambiguous (spawning the open/gated wart) and unsigned grants gave no per-member
authority. §11's **UIK-signed in-vault table** fixes both with existing machinery.

--------------------------------------------------------------------------------
## 4. Multiple agents: unaware · unmixable · safer

- **Unmixable:** each agent has its own identity file; the identity is selected at the `sc run`
  launch boundary; the mTLS **client cert IS the identity**, so the daemon always knows exactly
  which `ag_id` — two agents can't be confused unless pointed at the same file (they aren't).
  (Same non-mixing property as today's per-env api-key, now cryptographic.)
- **Unaware:** the agent (LLM) does nothing special — it uses the proxy env exactly as today.
  `sc run` sets up the per-agent context; the **`sc` transport** does the mTLS with that agent's
  identity file. The agent never touches the cert.
- **Safer than today:** identity = possession-proven (not a copyable string, private key never
  transmitted); the **raw key is NOT in the agent's env** (unlike today's `SAFECLAW_API_KEY` — a
  path in env, key on disk, higher exfil bar); per-agent isolation (each identity file in its own
  boundary); per-agent rotate/revoke. **The daemon holds only PUBLIC keys (verifier); privates stay agent-side.**

--------------------------------------------------------------------------------
## 5. Naming / paths / env — symmetric (locked)

| | Agent | Device |
|---|---|---|
| key | **AIK** (Agent Identity Key) | **DIK** (Device Identity Key) |
| id | `ag_…` | `dev_…` |
| identity file | `~/.safeclaw/agents/<name>/identity` (0600) | `~/.safeclaw/device/identity` (0600) |
| mint | `sc agent add <name>` | `sc login` (pairing) |
| env selector | **`SAFECLAW_AGENT_IDENTITY`** = path to the identity file | none — daemon-local, one per machine (not a wrapped child) |
| authorized set | vault **authorized-agents** | account **authorized-devices** |
| checked by | local daemon | cloud backend |

- The env var only applies to AGENTS (per-wrapped-child selection); the device identity is a
  fixed daemon-local file (`~/.safeclaw/device-key` → **migrate to** `~/.safeclaw/device/identity`).
- `SAFECLAW_AGENT_IDENTITY` holds a **path, not a secret** (leaking the var leaks a path).
- Vocabulary is symmetric everywhere: "identity key" / "identity file" / "authorized set" /
  "revoke = drop pubkey".

--------------------------------------------------------------------------------
## 6. What checks what · revoke effect (explicit)

- **AIK** — checked by the **local daemon** (authorized-agents + mask). **Revoke** = drop the
  `ag_id` from the vault grant → the daemon stops brokering for it. No re-key. (A leaked AIK is
  not remotely usable — agent identity is only presented to a local daemon.)
- **DIK** — checked by the **cloud backend** (authorized-devices). **Revoke** = drop the `dev_id`
  → that machine can no longer sync / relay / audit with the cloud, going forward. **Honest limit:
  it is a cloud-side de-authorization, NOT a remote wipe** — K/blobs already synced to that machine
  are not reached (same as today's bearer revoke).

--------------------------------------------------------------------------------
## 7. Migration — one wave, dual-auth window, no flag day

Both credentials move bearer → keypair with a compat window (same "never silent-brick" discipline):
- **Agent:** during rollout the daemon accepts BOTH the legacy api-key (Basic proxy-auth) AND an
  AIK client cert; new `sc run` uses the cert. Retire the Basic path when all agents have an AIK.
- **Device:** the cloud accepts BOTH the legacy device bearer AND a DIK proof; `sc upgrade` +
  next `sc login`/re-pair mints the DIK and registers its pubkey. Retire the bearer when the
  device census is clean.
- **Daemon rebuild required** (proxy transport + mTLS + DIK). daemon = LOCAL only (no cloud daemon
  since de-daemon); ship the binary → user `sc upgrade`s their box(es). No delicate cloud rollout.

--------------------------------------------------------------------------------
## 8. Value / threat model (honest scoping)

- **"How do you stop agent A using agent B's token in a hub with reused skills?"** — mTLS is the
  answer: A can't open a tunnel as B without B's private key (never transmitted; fresh challenge),
  so A cannot produce a request attributed to B. **Necessary but not sufficient:** it rests on
  per-agent key isolation (§4) — the identity file in a boundary co-located agents/skills can't read.
- **Service creds are already safe** (broker injects at the edge, never in the agent) — a poisoned
  shared skill can't harvest them today. AIK closes the remaining gap: the agent's OWN identity
  token (today a bearer in env) becomes a possession-proven key.
- **Third-party / federated agents:** public-key identity (publish `ag_id` pubkey → authorized_keys)
  is the only clean cross-org answer; bearers can't. Aligns with SPIFFE/SVID, OAuth actor-token, DID.
- **Honest priority:** locally today AIK is defense-in-depth + removes the injectable env bearer;
  its full value is the hub / multi-agent / third-party / enterprise-audit future. DIK is lower
  urgency than AIK (device key lives in a 0600 file, not an injectable agent env) but is done in
  this wave for symmetry + to kill the last replayable bearer.

--------------------------------------------------------------------------------
## 9. Build sequence (one wave)

1. **Vault-level agent management (mask): grant / mask / revoke, keyed by agent handle.** Ships
   FIRST — does NOT depend on AIK (revoke works, no re-key). This is the immediately-testable piece.
2. **AIK + hop-A mutual mTLS:** `sc agent add` mints AIK (`ag_…`, identity file); proxy → https +
   client-cert; daemon binds tunnel→`ag_id` + authorized-agents check; `sc run` uses
   `SAFECLAW_AGENT_IDENTITY`; dual-auth with the legacy api-key.
3. **DIK + hop-B mutual mTLS:** `sc login` mints DIK (`dev_…`); daemon↔cloud calls use it; backend
   verifies authorized-devices; dual-auth with the legacy device bearer; migrate `device-key` path.
4. **Frontend:** agent + device management (list / rename / revoke) on the symmetric model; Agents
   tab shows `ag_id` + member attribution; account Access page lists devices by `dev_id`.
5. **Retire bearers** once both censuses are clean (LAST, gated).

--------------------------------------------------------------------------------
## 9.1 Build status (2026-08-09, overnight autonomous pass)

Shipped ADDITIVE + DUAL-AUTH + LEGACY-DEFAULT; all layers green; held uncommitted for the
user's batch e2e. See `IDENTITY_WAVE_BUILD_LOG.md` (repo root) for the decision list.

- **Step 1 (vault-level agent mgmt) — DONE.** `AgentAdmission{Open,Gated}` (unsigned E2E aux,
  `open` default = non-bricking); admission-aware `agent_mask_allows` /
  `agent_allowed_connections` + cache; FE admit/mask/revoke/set-mode write handlers; **Agents
  tab** (team-only). "Present grant = admitted; drop grant = clean revoke, no re-key" is live.
- **Step 2 (AIK/DIK mint + registration) — DONE (store); serving DEFERRED to step 3.**
  `IdKind::Device`+`dev_`; `identity_file` module (mint/write/load, 0600 JSON, unit-tested);
  `sc agent add` mints AIK→file + registers `ag_` pubkey + prints `SAFECLAW_AGENT_IDENTITY`;
  `sc login` mints/reuses DIK→file + registers `dev_` pubkey. Backend stores pubkeys on
  `api_keys.sig_pub`/`identity_id` (migration `2026-08-09-01-api-key-pubkey.sql`, defensive
  insert). Legacy api-key + device-key still the ACTIVE transport (§7). The identities are
  now fully PROVISIONED end-to-end; only the transport USING them remains.
- **Steps 2-transport (hop-A) + 3 (hop-B) — DEFERRED (design-confirm + runtime e2e).** Two
  real constraints found in code that refine §1:
  - **hop-A** faithful mTLS needs the `sc`-transport shim (§4): generic agent HTTP clients
    (curl/node/python/git) cannot present a client cert to an HTTPS forward proxy via env, so
    "the sc transport does the mTLS" = a per-`sc run` local mTLS-wrapping forward proxy
    (child → plain-http loopback → mTLS(AIK) → daemon proxy). Large + not runtime-testable
    blind; build it as its own focused pass, then flip via dual-auth.
  - **hop-B** literal TLS-mTLS is impractical (the cloud sits behind Railway's TLS
    termination, which doesn't surface client-cert mTLS). Use the §1-sanctioned alternative:
    a **DIK-signed request** (Ed25519 PoP over a fresh challenge / request digest in a header),
    verified by the Node backend against `api_keys.sig_pub` where `identity_id` starts `dev_`.
    Dual-auth with the device bearer; retire the bearer when the device census is clean.
  - Daemon-side readiness for hop-A: add a `/api/vault/agents/pubkeys` serve (parallel to
    `/hashes`) → daemon syncs authorized `ag_` pubkeys → the proxy verifies the AIK cert and
    binds the tunnel to `ag_id`, then the mask lookup key moves prefix→`ag_id` (state.rs:245
    already anticipates this).

--------------------------------------------------------------------------------
## 10. Non-goals (this wave)
- A real issuing CA / PKI (SPIFFE-style) — optional enterprise layer later.
- Remote-agent → cloud-broker path — future, gated (no such path today).
- Per-op agent signatures — optional audit hardening; mutual mTLS on the connection is the base.
- UIK changes — untouched here (that's the unified-identity-schema wave).

--------------------------------------------------------------------------------
## 11. Agent authorization & connect/install flows (LOCKED 2026-08-10)

Reasoned to its simplest stable form with the user. **Supersedes** the admission framing in
§2/§3: dropped are open/gated modes, "presence = admitted" (Phase-1 build), and the interim
"membership-derived admission." The model below is the ground truth.

### 11.1 One authoritative authorization source
- **Account known-agents roster** (server, plaintext): the account's agents — `ag_` pubkey +
  label + owner account. Minted/registered by `sc agent add` over the device (DIK) channel
  (no K). **Management + discovery ONLY — never the daemon's authz source.**
- **Vault authorized-agents TABLE** (E2E, inside the encrypted blob): per authorized agent an item
  `{ ag_pubkey, owner us_, mask }`, **signed by the owning member's UIK**. **This is the daemon's
  ONLY authz source:** presented AIK (mTLS client cert) → its pubkey ∈ this table → apply that
  item's connection mask. No server join, no membership derivation, nothing else consulted.
- **Revoke** = remove the item (E2E write). **No re-key** (agent never held K).
- **Per-member authority** = the item's UIK signature IS the ownership/authority marker. The fold
  (daemon) + the server write-gate verify the signer ∈ { the agent's owner-member, any owner }: a
  member may add/modify/remove items only for their OWN agents; an owner overrides any. This REUSES
  the existing owner-config signing machinery (§ config_sig) — no new crypto, no new fragility.
- Writing the table needs **K** (unlocked session). One passkey unwraps the **per-account UIK**,
  which unseals every vault's K → one gesture can write authz across multiple vaults.

### 11.2 Auth = mutual mTLS (both hops) — §1 unchanged
hop-A: sc presents AIK client cert; daemon verifies + checks pubkey ∈ the vault table.
hop-B: daemon presents DIK; cloud verifies `dev_` ∈ authorized-devices (through a TLS-terminating
host, realized as a DIK-signed request — the app-layer equivalent).

### 11.3 The authz primitive surfaces at 4 natural moments (all write the same UIK-signed items)
1. **Connect a new agent** (account · `/access`): intent = an agent for my account → default
   authorize on **all my vaults** (multi = my vaults, default all). One passkey.
2. **Install an agent on a vault** (a vault surface): intent = an agent here → authorize **this
   vault only** (rides the current unlocked session; else one passkey).
3. **Create OR join a vault**: offer "allow these agents to use this vault" = multi-select **my
   agents, default all**, in the same passkey session as create/seal or join.
4. **Agents tab**: the ongoing management grid (per-agent × per-vault; revoke / mask).

### 11.4 Connect/install prompt + modal (build on the existing polished prompt)
- The agent-run prompt is ~unchanged (pair device [skip if paired] · `sc agent add` mints the
  identity env · persist skill + instructions · don't test). Only wording tweak: "three
  SAFECLAW_* dotenv lines" → "your complete SafeClaw env" (now includes the identity-file path).
- **Authorization is Console-side, NOT in the prompt.** Which vault(s) an agent lands on = which
  entry the user used (§11.3); the Console performs the UIK-signed write automatically when it
  detects the new agent in the roster (poll). The hard-won prompt stays lean.
- Modal: a clean "keep this open while your agent connects — it authorizes automatically" hint;
  on done, "✓ Connected and authorized on <scope>."
- Edge (modal closed before the agent finished): the agent appears in the Agents tab as
  "not authorized here · Authorize" — a one-click fallback, not the main path.

### 11.5 Three orthogonal actions, kept separate but each a one-click intent
1. register agent to account (mint · `sc agent add` · DIK channel · no K),
2. authorize agent in vault(s) (E2E · UIK-signed · K-gated) — surfaced at the 4 moments above,
3. point an agent at a vault (runtime config: vault id / `--vault`).
Device pairing (`sc login`) is the separate device-level action; the prompt folds it in
idempotently ("skip if paired").

### 11.6 Build deltas vs the Phase-1 checkpoint on `feat/identity-wave`
- Key the vault authz item by `ag_` pubkey (not api-key prefix); add `owner us_` + UIK signature;
  fold/server verify signer authority. Drop `AgentAdmission` open/gated entirely (default is now
  simply "not in the table = not authorized"; nothing bricks because the table ships WITH AIK —
  the legacy api-key path is untouched until bearers retire).
- Daemon authz consult reads ONLY the in-vault table (remove the derived/admission-mode logic).
- Console: the authz primitive component (multi-select) at the 4 moments; modal keep-open hint;
  vault-create/join multi-select "allow my agents (default all)."
