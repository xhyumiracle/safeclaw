# Requestor Identity — mutual mTLS for Agent (AIK) & Device (DIK)

**Status: DESIGN LOCKED (2026-08-09, user-approved). SSOT for the identity-upgrade wave.**
One coherent wave: replace the two BEARER credentials (agent api-key, device pair token) with
possession-proven **keypair identities**, verified by **mutual mTLS**, symmetric in naming /
paths / lifecycle. No loose ends, no half-migration. Code AFTER this doc.

> ⚠️ **BUILT AS application-layer PoP, NOT a TLS client-cert handshake (realized 2026-08-10).**
> This doc (and its name) frame the mechanism as "mutual mTLS" — that is the design abstraction and
> the intended *property*. What was actually IMPLEMENTED on **both** hops is an application-layer
> **proof-of-possession (PoP)** signature — the DPoP pattern (RFC 9449): a fresh keypair-signed token
> in the standard auth header, not a TLS client-cert handshake. mTLS is the transport-layer form of
> the same "prove you hold the private key" property; we ship the app-layer form because the TLS
> client-cert channel isn't available on either hop.
> - **hop-A (agent→daemon):** the AIK signs a per-CONNECT token carried in `Proxy-Authorization`
>   (`identity::agent_proxy_pop_input` → `scpop1.<pub>.<ts>.<sig>`), verified against the E2E
>   authorized-agents table. A standard client can't present a client cert to a forward proxy (and
>   hudsucker's inbound can't surface one to its authz handler), so the §1/§4/§9.1 "present the
>   cert / mTLS-wrapping shim" wording is the SUPERSEDED plan — see the decision-log reversal below.
>   Built = `agent_pop` + `proxy/handler` PoP verify + the `sc`-transport shim (`cli/agent_shim`).
> - **hop-B (daemon→cloud):** the DIK signs each request (`identity::device_request_signature_input`),
>   verified by the Node backend against the device's registered pubkey (Railway terminates TLS, so no
>   client cert reaches the app). This doc's decision-log already recorded hop-B as a signed request.
>
> Read every "mTLS / client cert" below as "PoP signature" for the built system. The **authz** model
> (§11 authorized-agents table) is unchanged and fully current — only the *auth transport* is PoP,
> not mTLS. Code refs: `design/sudp-identity-signing-revision.md` is a different (甲) wave.

**Status update 2026-08-10:** the agent-authorization model was reworked to its simplest stable
form. **GROUND TRUTH = §11 (LOCKED 2026-08-10)** for authz + connect/install flows; §1/§4/§5/§6/§7/§8
still hold for mTLS / multi-agent / naming / migration / threat model; **§2/§3 admission framing is
SUPERSEDED by §11.** Diagram: `design/identity-protocol.svg`. Post-compact execution plan: §11.6 +
§9.

**Status update 2026-08-20:** bootstrap/pairing — how AIK/DIK first get certified (§9.1's open
item) — is now **§12 (LOCKED, Device Flow / RFC 8628)**. It supersedes §11.3-pt1's "default all"
and §11.4's auto-authorize-on-poll. Vault-in-bootstrap defers to `design/vault-addressing.md`.

### Decision log (what · why · why-not · reversals — one line each)
- **AIK/DIK/UIK = Ed25519 keypairs, id = fold(pubkey)** · self-certifying, server can't swap a key behind an id · not bearers (injectable/replayable).
- **Auth = mutual mTLS both hops** (AIK client cert to daemon; DIK to cloud) · a big-co reviewer named requestor-identity-check = mTLS · not a bearer, not per-op signing.
- **hop-A needs the `sc` transport to present the cert** (generic HTTP clients can't client-cert an HTTPS proxy via env) · faithful to "sc transport does the mTLS" · NOT a data-path change the agent sees.
- **hop-B realized as a DIK-signed request** when the cloud sits behind TLS-terminating hosting · same mutual-auth outcome · literal TLS-client-cert not available there.
- **hop-A ALSO realized as a signed token, NOT a client cert** (2026-08-10, REVERSAL of the "present the cert" line above) · a forward proxy exposes no client-cert channel to a generic client, and hudsucker's inbound can't surface a client cert to its authz handler · so the AIK signs a per-CONNECT `Proxy-Authorization` PoP token (DPoP-style, RFC 9449), verified against the authorized-agents table — same "possession-proven, not a bearer" outcome. **Both hops = app-layer PoP; see the top banner.**
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

## 9.2 Build status (2026-08-10) — §11 authz model landed end-to-end

**Step 1 (§11.6 authz-table refactor) DONE, all 3 layers green + committed on
`feat/identity-wave` (unpushed):** core `c4e6e89` (`aux:agent/<ag_id>` = UIK-signed
authorized-agents table via `unwrap_verified_agent_grant`, reuses the owner-config signing
machinery; `AgentAdmission` open/gated deleted; consult keyed by `ag_id`, legacy prefix
falls to legacy-allow so nothing bricks; +authz unit test; 378 lib tests green), FE `660a9f0`
(`ConfigSigner.wrap` signs `agent/*` + auto-stamps `owner`=signer; fold blind-unwraps;
re-key verify-then-resign; presence=authorized; Agents tab + Connections mask key by `ag_id`),
BE `5b5e8b3` (roster serves `identity_id`+`sig_pub`; grants stay E2E + member-writable — the
daemon fold IS the "server write-gate" the server can't do on sealed ct). Prompt wording
`e36d3fd`.

**Remaining focused passes** (deliberately NOT shipped blind — coupled, not e2e-testable
here, would touch the LIVE sync path / auth core; per the §9.1 caution): the mTLS transport
(hop-A shim + hop-B DIK-signed request), connect-time auto-authorize UX (§11.3 ①②③ — needs
the one-passkey→many-vaults ceremony; today agents are allow-by-default on the legacy
transport so this is future-facing), the fail-closed flip (AIK path only, in the proxy
handler not the consult), and retiring bearers. Full plan = repo-root
`IDENTITY_WAVE_BUILD_LOG.md` → "NEXT".

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
> ⛔ **pt1's "default all" SUPERSEDED by §12.4** — default = the single vault in context; "all my
> vaults" is an explicit opt-in (a broad default also manufactures multi-vault ambiguity, §12.6).
> The 4 moments + multi-select otherwise stand.
1. **Connect a new agent** (account · `/access`): intent = an agent for my account → default
   authorize on **all my vaults** (multi = my vaults, default all). One passkey.
2. **Install an agent on a vault** (a vault surface): intent = an agent here → authorize **this
   vault only** (rides the current unlocked session; else one passkey).
3. **Create OR join a vault**: offer "allow these agents to use this vault" = multi-select **my
   agents, default all**, in the same passkey session as create/seal or join.
4. **Agents tab**: the ongoing management grid (per-agent × per-vault; revoke / mask).

### 11.4 Connect/install prompt + modal (build on the existing polished prompt)
> ⛔ **SUPERSEDED by §12** (Device Flow): the "Console auto-authorizes when it detects the new
> agent in the roster (poll)" + "modal keep-open, authorizes automatically" model is replaced by an
> explicit `/pair` ceremony with `user_code` binding. Kept truth: authorization is Console-side,
> never in the prompt.
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

--------------------------------------------------------------------------------
## 12. Bootstrap / pairing — Device Flow (LOCKED 2026-08-20, user-approved)

How AIK/DIK first get **certified** — the enrollment channel §9.1 left open. Shape = **OAuth 2.0
Device Authorization Grant (RFC 8628)**. Additive + dual-auth (§7): the `pair_token` path and the
vid-in-proxy face keep running through the window; retire on the same gate as the bearers —
**nothing currently running breaks.** Design mock: `safeclaw-market/designs/device-flow-pairing.html`.

### 12.1 Reversed direction, one primitive
- Today a human mints a `pair_token` and pastes it into the agent prompt (secret → context → transcript).
- Device Flow: the **agent/daemon initiates**, gets a `device_code` (kept — the secret poll handle)
  + a short **`user_code`** (the only thing shown) + a verification URI. The agent **emits** the
  `user_code`; admission arrives on the back-channel poll. `user_code` is low-entropy, short-TTL,
  useless without an authenticated browser session — a transcript leak is near-harmless.
- **One primitive:** a single authorization request certifies a **list of principals**, each with a
  declared scope. The list = whichever pubkeys aren't yet in the authorized set. First pairing =
  `{device, agent}` (one ceremony, no double burden); a new agent on a trusted device = `{agent}`.
  "Already trusted" is not a mode — the device pubkey is simply already registered, so it's absent
  from the list. **No `if-first-else`.**

### 12.2 Approval = admission, not a cert (§0 unchanged)
Approval mints **no cert / bearer**. It **admits the pubkey into the authorized set** (ssh
`authorized_keys` style):
- **DIK** → account authorized-devices = an `api_keys` row (`sig_pub`/`identity_id`).
- **AIK** → the E2E **UIK-signed `aux:agent/<ag_id>` item** (§11.1), written via the existing
  generic route `PUT /v/{vid}/items/{item_id}` in the ceremony's passkey session (one passkey →
  UIK → every selected vault's K, one gesture). **No new authz route.**
Runtime auth is untouched (hop-A AIK PoP, hop-B DIK-signed request; §1/§11.2). Device Flow is the
**enrollment channel only** — pubkeys up, admission down, privates never leave the machine.

### 12.3 Registration is possession-proven, not TOFU
Today the exchange/create handlers store any pubkey the caller sends with **no PoP** (the DIK
verifier exists but is audit-only). Under Device Flow the **poll carries a PoP** over the
`device_code` (signed by the private key being registered): the server admits a pubkey only when
possession is proven **and** the human approved. Closes the TOFU hole.

### 12.4 Every agent explicitly confirmed; least-privilege at the grant
No local silent mint — each new agent is browser-confirmed (the human sees `ag_id`, path, scope).
**Hard boundary = the authorized-set** (`ag ∈ authorized(vid)`, daemon-enforced): reach is set at
authorization, not runtime. **Default selection = the single vault in context, NOT all** ("all my
vaults" is an explicit opt-in) — least-privilege, and a narrow grant also avoids manufacturing the
multi-vault ambiguity of §12.6. (Supersedes §11.3-pt1.)

### 12.5 Routes + ceremony — reshape `pair-token` in place
One `/api/pair/*` family (reuse the `pair_tokens` table + poll skeleton; do **not** fork a parallel
`/api/device/*` — "device" collides with DIK):

| now | becomes | role |
|---|---|---|
| `POST /api/pair-token/mint` | `POST /api/pair/authorize` | issue `device_code` + `user_code` + verify-URI; body = principal list + proposed scope |
| `POST /api/pair-token/exchange` (AUTH=NONE, TOFU) | `POST /api/pair/poll` | daemon polls with `device_code`; `authorization_pending` until approved; then admit (PoP-gated) |
| `POST /api/pair-token/status` | folded into the ceremony's own state | — |
| — | `GET /pair` (console) | the ceremony |

**`/pair`** models on `/grant/[id]` (standalone minimal-header, passkey gesture): passkey proves
the human → renders the **principal list** (device/agent rows + scope) + a **`user_code` confirm
box** (binds "the CLI session that initiated" to "the human approving" — the sole reason `user_code`
exists, and why we keep a code over click-only) → approve/reject → the two admissions of §12.2 in
one passkey session.

### 12.6 Prompt stays fully static; vault ≠ prompt data
- **Setup prompt** = skill + `sc login` / `sc agent add`. **No vault id, no key, no account id —
  zero per-install customization** (HF-parity). The `user_code` is printed **by the CLI** (output),
  never pasted in.
- **Which vault an agent lands on** = the human's ceremony selection (an authorization property of
  the AIK), resolved daemon-side — never carried by the agent. (Task-prompt text naming a vault is
  the human's data, not setup.)
- **Ambient vault** = single source `SAFECLAW_VAULT_ID` (set by `sc run`; resolve or `--vault`;
  **fail-closed** on multi-with-no-default). Both faces read it: `sc` directly; the transparent face
  via the **AIK shim injecting the vid** → `HTTPS_PROXY` is a **bare loopback** (no vid, no key; key
  = AIK PoP). Per-op switch = `--vault` (stateless, still `ag ∈ authorized`); whole-ambient switch =
  relaunch; **no state file**. Addressing SSOT = `design/vault-addressing.md` (see its 2026-08-20
  note). Verified 2026-08-20: the explicit broker face already runs bare
  (`SAFECLAW_BROKER_URL = http://127.0.0.1:<port>`, vid only in `SAFECLAW_VAULT_ID`).

### 12.7 Retire (after the dual-auth window)
- `install_prompt` carrying a `pair_token` → the prompt carries only the commands; the code comes
  **from** the CLI.
- `pair-token/exchange`'s AUTH=NONE TOFU path → approval-then-admit + registration PoP (§12.3).
- `connect-agent-modal.tsx onAuthorizeAgent` auto-write + §11.4 "modal keep-open, auto-authorizes on
  poll" → the explicit `/pair` ceremony.
- Legacy vid-in-`HTTPS_PROXY` → drop when the shim is the sole transport (same gate as retiring
  bearers, §7).

### 12.8 Install prompt → static one-liner + onboarding doc (two-phase) [MARK: Phase 1 buildable now]
HF-style split. **Skill** (`safeclaw-skill.md`) stays generic ("how to use", ongoing) — untouched.
An **onboarding doc** (public `/docs`, fold into the existing agent guide — do NOT fork) becomes the
home for the current `install_prompt`'s **non-skill, must-keep content**: the step sequence **and the
tuned framing that keeps a security-minded agent from refusing**. Relocate that wording **verbatim**
— it is load-bearing (drop-test it does NOT pass). The **prompt** collapses to one benign line that
points at the doc; a one-line pointer + the official-domain doc URL together carry the "this is safe"
frame (HF's exact pattern).
- **Phase 1 (doc-split) — ⛔ ROLLED BACK 2026-08-20 (user):** "prompt 不多,单独开一个 doc 似乎没
  必要." The `install_prompt` stays **self-contained** (its tuned, refusal-proof framing lives in the
  prompt, not a doc). No doc-pointer shrink. Phase 2 (token-drop) still stands — it just collapses the
  *self-contained* prompt to a token-less one once §12 Device Flow is e2e-verified, and is where the
  "sc too old → run `sc upgrade`" note lands (needs sc >= a device-flow-capable version).
- **Phase 2 (rides §12 Device Flow):** the token leaves the prompt → a **pure static one-liner**.
- **Validation:** "agent still onboards without balking" is a live onboarding e2e (with the user),
  NOT statically testable here.

### 12.9 Unified force-upgrade floor (LOCKED 2026-08-20, user-approved) [BUILT dev]
The premise the user set: with many breaking changes since 0.9.x, do NOT try to make every old daemon
keep half-working. Be blunt — **old versions are no longer supported; run `sc upgrade`; after upgrade
you are guaranteed to be running the new binary.** Two mechanisms, plus one honest ceiling.

**(1) Global version floor at ONE dispatch chokepoint (backend).** `daemonUpgradeGate(req,res)` in
`vault-routes.mjs`, called once at the top of `tryHandleVaultRoute` for the whole daemon data-plane
(`inAgentNew` = blob/items/keys/membership/audit + `inOpRelay` + the SSE stream). Refuses any
**device-tier** api-key below `team.MIN_DAEMON_VERSION` (`team.mjs`, currently `0.10.0`) with the
stable `403 {code:'SC_UPGRADE_REQUIRED', min_version, upgrade:'sc upgrade', message}`. Keys on the
device tier, so browser sessions (no `sc_` key) and agent-tier keys pass through untouched;
`verifyApiKey` is prefix-cached so the resolve is near-free even though the handler re-resolves.
**Absent `x-safeclaw-version` counts as old** (`versionLt(undefined,…)=true`), which catches
pre-header 0.9.x daemons. This is a SUPERSET of the old fmt2-only `teamSyncGate` (kept only as the
hook for a format that needs an EVEN HIGHER floor than the global one; today equal ⇒ no-op).
  - **Why one chokepoint, not per-handler:** every daemon→cloud call funnels through
    `tryHandleVaultRoute` (relay.mjs forwards here), so one gate covers all daemon routes and any
    future one for free — "unified pipeline, not a patch."
  - **Coverage verified (core):** every current daemon→cloud request on a gated route carries
    `x-safeclaw-version` (all sync/op-relay/audit via `egress_proxy::client`, SSE via
    `client_streaming`; CLI + loopback calls hit the LOCAL daemon, not the cloud gate). ⇒ no
    false-positive on a current daemon. Header value = `CARGO_PKG_VERSION` (bare), correct for the
    floor since `versionLt` ignores the `-rc` suffix (an rc of 0.10 is allowed).
  - **Old daemon reaction is safe:** it maps 401/403 → park-on-local-cache (no data loss), and (0.10+)
    surfaces `SC_UPGRADE_REQUIRED` to the agent as HTTP 426 (`proxy/handler.rs`).
  - **⚠ Release coordination:** the floor lives on dev at `0.10.0`. Bump `MIN_DAEMON_VERSION` (and
    promote it to prod) ONLY in lock-step with a released stable users can `sc upgrade` TO — raising it
    past the newest release strands every daemon with no target.

**(2) "You end up on the new binary" self-check (core).** `up.rs::restart()` (the chokepoint
`sc upgrade` execs into) now calls `warn_if_stale_after_restart()`: after the bounce it probes the
local daemon's `/health` version and compares it to `build_version()`. The common install (unit
ExecStart path == the binary `sc upgrade` overwrote) relaunches the new binary by construction; this
catches the rare exceptions (service unit points at a *different* `sc` = path drift, or the bounce
didn't take) and makes them LOUD + actionable (`sc down && sc up`) instead of a silent stale daemon.
We deliberately do NOT rewrite the unit's ExecStart path in place (symlink/spacing edge cases,
fragile) — the loud self-check covers all failure modes with one mechanism.

**Honest ceiling (un-fixable retroactively):** a shipped 0.9.x daemon serving an agent from its
**already-cached** secrets is an OFFLINE local path — the cloud floor cannot refuse it. Mitigations:
the value is stale-but-valid (not corrupt); ANY cloud touch (new grant, new item, membership/re-key)
is refused; and pre-launch the population is small ⇒ operational fix = watch `/admin` version census
and get the few users to `sc upgrade`. This is why the upgrade window must be short and loud, not
silent (cf. S1/S2: agent-facing stale-serve, OAuth rotating-refresh fork on a parked device).

**Non-goals:** gating pairing (`/api/pair*`) or `agents/hashes` — an old daemon that pairs is
force-upgraded on its very first sync, and hashes carry no content. Front-end untouched (the console's
`/api/me/daemon-status` soft nudge already exists).

## 13. Identity migration / legacy cutover (LOCKED 2026-08-20, user-approved)

The wave shipped the crypto substrate (AIK/DIK keypairs, PoP) additively behind dual-auth, so nothing
breaks — but that left the actual *adoption* unbuilt: existing agents/devices carry NO keypair
("legacy"), there is no in-place upgrade and no nudge, so the AIK/DIK census can never reach 0 and the
compat-sunset rows (`compat-sunset.md` #1/#2/#3/#6/#7) can never be deleted. The wave can't *finish*.
User's call (2026-08-20): don't build in-place AIK/DIK upgrade — **wipe + re-pair from scratch**. It's
cleaner and less code.

### 13.0 Principles (constraints first)
- **P1 — passkeys/UIK are the person's vault access ⇒ NEVER wipeable** (wipe = self-lockout). UIK must
  upgrade *in place*.
- **P2 — agents/devices are cheap, re-pairable identities holding NO unique data** (vault data is
  sealed and untouched) ⇒ safe to wipe; re-pair under the new flow mints a proper AIK/DIK from birth.
- **P3 — the migration must let us DELETE the dual-auth compat.** A "census reaches 0 eventually"
  driver isn't enough; a hard cut makes it 0 now, so the legacy paths can be ripped out and the wave
  closes.
- **P4 — one coordinated cutover, riding the 0.10 force-upgrade (§12.9)**, not a drawn-out campaign.
- **P5 — no silent destruction** (clear consent/messaging), and **P6 — never lock the user out**
  (after a wipe they can always re-pair because their passkey/UIK is untouched).
- **P7 — minimal clicks for the unavoidable in-place work (UIK).**

### 13.1 Non-goals
In-place AIK/DIK upgrade (rejected — wipe+re-pair). Preserving legacy agent/device identities across
the cut. A gradual/opt-in migration. Touching vault data or UIK/passkeys during the agent/device wipe.

### 13.2 Per-identity plan
- **DIK (devices) — WIPE + re-`sc login`.** The cut = **enforce DIK** (flip `SC_DEVICE_SIG_AUDIT`
  audit→reject + the `MIN_TEAM_DAEMON_VERSION` bump, compat-sunset #3/#7): a device with no DIK is
  refused, so it must re-run `sc login`, which already mints+registers a DIK (`cli/login.rs`). The
  daemon surfaces "re-run `sc login`" on that rejection (same shape as §12.9's "run `sc upgrade`"). A
  console **"reset devices"** affordance revokes the stale device `api_keys` rows so they don't linger.
- **AIK (agents) — WIPE + re-add.** Same: legacy (no-`identity_id`) agents are revoked; the user
  re-pairs via `sc agent add` / the §12 device-flow, which mints an AIK from birth. Requiring AIK
  (fail-closed hop-A, compat-sunset #1/#2) is the enforcement that makes a legacy api-key agent stop
  working, forcing the re-add.
- **Migration UX = a GUIDED, USER-PRESSED button** — the middle path between a silent server wipe
  (reads as "you deleted my stuff", angers) and pure passive enforcement (things mysteriously break).
  The console surfaces a clear **"Upgrade your agents & devices"** affordance (identity nudge → confirm
  modal: "this signs out your N legacy agents/devices; re-pair each after — your passkeys and vault
  access are untouched"). The USER presses it → it revokes only the **legacy (keypair-less)**
  agent/device creds (reuses `handleRevokeKey`) → the console then **guides the re-pair** (per device
  `sc login`, per agent `sc agent add`; headless fine via the §12 device-flow URL). Re-pair mints
  AIK/DIK from birth. User-initiated ⇒ not angering; explicit ⇒ they know exactly what happens. Target
  legacy-only (never an already-upgraded entity); NEVER a "reset passkeys" sibling (P1).
  - **Enforcement is the BACKSTOP deadline, not the primary UX.** For holdouts who ignore the nudge,
    the coordinated cutover eventually flips DIK-reject / require-AIK ("legacy support ends <date>;
    upgrade now, one click"): legacy stops being accepted, the daemon says "re-run `sc login`", re-pair
    becomes mandatory. This is what *guarantees* the census reaches 0. The delete-trigger counts only
    **ACTIVE (used <30d) keypair-less** creds, so post-button / post-deadline it drains within the
    inactivity window (a lazy reaper GC's long-dead rows). Pre-launch (≈one user) the button alone
    drains it; the deadline only matters at scale.
- **UIK (passkeys) — in place, minimal clicks.** Mechanism exists (`upgradePasskey`,
  `lib/vault-grant.ts`) but is buried in a per-vault tab. Move it to the account level
  (`/account/passkeys`), add an account **nudge banner** ("N passkeys need upgrading"), and drive it in
  the **fewest gestures the crypto allows** (see §13.5).

### 13.3 Cutover ordering (rides §12.9)
1. 0.10 stable out + force-upgrade floor live (§12.9) — daemons are already ≥0.10.
2. Ship the migration UX: account-level UIK upgrade + the identity nudge banner + the guided
   **"Upgrade agents & devices"** button (user-pressed → revoke legacy + guide re-pair) + the daemon
   "re-run `sc login`" surfacing.
3. Flip enforcement: DIK audit→reject, hop-A require-AIK (fail-closed). Legacy agents/devices now stop
   working ⇒ users re-pair; passkeys upgrade in place.
4. **Active-legacy census drains to 0 within the inactivity window** (post-flip a legacy cred is
   rejected → goes unused → drops out of the active count; §13.2 — bounded, no wipe). Then **delete the
   compat** (compat-sunset #1/#2/#3/#6/#7 + their code) and re-run green gates.

### 13.4 Compat this unlocks (delete after the cut)
`compat-sunset.md` rows **#1** (dual-window agent-id keying), **#2** (hop-A legacy Basic api-key),
**#3** (hop-B legacy device bearer), **#6** (`~/.safeclaw/device-key`), **#7** (`SC_DEVICE_SIG_AUDIT`).
Row **#5** (NoUik/fmt1) is a separate *vault-format* census with its own self-heal (task B1b); row
**#4** (config-sig) is the 甲 cutover — both out of scope here.

### 13.5 RESOLVED (verified 2026-08-20): UIK upgrade is PER-PASSKEY, one tap on its own device — no batch
`upgradePasskey` (`vault-grant.ts:1975`) derives the target passkey's wrap key `W_c` from **that
passkey's OWN PRF assertion** (`safePasskeyGet` on the target, lines 1992-2001) and wraps the UIK under
it — so upgrading passkey X requires X's authenticator present + tapped. There is **no pubkey-only /
batch path**: a passkey that isn't present can't produce its PRF, so its wrap can't be computed. This
is crypto-fundamental (each passkey independently holds the UIK under its own PRF key) and a GOOD
property — a compromised/absent passkey can't be silently enrolled onto attacker devices; the target
must physically consent.
**⇒ UIK upgrade = ONE tap per legacy passkey, on the device that holds it.** Clean UX (clarity beats
click-count): the account page (`/account/passkeys`) lists every passkey, flags the legacy ones WITH
their device label, gives the passkey present on THIS device a live one-tap "Upgrade" CTA, and clearly
signposts the rest ("upgrade on <device>: one tap"); a nudge banner surfaces the count. The user
grasps the WHY (independent keys) and the WHAT (one tap where each key lives).

### 13.6 Build list
1. **FE:** account-level `/account/passkeys` — list all passkeys, flag legacy + device label, live
   one-tap "Upgrade" for the passkey on THIS device + "upgrade on <device>" signpost for the rest
   (§13.5, per-passkey by crypto) + the identity nudge banner.
2. **FE+BE:** console guided **"Upgrade agents & devices"** button — user-pressed → confirm modal →
   revoke LEGACY (keypair-less) agent/device creds (reuses `handleRevokeKey`) → guide re-pair.
3. **Core:** on DIK-reject / AIK-required, daemon surfaces "re-run `sc login`" (mirror §12.9).
4. **BE+Core:** flip DIK enforce (`SC_DEVICE_SIG_AUDIT`→reject) + hop-A require-AIK (fail-closed),
   census-gated.
5. **Delete compat** (§13.4) + green gates.
Supersedes the "in-place AIK/DIK upgrade" reading of tasks #72/#75/#81; those shrink to this list.

### 13.7 Why this is optimal (adversarial review)
- **Wipe+re-pair isn't just simpler, it's more SECURE than a silent DIK self-heal.** Self-heal would
  bolt a DIK onto a device that was TOFU-paired (no proof at pairing) — grandfathering an unproven
  identity into the "proven" model. Re-`sc login` re-establishes the device under the §12 device-flow
  with PoP, so every post-cut identity is proven-from-birth. (For agents there is no silent option at
  all — an agent can't self-mint an authorized AIK without a UIK-signed ceremony — so re-pair is
  forced there regardless; doing devices the same way keeps ONE model, not two.)
- **Do the cut PRE-LAUNCH.** The re-pair cost scales with entities-per-user; pre-launch that's a
  handful. Cutting now means every *launched* user starts on the new model and never faces a
  migration — the cost is only ever paid by today's tiny dogfood population. Post-launch this same hard
  cut would be a coordinated fleet event; now it's free. This is the decisive timing argument.
- **Rejected alternatives:** (a) in-place AIK/DIK upgrade — most code, must graft keypairs onto
  existing identities + re-authorize, and still leaves TOFU grandfathering; (b) silent DIK self-heal —
  zero friction but grandfathers unproven devices AND has no agent analogue, so you'd ship two
  divergent migration models; (c) do nothing / dual-auth forever — the census never drains, the compat
  is immortal, the wave never closes (the status quo this doc kills).
- **Residual honest costs:** an agent cut mid-task breaks (message clearly; it rides a deliberate
  upgrade window). UIK is one tap per passkey per device (§13.5, crypto-bound — not a UI choice); the
  UX sells clarity, not a false "one click for all".
- **Verdict:** optimal for the pre-launch window; **fully settled, no open questions** (§13.5 resolved
  2026-08-20). Net effect on the codebase is *negative* lines (delete 5 compat rows) — the tell that
  the direction is right.

## 14. Agent admission = browser-confirm ceremony (LOCKED 2026-08-21, user-approved · Option A)

**The gap (user-caught).** `sc agent add` on a paired device SILENTLY registers a new agent to the
account roster — `handleCreateAgent` (`vault-routes.mjs:1458`) auths on `agentMgmtAccount` (session OR
**device-key**) and just `generateApiKey`s it. No owner browser-confirm. That contradicts §12.1's
principle ("every new agent, even via a trusted device, goes through browser pairing confirmation" —
the ONE primitive). The Agents-tab toggle is only the per-VAULT access control, not the ADMISSION
authorization. Not a hard hole today (an un-toggled agent is inert), but the model is wrong and
sharpens to a hole under any auto-authorize (§11.4).

**Why the original "elegant handoff" (§12 build) got this wrong.** It CONFLATED two layers that are
crypto-distinct:
- **Admission** (account roster: the agent `api_keys` row + registered AIK pubkey) = server-side,
  needs **NO K**.
- **Vault access** (E2E UIK-signed `aux:agent/<ag_id>`) = needs **K** (the Agents-tab toggle).
Believing admission also needed K (which /pair lacks), it shortcut admission to the silent device-key
path. **Splitting them is the fix:** /pair does admission (session-auth, no K); the toggle keeps vault
authz (K). This also retires the "can't sign at /pair" objection that drove the handoff.

**Option A (chosen) — the ONE primitive: `sc agent add` runs the device-flow /pair ceremony.**
1. `sc agent add <name>` mints the AIK (as now) → instead of the silent `POST /api/vault/agents`,
   initiates `POST /api/pair/authorize` with `{principal:'agent', agent_name, agent_pubkey}` → gets
   device_code + user_code + /pair link → prints code+link → polls `/api/pair/poll` (like `sc login`).
2. The agent is **pending** (NOT admitted; not in the active roster; not vault-toggle-able).
3. Owner opens /pair → the page renders **"Authorize agent `<name>`"** (principal=agent, vs "Connect
   device") → approves. **Session-auth, NO passkey/K** (admission is a roster entry).
4. Approve → backend admits it (creates the agent `api_keys` row via `generateApiKey` with the AIK) →
   poll returns → `sc agent add` completes (prints env).
5. Admitted agent now appears in Agents tab → owner toggles vault access (K-signed, **unchanged**).

Two clean gates: **admission = browser-confirm (session)**, **vault access = toggle (K)**. "Only an
admitted agent reaches the vault toggle" — the user's requirement.

**Reuse (extend, not rebuild):** `/api/pair/*` + `/pair` page + poll + `device_pairings` table +
`sc login`'s device_flow_pair scaffolding all carry over; add a `principal` discriminator (device |
agent) end-to-end.

**Build list:**
1. **BE:** `/api/pair/authorize` accepts `principal:'agent'` (+ agent_name, agent_pubkey) → pending row
   (reuse `device_pairings` + a `principal` column, or a sibling). `/api/pair/lookup` returns principal
   + name so /pair renders the right copy. `/api/pair/approve` for an agent = session-auth admit:
   `generateApiKey({tier:'agent', sig_pub, identity_id})`, return token to the poller. `/api/pair/poll`
   returns the agent token on approval. **Retire/gate** `handleCreateAgent`'s silent path.
2. **Core:** `sc agent add` → mint AIK → `/api/pair/authorize (principal=agent)` → print code+link →
   poll → on approved, persist AIK + print env. (Mirrors `device_flow_pair`.)
3. **FE:** `/pair` handles principal=agent (title "Authorize agent <name>", approve = admit, no
   vault-pick required for admission). Agents tab shows only ADMITTED agents (pending ones aren't
   toggle-able).

**Locked decisions** [⚠️ PARTIALLY SUPERSEDED 2026-08-21 by §15 — admission is upgraded from
session-auth to **owner-UIK-signed** (for symmetry with revoke + so the daemon can verify it). §14's
real invariant ("admission needs NO vault-K") STANDS: the UIK is the owner's account identity, not any
vault's K. Only "session-auth, no signature" is revised. Everything else here (two-step admission ≠
vault-access, ONE /pair primitive, never auto-admit) stands and ships as-is for launch]**:** admission
= session-auth (no K); vault access = K-toggle (unchanged); agent uses
the SAME /pair ceremony as device (ONE primitive); v1 may confirm each principal separately (combined
device+first-agent multi-principal approval page = later nicety); NEVER auto-admit (retire §11.4
auto-authorize). **Non-goal:** admission granting vault access automatically (strictly two steps).

---

## §15. Account principal ledger + universal revocation-drop (design 2026-08-21, UNBUILT)

**Principle.** Owner decisions over the account's *principals* (devices, agents) — both ADMIT (pair /
`sc agent add`) and REVOKE — are **owner-signed** and, while the target is online, **enforced locally**:
a revoked device/agent loses the ability to use secrets. This is a UNIVERSAL invariant, not a team
privilege. Scope: the online case (a reachable daemon syncs the signed removal and acts). A
deliberately-offline device is out of scope (inherent: its disk is unreachable; K is memory-only +
re-lock on restart is the residual mitigation, plus the team offline-lease where it applies).

**Two crypto-distinct layers, both owner-signed (this is the whole model):**

| Layer | What it authorizes | Channel | Signer / anchor | Revoke → daemon does |
|---|---|---|---|---|
| **Account admission** | device/agent is a principal of the ACCOUNT | NEW account principal ledger | owner **UIK**, anchored to a per-account TOFU-pinned owner-UIK root | device `−` → LOCK + WIPE **all** vaults + logout; agent `−` → global broker reject |
| **Per-vault access** | principal may use vault Y | per-vault (authorized-agents for agents; passkey-membership for devices) | **K** (per-vault, existing genesis anchor) | remove → drop **that one** vault |

**Pair and revoke are the two ends of ONE account-level lifecycle → design them together, symmetric.**
The account principal ledger is an append-only, owner-UIK-signed log: `+device D` / `−device D` /
`+agent A` / `−agent A`. Pair = signed `+`, revoke = signed `−`, same anchor, same verify. This
SUPERSEDES §14's session-only admission: /pair approval becomes an owner passkey signature (UIK), not a
session click. Cost: one extra tap at /pair. Win: a stolen session can no longer admit a rogue
principal or revoke your devices (DoS), and the roster is daemon-verifiable — which is what makes
revoke enforceable.

**The missing primitive = an ACCOUNT-level trust anchor.** Today every owner-signed authz is per-vault
(anchored to that vault's creator UIK genesis). Devices/agents are account-scoped and must be
revocable even with 0 vaults, so they cannot ride a per-vault anchor. Fix: TOFU-pin the account
owner's UIK pubkey as an account trust root at first pair (mirrors the per-vault genesis-anchor
pattern, lifted to account scope). Everything else reuses the proven per-vault delegation-log
machinery (domain-separated Ed25519 inputs, append-only signed log, daemon fold + sidecar verify),
just at account scope.

**Per-vault drop (the SECOND primitive) is a two-authoring / one-reaction shape.**
- Two authoring actions, different scope: **delete-vault** = account-wide tombstone (vault gone for
  everyone); **offboard-member** = single-member removal (vault stays for others). "team removes user
  from vault" ≡ "user deletes own personal vault" — both are a vault-owner-signed "access to vault Y is
  gone."
- ONE daemon reaction: *verify a vault-owner-signed "vault Y access gone" → actively LOCK + WIPE vault
  Y locally.* Team already has the reactive half via membership-loss (the removed member's daemon stops
  serving); GAPS to close: (a) the vault-DELETE tombstone is currently UNSIGNED server cleartext
  (`sync.rs` acts on `status:"deleted"` before the signed-envelope check) — sign it; (b) upgrade
  "stops serving" to "actively LOCK + WIPE"; (c) extend to personal vaults.
- **agent** revoke by a team = per-vault MASK/block only (the agent is its user's account asset; a team
  cannot destroy another account's agent). Global agent revoke (`sc agent rm`) is the account layer.

**Delivery-before-hard-kill (sequencing).** For an online target to VERIFY its own revocation and
self-drop, the signed `−` must reach it over a channel it can still sync. So: publish the owner-signed
removal → target pulls + verifies + drops → THEN hard-kill its device-key. Killing the key first only
yields a bare 401, which today (correctly, to survive transient backend 403s) PARKS and does not drop —
so a key-kill alone must NOT be relied on for enforcement.

**Already shipped (rc.9, the small clear pieces):** `sc logout` now (a) stops the daemon on macOS too
(previously Linux-only → a mac self-logout left the daemon serving), and (b) wipes local
`<state_dir>/vaults/`. So self-unpair already enforces "this machine can't use secrets."

**Scope / sequencing.** Current §14 session-admission SHIPS for launch (low-stakes roster, inert until
vault-toggled). The signed account principal ledger + universal revocation-drop is a dedicated
POST-LAUNCH wave (new account anchor + ledger + daemon account-ledger sync/verify/drop + /pair
admission becomes UIK-signed + sign the vault-delete tombstone). Design-lock this section first, then
build.

**Non-goals:** enforcing against a deliberately-offline device (inherent limit); admission granting
vault access (still strictly two steps, §14 stands); a per-vault fan-out for device revoke (rejected —
device revoke is an account fact, must work with 0 vaults). See
[[project_agent_device_identity_mtls]], [[project_vault_auto_discovery]],
[[project_team_edition_design]].
