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
