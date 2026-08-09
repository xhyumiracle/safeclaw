# Requestor Identity — mutual mTLS for Agent (AIK) & Device (DIK)

**Status: DESIGN LOCKED (2026-08-09, user-approved). SSOT for the identity-upgrade wave.**
One coherent wave: replace the two BEARER credentials (agent api-key, device pair token) with
possession-proven **keypair identities**, verified by **mutual mTLS**, symmetric in naming /
paths / lifecycle. No loose ends, no half-migration. Code AFTER this doc.

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

The mask is enforced on the agent's **owner-member's own daemon** (which holds that member's K),
so an agent's reach is **always ⊆ its owner-member** — it can never escalate. Therefore:
1. **Account layer: the agent exists** (mint/revoke the AIK; account-wide). Irreducible.
2. **Vault layer: ONE grant per (agent, vault) = its reach here.** "Admission" and "mask" are the
   SAME grant object, not two layers: **present = admitted (whitelist, fail-closed → clean revoke);
   the grant's deny-list = which connections (new ones stay open for an admitted agent).**

- **Who authorizes:** a **member self-authorizes their OWN agents** (safe — agent ⊆ that member,
  grants nothing new); an **owner** can admit/revoke ANY agent + override masks.
- **Storage:** the grant lives in the E2E vault, **one current-state record per agent** (NOT an
  append-only per-action log — that was wrongly copied from the owner delegation log; the owner
  log guards K, agent grants don't). Per-agent signing is OPTIONAL hardening (least-privilege
  integrity vs a co-member), NOT a boundary; **v1 unsigned E2E is fine** (bounded by agent ⊆ member).
- **Revoke = drop the grant. NO re-key** (the agent never held K). Contrast member offboard (re-keys).

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
