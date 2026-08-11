# Compat sunset — what to delete once all users have upgraded

Short ledger of **intentional backward-compat** kept live during the identity wave /
甲 / team rollout. Each row is dead weight to remove **after its trigger fires** — NOT
before (removing early drops protection for un-upgraded clients). Pairs with
`../../IDENTITY_WAVE_BUILD_LOG.md` → JOINT E2E PLAN + RESIDUE SWEEP.

Repos: `core` = safeclaw/ · `be` = safeclaw-pro-backend/ · `fe` = safeclaw-pro-frontend/.

| # | Compat kept | Why kept | Delete trigger | Where (repo:paths) |
|---|---|---|---|---|
| 1 | **Dual-window agent-id keying `identity_id \|\| prefix`** (and `?? prefix`) | legacy api-key agents have no `ag_`/`identity_id` yet | agent census: every agent has minted an AIK (`identity_id` non-null) | fe: `tab-agents.tsx` grantKey, `connections-tab.tsx` selKey, `team-dashboard.tsx` agentMap · core: `state.rs` mask consult legacy-prefix branch |
| 2 | **hop-A legacy Basic api-key** — now serves ONLY legacy DIRECT (non-shim) agents. The shim path is api-key-free (CONNECT was always PoP-only; api-face + forward moved off the key in slice 4, `60a9629`). Remaining: proxy-auth fallback for direct agents + key in env on the non-shim path + `sc agent add` prints it | AIK PoP path is opt-in until every agent has an authorized AIK | DIRECT-agent census → 0, then fail-closed flip (AIK sole path); needs the authorize-AIK UX first (§11.4/§B) | core: `api_key.rs`, `proxy/handler.rs` `key_is_valid` else-branch + `api_face.rs::require_agent` legacy branch, `cli/agent.rs` env print, `cli/run.rs` direct (non-shim) path |
| 3 | **hop-B legacy device bearer** (`.bearer_auth(dk)` alongside `dik_pop`; backend accepts bearer) | DIK PoP is additive/compute-only until enforced | bump `MIN_TEAM_DAEMON_VERSION` → enforce DIK; flip `SC_DEVICE_SIG_AUDIT` from audit to reject | core: `sync.rs`/`relay/client.rs`/`sync_stream.rs` bearer sites · be: `vault-routes.mjs` `resolveAuth` bearer path + `deviceSigVerdict` (audit→enforce) |
| 4 | **config-sig record fallback + `vault_config_ids` registry gate** | pre-甲 owner-config protection, belt-and-suspenders with `recordWriteGate` | 甲 cutover: bump gate → require item-sig | core: `storage/sealed_vault.rs` config-sig fold fallback + `unwrap_verified_config`/`unwrap_verified_agent_grant` config-sig arms · be: `vault-routes.mjs` `handleConfigIdsRegister` + `/config-ids` route + `team.registerConfigIds`/`isConfigId` + `vault_config_ids` table · core daemon: `sync.rs` `/config-ids` POST in `deliver_team_marks` |
| 5 | **NoUik / fmt1-personal unsigned path** (unsigned records honored; `vault_keys` /keys path; `vault_keys.author_account_id` write-only col) | pre-team prod = single-user fmt1 personal vaults | fmt1 census → 0 (task B1b) | core: NoUik trust / unsigned-honored fold arms · be: `vault-routes.mjs` fmt=1 `/keys` path + `author_account_id` write; drop the column |
| 6 | **`~/.safeclaw/device-key` alongside the DIK identity file** | device migrates to a keypair; both live during rollout | after DIK is the sole device auth (with #3) | core: `sync.rs::device_key`, `cli/login.rs` device-key write, `cli/logout.rs` |
| 7 | **`SC_DEVICE_SIG_AUDIT` compute-only flag** | validate hop-B parity over the real wire before enforcing | when #3 enforces (audit becomes the gate) | be: `vault-routes.mjs` `resolveAuth` audit block + `keyset-roles.mjs::deviceSigVerdict` |

## Pre-existing tech-debt (optional, not rollout-gated)
- **`now_unix` sprawl:** identity-wave copies now share `core:util.rs::now_unix`, but pre-existing
  named copies remain (`store/adapters/gcp.rs`, `storage/pending_passkey.rs`, `cli/webauthn.rs`[pub])
  plus ~40 inline `SystemTime::now().duration_since(UNIX_EPOCH)` idioms. Fold into `crate::util::now_unix`
  opportunistically; no rollout dependency.

## Discipline
Nothing here is removed on a hunch — each waits for its trigger. When a trigger fires, delete the row's
code + this row together, and re-run the green gates for the touched repos.
