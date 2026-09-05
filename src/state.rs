//! Top-level application state.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

use crate::approval::ApprovalStore;
use crate::audit::AuditRegistry;
use crate::config::Config;
use crate::passkey::challenge::ChallengeStore;
use crate::service::ServiceRegistry;
use crate::storage::VaultDir;

/// Broadcast payload for the per-vault SSE channel. The receiver-side filter
/// is on `vault_id`; subscribers belonging to other vaults drop the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalEvent {
    pub vault_id: String,
    pub approval_id: String,
    /// One of "pending" | "approved" | "rejected".
    pub kind: String,
    /// Summary of the approved Operation (act.kind, target, scope) — present
    /// for pending. Frontend uses it to render the request card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_summary: Option<Value>,
    /// Cached upstream response for broker (Use) approvals after approve —
    /// `{status, headers, body, body_base64}` JSON. Present for approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_preview: Option<Value>,
    /// Rejection reason — present for rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Broadcast channel capacity. Lagging subscribers (typically tabs sleeping
/// in a background pinch) will drop events older than this — they reconnect
/// fresh and lose history, which is acceptable for a watcher UI.
const EVENT_CHANNEL_CAPACITY: usize = 128;

// ── Vault state (H3 / PROTOCOL.md §6.3) ──────────────────────────────────────
//
// Per-vault runtime state. Daemon boots Locked; user runs the SUDP
// `Custom("vault-unlock")` op to transition Unlocked (and side-effect a
// per-service secrets_cache bootstrap for `allow`-policy services). No auto-
// lock timer — that would break the `allow` invariant ("once unlocked, no
// further friction during the session"). Lock is always user-initiated via
// `Custom("vault-lock")` op.

/// A cached secret value with optional expiry. Per PROTOCOL.md §6.2,
/// memory residence is policy-driven:
///   - `allow` services → `expires_at = None` (lives the whole unlocked
///     session, populated at unlock bootstrap)
///   - `ask` services → `expires_at = Some(unix_secs)`, filled after
///     `approval-confirm` with the matched rule's `ttl`
///   - `ask-always` services → never in `entries`; their one-shot grants
///     live in `op_grants`, keyed by the approved request tuple
///
/// `cache_lookup` does lazy eviction: an entry past its `expires_at`
/// is removed and treated as a miss. No active sweeper today —
/// expired bytes linger in memory until the next lookup, which is
/// acceptable since the daemon already holds plaintexts for all
/// allow-level services anyway.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub value: Vec<u8>,
    /// `None` = never expires within the unlocked session (allow-level).
    /// `Some(t)` = expires at unix-second `t` (ask-level TTL).
    pub expires_at: Option<u64>,
    /// `true` = this value was pre-loaded at unlock by `bootstrap_cache_from_view`
    /// (the connection's read floor is `allow`), NOT produced by a passkey grant.
    /// The allow fast-path (`cache_lookup`) uses it, but the `ask` path
    /// (`cache_lookup_grant`) must IGNORE it — a per-path ask rule has to
    /// force a fresh approval, never ride the allow-level residency. (The
    /// ask-always path never reads `entries` at all — see `op_grants`.) A real
    /// grant (from `approve_op`) overwrites it with `from_bootstrap = false`.
    pub from_bootstrap: bool,
    /// Op-agent binding (team §C1): for a GRANT entry, the prefix of the agent
    /// key the approval was minted for — `cache_lookup_grant` misses for any
    /// other agent. `None` on bootstrap/residency entries (allow-level values
    /// are not approvals; any policy-allowed agent may use them).
    pub agent_prefix: Option<String>,
}

/// How long an approved `ask-always` one-shot grant stays redeemable
/// (`op_grants` expiry = approve-time + this). Generous on purpose: the
/// replay is agent-driven, and an agent that only acts when its user next
/// prompts it can take many minutes. Safety comes from single-use + exact
/// request binding, not from this window.
pub const ASK_ALWAYS_REPLAY_WINDOW_SECS: u64 = 1800;

#[derive(Debug, Clone, Default)]
pub struct SecretsCache {
    /// service_id → cached auth value with per-entry expiry. Filled by:
    ///   - unlock bootstrap (only services whose default read level is
    ///     `allow` — see `bootstrap_cache_from_view`)
    ///   - post-approval insert from `approve_op` for `ask` and `allow`-
    ///     cache-miss paths (the secret was fresh-decrypted under the
    ///     grant's W_c during forward; we re-use it for subsequent
    ///     requests up to the policy TTL).
    /// `ask-always` services are deliberately absent (PROTOCOL.md §6.2
    /// "ask-always 服务: 永不进 cache").
    pub entries: HashMap<String, CacheEntry>,
    /// service_id → { secret_name → bytes } for every direct secret an
    /// `allow`-level service references. Populated at unlock bootstrap so the
    /// allow fast-path can resolve *multi-secret* services (e.g. a Twilio-style
    /// `account_sid` + `auth_token` pair) without a vault view — which only
    /// exists behind a fresh grant. Single-secret services get a one-entry
    /// map; oauth services get no entry (their token comes from `oauth_access`).
    /// Lives the whole unlocked session (allow semantics); wiped on lock.
    pub allow_secrets: HashMap<String, HashMap<String, Vec<u8>>>,
    /// The effective policy tree — the vault's `aux.policy` overlaid on the
    /// compiled-in `Policy::default()` at unlock/refresh (so unset parts use
    /// safe defaults). Holds default floors, per-tag, and per-connection
    /// user policy. Built-in per-service rules are NOT cached here — they're
    /// read live from the service registry at eval and merged with this tree's
    /// `connections.<id>.rules`. Rebuilt on every vault write → a policy edit is
    /// realtime on the next request.
    pub policy: crate::core::policy::Policy,
    /// Audit log retention in days. Snapshot of `aux.audit_retention_days`
    /// at unlock. `None` = keep forever. Used by `GET /v/{vid}/approvals` to
    /// opportunistically prune old rows before listing.
    pub audit_retention_days: Option<u32>,
    /// Honors the `ask` (vs `ask-always`) semantic: after the user approves
    /// an Ask-level op, the daemon caches the approval so subsequent
    /// requests *of the same scope* within the TTL fast-path without
    /// re-prompting. `ask-always` never lands here; `allow` doesn't need it.
    ///
    /// Key shape: `(agent_prefix, connection_id, rule_id, method, host)`. The
    /// grant is bound to:
    ///   - the **agent** that triggered the approved op (op-agent binding,
    ///     team §C1) — agent A's approved ask never fast-paths agent B's
    ///     identical request inside the window;
    ///   - the **connection** — approving account A's send never fast-paths B;
    ///   - the matched **policy rule** — which carries the path scope, so a
    ///     grant can never reach beyond the rule the user's approval matched;
    ///   - the **HTTP method** — so approving a read (GET) never silently
    ///     authorizes a later write (POST/DELETE) inside the window;
    ///   - the resolved **destination host** — an approval for host A must not
    ///     authorize host B within the TTL (host is request data in the
    ///     phantom-only model: one connection may anchor several hosts).
    /// A tag-/connection-default Ask (no rule matched) is deliberately
    /// **not cached** — it has no author-defined path scope to bound a grant,
    /// so it re-prompts every request. Value: Unix-epoch-second expiry.
    ///
    /// Lives in the same memory window as the rest of the cache: dropped on
    /// lock (which zero-outs the entire cache via Default drop). Daemon
    /// restart also blows it away (vaults boot Locked, cache starts empty).
    pub rule_approvals: HashMap<(String, String, String, String, String), u64>,
    /// `ask-always` one-shot grants, keyed by the REQUEST the user approved:
    /// `(agent_prefix, connection_id, method, host, path, scope_digest)` —
    /// agent-bound like `rule_approvals` (a grant minted for agent A's request
    /// cannot be spent by agent B). Written by
    /// `approve_op` when the op's policy level was AskAlways; consumed (removed)
    /// by the proxy's replay exactly once. This is what makes an `ask-always`
    /// approval mean "this action, once": a grant minted for `POST /v2/purchase`
    /// can never be spent by a different method/host/path on the same
    /// connection, and the ask-always path never falls back to the conn-keyed
    /// `entries` (so it can't ride a plain-ask leftover or the allow residency).
    ///
    /// `scope_digest` (Phase 2) folds the values of the service's declared
    /// `[requests]` scope fields into the identity (`""` when a service declares
    /// none — the Phase-1 path-only key). So approving `amount=80` cannot be
    /// replayed as `amount=180`: the redeem re-extracts the fields, the digest
    /// differs, the grant misses (without being consumed) and re-prompts. See
    /// `crate::service::scope_digest` and design/request-scope.md.
    ///
    /// Expiry is deliberately GENEROUS (`ASK_ALWAYS_REPLAY_WINDOW_SECS`, not a
    /// short grace): an agent that only replays when its user next prompts it
    /// (e.g. a chat agent) may take minutes to re-run. Single-use + exact
    /// binding is what makes the long window safe — time is not the guard.
    /// Same memory window as the rest of the cache: dropped on lock/refresh.
    pub op_grants: HashMap<(String, String, String, String, String, String), CacheEntry>,
    /// Item names present in the decrypted `native-secrets` kv (names only,
    /// never values). Surface for `GET /v/{vid}/secret-keys` so the frontend
    /// can decide which services are "reachable" without paying for an
    /// external-store roundtrip. Populated at unlock; cleared on lock.
    pub native_keys: HashSet<String>,
    /// External stores' LIVE adapters, built once at unlock so `list()`
    /// (`GET /v/{vid}/secret-keys`) and the allow-path lazy fill
    /// (`lazy_fill_external`) can call out without re-decrypting the vault.
    /// Sharing one instance per store for the whole unlocked session is
    /// what makes the adapter's internal OAuth-token cache real (a fresh
    /// instance per call re-mints every time). Sparse — only kinds with an
    /// adapter (today: gcp-secret-manager) populate.
    ///
    /// F-19: the adapter owns the SA private key and zeroizes it on drop,
    /// so lock still scrubs the credential with the rest of the cache.
    pub external_stores:
        HashMap<String, (crate::storage::plaintext::Store, Arc<crate::store::Adapter>)>,
    /// `aux.store_order` filtered to the stores present in
    /// `external_stores`, preserving the vault's resolution order. The lazy
    /// fill walks THIS (first match wins) so external residency can never
    /// disagree with `resolve_value_async`'s store_order semantics.
    pub external_store_order: Vec<String>,
    /// External stores that FAILED to materialise at unlock (bad SA JSON,
    /// missing credentials_item, …): `store_id → sanitised reason`. Fail
    /// loudly: `secret-keys` surfaces these as `store_errors` so a
    /// misconfigured store shows up broken in the console instead of
    /// silently vanishing. Full error goes to the daemon log only (F-20).
    pub external_store_errors: Vec<(String, String)>,
    /// Key NAMES the external stores expose, enumerated in the background
    /// right after unlock (`unlock_vault` spawns one `list()` sweep) and
    /// amended by every successful lazy fill. Registry `connected` and the
    /// `entries` listing read native ∪ THIS, so an external-backed
    /// connection looks connected to agents. Shared slot (`Arc<Mutex<…>>`)
    /// so the background sweep can write back without re-entering the
    /// vault-states lock; names only, never values. Advisory — resolution
    /// authority stays with the adapters (a name missing here still
    /// lazy-fills; a stale name here just shows optimistic status).
    pub external_keys: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// Derived OAuth access_tokens, keyed by service_id. These are the
    /// short-lived bearer values minted by exchanging the long-lived
    /// `refresh_token` (which lives in `entries`) at the provider's
    /// /token endpoint. **Never persisted to vault** — the design says
    /// only the immutable refresh_token enters the vault; the
    /// access_token is derived state that's allowed to evaporate on
    /// lock / daemon restart (next /use just re-mints it).
    ///
    /// `expires_at` tracks the provider-reported expiry (with a 60s
    /// safety margin baked in at insert time). `cache_lookup`'s
    /// generic eviction doesn't apply here — `oauth_access_lookup`
    /// has its own lazy eviction below.
    ///
    /// Keyed by **`sha256(refresh_token)`** hex (§5): the access token is a pure
    /// function of the refresh token, so keying on the INPUT auto-invalidates on
    /// reconnect / refresh rotation (new refresh → natural miss → fresh mint) and
    /// two accounts never collide for free (different refresh → different key).
    pub oauth_access: HashMap<String, CacheEntry>,
    /// Routing snapshot: `connection_id → { service, hosts }`, taken from
    /// `aux.connections` at unlock (CONNECTION_SCHEMA.md §6). A brokered request
    /// resolves its connection's service through this map (falling back to
    /// `conn` itself when absent — an unconnected service IS its own default
    /// connection). Wiped on lock.
    ///
    /// NOTE on the maps above (`entries`, `allow_secrets`, `oauth_access`,
    /// `rule_approvals`): the daemon keys them by **connection_id**, so two
    /// connections of one service never share a cache slot. Policy is likewise
    /// per-connection (`policy.connections.<id>`), while the built-in rules it
    /// merges come from the shared service definition.
    pub connections: HashMap<String, crate::storage::plaintext::Connection>,
    /// The vault's **authorized-agents table** (design §11.1), keyed by `ag_id`
    /// (`derive_id(Agent, pubkey)`). Snapshot of `view.aux.agents` at
    /// unlock/refresh. **Presence = authorized**; an `ag_id` with no entry is not
    /// in the table. Consulted ONLY on the AIK (PoP) path where the daemon knows
    /// the presented `ag_id`; the legacy Basic api-key path (dual-auth window)
    /// carries an api-key prefix, which is never in this `ag_`-keyed table → the
    /// mask lookup misses → the caller falls to the legacy allow (nothing bricks
    /// until bearers retire).
    pub agents: std::collections::BTreeMap<String, crate::storage::plaintext::AgentEntry>,
    /// Custom (per-vault `aux.services`) service definitions, validated at
    /// unlock. Wiped on lock (Default drop). A custom service folds into
    /// discovery like a compiled one and never shadows a built-in id.
    pub custom_services: HashMap<String, crate::service::ServiceDef>,
}

#[derive(Debug)]
pub enum VaultState {
    Locked,
    Unlocked {
        cache: SecretsCache,
        /// Retained state key `K` (zeroized on drop). Held for the unlocked
        /// session so a sealed blob pulled from cloud sync can be re-decrypted
        /// and the cache refreshed WITHOUT another passkey (Slice 3 realtime
        /// sync — matches 1Password's "vault key resident while unlocked").
        /// Dropped (wiped) on lock/delete along with the rest of this variant.
        state_key: zeroize::Zeroizing<Vec<u8>>,
        /// Unix epoch seconds when this Unlocked state began. Informational
        /// only today (no auto-lock); kept for future audit / debug.
        #[allow(dead_code)]
        unlocked_at: u64,
    },
}

/// A loopback OAuth connect awaiting its `?code&state` redirect. Points a
/// pending `state` (RFC 6749) at the (vault, connection) whose sealed
/// `connecting` entry holds the matching code_verifier, and carries the
/// loopback PORT its provider will redirect to (allowlist-checked at
/// registration — `ServiceRegistry::loopback_allowlist`): 8765 for the
/// canonical callback, 1455 for openai_codex's registered one.
#[derive(Clone)]
pub struct PendingLoopback {
    pub vault_id: String,
    pub conn_id: String,
    pub port: u16,
    inserted_at: std::time::Instant,
}

pub struct AppState {
    pub config: Config,
    pub vaults: VaultDir,
    /// Last successful cloud contact per vault (unlock initialises, sync
    /// successes refresh). Drives the shared-vault offline lease (team §7.5):
    /// a daemon cut off from the cloud — network loss OR revoked/offboarded
    /// credentials parking its sync — keeps serving a SHARED vault only for
    /// the lease window.
    pub cloud_contact: Mutex<HashMap<String, std::time::Instant>>,
    /// Server-authoritative vault sharedness (team §4: explicit `kind`, default
    /// private), delivered on the `/blob` sync envelope OUTSIDE the sealed body —
    /// `kind` is a server operational fact, never E2E. `true` = shared, `false` =
    /// private; an ABSENT entry (never synced, or an old server that omits the
    /// field) reads as private via `vault_is_shared` — the fail-safe default so a
    /// personal vault (and any pre-sync state) is never leased. Supersedes the old
    /// "derive shared from the E2E members map" heuristic (review H1). In-memory
    /// only, repopulated on each pull — same restart-softness as `cloud_contact`,
    /// which the offline lease already accepts (it is a soft backstop).
    pub vault_shared: Mutex<HashMap<String, bool>>,
    /// Vaults whose cloud sync returned `SC_UPGRADE_REQUIRED` — this daemon is too
    /// old for their (newer) item format (design 甲). While set, the broker refuses
    /// with [`crate::error::ScCode::UpgradeRequired`] so the AGENT gets an actionable
    /// "run `sc upgrade`" instead of a silent parked-sync failure. In-memory only,
    /// (re)set by the sync path; cleared when a sync succeeds again.
    pub vault_upgrade_required: Mutex<std::collections::HashSet<String>>,
    /// Team-edition extension hooks (team-edition §9 open/closed split). The
    /// open build leaves the [`crate::team_hooks::NoopHooks`] default (no team
    /// policy); the closed `safeclaw-ee` overlay injects real ones via
    /// [`AppState::with_team_hooks`]. Serve-time team policy (the offline lease,
    /// etc.) lives behind these, never inline in open core.
    pub team: std::sync::Arc<dyn crate::team_hooks::TeamHooks>,
    /// Vaults whose addressing migration completed locally but whose cloud
    /// `format=2` mark hasn't landed yet — the sync loop drains this after a
    /// successful item push (团队 §8.3: mark only after the rows are up).
    pub pending_format_mark: Mutex<std::collections::HashSet<String>>,
    /// Owner lock-list registrations awaiting delivery: vault → blinded ids of
    /// the config singletons (computed at unlock while K was in hand; the sync
    /// loop POSTs them once for SHARED vaults). §5.15 two-tier write model.
    pub pending_config_ids: Mutex<HashMap<String, Vec<String>>>,
    pub challenges: Mutex<ChallengeStore>,
    pub approvals: Mutex<ApprovalStore>,
    pub services: ServiceRegistry,
    pub events: broadcast::Sender<ApprovalEvent>,
    /// Per-vault Locked/Unlocked state. Absent entry = Locked. Lives entirely
    /// in process memory; daemon restart returns all vaults to Locked.
    pub vault_states: Mutex<HashMap<String, VaultState>>,
    /// The hosts each vault anchored the last time it was seen Unlocked
    /// (lowercased, refreshed on every union pass). Kept ACROSS Lock so the
    /// proxy still recognizes — and MITMs — brokered-host traffic while the
    /// vault is locked: a phantom then meets an explicit `vault_locked`
    /// instead of leaking upstream through a blind tunnel. Connections live in
    /// the sealed blob, so this memory is the only locked-time anchor
    /// knowledge; in-memory only (a daemon restarted before any unlock stays
    /// blind, the documented residual), dropped when the vault is deleted.
    /// Lock order: always `vault_states` first, then this.
    pub last_host_unions: Mutex<HashMap<String, Vec<String>>>,
    /// Per-vault audit log (PROTOCOL.md §5.3). Connections opened lazily on
    /// first write/query per vault. Survives daemon restarts — unlike
    /// `approvals` / `vault_states` which are in-memory only.
    pub audits: AuditRegistry,
    /// Daemon HPKE outer-envelope keypair (PROTOCOL.md §4.2.1 M1). Loaded
    /// once at startup, used to open pending-passkey seals (cross-device
    /// add-passkey) and — in future — `[HPKE: MUST]` grant submissions.
    pub sc: crate::crypto::envelope::ScKeyPair,
    /// Per-vault async mutex serializing vault.dat read-modify-write cycles.
    /// Two concurrent approve calls on the same vault both read the pre-write
    /// state and race to rename the tmpfile — the second write wins silently.
    /// Holding this lock for the full approve lifetime prevents that race.
    /// Uses tokio::sync::Mutex so it can be held across await points.
    pub vault_write_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Per-vault SSE connection semaphore (cap = MAX_SSE_PER_VAULT).
    /// OwnedSemaphorePermit is stored in each live stream; dropping the
    /// stream drops the permit, automatically releasing the slot.
    pub sse_semaphores: Mutex<HashMap<String, Arc<tokio::sync::Semaphore>>>,
    /// Account-level set of broker-authorizing agent-key HASHES (sha256 hex),
    /// synced from the cloud (`/api/vault/agents/hashes`). This is the SOLE
    /// broker auth (agent ≡ api-key): a presented key is valid iff sha256(key)
    /// is a member. Empty ⇒ reject (a paired daemon requires an agent key; an
    /// unpaired/local-only daemon has no broker plane to gate). See
    /// [[project_vault_agent_architecture_2026_06_25]].
    pub agent_key_hashes: Mutex<std::collections::HashSet<String>>,
    /// Serializer + debounce stamp for the on-auth-miss hash refresh
    /// (`sync::refresh_agent_keys_on_miss`): a key minted seconds ago
    /// (`sc agent add` → immediate use) must not wait out the 30s sync loop,
    /// but a bad-key flood must not hammer the backend either. tokio Mutex —
    /// held ACROSS the refresh fetch so concurrent misses wait for the
    /// in-flight result instead of being bounced to a reject.
    pub agent_key_resync: tokio::sync::Mutex<Option<std::time::Instant>>,
    /// Single-flight for the allow-path external-store lazy fill
    /// (`lazy_fill_external`): a burst of first requests on a GCP-backed
    /// connection must resolve ONCE, not once per request. tokio Mutex —
    /// held across the store round-trip so concurrent misses wait for the
    /// in-flight fill and then hit the cache on their re-check.
    pub external_fill_lock: tokio::sync::Mutex<()>,
    /// OAuth connections whose refresh_token was rejected (`invalid_grant`) at
    /// /use — surfaced via `/registry` as `needs_reauth` so the console prompts a
    /// reconnect. Keyed by `(vault_id, connection_id)`. In-memory + self-healing:
    /// cleared on a successful refresh or a fresh connect; a still-dead token
    /// re-marks on the next use.
    pub oauth_reauth_needed: Mutex<std::collections::HashSet<(String, String)>>,
    /// Authorization codes this daemon has already REDEEMED (sha256-hex → when).
    /// An OAuth code is single-use: a stale write (a buggy web Save, a
    /// cross-device echo, or a pull that re-introduces the `connecting` entry
    /// before our success push lands) can resurrect a code we already consumed.
    /// Re-exchanging it earns `invalid_grant`, which the connect state machine
    /// would misread as a terminal failure and use to clobber the live
    /// connection. This is the idempotency key: skip any code already here.
    /// Daemon-local + NEVER synced (so no stale write can revert it); in-memory
    /// (a restart empties it, by which point the cloud has converged). Entries
    /// self-reap after `REDEEMED_CODE_TTL` (codes expire ~10min upstream).
    pub oauth_redeemed_codes: Mutex<HashMap<String, std::time::Instant>>,
    /// Most-recent lifecycle-ceremony op this daemon has open, keyed by
    /// `(vault_id, ceremony_name)` (e.g. `vault-unlock`). When a new ceremony op
    /// is created it supersedes the prior one — the daemon withdraws the stale
    /// op from the relay so the console stops showing "1 approval waiting" after
    /// a `sc unlock` was abandoned + retried. See requester-cancel design.
    pub live_ceremony_ops: Mutex<HashMap<(String, String), String>>,
    /// The device egress proxy the resident proxy's forward hop tunnels through,
    /// in a swappable cell so `sc proxy set/clear` HOT-reloads it via
    /// `/proxy/reload` — no daemon restart, no vault re-unlock. Shared with the
    /// hudsucker forward connector (see `proxy::upstream`); the reqwest side
    /// swaps via `core::forward::reload_egress_proxy`.
    pub egress_proxy: crate::proxy::upstream::EgressProxyCell,
    /// In-flight loopback OAuth connects awaiting their `?code&state` redirect on
    /// the shared 8765 callback. `state` → the (vault, connection) whose sealed
    /// `connecting` entry holds the matching code_verifier. Populated each sync
    /// tick from a `connecting` entry that carries a `state` and no code yet;
    /// consumed + removed when `auth::loopback` catches the redirect. In-memory +
    /// daemon-local; entries self-reap at the 2h ceiling (`LOOPBACK_PENDING_TTL`)
    /// so an abandoned consent never lingers.
    pub oauth_pending: Mutex<HashMap<String, PendingLoopback>>,
    /// Guard so each on-demand loopback listener runs as a SINGLE shared
    /// instance PER PORT: a port is present while its listener task is live.
    /// `auth::loopback::ensure_running` inserts and spawns only on a fresh
    /// port, so N concurrent connects share ONE listener per port (the daemon
    /// never races itself into a port conflict). A port is removed when its
    /// task exits (idle self-close or bind failure).
    pub oauth_listener_running: Mutex<std::collections::HashSet<u16>>,
    /// Secret values a local CLI deposited for a pending write op
    /// (`connection-add` / `secret-set`), keyed by their salted digest. The op
    /// carries ONLY the digest in `act.scope` — the full op JSON rides to the
    /// cloud op-relay for the grant page, so plaintext values must never be in
    /// it (and the salt keeps a weak value from being brute-forced from the
    /// public digest). Approving the op binds the digest via β; the act then
    /// takes the stash, re-verifies the digest, and writes the values. In-memory
    /// + daemon-local; entries self-reap after their own op-window TTL.
    pub op_payloads: Mutex<HashMap<String, OpPayloadEntry>>,
}

/// One deposited value-set awaiting its op's approval. See
/// [`AppState::op_payloads`].
pub struct OpPayloadEntry {
    inserted_at: std::time::Instant,
    ttl: std::time::Duration,
    nonce: [u8; 32],
    pub values: std::collections::BTreeMap<String, String>,
}

impl AppState {
    /// Inject the closed `safeclaw-ee` team hooks (team-edition §9). The open
    /// build leaves the [`crate::team_hooks::NoopHooks`] default; the overlay's
    /// `main` calls this on the fresh `AppState` before it is wrapped in `Arc`.
    /// Chainable.
    pub fn with_team_hooks(
        mut self,
        hooks: std::sync::Arc<dyn crate::team_hooks::TeamHooks>,
    ) -> Self {
        self.team = hooks;
        self
    }

    pub fn new(config: Config) -> Self {
        let vaults = VaultDir::new(&config.state_dir);
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let audits = AuditRegistry::new(vaults.clone());
        let sc = crate::crypto::envelope::ScKeyPair::load_or_generate()
            .expect("sc_sk load/generate failed — check ~/.safeclaw/crypto perms");
        Self {
            config,
            vaults,
            cloud_contact: Mutex::new(HashMap::new()),
            vault_shared: Mutex::new(HashMap::new()),
            vault_upgrade_required: Mutex::new(std::collections::HashSet::new()),
            team: std::sync::Arc::new(crate::team_hooks::NoopHooks),
            pending_format_mark: Mutex::new(std::collections::HashSet::new()),
            pending_config_ids: Mutex::new(HashMap::new()),
            challenges: Mutex::new(ChallengeStore::new()),
            approvals: Mutex::new(ApprovalStore::new()),
            services: ServiceRegistry::load(),
            events,
            vault_states: Mutex::new(HashMap::new()),
            last_host_unions: Mutex::new(HashMap::new()),
            audits,
            sc,
            vault_write_locks: Mutex::new(HashMap::new()),
            sse_semaphores: Mutex::new(HashMap::new()),
            agent_key_hashes: Mutex::new(std::collections::HashSet::new()),
            agent_key_resync: tokio::sync::Mutex::new(None),
            external_fill_lock: tokio::sync::Mutex::new(()),
            oauth_reauth_needed: Mutex::new(std::collections::HashSet::new()),
            oauth_redeemed_codes: Mutex::new(HashMap::new()),
            live_ceremony_ops: Mutex::new(HashMap::new()),
            egress_proxy: crate::proxy::upstream::new_cell(),
            oauth_pending: Mutex::new(HashMap::new()),
            oauth_listener_running: Mutex::new(std::collections::HashSet::new()),
            op_payloads: Mutex::new(HashMap::new()),
        }
    }

    /// Stash-lifetime ceiling. Each entry carries its own TTL — the vault's
    /// approval window + slack (see op_payload.rs), so the stash strictly
    /// outlives every moment its op is still approvable. The "user approved
    /// but the deposited value had already expired" failure was exactly a
    /// fixed 300s here under a longer op window; per-entry TTLs from the ONE
    /// policy knob make that class structurally impossible. The ceiling only
    /// bounds a pathological policy value.
    const MAX_OP_PAYLOAD_TTL: std::time::Duration = std::time::Duration::from_secs(86_460);
    /// Flood cap. A human runs one `sc connect` at a time; 32 concurrent
    /// pending stashes is already pathological.
    const MAX_OP_PAYLOADS: usize = 32;

    /// Salted commitment over a value-set: `sha256(DS ‖ nonce ‖ canonical(values))`.
    /// BTreeMap serialization is key-sorted, so `to_vec` is canonical.
    fn op_payload_digest(
        nonce: &[u8; 32],
        values: &std::collections::BTreeMap<String, String>,
    ) -> String {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(b"safeclaw/v1/op-payload");
        h.update(nonce);
        h.update(serde_json::to_vec(values).unwrap_or_default());
        h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Deposit a value-set; returns the digest the op's `act.scope` must carry.
    /// `None` when the stash is full (flood guard).
    pub fn op_payload_insert(
        &self,
        values: std::collections::BTreeMap<String, String>,
        ttl: std::time::Duration,
    ) -> Option<String> {
        use rand::RngCore as _;
        let ttl = ttl.min(Self::MAX_OP_PAYLOAD_TTL);
        let mut m = self.op_payloads.lock().unwrap();
        let now = std::time::Instant::now();
        m.retain(|_, e| now.duration_since(e.inserted_at) < e.ttl);
        if m.len() >= Self::MAX_OP_PAYLOADS {
            return None;
        }
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let digest = Self::op_payload_digest(&nonce, &values);
        m.insert(
            digest.clone(),
            OpPayloadEntry {
                inserted_at: now,
                ttl,
                nonce,
                values,
            },
        );
        Some(digest)
    }

    /// Consume the stash for an approved op. Single-use (removed on take);
    /// expired entries and digest mismatches (defense-in-depth recompute)
    /// yield `None` — the caller fails the act closed.
    pub fn op_payload_take(
        &self,
        digest: &str,
    ) -> Option<std::collections::BTreeMap<String, String>> {
        let entry = self.op_payloads.lock().unwrap().remove(digest)?;
        if entry.inserted_at.elapsed() >= entry.ttl {
            return None;
        }
        if Self::op_payload_digest(&entry.nonce, &entry.values) != digest {
            return None;
        }
        Some(entry.values)
    }

    /// Replace the synced account-level agent-key hash-set (sha256 hex).
    /// Returns whether the set actually changed, so the 30s refresh loop can
    /// log only real updates instead of one line per tick.
    pub fn set_agent_key_hashes(&self, hashes: std::collections::HashSet<String>) -> bool {
        let mut cur = self.agent_key_hashes.lock().unwrap();
        let changed = *cur != hashes;
        *cur = hashes;
        changed
    }

    /// TTL for the redeemed-code ledger. OAuth authorization codes expire
    /// ~10min after issue; 15min covers clock skew, then entries self-reap.
    const REDEEMED_CODE_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

    /// Record that this daemon successfully redeemed `code` — the idempotency
    /// key that stops a stale re-introduction from re-exchanging it. See
    /// [`Self::oauth_redeemed_codes`].
    pub fn note_code_redeemed(&self, code: &str) {
        let mut m = self.oauth_redeemed_codes.lock().unwrap();
        Self::reap_redeemed(&mut m);
        m.insert(crate::api_key::sha256_hex(code), std::time::Instant::now());
    }

    /// True iff this daemon already redeemed `code` — a re-exchange would be a
    /// no-win `invalid_grant`, so the connect machine skips it.
    pub fn was_code_redeemed(&self, code: &str) -> bool {
        let mut m = self.oauth_redeemed_codes.lock().unwrap();
        Self::reap_redeemed(&mut m);
        m.contains_key(&crate::api_key::sha256_hex(code))
    }

    fn reap_redeemed(m: &mut HashMap<String, std::time::Instant>) {
        let now = std::time::Instant::now();
        m.retain(|_, t| now.duration_since(*t) < Self::REDEEMED_CODE_TTL);
    }

    /// Ceiling on how long a loopback connect stays matchable while awaiting its
    /// redirect. The primary driver is "there's an unfinished connect"; this 2h
    /// cap is the backstop so an abandoned consent never keeps the entry alive
    /// forever. Generous on purpose — the listener is benign (`auth::loopback`).
    const LOOPBACK_PENDING_TTL: std::time::Duration = std::time::Duration::from_secs(2 * 60 * 60);

    /// Register (or refresh) a loopback connect awaiting its `?code&state`
    /// redirect. Idempotent — a repeated sync tick re-inserts the same mapping
    /// harmlessly (and refreshes its 2h clock).
    pub fn note_loopback_pending(&self, state: &str, vault_id: &str, conn_id: &str, port: u16) {
        if state.is_empty() {
            return;
        }
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        m.insert(
            state.to_string(),
            PendingLoopback {
                vault_id: vault_id.to_string(),
                conn_id: conn_id.to_string(),
                port,
                inserted_at: std::time::Instant::now(),
            },
        );
    }

    /// Resolve + REMOVE the (vault, connection) for a caught `state`, or `None`
    /// if unknown/expired. Removal makes the match single-use: a replayed
    /// redirect finds nothing (and gets the bland 404).
    pub fn take_loopback_pending(&self, state: &str) -> Option<PendingLoopback> {
        if state.is_empty() {
            return None;
        }
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        m.remove(state)
    }

    /// True iff some loopback connect is awaiting a redirect on `port` (reaps
    /// expired entries first). Drives that port's on-demand listener: non-empty
    /// ⇒ keep (or open) its window; empty ⇒ let it self-close.
    pub fn has_loopback_pending_on(&self, port: u16) -> bool {
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        m.values().any(|p| p.port == port)
    }

    /// The distinct ports with a connect currently awaiting a redirect — one
    /// on-demand listener per entry (`auth::loopback::ensure_running`).
    pub fn pending_loopback_ports(&self) -> Vec<u16> {
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        let mut ports: Vec<u16> = m.values().map(|p| p.port).collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Drop any pending-loopback entries for a (vault, connection) that reached a
    /// terminal state (completed / failed), so the on-demand listener can close
    /// promptly instead of lingering to the 2h cap. The auto-catch path already
    /// took its entry out; this covers the paste-fallback path, whose pre-seal
    /// registered an entry no redirect ever consumed.
    pub fn clear_loopback_for_conn(&self, vault_id: &str, conn_id: &str) {
        let mut m = self.oauth_pending.lock().unwrap();
        m.retain(|_, p| !(p.vault_id == vault_id && p.conn_id == conn_id));
    }

    fn reap_loopback(m: &mut HashMap<String, PendingLoopback>) {
        let now = std::time::Instant::now();
        m.retain(|_, p| now.duration_since(p.inserted_at) < Self::LOOPBACK_PENDING_TTL);
    }

    /// Emit an event into the broadcast channel. Silently swallows the "no
    /// active subscribers" case (it's normal — happens before any /try tab is
    /// connected).
    pub fn emit_event(&self, ev: ApprovalEvent) {
        let _ = self.events.send(ev);
    }

    /// True iff this vault is currently Locked (including "never unlocked
    /// since process boot").
    pub fn is_vault_locked(&self, vault_id: &str) -> bool {
        let states = self.vault_states.lock().unwrap();
        !matches!(states.get(vault_id), Some(VaultState::Unlocked { .. }))
    }

    /// Transition a vault to Unlocked with the given bootstrap cache and the
    /// retained state key `K`. Overwrites any prior state (a fresh unlock
    /// invalidates the previous cache + key).
    pub fn unlock_vault(
        &self,
        vault_id: String,
        cache: SecretsCache,
        state_key: zeroize::Zeroizing<Vec<u8>>,
    ) {
        // Team lease clock starts at unlock (a human was just present).
        self.record_cloud_contact(&vault_id);
        let unlocked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Background external-key enumeration: one list() per store so the
        // registry/entries surfaces see the flat namespace without a network
        // call on their read path. The task holds only the shared adapters
        // and the cache's keys slot — never AppState — so a re-unlock that
        // replaces the cache simply orphans this task's slot harmlessly.
        // Handle::try_current keeps plain #[test] callers (no runtime) safe.
        if !cache.external_stores.is_empty() {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let adapters: Vec<(String, Arc<crate::store::Adapter>)> = cache
                    .external_stores
                    .iter()
                    .map(|(id, (_, a))| (id.clone(), a.clone()))
                    .collect();
                let slot = cache.external_keys.clone();
                let vid = vault_id.clone();
                rt.spawn(async move {
                    let mut all = std::collections::HashSet::new();
                    for (store_id, adapter) in adapters {
                        match adapter.list().await {
                            Ok(names) => all.extend(names),
                            // Accessor-only SAs can't list — resolution still
                            // works (lazy fill amends the slot on first use).
                            Err(e) => tracing::warn!(vault = %vid, store = %store_id, "external key enumeration failed: {}", e),
                        }
                    }
                    if !all.is_empty() {
                        tracing::info!(vault = %vid, keys = all.len(), "external store keys enumerated");
                        *slot.lock().unwrap() = all;
                    }
                });
            }
        }
        let mut states = self.vault_states.lock().unwrap();
        states.insert(
            vault_id,
            VaultState::Unlocked {
                cache,
                state_key,
                unlocked_at,
            },
        );
    }

    /// Clone the retained state key `K` for an Unlocked vault, or `None` when
    /// the vault is Locked. Used by the cloud-sync refresh to re-decrypt a
    /// freshly-pulled sealed blob without a passkey.
    pub fn cloned_state_key(&self, vault_id: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { state_key, .. }) => Some(state_key.clone()),
            _ => None,
        }
    }

    /// Transition a vault to Locked, zeroing any cached secrets.
    pub fn lock_vault(&self, vault_id: &str) {
        let mut states = self.vault_states.lock().unwrap();
        states.insert(vault_id.to_string(), VaultState::Locked);
    }

    /// Retention setting for this vault's audit log. `None` when the vault
    /// is locked (so the daemon has no view into aux) OR when the user
    /// hasn't configured a retention (keep-forever default). The audit
    /// list handler treats both cases the same: skip prune.
    pub fn audit_retention_days(&self, vault_id: &str) -> Option<u32> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.audit_retention_days,
            _ => None,
        }
    }

    /// Resolve a `connection_id` to its service for an Unlocked vault
    /// (CONNECTION_SCHEMA.md §6). An explicit `aux.connections` entry names its
    /// `service`; otherwise the connection IS its own default — `conn == service`
    /// — which keeps unconnected/API-key services and the default OAuth
    /// connection resolvable. Locked vault → falls back to `conn`
    /// (the caller's locked-gate rejects before any real use).
    pub fn resolve_connection_service(&self, vault_id: &str, conn: &str) -> String {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache
                .connections
                .get(conn)
                .and_then(|c| c.service.clone())
                .unwrap_or_else(|| conn.to_string()),
            _ => conn.to_string(),
        }
    }

    /// A custom (per-vault `aux.services`) service definition, cloned out so no
    /// state lock is held across a forward. `None` when the vault is locked or
    /// the id isn't a custom service.
    pub fn custom_service(
        &self,
        vault_id: &str,
        service_id: &str,
    ) -> Option<crate::service::ServiceDef> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => {
                cache.custom_services.get(service_id).cloned()
            }
            _ => None,
        }
    }

    /// Look up a cached auth value for `(vault, connection)`. Returns None if
    /// the vault is Locked, the connection isn't bootstrapped/cached, the
    /// vault has never been unlocked, OR the entry's `expires_at` is in
    /// the past (lazy eviction).
    pub fn cache_lookup(&self, vault_id: &str, conn_id: &str) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let entry = cache.entries.get(conn_id)?;
        if let Some(exp) = entry.expires_at {
            if now >= exp {
                // Lazy eviction: TTL-expired entries are dropped here so
                // ask connections correctly fall back to the pending-op flow
                // once their cache window closes.
                cache.entries.remove(conn_id);
                return None;
            }
        }
        Some(entry.value.clone())
    }

    /// Look up the full `{ secret_name → bytes }` map an allow-level service
    /// needs to resolve its phantoms. Returns `None` if the vault is locked
    /// or the service wasn't bootstrapped with a named-secret set (e.g. an
    /// oauth service, or one resolved post-approval). The allow fast-path
    /// falls back to a single-secret map keyed by the primary in that case.
    pub fn cache_lookup_secrets(
        &self,
        vault_id: &str,
        conn_id: &str,
    ) -> Option<HashMap<String, Vec<u8>>> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.allow_secrets.get(conn_id).cloned(),
            _ => None,
        }
    }

    /// Insert (or overwrite) a cached auth value with optional TTL.
    /// `expires_at = None` means "live until lock" (allow-level
    /// semantics). `Some(t)` is unix-second expiry for ask-level
    /// TTL caching. No-op when the vault is locked at the time of
    /// the call (shouldn't happen on the approve-time write path,
    /// but defensive — `approve_op` runs concurrently with locks).
    pub fn cache_insert(
        &self,
        vault_id: &str,
        conn_id: &str,
        value: Vec<u8>,
        expires_at: Option<u64>,
        agent_prefix: Option<String>,
    ) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.entries.insert(
                conn_id.to_string(),
                // A real approval grant — consumable by the ask retry path,
                // bound to the agent the approval was minted for.
                CacheEntry {
                    value,
                    expires_at,
                    from_bootstrap: false,
                    agent_prefix,
                },
            );
        }
    }

    /// Store an `ask-always` one-shot grant, bound to the request tuple the
    /// user's passkey approved. Overwrites a prior grant for the same tuple
    /// (a fresh tap supersedes). No-op when the vault is locked.
    ///
    /// See [`ASK_ALWAYS_REPLAY_WINDOW_SECS`] for the expiry callers should use.
    pub fn op_grant_insert(
        &self,
        vault_id: &str,
        agent_prefix: &str,
        conn_id: &str,
        method: &str,
        host: &str,
        path: &str,
        scope_digest: &str,
        value: Vec<u8>,
        expires_at: u64,
    ) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.op_grants.insert(
                (
                    agent_prefix.to_string(),
                    conn_id.to_string(),
                    method.to_string(),
                    host.to_ascii_lowercase(),
                    path.to_string(),
                    scope_digest.to_string(),
                ),
                CacheEntry {
                    value,
                    expires_at: Some(expires_at),
                    from_bootstrap: false,
                    agent_prefix: Some(agent_prefix.to_string()),
                },
            );
        }
    }

    /// Redeem the scope-bound grant for exactly this request tuple. A request
    /// whose (method, host, path, scope_digest) differs from what the user
    /// approved is a miss and re-prompts; there is NO fallback to the conn-keyed
    /// `entries` (allow residency / plain-ask leftovers are not grants for a
    /// bound action). `None` when locked / absent / expired.
    ///
    /// `consume` distinguishes the two bound tiers:
    ///   - `ask-always` → `true`: single-use, removed on redeem (each request
    ///     re-prompts).
    ///   - a scoped `ask` → `false`: PEEK — the grant is reused for the SAME
    ///     bound action within its window, but a DIFFERENT action (different
    ///     digest) still misses and re-prompts. (An irreversible/spending action
    ///     should be `ask-always`: a peeked window still lets the identical
    ///     spend repeat, which for money is drainage.)
    pub fn op_grant_take(
        &self,
        vault_id: &str,
        agent_prefix: &str,
        conn_id: &str,
        method: &str,
        host: &str,
        path: &str,
        scope_digest: &str,
        consume: bool,
    ) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let key = (
            agent_prefix.to_string(),
            conn_id.to_string(),
            method.to_string(),
            host.to_ascii_lowercase(),
            path.to_string(),
            scope_digest.to_string(),
        );
        // Peek first so an expired entry (of either tier) is dropped and a
        // reusable ask grant survives a hit.
        let entry = cache.op_grants.get(&key)?;
        if entry.expires_at.is_some_and(|exp| now >= exp) {
            cache.op_grants.remove(&key);
            return None;
        }
        if consume {
            cache.op_grants.remove(&key).map(|e| e.value)
        } else {
            Some(entry.value.clone())
        }
    }

    /// Like [`Self::cache_lookup`] but **grant-only**: a bootstrap-resident value
    /// (`from_bootstrap`) is treated as a miss. Used by the `ask` path so the
    /// first matching request forces a passkey approval instead of riding the
    /// connection's allow-level residency; after approval the downgraded (Allow)
    /// retry reads the real grant via `cache_lookup`. Non-destructive; honors TTL.
    pub fn cache_lookup_grant(
        &self,
        vault_id: &str,
        conn_id: &str,
        agent_prefix: &str,
    ) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let entry = cache.entries.get(conn_id)?;
        if entry.from_bootstrap {
            return None;
        }
        // Op-agent binding: a grant minted for one agent is not a grant for
        // another — miss (and re-prompt) instead of riding it.
        if entry.agent_prefix.as_deref() != Some(agent_prefix) {
            return None;
        }
        if let Some(exp) = entry.expires_at {
            if now >= exp {
                cache.entries.remove(conn_id);
                return None;
            }
        }
        Some(entry.value.clone())
    }

    /// Look up a cached OAuth `access_token` by `sha256(refresh_token)` hex (§5).
    /// Returns `None` if locked, never minted, or past its expiry. Lazily evicts
    /// expired entries (same shape as `cache_lookup`).
    /// The per-vault async write lock — serializes anything that reseals the
    /// vault body (connect exchange, oauth refresh-token rotation) so two writers
    /// can't clobber each other. Same map the connect + sync paths use inline.
    pub fn vault_write_lock(&self, vault_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.vault_write_locks.lock().unwrap();
        Arc::clone(
            locks
                .entry(vault_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    pub fn oauth_access_lookup(&self, vault_id: &str, refresh_hash: &str) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let entry = cache.oauth_access.get(refresh_hash)?;
        if let Some(exp) = entry.expires_at {
            if now >= exp {
                cache.oauth_access.remove(refresh_hash);
                return None;
            }
        }
        Some(entry.value.clone())
    }

    /// Store a freshly-minted OAuth `access_token` under `sha256(refresh_token)`
    /// hex (§5). `expires_at` should be the provider-reported absolute expiry
    /// minus a small safety margin (the broker uses ~60s) so we refresh before
    /// the upstream would reject. No-op when the vault is locked at the time of
    /// the call.
    pub fn oauth_access_insert(
        &self,
        vault_id: &str,
        refresh_hash: &str,
        value: Vec<u8>,
        expires_at: u64,
    ) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.oauth_access.insert(
                refresh_hash.to_string(),
                CacheEntry {
                    value,
                    expires_at: Some(expires_at),
                    // oauth_access has its own lookup path; the flag is unread here.
                    from_bootstrap: false,
                    agent_prefix: None,
                },
            );
        }
    }

    /// Mark an OAuth connection's refresh_token as dead (invalid_grant at /use).
    /// Surfaced via `/registry` as `needs_reauth` so the console prompts reconnect.
    pub fn oauth_mark_reauth(&self, vault_id: &str, conn_id: &str) {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .insert((vault_id.to_string(), conn_id.to_string()));
    }

    /// Clear a connection's reauth flag (a refresh succeeded).
    pub fn oauth_clear_reauth(&self, vault_id: &str, conn_id: &str) {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .remove(&(vault_id.to_string(), conn_id.to_string()));
    }

    /// True iff `(vault, conn)`'s refresh_token was flagged dead.
    pub fn oauth_needs_reauth(&self, vault_id: &str, conn_id: &str) -> bool {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .contains(&(vault_id.to_string(), conn_id.to_string()))
    }

    /// Clear ALL reauth flags for a vault (a fresh connect just landed; any
    /// still-dead token re-marks on the next /use).
    pub fn oauth_clear_reauth_vault(&self, vault_id: &str) {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .retain(|(v, _)| v != vault_id);
    }

    /// Evaluate the per-request policy decision for `(vault, connection,
    /// service, method, path, body)`. Returns `None` when the vault is Locked
    /// or never unlocked (caller should treat that as "vault locked").
    ///
    /// Returned tuple: `(effective_level, matched_rule_id, ttl_seconds)`.
    ///
    /// Resolution (PROTOCOL.md §6.4):
    ///   - merge the service's built-in rules with this connection's
    ///     user rules (`cache.policy.connections[conn].rules`),
    ///   - most-restrictive matching rule wins (deny-override), each rule's
    ///     decision being its own `level`,
    ///   - else connection / tag / global default floor, else ask-always,
    ///   - **active `ask` approvals** — if the decision is `Ask`, a rule
    ///     matched, AND the `(connection, rule_id, method)` triple is in the
    ///     unexpired rule_approvals cache, downgrades to `Allow` so the
    ///     request fast-paths. Connection-default Ask (no rule) never caches.
    pub fn evaluate_request_policy(
        &self,
        vault_id: &str,
        agent_prefix: &str,
        connection_id: &str,
        service_id: &str,
        method: &str,
        path: &str,
        host: &str,
        body: Option<&str>,
        vars: &crate::core::policy::VarMap,
        // True when the service declares a `[requests]` scope SHAPE for this
        // path (i.e. the proxy resolved a `RequestScope`), regardless of whether
        // this particular request populated any values. A scoped path binds its
        // approval per-value through `op_grants`, so it must NEVER ride the
        // coarse connection-window downgrade below — otherwise a value-less
        // (empty-body) ask, approved once, would write a scope-blind window key
        // that a later, differently-valued request could ride without a fresh
        // passkey (approving a blank purchase then spending any amount).
        has_scope_shape: bool,
    ) -> Option<(
        crate::core::policy::AccessLevel,
        Option<String>,
        Option<u64>,
    )> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        // Built-in rules come from the connection's *service* definition (static);
        // the user's per-connection edits/additions (`aux.policy.connections.
        // <id>.rules`) merge on top. The merge is per-connection so two
        // connections of the same service can be policed independently.
        let conn_policy = cache.policy.connections.get(connection_id);
        let empty_rules = std::collections::HashMap::new();
        let built_in = self
            .services
            .default_policy_rules(service_id)
            .unwrap_or_default();
        let rules = crate::core::policy::merge_rules(
            &built_in,
            conn_policy.map(|c| &c.rules).unwrap_or(&empty_rules),
        );
        // Connection default floor (when no rule matches): user's per-connection
        // override field-wise over the service's `[default]`.
        let builtin_levels = self.services.default_policy_levels(service_id);
        let connection_levels = crate::core::policy::merge_levels(
            conn_policy.and_then(|c| c.default.as_ref()),
            builtin_levels.as_ref(),
        );
        // The tag/global floors live in `cache.policy` (the user's
        // `aux.policy` overlaid on compiled defaults at refresh). Read live
        // here → a policy edit is realtime on the next request.
        let tags = self.services.service_tags(service_id);
        let (level, matched_rule, ttl) = crate::core::policy::evaluate_with_match(
            method,
            path,
            body,
            vars,
            Some(&rules),
            connection_levels.as_ref(),
            &cache.policy,
            tags,
        );

        // Cache hit honors the `ask`-with-TTL semantic, but the grant is
        // scoped to the matched rule AND the HTTP method: a prior approval
        // for the same (service, rule, method), not yet expired, downgrades
        // this Ask to Allow so the request fast-paths without a passkey
        // prompt. Two deliberate bounds keep a window from over-reaching:
        //   - No rule matched (tag-/service-default Ask) → never a hit:
        //     there is no author-defined path scope to bound the grant.
        //   - Method is part of the key → approving a GET cannot fast-path a
        //     later POST/DELETE inside the window.
        // Passive cleanup: if expired, drop the entry instead of returning a
        // hit. `ask-always` and `deny` never consult or write the cache;
        // `allow` doesn't need to.
        //
        // Scoped paths are excluded: a `[requests]`-shaped path binds its
        // approval to the exact field VALUES via `op_grants` (a $40-to-Acme
        // grant never redeems a $75-to-EvilCorp request), so it must not also
        // have a coarse, value-blind connection window that a differently-valued
        // request could ride. Only a genuinely scope-less rule uses this window.
        if level == crate::core::policy::AccessLevel::Ask && !has_scope_shape {
            if let Some(rule_id) = matched_rule.clone() {
                // The grant is scoped to the **agent** (op-agent binding),
                // the **connection** (not the service), the matched rule, the
                // method, AND the resolved host: an approval for host A must
                // not fast-path host B in the window, and agent A's approval
                // never fast-paths agent B.
                let key = (
                    agent_prefix.to_string(),
                    connection_id.to_string(),
                    rule_id,
                    method.to_string(),
                    host.to_ascii_lowercase(),
                );
                if let Some(&exp) = cache.rule_approvals.get(&key) {
                    if exp > now {
                        return Some((crate::core::policy::AccessLevel::Allow, matched_rule, ttl));
                    } else {
                        cache.rule_approvals.remove(&key);
                    }
                }
            }
        }

        Some((level, matched_rule, ttl))
    }

    /// Record an `ask`-level approval into the per-vault TTL cache. Called
    /// from approve.rs when a Use op was approved AND the decision that
    /// created it was Ask (not AskAlways). `ttl_seconds` is the level's
    /// `ttl` falling back to `Policy.timeout` or a safe 300s default.
    ///
    /// The grant is scoped to `(service, rule_id, method)`. Two bounds:
    ///   - `rule_id == None` (tag-/service-default Ask, no rule matched)
    ///     is **not recorded** — without an author-defined path scope a grant
    ///     would blanket the whole service, so such ops re-prompt every time.
    ///   - `method` is part of the key, so approving one verb never lets a
    ///     different verb fast-path inside the window.
    ///
    /// No-op when the vault is locked at the moment of the call — that
    /// shouldn't happen in practice (the approve happens while the
    /// vault is unlocked) but we don't want to panic if it does.
    pub fn record_ask_approval(
        &self,
        vault_id: &str,
        agent_prefix: &str,
        connection_id: &str,
        rule_id: Option<String>,
        method: &str,
        host: &str,
        ttl_seconds: u64,
    ) {
        // No rule scope → not cacheable (see doc above).
        let Some(rule_id) = rule_id else { return };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.rule_approvals.insert(
                (
                    agent_prefix.to_string(),
                    connection_id.to_string(),
                    rule_id,
                    method.to_string(),
                    host.to_ascii_lowercase(),
                ),
                now + ttl_seconds,
            );
        }
    }

    /// Record a successful cloud contact for this vault (sync pull/push, or
    /// unlock — a human is present). Feeds the shared-vault offline lease.
    pub fn record_cloud_contact(&self, vault_id: &str) {
        self.cloud_contact
            .lock()
            .unwrap()
            .insert(vault_id.to_string(), std::time::Instant::now());
    }

    /// Seconds since the last cloud contact, `None` if never recorded (treated
    /// as fresh by callers — the entry appears at unlock).
    pub fn cloud_contact_age_secs(&self, vault_id: &str) -> Option<u64> {
        self.cloud_contact
            .lock()
            .unwrap()
            .get(vault_id)
            .map(|t| t.elapsed().as_secs())
    }

    /// Is this vault SHARED? Server-authoritative (team §4): the `kind` the
    /// server stamps on the `/blob` sync envelope, cached in `vault_shared`.
    /// An absent entry (never synced, or an old server without the field) is
    /// PRIVATE — the fail-safe default so a personal vault, and any pre-sync
    /// state, is never leased (review H1 is structurally impossible here: a
    /// private vault's `kind` never reads shared). Independent of unlock state,
    /// unlike the old E2E members-map derivation this replaces.
    pub fn vault_is_shared(&self, vault_id: &str) -> bool {
        *self
            .vault_shared
            .lock()
            .unwrap()
            .get(vault_id)
            .unwrap_or(&false)
    }

    /// Record the server-authoritative sharedness (`kind`) for a vault, from the
    /// `/blob` sync envelope. `true` = shared, `false` = private. Called by the
    /// sync path whenever a fresh envelope carries the field; absent-field pulls
    /// leave the last known value untouched (see `sync::apply_vault_kind`).
    pub fn set_vault_shared(&self, vault_id: &str, shared: bool) {
        self.vault_shared
            .lock()
            .unwrap()
            .insert(vault_id.to_string(), shared);
    }

    /// Eagerly seed `vault_shared` from the known-vaults catalog `kind` (server-
    /// authoritative, mirrored on every discovery, available WITHOUT unlocking a
    /// blob). Called at startup and after discovery so `vault_is_shared` is
    /// reliable before the first serve. DENYLIST normalization (shared iff `kind`
    /// is `team`/`shared`; `personal`/`private`/anything else = not shared) so a
    /// vocabulary drift never strips a personal vault. Only vaults with a known
    /// `kind` are seeded; the signed-envelope path still refreshes the live value.
    pub fn hydrate_shared_from_catalog(&self) {
        for kv in crate::cli::active::known_vaults() {
            if kv.kind.is_some() {
                self.set_vault_shared(&kv.vault, Self::kind_str_is_shared(kv.kind.as_deref()));
            }
        }
    }

    /// DENYLIST normalization of a server `kind` string to sharedness: shared iff
    /// `kind` is `team` or `shared` (case-insensitive); `personal` / `private` /
    /// `None` / anything else = NOT shared, so a vocabulary drift or a renamed kind
    /// never strips a personal vault from serving. Bridges the two `kind`
    /// vocabularies (discovery `personal/team/shared`, blob envelope `shared/private`).
    pub fn kind_str_is_shared(kind: Option<&str>) -> bool {
        matches!(
            kind.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
            Some("team") | Some("shared")
        )
    }

    /// Mark (or clear) a vault as needing a daemon upgrade — the cloud returned
    /// `SC_UPGRADE_REQUIRED` for its sync (design 甲). Set by the sync path on that
    /// signal, cleared on a successful sync. The broker reads it to fail loudly with
    /// an actionable "run `sc upgrade`" to the agent.
    pub fn set_vault_upgrade_required(&self, vault_id: &str, required: bool) {
        let mut set = self.vault_upgrade_required.lock().unwrap();
        if required {
            set.insert(vault_id.to_string());
        } else {
            set.remove(vault_id);
        }
    }

    /// Is this vault flagged `SC_UPGRADE_REQUIRED` (daemon too old for its format)?
    pub fn is_vault_upgrade_required(&self, vault_id: &str) -> bool {
        self.vault_upgrade_required
            .lock()
            .unwrap()
            .contains(vault_id)
    }

    /// Does this vault's reach mask let `agent_id` use `connection_id`?
    /// (team §8.1 — ONE pipeline: the proxy deny, the registry annotation and
    /// GET /vaults all read THIS.) The verdict:
    ///   - `Some(false)` — the agent IS in the authorized-agents table and its
    ///     mask denies this connection (the only denial the proxy acts on).
    ///   - `Some(true)` — in the table, mask allows.
    ///   - `None` — vault locked, OR `agent_id` is not in the `ag_`-keyed table.
    ///     The caller treats `None` as "no mask restriction" (allow): this is the
    ///     legacy Basic-auth path (api-key prefix, never in an `ag_`-keyed table)
    ///     during the dual-auth window. True fail-closed ("not in table = deny")
    ///     is enforced by the AIK proxy path once bearers retire (§11.6).
    pub fn agent_mask_allows(
        &self,
        vault_id: &str,
        agent_id: &str,
        connection_id: &str,
    ) -> Option<bool> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache
                .agents
                .get(agent_id)
                .map(|e| e.connections.allows(connection_id)),
            _ => None,
        }
    }

    /// Is `agent_id` present in this vault's authorized-agents table (§11)?
    /// Presence = authorized: the UIK-signed `ag_`-keyed table is the daemon's
    /// only authz source, and dropping a row is the revoke. Used by the hop-A AIK
    /// PoP proxy path to decide whether a crypto-verified `ag_…` may use this
    /// vault at all — distinct from [`agent_mask_allows`], which only restricts
    /// WHICH connections an already-authorized agent may reach. `false` when the
    /// vault is locked or the agent isn't in the table (fail-closed — the AIK path
    /// is opt-in and dual-authed with the legacy api-key, so this never bricks a
    /// legacy agent, whose api-key prefix simply isn't an `ag_` and takes the
    /// hash-set path instead).
    pub fn agent_is_authorized(&self, vault_id: &str, agent_id: &str) -> bool {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.agents.contains_key(agent_id),
            _ => false,
        }
    }

    /// Is `agent_id` present in the authorized-agents table of ANY currently
    /// UNLOCKED vault this daemon holds (§11)? The ACCOUNT-scoped check for the
    /// api-face reads (registry / op-poll / `/vaults`) — those aren't tied to a
    /// single vault, so a hop-A AIK PoP that proves possession of `ag_…` is a
    /// valid agent of this account for those cross-vault reads iff it's
    /// authorized on at least one vault. `false` if no unlocked vault authorizes
    /// it (fail-closed; dual-auth with the legacy api-key covers the transition).
    pub fn agent_is_authorized_any(&self, agent_id: &str) -> bool {
        let states = self.vault_states.lock().unwrap();
        states.values().any(|s| match s {
            VaultState::Unlocked { cache, .. } => cache.agents.contains_key(agent_id),
            _ => false,
        })
    }

    /// Which of `candidates` this agent is ALLOWED to reach in this vault —
    /// evaluated through `AgentMask::allows` so the blacklist and `All` resolve
    /// identically (team §8.1 ONE pipeline: same verdict as the proxy deny).
    /// `Some(set)` = the subset of `candidates` reachable under this agent's mask;
    /// `None` = vault locked OR `agent_id` is not in the authorized-agents table
    /// (the caller masks nothing — the legacy allow of the dual-auth window, since
    /// a legacy api-key prefix is never in the `ag_`-keyed table). Used by the
    /// registry/vaults surfaces to annotate rows without N lock round-trips.
    pub fn agent_allowed_connections(
        &self,
        vault_id: &str,
        agent_id: &str,
        candidates: &[String],
    ) -> Option<Vec<String>> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.agents.get(agent_id).map(|entry| {
                candidates
                    .iter()
                    .filter(|id| entry.connections.allows(id))
                    .cloned()
                    .collect()
            }),
            _ => None,
        }
    }

    /// The approval-hold window (seconds): how long a pending `ask` op waits
    /// for the passkey gesture before it expires. This is the user's
    /// `aux.policy.timeout` ("Approval timeout" in the console), or a 30-minute
    /// default. THE one approval window (SSOT): op.rs stamps it onto every
    /// ceremony op, the broker ask path mints with it, the op-payload stash
    /// and the relay poll budget derive from it. DISTINCT from the post-approval `ask`-once grant window (the
    /// rule/floor `ttl`) — a long grant window must not stretch the deadline the
    /// user has to actually approve. Falls back to the default when the vault is
    /// locked or sets no timeout.
    pub fn policy_approval_hold(&self, vault_id: &str) -> u64 {
        const DEFAULT_APPROVAL_HOLD: u64 = 1800;
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => {
                cache.policy.timeout.unwrap_or(DEFAULT_APPROVAL_HOLD)
            }
            _ => DEFAULT_APPROVAL_HOLD,
        }
    }

    // ── Proxy-facing accessors (resident phantom-only proxy) ─────────────────

    /// Clone a connection record out of the unlocked routing snapshot. `None`
    /// when the vault is Locked or the connection id is unknown.
    /// All connections of one vault (id → record), empty when locked. Used by
    /// the agent-face `/vaults` index.
    pub fn connections_snapshot(
        &self,
        vault_id: &str,
    ) -> Vec<(String, crate::storage::plaintext::Connection)> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache
                .connections
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            _ => Vec::new(),
        }
    }

    pub fn connection_snapshot(
        &self,
        vault_id: &str,
        conn: &str,
    ) -> Option<crate::storage::plaintext::Connection> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.connections.get(conn).cloned(),
            _ => None,
        }
    }

    /// Snapshot this vault's per-vault custom (`aux.services`) definitions from
    /// the unlocked cache. The OAuth connect-finisher resolves a custom service's
    /// exchange config against these — the global `self.services` registry holds
    /// built-ins only. Empty when the vault is Locked or none are authored.
    pub fn custom_services_snapshot(
        &self,
        vault_id: &str,
    ) -> std::collections::HashMap<String, crate::service::ServiceDef> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.custom_services.clone(),
            _ => Default::default(),
        }
    }

    /// The exact FQDNs a connection's credential may egress to, resolved
    /// through the compiled registry and the vault's custom services. `None`
    /// when the vault is Locked or the connection id is unknown.
    pub fn resolved_hosts_for(&self, vault_id: &str, conn: &str) -> Option<Vec<String>> {
        let states = self.vault_states.lock().unwrap();
        let cache = match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let conn_rec = cache.connections.get(conn)?;
        let def = conn_rec.service.as_deref().and_then(|s| {
            // custom-FIRST (see proxy::handler)
            cache
                .custom_services
                .get(s)
                .cloned()
                .or_else(|| self.services.get(s).cloned())
        });
        Some(crate::core::host::resolved_hosts(conn_rec, def.as_ref()))
    }

    /// True iff `host` is in the union of `resolved_hosts` over the connections
    /// of all unlocked vaults, OR in a locked vault's remembered union
    /// (`last_host_unions`). Decides MITM-vs-blind-tunnel at CONNECT time: only
    /// hosts a connection anchors are decrypted; everything else is a blind
    /// tunnel. Including locked vaults' last-known anchors means a phantom sent
    /// while locked reaches `pipeline`'s explicit `vault_locked` refusal instead
    /// of tunneling to the upstream literally; phantom-less traffic to those
    /// hosts still forwards untouched. Not vid-scoped on purpose — we MITM (and
    /// can return a precise error) even when the CONNECT's vid userinfo is
    /// wrong or absent.
    pub fn host_in_any_known_union(&self, host: &str) -> bool {
        let states = self.vault_states.lock().unwrap();
        let mut remembered = self.last_host_unions.lock().unwrap();
        let mut hit = false;
        // Unlocked vaults are authoritative; refresh each one's remembered
        // union in the same pass so it is current whenever the vault locks.
        for (vid, st) in states.iter() {
            let VaultState::Unlocked { cache, .. } = st else {
                continue;
            };
            let mut hosts: Vec<String> = Vec::new();
            for conn_rec in cache.connections.values() {
                let def = conn_rec.service.as_deref().and_then(|s| {
                    // custom-FIRST (see proxy::handler)
                    cache
                        .custom_services
                        .get(s)
                        .cloned()
                        .or_else(|| self.services.get(s).cloned())
                });
                for h in crate::core::host::resolved_hosts(conn_rec, def.as_ref()) {
                    hosts.push(h.to_ascii_lowercase());
                }
            }
            if hosts
                .iter()
                .any(|h| crate::core::host::host_anchor_matches(host, h))
            {
                hit = true;
            }
            remembered.insert(vid.clone(), hosts);
        }
        if hit {
            return true;
        }
        // Locked (or never-unlocked-this-boot) vaults: last-known anchors.
        for (vid, hosts) in remembered.iter() {
            if matches!(states.get(vid.as_str()), Some(VaultState::Unlocked { .. })) {
                continue;
            }
            if hosts
                .iter()
                .any(|h| crate::core::host::host_anchor_matches(host, h))
            {
                return true;
            }
        }
        false
    }

    /// Session-level host widen (component C partial): append an exact FQDN to a
    /// connection's anchored hosts in the unlocked routing snapshot so the
    /// agent's retried request passes the anchor. Durable persistence into
    /// `aux.connections` is a separate write (see BUILD_NOTES). No-op when the
    /// vault is Locked or the connection is unknown.
    pub fn widen_connection_host(&self, vault_id: &str, conn: &str, host: &str) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            if let Some(conn_rec) = cache.connections.get_mut(conn) {
                let hosts = conn_rec.hosts.get_or_insert_with(Vec::new);
                if !hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                    hosts.push(host.to_string());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    fn test_state() -> AppState {
        let cfg = Config {
            state_dir: PathBuf::from(format!("/tmp/safeclaw-test-{}", std::process::id())),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            rp_id: "localhost".into(),
            admin_key: None,
            relay_url: None,
            body_cap: crate::config::DEFAULT_BODY_CAP,
        };
        AppState::new(cfg)
    }

    #[test]
    fn kind_str_is_shared_is_a_denylist() {
        // Shared iff team/shared (case- and space-tolerant).
        assert!(AppState::kind_str_is_shared(Some("team")));
        assert!(AppState::kind_str_is_shared(Some("shared")));
        assert!(AppState::kind_str_is_shared(Some("  TEAM ")));
        // Everything else (incl. unknown / None) is NOT shared, so a personal
        // vault is never stripped from serving by a vocabulary drift.
        assert!(!AppState::kind_str_is_shared(Some("personal")));
        assert!(!AppState::kind_str_is_shared(Some("private")));
        assert!(!AppState::kind_str_is_shared(Some("solo")));
        assert!(!AppState::kind_str_is_shared(None));
    }

    #[test]
    fn default_build_is_personal_edition() {
        // The default build wires NoopHooks: the open-source PERSONAL edition,
        // which does not serve team vaults. The sync path leaves SHARED vaults to
        // the official build (see `build_serves_shared` / `leave_shared_to_official`
        // in sync.rs); the official build's EeHooks override this to `true`.
        assert!(!test_state().team.serves_shared_vaults());
    }

    /// The op-payload stash is single-use and digest-verified: a deposit is
    /// retrievable exactly once by its returned digest, and an unknown digest
    /// (wrong, replayed, or post-restart) fails closed.
    #[test]
    fn op_payload_deposit_is_single_use_and_digest_bound() {
        let state = test_state();
        let mut values = std::collections::BTreeMap::new();
        values.insert("MIMO_API_TOKEN".to_string(), "s3cret".to_string());
        let digest = state
            .op_payload_insert(values.clone(), std::time::Duration::from_secs(300))
            .expect("stash slot");
        // Two deposits of the SAME values must not collide (fresh salt each).
        let digest2 = state
            .op_payload_insert(values.clone(), std::time::Duration::from_secs(300))
            .expect("stash slot");
        assert_ne!(digest, digest2, "salted digests must differ per deposit");
        assert_eq!(state.op_payload_take(&digest), Some(values));
        assert_eq!(state.op_payload_take(&digest), None, "single-use");
        assert_eq!(state.op_payload_take("deadbeef"), None, "unknown digest");
    }

    fn unlock_with_empty_cache(state: &AppState, vault_id: &str) {
        state.unlock_vault(
            vault_id.to_string(),
            SecretsCache::default(),
            zeroize::Zeroizing::new(Vec::new()),
        );
    }

    /// Directly seed a bootstrap-resident entry (what `bootstrap_cache_from_view`
    /// produces for an allow-read connection) — there's no public setter since
    /// only unlock writes these.
    fn insert_bootstrap(state: &AppState, vault_id: &str, conn: &str, value: &[u8]) {
        let mut states = state.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.entries.insert(
                conn.to_string(),
                CacheEntry {
                    value: value.to_vec(),
                    expires_at: None,
                    from_bootstrap: true,
                    agent_prefix: None,
                },
            );
        }
    }

    #[test]
    fn bootstrap_entry_serves_allow_but_never_ask_paths() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        insert_bootstrap(&state, "v1", "github", b"tok");
        // allow fast-path uses the residency…
        assert_eq!(state.cache_lookup("v1", "github"), Some(b"tok".to_vec()));
        // …but ask must NOT: a bootstrap value is not a grant.
        assert_eq!(state.cache_lookup_grant("v1", "github", "agA"), None);
        // ask-always never reads `entries` at all — the residency (and even a
        // real conn-keyed ask grant) is invisible to op_grant_take.
        state.cache_insert(
            "v1",
            "github",
            b"granted".to_vec(),
            None,
            Some("agA".into()),
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "github",
                "DELETE",
                "api.github.com",
                "/repos/a/b",
                "",
                true
            ),
            None
        );
        // The ask path sees its grant as usual.
        assert_eq!(
            state.cache_lookup_grant("v1", "github", "agA"),
            Some(b"granted".to_vec())
        );
    }

    #[test]
    fn cache_insert_no_expiry_persists_lookups() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        state.cache_insert("v1", "svc", b"secret".to_vec(), None, Some("agA".into()));
        assert_eq!(state.cache_lookup("v1", "svc"), Some(b"secret".to_vec()));
        // Multiple lookups still hit (no eviction without expiry).
        assert_eq!(state.cache_lookup("v1", "svc"), Some(b"secret".to_vec()));
    }

    #[test]
    fn op_grant_take_consumes_single_use() {
        // The ask-always captive-portal contract: one approval = one replay.
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        let far = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/v2/purchase",
            "",
            b"tok".to_vec(),
            far,
        );
        // First take returns the value …
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                "",
                true
            ),
            Some(b"tok".to_vec())
        );
        // … and removes it: a second take misses, and nothing leaked into the
        // conn-keyed entries for the allow/ask paths to find.
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                "",
                true
            ),
            None
        );
        assert_eq!(state.cache_lookup("v1", "svc"), None);
    }

    /// Security regression (the $80/$180 hole): an ask-always grant is bound
    /// to the REQUEST the user approved. A replay whose method, host, or path
    /// differs must miss — and the miss must NOT consume the stored grant, so
    /// the legitimate replay still works afterwards.
    #[test]
    fn op_grant_take_is_request_bound() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        let far = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/v2/purchase",
            "",
            b"tok".to_vec(),
            far,
        );
        // Different path / method / host / connection → all miss.
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/refund",
                "",
                true
            ),
            None
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "DELETE",
                "api.x.com",
                "/v2/purchase",
                "",
                true
            ),
            None
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.y.com",
                "/v2/purchase",
                "",
                true
            ),
            None
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "other",
                "POST",
                "api.x.com",
                "/v2/purchase",
                "",
                true
            ),
            None
        );
        // Host comparison is case-insensitive (hosts are lowercased at insert).
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "API.X.COM",
                "/v2/purchase",
                "",
                true
            ),
            Some(b"tok".to_vec())
        );
    }

    /// Op-agent binding (team §C1): every grant surface is keyed by the agent
    /// the approval was minted for. Agent B holding a perfectly valid key must
    /// never redeem/ride agent A's approval — and B's miss must not consume
    /// A's grant.
    #[test]
    fn grants_are_agent_bound_across_all_three_surfaces() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        let far = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;

        // (1) ask-always / scoped op_grants.
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/v2/purchase",
            "",
            b"tok".to_vec(),
            far,
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agB",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                "",
                true
            ),
            None,
            "agent B cannot redeem A's grant"
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                "",
                true
            ),
            Some(b"tok".to_vec()),
            "B's miss must not have consumed A's grant"
        );

        // (2) unscoped-ask conn-keyed grant.
        state.cache_insert("v1", "svc", b"granted".to_vec(), None, Some("agA".into()));
        assert_eq!(state.cache_lookup_grant("v1", "svc", "agB"), None);
        assert_eq!(
            state.cache_lookup_grant("v1", "svc", "agA"),
            Some(b"granted".to_vec())
        );

        // (3) rule-approvals window: recorded for A, B still re-prompts.
        state.record_ask_approval("v1", "agA", "gh", Some("read".into()), "GET", "h.com", 60);
        {
            let states = state.vault_states.lock().unwrap();
            if let Some(VaultState::Unlocked { cache, .. }) = states.get("v1") {
                let key_a = (
                    "agA".to_string(),
                    "gh".to_string(),
                    "read".to_string(),
                    "GET".to_string(),
                    "h.com".to_string(),
                );
                let mut key_b = key_a.clone();
                key_b.0 = "agB".to_string();
                assert!(cache.rule_approvals.contains_key(&key_a));
                assert!(!cache.rule_approvals.contains_key(&key_b));
            } else {
                panic!("vault not unlocked");
            }
        }
    }

    #[test]
    fn op_grant_take_honors_expiry() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/p",
            "",
            b"stale".to_vec(),
            0,
        );
        // Expired grant is not returned (and is consumed/dropped).
        assert_eq!(
            state.op_grant_take("v1", "agA", "svc", "POST", "api.x.com", "/p", "", true),
            None
        );
    }

    /// Phase 2: the scope digest is part of the key. Approving `amount=80`
    /// (digest_80) means a replay whose fields hash to a DIFFERENT digest (the
    /// $180 request) misses — without consuming — so the honest $80 replay still
    /// works afterwards.
    #[test]
    fn op_grant_take_is_scope_digest_bound() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        let far = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let d80 = crate::service::scope_digest(&[("amount".into(), "80".into())]);
        let d180 = crate::service::scope_digest(&[("amount".into(), "180".into())]);
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/v2/purchase",
            &d80,
            b"tok".to_vec(),
            far,
        );
        // The tampered ($180) replay misses and does NOT consume…
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                &d180,
                true
            ),
            None
        );
        // …so the honest ($80) replay still succeeds, exactly once.
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                &d80,
                true
            ),
            Some(b"tok".to_vec())
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                &d80,
                true
            ),
            None
        );
    }

    /// A scoped `ask` peeks (reuses within its window for the SAME bound
    /// action), while a DIFFERENT bound value still misses — so the request
    /// consent is never a false promise, but the identical action isn't
    /// re-prompted every time (that's the ask-vs-ask-always distinction).
    #[test]
    fn op_grant_take_peek_reuses_same_action_but_not_a_different_one() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        let far = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let d_read = crate::service::scope_digest(&[("q".into(), "alpha".into())]);
        let d_other = crate::service::scope_digest(&[("q".into(), "beta".into())]);
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/search",
            &d_read,
            b"tok".to_vec(),
            far,
        );
        // Peek (consume=false) reuses the SAME action any number of times…
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/search",
                &d_read,
                false
            ),
            Some(b"tok".to_vec())
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/search",
                &d_read,
                false
            ),
            Some(b"tok".to_vec())
        );
        // …but a DIFFERENT bound value misses (re-prompt), without disturbing the grant.
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/search",
                &d_other,
                false
            ),
            None
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/search",
                &d_read,
                false
            ),
            Some(b"tok".to_vec())
        );
    }

    #[test]
    fn cache_lookup_evicts_expired_entry() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        // Already-expired entry.
        state.cache_insert("v1", "svc", b"secret".to_vec(), Some(0), Some("agA".into()));
        assert_eq!(state.cache_lookup("v1", "svc"), None);
        // Subsequent insert with valid TTL should succeed (lazy eviction
        // dropped the stale entry; nothing leaks across).
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        state.cache_insert(
            "v1",
            "svc",
            b"new".to_vec(),
            Some(future),
            Some("agA".into()),
        );
        assert_eq!(state.cache_lookup("v1", "svc"), Some(b"new".to_vec()));
    }

    #[test]
    fn cache_lookup_returns_none_when_locked() {
        let state = test_state();
        // Never unlocked.
        assert_eq!(state.cache_lookup("v1", "svc"), None);
        // Insert into a locked vault should be a no-op too.
        state.cache_insert("v1", "svc", b"x".to_vec(), None, Some("agA".into()));
        assert_eq!(state.cache_lookup("v1", "svc"), None);
    }

    /// Security regression: an `ask` approval is scoped to (service, rule,
    /// method). Approving a GET must NOT silently fast-path a later POST,
    /// even within the TTL window — closes the standing-authority hole where
    /// a single approval blanket-authorized every verb on a service.
    #[test]
    fn ask_grant_is_scoped_to_method_and_rule() {
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Policy, RuleConfig};

        // Inject the test rules as the connection's user rules (level = ask).
        // "gh" has no service definition, so built-in is empty and these are the only rules.
        let ask_rule = |pat: &str| RuleConfig {
            match_pattern: Some(pat.to_string()),
            level: Some(AccessLevel::Ask),
            ttl: Some(60),
            ..Default::default()
        };
        let mut rules = std::collections::HashMap::new();
        rules.insert("read".to_string(), ask_rule("GET /x"));
        rules.insert("write".to_string(), ask_rule("POST /x"));
        let mut policy = Policy::default();
        policy.connections.insert(
            "gh".to_string(),
            ConnectionPolicy {
                default: None,
                rules,
            },
        );

        let state = test_state();
        let vid = "v-scope";
        let mut cache = SecretsCache::default();
        cache.policy = policy;
        state.unlock_vault(vid.to_string(), cache, zeroize::Zeroizing::new(Vec::new()));

        // Baseline: GET resolves to Ask under the "read" rule. (Default
        // connection: connection_id == service_id == "gh".)
        let (lvl, rule, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "gh",
                "gh",
                "GET",
                "/x",
                "api.gh.com",
                None,
                &crate::core::policy::VarMap::new(),
                false, // unscoped rule: coarse connection-window applies
            )
            .unwrap();
        assert_eq!(lvl, AccessLevel::Ask);
        assert_eq!(rule.as_deref(), Some("read"));

        // User approves that GET toward host A.
        state.record_ask_approval(
            vid,
            "agA",
            "gh",
            Some("read".to_string()),
            "GET",
            "api.gh.com",
            60,
        );

        // The same GET toward the same host now fast-paths (the feature works).
        let (lvl, _, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "gh",
                "gh",
                "GET",
                "/x",
                "api.gh.com",
                None,
                &crate::core::policy::VarMap::new(),
                false, // unscoped rule: coarse connection-window applies
            )
            .unwrap();
        assert_eq!(lvl, AccessLevel::Allow, "approved GET should fast-path");

        // Same GET/rule toward a DIFFERENT host must NOT fast-path — the grant
        // is host-scoped (E2E-5 oracle: approve host A → call host B → re-ask).
        let (lvl, _, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "gh",
                "gh",
                "GET",
                "/x",
                "evil.gh.com",
                None,
                &crate::core::policy::VarMap::new(),
                false, // unscoped rule: coarse connection-window applies
            )
            .unwrap();
        assert_eq!(
            lvl,
            AccessLevel::Ask,
            "approving host A must never fast-path host B"
        );

        // A POST is a DIFFERENT verb/rule — the GET approval must not cover it.
        let (lvl, rule, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "gh",
                "gh",
                "POST",
                "/x",
                "api.gh.com",
                None,
                &crate::core::policy::VarMap::new(),
                false, // unscoped rule: coarse connection-window applies
            )
            .unwrap();
        assert_eq!(
            lvl,
            AccessLevel::Ask,
            "approving a GET must never fast-path a POST"
        );
        assert_eq!(rule.as_deref(), Some("write"));

        // A tag-default Ask (no rule) is never recorded, so it can never
        // produce a fast-path — record is a no-op for rule_id == None.
        state.record_ask_approval(vid, "agA", "gh", None, "GET", "api.gh.com", 60);
    }

    // A path that declares a `[requests]` scope shape must bind its approval
    // per-value (op_grants) and NEVER ride the coarse connection-window
    // downgrade — otherwise approving one value-less (empty-body) ask would let
    // any later value ride it (approve a blank purchase, then spend anything).
    #[test]
    fn scoped_path_never_rides_the_coarse_window() {
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Policy, RuleConfig};

        let mut rules = std::collections::HashMap::new();
        rules.insert(
            "purchase".to_string(),
            RuleConfig {
                match_pattern: Some("POST /buy".to_string()),
                level: Some(AccessLevel::Ask),
                ttl: Some(60),
                ..Default::default()
            },
        );
        let mut policy = Policy::default();
        policy.connections.insert(
            "shop".to_string(),
            ConnectionPolicy {
                default: None,
                rules,
            },
        );
        let state = test_state();
        let vid = "v-scoped";
        let mut cache = SecretsCache::default();
        cache.policy = policy;
        state.unlock_vault(vid.to_string(), cache, zeroize::Zeroizing::new(Vec::new()));

        // A value-less ask on this rule/conn/method/host got approved, seeding
        // the coarse connection-window key (exactly the empty-body path).
        state.record_ask_approval(
            vid,
            "agA",
            "shop",
            Some("purchase".to_string()),
            "POST",
            "api.shop.com",
            60,
        );

        // A scope-less caller still fast-paths — the legitimate coarse window.
        let (lvl, _, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "shop",
                "shop",
                "POST",
                "/buy",
                "api.shop.com",
                None,
                &crate::core::policy::VarMap::new(),
                false,
            )
            .unwrap();
        assert_eq!(
            lvl,
            AccessLevel::Allow,
            "an unscoped rule still uses the window"
        );

        // A SCOPED path must NOT ride that value-blind window — it re-asks so its
        // per-value op_grant binds the amount/merchant.
        let (lvl, _, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "shop",
                "shop",
                "POST",
                "/buy",
                "api.shop.com",
                None,
                &crate::core::policy::VarMap::new(),
                true,
            )
            .unwrap();
        assert_eq!(
            lvl,
            AccessLevel::Ask,
            "a scoped path must never fast-path via the coarse window"
        );
    }
}
