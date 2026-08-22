//! Cloud sealed-blob sync (Slice 3).
//!
//! The daemon is a thin pull/push client over the pro-backend's blind blob
//! store (`/v/{vid}/blob`, Supabase Storage behind it). On startup it pulls
//! the active vault's `SealedState` blob and writes it to the local
//! `vault.dat`, so a freshly-paired device can serve a vault that was sealed
//! in the browser. Cloud is the source of truth (1Password model); the pull
//! is version-gated (`?since=<local>`) so an already-current local copy is
//! left untouched and a web edit shows up on the next daemon (re)start.
//!
//! The cloud never decrypts: the blob is passkey-sealed (W_c is not in it).
//! Auth is the daemon's device-key (`~/.safeclaw/device-key`, a `sc_device_`
//! token), distinct from the agent→daemon broker api-key.
//!
//! Best-effort by design: any failure logs and leaves local state untouched
//! — a local-only daemon (no `cloud_backend` configured) just skips this and
//! serves whatever `vault.dat` is on disk. See [[project_slice3_design]].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::cli::active;
use crate::device_auth::DikRequestExt;
use crate::state::AppState;
use crate::storage::sealed_vault::{self, SealedVault};
use crate::sync_stream::{Mode, StreamHealth, VaultStatus, WakeCell, Work};

/// How long an auth-rejected (401/403) sync path parks before retrying. The
/// pre-parking behavior — `return`, killing sync for the daemon's lifetime —
/// meant ONE transient 403 (a backend deploy / auth-table migration) silently
/// ended a device's sync forever. A genuinely revoked device now burns one
/// cheap request per interval instead; real deletion still arrives as the
/// blob channel's tombstone. Module-scope and shared with the SSE
/// dispatcher's PARK_AUTH so the two shapes recover from an auth blip at the
/// same speed BY CONSTRUCTION — tune it once, both move.
pub(crate) const AUTH_RETRY: Duration = Duration::from_secs(600);

/// Outcome of a single blob `pull`. The cloud envelope's clear-text `status`
/// field (`"live"` | `"deleted"`) is the lifecycle channel; this enum is its
/// daemon-side projection so callers can branch on it without re-parsing JSON.
///
/// - `Unchanged` — local copy is already current (or the cloud has no blob row
///   at all: an HTTP 404 keeps its long-standing meaning of "never sealed").
/// - `Updated(version)` — a newer, `status:"live"` blob was pulled and written
///   to `vault.dat`; `version` is the cloud-stamped revision now on disk.
/// - `Deleted` — the cloud row is a tombstone (`status:"deleted"`). This is the
///   ONLY signal that destroys local vault state (see `drop_local_vault`); a
///   live-but-undecryptable blob is deliberately NOT a delete (design/sync.md §4
///   case 3 — log only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    Unchanged,
    Updated(u64),
    Deleted,
}

/// Read the persisted device-key (`~/.safeclaw/device-key`, written by
/// `sc login`). Returns None when the device hasn't been paired.
pub fn device_key() -> Option<String> {
    let home = dirs::home_dir()?;
    let raw = std::fs::read_to_string(home.join(".safeclaw").join("device-key")).ok()?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Sidecar next to a vault's `vault.dat` recording the last-pulled blob
/// version, so `?since=` can short-circuit an unchanged cloud copy.
fn version_sidecar(state_dir: &Path, vault: &str) -> PathBuf {
    state_dir.join("vaults").join(vault).join(".blob_version")
}

fn read_local_version(state_dir: &Path, vault: &str) -> u64 {
    std::fs::read_to_string(version_sidecar(state_dir, vault))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Pull the active vault's sealed blob from the cloud and write `vault.dat`
/// if the cloud copy is newer than the local one. Never returns Err — a
/// failed or unconfigured sync must not stop the daemon from serving.
pub async fn pull_on_start(state_dir: &Path) {
    let cfg = match active::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("cloud sync: no CLI config ({}); skipping pull", e);
            return;
        }
    };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        tracing::debug!("cloud sync: no cloud_backend configured; local-only daemon");
        return;
    };
    let Some(dk) = device_key() else {
        tracing::debug!("cloud sync: no device-key (unpaired); skipping pull");
        return;
    };
    // Auto-discover every vault this ACCOUNT owns, not just the ones a manual
    // `sc vault use` recorded (design/vault-addressing.md). Persist newly found
    // ids into the known-vaults catalog BEFORE computing the pull set below, so
    // the daemon serves a console-created vault with no `sc vault use`. Blobs are
    // passkey-sealed, so syncing every account vault leaks nothing; unlock stays
    // passkey-gated. Best-effort: an old backend or a network blip just leaves
    // the locally-known set as it was.
    let discovered = discover_account_vault_ids(cloud, &dk).await;
    let fresh = remember_discovered(&cfg, &discovered);
    if !fresh.is_empty() {
        tracing::info!(count = fresh.len(), "cloud sync: adopted account vaults via discovery");
    }
    // All vaults this device knows (active ∪ known_vaults ∪ discovered) are kept
    // online — the agent addresses any of them by vid, no "switch vault" needed
    // (1P model). See [[project_vault_agent_architecture_2026_06_25]].
    let ids = synced_vault_ids(&cfg);
    if ids.is_empty() {
        tracing::debug!("cloud sync: no vaults to pull");
        return;
    }
    for vault in &ids {
        match pull(state_dir, cloud, vault, &dk).await {
            Ok(PullOutcome::Updated(version)) => {
                tracing::info!(vault = %vault, version, "cloud sync: pulled vault.dat from cloud")
            }
            Ok(PullOutcome::Unchanged) => {
                tracing::debug!(vault = %vault, "cloud sync: local vault.dat already current")
            }
            Ok(PullOutcome::Deleted) => {
                // The vault was deleted (tombstoned) cloud-side while this device
                // was offline. Drop the local copy on startup so we never serve a
                // retired vault. No AppState yet at this point (pre-serve), so the
                // disk + CLI-config side is dropped here; the in-memory K/audit
                // handle don't exist yet (daemon boots Locked, audit opens lazily).
                drop_local_vault_disk(state_dir, vault);
                tracing::info!(vault = %vault, "cloud sync: vault deleted upstream; dropped local state");
            }
            Err(e) => {
                tracing::warn!(vault = %vault, "cloud sync pull failed (serving local state): {}", e)
            }
        }
        // PER-ITEM: pull the KEYSET (the passkey-wrap layer, now on `/keys`)
        // BEFORE the content rows, so the folded view later sees a fresh K-wrap
        // layer. Best-effort; a 404 / non-per-item vault is a no-op.
        match pull_keys(state_dir, cloud, vault, &dk).await {
            Ok(n) if n > 0 => {
                tracing::info!(vault = %vault, adopted = n, "cloud sync: pulled keyset rows")
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(vault = %vault, "cloud sync: keyset pull failed: {}", e),
        }
        // PER-ITEM: pull content rows too (pre-serve, no cache to refresh yet —
        // the first unlock folds them). Best-effort; a 404 / non-per-item vault
        // is a no-op.
        match pull_items(state_dir, cloud, vault, &dk).await {
            Ok(n) if n > 0 => {
                tracing::info!(vault = %vault, adopted = n, "cloud sync: pulled item rows")
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(vault = %vault, "cloud sync: per-item pull failed: {}", e),
        }
    }
}

/// One-shot, on-demand sync of `vault_id`, backing `POST /v/{vid}/sync`
/// (`sc sync`): pull the latest blob from the cloud (if any), refresh the
/// in-memory cache, and complete any pending OAuth connect
/// (`<conn>_oauth_pending` → exchange → `<conn>_refresh_token`). Returns
/// `Ok(true)` when a newer blob was pulled. Never needs a passkey — it only
/// moves already-sealed state forward: the pull is device-key-authed, and the
/// connect re-seal uses the retained `K` from a prior unlock (no-ops if locked).
/// Result of an on-demand `sc sync`: whether new cloud state was pulled, plus the
/// [`ConnectReport`](crate::auth::connect::ConnectReport) of any pending-connect
/// work so the CLI can SURFACE completions / failures / "couldn't reach provider"
/// instead of the daemon eating them silently.
pub struct SyncOutcome {
    pub pulled: bool,
    pub connects: crate::auth::connect::ConnectReport,
}

pub async fn sync_vault_now(state: &Arc<AppState>, vault_id: &str) -> Result<SyncOutcome, String> {
    let cfg = active::load().map_err(|_| {
        "not set up yet — run `sc login` to pair this daemon with the cloud".to_string()
    })?;
    // `sc sync` only makes sense for a cloud-paired daemon. Distinguish the two
    // not-logged-in shapes so the message guides the user (mainstream: gcloud /
    // gh both point you at the login command rather than printing a raw error).
    let cloud = cfg
        .cloud_backend
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "local-only daemon (no cloud backend) — nothing to sync from the cloud; \
             run `sc login` to pair"
                .to_string()
        })?;
    let dk = device_key().ok_or_else(|| {
        "this daemon isn't paired with the cloud — run `sc login` first".to_string()
    })?;
    let pulled = match pull(&state.config.state_dir, cloud, vault_id, &dk).await? {
        PullOutcome::Updated(_version) => {
            refresh_after_pull(state, vault_id);
            true
        }
        PullOutcome::Unchanged => false,
        PullOutcome::Deleted => {
            // The vault was deleted (tombstoned) cloud-side. Drop all local
            // state — disk, retained K, audit handle, CLI config — under the
            // per-vault write lock (this runs at serving time via POST
            // /v/{vid}/sync, so it must not race a concurrent approve write) and
            // return without the connect step (there is nothing left to act on).
            drop_local_vault_locked(state, vault_id).await;
            tracing::info!(vault = %vault_id, "cloud sync: vault deleted upstream; dropped local state");
            return Ok(SyncOutcome {
                pulled: false,
                connects: Default::default(),
            });
        }
    };
    // PER-ITEM: pull the KEYSET (`/keys`), then the content item rows (`/items`).
    // The keyset now rides `/keys` (NOT the whole-blob `/blob`, which is a
    // keyset-lifecycle marker only); pull it FIRST so the item fold below sees a
    // fresh K-wrap layer. Best-effort — a 404 (endpoint not live) or a
    // not-yet-per-item vault is a no-op. On item adoption, refresh the cache from
    // the folded item view so the new rows are served without a re-unlock.
    if let Some(cloud2) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) {
        if let Some(dk2) = device_key() {
            match pull_keys(&state.config.state_dir, cloud2, vault_id, &dk2).await {
                Ok(n) if n > 0 => {
                    state.record_cloud_contact(vault_id);
                    tracing::info!(vault = %vault_id, adopted = n, "keyset pull: adopted rows")
                }
                Ok(_) => state.record_cloud_contact(vault_id),
                Err(e) => tracing::debug!(vault = %vault_id, "keyset pull failed: {}", e),
            }
            match pull_items(&state.config.state_dir, cloud2, vault_id, &dk2).await {
                Ok(n) if n > 0 => {
                    state.record_cloud_contact(vault_id);
                    tracing::info!(vault = %vault_id, adopted = n, "per-item pull: adopted rows");
                    refresh_after_item_pull(state, vault_id);
                }
                Ok(_) => state.record_cloud_contact(vault_id),
                Err(e) => tracing::debug!(vault = %vault_id, "per-item pull failed: {}", e),
            }
        }
    }
    // Complete a pending connect even when the blob was unchanged — the pending
    // item may have synced earlier (background watcher) but never been processed.
    // Capture the outcome so `sc sync` can report it (completed / reconnect /
    // couldn't-reach-provider) instead of the failure staying buried in the log.
    let connects = crate::auth::connect::process_vault_connects(state, vault_id, None).await;
    // PER-ITEM (bidirectional): flush any LOCAL-ahead keys/items to the cloud.
    // Sync used to only PULL, so a daemon-side change that never got pushed —
    // e.g. a completed OAuth connect whose push was stranded behind a conflicting
    // row — would stay local-only, and other devices / the web console would
    // never see it (the connection sits "connecting" forever). Best-effort;
    // already-synced rows 409-skip without blocking the rest.
    push_keys_best_effort(state, vault_id).await;
    push_items_best_effort(state, vault_id).await;
    deliver_team_marks(state, vault_id).await;
    Ok(SyncOutcome { pulled, connects })
}

/// Drain the post-migration cloud marks for one vault (team §8.3/§5.15):
/// the owner lock-list registration (config-ids) and the one-way `format=2`
/// ratchet. Both idempotent server-side; delivered only after the push above
/// so the format gate never fronts rows that aren't up yet. Best-effort —
/// stays queued for the next round on any failure.
async fn deliver_team_marks(state: &Arc<AppState>, vault_id: &str) {
    let cfg = match crate::cli::active::load() {
        Ok(c) => c,
        Err(_) => return,
    };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return;
    };
    let Some(dk) = device_key() else { return };
    let has_ids = state
        .pending_config_ids
        .lock()
        .unwrap()
        .get(vault_id)
        .cloned();
    let has_format = state.pending_format_mark.lock().unwrap().contains(vault_id);
    if has_ids.is_none() && !has_format {
        return;
    }
    let Ok(client) = crate::cli::egress_proxy::client(Duration::from_secs(10)) else {
        return;
    };
    let cloud = cloud.trim_end_matches('/');
    if let Some(ids) = has_ids {
        let url = format!("{}/v/{}/config-ids", cloud, vault_id);
        let body = serde_json::json!({ "ids": ids });
        match client
            .post(&url)
            .bearer_auth(&dk)
            .dik_pop("POST", &url, &serde_json::to_vec(&body).unwrap_or_default())
            .json(&body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                state.pending_config_ids.lock().unwrap().remove(vault_id);
                tracing::info!(vault = %vault_id, "owner lock-list registered");
            }
            Ok(r) => {
                tracing::debug!(vault = %vault_id, status = %r.status(), "config-ids register deferred")
            }
            Err(e) => tracing::debug!(vault = %vault_id, "config-ids register failed: {}", e),
        }
    }
    if has_format {
        let url = format!("{}/v/{}/format", cloud, vault_id);
        let body = serde_json::json!({ "format": 2 });
        match client
            .patch(&url)
            .bearer_auth(&dk)
            .dik_pop("PATCH", &url, &serde_json::to_vec(&body).unwrap_or_default())
            .json(&body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                state.pending_format_mark.lock().unwrap().remove(vault_id);
                tracing::info!(vault = %vault_id, "vault marked format=2 (unified addressing)");
            }
            Ok(r) => {
                tracing::debug!(vault = %vault_id, status = %r.status(), "format mark deferred")
            }
            Err(e) => tracing::debug!(vault = %vault_id, "format mark failed: {}", e),
        }
    }
}

/// After a per-item pull adopted new rows, refresh the in-memory cache for an
/// UNLOCKED vault by folding the per-item store with the retained `K` — no
/// passkey. Locked vault (no K) → no-op (the next unlock folds the new rows). A
/// rotated `K` that can't unseal → log + leave the cache (graceful).
fn refresh_after_item_pull(state: &Arc<AppState>, vault: &str) {
    let Some(k) = state.cloned_state_key(vault) else {
        return;
    };
    let Some(pv) = read_per_item_store(&state.config.state_dir, vault) else {
        return;
    };
    match crate::server::handlers::metadata::decrypt_vault_view_peritem_with_key(&k, &pv, vault) {
        Ok(view) => {
            let cache = crate::server::handlers::approve::bootstrap_cache_from_view(&view, state);
            state.unlock_vault(vault.to_string(), cache, k);
            tracing::info!(vault = %vault, "per-item pull: cache refreshed from item rows");
        }
        Err(_) => {
            tracing::warn!(
                vault = %vault,
                "per-item pull: retained K can't unseal a row (rotated K?); lock+unlock to see new state"
            );
        }
    }
}

/// Vault ids this device keeps synced: the active vault plus every vault in
/// `known_vaults` (added by `sc vault use` / `sc vault create`), deduped. The
/// agent reaches any of them by vid; `sc vault use` is only the CLI default.
fn synced_vault_ids(cfg: &crate::cli::active::CliConfig) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    if let Some(v) = cfg.vault.as_deref().filter(|s| !s.is_empty()) {
        ids.push(v.to_string());
    }
    for kv in crate::cli::active::known_vaults() {
        if !kv.vault.is_empty() && !ids.iter().any(|x| x == &kv.vault) {
            ids.push(kv.vault);
        }
    }
    ids
}

/// GET the account's vault ids from the cloud — the same `/api/vault/vaults` the
/// console lists, now device-key authable. The daemon keeps EVERY account vault
/// synced (1P per-item model), so a vault created in the browser reaches this
/// device with no `sc vault use`. Best-effort: any failure returns an empty list
/// and the caller leaves the locally-known set untouched. This never REMOVES a
/// vault; deletion is the tombstone path (`PullOutcome::Deleted`).
async fn discover_account_vault_ids(cloud: &str, dk: &str) -> Vec<String> {
    let cloud = cloud.trim_end_matches('/');
    let url = format!("{}/api/vault/vaults", cloud);
    let Ok(client) = crate::cli::egress_proxy::client(Duration::from_secs(15)) else {
        return Vec::new();
    };
    let resp = match client
        .get(&url)
        .bearer_auth(dk)
        .dik_pop("GET", &url, &[])
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("vault discovery: reach {} failed: {}", cloud, e);
            return Vec::new();
        }
    };
    if !resp.status().is_success() {
        // 404 = a backend that predates device-key vault listing; anything else
        // is transient. Either way, keep what we already know.
        tracing::debug!(status = %resp.status(), "vault discovery: non-success (old backend?)");
        return Vec::new();
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!("vault discovery: parse failed: {}", e);
            return Vec::new();
        }
    };
    body.get("vaults")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.get("id").and_then(|i| i.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Persist discovered vault ids into the known-vaults catalog under this device's
/// local daemon URL, so `synced_vault_ids` / `sc vault ls` include them. Returns
/// the ids that were NOT already known (the ones freshly adopted this call), so
/// the caller can spawn a watcher for each new one. Setting a DEFAULT is a
/// separate act (`sc vault use`); discovery only makes vaults AVAILABLE.
fn remember_discovered(cfg: &crate::cli::active::CliConfig, ids: &[String]) -> Vec<String> {
    let daemon = cfg
        .daemon
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", crate::config::CONTROL_PORT));
    let known: std::collections::HashSet<String> = crate::cli::active::known_vaults()
        .into_iter()
        .map(|kv| kv.vault)
        .collect();
    let mut fresh = Vec::new();
    for id in ids {
        if known.contains(id) {
            continue;
        }
        match crate::cli::active::remember(&daemon, id) {
            Ok(()) => fresh.push(id.clone()),
            Err(e) => tracing::debug!(vault = %id, "vault discovery: remember failed: {}", e),
        }
    }
    fresh
}

/// Live auto-discovery: adopt an account vault created AFTER the daemon started
/// (e.g. in the console) without a restart. Re-lists the account's vaults on an
/// interval; a genuinely new one is persisted, pulled once so it serves right
/// away, then handed to a steady `watch_loop`. That watcher rides long-poll
/// (its cell is not in the SSE dispatcher's fixed set); the next daemon restart
/// folds it into the SSE stream. Spawned unconditionally for a paired daemon, so
/// even a device with zero vaults today adopts its first console-created one.
async fn discovery_reconcile_loop(
    state: Arc<AppState>,
    cloud: String,
    dk: String,
    mut watched: std::collections::HashSet<String>,
) {
    /// Cadence for spotting a newly created vault. Fast path for existing vaults
    /// is still the per-vault watcher; this only governs first adoption latency.
    const INTERVAL: Duration = Duration::from_secs(120);
    // A private health channel pinned Down: dynamically-added vaults run on
    // long-poll (Fallback), and holding the sender here keeps every spawned
    // watcher's `health_rx.changed()` parked instead of erroring on a dropped
    // sender.
    let (_health_tx, health_rx) = tokio::sync::watch::channel(StreamHealth::Down);
    loop {
        tokio::time::sleep(INTERVAL).await;
        let cfg = match active::load() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let discovered = discover_account_vault_ids(&cloud, &dk).await;
        let fresh = remember_discovered(&cfg, &discovered);
        for vid in fresh {
            if !watched.insert(vid.clone()) {
                continue;
            }
            let st = state.clone();
            let cl = cloud.clone();
            let dkk = dk.clone();
            let hr = health_rx.clone();
            tracing::info!(vault = %vid, "cloud sync: live-adopted a new account vault (long-poll until restart)");
            tokio::spawn(async move {
                let cell = Arc::new(WakeCell::new());
                // Pull once so the vault serves immediately, then keep it current.
                let _ = pull(&st.config.state_dir, &cl, &vid, &dkk).await;
                watch_loop(st, vid, cl, dkk, cell, hr).await;
            });
        }
    }
}

/// Spawn one `watch_loop` per synced vault (active ∪ known_vaults), so every
/// vault is kept live, not just the active one. Gated like the rest of sync —
/// no-op for a local-only/unpaired daemon. Vaults added after start are picked
/// up on the next daemon (re)start.
///
/// SSE sync push (design/sse-sync.md): ONE dispatcher task owns the
/// event stream for the whole daemon; each vault task gets a merged
/// pending-wake cell plus the global health watch, and picks its select!
/// shape per round from the cell's mode. The dispatcher holds only WEAK refs
/// to the cells — a vault task that exits (tombstone) drops the sole strong
/// ref, which is how the dispatcher knows to prune the vid from `?vids` at
/// its next reconnect. The dispatcher is spawned even when `sync_stream=off`:
/// it re-reads the switch at every (re)connect, so a runtime flip in either
/// direction takes effect without a restart.
pub fn spawn_watchers(state: Arc<AppState>) {
    let cfg = match active::load() {
        Ok(c) => c,
        Err(_) => return,
    };
    let Some(cloud) = cfg.cloud_backend.clone().filter(|s| !s.is_empty()) else {
        tracing::debug!("cloud sync watch: no cloud_backend; not started (local-only daemon)");
        return;
    };
    let Some(dk) = device_key() else {
        tracing::debug!("cloud sync watch: no device-key (unpaired); not started");
        return;
    };
    let cloud = cloud.trim_end_matches('/').to_string();
    let (health_tx, health_rx) = tokio::sync::watch::channel(StreamHealth::Down);
    // v1.1: re-expose the health read daemon-wide — the agent-hash loop's
    // cadence and the relay pollers' interval key off it, and both live
    // outside the vault tasks this channel was built for. See
    // `sync_stream::publish_stream_health` for why a OnceLock set HERE beats
    // creating the channel at AppState construction.
    crate::sync_stream::publish_stream_health(health_rx.clone());
    let mut cells: Vec<(String, std::sync::Weak<WakeCell>)> = Vec::new();
    for vault in synced_vault_ids(&cfg) {
        let cell = Arc::new(WakeCell::new());
        cells.push((vault.clone(), Arc::downgrade(&cell)));
        tokio::spawn(watch_loop(
            state.clone(),
            vault,
            cloud.clone(),
            dk.clone(),
            cell,
            health_rx.clone(),
        ));
    }
    if !cells.is_empty() {
        tokio::spawn(crate::sync_stream::dispatcher(
            cloud.clone(),
            dk.clone(),
            cells,
            health_tx,
        ));
    }
    // Live auto-discovery (design/vault-addressing.md): adopt account vaults
    // created after startup with no restart. Runs even with zero vaults today, so
    // a freshly-paired device picks up its first console-created vault. Seeded
    // with the vaults already watched above so it only spawns for NEW ones.
    let watched: std::collections::HashSet<String> =
        synced_vault_ids(&cfg).into_iter().collect();
    // §15 account principal ledger: pull + verify + (flag-gated) enforce a VERIFIED
    // self-revoke (lock + wipe all + logout). The anchor is the account's owner-UIK
    // us_ pinned at login (NOT the account UUID) — self-certifying. Dormant until
    // SAFECLAW_PRINCIPAL_ENFORCE is on (the P6 cutover flips the default). Uses clones
    // so the discovery loop below still takes ownership.
    if let Some(anchor_uik) = active::account_uik() {
        tokio::spawn(crate::principal_ledger::principal_ledger_loop(
            state.clone(),
            cloud.clone(),
            dk.clone(),
            anchor_uik,
        ));
    }
    tokio::spawn(discovery_reconcile_loop(state, cloud, dk, watched));
}

/// Pull the vault's sealed blob (version-gated by the `.blob_version` sidecar).
/// On a newer live blob, writes `vault.dat` and returns `Updated(version)`.
/// Returns `Unchanged` when local is already current OR the cloud has no row
/// (HTTP 404 — "never sealed", unchanged meaning preserved). Returns `Deleted`
/// when the envelope's `status` is `"deleted"` (tombstone) — the caller drops
/// local state; nothing is written to disk on this branch.
async fn pull(
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<PullOutcome, String> {
    let local_ver = read_local_version(state_dir, vault);
    let url = format!(
        "{}/v/{}/blob?since={}",
        cloud.trim_end_matches('/'),
        vault,
        local_ver
    );
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15))
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .get(&url)
        .bearer_auth(device_key)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;

    match resp.status().as_u16() {
        200 => {}
        // 404 = no blob row at all (never sealed). UNCHANGED meaning is kept
        // EXACTLY as before — a tombstone is a 200 with status:"deleted", never
        // a 404, so a delete can no longer masquerade as "nothing sealed yet".
        404 => return Ok(PullOutcome::Unchanged),
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("cloud blob GET HTTP {}", other)),
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse blob response: {}", e))?;

    Ok(classify_pull_body(state_dir, vault, &body)?)
}

/// Extract the server-authoritative vault `kind` from a `/blob` (or `/blob/wait`)
/// response envelope (team §4). `kind` rides OUTSIDE the sealed blob — a server
/// operational fact, never E2E — so the daemon reads it straight off the
/// envelope. `Some(true)` = `"shared"`, `Some(false)` = `"private"`, `None` if
/// the field is absent/unrecognized (an old server, or a probe the server didn't
/// stamp) — the caller then leaves the last known sharedness untouched (never
/// downgrades a known-shared vault to private on a field-less poll). Additive by
/// construction: a server that never sends `kind` changes nothing (every vault
/// stays at the fail-safe private default in `vault_is_shared`).
fn parse_shared_from_body(body: &serde_json::Value) -> Option<bool> {
    match body.get("kind").and_then(|v| v.as_str()) {
        Some("shared") => Some(true),
        Some("private") => Some(false),
        _ => None,
    }
}

/// Decode standard base64 (the backend emits `Buffer.toString("base64")`).
fn decode_b64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Decode a base64 64-byte Ed25519 signature.
fn decode_sig64(s: &str) -> Option<[u8; 64]> {
    let v = decode_b64(s)?;
    if v.len() != 64 {
        return None;
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(&v);
    Some(a)
}

/// Apply the server-signed operational envelope (team §9 — "谁是权威谁签名"):
/// trust `kind` and advance the offline-lease contact clock ONLY from a signature
/// we can verify against the pinned server key. A present-but-invalid signature
/// (a fake / MITM `/blob` server, or a tampered local cache) is IGNORED with a
/// warning — so a local attacker can neither flip a shared vault to private (to
/// kill its lease) nor forge a recent contact (to hold the lease open offline).
/// An ABSENT `env` (a legacy server that does not sign yet) falls back to trusting
/// the plain top-level `kind`, so the rollout is additive and never silent-bricks
/// (§7). This defends the daemon's cache against LOCAL tampering, not against a
/// compromised server (§9); the hard revocation is always upstream-key rotation.
fn apply_verified_envelope(state: &Arc<AppState>, vault: &str, body: &serde_json::Value) {
    if let Some(env) = body.get("env") {
        // Signed path: the top-level `kind` is covered by the `env` signature.
        let kind = body
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("private");
        let format = env.get("format").and_then(|v| v.as_u64()).unwrap_or(0);
        let epoch = env
            .get("membership_epoch")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let issued_at = env.get("issued_at").and_then(|v| v.as_u64()).unwrap_or(0);
        let nonce = env
            .get("nonce")
            .and_then(|v| v.as_str())
            .and_then(decode_b64)
            .unwrap_or_default();
        let verified = env
            .get("sig")
            .and_then(|v| v.as_str())
            .and_then(decode_sig64)
            .map(|sig| {
                crate::crypto::server_key::verify_envelope(
                    vault, kind, format, epoch, issued_at, &nonce, &sig,
                )
            })
            .unwrap_or(false);
        if !verified {
            tracing::warn!(vault = %vault, "cloud sync: server envelope signature INVALID — ignoring operational facts (kind/lease)");
            return;
        }
        state.set_vault_shared(vault, kind == "shared");
    } else if let Some(shared) = parse_shared_from_body(body) {
        // Legacy server (no `env` signature): trust the plain `kind` field.
        state.set_vault_shared(vault, shared);
    }
    // Contact token: advance the lease freshness clock only from a verified token.
    if let Some(tok) = body.get("contact_token") {
        let account_id = tok.get("account_id").and_then(|v| v.as_str()).unwrap_or("");
        let issued_at = tok.get("issued_at").and_then(|v| v.as_u64()).unwrap_or(0);
        let nonce = tok
            .get("nonce")
            .and_then(|v| v.as_str())
            .and_then(decode_b64)
            .unwrap_or_default();
        let verified = tok
            .get("sig")
            .and_then(|v| v.as_str())
            .and_then(decode_sig64)
            .map(|sig| {
                crate::crypto::server_key::verify_contact_token(
                    vault, account_id, issued_at, &nonce, &sig,
                )
            })
            .unwrap_or(false);
        if verified {
            state.record_cloud_contact(vault);
        } else {
            tracing::warn!(vault = %vault, "cloud sync: contact token signature INVALID — not advancing lease clock");
        }
    }
}

/// Parse a 200 blob-GET body into a `PullOutcome` and, for a live update,
/// persist the blob to `vault.dat`. Factored out of `pull` so the watch loop
/// (which reads its own long-poll body) and the unit tests share one classifier.
///
/// Branch order (status wins over content):
/// 1. `status == "deleted"` → `Deleted` (tombstone; never touch disk here).
/// 2. `{ unchanged: true }` → `Unchanged` (cheap freshness probe).
/// 3. a `blob` present (status absent or `"live"`) → persist, `Updated`.
fn classify_pull_body(
    state_dir: &Path,
    vault: &str,
    body: &serde_json::Value,
) -> Result<PullOutcome, String> {
    // Tombstone: an explicit deleted status is the ONLY drop trigger. Checked
    // before `unchanged`/`blob` so a tombstone is never mistaken for content.
    if body.get("status").and_then(|v| v.as_str()) == Some("deleted") {
        // §15 leg A: gate the drop on the (dual-path) tombstone check. Flag OFF (default)
        // → always Deleted (unchanged). Flag ON → Deleted only for a verified owner
        // tombstone; an unsigned/forged delete parks as Unchanged (a later valid pull drops).
        if tombstone_should_drop(state_dir, vault, body) {
            return Ok(PullOutcome::Deleted);
        }
        return Ok(PullOutcome::Unchanged);
    }

    // `{ unchanged: true }` — the cheap freshness probe said local is current.
    if body
        .get("unchanged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok(PullOutcome::Unchanged);
    }

    let version = body.get("version").and_then(|v| v.as_u64()).unwrap_or(0);

    // PER-ITEM: a per-item vault's `/blob` row is now a keyset-lifecycle marker
    // ONLY — the browser writes `{ lifecycle: "per-item-v3", version }` with NO
    // `blob` field (setupEnvVault). The keyset itself rides `/keys`
    // (`pull_keys`), not the whole-blob path. So a live 200 body with no `blob`
    // (and not a tombstone — handled above) is NOT an error and must NOT be
    // persisted to `vault.dat`: treat it as `Unchanged`. (A legacy whole-blob
    // vault still sends a `blob`; that path is unchanged below.) The version
    // cursor MUST still advance (see `record_blob_version`).
    let Some(blob) = body.get("blob") else {
        record_blob_version(state_dir, vault, version);
        return Ok(PullOutcome::Unchanged);
    };
    // PER-ITEM: `putBlob` wraps the lifecycle marker, so it arrives as
    // `{ blob: { lifecycle: "per-item-v3", version } }` — the marker DOES sit
    // under `blob` (the no-`blob` case above only covers a bare row). It is NOT a
    // whole SealedState: the keyset rides `/keys`, content rides `/items`. Never
    // persist it as vault.dat — treat as Unchanged so `sc sync` doesn't choke
    // trying to parse a lifecycle marker as a SealedState (missing `registry`).
    if blob.get("lifecycle").is_some() {
        record_blob_version(state_dir, vault, version);
        return Ok(PullOutcome::Unchanged);
    }

    persist_blob(state_dir, vault, blob, version)?;
    Ok(PullOutcome::Updated(version))
}

/// Advance the `.blob_version` cursor WITHOUT writing `vault.dat`. A per-item
/// vault's `/blob` row is a lifecycle marker that is never persisted as
/// content, but its `version` must still advance the `?since=` cursor —
/// otherwise every `/blob` probe re-delivers the marker, and `/blob/wait`
/// (which answers instantly whenever `version > since`) never parks: that
/// unrecorded cursor was the pre-0.9.36 bug that turned the 25s long-poll
/// into a ~1.5s hot loop. `version == 0` (field absent) records nothing.
fn record_blob_version(state_dir: &Path, vault: &str, version: u64) {
    if version == 0 {
        return;
    }
    let sidecar = version_sidecar(state_dir, vault);
    if let Some(parent) = sidecar.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&sidecar, version.to_string()) {
        tracing::warn!(vault = %vault, "cloud sync: failed to record blob version: {}", e);
    }
}

/// Validate a pulled blob as a `SealedVault`, write it to `vault.dat`
/// atomically, and record the version sidecar. Shared by the start-time pull
/// and the runtime watch loop. Validates BEFORE touching disk — never persist
/// garbage over a working vault.dat.
fn persist_blob(
    state_dir: &Path,
    vault: &str,
    blob: &serde_json::Value,
    version: u64,
) -> Result<(), String> {
    let sealed: SealedVault = serde_json::from_value(blob.clone())
        .map_err(|e| format!("cloud blob is not a valid SealedState: {}", e))?;
    let vault_path = state_dir.join("vaults").join(vault).join("vault.dat");
    sealed_vault::write_atomic(&vault_path, &sealed)
        .map_err(|e| format!("write vault.dat: {}", e))?;
    if let Err(e) = std::fs::write(version_sidecar(state_dir, vault), version.to_string()) {
        tracing::warn!(vault = %vault, "cloud sync: wrote vault.dat but failed to record version: {}", e);
    }
    Ok(())
}

/// Remove the on-disk footprint of a vault: `vault.dat` and the `.blob_version`
/// sidecar. Best-effort and idempotent (missing files are not an error). Used by
/// both the in-process drop path and the pre-serve startup drop. Deliberately
/// narrow — it removes ONLY the two sync-owned files, not the whole vault dir
/// (the audit `.db` is closed/removed by the registry's `forget`, and we keep the
/// directory shell so a re-pair to the same id, were one to happen, isn't
/// confused by a half-present tree).
fn drop_local_vault_disk(state_dir: &Path, vault: &str) {
    let vault_dir = state_dir.join("vaults").join(vault);
    let vault_path = vault_dir.join("vault.dat");
    if let Err(e) = std::fs::remove_file(&vault_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(vault = %vault, "cloud sync: failed to remove vault.dat on delete: {}", e);
        }
    }
    let sidecar = version_sidecar(state_dir, vault);
    if let Err(e) = std::fs::remove_file(&sidecar) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(vault = %vault, "cloud sync: failed to remove .blob_version on delete: {}", e);
        }
    }
}

/// Drop ALL local state for a vault that was deleted (tombstoned) cloud-side.
/// This is the sole code path that destroys local vault state, and it is only
/// reached on an explicit `status:"deleted"` tombstone (never on a decrypt
/// failure — see design/sync.md §4 case 3). Order matters:
///  1. `lock_vault` — transition to Locked, which DROPS the `Unlocked` variant
///     and thereby zeroizes the retained state key `K` (`Zeroizing<Vec<u8>>`)
///     and the whole secrets cache. Done first so K is gone before we touch the
///     ciphertext it protected.
///  2. remove `vault.dat` + `.blob_version` from disk.
///  3. close/forget the per-vault audit SQLite handle (the registry reopens
///     lazily if ever asked again; on a tombstone it won't be).
///  4. forget the vault from the CLI `known_vaults` config so the next daemon
///     start doesn't re-add a watcher for the dead id.
/// The caller is responsible for stopping this vault's `watch_loop` (it returns
/// from the loop after calling us). Best-effort throughout — a failure in any
/// step logs and proceeds; nothing here may stop the daemon from serving.
fn drop_local_vault(state: &Arc<AppState>, vault: &str) {
    // 1. Zeroize retained K + cache by transitioning to Locked.
    state.lock_vault(vault);
    // 2. Disk.
    drop_local_vault_disk(&state.config.state_dir, vault);
    // 3. Audit handle (closes the SQLite connection; idempotent).
    state.audits.forget(vault);
    // 4. CLI config — drop from known_vaults / clear active if it was active.
    match active::forget_vault(vault) {
        Ok(true) => {}
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(vault = %vault, "cloud sync: failed to forget vault from CLI config: {}", e)
        }
    }
}

/// Async wrapper that acquires the per-vault write lock, then drops all local
/// state. EVERY runtime drop (while the daemon is serving, with concurrent
/// approve.rs / connect writers) MUST go through this so the destroy can't race
/// a concurrent `vault.dat` write — `write_atomic`'s tmp+rename could otherwise
/// land AFTER `remove_file` and re-create a live file for a tombstoned id. The
/// ONLY lock-free drop is `pull_on_start`'s (pre-serve: no AppState, no
/// concurrent writers yet), which uses `drop_local_vault_disk` directly.
pub(crate) async fn drop_local_vault_locked(state: &Arc<AppState>, vault: &str) {
    let lock = {
        let mut locks = state.vault_write_locks.lock().unwrap();
        Arc::clone(
            locks
                .entry(vault.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    };
    let _guard = lock.lock().await;
    drop_local_vault(state, vault);
}

/// §15 leg-B: if THIS account's UIK is VERIFIED-not-a-member of a shared vault (an
/// owner offboarded us), actively LOCK + WIPE it locally. Returns `true` if it wiped
/// (the caller stops this vault's watcher — a later pull would re-adopt the triple).
/// SAFE: acts ONLY on a `Verified`, non-empty fold that EXCLUDES our `us_`
/// ([`PerItemVault::verified_membership`] = `Some(false)`); an untrusted / rolled-back
/// / bootstrap / personal-`NoUik` vault yields `None` → parks. Flag-gated (default OFF,
/// P6 flips it). Recoverable if ever wrong: the discovery loop won't re-add a
/// non-member vault, and a re-invite + passkey re-unlock restores it.
async fn enforce_membership_presence(state: &Arc<AppState>, vault: &str) -> bool {
    if !crate::principal_ledger::principal_enforce_enabled() {
        return false;
    }
    let Some(us) = active::account_uik() else {
        return false;
    };
    let Some(pv) = read_per_item_store(&state.config.state_dir, vault) else {
        return false; // no local keyset yet → nothing to lose
    };
    if pv.verified_membership(vault, &us) == Some(false) {
        tracing::warn!(
            vault = %vault, us = %us,
            "membership: this account is VERIFIED not a member of this vault (owner offboarded) — locking + wiping local state"
        );
        drop_local_vault_locked(state, vault).await;
        return true;
    }
    false
}

/// §15 leg A: decide whether a `status:"deleted"` tombstone should DROP local state.
/// Dual-path: with the require-signed flag OFF (default) ANY tombstone drops — the
/// legacy behavior, byte-for-byte unchanged. With it ON, drop ONLY on an owner-signed
/// tombstone (`tombstone_sig`/`tombstone_signer` in the body) that verifies against the
/// vault's fold-owner set; a server flipping `status` without a valid owner signature is
/// then REJECTED (parked), not obeyed. NEVER acts on a bare 401 (that path parks
/// upstream) — this only gates an explicit deleted-status body.
fn tombstone_should_drop(state_dir: &Path, vault: &str, body: &serde_json::Value) -> bool {
    if !crate::principal_ledger::require_signed_tombstone() {
        return true; // legacy dual-path: unsigned deletes still drop until the P6 flip
    }
    // No per-item keyset at all (a pure legacy fmt1 vault, or one never synced here) → no
    // fold-owner to verify against and no fmt2 K/blob to protect → keep the legacy drop
    // (F3: require-signed must never STRAND a legacy delete, only harden fmt2).
    let Some(pv) = read_per_item_store(state_dir, vault) else {
        return true;
    };
    if pv.is_legacy_nouik(vault) {
        return true; // legacy NoUik vault: no signed owner set → legacy drop
    }
    // fmt2 vault: require a verified owner tombstone; an unsigned/forged delete parks.
    let (Some(sig), Some(signer)) = (
        body.get("tombstone_sig").and_then(|v| v.as_str()).filter(|s| !s.is_empty()),
        body.get("tombstone_signer").and_then(|v| v.as_str()).filter(|s| !s.is_empty()),
    ) else {
        tracing::warn!(vault = %vault, "tombstone: require-signed ON but the delete carries no owner signature; NOT dropping");
        return false;
    };
    if pv.tombstone_verified(vault, signer, sig) {
        true
    } else {
        tracing::warn!(vault = %vault, signer = %signer, "tombstone: owner signature did NOT verify; NOT dropping (possible server-forged delete)");
        false
    }
}

/// After a runtime pull wrote a new `vault.dat`, refresh the in-memory cache
/// for an UNLOCKED vault using the retained state key `K` — no passkey. If the
/// vault is Locked (no retained `K`), nothing is cached to refresh; the next
/// unlock reads the new file. If the new ciphertext was sealed under a ROTATED
/// `K`, `K` can't open it — leave the cache and log (graceful: lock+unlock to
/// see new state), mirroring the post-write refresh path.
fn refresh_after_pull(state: &Arc<AppState>, vault: &str) {
    let Some(k) = state.cloned_state_key(vault) else {
        return; // Locked — no retained K
    };
    let vault_path = state
        .config
        .state_dir
        .join("vaults")
        .join(vault)
        .join("vault.dat");
    let sealed = match sealed_vault::read(&vault_path) {
        Ok(Some(v)) => v,
        _ => return,
    };
    match crate::server::handlers::metadata::decrypt_vault_view_with_key(&k, &sealed) {
        Ok(view) => {
            let cache = crate::server::handlers::approve::bootstrap_cache_from_view(&view, state);
            state.unlock_vault(vault.to_string(), cache, k);
            tracing::info!(vault = %vault, "cloud sync: cache refreshed after pull (no re-unlock)");
        }
        Err(_) => {
            tracing::warn!(
                vault = %vault,
                "cloud sync: retained key can't open pulled ciphertext (rotated K?); lock+unlock to see new state"
            );
        }
    }
}

/// Push the local `vault.dat` (sealed blob) back up to the cloud so OTHER
/// devices' daemons pull it. Used after a daemon-side mutation the browser
/// didn't make — notably an OAuth connect's exchange: Google authorization
/// codes are SINGLE-USE, so only one daemon can redeem a pending connect; the
/// resulting refresh_token must propagate to every device via the cloud blob
/// (otherwise other daemons forever sync only the stale `*_oauth_pending`).
///
/// **Cloud-blind preserved:** the pushed blob is ciphertext (passkey-sealed,
/// `W_c` not in it) — the cloud stores it blind, never decrypts. Best-effort:
/// a local-only/unpaired daemon or any network error just logs; the
/// refresh_token is already durable in the local `vault.dat` either way.
pub async fn push_blob_best_effort(state: &Arc<AppState>, vault_id: &str) {
    let Ok(cfg) = active::load() else { return };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return; // local-only daemon — nothing to push to
    };
    let Some(dk) = device_key() else {
        return; // unpaired — no device-key to authenticate the push
    };
    let vault_path = state
        .config
        .state_dir
        .join("vaults")
        .join(vault_id)
        .join("vault.dat");
    let client = match crate::cli::egress_proxy::client(Duration::from_secs(15)) {
        Ok(c) => c,
        Err(_) => return,
    };
    let url = format!("{}/v/{}/blob", cloud.trim_end_matches('/'), vault_id);

    // Optimistic-concurrency push. Each attempt re-reads the local vault.dat
    // (it may have been re-sealed by the conflict-recovery step below) and PUTs
    // it with `base_version` = the version we believe the cloud row is at. A
    // `409 {conflict, version}` means another writer won the race: we pull the
    // newer blob (persisted under the SAME K — one-K-per-id), re-apply our
    // daemon-side mutation on the fresh state (the OAuth re-seal), then retry
    // with the cloud's new version as the next base. Bounded to MAX_CAS_RETRIES;
    // after the bound we give up (best-effort — the local vault.dat is durable).
    const MAX_CAS_RETRIES: u32 = 3;
    for attempt in 0..=MAX_CAS_RETRIES {
        // Build the request body in an inner scope so `sealed` (a `SealedVault`,
        // not `Send`) is dropped BEFORE any later `.await` — keeping this future
        // `Send` for `tokio::spawn`. Re-read each attempt: a prior 409's recovery
        // re-sealed vault.dat. base_version = the version we last recorded for
        // this row (opts into server-side CAS; legacy v1.0.22 omits it → LWW).
        let body = {
            let sealed = match sealed_vault::read(&vault_path) {
                Ok(Some(v)) => v,
                _ => return,
            };
            let blob = match serde_json::to_value(&sealed) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(vault = %vault_id, "push-back: serialize failed: {}", e);
                    return;
                }
            };
            let base_version = read_local_version(&state.config.state_dir, vault_id);
            serde_json::json!({ "blob": blob, "base_version": base_version })
        };
        let resp = match client
            .put(&url)
            .bearer_auth(&dk)
            .dik_pop("PUT", &url, &serde_json::to_vec(&body).unwrap_or_default())
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(vault = %vault_id, "push-back: PUT failed: {}", e);
                return;
            }
        };

        let status = resp.status();
        if status.as_u16() == 409 {
            // Drop the response (and its borrow of the connection) before any
            // await below, so this future stays `Send` for `tokio::spawn`.
            drop(resp);
            if attempt == MAX_CAS_RETRIES {
                tracing::warn!(
                    vault = %vault_id,
                    "push-back: gave up after {} CAS retries (local vault.dat is durable)",
                    MAX_CAS_RETRIES
                );
                return;
            }
            tracing::info!(vault = %vault_id, attempt, "push-back: 409 conflict; pulling newer blob and re-applying");
            // Cloud moved on: pull the winner under the same K, re-apply our
            // mutation, then loop to retry with the fresh base_version. Factored
            // into its own fn so no non-`Send` request-build local can leak
            // across its awaits (keeps `push_blob_best_effort` spawnable).
            if !recover_after_conflict(state, cloud, vault_id, &dk).await {
                return; // give up (deleted, or pull error) — already logged
            }
            continue;
        }

        if !status.is_success() {
            tracing::warn!(vault = %vault_id, "push-back: cloud rejected (HTTP {})", status);
            return;
        }

        // Record the version the cloud assigned, so our OWN watcher doesn't treat
        // the blob we just pushed as a newer remote change and re-pull it.
        if let Ok(body) = resp.json::<serde_json::Value>().await {
            if let Some(version) = body.get("version").and_then(|v| v.as_u64()) {
                let _ = std::fs::write(
                    version_sidecar(&state.config.state_dir, vault_id),
                    version.to_string(),
                );
            }
        }
        tracing::info!(vault = %vault_id, "push-back: pushed refreshed sealed blob to cloud");
        return;
    }
}

/// One CAS-conflict recovery step for `push_blob_best_effort`: pull the winning
/// blob (persisted under the SAME K — one-K-per-id), then re-apply the
/// daemon-side mutation (the pending OAuth connect re-seal) on the fresh state.
/// Returns `true` to retry the PUT, `false` to give up (a tombstone showed up
/// mid-push → local state dropped, or the pull errored). Kept separate so its
/// await scopes are clean and the caller's future stays `Send`.
async fn recover_after_conflict(
    state: &Arc<AppState>,
    cloud: &str,
    vault_id: &str,
    dk: &str,
) -> bool {
    // Pull the winning blob and persist it under the same K. This writes
    // vault.dat AND updates the .blob_version sidecar to the cloud's new
    // version, which becomes our next `base_version`.
    match pull(&state.config.state_dir, cloud, vault_id, dk).await {
        Ok(PullOutcome::Updated(_)) | Ok(PullOutcome::Unchanged) => {}
        Ok(PullOutcome::Deleted) => {
            // Deleted out from under us mid-push — stop and drop local state
            // (under the write lock; we're serving) and never resurrect a
            // tombstoned vault.
            drop_local_vault_locked(state, vault_id).await;
            tracing::info!(vault = %vault_id, "push-back: vault deleted upstream during conflict; dropped local state");
            return false;
        }
        Err(e) => {
            tracing::warn!(vault = %vault_id, "push-back: conflict-recovery pull failed: {}", e);
            return false;
        }
    }
    // Re-apply our daemon-side mutation (the pending OAuth connect) on top of the
    // freshly-pulled state and re-seal vault.dat. Uses the retained K (no
    // passkey); no-ops if locked or nothing pending.
    //
    // We call `apply_pending_connects` (the push-FREE inner step), NOT the public
    // `process_vault_connects` (which would spawn another `push_blob_best_effort`
    // and form an async-recursion cycle the compiler can't prove `Send`). We are
    // already inside the push loop: the very next iteration re-reads the re-sealed
    // vault.dat and re-PUTs, so the fan-out is covered without the recursive edge.
    crate::auth::connect::apply_pending_connects(state, vault_id, None).await;
    true
}

/// Fetch the account-level agent-key hash-set (`/api/vault/agents/hashes`,
/// device-key authed). Returns None on any failure (caller keeps the prior
/// set). The hashes are sha256(token) hex — the broker validates a presented
/// key by re-hashing and checking membership; the cloud never sees plaintext.
async fn fetch_agent_key_hashes(
    client: &reqwest::Client,
    cloud: &str,
    device_key: &str,
) -> Option<std::collections::HashSet<String>> {
    let url = format!("{}/api/vault/agents/hashes", cloud.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .bearer_auth(device_key)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let keys = body.get("keys")?.as_array()?;
    Some(
        keys.iter()
            .filter_map(|k| {
                k.get("hash")
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string())
            })
            .collect(),
    )
}

/// One-shot refresh of the broker's agent-key hash-set. Best-effort + gated
/// like the blob sync (no-op for a local-only/unpaired daemon). Call once
/// before serving so the broker accepts account agent-keys from the start.
pub async fn sync_agent_keys_once(state: &Arc<AppState>) {
    sync_agent_keys_with_timeout(state, Duration::from_secs(15)).await;
}

async fn sync_agent_keys_with_timeout(state: &Arc<AppState>, timeout: Duration) {
    let cfg = match active::load() {
        Ok(c) => c,
        Err(_) => return,
    };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return;
    };
    let Some(dk) = device_key() else {
        return;
    };
    let client = match crate::cli::egress_proxy::client(timeout) {
        Ok(c) => c,
        Err(_) => return,
    };
    if let Some(hashes) = fetch_agent_key_hashes(&client, cloud, &dk).await {
        let n = hashes.len();
        // Log only when the set actually moved — this runs on a 30s loop, and
        // an unconditional line here is the daemon's loudest idle chatter.
        if state.set_agent_key_hashes(hashes) {
            tracing::info!(count = n, "agent-key hash-set updated");
        }
    }
}

/// One serialized refresh on an agent-key AUTH MISS. A key minted seconds ago
/// (`sc agent add` prints the agent's env → the agent uses it immediately)
/// would otherwise sit invalid for up to the 30s loop interval — the exact
/// window the install flow now hits. The tokio Mutex is held ACROSS the fetch:
/// a concurrent miss WAITS for the in-flight refresh (then sees the fresh
/// stamp) instead of being bounced to a reject, and a bad-key flood is capped
/// at one outstanding backend call per 2s window. The short 3s timeout bounds
/// the reject path's latency when the backend is down. Always returns true =
/// "the hash-set is now as fresh as it gets — re-check membership".
pub async fn refresh_agent_keys_on_miss(state: &Arc<AppState>) -> bool {
    const DEBOUNCE: Duration = Duration::from_secs(2);
    let mut last = state.agent_key_resync.lock().await;
    if matches!(*last, Some(t) if t.elapsed() < DEBOUNCE) {
        return true;
    }
    *last = Some(std::time::Instant::now());
    sync_agent_keys_with_timeout(state, Duration::from_secs(3)).await;
    true
}

/// Agent-hash poll cadence while the SSE stream is healthy (v1.1): the
/// stream's `agent_hashes` event plus the resync-on-reconnect fire are the
/// propagation path, so this poll is pure belt-and-suspenders — 600s keeps
/// the documented bound ("revocation: instant, worst case 10 min"; Railway's
/// ≤15-min rotation forces the reconnect resync regardless). Add-key latency
/// is independent of the cadence either way: `refresh_agent_keys_on_miss`
/// refetches on first sight of an unknown key.
const AGENT_KEYS_CADENCE_STREAMED: Duration = Duration::from_secs(600);
/// Stream down or `sync_stream=off`: the pre-v1.1 30s — degraded
/// environments keep the poll as their ONLY propagation path.
const AGENT_KEYS_CADENCE_POLL: Duration = Duration::from_secs(30);

/// Cadence selection, factored for the unit test. The relaxed cadence needs
/// PROOF the events can reach us (`agent_hash_events_live()`: live stream
/// AND the backend declared the cap in hello) — bare stream health would
/// relax the poll against a v1-only backend that never emits the event.
fn agent_keys_cadence(agent_hash_events_live: bool) -> Duration {
    if agent_hash_events_live {
        AGENT_KEYS_CADENCE_STREAMED
    } else {
        AGENT_KEYS_CADENCE_POLL
    }
}

/// Periodically refresh the agent-key hash-set so a dashboard revoke / a newly
/// added agent takes effect on this daemon. Detached, best-effort. v1.1:
/// event-driven — the SSE dispatcher fires the agent-hash notify on an
/// `agent_hashes` stream event AND after every reconnect hello, either of
/// which resyncs immediately; the sleep is the fallback bound, mode-sized by
/// stream health. Logging stays inside `sync_agent_keys_once` (only on a
/// hash-set CHANGE), so neither wake source adds idle chatter.
pub async fn sync_agent_keys_loop(state: Arc<AppState>) {
    /// ★ Storm floor, mirroring `refresh_agent_keys_on_miss`'s 2s debounce:
    /// a chatty/buggy stream costs ≤1 hash-set fetch per 2s, never
    /// RTT-speed refetching (each fetch builds a fresh client = TLS).
    const FETCH_FLOOR: Duration = Duration::from_secs(2);
    loop {
        sync_agent_keys_once(&state).await;
        let fetched = tokio::time::Instant::now();
        // Arm AFTER the fetch: `notify_one` parks a permit, so an event that
        // fired mid-fetch completes this wait instantly (one redundant
        // cursor-cheap refetch at worst, never a lost revoke).
        loop {
            tokio::select! {
                _ = crate::sync_stream::agent_hashes_notified() => break,
                _ = tokio::time::sleep(agent_keys_cadence(crate::sync_stream::agent_hash_events_live())) => break,
                // A health flip mid-sleep re-sizes the wait: a 600s streamed
                // sleep must not ride across an Up→Down flip — the 30s
                // Down-mode promise is per-mode, not per-cycle.
                _ = crate::sync_stream::stream_health_edge() => continue,
            }
        }
        tokio::time::sleep_until(fetched + FETCH_FLOOR).await;
    }
}

// ── Audit shipper (de-daemon, DE_DAEMON.md §4) ──────────────────────────────
// Local-first outbox: the daemon already writes every op to its per-vault
// `audit.db` synchronously (offline-safe). This loop is the DELIVERY half — it
// pushes terminal Use-op rows (synced=0) to the cloud `audit_events` table so
// the console can show activity WITHOUT a cloud daemon. Best-effort + gated
// exactly like blob sync: a local-only / unpaired daemon never ships. The
// backend UPSERTs on the daemon-minted `event_id`, so at-least-once delivery
// (ship, then crash before marking) is idempotent.

/// Max rows shipped per vault per backend round-trip. Bounds request size; a
/// larger backlog drains across successive batches within one sweep.
const AUDIT_SHIP_BATCH: u32 = 200;

/// One audit event in the cloud-ingest wire shape. The backend stamps
/// `vault_id` (from the URL path) and `account_id` (from the authenticated
/// device-key) — the daemon never asserts ownership in the body. Secret values,
/// query strings, and request/response bodies are NEVER included (audit.rs only
/// ever records method / sanitized path / status / timestamps / key prefix).
#[derive(serde::Serialize)]
struct AuditEventWire {
    event_id: String, // daemon-minted op id; the backend's UPSERT key
    ts: i64,          // event time (unix secs): decided_at, else created_at
    decision: String, // allowed | approved | denied | rejected | expired | cancelled
    op_id: String,    // approval linkage (= event_id for Use ops)
    act_kind: String, // 'use' | ceremony kinds (enroll/write/…)
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>, // "METHOD path", e.g. "POST /v1/chat/completions"
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>, // ceremony subject (key name / connection id)
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>, // agent api-key PREFIX (= cloud api_keys.prefix)
}

fn event_from_row(row: &crate::audit::ApprovalRow) -> AuditEventWire {
    let action = match (&row.method, &row.path) {
        (Some(m), Some(p)) => Some(format!("{} {}", m, p)),
        (Some(m), None) => Some(m.clone()),
        (None, Some(p)) => Some(p.clone()),
        (None, None) => None,
    };
    AuditEventWire {
        event_id: row.id.clone(),
        ts: row.decided_at.unwrap_or(row.created_at),
        decision: row.status.clone(),
        op_id: row.id.clone(),
        act_kind: row.act_kind.clone(),
        service: row.service.clone(),
        action,
        target: row.target.clone(),
        agent_id: row.agent_prefix.clone(),
    }
}

/// The `audit_ceremonies` switch: ship control-plane terminal outcomes
/// alongside Use ops? Default ON (user decision 2026-07-14: the console's
/// approved tile counts every consent terminal). Same shape as
/// `sync_stream_enabled` — env `SAFECLAW_AUDIT_CEREMONIES` beats the config
/// key, `off`-family synonyms disable, anything unrecognized stays on the
/// default but warns once.
fn audit_ceremonies_enabled(cfg: &crate::cli::active::CliConfig) -> bool {
    let v = std::env::var("SAFECLAW_AUDIT_CEREMONIES")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            cfg.audit_ceremonies
                .as_ref()
                .map(|s| s.trim().to_ascii_lowercase())
        });
    match v.as_deref() {
        None | Some("auto" | "on") => true,
        Some("off" | "0" | "false" | "no" | "disabled") => false,
        Some(other) => {
            static WARNED: std::sync::Once = std::sync::Once::new();
            let other = other.to_string();
            WARNED.call_once(|| {
                tracing::warn!(
                    value = %other,
                    "audit_ceremonies: unrecognized value (expected auto|off); treating as auto"
                );
            });
            true
        }
    }
}

/// Periodically ship each synced vault's unshipped audit rows to the cloud.
/// Detached + best-effort: any failure backs off to the next tick and never
/// affects serving.
pub async fn ship_audit_loop(state: Arc<AppState>) {
    loop {
        ship_audit_once(&state).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// One sweep across all synced vaults (active ∪ known_vaults).
pub async fn ship_audit_once(state: &Arc<AppState>) {
    let Ok(cfg) = active::load() else {
        return;
    };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return; // local-only daemon — nowhere to ship
    };
    let Some(dk) = device_key() else {
        return; // unpaired — no device-key to authenticate the ingest
    };
    let cloud = cloud.trim_end_matches('/');
    let client = match crate::cli::egress_proxy::client(Duration::from_secs(15)) {
        Ok(c) => c,
        Err(_) => return,
    };
    let ceremonies = audit_ceremonies_enabled(&cfg);
    for vault in synced_vault_ids(&cfg) {
        ship_vault_audit(state, &client, cloud, &dk, &vault, ceremonies).await;
    }
}

async fn ship_vault_audit(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    cloud: &str,
    device_key: &str,
    vault: &str,
    ship_ceremonies: bool,
) {
    // `for_vault` only opens DBs for vaults that exist on disk; a known-but-not-
    // yet-served vault just yields NotFound and is skipped this tick.
    let store = match state.audits.for_vault(vault) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Opportunistic retention: prune local rows past the vault's window so the
    // outbox + audit.db don't grow unbounded. Cloud-side TTL is separate (§4).
    if let Some(days) = state.audit_retention_days(vault) {
        if let Some(cutoff) = retention_cutoff(days) {
            let _ = store.prune_older_than(cutoff);
        }
    }

    // Drain the backlog in batches; stop on the first error (retry next tick)
    // or when a short page signals the queue is empty.
    loop {
        let rows = match store.list_unsynced(AUDIT_SHIP_BATCH, ship_ceremonies) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(vault = %vault, "audit ship: list_unsynced failed: {}", e);
                return;
            }
        };
        if rows.is_empty() {
            return;
        }
        let events: Vec<AuditEventWire> = rows.iter().map(event_from_row).collect();
        let url = format!("{}/v/{}/audit", cloud, vault);
        let body = serde_json::json!({ "events": events });
        let resp = client
            .post(&url)
            .bearer_auth(device_key)
            .dik_pop("POST", &url, &serde_json::to_vec(&body).unwrap_or_default())
            .json(&body)
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
                let n = ids.len();
                if let Err(e) = store.mark_synced(&ids) {
                    tracing::warn!(vault = %vault, "audit ship: mark_synced failed: {}", e);
                    return; // avoid re-shipping the same batch in a tight loop
                }
                tracing::debug!(vault = %vault, count = n, "audit shipped");
                if (n as u32) < AUDIT_SHIP_BATCH {
                    return; // drained
                }
            }
            Ok(r) => {
                tracing::debug!(
                    vault = %vault, status = %r.status(),
                    "audit ship: backend rejected batch; retrying next tick"
                );
                return;
            }
            Err(e) => {
                tracing::debug!(vault = %vault, "audit ship: unreachable backend: {}", e);
                return;
            }
        }
    }
}

/// Unix-seconds cutoff for `days` of retention, or None on a clock error.
fn retention_cutoff(days: u32) -> Option<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(now - (days as i64) * 86_400)
}

/// Long-lived background sync watcher — one task per synced vault, holding up
/// to TWO server long-polls concurrently (`tokio::select!`), both ~25s
/// server-held so an idle daemon PARKS instead of polling:
///
///  - `/blob/wait?since=<.blob_version>` — the LIFECYCLE channel, and the sole
///    lifecycle AUTHORITY (tombstone drop, auth-stop). For a whole-blob vault a
///    wake also delivers the new sealed blob; for a per-item vault the row is a
///    lifecycle marker whose `version` still bumps on keyset/lifecycle writes.
///  - `/items/wait?since=<items_seq>` — the CONTENT channel: a per-item write
///    anywhere (web policy edit, second device) bumps a row's `seq` and wakes
///    us instantly. ADVISORY wake-only: every error here just backs off and
///    re-arms — it never stops the loop and never drops state (a tombstoned
///    vault 403s on this route; the blob channel delivers the actual verdict).
///    Disabled for the run on 404 (backend without the route); blob-channel
///    wakes still pull items.
///
/// Either wake runs the same serial pull block (`pull_and_process`) IN THIS
/// task, so `pull_items`' read-modify-write of the per-item store stays
/// single-flight per vault — same serialization as the old one-channel loop.
///
/// THIRD SHAPE (design/sse-sync.md): when the SSE dispatcher's hello has
/// confirmed this vault (`cell.mode() == Sse`), the round holds NO long-polls
/// at all — it selects over the cell's wake / an event-independent 300s
/// reconcile deadline / the global stream-health watch, and reacts to merged
/// hints by running the SAME pull paths (blob `?since` probe through the
/// shared `handle_blob_wake_body`, then `pull_and_process`). The mode is
/// re-read every round, so the task flips shapes the moment the dispatcher
/// demotes it (stream death) or promotes it (hello). Everything stays
/// cursor-gated, so duplicate/stale/echoed events are no-ops by construction.
///
/// The `since` cursors are what make parking work: the server answers the
/// instant its version/seq exceeds `since`. A cursor that never advances
/// (the pre-0.9.36 per-item bug — lifecycle markers skipped the sidecar
/// write) turns the 25s long-poll into a ~1.5s hot loop.
/// Best-effort + detached: a local-only/unpaired/offline daemon just no-ops or
/// backs off, and any failure here NEVER affects serving. See
/// [[project_realtime_sync_v1_decision]].
pub async fn watch_loop(
    state: Arc<AppState>,
    vault: String,
    cloud: String,
    dk: String,
    cell: Arc<WakeCell>,
    mut health_rx: tokio::sync::watch::Receiver<StreamHealth>,
) {
    let state_dir = state.config.state_dir.clone();
    // Read-timeout MUST exceed the server's long-poll hold (~25s) plus slack.
    const WATCH_TIMEOUT: Duration = Duration::from_secs(40);
    let mut client = match crate::cli::egress_proxy::client(WATCH_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("cloud sync watch: client init failed: {}", e);
            return;
        }
    };
    tracing::info!(vault = %vault, "cloud sync watch loop started");

    enum Wake {
        Blob(Result<reqwest::Response, reqwest::Error>),
        Items(Result<reqwest::Response, reqwest::Error>),
        /// The reconciliation floor fired — no channel answered for a full
        /// interval. Run the pull block anyway so staleness stays BOUNDED even
        /// when both long-poll channels are wedged (laptop sleep / network
        /// flap can strand a hold in a state where wakes stop arriving — seen
        /// live 2026-07-13: a gmail connect's pre-sealed entry sat in the
        /// cloud >1h while the daemon's channels stayed silent; `sc sync`
        /// adopted it instantly).
        Reconcile,
        /// The SSE dispatcher flipped stream health. Nothing to pull — the
        /// point is to drop the held long-polls and re-read the cell's mode
        /// at the loop top NOW, instead of waiting out a full ~25s hold
        /// before noticing a recovered stream.
        Health,
    }

    /// Upper bound on how stale a wedged watcher can go. Long-poll wakes are
    /// still the fast path (instant); this timer only matters when they stop
    /// coming. One cheap cursor-read per interval per vault — noise next to
    /// the ~25s park cycle.
    const RECONCILE_INTERVAL: Duration = Duration::from_secs(300);
    /// Rebuild the HTTP client after this many consecutive channel errors. A
    /// poisoned connection pool (network flap / laptop sleep leaves half-open
    /// sockets, a dead egress-proxy hop) fails every request from THIS client
    /// while a fresh one works — seen live 2026-07-13: a laptop watcher went
    /// silent for >1h while a fresh `sc sync` client adopted rows instantly.
    const REBUILD_AFTER_ERRS: u32 = 3;
    /// Wall-vs-monotonic divergence that reads as "the system slept mid-round".
    /// macOS/Linux monotonic clocks exclude suspend, so a lid-close shows up as
    /// wall time far ahead of monotonic time for the same round.
    const SUSPEND_SLACK: Duration = Duration::from_secs(30);

    let mut backoff = Duration::from_secs(2);
    let mut consec_errs = 0u32;
    let mut items_channel = true; // false after a 404 (backend without /items/wait)
                                  // ★ SSE-shape reconcile clock, INDEPENDENT of event traffic: under
                                  // long-poll the loop-top cursor read + 25s turnover WAS the implicit
                                  // reconcile; the SSE shape holds no polls, so it must carry its own bound
                                  // (pg_cron-class writes, missed emits) that steady events cannot starve.
    let mut last_reconcile = std::time::Instant::now();
    loop {
        let round_wall = std::time::SystemTime::now();
        let round_mono = std::time::Instant::now();

        // ── Third shape: SSE wake cell (design/sse-sync.md) ──────────
        // Mode is set only by the dispatcher: Sse while the stream's hello
        // covers this vault, Fallback otherwise. Every branch below ends in
        // `continue` (or `return` on tombstone), so the long-poll code after
        // this block is untouched when the shape is active.
        if cell.mode() == Mode::Sse {
            // Arm the wake BEFORE reading the cell — the standard
            // missed-wakeup pattern: a merge landing between the check and
            // the park is captured as a stored Notify permit and completes
            // the select instantly.
            let notified = cell.notified();
            if !cell.has_work() {
                let deadline = last_reconcile + RECONCILE_INTERVAL;
                let until_reconcile = deadline.saturating_duration_since(std::time::Instant::now());
                tokio::select! {
                    _ = notified => {}
                    _ = tokio::time::sleep(until_reconcile) => {}
                    r = health_rx.changed() => {
                        if r.is_err() {
                            // Dispatcher gone (should never happen): fall
                            // back to long-poll for good rather than idling
                            // on a stream nobody feeds.
                            cell.set_mode(Mode::Fallback);
                        }
                        continue; // re-pick the shape at the loop top
                    }
                }
            }

            // Suspend detection runs per round in BOTH shapes (an SSE round =
            // wake-to-wake). No per-task HTTP client to rebuild here — the
            // dispatcher's own 45s no-bytes liveness reconnects the stream
            // ≤45s after resume; this task just catches up on content.
            let wall = round_wall.elapsed().unwrap_or_default();
            let mono = round_mono.elapsed();
            if wall > mono + SUSPEND_SLACK {
                tracing::info!(
                    vault = %vault,
                    slept_secs = (wall - mono).as_secs(),
                    "cloud sync watch: system suspend detected mid-round — reconciling"
                );
                pull_and_process(&state, &state_dir, &cloud, &vault, &dk, "resume").await;
                backoff = Duration::from_secs(2);
                continue; // pending work (if any) is still in the cell
            }

            let work = cell.take_work();
            let mut clean = true;
            let mut auth_park = false;
            // Whether the vault-event branch already ran the serial pull
            // block (it runs unconditionally inside handle_blob_wake_body) —
            // a write that emitted BOTH a vault and an items hint must not
            // pay for the pulls twice in the same wake.
            let mut pulled = false;

            // Pending vault slot. In Sse mode the vault EVENT is the
            // lifecycle authority (design doc) — the same trust as the blob
            // channel's body (authenticated TLS to our own backend), and an
            // explicit "deleted" stays the ONLY local-state destroyer.
            if let Some((version, status)) = work.vault {
                if status == VaultStatus::Deleted {
                    // §15 leg A: the SSE vault EVENT carries no tombstone signature, so
                    // it can direct-drop only under the legacy (flag-OFF) path. With
                    // require-signed ON, do NOT drop/stop here — fall through so the
                    // reconcile blob probe re-fetches the SIGNED tombstone body, which
                    // `handle_blob_wake_body` gates against the fold-owner set.
                    if !crate::principal_ledger::require_signed_tombstone() {
                        drop_local_vault_locked(&state, &vault).await;
                        tracing::info!(vault = %vault, "cloud sync: vault deleted upstream; dropped local state");
                        // Task exit drops the sole strong ref to the cell; the
                        // dispatcher prunes this vid from `?vids` at its next
                        // reconnect.
                        return;
                    }
                }
                // ★ Cursor re-read from disk at use time, never cached across
                // parks — the loop-top discipline the long-poll shape gets
                // for free.
                if version > read_local_version(&state_dir, &vault) {
                    // MIRROR: the sse-reconcile branch below folds the same
                    // probe outcomes — keep the arms in step.
                    match probe_blob_and_handle(
                        &state,
                        &state_dir,
                        &cloud,
                        &vault,
                        &dk,
                        "sse-vault",
                    )
                    .await
                    {
                        Ok(BlobWake::Stopped) => return,
                        Ok(BlobWake::Unchanged) => {}
                        Ok(BlobWake::Handled {
                            persist_failed,
                            pulls_ok,
                        }) => {
                            pulled = true;
                            if !persist_failed && pulls_ok {
                                // A clean Handled round ≡ a reconcile (blob
                                // `?since` probe + the full pull block — the
                                // exact requests the 300s floor issues), so
                                // stamp the clock like the fallback blob arm
                                // does; under steady vault events the floor
                                // would otherwise re-run an identical round
                                // every 300s for nothing.
                                last_reconcile = std::time::Instant::now();
                            }
                            clean = clean && !persist_failed && pulls_ok;
                        }
                        Err(ProbeError::Auth) => auth_park = true,
                        Err(ProbeError::Other(e)) => {
                            tracing::debug!(vault = %vault, "cloud sync watch: sse blob probe failed: {}", e);
                            clean = false;
                        }
                    }
                }
            }

            // items/keys flags → the shared serial pull block (pull_keys
            // runs first inside it, as today) — skipped when the vault
            // branch just ran it (`pulled`); the flags' work rode along.
            if !auth_park && !pulled && (work.items || work.keys) {
                pulled = true;
                if !pull_and_process(&state, &state_dir, &cloud, &vault, &dk, "sse-wake").await {
                    clean = false;
                }
                // §15 leg-B: a just-adopted membership triple may have offboarded us.
                if enforce_membership_presence(&state, &vault).await {
                    return; // wiped → stop this watcher (a re-pull would re-adopt)
                }
            }

            // ★ The reconcile floor fires on schedule even under steady
            // events (see `last_reconcile`): blob `?since` probe through the
            // shared handler, plus the pull block.
            if !auth_park && last_reconcile.elapsed() >= RECONCILE_INTERVAL {
                let mut ok = true;
                match probe_blob_and_handle(
                    &state,
                    &state_dir,
                    &cloud,
                    &vault,
                    &dk,
                    "sse-reconcile",
                )
                .await
                {
                    // MIRROR: keep these arms in step with the sse-vault
                    // branch above — same probe, same outcome policy; only
                    // the Unchanged handling differs by design.
                    Ok(BlobWake::Stopped) => return,
                    Ok(BlobWake::Unchanged) => {
                        // Blob row is current; the reconcile still owns
                        // items/keys staleness — run the pull block
                        // (cursor-gated, mostly `{unchanged}`-cheap), unless
                        // this very round already ran it cleanly.
                        ok = (pulled && clean)
                            || pull_and_process(
                                &state,
                                &state_dir,
                                &cloud,
                                &vault,
                                &dk,
                                "sse-reconcile",
                            )
                            .await;
                        // §15 leg-B: periodic fallback catch for an offboard the
                        // SSE wake missed.
                        if enforce_membership_presence(&state, &vault).await {
                            return;
                        }
                    }
                    Ok(BlobWake::Handled {
                        persist_failed,
                        pulls_ok,
                    }) => ok = !persist_failed && pulls_ok,
                    Err(ProbeError::Auth) => auth_park = true,
                    Err(ProbeError::Other(e)) => {
                        tracing::debug!(vault = %vault, "cloud sync watch: sse reconcile probe failed: {}", e);
                        ok = false;
                    }
                }
                if ok {
                    last_reconcile = std::time::Instant::now();
                } else {
                    // Deadline NOT advanced: the bounded retry below re-runs
                    // it on the backoff, not in another 300s.
                    clean = false;
                }
            }

            if auth_park {
                // 401/403 parking semantics preserved from the long-poll
                // shape: park, don't die — a transient 403 (backend deploy,
                // auth migration) must not end this device's sync until
                // restart. Real deletion arrives as a vault event, never as
                // a 403.
                cell.reinject(work);
                tracing::warn!(
                    vault = %vault,
                    "cloud sync watch: auth rejected on sse pull; retrying in {}s",
                    AUTH_RETRY.as_secs()
                );
                tokio::time::sleep(AUTH_RETRY).await;
                continue;
            }

            if clean {
                backoff = Duration::from_secs(2);
            } else {
                // ★ Bounded pull-failure retry (design doc): the long-poll
                // shape gets re-delivery for free — an unadvanced cursor
                // makes the server answer the re-armed hold instantly — but
                // SSE consumed this event ONCE, so a failed pull must retry
                // here. Re-inject the taken work (the cell's monotone merge
                // keeps any racing fresher event on top) and eat the existing
                // 2s→60s backoff instead of waiting out the reconcile floor.
                // The pull FLAGS are forced on: the blob probe may already
                // have advanced the cursor before a sub-pull failed, which
                // would version-gate a bare vault slot into a no-op retry —
                // the retry's job is precisely to re-run the pull block, and
                // a spurious re-pull is one cheap cursor-gated {unchanged}.
                cell.reinject(Work {
                    vault: work.vault,
                    items: true,
                    keys: true,
                });
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
            continue;
        }

        // ── Fallback shapes: the pre-SSE long-poll rounds, unchanged ──────
        let local_ver = read_local_version(&state_dir, &vault);
        let blob_url = format!("{}/v/{}/blob/wait?since={}", cloud, vault, local_ver);
        let blob_fut = client
            .get(&blob_url)
            .bearer_auth(&dk)
            .dik_pop("GET", &blob_url, &[])
            .send();
        // The content channel only exists once the vault has a per-item store
        // (its cursor lives there). Reading the store each round is a small
        // local file parse — negligible against a 25s park.
        let items_since = if items_channel {
            read_per_item_store(&state_dir, &vault).map(|pv| pv.items_seq)
        } else {
            None
        };
        let wake = match items_since {
            Some(seq) => {
                let items_url = format!("{}/v/{}/items/wait?since={}", cloud, vault, seq);
                let items_fut = client
                    .get(&items_url)
                    .bearer_auth(&dk)
                    .dik_pop("GET", &items_url, &[])
                    .send();
                // Whichever channel answers first wins; the loser is dropped
                // mid-hold (the server notices the close) and re-armed next
                // round. Worst case that's one extra request per ~25s window.
                tokio::select! {
                    r = blob_fut => Wake::Blob(r),
                    r = items_fut => Wake::Items(r),
                    _ = tokio::time::sleep(RECONCILE_INTERVAL) => Wake::Reconcile,
                    _ = health_changed(&mut health_rx) => Wake::Health,
                }
            }
            None => tokio::select! {
                r = blob_fut => Wake::Blob(r),
                _ = tokio::time::sleep(RECONCILE_INTERVAL) => Wake::Reconcile,
                _ = health_changed(&mut health_rx) => Wake::Health,
            },
        };

        // Suspend detection: wall time far ahead of monotonic time for one
        // round means the system slept mid-hold. Whatever state the parked
        // request / connection pool woke up in, don't trust it: fresh client,
        // immediate reconcile, fresh holds. This is what turns "laptop lid
        // reopened" into a ~1s catch-up instead of a silent stale watcher.
        let wall = round_wall.elapsed().unwrap_or_default();
        let mono = round_mono.elapsed();
        if wall > mono + SUSPEND_SLACK {
            tracing::info!(
                vault = %vault,
                slept_secs = (wall - mono).as_secs(),
                "cloud sync watch: system suspend detected mid-round — rebuilding client + reconciling"
            );
            if let Ok(c) = crate::cli::egress_proxy::client(WATCH_TIMEOUT) {
                client = c;
            }
            pull_and_process(&state, &state_dir, &cloud, &vault, &dk, "resume").await;
            backoff = Duration::from_secs(2);
            consec_errs = 0;
            continue; // drop the possibly-stale wake; fresh holds re-deliver
        }

        match wake {
            Wake::Blob(Ok(resp)) => match resp.status().as_u16() {
                200 => {
                    backoff = Duration::from_secs(2);
                    consec_errs = 0;
                    // A successful sync means our version is accepted — clear any
                    // stale SC_UPGRADE_REQUIRED flag (design 甲).
                    state.set_vault_upgrade_required(&vault, false);
                    let body: serde_json::Value = match resp.json().await {
                        Ok(b) => b,
                        Err(_) => {
                            tokio::time::sleep(backoff).await;
                            continue;
                        }
                    };
                    // Body handling lives in the SHARED handler (also fed by
                    // the SSE shape's blob probes) — behavior here is the
                    // pre-SSE arm verbatim: tombstone → drop + stop;
                    // unchanged → re-poll; else persist-under-lock / marker
                    // cursor advance, then the serial pull block; a persist
                    // failure never advanced the cursor, so it must eat a
                    // backoff or the instant re-answer becomes a hot loop.
                    match handle_blob_wake_body(
                        &state, &state_dir, &cloud, &vault, &dk, &body, "blob",
                    )
                    .await
                    {
                        BlobWake::Stopped => return,
                        BlobWake::Unchanged => {
                            // Long-poll window elapsed with no change — re-poll.
                            continue;
                        }
                        BlobWake::Handled { persist_failed, .. } => {
                            // A blob answer + the pull block ≡ a reconcile;
                            // stamping it keeps the SSE shape's clock fresh
                            // across a later mode flip (no behavior change in
                            // this shape — sub-pull errors stay best-effort
                            // here, exactly as before).
                            last_reconcile = std::time::Instant::now();
                            if persist_failed {
                                tokio::time::sleep(backoff).await;
                                backoff = (backoff * 2).min(Duration::from_secs(60));
                            }
                        }
                    }
                }
                404 => {
                    // No blob in the cloud yet — gentle retry.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                401 | 403 => {
                    // Distinguish a FORCED UPGRADE (`SC_UPGRADE_REQUIRED`: this daemon
                    // is too old for the vault's item format, design 甲) from a
                    // transient 403. On the former, flag the vault so the broker fails
                    // loudly with `sc upgrade` to the agent (not a silent park); else
                    // it's transient — park, don't die (backend deploy / auth
                    // migration). See AUTH_RETRY.
                    let status = resp.status();
                    let upgrade = resp
                        .json::<serde_json::Value>()
                        .await
                        .ok()
                        .and_then(|b| {
                            b.get("code")
                                .and_then(|v| v.as_str())
                                .map(|c| c == "SC_UPGRADE_REQUIRED")
                        })
                        .unwrap_or(false);
                    state.set_vault_upgrade_required(&vault, upgrade);
                    if upgrade {
                        tracing::warn!(vault = %vault, "cloud sync: SC_UPGRADE_REQUIRED — this daemon is too old for the vault format; run `sc upgrade`");
                    } else {
                        tracing::warn!(
                            vault = %vault,
                            "cloud sync watch: auth rejected (HTTP {}); retrying in {}s",
                            status,
                            AUTH_RETRY.as_secs()
                        );
                    }
                    tokio::time::sleep(AUTH_RETRY).await;
                }
                _ => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            },
            Wake::Items(Ok(resp)) => match resp.status().as_u16() {
                200 => {
                    backoff = Duration::from_secs(2);
                    consec_errs = 0;
                    let body: serde_json::Value = match resp.json().await {
                        Ok(b) => b,
                        Err(_) => {
                            tokio::time::sleep(backoff).await;
                            continue;
                        }
                    };
                    if body
                        .get("unchanged")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        // Long-poll window elapsed with no change — re-poll.
                        continue;
                    }
                    // Rows changed. The wait body carries them, but re-fetching via
                    // the shared pull block (same code as blob wakes + `sc sync`)
                    // keeps ONE adopt path; one cheap extra request per real change.
                    pull_and_process(&state, &state_dir, &cloud, &vault, &dk, "items").await;
                }
                404 => {
                    items_channel = false;
                    tracing::info!(vault = %vault, "cloud sync watch: /items/wait unavailable (404); content rides blob-channel wakes only");
                }
                401 | 403 => {
                    // Could be a deletion in progress (a tombstoned vault fails this
                    // route's ownership gate) or a revoked device — either way the
                    // blob channel owns the verdict. Back off, never stop from here.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                _ => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            },
            Wake::Reconcile => {
                // No channel answered for a full interval (normal rounds turn
                // over every ~25s). Whatever the holds are stuck on, the pull
                // block below re-reads the real cursors and adopts anything
                // missed; dropping the stale request futures re-arms both
                // channels fresh next round.
                tracing::info!(vault = %vault, "cloud sync watch: no wake for {}s — reconciling", RECONCILE_INTERVAL.as_secs());
                pull_and_process(&state, &state_dir, &cloud, &vault, &dk, "reconcile").await;
                last_reconcile = std::time::Instant::now();
            }
            Wake::Health => {
                // The SSE dispatcher flipped stream health; the cell's mode
                // is already set. Dropping the held long-polls and re-reading
                // the mode at the loop top IS the reaction — without this arm
                // a Fallback→Sse promotion would wait out a full ~25s hold.
            }
            Wake::Blob(Err(e)) | Wake::Items(Err(e)) => {
                // Transient (timeout/offline). The 40s read-timeout exceeds the
                // 25s server hold, so a clean long-poll return shouldn't error
                // here — worth a (debug) trace: a silent Err loop reads as "the
                // daemon is fine" while sync is actually down.
                consec_errs += 1;
                tracing::debug!(vault = %vault, errors = consec_errs, "cloud sync watch: channel error: {}", e);
                if consec_errs % REBUILD_AFTER_ERRS == 0 {
                    // Every request from this client failing while the network
                    // may be fine points at the client itself (poisoned pool /
                    // stale proxy tunnel). Swap it and reconcile — if the
                    // network really is down, the fresh client fails the same
                    // cheap way and we're back here one backoff later.
                    tracing::warn!(
                        vault = %vault,
                        errors = consec_errs,
                        "cloud sync watch: consecutive channel errors — rebuilding HTTP client + reconciling"
                    );
                    if let Ok(c) = crate::cli::egress_proxy::client(WATCH_TIMEOUT) {
                        client = c;
                    }
                    pull_and_process(&state, &state_dir, &cloud, &vault, &dk, "rebuild").await;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

/// Park the select arm forever when the health channel is CLOSED (dispatcher
/// exited — only possible once every vault task is gone, or on a dispatcher
/// panic). A raw `changed()` would resolve `Err` immediately and forever,
/// turning the fallback select into a hot loop; pending-forever makes the arm
/// simply go quiet while the long-poll arms keep working.
async fn health_changed(rx: &mut tokio::sync::watch::Receiver<StreamHealth>) {
    if rx.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Outcome of [`handle_blob_wake_body`] — the shared blob-body handler.
enum BlobWake {
    /// Tombstone: all local state dropped (under the write lock); the
    /// caller's watch task must exit.
    Stopped,
    /// `{unchanged:true}` freshness-probe answer — nothing to do; the pull
    /// block did NOT run (matches the long-poll arm's bare re-poll).
    Unchanged,
    /// Body handled and the serial pull block ran. `persist_failed` = a real
    /// blob failed to write; the cursor was NOT advanced, so the caller must
    /// back off (long-poll: the instant re-answer would hot-loop; SSE: the
    /// bounded retry re-arms it). `pulls_ok` = the keyset+item sub-pulls
    /// inside `pull_and_process` all succeeded — only the SSE shape acts on
    /// it (long-poll gets re-delivery for free and stays best-effort).
    Handled {
        persist_failed: bool,
        pulls_ok: bool,
    },
}

/// ★ The ONE runtime blob-body handler (design/sse-sync.md §Core,
/// "shared blob-body handler"), factored from the long-poll blob-200 arm so
/// the SSE shape reuses it verbatim. Deliberately NOT `classify_pull_body`:
/// that path (`pull` / `sc sync` parity) persists WITHOUT the per-vault write
/// lock — fine pre-serve, a race at watch time (a concurrent approve.rs
/// re-seal could interleave with the persist's tmp+rename). This handler
/// persists UNDER `vault_write_locks`, and holds the lock ONLY across the
/// persist — never across network calls or `process_vault_connects` (which
/// takes it itself; the invariant the whole sync module rests on).
///
/// Behavior is the pre-SSE arm verbatim:
///  1. `status:"deleted"` → drop ALL local state (zeroize K, remove
///     vault.dat + sidecar, close audit, forget CLI config) → `Stopped`.
///     Only an explicit tombstone destroys; a live-but-undecryptable blob is
///     log-only (refresh_after_pull).
///  2. `{unchanged:true}` → `Unchanged`, no pulls.
///  3. A real SealedState blob → persist under the lock (+ cache refresh); a
///     per-item lifecycle marker (or absent blob) → `record_blob_version`
///     ONLY — the cursor MUST advance or the wait channel answers instantly
///     forever (the pre-0.9.36 ~1.5s spin). Then the unconditional serial
///     pull block (`pull_and_process`) — content lives in /keys + /items.
async fn handle_blob_wake_body(
    state: &Arc<AppState>,
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    dk: &str,
    body: &serde_json::Value,
    channel: &str,
) -> BlobWake {
    if body.get("status").and_then(|v| v.as_str()) == Some("deleted") {
        // §15 leg A: gate the drop (dual-path). Flag OFF (default) → drop as today.
        // Flag ON → drop only on a verified owner tombstone; else park (keep watching).
        if tombstone_should_drop(state_dir, vault, body) {
            // Drop under the per-vault write lock so the destroy can't race a
            // concurrent approve.rs / connect write to vault.dat.
            drop_local_vault_locked(state, vault).await;
            tracing::info!(vault = %vault, "cloud sync: vault deleted upstream (owner-verified); dropped local state");
            return BlobWake::Stopped;
        }
        return BlobWake::Unchanged;
    }
    // Server-authoritative operational facts (team §4/§9): trust `kind` + advance
    // the offline-lease clock only from a server signature we can verify against
    // the pinned key (a fake/MITM server or a tampered cache is ignored); an
    // unsigned legacy envelope falls back to the plain `kind`. THE continuous
    // refresh path — long-poll and SSE both land here.
    apply_verified_envelope(state, vault, body);
    if body
        .get("unchanged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return BlobWake::Unchanged;
    }
    let version = body.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let mut persist_failed = false;
    if let Some(blob) = body.get("blob").filter(|b| b.get("lifecycle").is_none()) {
        // Serialize against approve.rs's vault.dat writes.
        let lock = {
            let mut locks = state.vault_write_locks.lock().unwrap();
            Arc::clone(
                locks
                    .entry(vault.to_string())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let _guard = lock.lock().await;
        if let Err(e) = persist_blob(state_dir, vault, blob, version) {
            tracing::warn!(vault = %vault, "cloud sync watch: persist failed: {}", e);
            persist_failed = true;
        } else {
            refresh_after_pull(state, vault);
        }
    } else {
        // Lifecycle marker (or blob absent): nothing to persist, but the
        // cursor MUST advance (see the fn doc).
        record_blob_version(state_dir, vault, version);
    }
    let pulls_ok = pull_and_process(state, state_dir, cloud, vault, dk, channel).await;
    BlobWake::Handled {
        persist_failed,
        pulls_ok,
    }
}

/// Why [`probe_blob_and_handle`] couldn't produce a body.
enum ProbeError {
    /// 401/403 — the caller applies the long-poll AUTH_RETRY parking.
    Auth,
    /// Network/decode/unexpected status — the caller's bounded 2s→60s retry.
    Other(String),
}

/// The SSE shape's blob fetch (design doc: "fetches with a plain 15s-client
/// `GET /v/{vid}/blob?since=<cursor>` ... and feeds the body to that
/// helper"): cursor re-read from disk at call time, client built fresh (the
/// proxy hot-reload contract, same as `pull`), body → the shared handler.
/// The network call NEVER runs under the vault write lock — the handler
/// takes it only around its persist. A 404 keeps its long-standing "never
/// sealed" meaning (a tombstone is always a 200 with `status:"deleted"`).
async fn probe_blob_and_handle(
    state: &Arc<AppState>,
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    dk: &str,
    channel: &str,
) -> Result<BlobWake, ProbeError> {
    let since = read_local_version(state_dir, vault);
    let url = format!(
        "{}/v/{}/blob?since={}",
        cloud.trim_end_matches('/'),
        vault,
        since
    );
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15))
        .map_err(|e| ProbeError::Other(format!("http client init: {}", e)))?;
    let resp = client
        .get(&url)
        .bearer_auth(dk)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .map_err(|e| ProbeError::Other(format!("reach {}: {}", cloud, e)))?;
    match resp.status().as_u16() {
        200 => {}
        404 => return Ok(BlobWake::Unchanged),
        401 | 403 => return Err(ProbeError::Auth),
        other => return Err(ProbeError::Other(format!("blob GET HTTP {}", other))),
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| ProbeError::Other(format!("parse blob response: {}", e)))?;
    Ok(handle_blob_wake_body(state, state_dir, cloud, vault, dk, &body, channel).await)
}

/// The shared wake block, run serially in the vault's watcher task: pull the
/// KEYSET (`/keys`) FIRST so the item fold sees a fresh K-wrap layer, then pull
/// item rows (refreshing the unlocked cache when anything was adopted), then
/// complete any pending browser-initiated OAuth connect that just synced in
/// (the code→token exchange + refresh_token persist — running it AFTER the
/// pulls means a connect lands on this wake, not one tick late; matches the
/// explicit `sc sync` path). Best-effort throughout; `process_vault_connects`
/// takes the vault write lock itself (not reentrant), so callers must not hold
/// it. `channel` is only for the trace line.
///
/// Returns whether BOTH sub-pulls succeeded. Long-poll callers ignore it (a
/// missed wake re-delivers itself via the unadvanced cursor); the SSE shape
/// uses it for its ★ bounded retry, because the stream delivered the hint
/// exactly once. Connect processing is not counted — it has its own
/// state-machine retries and never gates sync.
async fn pull_and_process(
    state: &Arc<AppState>,
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    dk: &str,
    channel: &str,
) -> bool {
    let mut ok = true;
    match pull_keys(state_dir, cloud, vault, dk).await {
        Ok(n) if n > 0 => {
            tracing::info!(vault = %vault, adopted = n, "cloud sync watch: pulled keyset rows")
        }
        Ok(_) => {}
        Err(e) => {
            tracing::debug!(vault = %vault, "cloud sync watch: keyset pull failed: {}", e);
            ok = false;
        }
    }
    match pull_items(state_dir, cloud, vault, dk).await {
        Ok(n) if n > 0 => {
            // INFO parity with the keyset line above: item adoptions are the
            // content channel doing its job — their absence from the log was
            // what made a wedged watcher indistinguishable from a quiet one.
            tracing::info!(vault = %vault, adopted = n, "cloud sync watch: pulled item rows");
            refresh_after_item_pull(state, vault);
        }
        Ok(_) => {}
        Err(e) => {
            tracing::debug!(vault = %vault, "cloud sync watch: per-item pull failed: {}", e);
            ok = false;
        }
    }
    crate::auth::connect::process_vault_connects(state, vault, None).await;
    tracing::debug!(vault = %vault, channel = channel, "cloud sync watch: wake processed");
    ok
}

// ─────────────────────────────────────────────────────────────────────────
// PER-ITEM SYNC  (PER_ITEM_SYNC.md §4/§5 / build contract §4 priority 3)
//
// The whole-blob `pull`/`push_blob_best_effort`/`watch_loop` above stay for the
// KEYSET lifecycle (the `/blob` row is now keyset-only, §7). The functions here
// are the CONTENT sync: the daemon holds N sealed item rows in
// `vault.per-item.json` and pulls/pushes them against the backend `/items`
// endpoints (contract §3):
//
//   GET  /v/{vid}/items?since=<seq> → { items:[{item_id,version,seq,ct}], seq }
//   PUT  /v/{vid}/items/{item_id}   { base_version?, version, ct } → CAS
//                                   → 200 {version,seq} | 409 {currentVersion}
//   GET  /v/{vid}/items/wait?since=<seq> (daemon long-poll)
//   DELETE /v/{vid}/items/{item_id}?gc_version=<v> (tombstone GC)
//
// PULL adopts server truth (§5): a newer version replaces the local row, a
// tombstone is stored (fold_view drops it), the cursor advances to max(seq).
// PUSH is per-item CAS (§4); 409 → reconcile — re-apply on the fresh item if the
// edit is independent, else write a conflict-copy (never last-writer-wins).
//
// Backing HTTP is only exercised once the backend `/items` endpoints are live;
// until then these are wired but a 404 leaves the local per-item store as the
// authoritative content (stubbed[]).
// ─────────────────────────────────────────────────────────────────────────

use crate::storage::sealed_vault::{self as pv_store, PerItemVault};

/// One row of a `/items` pull.
#[derive(Debug, Clone, serde::Deserialize)]
struct ItemRow {
    item_id: String,
    version: u64,
    #[allow(dead_code)]
    seq: u64,
    /// base64url-nopad of `suite‖nonce‖ct‖tag`.
    ct: String,
    /// A1.2 per-record signature (base64url, over the ciphertext) + the signer's
    /// self-id. Absent on legacy/unsigned rows (fmt1 personal / pre-migration).
    #[serde(default)]
    sig: Option<String>,
    #[serde(default)]
    signer: Option<String>,
}

/// Load the per-item store for a vault, or `None` if it doesn't exist yet.
fn read_per_item_store(state_dir: &Path, vault: &str) -> Option<PerItemVault> {
    let path = state_dir
        .join("vaults")
        .join(vault)
        .join("vault.per-item.json");
    pv_store::read_per_item(&path).ok().flatten()
}

fn write_per_item_store(state_dir: &Path, vault: &str, pv: &PerItemVault) -> Result<(), String> {
    let path = state_dir
        .join("vaults")
        .join(vault)
        .join("vault.per-item.json");
    pv_store::write_per_item_atomic(&path, pv).map_err(|e| format!("write per-item store: {}", e))
}

/// Adopt a batch of pulled item rows into the local store (server-authoritative,
/// §5): a strictly-newer `version` replaces the local row; the cursor advances
/// to the max `seq` seen. Tombstones are stored like any other row — `fold_view`
/// drops them at read time, and a later GC hard-deletes them. Returns the number
/// of rows adopted.
fn adopt_item_rows(pv: &mut PerItemVault, rows: &[ItemRow], max_seq: u64) -> Result<usize, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut adopted = 0usize;
    for row in rows {
        // Only adopt a strictly-newer version (server is authoritative, but a
        // stale replay must not clobber a fresher local row we already pushed).
        let keep = pv
            .get_item(&row.item_id)
            .map(|s| row.version > s.version)
            .unwrap_or(true);
        if !keep {
            continue;
        }
        let ct = URL_SAFE_NO_PAD
            .decode(row.ct.as_bytes())
            .map_err(|e| format!("item ct not base64url: {}", e))?;
        pv.put_raw_signed(row.item_id.clone(), row.version, ct, row.sig.clone(), row.signer.clone());
        adopted += 1;
    }
    if max_seq > pv.items_seq {
        pv.items_seq = max_seq;
    }
    Ok(adopted)
}

/// Pull item rows changed since the local `.items_seq` cursor and adopt them.
/// Best-effort: a 404 (endpoint not live yet) or a missing local store is a
/// no-op. Returns the number of rows adopted.
pub async fn pull_items(
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<usize, String> {
    let Some(mut pv) = read_per_item_store(state_dir, vault) else {
        return Ok(0); // no per-item store yet (vault not enrolled per-item)
    };
    let url = format!(
        "{}/v/{}/items?since={}",
        cloud.trim_end_matches('/'),
        vault,
        pv.items_seq
    );
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15))
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .get(&url)
        .bearer_auth(device_key)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    match resp.status().as_u16() {
        200 => {}
        404 => return Ok(0), // /items not live yet — no-op (stubbed[])
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("items GET HTTP {}", other)),
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse items response: {}", e))?;
    let rows: Vec<ItemRow> = body
        .get("items")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("parse items array: {}", e))?
        .unwrap_or_default();
    let max_seq = body
        .get("seq")
        .and_then(|v| v.as_u64())
        .unwrap_or(pv.items_seq);
    let adopted = adopt_item_rows(&mut pv, &rows, max_seq)?;
    if adopted > 0 || max_seq > 0 {
        write_per_item_store(state_dir, vault, &pv)?;
    }
    Ok(adopted)
}

/// Push a single item to the cloud with per-item CAS (§4). `base_version` is the
/// version the writer last read (absent → create). On `200` returns the cloud-
/// stamped `{version, seq}`; on `409` returns the conflict's `currentVersion` so
/// the caller can reconcile (re-apply on fresh, or conflict-copy — NEVER LWW).
///
/// `PushOutcome::EndpointMissing` (a 404) means the backend `/items` route isn't
/// live yet — the caller treats it as a no-op (stubbed[]).
pub enum PushOutcome {
    Ok { version: u64, seq: u64 },
    Conflict { current_version: u64 },
    EndpointMissing,
}

pub async fn push_item(
    cloud: &str,
    vault: &str,
    device_key: &str,
    item_id: &str,
    base_version: Option<u64>,
    version: u64,
    ct_b64: &str,
) -> Result<PushOutcome, String> {
    let url = format!(
        "{}/v/{}/items/{}",
        cloud.trim_end_matches('/'),
        vault,
        item_id
    );
    // CREATE omits base_version entirely (sending 0 → 409); only include it on
    // update (contract "BACKEND WIRE": a CREATE omits base_version).
    let mut body = serde_json::json!({ "version": version, "ct": ct_b64 });
    if let Some(bv) = base_version {
        body["base_version"] = serde_json::json!(bv);
    }
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15))
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .put(&url)
        .bearer_auth(device_key)
        .dik_pop("PUT", &url, &serde_json::to_vec(&body).unwrap_or_default())
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    match resp.status().as_u16() {
        200 => {
            let b: serde_json::Value =
                resp.json().await.map_err(|e| format!("parse put: {}", e))?;
            Ok(PushOutcome::Ok {
                version: b.get("version").and_then(|v| v.as_u64()).unwrap_or(version),
                seq: b.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
            })
        }
        409 => {
            let b: serde_json::Value = resp.json().await.unwrap_or_default();
            let current = b
                .get("currentVersion")
                .and_then(|v| v.as_u64())
                .unwrap_or(version);
            Ok(PushOutcome::Conflict {
                current_version: current,
            })
        }
        404 => Ok(PushOutcome::EndpointMissing),
        other => Err(format!("item PUT HTTP {}", other)),
    }
}

/// Hard-delete a tombstone row that has fully propagated (GC, §6): DELETE
/// `/items/{id}?gc_version=<v>`. Idempotent; only removes the exact version the
/// caller saw so it never drops a newer row that replaced the tombstone.
pub async fn gc_item(
    cloud: &str,
    vault: &str,
    device_key: &str,
    item_id: &str,
    gc_version: u64,
) -> Result<(), String> {
    let url = format!(
        "{}/v/{}/items/{}?gc_version={}",
        cloud.trim_end_matches('/'),
        vault,
        item_id,
        gc_version
    );
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15))
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .delete(&url)
        .bearer_auth(device_key)
        .dik_pop("DELETE", &url, &[])
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    if resp.status().is_success() || resp.status().as_u16() == 404 {
        Ok(())
    } else {
        Err(format!("item GC DELETE HTTP {}", resp.status()))
    }
}

/// Push every LOCAL item whose version is ahead of what the cloud last confirmed
/// (tracked by the per-item store's own rows). Each row is pushed with CAS; a
/// 409 is reconciled per §4:
///   - independent edit (the cloud's newer row is a DIFFERENT logical item, i.e.
///     our push targeted a row the cloud doesn't have or has at a lower version)
///     → adopt the cloud row and retry with the fresh base;
///   - genuine same-item conflict (both wrote the same id) → leave theirs, write
///     OURS as a conflict-copy (deterministic id via `conflict_copy_id`, so a
///     retry can't spawn a second) — needs `K`, so it runs only for an UNLOCKED
///     vault; a locked vault defers the conflict-copy to the next unlock.
///
/// NOTE: the full conflict-copy branch requires K + the item's (ns,name), which
/// we recover by unsealing the local row. Where the vault is locked, the row is
/// left ahead and retried next unlock (documented in stubbed[]).
pub async fn push_items_best_effort(state: &Arc<AppState>, vault_id: &str) {
    let Ok(cfg) = active::load() else { return };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return;
    };
    let Some(dk) = device_key() else { return };
    let cloud = cloud.trim_end_matches('/');
    let state_dir = &state.config.state_dir;

    let Some(pv) = read_per_item_store(state_dir, vault_id) else {
        return;
    };
    // Snapshot only the DIRTY rows (version > synced_version) so we don't hold
    // the store across awaits. Clean rows (already confirmed on the cloud) are
    // skipped outright — re-offering them cost one 409 round-trip PER ROW on
    // EVERY sync (the "sc sync is slow and nothing even changed" bug).
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut rows: Vec<(String, u64, String, bool)> = pv
        .items
        .iter()
        .filter(|(_, s)| s.version > s.synced_version)
        .map(|(id, s)| {
            (
                id.clone(),
                s.version,
                URL_SAFE_NO_PAD.encode(&s.ct),
                s.tombstone,
            )
        })
        .collect();
    if rows.is_empty() {
        return;
    }
    // Writes BEFORE deletes: push every live row first, tombstones last (stable
    // sort keeps the id order within each group). A completed connect writes
    // its `connection`/secret rows AND a tombstone for the old `connecting` row
    // in one batch; if the tombstone reached the cloud first, a syncing console
    // would briefly see the connect withdrawn with no connection yet ("not
    // configured"). Ordering the delete last means every intermediate snapshot
    // is either still-connecting or fully-connected, never a dangling gap.
    rows.sort_by_key(|(_, _, _, tombstone)| *tombstone);

    // A conflict/error on ONE item says nothing about the others (each item_id
    // is independent), so we NEVER stop the loop early — doing so would strand
    // every item ordered after the first conflict. We push what we can, adopt
    // server truth for the conflicting items with a single pull afterward, and
    // leave any genuine same-item conflict to `reconcile_conflicts_after_pull`
    // at unlock (needs K + (ns,name)).
    let mut conflicted = false;
    let mut endpoint_missing = false;
    let mut pushed: Vec<(String, u64)> = Vec::new();
    for (id, version, ct_b64, _tombstone) in rows {
        // base_version = version-1 for an update; a version-1 row is a create.
        let base_version = if version > 1 { Some(version - 1) } else { None };
        match push_item(cloud, vault_id, &dk, &id, base_version, version, &ct_b64).await {
            Ok(PushOutcome::Ok { .. }) => pushed.push((id, version)),
            Ok(PushOutcome::EndpointMissing) => {
                endpoint_missing = true;
                break; // the whole /items endpoint is down — nothing more to try
            }
            Ok(PushOutcome::Conflict { current_version }) => {
                tracing::debug!(
                    vault = %vault_id, item = %id, current_version,
                    "per-item push: 409 conflict; skipping item, adopting server truth after loop"
                );
                conflicted = true;
            }
            Err(e) => {
                // Transient — skip this item, keep trying the others.
                tracing::warn!(vault = %vault_id, item = %id, "per-item push failed: {}", e);
            }
        }
    }
    // Mark what landed as clean — re-read the store (a writer may have raced us)
    // and only stamp rows still at the exact version we pushed; a row bumped
    // meanwhile stays dirty and goes out on the next sync.
    if !pushed.is_empty() {
        if let Some(mut pv) = read_per_item_store(state_dir, vault_id) {
            let mut changed = false;
            for (id, version) in &pushed {
                if let Some(s) = pv.items.get_mut(id) {
                    if s.version == *version && s.synced_version < *version {
                        s.synced_version = *version;
                        changed = true;
                    }
                }
            }
            if changed {
                if let Err(e) = write_per_item_store(state_dir, vault_id, &pv) {
                    tracing::warn!(vault = %vault_id, "per-item push: synced-version write-back failed: {}", e);
                }
            }
        }
    }
    if conflicted && !endpoint_missing {
        let _ = pull_items(state_dir, cloud, vault_id, &dk).await;
    }
    tracing::debug!(vault = %vault_id, "per-item push: dirty items pushed");
}

// ─────────────────────────────────────────────────────────────────────────
// PER-ITEM KEYSET SYNC  (the passkey-wrap layer now rides `/keys`, §7)
//
// The keyset (registry pubkeys + per-cred `prf_salt`/`wrapped_key` = what GIVES
// you `K`) USED to ride the whole-blob `/blob` row. The frontend now writes it
// to `/keys` instead (ONE `vault_keys` row per credential, cid-keyed), so the
// daemon must sync it via `/keys` too, byte-compatible with the frontend:
//
//   GET /v/{vid}/keys?since=<seq> → { keys:[{cid,version,seq,data}], seq }
//   PUT /v/{vid}/keys/{cid}       { base_version?, version, data } → CAS
//                                 → 200 {version,seq} | 409 {currentVersion}
//
// `data = { x, y, device_name, x25519_pub?, prf_salt, wrapped_key }`. Encodings
// (verified against lib/vault-grant.ts + lib/safeclaw-crypto.ts):
//   - cid (row PK)              = base64url-nopad  (WebAuthn credential id)
//   - x / y                     = STANDARD base64  (kept verbatim as strings)
//   - prf_salt / wrapped_key    = STANDARD base64  (leniently decoded to bytes)
//   - x25519_pub                = base64url        (NOT stored — no sudp field)
//   - device_name               = plain string
// The daemon decodes data fields with the LENIENT `decode_keys_data_field`
// (mirrors the frontend's `fromBase64`: accept std OR url, padded or not) so the
// std-base64 fields never break unwrap of `K`.
//
// The keyset must be pulled BEFORE the items each sync cycle so the view is
// folded against a fresh `K`-wrap layer.
// ─────────────────────────────────────────────────────────────────────────

/// One row of a `/keys` pull. `data` is the cloud-VISIBLE keyset material (it is
/// what gives you `K`, so it can't be sealed under `K`).
#[derive(Debug, Clone, serde::Deserialize)]
struct KeyRow {
    cid: String,
    version: u64,
    #[allow(dead_code)]
    seq: u64,
    data: KeyRowData,
}

/// The `data` blob of a `/keys` row — mirrors the frontend `VaultKeyData`.
#[derive(Debug, Clone, serde::Deserialize)]
struct KeyRowData {
    x: String,
    y: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    #[allow(dead_code)]
    x25519_pub: Option<String>,
    prf_salt: String,
    wrapped_key: String,
    /// Optional key-check value (KCV) `v_c` — present once enrolled/backfilled
    /// against a build that computes it; absent on older rows.
    #[serde(default)]
    wc_check: Option<String>,
    /// v2 (UIK) fields — present iff this vault is a `custody → UIK → K` keyset
    /// (team-shared-vault-security-model.md §5). In v2, `wrapped_key` wraps the
    /// UIK root (not `K`), and `K` is recovered from the per-credential seal
    /// below. All four travel together; `uik` is `Some` on the keyset once any
    /// row carries them. Base64 (lenient-decoded like the other data fields).
    /// `uik_user_id` = the member's `us_…` account key.
    #[serde(default)]
    uik_user_id: Option<String>,
    /// The member's UIK Ed25519 signing public key (config/role sig verify).
    #[serde(default)]
    uik_sig_pub: Option<String>,
    /// The member's UIK X25519 encryption public key.
    #[serde(default)]
    uik_enc_pub: Option<String>,
    /// HPKE encapsulated key for the K-seal.
    #[serde(default)]
    uik_k_encapped: Option<String>,
    /// HPKE ciphertext = `Seal(K)` to `uik_enc_pub`.
    #[serde(default)]
    uik_k_ct: Option<String>,
    /// This member's role (`"owner"` / `"member"`), an owner-signed attribute on
    /// the cred (design/identity-uik-aik.md §4.3). Absent on a legacy row ⇒
    /// defaults to `Member` (least privilege) on adopt.
    #[serde(default)]
    uik_role: Option<crate::storage::plaintext::MemberRole>,
    /// The CREATOR's Ed25519 signature over
    /// `role_grant_input(vault, user, role, generation)` (base64, raw 64 bytes),
    /// signed at the keyset `generation` — verified against the pinned
    /// `uik_creator_sig_pub` at the CURRENT generation to derive the owner-set
    /// (F3-b generation-binding). Absent on a legacy row ⇒ the cred is not an owner.
    #[serde(default)]
    uik_role_sig: Option<String>,
    /// The vault's ROOT owner (creator) UIK signing pubkey (base64, raw 32 bytes).
    /// Keyset-LEVEL but carried REDUNDANTLY on every row (like `uik_generation`).
    /// TOFU-pinned SET-ONCE by the daemon on adopt — first-seen wins, a non-empty
    /// local pin is NEVER overwritten (a backend can't swap the role anchor).
    #[serde(default)]
    uik_creator_sig_pub: Option<String>,
    /// DP-S1 re-key epoch (team-shared-vault-security-model.md §3.2). Keyset-LEVEL
    /// but carried REDUNDANTLY on every row of a re-keyed vault (all rows share
    /// it), mirroring how the uik cred fields ride here. Absent / `0` = gen-0
    /// (never re-keyed) — the daemon then treats the vault as gen 0 (additive).
    #[serde(default)]
    uik_generation: Option<u64>,
    /// The owner-signed proof authorizing the current `uik_generation` (present iff
    /// generation > 0). JSON `{generation, k_commitment(b64), sig(b64), signer_id}`
    /// — the daemon decodes it into a `RekeyProof` and refuses to fold a re-keyed
    /// keyset whose proof is missing/invalid (`verify_rekey_proof`).
    #[serde(default)]
    uik_rekey_proof: Option<serde_json::Value>,
    /// The append-only owner-signed DELEGATION LOG (any-owner add/promote/demote/remove
    /// since the last checkpoint) — keyset-LEVEL, carried REDUNDANTLY on every row like
    /// the anchor + generation. JSON array of `DelegationEvent` (sig as STANDARD b64).
    /// Adopted as an append-only UNION (`adopt_delegation_meta`); the authoritative
    /// owner-set is re-derived from signatures in `fold_owner_set`. Absent on a
    /// gen-0 / no-delegation vault.
    #[serde(default)]
    uik_delegation_log: Option<serde_json::Value>,
    /// The root-succession + compaction chain (`RootSuccession` array, JSON; pubkey/sig
    /// as STANDARD b64) — the root-signed source of BOTH the current root and the
    /// derived `role_epoch`. Carried REDUNDANTLY on every row; adopted as an append-only
    /// union. Absent = the creator is still the genesis root at epoch 0.
    #[serde(default)]
    uik_root_succession: Option<serde_json::Value>,
}

/// Pull keyset rows changed since the local `.keyset_seq` cursor and adopt them
/// into the keyset (registry + credentials), keyed by cid. Server-authoritative
/// like `pull_items`: a row whose `version` is `<=` the version we already hold
/// for that cid is skipped (we track the highest adopted version per cid via the
/// pulled `version`, since the daemon keeps no on-disk per-cred version — the
/// cursor advance + a fresh full pull on `keyset_seq=0` keep us convergent). The
/// cursor advances to the response max `seq`; the store is persisted.
///
/// If no local `PerItemVault` exists yet, an EMPTY one is created first (a
/// device that pulls keys before its first enroll/seed still lands a keyset).
///
/// Best-effort: a 404 (endpoint not live yet) is a no-op. Returns the number of
/// rows adopted.
pub async fn pull_keys(
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<usize, String> {
    // Create an empty per-item store on demand so a device that pulls keys
    // before it has ever seeded items still ends up with a keyset on disk.
    let mut pv = read_per_item_store(state_dir, vault).unwrap_or_else(empty_keyset_store);

    let url = format!(
        "{}/v/{}/keys?since={}",
        cloud.trim_end_matches('/'),
        vault,
        pv.keyset_seq
    );
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15))
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .get(&url)
        .bearer_auth(device_key)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    match resp.status().as_u16() {
        200 => {}
        404 => return Ok(0), // /keys not live yet — no-op
        // fmt>=2 vault: the backend serves the end-to-end verify(anchor, members, proof)
        // TRIPLE at /membership, not row-shaped /keys. Route there. Legacy fmt=1 personal
        // vaults keep the row path below (single request, unchanged).
        409 => return pull_membership(state_dir, cloud, vault, device_key).await,
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("keys GET HTTP {}", other)),
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse keys response: {}", e))?;
    let rows: Vec<KeyRow> = body
        .get("keys")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("parse keys array: {}", e))?
        .unwrap_or_default();
    let max_seq = body
        .get("seq")
        .and_then(|v| v.as_u64())
        .unwrap_or(pv.keyset_seq);
    let adopted = adopt_key_rows(&mut pv, vault, &rows)?;
    if max_seq > pv.keyset_seq {
        pv.keyset_seq = max_seq;
    }
    // Persist even a zero-adopt pull so the advanced cursor sticks.
    write_per_item_store(state_dir, vault, &pv)?;
    Ok(adopted)
}

/// Pull a fmt=2 vault's `verify(anchor, members, proof)` TRIPLE from `GET /v/{vid}/membership`
/// and adopt it into the keyset (unified-identity-schema.md §3). The end-to-end counterpart
/// of `pull_keys`: the WIRE is the triple (no row format), but the in-memory keyset it builds
/// is byte-identical to what `adopt_key_rows` builds (same fold, same unlock). `since` =
/// `keyset_seq` cursor, shared with `pull_keys` (a fmt=2 vault only ever reaches here after
/// the initial `/keys` 409). A `keyset_seq`-only reply (nothing new) or a null-anchor reply
/// (vault not bootstrapped yet) adopts nothing but still advances the cursor.
async fn pull_membership(
    state_dir: &Path,
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<usize, String> {
    let mut pv = read_per_item_store(state_dir, vault).unwrap_or_else(empty_keyset_store);
    // The `keyset_seq` cursor is per-FORMAT: the v1 `/keys` sequence and the v2
    // `/membership` `keyset_seq` are DIFFERENT counters. On a fmt1→fmt2 MIGRATION the
    // local cursor is still the v1 value (often far ahead of the fresh membership's
    // seq), so a since-delta would reply "nothing new" and the triple would never land
    // — the daemon would stay stuck on its stale v1 keyset. Detect the first v2 pull
    // (local keyset has no `uik` yet) and pull the FULL triple from `since=0`, then
    // adopt the membership's OWN seq (even if numerically lower than the old v1 cursor).
    let first_v2 = pv.keyset.uik.is_none();
    let since = if first_v2 { 0 } else { pv.keyset_seq };
    let url = format!(
        "{}/v/{}/membership?since={}",
        cloud.trim_end_matches('/'),
        vault,
        since
    );
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15))
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .get(&url)
        .bearer_auth(device_key)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    match resp.status().as_u16() {
        200 => {}
        404 => return Ok(0), // /membership not live yet — no-op
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("membership GET HTTP {}", other)),
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse membership response: {}", e))?;
    let max_seq = body
        .get("keyset_seq")
        .and_then(|v| v.as_u64())
        .unwrap_or(pv.keyset_seq);
    // A since-delta "nothing new" reply carries only keyset_seq; a pre-bootstrap vault
    // carries a null anchor. Either way there is no triple to adopt — just advance the cursor.
    let adopted = match body.get("anchor").and_then(|v| v.as_str()) {
        Some(anchor) if !anchor.is_empty() => adopt_membership_triple(&mut pv, vault, anchor, &body)?,
        _ => 0,
    };
    if first_v2 {
        // Switching from the v1 `/keys` cursor to the v2 `/membership` sequence: adopt
        // the membership's seq outright (the usual monotonic guard would keep the stale,
        // higher v1 value and freeze out future v2 deltas).
        pv.keyset_seq = max_seq;
    } else if max_seq > pv.keyset_seq {
        pv.keyset_seq = max_seq;
    }
    write_per_item_store(state_dir, vault, &pv)?;
    Ok(adopted)
}

/// Adopt a `verify(anchor, members, proof)` membership TRIPLE (fmt=2, end-to-end) into the
/// in-memory keyset — the daemon-side equivalent of `adopt_key_rows`, fed from the triple
/// instead of per-cred rows. It reuses the SAME keyset writers (`adopt_creator_pin` /
/// `set_uik_cred_b64` / `adopt_delegation_meta` / `adopt_rekey_meta`) in the SAME order, so
/// the fold + unlock + golden vectors stay byte-identical; ONLY the source of the fields
/// changes. The daemon's OWN member is keyed under its credential cid(s) (so v2 unlock's
/// `uik.creds[own_cid]` lookup finds the K-seal); OTHER members are keyed under their `us_…`
/// id (the fold iterates `creds.values()` — the map key is irrelevant there).
fn adopt_membership_triple(
    pv: &mut PerItemVault,
    vault_id: &str,
    anchor_b64: &str,
    body: &serde_json::Value,
) -> Result<usize, String> {
    // Creator (root) anchor — TOFU-pinned set-once (reused helper).
    adopt_creator_pin(pv, &Some(anchor_b64.to_string()))
        .map_err(|e| format!("adopt creator pin: {}", e))?;

    // The caller's OWN credentials: identity_id → [cid]. The daemon keys its own member's
    // seal under these cids so the grant's credential_id resolves at v2 unlock.
    let mut cids_by_member: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    if let Some(creds) = body.get("credentials").and_then(|v| v.as_array()) {
        for c in creds {
            if let (Some(cid), Some(idid)) = (
                c.get("cid").and_then(|v| v.as_str()),
                c.get("identity_id").and_then(|v| v.as_str()),
            ) {
                cids_by_member
                    .entry(idid.to_string())
                    .or_default()
                    .push(cid.to_string());
            }
            // Adopt this credential's WebAuthn pubkey (x/y) into the registry so the
            // daemon can VERIFY its approve/unlock assertion — `uik.creds` carries the
            // K-seal but NOT the ES256 pubkey, so without this a v2 tap fails with
            // "unknown credential". Own creds only (the serve returns the caller's own).
            if let (Some(cid), Some(x), Some(y)) = (
                c.get("cid").and_then(|v| v.as_str()),
                c.get("x").and_then(|v| v.as_str()),
                c.get("y").and_then(|v| v.as_str()),
            ) {
                let dn = c.get("device_name").and_then(|v| v.as_str()).unwrap_or("");
                pv.set_registry_pubkey(cid, x, y, dn)
                    .map_err(|e| format!("adopt registry pubkey {}: {}", cid, e))?;
            }
        }
    }

    let (Some(members), Some(identities)) = (
        body.get("members").and_then(|v| v.as_object()),
        body.get("identities").and_then(|v| v.as_object()),
    ) else {
        return Ok(0); // an anchor with no members/identities seats nobody
    };

    let mut adopted = 0usize;
    for (id, m) in members {
        let ident = identities.get(id);
        // The FOLD self-certifies a checkpoint on `sig_pub` + `role_sig` (authority), NOT on
        // K-delivery — so seat a cred whenever `sig_pub` is present, defaulting the delivery
        // fields (enc_pub / k_encapped / k_ct) to empty when absent. Those are used only to
        // UNLOCK the daemon's OWN cred (which always carries them); for other members they are
        // inert. This matches the backend/frontend fold (which seat from sig_pub+role_sig
        // alone) so the owner-set is identical across all three even for a member whose
        // nullable `enc_pub` / K fields are missing. A member with no `sig_pub` can't be
        // self-certified → skip (fail-closed); the delegation log still folds them from sigs.
        let Some(sig_pub) = ident.and_then(|i| i.get("sig_pub")).and_then(|v| v.as_str()) else {
            continue;
        };
        let enc_pub = ident.and_then(|i| i.get("enc_pub")).and_then(|v| v.as_str()).unwrap_or("");
        let k_encapped = m.get("k_encapped").and_then(|v| v.as_str()).unwrap_or("");
        let k_ct = m.get("k_ct").and_then(|v| v.as_str()).unwrap_or("");
        // A bad/absent role token degrades to Member (least privilege) — NEVER `?`-fail the
        // whole pull (that would leave the keyset stale), matching the frontend's coercion.
        let role: crate::storage::plaintext::MemberRole = m
            .get("role")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let role_sig = m.get("role_sig").and_then(|v| v.as_str()).unwrap_or("");
        // Key the OWN member under its credential cid(s); OTHER members under their us_id.
        let keys: Vec<String> = match cids_by_member.get(id) {
            Some(cids) if !cids.is_empty() => cids.clone(),
            _ => vec![id.clone()],
        };
        for key in keys {
            pv.set_uik_cred_b64(&key, id, sig_pub, enc_pub, k_encapped, k_ct, role, role_sig)
                .map_err(|e| format!("adopt uik seal {}: {}", id, e))?;
        }
        adopted += 1;
    }

    // Keyset-level delegation state + re-key meta (reused helpers, SAME order as adopt_key_rows:
    // creds+anchor first, then delegation, then the verify-before-ratchet re-key gate).
    let proof = body.get("proof");
    let delegation_log = proof.and_then(|p| p.get("delegation_log")).cloned();
    let root_succession = proof.and_then(|p| p.get("succession")).cloned();
    adopt_delegation_meta(pv, vault_id, &delegation_log, &root_succession)
        .map_err(|e| format!("adopt delegation meta: {}", e))?;
    let generation = proof.and_then(|p| p.get("generation")).and_then(|v| v.as_u64());
    let rekey_proof = proof.and_then(|p| p.get("rekey_proof")).cloned();
    adopt_rekey_meta(pv, vault_id, generation, &rekey_proof)
        .map_err(|e| format!("adopt rekey meta: {}", e))?;
    Ok(adopted)
}

/// A fresh, EMPTY per-item store with an empty keyset — the on-demand target for
/// `pull_keys` on a device that has no `vault.per-item.json` yet. It has NO
/// credentials and NO items; `pull_keys` fills the keyset from the cloud rows.
fn empty_keyset_store() -> PerItemVault {
    use sudp::state::{Registry, CURRENT_VERSION};
    PerItemVault {
        keyset: pv_store::Keyset {
            version: CURRENT_VERSION,
            registry: Registry::new(),
            credentials: Vec::new(),
            keyset_version: 0,
            // Filled from cloud `/keys` rows by `pull_keys`; the UIK layer (if the
            // vault is v2) is adopted alongside the credential rows.
            uik: None,
        },
        items: std::collections::BTreeMap::new(),
        items_seq: 0,
        keyset_seq: 0,
    }
}

/// Adopt a batch of pulled `/keys` rows into the keyset. A row whose `version`
/// is `<=` the highest we've already adopted for that cid IN THIS BATCH is
/// skipped (guards a stale replay within one response); across pulls, the
/// `keyset_seq` cursor gates re-delivery. Each adopted row upserts the registry
/// pubkey + the `SealedCredential`. Returns the count adopted.
fn adopt_key_rows(pv: &mut PerItemVault, vault_id: &str, rows: &[KeyRow]) -> Result<usize, String> {
    // Track the max version seen per cid in this batch so an out-of-order pair
    // (same cid, v3 then v2) adopts only the newer.
    let mut seen: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
    let mut adopted = 0usize;
    // Sort by version so a lower version can't overwrite a higher one when both
    // appear in the same page (the cloud SHOULD send at most one row per cid,
    // but defend in depth).
    let mut ordered: Vec<&KeyRow> = rows.iter().collect();
    ordered.sort_by_key(|r| r.version);
    // PASS 1 — apply every row's credential material + creator anchor FIRST. The
    // re-key gate in PASS 2 (`adopt_rekey_meta`, verify-before-ratchet) confirms
    // the owner-signed generation bump against the owner-set AT the PROPOSED
    // generation `G`; a legit re-key re-signs every surviving role grant at `G` and
    // rides them on THESE same rows, so ALL grants must be in place before the gate
    // runs — otherwise a genuine bump's signer would not yet be a confirmable
    // owner @G. (Confirmed ordering: cred/anchor adoption strictly precedes the
    // re-key-meta adoption.)
    for row in &ordered {
        if let Some(&v) = seen.get(row.cid.as_str()) {
            if row.version <= v {
                continue;
            }
        }
        pv.upsert_key_row(
            &row.cid,
            &row.data.x,
            &row.data.y,
            &row.data.device_name,
            &row.data.prf_salt,
            &row.data.wrapped_key,
            row.data.wc_check.as_deref(),
        )
        .map_err(|e| format!("adopt key row {}: {}", row.cid, e))?;
        // v2 (UIK) keyset: adopt the per-credential K-seal riding in the same row
        // (all four fields travel together; a partial set = a malformed row we
        // skip the UIK adoption for rather than store a half seal).
        if let (Some(uid), Some(sig), Some(enc), Some(encapped), Some(ct)) = (
            row.data.uik_user_id.as_deref(),
            row.data.uik_sig_pub.as_deref(),
            row.data.uik_enc_pub.as_deref(),
            row.data.uik_k_encapped.as_deref(),
            row.data.uik_k_ct.as_deref(),
        ) {
            // Role rides the SAME record (SSOT): a missing role token defaults to
            // Member (least privilege), a missing signature leaves the cred a
            // non-owner (fails `resolve_membership_trust`'s verify).
            let role = row.data.uik_role.unwrap_or_default();
            let role_sig = row.data.uik_role_sig.as_deref().unwrap_or("");
            pv.set_uik_cred_b64(&row.cid, uid, sig, enc, encapped, ct, role, role_sig)
                .map_err(|e| format!("adopt uik seal {}: {}", row.cid, e))?;
        }
        // The vault's ROOT owner (creator) anchor — keyset-LEVEL, carried per row.
        // TOFU-pinned SET-ONCE (first-seen wins; never overwrite a non-empty pin).
        adopt_creator_pin(pv, &row.data.uik_creator_sig_pub)
            .map_err(|e| format!("adopt creator pin {}: {}", row.cid, e))?;
        seen.insert(row.cid.as_str(), row.version);
        adopted += 1;
    }
    // PASS 2a — with ALL creds + the creator anchor now in place, adopt the
    // keyset-LEVEL DELEGATION state (append-only union of the owner-signed event log
    // and the root-succession/compaction chain). Done BEFORE the re-key gate so the
    // owner-set the re-key gate folds is already current. It rides REDUNDANTLY on
    // every row; union+dedup makes per-row application idempotent.
    for row in &ordered {
        adopt_delegation_meta(
            pv,
            vault_id,
            &row.data.uik_delegation_log,
            &row.data.uik_root_succession,
        )
        .map_err(|e| format!("adopt delegation meta {}: {}", row.cid, e))?;
    }
    // PASS 2b — adopt the keyset-LEVEL DP-S1 re-key metadata (`generation` +
    // owner-signed proof). Monotonic + owner-signature-gated (the owner-set is now
    // folded over the just-adopted delegation state); only a strictly-higher
    // generation carrying a VALID owner-signed proof advances the local ratchet.
    for row in &ordered {
        adopt_rekey_meta(
            pv,
            vault_id,
            row.data.uik_generation,
            &row.data.uik_rekey_proof,
        )
        .map_err(|e| format!("adopt rekey meta {}: {}", row.cid, e))?;
    }
    Ok(adopted)
}

/// TOFU-pin the vault's ROOT owner (creator) UIK signing pubkey onto the keyset
/// (design/identity-uik-aik.md §4.3 — the owner-authority genesis anchor).
/// FIRST-SEEN WINS: adopt `creator_sig_pub` only when the local copy is empty;
/// NEVER overwrite a non-empty pin. A colluding backend could otherwise serve a
/// keyset claiming a DIFFERENT creator pubkey to forge an owner-set (self-promote
/// via a key it controls); pinning set-once makes the anchor immutable after the
/// first successful adopt (mirrors `adopt_rekey_meta`'s monotonic generation
/// rule). An empty / absent value is a no-op (a legacy row carries no anchor).
fn adopt_creator_pin(
    pv: &mut PerItemVault,
    creator_sig_pub_b64: &Option<String>,
) -> Result<(), String> {
    let Some(b64) = creator_sig_pub_b64.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let pub_bytes =
        pv_store::decode_keys_data_field(b64).map_err(|e| format!("creator_sig_pub: {}", e))?;
    if pub_bytes.is_empty() {
        return Ok(());
    }
    let uik = pv
        .keyset
        .uik
        .get_or_insert_with(pv_store::KeysetUik::default);
    // Set-once: a non-empty pin is the immutable genesis anchor; leave it.
    if uik.creator_sig_pub.is_empty() {
        uik.creator_sig_pub = pub_bytes;
    }
    Ok(())
}

/// Adopt a `/keys` row's keyset-LEVEL DELEGATION state — the append-only
/// `delegation_log` (owner-signed add/promote/demote/remove events) and the
/// `root_succession` chain (root transfers + compactions, the derived-`role_epoch`
/// source). Both are keyset-wide (carried REDUNDANTLY on every row, like the anchor
/// and generation) and APPEND-ONLY: the daemon UNIONS incoming entries into its local
/// copy and NEVER shrinks it, so a colluding server serving a stale/shorter set can't
/// roll back the owner-set — rollback-safety BY CONSTRUCTION. Unlike `generation`
/// (a stored scalar gating K selection, hence verify-before-ratchet), the owner-set is
/// RE-DERIVED from signatures every fold ([`SealedVault::fold_owner_set`] /
/// `resolve_current_root`), so a forged event/cert adopted here is simply INERT — the
/// fold ignores it. Adopt only screens for well-formedness (32-byte pubkeys / 64-byte
/// sigs) + de-duplicates, to keep a re-delivered row from growing the log unboundedly.
/// A vault with no UIK layer (v1) is a no-op.
fn adopt_delegation_meta(
    pv: &mut PerItemVault,
    vault_id: &str,
    delegation_log: &Option<serde_json::Value>,
    root_succession: &Option<serde_json::Value>,
) -> Result<(), String> {
    if pv.keyset.uik.is_none() {
        return Ok(()); // v1 / no UIK layer — nothing to adopt
    }
    // ── Root-succession / compaction chain (append-only union) ──
    if let Some(v) = root_succession {
        let incoming: Vec<sealed_vault::RootSuccession> = serde_json::from_value(v.clone())
            .map_err(|e| format!("parse root_succession: {}", e))?;
        let uik = pv.keyset.uik.as_mut().unwrap();
        for s in incoming {
            // Storage hygiene: keep only well-formed certs (32-byte pubkey, 64-byte
            // sig). Whether the cert actually chains from the current root is decided
            // at fold time by `resolve_current_root` — a garbage cert stored here is
            // inert (never advances the root).
            if <[u8; 32]>::try_from(s.new_root_sig_pub.as_slice()).is_err()
                || <[u8; 64]>::try_from(s.sig.as_slice()).is_err()
            {
                continue;
            }
            let dup = uik.root_succession.iter().any(|e| {
                e.old_root_id == s.old_root_id
                    && e.new_root_id == s.new_root_id
                    && e.role_epoch == s.role_epoch
                    && e.sig == s.sig
            });
            if !dup {
                uik.root_succession.push(s);
            }
        }
    }
    // ── Delegation log (append-only union) ──
    if let Some(v) = delegation_log {
        let incoming: Vec<sealed_vault::DelegationEvent> = serde_json::from_value(v.clone())
            .map_err(|e| format!("parse delegation_log: {}", e))?;
        let uik = pv.keyset.uik.as_mut().unwrap();
        for e in incoming {
            // SIG-VERIFY-AT-ADOPT: only store an event that SELF-VERIFIES — its inline
            // `granter_sig_pub` derives to `granter_id` AND its signature checks out.
            // (Enabled by the self-certifying inline key.) This keeps a colluding
            // server from bloating the log with well-formed junk events that every
            // later fold would re-verify (a sticky CPU DoS), and stops a junk event
            // from ever entering the fold to contend for a seq slot. The AUTHORITY
            // check — granter is an Owner in the fold — still happens at fold time
            // (it needs the full owner-set context).
            let Ok(granter_pub) = <[u8; 32]>::try_from(e.granter_sig_pub.as_slice()) else {
                continue;
            };
            if crate::identity::derive_id(crate::identity::IdKind::User, &granter_pub)
                != e.granter_id
            {
                continue;
            }
            let Ok(sig) = <[u8; 64]>::try_from(e.sig.as_slice()) else {
                continue;
            };
            let role_tok = if e.op == "remove" {
                ""
            } else {
                crate::storage::sealed_vault::role_str(e.role)
            };
            let input = crate::identity::delegation_event_input(
                vault_id,
                &e.op,
                &e.subject_id,
                role_tok,
                &e.granter_id,
                e.seq,
                e.role_epoch,
            );
            if !crate::identity::verify(&granter_pub, &input, &sig) {
                continue; // signature does not self-verify → junk, do not store
            }
            let dup = uik.delegation_log.iter().any(|x| {
                x.op == e.op
                    && x.subject_id == e.subject_id
                    && x.granter_id == e.granter_id
                    && x.seq == e.seq
                    && x.role_epoch == e.role_epoch
                    && x.sig == e.sig
            });
            if !dup {
                uik.delegation_log.push(e);
            }
        }
    }
    Ok(())
}

/// Apply a `/keys` row's keyset-LEVEL DP-S1 re-key metadata onto the keyset's UIK
/// layer: `generation` + the owner-signed `RekeyProof`. Both are keyset-wide (a
/// re-keyed vault repeats them on every row). VERIFY-BEFORE-RATCHET: a
/// strictly-higher proposed generation `G` advances the local monotonic
/// generation (and stores the proof) ONLY when the accompanying proof is present,
/// is FOR `G`, and is signed by an OWNER in the current folded owner-set
/// ([`PerItemVault::fold_owner_set`]) with a valid signature over
/// [`crate::identity::rekey_sig_input`]. Otherwise the higher generation is
/// IGNORED (neither `generation` nor `rekey_proof` change) — this is what stops a
/// current member forging `uik_generation: 999` with no valid owner proof from
/// ratcheting the fleet into the fold-time `verify_rekey_proof` `Unauthorized`
/// brick (a sticky DoS). `fold_view`'s `verify_rekey_proof` keeps the additional
/// k_commitment↔real-K binding check (defense in depth). A row with no / `0`
/// generation leaves the keyset untouched (gen-0 vaults never carry them → stay
/// gen 0, additive).
fn adopt_rekey_meta(
    pv: &mut PerItemVault,
    vault_id: &str,
    generation: Option<u64>,
    proof: &Option<serde_json::Value>,
) -> Result<(), String> {
    let Some(generation) = generation.filter(|g| *g > 0) else {
        return Ok(());
    };
    // DP-S1 generation is a MONOTONIC ratchet: only CONSIDER a STRICTLY HIGHER
    // generation. A malicious backend could otherwise serve an OLDER keyset (with
    // its genuine, still-valid older proof) to roll a daemon's generation BACKWARD
    // and undo a forward-secret re-key. A generation `<=` what we already hold is
    // ignored — we overwrite NEITHER `generation` NOR `rekey_proof`. (A stale/equal
    // adopt short-circuits here BEFORE the signature work below.)
    let current = pv.keyset.uik.as_ref().map(|u| u.generation).unwrap_or(0);
    if generation <= current {
        return Ok(());
    }
    // VERIFY-BEFORE-RATCHET (HIGH-severity generation-ratchet DoS fix). The old
    // code ratcheted `generation` on UNVERIFIED input — it stored ANY higher
    // proposed generation and deferred the owner-signature check to fold-time
    // `verify_rekey_proof`. A current MEMBER could then PUT its own keyset row with
    // `uik_generation: 999` and no valid proof; every daemon pulled it, advanced to
    // 999, and `verify_rekey_proof` then failed → `fold_view` returned
    // `Unauthorized` → EVERY request for the vault was denied (a sticky fleet
    // brick). We now REQUIRE a valid owner-signed proof AT the proposed generation
    // `G` BEFORE advancing: a forged bump is IGNORED (local generation untouched),
    // so the fleet never ratchets into the fold-time brick. The k_commitment↔real-K
    // binding stays at fold-time `verify_rekey_proof` (K isn't available here) —
    // defense in depth.
    let Some(p) = proof.as_ref() else {
        return Ok(()); // higher generation with NO proof = a forged bump → ignore
    };
    // The proof must be FOR generation `G` (not a valid proof for some other gen
    // spliced onto a `G` claim).
    if p.get("generation").and_then(|v| v.as_u64()) != Some(generation) {
        return Ok(());
    }
    let signer_id = p
        .get("signer_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let k_commitment = p
        .get("k_commitment")
        .and_then(|v| v.as_str())
        .map(pv_store::decode_keys_data_field)
        .transpose()
        .map_err(|e| format!("k_commitment: {}", e))?
        .unwrap_or_default();
    let sig_bytes = p
        .get("sig")
        .and_then(|v| v.as_str())
        .map(pv_store::decode_keys_data_field)
        .transpose()
        .map_err(|e| format!("sig: {}", e))?
        .unwrap_or_default();
    // Membership anti-rollback commitment (Part 2): the re-key proof binds the
    // delegation-log prefix current at re-key time (owner-signed). Absent/0 = empty.
    let membership_len = p.get("membership_len").and_then(|v| v.as_u64()).unwrap_or(0);
    let membership_hash = p
        .get("membership_hash")
        .and_then(|v| v.as_str())
        .map(pv_store::decode_keys_data_field)
        .transpose()
        .map_err(|e| format!("membership_hash: {}", e))?
        .unwrap_or_default();
    let Ok(sig) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return Ok(()); // malformed signature → ignore (don't ratchet)
    };
    // The signer must be an OWNER in the CURRENT folded owner-set. A K-rotation
    // (`generation` bump) is ORTHOGONAL to the role checkpoint (`role_epoch`) under
    // the two-counter model, so the owner-set is folded at the current role_epoch
    // (checkpoint ∘ delegation_log), NOT re-derived at the proposed `generation`. A
    // member's self-signed proof fails here (a member is not an owner).
    if pv.fold_owner_set(vault_id).get(&signer_id)
        != Some(&crate::storage::plaintext::MemberRole::Owner)
    {
        return Ok(());
    }
    // The signer's published sig pubkey (C.1 anchor): a keyset cred whose derived
    // id matches `signer_id` — a backend-minted key isn't in the keyset.
    let signer_pub: Option<[u8; 32]> = pv.keyset.uik.as_ref().and_then(|uik| {
        uik.creds.values().find_map(|c| {
            let a = <[u8; 32]>::try_from(c.sig_pub.as_slice()).ok()?;
            (crate::identity::derive_id(crate::identity::IdKind::User, &a) == signer_id)
                .then_some(a)
        })
    });
    let Some(signer_pub) = signer_pub else {
        return Ok(());
    };
    let input = crate::identity::rekey_sig_input(
        vault_id,
        generation,
        &k_commitment,
        &signer_id,
        membership_len,
        &membership_hash,
    );
    if !crate::identity::verify(&signer_pub, &input, &sig) {
        return Ok(()); // signature does not verify → forged bump → ignore
    }
    // Verified owner-signed proof at `G`: NOW ratchet forward + store the proof.
    let uik = pv
        .keyset
        .uik
        .get_or_insert_with(pv_store::KeysetUik::default);
    uik.generation = generation;
    uik.rekey_proof = Some(pv_store::RekeyProof {
        generation,
        k_commitment,
        sig: sig_bytes,
        signer_id,
        membership_len,
        membership_hash,
    });
    Ok(())
}

/// Push the daemon's keyset credentials ahead of the cloud after a daemon-side
/// mutation of the acting credential (a Write rotates its `prf_salt`/`wrapped_key`
/// via `replace_after_write`; a connect re-seals through the same `K`). Mirrors
/// `push_items_best_effort`'s 409/adopt handling — NEVER clobber: on a 409 we
/// adopt the cloud's rows (via `pull_keys`) and stop rather than force-overwrite.
///
/// The daemon keeps no on-disk per-cred version, so we CAS with `base_version` =
/// the row's current cloud version derived from `keyset_seq`-tracked pulls. In
/// practice we PUT as an UPDATE (`base_version = <last pulled>`), falling back to
/// a CREATE (base_version omitted) only when the row is unknown cloud-side. Since
/// we can't cheaply know the cloud version per cid without a pull, we first
/// `pull_keys` to refresh, read the freshest local keyset, and PUT each credential
/// at `version = pulled+1` with `base_version = pulled` — a 409 means someone
/// else moved it, so we re-pull and stop (best-effort; local keyset is durable).
/// Build one `/keys` row's `data` JSON for a credential, byte-compatible with the
/// frontend `VaultKeyData`. Carries the passkey-wrap material (x/y/device_name/
/// prf_salt/wrapped_key, STANDARD base64 for the byte fields to match `toBase64`),
/// the optional KCV, the v2 (UIK) per-credential K-seal VERBATIM (the daemon can't
/// reconstruct another member's seal — that needs their root — so it forwards
/// exactly what it adopted), AND the keyset-LEVEL DP-S1 re-key metadata
/// (`uik_generation` + `uik_rekey_proof`) emitted REDUNDANTLY on EVERY row of a
/// re-keyed vault (all rows share them, mirroring the uik cred fields). Returns
/// `None` when the credential has no registry pubkey (can't form a complete row).
fn key_row_data_for(
    pv: &PerItemVault,
    cred: &sudp::state::SealedCredential,
) -> Option<serde_json::Value> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    let cid_b64 = URL_SAFE_NO_PAD.encode(&cred.credential_id);
    // Pull the registry pubkey for x/y/device_name; keep x/y verbatim (they are
    // already the strings the frontend wrote — std-base64).
    let pk = pv
        .keyset
        .registry
        .get::<sudp::passkey::WebAuthn>(&cred.credential_id)
        .ok()
        .flatten()?;
    let mut data = serde_json::json!({
        "x": pk.x,
        "y": pk.y,
        "device_name": pk.device_name,
        "prf_salt": STANDARD.encode(&cred.prf_salt),
        "wrapped_key": STANDARD.encode(&cred.wrapped_key),
    });
    // Optional KCV cloud-side (STANDARD base64) so other devices / later pulls see
    // it. Omitted entirely when absent.
    if let Some(v) = &cred.wc_check {
        data["wc_check"] = serde_json::Value::String(STANDARD.encode(v));
    }
    // v2 (UIK) keyset: carry this credential's K-seal VERBATIM (owner-authored;
    // the daemon only transports it).
    if let Some(entry) = pv.uik_cred(&cid_b64) {
        data["uik_user_id"] = serde_json::Value::String(entry.user_id.clone());
        data["uik_sig_pub"] = serde_json::Value::String(STANDARD.encode(&entry.sig_pub));
        data["uik_enc_pub"] = serde_json::Value::String(STANDARD.encode(&entry.enc_pub));
        data["uik_k_encapped"] = serde_json::Value::String(STANDARD.encode(&entry.k_encapped));
        data["uik_k_ct"] = serde_json::Value::String(STANDARD.encode(&entry.k_ct));
        // Owner-signed role attribute on the SAME record (SSOT). The role token
        // always travels; the signature only when present (a legacy cred has none).
        data["uik_role"] = serde_json::to_value(entry.role).unwrap_or(serde_json::Value::Null);
        if !entry.role_sig.is_empty() {
            data["uik_role_sig"] = serde_json::Value::String(STANDARD.encode(&entry.role_sig));
        }
    }
    // Keyset-LEVEL role anchor + DP-S1 re-key metadata (both emitted REDUNDANTLY on
    // EVERY row). The creator pubkey rides once pinned; a gen-0 vault carries no
    // re-key fields, so the daemon reads it as gen 0.
    if let Some(uik) = pv.keyset.uik.as_ref() {
        if !uik.creator_sig_pub.is_empty() {
            data["uik_creator_sig_pub"] =
                serde_json::Value::String(STANDARD.encode(&uik.creator_sig_pub));
        }
        if uik.generation > 0 {
            data["uik_generation"] = serde_json::json!(uik.generation);
            if let Some(proof) = uik.rekey_proof.as_ref() {
                data["uik_rekey_proof"] = serde_json::json!({
                    "generation": proof.generation,
                    "k_commitment": STANDARD.encode(&proof.k_commitment),
                    "sig": STANDARD.encode(&proof.sig),
                    "signer_id": proof.signer_id,
                    "membership_len": proof.membership_len,
                    "membership_hash": STANDARD.encode(&proof.membership_hash),
                });
            }
        }
        // Keyset-LEVEL delegation state (append-only): the owner-signed event log and
        // the root-succession/compaction chain. Emitted VERBATIM (serde → the same
        // STANDARD-b64 wire the browser writes and the daemon adopts) and only when
        // non-empty, so a gen-0 / no-delegation vault carries neither field.
        if !uik.delegation_log.is_empty() {
            if let Ok(v) = serde_json::to_value(&uik.delegation_log) {
                data["uik_delegation_log"] = v;
            }
        }
        if !uik.root_succession.is_empty() {
            if let Ok(v) = serde_json::to_value(&uik.root_succession) {
                data["uik_root_succession"] = v;
            }
        }
    }
    Some(data)
}

pub async fn push_keys_best_effort(state: &Arc<AppState>, vault_id: &str) {
    let Ok(cfg) = active::load() else { return };
    let Some(cloud) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) else {
        return;
    };
    let Some(dk) = device_key() else { return };
    let cloud = cloud.trim_end_matches('/');
    let state_dir = &state.config.state_dir;

    // Refresh from the cloud first so our `base_version` is current (never
    // clobber a newer cloud keyset). Best-effort — a 404/offline just means we
    // push against version 0 (create) which the backend rejects with 409 if the
    // row exists, and we re-pull.
    let cloud_versions = match fetch_key_versions(cloud, vault_id, &dk).await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(vault = %vault_id, "keyset push: version probe failed: {}", e);
            return;
        }
    };

    let Some(pv) = read_per_item_store(state_dir, vault_id) else {
        return;
    };

    // Snapshot the credentials (cid_b64, keyData) so we don't hold the store
    // across awaits. Build each row's `data` byte-compatible with the frontend.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut rows: Vec<(String, serde_json::Value)> = Vec::new();
    for cred in &pv.keyset.credentials {
        let cid_b64 = URL_SAFE_NO_PAD.encode(&cred.credential_id);
        let Some(data) = key_row_data_for(&pv, cred) else {
            continue; // no registry entry — can't form a complete row
        };
        rows.push((cid_b64, data));
    }

    for (cid_b64, data) in rows {
        let cloud_ver = cloud_versions.get(&cid_b64).copied();
        let (base_version, version) = match cloud_ver {
            Some(v) => (Some(v), v + 1), // UPDATE: CAS against cloud's version
            None => (None, 1),           // CREATE: omit base_version
        };
        match push_key(cloud, vault_id, &dk, &cid_b64, base_version, version, &data).await {
            Ok(PushOutcome::Ok { .. }) => {}
            Ok(PushOutcome::EndpointMissing) => return, // /keys not live — stop
            Ok(PushOutcome::Conflict { current_version }) => {
                // Someone moved this row cloud-side: adopt server truth (pull) and
                // stop — NEVER last-writer-wins on the keyset (it gives you K).
                tracing::info!(
                    vault = %vault_id, cid = %cid_b64, current_version,
                    "keyset push: 409 conflict; adopting cloud keyset row (no clobber)"
                );
                let _ = pull_keys(state_dir, cloud, vault_id, &dk).await;
                return;
            }
            Err(e) => {
                tracing::warn!(vault = %vault_id, cid = %cid_b64, "keyset push failed: {}", e);
                return;
            }
        }
    }
    tracing::debug!(vault = %vault_id, "keyset push: all local credentials pushed");
}

/// Probe the cloud for the current `{cid → version}` of every keyset row, so
/// `push_keys_best_effort` can CAS with the right `base_version`. Returns an
/// empty map on a 404 (endpoint not live) so a first push becomes a CREATE.
async fn fetch_key_versions(
    cloud: &str,
    vault: &str,
    device_key: &str,
) -> Result<std::collections::HashMap<String, u64>, String> {
    let url = format!("{}/v/{}/keys?since=0", cloud.trim_end_matches('/'), vault);
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15))
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .get(&url)
        .bearer_auth(device_key)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    match resp.status().as_u16() {
        200 => {}
        404 => return Ok(std::collections::HashMap::new()),
        401 | 403 => return Err(format!("cloud auth rejected (HTTP {})", resp.status())),
        other => return Err(format!("keys GET HTTP {}", other)),
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse keys response: {}", e))?;
    let rows: Vec<KeyRow> = body
        .get("keys")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| format!("parse keys array: {}", e))?
        .unwrap_or_default();
    Ok(rows.into_iter().map(|r| (r.cid, r.version)).collect())
}

/// PUT one keyset row with CAS (§7). Mirrors `push_item`: a CREATE omits
/// `base_version` (sending 0 → 409); an UPDATE includes it. On `200` returns the
/// cloud-stamped `{version, seq}`; `409` → `Conflict{current_version}`; a `404`
/// (endpoint not live) → `EndpointMissing`.
async fn push_key(
    cloud: &str,
    vault: &str,
    device_key: &str,
    cid: &str,
    base_version: Option<u64>,
    version: u64,
    data: &serde_json::Value,
) -> Result<PushOutcome, String> {
    let url = format!("{}/v/{}/keys/{}", cloud.trim_end_matches('/'), vault, cid);
    let mut body = serde_json::json!({ "version": version, "data": data });
    if let Some(bv) = base_version {
        body["base_version"] = serde_json::json!(bv);
    }
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15))
        .map_err(|e| format!("http client init: {}", e))?;
    let resp = client
        .put(&url)
        .bearer_auth(device_key)
        .dik_pop("PUT", &url, &serde_json::to_vec(&body).unwrap_or_default())
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("reach {}: {}", cloud, e))?;
    match resp.status().as_u16() {
        200 => {
            let b: serde_json::Value =
                resp.json().await.map_err(|e| format!("parse put: {}", e))?;
            Ok(PushOutcome::Ok {
                version: b.get("version").and_then(|v| v.as_u64()).unwrap_or(version),
                seq: b.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
            })
        }
        409 => {
            let b: serde_json::Value = resp.json().await.unwrap_or_default();
            let current = b
                .get("currentVersion")
                .and_then(|v| v.as_u64())
                .unwrap_or(version);
            Ok(PushOutcome::Conflict {
                current_version: current,
            })
        }
        404 => Ok(PushOutcome::EndpointMissing),
        other => Err(format!("key PUT HTTP {}", other)),
    }
}

#[cfg(test)]
mod peritem_tests {
    use super::*;
    use crate::storage::item::{ItemNs, VaultKeys};
    use crate::storage::sealed_vault::PerItemVault;
    use sudp::primitives::StdPrimitives;

    fn empty_pv() -> PerItemVault {
        PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap()
    }

    /// Adopt replaces a strictly-newer version and advances the cursor; a stale
    /// (<= local) version is ignored (no clobber of a fresher local push).
    #[test]
    fn adopt_replaces_newer_and_advances_cursor() {
        let k = [0x42u8; 32];
        let vid = "v";
        let mut pv = empty_pv();
        // Local row at version 2.
        let id = pv
            .seal_and_upsert::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Secret,
                "A",
                2,
                &crate::storage::item::ItemPayload::secret_live("A", "local"),
            )
            .unwrap();

        // A stale row (version 1) must NOT replace it.
        let stale = ItemRow {
            item_id: id.clone(),
            version: 1,
            seq: 5,
            ct: "AAAA".into(),
            sig: None,
            signer: None,
        };
        let n = adopt_item_rows(&mut pv, std::slice::from_ref(&stale), 5).unwrap();
        assert_eq!(n, 0, "stale version ignored");
        assert_eq!(pv.get_item(&id).unwrap().version, 2);
        assert_eq!(pv.items_seq, 5, "cursor still advances to max seq");

        // A newer row (version 3) replaces it (raw ct adopted verbatim).
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let newer_ct = URL_SAFE_NO_PAD.encode([1u8, 2, 3, 4]);
        let newer = ItemRow {
            item_id: id.clone(),
            version: 3,
            seq: 9,
            ct: newer_ct,
            sig: None,
            signer: None,
        };
        let n = adopt_item_rows(&mut pv, std::slice::from_ref(&newer), 9).unwrap();
        assert_eq!(n, 1);
        assert_eq!(pv.get_item(&id).unwrap().version, 3);
        assert_eq!(pv.get_item(&id).unwrap().ct, vec![1u8, 2, 3, 4]);
        assert_eq!(pv.items_seq, 9);
    }

    /// A `/keys` row `data` JSON shaped EXACTLY as the frontend writes it
    /// (`lib/vault-grant.ts` addPasskey / setupEnvVault via `toBase64`): x/y/
    /// prf_salt/wrapped_key are STANDARD base64 (with `+`/`/`/`=`), x25519_pub is
    /// base64url, cid is base64url-nopad. Adopting it must upsert the keyset with
    /// the correctly-DECODED prf_salt/wrapped_key + a registry pubkey entry —
    /// proving the LENIENT decoder handles the frontend's mixed encodings so the
    /// daemon can still unwrap K.
    #[test]
    fn keys_row_roundtrips_frontend_std_base64_data() {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        use base64::Engine;
        use sudp::passkey::WebAuthn;

        // Raw bytes the frontend would have encoded.
        let cred_id_raw: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
        let prf_salt_raw: Vec<u8> = (0u8..32).collect();
        // Pick wrap bytes whose STANDARD base64 contains `+` AND `/` (so a strict
        // base64url decoder would REJECT them → the exact break this guards).
        let wrapped_key_raw: Vec<u8> = vec![
            0xFB, 0xFF, 0xBF, 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8B, 0x30, 0xD3,
            0x8F, 0x41, 0x14, 0x93, 0x51, 0x55, 0x97, 0x61, 0x96, 0x9B,
        ];
        let x_raw: Vec<u8> = vec![0xAAu8; 32];
        let y_raw: Vec<u8> = vec![0xBBu8; 32];
        let x25519_raw: Vec<u8> = vec![0xCCu8; 32];

        // cid = base64url-nopad; data fields = STANDARD base64 (x/y/prf_salt/
        // wrapped_key), x25519_pub = base64url (matches the frontend exactly).
        let cid_b64 = URL_SAFE_NO_PAD.encode(&cred_id_raw);
        let x_std = STANDARD.encode(&x_raw);
        let wrapped_std = STANDARD.encode(&wrapped_key_raw);
        assert!(
            wrapped_std.contains('+') || wrapped_std.contains('/'),
            "test fixture must exercise std-base64-only chars"
        );
        let data = serde_json::json!({
            "x": x_std,
            "y": STANDARD.encode(&y_raw),
            "device_name": "Mac · sunny-panda",
            "x25519_pub": URL_SAFE_NO_PAD.encode(&x25519_raw),
            "prf_salt": STANDARD.encode(&prf_salt_raw),
            "wrapped_key": wrapped_std,
        });
        let row_json = serde_json::json!({
            "cid": cid_b64,
            "version": 1u64,
            "seq": 7u64,
            "data": data,
        });
        let row: KeyRow = serde_json::from_value(row_json).unwrap();

        // Adopt into a fresh empty keyset store (the on-demand pull_keys target).
        let mut pv = empty_keyset_store();
        let n = adopt_key_rows(&mut pv, "v", std::slice::from_ref(&row)).unwrap();
        assert_eq!(n, 1);

        // 1. The SealedCredential has the correctly-DECODED prf_salt + wrapped_key.
        let cred = pv
            .keyset
            .credentials
            .iter()
            .find(|c| c.credential_id == cred_id_raw)
            .expect("credential adopted");
        assert_eq!(cred.prf_salt, prf_salt_raw, "prf_salt lenient-decoded");
        assert_eq!(
            cred.wrapped_key, wrapped_key_raw,
            "wrapped_key lenient-decoded"
        );

        // 2. The registry has the pubkey entry (x/y kept verbatim as the frontend
        //    strings; sudp stores WebAuthnPublicKey.x/y as-is).
        let pk = pv
            .keyset
            .registry
            .get::<WebAuthn>(&cred_id_raw)
            .unwrap()
            .expect("registry pubkey adopted");
        assert_eq!(pk.x, x_std, "x kept verbatim (std-base64 string)");
        assert_eq!(pk.device_name, "Mac · sunny-panda");

        // 3. Idempotent re-adopt of the SAME row (version 1) doesn't duplicate
        //    the credential.
        let _ = adopt_key_rows(&mut pv, "v", std::slice::from_ref(&row)).unwrap();
        assert_eq!(
            pv.keyset
                .credentials
                .iter()
                .filter(|c| c.credential_id == cred_id_raw)
                .count(),
            1,
            "no duplicate credential on re-adopt"
        );

        // 4. Serialize the store and confirm the SealedCredential round-trips
        //    through sudp's STANDARD `wire::b64bytes` codec (byte-stable on disk).
        let bytes = serde_json::to_vec(&pv).unwrap();
        let back: PerItemVault = serde_json::from_slice(&bytes).unwrap();
        let back_cred = back
            .keyset
            .credentials
            .iter()
            .find(|c| c.credential_id == cred_id_raw)
            .unwrap();
        assert_eq!(back_cred.wrapped_key, wrapped_key_raw);
    }

    /// DP-S1 wire plumbing (Part 1): a re-keyed vault's keyset-LEVEL `generation`
    /// + owner-signed `rekey_proof` ride REDUNDANTLY on every `/keys` row's data.
    /// Emitting a row via `key_row_data_for` (the push side) and re-adopting it
    /// via `adopt_key_rows` (the pull side) must restore BOTH keyset-level fields
    /// verbatim — the roundtrip a peer performs when it pulls a re-keyed keyset.
    #[test]
    fn rekey_meta_survives_push_to_adopt_roundtrip() {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        // A genuine vault OWNER (also the creator anchor): the re-key proof and the
        // owner cred's role grant are both signed with this key at generation 3, so
        // the adopt-side verify-before-ratchet gate accepts the bump and restores
        // the keyset-level fields (a forged/unsigned proof would be IGNORED — see
        // `member_gen_poison_ignored`).
        let vault = "vault-rt";
        let owner = UikRoot::from_root([0x77u8; 32]);
        let owner_sig_pub = owner.signing().public_bytes().to_vec();
        let owner_id = owner.user_id();
        let gen = 3u64;
        let commit = vec![0xABu8; 32];
        let membership = crate::identity::membership_commitment(&[]).to_vec(); // empty log
        let rk_sig = owner
            .signing()
            .sign(&crate::identity::rekey_sig_input(
                vault, gen, &commit, &owner_id, 0, &membership,
            ))
            .to_vec();
        let grant = owner
            .signing()
            .sign(&crate::identity::role_grant_input(
                vault, &owner_id, "owner", gen,
            ))
            .to_vec();

        let mut pv = empty_pv();
        let cid_b64 = URL_SAFE_NO_PAD.encode(b"c"); // empty_pv's credential id
                                                    // Promote to v2 with an OWNER cred (role grant signed @gen), pin the
                                                    // creator anchor, and set the owner-signed re-key state (gen 3 + proof).
        pv.set_uik_cred(
            cid_b64.clone(),
            owner_id.clone(),
            owner_sig_pub.clone(), // sig_pub
            vec![8u8; 32],         // enc_pub
            vec![1u8; 48],         // k_encapped
            vec![2u8; 48],         // k_ct
            MemberRole::Owner,
            grant.clone(), // role_sig (creator-signed @gen)
        );
        {
            let uik = pv.keyset.uik.as_mut().unwrap();
            uik.creator_sig_pub = owner_sig_pub.clone();
            uik.generation = gen;
            uik.rekey_proof = Some(pv_store::RekeyProof {
                generation: gen,
                k_commitment: commit.clone(),
                sig: rk_sig.clone(),
                signer_id: owner_id.clone(),
                membership_len: 0,
                membership_hash: membership.clone(),
            });
        }

        // Push side: emit the row `data` exactly as `push_keys_best_effort` does.
        let cred = pv.keyset.credentials[0].clone();
        let data = key_row_data_for(&pv, &cred).expect("row data built");
        assert_eq!(data["uik_generation"], serde_json::json!(gen));
        assert!(data["uik_rekey_proof"].is_object(), "proof object emitted");

        // Pull side: a peer adopts the row into a fresh empty keyset store.
        let row_json = serde_json::json!({
            "cid": cid_b64,
            "version": 2u64,
            "seq": 4u64,
            "data": data,
        });
        let row: KeyRow = serde_json::from_value(row_json).unwrap();
        let mut peer = empty_keyset_store();
        let n = adopt_key_rows(&mut peer, vault, std::slice::from_ref(&row)).unwrap();
        assert_eq!(n, 1);

        // Keyset-level fields restored byte-for-byte AND the ratchet advanced —
        // because the owner-signed proof verified at gen 3 (verify-before-ratchet).
        let uik = peer.keyset.uik.as_ref().expect("uik layer adopted");
        assert_eq!(uik.generation, 3, "generation restored");
        let proof = uik.rekey_proof.as_ref().expect("rekey_proof restored");
        assert_eq!(proof.generation, 3);
        assert_eq!(proof.signer_id, owner_id);
        assert_eq!(proof.k_commitment, commit);
        assert_eq!(proof.sig, rk_sig);

        // A gen-0 (never-re-keyed) row carries NEITHER field (additive).
        let mut pv0 = empty_pv();
        pv0.set_uik_cred(
            cid_b64.clone(),
            owner_id.clone(),
            owner_sig_pub.clone(),
            vec![8u8; 32],
            vec![1u8; 48],
            vec![2u8; 48],
            MemberRole::Member,
            Vec::new(),
        );
        let cred0 = pv0.keyset.credentials[0].clone();
        let data0 = key_row_data_for(&pv0, &cred0).expect("row data built");
        assert!(
            data0.get("uik_generation").is_none(),
            "gen-0 omits generation"
        );
        assert!(data0.get("uik_rekey_proof").is_none(), "gen-0 omits proof");
    }

    /// DP-S1 generation is a MONOTONIC ratchet (security): a later adopt carrying
    /// an OLDER generation must NOT roll the keyset backward. A malicious backend
    /// could otherwise replay a stale keyset (with its genuine, still-valid older
    /// proof) to undo a forward-secret re-key. A strictly HIGHER generation is
    /// still adopted (the legit forward path).
    #[test]
    fn adopt_rekey_meta_generation_is_monotonic() {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        // Genuine owner (also the creator anchor). Every adopted bump carries a
        // real owner-signed proof at its generation, and the owner's role grant is
        // (re-)signed at that generation — EXACTLY as a legit re-key rides them on
        // the same synced rows. This exercises the monotonic ratchet on top of the
        // verify-before-ratchet gate.
        let vault = "vault-mono";
        let owner = UikRoot::from_root([0x55u8; 32]);
        let owner_sig_pub = owner.signing().public_bytes().to_vec();
        let owner_id = owner.user_id();

        let mut pv = empty_keyset_store();
        // (Re-)sign the owner's role grant at `gen` and (re)install the owner cred +
        // pinned creator anchor, so `owner_set_at(vault, gen)` confirms the owner.
        let set_grant = |pv: &mut PerItemVault, gen: u64| {
            let grant = owner
                .signing()
                .sign(&crate::identity::role_grant_input(
                    vault, &owner_id, "owner", gen,
                ))
                .to_vec();
            pv.set_uik_cred(
                "cid-owner".into(),
                owner_id.clone(),
                owner_sig_pub.clone(),
                vec![9u8; 32],
                vec![1u8; 40],
                vec![2u8; 40],
                MemberRole::Owner,
                grant,
            );
            pv.keyset.uik.as_mut().unwrap().creator_sig_pub = owner_sig_pub.clone();
        };
        // A genuine owner-signed re-key proof at `gen` (empty delegation log → empty
        // membership commitment).
        let proof = |gen: u64| -> Option<serde_json::Value> {
            let commit = [gen as u8; 32];
            let membership = crate::identity::membership_commitment(&[]);
            let sig = owner.signing().sign(&crate::identity::rekey_sig_input(
                vault, gen, &commit, &owner_id, 0, &membership,
            ));
            Some(serde_json::json!({
                "generation": gen,
                "signer_id": owner_id,
                "k_commitment": URL_SAFE_NO_PAD.encode(commit),
                "sig": URL_SAFE_NO_PAD.encode(sig),
                "membership_len": 0,
                "membership_hash": URL_SAFE_NO_PAD.encode(membership),
            }))
        };

        // First re-key: gen 3 adopted from a clean (gen-0) keyset.
        set_grant(&mut pv, 3);
        adopt_rekey_meta(&mut pv, vault, Some(3), &proof(3)).unwrap();
        assert_eq!(pv.keyset.uik.as_ref().unwrap().generation, 3);
        assert_eq!(
            pv.keyset
                .uik
                .as_ref()
                .unwrap()
                .rekey_proof
                .as_ref()
                .unwrap()
                .generation,
            3
        );

        // Rollback attempt: an OLDER gen-1 keyset is IGNORED by monotonicity (it
        // short-circuits before the signature check) — generation AND proof both
        // stay at 3 (neither overwritten).
        adopt_rekey_meta(&mut pv, vault, Some(1), &proof(1)).unwrap();
        assert_eq!(
            pv.keyset.uik.as_ref().unwrap().generation,
            3,
            "older generation must not roll back"
        );
        assert_eq!(
            pv.keyset
                .uik
                .as_ref()
                .unwrap()
                .rekey_proof
                .as_ref()
                .unwrap()
                .generation,
            3,
            "older proof must not overwrite the current one"
        );

        // Equal gen is also a no-op (idempotent re-adopt of the same keyset).
        adopt_rekey_meta(&mut pv, vault, Some(3), &proof(3)).unwrap();
        assert_eq!(pv.keyset.uik.as_ref().unwrap().generation, 3);

        // A genuinely NEWER re-key (gen 5) IS adopted — the grant is re-signed @5
        // (as a legit re-key does) and the forward path still works.
        set_grant(&mut pv, 5);
        adopt_rekey_meta(&mut pv, vault, Some(5), &proof(5)).unwrap();
        assert_eq!(
            pv.keyset.uik.as_ref().unwrap().generation,
            5,
            "higher generation adopted"
        );
        assert_eq!(
            pv.keyset
                .uik
                .as_ref()
                .unwrap()
                .rekey_proof
                .as_ref()
                .unwrap()
                .generation,
            5
        );
    }

    /// HIGH-severity generation-ratchet DoS regression (verify-before-ratchet).
    /// `adopt_rekey_meta` must NOT advance the monotonic keyset `generation` on a
    /// strictly-higher generation whose owner-signed proof is missing / member-
    /// signed / otherwise invalid. Otherwise a current MEMBER could PUT its own
    /// keyset row (self-cid is allowed by the backend) with `uik_generation: 999`
    /// and no valid proof; every daemon would ratchet to 999, then fold-time
    /// `verify_rekey_proof` would fail → every request for the vault is denied (a
    /// sticky fleet brick — the exact "generation storm" the owner-signed
    /// generation was meant to prevent). The gate verifies the OWNER signature at
    /// the proposed generation BEFORE ratcheting: a forged bump leaves the local
    /// generation untouched; a genuine owner-signed bump still advances it.
    #[test]
    fn member_gen_poison_ignored() {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let vault = "vault-poison";
        let creator = UikRoot::from_root([0x11u8; 32]); // vault owner (creator anchor)
        let member = UikRoot::from_root([0x22u8; 32]); // a current, NON-owner member
        let creator_sig_pub = creator.signing().public_bytes().to_vec();
        let creator_id = creator.user_id();
        let member_sig_pub = member.signing().public_bytes().to_vec();
        let member_id = member.user_id();

        // A v2 keyset at generation 0: creator (Owner) + member (Member), each grant
        // creator-signed at gen 0, creator anchor pinned.
        let mut pv = empty_keyset_store();
        let creator_grant = creator
            .signing()
            .sign(&crate::identity::role_grant_input(
                vault,
                &creator_id,
                "owner",
                0,
            ))
            .to_vec();
        pv.set_uik_cred(
            "cid-creator".into(),
            creator_id.clone(),
            creator_sig_pub.clone(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            creator_grant,
        );
        let member_grant = creator
            .signing()
            .sign(&crate::identity::role_grant_input(
                vault, &member_id, "member", 0,
            ))
            .to_vec();
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member_sig_pub.clone(),
            vec![8u8; 32],
            vec![3u8; 40],
            vec![4u8; 40],
            MemberRole::Member,
            member_grant,
        );
        pv.keyset.uik.as_mut().unwrap().creator_sig_pub = creator_sig_pub.clone();
        assert_eq!(
            pv.keyset.uik.as_ref().unwrap().generation,
            0,
            "keyset starts at generation 0"
        );

        // --- Attack 1: a strictly-higher generation with NO proof → IGNORED. ---
        adopt_rekey_meta(&mut pv, vault, Some(999), &None).unwrap();
        assert_eq!(
            pv.keyset.uik.as_ref().unwrap().generation,
            0,
            "gen:999 with no proof must NOT ratchet",
        );

        // --- Attack 2: a MEMBER-signed proof at gen 999 → IGNORED. ---
        // The backend lets a member PUT its own self-cid row, so a member can self-
        // sign a re-key proof. It is not an OWNER @999, so the gate rejects it.
        let commit = [0x99u8; 32];
        let member_rk_sig = member
            .signing()
            .sign(&crate::identity::rekey_sig_input(
                vault,
                999,
                &commit,
                &member_id,
                0,
                &crate::identity::membership_commitment(&[]),
            ))
            .to_vec();
        let member_proof = Some(serde_json::json!({
            "generation": 999u64,
            "signer_id": member_id,
            "k_commitment": URL_SAFE_NO_PAD.encode(commit),
            "sig": URL_SAFE_NO_PAD.encode(&member_rk_sig),
        }));
        adopt_rekey_meta(&mut pv, vault, Some(999), &member_proof).unwrap();
        assert_eq!(
            pv.keyset.uik.as_ref().unwrap().generation,
            0,
            "member-signed gen:999 proof must NOT ratchet (signer is not an owner @999)",
        );
        assert!(
            pv.keyset.uik.as_ref().unwrap().rekey_proof.is_none(),
            "no forged proof is stored",
        );

        // --- Legit path: a genuine OWNER-signed re-key at gen 1 → advances. ---
        // A real re-key re-signs every surviving grant at the new generation on the
        // same synced rows; simulate the creator's grant re-signed @1.
        let creator_grant1 = creator
            .signing()
            .sign(&crate::identity::role_grant_input(
                vault,
                &creator_id,
                "owner",
                1,
            ))
            .to_vec();
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .creds
            .get_mut("cid-creator")
            .expect("creator cred")
            .role_sig = creator_grant1;
        let commit1 = [0x01u8; 32];
        let membership1 = crate::identity::membership_commitment(&[]); // empty delegation log
        let owner_rk_sig = creator
            .signing()
            .sign(&crate::identity::rekey_sig_input(
                vault,
                1,
                &commit1,
                &creator_id,
                0,
                &membership1,
            ))
            .to_vec();
        let owner_proof = Some(serde_json::json!({
            "generation": 1u64,
            "signer_id": creator_id,
            "k_commitment": URL_SAFE_NO_PAD.encode(commit1),
            "sig": URL_SAFE_NO_PAD.encode(&owner_rk_sig),
            "membership_len": 0,
            "membership_hash": URL_SAFE_NO_PAD.encode(membership1),
        }));
        adopt_rekey_meta(&mut pv, vault, Some(1), &owner_proof).unwrap();
        assert_eq!(
            pv.keyset.uik.as_ref().unwrap().generation,
            1,
            "genuine owner-signed re-key at gen 1 advances the ratchet",
        );
        let stored = pv
            .keyset
            .uik
            .as_ref()
            .unwrap()
            .rekey_proof
            .as_ref()
            .expect("owner-signed proof stored");
        assert_eq!(stored.generation, 1);
        assert_eq!(stored.signer_id, creator_id);
    }

    /// The delegation state (owner-signed event log + root-succession/compaction
    /// chain) actually SYNCS through the `/keys` wire: a fresh device that adopts the
    /// carried fields reconstructs the SAME owner-set as the origin — the whole point
    /// of the sync carriage (without it the fold works in-memory but never propagates).
    #[test]
    fn delegation_state_syncs_via_keys_wire() {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;

        let vault = "vault-deleg-sync";
        let creator = UikRoot::from_root([0x11u8; 32]);
        let a = UikRoot::from_root([0x33u8; 32]);
        let b = UikRoot::from_root([0x44u8; 32]);
        let creator_id = creator.user_id();
        let (a_id, b_id) = (a.user_id(), b.user_id());
        let creator_pub = creator.signing().public_bytes().to_vec();

        // Build a v2 keyset: creator anchor + creator owner-grant @0; A & B are creds
        // with NO checkpoint grant (their ownership will come ONLY from the log).
        let build = |with_log: bool| -> PerItemVault {
            let mut pv = empty_keyset_store();
            let cg = creator
                .signing()
                .sign(&crate::identity::role_grant_input(
                    vault,
                    &creator_id,
                    "owner",
                    0,
                ))
                .to_vec();
            pv.set_uik_cred(
                "cid-c".into(),
                creator_id.clone(),
                creator_pub.clone(),
                vec![9u8; 32],
                vec![1u8; 40],
                vec![2u8; 40],
                MemberRole::Owner,
                cg,
            );
            for (cid, who, id) in [("cid-a", &a, &a_id), ("cid-b", &b, &b_id)] {
                pv.set_uik_cred(
                    cid.into(),
                    id.clone(),
                    who.signing().public_bytes().to_vec(),
                    vec![9u8; 32],
                    vec![1u8; 40],
                    vec![2u8; 40],
                    MemberRole::Member,
                    Vec::new(),
                );
            }
            pv.keyset.uik.as_mut().unwrap().creator_sig_pub = creator_pub.clone();
            if with_log {
                // creator sets A owner (seq 1); A (a non-root owner) sets B (seq 2).
                for (signer, subj, seq) in [(&creator, &a_id, 1u64), (&a, &b_id, 2u64)] {
                    let gid = signer.user_id();
                    let gpub = signer.signing().public_bytes().to_vec();
                    let sig = signer
                        .signing()
                        .sign(&crate::identity::delegation_event_input(
                            vault, "set", subj, "owner", &gid, seq, 0,
                        ))
                        .to_vec();
                    pv.keyset.uik.as_mut().unwrap().delegation_log.push(
                        sealed_vault::DelegationEvent {
                            op: "set".into(),
                            subject_id: subj.clone(),
                            role: MemberRole::Owner,
                            granter_id: gid,
                            granter_sig_pub: gpub,
                            seq,
                            role_epoch: 0,
                            sig,
                        },
                    );
                }
            }
            pv
        };

        let source = build(true);
        let src_owners = source.fold_owner_set(vault);
        assert_eq!(
            src_owners.get(&a_id),
            Some(&MemberRole::Owner),
            "A owner @ source"
        );
        assert_eq!(
            src_owners.get(&b_id),
            Some(&MemberRole::Owner),
            "B owner @ source"
        );

        // Serialize the log the way `key_row_data_for` does (serde → wire). The sig
        // MUST ride as a base64 STRING (the shape the browser/backend agree on).
        let log_json =
            serde_json::to_value(&source.keyset.uik.as_ref().unwrap().delegation_log).unwrap();
        assert!(
            log_json[0]["sig"].is_string(),
            "delegation event sig rides as a STANDARD-b64 string on the /keys wire",
        );

        // A fresh device that adopted only the CREDS (no log) sees just the creator.
        let mut fresh = build(false);
        assert!(
            !fresh.fold_owner_set(vault).contains_key(&a_id),
            "no log adopted yet → A is not an owner on the fresh device",
        );

        // Adopt the carried log → the fresh device reconstructs the FULL owner-set.
        adopt_delegation_meta(&mut fresh, vault, &Some(log_json.clone()), &None).unwrap();
        assert_eq!(
            fresh.fold_owner_set(vault),
            src_owners,
            "delegation log syncs: the fresh device folds the SAME owner-set",
        );

        // Idempotent: re-adopting the same wire does NOT grow the log (dedup).
        adopt_delegation_meta(&mut fresh, vault, &Some(log_json), &None).unwrap();
        assert_eq!(
            fresh.keyset.uik.as_ref().unwrap().delegation_log.len(),
            2,
            "re-adopting the same rows de-dups (no unbounded growth)",
        );
    }

    /// PARITY: adopting the end-to-end `verify(anchor, members, proof)` TRIPLE
    /// (`adopt_membership_triple`, the fmt=2 wire) folds to the EXACT SAME owner-set as
    /// adopting the equivalent cid-keyed `/keys` rows. This is the load-bearing guarantee
    /// of ET3 — the daemon speaks the triple on the wire but its in-memory keyset (hence
    /// fold + unlock) is byte-identical to the legacy row path. Same crypto, two wires.
    #[test]
    fn membership_triple_adopts_same_owner_set_as_keys_wire() {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let vault = "vault-triple-parity";
        let creator = UikRoot::from_root([0x11u8; 32]);
        let a = UikRoot::from_root([0x33u8; 32]);
        let b = UikRoot::from_root([0x44u8; 32]);
        let creator_id = creator.user_id();
        let (a_id, b_id) = (a.user_id(), b.user_id());
        let creator_pub = creator.signing().public_bytes().to_vec();

        // SOURCE: the SAME v2 keyset the /keys wire produces — creator owner-grant @0 + an
        // owner-signed log (creator→A owner, A→B owner) — folded to its owner-set.
        let mut source = empty_keyset_store();
        let cg = creator
            .signing()
            .sign(&crate::identity::role_grant_input(vault, &creator_id, "owner", 0))
            .to_vec();
        source.set_uik_cred(
            "cid-c".into(),
            creator_id.clone(),
            creator_pub.clone(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            cg.clone(),
        );
        for (cid, who, id) in [("cid-a", &a, &a_id), ("cid-b", &b, &b_id)] {
            source.set_uik_cred(
                cid.into(),
                id.clone(),
                who.signing().public_bytes().to_vec(),
                vec![9u8; 32],
                vec![1u8; 40],
                vec![2u8; 40],
                MemberRole::Member,
                Vec::new(),
            );
        }
        source.keyset.uik.as_mut().unwrap().creator_sig_pub = creator_pub.clone();
        for (signer, subj, seq) in [(&creator, &a_id, 1u64), (&a, &b_id, 2u64)] {
            let gid = signer.user_id();
            let gpub = signer.signing().public_bytes().to_vec();
            let sig = signer
                .signing()
                .sign(&crate::identity::delegation_event_input(
                    vault, "set", subj, "owner", &gid, seq, 0,
                ))
                .to_vec();
            source
                .keyset
                .uik
                .as_mut()
                .unwrap()
                .delegation_log
                .push(sealed_vault::DelegationEvent {
                    op: "set".into(),
                    subject_id: subj.clone(),
                    role: MemberRole::Owner,
                    granter_id: gid,
                    granter_sig_pub: gpub,
                    seq,
                    role_epoch: 0,
                    sig,
                });
        }
        let src_owners = source.fold_owner_set(vault);
        assert_eq!(src_owners.get(&a_id), Some(&MemberRole::Owner));
        assert_eq!(src_owners.get(&b_id), Some(&MemberRole::Owner));

        // Build the EQUIVALENT triple (a GET /v/{vid}/membership body) from the SAME data.
        let enc = |bytes: &[u8]| STANDARD.encode(bytes);
        let member = |role: &str, sig: Option<&[u8]>| {
            let mut m = serde_json::json!({
                "role": role,
                "k_encapped": enc(&[1u8; 40]),
                "k_ct": enc(&[2u8; 40]),
            });
            if let Some(s) = sig {
                m["role_sig"] = serde_json::Value::String(enc(s));
            }
            m
        };
        let ident = |uik: &UikRoot| {
            serde_json::json!({ "sig_pub": enc(&uik.signing().public_bytes()), "enc_pub": enc(&[9u8; 32]) })
        };
        let mut members = serde_json::Map::new();
        members.insert(creator_id.clone(), member("owner", Some(&cg)));
        members.insert(a_id.clone(), member("member", None));
        members.insert(b_id.clone(), member("member", None));
        let mut identities = serde_json::Map::new();
        identities.insert(creator_id.clone(), ident(&creator));
        identities.insert(a_id.clone(), ident(&a));
        identities.insert(b_id.clone(), ident(&b));
        let log_json =
            serde_json::to_value(&source.keyset.uik.as_ref().unwrap().delegation_log).unwrap();
        let anchor_b64 = enc(&creator_pub);
        let body = serde_json::json!({
            "anchor": anchor_b64,
            "members": serde_json::Value::Object(members),
            "proof": { "delegation_log": log_json, "succession": [], "generation": 0 },
            "identities": serde_json::Value::Object(identities),
            "credentials": [ { "cid": "cid-c", "identity_id": creator_id.clone() } ],
        });

        // Adopt the TRIPLE into a fresh keyset and assert the owner-set is IDENTICAL.
        let mut fresh = empty_keyset_store();
        adopt_membership_triple(&mut fresh, vault, &anchor_b64, &body).unwrap();
        assert_eq!(
            fresh.fold_owner_set(vault),
            src_owners,
            "the membership TRIPLE folds to the SAME owner-set as the /keys wire",
        );
    }

    /// F1 regression: a checkpoint member seated by a valid root-signed `role_sig` folds as
    /// OWNER even when its K-DELIVERY fields (`enc_pub` / `k_encapped` / `k_ct`) are absent.
    /// The fold is about AUTHORITY (sig_pub + role_sig), not delivery; the backend + frontend
    /// seat such a member, so the daemon must too, or the owner-set diverges across layers.
    #[test]
    fn membership_triple_seats_checkpoint_owner_without_k_delivery_fields() {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let vault = "vault-f1";
        let creator = UikRoot::from_root([0x11u8; 32]);
        let m = UikRoot::from_root([0x55u8; 32]);
        let creator_id = creator.user_id();
        let m_id = m.user_id();
        let enc = |b: &[u8]| STANDARD.encode(b);

        // Both owner via root-signed checkpoint grants @0; `m` gets NO enc_pub / k_encapped / k_ct.
        let cg = creator.signing().sign(&crate::identity::role_grant_input(vault, &creator_id, "owner", 0)).to_vec();
        let mg = creator.signing().sign(&crate::identity::role_grant_input(vault, &m_id, "owner", 0)).to_vec();
        let mut members = serde_json::Map::new();
        members.insert(creator_id.clone(), serde_json::json!({
            "role": "owner", "k_encapped": enc(&[1u8; 40]), "k_ct": enc(&[2u8; 40]), "role_sig": enc(&cg),
        }));
        members.insert(m_id.clone(), serde_json::json!({ "role": "owner", "role_sig": enc(&mg) }));
        let mut identities = serde_json::Map::new();
        identities.insert(creator_id.clone(), serde_json::json!({
            "sig_pub": enc(&creator.signing().public_bytes()), "enc_pub": enc(&[9u8; 32]),
        }));
        // `m`: sig_pub present, enc_pub MISSING (nullable column).
        identities.insert(m_id.clone(), serde_json::json!({ "sig_pub": enc(&m.signing().public_bytes()) }));
        let anchor_b64 = enc(&creator.signing().public_bytes());
        let body = serde_json::json!({
            "anchor": anchor_b64,
            "members": serde_json::Value::Object(members),
            "proof": { "generation": 0 },
            "identities": serde_json::Value::Object(identities),
            "credentials": [ { "cid": "cid-c", "identity_id": creator_id.clone() } ],
        });
        let mut pv = empty_keyset_store();
        adopt_membership_triple(&mut pv, vault, &anchor_b64, &body).unwrap();
        assert_eq!(
            pv.fold_owner_set(vault).get(&m_id),
            Some(&MemberRole::Owner),
            "a checkpoint owner with a valid role_sig folds as owner even with no enc_pub/K",
        );
    }

    /// A compaction (root-signed SELF-succession) syncs through the `/keys` wire: the
    /// derived `role_epoch` advances on a fresh device that adopts the carried
    /// `root_succession`, so a stale pre-compaction grant is dropped there too.
    #[test]
    fn compaction_syncs_and_derives_role_epoch() {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        use base64::Engine as _;

        let vault = "vault-compact-sync";
        let creator = UikRoot::from_root([0x11u8; 32]);
        let member = UikRoot::from_root([0x22u8; 32]);
        let creator_id = creator.user_id();
        let member_id = member.user_id();
        let creator_pub = creator.signing().public_bytes().to_vec();

        // creator owner-grant @0, member owner-grant @0 (a checkpoint grant, so a
        // compaction that doesn't re-sign it must drop the member).
        let mut pv = empty_keyset_store();
        let cg = creator
            .signing()
            .sign(&crate::identity::role_grant_input(
                vault,
                &creator_id,
                "owner",
                0,
            ))
            .to_vec();
        pv.set_uik_cred(
            "cid-c".into(),
            creator_id.clone(),
            creator_pub.clone(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            cg,
        );
        let mg = creator
            .signing()
            .sign(&crate::identity::role_grant_input(
                vault, &member_id, "owner", 0,
            ))
            .to_vec();
        pv.set_uik_cred(
            "cid-m".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            mg,
        );
        pv.keyset.uik.as_mut().unwrap().creator_sig_pub = creator_pub.clone();
        assert_eq!(
            pv.fold_owner_set(vault).get(&member_id),
            Some(&MemberRole::Owner),
            "member is an owner @epoch 0",
        );

        // The creator compacts to epoch 1 (self-succession) WITHOUT re-signing the
        // member's grant → serialize the succession chain to the wire.
        let root_id = creator_id.clone();
        let succ_sig = creator
            .signing()
            .sign(&crate::identity::root_succession_input(
                vault,
                &root_id,
                &root_id,
                &creator.signing().public_bytes(),
                1,
            ))
            .to_vec();
        let succ_json = serde_json::json!([{
            "old_root_id": root_id,
            "new_root_id": root_id,
            "new_root_sig_pub": base64::engine::general_purpose::STANDARD.encode(&creator_pub),
            "role_epoch": 1u64,
            "sig": base64::engine::general_purpose::STANDARD.encode(&succ_sig),
        }]);

        // A fresh device with the SAME creds but no succession → member still owner.
        // Adopt the carried compaction → derived epoch is 1, the stale grant drops.
        adopt_delegation_meta(&mut pv, vault, &None, &Some(succ_json.clone())).unwrap();
        let os = pv.fold_owner_set(vault);
        assert_eq!(
            os.get(&creator_id),
            Some(&MemberRole::Owner),
            "the root stays an owner across compaction (genesis pin)",
        );
        assert!(
            !os.contains_key(&member_id),
            "compaction syncs: derived role_epoch=1 drops the member's stale @0 grant",
        );
        // Dedup: re-adopting the same cert doesn't grow the chain.
        adopt_delegation_meta(&mut pv, vault, &None, &Some(succ_json)).unwrap();
        assert_eq!(
            pv.keyset.uik.as_ref().unwrap().root_succession.len(),
            1,
            "re-adopting the same succession cert de-dups",
        );
    }

    /// The vault's ROOT owner (creator) anchor is TOFU-pinned SET-ONCE (design/
    /// identity-uik-aik.md §4.3). Adopting a keyset that claims creator=A pins A;
    /// a LATER adopt claiming creator=B must NOT overwrite it — else a colluding
    /// backend could swap the role anchor to a key it controls and forge the
    /// owner-set. First-seen wins (mirrors `adopt_rekey_meta`'s monotonic rule).
    #[test]
    fn creator_sig_pub_set_once() {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        use base64::Engine;
        let cid_b64 = URL_SAFE_NO_PAD.encode(b"c");
        let pub_a = vec![0xAAu8; 32];
        let pub_b = vec![0xBBu8; 32];

        // A minimal valid `/keys` row carrying the keyset-LEVEL creator anchor.
        let row = |creator_pub: &[u8], version: u64| -> KeyRow {
            let data = serde_json::json!({
                "x": "x",
                "y": "y",
                "device_name": "Dev",
                "prf_salt": STANDARD.encode([0u8; 32]),
                "wrapped_key": STANDARD.encode([0u8; 48]),
                "uik_creator_sig_pub": STANDARD.encode(creator_pub),
            });
            serde_json::from_value(serde_json::json!({
                "cid": cid_b64,
                "version": version,
                "seq": version,
                "data": data,
            }))
            .unwrap()
        };

        let mut peer = empty_keyset_store();
        // First adopt pins creator = A.
        adopt_key_rows(&mut peer, "v", std::slice::from_ref(&row(&pub_a, 1))).unwrap();
        assert_eq!(
            peer.keyset.uik.as_ref().unwrap().creator_sig_pub,
            pub_a,
            "first-seen creator anchor pinned"
        );

        // A later adopt claiming creator = B must NOT overwrite the pin.
        adopt_key_rows(&mut peer, "v", std::slice::from_ref(&row(&pub_b, 2))).unwrap();
        assert_eq!(
            peer.keyset.uik.as_ref().unwrap().creator_sig_pub,
            pub_a,
            "creator pin is set-once (TOFU); a swap attempt is ignored"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// v1.1 mode-dependent agent-hash cadence: 600s while the stream carries
    /// the events (poll = belt-and-suspenders), the legacy 30s when the poll
    /// is the only propagation path.
    #[test]
    fn agent_keys_cadence_is_mode_dependent() {
        assert_eq!(agent_keys_cadence(true), Duration::from_secs(600));
        assert_eq!(agent_keys_cadence(false), Duration::from_secs(30));
    }

    /// The browser assembles the blob client-side; this guards that the exact
    /// shape it produces (compact JSON, registry value field order
    /// `x`/`y`/`device_name`, standard-base64 byte fields, registry key =
    /// std-b64(credential_id)) deserializes into a SealedVault and survives a
    /// write_atomic → read round-trip. Values are a real vault.dat sample.
    /// If the frontend's `setupEnvVault` assembly and this ever drift, this
    /// fails before the e2e does. Mirrors lib/vault-grant.ts setupEnvVault.
    #[test]
    fn frontend_assembled_blob_parses_and_roundtrips() {
        let cid = "UNwLi9p8ykq/YcbW/mk7loMRg8NyDZ021BoA8L2MOBZo//Cdi6Gqh1rhIvT8FHsiq6CsubhU";
        // Compact, exactly as the browser serializes (JSON.stringify):
        let blob = serde_json::json!({
            "version": 1,
            "registry": {
                cid: { "x": "72laEiwOtkMX5s7o280rWZk2zAfVG64gtsXAbBS46c4=",
                       "y": "B56KGrJOCOvfT3hR36M4sXimg8dlmLfhK8g+Kf2R66c=",
                       "device_name": "Mac · sunny-panda" }
            },
            "credentials": [
                { "credential_id": cid,
                  "prf_salt": "9gZJFej46o71aNu7955eqwygNwrptzCyg3D40FNQxPI=",
                  "wrapped_key": "OjModKRUWfStXREA8a+5WE06boSM2WhUl2e34x6+PzeWXupr0ulv13OdSwSkbXBRG5FEIbh9VVaKk9ESpuZfKcZbCosHJj7y" }
            ],
            "ciphertext": "fQslPsTIWQLbmWNoD/rJfXlwsaU2RvY5N2U3EqJf6FYWUugz9CSjRlXyc0/M7mc3"
        });

        // 1. Parses into the daemon's SealedVault (the pull path).
        let sealed: SealedVault =
            serde_json::from_value(blob).expect("frontend blob must parse as SealedVault");
        assert_eq!(sealed.credentials.len(), 1);
        assert_eq!(sealed.registry.len(), 1);

        // 2. write_atomic → read round-trips byte-for-field (what pull does).
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        sealed_vault::write_atomic(&path, &sealed).unwrap();
        let back = sealed_vault::read(&path).unwrap().unwrap();
        assert_eq!(
            back.credentials[0].credential_id,
            sealed.credentials[0].credential_id
        );
        assert_eq!(back.ciphertext, sealed.ciphertext);
    }

    /// A tombstone (`status:"deleted"`) classifies as `Deleted` and writes
    /// NOTHING to disk — the drop is the caller's job, never a side effect of
    /// parsing. Status wins even if a (stale) `blob`/`version` is also present.
    #[test]
    fn deleted_status_classifies_as_deleted_and_writes_nothing() {
        let dir = tempdir().unwrap();
        let body = serde_json::json!({
            "status": "deleted",
            "version": 1782722939030u64,
            // A defensive case: even with a blob present, deleted must win.
            "blob": { "garbage": true }
        });
        let outcome = classify_pull_body(dir.path(), "v-del", &body).unwrap();
        assert_eq!(outcome, PullOutcome::Deleted);
        // No vault.dat or sidecar created by the classifier.
        assert!(!dir
            .path()
            .join("vaults")
            .join("v-del")
            .join("vault.dat")
            .exists());
        assert!(!version_sidecar(dir.path(), "v-del").exists());
    }

    /// `parse_shared_from_body` maps the server `kind` envelope field (team §4):
    /// "shared"→Some(true), "private"→Some(false); absent / null / unrecognized →
    /// None so the caller leaves the last known value (fail-safe private default).
    #[test]
    fn parse_shared_from_body_maps_kind_field() {
        use serde_json::json;
        assert_eq!(
            parse_shared_from_body(&json!({"kind": "shared"})),
            Some(true)
        );
        assert_eq!(
            parse_shared_from_body(&json!({"kind": "private"})),
            Some(false)
        );
        assert_eq!(parse_shared_from_body(&json!({"kind": "bogus"})), None);
        assert_eq!(parse_shared_from_body(&json!({"kind": null})), None);
        assert_eq!(parse_shared_from_body(&json!({})), None);
        // Coexists with a real live envelope (blob + version + kind).
        assert_eq!(
            parse_shared_from_body(&json!({"version": 5u64, "blob": {}, "kind": "shared"})),
            Some(true)
        );
    }

    /// `{ unchanged: true }` (no status, or status:"live") classifies as
    /// `Unchanged` and writes nothing.
    #[test]
    fn unchanged_body_classifies_as_unchanged() {
        let dir = tempdir().unwrap();
        let body = serde_json::json!({ "unchanged": true });
        assert_eq!(
            classify_pull_body(dir.path(), "v-unch", &body).unwrap(),
            PullOutcome::Unchanged
        );
        let body_live = serde_json::json!({ "status": "live", "unchanged": true });
        assert_eq!(
            classify_pull_body(dir.path(), "v-unch", &body_live).unwrap(),
            PullOutcome::Unchanged
        );
    }

    /// PER-ITEM: a per-item vault's `/blob` GET now returns a keyset-lifecycle
    /// marker with NO `blob` field (`{ lifecycle:"per-item-v3", version }`). The
    /// classifier must treat it as `Unchanged` (the keyset rides `/keys` now) and
    /// write NOTHING to `vault.dat` — NOT error, NOT persist. The version
    /// SIDECAR, however, MUST advance: an unrecorded marker version means every
    /// `?since=` probe re-fires — `/blob/wait` answered instantly forever and the
    /// 25s long-poll became a ~1.5s hot loop (the 0.9.36 spin bug).
    #[test]
    fn lifecycle_only_body_classifies_as_unchanged_and_records_version() {
        let dir = tempdir().unwrap();
        let body = serde_json::json!({ "lifecycle": "per-item-v3", "version": 7u64 });
        assert_eq!(
            classify_pull_body(dir.path(), "v-life", &body).unwrap(),
            PullOutcome::Unchanged
        );
        // No vault.dat written — a lifecycle marker is not content.
        assert!(!dir
            .path()
            .join("vaults")
            .join("v-life")
            .join("vault.dat")
            .exists());
        // ...but the cursor advanced, so the next since=7 probe can park.
        assert_eq!(read_local_version(dir.path(), "v-life"), 7);
        // Even a bare `{}` (no blob, no status, no unchanged) is Unchanged, not
        // an error (the old code returned Err "blob missing"). No version field
        // → nothing to record.
        assert_eq!(
            classify_pull_body(dir.path(), "v-empty", &serde_json::json!({})).unwrap(),
            PullOutcome::Unchanged
        );
        assert!(!version_sidecar(dir.path(), "v-empty").exists());
        // THE REAL WIRE SHAPE: `putBlob` wraps the marker, and handleBlobGet
        // returns `{ blob: { lifecycle, version }, version, status:"live" }`. The
        // marker sits UNDER `blob`, so this must be Unchanged (not parsed as a
        // SealedState). This is the shape `sc sync` actually receives — the case
        // the top-level-`lifecycle` body above never exercised.
        let wrapped = serde_json::json!({
            "blob": { "lifecycle": "per-item-v3", "version": 9u64 },
            "version": 9u64,
            "status": "live"
        });
        assert_eq!(
            classify_pull_body(dir.path(), "v-wrap", &wrapped).unwrap(),
            PullOutcome::Unchanged
        );
        assert!(!dir
            .path()
            .join("vaults")
            .join("v-wrap")
            .join("vault.dat")
            .exists());
        assert_eq!(read_local_version(dir.path(), "v-wrap"), 9);
    }

    /// A live blob (status absent → treated live, backward-compatible with the
    /// v1.0.22 cloud that never sends `status`) persists `vault.dat` + the
    /// version sidecar and classifies as `Updated(version)`.
    #[test]
    fn live_blob_persists_and_classifies_as_updated() {
        let cid = "UNwLi9p8ykq/YcbW/mk7loMRg8NyDZ021BoA8L2MOBZo//Cdi6Gqh1rhIvT8FHsiq6CsubhU";
        let blob = serde_json::json!({
            "version": 1,
            "registry": {
                cid: { "x": "72laEiwOtkMX5s7o280rWZk2zAfVG64gtsXAbBS46c4=",
                       "y": "B56KGrJOCOvfT3hR36M4sXimg8dlmLfhK8g+Kf2R66c=",
                       "device_name": "Mac · sunny-panda" }
            },
            "credentials": [
                { "credential_id": cid,
                  "prf_salt": "9gZJFej46o71aNu7955eqwygNwrptzCyg3D40FNQxPI=",
                  "wrapped_key": "OjModKRUWfStXREA8a+5WE06boSM2WhUl2e34x6+PzeWXupr0ulv13OdSwSkbXBRG5FEIbh9VVaKk9ESpuZfKcZbCosHJj7y" }
            ],
            "ciphertext": "fQslPsTIWQLbmWNoD/rJfXlwsaU2RvY5N2U3EqJf6FYWUugz9CSjRlXyc0/M7mc3"
        });
        let dir = tempdir().unwrap();
        let body = serde_json::json!({ "version": 42u64, "blob": blob });
        let outcome = classify_pull_body(dir.path(), "v-live", &body).unwrap();
        assert_eq!(outcome, PullOutcome::Updated(42));
        assert!(dir
            .path()
            .join("vaults")
            .join("v-live")
            .join("vault.dat")
            .exists());
        assert_eq!(read_local_version(dir.path(), "v-live"), 42);
    }

    /// `forget_vault` removes a known vault by vid alone and is idempotent.
    /// (Drives the cloud-sync delete path's CLI-config cleanup.) Runs against a
    /// temp HOME so the developer's real `~/.safeclaw/config.toml` is untouched.
    #[test]
    fn forget_vault_by_vid_is_idempotent() {
        use crate::cli::active::{self, CliConfig, KnownVault};
        let home = tempdir().unwrap();
        // active.rs resolves config via dirs::home_dir() → $HOME.
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", home.path());

        let cfg = CliConfig {
            daemon: Some("http://localhost:1".into()),
            vault: Some("vid-A".into()),
            known_vaults: vec![
                KnownVault {
                    daemon: "http://localhost:1".into(),
                    vault: "vid-A".into(),
                },
                KnownVault {
                    daemon: "http://localhost:1".into(),
                    vault: "vid-B".into(),
                },
            ],
            ..Default::default()
        };
        active::save(&cfg).unwrap();

        // Remove the ACTIVE vault by vid: dropped from the catalog AND cleared
        // active. The write also migrates the legacy config-field entries into
        // the catalog file (`known_vaults.toml`) and clears the field.
        assert_eq!(active::forget_vault("vid-A"), Ok(true));
        let after = active::load().unwrap();
        assert!(after.vault.is_none());
        assert!(after.daemon.is_none());
        assert!(
            after.known_vaults.is_empty(),
            "legacy field migrated to the file"
        );
        // Dropping the ACTIVE vault leaves the deleted-upstream breadcrumb so
        // `sc status` / `resolve_active` can say "re-pair", not "no vaults yet".
        assert_eq!(after.vault_deleted_upstream.as_deref(), Some("vid-A"));
        let known = active::known_vaults();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].vault, "vid-B");

        // Idempotent: forgetting it again is a no-op (Ok(false)).
        assert_eq!(active::forget_vault("vid-A"), Ok(false));
        // A non-active known vault: removed, active untouched — and no
        // breadcrumb overwrite (vid-A is still the one worth reporting).
        assert_eq!(active::forget_vault("vid-B"), Ok(true));
        assert!(active::known_vaults().is_empty());
        assert_eq!(
            active::load().unwrap().vault_deleted_upstream.as_deref(),
            Some("vid-A")
        );

        // The next successful pairing/selection clears the breadcrumb.
        active::put_active("http://localhost:1", "vid-C").unwrap();
        assert!(active::load().unwrap().vault_deleted_upstream.is_none());

        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
}
