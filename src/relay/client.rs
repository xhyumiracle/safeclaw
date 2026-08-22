//! op-relay egress client: register an op, poll for the deposited grant, and
//! apply it locally. See `relay/mod.rs` for the why.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};

use crate::device_auth::DikRequestExt;
use crate::state::AppState;

/// Poll cadence (v1.1, mode-dependent). The wait between polls is
/// `timeout(interval, op-event notify)`: the SSE `op` event ACCELERATES the
/// next poll, it never replaces it — the poll response stays the source of
/// truth for status. 15s only with PROOF the event can reach us —
/// `op_events_for(vid)`: this vid is on the live stream AND the backend
/// declared the `op` cap in hello. Anything short of proof (stream down,
/// vault born after daemon start, over the vid cap, v1-only backend) keeps
/// the legacy 2s cadence — an approval must never silently wait out a
/// relaxed poll for an event that cannot arrive.
const POLL_STREAMED: Duration = Duration::from_secs(15);
const POLL_FALLBACK: Duration = Duration::from_secs(2);
/// ★ Storm floor: an event wake never polls sooner than this after the
/// previous poll — events accelerate the poll, they don't replace its
/// pacing (a buggy emitter must cost ≤1 poll/s, not RTT-speed; same rule
/// as refresh_agent_keys_on_miss's debounce).
const POLL_FLOOR: Duration = Duration::from_secs(1);
/// Daemon-side safety cap so a never-approved op's task can't run forever
/// (the relay also enforces a TTL). Derived per-op from the op's own expiry
/// (SSOT: aux.policy.timeout stamps every pending op) + slack past the
/// in-loop `expires_at + 5` precise stop; clamped so a pathological expiry
/// can neither stop the poll instantly nor pin a task for days.
fn poll_budget(expires_at: u64) -> Duration {
    Duration::from_secs(expires_at.saturating_sub(now()).clamp(60, 86_400) + 60)
}

/// Interval selection, factored for the unit test.
fn poll_interval(op_events_reach_us: bool) -> Duration {
    if op_events_reach_us {
        POLL_STREAMED
    } else {
        POLL_FALLBACK
    }
}

/// Park until the next poll is due: an `op` stream event for OUR op_id or
/// the mode-sized interval, whichever first — then honor the storm floor
/// relative to the LAST poll. `notify_one` parks a permit, so an event that
/// fires while a poll response is in flight completes the next wait
/// instantly instead of being lost.
async fn next_poll_due(
    op_wait: &crate::sync_stream::OpWaitGuard<'_>,
    vault_id: &str,
    last_poll: tokio::time::Instant,
) {
    let interval = poll_interval(crate::sync_stream::op_events_for(vault_id));
    let _ = tokio::time::timeout(interval, op_wait.notified()).await;
    // Past deadlines return immediately — the floor only bites event storms.
    tokio::time::sleep_until(last_poll + POLL_FLOOR).await;
}

/// Fire-and-forget: register `op_id` with the relay and drive it to
/// completion in a background task. No-op (returns immediately) when no relay
/// is configured. Never blocks op creation; all failures are logged, not
/// propagated — the local path still works without the relay.
pub fn spawn_register_and_poll(
    state: Arc<AppState>,
    vault_id: String,
    op_id: String,
    op: Value,
    r: String,
    expires_at: u64,
    // The triggering agent's id (api-key prefix / AIK id), forwarded to the
    // relay so the approve page can name WHO asked. None for user-initiated
    // lifecycle ceremonies (unlock/lock/delete).
    agent_id: Option<String>,
) {
    let (relay_url, auth_token) = match resolve_relay(&state) {
        Some(v) => v,
        None => return, // local-only daemon (no cloud pairing); nothing to do
    };
    tokio::spawn(async move {
        if let Err(e) = run(
            state,
            &relay_url,
            &auth_token,
            &vault_id,
            &op_id,
            &op,
            &r,
            expires_at,
            agent_id.as_deref(),
        )
        .await
        {
            tracing::warn!(op = %op_id, "relay register/poll ended: {}", e);
        }
    });
}

/// Fire-and-forget: withdraw a still-pending op from the relay (device-key
/// auth). Called when a new ceremony op supersedes a stale one — the requester
/// voids its OWN prior request. No passkey/W_c involved (nothing was granted).
/// The backend only flips `pending → cancelled`, so an already-approved op is
/// untouched. No-op when there's no cloud relay configured.
pub fn spawn_cancel(state: Arc<AppState>, vault_id: String, op_id: String) {
    let (base, auth_token) = match resolve_relay(&state) {
        Some(v) => v,
        None => return,
    };
    let daemon_pubkey = URL_SAFE_NO_PAD.encode(state.sc.pk_bytes());
    tokio::spawn(async move {
        let url = format!("{}/v/{}/op/relay/{}/cancel", base, vault_id, op_id);
        let client = match crate::cli::egress_proxy::client(Duration::from_secs(10)) {
            Ok(c) => c,
            Err(_) => return,
        };
        let cancel_body = json!({ "daemon_pubkey": daemon_pubkey });
        match client
            .post(&url)
            .bearer_auth(&auth_token)
            .dik_pop("POST", &url, &serde_json::to_vec(&cancel_body).unwrap_or_default())
            .json(&cancel_body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                tracing::info!(op = %op_id, "superseded op withdrawn from relay");
            }
            Ok(r) => tracing::debug!(op = %op_id, "relay cancel HTTP {}", r.status()),
            Err(e) => tracing::debug!(op = %op_id, "relay cancel error: {}", e),
        }
    });
}

/// Resolve `(relay_base, auth_token)` for op-relay registration.
///
/// Primary (the local-daemon pivot): a paired daemon dials its cloud backend
/// (`cloud_backend`, persisted at `sc login`) and authenticates as itself with
/// the `sc_device_` device-key — exactly the channel the Slice-3 blob sync
/// already uses. Backend gate: `resolveAuth` + `isOwnedVaultId`.
///
/// Fallback: an operator-supplied `SAFECLAW_RELAY_URL` + `SAFECLAW_ADMIN_KEY`
/// (self-host / SaaS-custodian deployments that pre-date pairing).
///
/// `None` ⇒ no relay ⇒ purely local daemon; the local op-page ceremony stands.
fn resolve_relay(state: &AppState) -> Option<(String, String)> {
    if let Ok(cfg) = crate::cli::active::load() {
        if let Some(base) = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty()) {
            if let Some(dk) = crate::sync::device_key() {
                return Some((base.trim_end_matches('/').to_string(), dk));
            }
        }
    }
    let base = state.config.relay_url.clone().filter(|s| !s.is_empty())?;
    let key = state.config.admin_key.clone().filter(|s| !s.is_empty())?;
    Some((base.trim_end_matches('/').to_string(), key))
}

async fn run(
    state: Arc<AppState>,
    relay_url: &str,
    auth_token: &str,
    vault_id: &str,
    op_id: &str,
    op: &Value,
    r: &str,
    expires_at: u64,
    agent_id: Option<&str>,
) -> Result<(), String> {
    let base = relay_url.trim_end_matches('/');
    // v1.1: register for `op` stream events before anything can flip the
    // op's status. The guard IS the registration — Drop deregisters — so
    // EVERY exit path out of this function (the early error returns below
    // included) removes the entry; a leak here would grow the daemon-global
    // map for the daemon's lifetime.
    let op_wait = crate::sync_stream::op_events().register(op_id);
    let client = crate::cli::egress_proxy::client(Duration::from_secs(35))
        .map_err(|e| format!("relay client init: {}", e))?;

    // 1. Register the pending op. op_summary is the full op JSON (the page
    //    renders it AND uses it + r to recompute the WebAuthn binding β).
    //    We also include the vault's passkey public material (cid + prf_salt)
    //    so the browser — which can't reach this localhost daemon's
    //    /v/{vid}/passkeys — can pick the credential and derive W_c. cid and
    //    prf_salt are public per PROTOCOL.md §4.3.
    let daemon_pubkey = URL_SAFE_NO_PAD.encode(state.sc.pk_bytes());
    let op_summary = STANDARD.encode(serde_json::to_vec(op).unwrap_or_default());
    let passkeys = fetch_passkeys(&client, state.config.port, vault_id).await;
    let reg_url = format!("{}/v/{}/op/relay/register", base, vault_id);
    let reg_body = json!({
        "op_id": op_id,
        "daemon_pubkey": daemon_pubkey,
        "op_summary": op_summary,
        "passkeys": passkeys,
        "r": r,
        "expires_at": expires_at,
        // WHO triggered this op — the agent the local broker authenticated.
        // Advisory attribution for the approve page (the backend resolves it to
        // a label); null for user-initiated lifecycle ceremonies.
        "agent_id": agent_id,
    });
    let reg = client
        .post(&reg_url)
        .bearer_auth(auth_token)
        .dik_pop("POST", &reg_url, &serde_json::to_vec(&reg_body).unwrap_or_default())
        .json(&reg_body)
        .send()
        .await
        .map_err(|e| format!("relay register: {}", e))?;
    if !reg.status().is_success() {
        return Err(format!("relay register HTTP {}", reg.status()));
    }
    tracing::info!(op = %op_id, "registered with op-relay");

    // 2. Poll for the deposited grant. Status semantics are UNCHANGED from
    //    the pre-event loop — only the wait between polls is event-aware.
    let poll_url = format!("{}/v/{}/op/relay/{}", base, vault_id, op_id);
    let deadline = tokio::time::Instant::now() + poll_budget(expires_at);
    while tokio::time::Instant::now() < deadline {
        if now() > expires_at + 5 {
            return Ok(()); // op expired; stop quietly
        }
        let last_poll = tokio::time::Instant::now();
        let resp = match client
            .get(&poll_url)
            .bearer_auth(auth_token)
            .dik_pop("GET", &poll_url, &[])
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(op = %op_id, "relay poll transient error: {}", e);
                next_poll_due(&op_wait, vault_id, last_poll).await;
                continue;
            }
        };
        match resp.status().as_u16() {
            200 => {
                // Approved: body carries the browser-deposited grant JSON.
                let body: Value = resp
                    .json()
                    .await
                    .map_err(|e| format!("relay poll parse: {}", e))?;
                let grant = body.get("sealed_grant").cloned().unwrap_or(body);
                if let Err(e) = apply_grant(state.clone(), op_id, grant).await {
                    // The human APPROVED but the daemon can't apply this grant.
                    // The canonical cause now is a tapped passkey that isn't in
                    // THIS vault's keyset ("unknown credential"), after the approve
                    // path's self-heal re-pull still couldn't resolve it. Record the
                    // reason locally, then REJECT the op so `sc unlock` / `sc op
                    // wait` returns a definitive, actionable error. Ending the poll
                    // with Err instead (the old behavior) left the relay op
                    // 'approved' and hung the CLI forever on "Waiting for approval".
                    if let Ok(audit) = state.audits.for_vault(vault_id) {
                        let _ = audit.finalize(
                            op_id,
                            crate::audit::STATUS_EXPIRED,
                            now() as i64,
                            None,
                            Some(&format!("approved but apply failed: {}", e)),
                            None,
                        );
                    }
                    tracing::warn!(op = %op_id, "approved grant could not be applied ({}); rejecting so the CLI fails clearly instead of hanging", e);
                    apply_reject(state.clone(), op_id).await;
                    return Ok(());
                }
                return Ok(());
            }
            403 => {
                // Rejected by the user.
                apply_reject(state.clone(), op_id).await;
                return Ok(());
            }
            202 => {
                next_poll_due(&op_wait, vault_id, last_poll).await;
            }
            404 => return Ok(()), // unknown/expired on the relay side
            409 => {
                // Cancelled: the requester (this daemon, via a superseding op)
                // withdrew it. Stop polling — nothing more will arrive.
                tracing::info!(op = %op_id, "relay op cancelled by requester; poll stopping");
                return Ok(());
            }
            other => {
                tracing::debug!(op = %op_id, "relay poll HTTP {}", other);
                next_poll_due(&op_wait, vault_id, last_poll).await;
            }
        }
    }
    Ok(())
}

/// Apply a relay-fetched grant by replaying it through the daemon's own
/// `/op/{id}/approve` endpoint over localhost. This reuses the full approve
/// path (incl. the §4.2 W_c unseal) verbatim — no logic is duplicated.
async fn apply_grant(state: Arc<AppState>, op_id: &str, grant: Value) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("loopback client init: {}", e))?;
    let url = format!(
        "http://127.0.0.1:{}/op/{}/approve",
        state.config.port, op_id
    );
    let resp = client
        .post(&url)
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("loopback approve: {}", e))?;
    let status = resp.status();
    if status.is_success() {
        tracing::info!(op = %op_id, "relay grant applied via loopback approve");
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!("loopback approve HTTP {}: {}", status, body))
    }
}

async fn apply_reject(state: Arc<AppState>, op_id: &str) {
    let url = format!("http://127.0.0.1:{}/op/{}/reject", state.config.port, op_id);
    if let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        let _ = client.post(&url).send().await;
        tracing::info!(op = %op_id, "relay grant rejected via loopback");
    }
}

/// Loopback-fetch the vault's passkey public material (cid + prf_salt + pubkey)
/// so the relay can hand it to the browser. Returns `[]` on any failure — the
/// page then reports "no passkeys" rather than the whole op failing.
async fn fetch_passkeys(client: &reqwest::Client, port: u16, vault_id: &str) -> Value {
    let url = format!("http://127.0.0.1:{}/v/{}/passkeys", port, vault_id);
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(v) => v.get("passkeys").cloned().unwrap_or_else(|| json!([])),
            Err(_) => json!([]),
        },
        _ => json!([]),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v1.1 mode-dependent poll interval: 15s safety net behind the stream's
    /// `op` event, the legacy 2s when the poll is the only path.
    #[test]
    fn poll_interval_is_mode_dependent() {
        assert_eq!(poll_interval(true), Duration::from_secs(15));
        assert_eq!(poll_interval(false), Duration::from_secs(2));
    }
}
