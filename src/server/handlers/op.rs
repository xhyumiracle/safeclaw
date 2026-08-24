//! `POST /v/{vid}/op` — R-side operation creation.
//!
//! Body: a canonical sudp `Operation`. The custodian stores it as a pending
//! approval, issues a fresh challenge `r`, and returns `{ op_id, r, expires_at }`.
//! U later authorizes via `POST /op/{op_id}/approve` (binding β computed over r).
//!
//! All flows route through here — R-driven (Use/Export) AND U-direct
//! (Enroll/Write/console-Export). The two-RTT shape is uniform.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{ConnectInfo, Path, State},
    Json,
};
use serde_json::{json, Value};

use crate::audit;
use crate::error::{AppError, Result};
use crate::protocol::operation::{ActType, Operation};
use crate::state::{AppState, ApprovalEvent};

pub async fn create(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Path(vault_id): Path<String>,
    Json(op): Json<Operation>,
) -> Result<Json<Value>> {
    validate_vault_id(&vault_id)?;
    reject_broker_kind(&op.act.kind)?;
    // F-11: validate op.act.target length. A 256-char cap prevents
    // unbounded strings from reaching audit rows and downstream handlers.
    // Character set is not enforced globally (target syntax is act-kind
    // specific), but the length cap applies universally.
    if op.act.target.len() > 256 {
        return Err(AppError::BadRequest(
            "op.act.target too long (max 256 chars)".into(),
        ));
    }
    // Locked-state gate (H3 / PROTOCOL.md §6.3): when the vault is Locked,
    // only the unlock ceremony (and first-time Enroll, which auto-unlocks)
    // is admissible. Everything else gets a canned 409 so the caller knows
    // to drive a `Custom("vault-unlock")` op first.
    let is_lifecycle_bypass = matches!(&op.act.kind, ActType::Enroll)
        || matches!(&op.act.kind, ActType::Custom(name) if name == "vault-unlock");
    if !is_lifecycle_bypass && state.is_vault_locked(&vault_id) {
        return Err(AppError::VaultLocked);
    }
    // ONE approval window (SSOT, user decision 2026-07-14): ops that arrive
    // without an explicit Valid window — the CLI ceremonies (unlock / set /
    // connect) — inherit the vault's `aux.policy.timeout`, the SAME knob the
    // broker's ask path uses, so the grant-page countdown, the value stash,
    // and the op's own expiry can never disagree. A locked vault (the unlock
    // ceremony) can't read its policy and takes the 30-min default.
    let mut op = op;
    if op.valid.exp.is_none() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        op.valid.exp = Some(now_unix + state.policy_approval_hold(&vault_id));
    }
    let ip: IpAddr = addr.ip();
    let r = {
        let mut store = state.challenges.lock().unwrap();
        store.issue(ip).ok_or(AppError::TooManyRequests)?
    };
    let (op_id, expires_at) = {
        let mut store = state.approvals.lock().unwrap();
        let id = store.create(vault_id.clone(), op.clone(), r.clone());
        let exp = store.get(&id).map(|r| r.expires_at_unix).unwrap_or(0);
        (id, exp)
    };

    // Persist a `pending` audit row so `GET /v/{vid}/approvals?status=pending`
    // can return current pendings on page load (in-memory ApprovalStore is
    // process-bound). Best-effort — audit failure must NOT block op creation.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(store) = state.audits.for_vault(&vault_id) {
        // F-22: cap pending ops per vault to prevent SQLite table flooding.
        const MAX_PENDING_PER_VAULT: i64 = 500;
        match store.count_pending() {
            Ok(n) if n >= MAX_PENDING_PER_VAULT => {
                return Err(AppError::TooManyRequests);
            }
            Err(e) => {
                tracing::warn!(vault = %vault_id, "audit count_pending failed: {}", e);
                // non-fatal — let the op through rather than blocking legitimate use
            }
            _ => {}
        }
        let row = audit::row_from_op(&op_id, &op, now, expires_at as i64);
        if let Err(e) = store.insert(&row) {
            tracing::warn!(vault = %vault_id, op = %op_id, "audit insert pending failed: {}", e);
        }
    }

    // Slice-2 web approval: if a cloud op-relay is configured, register this
    // pending op and poll for the browser-deposited grant in the background.
    // No-op when relay_url is unset (purely local daemon).
    crate::relay::client::spawn_register_and_poll(
        state.clone(),
        vault_id.clone(),
        op_id.clone(),
        serde_json::to_value(&op).unwrap_or(Value::Null),
        r.clone(),
        expires_at,
        None, // user-initiated lifecycle ceremony — no triggering agent
    );

    // Requester-side supersede: a lifecycle ceremony (unlock/lock) is a
    // singleton — at most one should be live per vault. When a new one is
    // created (e.g. the user Ctrl-C'd `sc unlock` and retried), withdraw the
    // stale prior op so the console stops showing "1 approval waiting". Only
    // ceremonies supersede; Use/Export ops can legitimately be concurrent.
    if let ActType::Custom(name) = &op.act.kind {
        if name == "vault-unlock" || name == "vault-lock" {
            let prev = {
                let mut live = state.live_ceremony_ops.lock().unwrap();
                live.insert((vault_id.clone(), name.clone()), op_id.clone())
            };
            if let Some(prev_id) = prev {
                if prev_id != op_id {
                    cancel_superseded(&state, &vault_id, &prev_id, now);
                }
            }
        }
    }

    state.emit_event(ApprovalEvent {
        vault_id: vault_id,
        approval_id: op_id.clone(),
        kind: "pending".into(),
        op_summary: Some(serde_json::to_value(&op).unwrap_or(Value::Null)),
        response_preview: None,
        reason: None,
    });

    Ok(Json(json!({
        "op_id": op_id,
        "r": r,
        "expires_at": expires_at,
    })))
}

/// Withdraw a ceremony op that a newer one just superseded. Local: flip the
/// stale in-memory record terminal + stamp its audit row `cancelled`. Cloud:
/// withdraw it from the relay (device-key auth, no passkey — no credential is
/// touched). All best-effort; the backend cancel only affects a `pending` op.
fn cancel_superseded(state: &Arc<AppState>, vault_id: &str, op_id: &str, now: i64) {
    const REASON: &str = "superseded by a newer request";
    let was_pending = {
        let mut store = state.approvals.lock().unwrap();
        store.reject(op_id, REASON).is_some()
    };
    if was_pending {
        if let Ok(store) = state.audits.for_vault(vault_id) {
            if let Err(e) = store.finalize(
                op_id,
                audit::STATUS_CANCELLED,
                now,
                None,
                Some(REASON),
                None,
            ) {
                tracing::warn!(vault = %vault_id, op = %op_id, "audit finalize cancelled failed: {}", e);
            }
        }
        state.emit_event(ApprovalEvent {
            vault_id: vault_id.to_string(),
            approval_id: op_id.to_string(),
            kind: "cancelled".into(),
            op_summary: None,
            response_preview: None,
            reason: Some(REASON.into()),
        });
    }
    crate::relay::client::spawn_cancel(state.clone(), vault_id.to_string(), op_id.to_string());
}

/// Reject op kinds that are broker-plane primitives. Today: `Use`.
///
/// Reasoning: a Use op forwards an upstream HTTP request and is the unit
/// SaaS bills on. It must originate from the broker path (proxy port for
/// the network-gate deployment; SaaS-stamped JSON-API for a future
/// crypto-gate deployment) — never from the control-plane endpoint, which
/// has no billing gate by construction.
///
/// Control-plane ops (Enroll, Write, Export, Custom("vault-unlock"/...))
/// pass through; they're user-initiated state changes authorized by a
/// passkey-signed grant.
fn reject_broker_kind(kind: &ActType) -> Result<()> {
    if matches!(kind, ActType::Use) {
        return Err(AppError::BadRequest(
            "Use ops must be created via the broker path, not the control-plane op endpoint".into(),
        ));
    }
    Ok(())
}

pub fn validate_vault_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 128 {
        return Err(AppError::BadRequest(
            "invalid vault_id (1-128 chars)".into(),
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::BadRequest("vault_id has illegal chars".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_use_kind() {
        let r = reject_broker_kind(&ActType::Use);
        assert!(matches!(r, Err(AppError::BadRequest(_))));
    }

    #[test]
    fn accept_control_plane_kinds() {
        for kind in [
            ActType::Enroll,
            ActType::Write,
            ActType::Export,
            ActType::Custom("vault-unlock".into()),
            ActType::Custom("vault-lock".into()),
            ActType::Custom("vault-delete".into()),
        ] {
            assert!(
                reject_broker_kind(&kind).is_ok(),
                "kind {:?} should pass",
                kind
            );
        }
    }

    fn test_state() -> AppState {
        let cfg = crate::config::Config {
            state_dir: std::path::PathBuf::from(format!(
                "/tmp/safeclaw-test-op-{}",
                std::process::id()
            )),
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

    /// RED LINE (verified invariant — see the export/allow discussion): an
    /// `Export` hands over the RAW secret (irreversible ownership transfer),
    /// so it MUST always require a passkey grant and must NEVER be
    /// auto-executed by the read/write `allow` policy default (cb124ca).
    ///
    /// The protection is architectural, not a policy line: `Use` (the only
    /// kind the `allow` fast-path can run) is forced onto the broker path by
    /// `reject_broker_kind`, while the control-plane `/op` endpoint consults
    /// NO policy for ANY kind — it always parks a pending op needing
    /// `/op/{id}/approve`. This test locks that: an Export on an UNLOCKED,
    /// default-`allow` vault still returns a pending `{op_id, r}` and reveals
    /// no secret inline. If someone ever wires policy-allow auto-execution
    /// into the Export path, this goes red.
    #[tokio::test]
    async fn export_is_always_pending_never_auto_executed_under_allow_default() {
        use crate::protocol::operation::{Act, Bind, Valid};

        let state = Arc::new(test_state());
        // Unlock with the default cache → the read/write `allow` default is
        // in force. This is the exact regime that must NOT reach Export.
        state.unlock_vault(
            "v1".into(),
            crate::state::SecretsCache::default(),
            zeroize::Zeroizing::new(Vec::new()),
        );

        let op = Operation {
            act: Act {
                kind: ActType::Export,
                target: "native-secrets.github_token".into(),
                scope: Value::Null,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, Some(300)),
        };

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let resp = create(
            State(state.clone()),
            ConnectInfo(addr),
            Path("v1".into()),
            Json(op),
        )
        .await
        .expect("Export op-create should succeed (and park a pending op)");

        let body = resp.0;
        // Pending: an op_id + challenge were issued, awaiting a passkey grant.
        assert!(
            body.get("op_id").and_then(|v| v.as_str()).is_some(),
            "Export must return a pending op_id, got {body}"
        );
        assert!(
            body.get("r").is_some(),
            "pending Export must carry a challenge `r`, got {body}"
        );
        // Nothing executed inline: no raw secret / reveal payload leaked.
        for leak in ["value", "secret", "plaintext", "revealed"] {
            assert!(
                body.get(leak).is_none(),
                "Export create must NOT reveal '{leak}' inline (allow default leaked into Export!): {body}"
            );
        }
    }
}
