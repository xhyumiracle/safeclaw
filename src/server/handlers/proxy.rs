//! `POST /proxy/reload` — hot-reload the device egress proxy into the running
//! daemon's swappable clients after `sc proxy set/clear` rewrites the stored
//! value. It re-points BOTH egress paths — the shared reqwest client (OAuth
//! mint / GCP / snaplii, via [`crate::core::forward::reload_egress_proxy`]) and
//! the resident proxy's forward connector (the shared [`AppState::egress_proxy`]
//! cell) — with NO daemon restart, so the in-memory vault key survives and the
//! operator never re-unlocks.
//!
//! Takes NO parameters: it always re-reads the on-disk egress proxy (env >
//! file). So even if the control plane is bound beyond loopback, this can only
//! re-point the daemon at its OWN local config, never an attacker-chosen proxy —
//! it carries no gate of its own by design.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::state::AppState;

pub async fn reload(State(state): State<Arc<AppState>>) -> Json<Value> {
    crate::core::forward::reload_egress_proxy();
    crate::proxy::upstream::reload_cell(&state.egress_proxy);
    let proxy = crate::cli::egress_proxy::effective();
    tracing::info!(
        proxy = proxy.as_deref().unwrap_or("(direct)"),
        "egress proxy hot-reloaded"
    );
    Json(json!({ "ok": true, "proxy": proxy }))
}

/// The body `sc run` POSTs to `/proxy/ambient`: the operator's live shell proxy,
/// or `null` when this shell has no proxy (so the daemon falls back to its file).
#[derive(serde::Deserialize)]
pub struct AmbientBody {
    #[serde(default)]
    pub proxy: Option<String>,
}

/// `POST /proxy/ambient` — a short-lived `sc` command (today `sc run`) reports
/// the operator's LIVE shell egress proxy so the long-running daemon can follow
/// it WITHOUT a persisted `sc proxy set`. Sets the in-memory ambient value (never
/// persisted) and, only when it changed, hot-reloads the egress clients exactly
/// like `/proxy/reload`.
///
/// LOOPBACK-ONLY, unlike `/proxy/reload`: `/proxy/reload` re-reads the daemon's
/// OWN local file and so is safe from any origin, but this accepts a caller-
/// CHOSEN proxy (which may carry userinfo credentials), so it must never be
/// reachable off-box even if the control plane is bound beyond loopback. A remote
/// daemon uses `sc proxy set`, never this. Non-loopback peers get 403.
pub async fn ambient(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<AmbientBody>,
) -> Response {
    if !peer.ip().is_loopback() {
        return (StatusCode::FORBIDDEN, "loopback only").into_response();
    }
    let proxy = body
        .proxy
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let changed = crate::cli::egress_proxy::set_ambient(proxy.clone());
    if changed {
        crate::core::forward::reload_egress_proxy();
        crate::proxy::upstream::reload_cell(&state.egress_proxy);
    }
    // NEVER log or return the proxy URL itself — it can carry userinfo
    // credentials. Presence + whether egress is now proxied is all we surface.
    tracing::debug!(
        has_ambient = proxy.is_some(),
        proxied = crate::cli::egress_proxy::effective().is_some(),
        changed,
        "ambient egress proxy reported"
    );
    Json(json!({ "ok": true })).into_response()
}
