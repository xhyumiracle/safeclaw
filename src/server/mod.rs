//! HTTP server: control/API plane (`CONTROL_PORT`, `:23293`) router.
//!
//! v1 URL surface (PROTOCOL.md §4.1 / `[[v1-endpoint-design]]` /
//! `[[architecture-final-2026-05-27]]`):
//!
//! ```text
//! POST /v/{vid}/op              R-side op creation (or U-direct: Enroll/Write/Export)
//! GET  /v/{vid}/passkeys        list enrolled credentials for this vault
//! GET  /v/{vid}/events          SSE lifecycle stream
//! GET  /registry                static service catalog (no vault contents)
//! GET  /v/{vid}/registry        per-vault live view (catalog + connected state)
//! GET  /op/{op_id}              poll op status + cached value
//! POST /op/{op_id}/approve      U submits grant G → T validates, dispatches act
//! POST /op/{op_id}/reject       U denies
//! GET  /health                  custodian health
//! GET  /pubkey                  custodian HPKE bootstrap key (placeholder)
//! GET  /skill.md                skill file for agents (?agent=claude|cursor|codex)
//! ```
//!
//! Public root paths (`/health`, `/registry`, `/pubkey`, `/skill.md`) were originally
//! prefixed `/c/*`; the prefix was dropped 2026-05-27 to align with the
//! "zero remapping" backend story (SaaS proxy forwards the same URLs).
//!
//! Vault selection is via URL path (`{vid}`). The custodian does no
//! principal authentication — that's a deployment-layer concern (the
//! SafeClaw pro-backend is the auth boundary).

pub mod broker;
pub mod broker_flow;
pub mod handlers;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};

use crate::state::AppState;

/// Maximum request body size for all control-plane endpoints.
/// 256 KB is ample for any legitimate operation descriptor or grant.
const MAX_BODY_BYTES: usize = 256 * 1024;

pub fn app_router(state: Arc<AppState>) -> Router {
    // ── Control plane ────────────────────────────────────────────────────
    // Vault lifecycle, op approval, passkeys, registry. NOT agent-key gated:
    // op/approve is gated by the op_id capability + passkey signature (the
    // passkey wall); registry/passkeys are auth-free localhost reads. This is
    // exactly the surface the old admin port carried.
    let mut router = Router::new()
        // Custodian-level (no vault context).
        .route("/health", get(handlers::health::health))
        .route("/pubkey", get(handlers::metadata::pubkey))
        .route("/registry", get(handlers::registry::catalog))
        .route("/skill.md", get(handlers::skill::skill_md))
        // Vault-scoped.
        .route("/v/{vid}/op", post(handlers::op::create))
        // Local value deposit for connection-add / secret-set write ops — the
        // op itself carries only a salted digest (its JSON rides to the cloud
        // relay for the grant page; plaintext values never do).
        .route("/v/{vid}/op-payload", post(handlers::op_payload::create))
        .route("/v/{vid}/sync", post(handlers::metadata::sync_now))
        .route("/v/{vid}/passkeys", get(handlers::metadata::passkeys))
        .route(
            "/v/{vid}/pending-passkeys",
            post(handlers::pending_passkey::create),
        )
        .route("/v/{vid}/events", get(handlers::events::stream))
        .route(
            "/v/{vid}/secret-keys",
            get(handlers::secret_keys::secret_keys),
        )
        .route("/v/{vid}/registry", get(handlers::registry::vault_registry))
        .route("/v/{vid}/usage", get(handlers::usage::usage))
        // Device egress-proxy hot-reload (after `sc proxy set/clear`) — no vault
        // context, no params: re-reads the local stored value into the live
        // clients so the daemon re-points egress without a restart/re-unlock.
        .route("/proxy/reload", post(handlers::proxy::reload))
        // Live ambient egress-proxy report (from `sc run`) — the daemon follows
        // the operator's current shell proxy without a persisted `sc proxy set`.
        // In-memory only; LOOPBACK-ONLY (it takes a caller-chosen proxy value).
        .route("/proxy/ambient", post(handlers::proxy::ambient))
        // Browser-fired sync hint (a `no-cors` POST from the console right
        // after it pre-seals an OAuth connect). Authority-free by contract:
        // host-allowlisted, rate-limited, uniform 204 — see nudge.rs. The
        // no-CorsLayer posture below is unaffected (the console never reads
        // the reply; `no-cors` responses are opaque).
        .route("/sync/nudge", post(handlers::nudge::sync_nudge))
        // Op-flat (vault context lives on the approval record).
        // GET /op/{id} returns the JSON poll response (status + cached value).
        // The agent / CLI polls this; the human approves on safeclaw.pro via
        // the op-relay, so the daemon serves no approval HTML of its own.
        .route("/op/{op_id}", get(handlers::approve::get_op))
        .route("/op/{op_id}/approve", post(handlers::approve::approve_op))
        .route("/op/{op_id}/reject", post(handlers::approve::reject_op))
        .with_state(state.clone());
    router = router.layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    // ── Agent-surface control routes ─────────────────────────────────────
    // The only agent-facing HTTP route left on the control plane is the
    // `/export` disabled stub (raw-secret exfil off the agent surface — the
    // op-plane Export ceremony is the human path). Live credential traffic no
    // longer goes through an HTTP route: it rides the resident phantom-only
    // proxy (S2, a separate listener). This sub-router carries the agent-key
    // gate (`require_api_key`) so the stub stays scoped like the old broker
    // surface without touching the passkey/admin-gated control routes.
    let broker = broker_router(state);
    router = router.merge(broker);

    // CORS: the only browser inbound was the embedded op-page, now deleted —
    // approval happens on safeclaw.pro, not against the daemon. With no browser
    // flow left, no CorsLayer is added (the broker plane must stay off browsers
    // anyway — F-25). Self-host dev that fronts the daemon with a browser can
    // still terminate CORS at its reverse proxy.
    router
}

/// The agent-key-gated broker sub-router. Split out so the gate is a layer on
/// these broker routes only — the control routes in `app_router` keep their own
/// (passkey / X-Admin-Key / auth-free-localhost) gating untouched.
fn broker_router(state: Arc<AppState>) -> Router {
    use crate::proxy::env;

    Router::new()
        // /export → disabled stub (raw-secret export off the agent surface; the
        // op-plane Export ceremony is the human path).
        .route("/v/{vid}/export/{key}", post(env::disabled))
        // Agent-key gate — scoped to exactly this route.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api_key::require_api_key,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
