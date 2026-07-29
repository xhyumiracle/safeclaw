//! The 23294 **API face** — a read-only responder living on the proxy listener.
//!
//! The proxy port serves two RFC 7230 §5.3 request-line forms
//! (CREDENTIAL_BROKER.md §14): CONNECT / absolute-form = the credential proxy
//! (MITM / blind-tunnel);
//! **origin-form** (`GET /v/{vid}/registry`) = discovery + op-poll, self-answered
//! here so the agent needs ONE port. A self-authority absolute-form request (the
//! agent wrongly routed discovery through its own proxy) is the loop-guard case,
//! also handled here. Everything is a plain READ:
//! - `/health`, `/ca` — unauthenticated (liveness / public CA cert).
//! - `/v/{vid}/registry`, `/op/{id}` — the agent Bearer key (§8).
//!
//! Writes / ceremony never appear here — they stay on the control port (23293),
//! passkey-gated and invisible to the agent. The read projections come from the
//! SAME functions the control plane serves (`registry::vault_registry_value`,
//! `approve::op_poll_value`, `health::health_value`), so the two ports can't
//! drift; auth reuses the pure `api_key::check_token`. Both shared surfaces are
//! `Value`/`&str`-typed, so this module never touches axum's `http` types.

use std::sync::Arc;

use hudsucker::hyper::{header, HeaderMap, Method, Request, Response, StatusCode};
use hudsucker::Body;
use serde_json::{json, Value};

use crate::error::ScCode;
use crate::state::AppState;

/// Is `req` addressed to us (the API face) rather than a proxied upstream? True
/// for origin-form (no authority — a direct `GET /path` to this port) and for
/// the self-authority loop-guard (absolute-form whose host:port is our own
/// loopback proxy). Any other authority is a real proxy target → false.
pub fn is_api_face(req: &Request<Body>, proxy_port: u16) -> bool {
    match req.uri().host() {
        None => true,
        Some(h) => is_self_authority(h, req.uri().port_u16(), proxy_port),
    }
}

fn is_self_authority(host: &str, port: Option<u16>, proxy_port: u16) -> bool {
    let loopback = matches!(host, "127.0.0.1" | "::1" | "localhost");
    // Require the EXACT proxy port: `127.0.0.1:<other>` is a real localhost
    // upstream the agent is proxying to, not a loop back into us.
    loopback && port == Some(proxy_port)
}

/// Self-answer an API-face request. GET-only; unknown paths → 404. Every
/// projection is a synchronous read; the only await is the debounced hash
/// refresh on an auth miss.
pub async fn respond(state: &Arc<AppState>, req: &Request<Body>) -> Response<Body> {
    if req.method() != Method::GET {
        return problem(ScCode::MethodNotAllowed, "GET only");
    }
    let path = req.uri().path().to_string();

    // ── Unauthenticated: liveness + public CA ────────────────────────────────
    if path == "/health" {
        return json(
            StatusCode::OK,
            &crate::server::handlers::health::health_value(state),
        );
    }
    if path == "/ca" {
        return ca_pem(state);
    }

    // ── Bearer-gated reads (§8) ──────────────────────────────────────────────
    if let Some(op_id) = path.strip_prefix("/op/") {
        if let Err(r) = require_key(state, req.headers()).await {
            return r;
        }
        // Op-agent binding (team §C1): an agent-created op is pollable only by
        // the agent that triggered it — a different (still valid) key gets the
        // same shape as an unknown op, so this face leaks nothing about other
        // agents' pending work. Ops with no agent stamp (ceremonies) stay
        // reachable by any valid key, matching today's user-surface semantics.
        {
            let bound = state
                .approvals
                .lock()
                .unwrap()
                .get(op_id)
                .and_then(|r| r.agent_prefix.clone());
            if let Some(expected) = bound {
                let caller = bearer_token(req.headers())
                    .as_deref()
                    .map(crate::audit::agent_key_prefix)
                    .unwrap_or_default();
                if caller != expected {
                    return problem(ScCode::NotFound, "Not found");
                }
            }
        }
        return match crate::server::handlers::approve::op_poll_value(state, op_id) {
            Ok(v) => op_poll_response(&v),
            Err(e) => app_err(e),
        };
    }
    if let Some(vid) = path
        .strip_prefix("/v/")
        .and_then(|r| r.strip_suffix("/registry"))
    {
        if let Err(r) = require_key(state, req.headers()).await {
            return r;
        }
        let q = crate::server::handlers::registry::RegistryQuery::from_query_str(
            req.uri().query().unwrap_or(""),
        );
        return match crate::server::handlers::registry::vault_registry_value(state, vid, &q) {
            Ok(v) => json(StatusCode::OK, &v),
            Err(e) => app_err(e),
        };
    }

    problem(ScCode::NotFound, "Not found")
}

/// Gate a request on the agent Bearer key (§8): the same membership check the
/// control plane uses, via the pure `check_token`. On a miss with a key
/// PRESENT, one debounced hash refresh (a just-minted `sc agent add` key must
/// not 401 for the 30s sync loop), then re-check. `Err` carries the ready 401.
async fn require_key(state: &Arc<AppState>, headers: &HeaderMap) -> Result<(), Response<Body>> {
    let token = bearer_token(headers);
    if key_in_set(state, token.as_deref()) {
        return Ok(());
    }
    if token.is_some()
        && crate::sync::refresh_agent_keys_on_miss(state).await
        && key_in_set(state, token.as_deref())
    {
        return Ok(());
    }
    Err(problem(
        ScCode::Unauthorized,
        "missing or invalid agent api key",
    ))
}

fn key_in_set(state: &AppState, token: Option<&str>) -> bool {
    let hashes = state.agent_key_hashes.lock().unwrap();
    crate::api_key::check_token(&hashes, token).is_ok()
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
        .map(|s| s.to_string())
}

/// `GET /ca` — the resident CA PEM (public cert; the agent trusts it ADDITIVELY
/// for its self-construct client, mitmproxy `mitm.it`-style). Unauthenticated:
/// a public certificate, and served over plain localhost HTTP so there's no
/// chicken-and-egg. Read from THIS daemon's state dir (where `ca::load_or_generate`
/// wrote it).
fn ca_pem(state: &AppState) -> Response<Body> {
    let path = state.config.state_dir.join("ca.pem");
    match std::fs::read(&path) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/x-pem-file")
            .body(Body::from(bytes))
            .unwrap_or_else(|_| plain_500()),
        Err(e) => {
            tracing::warn!("api_face: read {} failed: {}", path.display(), e);
            problem(ScCode::CaUnavailable, "resident CA unreadable")
        }
    }
}

fn app_err(e: crate::error::AppError) -> Response<Body> {
    let (code, detail) = e.code();
    problem(code, &detail)
}

/// RFC 9457 rendering for this face — the SAME `problem_body` row the control
/// plane emits, so both ports map an error identically.
fn problem(code: ScCode, detail: &str) -> Response<Body> {
    let status = StatusCode::from_u16(code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_vec(&crate::error::problem_body(code, detail))
        .unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/problem+json")
        .header("x-safeclaw-error", code.as_str())
        .body(Body::from(body))
        .unwrap_or_else(|_| plain_500())
}

/// `/op/{id}` poll response — the shared `op_poll_value` body PLUS the same
/// `Retry-After` pacing hint the control-plane poll sets on a pending op, so the
/// agent (which polls THIS API face at the absolute poll_url, §9) keeps the
/// standard cadence and the two faces stay byte-for-byte identical.
fn op_poll_response(v: &Value) -> Response<Body> {
    let pending = v.get("status").and_then(|s| s.as_str()) == Some("pending");
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec());
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json");
    if pending {
        b = b.header(
            header::RETRY_AFTER,
            crate::approval::store::POLL_INTERVAL_HINT_SECS.to_string(),
        );
    }
    b.body(Body::from(body)).unwrap_or_else(|_| plain_500())
}

fn json(status: StatusCode, v: &Value) -> Response<Body> {
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| plain_500())
}

fn plain_500() -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from("{}"))
        .expect("static response builds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_authority_requires_exact_proxy_port() {
        assert!(is_self_authority("127.0.0.1", Some(23294), 23294));
        assert!(is_self_authority("localhost", Some(23294), 23294));
        assert!(is_self_authority("::1", Some(23294), 23294));
        // A different port is a real localhost upstream, not a loop.
        assert!(!is_self_authority("127.0.0.1", Some(3000), 23294));
        // A missing port is not our exact authority either.
        assert!(!is_self_authority("127.0.0.1", None, 23294));
        // A non-loopback host is always a proxy target.
        assert!(!is_self_authority("api.github.com", Some(23294), 23294));
    }

    #[test]
    fn origin_form_is_api_face_absolute_upstream_is_not() {
        // Origin-form (no authority) → the API face.
        let origin = Request::builder()
            .uri("/v/abc/registry")
            .body(Body::empty())
            .unwrap();
        assert!(is_api_face(&origin, 23294));

        // Absolute-form to a real upstream → NOT the API face (a proxy request).
        let upstream = Request::builder()
            .uri("http://api.github.com/x")
            .body(Body::empty())
            .unwrap();
        assert!(!is_api_face(&upstream, 23294));

        // Absolute-form looped back at our own authority → the API face (guard).
        let loop_back = Request::builder()
            .uri("http://127.0.0.1:23294/health")
            .body(Body::empty())
            .unwrap();
        assert!(is_api_face(&loop_back, 23294));
    }
}
