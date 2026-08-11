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
    // The exact origin-form target on the wire (path + any query) — the hop-A PoP
    // binds THIS string (`apiface:<pq>`), so the shim signs the same request-line
    // target it sends and a token can't be lifted to another api-face path.
    let pq = req
        .uri()
        .path_and_query()
        .map(|x| x.as_str().to_string())
        .unwrap_or_else(|| path.clone());

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
        let caller = match require_agent(state, req.headers(), &pq).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        // Op-agent binding (team §C1): an agent-created op is pollable only by
        // the agent that triggered it — a different (still valid) agent gets the
        // same shape as an unknown op, so this face leaks nothing about other
        // agents' pending work. Ops with no agent stamp (ceremonies) stay
        // reachable by any valid agent, matching today's user-surface semantics.
        // `caller` is the resolved attribution (hop-A `ag_` or legacy key prefix),
        // the SAME id the proxy path stamped on the op at creation — so the two
        // faces compare like-for-like across the dual-auth window.
        {
            let bound = state
                .approvals
                .lock()
                .unwrap()
                .get(op_id)
                .and_then(|r| r.agent_prefix.clone());
            if let Some(expected) = bound {
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
    // GET /vaults — the agent's vault index (team §A/§7.7): every vault this
    // daemon holds, with lock state and a per-vault connection summary the
    // caller's reach mask has already been applied to. EXISTS ONLY ON THIS
    // AUTHED AGENT FACE — the control plane deliberately never exposes a
    // vault index (see registry.rs's no-vault_id note). The vid in each entry
    // is the address the agent puts on the wire (proxy auth / URL); item
    // names stay bare and resolve inside the chosen vault.
    if path == "/vaults" {
        let agent = match require_agent(state, req.headers(), &pq).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let mut vaults: Vec<Value> = Vec::new();
        let ids = state.vaults.list().unwrap_or_default();
        for vid in ids {
            let locked = state.is_vault_locked(&vid);
            let mut conns: Vec<Value> = Vec::new();
            if !locked {
                let snapshot = state.connections_snapshot(&vid);
                let candidates: Vec<String> = snapshot.iter().map(|(id, _)| id.clone()).collect();
                let allowed = state.agent_allowed_connections(&vid, &agent, &candidates);
                let allow: Option<std::collections::HashSet<String>> =
                    allowed.map(|w| w.into_iter().collect());
                for (id, conn) in snapshot {
                    let masked = allow.as_ref().map(|a| !a.contains(&id)).unwrap_or(false);
                    let mut row = json!({ "id": id, "service": conn.service });
                    if masked {
                        row["locked"] = Value::Bool(true);
                    }
                    conns.push(row);
                }
                conns.sort_by(|a, b| {
                    a["id"].as_str().unwrap_or("").cmp(b["id"].as_str().unwrap_or(""))
                });
            }
            vaults.push(json!({
                "vid": vid,
                "locked": locked,
                "connections": conns,
            }));
        }
        return json(StatusCode::OK, &json!({ "vaults": vaults }));
    }
    if let Some(vid) = path
        .strip_prefix("/v/")
        .and_then(|r| r.strip_suffix("/registry"))
    {
        let agent = match require_agent(state, req.headers(), &pq).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let q = crate::server::handlers::registry::RegistryQuery::from_query_str(
            req.uri().query().unwrap_or(""),
        );
        // Agent surface: annotate reach-masked connections as locked stubs, keyed
        // by the resolved attribution (hop-A `ag_` or legacy key prefix).
        return match crate::server::handlers::registry::vault_registry_value(
            state,
            vid,
            &q,
            Some(agent.as_str()),
        ) {
            Ok(v) => json(StatusCode::OK, &v),
            Err(e) => app_err(e),
        };
    }

    problem(ScCode::NotFound, "Not found")
}

/// Gate an api-face request and resolve the caller's attribution (§8). Dual-auth:
///
/// - **hop-A AIK PoP** — a `scpop1…` token in the Bearer slot (the `sc` transport
///   holds the AIK and mints it, keeping the key out of the child env). Crypto-
///   verified against the request-line target (`apiface:<pq>`, account-scoped
///   `vault=""`; the api-face is account-scoped, exactly like the legacy shared
///   key hash-set), then authorized by `ag_` ∈ ANY unlocked vault's authorized-
///   agents table. A `scpop1…` that doesn't verify/authorize is a 401 — it's not
///   an api-key, so there's nothing to fall back to. Returns the resolved `ag_`.
/// - **legacy Bearer api-key** — the same membership check the control plane uses
///   via the pure `check_token`. On a miss with a key PRESENT, one debounced hash
///   refresh (a just-minted `sc agent add` key must not 401 for the 30s sync
///   loop), then re-check. Returns the key prefix (never the full key).
///
/// The returned id is the SAME attribution the proxy path stamps
/// (`BrokerHandler::agent_attribution`), so op-binding, reach masks, and registry
/// annotation agree across both faces. `Err` carries the ready 401.
async fn require_agent(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    pq: &str,
) -> Result<String, Response<Body>> {
    let token = bearer_token(headers);
    // hop-A: an AIK PoP in the Bearer slot (`scpop1.…`) is unambiguous vs. an
    // `sc_…` api-key — verify + authorize here; on failure it's a hard 401 (a
    // PoP string is never a hash-set member, so no api-key fallback applies).
    if let Some(tok) = token.as_deref() {
        if tok.starts_with(&format!("{}.", crate::agent_pop::TOKEN_PREFIX)) {
            let target = crate::agent_pop::apiface_target(pq);
            let ag = crate::agent_pop::verify_agent_proxy_pop(
                tok,
                "",
                &target,
                crate::util::now_unix(),
                crate::agent_pop::DEFAULT_MAX_SKEW_SECS,
            )
            .filter(|ag| state.agent_is_authorized_any(ag));
            return ag.ok_or_else(|| {
                problem(ScCode::Unauthorized, "missing or invalid agent api key")
            });
        }
    }
    // Legacy Bearer api-key (dual-auth) — unchanged, incl. the debounced refresh.
    if key_in_set(state, token.as_deref()) {
        return Ok(legacy_attribution(token.as_deref()));
    }
    if token.is_some()
        && crate::sync::refresh_agent_keys_on_miss(state).await
        && key_in_set(state, token.as_deref())
    {
        return Ok(legacy_attribution(token.as_deref()));
    }
    Err(problem(
        ScCode::Unauthorized,
        "missing or invalid agent api key",
    ))
}

/// The legacy attribution id for a Bearer api-key: its prefix (never the full
/// key/token), matching the proxy path's `legacy_key_prefix`.
fn legacy_attribution(token: Option<&str>) -> String {
    token.map(crate::audit::agent_key_prefix).unwrap_or_default()
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
