use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// THE error-code registry — every error SafeClaw raises on any surface
/// (control-plane JSON, proxy text plane, CLI stderr) names exactly one of
/// these. Codes are snake_case and self-describing (an agent never needs a
/// lookup table); `docs/reference/diagnostics.md` is this enum's rendered table and must
/// change in the same commit. Status/action/cause are pure functions of the
/// code so every surface maps an error identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScCode {
    // ── control plane / API face ─────────────────────────────────────────
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict,
    VaultLocked,
    RateLimited,
    Internal,
    CaUnavailable,
    // ── proxy plane (credential pipeline) ────────────────────────────────
    AgentKey,
    AmbiguousPhantom,
    ApprovalNeeded,
    ApprovalRegister,
    BrokerBodyLimit,
    EgressUnreachable,
    ExposesUnsupported,
    HostForbidden,
    /// A team reach mask excludes this connection for the calling agent
    /// (team §8.1: visible-but-locked — the connection exists, this agent
    /// is not enabled for it; the responsible member can enable it).
    MaskNotEnabled,
    HostNotAnchored,
    MultiConnection,
    NoVault,
    OauthMint,
    PhantomPlainHttp,
    PolicyDenied,
    RefreshForbidden,
    SecretEncoding,
    StoreUnavailable,
    UnknownConnection,
    UpstreamBody,
    UpstreamError,
}

impl ScCode {
    /// `(status, code, title, action, cause)` — the single row this code owns.
    ///
    /// `action` is what the AGENT should do next: `unlock` (have the user
    /// unlock), `approve` (follow the approve URL in the body), `retry`,
    /// `configure` (a machine/daemon knob, the message names it),
    /// `fix_request` (the request itself is wrong), `none` (explicit refusal —
    /// don't work around it, per P2).
    ///
    /// `cause` attributes the failure: `request`, `auth`, `vault`, `policy`,
    /// `config`, `environment` (this machine's network, NOT SafeClaw),
    /// `upstream` (the service side, NOT SafeClaw), `internal`.
    pub fn row(&self) -> (u16, &'static str, &'static str, &'static str, &'static str) {
        use ScCode::*;
        match self {
            BadRequest => (400, "bad_request", "Bad request", "fix_request", "request"),
            Unauthorized => (401, "unauthorized", "Unauthorized", "configure", "auth"),
            Forbidden => (403, "forbidden", "Forbidden", "none", "auth"),
            NotFound => (404, "not_found", "Not found", "fix_request", "request"),
            MethodNotAllowed => (
                405,
                "method_not_allowed",
                "Method not allowed",
                "fix_request",
                "request",
            ),
            Conflict => (409, "conflict", "Conflict", "fix_request", "request"),
            VaultLocked => (423, "vault_locked", "Vault locked", "unlock", "vault"),
            RateLimited => (429, "rate_limited", "Rate limited", "retry", "request"),
            Internal => (500, "internal", "Internal error", "retry", "internal"),
            CaUnavailable => (500, "ca_unavailable", "CA unavailable", "retry", "internal"),
            AgentKey => (407, "agent_key", "Agent key invalid", "configure", "auth"),
            AmbiguousPhantom => (
                400,
                "ambiguous_phantom",
                "Ambiguous phantom",
                "fix_request",
                "request",
            ),
            ApprovalNeeded => (
                401,
                "approval_needed",
                "Approval needed",
                "approve",
                "policy",
            ),
            ApprovalRegister => (
                503,
                "approval_register",
                "Approval registration failed",
                "retry",
                "internal",
            ),
            BrokerBodyLimit => (
                413,
                "broker_body_limit",
                "Body over broker cap",
                "configure",
                "config",
            ),
            EgressUnreachable => (
                502,
                "egress_unreachable",
                "Egress unreachable",
                "configure",
                "environment",
            ),
            ExposesUnsupported => (
                400,
                "exposes_unsupported",
                "Role not mintable",
                "fix_request",
                "request",
            ),
            HostForbidden => (403, "host_forbidden", "Host forbidden", "none", "policy"),
            MaskNotEnabled => (
                403,
                "mask_not_enabled",
                "Connection not enabled for this agent",
                "none",
                "policy",
            ),
            HostNotAnchored => (
                403,
                "host_not_anchored",
                "Host not anchored",
                "approve",
                "policy",
            ),
            MultiConnection => (
                400,
                "multi_connection",
                "Multiple connections in one request",
                "fix_request",
                "request",
            ),
            NoVault => (403, "no_vault", "No vault bound", "configure", "config"),
            OauthMint => (502, "oauth_mint", "OAuth mint failed", "retry", "upstream"),
            PhantomPlainHttp => (
                400,
                "phantom_plain_http",
                "Phantom over plain HTTP",
                "fix_request",
                "request",
            ),
            PolicyDenied => (403, "policy_denied", "Denied by policy", "none", "policy"),
            RefreshForbidden => (
                403,
                "refresh_forbidden",
                "Refresh token never leaves the vault",
                "fix_request",
                "policy",
            ),
            SecretEncoding => (
                500,
                "secret_encoding",
                "Credential encoding error",
                "none",
                "internal",
            ),
            StoreUnavailable => (
                502,
                "store_unavailable",
                "External store unavailable",
                "retry",
                "upstream",
            ),
            UnknownConnection => (
                400,
                "unknown_connection",
                "Unknown connection",
                "fix_request",
                "request",
            ),
            UpstreamBody => (
                502,
                "upstream_body",
                "Body read failed",
                "retry",
                "upstream",
            ),
            UpstreamError => (
                502,
                "upstream_error",
                "Upstream request failed",
                "retry",
                "upstream",
            ),
        }
    }

    pub fn status(&self) -> u16 {
        self.row().0
    }

    pub fn as_str(&self) -> &'static str {
        self.row().1
    }
}

/// The ONE canonical remediation line for a locked vault — every surface
/// (control 423, proxy 423, CLI) says exactly this, so the agent sees one
/// consistent state and relays one consistent fix.
pub const VAULT_LOCKED_MSG: &str = "vault locked — run `sc up` to unlock, then retry";

/// RFC 9457 `application/problem+json` body for a code + detail message.
/// Extension members: `code` / `action` / `cause` (see [`ScCode::row`]),
/// plus legacy `error` / `message` dual-emitted for one transition window
/// (console + older CLIs parse those; remove after both are migrated).
pub fn problem_body(code: ScCode, detail: &str) -> serde_json::Value {
    let (status, code_s, title, action, cause) = code.row();
    json!({
        "type": format!("https://safeclaw.pro/errors/{}", code_s),
        "title": title,
        "status": status,
        "detail": detail,
        "code": code_s,
        "action": action,
        "cause": cause,
        // legacy shape (pre-9457) — dual-emit, do not add new readers
        "error": code_s,
        "message": detail,
    })
}

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound,
    Conflict(String),
    /// Vault is locked (no in-memory key). Distinct from `Conflict` so the agent
    /// can tell "unlock needed → run `sc up`" apart from other 409s. HTTP 423.
    VaultLocked,
    TooManyRequests,
    Internal(String),
}

impl AppError {
    /// The registry code + detail this error projects to. Shared by the axum
    /// `IntoResponse` below AND the hudsucker 23294 API face
    /// (`proxy::api_face`), so both ports map an error identically.
    pub fn code(&self) -> (ScCode, String) {
        match self {
            AppError::BadRequest(msg) => (ScCode::BadRequest, msg.clone()),
            AppError::Unauthorized(msg) => (ScCode::Unauthorized, msg.clone()),
            AppError::Forbidden(msg) => (ScCode::Forbidden, msg.clone()),
            AppError::NotFound => (ScCode::NotFound, "Not found".to_string()),
            AppError::Conflict(msg) => (ScCode::Conflict, msg.clone()),
            AppError::VaultLocked => (ScCode::VaultLocked, VAULT_LOCKED_MSG.to_string()),
            AppError::TooManyRequests => (ScCode::RateLimited, "Rate limit exceeded".to_string()),
            AppError::Internal(msg) => {
                tracing::error!("internal error: {}", msg);
                (ScCode::Internal, "Internal server error".to_string())
            }
        }
    }

    /// `(http status u16, machine code, human message)` — legacy projection,
    /// kept for callers that only need the tuple.
    pub fn parts(&self) -> (u16, &'static str, String) {
        let (code, detail) = self.code();
        (code.status(), code.as_str(), detail)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, detail) = self.code();
        let status =
            StatusCode::from_u16(code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut res = (status, Json(problem_body(code, &detail))).into_response();
        res.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );
        res
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            AppError::NotFound => write!(f, "Not found"),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::VaultLocked => write!(f, "Vault locked"),
            AppError::TooManyRequests => write!(f, "Rate limit exceeded"),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Internal(format!("IO error: {}", e))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Internal(format!("JSON error: {}", e))
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(e: base64::DecodeError) -> Self {
        AppError::BadRequest(format!("Base64 decode error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registry row must be internally consistent: a real HTTP status,
    /// a snake_case code, and a status that matches what `AppError` variants
    /// project (the two surfaces must never disagree on a code's status).
    #[test]
    fn registry_rows_are_consistent() {
        use ScCode::*;
        let all = [
            BadRequest,
            Unauthorized,
            Forbidden,
            NotFound,
            MethodNotAllowed,
            Conflict,
            VaultLocked,
            RateLimited,
            Internal,
            CaUnavailable,
            AgentKey,
            AmbiguousPhantom,
            ApprovalNeeded,
            ApprovalRegister,
            BrokerBodyLimit,
            EgressUnreachable,
            ExposesUnsupported,
            HostForbidden,
            HostNotAnchored,
            MultiConnection,
            NoVault,
            OauthMint,
            PhantomPlainHttp,
            PolicyDenied,
            RefreshForbidden,
            SecretEncoding,
            StoreUnavailable,
            UnknownConnection,
            UpstreamBody,
            UpstreamError,
        ];
        for c in all {
            let (status, code, title, action, cause) = c.row();
            assert!((400..=599).contains(&status), "{code}: status {status}");
            assert!(
                code.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "{code}: not snake_case"
            );
            assert!(!title.is_empty());
            assert!(
                [
                    "unlock",
                    "approve",
                    "retry",
                    "configure",
                    "fix_request",
                    "none"
                ]
                .contains(&action),
                "{code}: unknown action {action}"
            );
            assert!(
                [
                    "request",
                    "auth",
                    "vault",
                    "policy",
                    "config",
                    "environment",
                    "upstream",
                    "internal"
                ]
                .contains(&cause),
                "{code}: unknown cause {cause}"
            );
        }
    }

    /// problem_body carries both the 9457 members and the legacy dual-emit.
    #[test]
    fn problem_body_dual_emits() {
        let b = problem_body(ScCode::VaultLocked, VAULT_LOCKED_MSG);
        assert_eq!(b["code"], "vault_locked");
        assert_eq!(b["error"], "vault_locked");
        assert_eq!(b["status"], 423);
        assert_eq!(b["detail"], b["message"]);
        assert_eq!(b["type"], "https://safeclaw.pro/errors/vault_locked");
        assert_eq!(b["action"], "unlock");
    }
}
