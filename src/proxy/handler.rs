//! The resident proxy's request handler: the whole brokered pipeline.
//!
//! One `BrokerHandler` is cloned per TCP connection. On a CONNECT it captures
//! the vault id from `Proxy-Authorization` and decides MITM-vs-blind-tunnel by
//! whether the destination host is anchored by any known vault's connection
//! (unlocked live, or a locked vault's last-known anchors — so a phantom sent
//! while locked gets an explicit `vault_locked` instead of a blind tunnel).
//! For each intercepted inner request it: finds phantoms, resolves them to ONE
//! connection, enforces the host anchor, evaluates policy, substitutes the real
//! credential at egress, strips the agent's own/proxy auth, and forwards. A
//! request with no phantom is forwarded untouched — the phantom is the only
//! injection trigger.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use http_body_util::BodyExt;
use hudsucker::hyper::{header, HeaderMap, Method, Request, Response, StatusCode, Uri};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use serde_json::json;

use crate::error::ScCode;
use crate::proxy::resolver::{self, Phantom};
use crate::state::AppState;

/// The last-resort `ask`-once window when neither the matched rule nor any
/// floor (`default.ttl`) pins one — the "Ask once" grant lasts this long after
/// approval. Kept in sync with the console's shown default (15 min).
const DEFAULT_ASK_TTL: u64 = 900;

/// What `handle_response` needs to write the terminal audit row after the
/// upstream answers a forwarded (allow) request.
#[derive(Clone)]
pub struct AuditPending {
    pub vault_id: String,
    pub service: String,
    pub method: String,
    pub path: String,
    /// Agent attribution for the audit row: prefix of the CONNECT-authenticated
    /// agent api-key (see `audit::agent_key_prefix`). Never the full key.
    pub agent_prefix: Option<String>,
}

#[derive(Clone)]
pub struct BrokerHandler {
    pub state: Arc<AppState>,
    /// Vault id captured from the CONNECT's `Proxy-Authorization` username,
    /// inherited by every inner-request clone of this handler.
    pub vid: Option<String>,
    /// Agent api-key captured from the CONNECT's `Proxy-Authorization` PASSWORD
    /// (§8) — the agent's identity, verified in `pipeline` before any phantom
    /// substitution. Inherited by inner-request clones alongside `vid`.
    pub key: Option<String>,
    /// The `ag_…` id of a CRYPTO-VERIFIED agent PoP token (hop-A), resolved at
    /// CONNECT time in `should_intercept` (that's where the CONNECT authority the
    /// token binds is available) and inherited by inner-request clones. `Some`
    /// only when the `Proxy-Authorization` password was a valid, fresh `scpop1…`
    /// token for this vault+target; `None` for the legacy Basic api-key path. The
    /// authorization check (this `ag_` ∈ the vault's authorized-agents table) is
    /// still done in `pipeline` — this field is only "who proved possession".
    pub agent_id: Option<String>,
    /// Set on the allow/forward path; consumed by `handle_response`.
    pub pending: Option<AuditPending>,
}

impl BrokerHandler {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            vid: None,
            key: None,
            agent_id: None,
            pending: None,
        }
    }
}

impl HttpHandler for BrokerHandler {
    async fn should_intercept(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        // The agent's (vid, api-key) ride the CONNECT's Proxy-Authorization
        // userinfo (`base64("<vid>:<key>")`); capture both so inner-request clones
        // inherit them (read-only). The key is VERIFIED later in `pipeline`,
        // before any substitution — here we only need vid PRESENCE.
        let (vid, key) = creds_from_proxy_auth(req);
        self.vid = vid;
        self.key = key;
        // hop-A: if the Proxy-Auth password is an agent PoP token (`scpop1…`),
        // crypto-verify it HERE — the CONNECT authority it binds (`host:port`) is
        // only available at CONNECT time (the inner-request pipeline sees a bare
        // host). A valid, fresh token for THIS vault + target resolves the `ag_`
        // id; the authorization check (`ag_` ∈ the vault's authorized-agents
        // table) happens in `pipeline`. Dual-auth: a non-PoP password (a legacy
        // Basic api-key) leaves `agent_id` None and takes the hash-set path, so
        // nothing bricks. Only the crypto (signature + freshness) is checked here.
        self.agent_id = match (self.vid.as_deref(), self.key.as_deref(), req.uri().authority()) {
            (Some(vid), Some(key), Some(authority)) => crate::agent_pop::verify_agent_proxy_pop(
                key,
                vid,
                authority.as_str(),
                crate::util::now_unix(),
                crate::agent_pop::DEFAULT_MAX_SKEW_SECS,
            ),
            _ => None,
        };
        // Absent Proxy-Auth (no vid) → non-participating traffic: blind-tunnel it
        // (§8; a stray phantom then reaches upstream literally → clean 401, never
        // a leak). A creds-less CONNECT to a host we DO anchor was already met
        // with a 407 in handle_request (RFC 7235 challenge), so anything absent
        // reaching here targets a host no known vault anchors. Only a request
        // that NAMES a vault and targets an anchored host is a MITM candidate —
        // the precise per-vault anchor + the key check happen in `pipeline`.
        if self.vid.is_none() {
            return false;
        }
        match req.uri().host() {
            Some(h) => self.state.host_in_any_known_union(h),
            None => false,
        }
    }

    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        // A CONNECT normally passes straight through to process_connect, which
        // returns `200 Connection established` and then lets should_intercept
        // read the CONNECT's Proxy-Authorization to decide MITM-vs-tunnel.
        //
        // But not every client sends proxy credentials preemptively. The RFC 7235
        // convention is to send an unauthenticated request first and only repeat
        // it WITH credentials after a `407 Proxy Authentication Required`
        // challenge. Debian/Ubuntu git (libcurl-gnutls) does exactly this — the
        // whole system-git population; curl, wget and python were measured
        // sending creds preemptively, so they were never affected. A challenge-
        // first client's creds-less CONNECT has no vid, so today it gets
        // blind-tunneled — the phantom is never substituted and reaches the
        // upstream literally (a clean 401, but the credential path silently never
        // engages). Answer it with a 407 so it re-sends authenticated. Scope the
        // challenge to a host some known vault anchors: unrelated traffic still
        // tunnels untouched, preserving "only routed traffic is touched".
        if req.method() == Method::CONNECT {
            let (vid, _) = creds_from_proxy_auth(&req);
            if vid.is_none() {
                if let Some(h) = req.uri().host() {
                    if self.state.host_in_any_known_union(h) {
                        return proxy_auth_challenge().into();
                    }
                }
            }
            return req.into();
        }

        // API face (CREDENTIAL_BROKER.md §14): an origin-form request (or an absolute-form
        // one looped back at our own authority) is discovery / op-poll / health /
        // ca — self-answered read-only here, never forwarded upstream. This is the
        // agent's ONE port: the same listener serves the proxy face (below) and
        // this read API.
        if crate::proxy::api_face::is_api_face(&req, self.state.config.proxy_port) {
            return crate::proxy::api_face::respond(&self.state, &req)
                .await
                .into();
        }

        self.pipeline(ctx, req).await
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        if let Some(p) = self.pending.take() {
            write_forward_audit(&self.state, &p, res.status().as_u16());
        }
        res
    }

    /// A forward-hop to the upstream failed (couldn't connect, egress proxy
    /// refused/dropped the CONNECT, TLS to the origin failed, …). hudsucker's
    /// DEFAULT for this is an EMPTY `502` — which is the worst possible signal
    /// for the audience here: an AI agent making a brokered call gets a blank
    /// body and can't tell a NETWORK/PROXY problem from a dead credential or a
    /// provider outage, so it typically misreports "the token is broken." The
    /// precise cause our `TunnelConnector` already computed (host:port + whether
    /// it was a direct dial or a proxy CONNECT) otherwise reaches only the daemon
    /// log. Surface it on the wire instead, tagged `egress_unreachable`, and — for
    /// a reachability failure — say how to point us at a proxy.
    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        err: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        egress_error_response(err)
    }
}

impl BrokerHandler {
    /// Is the captured agent key (CONNECT Proxy-Auth password) a member of the
    /// synced hash-set (§8)? The proxy authenticates the AGENT — not "localhost"
    /// — before injecting any credential. Same membership check the control
    /// plane + API face use, via the pure `check_token`.
    fn key_is_valid(&self) -> bool {
        // hop-A path: a crypto-verified agent PoP (resolved in `should_intercept`)
        // is valid iff its `ag_` is in THIS vault's authorized-agents table
        // (§11 presence = authorized). Dual-auth: if there's no PoP, or it isn't
        // authorized for this vault, fall back to the legacy synced api-key
        // hash-set — so a legacy Basic api-key keeps working unchanged.
        if let (Some(ag), Some(vid)) = (self.agent_id.as_deref(), self.vid.as_deref()) {
            if self.state.agent_is_authorized(vid, ag) {
                return true;
            }
        }
        let hashes = self.state.agent_key_hashes.lock().unwrap();
        crate::api_key::check_token(&hashes, self.key.as_deref()).is_ok()
    }

    /// Stable attribution id for the current agent — used for audit rows, the
    /// mask lookup, and the grant cache key. For a hop-A PoP agent it's the
    /// resolved `ag_` (so approvals cache + replay correctly, and mask is
    /// ag_-keyed per §11); for the legacy Basic path it's the api-key prefix
    /// (never the full key/token). One helper so all three surfaces agree.
    fn agent_attribution(&self) -> Option<String> {
        self.agent_id
            .clone()
            .or_else(|| legacy_key_prefix(self.key.as_deref()))
    }

    async fn pipeline(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let is_https = req.uri().scheme_str() == Some("https");
        let dest_host = match req.uri().host() {
            Some(h) => h.to_ascii_lowercase(),
            None => return req.into(), // origin-form / no authority: not ours
        };
        let ip = ctx.client_addr.ip();

        let (parts, body) = req.into_parts();
        // `orig_body` is the un-scanned streaming body; `body_bytes` is the
        // buffered copy when we scan. Exactly one is live past the scan below,
        // so both consumers `take()` from the Option.
        let mut orig_body = Some(body);
        let method = parts.method.as_str().to_string();
        let path = parts.uri.path().to_string();
        let pq = parts
            .uri
            .path_and_query()
            .map(|x| x.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        // ── gather phantom-bearing scan sites ────────────────────────────────
        let mut phantoms: Vec<Phantom> = Vec::new();
        merge_phantoms(&mut phantoms, resolver::collect_phantoms(&pq));
        for value in parts.headers.values() {
            if let Ok(s) = value.to_str() {
                merge_phantoms(&mut phantoms, resolver::collect_phantoms(s));
            }
        }
        // Authorization: Basic <b64> — decode before matching.
        if let Some(decoded) = basic_auth_decoded(&parts.headers) {
            merge_phantoms(&mut phantoms, resolver::collect_phantoms(&decoded));
        }

        // ── unified body boundary (P1) ───────────────────────────────────────
        // Policy judgment and phantom resolution consume ONE buffered view of
        // the body, produced right here — never two boundaries. A request that
        // names a phantom in its URL/headers is brokered, so its body MUST fit
        // the cap for policy to see it: over-cap is a hard, explained refusal
        // (413) — never a policy-blind forward with a live credential, and
        // never an approval prompt over content the user can't read (P2).
        // Content-Type takes no part in this decision (it's caller-controlled);
        // for phantom-less requests it stays a cheap heuristic for whether a
        // body-only phantom is worth looking for — an unscanned body-only
        // phantom just reaches upstream literally (a clean 401, the documented
        // semantic).
        let cap = self.state.config.body_cap;
        let header_phantoms = !phantoms.is_empty();
        if header_phantoms {
            // A declared over-cap length is refused before reading a byte.
            if let Some(n) = content_length(&parts.headers) {
                if n > cap {
                    return body_over_cap(n, cap).into();
                }
            }
        }
        let scan_body = header_phantoms
            || (body_is_text(&parts.headers)
                && content_length(&parts.headers)
                    .map(|n| n <= cap)
                    .unwrap_or(false));

        let mut body_bytes: Option<Vec<u8>> = None;
        if scan_body {
            // `Limited` enforces the cap even without a Content-Length
            // (chunked transfer) — the declared-length check above is only the
            // cheap early exit.
            let limited = http_body_util::Limited::new(
                orig_body.take().expect("body present before scan"),
                cap as usize,
            );
            match limited.collect().await {
                Ok(collected) => body_bytes = Some(collected.to_bytes().to_vec()),
                Err(e)
                    if e.downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some() =>
                {
                    return body_over_cap(0, cap).into();
                }
                Err(e) => {
                    tracing::warn!("proxy: body collect failed: {}", e);
                    return err_response(ScCode::UpstreamBody, "failed to read request body")
                        .into();
                }
            }
        }
        // One lossy view serves BOTH the phantom scan and policy below, so a
        // binary(ish) body is not a blind spot: rules evaluate against what is
        // actually there. Forwarding still uses the untouched raw bytes.
        let body_text: Option<String> = body_bytes
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned());
        if let Some(s) = body_text.as_deref() {
            merge_phantoms(&mut phantoms, resolver::collect_phantoms(s));
        }

        // No phantom anywhere → forward untouched (rebuild body if we buffered).
        if phantoms.is_empty() {
            // We only reach here for an intercepted request — the host is anchored
            // by some unlocked connection — that named no phantom. Most often the
            // caller simply forgot it; left untouched the request goes upstream
            // unauthenticated and the puzzling result is a bare 401/403 with no
            // hint that the credential was never in the request. Leave a greppable
            // breadcrumb (`sc logs --raw | grep phantom`) for exactly that debug.
            tracing::debug!(
                host = %dest_host,
                "routed to an anchored host but the request carries no phantom — \
                 forwarded unauthenticated; include the connection's phantom \
                 (e.g. __sc__<conn>__) if brokering was intended"
            );
            let body = body_bytes
                .map(Body::from)
                .unwrap_or_else(|| orig_body.take().unwrap_or_else(Body::empty));
            return Request::from_parts(parts, body).into();
        }

        // A phantom over plain HTTP can't be TLS-substituted — refuse.
        if !is_https {
            return err_response(
                ScCode::PhantomPlainHttp,
                "a phantom requires HTTPS (the proxy only substitutes inside TLS)",
            )
            .into();
        }

        // ── one connection per request ───────────────────────────────────────
        let mut conns: Vec<&str> = phantoms.iter().map(|p| p.conn.as_str()).collect();
        conns.sort_unstable();
        conns.dedup();
        if conns.len() != 1 {
            return err_response(
                ScCode::MultiConnection,
                &format!(
                    "one connection per request — this request names {}",
                    conns.join(", ")
                ),
            )
            .into();
        }
        let conn = conns[0].to_string();

        // ── verify the agent key, then bind the vault (§8) ───────────────────
        // A phantom-bearing request MUST present a valid agent api-key: the proxy
        // is the credential injector and localhost is NOT a trust boundary, so
        // verify the AGENT's identity BEFORE resolving/substituting. The key rode
        // the CONNECT's Proxy-Auth password; `should_intercept` already
        // blind-tunnels absent-auth, so reaching here means Proxy-Auth was present
        // — a bad/missing key is an explicit 407, never a silent fallback. On a
        // miss with a key PRESENT, refresh the hash-set once (debounced): a key
        // minted seconds ago by `sc agent add` must not 407 for the 30s loop.
        if !self.key_is_valid() {
            let refreshed =
                self.key.is_some() && crate::sync::refresh_agent_keys_on_miss(&self.state).await;
            if !refreshed || !self.key_is_valid() {
                return err_response(
                    ScCode::AgentKey,
                    "invalid or missing SafeClaw agent api key",
                )
                .into();
            }
        }
        let vault_id = match self.vid.clone() {
            Some(v) => v,
            // Unreachable in practice: `should_intercept` requires a vid to MITM,
            // and a phantom over plain HTTP is refused above. Fail closed rather
            // than guess a vault.
            None => {
                return err_response(
                    ScCode::NoVault,
                    "no vault bound — route credential traffic with `sc run`",
                )
                .into()
            }
        };
        // Daemon too old for this vault's format (cloud returned SC_UPGRADE_REQUIRED
        // for its sync, design 甲) → fail LOUDLY so the agent runs `sc upgrade`,
        // instead of a silent parked-sync mystery the agent works around or calls a bug.
        if self.state.is_vault_upgrade_required(&vault_id) {
            return err_response(
                ScCode::UpgradeRequired,
                "SafeClaw needs an update to use this vault — run `sc upgrade`",
            )
            .into();
        }
        if self.state.is_vault_locked(&vault_id) {
            return err_response(ScCode::VaultLocked, crate::error::VAULT_LOCKED_MSG).into();
        }

        // ── reach mask (team §8.1) ───────────────────────────────────────────
        // Visible-but-locked semantics: a masked-off connection is announced as
        // `locked` in the registry, and a named use gets THIS explicit,
        // actionable refusal — never a silent 404, never a policy prompt.
        {
            // Mask lookup key = the agent's attribution id (resolved `ag_` for a
            // hop-A PoP agent — table+mask are ag_-keyed since §11 — else the
            // legacy api-key prefix for the dual-auth Basic path).
            let mask_agent = self.agent_attribution().unwrap_or_default();
            if self.state.agent_mask_allows(&vault_id, &mask_agent, &conn) == Some(false) {
                return err_response(
                    ScCode::MaskNotEnabled,
                    &format!(
                        "connection '{}' exists in this vault but is not enabled for this agent; \
                         the responsible member can enable it in the console (Agents)",
                        conn
                    ),
                )
                .into();
            }
        }

        // ── team serve gate (shared-vault offline lease, etc.) ───────────────
        // Serve-time team policy is team-EXCLUSIVE (team-edition §9) and lives in
        // the closed `safeclaw-ee` overlay behind this hook. The open build wires
        // `NoopHooks` → no gate, so a personal vault is never leased. The overlay
        // impl reads `vault_is_shared` + `cloud_contact_age_secs` (both kept as
        // neutral core bookkeeping) to enforce the offline lease.
        if let Some(denial) = self.state.team.serve_gate(self.state.as_ref(), &vault_id) {
            return err_response(denial.code, &denial.message).into();
        }

        // ── resolve the connection ───────────────────────────────────────────
        // Resolve the connection record. An explicit aux.connections entry wins;
        // otherwise, if <conn> names a known service (compiled or custom) we
        // synthesize its DEFAULT connection (conn == service, hosts derived from
        // the service) so a default-connection phantom `__sc__<service>__`
        // resolves and the resident default-connection credential — bootstrapped
        // into the cache under the service id — is reachable. Only a genuinely
        // unknown id fails closed.
        let conn_rec = match self.state.connection_snapshot(&vault_id, &conn) {
            Some(rec) => rec,
            None => {
                let known_service = self.state.services.get(&conn).is_some()
                    || self.state.custom_service(&vault_id, &conn).is_some();
                if known_service {
                    crate::storage::plaintext::Connection {
                        name: None,
                        service: Some(conn.clone()),
                        hosts: None,
                        secrets: None,
                        keys: None,
                    }
                } else {
                    return err_response(
                        ScCode::UnknownConnection,
                        &format!("unknown connection '{}'", conn),
                    )
                    .into();
                }
            }
        };
        let def = conn_rec.service.as_deref().and_then(|s| {
            // custom-FIRST precedence (the SSoT for this rule): a vault-authored
            // def (aux.services) shadows a same-id registry service, so shipping
            // a first-party service NEVER silently repoints a user's existing
            // connection (their `gcp` that is really github keeps working). The
            // registry def applies only where no custom def exists — a fresh,
            // opt-in connection, gated by the create-time duplicate-id check.
            self.state
                .custom_service(&vault_id, s)
                .or_else(|| self.state.services.get(s).cloned())
        });
        // Some(input KEY) ⇔ this connection's wire credential is MINTED (oauth2
        // access token, snaplii JWT). The key rides along so the resolver can
        // answer a phantom naming the mint's INPUT secret (refresh token /
        // api key) with the precise refusal (never-injectable), not a generic
        // role error.
        let mint_input = def.as_ref().and_then(|d| d.mint_input_role());
        // The vault role that backs this connection's credential (oauth refresh
        // key, else first declared secret), resolved from the SAME custom-aware
        // `def` above — NOT re-derived registry-only downstream. This is the op
        // `target` a captive-portal (ask) approval resolves + stashes, so a
        // custom `[oauth2]` service (registry miss) still names its real secret
        // instead of falling back to the connection id.
        let op_role = def.as_ref().and_then(|d| d.env_role());
        // The service id policy/mint use; for a raw connection there is none so
        // the conn id stands in (registry lookups miss → global default floor).
        let service_id = conn_rec.service.clone().unwrap_or_else(|| conn.clone());
        // Compute hosts from the record we hold — NOT a second cache lookup,
        // which would miss a synthesized default connection and wrongly empty the
        // anchor (→ spurious widen-deny). For the synthesized default this
        // derives the service's declared hosts.
        let resolved_hosts = crate::core::host::resolved_hosts(&conn_rec, def.as_ref());

        // ── host anchor (exact FQDN, with the private/metadata floor beneath) ─
        if !crate::core::host::host_allowed(&dest_host, &resolved_hosts) {
            if !crate::service::validate::host_egress_allowed(&dest_host) {
                return err_response(
                    ScCode::HostForbidden,
                    &format!(
                        "destination '{}' is not a permitted egress target",
                        dest_host
                    ),
                )
                .into();
            }
            return self.widen_deny(&vault_id, &conn, &dest_host, ip).await;
        }

        // ── request scope (Phase 2, design/request-scope.md) ─────────────────────
        // Resolve the matching `[requests]` shape and extract its vars from the
        // SAME buffered body view (unified boundary) + the URL query. Feeds
        // three consumers: the policy `when` predicate (`vars`), the ask-always
        // grant identity (`scope_digest`), and the approval consent (via
        // `req_scope` → captive_portal). Absent shape ⇒ empty vars + `""` digest
        // = the Phase-1 path-only grant, unchanged.
        let req_scope = def.as_ref().and_then(|d| {
            d.extract_request_scope(&method, &path, parts.uri.query(), body_text.as_deref())
        });
        let vars: crate::core::policy::VarMap = req_scope
            .as_ref()
            .map(|r| r.vars.clone())
            .unwrap_or_default();
        let scope_digest = req_scope.as_ref().map(|r| r.digest()).unwrap_or_default();

        // ── policy ───────────────────────────────────────────────────────────
        // The same lossy view the phantom scan used (unified boundary).
        let body_for_policy = body_text.as_deref();
        // Op-agent binding: every approval/grant surface below keys on the
        // requesting agent (the pipeline validated self.key before secrets).
        let agent_prefix = self.agent_attribution().unwrap_or_default();
        let decision = self.state.evaluate_request_policy(
            &vault_id,
            &agent_prefix,
            &conn,
            &service_id,
            &method,
            &path,
            &dest_host,
            body_for_policy,
            &vars,
            // A declared `[requests]` shape (even with no resolved values) makes
            // this a scoped path: bind per-value via op_grants, never the coarse
            // connection-window downgrade.
            req_scope.is_some(),
        );
        let (level, rule_id, ttl) = match decision {
            Some(d) => d,
            None => {
                return err_response(ScCode::VaultLocked, crate::error::VAULT_LOCKED_MSG).into()
            }
        };

        use crate::core::policy::AccessLevel;
        if level == AccessLevel::Deny {
            write_forward_audit(
                &self.state,
                &AuditPending {
                    vault_id: vault_id.clone(),
                    service: service_id.clone(),
                    method: method.clone(),
                    path: path.clone(),
                    agent_prefix: self.agent_attribution(),
                },
                0,
            );
            return err_response(ScCode::PolicyDenied, "this request is denied by policy").into();
        }

        // The credential bytes come from the session cache (the proxy has no
        // grant to open the vault). A miss falls through to the captive portal.
        //   - Allow: read the resident value (incl. the unlock bootstrap) + the
        //     allow multi-secret map — the frictionless fast-path.
        //   - Ask: GRANT-ONLY. Ignores the allow-level bootstrap
        //     (`cache_lookup_grant` skips `from_bootstrap` entries, and we pass
        //     no `allow_secrets` map) so a per-path ask rule ALWAYS forces a
        //     fresh passkey the first time, even on a connection whose read
        //     floor is `allow` and is therefore resident. A downgraded
        //     (approved-and-cached) Ask arrives here as Allow and reads its
        //     grant via the fast-path above.
        //   - AskAlways: ONE-SHOT, REQUEST-BOUND. Redeems only the grant the
        //     approve ceremony minted for exactly this (connection, method,
        //     host, path) — consumed single-use. It never reads `entries` at
        //     all, so it can't ride the allow residency OR a plain-ask/stale
        //     leftover: an approval is spendable only by the action the user
        //     saw, once.
        let scoped = !scope_digest.is_empty();
        let (primary, secrets_map) = match level {
            // Single-use, request-bound.
            AccessLevel::AskAlways => (
                self.state.op_grant_take(
                    &vault_id,
                    &agent_prefix,
                    &conn,
                    &method,
                    &dest_host,
                    &path,
                    &scope_digest,
                    true,
                ),
                None,
            ),
            // A scoped `ask` is ALSO request-bound (peek/reuse within window),
            // so its consent is never a false promise: a different field value
            // misses and re-prompts. An UNSCOPED ask keeps the Phase-1 conn-keyed
            // grant (the documented "usable but not fully bound" default).
            AccessLevel::Ask if scoped => (
                self.state.op_grant_take(
                    &vault_id,
                    &agent_prefix,
                    &conn,
                    &method,
                    &dest_host,
                    &path,
                    &scope_digest,
                    false,
                ),
                None,
            ),
            AccessLevel::Ask => (
                self.state.cache_lookup_grant(&vault_id, &conn, &agent_prefix),
                None,
            ),
            _ => (
                self.state.cache_lookup(&vault_id, &conn),
                self.state.cache_lookup_secrets(&vault_id, &conn),
            ),
        };

        // First touch of an external-store-backed connection: an Allow-level
        // miss tries ONE lazy fill (fetch into the same `from_bootstrap`
        // residency the unlock bootstrap gives native secrets — see
        // `lazy_fill_external`), then re-reads the cache. A second miss falls
        // through to the portal exactly as before; ask/ask-always never lazy
        // fill (their ceremony resolves through the vault view, store-agnostic
        // already).
        let mut primary = primary;
        let mut secrets_map = secrets_map;
        let mut lazy_filled = false;
        let values = loop {
            match self
                .resolve_values(
                    &vault_id,
                    &conn,
                    &service_id,
                    mint_input.as_deref(),
                    &phantoms,
                    primary.take(),
                    secrets_map.take(),
                )
                .await
            {
                Ok(v) => break v,
                Err(ResolveErr::NeedsApproval) => {
                    if level == AccessLevel::Allow && !lazy_filled {
                        match crate::server::handlers::approve::lazy_fill_external(
                            &self.state,
                            &vault_id,
                            &conn,
                        )
                        .await
                        {
                            Ok(true) => {
                                lazy_filled = true;
                                primary = self.state.cache_lookup(&vault_id, &conn);
                                secrets_map = self.state.cache_lookup_secrets(&vault_id, &conn);
                                continue;
                            }
                            Ok(false) => {}
                            Err(store_id) => {
                                // P2: a configured store's outage is an explicit
                                // refusal, never a portal that would misread it
                                // as "needs approval".
                                return err_response(
                                    ScCode::StoreUnavailable,
                                    &format!(
                                        "external store '{}' failed while resolving this \
                                         connection's secret — check the store's credentials \
                                         and permissions (daemon logs have the full error)",
                                        store_id
                                    ),
                                )
                                .into();
                            }
                        }
                    }
                    return self
                        .captive_portal(
                            &vault_id,
                            &conn,
                            &conn_rec,
                            &service_id,
                            op_role.clone(),
                            &dest_host,
                            &method,
                            &path,
                            level,
                            rule_id,
                            ttl,
                            req_scope.as_ref(),
                            ip,
                        )
                        .await;
                }
                Err(ResolveErr::Ambiguous) => {
                    let roles = phantom_role_hint(&conn, &conn_rec, def.as_ref());
                    return err_response(
                        ScCode::AmbiguousPhantom,
                        &format!(
                            "'{}' exposes several secrets — use a role phantom: {}",
                            conn, roles
                        ),
                    )
                    .into();
                }
                Err(ResolveErr::RefreshForbidden) => {
                    return err_response(
                        ScCode::RefreshForbidden,
                        "a refresh token never leaves the vault — this connection injects a \
                     minted access token (use its default phantom). To reveal the stored \
                     secret, the user runs `sc secret get` (passkey ceremony)",
                    )
                    .into();
                }
                Err(ResolveErr::Exposes(role)) => {
                    return err_response(
                        ScCode::ExposesUnsupported,
                        &format!("connection '{}' role '{}' is not yet mintable", conn, role),
                    )
                    .into();
                }
                Err(ResolveErr::Mint(msg)) => {
                    return err_response(ScCode::OauthMint, &msg).into();
                }
                Err(ResolveErr::NotUtf8) => {
                    return err_response(
                        ScCode::SecretEncoding,
                        "resolved credential is not valid UTF-8",
                    )
                    .into();
                }
            }
        };

        // ── substitute everywhere + strip shadowing auth, then forward ───────
        let mut parts = parts;
        // URL: rebuild the absolute URI with the substituted path+query. The
        // authority (host[:port]) is preserved from the MITM'd request.
        let (new_pq, _) = resolver::substitute(&pq, |ph| values.get(&ph.raw).cloned());
        if new_pq != pq {
            let authority = parts
                .uri
                .authority()
                .map(|a| a.as_str().to_string())
                .unwrap_or_else(|| dest_host.clone());
            if let Ok(u) = format!("https://{}{}", authority, new_pq).parse::<Uri>() {
                parts.uri = u;
            }
        }

        // Headers: substitute values, decode/re-encode Basic, strip proxy/agent
        // auth, drop hop-by-hop; content-length is dropped only if we rewrote
        // the body (hyper re-derives it from the sized body).
        let body_rewritten = body_bytes.is_some();
        let new_headers = rewrite_headers(&parts.headers, &values, body_rewritten);
        parts.headers = new_headers;

        // Body: substitute if we buffered it.
        let out_body = match body_bytes {
            Some(bytes) => match std::str::from_utf8(&bytes) {
                Ok(s) => {
                    let (ns, _) = resolver::substitute(s, |ph| values.get(&ph.raw).cloned());
                    Body::from(ns.into_bytes())
                }
                Err(_) => Body::from(bytes),
            },
            None => orig_body.take().unwrap_or_else(Body::empty),
        };

        self.pending = Some(AuditPending {
            vault_id,
            service: service_id,
            method,
            path,
            agent_prefix: self.agent_attribution(),
        });
        Request::from_parts(parts, out_body).into()
    }

    /// Resolve every phantom to its credential string. Errors distinguish
    /// "needs a passkey" (→ portal) from hard misuse (→ 4xx).
    #[allow(clippy::too_many_arguments)]
    async fn resolve_values(
        &self,
        vault_id: &str,
        conn: &str,
        service_id: &str,
        mint_input: Option<&str>,
        phantoms: &[Phantom],
        primary: Option<Vec<u8>>,
        secrets_map: Option<HashMap<String, Vec<u8>>>,
    ) -> Result<HashMap<String, String>, ResolveErr> {
        let mut out = HashMap::new();
        for ph in phantoms {
            let is_minted = mint_input.is_some();
            let bytes: Vec<u8> =
                if is_minted && ph.role.as_deref().map(|r| r == "access").unwrap_or(true) {
                    // The ACCESS phantom of a minted mechanism: mint from the stored
                    // input secret (primary) — oauth refresh token / snaplii api key.
                    let refresh = primary.clone().ok_or(ResolveErr::NeedsApproval)?;
                    crate::server::broker_flow::resolve_auth_value(
                        &self.state,
                        vault_id,
                        conn,
                        service_id,
                        &refresh,
                    )
                    .await
                    .map_err(|e| match e {
                        crate::error::AppError::Unauthorized(m) => ResolveErr::Mint(m),
                        other => ResolveErr::Mint(format!("{:?}", other)),
                    })?
                } else if is_minted {
                    let role = ph.role.clone().unwrap_or_default();
                    // Naming the REFRESH secret is a category error, not a missing
                    // feature: phantoms resolve to a connection's PRODUCED value
                    // (the minted access token), never a production INPUT. The
                    // refusal is precise so the boundary self-documents.
                    if mint_input.is_some_and(|k| role.eq_ignore_ascii_case(k)) {
                        return Err(ResolveErr::RefreshForbidden);
                    }
                    // An `exposes` value derived at connect (e.g. codex account_id):
                    // stored UPPERCASED in the vault, cached with the connection's
                    // other roles — matched case-insensitively like any role. Absent
                    // (not yet derived / pre-`exposes` connect) → the precise refusal.
                    match secrets_map.as_ref().and_then(|m| {
                        m.iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case(&role))
                            .map(|(_, v)| v.clone())
                    }) {
                        Some(v) => v,
                        None => return Err(ResolveErr::Exposes(role)),
                    }
                } else {
                    match &ph.role {
                        Some(r) => secrets_map
                            .as_ref()
                            .and_then(|m| {
                                m.iter()
                                    .find(|(k, _)| k.eq_ignore_ascii_case(r))
                                    .map(|(_, v)| v.clone())
                            })
                            .ok_or(ResolveErr::NeedsApproval)?,
                        None => match &secrets_map {
                            Some(m) if m.len() > 1 => return Err(ResolveErr::Ambiguous),
                            Some(m) if m.len() == 1 => m.values().next().cloned().unwrap(),
                            _ => primary.clone().ok_or(ResolveErr::NeedsApproval)?,
                        },
                    }
                };
            let s = String::from_utf8(bytes).map_err(|_| ResolveErr::NotUtf8)?;
            out.insert(ph.raw.clone(), s);
        }
        Ok(out)
    }

    /// Build + register the captive-portal (ask) op and return the 401 that
    /// surfaces the approve link through a dumb tool's error output.
    #[allow(clippy::too_many_arguments)]
    async fn captive_portal(
        &self,
        vault_id: &str,
        conn: &str,
        conn_rec: &crate::storage::plaintext::Connection,
        service_id: &str,
        op_role: Option<String>,
        host: &str,
        method: &str,
        path: &str,
        level: crate::core::policy::AccessLevel,
        rule_id: Option<String>,
        ttl: Option<u64>,
        req_scope: Option<&crate::service::RequestScope>,
        ip: IpAddr,
    ) -> RequestOrResponse {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        let now = now_secs();
        // Two DIFFERENT windows, deliberately independent:
        //   - grant_ttl: how long the approved `ask`-once grant stays cached so
        //     later matching requests fast-path (rule/floor `ttl`, else 15 min).
        //   - hold_secs: how long THIS pending op waits for the passkey before it
        //     expires (aux.policy.timeout, else 5 min). A long grant window must
        //     not stretch the approval deadline.
        let grant_ttl = ttl.unwrap_or(DEFAULT_ASK_TTL);
        let hold_secs = self.state.policy_approval_hold(vault_id);

        // `op_role` was resolved in `handle` from the custom-aware `def` (the
        // same source the forward path mints from); a raw, service-less
        // connection has none, so the connection id stands in.
        let role = op_role.unwrap_or_else(|| service_id.to_string());
        // The op `target` is the role's bound BARE key (record `keys` map,
        // identity default) — the same slot every writer uses.
        let target = crate::storage::plaintext::secret_key_for(Some(conn_rec), &role);

        let mut scope = json!({
            "connection_id": conn,
            "service": service_id,
            "host": host,
            "method": method,
            "path": path,
            "authorize_only": true,
        });
        // Op-agent binding (team §C1): the requesting agent's key prefix is
        // signed into β via the scope, so the human's approval covers "for
        // THIS agent" — swapping agents invalidates the grant. The grant page
        // can render it as the requester line. Enforcement reads the record's
        // copy (ApprovalRecord.agent_prefix), not this.
        if let Some(prefix) = self.agent_attribution() {
            scope["agent"] = serde_json::Value::String(prefix);
        }
        // Phase 2: fold the bound `[requests]` scope-field VALUES and the consent
        // template into the op scope. They are signed into β (the user's passkey
        // authorizes exactly the fields shown) and re-derived at approve to build
        // the grant-identity digest. Values are STRINGS — the canonical (JCS)
        // encoder rejects floats, and it keeps approve/redeem digests byte-equal.
        if let Some(rs) = req_scope {
            // Mark this a scoped path (a `[requests]` shape matched), so approve
            // never records a value-blind coarse-window key for it — even when
            // NO field values resolved (an empty-body ask). Without this, one
            // approved blank ask would open a window any later value could ride.
            scope["scoped"] = serde_json::Value::Bool(true);
            if !rs.bound.is_empty() {
                let obj: serde_json::Map<String, serde_json::Value> = rs
                    .bound
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect();
                scope["scope_vars"] = serde_json::Value::Object(obj);
            }
            // Display-only (not in the digest); still signed into β, a string so
            // JCS is happy. The `{{ vars.x | filter }}` template; the console
            // interpolates (auto-escaping values) and dispatches filters.
            if let Some(c) = &rs.consent {
                scope["consent"] = serde_json::Value::String(c.clone());
            }
        }
        let op = Operation {
            act: Act {
                kind: ActType::Use,
                target,
                scope,
            },
            bind: Bind {
                redeemer: vault_id.to_string(),
                recipient: None,
            },
            valid: Valid::single_use(now, Some(now + hold_secs)),
        };
        let pc = crate::approval::PolicyContext {
            level,
            rule_id,
            ttl_seconds: grant_ttl,
            host: Some(host.to_string()),
        };

        match crate::server::broker_flow::register_pending_use(
            &self.state,
            vault_id,
            op,
            Some(pc),
            ip,
            self.agent_attribution(),
        ) {
            Ok((op_id, _r, expires_at)) => {
                let approve_url = crate::cli::active::grant_url(&op_id);
                // §9: absolute poll_url. This 401 is emitted mid-proxy (e.g. while
                // brokering a gmail request), so a relative `/op/<id>` would
                // resolve against the UPSTREAM's domain. Loopback is the only
                // address the daemon can assert about itself — correct for the
                // supported local deployment. (A remote-exposed proxy — future,
                // gated — would need an advertised-origin config atom; until
                // then a remote agent just re-runs the command instead of
                // polling, the skill's primary path.)
                let poll_url = format!(
                    "http://127.0.0.1:{}/op/{}",
                    self.state.config.proxy_port, op_id
                );
                let body = format!(
                    "SafeClaw approval needed to use this credential.\n\
                     Approve with your passkey:\n  {}\n\
                     {}Then re-run the same command.\n\n\
                     {}\n",
                    approve_url,
                    wait_hint(&approve_url, &op_id),
                    json!({
                        "status": "pending",
                        "op_id": op_id,
                        "approve_url": approve_url,
                        "poll_url": poll_url,
                        "expires_at": expires_at,
                    })
                );
                let mut b = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .header("x-safeclaw-error", ScCode::ApprovalNeeded.as_str())
                    .header("x-safeclaw-approve-url", approve_url.as_str())
                    .header("x-safeclaw-op-id", op_id.as_str())
                    .header(header::LOCATION, format!("/op/{}", op_id));
                let interval = crate::approval::store::POLL_INTERVAL_HINT_SECS;
                b = b.header(header::RETRY_AFTER, interval.to_string());
                b.body(Body::from(body))
                    .unwrap_or_else(|_| plain(StatusCode::UNAUTHORIZED, "approval required"))
                    .into()
            }
            Err(e) => err_response(
                ScCode::ApprovalRegister,
                &format!("could not register approval: {:?}", e),
            )
            .into(),
        }
    }

    /// Host-anchor miss to a public host → DENY + a one-tap widen op (component
    /// C). The 403 body carries the approve link labeled as a permanent grant.
    async fn widen_deny(
        &self,
        vault_id: &str,
        conn: &str,
        host: &str,
        ip: IpAddr,
    ) -> RequestOrResponse {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        let now = now_secs();
        let mut scope = json!({
            "connection_id": conn,
            "host": host,
            "etld1": etld1(host),
        });
        // Same signed agent stamp as the credential-use op above.
        if let Some(prefix) = self.agent_attribution() {
            scope["agent"] = serde_json::Value::String(prefix);
        }
        let op = Operation {
            act: Act {
                kind: ActType::Custom("widen-host".into()),
                target: String::new(),
                scope,
            },
            bind: Bind {
                redeemer: vault_id.to_string(),
                recipient: None,
            },
            // Portal pendings inherit the SAME approval window as every
            // other pending op (aux.policy.timeout; SSOT) — was a fixed 15 min.
            valid: Valid::single_use(now, Some(now + self.state.policy_approval_hold(vault_id))),
        };
        let approve_line = match crate::server::broker_flow::register_pending_use(
            &self.state,
            vault_id,
            op,
            None,
            ip,
            self.agent_attribution(),
        ) {
            Ok((op_id, _r, exp)) => {
                let approve_url = crate::cli::active::grant_url(&op_id);
                // Same machine-readable tail as the credential-use 401 above —
                // the waiter contract is op-generic, so the widen op gets it too.
                let poll_url = format!(
                    "http://127.0.0.1:{}/op/{}",
                    self.state.config.proxy_port, op_id
                );
                let body = format!(
                    "SafeClaw: connection '{}' is not anchored to '{}'.\n\
                     Approve adding this host as a PERMANENT grant (passkey):\n  {}\n\
                     {}Then re-run the same command.\n\n\
                     {}\n",
                    conn,
                    host,
                    approve_url,
                    wait_hint(&approve_url, &op_id),
                    json!({
                        "status": "pending",
                        "op_id": op_id,
                        "approve_url": approve_url,
                        "poll_url": poll_url,
                        "expires_at": exp,
                    })
                );
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .header("x-safeclaw-approve-url", approve_url.as_str())
                    .header("x-safeclaw-op-id", op_id.as_str())
                    .header("x-safeclaw-error", ScCode::HostNotAnchored.as_str())
                    .body(Body::from(body))
                    .unwrap_or_else(|_| plain(StatusCode::FORBIDDEN, "host not anchored"))
                    .into();
            }
            Err(e) => format!("(could not open a widen request: {:?})", e),
        };
        err_response(
            ScCode::HostNotAnchored,
            &format!(
                "connection '{}' is not anchored to '{}' {}",
                conn, host, approve_line
            ),
        )
        .into()
    }
}

/// The waiter line for pending-approval bodies — only when the approve link
/// is absolute (cloud-paired). An unpaired daemon has no reachable approval
/// surface, and a hinted wait there would just block until the op expires.
fn wait_hint(approve_url: &str, op_id: &str) -> String {
    if approve_url.starts_with("http") {
        format!(
            "To wait: sc op wait {}   (background it; its exit is the signal)\n",
            op_id
        )
    } else {
        String::new()
    }
}

/// Resolution failure taxonomy — decides portal vs 4xx vs 5xx.
enum ResolveErr {
    /// The credential isn't in the session cache — needs a passkey (→ portal).
    NeedsApproval,
    /// Bare `__sc__conn__` on a connection exposing several secrets.
    Ambiguous,
    /// An oauth2 `exposes` role the mint doesn't surface yet.
    Exposes(String),
    /// The phantom names the oauth REFRESH secret — never injectable (a
    /// production input, not a produced value); egress would equal export.
    RefreshForbidden,
    /// The oauth mint failed / the refresh token is dead.
    Mint(String),
    /// The resolved bytes aren't valid UTF-8.
    NotUtf8,
}

// ── free helpers ─────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Merge `more` into `acc`, de-duplicating on `raw` in O(1) per element and
/// capped at [`resolver::MAX_PHANTOMS_PER_SITE`]. Each scan site
/// (`collect_phantoms`) is already capped and O(N); this keeps the cross-site
/// union bounded too, so no attacker-chosen body can drive quadratic work here.
fn merge_phantoms(acc: &mut Vec<Phantom>, more: Vec<Phantom>) {
    let mut seen: std::collections::HashSet<String> =
        acc.iter().map(|p| p.raw.clone()).collect();
    for p in more {
        if acc.len() >= resolver::MAX_PHANTOMS_PER_SITE {
            break;
        }
        if seen.insert(p.raw.clone()) {
            acc.push(p);
        }
    }
}

/// The legacy Basic api-key attribution prefix (never the full key). Factored out
/// of [`BrokerHandler::agent_attribution`] so that helper can reference it without
/// the raw-prefix expression appearing at the call sites (all of which now go
/// through `agent_attribution` so PoP `ag_` and legacy prefixes resolve uniformly).
fn legacy_key_prefix(key: Option<&str>) -> Option<String> {
    key.map(crate::audit::agent_key_prefix)
}

/// Read `(vid, api-key)` from a CONNECT's `Proxy-Authorization: Basic
/// base64("<vid>:<key>")`. The vid (username) routes the request to a vault; the
/// key (password) is the agent's identity (§8). Each is `None` when
/// absent/empty. A `None` vid means no Proxy-Auth at all ⇒ non-participating
/// traffic (`should_intercept` blind-tunnels it). The key is NOT trimmed (it's
/// an opaque token hashed for the membership check); the vid is.
fn creds_from_proxy_auth(req: &Request<Body>) -> (Option<String>, Option<String>) {
    let Some(text) = req
        .headers()
        .get(header::PROXY_AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Basic ")
                .or_else(|| s.strip_prefix("basic "))
        })
        .and_then(|b64| {
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .ok()
        })
        .and_then(|d| String::from_utf8(d).ok())
    else {
        return (None, None);
    };
    let (vid, key) = match text.split_once(':') {
        Some((v, k)) => (v.trim(), k),
        None => (text.trim(), ""),
    };
    let vid = (!vid.is_empty()).then(|| vid.to_string());
    let key = (!key.is_empty()).then(|| key.to_string());
    (vid, key)
}

/// Decode `Authorization: Basic <b64>` to `user:pass`, if present.
fn basic_auth_decoded(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = v
        .strip_prefix("Basic ")
        .or_else(|| v.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    String::from_utf8(decoded).ok()
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn body_is_text(headers: &HeaderMap) -> bool {
    match headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        Some(ct) => {
            let ct = ct.to_ascii_lowercase();
            ct.contains("json")
                || ct.starts_with("text/")
                || ct.contains("x-www-form-urlencoded")
                || ct.contains("xml")
        }
        None => false,
    }
}

/// Rebuild the header map: substitute phantom values, decode/re-encode Basic,
/// strip Proxy-Authorization + any agent Authorization the injected cred
/// replaces, drop hop-by-hop, and drop content-length when the body was rewritten.
fn rewrite_headers(
    headers: &HeaderMap,
    values: &HashMap<String, String>,
    body_rewritten: bool,
) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if lname == "proxy-authorization" || crate::server::broker_flow::is_hop_by_hop(&lname) {
            continue;
        }
        if body_rewritten && lname == "content-length" {
            continue;
        }
        let Ok(vs) = value.to_str() else {
            out.insert(name.clone(), value.clone());
            continue;
        };
        if lname == "authorization" {
            // Basic → decode, substitute, re-encode; else substitute raw. If no
            // phantom was in it, the agent's own auth is stripped (the injected
            // credential elsewhere is the real one; agents can't shadow it).
            if let Some(rest) = vs
                .strip_prefix("Basic ")
                .or_else(|| vs.strip_prefix("basic "))
            {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(rest.trim()) {
                    if let Ok(text) = String::from_utf8(decoded) {
                        let (new_text, any) =
                            resolver::substitute(&text, |ph| values.get(&ph.raw).cloned());
                        if any {
                            let enc = base64::engine::general_purpose::STANDARD
                                .encode(new_text.as_bytes());
                            if let Ok(hv) = header::HeaderValue::from_str(&format!("Basic {}", enc))
                            {
                                out.insert(header::AUTHORIZATION, hv);
                            }
                            continue;
                        }
                    }
                }
                // Basic with no phantom → strip.
                continue;
            }
            let (new_v, any) = resolver::substitute(vs, |ph| values.get(&ph.raw).cloned());
            if any {
                if let Ok(hv) = header::HeaderValue::from_str(&new_v) {
                    out.insert(header::AUTHORIZATION, hv);
                }
            }
            // No phantom in Authorization → strip (don't forward the agent's own).
            continue;
        }
        // Any other header: substitute in place (no-op if it has no phantom).
        // `append` preserves legitimately repeated headers (e.g. Cookie).
        let (new_v, _) = resolver::substitute(vs, |ph| values.get(&ph.raw).cloned());
        match header::HeaderValue::from_str(&new_v) {
            Ok(hv) => {
                out.append(name.clone(), hv);
            }
            Err(_) => {
                out.append(name.clone(), value.clone());
            }
        }
    }
    out
}

/// A human hint listing a connection's role phantoms (for the ambiguous case).
fn phantom_role_hint(
    conn: &str,
    rec: &crate::storage::plaintext::Connection,
    def: Option<&crate::service::ServiceDef>,
) -> String {
    let map = match def {
        Some(d) => crate::core::host::phantoms_for(conn, d),
        // Raw connection: the injectable keys are the record's explicit
        // `secrets` list — the same source `sc connection ls` prints. (This
        // used to fall back to the bare phantom, i.e. the exact form the
        // Ambiguous error had just rejected.)
        None => crate::core::host::phantoms_for_raw(conn, rec.secrets.as_deref().unwrap_or(&[])),
    };
    if map.is_empty() {
        crate::core::host::short_phantom(conn)
    } else {
        map.into_values().collect::<Vec<_>>().join(", ")
    }
}

/// Naive eTLD+1 (display only): the last two dot-labels of `host`.
fn etld1(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 2 {
        labels[labels.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

fn plain(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(msg.to_string()))
        .expect("static response builds")
}

/// The unified-boundary refusal (P1/P2): a phantom-bearing request whose body
/// exceeds the broker cap gets a 413 that says exactly what was over and how
/// to raise the knob — never a policy-blind forward with a live credential,
/// and never an approval prompt over content the user can't read.
/// `declared = 0` means the length was unknown (chunked) and the cap was hit
/// while buffering.
fn body_over_cap(declared: u64, cap: u64) -> Response<Body> {
    let what = if declared > 0 {
        format!("declared Content-Length ({} bytes)", declared)
    } else {
        "streamed body".to_string()
    };
    err_response(
        ScCode::BrokerBodyLimit,
        &format!(
            "this request names a phantom but its {} exceeds the broker's inspectable \
             cap ({} bytes) — the proxy will not forward a credential alongside a body \
             policy cannot see. If the request is legitimate, raise the daemon's \
             --body-cap / SAFECLAW_BODY_CAP.",
            what, cap
        ),
    )
}

/// Build the agent-facing body for a failed forward-hop (see `handle_error`).
/// A connect-phase failure is a reachability/egress problem, so it names the
/// cause and how to configure a proxy; anything else is reported plainly without
/// a proxy hint that would misdirect. Either way we lead with "not a credential
/// problem" so the agent doesn't blame the token, and tag it `egress_unreachable`
/// / `upstream_error` so tooling can branch on the header.
fn egress_error_response(err: hudsucker::hyper_util::client::legacy::Error) -> Response<Body> {
    let is_connect = err.is_connect();
    let cause = error_chain(&err);
    // Preserve the observability the default handler gave (it logged the raw err).
    tracing::error!(cause = %cause, is_connect, "forward-hop to upstream failed");
    let (code, msg) = egress_error_parts(
        is_connect,
        &cause,
        crate::cli::egress_proxy::effective().is_some(),
    );
    err_response(code, &msg)
}

/// The `(x-safeclaw-error code, body)` for a forward-hop failure. Pure so the
/// branching (connect vs not, proxy configured vs not) is testable without a
/// `hyper_util` error, which has no public constructor. Never echoes the proxy
/// URL — it can carry userinfo — pointing at `sc proxy show` instead.
fn egress_error_parts(is_connect: bool, cause: &str, has_proxy: bool) -> (ScCode, String) {
    if !is_connect {
        return (
            ScCode::UpstreamError,
            format!(
                "could not complete the upstream request (not a credential problem): {}",
                cause
            ),
        );
    }
    let hint = if has_proxy {
        "Egress goes through your configured proxy — make sure it's up and can reach \
         that host (`sc proxy show`), or change it with `sc proxy set <url>` / `sc proxy clear`."
    } else {
        "No egress proxy is set — if this machine reaches the internet only through a \
         proxy, run `sc proxy set <url>`."
    };
    (
        ScCode::EgressUnreachable,
        format!(
            "egress failed (not a credential problem): {}. {}",
            cause, hint
        ),
    )
}

/// Flatten an error's `source()` chain into one line, dropping empty/duplicate
/// frames. For a forward-hop failure the deepest frame is our `TunnelConnector`
/// message (e.g. `forward connect to gmail.googleapis.com:443 timed out`), which
/// already names host:port and direct-vs-proxy.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut cur: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = cur {
        let s = e.to_string();
        if !s.is_empty() && !parts.iter().any(|p| p == &s) {
            parts.push(s);
        }
        cur = e.source();
    }
    parts.join(": ")
}

/// A plain-text 4xx/5xx for the MITM plane. Status comes from the registry
/// (`ScCode::row`, the same row every surface uses); the machine token rides
/// `x-safeclaw-error` AND leads the body (`SafeClaw: <code>: <msg>`), so the
/// error is attributable even when a tool surfaces only one of the two.
/// text/plain is deliberate — a SafeClaw refusal must never parse as the
/// upstream service's payload.
fn err_response(code: ScCode, msg: &str) -> Response<Body> {
    let status = StatusCode::from_u16(code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-safeclaw-error", code.as_str())
        .body(Body::from(format!(
            "SafeClaw: {}: {}\n",
            code.as_str(),
            msg
        )))
        .unwrap_or_else(|_| plain(status, msg))
}

/// A `407 Proxy Authentication Required` challenge for a CONNECT that arrived
/// without proxy credentials but targets a host we broker. RFC 7235 challenge-
/// first clients (notably Debian/Ubuntu git over libcurl-gnutls) send no
/// `Proxy-Authorization` until they see this, then repeat the CONNECT
/// authenticated. `Basic` is the only scheme we
/// accept — the CONNECT userinfo carries `base64("<vid>:<key>")`; the realm
/// names us. Empty body + explicit zero length so the connection stays alive and
/// the client retries the CONNECT on it.
fn proxy_auth_challenge() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(header::PROXY_AUTHENTICATE, "Basic realm=\"safeclaw\"")
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap_or_else(|_| {
            plain(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "proxy auth required",
            )
        })
}

/// Best-effort terminal audit row for a forwarded (or denied) request. Denies
/// pass `upstream_status = 0`.
fn write_forward_audit(state: &AppState, p: &AuditPending, upstream_status: u16) {
    let Ok(store) = state.audits.for_vault(&p.vault_id) else {
        return;
    };
    let now = now_secs() as i64;
    let status = if upstream_status == 0 {
        crate::audit::STATUS_DENIED
    } else {
        crate::audit::STATUS_ALLOWED
    };
    let row = crate::audit::ApprovalRow {
        id: uuid::Uuid::new_v4().to_string(),
        created_at: now,
        decided_at: Some(now),
        expires_at: now,
        status: status.into(),
        act_kind: "use".into(),
        service: Some(p.service.clone()),
        method: Some(p.method.clone()),
        path: Some(p.path.clone()),
        target: None,
        reason: None,
        credential_id: None,
        upstream_status: if upstream_status == 0 {
            None
        } else {
            Some(upstream_status as i64)
        },
        agent_prefix: p.agent_prefix.clone(),
    };
    if let Err(e) = store.insert(&row) {
        tracing::warn!(vault = %p.vault_id, "proxy audit insert failed: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    /// The unified-boundary refusal contract: 413, machine-readable error
    /// token, and a message naming both the offending size and the knob —
    /// P2 says the caller must learn exactly what was over and how to widen.
    #[test]
    fn body_over_cap_is_explained_413() {
        let resp = body_over_cap(50_000_000, 32 * 1024 * 1024);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            resp.headers().get("x-safeclaw-error").unwrap(),
            "broker_body_limit"
        );
        // Chunked variant (length unknown while buffering) still explains.
        let resp = body_over_cap(0, 1024);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn error_chain_flattens_and_dedups() {
        #[derive(Debug)]
        struct E(&'static str, Option<Box<E>>);
        impl std::fmt::Display for E {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.0)
            }
        }
        impl std::error::Error for E {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.1.as_deref().map(|e| e as &dyn std::error::Error)
            }
        }
        let e = E(
            "client error (Connect)",
            Some(Box::new(E(
                "forward connect to gmail.googleapis.com:443 timed out",
                None,
            ))),
        );
        assert_eq!(
            error_chain(&e),
            "client error (Connect): forward connect to gmail.googleapis.com:443 timed out"
        );
        // Duplicate frames collapse.
        let dup = E("same", Some(Box::new(E("same", None))));
        assert_eq!(error_chain(&dup), "same");
    }

    #[test]
    fn egress_error_parts_reachability_names_proxy_knob_not_credential() {
        let cause = "forward connect to gmail.googleapis.com:443 timed out";

        // Connect failure, no proxy configured: tell them how to set one, and
        // make clear it is NOT a credential problem (the agent's #1 misread).
        let (code, msg) = egress_error_parts(true, cause, false);
        assert_eq!(code, ScCode::EgressUnreachable);
        assert!(msg.contains(cause));
        assert!(msg.contains("not a credential problem"));
        assert!(msg.contains("sc proxy set"));
        assert!(msg.contains("No egress proxy is set"));

        // Connect failure WITH a proxy configured: point at the proxy, never
        // echo its URL (it can carry userinfo), offer show/clear.
        let (code, msg) = egress_error_parts(true, cause, true);
        assert_eq!(code, ScCode::EgressUnreachable);
        assert!(msg.contains("configured proxy"));
        assert!(msg.contains("sc proxy show"));
        assert!(msg.contains("sc proxy clear"));

        // NOT a connect failure (e.g. upstream sent a bad response): no proxy
        // hint that would misdirect, distinct token.
        let (code, msg) = egress_error_parts(false, "invalid HTTP response", false);
        assert_eq!(code, ScCode::UpstreamError);
        assert!(!msg.contains("sc proxy set"));
        assert!(msg.contains("not a credential problem"));
    }

    #[test]
    fn creds_from_proxy_auth_splits_vid_and_key() {
        // vid:key → both captured (the key is the agent's identity, §8).
        let req = Request::builder()
            .uri("api.github.com:443")
            .header(
                header::PROXY_AUTHORIZATION,
                format!("Basic {}", b64(b"vault-abc:sc_agent_k9")),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            creds_from_proxy_auth(&req),
            (
                Some("vault-abc".to_string()),
                Some("sc_agent_k9".to_string())
            )
        );

        // Legacy empty password (`vid:`) → vid present, key None (→ 407 later,
        // it's participating but unauthenticated).
        let no_key = Request::builder()
            .uri("api.github.com:443")
            .header(
                header::PROXY_AUTHORIZATION,
                format!("Basic {}", b64(b"vault-abc:")),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            creds_from_proxy_auth(&no_key),
            (Some("vault-abc".to_string()), None)
        );
    }

    #[test]
    fn creds_absent_or_empty_vid_is_none() {
        // No Proxy-Auth at all → non-participating (blind-tunnel).
        let none = Request::builder()
            .uri("api.github.com:443")
            .body(Body::empty())
            .unwrap();
        assert_eq!(creds_from_proxy_auth(&none), (None, None));
        // Empty vid (`:key`) is not a routing hint → vid None.
        let empty_vid = Request::builder()
            .uri("api.github.com:443")
            .header(
                header::PROXY_AUTHORIZATION,
                format!("Basic {}", b64(b":sc_agent_k9")),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(creds_from_proxy_auth(&empty_vid).0, None);
    }

    #[test]
    fn proxy_auth_challenge_is_407_with_basic_realm() {
        // RFC 7235 challenge-first clients (Debian/Ubuntu git over libcurl-gnutls)
        // only send Proxy-Authorization after this exact response.
        let res = proxy_auth_challenge();
        assert_eq!(res.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(
            res.headers().get(header::PROXY_AUTHENTICATE).unwrap(),
            "Basic realm=\"safeclaw\"",
        );
    }

    #[test]
    fn basic_auth_decode_roundtrip() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", b64(b"x:secret")).parse().unwrap(),
        );
        assert_eq!(basic_auth_decoded(&h).as_deref(), Some("x:secret"));
    }

    #[test]
    fn etld1_takes_last_two_labels() {
        assert_eq!(etld1("foo.bar.github.com"), "github.com");
        assert_eq!(etld1("api.stripe.com"), "stripe.com");
        assert_eq!(etld1("localhost"), "localhost");
    }

    #[test]
    fn rewrite_headers_strips_proxy_auth_and_injects_basic() {
        let mut values = HashMap::new();
        values.insert("__sc__github__".to_string(), "ghp_REAL".to_string());
        let mut h = HeaderMap::new();
        h.insert(
            header::PROXY_AUTHORIZATION,
            "Basic Zm9vOg==".parse().unwrap(),
        );
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", b64(b"x:__sc__github__"))
                .parse()
                .unwrap(),
        );
        let out = rewrite_headers(&h, &values, false);
        assert!(
            out.get(header::PROXY_AUTHORIZATION).is_none(),
            "proxy auth stripped"
        );
        let auth = out.get(header::AUTHORIZATION).unwrap().to_str().unwrap();
        let enc = auth.strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(enc)
            .unwrap();
        assert_eq!(decoded, b"x:ghp_REAL", "phantom substituted inside Basic");
    }

    #[test]
    fn rewrite_headers_substitutes_basic_username_position() {
        // git clone https://__sc__github__@github.com → Basic b64("phantom:") —
        // the phantom rides the USERNAME slot (password empty). Regression pair
        // to the password-position test above.
        let mut values = HashMap::new();
        values.insert("__sc__github__".to_string(), "ghp_REAL".to_string());
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", b64(b"__sc__github__:"))
                .parse()
                .unwrap(),
        );
        let out = rewrite_headers(&h, &values, false);
        let auth = out
            .get(header::AUTHORIZATION)
            .expect("auth header survived")
            .to_str()
            .unwrap();
        let enc = auth.strip_prefix("Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(enc)
            .unwrap();
        assert_eq!(
            decoded, b"ghp_REAL:",
            "phantom substituted in USERNAME position"
        );
    }

    #[test]
    fn rewrite_headers_strips_shadowing_agent_bearer() {
        // The phantom lives elsewhere; the agent's own Authorization must not
        // ride along (it would shadow the injected credential).
        let values: HashMap<String, String> = HashMap::new();
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "Bearer agents-own-token".parse().unwrap(),
        );
        let out = rewrite_headers(&h, &values, false);
        assert!(out.get(header::AUTHORIZATION).is_none());
    }

    #[test]
    fn rewrite_headers_substitutes_bearer_phantom() {
        let mut values = HashMap::new();
        values.insert("__sc__stripe_key__".to_string(), "sk_live_X".to_string());
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "Bearer __sc__stripe_key__".parse().unwrap(),
        );
        let out = rewrite_headers(&h, &values, false);
        assert_eq!(
            out.get(header::AUTHORIZATION).unwrap().to_str().unwrap(),
            "Bearer sk_live_X"
        );
    }

    #[test]
    fn rewrite_headers_drops_content_length_when_body_rewritten() {
        let values: HashMap<String, String> = HashMap::new();
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_LENGTH, "42".parse().unwrap());
        h.insert("x-custom", "keep-me".parse().unwrap());
        let out = rewrite_headers(&h, &values, true);
        assert!(out.get(header::CONTENT_LENGTH).is_none());
        assert_eq!(out.get("x-custom").unwrap(), "keep-me");
    }
}
