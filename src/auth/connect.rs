//! OAuth CONNECT completion on the daemon (CONNECTION_SCHEMA.md §5).
//!
//! The browser drives Google consent with the **public Desktop client + PKCE**
//! and seals `{ service, config, code, verifier }` into `aux.connecting[<id>]`
//! (CONNECTION_SCHEMA.md §2). To stay **cloud-blind**, the code is relayed to the
//! daemon *through the sealed vault* (the cloud only ever stores ciphertext) —
//! never through the backend. This module is the daemon side of that handshake:
//!
//! 1. with the vault **open** (retained `K` from an unlocked session), read every
//!    in-flight connect from `aux.connecting`;
//! 2. for each, resolve the connection's *service* → its provider
//!    (client_id / secret / token_url + the fixed redirect_uri, all from the
//!    public Desktop literal) and exchange the code at `token_url`;
//! 3. WRITE the durable refresh_token at its bound BARE key (§3 `keys` map) and
//!    **MOVE** the entry from `aux.connecting` into `aux.connections`; re-seal the
//!    body under the same `K` and persist `vault.dat`.
//!
//! **No approval op.** This is the completion of a *user-initiated*,
//! passkey-sealed, Google-authenticated connect; the daemon holds `K` while
//! unlocked and re-seals directly. Approval-ops gate *agent* requests, not the
//! daemon's own connect-completion. An agent cannot forge a Google login plus a
//! passkey-sealed code.
//!
//! **Multi-connection.** `connection_id` is independent of `service_id`: each
//! `connecting`/`connections` entry names its `service` explicitly, so two Gmail
//! accounts (`gmail`, `gmail_work`) connect side-by-side. Every secret is stored
//! at a BARE uppercase KEY; the connection record's `keys` map binds each role
//! to its key (identity for the default connection, `<ROLE>_<QUALIFIER>` by
//! default for a named one — see [`secret_key_for`] / [`suggested_secret_key`]).
//!
//! **Best-effort, never fatal.** Anything that goes wrong logs and is skipped; a
//! malformed/unresolvable pending or an exchange failure (e.g. an expired code)
//! leaves the `connecting` entry in place so the user can retry within the code
//! TTL (~10 min). It never panics the daemon and never blocks serving.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{de::DeserializeOwned, Serialize};
use sudp::state::ProtectedState;

use crate::auth::oauth2::{ExchangedTokens, OAuthStyle};
use crate::state::AppState;
use crate::storage::plaintext::{secret_key_for, suggested_secret_key, Connecting, Connection};

/// The OAuth client/endpoint a pending connect resolves to before exchange, plus
/// the service's secret role (so we know where to write the result).
#[derive(Debug, Clone)]
pub struct ExchangeConfig {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub style: OAuthStyle,
    /// The OAuth client's fixed redirect_uri (provider config), echoed at the
    /// token call so it matches the browser's consent request.
    pub redirect_uri: String,
    /// The service's mainstream secret role, e.g. `GMAIL_REFRESH_TOKEN` — the base
    /// name the refresh_token is written under (namespaced per `conn`).
    pub secret_role: String,
    /// The secret KEY a returned OIDC id_token is stored under, when the service
    /// declares one (`[oauth2].id_token`). `None` = don't store it.
    pub id_token_role: Option<String>,
    /// `exposes` roles derived from the exchange's id_token: `(role, claim
    /// path)`. The role is stored UPPERCASED at its §3 address (env-key
    /// convention; the lowercase phantom segment matches case-insensitively).
    pub exposes: Vec<(String, Vec<String>)>,
}

/// Resolve the exchange config for a connection's **service**. The service def
/// is looked up in the built-in registry first, then this vault's own
/// per-vault custom services (`aux.services`, e.g. a user-authored inline
/// `[oauth2]`) — without the fallback a custom OAuth service's connect could
/// never complete (its def isn't in the global registry). `None` when the
/// service is unknown to BOTH, isn't oauth2, or is missing a token_url /
/// client_id / secret role.
pub fn resolve_exchange_config(
    services: &crate::service::ServiceRegistry,
    custom: &std::collections::HashMap<String, crate::service::ServiceDef>,
    service: &str,
) -> Option<ExchangeConfig> {
    // custom-FIRST (see proxy::handler): a vault-authored def wins over a same-id
    // registry service for connect / token-exchange too.
    let svc = custom.get(service).or_else(|| services.get(service))?;
    let oauth = svc.oauth2()?;
    let resolved = services.resolve_oauth_config(oauth);
    let token_url = resolved.token_url?;
    let client_id = resolved.client_id?;
    let secret_role = oauth.refresh_token.clone();
    let style = services.oauth_style(oauth);
    // Each exposed role's claim path: the explicit `[oauth2].claims` mapping,
    // else the role name itself as a top-level claim.
    let exposes = oauth
        .exposes
        .iter()
        .map(|role| {
            let path = oauth
                .claims
                .get(role)
                .cloned()
                .unwrap_or_else(|| vec![role.clone()]);
            (role.clone(), path)
        })
        .collect();
    Some(ExchangeConfig {
        token_url,
        client_id,
        client_secret: resolved.client_secret,
        style,
        redirect_uri: resolved.redirect_uri,
        secret_role,
        id_token_role: oauth.id_token.clone(),
        exposes,
    })
}

/// The loopback port a `service`'s consent redirect will land on — resolved
/// from its def with the SAME custom-FIRST rule as the exchange (a vault-
/// authored def wins over a same-id registry service), because that resolved
/// redirect_uri is what the console baked into the consent URL. `None` for a
/// non-oauth service or a non-loopback/portless redirect. The caller gates the
/// result on `ServiceRegistry::loopback_allowlist` — resolution says where the
/// redirect will land, the allowlist says whether we may listen there.
fn loopback_port_for(
    services: &crate::service::ServiceRegistry,
    custom: &std::collections::HashMap<String, crate::service::ServiceDef>,
    service: &str,
) -> Option<u16> {
    let svc = custom.get(service).or_else(|| services.get(service))?;
    let oauth = svc.oauth2()?;
    crate::service::loopback_port(&services.resolve_oauth_config(oauth).redirect_uri)
}

/// Read a `connection_id → T` map out of `m.aux[<key>]`. Empty when the key is
/// absent or doesn't parse (forward-compat: a newer schema we can't read yields
/// no entries — never an error).
fn aux_map<T: DeserializeOwned>(m: &ProtectedState, key: &str) -> BTreeMap<String, T> {
    m.aux
        .get(key)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

/// Write a `connection_id → T` map back into `m.aux[<key>]`, dropping the key
/// entirely when the map is empty (matching the `skip_serializing_if` shape the
/// rest of the aux schema round-trips with). Leaves all other aux fields intact.
fn set_aux_map<T: Serialize>(m: &mut ProtectedState, key: &str, map: BTreeMap<String, T>) {
    if !m.aux.is_object() {
        // A v3 vault's aux is always an object; tolerate a malformed one by
        // starting fresh rather than panicking.
        m.aux = serde_json::json!({});
    }
    let obj = m.aux.as_object_mut().expect("aux normalized to object");
    if map.is_empty() {
        obj.remove(key);
    } else if let Ok(v) = serde_json::to_value(&map) {
        obj.insert(key.to_string(), v);
    }
}

/// Apply one successful exchange to the open `ProtectedState`: write the durable
/// refresh_token at its bound BARE key (overwriting any prior one — a re-connect
/// supersedes), store the id_token / its derived `exposes` claims when the
/// service declares them, and **MOVE** the entry from `aux.connecting` into
/// `aux.connections` (no partial/duplicate record). `hosts` carries any exact
/// FQDNs pinned at connect for a wildcard service; `keys` carries the creator's
/// explicit role→KEY bindings — absent, a NAMED connection gets the
/// [`suggested_secret_key`] defaults derived here (the default connection binds
/// identity, so it stores no map). Pure state transition (no I/O) so it's
/// unit-testable against a mocked `ProtectedState`.
pub fn apply_exchange_result(
    m: &mut ProtectedState,
    conn: &str,
    service: &str,
    hosts: Option<Vec<String>>,
    keys: Option<BTreeMap<String, String>>,
    cfg: &ExchangeConfig,
    tokens: &ExchangedTokens,
) {
    // The record's role→KEY bindings. Every role this exchange stores must be
    // bound BEFORE the writes below so writer and future readers use one map.
    let keys: Option<BTreeMap<String, String>> = keys.or_else(|| {
        if conn == service {
            return None; // identity binding — no map stored
        }
        let mut map = BTreeMap::new();
        let mut bind = |role: &str| {
            let r = role.to_ascii_uppercase();
            let k = suggested_secret_key(conn, service, &r);
            map.insert(r, k);
        };
        bind(&cfg.secret_role);
        if let Some(idt_role) = &cfg.id_token_role {
            bind(idt_role);
        }
        for (role, _) in &cfg.exposes {
            bind(role);
        }
        Some(map)
    });
    let rec = Connection {
        name: None, // set below from the connecting entry
        service: Some(service.to_string()),
        hosts,
        secrets: None,
        keys,
    };
    if let Some(rt) = &tokens.refresh_token {
        m.put_secret(
            secret_key_for(Some(&rec), &cfg.secret_role),
            rt.as_bytes().to_vec(),
        );
    }
    if let Some(idt) = &tokens.id_token {
        // Store the raw id_token only when the service names a slot for it.
        if let Some(idt_role) = &cfg.id_token_role {
            m.put_secret(
                secret_key_for(Some(&rec), idt_role),
                idt.as_bytes().to_vec(),
            );
        }
        // Derive each exposed role from its id_token claim. Stored UPPERCASED
        // (env-key convention for vault items); the lowercase phantom segment
        // resolves case-insensitively. A missing claim is logged, not fatal —
        // the phantom then answers with the precise "not derived" refusal.
        for (role, path) in &cfg.exposes {
            match crate::auth::oauth2::id_token_claim(idt, path) {
                Some(v) => {
                    let key = role.to_ascii_uppercase();
                    m.put_secret(secret_key_for(Some(&rec), &key), v.into_bytes());
                }
                None => tracing::warn!(
                    conn = %conn,
                    role = %role,
                    "oauth connect: id_token carries no claim at the exposes path"
                ),
            }
        }
    } else if !cfg.exposes.is_empty() {
        tracing::warn!(
            conn = %conn,
            "oauth connect: service exposes derived roles but the exchange returned no id_token"
        );
    }
    // MOVE: drop from `connecting`, add to `connections` (name carried over).
    let mut connecting = aux_map::<Connecting>(m, "connecting");
    let name = connecting.remove(conn).and_then(|c| c.name);
    set_aux_map(m, "connecting", connecting);

    let mut connections = aux_map::<Connection>(m, "connections");
    // Service-backed: secrets derive from the service def, never stored here;
    // `keys` is the role→KEY binding fixed above.
    connections.insert(conn.to_string(), Connection { name, ..rec });
    set_aux_map(m, "connections", connections);
}

/// Collect the in-flight connects worth exchanging from `aux.connecting`. Pure
/// (no network) for testability.
///
/// A connect that already carries a terminal `error` (its code was
/// `invalid_grant` — expired/used) is DONE, not pending: it stays in
/// `connecting` only so the console can render "reconnect". Re-exchanging it is
/// futile AND harmful — the re-mark re-pushes the entry, which the cloud-sync
/// watcher sees as a change and re-processes, forming a self-perpetuating retry
/// storm against the token endpoint. So skip error'd entries; only a fresh
/// connect (no `error`) or a transient failure (never stamped one) is retried.
fn collect_pending(m: &ProtectedState) -> Vec<(String, Connecting)> {
    aux_map::<Connecting>(m, "connecting")
        .into_iter()
        // Skip an entry still AWAITING its code (empty `code`): an auto-catch
        // connect seals `{code_verifier, state}` BEFORE consent and only gets a
        // code once the 8765 listener catches the redirect (or the user pastes).
        // Exchanging an empty code would earn a bogus invalid_grant and clobber
        // the flow. `error.is_none()` still excludes terminally-failed entries.
        .filter(|(_, c)| c.oauth2.error.is_none() && !c.oauth2.code.is_empty())
        .collect()
}

/// Merge codes the 8765 loopback listener caught into their matching pending
/// entries (keyed by connection id), so [`collect_pending`] picks them up for
/// exchange this cycle. Only fills an EMPTY code — never overwrites one already
/// present (a racing paste wins whichever landed first). Pure state edit.
fn inject_codes(m: &mut ProtectedState, codes: &std::collections::BTreeMap<String, String>) {
    let mut connecting = aux_map::<Connecting>(m, "connecting");
    let mut changed = false;
    for (conn, code) in codes {
        if let Some(entry) = connecting.get_mut(conn) {
            if entry.oauth2.code.is_empty() && !code.is_empty() {
                entry.oauth2.code = code.clone();
                changed = true;
            }
        }
    }
    if changed {
        set_aux_map(m, "connecting", connecting);
    }
}

/// Per-run outcome of the connect state machine, so callers (and ultimately
/// `sc sync`) can SURFACE what happened instead of failing silently. Three
/// disjoint buckets:
/// - `completed`: got a refresh_token, MOVEd to `connections`.
/// - `failed`: TERMINALLY rejected (`invalid_grant` / other 4xx) — an `error` was
///   stamped so the console renders "reconnect"; carries the provider's reason.
/// - `unreached`: a TRANSIENT failure (couldn't reach the provider — network /
///   proxy / 5xx) — left pending, NO error stamped, retried next sync; carries the
///   provider host so the user can tell "my egress is broken" from "the code died".
#[derive(Debug, Default, Clone)]
pub struct ConnectReport {
    pub completed: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub unreached: Vec<(String, String)>,
}

impl ConnectReport {
    /// Did anything MUTATE the sealed state (⇒ the caller must persist + push)?
    /// A transient `unreached` stamps nothing, so it does not count.
    pub fn changed(&self) -> bool {
        !self.completed.is_empty() || !self.failed.is_empty()
    }
}

/// The bare host of a token endpoint (`https://oauth2.googleapis.com/token` →
/// `oauth2.googleapis.com`), for the human-readable "couldn't reach X" signal.
fn provider_host(token_url: &str) -> String {
    let after = token_url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(token_url);
    after
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(token_url)
        .to_string()
}

/// Sentinel the exchange closure returns for a code THIS daemon has already
/// redeemed (see [`crate::state::AppState::was_code_redeemed`]). `run_pending`
/// treats it as neither success nor failure: skip silently, leave the entry,
/// stamp NO error — a re-`invalid_grant` on an already-consumed code must never
/// clobber the live connection.
const ALREADY_REDEEMED: &str = "__sc_already_redeemed__";

/// Drive the connecting→refresh→move state machine over an open `ProtectedState`,
/// given an async `exchange` closure (injected so tests can avoid real network
/// calls). Mutates `m` in place; returns a [`ConnectReport`] of what happened. On
/// a per-connect failure it logs and **leaves the `connecting` entry in place**
/// (the user retries within the code TTL) — it never aborts the whole batch.
///
/// The caller persists + pushes whenever [`ConnectReport::changed`] is true.
///
/// `exchange(conn, cfg, connecting)` performs the code→token call and returns the
/// tokens (or an error string to log + skip).
pub async fn run_pending<F, Fut>(
    services: &crate::service::ServiceRegistry,
    custom: &std::collections::HashMap<String, crate::service::ServiceDef>,
    m: &mut ProtectedState,
    mut exchange: F,
) -> ConnectReport
where
    F: FnMut(String, ExchangeConfig, Connecting) -> Fut,
    Fut: std::future::Future<Output = Result<ExchangedTokens, String>>,
{
    let pending = collect_pending(m);
    let mut report = ConnectReport::default();
    for (conn, p) in pending {
        let Some(cfg) = resolve_exchange_config(services, custom, &p.service) else {
            tracing::warn!(
                conn = %conn,
                service = %p.service,
                "oauth connect: no oauth2 exchange config for the connection's service \
                 (unknown/non-oauth2 service or missing provider creds); leaving connecting"
            );
            continue;
        };
        // Capture what the post-exchange MOVE needs before `p` is consumed.
        let service = p.service.clone();
        let hosts = p.hosts.clone();
        let keys = p.keys.clone();
        let cfg_apply = cfg.clone();
        let host = provider_host(&cfg_apply.token_url);
        match exchange(conn.clone(), cfg, p).await {
            Ok(tokens) => {
                if tokens.refresh_token.is_none() {
                    // No durable credential came back (consent without offline
                    // access). Leave connecting so the user can redo consent.
                    tracing::warn!(
                        conn = %conn,
                        "oauth connect: exchange returned no refresh_token; leaving connecting"
                    );
                    continue;
                }
                apply_exchange_result(m, &conn, &service, hosts, keys, &cfg_apply, &tokens);
                report.completed.push(conn.clone());
                tracing::info!(
                    conn = %conn,
                    "oauth connect: refresh_token persisted; moved to connections"
                );
            }
            Err(e) => {
                if e == ALREADY_REDEEMED {
                    // Idempotency: this daemon already redeemed this code, and a
                    // stale write (a buggy web Save, a cross-device echo, or a
                    // pull that resurrected the pending entry before our success
                    // push landed) put it back in `connecting`. Re-sending it
                    // would earn a no-win `invalid_grant`; treat it as neither
                    // success nor failure — leave the entry, stamp nothing, let
                    // sync convergence settle it.
                    tracing::info!(
                        conn = %conn,
                        "oauth connect: code already redeemed by this daemon — skipping stale re-introduction (not a failure)"
                    );
                    continue;
                }
                if let Some(reason) = terminal_exchange_reason(&e) {
                    // Terminal: retrying the SAME code/config can never succeed.
                    // Stamp the connecting entry so the console shows
                    // "failed — reconnect" (with the provider's reason) instead
                    // of a perpetual "connecting" retry-storming the token
                    // endpoint. Only a fresh consent (new code, possibly a fixed
                    // def) recovers — it overwrites this entry, clearing the
                    // error.
                    mark_connecting_failed(m, &conn, &reason);
                    report.failed.push((conn.clone(), reason));
                    tracing::warn!(conn = %conn, "oauth connect: terminal exchange rejection — marked failed: {}", e);
                } else {
                    // Transient (network / provider 5xx / rate limit) — leave
                    // connecting + retry on the next sync. Report it so `sc sync`
                    // can say "couldn't reach <host>" instead of a silent spin.
                    report.unreached.push((conn.clone(), host));
                    tracing::warn!(conn = %conn, "oauth connect: exchange failed (transient), will retry: {}", e);
                }
            }
        }
    }
    report
}

/// Classify an exchange failure: `Some(reason)` when re-sending the SAME
/// request can never succeed (the provider REJECTED it — expired code, missing
/// client_secret, bad client, wrong redirect …), `None` when it's worth
/// retrying (network error, provider 5xx, rate limit). Blindly retrying a
/// rejection forms a retry storm against the token endpoint: the sync watcher
/// re-processes the pending entry every cycle, forever.
///
/// The error is a formatted string (`exchange_code` returns
/// `"… returned HTTP <status> — <body>"`), so classification is textual: any
/// 4xx is a rejection except 408 (timeout) and 429 (rate limit). The reason
/// surfaces the provider's `error_description`/`error` when the body is the
/// standard RFC 6749 §5.2 JSON.
fn terminal_exchange_reason(e: &str) -> Option<String> {
    if e.contains("invalid_grant") {
        return Some("authorization expired or already used".to_string());
    }
    let rejected = e.contains("returned HTTP 4")
        && !e.contains("returned HTTP 408")
        && !e.contains("returned HTTP 429");
    if !rejected {
        return None;
    }
    let detail = e
        .split_once("— ")
        .and_then(|(_, body)| serde_json::from_str::<serde_json::Value>(body.trim()).ok())
        .and_then(|v| {
            v.get("error_description")
                .or_else(|| v.get("error"))
                .and_then(|d| d.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "provider rejected the exchange".to_string());
    Some(format!("provider rejected the exchange: {}", detail))
}

/// Stamp a terminal `error` on one `connecting` entry (leaving code/code_verifier
/// so the console still knows which connection it is). No-op if the entry is gone.
fn mark_connecting_failed(m: &mut ProtectedState, conn: &str, reason: &str) {
    let mut connecting = aux_map::<Connecting>(m, "connecting");
    if let Some(entry) = connecting.get_mut(conn) {
        entry.oauth2.error = Some(reason.to_string());
    }
    set_aux_map(m, "connecting", connecting);
}

/// Process all in-flight connects (`aux.connecting`) for one vault: open the body
/// with the retained `K`, exchange each pending code, write the refresh_tokens,
/// MOVE each entry to `aux.connections`, re-seal under the same `K`, and persist
/// `vault.dat`.
///
/// Best-effort end-to-end:
/// - Locked vault (no retained `K`) → skip (the next unlock re-runs this).
/// - No pending connects → no-op (no disk write).
/// - A retained `K` that can't open the body (rotated `K`) → log + skip.
/// - Per-connect failures are handled by [`run_pending`] (leave + retry).
///
/// Holds the per-vault write lock for the open→mutate→re-seal→write cycle so it
/// serializes against approve.rs's writes and the cloud-sync pull (same lock).
/// Never panics; any error logs and returns.
pub async fn process_vault_connects(
    state: &Arc<AppState>,
    vault_id: &str,
    injected: Option<std::collections::BTreeMap<String, String>>,
) -> ConnectReport {
    // Apply any pending connects (open → exchange → re-seal → persist). On a
    // completion, fan the re-sealed blob out to OTHER devices via the cloud.
    // `injected` (conn → code) carries any codes the 8765 loopback listener just
    // caught; `None` on the ordinary sync path (nothing to inject).
    let report = apply_pending_connects(state, vault_id, injected).await;
    if report.changed() {
        // A fresh connect landed → clear any stale needs-reauth flag for this
        // vault (a still-dead token re-marks on the next /use).
        state.oauth_clear_reauth_vault(vault_id);
        // Propagate to OTHER devices: push the re-sealed blob back to the cloud.
        // A Google authorization code is single-use, so only THIS daemon could
        // redeem the pending connect — every other device's daemon must PULL the
        // resulting refresh_token rather than re-exchange (which fails
        // `invalid_grant`). Cloud-blind preserved: the pushed blob is ciphertext.
        // Detached + best-effort, after the write lock drops (push only reads
        // vault.dat + HTTP).
        let state = state.clone();
        let vid = vault_id.to_string();
        tokio::spawn(async move {
            // Keyset lifecycle rides the whole-blob push (the `/blob` marker) AND
            // the per-cred wrap material rides `/keys`; content (the new
            // refresh-token secret + connection MOVE) rides the per-item push.
            crate::sync::push_blob_best_effort(&state, &vid).await;
            crate::sync::push_keys_best_effort(&state, &vid).await;
            crate::sync::push_items_best_effort(&state, &vid).await;
        });
    }
    report
}

/// Apply pending connects WITHOUT the cloud push-back. Returns a [`ConnectReport`]
/// of what happened (empty when locked / nothing pending). The push fan-out lives
/// in the public `process_vault_connects` wrapper, NOT here — that split is
/// load-bearing: the cloud-sync CAS-conflict recovery
/// (`sync::recover_after_conflict`) calls this inner fn to re-apply its mutation
/// on a freshly-pulled blob; routing it through the push-spawning wrapper would
/// form an async-recursion cycle (push → recover → process → push) the compiler
/// can't prove `Send`. Keeping the push out of the recursive edge breaks it.
pub(crate) async fn apply_pending_connects(
    state: &Arc<AppState>,
    vault_id: &str,
    injected: Option<std::collections::BTreeMap<String, String>>,
) -> ConnectReport {
    let Some(k) = state.cloned_state_key(vault_id) else {
        return ConnectReport::default(); // Locked — no retained K; next unlock retries.
    };

    let lock = {
        let mut locks = state.vault_write_locks.lock().unwrap();
        Arc::clone(
            locks
                .entry(vault_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    };
    let _guard = lock.lock().await;

    let vault_path = state
        .config
        .state_dir
        .join("vaults")
        .join(vault_id)
        .join("vault.dat");
    // Open the vault body from whichever store backs it. A daemon-side
    // Enroll/Write vault has a whole-blob vault.dat; a WEB-enrolled vault has
    // ONLY the per-item store (vault.per-item.json) — for that we fold the item
    // rows into a view and rebuild the ProtectedState M the connect machine runs
    // on (inverse of VaultPlaintextView::from_protected_state).
    let vault_dat = match crate::storage::sealed_vault::read(&vault_path) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth connect: read vault.dat failed: {}", e);
            None
        }
    };
    let mut m = if let Some(vault) = &vault_dat {
        match crate::server::handlers::metadata::open_protected_state_with_key(&k, vault) {
            Ok(m) => m,
            Err(_) => {
                // Rotated K — a re-unlock heals. Trace it: this return also
                // silently skips loopback-listener arming, so without a line
                // here a skipped scan is indistinguishable from "no pending
                // connect".
                tracing::debug!(vault = %vault_id, "oauth connect: vault.dat undecryptable with retained K — skipping scan (re-unlock heals)");
                return ConnectReport::default();
            }
        }
    } else {
        let Ok(pi_path) = state.vaults.per_item_path(vault_id) else {
            return ConnectReport::default();
        };
        let Ok(Some(pv)) = crate::storage::sealed_vault::read_per_item(&pi_path) else {
            return ConnectReport::default(); // neither vault.dat nor a per-item store
        };
        let view = match crate::server::handlers::metadata::decrypt_vault_view_peritem_with_key(
            &k, &pv, vault_id,
        ) {
            Ok(v) => v,
            Err(_) => {
                tracing::debug!(vault = %vault_id, "oauth connect: per-item view undecryptable with retained K — skipping scan (re-unlock heals)");
                return ConnectReport::default();
            }
        };
        match build_m_from_view(&view) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(vault = %vault_id, "oauth connect: rebuild M from per-item failed: {}", e);
                return ConnectReport::default();
            }
        }
    };

    // Register every loopback connect still AWAITING its redirect (carries a
    // `state`, no code yet) so the on-demand listener can match an incoming
    // `?code&state` to this (vault, connection). The listen PORT comes from the
    // connect's service def (custom-FIRST, same resolution the exchange uses)
    // and must sit in the allowlist parsed from LOCALLY-INSTALLED defs — vault
    // content picks among shipped targets (8765 canonical, 1455 openai_codex),
    // it can never open a new port. Off-allowlist redirect ⇒ paste-only.
    // Runs each ordinary sync tick, keeping the in-memory index fresh
    // (self-reaps at the 2h ceiling). Skipped on the injected path (the
    // completion call for an entry we already took out of the index) so a
    // just-completed connect isn't re-registered stale.
    if injected.is_none() {
        let custom = state.custom_services_snapshot(vault_id);
        let allowed = state.services.loopback_allowlist();
        for (conn_id, c) in aux_map::<Connecting>(&m, "connecting") {
            if c.oauth2.code.is_empty() {
                if let Some(st) = &c.oauth2.state {
                    match loopback_port_for(&state.services, &custom, &c.service) {
                        Some(port) if allowed.contains(&port) => {
                            state.note_loopback_pending(st, vault_id, &conn_id, port);
                        }
                        Some(port) => tracing::debug!(
                            conn = %conn_id, port,
                            "oauth connect: redirect port not in the local-def allowlist; paste-only"
                        ),
                        None => tracing::debug!(
                            conn = %conn_id,
                            "oauth connect: no loopback redirect target; paste-only"
                        ),
                    }
                }
            }
        }
        // Open each pending port's listener ON DEMAND — only while some connect
        // is awaiting its redirect there. Idempotent + single-instance per port:
        // N concurrent connects (across all vaults) share ONE listener per port
        // (`ensure_running` no-ops if already up, so the daemon never races
        // itself into a port conflict); each self-closes when its last pending
        // clears. No pending ⇒ nothing opens.
        for port in state.pending_loopback_ports() {
            crate::auth::loopback::ensure_running(state.clone(), port);
        }
    }

    // Fill in any codes the 8765 listener caught this round, so the matching
    // entries become exchangeable in the pre-check + run below.
    if let Some(injected) = &injected {
        inject_codes(&mut m, injected);
    }

    // Cheap pre-check: nothing to do if there are no in-flight connects.
    if collect_pending(&m).is_empty() {
        return ConnectReport::default();
    }

    let services = &state.services;
    // Per-vault custom services (`aux.services`) so a user-authored inline
    // [oauth2] service's connect can resolve — the bootstrap that populates
    // this cache always runs before us (sync/watch/unlock+write all refresh
    // the cache, THEN process connects), so it's fresh here.
    let custom = state.custom_services_snapshot(vault_id);
    let st = state.clone();
    let report = run_pending(services, &custom, &mut m, move |_conn, cfg, p| {
        let state = st.clone();
        async move {
            // Idempotency key = the authorization code. A single-use code this
            // daemon already redeemed must never be re-exchanged (a stale write
            // can resurrect its `connecting` entry); re-sending earns a no-win
            // `invalid_grant` that would clobber the live connection. The ledger
            // is daemon-local + never synced, so no stale write can revert it.
            if state.was_code_redeemed(&p.oauth2.code) {
                return Err(ALREADY_REDEEMED.to_string());
            }
            let out = crate::auth::oauth2::exchange_code(
                &cfg.token_url,
                &cfg.client_id,
                cfg.client_secret.as_deref(),
                &p.oauth2.code,
                &p.oauth2.code_verifier,
                &cfg.redirect_uri,
                cfg.style,
            )
            .await;
            if out.is_ok() {
                state.note_code_redeemed(&p.oauth2.code);
            }
            out
        }
    })
    .await;

    // A terminal connect (completed or failed) no longer awaits a redirect —
    // drop its pending-loopback index entry so the on-demand 8765 listener can
    // close promptly (the auto-catch path already took it; this covers a
    // paste-fallback completion whose pre-seal entry no redirect consumed).
    for c in &report.completed {
        state.clear_loopback_for_conn(vault_id, c);
    }
    for (c, _) in &report.failed {
        state.clear_loopback_for_conn(vault_id, c);
    }

    if !report.changed() {
        // Nothing MUTATED (all left pending / transient) — don't rewrite or push.
        // Still return the report so a transient `unreached` surfaces to `sc sync`.
        return report;
    }
    // A terminal failure (invalid_grant) with no completion still MUTATED the
    // state (stamped `error` on the connecting entry) — fall through so it's
    // persisted + pushed, surfacing "reconnect" in the console.

    // Post-connect view: the new refresh_token secret + connecting→connections
    // MOVE, folded from the mutated M.
    let view = match crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth connect: view rebuild failed: {}", e);
            return ConnectReport::default();
        }
    };

    // Persist. If a whole-blob vault.dat backs this vault, re-seal + write it so
    // the legacy path stays authoritative. EITHER way, write the change to the
    // per-item store (the content that syncs via /items) — for a web-enrolled
    // per-item vault this is the ONLY durable write. Per-item upserts are
    // version-bumped for CAS, so a concurrent browser edit to a DIFFERENT item
    // never collides (contract §4).
    if let Some(mut vault) = vault_dat {
        if let Err(e) = crate::server::handlers::metadata::reseal_body_with_key(&k, &mut vault, &m)
        {
            tracing::warn!(vault = %vault_id, "oauth connect: re-seal failed: {}", e);
            return ConnectReport::default();
        }
        if let Err(e) = crate::storage::sealed_vault::write_atomic(&vault_path, &vault) {
            tracing::warn!(vault = %vault_id, "oauth connect: write vault.dat failed: {}", e);
            return ConnectReport::default();
        }
        reconcile_per_item_after_connect(state, vault_id, Some(&vault), &view, &k);
    } else {
        reconcile_per_item_after_connect(state, vault_id, None, &view, &k);
    }
    tracing::info!(
        vault = %vault_id,
        connects = report.completed.len(),
        failed = report.failed.len(),
        "oauth connect: processed"
    );

    // Refresh the in-memory cache so /use sees the new refresh_token without a
    // manual lock/unlock. Best-effort.
    let cache = crate::server::handlers::approve::bootstrap_cache_from_view(&view, state);
    state.unlock_vault(vault_id.to_string(), cache, k);

    report
}

/// Persist a ROTATED refresh_token back into the sealed vault at its bound BARE
/// key (`secret_key_for` over the established connection record — the SAME slot
/// the connect exchange wrote). A rotating provider (OpenAI) hands back a fresh refresh_token on every
/// refresh and invalidates the one we sent, so the broker calls this after a
/// mint; otherwise the NEXT refresh would present a dead token and force a
/// spurious reconnect.
///
/// Mirrors the read → mutate → reseal → reconcile tail of [`apply_pending_connects`]
/// but writes ONE secret and runs no exchange. The caller (the broker mint path)
/// ALREADY HOLDS the per-vault write lock ([`AppState::vault_write_lock`]) — this
/// does NOT re-acquire it (that lock is what serializes this against a concurrent
/// connect exchange). Best-effort: logs and returns `false` on any vault-I/O
/// failure — a lost rotation only forces a later reconnect, never a corrupt write.
pub(crate) async fn persist_rotated_refresh_locked(
    state: &Arc<AppState>,
    vault_id: &str,
    conn_id: &str,
    role: &str,
    new_refresh_token: &str,
) -> bool {
    let Some(k) = state.cloned_state_key(vault_id) else {
        return false; // locked — nothing retained to write with
    };

    let vault_path = state
        .config
        .state_dir
        .join("vaults")
        .join(vault_id)
        .join("vault.dat");
    let vault_dat = match crate::storage::sealed_vault::read(&vault_path) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth rotate: read vault.dat failed: {}", e);
            None
        }
    };
    let mut m = if let Some(vault) = &vault_dat {
        match crate::server::handlers::metadata::open_protected_state_with_key(&k, vault) {
            Ok(m) => m,
            Err(_) => return false, // rotated K — next unlock re-reads
        }
    } else {
        let Ok(pi_path) = state.vaults.per_item_path(vault_id) else {
            return false;
        };
        let Ok(Some(pv)) = crate::storage::sealed_vault::read_per_item(&pi_path) else {
            return false;
        };
        let view = match crate::server::handlers::metadata::decrypt_vault_view_peritem_with_key(
            &k, &pv, vault_id,
        ) {
            Ok(v) => v,
            Err(_) => return false,
        };
        match build_m_from_view(&view) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(vault = %vault_id, "oauth rotate: rebuild M failed: {}", e);
                return false;
            }
        }
    };

    // Resolve the role's bound key from the established record — the map the
    // exchange wrote (or identity for a default connection).
    let rec = aux_map::<Connection>(&m, "connections").remove(conn_id);
    m.put_secret(
        secret_key_for(rec.as_ref(), role),
        new_refresh_token.as_bytes().to_vec(),
    );

    let view = match crate::storage::plaintext::VaultPlaintextView::from_protected_state(&m) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "oauth rotate: view rebuild failed: {}", e);
            return false;
        }
    };
    if let Some(mut vault) = vault_dat {
        if let Err(e) = crate::server::handlers::metadata::reseal_body_with_key(&k, &mut vault, &m)
        {
            tracing::warn!(vault = %vault_id, "oauth rotate: re-seal failed: {}", e);
            return false;
        }
        if let Err(e) = crate::storage::sealed_vault::write_atomic(&vault_path, &vault) {
            tracing::warn!(vault = %vault_id, "oauth rotate: write vault.dat failed: {}", e);
            return false;
        }
        reconcile_per_item_after_connect(state, vault_id, Some(&vault), &view, &k);
    } else {
        reconcile_per_item_after_connect(state, vault_id, None, &view, &k);
    }

    let cache = crate::server::handlers::approve::bootstrap_cache_from_view(&view, state);
    state.unlock_vault(vault_id.to_string(), cache, k);
    tracing::info!(vault = %vault_id, conn = %conn_id, "oauth refresh: rotated refresh_token persisted");
    true
}

/// Rebuild a [`ProtectedState`] `M` from a folded per-item view — the inverse of
/// [`VaultPlaintextView::from_protected_state`]. Lets the connect state machine
/// (which reads/writes `M`'s aux + secrets) run against a web-enrolled per-item
/// vault that has no whole-blob `vault.dat`.
fn build_m_from_view(
    view: &crate::storage::plaintext::VaultPlaintextView,
) -> Result<ProtectedState, String> {
    let mut m = ProtectedState::new();
    m.aux = serde_json::to_value(&view.aux).map_err(|e| format!("aux to json: {}", e))?;
    for (name, bytes) in &view.native_secrets {
        m.put_secret(name.clone(), bytes.clone());
    }
    Ok(m)
}

/// Daemon-side persist of an already-mutated view — the grant-approved
/// equivalent of the CLI's `seal_and_submit_write` for an aux edit (e.g.
/// `sc service rm` / `sc service add`). Reseals the whole-blob `vault.dat` when
/// one backs this vault, reconciles the per-item store (diff + version bump,
/// contract §4), and refreshes the in-memory cache so the change is live for the
/// broker. Does NOT push — the caller spawns the sync fan-out AFTER its write
/// guard drops (the push path re-takes the per-vault write lock, which is not
/// reentrant), exactly as `ActType::Write` does. `k` is the state key recovered
/// from the grant's `W_c` (via `open_view_for_grant_keep_key`), so the CLI never
/// touches the PRF-derived user key — a `sc service` write works over SSH
/// through the plain grant link.
pub(crate) fn persist_mutated_view(
    state: &Arc<AppState>,
    vault_id: &str,
    view: &crate::storage::plaintext::VaultPlaintextView,
    k: &[u8],
) -> Result<(), String> {
    let m = build_m_from_view(view)?;
    let vault_path = state
        .config
        .state_dir
        .join("vaults")
        .join(vault_id)
        .join("vault.dat");
    let vault_dat = crate::storage::sealed_vault::read(&vault_path)
        .ok()
        .flatten();
    if let Some(mut vault) = vault_dat {
        crate::server::handlers::metadata::reseal_body_with_key(k, &mut vault, &m)
            .map_err(|e| format!("reseal vault.dat: {}", e))?;
        crate::storage::sealed_vault::write_atomic(&vault_path, &vault)
            .map_err(|e| format!("write vault.dat: {}", e))?;
        reconcile_per_item_after_connect(state, vault_id, Some(&vault), view, k);
    } else {
        reconcile_per_item_after_connect(state, vault_id, None, view, k);
    }
    let cache = crate::server::handlers::approve::bootstrap_cache_from_view(view, state);
    state.unlock_vault(
        vault_id.to_string(),
        cache,
        zeroize::Zeroizing::new(k.to_vec()),
    );
    Ok(())
}

/// Apply the post-connect state (new refresh-token secret + connecting→
/// connections MOVE) to the local per-item store as version-bumped item
/// upserts/tombstones, then persist it. Best-effort; logs and returns on any
/// error (the whole-blob vault.dat already holds the durable state).
fn reconcile_per_item_after_connect(
    state: &Arc<AppState>,
    vault_id: &str,
    vault: Option<&crate::storage::SealedVault>,
    view: &crate::storage::plaintext::VaultPlaintextView,
    k: &[u8],
) {
    use crate::storage::sealed_vault::{Keyset, PerItemVault};
    let Ok(path) = state.vaults.per_item_path(vault_id) else {
        return;
    };
    // Reuse the existing per-item store if present (so versions/cursors are
    // preserved); otherwise bootstrap one from the whole-blob keyset. A
    // web-enrolled per-item vault ALWAYS has a store, so `vault` is `None` there
    // and the bootstrap branch is only reached on the vault.dat path.
    let mut pv = match crate::storage::sealed_vault::read_per_item(&path) {
        Ok(Some(pv)) => pv,
        _ => {
            let Some(vault) = vault else { return };
            PerItemVault {
                keyset: Keyset {
                    version: vault.version,
                    registry: vault.registry.clone(),
                    credentials: vault.credentials.clone(),
                    keyset_version: 0,
                    // Bootstrapped from a v1 whole-blob vault → v1 keyset.
                    uik: None,
                },
                items: std::collections::BTreeMap::new(),
                items_seq: 0,
                keyset_seq: 0,
            }
        }
    };
    match pv.reconcile_from_view::<sudp::primitives::StdPrimitives>(
        crate::storage::item::VaultKeys::single(k),
        vault_id,
        view,
    ) {
        Ok(changed) => {
            if changed.is_empty() {
                return;
            }
            if let Err(e) = crate::storage::sealed_vault::write_per_item_atomic(&path, &pv) {
                tracing::warn!(vault = %vault_id, "per-item connect reconcile write failed: {}", e);
                return;
            }
            tracing::info!(
                vault = %vault_id,
                changed = changed.len(),
                "per-item store updated after connect (refresh-token + connection MOVE)"
            );
        }
        Err(e) => {
            tracing::warn!(vault = %vault_id, "per-item connect reconcile failed: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ProtectedState` whose `aux.connecting` carries one in-flight connect.
    /// The rest of the aux is a minimal valid v3 shell (only `connecting` matters
    /// to these functions).
    fn with_connecting(conn: &str, service: &str, code: &str) -> ProtectedState {
        let mut m = ProtectedState::new();
        m.aux = serde_json::json!({
            "version": 3,
            "stores": {},
            "store_order": [],
            "connecting": {
                conn: { "service": service, "oauth2": { "code": code, "code_verifier": "verif-xyz" } }
            }
        });
        m
    }

    fn tokens(rt: Option<&str>) -> ExchangedTokens {
        ExchangedTokens {
            refresh_token: rt.map(|s| s.to_string()),
            access_token: "at-123".to_string(),
            expires_at: 9_999_999_999,
            id_token: None,
        }
    }

    /// A minimal ExchangeConfig for apply_exchange_result tests — only the
    /// write-side fields matter (endpoints/client are exchange-side).
    fn cfg(role: &str) -> ExchangeConfig {
        ExchangeConfig {
            token_url: "https://example.test/token".into(),
            client_id: "client".into(),
            client_secret: None,
            style: OAuthStyle::Form,
            redirect_uri: "http://127.0.0.1:8765/cb".into(),
            secret_role: role.to_string(),
            id_token_role: None,
            exposes: vec![],
        }
    }

    /// The compiled-in defaults include the gmail service + the google provider
    /// literal, so resolve_exchange_config finds a real config.
    fn gmail_registry() -> crate::service::ServiceRegistry {
        crate::service::ServiceRegistry::load()
    }

    /// No per-vault custom services — most tests exercise the built-in path.
    fn no_custom() -> std::collections::HashMap<String, crate::service::ServiceDef> {
        std::collections::HashMap::new()
    }

    #[test]
    fn collect_pending_reads_aux_connecting() {
        let m = with_connecting("gmail", "gmail", "code-AUX");
        let got = collect_pending(&m);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "gmail");
        assert_eq!(got[0].1.service, "gmail");
        assert_eq!(got[0].1.oauth2.code, "code-AUX");
    }

    #[test]
    fn collect_pending_empty_when_none() {
        let mut m = ProtectedState::new();
        m.aux = serde_json::json!({ "version": 3, "stores": {}, "store_order": [] });
        assert!(collect_pending(&m).is_empty());
    }

    #[test]
    fn collect_pending_skips_terminally_failed() {
        // A connect whose code was invalid_grant carries a terminal `error`.
        // It must NOT be re-collected (else we re-exchange a dead code every
        // sync tick + re-push it, forming a retry storm). It stays in the aux so
        // the console can show "reconnect" — just isn't retried.
        let mut m = with_connecting("gmail", "gmail", "code-DEAD");
        m.aux["connecting"]["gmail"]["oauth2"]["error"] =
            serde_json::json!("authorization expired or already used");
        assert!(
            collect_pending(&m).is_empty(),
            "an error-stamped connect must not be treated as pending"
        );
    }

    #[test]
    fn collect_pending_skips_entry_awaiting_its_code() {
        // An auto-catch connect seals { code_verifier, state } with NO code yet.
        // collect_pending must skip it (exchanging an empty code earns a bogus
        // invalid_grant) — until the 8765 listener injects the caught code.
        let mut m = with_connecting("gmail", "gmail", ""); // empty code
        m.aux["connecting"]["gmail"]["oauth2"]["state"] = serde_json::json!("st-123");
        assert!(
            collect_pending(&m).is_empty(),
            "an entry awaiting its redirect code must not be treated as pending"
        );
        // Inject the caught code → it becomes collectable for exchange.
        let mut codes = std::collections::BTreeMap::new();
        codes.insert("gmail".to_string(), "code-CAUGHT".to_string());
        inject_codes(&mut m, &codes);
        let got = collect_pending(&m);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1.oauth2.code, "code-CAUGHT");
    }

    #[test]
    fn inject_codes_fills_empty_only() {
        // A racing manual paste may have already put a code on the entry — the
        // caught code must NOT overwrite it (whichever landed first wins).
        let mut m = with_connecting("gmail", "gmail", "already-there");
        let mut codes = std::collections::BTreeMap::new();
        codes.insert("gmail".to_string(), "new-code".to_string());
        inject_codes(&mut m, &codes);
        assert_eq!(
            aux_map::<Connecting>(&m, "connecting")["gmail"].oauth2.code,
            "already-there",
        );
    }

    #[test]
    fn apply_exchange_default_writes_bare_and_moves() {
        // Default connection: conn == service → bare refresh_token name, no map.
        let mut m = with_connecting("gmail", "gmail", "code-AUX");
        apply_exchange_result(
            &mut m,
            "gmail",
            "gmail",
            None,
            None,
            &cfg("GMAIL_REFRESH_TOKEN"),
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("GMAIL_REFRESH_TOKEN").unwrap(), b"rt-NEW");
        assert!(
            aux_map::<Connecting>(&m, "connecting").is_empty(),
            "connecting entry must be dropped after exchange"
        );
        let conns = aux_map::<Connection>(&m, "connections");
        assert_eq!(
            conns.get("gmail").and_then(|c| c.service.as_deref()),
            Some("gmail")
        );
        assert!(
            conns.get("gmail").and_then(|c| c.keys.as_ref()).is_none(),
            "default conn stores no keys map"
        );
    }

    #[test]
    fn apply_exchange_named_writes_suggested_bare_key_and_records_binding() {
        // Named connection: conn != service → suggested `<ROLE>_<QUALIFIER>`
        // BARE key, recorded in the connection's `keys` map.
        let mut m = with_connecting("gmail_work", "gmail", "code-AUX");
        apply_exchange_result(
            &mut m,
            "gmail_work",
            "gmail",
            None,
            None,
            &cfg("GMAIL_REFRESH_TOKEN"),
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("GMAIL_REFRESH_TOKEN_WORK").unwrap(), b"rt-NEW");
        assert!(
            m.secrets.get("GMAIL_REFRESH_TOKEN").is_none(),
            "named conn must not clobber the default's key"
        );
        let conns = aux_map::<Connection>(&m, "connections");
        let rec = conns.get("gmail_work").expect("record moved");
        assert_eq!(rec.service.as_deref(), Some("gmail"));
        assert_eq!(
            rec.keys
                .as_ref()
                .and_then(|k| k.get("GMAIL_REFRESH_TOKEN"))
                .map(String::as_str),
            Some("GMAIL_REFRESH_TOKEN_WORK"),
        );
    }

    #[test]
    fn apply_exchange_named_honors_creator_chosen_keys() {
        // A creator-supplied binding (e.g. "reuse my existing key") wins over
        // the suggestion, for both the write and the recorded map.
        let mut m = with_connecting("gmail_work", "gmail", "code-AUX");
        let mut keys = BTreeMap::new();
        keys.insert(
            "GMAIL_REFRESH_TOKEN".to_string(),
            "MY_WORK_GMAIL_RT".to_string(),
        );
        apply_exchange_result(
            &mut m,
            "gmail_work",
            "gmail",
            None,
            Some(keys),
            &cfg("GMAIL_REFRESH_TOKEN"),
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("MY_WORK_GMAIL_RT").unwrap(), b"rt-NEW");
        let conns = aux_map::<Connection>(&m, "connections");
        assert_eq!(
            conns
                .get("gmail_work")
                .and_then(|c| c.keys.as_ref())
                .and_then(|k| k.get("GMAIL_REFRESH_TOKEN"))
                .map(String::as_str),
            Some("MY_WORK_GMAIL_RT"),
        );
    }

    #[test]
    fn apply_exchange_carries_pinned_hosts_into_connection() {
        let mut m = with_connecting("acme-forge", "acme", "code-AUX");
        apply_exchange_result(
            &mut m,
            "acme-forge",
            "acme",
            Some(vec!["tenant.acme.dev".to_string()]),
            None,
            &cfg("ACME_TOKEN"),
            &tokens(Some("rt-NEW")),
        );
        let conns = aux_map::<Connection>(&m, "connections");
        assert_eq!(
            conns.get("acme-forge").and_then(|c| c.hosts.clone()),
            Some(vec!["tenant.acme.dev".to_string()]),
        );
    }

    #[test]
    fn apply_exchange_derives_exposes_from_id_token() {
        use base64::Engine as _;
        let enc = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        let claims = serde_json::json!({
            "https://api.openai.com/auth": { "chatgpt_account_id": "acct-42" }
        });
        let idt = format!(
            "{}.{}.{}",
            enc(b"{}"),
            enc(claims.to_string().as_bytes()),
            enc(b"s")
        );

        let mut m = with_connecting("openai_codex", "openai_codex", "code-AUX");
        let mut c = cfg("OPENAI_CODEX_REFRESH_TOKEN");
        c.exposes = vec![(
            "account_id".to_string(),
            vec![
                "https://api.openai.com/auth".to_string(),
                "chatgpt_account_id".to_string(),
            ],
        )];
        let mut t = tokens(Some("rt-NEW"));
        t.id_token = Some(idt);
        apply_exchange_result(&mut m, "openai_codex", "openai_codex", None, None, &c, &t);
        assert_eq!(m.secret("OPENAI_CODEX_REFRESH_TOKEN").unwrap(), b"rt-NEW");
        // Derived role stored UPPERCASED at the bare (default-conn) address.
        assert_eq!(m.secret("ACCOUNT_ID").unwrap(), b"acct-42");
    }

    #[test]
    fn apply_exchange_overwrites_existing_refresh_token() {
        let mut m = with_connecting("gmail", "gmail", "code-A");
        m.put_secret("GMAIL_REFRESH_TOKEN", b"rt-OLD".to_vec());
        apply_exchange_result(
            &mut m,
            "gmail",
            "gmail",
            None,
            None,
            &cfg("GMAIL_REFRESH_TOKEN"),
            &tokens(Some("rt-NEW")),
        );
        assert_eq!(m.secret("GMAIL_REFRESH_TOKEN").unwrap(), b"rt-NEW");
    }

    #[tokio::test]
    async fn run_pending_success_moves_and_writes() {
        let services = gmail_registry();
        let role = services
            .service_env_key("gmail")
            .expect("gmail has a secret role");
        let mut m = with_connecting("gmail", "gmail", "code-AUX");

        let mut seen = None;
        let report = run_pending(&services, &no_custom(), &mut m, |conn, cfg, p| {
            seen = Some((
                conn.clone(),
                cfg.token_url.clone(),
                cfg.redirect_uri.clone(),
                p.oauth2.code.clone(),
            ));
            async move { Ok(tokens(Some("rt-NEW"))) }
        })
        .await;

        assert_eq!(report.completed, vec!["gmail".to_string()]);
        assert!(
            aux_map::<Connecting>(&m, "connecting").is_empty(),
            "connecting cleared"
        );
        assert_eq!(
            aux_map::<Connection>(&m, "connections")
                .get("gmail")
                .and_then(|c| c.service.clone()),
            Some("gmail".to_string()),
        );
        assert_eq!(m.secret(&role).unwrap(), b"rt-NEW");
        let (conn, token_url, redirect_uri, code) = seen.expect("exchange called");
        assert_eq!(conn, "gmail");
        assert_eq!(code, "code-AUX");
        assert!(
            token_url.starts_with("https://oauth2.googleapis.com/token"),
            "token_url must come from the google provider literal, got {token_url}"
        );
        assert!(
            redirect_uri.starts_with("http://127.0.0.1"),
            "redirect_uri must come from the provider/loopback default, got {redirect_uri}"
        );
    }

    #[tokio::test]
    async fn run_pending_failure_leaves_connecting() {
        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-EXPIRED");

        let report = run_pending(
            &services,
            &no_custom(),
            &mut m,
            |_conn, _cfg, _p| async move {
                Err("oauth2 code-exchange returned HTTP 400 — invalid_grant".to_string())
            },
        )
        .await;

        assert!(
            report.completed.is_empty(),
            "a failed exchange completes nothing"
        );
        assert_eq!(
            report.failed.len(),
            1,
            "invalid_grant is a terminal failure"
        );
        assert!(
            aux_map::<Connecting>(&m, "connecting").contains_key("gmail"),
            "connecting must survive a failed exchange (user retries within TTL)"
        );
        assert!(aux_map::<Connection>(&m, "connections").is_empty());
    }

    #[test]
    fn terminal_exchange_reason_classifies_rejections_vs_transients() {
        // 4xx rejections are terminal, with the provider's detail surfaced.
        let missing_secret = terminal_exchange_reason(
            "oauth2 code-exchange returned HTTP 400 Bad Request — {\"error\":\"invalid_request\",\"error_description\":\"client_secret is missing.\"}",
        );
        assert_eq!(
            missing_secret.as_deref(),
            Some("provider rejected the exchange: client_secret is missing.")
        );
        assert!(terminal_exchange_reason("… invalid_grant …").is_some());
        assert!(
            terminal_exchange_reason("oauth2 code-exchange returned HTTP 401 — nope").is_some()
        );
        // Network errors, 5xx, timeouts, and rate limits stay retryable.
        assert!(
            terminal_exchange_reason("oauth2 code-exchange request failed: connection reset")
                .is_none()
        );
        assert!(
            terminal_exchange_reason("oauth2 code-exchange returned HTTP 500 — oops").is_none()
        );
        assert!(
            terminal_exchange_reason("oauth2 code-exchange returned HTTP 429 — slow down")
                .is_none()
        );
        assert!(
            terminal_exchange_reason("oauth2 code-exchange returned HTTP 408 — timeout").is_none()
        );
    }

    #[tokio::test]
    async fn run_pending_rejection_marks_failed_transient_does_not() {
        let services = gmail_registry();

        // A 400 rejection (not invalid_grant) stamps a terminal error.
        let mut m = with_connecting("gmail", "gmail", "code-A");
        let report = run_pending(&services, &no_custom(), &mut m, |_conn, _cfg, _p| async move {
            Err("oauth2 code-exchange returned HTTP 400 Bad Request — {\"error\":\"invalid_request\",\"error_description\":\"client_secret is missing.\"}".to_string())
        })
        .await;
        assert_eq!((report.completed.len(), report.failed.len()), (0, 1));
        let entry = &aux_map::<Connecting>(&m, "connecting")["gmail"];
        assert!(
            entry
                .oauth2
                .error
                .as_deref()
                .unwrap_or("")
                .contains("client_secret is missing."),
            "the provider's reason must surface on the entry: {:?}",
            entry.oauth2.error
        );

        // A 5xx stays pending with NO error (retried next sync), but IS surfaced
        // as `unreached` so `sc sync` can say "couldn't reach the provider".
        let mut m = with_connecting("gmail", "gmail", "code-B");
        let report = run_pending(
            &services,
            &no_custom(),
            &mut m,
            |_conn, _cfg, _p| async move {
                Err("oauth2 code-exchange returned HTTP 500 — oops".to_string())
            },
        )
        .await;
        assert_eq!((report.completed.len(), report.failed.len()), (0, 0));
        assert_eq!(
            report.unreached.len(),
            1,
            "a transient failure is reported as unreached"
        );
        assert!(aux_map::<Connecting>(&m, "connecting")["gmail"]
            .oauth2
            .error
            .is_none());
    }

    #[tokio::test]
    async fn run_pending_already_redeemed_skips_without_failing() {
        // A code THIS daemon already redeemed can be resurrected in `connecting`
        // by a stale write (buggy web Save, cross-device echo, or a pull that
        // re-introduces the entry before our success push lands). Re-exchanging
        // it would earn `invalid_grant`; the exchange closure returns the
        // ALREADY_REDEEMED sentinel instead. The machine must SKIP it: nothing
        // reported, and the entry LEFT UNTOUCHED (no error — a redeemed code is
        // not a failure, so it must never clobber the live connection).
        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-USED");
        let report = run_pending(
            &services,
            &no_custom(),
            &mut m,
            |_conn, _cfg, _p| async move { Err(ALREADY_REDEEMED.to_string()) },
        )
        .await;
        assert_eq!(
            (
                report.completed.len(),
                report.failed.len(),
                report.unreached.len()
            ),
            (0, 0, 0),
            "a redeemed-code skip must report nothing"
        );
        assert!(
            !report.changed(),
            "nothing mutated ⇒ caller must not persist/push"
        );
        let entry = &aux_map::<Connecting>(&m, "connecting")["gmail"];
        assert!(
            entry.oauth2.error.is_none(),
            "a redeemed code must NOT be stamped failed: {:?}",
            entry.oauth2.error
        );
        assert_eq!(entry.oauth2.code, "code-USED", "the entry is left intact");
    }

    #[tokio::test]
    async fn run_pending_no_refresh_token_leaves_connecting() {
        let services = gmail_registry();
        let mut m = with_connecting("gmail", "gmail", "code-A");

        let report = run_pending(
            &services,
            &no_custom(),
            &mut m,
            |_conn, _cfg, _p| async move {
                Ok(tokens(None)) // consent without offline access → no refresh_token
            },
        )
        .await;

        assert!(report.completed.is_empty());
        assert!(
            aux_map::<Connecting>(&m, "connecting").contains_key("gmail"),
            "no durable token ⇒ leave connecting"
        );
    }

    #[tokio::test]
    async fn run_pending_unknown_service_leaves_connecting() {
        let services = gmail_registry();
        let mut m = with_connecting("whatever", "nosuchservice", "code-A");

        let mut called = false;
        let report = run_pending(&services, &no_custom(), &mut m, |_conn, _cfg, _p| {
            called = true;
            async move { Ok(tokens(Some("rt"))) }
        })
        .await;

        assert!(report.completed.is_empty());
        assert!(!called, "exchange must not run when no config resolves");
        assert!(aux_map::<Connecting>(&m, "connecting").contains_key("whatever"));
    }

    #[test]
    fn resolve_exchange_config_for_gmail_uses_public_desktop_client() {
        let services = gmail_registry();
        let cfg = resolve_exchange_config(&services, &no_custom(), "gmail")
            .expect("gmail resolves to an oauth2 exchange config");
        assert!(cfg
            .token_url
            .starts_with("https://oauth2.googleapis.com/token"));
        assert!(
            cfg.client_id.ends_with(".apps.googleusercontent.com"),
            "client_id must be the google provider literal"
        );
        // The public Desktop client ships a (non-confidential) secret.
        assert!(cfg.client_secret.is_some());
        assert!(matches!(cfg.style, OAuthStyle::Form));
        assert!(cfg.redirect_uri.starts_with("http://127.0.0.1"));
        assert!(
            !cfg.secret_role.is_empty(),
            "gmail service declares a secret role"
        );
    }

    #[test]
    fn resolve_exchange_config_none_for_unknown() {
        let services = gmail_registry();
        assert!(resolve_exchange_config(&services, &no_custom(), "nosuchservice").is_none());
    }

    #[test]
    fn resolve_exchange_config_finds_a_per_vault_custom_service() {
        // A user-authored inline [oauth2] service lives ONLY in aux.services,
        // never the built-in registry — the finisher must resolve it via the
        // `custom` map (regression: without it a custom OAuth connect could
        // never complete and retried forever).
        let services = gmail_registry();
        let toml_src = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["REFRESH_TOKEN"]

[auth]
type = "oauth2"
authorization_url = "https://auth.acme.dev/authorize"
token_url = "https://auth.acme.dev/token"
client_id = "acme-public"
refresh_token = "REFRESH_TOKEN"
"#;
        let def: crate::service::ServiceDef =
            toml::from_str(toml_src).expect("valid custom oauth2 def");
        let mut custom = std::collections::HashMap::new();
        custom.insert("acme".to_string(), def);

        // Unknown to the built-in registry alone…
        assert!(resolve_exchange_config(&services, &no_custom(), "acme").is_none());
        // …resolvable once the vault's own custom def is supplied.
        let cfg = resolve_exchange_config(&services, &custom, "acme")
            .expect("custom inline oauth2 service resolves");
        assert_eq!(cfg.token_url, "https://auth.acme.dev/token");
        assert_eq!(cfg.client_id, "acme-public");
        assert_eq!(cfg.secret_role, "REFRESH_TOKEN");
    }

    #[test]
    fn resolve_exchange_config_custom_shadows_same_id_registry() {
        // custom-FIRST precedence: when a vault-authored def and a registry
        // service share an id, the USER's def wins — so shipping a first-party
        // service never silently repoints an existing custom connection (a user's
        // `gmail` that is really something else keeps its own wiring). The
        // registry defines `gmail`; a same-id custom def with a distinct token
        // endpoint must shadow it.
        let services = gmail_registry();
        // Sanity: the registry really defines `gmail` (else this proves nothing).
        assert!(
            resolve_exchange_config(&services, &no_custom(), "gmail").is_some(),
            "registry must define gmail for the shadow test to be meaningful"
        );
        let toml_src = r#"
[service]
id = "gmail"
name = "Custom shadow of gmail"
hosts = ["api.example.test"]
secrets = ["REFRESH_TOKEN"]

[auth]
type = "oauth2"
authorization_url = "https://shadow.test/authorize"
token_url = "https://shadow.test/token"
client_id = "shadow-client"
refresh_token = "REFRESH_TOKEN"
"#;
        let def: crate::service::ServiceDef =
            toml::from_str(toml_src).expect("valid custom oauth2 def");
        let mut custom = std::collections::HashMap::new();
        custom.insert("gmail".to_string(), def);

        let cfg = resolve_exchange_config(&services, &custom, "gmail")
            .expect("resolves with a same-id custom def present");
        // The CUSTOM endpoint + client win, not the registry's Google ones.
        assert_eq!(cfg.token_url, "https://shadow.test/token");
        assert_eq!(cfg.client_id, "shadow-client");
    }
}
