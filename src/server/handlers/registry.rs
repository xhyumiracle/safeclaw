//! Service discovery — two endpoints, one shared catalog, TWO arrays.
//!
//! - `GET /registry` — static service catalog. What SafeClaw *supports*,
//!   vault-agnostic. Drives /try landing, docs, public browse. No vault
//!   state, and `connections` is empty. Also produced offline (no server) via
//!   `sc registry` / [`render_catalog`] for CI.
//!
//! - `GET /v/{vid}/registry` — live, per-vault view. The same `services` catalog
//!   PLUS a `connections` array (1:1 with `aux.connections`, carrying the DERIVED
//!   `connected` flag + ready-made `phantoms` list — the only ids the proxy
//!   resolves), plus top-level `vault_entries` (native-secrets item names; `null`
//!   when locked), `console_url`, `locked`. This is the endpoint the agent skill
//!   points at.
//!
//! The two arrays are the two altitudes: `services` = what's supported (browse
//! catalog, no `connected`/`phantoms`); `connections` = what's usable right now.
//!
//! Query params (all optional, compose, and apply to BOTH arrays):
//! - `?include=policy` adds the explicit `policy.rules` list back into each
//!   service (console UI). Default omits it.
//! - `?ids=a,b` keeps only those service/connection ids (unknown ids drop).
//! - `?view=summary` returns thin rows (drops the heavy fields), keeping identity
//!   + connection state. The agent's two-step: `?view=summary` to orient cheaply,
//!   then `?ids=<id>` for full detail on the one it's about to call.

use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::host::{phantoms_for, phantoms_for_raw, resolved_hosts};
use crate::error::Result;
use crate::server::handlers::op::validate_vault_id;
use crate::service::{ServiceDef, ServiceRegistry};
use crate::state::{AppState, VaultState};
use crate::storage::plaintext::{secret_key_for, Connection};

/// The current registry wire version.
const REGISTRY_VERSION: u32 = 4;

#[derive(Debug, Deserialize)]
pub struct RegistryQuery {
    /// Comma-separated extras. Today only `policy` is recognised — it
    /// expands `policy.rules` per service. Unknown values are ignored.
    #[serde(default)]
    pub include: Option<String>,
    /// Comma-separated ids to keep (applies to services AND connections).
    /// Absent = all. Unknown ids silently drop.
    #[serde(default)]
    pub ids: Option<String>,
    /// `summary` = thin rows (drops the heavy fields), keeping identity +
    /// connection state. Anything else (incl. absent) = full.
    #[serde(default)]
    pub view: Option<String>,
}

impl RegistryQuery {
    fn include_policy_rules(&self) -> bool {
        self.include
            .as_deref()
            .map(|s| s.split(',').any(|t| t.trim() == "policy"))
            .unwrap_or(false)
    }

    fn is_summary(&self) -> bool {
        self.view.as_deref() == Some("summary")
    }

    /// The `?ids=` allow-set, or `None` for "all". Blanks are trimmed out;
    /// an all-blank list (`?ids=`) reads as an empty set → matches nothing.
    fn ids_filter(&self) -> Option<HashSet<String>> {
        self.ids.as_deref().map(|s| {
            s.split(',')
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .map(|t| t.to_string())
                .collect()
        })
    }

    /// Parse a raw URL query string (`include=..&ids=..&view=..`) — used by the
    /// 23294 API face, which self-answers origin-form requests and so has no
    /// axum `Query` extractor. Unknown keys are ignored.
    pub fn from_query_str(raw: &str) -> Self {
        let mut include = None;
        let mut ids = None;
        let mut view = None;
        for pair in raw.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let val = urlencoding::decode(v)
                .map(|c| c.into_owned())
                .unwrap_or_else(|_| v.to_string());
            match k {
                "include" => include = Some(val),
                "ids" => ids = Some(val),
                "view" => view = Some(val),
                _ => {}
            }
        }
        RegistryQuery { include, ids, view }
    }
}

/// A catalog SERVICE row — what SafeClaw supports. Carries NO `connected` /
/// `phantoms` (a phantom names a CONNECTION, not a service; connection state
/// lives on the `connections` array).
#[derive(Debug, Serialize)]
pub struct RegistryService {
    pub id: String,
    pub name: String,
    /// Classification tags ("ai", "app", "messaging", …). Always serialized
    /// (empty for untagged custom services) so consumers see a stable shape.
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Anchored egress hosts (service-declared exact FQDNs / `*.suffix`).
    /// Omitted in `?view=summary`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Declared durable secret KEYs (uniform for ALL services — §3). For an
    /// oauth2 service this is its refresh-token KEY. Omitted in `?view=summary`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<RegistryServicePolicy>,
    /// The PUBLIC `[auth]` half — mechanism type plus, for oauth2, provider +
    /// scopes — mirrors the toml's `[auth] type = …`. The confidential wiring
    /// (client_secret / token_url) is never exposed (cloud-blind). Absent for
    /// static services / summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<RegistryServiceAuth>,
    /// Auxiliary: where a human mints this service's key/token ([service]
    /// `secret_url`). Display-only. Absent for summary / services without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_url: Option<String>,
    /// Public OAuth consent params (authorization_url / client_id / scopes /
    /// pkce / redirect_uri) — what a frontend needs to START a cloud-blind
    /// connect. Absent for non-oauth2 / summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<crate::service::ConnectDescriptor>,
    /// Plain agent-facing `setup` prose (v4). Present only on the per-vault
    /// registry, full view. The generic counterpart to `connect`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<String>,
}

/// The public `[auth]` summary on a service catalog row (browse view),
/// type-discriminated like the toml section it mirrors.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RegistryServiceAuth {
    Oauth2 {
        provider: String,
        scopes: Vec<String>,
    },
    Snaplii {},
}

/// An established CONNECTION row — 1:1 with `aux.connections` plus the DERIVED
/// `connected` flag and ready-made `phantoms`. These are the only ids the proxy
/// resolves, so discovery and resolution can't drift. Only present on the
/// per-vault endpoint (empty when locked / on the static catalog).
#[derive(Debug, Serialize)]
pub struct RegistryConnection {
    pub id: String,
    /// The service TYPE this instantiates, or absent for a RAW connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Anchored egress hosts (exact FQDNs). Omitted in `?view=summary`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// A RAW connection's explicit secret KEYs (§2). Absent for a service-backed
    /// connection (its secrets derive from the service). Omitted in summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
    /// `true` = every secret this connection needs is present at its address.
    pub connected: bool,
    /// Ready-made phantom strings (a LIST — §6). The agent copies these verbatim,
    /// never constructs them. Omitted in `?view=summary`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub phantoms: Vec<String>,
    /// `true` = this OAuth connection's refresh_token was rejected
    /// (invalid_grant) at token mint — user must reconnect. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_reauth: Option<bool>,
    /// `true` = the calling agent's reach mask excludes this connection
    /// (team §8.1 visible-but-locked: it exists, this agent is not enabled;
    /// naming it in a request gets an explicit `mask_not_enabled` refusal;
    /// the responsible member can enable it in the console). Only set on the
    /// agent-facing proxy surface; the console never sees it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RegistryServicePolicy {
    pub defaults: RegistryPolicyDefaults,
    /// Explicit per-action rules. Omitted unless `?include=policy`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<RegistryPolicyRule>>,
}

#[derive(Debug, Serialize)]
pub struct RegistryPolicyDefaults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RegistryPolicyRule {
    pub id: String,
    pub label: String,
    /// Single pattern serializes as a bare string (registry.json stays stable for
    /// one-match rules); a list serializes as a list (OR — see core `PolicyRule`).
    #[serde(
        rename = "match",
        serialize_with = "crate::core::policy::match_spec::serialize"
    )]
    pub match_pattern: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Structured field condition (`"vars.amount > 80"`) — surfaced so the
    /// console can show it beside the rule and offer it as an override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    /// The built-in access decision (`allow` | `ask` | `ask-always` | `deny`)
    /// the recipe declares for this action. The console shows it and lets the
    /// user override it per-connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RegistryResponse {
    pub version: u32,
    /// The browse catalog — what SafeClaw supports.
    pub services: Vec<RegistryService>,
    /// Established connections (1:1 with `aux.connections`, derived
    /// `connected`/`phantoms`). Empty on the static catalog + when locked.
    pub connections: Vec<RegistryConnection>,
    /// The policy tree baseline (risk map + default floors + categories).
    pub policy: serde_json::Value,
    // ── Per-vault overlay — only set by /v/{vid}/registry ────────────
    //
    // Deliberately no `vault_id` field (see git history) — exposing it would let
    // an agent bypass the SaaS apiKey gate by hitting the daemon's auth-free
    // `/v/{vid}/*` endpoints directly.
    /// PER-VAULT lock state (§6 — scoped to THIS vault, not the whole daemon).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
    /// Native-secrets item names present in this vault. `Some([..])` when
    /// unlocked, `Some(null)` when locked (distinguishes "nothing" from
    /// "can't see").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_entries: Option<Option<Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_url: Option<String>,
    /// Consent descriptors for the vault's own control-plane acts (acts.toml,
    /// raw templates — the client interpolates over the signed op it holds).
    /// Only on the published SSoT catalog (`sc registry --json` → registry.json,
    /// same opt-in as policy rules); the agent-facing `GET /registry` stays lean.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acts:
        Option<&'static std::collections::BTreeMap<String, crate::protocol::consent::ActConsent>>,
}

/// The secret roles that must be present for a service to be "connected": every
/// declared durable secret (uniform for ALL services — §3; an oauth2 service's
/// refresh-token KEY is in `secrets`). Empty ⇒ the service needs no credential.
fn required_keys(def: &ServiceDef) -> Vec<String> {
    def.service.secrets.clone()
}

fn policy_for(
    services: &ServiceRegistry,
    id: &str,
    include_rules: bool,
) -> Option<RegistryServicePolicy> {
    let p = services.policy_file(id)?;
    let defaults = p
        .default
        .as_ref()
        .map(|m| RegistryPolicyDefaults {
            read: m.get("read").cloned(),
            write: m.get("write").cloned(),
            ttl: m.get("ttl").and_then(|v| v.parse().ok()),
        })
        .unwrap_or(RegistryPolicyDefaults {
            read: None,
            write: None,
            ttl: None,
        });
    let rules = if include_rules {
        Some(
            p.rule
                .iter()
                .map(|r| {
                    let level = r
                        .level
                        .as_deref()
                        .and_then(crate::core::policy::AccessLevel::parse)
                        .map(|l| l.to_string());
                    RegistryPolicyRule {
                        id: r.id.clone(),
                        label: r.label.clone(),
                        match_pattern: r.match_pattern.clone(),
                        body: r.body.clone(),
                        when: r.when.clone(),
                        level,
                        ttl: r.ttl,
                    }
                })
                .collect(),
        )
    } else {
        None
    };
    Some(RegistryServicePolicy { defaults, rules })
}

/// A service's `setup` hint — plain agent-facing prose in v4. No template tokens.
fn render_setup(def: &ServiceDef) -> Option<String> {
    def.setup.clone()
}

/// Build one catalog SERVICE row (no connection state).
fn build_service(
    services: &ServiceRegistry,
    id: &str,
    def: &ServiceDef,
    include_policy_rules: bool,
    render_setup_hint: bool,
    summary: bool,
) -> RegistryService {
    if summary {
        return RegistryService {
            id: id.to_string(),
            name: def.service.name.clone(),
            tags: def.service.tags.clone(),
            description: None,
            hosts: vec![],
            secrets: vec![],
            policy: None,
            auth: None,
            secret_url: None,
            connect: None,
            setup: None,
        };
    }

    let policy = policy_for(services, id, include_policy_rules);
    let auth = def.auth.as_ref().map(|a| match a {
        crate::service::AuthDef::Oauth2(o) => RegistryServiceAuth::Oauth2 {
            // Wire shape stays a plain string; a fully-inline section (no
            // template) reads "custom" — same label ConnectDescriptor falls
            // back to.
            provider: o.provider.clone().unwrap_or_else(|| "custom".to_string()),
            scopes: o.scopes.clone(),
        },
        crate::service::AuthDef::Snaplii(_) => RegistryServiceAuth::Snaplii {},
    });

    RegistryService {
        id: id.to_string(),
        name: def.service.name.clone(),
        tags: def.service.tags.clone(),
        description: def.service.help.clone(),
        hosts: def.service.hosts.clone(),
        secrets: def.service.secrets.clone(),
        policy,
        auth,
        secret_url: def.service.secret_url.clone(),
        // Resolve the descriptor from the `def` in hand, not by id — the id
        // lookup only knows built-ins, so a per-vault custom oauth2 service
        // (passed here with its own def) would get `connect: null` and never
        // look connectable in the console.
        connect: def
            .oauth2()
            .and_then(|o| services.connect_descriptor_for(o)),
        setup: if render_setup_hint {
            render_setup(def)
        } else {
            None
        },
    }
}

/// Build one CONNECTION row from an `aux.connections` entry: derive `connected` +
/// the ready-made `phantoms` list. Service-backed → the service def's phantoms
/// (oauth ACCESS + exposes, or the declared direct secrets), connected when every
/// required role's bound key (§3 `keys` map, identity default) is present. Raw →
/// its explicit `secrets` (§2), connected when every declared KEY is present.
fn build_connection(
    conn_id: &str,
    conn: &Connection,
    def: Option<&ServiceDef>,
    native_keys: &HashSet<String>,
    external_keys: &HashSet<String>,
    summary: bool,
) -> RegistryConnection {
    let (connected, phantoms, secrets): (bool, Vec<String>, Option<Vec<String>>) = match &conn
        .service
    {
        Some(_service_id) => {
            let phantoms: Vec<String> = def
                .map(|d| phantoms_for(conn_id, d).into_values().collect())
                .unwrap_or_default();
            let connected = def
                .map(|d| {
                    let required = required_keys(d);
                    required.is_empty()
                        || required.iter().all(|role| {
                            let key = secret_key_for(Some(conn), role);
                            // One flat namespace: native (case-insensitive
                            // canonical) OR an external store's key (exact —
                            // external naming is case-sensitive).
                            native_keys.iter().any(|k| k.eq_ignore_ascii_case(&key))
                                || external_keys.contains(&key)
                        })
                })
                .unwrap_or(false);
            (connected, phantoms, None)
        }
        None => {
            let keys = conn.secrets.clone().unwrap_or_default();
            let connected = !keys.is_empty()
                && keys.iter().all(|k| {
                    native_keys.iter().any(|n| n.eq_ignore_ascii_case(k))
                        || external_keys.contains(k)
                });
            let phantoms: Vec<String> = phantoms_for_raw(conn_id, &keys).into_values().collect();
            (connected, phantoms, Some(keys))
        }
    };

    RegistryConnection {
        id: conn_id.to_string(),
        service: conn.service.clone(),
        hosts: if summary {
            Vec::new()
        } else {
            resolved_hosts(conn, def)
        },
        secrets: if summary { None } else { secrets },
        connected,
        phantoms: if summary { Vec::new() } else { phantoms },
        needs_reauth: None,
        locked: None,
    }
}

fn console_url(state: &AppState, vault_id: &str) -> String {
    // Deep-link to THIS vault so the agent can hand the user a link that lands
    // straight on their vault. Demo vaults (minted by /try) live on /try.
    let origin = state.config.origin.trim_end_matches('/');
    if vault_id.starts_with("demo-") {
        format!("{}/try", origin)
    } else {
        format!("{}/vault/{}", origin, vault_id)
    }
}

/// Render the static, vault-agnostic service catalog from a `ServiceRegistry`.
/// Pure — no `AppState`, no vault, no I/O — so `sc registry` / CI can produce the
/// exact catalog the daemon serves. `connections` is empty (no vault).
pub fn render_catalog(
    services: &ServiceRegistry,
    include_policy_rules: bool,
    ids: Option<&HashSet<String>>,
    summary: bool,
) -> Result<RegistryResponse> {
    let rendered: Vec<RegistryService> = services
        .iter_sorted()
        .into_iter()
        .filter(|(_, def)| !def.service.hidden)
        .filter(|(id, _)| ids.map_or(true, |set| set.contains(*id)))
        .map(|(id, def)| build_service(services, id, def, include_policy_rules, false, summary))
        .collect();
    Ok(RegistryResponse {
        version: REGISTRY_VERSION,
        services: rendered,
        connections: Vec::new(),
        policy: serde_json::to_value(crate::core::policy::Policy::default())?,
        locked: None,
        vault_entries: None,
        console_url: None,
        acts: include_policy_rules.then(crate::protocol::consent::act_catalog),
    })
}

/// `GET /registry` — static service catalog.
pub async fn catalog(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RegistryQuery>,
) -> Result<Json<Value>> {
    let body = render_catalog(
        &state.services,
        q.include_policy_rules(),
        q.ids_filter().as_ref(),
        q.is_summary(),
    )?;
    Ok(Json(serde_json::to_value(body)?))
}

/// `GET /v/{vid}/registry` — per-vault live view (catalog + connections).
pub async fn vault_registry(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Query(q): Query<RegistryQuery>,
) -> Result<Json<Value>> {
    Ok(Json(vault_registry_value(&state, &vault_id, &q, None)?))
}

/// The `/v/{vid}/registry` projection as a plain `Value`. Shared by the axum
/// control-plane handler (above) AND the 23294 API face (`proxy::api_face`), so
/// discovery can't drift between the two ports. Pure read — briefly locks
/// `vault_states`, no I/O.
pub fn vault_registry_value(
    state: &AppState,
    vault_id: &str,
    q: &RegistryQuery,
    agent_prefix: Option<&str>,
) -> Result<Value> {
    validate_vault_id(vault_id)?;
    let include_policy_rules = q.include_policy_rules();
    let ids_filter = q.ids_filter();
    let summary = q.is_summary();

    // Snapshot native_keys + connections + custom services + lock state under the
    // mutex, then drop it before rendering.
    #[allow(clippy::type_complexity)]
    let (native_keys, external_keys, custom_services, connections, locked): (
        HashSet<String>,
        HashSet<String>,
        Vec<(String, ServiceDef)>,
        std::collections::HashMap<String, Connection>,
        bool,
    ) = {
        let states = state.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => {
                let mut custom: Vec<(String, ServiceDef)> = cache
                    .custom_services
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                custom.sort_by(|a, b| a.0.cmp(&b.0));
                (
                    cache.native_keys.clone(),
                    cache.external_keys.lock().unwrap().clone(),
                    custom,
                    cache.connections.clone(),
                    false,
                )
            }
            _ => (
                HashSet::new(),
                HashSet::new(),
                Vec::new(),
                std::collections::HashMap::new(),
                true,
            ),
        }
    };

    // ── services[] — the catalog (built-in + custom), no connection state ─────
    let mut services: Vec<RegistryService> = state
        .services
        .iter_sorted()
        .into_iter()
        .filter(|(_, def)| !def.service.hidden)
        .filter(|(id, _)| ids_filter.as_ref().map_or(true, |set| set.contains(*id)))
        .map(|(id, def)| {
            build_service(
                &state.services,
                id,
                def,
                include_policy_rules,
                true,
                summary,
            )
        })
        .collect();
    for (id, def) in &custom_services {
        if ids_filter.as_ref().map_or(false, |set| !set.contains(id)) {
            continue;
        }
        if def.service.hidden {
            continue;
        }
        services.push(build_service(
            &state.services,
            id,
            def,
            include_policy_rules,
            true,
            summary,
        ));
    }
    services.sort_by(|a, b| a.id.cmp(&b.id));

    // ── connections[] — 1:1 with aux.connections + derived state ──────────────
    let mut conn_rows: Vec<RegistryConnection> = Vec::new();
    if !locked {
        for (conn_id, conn) in &connections {
            if ids_filter
                .as_ref()
                .map_or(false, |set| !set.contains(conn_id))
            {
                continue;
            }
            let def: Option<ServiceDef> = conn.service.as_deref().and_then(|s| {
                // custom-FIRST (see proxy::handler): the console shows the def a
                // connection actually resolves against.
                custom_services
                    .iter()
                    .find(|(k, _)| k == s)
                    .map(|(_, d)| d.clone())
                    .or_else(|| state.services.get(s).cloned())
            });
            let mut row = build_connection(
                conn_id,
                conn,
                def.as_ref(),
                &native_keys,
                &external_keys,
                summary,
            );
            if row.connected && state.oauth_needs_reauth(vault_id, conn_id) {
                row.needs_reauth = Some(true);
            }
            conn_rows.push(row);
        }
        conn_rows.sort_by(|a, b| a.id.cmp(&b.id));
        // Agent-facing reach mask (team §8.1): a masked-off connection stays
        // VISIBLE (the agent can conclude "exists, but I need enabling" instead
        // of "not configured") but is stripped to a minimal locked stub — no
        // hosts/secrets/phantoms.
        if let Some(agent) = agent_prefix {
            if let Some(whitelist) = state.agent_mask_whitelist(vault_id, agent) {
                use std::collections::HashSet as MaskSet;
                let allow: MaskSet<&str> = whitelist.iter().map(|s| s.as_str()).collect();
                for row in conn_rows.iter_mut() {
                    if !allow.contains(row.id.as_str()) {
                        row.hosts.clear();
                        row.secrets = None;
                        row.phantoms.clear();
                        row.needs_reauth = None;
                        row.connected = false;
                        row.locked = Some(true);
                    }
                }
            }
        }
    }

    let vault_entries = if locked {
        Some(None)
    } else {
        let mut entries: Vec<String> = native_keys.into_iter().collect();
        entries.extend(external_keys.iter().cloned());
        entries.sort();
        entries.dedup();
        Some(Some(entries))
    };

    let body = RegistryResponse {
        version: REGISTRY_VERSION,
        services,
        connections: conn_rows,
        policy: serde_json::to_value(crate::core::policy::Policy::default())?,
        locked: Some(locked),
        vault_entries,
        console_url: Some(console_url(state, vault_id)),
        acts: None,
    };
    Ok(serde_json::to_value(body)?)
}

#[cfg(test)]
mod setup_tests {
    use super::*;

    #[test]
    fn custom_oauth_service_gets_a_connect_descriptor() {
        // A per-vault custom [oauth2] service is passed to build_service with its
        // own def (it isn't in the built-in registry). Regression: resolving the
        // descriptor by id returned None for it, so the console never saw it as
        // connectable — resolve from the def instead.
        let services = crate::service::ServiceRegistry::load();
        let def: ServiceDef = toml::from_str(
            r#"
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
"#,
        )
        .unwrap();
        assert!(
            services.get("acme").is_none(),
            "precondition: acme is NOT a built-in",
        );
        let row = build_service(&services, "acme", &def, false, false, false);
        let d = row
            .connect
            .expect("custom oauth2 service must advertise a connect descriptor");
        assert_eq!(d.provider, "custom");
        assert_eq!(d.authorization_url, "https://auth.acme.dev/authorize");
        assert_eq!(d.client_id, "acme-public");
        // The descriptor mirrors the def 1:1 — token_url rides too.
        assert_eq!(d.token_url.as_deref(), Some("https://auth.acme.dev/token"));
    }

    #[test]
    fn render_setup_is_plain_passthrough() {
        let toml = r#"
setup = """
Put the phantom in the URL: sc run -- git clone https://x:__sc__github__@github.com/o/r
"""

[service]
id = "github"
name = "GitHub"
hosts = ["github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def: ServiceDef = toml::from_str(toml).unwrap();
        let s = render_setup(&def).expect("setup passthrough");
        assert!(s.contains("sc run --"), "{}", s);

        let no_setup: ServiceDef =
            toml::from_str("[service]\nid=\"x\"\nname=\"X\"\nhosts=[\"x.com\"]\n").unwrap();
        assert!(render_setup(&no_setup).is_none());
    }

    fn q(ids: Option<&str>, view: Option<&str>) -> RegistryQuery {
        RegistryQuery {
            include: None,
            ids: ids.map(|s| s.to_string()),
            view: view.map(|s| s.to_string()),
        }
    }

    #[test]
    fn ids_filter_parses_and_trims() {
        assert!(q(None, None).ids_filter().is_none());
        assert_eq!(
            q(Some("gmail,github"), None).ids_filter().unwrap(),
            ["gmail", "github"].iter().map(|s| s.to_string()).collect()
        );
        assert_eq!(
            q(Some(" gmail , "), None).ids_filter().unwrap(),
            ["gmail"].iter().map(|s| s.to_string()).collect()
        );
        assert!(q(Some(""), None).ids_filter().unwrap().is_empty());
    }

    #[test]
    fn view_summary_toggle() {
        assert!(!q(None, None).is_summary());
        assert!(!q(None, Some("full")).is_summary());
        assert!(q(None, Some("summary")).is_summary());
    }

    #[test]
    fn service_summary_drops_heavy_fields() {
        let reg = ServiceRegistry::compiled_only();
        let (id, def) = reg
            .iter_sorted()
            .into_iter()
            .next()
            .expect("a compiled service");

        let full = build_service(&reg, id, def, false, true, false);
        let sum = build_service(&reg, id, def, false, true, true);

        assert_eq!(sum.id, full.id);
        assert_eq!(sum.name, full.name);
        assert_eq!(sum.tags, full.tags);
        // Heavy fields drop from the summary wire (skip_serializing_if).
        assert!(sum.hosts.is_empty());
        assert!(sum.secrets.is_empty());
        assert!(sum.policy.is_none());
        assert!(sum.connect.is_none());
        assert!(sum.auth.is_none());
        assert!(sum.setup.is_none());
        // Full view carries the declared hosts + secrets.
        assert_eq!(full.hosts, def.service.hosts);
        assert_eq!(full.secrets, def.service.secrets);
    }

    #[test]
    fn connection_rows_derive_phantoms_and_connected() {
        // Raw connection: explicit secrets, connected when the KEY is present.
        let conn = Connection {
            name: None,
            service: None,
            hosts: Some(vec!["api.stripe.com".to_string()]),
            secrets: Some(vec!["STRIPE_KEY".to_string()]),
            keys: None,
        };
        let present: HashSet<String> = ["STRIPE_KEY".to_string()].into_iter().collect();
        let empty: HashSet<String> = HashSet::new();
        let row = build_connection("stripe_key", &conn, None, &present, &empty, false);
        assert!(row.connected);
        assert_eq!(row.phantoms, vec!["__sc__stripe_key__".to_string()]);
        assert_eq!(row.secrets, Some(vec!["STRIPE_KEY".to_string()]));
        assert_eq!(row.service, None);

        // Missing everywhere → not connected.
        let row = build_connection("stripe_key", &conn, None, &empty, &empty, false);
        assert!(!row.connected);

        // Key hosted ONLY by an external store (exact name) → connected: the
        // flat namespace doesn't care which store holds the bytes.
        let external: HashSet<String> = ["STRIPE_KEY".to_string()].into_iter().collect();
        let row = build_connection("stripe_key", &conn, None, &empty, &external, false);
        assert!(row.connected);
    }
}
