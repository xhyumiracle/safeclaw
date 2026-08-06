//! v4 vault plaintext shape — per `design/stores-and-items.md`.
//!
//! Physical layout (Design B): the decrypted protected state `M` =
//! `sudp::state::ProtectedState { targets, peers, aux }` carries:
//!
//! - `M.targets` — `native-secrets` item values. sudp's `TargetValue`
//!   zero-on-drop + b64-binary-safe encoding give us byte-safe storage
//!   for the only store kind that holds authoritative bytes locally.
//! - `M.aux`     — everything else (stores configuration, store_order,
//!   per-store items metadata for non-byte-storing stores). Parsed into
//!   [`VaultAux`].
//! - `M.peers`   — sudp-internal credential rewrap map. Untouched here.
//!
//! The doc's `vault.enc` example is a *logical* view that merges these
//! two physical pools; runtime code goes through [`VaultPlaintextView`]
//! to query items by name with resolution-order semantics.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sudp::state::ProtectedState;

use crate::core::policy::Policy;
use crate::error::{AppError, Result};

/// Current schema version. Hard-fail on any other value.
pub const PLAINTEXT_VERSION: u32 = 4;

/// Reserved store ID. `native-secrets` is always present in every vault.
pub const NATIVE_SECRETS_ID: &str = "native-secrets";

/// Reserved kind string, equal to the reserved store ID.
pub const NATIVE_SECRETS_KIND: &str = "native-secrets";

/// Category — how a store's items resolve. `Value` = bytes resolvable to a
/// single secret string. `File` is a LEGACY variant, retained only so vaults
/// sealed before the file-store removal still deserialize; no store creates it
/// now (restore point: tag `checkpoint/file-feature`). Declared per-store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Value,
    /// Legacy — retained for backward-compatible deserialization only.
    File,
}

/// A single store record inside `aux.stores`. `kind` selects the adapter;
/// `items` holds adapter-specific item metadata (shape varies by kind).
/// Adapter-specific config fields live alongside in `extra` for forward-
/// compat with stores we don't have parse rules for yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub kind: String,
    pub category: Category,
    /// Per-item metadata. For `native-secrets`, this map is empty in `aux`
    /// because byte values physically live in `ProtectedState.targets`. For
    /// external stores (gcp / 1p / aws — Phase 2+), shape is adapter-defined.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub items: BTreeMap<String, serde_json::Value>,
    /// Adapter-specific configuration (e.g. `project_id` for gcp).
    /// Preserved verbatim on round-trip so unknown fields don't drop.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// An **established** connection — an instance of a service (TYPE) the user has
/// connected. Keyed (in `VaultAux.connections`) by `connection_id`: a slug that
/// is the user's handle AND the routing/cache/audit unit. `== service_id` for
/// the default (unprefixed) connection; a distinct slug for a named one
/// (see `design/connection-schema.md` §2).
///
/// Status is **DERIVED**, never stored: present in `connections` with its
/// required secret(s) present → Connected; a required secret missing → Partly
/// configured. There is no status field to drift out of sync.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Connection {
    /// User-facing display name — the FULL string shown in lists ("GitHub ·
    /// Work Laptop", "Gmail", "Stripe Key"), verbatim as composed/typed at
    /// creation. Same field name + contract as a service's `name`: every
    /// creation path writes it; it is display-only (the conn id stays the
    /// technical handle for phantoms / policy / audit). Wire-optional ONLY
    /// for legacy rows (pre-name, CLI-created, or written as `label` — the
    /// serde alias) — absent = render the id.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "label")]
    pub name: Option<String>,
    /// The service (TYPE) this instantiates, or `None` for a **raw** connection
    /// (`sc set K --host h`) that references no service and anchors its own
    /// `hosts`. When set, hosts derive from the service (SSoT); an instance may
    /// only PIN exact FQDNs within a service's `*.suffix` wildcards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// The connection's anchored hosts. Required for a raw connection (the
    /// egress anchor). For a service-backed connection: `None` when the service
    /// declares exact hosts only (derived, no stored copy); the pinned exact
    /// FQDNs (⊆ the service's `*.suffix` entries) when the service is wildcard.
    /// Enforced exact-FQDN at egress; never a bare `*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    /// The UPPERCASE secret KEY names this connection uses. **REQUIRED for a raw
    /// connection** (`service: None`) — it answers "which secrets" directly, so
    /// discovery and cache-bootstrap read it instead of reverse-indexing the
    /// native-secrets namespace by casing. **OMITTED (`None`) for a service-backed
    /// connection**: its secrets derive from the service's declared `secrets`
    /// (including the oauth2 refresh-token KEY). One canonical answer, no drift.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<String>>,
    /// Service-backed connections only: explicit `ROLE → vault KEY` bindings
    /// (CONNECTION_SCHEMA.md §3). Sparse — a missing role binds to its own bare
    /// mainstream name (the default connection's identity binding), so a default
    /// connection normally stores no map at all. A NAMED connection's creator
    /// writes one (suggested `<ROLE>_<QUALIFIER>`, see [`suggested_secret_key`])
    /// so two accounts of one service never collide on a key; any binding may
    /// point at an existing vault key to share it. Raw connections never use
    /// this — their `secrets` list IS the binding (role == KEY).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<BTreeMap<String, String>>,
}

/// An **in-flight** connect handshake — everything the daemon needs to redeem
/// the OAuth code and produce the durable secret. On a successful exchange the
/// daemon writes the secret and **MOVES** the entry into `connections` (dropping
/// it here) — there is never a partial/duplicate record.
///
/// Relayed to the daemon *through the sealed vault* to stay cloud-blind: the
/// browser drives consent, seals `{ service, hosts?, oauth2: { code, code_verifier } }`
/// here, and the daemon (not the backend) performs the code→token exchange. The
/// generic identity (`service`, `hosts`) is top-level; the mechanism handshake
/// state nests under the mechanism key (`oauth2`) so a future auth mechanism
/// nests under ITS key without the schema getting messy. `redirect_uri` is NOT
/// here — it's a fixed property of the OAuth client, held in the service's
/// `[oauth2]` section.
/// Mirrors the frontend `lib/vault-grant.ts` `Connecting` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connecting {
    /// User-facing display name, carried through to the established
    /// [`Connection`] on exchange (see `Connection::name`).
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "label")]
    pub name: Option<String>,
    /// The service (TYPE) being instantiated.
    pub service: String,
    /// Exact FQDNs pinned at connect for a `*.suffix` wildcard service, carried
    /// through to the established [`Connection`] on exchange. Omitted (`None`)
    /// for an exact-hosts service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    /// Explicit `ROLE → vault KEY` bindings chosen at connect, carried through
    /// to the established [`Connection`] on exchange (see `Connection::keys`).
    /// Absent = the daemon derives the default binding at exchange time
    /// (identity for the default connection, [`suggested_secret_key`] for a
    /// named one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<BTreeMap<String, String>>,
    /// OAuth2 (RFC 6749 authorization_code + RFC 7636 PKCE) handshake state.
    /// Nested under the mechanism key — mirrors the service.toml `[oauth2]`.
    pub oauth2: ConnectingOAuth2,
}

/// The oauth2 handshake temps of an in-flight connect (RFC 6749 / 7636). These
/// are flow-standard, not per-service, so they live here rather than in the
/// service.toml `[oauth2]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectingOAuth2 {
    /// The single-use authorization code from the loopback redirect (RFC 6749).
    /// EMPTY until the code arrives — either the daemon's 8765 loopback listener
    /// auto-catches the redirect (`crate::auth::loopback`) or the user pastes it
    /// back (fallback). A pending entry with an empty `code` is "awaiting the
    /// redirect", not yet exchangeable (the daemon skips it); its `state` (below)
    /// is how the listener matches the incoming redirect to this entry.
    #[serde(default)]
    pub code: String,
    /// The PKCE code_verifier (RFC 7636) the browser generated for this flow.
    pub code_verifier: String,
    /// The `state` param (RFC 6749 §10.12) the browser generated for this flow.
    /// Sealed so the daemon's shared 8765 loopback listener can match an incoming
    /// `?code&state` redirect to THIS pending connect (one listener serves every
    /// provider; `state` is the unguessable router key). Absent on legacy
    /// paste-only entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Terminal exchange failure — set by the daemon when the code→token
    /// exchange fails non-recoverably (`invalid_grant`: the authorization code
    /// expired or was already used). The console renders "connection failed,
    /// reconnect" instead of a perpetual "connecting". Absent while the connect
    /// is still in flight (transient errors leave this unset so the next sync
    /// retries). Cleared when a fresh connect overwrites the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The vault KEY a connection's secret ROLE resolves to (CONNECTION_SCHEMA.md
/// §3). Every secret lives at a **bare**, env-valid, UPPERCASE KEY — the flat
/// pool is one env namespace, 1:1 with env/GCP-read-through import; nothing is
/// namespaced. The connection RECORD binds roles to keys: an explicit
/// `keys[ROLE]` entry wins (case-insensitive on the role), otherwise the role's
/// own mainstream name — the identity binding every default connection uses.
/// The address is **stored data, not a computed convention**, so writer and
/// reader can't drift.
pub fn secret_key_for(conn: Option<&Connection>, role: &str) -> String {
    if let Some(m) = conn.and_then(|c| c.keys.as_ref()) {
        if let Some(k) = m.get(role) {
            return k.clone();
        }
        if let Some((_, k)) = m.iter().find(|(r, _)| r.eq_ignore_ascii_case(role)) {
            return k.clone();
        }
    }
    role.to_string()
}

impl Connection {
    /// The vault KEYs this connection's secrets live at: a service-backed
    /// connection's declared roles bound via `keys`/identity (resolved through
    /// `reg`), or a raw connection's explicit UPPERCASE `secrets` list. A
    /// service unknown to `reg` (e.g. a per-vault custom def not loaded) yields
    /// no service-role addresses — the recorded `keys` bindings still surface
    /// through [`VaultAux::connection_claims`].
    pub fn secret_addresses(&self, reg: &crate::service::ServiceRegistry) -> Vec<String> {
        match self.service.as_deref() {
            Some(service) => match reg.get(service) {
                Some(def) => def
                    .service
                    .secrets
                    .iter()
                    .map(|role| secret_key_for(Some(self), &role.to_ascii_uppercase()))
                    .collect(),
                None => Vec::new(),
            },
            None => self
                .secrets
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.to_ascii_uppercase())
                .collect(),
        }
    }
}

impl VaultAux {
    /// Every vault KEY some connection (other than `exclude`) references, mapped
    /// to the referencing connection ids — the shared-pool guard every deletion
    /// flow consults (CONNECTION_SCHEMA.md §3): connections REFERENCE keys, they
    /// don't own them, so a key another connection still references is never
    /// deleted with this one, and deleting a key never cascades into a
    /// connection (it just turns unconfigured). Covers raw `secrets` lists,
    /// service `keys`-map values, and each service's declared-role identity
    /// bindings (resolved via `reg`; a per-vault CUSTOM service's identity roles
    /// aren't in `reg`, but its recorded `keys` bindings still count).
    pub fn connection_claims(
        &self,
        reg: &crate::service::ServiceRegistry,
        exclude: &str,
    ) -> BTreeMap<String, Vec<String>> {
        let mut claims: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (id, rec) in &self.connections {
            if id == exclude {
                continue;
            }
            let mut add = |key: String| {
                let by = claims.entry(key).or_default();
                if !by.contains(id) {
                    by.push(id.clone());
                }
            };
            match rec.service.as_deref() {
                None => {
                    for k in rec.secrets.clone().unwrap_or_default() {
                        add(k.to_ascii_uppercase());
                    }
                }
                Some(service) => {
                    if let Some(def) = reg.get(service) {
                        for role in &def.service.secrets {
                            add(secret_key_for(Some(rec), &role.to_ascii_uppercase()));
                        }
                    }
                    for k in rec.keys.clone().unwrap_or_default().into_values() {
                        add(k);
                    }
                }
            }
        }
        claims
    }
}

/// Creation-time DEFAULT `keys` binding for a **named** connection's role:
/// `<ROLE>_<QUALIFIER>` (qualifier = `conn_id` minus the `<service>_` prefix,
/// uppercased) — distinct from the default connection's bare mainstream name so
/// two accounts of one service never collide. A suggestion only: the creator
/// may override (e.g. bind to an existing key); the stored record is
/// authoritative. Identity (the bare role) for the default connection.
pub fn suggested_secret_key(conn_id: &str, service_id: &str, role: &str) -> String {
    if conn_id == service_id {
        return role.to_string();
    }
    let qual = conn_id
        .strip_prefix(&format!("{service_id}_"))
        .unwrap_or(conn_id);
    // Keep the suggestion env-valid whatever the qualifier charset: uppercase,
    // any non-[A-Z0-9] byte → `_`.
    let qual: String = qual
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("{role}_{qual}")
}

/// Membership role inside a shared vault. Two tiers by design (team §7.1/§5.15):
/// `Owner` = manage (config, members, reveal, kill switch); `Member` = edit
/// (content). Multiple owners are the norm; the LAST owner can never be removed
/// or demoted (§7.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MemberRole {
    Owner,
    /// The least-privilege default: a cred that loads without an explicit role
    /// (legacy row, serde default) is a `Member`, never an `Owner`. This is the
    /// fail-closed choice for the owner-authority anchor — a missing role can
    /// never silently confer owner powers.
    #[default]
    Member,
}

/// A single agent's reach mask — which connections of THIS vault the agent may
/// use (design/team §8.1). `All` is the default (absent item ≡ `All`, personal
/// parity). `Selected` is a fail-closed whitelist: a connection added to the
/// vault later is NOT reachable until explicitly listed. Everything else about
/// agent permissioning (per-request levels, approvals) stays vault-wide policy —
/// the mask is a reach/visibility gate, deliberately not a rule tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", untagged)]
pub enum AgentMask {
    /// `"all"` — no restriction from the mask.
    All(AllTag),
    /// Explicit whitelist of `connection_id`s.
    Selected(Vec<String>),
}

/// Serde helper: the `All` arm serializes as the bare string `"all"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllTag {
    #[serde(rename = "all")]
    All,
}

impl Default for AgentMask {
    fn default() -> Self {
        AgentMask::All(AllTag::All)
    }
}

impl AgentMask {
    /// Does the mask let this agent reach `connection_id`?
    pub fn allows(&self, connection_id: &str) -> bool {
        match self {
            AgentMask::All(_) => true,
            AgentMask::Selected(list) => list.iter().any(|c| c == connection_id),
        }
    }

    /// `None` = unrestricted; `Some(set)` = the whitelist (fail-closed).
    pub fn selected(&self) -> Option<&[String]> {
        match self {
            AgentMask::All(_) => None,
            AgentMask::Selected(list) => Some(list),
        }
    }
}

/// The body of an `agent:<agent_id>` item: today just the mask, kept as a
/// struct so future per-agent fields land without re-addressing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentEntry {
    #[serde(default)]
    pub connections: AgentMask,
}

/// `aux` payload — everything inside `ProtectedState.aux` for v4 vaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAux {
    pub version: u32,
    pub stores: BTreeMap<String, Store>,
    pub store_order: Vec<String>,
    /// The policy tree — default floors, per-category, and per-connection user
    /// policy (PROTOCOL.md §5.2 / §6.4 `M.policy`). Absent on
    /// fresh vaults → daemon uses `Policy::default()`. Replaces the old split
    /// `policy_defaults` + `service_state`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
    /// In-flight connects, keyed by `connection_id`. Each carries everything the
    /// daemon needs to redeem the OAuth code; on exchange the entry MOVEs to
    /// `connections`. Sparse — empty when nothing is mid-handshake. See
    /// [`Connecting`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub connecting: BTreeMap<String, Connecting>,
    /// Established connections, keyed by `connection_id`. Sparse. Status is
    /// derived (see [`Connection`]).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub connections: BTreeMap<String, Connection>,
    /// Audit log retention in days. `None` = keep forever; integer = drop
    /// rows older than this on the next `GET /v/{vid}/approvals` call.
    /// Frontend offers 7 / 30 / 90 / forever; the daemon clamps to a
    /// sensible range during prune.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_retention_days: Option<u32>,
    /// Per-vault custom service definitions: `service_id → verbatim v4
    /// service.toml source`. Validated (v4 schema, inline-complete `[oauth2]`,
    /// no tool-named sections) at unlock before it can broker,
    /// and again at author time. Sparse — empty when the user authored none. A
    /// custom service is folded into the catalog exactly like a compiled one;
    /// it never shadows a built-in id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, String>,
    /// Per-agent reach masks, keyed by agent id (pubkey-derived once identity
    /// ships; api-key id until then). Sparse — an absent entry means the agent
    /// reaches everything (`AgentMask::All`, personal parity). Sliced to
    /// `agent:<id>` items at the sync layer (one item per agent = independent
    /// CAS, same pattern as connections). Team §8.1.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agents: BTreeMap<String, AgentEntry>,
}

impl VaultAux {
    /// Build the minimal initial aux for a freshly enrolled vault: the reserved
    /// `native-secrets` store present and empty, order `[native-secrets]`.
    pub fn initial() -> Self {
        let mut stores = BTreeMap::new();
        stores.insert(
            NATIVE_SECRETS_ID.to_string(),
            Store {
                kind: NATIVE_SECRETS_KIND.to_string(),
                category: Category::Value,
                items: BTreeMap::new(),
                extra: serde_json::Map::new(),
            },
        );
        Self {
            version: PLAINTEXT_VERSION,
            stores,
            store_order: vec![NATIVE_SECRETS_ID.to_string()],
            policy: None,
            connecting: BTreeMap::new(),
            connections: BTreeMap::new(),
            audit_retention_days: None,
            services: BTreeMap::new(),
            agents: BTreeMap::new(),
        }
    }
}

/// Runtime view of a decrypted vault. Merges the two physical pools
/// (`targets` and `aux`) so callers can ask resolution-order questions
/// without caring about layout.
#[derive(Debug)]
pub struct VaultPlaintextView {
    pub aux: VaultAux,
    /// Native-secrets items: `item_name → raw bytes`. Materialised from
    /// `ProtectedState.targets`. Stored as owned bytes (not `TargetValue`)
    /// because the view's lifetime is the request, not the protocol
    /// boundary — sudp's zeroize is preserved up to the moment we copy.
    pub native_secrets: BTreeMap<String, Vec<u8>>,
    /// True when the fold saw any live legacy `aux:*` item — the trigger for
    /// the one-shot addressing migration (team §8.3). Always false for views
    /// opened from a whole-blob `ProtectedState` (no addressing there).
    pub legacy_addressing: bool,
}

impl VaultPlaintextView {
    /// Parse from an opened `ProtectedState`. Hard-fails on `version != 4`.
    pub fn from_protected_state(m: &ProtectedState) -> Result<Self> {
        let aux: VaultAux = serde_json::from_value(m.aux.clone())
            .map_err(|e| AppError::Internal(format!("vault aux parse: {}", e)))?;
        if aux.version != PLAINTEXT_VERSION {
            return Err(AppError::Internal(format!(
                "vault plaintext version {} (expected {}) — vault is from an older binary; re-enroll required",
                aux.version, PLAINTEXT_VERSION
            )));
        }
        let mut native_secrets = BTreeMap::new();
        for (name, val) in m.secrets.iter() {
            native_secrets.insert(name.clone(), val.as_bytes().to_vec());
        }
        Ok(VaultPlaintextView {
            aux,
            native_secrets,
            legacy_addressing: false,
        })
    }

    /// Synchronous resolve restricted to `native-secrets`. Used by the
    /// unlock cache-bootstrap path that runs inside a non-async section.
    /// Other store kinds (gcp/1p/aws) require async I/O — use
    /// [`Self::resolve_value_async`] to walk those.
    pub fn resolve_value_native(&self, item_name: &str) -> Option<&[u8]> {
        for store_id in &self.aux.store_order {
            let Some(store) = self.aux.stores.get(store_id) else {
                continue;
            };
            if store.category != Category::Value {
                continue;
            }
            if store.kind == NATIVE_SECRETS_KIND {
                if let Some(bytes) = self.native_secrets.get(item_name) {
                    return Some(bytes.as_slice());
                }
            }
            // External adapter kinds are skipped here; caller that needs
            // them should use the async path.
        }
        None
    }

    /// Resolve a value-category item by name through the full store_order
    /// using the v3 adapter dispatch. First match wins; errors from a
    /// configured store propagate (no silent fallback). `Ok(None)` means
    /// no store has the item.
    pub async fn resolve_value_async(
        &self,
        item_name: &str,
    ) -> crate::error::Result<Option<Vec<u8>>> {
        for store_id in &self.aux.store_order {
            let Some(store) = self.aux.stores.get(store_id) else {
                continue;
            };
            if store.category != Category::Value {
                continue;
            }
            let adapter = crate::store::build_adapter(store_id, store, self)?;
            if let Some(bytes) = adapter.resolve(item_name).await? {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_claims_cover_raw_keysmap_and_identity_bindings() {
        // Registry is loaded so gmail's declared GMAIL_REFRESH_TOKEN role
        // resolves; a raw conn owns its explicit secrets; a named conn binds via
        // its keys map. The default gmail conn's IDENTITY binding is the case the
        // old ad-hoc guards missed.
        let reg = crate::service::ServiceRegistry::load();
        let mut aux = VaultAux::initial();
        aux.connections.insert(
            "stripe_key".into(),
            Connection {
                name: None,
                service: None,
                hosts: None,
                secrets: Some(vec!["SHARED_KEY".into()]),
                keys: None,
            },
        );
        aux.connections.insert(
            "gmail".into(),
            Connection {
                name: None,
                service: Some("gmail".into()),
                hosts: None,
                secrets: None,
                keys: None,
            },
        );
        let mut work_keys = BTreeMap::new();
        work_keys.insert(
            "GMAIL_REFRESH_TOKEN".into(),
            "GMAIL_REFRESH_TOKEN_WORK".into(),
        );
        aux.connections.insert(
            "gmail_work".into(),
            Connection {
                name: None,
                service: Some("gmail".into()),
                hosts: None,
                secrets: None,
                keys: Some(work_keys),
            },
        );

        // Excluding the raw conn: its own key isn't a claim, but BOTH gmail
        // conns' keys are (default via identity, named via its map).
        let claims = aux.connection_claims(&reg, "stripe_key");
        assert!(!claims.contains_key("SHARED_KEY"));
        assert_eq!(
            claims.get("GMAIL_REFRESH_TOKEN").map(Vec::as_slice),
            Some(&["gmail".to_string()][..])
        );
        assert_eq!(
            claims.get("GMAIL_REFRESH_TOKEN_WORK").map(Vec::as_slice),
            Some(&["gmail_work".to_string()][..])
        );

        // secret_addresses: a raw conn lists its own; a named conn resolves its
        // bound key; the default conn is the identity role.
        let raw = &aux.connections["stripe_key"];
        assert_eq!(raw.secret_addresses(&reg), vec!["SHARED_KEY".to_string()]);
        assert_eq!(
            aux.connections["gmail"].secret_addresses(&reg),
            vec!["GMAIL_REFRESH_TOKEN".to_string()]
        );
        assert_eq!(
            aux.connections["gmail_work"].secret_addresses(&reg),
            vec!["GMAIL_REFRESH_TOKEN_WORK".to_string()]
        );
    }

    fn build_protected_state(
        aux_json: serde_json::Value,
        targets: &[(&str, &[u8])],
    ) -> ProtectedState {
        let mut m = ProtectedState::new();
        m.aux = aux_json;
        for (k, v) in targets {
            m.put_secret(k.to_string(), v.to_vec());
        }
        m
    }

    // Backward-compat: a vault sealed before the file-store removal still has a
    // `native-files` store (category "file"); it must still deserialize.
    #[test]
    fn parse_minimal_aux_succeeds() {
        let m = build_protected_state(
            serde_json::json!({
                "version": 4,
                "stores": {
                    "native-secrets": { "kind": "native-secrets", "category": "value" },
                    "native-files":   { "kind": "native-files",   "category": "file"  }
                },
                "store_order": ["native-secrets", "native-files"]
            }),
            &[("openai_api_key", b"sk-test")],
        );
        let view = VaultPlaintextView::from_protected_state(&m).unwrap();
        assert_eq!(view.aux.version, 4);
        assert_eq!(view.aux.store_order, vec!["native-secrets", "native-files"]);
        assert_eq!(
            view.resolve_value_native("openai_api_key"),
            Some(&b"sk-test"[..])
        );
        assert_eq!(view.resolve_value_native("nonexistent"), None);
    }

    #[test]
    fn parse_wrong_version_rejected() {
        let m = build_protected_state(
            serde_json::json!({
                "version": 2,
                "stores": {},
                "store_order": []
            }),
            &[],
        );
        let err = VaultPlaintextView::from_protected_state(&m).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(msg.contains("version 2"), "got: {}", msg);
    }

    #[test]
    fn initial_aux_round_trips() {
        let aux = VaultAux::initial();
        let json = serde_json::to_value(&aux).unwrap();
        let aux2: VaultAux = serde_json::from_value(json).unwrap();
        assert_eq!(aux2.version, 4);
        assert!(aux2.stores.contains_key("native-secrets"));
        assert!(!aux2.stores.contains_key("native-files")); // file store removed
        assert_eq!(aux2.store_order, vec!["native-secrets"]);
    }

    #[test]
    fn secret_key_resolution_record_wins_identity_default() {
        // No record / no map / unmapped role → identity (the bare role).
        assert_eq!(
            secret_key_for(None, "GMAIL_REFRESH_TOKEN"),
            "GMAIL_REFRESH_TOKEN"
        );
        let bare = Connection::default();
        assert_eq!(
            secret_key_for(Some(&bare), "GMAIL_REFRESH_TOKEN"),
            "GMAIL_REFRESH_TOKEN"
        );
        // A `keys` entry wins, matched case-insensitively on the role.
        let mut keys = BTreeMap::new();
        keys.insert(
            "GMAIL_REFRESH_TOKEN".to_string(),
            "GMAIL_REFRESH_TOKEN_BOB".to_string(),
        );
        let rec = Connection {
            keys: Some(keys),
            ..Connection::default()
        };
        assert_eq!(
            secret_key_for(Some(&rec), "GMAIL_REFRESH_TOKEN"),
            "GMAIL_REFRESH_TOKEN_BOB"
        );
        assert_eq!(
            secret_key_for(Some(&rec), "gmail_refresh_token"),
            "GMAIL_REFRESH_TOKEN_BOB"
        );
        assert_eq!(secret_key_for(Some(&rec), "OTHER_ROLE"), "OTHER_ROLE");
    }

    #[test]
    fn suggested_key_identity_for_default_qualified_for_named() {
        assert_eq!(
            suggested_secret_key("gmail", "gmail", "GMAIL_REFRESH_TOKEN"),
            "GMAIL_REFRESH_TOKEN"
        );
        assert_eq!(
            suggested_secret_key("gmail_bob", "gmail", "GMAIL_REFRESH_TOKEN"),
            "GMAIL_REFRESH_TOKEN_BOB"
        );
        // Non-`<service>_`-prefixed / odd-charset ids stay env-valid.
        assert_eq!(
            suggested_secret_key("work-acct", "gmail", "GMAIL_REFRESH_TOKEN"),
            "GMAIL_REFRESH_TOKEN_WORK_ACCT"
        );
    }
}
