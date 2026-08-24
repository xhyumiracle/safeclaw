//! CLI-side config (`~/.safeclaw/config.toml`) + the single derivation point
//! for every daemon URL the CLI uses.
//!
//! The DEVICE atoms live here: `daemon` (the daemon the human's `sc` talks to)
//! and `vault` (the durable default), plus cloud pairing coordinates. URLs are
//! DERIVED from the atoms, never stored (CREDENTIAL_BROKER.md §14: atoms are
//! truth, `_url`s are projections):
//!
//! - control root  = daemon host + `CONTROL_PORT` (ceremony/write plane)
//! - API-face root = daemon host + `PROXY_PORT`   (the agent's `BROKER_URL`)
//!
//! THE self-consistency invariant: both planes derive from ONE daemon-host
//! value. When `$SAFECLAW_BROKER_URL` is set (an agent's env snapshot), its
//! host wins — an agent's shelled `sc` then targets the SAME daemon the
//! agent's own HTTP does, by construction; the two faces cannot split.
//!
//! On-disk field name: `daemon`. Configs written by an older build used
//! `custodian`; `#[serde(alias = "custodian")]` keeps those loading (pre-launch
//! is wipe+re-enroll, so the alias is belt-and-suspenders, not a migration).
//! The vault-history catalog lives in its own file
//! (`~/.safeclaw/known_vaults.toml`, ssh known_hosts-style — append-growing,
//! harmless to delete), separate from the active selection.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct CliConfig {
    /// The local daemon URL the human's `sc` talks to (loopback after login).
    #[serde(default, alias = "custodian")]
    pub daemon: Option<String>,
    #[serde(default)]
    pub vault: Option<String>,
    /// LEGACY location of the vault-history catalog — now lives in
    /// `~/.safeclaw/known_vaults.toml` (see [`known_vaults`]). Still read (and
    /// merged) so pre-split configs keep working; the first catalog WRITE
    /// migrates entries over and clears this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_vaults: Vec<KnownVault>,
    /// Cloud pro-backend origin for sealed-blob sync (Slice 3) AND the
    /// op-relay (web approval). Set by `sc login`; the daemon pulls
    /// `{cloud_backend}/v/{vault}/blob` and registers pending ops at
    /// `{cloud_backend}/v/{vault}/op/relay/*`. Distinct from `daemon`,
    /// which after login points at the LOCAL daemon the agent talks to.
    /// See [[project_slice3_design]].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_backend: Option<String>,
    /// Cloud FRONTEND origin (where the human taps their passkey: the web
    /// approval page at `{frontend_origin}/grant/{op_id}`). Returned by the
    /// pair-token exchange as `console_url`. Distinct from `cloud_backend`
    /// (the API host, typically `api.<frontend>`). Set by `sc login`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend_origin: Option<String>,
    /// Persistent user preferences. Set via `sc config set <key> <value>`.
    /// Resolution chain for any setting: flag > env > this > built-in
    /// default.
    #[serde(default, skip_serializing_if = "Settings::is_empty")]
    pub settings: Settings,
    /// SSE sync-stream switch (design/sse-sync.md): absent/"auto" =
    /// connect the wake stream, "off" = pure long-poll. Read by the stream
    /// dispatcher at every (re)connect, so flipping it bites within ~15 min
    /// without a restart. `SAFECLAW_SYNC_STREAM` overrides — and, unlike this
    /// key, survives an OLD binary's config save (which drops unknown keys),
    /// so the env var is the robust rollback lever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_stream: Option<String>,
    /// Ceremony-audit switch: absent/"auto" = the audit shipper also ships
    /// control-plane terminal outcomes (unlock/set/connect grants) to the
    /// cloud audit_events, "off" = Use ops only (the pre-rc.6 contract).
    /// Read once per 30s ship tick, so flipping it bites without a restart;
    /// while off, ceremony rows stay in the local outbox and back-ship on
    /// re-enable (bounded by audit retention). `SAFECLAW_AUDIT_CEREMONIES`
    /// overrides, same robustness rationale as `sync_stream` above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ceremonies: Option<String>,
    /// Set when the ACTIVE vault was tombstoned cloud-side (deleted on the
    /// web) and the sync path cleared the selection — the one case where "no
    /// vault selected" is a surprise, not a choice. `sc status` and
    /// `resolve_active` read it to say "your vault was deleted — re-pair"
    /// instead of a blank zero-vault state. Cleared by the next successful
    /// pairing/selection (`put_active*`) and by logout. A user-driven
    /// `sc vault forget` never sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_deleted_upstream: Option<String>,
    /// The account's Supabase UUID, captured at `sc login`. ROLE = logging / debug /
    /// support identification ONLY: it matches the id shown in the web console, so a
    /// human can tie this machine to an account. It is NOT an identity or verification
    /// anchor — a database UUID cannot be checked against a signature. Everything that
    /// verifies OWNER intent (the principal ledger, membership, tombstones) uses
    /// `account_uik` (the self-certifying `us_…`) below. Keeping the two apart is the
    /// fix for the Fix-0 confusion: an earlier build wrongly pinned THIS UUID as the
    /// ledger anchor, so `derive_id(uik_pub) == account_id` never matched and nothing
    /// verified. Cleared by logout / self-revoke.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// §15: the account's owner-UIK id (`us_…`) — the REAL principal-ledger anchor
    /// (the `account_id` above is the Supabase UUID, NOT the anchor). Self-certifying:
    /// `derive_id(User, uik_pub) == account_uik`. Delivered + pinned at pairing; the
    /// daemon verifies the ledger anchor + its own per-vault membership against it.
    /// Absent on an older backend / pre-UIK account (the ledger loop then doesn't run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_uik: Option<String>,
    /// §15 principal-ledger enforcement switch: DEFAULT OFF — a verified revoke of
    /// THIS device only locks+wipes when this is "on". `SAFECLAW_PRINCIPAL_ENFORCE`
    /// overrides (and survives an old binary's config save). Flipped on at the P6
    /// cutover. See [`crate::principal_ledger::principal_enforce_enabled`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_enforce: Option<String>,
    /// §15 leg-A require-signed-tombstone switch: DEFAULT OFF — an unsigned
    /// `status:"deleted"` still drops local state (legacy). When "on", the daemon drops
    /// only on an owner-signed tombstone that verifies against the vault fold-owner set.
    /// `SAFECLAW_REQUIRE_SIGNED_TOMBSTONE` overrides. Flipped on at the P6 cutover. See
    /// [`crate::principal_ledger::require_signed_tombstone`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_signed_tombstone: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Settings {
    /// Localhost callback port for browser-gesture commands (`unlock`,
    /// `vault create`, etc.). The CLI binds this to receive WebAuthn
    /// redirects. Useful with SSH `-L` forwarding when the browser
    /// lives on a different machine than the daemon. Env override:
    /// `SAFECLAW_CB_PORT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cb_port: Option<u16>,
}

impl Settings {
    fn is_empty(&self) -> bool {
        self.cb_port.is_none()
    }
}

/// Resolve the effective `cb_port`: flag override wins, otherwise read
/// the persisted setting. (Env is handled by clap's `env = ...` and is
/// already folded into the flag value.)
pub fn settings_cb_port() -> Option<u16> {
    load().ok().and_then(|c| c.settings.cb_port)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct KnownVault {
    /// The daemon URL this vault lives behind. (On-disk alias: `custodian`.)
    #[serde(alias = "custodian")]
    pub daemon: String,
    pub vault: String,
    /// Cloud-authoritative display label, mirrored on every discovery. Human /
    /// agent facing ONLY — the `vault` id stays the canonical, unique, STABLE
    /// handle (labels can be renamed and are not unique). `None` for a legacy
    /// catalog entry until the next discovery refresh fills it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Vault kind (`personal` / `team` / `shared`), mirrored on discovery.
    /// DISPLAY-only (shown by `sc vault ls`); never an addressing token, so a
    /// vault literally labeled "team" can't collide with the kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

pub fn config_path() -> Result<PathBuf, String> {
    let base = dirs::home_dir().ok_or_else(|| "no home dir".to_string())?;
    Ok(base.join(".safeclaw").join("config.toml"))
}

pub fn load() -> Result<CliConfig, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let text = String::from_utf8(bytes).map_err(|_| "config.toml not utf8".to_string())?;
    toml::from_str(&text).map_err(|e| format!("parse {}: {}", path.display(), e))
}

pub fn save(cfg: &CliConfig) -> Result<PathBuf, String> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }
    let body = toml::to_string_pretty(cfg).map_err(|e| format!("serialize config: {}", e))?;
    let tmp = path.with_extension("toml.tmp");
    {
        let mut f =
            fs::File::create(&tmp).map_err(|e| format!("create {}: {}", tmp.display(), e))?;
        f.write_all(body.as_bytes())
            .map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    }
    fs::rename(&tmp, &path)
        .map_err(|e| format!("rename {} -> {}: {}", tmp.display(), path.display(), e))?;
    Ok(path)
}

// ── known-vaults catalog (own file, design wave §E) ─────────────────────────

pub fn known_vaults_path() -> Result<PathBuf, String> {
    let base = dirs::home_dir().ok_or_else(|| "no home dir".to_string())?;
    Ok(base.join(".safeclaw").join("known_vaults.toml"))
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KnownVaultsFile {
    #[serde(default)]
    vaults: Vec<KnownVault>,
}

/// Every vault this machine has used: the catalog file, plus any entries still
/// in the legacy `config.toml` field (pre-split configs). File order first;
/// the next catalog WRITE migrates the legacy entries over.
pub fn known_vaults() -> Vec<KnownVault> {
    let mut list = read_known_file();
    if let Ok(cfg) = load() {
        for kv in cfg.known_vaults {
            if !list.contains(&kv) {
                list.push(kv);
            }
        }
    }
    list
}

fn read_known_file() -> Vec<KnownVault> {
    // Reads are LENIENT (a corrupt catalog acts empty — like a deleted
    // known_hosts); writes are not: `update_known_vaults` refuses to rewrite
    // over a file it couldn't parse, so a hand-edit typo can't become silent
    // data loss.
    known_file_parse_error().ok().flatten().unwrap_or_default()
}

/// `Ok(Some(vaults))` = file parsed; `Ok(None)` = no file; `Err` = file exists
/// but doesn't parse.
fn known_file_parse_error() -> Result<Option<Vec<KnownVault>>, String> {
    let Ok(path) = known_vaults_path() else {
        return Ok(None);
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(None);
    };
    toml::from_str::<KnownVaultsFile>(&text)
        .map(|f| Some(f.vaults))
        .map_err(|e| format!("{} doesn't parse: {}", path.display(), e))
}

/// Rewrite the catalog with `mutate` applied to the MERGED view (file + legacy
/// config field). Atomic tmp-rename write; completes the migration by clearing
/// the legacy field afterwards. Refuses to clobber an unparseable file.
fn update_known_vaults<F: FnOnce(&mut Vec<KnownVault>)>(mutate: F) -> Result<(), String> {
    if let Err(e) = known_file_parse_error() {
        return Err(format!(
            "refusing to rewrite the vault catalog: {} — fix or delete the file, then retry",
            e
        ));
    }
    let mut list = known_vaults();
    mutate(&mut list);
    let path = known_vaults_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }
    let body = toml::to_string_pretty(&KnownVaultsFile { vaults: list })
        .map_err(|e| format!("serialize known_vaults: {}", e))?;
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, body).map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    fs::rename(&tmp, &path)
        .map_err(|e| format!("rename {} -> {}: {}", tmp.display(), path.display(), e))?;
    if let Ok(mut cfg) = load() {
        if !cfg.known_vaults.is_empty() {
            cfg.known_vaults.clear();
            let _ = save(&cfg);
        }
    }
    Ok(())
}

/// Wipe the catalog (logout).
pub fn clear_known_vaults() -> Result<(), String> {
    update_known_vaults(|l| l.clear())
}

/// Upsert one vault into the catalog, keyed by `(daemon, vault)`. Refreshes the
/// cloud-mirrored `label`/`kind` when the caller supplies them (a rename lands on
/// the next discovery); a meta-less caller (`sc vault use`) never wipes an
/// existing label. Keying on the id — not full-struct equality — is what lets a
/// label change in place instead of leaving a stale duplicate row.
fn upsert_vault(
    daemon: &str,
    vault: &str,
    label: Option<String>,
    kind: Option<String>,
) -> Result<(), String> {
    let daemon = daemon.to_string();
    let vault = vault.to_string();
    update_known_vaults(move |l| {
        if let Some(e) = l.iter_mut().find(|kv| kv.daemon == daemon && kv.vault == vault) {
            if label.is_some() {
                e.label = label;
            }
            if kind.is_some() {
                e.kind = kind;
            }
        } else {
            l.push(KnownVault {
                daemon,
                vault,
                label,
                kind,
            });
        }
    })
}

/// Dedupe-append one vault to the catalog (no cloud meta — `sc vault use`/create).
fn remember_vault(daemon: &str, vault: &str) -> Result<(), String> {
    upsert_vault(daemon, vault, None, None)
}

/// Upsert a DISCOVERED account vault together with its cloud `label`/`kind`. The
/// daemon calls this on every discovery so `sc vault ls` and `--vault <name>`
/// resolution ([`resolve_vault_token`]) stay fresh across renames.
pub fn remember_discovered_vault(
    daemon: &str,
    vault: &str,
    label: Option<String>,
    kind: Option<String>,
) -> Result<(), String> {
    upsert_vault(daemon, vault, label, kind)
}

/// Remove a vault from the catalog. If it was active, clears active — even
/// when the pair is absent from the catalog (e.g. a hand-deleted catalog
/// file), mirroring `forget_vault`. Returns true if anything changed.
pub fn forget(custodian: &str, vault: &str) -> Result<bool, String> {
    let removed_known = known_vaults()
        .iter()
        .any(|kv| kv.daemon == custodian && kv.vault == vault);
    if removed_known {
        update_known_vaults(|l| l.retain(|kv| !(kv.daemon == custodian && kv.vault == vault)))?;
    }
    let mut cfg = load().unwrap_or_default();
    let cleared_active =
        cfg.daemon.as_deref() == Some(custodian) && cfg.vault.as_deref() == Some(vault);
    if cleared_active {
        cfg.daemon = None;
        cfg.vault = None;
        save(&cfg)?;
    }
    Ok(removed_known || cleared_active)
}

/// Remove a vault from the catalog by **vault id alone** (any custodian), and
/// clear the active selection if it pointed at that vault. Used by the
/// cloud-sync delete-propagation path, which only knows the vid (a tombstone
/// carries no custodian). Idempotent: a vault not present is `Ok(false)`,
/// never an error.
pub fn forget_vault(vault: &str) -> Result<bool, String> {
    let removed_known = known_vaults().iter().any(|kv| kv.vault == vault);
    if removed_known {
        update_known_vaults(|l| l.retain(|kv| kv.vault != vault))?;
    }
    let mut cfg = load().unwrap_or_default();
    let cleared_active = cfg.vault.as_deref() == Some(vault);
    if cleared_active {
        cfg.daemon = None;
        cfg.vault = None;
        cfg.vault_deleted_upstream = Some(vault.to_string());
        save(&cfg)?;
    }
    Ok(removed_known || cleared_active)
}

/// Dedupe-add a vault to the known-vaults catalog WITHOUT changing the active
/// selection. The daemon's auto-discovery path calls this for every vault the
/// account owns (design/vault-addressing.md), so `sc vault ls` and the sync
/// watcher pick them up with no manual `sc vault use`. Choosing a DEFAULT stays
/// a separate, explicit act (`put_active`) — discovery never writes `config.vault`,
/// so an explicit default stays put when new vaults appear.
pub fn remember(daemon: &str, vault: &str) -> Result<(), String> {
    remember_vault(daemon, vault)
}

/// Set the active vault and dedupe-add it to the catalog.
pub fn put_active(daemon: &str, vault: &str) -> Result<PathBuf, String> {
    remember_vault(daemon, vault)?;
    let mut cfg = load().unwrap_or_default();
    cfg.daemon = Some(daemon.to_string());
    cfg.vault = Some(vault.to_string());
    cfg.vault_deleted_upstream = None;
    save(&cfg)
}

/// Record the cloud pairing coordinates (`sc login`) WITHOUT choosing a vault.
/// Device pairing is account-level and vault-agnostic (design/vault-addressing.md):
/// the daemon auto-discovers the account's vaults on start, a single one
/// auto-selects, and a multi-vault account is resolved by the user (`sc vault
/// use`) or per command (`--vault`). The agent talks to the local `daemon`; the
/// daemon syncs against the cloud (`cloud_backend`). Leaves `config.vault` as it
/// was: a fresh machine has none (auto-select decides), and a re-pair keeps an
/// explicit default the user already set.
pub fn put_cloud_coords(
    daemon: &str,
    cloud_backend: &str,
    frontend_origin: Option<&str>,
    account_id: Option<&str>,
    account_uik: Option<&str>,
) -> Result<PathBuf, String> {
    let mut cfg = load().unwrap_or_default();
    cfg.daemon = Some(daemon.to_string());
    cfg.vault_deleted_upstream = None;
    cfg.cloud_backend = Some(cloud_backend.to_string());
    cfg.frontend_origin = frontend_origin
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string());
    // §15: persist the paired account UUID (reference) + the owner-UIK us_ (the
    // real, self-certifying principal-ledger anchor). Keep prior values if this
    // pairing response omits them (older backend / pre-UIK account).
    if let Some(a) = account_id.filter(|s| !s.is_empty()) {
        cfg.account_id = Some(a.to_string());
    }
    if let Some(u) = account_uik.filter(|s| !s.is_empty()) {
        cfg.account_uik = Some(u.to_string());
    }
    save(&cfg)
}

/// The account's Supabase UUID, for logging / debug / support display ONLY (matching a
/// daemon to a console account). NEVER an identity or verification anchor — use
/// [`account_uik`] for anything that checks owner intent. `None` for a local-only daemon.
pub fn account_id() -> Option<String> {
    load().ok()?.account_id.filter(|s| !s.is_empty())
}

/// The account's owner-UIK id (`us_…`) captured at pairing — the §15 principal-ledger
/// ANCHOR + the daemon's own per-vault member identity. `None` on an older backend /
/// pre-UIK account (the ledger loop then doesn't start; membership-loss wipe is skipped).
pub fn account_uik() -> Option<String> {
    load().ok()?.account_uik.filter(|s| !s.is_empty())
}

/// Clear the cloud pairing from config + the known-vaults catalog (the inverse of
/// [`put_cloud_coords`]): drop daemon/vault/cloud_backend/frontend_origin/account_id
/// + known_vaults, preserve user `settings`. Used by the §15 self-revoke wipe so it
/// leaves the same state `sc logout` does.
pub fn clear_pairing() -> Result<(), String> {
    let mut cfg = load().unwrap_or_default();
    cfg.daemon = None;
    cfg.vault = None;
    cfg.cloud_backend = None;
    cfg.frontend_origin = None;
    cfg.account_id = None;
    cfg.account_uik = None;
    cfg.vault_deleted_upstream = None;
    cfg.known_vaults.clear();
    save(&cfg)?;
    clear_known_vaults()
}

/// Resolve the cloud FRONTEND origin (for the human web-approval link
/// `{origin}/grant/{op_id}`). Prefers the `console_url` persisted at login;
/// falls back to deriving it from `cloud_backend` by dropping a leading
/// `api.` label (the deployment convention is `api.<frontend>`). Returns
/// `None` for a local-only / self-host daemon (no cloud pairing).
pub fn frontend_origin() -> Option<String> {
    let cfg = load().ok()?;
    if let Some(fo) = cfg.frontend_origin.as_deref().filter(|s| !s.is_empty()) {
        return Some(fo.trim_end_matches('/').to_string());
    }
    let backend = cfg.cloud_backend.as_deref().filter(|s| !s.is_empty())?;
    Some(derive_frontend_from_backend(backend))
}

/// Human web-approval link for an op. When the daemon is cloud-paired this is
/// the absolute cloud page `{frontend_origin}/grant/{op_id}` — the only
/// approval surface a remote user can actually reach (the daemon is
/// zero-inbound localhost). For a local-only / self-host daemon it's the
/// relative `/op/{op_id}` poll path (JSON status — no local approval page
/// exists yet, which is why callers gate absolute-vs-relative). Single source
/// of truth for both the broker's `approve_url` and the CLI's remote-approve arm.
pub fn grant_url(op_id: &str) -> String {
    match frontend_origin() {
        Some(origin) => format!("{}/grant/{}", origin, op_id),
        None => format!("/op/{}", op_id),
    }
}

/// `https://api.dev.safeclaw.pro` → `https://dev.safeclaw.pro`. Only strips a
/// leading `api.` on the host; everything else (scheme, port, path) is kept.
/// A backend host without an `api.` prefix is returned unchanged (self-host
/// where frontend == backend).
fn derive_frontend_from_backend(backend: &str) -> String {
    let trimmed = backend.trim_end_matches('/');
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((s, r)) => (s, r),
        None => return trimmed.to_string(),
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    let host_port = host_port.strip_prefix("api.").unwrap_or(host_port);
    match path {
        Some(p) => format!("{}://{}/{}", scheme, host_port, p),
        None => format!("{}://{}", scheme, host_port),
    }
}

/// Split a combined URL like `http://host:port/v/<vid>` into
/// `(root, vid)`. Returns None if the URL doesn't carry `/v/<vid>`.
pub fn split_vault_url(url: &str) -> Option<(String, String)> {
    let trimmed = url.trim_end_matches('/');
    let (root, tail) = trimmed.rsplit_once("/v/")?;
    if tail.is_empty() || tail.contains('/') {
        return None;
    }
    Some((root.to_string(), tail.to_string()))
}

pub fn join_vault_url(daemon: &str, vault: &str) -> String {
    format!("{}/v/{}", daemon.trim_end_matches('/'), vault)
}

// ── Atom derivation (design wave §C/§D) ─────────────────────────────────────

/// `scheme://host` of a URL — port and path stripped, `[::1]`-style bracketed
/// hosts kept whole. `None` when there's no `scheme://` or no host.
fn scheme_host(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host_port = rest.split('/').next().unwrap_or("");
    let host = if let Some(r) = host_port.strip_prefix('[') {
        format!("[{}]", r.split_once(']')?.0)
    } else {
        host_port.split(':').next().unwrap_or("").to_string()
    };
    if host.is_empty() {
        return None;
    }
    Some(format!("{}://{}", scheme, host))
}

/// The agent's broker-face URL from the env: `$SAFECLAW_BROKER_URL` (the
/// self-describing name, SafeClaw's broker/API face, not the control port).
/// Empty values are ignored.
pub fn env_broker_url() -> Option<String> {
    std::env::var("SAFECLAW_BROKER_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

fn env_daemon_host() -> Option<String> {
    env_broker_url().and_then(|u| scheme_host(&u))
}

/// The DEVICE's daemon-host atom (`scheme://host`): config's `daemon` with its
/// port stripped, else loopback. This is what the device-side projections
/// (`sc env`, the `sc agent add` minter) derive from — deliberately NOT the
/// process env: a tool that re-read its own output would freeze stale values.
pub fn device_daemon_host(cfg: &CliConfig) -> String {
    cfg.daemon
        .as_deref()
        .and_then(scheme_host)
        .unwrap_or_else(|| "http://127.0.0.1".to_string())
}

/// The control root (`scheme://host:<control-port>`) every ceremony/write `sc`
/// call targets. Env-first: `$SAFECLAW_BROKER_URL`'s HOST wins when set (the
/// invariant — shelled `sc` and the agent's own HTTP share one daemon); else
/// config's `daemon` VERBATIM (it may carry a hand-edited custom control
/// port); else the loopback default. The env value carries the PROXY port,
/// never the control port, so the control port comes from [`control_port`]:
/// `$SAFECLAW_PORT` when set, else the constant. This is the SAME env `sc
/// serve` and `sc login` read, so exporting `SAFECLAW_PORT=<p>` moves the
/// daemon, its recorded config, AND this resolution together — a coordinated
/// port change survives even in an agent shell that carries a proxy-face
/// `SAFECLAW_BROKER_URL`.
pub fn control_root(cfg: &CliConfig) -> String {
    control_root_from(env_daemon_host(), cfg.daemon.as_deref(), control_port())
}

/// The control-plane port the `sc` CLI targets: `$SAFECLAW_PORT` when set (the
/// single override, shared with `sc serve` / `sc login`), else the constant.
fn control_port() -> u16 {
    std::env::var("SAFECLAW_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(crate::config::CONTROL_PORT)
}

/// The proxy-face port the `sc` CLI targets: `$SAFECLAW_PROXY_PORT` when set (the
/// single override, shared with `sc serve`), else the constant. Mirrors
/// [`control_port`] so a stale proxy port baked into an agent's snapshot
/// (`$SAFECLAW_BROKER_URL` from an old `sc agent add`) never wins — a moved
/// daemon self-heals, and a real custom port is coordinated the same way
/// `$SAFECLAW_PORT` coordinates the control face.
fn proxy_port() -> u16 {
    std::env::var("SAFECLAW_PROXY_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(crate::config::PROXY_PORT)
}

fn control_root_from(env_host: Option<String>, config_daemon: Option<&str>, port: u16) -> String {
    if let Some(h) = env_host {
        return format!("{}:{}", h, port);
    }
    config_daemon
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string())
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", port))
}

/// The API-face root (`scheme://host:<proxy-port>`) — the daemon face an agent
/// holds as `SAFECLAW_BROKER_URL`. Env-first HOST (the single-host invariant:
/// proxy and control share one daemon host), else the device atom; the PORT is
/// always [`proxy_port`], NEVER the snapshot's port. This is symmetric with
/// [`control_root`], which likewise takes the env HOST but resolves the port
/// itself — so a stale `$SAFECLAW_BROKER_URL` port from an old `sc agent add`
/// (the daemon since moved) is ignored by BOTH faces and self-heals, instead of
/// silently pinning the child's `HTTPS_PROXY` to a dead port. The env value
/// passes the SAME `scheme_host` parse gate as `control_root` — a malformed
/// value is ignored by BOTH faces, never honored by one and dropped by the
/// other (that asymmetry would split the invariant).
pub fn api_face_root(cfg: &CliConfig) -> String {
    api_face_root_with(env_broker_url(), cfg)
}

fn api_face_root_with(env_url: Option<String>, cfg: &CliConfig) -> String {
    let host = env_url
        .as_deref()
        .and_then(scheme_host)
        .unwrap_or_else(|| device_daemon_host(cfg));
    format!("{}:{}", host, proxy_port())
}

/// The device-default vault (config default, else the single known vault) —
/// the chain WITHOUT the env pin, for projections that mint fresh env output
/// (`sc env`, `sc agent add`): reading the pin there would freeze a stale pin
/// into new output.
pub fn device_default_vault(cfg: &CliConfig) -> Option<String> {
    cfg.vault.clone().or_else(single_known_vault)
}

/// The global `--vault` flag, recorded once by main right after clap parse so
/// every handler resolves it through the ONE chain below instead of each
/// subcommand carrying its own copy of the flag (design/vault-addressing.md).
static VAULT_FLAG: OnceLock<Option<String>> = OnceLock::new();

pub fn set_vault_flag(v: Option<String>) {
    let _ = VAULT_FLAG.set(v);
}

pub fn vault_flag() -> Option<String> {
    VAULT_FLAG
        .get()
        .cloned()
        .flatten()
        .filter(|s| !s.is_empty())
}

/// Resolve the active `(control_root, vault)` pair every short-lived `sc`
/// command routes through — the single choke point (CREDENTIAL_BROKER.md §14).
///
/// - **control root:** see [`control_root`] — the env `BROKER_URL` HOST wins
///   (the single-host invariant), else config, else the loopback default.
/// - **vault precedence:** `--vault flag > $SAFECLAW_VAULT_ID (env pin) >
///   config default > single-vault auto-select`. The env pin is launch-scoped
///   context (`sc run` injects it into the child) — it's what makes an agent's
///   shelled-out `sc` target the SAME vault its own HTTP does. Nothing durable
///   mints it, so a fresh shell follows config + `sc vault use`.
pub fn resolve_active(vault_override: Option<&str>) -> Result<(String, String), String> {
    let cfg = load()?;
    let explicit = vault_override
        .map(str::to_string)
        .or_else(vault_flag)
        .or_else(|| {
            std::env::var("SAFECLAW_VAULT_ID")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| cfg.vault.clone());
    if let Some(token) = explicit {
        let (daemon, vault) = resolve_vault_token(&token, &cfg)?;
        return Ok((
            control_root_from(env_daemon_host(), Some(&daemon), control_port()),
            vault,
        ));
    }
    // Single-vault auto-select: the catalog entry records WHICH daemon that
    // vault lives behind — pair them, so a cleared active selection can't
    // send the auto-selected vault to the default control root. The env host
    // still wins (invariant).
    if let Some(kv) = single_known_entry() {
        return Ok((
            control_root_from(env_daemon_host(), Some(&kv.daemon), control_port()),
            kv.vault,
        ));
    }
    // Stranded by an upstream delete, not by never having paired: name the
    // vault and point at re-pairing instead of the generic "no vault" error.
    if let Some(dead) = cfg.vault_deleted_upstream.as_deref() {
        return Err(format!(
            "vault {} was deleted on the web, so this device's pairing to it is gone — \
             generate a new install token in the console (\"Connect a new agent\") and run `sc login`",
            dead
        ));
    }
    Err("no vault selected — run `sc login` or `sc vault use`".to_string())
}

/// Client-side mirror of the daemon's vault-id rule (`op::validate_vault_id`:
/// 1-128 chars of `[A-Za-z0-9-_]`). Catches a display NAME ("test vault2") or a
/// typo at the argument boundary with a pointer to `sc vault ls`, instead of
/// letting it travel to the daemon and surface as a deep, opaque
/// "passkeys HTTP 400 Bad Request" (after the user already typed a
/// confirmation, in `sc vault rm`'s case).
fn validate_vault_id_arg(v: &str) -> Result<(), String> {
    let ok = !v.is_empty()
        && v.len() <= 128
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "'{}' is not a vault id (ids use letters, digits, '-' and '_') — run `sc vault ls` and pass the id from the `/v/<id>` part of the URL",
            v
        ))
    }
}

/// Resolve a user/agent `--vault` token to `(daemon, vault_id)` the
/// git/docker/kubectl way: an exact id, an exact label (case-insensitive), or a
/// unique id-prefix — whichever is UNAMBIGUOUS. Ambiguity is an error listing
/// the candidates, never a guess (the failure mode this exists to kill: an agent
/// told "the team vault" picking one at random). A syntactically-valid id not
/// yet in the catalog (a just-created vault) is accepted verbatim. Spaces belong
/// to a label: quote it, or pass a short id-prefix (no spaces, no quoting).
pub fn resolve_vault_token(token: &str, cfg: &CliConfig) -> Result<(String, String), String> {
    let token = token.trim();
    let known = known_vaults();
    // 1. exact id — the canonical handle always wins.
    if let Some(kv) = known.iter().find(|kv| kv.vault == token) {
        return Ok((kv.daemon.clone(), kv.vault.clone()));
    }
    // 2. exact label, case-insensitive — unique or fail loud.
    let by_label: Vec<&KnownVault> = known
        .iter()
        .filter(|kv| {
            kv.label
                .as_deref()
                .map(|l| l.trim().eq_ignore_ascii_case(token))
                .unwrap_or(false)
        })
        .collect();
    match by_label.as_slice() {
        [kv] => return Ok((kv.daemon.clone(), kv.vault.clone())),
        [] => {}
        many => return Err(ambiguous_vault_err(token, "name", many)),
    }
    // 3. unique id-prefix (docker/git style); >=4 chars so a stray word can't sweep.
    if token.len() >= 4
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        let by_prefix: Vec<&KnownVault> =
            known.iter().filter(|kv| kv.vault.starts_with(token)).collect();
        match by_prefix.as_slice() {
            [kv] => return Ok((kv.daemon.clone(), kv.vault.clone())),
            [] => {}
            many => return Err(ambiguous_vault_err(token, "id prefix", many)),
        }
    }
    // 4. a full-length valid id the catalog hasn't recorded yet (just created /
    //    catalog lag) — accept verbatim against the default daemon.
    if validate_vault_id_arg(token).is_ok() && token.len() >= 20 {
        let daemon = cfg
            .daemon
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("http://127.0.0.1:{}", crate::config::CONTROL_PORT));
        return Ok((daemon, token.to_string()));
    }
    Err(format!(
        "no vault matches '{}' — run `sc vault ls` and pass its id, a unique id prefix, or its exact name (quote a name with spaces)",
        token
    ))
}

/// Render the "be specific" error when a token matches multiple vaults — lists
/// each candidate's name + short id so the caller can disambiguate.
fn ambiguous_vault_err(token: &str, by: &str, cands: &[&KnownVault]) -> String {
    let list = cands
        .iter()
        .map(|kv| {
            let short = kv.vault.get(..8).unwrap_or(&kv.vault);
            match kv.label.as_deref() {
                Some(l) => format!("  {} ({})", l, short),
                None => format!("  {}", kv.vault),
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "'{}' matches {} vaults by {} — be specific (use the id or a unique prefix):\n{}",
        token,
        cands.len(),
        by,
        list
    )
}

/// Single-vault auto-select (§5): exactly one known vault defaults to it, so a
/// fresh shell needs no `sc vault use` and the agent/human vault can't diverge
/// in the common single-vault case. `None` for zero or many.
fn single_known_entry() -> Option<KnownVault> {
    let mut it = known_vaults().into_iter();
    match (it.next(), it.next()) {
        (Some(kv), None) => Some(kv),
        _ => None,
    }
}

fn single_known_vault() -> Option<String> {
    single_known_entry().map(|kv| kv.vault)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A display name / typo passed as `--vault` must fail at the argument
    /// boundary with the `sc vault ls` pointer, not travel to the daemon and
    /// come back as an opaque "passkeys HTTP 400" (the `sc vault rm
    /// "test vault2"` report).
    #[test]
    fn vault_id_arg_rejects_names_and_accepts_ids() {
        assert!(validate_vault_id_arg("v-abc_123").is_ok());
        assert!(validate_vault_id_arg("test vault2").is_err());
        assert!(validate_vault_id_arg("").is_err());
        assert!(validate_vault_id_arg("http://x/v/id").is_err());
        let msg = validate_vault_id_arg("test vault2").unwrap_err();
        assert!(
            msg.contains("sc vault ls"),
            "error must point at vault ls: {msg}"
        );
    }

    #[test]
    fn split_vault_url_basic() {
        assert_eq!(
            split_vault_url("http://localhost:23295/v/abc"),
            Some(("http://localhost:23295".to_string(), "abc".to_string()))
        );
    }

    #[test]
    fn split_vault_url_no_vid_returns_none() {
        assert_eq!(split_vault_url("http://localhost:23295"), None);
        assert_eq!(split_vault_url("http://localhost:23295/v/"), None);
    }

    #[test]
    fn scheme_host_strips_port_and_path() {
        assert_eq!(
            scheme_host("http://127.0.0.1:23294"),
            Some("http://127.0.0.1".into())
        );
        assert_eq!(
            scheme_host("https://box.example.com:23294/x/y"),
            Some("https://box.example.com".into())
        );
        assert_eq!(
            scheme_host("http://[::1]:23294"),
            Some("http://[::1]".into())
        );
        assert_eq!(scheme_host("no-scheme"), None);
        assert_eq!(scheme_host("http://"), None);
    }

    #[test]
    fn control_root_env_host_wins_config_verbatim_else_default() {
        use crate::config::CONTROL_PORT;
        // hand-edited custom control port in config
        let cfg_daemon = Some("http://127.0.0.1:9999");
        // Env host set (an agent's shell): its HOST + the resolved control port —
        // the single-host invariant (proxy face and control face share a daemon).
        assert_eq!(
            control_root_from(
                Some("https://box.example.com".into()),
                cfg_daemon,
                CONTROL_PORT
            ),
            format!("https://box.example.com:{}", CONTROL_PORT)
        );
        // A moved control port (SAFECLAW_PORT) rides through the env-host branch,
        // so an agent shell carrying a proxy-face BROKER_URL still targets it.
        assert_eq!(
            control_root_from(Some("http://127.0.0.1".into()), cfg_daemon, 23293),
            "http://127.0.0.1:23293"
        );
        // No env: config's control root VERBATIM (custom port preserved).
        assert_eq!(
            control_root_from(None, cfg_daemon, CONTROL_PORT),
            "http://127.0.0.1:9999"
        );
        // Bare machine: loopback default at the resolved port.
        assert_eq!(
            control_root_from(None, None, CONTROL_PORT),
            format!("http://127.0.0.1:{}", CONTROL_PORT)
        );
    }

    #[test]
    fn api_face_root_env_host_wins_port_always_resolved() {
        use crate::config::PROXY_PORT;
        let cfg = CliConfig {
            daemon: Some("http://box.example.com:23299".into()),
            ..Default::default()
        };
        // Env host wins, but the PORT is always proxy_port() — a stale port in
        // the agent's snapshot (`:9999`, an old daemon) is DROPPED, not pinned
        // into the child's HTTPS_PROXY. Symmetric with control_root.
        assert_eq!(
            api_face_root_with(Some("http://box.example.com:9999/".into()), &cfg),
            format!("http://box.example.com:{}", PROXY_PORT)
        );
        // No env: device daemon HOST + the resolved proxy port.
        assert_eq!(
            api_face_root_with(None, &cfg),
            format!("http://box.example.com:{}", PROXY_PORT)
        );
        // A malformed env value (no scheme) falls back to the device HOST — the
        // same parse gate as control_root, so the two can't split on it.
        assert_eq!(
            api_face_root_with(Some("box.example.com:9999".into()), &cfg),
            format!("http://box.example.com:{}", PROXY_PORT)
        );
    }

    #[test]
    fn derive_frontend_strips_api_label() {
        assert_eq!(
            derive_frontend_from_backend("https://api.dev.safeclaw.pro"),
            "https://dev.safeclaw.pro"
        );
        assert_eq!(
            derive_frontend_from_backend("https://api.safeclaw.pro/"),
            "https://safeclaw.pro"
        );
        // No api. prefix (self-host) → unchanged.
        assert_eq!(
            derive_frontend_from_backend("http://localhost:8787"),
            "http://localhost:8787"
        );
        // Only the leading label is stripped; a path is preserved.
        assert_eq!(
            derive_frontend_from_backend("https://api.example.com/base"),
            "https://example.com/base"
        );
    }
}
