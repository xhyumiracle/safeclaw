//! `sc login --pair-token <X>` — exchange a one-shot pair-token (minted by
//! safeclaw.pro's "Connect a new agent" modal) for this host's persistent
//! cloud-side daemon credential.
//!
//! The CLI POSTs the token to `<custodian>/api/pair-token/exchange`. The
//! pro-backend validates+single-uses the token (10-min TTL) and returns
//! `{ account_id, vault_id, device_key, pro_backend_url }`. We then:
//!
//!   1. Persist `device_key` (a `sc_device_<rand>` token) to
//!      `~/.safeclaw/device-key` (mode 0600). This is the daemon→cloud auth
//!      token — Token 2 — distinct from `~/.safeclaw/api-key`, which is the
//!      local agent→daemon broker key (Token 1). The agent never sees the
//!      device-key.
//!   2. Persist `(pro_backend_url, account_id)` as the active CLI vault via
//!      `active::put_active(...)`. account_id doubles as the vault id under
//!      the V1 §12.2 account-bound model.
//!
//! Idempotent: re-running with a fresh token simply overwrites both files.
//! `sc up` reads the credential at start time.

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::cli::active::put_active_with_cloud;
use crate::config::LoginArgs;

/// Default daemon control-plane port (matches `ServeArgs` `SAFECLAW_PORT`).
const DEFAULT_DAEMON_PORT: u16 = crate::config::CONTROL_PORT;

/// Resolve which cloud the pair-token is exchanged against. Precedence:
///   1. `SAFECLAW_CLOUD_URL` — runtime self-host escape hatch (any URL; HTTPS
///      enforced below). Undocumented; for people running their own custodian.
///   2. `--env {prod,dev}` — the FIRST-PARTY selector the console's install
///      prompt uses. It is a SYMBOL, not a URL: it resolves only against the
///      compiled-in allowlist below. This is deliberate — `sc login` has no
///      `--custodian <url>` flag, because a malicious skill prompt could
///      otherwise redirect pairing to an attacker host. A symbol bounded to
///      first-party domains means a hostile prompt can at worst flip you
///      between your OWN prod/dev, never to a third party. The prod console
///      omits the flag (→ default prod); the dev console appends `--env dev`.
///   3. `SAFECLAW_BAKED_CLOUD_URL` — compile-time self-host bake.
///   4. Default: prod. Every real user only ever deals with prod.
/// The resolved value is only the target at `sc login` time; once paired, the
/// machine is pinned to the backend persisted in config.toml, so this never
/// matters again for that machine.
fn resolve_custodian(env_flag: Option<&str>) -> Result<String, String> {
    if let Ok(u) = std::env::var("SAFECLAW_CLOUD_URL") {
        if !u.is_empty() {
            return Ok(u);
        }
    }
    if let Some(env) = env_flag {
        return env_selector_to_url(env);
    }
    if let Some(u) = option_env!("SAFECLAW_BAKED_CLOUD_URL") {
        if !u.is_empty() {
            return Ok(u.to_string());
        }
    }
    Ok("https://safeclaw.pro".to_string())
}

/// The `--env` allowlist. A SYMBOL → first-party URL only; anything else is a
/// hard error. This is the gate that keeps a hostile install prompt from
/// steering pairing off first-party domains — do not widen it to accept URLs.
fn env_selector_to_url(env: &str) -> Result<String, String> {
    match env {
        "prod" => Ok("https://safeclaw.pro".to_string()),
        "dev" => Ok("https://dev.safeclaw.pro".to_string()),
        other => Err(format!(
            "unknown --env '{}': expected 'prod' or 'dev'",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::env_selector_to_url;

    #[test]
    fn env_selector_allowlist_maps_first_party_only() {
        assert_eq!(env_selector_to_url("prod").unwrap(), "https://safeclaw.pro");
        assert_eq!(
            env_selector_to_url("dev").unwrap(),
            "https://dev.safeclaw.pro"
        );
        // Anything that is not an exact first-party symbol is rejected — a
        // hostile prompt cannot smuggle a custodian URL through `--env`.
        assert!(env_selector_to_url("https://attacker.com").is_err());
        assert!(env_selector_to_url("staging").is_err());
        assert!(env_selector_to_url("").is_err());
    }
}

#[derive(Debug, Deserialize)]
struct ExchangeResp {
    account_id: String,
    vault_id: String,
    device_key: String,
    pro_backend_url: String,
    /// Cloud FRONTEND origin (web approval page host). Optional for forward-
    /// compat with older backends; the daemon derives it from
    /// `pro_backend_url` when absent.
    #[serde(default)]
    console_url: Option<String>,
}

pub async fn run(args: LoginArgs) -> Result<(), String> {
    // ── Resolve cloud endpoint: env override > --env selector > baked ─────
    let custodian = resolve_custodian(args.env.as_deref())?;
    let custodian = custodian.trim_end_matches('/').to_string();

    // ── Enforce HTTPS for the custodian URL ──────────────────────────────
    // The pair-token is single-use but high-value (POSTing it returns the
    // device_key), and the response carries `pro_backend_url` +
    // `device_key` which we persist and trust on subsequent runs. An
    // `http://` custodian leaks the token on the wire AND lets an on-path
    // attacker swap the response for an attacker-controlled daemon. Reject
    // by default; the only legitimate cleartext case is dev-loopback.
    if !args.insecure_http && !custodian.starts_with("https://") && !is_localhost_http(&custodian) {
        return Err(format!(
            "custodian URL must use HTTPS ({} is plaintext); \
             pass --insecure-http to override (test-only)",
            custodian
        ));
    }

    // ── Resolve device name: flag > OS hostname > $HOSTNAME / $COMPUTERNAME
    //    env > literal. The hostname syscall is the reliable source — the env
    //    vars are unset in most non-login / non-interactive shells, which is
    //    what used to strand a device on the "agent-device" fallback. ──
    let device_name = args
        .device_name
        .clone()
        .or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "agent-device".to_string());

    // ── POST <custodian>/api/pair-token/exchange ─────────────────────────
    // Dedicated 10s timeout; this is a single round-trip and we don't want
    // it to inherit the longer browser-gesture timeouts other CLI calls use.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;

    // ── Device identity (DIK): reuse this machine's keypair or mint a fresh one
    // (identity wave §5). Stable across re-logins so a device keeps one `dev_…`
    // id. The private SEED stays on disk (0600, `~/.safeclaw/device/identity`);
    // only the PUBLIC key is registered with the cloud (authorized-devices set),
    // additive to the legacy device-key bearer that still authenticates
    // daemon↔cloud during the dual-auth window (§7).
    let dik_path = crate::identity_file::device_identity_path()?;
    let (dik_seed, dev_id) = match crate::identity_file::load(&dik_path) {
        Ok(loaded) if loaded.kind == crate::identity::IdKind::Device => (loaded.seed, loaded.id),
        _ => crate::identity_file::mint(crate::identity::IdKind::Device),
    };
    let (dik, _) = crate::identity_file::resolve(crate::identity::IdKind::Device, &dik_seed);
    let dik_pub = data_encoding::BASE64.encode(&dik.public_bytes());

    let body = json!({
        "pair_token": args.pair_token,
        "device_name": device_name,
        // Additive: an older custodian ignores these; a current one records the
        // pubkey for the authorized-devices set.
        "device_id": dev_id,
        "device_pubkey": dik_pub,
    });

    let url = format!("{}/api/pair-token/exchange", custodian);
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| crate::cli::neterr::reach_failed(&custodian, &e))?;

    let status = resp.status();
    if !status.is_success() {
        let detail = resp.text().await.unwrap_or_default();
        let detail_trimmed = detail.trim();
        return Err(match status.as_u16() {
            401 => format!(
                "pair-token invalid or unknown. Generate a new one at {}/dashboard (\"Connect a new agent\").",
                custodian
            ),
            // 409 = `no_vault`: the vault this token was pinned to is gone
            // (deleted between mint and exchange), or the account has nothing
            // sealed. The server message says which — surface it verbatim.
            // (Historically 409 meant "already used"; that's 401 now.)
            409 => {
                let msg = serde_json::from_str::<serde_json::Value>(detail_trimmed)
                    .ok()
                    .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_string))
                    .unwrap_or_else(|| "no vault to connect".to_string());
                format!(
                    "{}. Generate a new install token at {}/dashboard (\"Connect a new agent\").",
                    msg, custodian
                )
            }
            410 => format!(
                "pair-token expired. Generate a new one at {}/dashboard (\"Connect a new agent\").",
                custodian
            ),
            other => {
                if detail_trimmed.is_empty() {
                    format!("custodian returned HTTP {}", other)
                } else {
                    format!("custodian returned HTTP {}: {}", other, detail_trimmed)
                }
            }
        });
    }

    let parsed: ExchangeResp = resp
        .json()
        .await
        .map_err(|e| format!("parse exchange response: {}", e))?;

    // ── Persist the device-key to ~/.safeclaw/device-key (0600) ──────────
    let key_path = device_key_path()?;
    write_device_key(&key_path, &parsed.device_key)?;

    // ── Persist the DIK identity file (0600) after a successful exchange ──
    // Idempotent when reused. The daemon reads this for the daemon↔cloud mTLS /
    // signed-request path once hop-B ships; until then the device-key bearer
    // above stays the active transport.
    if let Err(e) = crate::identity_file::write(&dik_path, crate::identity::IdKind::Device, &dik_seed)
    {
        // Non-fatal: pairing succeeded; the DIK is an additive upgrade. Warn but
        // don't strand the device on a write hiccup.
        eprintln!("warning: could not persist device identity ({e}); device-key pairing still succeeded");
    }

    // ── Persist active vault + cloud sync coordinates ────────────────────
    // The AGENT talks to the LOCAL daemon (active `custodian`), not the
    // cloud — the daemon brokers locally and only the daemon reaches the
    // cloud, for sealed-blob sync (Slice 3). So active custodian = the
    // localhost daemon URL, and we record `pro_backend_url` separately as
    // `cloud_backend` for the daemon's pull/push. Use the server-returned
    // pro_backend_url (source of truth) over the request custodian — they
    // normally match, but the server can canonicalize the host.
    let pro_backend_url = parsed.pro_backend_url.trim_end_matches('/').to_string();
    let daemon_port = std::env::var("SAFECLAW_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_DAEMON_PORT);
    let local_custodian = format!("http://127.0.0.1:{}", daemon_port);
    put_active_with_cloud(
        &local_custodian,
        &parsed.vault_id,
        &pro_backend_url,
        parsed.console_url.as_deref(),
    )
    .map_err(|e| format!("save active config: {}", e))?;

    eprintln!(
        "Paired to {} (vault {}); your agent talks to {}.",
        pro_backend_url, parsed.vault_id, local_custodian
    );
    if parsed.account_id != parsed.vault_id {
        eprintln!("  account: {}", parsed.account_id);
    }

    // Bring SafeClaw to a ready state right after pairing: get the daemon
    // running on the just-persisted pairing config, then unlock via the single
    // chokepoint — so the agent never runs a separate up/unlock and the user
    // just taps a passkey. `login` ⊃ `restart` ⊃ `unlock`: we reuse the same
    // bring-up verbs rather than re-implementing them here.
    // Best-effort: pairing already succeeded; if bring-up can't run (e.g. a
    // non-Linux host with no service manager), point the user at `sc up`.
    eprintln!("Starting SafeClaw and unlocking your vault…");
    if crate::cli::service::unit_installed() {
        // Re-pair / post-upgrade: a daemon may already be running on the OLD
        // pairing config. Bounce it so it reloads the just-persisted config,
        // then unlock — exactly `sc restart`. Critical for the WebAuthn
        // origin/rpId, which `from_serve_args` reads ONCE at startup: a stale
        // daemon would validate grants against localhost and reject the
        // web-gestured unlock. Routing through `restart` (not a unit rewrite)
        // also avoids re-baking a stale `SAFECLAW_*` env into the unit.
        if let Err(e) = crate::cli::up::restart().await {
            eprintln!("  couldn't finish bring-up ({e}); run `sc up` to finish.");
        }
    } else {
        // First pairing on this host: install + start the service (its fresh
        // config is already correct, so no bounce needed), then unlock.
        if let Err(e) = crate::cli::service::run_start_systemd(false).await {
            eprintln!("  couldn't auto-start the daemon ({e}); run `sc up` to finish.");
            return Ok(());
        }
        if let Err(e) = crate::cli::up::ensure_unlocked().await {
            eprintln!("  couldn't auto-unlock ({e}); run `sc up` to finish.");
        }
    }

    Ok(())
}

/// Loopback-exemption check for the HTTPS gate: `http://localhost[:PORT]`
/// and `http://127.0.0.1[:PORT]` (with optional trailing path) are allowed
/// without `--insecure-http` because the traffic never leaves the host. We
/// intentionally do NOT exempt `0.0.0.0`, `[::1]`, or arbitrary RFC1918
/// addresses — those can be reachable from off-host on misconfigured nets,
/// and the gate is the conservative call.
fn is_localhost_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    // host[:port] is everything before the first '/'
    let host_port = rest.split('/').next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("");
    host == "localhost" || host == "127.0.0.1"
}

/// `~/.safeclaw/device-key` — the cloud-side device key (Token 2,
/// a `sc_device_...` token) persisted after `sc login`. Distinct from
/// `~/.safeclaw/api-key` (the local agent→daemon broker key, Token 1):
/// this one is used by the daemon itself to authenticate against the SaaS
/// op-relay once Slice C wires daemon→cloud registration. The agent never
/// sees it.
fn device_key_path() -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "cannot locate home dir".to_string())?;
    Ok(home.join(".safeclaw").join("device-key"))
}

fn write_device_key(path: &std::path::Path, device_key: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }
    std::fs::write(path, device_key).map_err(|e| format!("write {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort chmod — we don't fail the login if perms can't be
        // tightened on exotic filesystems.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}
