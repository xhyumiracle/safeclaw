//! `sc logout` — unpair this machine: the inverse of `sc login`.
//!
//! `sc login` writes three things: the `~/.safeclaw/device-key` (this host's
//! cloud credential), the active pairing in `config.toml` (custodian, vault,
//! cloud_backend, frontend_origin), and the `known_vaults` history. `logout`
//! undoes all of it and stops the daemon, so a re-pair starts clean and the
//! daemon stops syncing / log-spamming on now-orphaned vaults.
//!
//! By default it revokes the cloud-side device-key row too: once the local
//! file is gone its plaintext is unrecoverable, so the server row could never
//! be matched again — leaving it would just accumulate dead "paired devices"
//! in the dashboard. `--keep-remote` skips the cloud revoke (rare; only when
//! something external still manages that key).
//!
//! What we deliberately DON'T touch: the agent's `SAFECLAW_VAULT_URL` /
//! `SAFECLAW_API_KEY` env in the user's shell profile. That's the user's file
//! to edit (per their config-ownership) — we print a reminder instead.

use serde::Deserialize;

use crate::cli::active::{load, save, CliConfig};
use crate::config::LogoutArgs;
use crate::device_auth::DikRequestExt;

pub async fn run(args: LogoutArgs) -> Result<(), String> {
    let cfg = load().unwrap_or_default();
    let was_paired =
        cfg.daemon.is_some() || cfg.cloud_backend.is_some() || crate::sync::device_key().is_some();

    // 1. Revoke the device-key cloud-side (default) — BEFORE we drop the local
    //    credential we'd need to authenticate the revoke. Best-effort: a failure
    //    (e.g. offline) must not block the local unpair. `--keep-remote` skips it.
    if !args.keep_remote {
        match revoke_device_cloud(&cfg).await {
            Ok(Some(label)) => eprintln!("✓ revoked this device cloud-side ({label})"),
            Ok(None) => eprintln!("  (no matching device found cloud-side — nothing to revoke)"),
            Err(e) => eprintln!("  couldn't revoke cloud-side ({e}); continuing with local unpair"),
        }
    }

    // 2. Stop the daemon so it stops serving/syncing this account's vaults and
    //    drops in-memory K. Cross-platform: macOS previously skipped this, so a
    //    self-logout left the daemon running (K in memory, vault.dat on disk) and
    //    kept substituting secrets — the "unpair -> this machine can't use
    //    secrets" expectation has to hold for self-logout too. Best-effort.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let _ = crate::cli::service::run_stop();
    }

    // 2b. Wipe local sealed vault state (`<state_dir>/vaults/`). Unpair means this
    //    machine is out; the sealed blobs are ciphertext (no leak), but leaving
    //    them is untidy and a re-pair re-pulls them from the cloud. Best-effort —
    //    a wipe failure must not block the unpair.
    {
        let vaults_dir = crate::config::default_state_dir().join("vaults");
        if vaults_dir.exists() {
            let _ = std::fs::remove_dir_all(&vaults_dir);
        }
    }

    // 3. Remove the device-key file (this host's identity to the cloud).
    if let Some(home) = dirs::home_dir() {
        let p = home.join(".safeclaw").join("device-key");
        if p.exists() {
            std::fs::remove_file(&p).map_err(|e| format!("remove {}: {}", p.display(), e))?;
        }
    }

    // 4. Clear the pairing from config.toml: active vault, cloud backend,
    //    frontend origin, and the known-vaults catalog (its own file; incl. any
    //    orphans). Preserve user `settings` (e.g. cb_port) — not pairing state.
    let mut cleared = load().unwrap_or_default();
    cleared.daemon = None;
    cleared.vault = None;
    cleared.cloud_backend = None;
    cleared.frontend_origin = None;
    cleared.account_id = None;
    cleared.account_uik = None;
    cleared.vault_deleted_upstream = None;
    cleared.known_vaults.clear();
    save(&cleared)?;
    crate::cli::active::clear_known_vaults()?;

    if was_paired {
        eprintln!("Unpaired this machine — daemon stopped, local pairing cleared.");
    } else {
        eprintln!("Nothing was paired; cleared any stale local config.");
    }
    eprintln!();
    eprintln!("  Your agent's SAFECLAW_* env (BROKER_URL / AGENT_IDENTITY) may");
    eprintln!("  still be persisted in its .env — it's stale now; remove it. Agents stay");
    eprintln!("  valid account-wide (logout revokes only this DEVICE) — revoke unused ones");
    eprintln!("  with `sc agent rm`. Re-pair with `sc login`.");
    Ok(())
}

#[derive(Deserialize)]
struct DeviceKey {
    id: String,
    prefix: String,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize)]
struct DeviceList {
    #[serde(default)]
    keys: Vec<DeviceKey>,
}

/// Find this host's device-key in the account's device list (match on prefix)
/// and DELETE it cloud-side. `Ok(None)` if no row matches (already gone). Uses
/// the same device-key bearer + `/api/vault/devices` endpoints as `sc agent`.
async fn revoke_device_cloud(cfg: &CliConfig) -> Result<Option<String>, String> {
    let cloud = cfg
        .cloud_backend
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or("this device isn't cloud-paired")?;
    let cloud = cloud.trim_end_matches('/');
    let key = crate::sync::device_key().ok_or("no device-key to revoke")?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;

    let list_url = format!("{}/api/vault/devices", cloud);
    let resp = client
        .get(&list_url)
        .bearer_auth(&key)
        .dik_pop("GET", &list_url, &[])
        .send()
        .await
        .map_err(|e| crate::cli::neterr::reach_failed(cloud, &e))?;
    if !resp.status().is_success() {
        return Err(format!("list devices: HTTP {}", resp.status()));
    }
    let list: DeviceList = resp
        .json()
        .await
        .map_err(|e| format!("parse devices: {}", e))?;

    // The device list returns each key's stable PREFIX; our full key starts with it.
    let Some(me) = list.keys.into_iter().find(|d| key.starts_with(&d.prefix)) else {
        return Ok(None);
    };
    let label = me.label.clone().unwrap_or_else(|| me.prefix.clone());

    let del_url = format!("{}/api/vault/devices/{}", cloud, me.id);
    let del = client
        .delete(&del_url)
        .bearer_auth(&key)
        .dik_pop("DELETE", &del_url, &[])
        .send()
        .await
        .map_err(|e| crate::cli::neterr::reach_failed(cloud, &e))?;
    if !del.status().is_success() {
        return Err(format!("revoke: HTTP {}", del.status()));
    }
    Ok(Some(label))
}
