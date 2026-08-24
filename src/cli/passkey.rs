//! `safeclaw passkey ...` — manage the active vault's enrolled passkeys.
//!
//! Only `ls` ships today; `add` / `rm` / `rename` need the same
//! WebAuthn + crypto plumbing as `sc vault create` and `sc write`,
//! they'll land alongside those. The placeholder stubs print a clear
//! "deferred" message so the surface is discoverable from `--help`.

use std::time::Duration;

use serde::Deserialize;

use crate::cli::active::resolve_active;
use crate::config::{PasskeyRemoveArgs, PasskeyRenameArgs, PasskeySubcommand};

pub async fn run(sub: PasskeySubcommand, json: bool) -> Result<(), String> {
    match sub {
        PasskeySubcommand::Ls(_a) => run_ls(json).await,
        PasskeySubcommand::Add(_) => Err(
            "passkey add, not yet implemented (needs the /v/new-style crypto ceremony)"
                .into(),
        ),
        PasskeySubcommand::Rm(a) => Err(format!(
            "passkey rm {}, not yet implemented (needs passkey-signed Custom op)",
            a.credential_id
        )),
        PasskeySubcommand::Rename(a) => Err(format!(
            "passkey rename {} -> {}, not yet implemented (daemon has no metadata-update endpoint)",
            a.credential_id, a.new_name
        )),
    }
}

#[derive(Debug, Deserialize)]
struct PasskeysBody {
    #[serde(default)]
    vault_exists: bool,
    #[serde(default)]
    passkeys: Vec<PasskeyMeta>,
}

#[derive(Debug, Deserialize)]
struct PasskeyMeta {
    credential_id: String,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    transports: Vec<String>,
    #[serde(default)]
    last_used_at: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
}

async fn run_ls(json: bool) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let url = format!(
        "{}/v/{}/passkeys",
        custodian.trim_end_matches('/'),
        urlencoding::encode(&vault)
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("reach custodian: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "custodian returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: PasskeysBody = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    if json {
        // Machine-readable mirror of the human table: one object per enrolled
        // passkey (public metadata only). A not-yet-enrolled or empty vault
        // emits an empty array.
        let arr: Vec<serde_json::Value> = body
            .passkeys
            .iter()
            .map(|p| {
                serde_json::json!({
                    "credential_id": p.credential_id,
                    "device_name": p.device_name,
                    "transports": p.transports,
                    "last_used_at": p.last_used_at,
                    "created_at": p.created_at,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if !body.vault_exists {
        println!(
            "(vault {} is not yet enrolled — run `safeclaw setup`)",
            vault
        );
        return Ok(());
    }
    if body.passkeys.is_empty() {
        println!(
            "(vault {} has no passkeys — re-enroll via `safeclaw setup`)",
            vault
        );
        return Ok(());
    }
    let id_w = body
        .passkeys
        .iter()
        .map(|p| p.credential_id.len())
        .max()
        .unwrap_or(0)
        .min(32)
        .max(8);
    println!(
        "  {:<iw$}  {:<24}  {}",
        "CREDENTIAL_ID",
        "DEVICE",
        "LAST USED",
        iw = id_w
    );
    for p in &body.passkeys {
        let id_display = if p.credential_id.len() > id_w {
            format!("{}…", &p.credential_id[..id_w.saturating_sub(1)])
        } else {
            p.credential_id.clone()
        };
        let device = p.device_name.as_deref().unwrap_or("(unnamed)");
        let last_used = p
            .last_used_at
            .as_deref()
            .or(p.created_at.as_deref())
            .unwrap_or("?");
        println!(
            "  {:<iw$}  {:<24}  {}{}",
            id_display,
            device,
            last_used,
            if !p.transports.is_empty() {
                format!("  [{}]", p.transports.join(","))
            } else {
                String::new()
            },
            iw = id_w
        );
    }
    Ok(())
}

#[allow(dead_code)]
fn _silence_unused(_a: PasskeyRemoveArgs, _b: PasskeyRenameArgs) {}
