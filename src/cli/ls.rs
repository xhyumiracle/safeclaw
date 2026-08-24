//! `safeclaw ls` — list secret names known to the active vault.
//!
//! Hits the custodian's `GET /v/{vid}/secret-keys` (cache-driven; no passkey
//! ceremony). Vault must be Unlocked — the custodian answers `vault_locked`
//! (423) otherwise, rendered with the canonical locked hint (`sc unlock`): a
//! daemon that returned 423 is by definition running, so unlock is the precise
//! fix, not the broader `sc up` (which also covers a down daemon).
//!
//! Output is one row per key with its source tag. Same key surfacing from
//! multiple sources prints multiple rows; whichever source wins resolution
//! is decided at /use time per the per-vault `store_order`, not here.

use std::time::Duration;

use serde::Deserialize;

use crate::cli::active::resolve_active;
use crate::config::CommonArgs;

#[derive(Debug, Deserialize)]
struct KeysKnown {
    native_keys: Vec<String>,
    #[serde(default)]
    stores: Vec<StoreKeys>,
    #[serde(default)]
    store_errors: Vec<StoreError>,
}

#[derive(Debug, Deserialize)]
struct StoreKeys {
    id: String,
    kind: String,
    keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StoreError {
    store_id: String,
    error: String,
}

pub async fn run(_args: CommonArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;

    let url = format!(
        "{}/v/{}/secret-keys",
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
        .map_err(|e| format!("reach custodian at {}: {}", custodian, e))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        if crate::cli::apierr::is_vault_locked(status, &body) {
            return Err(crate::error::VAULT_LOCKED_MSG.into());
        }
        return Err(crate::cli::apierr::line(status, &body).into());
    }
    let body: KeysKnown = resp.json().await.map_err(|e| format!("parse: {}", e))?;

    // Layout: native keys at top (no header — they're the default
    // source for this vault). Each connected external store gets its
    // own labelled section. Avoids the previous two-column form where
    // "native" read like a value sitting in a phantom "type" column.
    let any_native = !body.native_keys.is_empty();
    let any_store = body.stores.iter().any(|s| !s.keys.is_empty());

    if !any_native && !any_store {
        println!("(no keys — vault is empty and no external stores connected)");
    } else {
        for k in &body.native_keys {
            println!("  {}", k);
        }
        let mut printed_anything = any_native;
        for s in &body.stores {
            if s.keys.is_empty() {
                continue;
            }
            if printed_anything {
                println!();
            }
            println!("[{}: {}]", s.kind, s.id);
            for k in &s.keys {
                println!("  {}", k);
            }
            printed_anything = true;
        }
    }

    for e in &body.store_errors {
        eprintln!("note: store {} list failed — {}", e.store_id, e.error);
    }

    Ok(())
}
