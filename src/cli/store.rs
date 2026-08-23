//! `safeclaw store ...` — external store inspection.
//!
//! Today: `store ls` only. `connect` / `disconnect` need the Write op
//! path (vault re-encryption), which isn't shipped on the CLI yet — see
//! the pending decision in `[[cli-implementation]]`.

use std::time::Duration;

use serde::Deserialize;

use crate::cli::active::resolve_active;
use crate::config::StoreSubcommand;

pub async fn run(sub: StoreSubcommand, json: bool) -> Result<(), String> {
    match sub {
        StoreSubcommand::Ls(_args) => {
            let (custodian, vault) = resolve_active(None)?;
            ls(&custodian, &vault, json).await
        }
    }
}

#[derive(Debug, Deserialize)]
struct KeysKnown {
    #[serde(default)]
    stores: Vec<StoreEntry>,
    #[serde(default)]
    store_errors: Vec<StoreError>,
}

#[derive(Debug, Deserialize)]
struct StoreEntry {
    id: String,
    kind: String,
    keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StoreError {
    store_id: String,
    error: String,
}

async fn ls(custodian: &str, vault: &str, json: bool) -> Result<(), String> {
    let url = format!(
        "{}/v/{}/secret-keys",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
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
    if resp.status().as_u16() == 409 {
        return Err("vault locked — run `safeclaw unlock` first".into());
    }
    if !resp.status().is_success() {
        return Err(format!(
            "custodian returned HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: KeysKnown = resp.json().await.map_err(|e| format!("parse: {}", e))?;

    if json {
        // Machine-readable mirror of the human table: one object per store (id,
        // kind, key count) plus any per-store list errors.
        let stores: Vec<serde_json::Value> = body
            .stores
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "kind": s.kind,
                    "keys": s.keys.len(),
                })
            })
            .collect();
        let errors: Vec<serde_json::Value> = body
            .store_errors
            .iter()
            .map(|e| serde_json::json!({ "store_id": e.store_id, "error": e.error }))
            .collect();
        let out = serde_json::json!({ "stores": stores, "store_errors": errors });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into())
        );
        return Ok(());
    }

    if body.stores.is_empty() && body.store_errors.is_empty() {
        println!("(no external stores connected)");
        return Ok(());
    }
    let id_w = body
        .stores
        .iter()
        .map(|s| s.id.len())
        .max()
        .unwrap_or(0)
        .max(2);
    let kind_w = body
        .stores
        .iter()
        .map(|s| s.kind.len())
        .max()
        .unwrap_or(0)
        .max(4);
    println!(
        "  {:<iw$}  {:<kw$}  {}",
        "ID",
        "KIND",
        "KEYS",
        iw = id_w,
        kw = kind_w
    );
    for s in &body.stores {
        println!(
            "  {:<iw$}  {:<kw$}  {}",
            s.id,
            s.kind,
            s.keys.len(),
            iw = id_w,
            kw = kind_w
        );
    }
    for e in &body.store_errors {
        eprintln!("note: store {} list failed — {}", e.store_id, e.error);
    }
    Ok(())
}
