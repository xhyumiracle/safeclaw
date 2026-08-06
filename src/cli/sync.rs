//! `safeclaw sync` — force an on-demand cloud pull + complete any pending OAuth
//! connect, without waiting for the background watcher. Handy right after a web
//! "Connect" if the console is still showing "Connecting…": it pulls the latest
//! sealed blob and runs the `<conn>_oauth_pending` → exchange → refresh_token
//! step now. No passkey — it only advances already-sealed state.

use crate::cli::active::resolve_active;
use crate::config::SyncArgs;

pub async fn run(_args: SyncArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let url = format!(
        "{}/v/{}/sync",
        custodian.trim_end_matches('/'),
        urlencoding::encode(&vault),
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let resp = client
        .post(&url)
        .send()
        .await
        .map_err(|e| format!("reach daemon at {}: {}", custodian, e))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse daemon response: {}", e))?;
    if body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        let pulled = body
            .get("pulled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        eprintln!(
            "safeclaw sync — ok ({})",
            if pulled {
                "pulled new state from cloud"
            } else {
                "already current"
            }
        );
        report_connects(body.get("connects"));
        Ok(())
    } else {
        // The daemon's sync error crosses a process boundary as a string; if it
        // reads as a backend-reachability failure (e.g. "reach api.safeclaw.pro:
        // …"), append the conditional proxy hint — objectively, without claiming
        // a proxy is missing.
        let raw = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("sync failed");
        Err(crate::cli::neterr::with_proxy_hint(raw))
    }
}

/// Surface what happened to pending OAuth connects this sync, so a daemon-side
/// exchange failure is VISIBLE at the command that triggered it instead of only
/// in `sc logs`. Stays silent when there was nothing pending.
fn report_connects(connects: Option<&serde_json::Value>) {
    let Some(c) = connects else { return };
    let conns = |arr: Option<&serde_json::Value>| -> Vec<String> {
        arr.and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|it| it.get("conn").and_then(|v| v.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };

    let completed: Vec<String> = c
        .get("completed")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !completed.is_empty() {
        eprintln!("  connected: {}", completed.join(", "));
    }

    // Terminal: the console shows "Connect failed — reconnect"; echo the reason.
    if let Some(failed) = c.get("failed").and_then(|v| v.as_array()) {
        for f in failed {
            let conn = f
                .get("conn")
                .and_then(|v| v.as_str())
                .unwrap_or("connection");
            let reason = f
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("rejected");
            eprintln!("  {conn}: connect failed ({reason}) — reconnect from the console.");
        }
    }

    // Transient: the daemon couldn't REACH the provider. Honest, not a hard fail
    // (it retries) — but the signal a user needs to check egress / `sc proxy`.
    let unreached = conns(c.get("unreached"));
    if !unreached.is_empty() {
        let host = c
            .get("unreached")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|it| it.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("the provider");
        eprintln!(
            "  {}: couldn't reach {host} (network/proxy?) — will retry. \
             Behind a proxy? `sc proxy set <url>`.",
            unreached.join(", ")
        );
    }
}
