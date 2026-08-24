//! Daemon read-only diagnostics: `sc pubkey` (HPKE outer-envelope key, fetched
//! from a running daemon) and `sc registry` (public service catalog, rendered
//! OFFLINE from the compiled-in services — no daemon needed). Daemon lifecycle
//! (up / down / restart / logs / serve) lives in `service` + `up`; vault/daemon
//! status in `status`.

use crate::cli::active::resolve_active;
use crate::config::CommonArgs;

pub async fn pubkey(args: CommonArgs) -> Result<(), String> {
    fetch_print(args, "/pubkey").await
}

/// `sc registry` — render the static service catalog from the compiled-in
/// services, no running daemon. This is the exact shape `GET /registry` serves;
/// CI runs `sc registry --json` to publish the catalog artifact the console
/// reads. Offline by construction (`ServiceRegistry::compiled_only()`).
pub fn registry(json: bool) -> Result<(), String> {
    let reg = crate::service::ServiceRegistry::compiled_only();
    // include_policy_rules = true: this catalog is the SSoT the CONSOLE reads
    // (CI publishes it as registry.json) and the policy panel needs each
    // service's per-action rules. The agent-facing `GET /registry` still omits
    // them by default (lean); only this published artifact opts in.
    let catalog = crate::server::handlers::registry::render_catalog(&reg, true, None, false)
        .map_err(|e| e.to_string())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&catalog).map_err(|e| e.to_string())?
        );
    } else {
        println!("{:<24} {:<30} TAGS", "ID", "NAME");
        for s in &catalog.services {
            println!("{:<24} {:<30} {}", s.id, s.name, s.tags.join(","));
        }
    }
    Ok(())
}

async fn fetch_print(_args: CommonArgs, path: &str) -> Result<(), String> {
    let daemon = resolve_daemon_url()?;
    let url = format!("{}{}", daemon.trim_end_matches('/'), path);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("reach daemon: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&body).unwrap_or_default()
    );
    Ok(())
}

/// The daemon control root. `resolve_active` errs only when no vault is
/// selected — fall back to the SAME shared derivation (env-first host), not a
/// hardcoded localhost that would ignore an agent's `$SAFECLAW_BROKER_URL`.
fn resolve_daemon_url() -> Result<String, String> {
    if let Ok((c, _)) = resolve_active(None) {
        return Ok(c);
    }
    let cfg = crate::cli::active::load().unwrap_or_default();
    Ok(crate::cli::active::control_root(&cfg))
}
