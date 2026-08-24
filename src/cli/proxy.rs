//! `sc proxy set/get/unset` — manage the device's upstream EGRESS proxy.
//!
//! The daemon runs under launchd/systemd and does NOT inherit the operator's
//! shell `HTTPS_PROXY`, so behind a corporate or on-demand proxy its own egress
//! (OAuth code/refresh exchange, the resident proxy's forward hop, `sc upgrade`)
//! would hit the internet directly and time out. This stores the proxy at the
//! device level ([`egress_proxy`]) and HOT-reloads it into the running daemon
//! (`POST /proxy/reload`), which rebuilds its egress clients in place — instant,
//! with NO restart and NO vault re-unlock.

use crate::cli::{active, egress_proxy, service};
use crate::config::ProxySubcommand;

pub async fn run(sub: ProxySubcommand) -> Result<(), String> {
    match sub {
        ProxySubcommand::Set { url } => set(url).await,
        ProxySubcommand::Get => get(),
        ProxySubcommand::Unset => unset().await,
    }
}

/// Accept a bare `host:port` as `http://host:port`; leave a full URL as-is.
fn normalize(url: &str) -> String {
    let u = url.trim();
    if u.contains("://") {
        u.to_string()
    } else {
        format!("http://{}", u)
    }
}

async fn set(url: String) -> Result<(), String> {
    let url = normalize(&url);
    if egress_proxy::load().as_deref() == Some(url.as_str()) {
        eprintln!("Egress proxy already set to {url} — nothing to do.");
        return Ok(());
    }
    egress_proxy::store(&url)?;
    eprintln!("Egress proxy set to {url}.");
    apply_live().await
}

async fn unset() -> Result<(), String> {
    if egress_proxy::load().is_none() {
        eprintln!("No egress proxy configured, nothing to unset.");
        return Ok(());
    }
    egress_proxy::clear()?;
    eprintln!("Egress proxy cleared; the daemon will reach the internet directly.");
    apply_live().await
}

fn get() -> Result<(), String> {
    match egress_proxy::load() {
        Some(url) => {
            println!("{url}");
            // A real shell HTTPS_PROXY overrides the stored value (env > config).
            // Note it so the effective route is never a surprise.
            if let Some(shell) = std::env::var_os("HTTPS_PROXY").filter(|v| !v.is_empty()) {
                let shell = shell.to_string_lossy();
                if shell != url {
                    eprintln!(
                        "note: your shell HTTPS_PROXY ({shell}) overrides this for `sc` \
                         itself; the daemon uses the value above."
                    );
                }
            }
            Ok(())
        }
        None => Err("no egress proxy configured (set one with `sc proxy set <url>`)".to_string()),
    }
}

/// Hot-reload the running daemon's egress clients (`POST /proxy/reload`) so the
/// new value applies immediately — no restart, no vault re-unlock. When no
/// daemon is installed/reachable yet, the stored value is picked up by the first
/// `sc up`. A reload failure is never fatal to `sc proxy set` (the value is
/// already persisted); we just tell the user how it'll take effect.
async fn apply_live() -> Result<(), String> {
    if !service::unit_installed() {
        eprintln!("  (no daemon installed yet — it'll take effect on `sc up`.)");
        return Ok(());
    }
    let cfg = active::load().unwrap_or_default();
    let url = format!(
        "{}/proxy/reload",
        active::control_root(&cfg).trim_end_matches('/')
    );
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Err(format!("http client: {}", e)),
    };
    match client.post(&url).send().await {
        Ok(r) if r.status().is_success() => {
            eprintln!("  Applied to the running daemon (no restart).");
            Ok(())
        }
        Ok(r) => {
            eprintln!(
                "  (daemon returned HTTP {} — restart to apply: `sc restart`)",
                r.status()
            );
            Ok(())
        }
        Err(_) => {
            eprintln!("  (daemon not reachable — it'll take effect on next `sc up`.)");
            Ok(())
        }
    }
}
