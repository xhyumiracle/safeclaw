//! `safeclaw doctor` — quick self-check for "is my CLI set up right?"
//!
//! Read-only. Reports on:
//!   - active profile (which custodian + vault)
//!   - custodian reachability (`/health`)
//!   - whether the vault dir exists on the custodian (vault id resolves)
//!   - whether `$SAFECLAW_API_KEY` is set (informational — the agent's
//!     identity; required for credential substitution, §8)
//!
//! Each check prints a single line `[ok|warn|fail] message`. Exits with
//! non-zero status if any line is `fail` — so CI scripts can gate on it.

use std::time::Duration;

use crate::cli::active::{config_path, resolve_active};

#[derive(Debug, Clone, Copy)]
enum Mark {
    Ok,
    Warn,
    Fail,
}

impl Mark {
    fn label(self) -> &'static str {
        match self {
            Mark::Ok => "ok  ",
            Mark::Warn => "warn",
            Mark::Fail => "fail",
        }
    }
    /// Untrimmed key for machine output (`--json`).
    fn key(self) -> &'static str {
        match self {
            Mark::Ok => "ok",
            Mark::Warn => "warn",
            Mark::Fail => "fail",
        }
    }
}

struct Report {
    rows: Vec<(Mark, String)>,
}

impl Report {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }
    fn push(&mut self, mark: Mark, msg: impl Into<String>) {
        self.rows.push((mark, msg.into()));
    }
    fn print_and_status(&self) -> bool {
        for (m, msg) in &self.rows {
            println!("  [{}] {}", m.label(), msg);
        }
        !self.rows.iter().any(|(m, _)| matches!(m, Mark::Fail))
    }
    /// Render the report either as the human check list or (when `json`) as a
    /// `{ ok, checks: [{ level, message }] }` object mirroring the same rows.
    /// Returns the overall pass/fail status either way.
    fn emit(&self, json: bool) -> bool {
        if !json {
            return self.print_and_status();
        }
        let checks: Vec<serde_json::Value> = self
            .rows
            .iter()
            .map(|(m, msg)| serde_json::json!({ "level": m.key(), "message": msg }))
            .collect();
        let ok = !self.rows.iter().any(|(m, _)| matches!(m, Mark::Fail));
        let out = serde_json::json!({ "ok": ok, "checks": checks });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into())
        );
        ok
    }
}

pub async fn run(json: bool) -> Result<(), String> {
    let mut report = Report::new();

    // Platform + build (debug aid): the first thing a bug report needs — which
    // OS/arch and which CLI build. `std::env::consts` resolves at compile time
    // to the target this binary was built for (macos/linux/windows, x86_64/
    // aarch64), which is exactly the axis platform-specific issues split on.
    report.push(
        Mark::Ok,
        format!(
            "safeclaw {} ({}/{})",
            crate::build_version(),
            std::env::consts::OS,
            std::env::consts::ARCH,
        ),
    );

    // Environment overrides (debug aid): stale/mistaken SAFECLAW_* env vars are a
    // recurring cause of "why is it talking to the wrong port/host?" — a leftover
    // override silently wins over config. List the routing/location vars that are
    // actually set (names + values; these carry no secrets). Secrets are never
    // printed here — $SAFECLAW_API_KEY has its own row below.
    {
        const OVERRIDE_VARS: &[&str] = &[
            "SAFECLAW_PORT",
            "SAFECLAW_PROXY_PORT",
            "SAFECLAW_BROKER_URL",
            "SAFECLAW_DAEMON_URL",
            "SAFECLAW_CLOUD_URL",
            "SAFECLAW_VAULT_URL",
            "SAFECLAW_VAULT_ID",
            "SAFECLAW_STATE_DIR",
            "SAFECLAW_DATA",
            "SAFECLAW_CA_PATH",
        ];
        let set: Vec<String> = OVERRIDE_VARS
            .iter()
            .filter_map(|k| {
                std::env::var(k)
                    .ok()
                    .filter(|v| !v.is_empty())
                    .map(|v| format!("{}={}", k, v))
            })
            .collect();
        if set.is_empty() {
            report.push(Mark::Ok, "env overrides: none");
        } else {
            report.push(Mark::Ok, format!("env overrides: {}", set.join(", ")));
        }
    }

    // Config file
    match config_path() {
        Ok(p) if p.exists() => report.push(Mark::Ok, format!("config: {}", p.display())),
        Ok(p) => report.push(
            Mark::Warn,
            format!(
                "config: {} (missing — run `safeclaw vault create`)",
                p.display()
            ),
        ),
        Err(e) => report.push(Mark::Fail, format!("config path: {}", e)),
    }

    // Active config resolution
    let resolved = resolve_active(None);
    let (custodian, vault) = match resolved {
        Ok(pair) => {
            report.push(
                Mark::Ok,
                format!("active: custodian={} vault={}", pair.0, pair.1),
            );
            pair
        }
        Err(e) => {
            report.push(Mark::Fail, format!("active config: {}", e));
            let _ = report.emit(json);
            return Err("active-config resolution failed".into());
        }
    };

    // Custodian health
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("client init: {}", e))?;
    let health_url = format!("{}/health", custodian.trim_end_matches('/'));
    match client.get(&health_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                let count = body
                    .get("vault_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                report.push(
                    Mark::Ok,
                    format!(
                        "custodian: reachable (version {}, {} vault(s))",
                        version, count
                    ),
                );
            } else {
                report.push(
                    Mark::Fail,
                    format!("custodian: {} returned HTTP {}", custodian, status),
                );
            }
        }
        Err(e) => report.push(Mark::Fail, format!("custodian: unreachable — {}", e)),
    }

    // Vault dir exists?
    let passkeys_url = format!(
        "{}/v/{}/passkeys",
        custodian.trim_end_matches('/'),
        urlencoding::encode(&vault)
    );
    match client.get(&passkeys_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let exists = body
                .get("vault_exists")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let n = body
                .get("passkeys")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if exists {
                report.push(Mark::Ok, format!("vault: enrolled ({} passkey(s))", n));
            } else {
                report.push(
                    Mark::Warn,
                    "vault: not yet enrolled (use the console /try or /vault to set one up)",
                );
            }
        }
        Ok(resp) => report.push(Mark::Warn, format!("vault probe: HTTP {}", resp.status())),
        Err(e) => report.push(Mark::Warn, format!("vault probe: {}", e)),
    }

    // Agent identity (informational): a current agent authenticates by its AIK
    // (`SAFECLAW_AGENT_IDENTITY`, a path to an identity file `sc run` signs with);
    // a legacy agent may instead carry `SAFECLAW_API_KEY`. Either one lets this
    // shell broker credentials, and a human shell needs neither. Report whichever
    // is present so a fully set-up keyless agent is never told it has no agent env.
    match std::env::var("SAFECLAW_AGENT_IDENTITY") {
        Ok(v) if !v.is_empty() => {
            report.push(Mark::Ok, format!("$SAFECLAW_AGENT_IDENTITY: set ({})", v))
        }
        _ => match std::env::var("SAFECLAW_API_KEY") {
            Ok(v) if !v.is_empty() => report.push(
                Mark::Ok,
                format!("$SAFECLAW_API_KEY: set ({} chars, legacy)", v.len()),
            ),
            _ => report.push(
                Mark::Ok,
                "agent identity: none in this shell (fine for a human shell; an \
                 agent gets one from `sc agent add`)",
            ),
        },
    }

    // Egress proxy (informational): the one upstream the daemon + this CLI use to
    // reach the outside internet. Report the effective value and where it came
    // from; NEVER print userinfo. This is config state, not a verdict.
    {
        let file = crate::cli::egress_proxy::load();
        match crate::cli::egress_proxy::effective() {
            None => report.push(
                Mark::Ok,
                "egress proxy: none (connecting directly; loopback is never proxied)",
            ),
            Some(url) => {
                let source = if file.as_deref() == Some(url.as_str()) {
                    "from `sc proxy set`"
                } else {
                    "from shell HTTPS_PROXY (overrides `sc proxy set`)"
                };
                report.push(
                    Mark::Ok,
                    format!("egress proxy: {} ({})", redact_proxy(&url), source),
                );
            }
        }
    }

    // Cloud backend reachability: the egress that `sc agent` / `sc login` / sync
    // depend on. (The custodian check above is the LOCAL daemon over loopback,
    // which is never proxied, so it can't diagnose a real-internet egress
    // problem.) ANY HTTP response proves reachability; only a transport error is
    // "unreachable", and we state that fact WITHOUT asserting a proxy is the
    // cause — at most hinting one (`neterr`), per the objectivity rule.
    match crate::cli::active::load() {
        Ok(cfg) => match cfg.cloud_backend.filter(|s| !s.is_empty()) {
            Some(cloud) => {
                let cloud = cloud.trim_end_matches('/');
                // Probe THROUGH the effective egress proxy — the exact route the
                // daemon's sync takes — so a "reachable" here can't disagree with
                // a daemon that's actually stranded behind a proxy it can't use.
                let cloud_client = crate::cli::egress_proxy::client(Duration::from_secs(5))
                    .unwrap_or_else(|_| client.clone());
                match cloud_client.get(cloud).send().await {
                    Ok(_) => report.push(Mark::Ok, format!("cloud backend: reachable ({})", cloud)),
                    Err(e) => report.push(
                        Mark::Warn,
                        format!(
                            "cloud backend: {}",
                            crate::cli::neterr::reach_failed(cloud, &e)
                        ),
                    ),
                }
            }
            None => report.push(
                Mark::Warn,
                "cloud backend: not paired — run `sc login --pair-token <token>`",
            ),
        },
        // A config-load failure already surfaced as a `fail` row above.
        Err(_) => {}
    }

    let ok = report.emit(json);
    if ok {
        Ok(())
    } else {
        Err("one or more checks failed".into())
    }
}

/// Strip any `user:pass@` userinfo from a proxy URL so creds never print.
fn redact_proxy(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
            format!("{scheme}://{host}")
        }
        None => url
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(url)
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_proxy_drops_userinfo_keeps_host_port() {
        assert_eq!(redact_proxy("http://u:p@box:9999"), "http://box:9999");
        assert_eq!(
            redact_proxy("http://proxy.local:3128"),
            "http://proxy.local:3128"
        );
        assert_eq!(redact_proxy("box:9999"), "box:9999");
        assert_eq!(redact_proxy("u:p@box:9999"), "box:9999");
    }
}
