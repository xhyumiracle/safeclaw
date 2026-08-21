//! The agent-facing connection projection, shared by `sc status` (prints it)
//! and `sc git-credential` (matches git's request host against it).
//!
//! Source is the daemon's per-vault registry `connections` array
//! (`GET /v/{vid}/registry`, auth-free localhost): the rows an agent can actually
//! use — `connected` and carrying at least one ready-made phantom. We surface
//! `{name, hosts, phantoms}` only; the phantom strings are copied verbatim.

use std::time::Duration;

use serde_json::Value;

/// One usable connection as the agent sees it.
#[derive(Debug, Clone)]
pub struct ConnRow {
    pub name: String,
    /// Anchored egress hosts (exact FQDNs).
    pub hosts: Vec<String>,
    /// Ready-made phantom strings (a list — §6).
    pub phantoms: Vec<String>,
    /// The agent-facing `setup` hint of the backing service, when it has one:
    /// how to configure a local tool so its traffic is brokered. Lifted from the
    /// registry's `services` array so `sc connection ls --json` carries it, which
    /// is the keyless agent's only route to it (the api-face registry read is
    /// Bearer-gated). `None` for a raw connection or a service with no hint.
    pub setup: Option<String>,
}

/// Fetch + project the vault's usable connections. `daemon` is the control-plane
/// root (`http://host:CONTROL_PORT`); `vault` the vault id.
pub async fn connections(daemon: &str, vault: &str) -> Result<Vec<ConnRow>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let url = format!(
        "{}/v/{}/registry",
        daemon.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("registry: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("registry HTTP {}", resp.status()));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    Ok(project(&body))
}

/// Pull `{name, hosts, phantoms, setup}` out of the registry `connections`
/// array, resolving each connection's `setup` hint from the `services` array.
fn project(body: &Value) -> Vec<ConnRow> {
    let mut out = Vec::new();
    // service id -> its `setup` hint (present only on the per-vault registry).
    let setup_by_service: std::collections::HashMap<&str, String> = body
        .get("services")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let id = s.get("id").and_then(|v| v.as_str())?;
                    let setup = s.get("setup").and_then(|v| v.as_str())?;
                    Some((id, setup.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let Some(arr) = body.get("connections").and_then(|v| v.as_array()) else {
        return out;
    };
    for s in arr {
        let phantoms: Vec<String> = s
            .get("phantoms")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        // Only rows an agent can use right now: connected + at least one phantom.
        let connected = s
            .get("connected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !connected || phantoms.is_empty() {
            continue;
        }
        let name = s
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let hosts: Vec<String> = s
            .get("hosts")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let setup = s
            .get("service")
            .and_then(|v| v.as_str())
            .and_then(|svc| setup_by_service.get(svc).cloned());
        out.push(ConnRow {
            name,
            hosts,
            phantoms,
            setup,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn projects_connected_rows_with_phantoms() {
        let body = json!({
            "connections": [
                { "id": "github", "connected": true,
                  "hosts": ["api.github.com", "github.com"],
                  "phantoms": ["__sc__github__"] },
                // not connected → dropped
                { "id": "stripe", "connected": false,
                  "hosts": ["api.stripe.com"], "phantoms": ["__sc__stripe__"] },
                // connected but no phantoms → dropped
                { "id": "public", "connected": true, "hosts": ["x.com"] },
            ]
        });
        let rows = project(&body);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "github");
        assert_eq!(rows[0].hosts, vec!["api.github.com", "github.com"]);
        assert_eq!(rows[0].phantoms, vec!["__sc__github__".to_string()]);
    }

    #[test]
    fn empty_on_missing_connections() {
        assert!(project(&json!({})).is_empty());
        // A services-only (static catalog) body has no connections → empty.
        assert!(project(&json!({ "services": [] })).is_empty());
    }
}
