//! `sc agent` — manage this account's agent api-keys.
//!
//! agent ≡ api-key (1:1, account-level). Each agent gets its own `sc_agent_`
//! key; the cloud stores only its hash; the key works on ANY of the account's
//! paired devices (the daemon syncs the hash-set + validates locally). Auth is
//! this device's device-key (account-scoped), so `sc agent` works on any
//! paired machine. See [[project_vault_agent_architecture_2026_06_25]].

use std::time::Duration;

use serde::Deserialize;

use crate::cli::active::load as load_config;
use crate::config::{AgentAddArgs, AgentRmArgs, AgentSubcommand};
use crate::device_auth::DikRequestExt;

pub async fn run(sub: AgentSubcommand) -> Result<(), String> {
    match sub {
        AgentSubcommand::Add(a) => add(a).await,
        AgentSubcommand::Ls => ls().await,
        AgentSubcommand::Rm(a) => rm(a).await,
    }
}

/// Resolve (cloud backend, device-key) — both come from `sc login`.
fn cloud_and_key() -> Result<(String, String), String> {
    let cfg = load_config().map_err(|e| format!("read config: {}", e))?;
    let cloud = cfg
        .cloud_backend
        .filter(|s| !s.is_empty())
        .ok_or("this device isn't paired — run `sc login --pair-token <token>` first")?;
    let key = crate::sync::device_key()
        .ok_or("no device-key — run `sc login --pair-token <token>` first")?;
    Ok((cloud.trim_end_matches('/').to_string(), key))
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client init: {}", e))
}

#[derive(Deserialize)]
struct CreateResp {
    token: String,
}

#[derive(Deserialize)]
struct ListResp {
    keys: Vec<ListKey>,
}

#[derive(Deserialize)]
struct ListKey {
    id: String,
    prefix: String,
    label: Option<String>,
    last_used_at: Option<String>,
}

async fn add(args: AgentAddArgs) -> Result<(), String> {
    let (cloud, key) = cloud_and_key()?;
    let cfg = load_config().unwrap_or_default();
    let broker_url = format!(
        "{}:{}",
        crate::cli::active::device_daemon_host(&cfg),
        crate::config::PROXY_PORT
    );

    // ── Mint this agent's AIK (possession-proven identity; identity wave §2) ──
    // Ed25519 keypair, self-certifying `ag_…` id. The private SEED never leaves
    // this disk (0600) and never enters the agent's env — only the PUBLIC key is
    // registered with the cloud (which relays it to the authorized-agents set the
    // daemon verifies once mTLS ships). Persisted only AFTER the cloud accepts
    // the registration, so a failed create leaves no orphan file.
    let (seed, ag_id) = crate::identity_file::mint(crate::identity::IdKind::Agent);
    let (aik, _) = crate::identity_file::resolve(crate::identity::IdKind::Agent, &seed);
    let aik_pub = data_encoding::BASE64.encode(&aik.public_bytes());
    let identity_path = crate::identity_file::agent_identity_path(&args.name)?;

    let url = format!("{}/api/vault/agents", cloud);
    let body = serde_json::json!({
        "label": args.name,
        "tier": "agent",
        // Additive: an older backend ignores these; a current one records
        // the pubkey for the AIK authorized-set (dual-auth window §7).
        "agent_id": ag_id,
        "agent_pubkey": aik_pub,
    });
    let resp = client()?
        .post(&url)
        .bearer_auth(&key)
        .dik_pop("POST", &url, &serde_json::to_vec(&body).unwrap_or_default())
        .json(&body)
        .send()
        .await
        .map_err(|e| crate::cli::neterr::reach_failed(&cloud, &e))?;
    if !resp.status().is_success() {
        return Err(format!("create agent key failed: HTTP {}", resp.status()));
    }
    let r: CreateResp = resp
        .json()
        .await
        .map_err(|e| format!("parse response: {}", e))?;

    crate::identity_file::write(&identity_path, crate::identity::IdKind::Agent, &seed)?;

    // ── Mint-time projection (CREDENTIAL_BROKER.md §14): this IS the minter ─
    // Print the agent's env as dotenv lines: the daemon's API face, the AIK
    // identity PATH (a path, not a secret — the possession-proven identity, the
    // dual-auth target), and the legacy api-key (still the ACTIVE transport until
    // mTLS flips; kept so nothing bricks — design §7). The agent appends ONE
    // command's stdout to its own `.env` and never assembles a value. STDOUT
    // only; stderr guidance carries NO secret.
    //
    // Deliberately NOT baked: a precomputed proxy URL (froze a host:port that a
    // moved daemon made stale — `sc run` rebuilds it live), and a vault id
    // (froze the device default of mint day into a pin that shadowed
    // `sc vault use` forever — vault is per-call, not identity; see
    // design/vault-addressing.md). Identity-only env self-heals.
    println!("SAFECLAW_BROKER_URL={}", broker_url);
    println!("SAFECLAW_AGENT_IDENTITY={}", identity_path.display());
    println!("SAFECLAW_API_KEY={}", r.token);

    let rm_name = if args.name.contains(char::is_whitespace) {
        format!("'{}'", args.name)
    } else {
        args.name.clone()
    };
    eprintln!(
        "\nAgent '{}' created — its complete SafeClaw env (incl. its api key, shown ONCE) \
         went to stdout. Append those lines to the env file your framework loads, without \
         displaying them. Works on any paired device; revoke: `sc agent rm {}`.",
        args.name, rm_name
    );
    Ok(())
}

async fn fetch_agents(cloud: &str, key: &str) -> Result<Vec<ListKey>, String> {
    // `/api/vault/agents` is already tier-scoped server-side (agent|demo);
    // device-keys live under `/api/vault/devices`.
    let url = format!("{}/api/vault/agents", cloud);
    let resp = client()?
        .get(&url)
        .bearer_auth(key)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .map_err(|e| crate::cli::neterr::reach_failed(&cloud, &e))?;
    if !resp.status().is_success() {
        return Err(format!("list agents failed: HTTP {}", resp.status()));
    }
    let r: ListResp = resp
        .json()
        .await
        .map_err(|e| format!("parse response: {}", e))?;
    Ok(r.keys)
}

async fn ls() -> Result<(), String> {
    let (cloud, key) = cloud_and_key()?;
    let agents = fetch_agents(&cloud, &key).await?;
    if agents.is_empty() {
        println!("(no agents yet — `sc agent add <name>`)");
        return Ok(());
    }
    for k in &agents {
        let label = k.label.clone().unwrap_or_else(|| "(unnamed)".into());
        let last = k.last_used_at.clone().unwrap_or_else(|| "never".into());
        println!("{:<28} {}…  last-used {}", label, k.prefix, last);
    }
    Ok(())
}

async fn rm(args: AgentRmArgs) -> Result<(), String> {
    let (cloud, key) = cloud_and_key()?;
    let agents = fetch_agents(&cloud, &key).await?;
    let matches: Vec<&ListKey> = agents
        .iter()
        .filter(|k| {
            k.label.as_deref() == Some(args.name.as_str())
                || k.id == args.name
                || k.prefix == args.name
        })
        .collect();
    let id = match matches.as_slice() {
        [k] => k.id.clone(),
        [] => {
            return Err(format!(
                "no agent named '{}' (see `sc agent ls`)",
                args.name
            ))
        }
        _ => {
            return Err(format!(
                "'{}' matches multiple agents — remove by id or prefix (`sc agent ls`)",
                args.name
            ))
        }
    };
    let url = format!("{}/api/vault/agents/{}", cloud, id);
    let resp = client()?
        .delete(&url)
        .bearer_auth(&key)
        .dik_pop("DELETE", &url, &[])
        .send()
        .await
        .map_err(|e| crate::cli::neterr::reach_failed(&cloud, &e))?;
    if !resp.status().is_success() {
        return Err(format!("revoke failed: HTTP {}", resp.status()));
    }
    eprintln!(
        "Revoked agent '{}'. Streaming devices drop it within a second; an offline device drops it on its next sync.",
        args.name
    );
    Ok(())
}
