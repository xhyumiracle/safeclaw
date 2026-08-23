//! `sc agent` — manage this account's agent api-keys.
//!
//! agent ≡ api-key (1:1, account-level). Each agent gets its own `sc_agent_`
//! key; the cloud stores only its hash; the key works on ANY of the account's
//! paired devices (the daemon syncs the hash-set + validates locally). Auth is
//! this device's device-key (account-scoped), so `sc agent` works on any
//! paired machine. As of the identity wave each agent ALSO mints an AIK keypair
//! (hop-A PoP identity) here; the api-key stays as the dual-auth legacy path.
//! See [[project_vault_agent_architecture_2026_06_25]].

use std::time::Duration;

use serde::Deserialize;

use crate::cli::active::load as load_config;
use crate::config::{AgentAddArgs, AgentRmArgs, AgentSubcommand};
use crate::device_auth::DikRequestExt;

pub async fn run(sub: AgentSubcommand, json: bool) -> Result<(), String> {
    match sub {
        AgentSubcommand::Add(a) => add(a).await,
        AgentSubcommand::Ls => ls(json).await,
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

/// Device-Flow authorize response for the agent-admission ceremony (§14). Same
/// shape as `sc login`'s AuthorizeResp — a short-lived code pair the human
/// approves at `<console>/pair`.
#[derive(Deserialize)]
struct PairAuthorizeResp {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default)]
    interval: Option<u64>,
}

/// Poll response. `status` ∈ { pending, denied, approved }. Any credential the
/// server returns is ignored — the agent authenticates by its AIK (proof-of-
/// possession), so admission just needs the `approved` signal.
#[derive(Deserialize)]
struct PairPollResp {
    status: String,
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
    // Requires a paired device: the cloud backend to run the admission ceremony
    // against comes from `sc login`. (The ceremony's authorize/poll are
    // unauthenticated — the device_code + AIK PoP are the auth — so the
    // device-key itself isn't sent; requiring pairing is the "this machine
    // belongs to the account" precondition.)
    let (cloud, _key) = cloud_and_key()?;
    let cfg = load_config().unwrap_or_default();
    let broker_url = format!(
        "{}:{}",
        crate::cli::active::device_daemon_host(&cfg),
        crate::config::PROXY_PORT
    );

    // ── Mint this agent's AIK (possession-proven identity; identity wave §2) ──
    // Ed25519 keypair, self-certifying `ag_…` id. The private SEED never leaves
    // this disk (0600) and never enters the agent's env — only the PUBLIC key is
    // sent to the cloud. hop-A verifies the AIK per-CONNECT via a
    // Proxy-Authorization PoP token (DPoP-style), NOT mTLS. Persisted only AFTER
    // the owner approves admission, so a declined/expired ceremony leaves no
    // orphan identity file.
    let (seed, ag_id) = crate::identity_file::mint(crate::identity::IdKind::Agent);
    let (aik, _) = crate::identity_file::resolve(crate::identity::IdKind::Agent, &seed);
    let aik_pub = data_encoding::BASE64.encode(&aik.public_bytes());
    let identity_path = crate::identity_file::agent_identity_path(&args.name)?;

    // ── §14 agent-admission ceremony = the /pair browser confirm ─────────────
    // Adding an agent to the account is an OWNER decision, symmetric to pairing a
    // device: it goes through the same Device-Flow /pair page (ONE primitive),
    // just with principal='agent'. The silent `POST /api/vault/agents` device-key
    // path is retired — a new agent is now PENDING until the owner approves it in
    // the browser (admission = session-auth, no passkey/K; vault access stays the
    // separate K-signed Agents-tab toggle). No secret enters the prompt.
    let client = client()?;
    let auth_body = serde_json::json!({
        "principal": "agent",
        "device_name": args.name,   // the agent's name (reuses the shared column)
        "device_id": ag_id,
        "device_pubkey": aik_pub,
    });
    let auth_url = format!("{}/api/pair/authorize", cloud);
    let resp = client
        .post(&auth_url)
        .json(&auth_body)
        .send()
        .await
        .map_err(|e| crate::cli::neterr::reach_failed(&cloud, &e))?;
    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        let detail = resp.text().await.unwrap_or_default();
        // A 404 here usually means the server predates agent admission via /pair,
        // or `sc` is too old — upgrading is the fix either way.
        return Err(format!(
            "could not start agent authorization (HTTP {}{}). Your `sc` or the \
             server may be too old — run `sc upgrade` and try again.",
            code,
            if detail.trim().is_empty() { String::new() } else { format!(": {}", detail.trim()) }
        ));
    }
    let auth: PairAuthorizeResp = resp
        .json()
        .await
        .map_err(|e| format!("parse authorize response: {}", e))?;

    // PoP: sign the (secret) device_code with the AIK so the server proves — before
    // it admits anything — that we hold the key whose pubkey we registered. §12.3.
    let pop = data_encoding::BASE64.encode(&aik.sign(auth.device_code.as_bytes()));

    let open_uri = auth
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&auth.verification_uri);
    eprintln!();
    eprintln!(
        "To authorize the agent '{}' on your account, open this URL and approve it:",
        args.name
    );
    eprintln!("  {}", open_uri);
    eprintln!("Verification code: {}", auth.user_code);
    eprintln!();
    eprintln!("Waiting for you to approve in the browser…");

    // Poll until approved / denied / expired. Same cadence as `sc login`.
    let interval = auth.interval.unwrap_or(5).clamp(1, 30);
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let presp = client
            .post(format!("{}/api/pair/poll", cloud))
            .json(&serde_json::json!({ "device_code": auth.device_code, "pop": pop }))
            .send()
            .await
            .map_err(|e| crate::cli::neterr::reach_failed(&cloud, &e))?;
        let status = presp.status();
        if status.as_u16() == 410 {
            return Err("authorization code expired before you approved it; run `sc agent add` again.".to_string());
        }
        if !status.is_success() {
            let detail = presp.text().await.unwrap_or_default();
            return Err(format!(
                "agent authorization failed (HTTP {}{})",
                status.as_u16(),
                if detail.trim().is_empty() { String::new() } else { format!(": {}", detail.trim()) }
            ));
        }
        let poll: PairPollResp = presp
            .json()
            .await
            .map_err(|e| format!("parse poll response: {}", e))?;
        match poll.status.as_str() {
            "pending" => continue,
            "denied" => return Err("agent authorization was declined in the browser.".to_string()),
            "approved" => break,
            other => return Err(format!("unexpected authorization status '{}'", other)),
        }
    }

    // Admitted — NOW persist the AIK identity file (0600).
    crate::identity_file::write(&identity_path, crate::identity::IdKind::Agent, &seed)?;

    // ── Mint-time projection (CREDENTIAL_BROKER.md §14): this IS the minter ─
    // The agent's env is now just TWO non-secret lines: the daemon's API face and
    // the AIK identity PATH (a path, not a secret). Auth is the AIK's per-CONNECT
    // proof-of-possession, minted by `sc run`'s transport shim — NO api-key is
    // emitted (it was legacy dual-auth cruft the shim stripped anyway). So there's
    // no secret to guard: this output can be shown, and appended to the agent's env
    // file directly. The daemon still holds an account-roster row for this AIK.
    println!("SAFECLAW_BROKER_URL={}", broker_url);
    println!("SAFECLAW_AGENT_IDENTITY={}", identity_path.display());

    let rm_name = if args.name.contains(char::is_whitespace) {
        format!("'{}'", args.name)
    } else {
        args.name.clone()
    };
    eprintln!(
        "\nAgent '{}' authorized — its SafeClaw env (two non-secret lines: the broker URL \
         and its identity-file path) went to stdout. Append them to the env file your \
         framework loads. It can reach any vault you toggle on for it in the console's \
         Agents tab. Works on any paired device; revoke: `sc agent rm {}`.",
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

async fn ls(json: bool) -> Result<(), String> {
    let (cloud, key) = cloud_and_key()?;
    let agents = fetch_agents(&cloud, &key).await?;
    if json {
        // Machine-readable mirror of the human list: one object per agent.
        let arr: Vec<serde_json::Value> = agents
            .iter()
            .map(|k| {
                serde_json::json!({
                    "id": k.id,
                    "prefix": k.prefix,
                    "label": k.label,
                    "last_used_at": k.last_used_at,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if agents.is_empty() {
        println!("(no agents yet, `sc agent add <name>`)");
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
