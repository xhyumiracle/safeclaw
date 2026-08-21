//! `sc run` — the thin env-paster over the resident proxy + CA.
//!
//! `sc run -- <cmd…>` execs the child with the proxy/CA env bundle merged into
//! the inherited environment; `sc run --export-env` prints the same bundle as
//! shell `export` lines. It spins up NOTHING (the CA and proxy are resident,
//! owned by the daemon) and pastes NO plaintext secret — the agent writes the
//! phantom itself; the proxy substitutes at egress. Spec §6.

use std::path::Path;

use crate::agent_pop::AgentProxyPopSigner;
use crate::cli::active::{api_face_root, load as load_config, resolve_active};
use crate::cli::agent_shim::{self, ShimConfig};
use crate::cli::env::shell_quote;
use crate::cli::proxy_env::{
    build_bundle, control_plane_up, proxy_url_for_vault, resident_ca_bundle_path, resident_ca_path,
};
use crate::config::RunArgs;
use crate::identity::IdKind;

pub async fn run(args: RunArgs) -> Result<(), String> {
    // clap already makes --export-env and a command mutually exclusive; require
    // that exactly one is present.
    if !args.export_env && args.cmd.is_empty() {
        return Err(
            "nothing to run — `sc run -- <cmd>` to run a command, or `sc run --export-env`".into(),
        );
    }

    let (control, vid) = resolve_active(None)?;
    let ca = resident_ca_path();
    preflight(&ca, &control).await?;

    let proxy_url = agent_proxy_url(&vid);
    // Friendly hint (user's request): a shell with NEITHER an AIK identity nor a
    // legacy api-key can't authenticate credential substitution, so it will 407.
    // Say so once, up front. An AIK agent (SAFECLAW_AGENT_IDENTITY) takes the shim
    // path below and needs no key, so the note must recognize it too, or a keyless
    // agent that is fully set up gets a misleading warning.
    if !args.export_env && !agent_has_key() && load_agent_signer().is_none() {
        eprintln!(
            "note: this shell carries no SafeClaw agent identity, so credential substitution \
             will 407. Load your agent env (SAFECLAW_AGENT_IDENTITY, or a legacy SAFECLAW_API_KEY) \
             and retry. This is not a daemon or port problem; non-credential traffic is unaffected."
        );
    }

    if !args.export_env {
        warn_git_url_specific_proxy(&args.cmd);
    }

    // Hand the child a bundle = broker root + OS trust-store roots (not the
    // broker-only `ca.pem`), so tools without a compiled system-CApath fallback
    // (cargo) can still verify passthrough public hosts. Falls back to the
    // broker-only path on any error, so this never regresses brokered calls.
    let ca_str = resident_ca_bundle_path().to_string_lossy().to_string();
    // Chain onto an already-configured git helper rather than clobber it.
    let parent_count = std::env::var("GIT_CONFIG_COUNT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let mut bundle = build_bundle(&proxy_url, &ca_str, parent_count);
    // Pin the child (and any `sc` it shells — e.g. the git-credential helper) to
    // the SAME vault the proxy is routed to. Without this, `sc run --vault B`
    // routes the proxy to B but the child's `sc git-credential` would resolve the
    // ambient/config vault (§5 env-pin) and look for the connection in the wrong
    // vault — silently defeating the override for git flows.
    bundle.push(("SAFECLAW_VAULT_ID".to_string(), vid.clone()));

    if args.export_env {
        // --export-env stays on the direct path: a printed env can't own a
        // process-lifetime shim, so hop-A's shim only wraps the managed
        // `sc run -- cmd` form below.
        for (k, v) in &bundle {
            println!("export {}={}", k, shell_quote(v));
        }
        return Ok(());
    }

    // hop-A (design/agent-device-identity-mtls.md §9.1): if this shell carries an
    // AIK identity (`SAFECLAW_AGENT_IDENTITY` → an agent identity file), route the
    // child through the sc-transport shim so NO credential lands in the child env
    // — the shim holds the AIK (mints a per-CONNECT PoP) and the api-key (injected
    // as the api-face Bearer), and we strip the inherited key from the child.
    // ADDITIVE / dual-auth: with no AIK identity file this is skipped entirely and
    // the child takes today's direct exec path, so nothing changes for existing
    // agents (none set `SAFECLAW_AGENT_IDENTITY`).
    if let Some(signer) = load_agent_signer() {
        return run_via_shim(&args.cmd, &vid, &ca_str, parent_count, signer).await;
    }

    exec_child(&args.cmd, &bundle)
}

/// A URL-specific `http.<url>.proxy` in a gitconfig FILE outranks even the
/// command-scope `http.proxy` pin the bundle carries (git's URL matching
/// prefers specificity over scope), so git traffic to those URLs bypasses the
/// broker and a phantom reaches the upstream unswapped. That can't be won from
/// the environment — name the keys so the user can scope or drop them.
fn warn_git_url_specific_proxy(cmd: &[String]) {
    let is_git = cmd
        .first()
        .map(|p| Path::new(p).file_stem().is_some_and(|s| s == "git"))
        .unwrap_or(false);
    if !is_git {
        return;
    }
    let Ok(out) = std::process::Command::new("git")
        .args(["config", "--get-regexp", r"^http\..+\.proxy$"])
        .output()
    else {
        return; // no git on PATH / config unreadable — nothing to say
    };
    let found = String::from_utf8_lossy(&out.stdout);
    let found = found.trim();
    if found.is_empty() {
        return;
    }
    eprintln!(
        "note: your git config sets URL-specific proxies — git traffic to those URLs \
         bypasses SafeClaw, so credential substitution won't happen there:\n{found}\n\
         Drop the key (`git config --unset <key>`) if that host should be brokered."
    );
}

/// Load the agent's AIK signer from `SAFECLAW_AGENT_IDENTITY` (a PATH to the
/// agent identity file, per the locked naming — NOT a secret). `None` when unset
/// or not an agent identity, so `sc run` falls back to the direct path.
fn load_agent_signer() -> Option<AgentProxyPopSigner> {
    let path = std::env::var_os("SAFECLAW_AGENT_IDENTITY").filter(|p| !p.is_empty())?;
    let loaded = crate::identity_file::load(Path::new(&path)).ok()?;
    if loaded.kind != IdKind::Agent {
        return None;
    }
    Some(AgentProxyPopSigner::new(loaded.identity, loaded.id))
}

/// The `host:port` authority of a URL (scheme + path stripped) — where the shim
/// forwards to (the real daemon proxy, the same face the child dials today).
fn authority_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split('/').next().unwrap_or(rest).to_string()
}

/// Run the child through the sc-transport shim (hop-A). Starts the shim on an
/// ephemeral loopback port, points the child's `*_PROXY` at it with NO creds in
/// the URL, STRIPS the inherited `SAFECLAW_API_KEY` from the child env (the shim
/// authenticates by AIK PoP, so the child needs — and gets — no credential at
/// all), then SPAWNS (not execs) the child so the shim task keeps serving in this
/// process, waits, and propagates the exit code.
async fn run_via_shim(
    cmd: &[String],
    vid: &str,
    ca_str: &str,
    parent_count: Option<u32>,
    signer: AgentProxyPopSigner,
) -> Result<(), String> {
    let cfg = load_config().unwrap_or_default();
    let daemon_authority = authority_of(&api_face_root(&cfg));
    let (port, shim) = agent_shim::start(ShimConfig {
        vid: vid.to_string(),
        daemon_authority,
        signer,
    })
    .await
    .map_err(|e| format!("start sc transport: {}", e))?;

    // Child proxy → the shim, NO creds in the URL (the shim injects them).
    let shim_url = format!("http://127.0.0.1:{}", port);
    let mut bundle = build_bundle(&shim_url, ca_str, parent_count);
    bundle.push(("SAFECLAW_VAULT_ID".to_string(), vid.to_string()));

    let (prog, rest) = cmd.split_first().ok_or("no command to run")?;
    let mut c = tokio::process::Command::new(prog);
    c.args(rest);
    // The whole point of hop-A: the injectable api-key must NOT be in the child
    // env. The parent shell exported it (that's how a legacy agent authenticates);
    // the shim authenticates by AIK PoP instead, so strip the key from what the
    // child inherits — the child carries no credential at all.
    c.env_remove("SAFECLAW_API_KEY");
    for (k, v) in &bundle {
        c.env(k, v);
    }
    let status = c
        .status()
        .await
        .map_err(|e| format!("spawn {}: {}", prog, e))?;
    shim.abort();
    std::process::exit(status.code().unwrap_or(1));
}

/// The proxy URL the child's `HTTPS_PROXY` gets (CREDENTIAL_BROKER.md §14).
/// Always REBUILT for the resolved vid: the agent's own `$SAFECLAW_API_KEY`
/// spliced into the CURRENT API-face root (same daemon host as everything else —
/// the invariant), never a pre-baked full proxy URL copied verbatim. A snapshot
/// would pin a stale host:port from an old `sc agent add` (a moved daemon → the
/// child's proxy points at a dead port); rebuilding tracks the live daemon and
/// self-heals. `sc run` still never owns or persists the key — it reads the
/// agent's own from the env and splices it in memory only.
fn agent_proxy_url(vid: &str) -> String {
    let key = std::env::var("SAFECLAW_API_KEY")
        .ok()
        .filter(|s| !s.is_empty());
    let cfg = load_config().unwrap_or_default();
    proxy_url_for_vault(&api_face_root(&cfg), vid, key.as_deref())
}

/// Does this shell carry an agent identity? Its `$SAFECLAW_API_KEY`.
fn agent_has_key() -> bool {
    std::env::var("SAFECLAW_API_KEY")
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

/// The CA must exist and the daemon must be up (the proxy shares its process).
/// Otherwise a friendly `sc up` hint — never a mystery TLS / connection error
/// inside the child.
async fn preflight(ca: &Path, control_root: &str) -> Result<(), String> {
    if !ca.exists() {
        return Err(format!(
            "SafeClaw CA not found at {} — the daemon generates it on first start. Run `sc up`, then retry.",
            ca.display()
        ));
    }
    if control_plane_up(control_root).await {
        return Ok(());
    }
    // A stale broker URL (an old `sc agent add` snapshot) points the whole
    // resolution at a daemon HOST that has since moved — name the actual var the
    // agent set (new `SAFECLAW_BROKER_URL` or legacy `SAFECLAW_DAEMON_URL`),
    // rather than the misleading "isn't running" when a daemon may well be up on
    // the default host/port. (A stale PORT alone can't reach here: `control_root`
    // takes only the env HOST and resolves the port itself.)
    if let Some((name, u)) = ["SAFECLAW_BROKER_URL", "SAFECLAW_DAEMON_URL"]
        .into_iter()
        .find_map(|k| {
            std::env::var(k)
                .ok()
                .filter(|s| !s.is_empty())
                .map(|v| (k, v))
        })
    {
        return Err(format!(
            "SafeClaw isn't answering at {control_root} (host from your agent env's \
             {name}={u}). If the daemon moved or restarted elsewhere, unset that \
             stale value or re-run `sc agent add` to re-mint your env, then retry. \
             Otherwise start it with `sc up`."
        ));
    }
    Err("SafeClaw isn't running — bring it up with `sc up`, then retry.".into())
}

/// Exec the child with the bundle merged into the inherited env. On unix this
/// REPLACES the current process (so signals / exit status pass through
/// naturally); it only returns on failure.
#[cfg(unix)]
fn exec_child(cmd: &[String], bundle: &[(String, String)]) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let (prog, rest) = cmd.split_first().ok_or("no command to run")?;
    let mut c = std::process::Command::new(prog);
    c.args(rest);
    for (k, v) in bundle {
        c.env(k, v);
    }
    // exec never returns on success.
    let err = c.exec();
    Err(format!("exec {}: {}", prog, err))
}

/// Non-unix fallback: spawn + wait, propagating the child's exit code.
#[cfg(not(unix))]
fn exec_child(cmd: &[String], bundle: &[(String, String)]) -> Result<(), String> {
    let (prog, rest) = cmd.split_first().ok_or("no command to run")?;
    let mut c = std::process::Command::new(prog);
    c.args(rest);
    for (k, v) in bundle {
        c.env(k, v);
    }
    let status = c.status().map_err(|e| format!("spawn {}: {}", prog, e))?;
    std::process::exit(status.code().unwrap_or(1));
}
