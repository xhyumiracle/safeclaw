//! `sc run` — the thin env-paster over the resident proxy + CA.
//!
//! `sc run -- <cmd…>` execs the child with the proxy/CA env bundle merged into
//! the inherited environment; `sc run --export-env` prints the same bundle as
//! shell `export` lines. It spins up NOTHING (the CA and proxy are resident,
//! owned by the daemon) and pastes NO plaintext secret — the agent writes the
//! phantom itself; the proxy substitutes at egress. Spec §6.

use std::path::Path;

use crate::cli::active::{api_face_root, load as load_config, resolve_active};
use crate::cli::env::shell_quote;
use crate::cli::proxy_env::{
    build_bundle, control_plane_up, proxy_url_for_vault, resident_ca_bundle_path, resident_ca_path,
};
use crate::config::RunArgs;

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
    // Friendly hint (user's request): a human shell has no agent identity, so
    // credential substitution will 407. Say so once, up front — non-credential
    // traffic is unaffected, so this is a note, not an error.
    if !args.export_env && !agent_has_key() {
        eprintln!(
            "note: no SafeClaw agent key in this shell — credential substitution will 407. \
             Load your agent env (the file holding SAFECLAW_API_KEY) and retry; this is not a \
             daemon or port problem. Non-credential traffic is unaffected."
        );
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
        for (k, v) in &bundle {
            println!("export {}={}", k, shell_quote(v));
        }
        return Ok(());
    }

    exec_child(&args.cmd, &bundle)
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
