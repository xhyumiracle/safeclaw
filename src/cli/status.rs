//! `safeclaw status` / `safeclaw vault status` — current vault status.

use crate::cli::active::{frontend_origin, join_vault_url, load as load_config};
use crate::config::StatusArgs;

#[derive(Debug)]
pub struct VaultStatus {
    pub url: String,
    /// Web console page for this vault (`{frontend_origin}/vault/{id}`) — the
    /// one URL here that IS meant for a browser. `None` when the device was
    /// never paired (local-only / self-host: no console exists).
    pub console: Option<String>,
    pub state: VaultState,
}

#[derive(Debug, PartialEq)]
pub enum VaultState {
    /// Daemon unreachable.
    Unreachable,
    /// Vault id doesn't exist on the custodian.
    NotFound,
    /// Vault locked. Passkey count from /passkeys.
    Locked { passkeys: usize },
    /// Vault unlocked. Passkey + native-secret counts.
    Unlocked { passkeys: usize, secrets: usize },
}

/// Snapshot of the local daemon: is it up, and (if so) how many vaults
/// does it know about? Lets us give precise post-`sc start` guidance
/// like "daemon is up with 0 vaults — run `sc vault create`". ~400ms.
pub struct LocalDaemon {
    pub up: bool,
    pub version: Option<String>,
    pub vault_count: Option<u64>,
}

pub async fn probe_local_daemon(control_root: &str) -> LocalDaemon {
    // Liveness must AGREE with the signal `sc up` gates on. `sc up` no-ops when a
    // raw TCP connect to the control port succeeds (service::control_port_alive),
    // so `sc status` has to call that same daemon "running" or the two verbs
    // contradict each other: the fresh-Mac wedge where `sc up` returns done,
    // `sc status` says not-running, and `sc serve` then fails address-in-use. A
    // raw connect also refuses instantly when the daemon is truly down, so the
    // common "down" verdict stays snappy.
    if !control_port_tcp_alive(control_root).await {
        return LocalDaemon {
            up: false,
            version: None,
            vault_count: None,
        };
    }
    // Socket is held ⇒ the daemon IS up. Enrich with version/vault_count via an
    // HTTP /health round-trip, retried briefly: a cold multi-vault start can bind
    // the port a beat before /health answers, and a proxy-leaked or slow shot must
    // not erase the "running" verdict the TCP connect already proved.
    let health_url = format!("{}/health", control_root.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(700))
        .build()
        .ok();
    if let Some(client) = client.as_ref() {
        for attempt in 0..3u8 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            if let Ok(r) = client.get(&health_url).send().await {
                if r.status().is_success() {
                    let body: serde_json::Value =
                        r.json().await.unwrap_or(serde_json::Value::Null);
                    let version = body
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let vault_count = body.get("vault_count").and_then(|v| v.as_u64());
                    return LocalDaemon {
                        up: true,
                        version,
                        vault_count,
                    };
                }
            }
        }
    }
    // Socket held but HTTP wouldn't complete (proxy leak / still mid-start). Still
    // up: report running without version rather than contradict `sc up`.
    LocalDaemon {
        up: true,
        version: None,
        vault_count: None,
    }
}

/// Raw TCP liveness on the control port — the SAME honest signal
/// `service::control_port_alive` uses to gate `sc up`, so `sc status` can never
/// disagree with it. Targets the same host:port the HTTP probe resolves
/// (loopback in the normal case; an env-pinned host when a shell carries a
/// `$SAFECLAW_BROKER_URL`). Fully async so it never blocks the runtime; ~600ms
/// ceiling, but a down daemon refuses immediately.
async fn control_port_tcp_alive(control_root: &str) -> bool {
    let authority = control_root
        .trim_end_matches('/')
        .split("://")
        .last()
        .unwrap_or(control_root)
        .to_string();
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_millis(600),
            tokio::net::TcpStream::connect(authority.as_str()),
        )
        .await,
        Ok(Ok(_))
    )
}

pub async fn fetch_status(custodian: &str, vault: &str) -> VaultStatus {
    let url = join_vault_url(custodian, vault);
    // Mirrors the console's route shape (`/vault/{id}`, see fe vault-nav).
    let console = frontend_origin().map(|o| format!("{}/vault/{}", o, vault));
    let status = |state| VaultStatus {
        url: url.clone(),
        console: console.clone(),
        state,
    };
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return status(VaultState::Unreachable),
    };

    let pk_url = format!(
        "{}/v/{}/passkeys",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let pk_resp = match client.get(&pk_url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return status(VaultState::Unreachable),
    };
    let pk_body: serde_json::Value = match pk_resp.json().await {
        Ok(b) => b,
        Err(_) => return status(VaultState::Unreachable),
    };
    let exists = pk_body
        .get("vault_exists")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !exists {
        return status(VaultState::NotFound);
    }
    let passkeys = pk_body
        .get("passkeys")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    let kk_url = format!(
        "{}/v/{}/secret-keys",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    match client.get(&kk_url).send().await {
        Ok(r) if r.status().is_success() => {
            let n = r
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|b| {
                    b.get("native_keys")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                })
                .unwrap_or(0);
            status(VaultState::Unlocked {
                passkeys,
                secrets: n,
            })
        }
        Ok(r) if r.status().as_u16() == 409 => status(VaultState::Locked { passkeys }),
        _ => status(VaultState::Locked { passkeys }),
    }
}

pub async fn run(args: StatusArgs) -> Result<(), String> {
    let cfg = load_config()?;
    // ONE control root for the probe and every fetch below — derived env-first
    // (an agent's shelled `sc status` reports the agent's own daemon).
    let control = crate::cli::active::control_root(&cfg);
    let d = probe_local_daemon(&control).await;

    // Vault resolution mirrors `resolve_active` (§5): global `--vault` flag >
    // env pin > config default. Surface pin AND default so a shell pinned to a
    // different vault than the device default is legible (no coined verdict — the
    // facts). Routing DETECTION is gone (§9): the broker is opt-in, the agent
    // routes explicitly with `sc run`, so there's no "am I routed?" to report.
    let flag = crate::cli::active::vault_flag();
    let env_pin = std::env::var("SAFECLAW_VAULT_ID")
        .ok()
        .filter(|s| !s.is_empty());
    let config_default = cfg.vault.clone();
    let active_vault = flag
        .clone()
        .or_else(|| env_pin.clone())
        .or_else(|| config_default.clone());

    let vault = match active_vault.as_deref() {
        Some(v) => Some(fetch_status(&control, v).await),
        None => None,
    };

    // The daemon's two local faces, resolved the same env-first way every `sc`
    // call resolves them. Neither is a web page: `control` is what this CLI
    // probes, `broker` is what `sc run` wires into an agent's HTTPS_PROXY.
    // Shown even when the probe failed — "not running" with the probed control
    // URL next to it is exactly what makes a moved port diagnosable.
    let broker = crate::cli::active::api_face_root(&cfg);

    if args.json {
        print_json(
            &d,
            &control,
            &broker,
            &vault,
            env_pin.as_deref(),
            config_default.as_deref(),
        );
        return Ok(());
    }

    // ── Daemon ──────────────────────────────────────────────────────────
    println!("daemon");
    if d.up {
        println!("  state:   running");
        if let Some(v) = &d.version {
            println!("  version: {}", v);
        }
        if let Some(n) = d.vault_count {
            println!("  vaults:  {}", n);
        }
    } else {
        println!("  state:   not running — bring it up with `sc up`");
    }
    println!("  control: {}", control);
    println!("  broker:  {} (agent face; wired by `sc run`)", broker);
    // A shell carrying a stale `$SAFECLAW_BROKER_URL` snapshot (old `sc agent
    // add`, daemon since moved) is the port-mismatch case status exists to make
    // legible: the resolution above self-heals, so show the divergence.
    if let Some(env_url) = crate::cli::active::env_broker_url() {
        if env_url.trim_end_matches('/') != broker {
            println!("  note:    this shell's $SAFECLAW_BROKER_URL ({}) is stale; `sc run` uses the broker face above", env_url);
        }
    }
    println!();

    // ── Login (device pairing) ──────────────────────────────────────────
    // WHERE this host is paired, and which first-party environment — so a dev
    // login is never mistaken for prod. Derived from the cloud origin persisted
    // at `sc login`; `None` means a local-only daemon that was never paired.
    println!("login");
    match frontend_origin() {
        Some(origin) => {
            let host = origin_host(&origin);
            println!("  state: logged in");
            println!("  cloud: {} ({})", host, env_label(host));
        }
        None => println!("  state: not logged in — run `sc login`"),
    }
    println!();

    // ── Active vault ────────────────────────────────────────────────────
    match &vault {
        Some(s) => print_status(s),
        None => {
            println!("active vault");
            println!("  state: none selected");
            if let Some(dead) = cfg.vault_deleted_upstream.as_deref() {
                // Stranded by an upstream delete — "no vaults yet" would read
                // as if this device was never set up, when the truth is its
                // vault was deleted on the web. Name it and point at re-pairing.
                println!(
                    "  note:  vault {} was deleted on the web; this device's pairing to it is gone",
                    dead
                );
                println!("  hint:  generate a new install token in the console (\"Connect a new agent\"), then `sc login`");
            } else if d.vault_count == Some(0) {
                println!("  hint:  no vaults yet — seal one on the web, then `sc login`");
            } else if crate::cli::active::known_vaults().is_empty() {
                println!("  hint:  pick one with `sc vault use`, or `sc vault create`");
            } else {
                println!("  hint:  pick one with `sc vault use` (`sc vault ls` to list)");
            }
        }
    }
    // Pin-vs-config (§5): flag a shell pinned to a different vault than the device
    // default so a surprising `sc` target is legible. Suppressed under an explicit
    // `--vault` (a deliberate per-call choice needs no warning).
    if flag.is_none() {
        if let (Some(pin), Some(def)) = (env_pin.as_deref(), config_default.as_deref()) {
            if pin != def {
                println!("  note:  this shell is pinned to {} via $SAFECLAW_VAULT_ID; the device default is {}", pin, def);
                println!("         unset SAFECLAW_VAULT_ID to follow the default");
            }
        }
    }
    // Connections are NOT shown here: while the vault is locked they can't be
    // enumerated, so a "(none)" line would read as "you have zero" when the
    // truth is "unknown until unlocked". The agent discovers them through the
    // registry endpoint, and the human lists them with `sc connection ls`.
    Ok(())
}

/// `https://dev.safeclaw.pro/foo` → `dev.safeclaw.pro`. Scheme and any path are
/// dropped; a bare host (no scheme) is returned unchanged.
fn origin_host(origin: &str) -> &str {
    origin
        .split_once("://")
        .map_or(origin, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or(origin)
}

/// Short environment label for a paired cloud host: the first-party prod / dev
/// domains, else `self-host`. Purely cosmetic — it never gates anything.
fn env_label(host: &str) -> &'static str {
    match host {
        "safeclaw.pro" => "prod",
        "dev.safeclaw.pro" => "dev",
        _ => "self-host",
    }
}

fn print_json(
    d: &LocalDaemon,
    control: &str,
    broker: &str,
    vault: &Option<VaultStatus>,
    env_pin: Option<&str>,
    config_default: Option<&str>,
) {
    let vault_json = vault.as_ref().map(|s| {
        let (state, passkeys, secrets) = match &s.state {
            VaultState::Unreachable => ("unreachable", None, None),
            VaultState::NotFound => ("not_found", None, None),
            VaultState::Locked { passkeys } => ("locked", Some(*passkeys), None),
            VaultState::Unlocked { passkeys, secrets } => {
                ("unlocked", Some(*passkeys), Some(*secrets))
            }
        };
        serde_json::json!({
            "url": s.url,
            "console": s.console,
            "state": state,
            "passkeys": passkeys,
            "secrets": secrets,
        })
    });
    let login_json = match frontend_origin() {
        Some(origin) => {
            let host = origin_host(&origin).to_string();
            let env = env_label(&host);
            serde_json::json!({ "logged_in": true, "cloud": host, "env": env })
        }
        None => serde_json::json!({ "logged_in": false }),
    };
    let mismatch = matches!((env_pin, config_default), (Some(p), Some(c)) if p != c);
    let out = serde_json::json!({
        "daemon": {
            "up": d.up,
            "version": d.version,
            "vaults": d.vault_count,
            "control": control,
            "broker": broker,
        },
        "login": login_json,
        "vault": vault_json,
        // §5: the active vault + WHERE it came from (env pin vs device default),
        // so a mismatch is machine-detectable. No routing block — the broker is
        // opt-in (§9), so there's no "routed" state to report.
        "vault_selection": {
            "env_pin": env_pin,
            "config_default": config_default,
            "mismatch": mismatch,
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).unwrap_or_else(|_| out.to_string())
    );
}

pub fn print_status(s: &VaultStatus) {
    println!("active vault");
    // `control:` not `url:` — this is the vault's control-plane address (the
    // canonical vault handle), not a page; the browsable one is `console:`.
    println!("  control:  {}", s.url);
    if let Some(c) = &s.console {
        println!("  console:  {} (view in browser)", c);
    }
    match &s.state {
        VaultState::Unreachable => {
            if s.url.contains("//localhost") || s.url.contains("//127.0.0.1") {
                println!("  state:    unreachable — bring the daemon up with `sc up`");
            } else {
                println!("  state:    unreachable (is the daemon running?)");
            }
        }
        VaultState::NotFound => {
            println!("  state:    not found (run `sc vault create`, or pick a different URL with `sc vault use`)");
        }
        VaultState::Locked { passkeys } => {
            println!("  state:    locked (run `sc up` to unlock)");
            println!("  passkeys: {}", passkeys);
        }
        VaultState::Unlocked { passkeys, secrets } => {
            println!("  state:    unlocked");
            println!("  passkeys: {}", passkeys);
            println!("  secrets:  {}", secrets);
        }
    }
}
