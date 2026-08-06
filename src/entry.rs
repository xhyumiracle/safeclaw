//! The daemon/CLI entrypoint, factored out of `main.rs` so BOTH binaries can
//! reuse it: the open-source `safeclaw`/`sc` bins call [`run_cli`] with
//! [`crate::team_hooks::NoopHooks`], and the closed `safeclaw-ee` overlay's bin
//! calls it with its real hooks. `hooks` only reaches the daemon (`run_daemon` →
//! `AppState::with_team_hooks`); every other verb is identical across builds.
//! This is the ONE seam of the open/closed split (team-edition §9): a personal
//! build and the official build share 100% of this dispatch and differ only in
//! which `TeamHooks` implementation is injected.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::FromArgMatches;

use crate::cli;
use crate::config::{Cli, Command, Config, ServeArgs};
use crate::server::app_router;
use crate::state::AppState;
use crate::team_hooks::TeamHooks;

/// Parse argv and run the requested command. `hooks` is injected into the daemon
/// (`serve`) path only; all other verbs ignore it.
pub async fn run_cli(hooks: Arc<dyn TeamHooks>) -> Result<(), Box<dyn std::error::Error>> {
    // Loopback is never proxied: pin localhost into NO_PROXY before any HTTP
    // client is built, so a corporate HTTPS_PROXY (or the one `sc run` injects)
    // can't trap our calls to the local daemon. reqwest honours env proxies by
    // default, so shaping the env here covers every client at once.
    cli::proxy_env::pin_localhost_no_proxy();
    // Apply the device's configured EGRESS proxy (`sc proxy set`) to this
    // process's env before any client is built — the launchd/systemd daemon does
    // not inherit the operator's shell `HTTPS_PROXY`, so this is how the daemon's
    // backend sync, OAuth exchange, and MITM forward reach a corporate/on-demand
    // or region-required upstream. It covers every remote host (the SafeClaw
    // backend included, so `sc agent`/`sc login`/sync all honour it); a real
    // shell `HTTPS_PROXY` still wins, and only loopback stays direct.
    cli::egress_proxy::apply_to_env();

    // Parse through `cli::help::command()` (not `Cli::parse()`) so the top-level
    // `sc` / `sc --help` prints our grouped, gh-style help; per-command help is
    // still clap's default.
    let matches = cli::help::command().get_matches();
    let verbose = matches.get_count("verbose");
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    // `serve` installs its own subscriber below (long-running, different
    // defaults); every other (short-lived) verb gets a stderr subscriber only
    // when `-v` was asked, so a command's normal output stays clean.
    if !matches!(cli.command, Command::Serve(_)) {
        cli::logging::init_cli(verbose);
    }
    match cli.command {
        Command::Status(args) => {
            // CLI commands log to stderr; don't initialise the tracing
            // subscriber here (it'd pollute the user-facing output of a
            // short-lived command). The daemon path enables it below.
            cli::status::run(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw status: {}", e);
                    e.into()
                })
        }
        // `serve` is the foreground daemon entry — it bootstraps tracing, owns
        // the runtime, and runs forever, so handle it here, not through the
        // short-lived CLI dispatcher. This is the ONLY verb that uses `hooks`.
        Command::Serve(serve) => run_daemon(serve, verbose, hooks).await,
        Command::Down => cli::service::run_stop().map_err(daemon_err),
        // `sc restart` = bounce the daemon AND converge back to ready (re-unlock).
        // A process restart wipes the in-memory keys, so it routes through the
        // same `ensure_unlocked` chokepoint as `sc up` (see cli/up.rs::restart).
        Command::Restart => cli::up::restart()
            .await
            .map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw restart: {}", e);
                e.into()
            }),
        Command::Sync(args) => {
            cli::sync::run(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw sync: {}", e);
                    e.into()
                })
        }
        Command::Logs(args) => cli::service::run_logs(args).map_err(daemon_err),
        Command::Pubkey(args) => cli::custodian::pubkey(args).await.map_err(daemon_err),
        Command::Registry(args) => cli::custodian::registry(args).map_err(daemon_err),
        Command::Up => {
            // `sc up` = make SafeClaw ready: ensure the daemon is running, then
            // ensure the vault is unlocked (the single auto-unlock chokepoint;
            // see cli/up.rs). login / upgrade-restart / agent lazy-start all
            // route through here, so the user never runs a bare "unlock".
            cli::up::run()
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw up: {}", e);
                    e.into()
                })
        }
        Command::Unlock(args) => cli::unlock::run_unlock(args).await.map_err(daemon_err),
        Command::Lock(args) => cli::unlock::run_lock(args).await.map_err(daemon_err),
        Command::Ls(args) => cli::ls::run(args)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw ls: {}", e);
                e.into()
            }),
        Command::Get(args) => {
            cli::secret::run_get(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw get: {}", e);
                    e.into()
                })
        }
        Command::Doctor(args) => {
            cli::doctor::run(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw doctor: {}", e);
                    e.into()
                })
        }
        Command::Vault(args) => {
            cli::vault::run(args.sub)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw vault: {}", e);
                    e.into()
                })
        }
        Command::Config(args) => {
            cli::config::run(args.sub).map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw config: {}", e);
                e.into()
            })
        }
        Command::Proxy(args) => {
            cli::proxy::run(args.sub)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw proxy: {}", e);
                    e.into()
                })
        }
        Command::Store(args) => {
            cli::store::run(args.sub)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw store: {}", e);
                    e.into()
                })
        }
        Command::Passkey(args) => {
            cli::passkey::run(args.sub)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw passkey: {}", e);
                    e.into()
                })
        }
        Command::Agent(args) => {
            cli::agent::run(args.sub)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw agent: {}", e);
                    e.into()
                })
        }
        Command::Env => cli::env::run().map_err(|e| -> Box<dyn std::error::Error> {
            eprintln!("safeclaw env: {}", e);
            e.into()
        }),
        Command::GitCredential(args) => {
            // Invoked by git, not users. Never print to stderr on the happy path
            // (git reads stdout); surface only hard errors.
            cli::git_credential::run(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw git-credential: {}", e);
                    e.into()
                })
        }
        Command::Run(args) => {
            cli::run::run(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw run: {}", e);
                    e.into()
                })
        }
        // `sc connect …` is the hidden back-compat spelling of `sc connection add`.
        Command::Connect(args) => {
            cli::connect::run(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw connect: {}", e);
                    e.into()
                })
        }
        Command::Connection(args) => {
            use crate::config::ConnectionSubcommand;
            let r = match args.sub {
                ConnectionSubcommand::Add(a) => cli::connect::run(a).await,
                ConnectionSubcommand::Ls(a) => cli::connect::run_ls(a).await,
                ConnectionSubcommand::Rm(a) => cli::connect::run_rm(a).await,
            };
            r.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw connection: {}", e);
                e.into()
            })
        }
        Command::Upgrade(args) => {
            cli::upgrade::run(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw upgrade: {}", e);
                    e.into()
                })
        }
        Command::Login(args) => {
            cli::login::run(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw login: {}", e);
                    e.into()
                })
        }
        Command::Logout(args) => {
            cli::logout::run(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw logout: {}", e);
                    e.into()
                })
        }
        Command::Device(args) => {
            use crate::config::DeviceSubcommand;
            let r = match args.sub {
                DeviceSubcommand::Login(a) => cli::login::run(a).await,
                DeviceSubcommand::Logout(a) => cli::logout::run(a).await,
            };
            r.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw device: {}", e);
                e.into()
            })
        }
        Command::Secret(args) => {
            use crate::config::SecretSubcommand;
            let r = match args.sub {
                SecretSubcommand::Set(a) => cli::secret::run_set(a).await,
                SecretSubcommand::Get(a) => cli::secret::run_get(a).await,
                SecretSubcommand::Rm(a) => cli::secret::run_rm(a).await,
                SecretSubcommand::Ls(a) => cli::ls::run(a).await,
            };
            r.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw secret: {}", e);
                e.into()
            })
        }
        Command::Set(args) => {
            cli::secret::run_set(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw set: {}", e);
                    e.into()
                })
        }
        Command::Rm(args) => {
            cli::secret::run_rm(args)
                .await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    eprintln!("safeclaw rm: {}", e);
                    e.into()
                })
        }
        Command::Service(args) => {
            use crate::config::ServiceSubcommand;
            let r = match args.sub {
                ServiceSubcommand::Validate(a) => cli::service_def::run_validate(a).await,
                ServiceSubcommand::Add(a) => cli::service_def::run_add(a).await,
                ServiceSubcommand::Ls(a) => cli::service_def::run_ls(a).await,
                ServiceSubcommand::Rm(a) => cli::service_def::run_rm(a).await,
            };
            r.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw service: {}", e);
                e.into()
            })
        }
        Command::Op(args) => {
            use crate::config::OpSubcommand;
            let r = match args.sub {
                OpSubcommand::Wait(a) => cli::op::run_wait(a).await,
            };
            r.map_err(|e| -> Box<dyn std::error::Error> {
                eprintln!("safeclaw op: {}", e);
                e.into()
            })
        }
        Command::Version => {
            println!("safeclaw {}", crate::build_version());
            Ok(())
        }
    }
}

/// Shared error adapter for the daemon-lifecycle verbs (down/restart/logs/…):
/// print to stderr and box the error for the caller's return.
fn daemon_err(e: String) -> Box<dyn std::error::Error> {
    eprintln!("safeclaw: {}", e);
    e.into()
}

async fn run_daemon(
    args: ServeArgs,
    verbose: u8,
    hooks: Arc<dyn TeamHooks>,
) -> Result<(), Box<dyn std::error::Error>> {
    // A `-v/-vv/-vvv` on `sc serve` raises the daemon's own filter; an explicit
    // RUST_LOG still wins.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(cli::logging::serve_filter(verbose))
            }),
        )
        .init();

    let config = Config::from_serve_args(args);

    std::fs::create_dir_all(&config.state_dir)?;
    std::fs::create_dir_all(config.state_dir.join("vaults"))?;

    // Slice 3: pull the active vault's sealed blob from the cloud before
    // serving, so a freshly-paired device serves a vault sealed in the
    // browser. Best-effort — a local-only or offline daemon serves whatever
    // vault.dat is already on disk.
    crate::sync::pull_on_start(&config.state_dir).await;

    // Inject the team-edition hooks (team-edition §9): the open build passes
    // `NoopHooks`, the closed `safeclaw-ee` overlay its real ones. This is the
    // single point where the official binary's team behavior enters the daemon.
    let state = Arc::new(AppState::new(config.clone()).with_team_hooks(hooks));

    // Agent-centric auth: sync the account-level agent-key hash-set once
    // before serving (so account agent-keys are accepted from the start),
    // then keep it fresh in the background (revokes/new agents land in ~30s).
    crate::sync::sync_agent_keys_once(&state).await;
    tokio::spawn(crate::sync::sync_agent_keys_loop(state.clone()));

    // Slice 3 realtime sync: one detached long-poll watcher PER synced vault
    // (active ∪ known_vaults — all vaults stay live, not just the active one).
    // Best-effort — NOT in the serve select!, so a sync-loop exit never takes
    // the daemon down.
    crate::sync::spawn_watchers(state.clone());

    // De-daemon (DE_DAEMON.md §4): local-first audit outbox. The daemon writes
    // every op to its per-vault audit.db synchronously; this detached loop ships
    // terminal Use-op rows to the cloud `audit_events` table so the console can
    // show activity without a cloud daemon. Best-effort + gated like blob sync.
    tokio::spawn(crate::sync::ship_audit_loop(state.clone()));

    // Install the process-wide rustls crypto provider ONCE (aws-lc-rs, never
    // OpenSSL) before the proxy's TLS stacks touch it. Ignore "already set" —
    // some transitive dep may have installed it first; ours is identical.
    let _ = hudsucker::rustls::crypto::aws_lc_rs::default_provider().install_default();

    // The resident credential proxy (the ONE agent-facing surface) runs on its
    // own listener at PROXY_PORT, concurrently with the control/API plane below.
    // Best-effort + detached: a proxy exit logs and leaves the control plane
    // serving (never silently take the daemon down). See src/proxy/mod.rs.
    {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::proxy::serve(state).await {
                tracing::error!("resident proxy exited: {} — control plane stays up", e);
            }
        });
    }

    // OAuth loopback auto-catch (src/auth/loopback.rs) is NOT started here: the
    // 8765 listener opens ON DEMAND — the connect state machine calls
    // `loopback::ensure_running` only while some connect is awaiting its redirect
    // — and self-closes when idle. So there is nothing to spawn at boot.

    let listen_ip: std::net::IpAddr = config
        .listen
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());

    // Two localhost listeners (2026-07-03 phantom-only proxy): the control/API
    // plane (op/approve/passkeys/registry/admin) on CONTROL_PORT here, and the
    // resident MITM credential proxy on PROXY_PORT (spawned above). The agent
    // reaches control only via $SAFECLAW_VAULT_URL, so the port is env-addressed.
    let addr = SocketAddr::new(listen_ip, config.port);
    let app = app_router(state.clone());

    tracing::info!(
        listen = %addr,
        state_dir = %config.state_dir.display(),
        rp_id = %config.rp_id,
        origin = %config.origin,
        "safeclaw daemon starting"
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
