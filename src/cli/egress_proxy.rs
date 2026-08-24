//! Device-level EGRESS proxy: the ONE upstream HTTP proxy that BOTH the daemon
//! and this CLI use to reach every remote host — the SafeClaw backend (pairing,
//! `sc agent`, sync), third-party OAuth code/refresh exchanges, the resident MITM
//! proxy's forward hop, and `sc upgrade`'s GitHub fetch. Only loopback is exempt
//! (pinned into `NO_PROXY` by `proxy_env::pin_localhost_no_proxy`); every other
//! destination follows the proxy, exactly the way curl/git/Docker behave.
//!
//! WHY this exists separate from the child-facing proxy (`proxy_env`): the
//! macOS launchd agent (and the systemd unit) do NOT inherit the operator's
//! shell `HTTPS_PROXY`, and both unit generators whitelist only `SAFECLAW_*`, so
//! a `$HTTPS_PROXY` set in a terminal never reaches the long-running daemon.
//! Agents behind a corporate/on-demand proxy (and users in regions that can only
//! reach the SafeClaw backend through a proxy) therefore need a persisted,
//! device-level value the daemon — and every short-lived `sc` command — can read
//! on its own, without depending on the current shell.
//!
//! Model (deliberately the standard one — Docker/systemd/git all do this): the
//! proxy is CONFIGURED at the device level, persisted in a file, and applied to
//! the process env at startup BEFORE any HTTP client is built (reqwest honours
//! `*_PROXY` natively, so one env shaping covers every client). `sc proxy set`
//! writes it + bounces the daemon; changing it is a service-config change, not a
//! per-request knob. An explicit shell `HTTPS_PROXY` still WINS (env > config),
//! so this only fills the gap, never overrides an operator who set it directly.
//! Hosts that must stay direct (e.g. a narrow proxy that can't reach us) go in
//! the operator's own `NO_PROXY` — we never silently carve the backend out.

use std::sync::OnceLock;

use crate::config::default_state_dir;

/// The operator's REAL shell egress proxy, captured ONCE by `apply_to_env`
/// before it fills any env slot from the stored file. Needed by [`effective`]:
/// after `apply_to_env` has copied the file value into the env, we can no longer
/// tell an env-from-shell proxy from an env-from-file one, but env > config must
/// still hold. `None` = no shell proxy was set; unset (`get()` is `None`) = the
/// capture never ran (e.g. a unit test not going through `apply_to_env`).
static SHELL_PROXY: OnceLock<Option<String>> = OnceLock::new();

/// Persisted egress-proxy URL location: `<state_dir>/egress-proxy` (one line, the
/// URL). Absent/empty = no configured egress proxy.
pub fn path() -> std::path::PathBuf {
    default_state_dir().join("egress-proxy")
}

/// The configured egress-proxy URL, or `None` when unset. Trims whitespace and
/// treats an empty file as unset.
pub fn load() -> Option<String> {
    let s = std::fs::read_to_string(path()).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Persist `url` as the device egress proxy (0600 — it may carry proxy
/// userinfo). Overwrites any prior value.
pub fn store(url: &str) -> Result<(), String> {
    let p = path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;
    }
    std::fs::write(&p, format!("{}\n", url.trim()))
        .map_err(|e| format!("write {}: {}", p.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Remove the configured egress proxy (no-op if already absent).
pub fn clear() -> Result<(), String> {
    match std::fs::remove_file(path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {}", path().display(), e)),
    }
}

/// Apply the configured egress proxy to THIS process's environment before any
/// HTTP client is built. No-op when nothing is configured. Called at startup for
/// every `sc` invocation (daemon + CLI) so `serve`'s clients and `sc upgrade`'s
/// GitHub fetch both honour it. An already-set `HTTPS_PROXY` in the real env
/// takes precedence and is left untouched (env > config).
pub fn apply_to_env() {
    // Snapshot any REAL shell proxy BEFORE we fill env slots from the file, so
    // `effective()` can keep env > config even after this pollutes the env.
    let _ = SHELL_PROXY.get_or_init(shell_proxy_now);
    let Some(url) = load() else { return };
    for key in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        // Only fill the slot the operator didn't already set in their shell.
        if std::env::var_os(key).map(|v| v.is_empty()).unwrap_or(true) {
            std::env::set_var(key, &url);
        }
    }
    // NB: we do NOT pin the SafeClaw backend into NO_PROXY. A configured proxy
    // applies to every remote host (backend included) — the mainstream
    // convention, and the only behaviour that works for operators who can reach
    // us *only* through a proxy. Loopback stays direct via
    // `proxy_env::pin_localhost_no_proxy`; any other exceptions are the
    // operator's own `NO_PROXY` to make.
}

/// The egress proxy the DAEMON's own swappable clients (the shared reqwest
/// client + the resident proxy's forward connector) should use RIGHT NOW,
/// honouring env > config: a real shell proxy (captured at startup) wins;
/// otherwise the stored file — re-read FRESH so a runtime `sc proxy set` (which
/// rewrites the file) takes effect via `/proxy/reload` without touching, or
/// re-reading, process env. Falls back to [`load`] if the capture never ran.
pub fn effective() -> Option<String> {
    match SHELL_PROXY.get() {
        Some(Some(shell)) => Some(shell.clone()),
        _ => load(),
    }
}

/// Apply an EXPLICIT egress proxy (or explicit direct) to a reqwest client
/// builder — the single place the daemon's HTTP clients agree on how the device
/// proxy is applied. Loopback and any operator `NO_PROXY` stay direct; a
/// malformed proxy URL logs and falls back to a direct dial. Setting an explicit
/// proxy also disables reqwest's ambient-env proxy auto-detection, so this fully
/// OWNS the routing — it never silently inherits a stale `*_PROXY` from the env
/// `apply_to_env` froze at startup.
pub fn apply(b: reqwest::ClientBuilder, proxy: Option<&str>) -> reqwest::ClientBuilder {
    match proxy {
        Some(url) => match reqwest::Proxy::all(url) {
            Ok(p) => {
                let p = match std::env::var("NO_PROXY")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| reqwest::NoProxy::from_string(&s))
                {
                    Some(np) => p.no_proxy(Some(np)),
                    None => p,
                };
                b.proxy(p)
            }
            Err(e) => {
                tracing::warn!(
                    "egress proxy '{}' is not a valid proxy URL ({}) — dialing directly",
                    url,
                    e
                );
                b.no_proxy()
            }
        },
        // Explicit direct: ignore any proxy inherited in the process env.
        None => b.no_proxy(),
    }
}

/// Apply the currently-[`effective`] egress proxy to a client builder. Because
/// `effective()` re-reads the stored value FRESH, a `sc proxy set` that ran
/// after the daemon started (via `/proxy/reload`, no restart) is honoured by the
/// very next client built through here — the whole point of the hot path.
pub fn apply_effective(b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    apply(b, effective().as_deref())
}

/// The one constructor for the daemon's per-call cloud clients (sync loops,
/// op-relay): an HTTP client with the effective device egress proxy applied and
/// the given overall timeout. Routing sync/relay through here is what makes
/// `sc proxy set` reach them without a daemon restart — see the module header.
pub fn client(timeout: std::time::Duration) -> reqwest::Result<reqwest::Client> {
    apply_effective(reqwest::Client::builder().timeout(timeout).default_headers(version_headers()))
        .build()
}

/// Every cloud call announces the binary version (team §8.3: the backend's
/// format gate + the /admin version census read it). One constant header —
/// no fingerprinting surface beyond what User-Agent already carries.
fn version_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if let Ok(v) = reqwest::header::HeaderValue::from_str(env!("CARGO_PKG_VERSION")) {
        h.insert("x-safeclaw-version", v);
    }
    h
}

/// The constructor for the daemon's STREAMING cloud connection (the SSE sync
/// stream, design/sse-sync.md): same fresh-proxy contract as [`client`]
/// — built per (re)connect, so a runtime `sc proxy set` is honoured at the
/// very next dial — but with ONLY a connect budget. A total `.timeout()` here
/// would be a bug: it fires mid-body and would kill a healthy held-open
/// stream at the deadline. Liveness on the open stream is the caller's job
/// (sync_stream's 45s no-bytes watchdog).
pub fn client_streaming(connect: std::time::Duration) -> reqwest::Result<reqwest::Client> {
    apply_effective(
        reqwest::Client::builder()
            .connect_timeout(connect)
            .default_headers(version_headers()),
    )
    .build()
}

/// The first non-empty proxy set in THIS process's env right now. Read once by
/// `apply_to_env` before it shapes env, so it reflects the operator's shell.
fn shell_proxy_now() -> Option<String> {
    for key in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        if let Some(v) = std::env::var_os(key) {
            let v = v.to_string_lossy().trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}
