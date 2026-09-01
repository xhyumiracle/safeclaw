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
//!
//! LIVE FOLLOW (so a proxied agent just works without `sc proxy set`): every
//! `sc run` reports its shell proxy to the daemon's in-memory ambient slot (see
//! [`ambient`] / [`set_ambient`] and `POST /proxy/ambient`). The daemon then
//! follows the operator's CURRENT shell proxy, nothing is persisted, and a shell
//! with no proxy simply falls back to the file. `sc proxy set` stays the
//! explicit override and the only option for a headless/remote daemon that no
//! `sc run` ever reports to. Ambient and file are ONE resolver ([`effective`]),
//! not two mechanisms — ambient is just the env tier kept live instead of frozen.

use std::sync::RwLock;

use crate::config::default_state_dir;

/// The LIVE "ambient" egress proxy: the operator's shell proxy, kept CURRENT.
///
/// In a short-lived `sc` process this is SEEDED once from that process's own
/// shell at startup (`apply_to_env`) and never changes — so `effective()` is
/// still "this shell's proxy, else the file", exactly as before. In the
/// long-running daemon it is seeded from the daemon's OWN startup env (empty
/// under systemd/launchd, which don't inherit a shell) and then REFRESHED by
/// every `sc run`, which reports its shell proxy to `POST /proxy/ambient`. That
/// is what lets the daemon follow the operator's live proxy state with NO
/// persisted `sc proxy set`, and with no stale-value risk: it is in-memory only,
/// so a restart clears it and the next `sc run` re-seeds it.
///
/// `Some(url)` = an ambient proxy to use; `None` = none reported, fall through
/// to the file. Starts `None` (unseeded) until `apply_to_env` runs — so a unit
/// test that never calls it sees `effective()` == the file, as before.
static AMBIENT: RwLock<Option<String>> = RwLock::new(None);

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
    // Seed the ambient proxy from THIS process's REAL shell BEFORE we fill env
    // slots from the file, so `effective()` keeps env > config even after this
    // pollutes the env. Only seed an empty slot: a `/proxy/ambient` push that
    // already set a live value (daemon) must not be clobbered by a later call.
    {
        let mut a = AMBIENT.write().unwrap();
        if a.is_none() {
            *a = shell_proxy_now();
        }
    }
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
/// honouring env > config: the live ambient proxy (the shell proxy `sc run`
/// last reported, or this process's own shell) wins; otherwise the stored file,
/// re-read FRESH so a runtime `sc proxy set` (which rewrites the file) or an
/// ambient push takes effect via `/proxy/reload` / `/proxy/ambient` with no
/// restart. Falls back to [`load`] when nothing ambient is set.
pub fn effective() -> Option<String> {
    let ambient = AMBIENT.read().unwrap();
    let file = load();
    resolve(ambient.as_deref(), file.as_deref())
}

/// Pure precedence: the ambient (live shell / pushed) proxy wins over the stored
/// file, both over a direct route. Split out so the ordering is unit-testable
/// without touching the process-global `AMBIENT` (a global-mutating test would
/// be flaky under parallel runs).
fn resolve(ambient: Option<&str>, file: Option<&str>) -> Option<String> {
    ambient.or(file).map(str::to_string)
}

/// The live ambient egress proxy this process currently holds, WITHOUT the file
/// fallback. `sc run` reads it to report its shell proxy to the daemon: in a CLI
/// process this is exactly the shell proxy captured at startup (the file is the
/// daemon's own concern, so it must not be folded in here). `None` = this shell
/// has no proxy, which tells the daemon to fall through to its file config.
pub fn ambient() -> Option<String> {
    AMBIENT.read().unwrap().clone()
}

/// Set the live ambient egress proxy — the daemon's `/proxy/ambient` handler
/// calls this when an `sc run` reports its shell proxy. Returns whether the
/// value CHANGED, so the caller can skip a client rebuild when it didn't. Never
/// persists: purely in-memory, so it can never strand the daemon across a
/// restart the way a stale file could.
pub fn set_ambient(proxy: Option<String>) -> bool {
    let mut a = AMBIENT.write().unwrap();
    if *a == proxy {
        return false;
    }
    *a = proxy;
    true
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
    apply_effective(
        reqwest::Client::builder()
            .timeout(timeout)
            .default_headers(version_headers()),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_ambient_then_file_then_direct() {
        // Ambient (live shell / pushed) wins over the file...
        assert_eq!(
            resolve(Some("http://a"), Some("http://b")).as_deref(),
            Some("http://a")
        );
        // ...file is the fallback when nothing ambient is set...
        assert_eq!(resolve(None, Some("http://b")).as_deref(), Some("http://b"));
        // ...ambient alone still routes...
        assert_eq!(resolve(Some("http://a"), None).as_deref(), Some("http://a"));
        // ...and neither = direct.
        assert_eq!(resolve(None, None), None);
    }
}
