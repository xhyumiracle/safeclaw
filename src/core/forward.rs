//! The daemon's shared outbound HTTP client.
//!
//! Used by the oauth2 token calls, the external-store (GCP) adapter, and — via
//! `server::broker_flow` — the resident proxy's egress. Redirect policy is
//! `none` (the broker forwards a single hop; a 30x is returned to the caller,
//! never chased into a different host).
//!
//! Held behind a `RwLock` so the device egress proxy (`sc proxy set`) can be
//! HOT-SWAPPED at runtime, WITHOUT a daemon restart. A restart would drop the
//! in-memory vault key and force the operator to re-unlock; instead
//! `sc proxy set/clear` writes the stored value and pokes `/proxy/reload`, which
//! calls [`reload_egress_proxy`]. The client is built with an EXPLICIT proxy
//! resolved from `egress_proxy::effective()` (the live ambient proxy an `sc run`
//! last reported, else the stored file — not the raw process env), so a reload
//! fully re-points every future request.

use std::sync::RwLock;
use std::time::Duration;

use once_cell::sync::Lazy;

/// Fail FAST when the TCP/TLS handshake can't complete — a wrong or dead egress
/// proxy (or a firewall black-holing the route) otherwise leaves a connect
/// hanging for the OS default (~75s on macOS), stalling an OAuth exchange past
/// `sc sync`'s own 30s client timeout so the user sees a bare "timeout" instead
/// of the real "couldn't reach the provider" signal. Only the CONNECT is bounded
/// here; a slow-but-progressing response still rides the per-request timeout the
/// callers set.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

static HTTP_CLIENT: Lazy<RwLock<reqwest::Client>> = Lazy::new(|| {
    RwLock::new(build_client(
        crate::cli::egress_proxy::effective().as_deref(),
    ))
});

/// A cheap handle to the current shared client — `reqwest::Client` is internally
/// `Arc`'d, so this clone just bumps a refcount. Every daemon egress caller goes
/// through here so a `reload_egress_proxy()` reaches all of them at once.
pub fn http_client() -> reqwest::Client {
    HTTP_CLIENT.read().unwrap().clone()
}

/// Rebuild the shared client from the currently-effective egress proxy and swap
/// it in. Called by the `/proxy/reload` control route after `sc proxy set/clear`
/// rewrites the stored value — the daemon re-points its egress with no restart
/// (and so no vault re-unlock).
pub fn reload_egress_proxy() {
    let client = build_client(crate::cli::egress_proxy::effective().as_deref());
    *HTTP_CLIENT.write().unwrap() = client;
}

/// Build the shared client with an EXPLICIT proxy (or explicit direct). Loopback
/// and the cloud custodian stay on a direct route via the `NO_PROXY` that
/// `apply_to_env` pinned (custodian host + loopback), so a Google-only proxy
/// can't sink cloud sync. A malformed proxy URL logs and goes direct.
fn build_client(proxy: Option<&str>) -> reqwest::Client {
    let b = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT);
    crate::cli::egress_proxy::apply(b, proxy)
        .build()
        .expect("failed to build HTTP client")
}
