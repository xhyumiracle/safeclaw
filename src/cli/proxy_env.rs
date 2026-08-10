//! Shared plumbing for the resident credential proxy: the env bundle `sc run`
//! pastes onto a child, and the resident CA path. One place so `sc run` and the
//! daemon never disagree on the proxy address or the CA location.
//!
//! Routing DETECTION (probe host / `is_routed` / `$HTTPS_PROXY` introspection) is
//! deliberately gone (CREDENTIAL_BROKER.md §14): the broker is opt-in, so the agent
//! routes every credential request EXPLICITLY (`sc run` / `--proxy`) — the
//! "phantom sent unrouted" state is unreachable, so there's nothing to detect.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::default_state_dir;

/// Resident CA cert path: `$SAFECLAW_CA_PATH` when set (a hand-configured
/// remote daemon — the PUBLIC `ca.pem` copied over manually; the private
/// `ca.key` never leaves the daemon), else `<state_dir>/ca.pem`, where the
/// local daemon generated it on first start.
pub fn resident_ca_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SAFECLAW_CA_PATH") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    default_state_dir().join("ca.pem")
}

/// The CA bundle `sc run` hands a child: the broker root (needed to verify the
/// proxy's MITM cert on BROKERED hosts) PLUS the machine's OS trust-store roots
/// (needed to verify the REAL cert on PASSTHROUGH / non-brokered public hosts,
/// which the proxy tunnels transparently). Pointing tools at the broker-only
/// `ca.pem` breaks any tool with no compiled system-CApath fallback (cargo's
/// vendored libcurl is the notable one): it then can't verify a passthrough host
/// like `index.crates.io` and fails cert verification. Bundling the system roots
/// in fixes every such tool WITHOUT installing anything into the OS trust store —
/// we only READ the roots already there.
///
/// Written to `<state_dir>/ca-bundle.pem` fresh each call (picks up OS root
/// updates), atomically (temp + rename) so a concurrent `sc run` never reads a
/// torn file. On ANY failure — unreadable broker cert, no OS roots, unwritable
/// dir — we fall back to the broker-only path, i.e. exactly the pre-bundle
/// behaviour: brokered hosts keep working, passthrough hosts stay as they were.
/// The broker root is ALWAYS first, so the broker can never be silently dropped.
pub fn resident_ca_bundle_path() -> PathBuf {
    let broker = resident_ca_path();
    write_ca_bundle(&broker).unwrap_or(broker)
}

fn write_ca_bundle(broker: &Path) -> std::io::Result<PathBuf> {
    let broker_pem = std::fs::read_to_string(broker)?;
    // OS trust store, best effort: whatever loads, we use; load errors are
    // ignored (the broker root alone still makes brokered hosts work).
    let natives: Vec<Vec<u8>> = rustls_native_certs::load_native_certs()
        .certs
        .into_iter()
        .map(|c| c.as_ref().to_vec())
        .collect();
    let content = compose_ca_bundle(&broker_pem, &natives);
    let dir = broker.parent().unwrap_or_else(|| Path::new("."));
    let target = dir.join("ca-bundle.pem");
    // Atomic publish: pid-suffixed temp in the same dir, then rename (same-fs,
    // so the rename is atomic and a reader sees only whole content).
    let tmp = dir.join(format!(".ca-bundle.pem.tmp.{}", std::process::id()));
    std::fs::write(&tmp, content.as_bytes())?;
    std::fs::rename(&tmp, &target)?;
    Ok(target)
}

/// Compose the bundle text: broker cert(s) first (never dropped), then each OS
/// root as its own PEM block. Pure so the ordering + framing is unit-testable
/// without touching the OS trust store or the filesystem.
fn compose_ca_bundle(broker_pem: &str, extra_der: &[Vec<u8>]) -> String {
    let mut out = String::new();
    out.push_str(broker_pem.trim_end());
    out.push('\n');
    for der in extra_der {
        out.push_str(&der_to_pem(der));
    }
    out
}

/// DER → one PEM CERTIFICATE block (base64, 64-col lines). base64 output is
/// pure ASCII, so the per-chunk `from_utf8` cannot fail.
fn der_to_pem(der: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let b64 = STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// The proxy URL a child's `HTTPS_PROXY` points at: the API-face root
/// (`scheme://host:port`, from `active::api_face_root`) with `<vid>:<key>`
/// spliced into the userinfo. The vid (username) routes to a vault; the key
/// (password) is the agent's identity, verified by the proxy before any
/// substitution (§8). An absent key leaves the password slot empty
/// (`<vid>:@`) — the proxy 407s such a request (participating but
/// unauthenticated), the human-without-an-agent-key case. Deriving from the
/// API-face root keeps proxy and control on ONE daemon host (the invariant).
pub fn proxy_url_for_vault(api_root: &str, vid: &str, key: Option<&str>) -> String {
    let key_enc = key
        .map(|k| urlencoding::encode(k).into_owned())
        .unwrap_or_default();
    let (scheme, rest) = api_root.split_once("://").unwrap_or(("http", api_root));
    format!(
        "{}://{}:{}@{}",
        scheme,
        urlencoding::encode(vid),
        key_enc,
        rest.trim_end_matches('/')
    )
}

/// The env bundle that routes a child through the resident proxy and trusts its
/// CA. `proxy_url` is the full `http://<vid>:<key>@127.0.0.1:<port>` the child's
/// `HTTPS_PROXY` gets — built by `sc run` from the resolved vault + the agent's
/// key against the current daemon face. `parent_git_config_count` is the
/// inherited `GIT_CONFIG_COUNT` (if any) so our credential-helper registration
/// CHAINS at the next free index rather than clobbering an already-configured
/// helper. Returns ordered `(key, value)` pairs — no plaintext secret is ever
/// included; the agent writes the phantom.
pub fn build_bundle(
    proxy_url: &str,
    ca: &str,
    parent_git_config_count: Option<u32>,
) -> Vec<(String, String)> {
    // Set the WHOLE proxy family, both cases (`curl` reads only lowercase
    // `http_proxy` for plaintext — it ignores UPPER `HTTP_PROXY` as an httpoxy
    // defence, CVE-2016-5385 — and some tools read only one case or only
    // `ALL_PROXY`). NO_PROXY keeps every loopback spelling out of the broker.
    let no_proxy = "localhost,127.0.0.1,::1";
    let mut b = vec![
        ("HTTPS_PROXY".to_string(), proxy_url.to_string()),
        ("https_proxy".to_string(), proxy_url.to_string()),
        ("HTTP_PROXY".to_string(), proxy_url.to_string()),
        ("http_proxy".to_string(), proxy_url.to_string()),
        ("ALL_PROXY".to_string(), proxy_url.to_string()),
        ("all_proxy".to_string(), proxy_url.to_string()),
        ("NO_PROXY".to_string(), no_proxy.to_string()),
        ("no_proxy".to_string(), no_proxy.to_string()),
        // Node 24+ built-in fetch honours the proxy env only with this set.
        ("NODE_USE_ENV_PROXY".to_string(), "1".to_string()),
        // CA trust: `ca` is the combined bundle (broker root + OS roots) from
        // `resident_ca_bundle_path`. Each var is how a given toolchain finds its
        // CA file. cargo is the odd one out — its vendored libcurl ignores
        // SSL_CERT_FILE/CURL_CA_BUNDLE and reads only CARGO_HTTP_CAINFO — so it
        // needs its own entry or `sc run -- cargo …` can't verify passthrough
        // hosts like index.crates.io.
        ("SSL_CERT_FILE".to_string(), ca.to_string()),
        ("REQUESTS_CA_BUNDLE".to_string(), ca.to_string()),
        ("CURL_CA_BUNDLE".to_string(), ca.to_string()),
        ("NODE_EXTRA_CA_CERTS".to_string(), ca.to_string()),
        ("GIT_SSL_CAINFO".to_string(), ca.to_string()),
        ("DENO_CERT".to_string(), ca.to_string()),
        ("CARGO_HTTP_CAINFO".to_string(), ca.to_string()),
    ];
    // git's per-process config env (no gitconfig writes): register our helper at
    // the next free index. `!` is git's shell-command marker.
    let idx = parent_git_config_count.unwrap_or(0);
    b.push(("GIT_CONFIG_COUNT".to_string(), (idx + 2).to_string()));
    b.push((
        format!("GIT_CONFIG_KEY_{}", idx),
        "credential.helper".to_string(),
    ));
    b.push((
        format!("GIT_CONFIG_VALUE_{}", idx),
        "!sc git-credential".to_string(),
    ));
    // A gitconfig-file `http.proxy` outranks the `*_PROXY` env (git prefers its
    // own config), silently routing git around the broker — the phantom then
    // reaches the upstream unswapped as a literal. Command-scope config outranks
    // every file scope, so pin git to the proxy the env already carries. A
    // URL-specific `http.<url>.proxy` is still more specific and wins; `sc run`
    // preflight warns on those.
    b.push((
        format!("GIT_CONFIG_KEY_{}", idx + 1),
        "http.proxy".to_string(),
    ));
    b.push((
        format!("GIT_CONFIG_VALUE_{}", idx + 1),
        proxy_url.to_string(),
    ));
    b
}

/// Ensure THIS `sc` process never routes loopback traffic through a proxy:
/// merge `localhost` / `127.0.0.1` / `::1` into `NO_PROXY` (both cases) before
/// any reqwest client is built. reqwest honours the standard `*_PROXY` env by
/// default, so without this a user's corporate `HTTPS_PROXY` — or the
/// `HTTPS_PROXY` that `sc run` injects for a child that then shells `sc` — would
/// trap our own calls to the LOCAL daemon: a corp proxy can't reach 127.0.0.1,
/// and inside a `sc run` bundle the call would loop back through our own MITM.
/// Shaping the env once is simpler (and completer) than overriding proxy on
/// every client; remote hosts still honour the proxy, so corp egress keeps
/// working. Call once at startup, before the first HTTP client.
pub fn pin_localhost_no_proxy() {
    for key in ["NO_PROXY", "no_proxy"] {
        let merged = with_loopback(&std::env::var(key).unwrap_or_default());
        std::env::set_var(key, merged);
    }
}

/// Merge the loopback hosts into a comma-separated NO_PROXY value, preserving the
/// caller's existing entries and order, appending only what's missing (case-
/// insensitive). Pure so it's testable without touching process env.
fn with_loopback(current: &str) -> String {
    let mut hosts: Vec<String> = current
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for lb in ["localhost", "127.0.0.1", "::1"] {
        if !hosts.iter().any(|h| h.eq_ignore_ascii_case(lb)) {
            hosts.push(lb.to_string());
        }
    }
    hosts.join(",")
}

/// Is the daemon's control plane answering at `control_root` (from
/// `active::control_root` — env-first host)? `sc run`'s liveness gate — the
/// proxy shares the daemon process, so control up ⇒ proxy up.
pub async fn control_plane_up(control_root: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let url = format!("{}/health", control_root.trim_end_matches('/'));
    matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_url_carries_vault_and_key() {
        // vid in the username, api-key in the password, spliced into the
        // API-face root (same host as every other derived URL).
        assert_eq!(
            proxy_url_for_vault("http://127.0.0.1:23294", "default", Some("sc_agent_k9")),
            "http://default:sc_agent_k9@127.0.0.1:23294"
        );
        // No key → empty password slot (the proxy 407s it).
        assert_eq!(
            proxy_url_for_vault("http://127.0.0.1:23294", "default", None),
            "http://default:@127.0.0.1:23294"
        );
        // A remote API-face root keeps its host AND custom port.
        assert_eq!(
            proxy_url_for_vault("https://box.example.com:9999/", "v1", Some("k")),
            "https://v1:k@box.example.com:9999"
        );
    }

    #[test]
    fn bundle_has_full_family_and_helper() {
        let proxy = proxy_url_for_vault("http://127.0.0.1:23294", "abc", Some("k1"));
        let b = build_bundle(&proxy, "/x/ca.pem", None);
        let get = |k: &str| b.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        // Whole family, both cases (curl-plaintext + ALL_PROXY-only tools).
        for k in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            assert_eq!(get(k).unwrap(), proxy, "{k}");
        }
        assert_eq!(get("NO_PROXY").unwrap(), "localhost,127.0.0.1,::1");
        assert_eq!(get("no_proxy"), get("NO_PROXY"));
        assert_eq!(get("NODE_USE_ENV_PROXY").unwrap(), "1");
        for k in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "GIT_SSL_CAINFO",
            "DENO_CERT",
            // cargo's vendored libcurl reads only this one.
            "CARGO_HTTP_CAINFO",
        ] {
            assert_eq!(get(k).unwrap(), "/x/ca.pem");
        }
        assert_eq!(get("GIT_CONFIG_COUNT").unwrap(), "2");
        assert_eq!(get("GIT_CONFIG_KEY_0").unwrap(), "credential.helper");
        assert_eq!(get("GIT_CONFIG_VALUE_0").unwrap(), "!sc git-credential");
        // git must be pinned to the SAME proxy the env carries — a gitconfig
        // file's `http.proxy` would otherwise outrank the env and bypass it.
        assert_eq!(get("GIT_CONFIG_KEY_1").unwrap(), "http.proxy");
        assert_eq!(get("GIT_CONFIG_VALUE_1"), get("HTTPS_PROXY"));
    }

    #[test]
    fn der_to_pem_is_well_formed_and_roundtrips() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        // A DER long enough to force multiple 64-col base64 lines.
        let der: Vec<u8> = (0u8..=200).cycle().take(200).collect();
        let pem = der_to_pem(&der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        // Every body line is <= 64 cols (OpenSSL/libcurl reject over-wide PEM).
        for line in pem.lines().filter(|l| !l.starts_with("-----")) {
            assert!(line.len() <= 64, "over-wide PEM line: {}", line.len());
        }
        // The base64 body decodes back to the exact DER.
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert_eq!(STANDARD.decode(body).unwrap(), der);
    }

    #[test]
    fn compose_keeps_broker_first_and_never_drops_it() {
        let broker = "-----BEGIN CERTIFICATE-----\nQlJPS0VS\n-----END CERTIFICATE-----\n";
        let extras = vec![b"aaa".to_vec(), b"bbb".to_vec()];
        let out = compose_ca_bundle(broker, &extras);
        // Broker block leads, verbatim.
        assert!(out.starts_with("-----BEGIN CERTIFICATE-----\nQlJPS0VS"));
        // One broker + two OS roots = three CERTIFICATE blocks.
        assert_eq!(out.matches("BEGIN CERTIFICATE").count(), 3);
        // Zero OS roots (load failed / empty store) still keeps the broker — the
        // fallback must never leave the broker out.
        assert_eq!(
            compose_ca_bundle(broker, &[])
                .matches("BEGIN CERTIFICATE")
                .count(),
            1
        );
    }

    #[test]
    fn with_loopback_appends_missing_preserves_existing() {
        // Empty → just the loopback set.
        assert_eq!(with_loopback(""), "localhost,127.0.0.1,::1");
        // Existing corp entries kept + ordered first; only missing loopback added.
        assert_eq!(
            with_loopback("corp.internal, 10.0.0.0/8"),
            "corp.internal,10.0.0.0/8,localhost,127.0.0.1,::1"
        );
        // Idempotent + case-insensitive: no dupes when loopback already present.
        assert_eq!(
            with_loopback("LOCALHOST,127.0.0.1"),
            "LOCALHOST,127.0.0.1,::1"
        );
        assert_eq!(
            with_loopback("localhost,127.0.0.1,::1"),
            "localhost,127.0.0.1,::1"
        );
    }

    #[test]
    fn bundle_chains_git_config_indices() {
        // Parent already set two entries → we append at index 2, count becomes 3.
        let proxy = proxy_url_for_vault("http://127.0.0.1:23294", "abc", Some("k1"));
        let b = build_bundle(&proxy, "/x/ca.pem", Some(2));
        let get = |k: &str| b.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("GIT_CONFIG_COUNT").unwrap(), "4");
        assert_eq!(get("GIT_CONFIG_KEY_2").unwrap(), "credential.helper");
        assert_eq!(get("GIT_CONFIG_VALUE_2").unwrap(), "!sc git-credential");
        assert_eq!(get("GIT_CONFIG_KEY_3").unwrap(), "http.proxy");
        assert_eq!(get("GIT_CONFIG_VALUE_3"), get("HTTPS_PROXY"));
        // We do NOT touch the parent's lower indices.
        assert!(get("GIT_CONFIG_KEY_0").is_none());
    }
}
