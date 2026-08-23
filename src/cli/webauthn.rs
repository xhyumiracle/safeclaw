//! Shared browser-gesture infrastructure for CLI commands.
//!
//! All CLI commands that need a passkey gesture open a browser to the
//! daemon's `/op/{op_id}` page (content-negotiated: browser gets HTML,
//! API gets JSON). The page runs `navigator.credentials.get()` (or
//! `create()` for enroll) and returns the result to a localhost callback
//! the CLI spawns.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};

#[derive(Debug, Deserialize)]
pub struct GestureResult {
    pub status: String,
    pub credential_id: Option<String>,
    pub authenticator_data: Option<String>,
    pub client_data_json: Option<String>,
    pub signature: Option<String>,
    pub prf_first: Option<String>,
    pub attestation_object: Option<String>,
    pub public_key_x: Option<String>,
    pub public_key_y: Option<String>,
    pub error: Option<String>,
    pub state: Option<String>,
}

pub fn assertion_json(
    credential_id: &Option<String>,
    authenticator_data: &Option<String>,
    client_data_json: &Option<String>,
    signature: &Option<String>,
) -> Value {
    serde_json::json!({
        "credentialId": credential_id,
        "authenticatorData": authenticator_data,
        "clientDataJSON": client_data_json,
        "signature": signature,
    })
}

pub async fn do_browser_gesture(
    custodian: &str,
    op_id: &str,
    beta: &[u8],
    prf_salt: Option<&[u8]>,
    cred_id: &str,
    label: &str,
    no_browser: bool,
    timeout_secs: u64,
    enroll: bool,
    cb_port: Option<u16>,
) -> Result<GestureResult, String> {
    // Resolution: flag (already includes SAFECLAW_CB_PORT via clap)
    //   → ~/.safeclaw/config.toml [settings] cb_port → None (random).
    let cb_port_from_flag = cb_port;
    let cb_port = cb_port.or_else(crate::cli::active::settings_cb_port);
    let cb_port_from_config = cb_port_from_flag.is_none() && cb_port.is_some();

    // Show the SSH tunnel hint when:
    //   (a) SSH env vars are present (SSH_CONNECTION / SSH_CLIENT), OR
    //   (b) cb_port came from the persisted config — the user explicitly ran
    //       `sc config set cb-port` which is a reliable signal they set this
    //       up for SSH, even if SSH env vars weren't forwarded to this shell.
    //
    // Detail level:
    //   - cb_port known (either case): compact one-liner with the actual port.
    //   - cb_port unknown (first-time SSH detection): full two-step guide.
    if !no_browser && (ssh_session_detected() || cb_port_from_config) {
        print_ssh_tunnel_hint(custodian, cb_port);
    }

    let bind_addr = format!("127.0.0.1:{}", cb_port.unwrap_or(0));
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("bind {}: {}", bind_addr, e))?;
    // Use "localhost" not "127.0.0.1" — WebAuthn treats localhost as a
    // valid origin but rejects raw IP addresses.
    let local_addr = listener.local_addr().map_err(|e| format!("addr: {}", e))?;
    let state_token = random_hex(16);
    let (tx, rx) = oneshot::channel::<GestureResult>();
    let cb_state = Arc::new(CbState {
        tx: Mutex::new(Some(tx)),
    });
    let app = Router::new()
        .route("/done", get(handle_done))
        .with_state(cb_state);

    let cb_url = format!("http://localhost:{}/done", local_addr.port());
    let mut auth_url = format!(
        "{}/op/{}?challenge={}&cred_id={}&cb={}&state={}&label={}",
        custodian.trim_end_matches('/'),
        urlencoding::encode(op_id),
        URL_SAFE_NO_PAD.encode(beta),
        urlencoding::encode(cred_id),
        urlencoding::encode(&cb_url),
        urlencoding::encode(&state_token),
        urlencoding::encode(label),
    );
    if let Some(salt) = prf_salt {
        auth_url.push_str(&format!("&prf_salt={}", URL_SAFE_NO_PAD.encode(salt)));
    }
    if enroll {
        auth_url.push_str("&enroll=1");
    }

    eprintln!("If browser doesn't open, visit:");
    eprintln!("  {}", auth_url);
    eprintln!();
    if !no_browser {
        let _ = open_browser(&auth_url);
    }

    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    let result = tokio::select! {
        r = rx => r.map_err(|_| "callback channel dropped".to_string())?,
        _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
            server.abort();
            return Err(format!("timed out after {}s", timeout_secs));
        }
    };
    server.abort();

    if result.status != "ok" {
        return Err(format!(
            "gesture: {}",
            result.error.as_deref().unwrap_or(&result.status)
        ));
    }
    if result.state.as_deref() != Some(&state_token) {
        return Err("CSRF state mismatch".into());
    }
    eprintln!("  passkey ok");
    Ok(result)
}

pub async fn create_op(
    custodian: &str,
    vault: &str,
    op: &Value,
) -> Result<(String, String), String> {
    let client = http_client()?;
    let url = format!(
        "{}/v/{}/op",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let resp = client
        .post(&url)
        .json(op)
        .send()
        .await
        .map_err(|e| format!("create op: {}", e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        // Surface the daemon's human message (e.g. the 423 "vault locked. Run
        // `sc unlock`" hint) instead of a raw JSON error envelope.
        let msg = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v["message"].as_str().map(str::to_string))
            .unwrap_or(body);
        return Err(format!("create op HTTP {}: {}", status, msg));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    let op_id = body["op_id"].as_str().ok_or("no op_id")?.to_string();
    let r = body["r"].as_str().ok_or("no r")?.to_string();
    Ok((op_id, r))
}

pub fn compute_beta(r: &[u8], op: &Value) -> Result<Vec<u8>, String> {
    let beta =
        crate::crypto::binding::binding_for_op(crate::crypto::binding::DOMAIN_STANDARD, r, op)
            .map_err(|e| format!("beta: {}", e))?;
    Ok(beta.to_vec())
}

pub fn compute_beta_setup(r: &[u8], op: &Value) -> Result<Vec<u8>, String> {
    let beta = crate::crypto::binding::binding_for_op(crate::crypto::binding::DOMAIN_SETUP, r, op)
        .map_err(|e| format!("beta: {}", e))?;
    Ok(beta.to_vec())
}

pub const PRF_EVAL_SALT: &[u8] = b"safeclaw-prf-v1";

pub fn prf_to_user_key(prf_first: &[u8]) -> Result<Vec<u8>, String> {
    use sudp::primitives::{HkdfSha256, Kdf as _};
    let salt = [0u8; 32];
    let info = b"sudp/v1/webauthn-prf-userkey";
    let k = HkdfSha256::derive_32(prf_first, &salt, info)
        .map_err(|e| format!("HKDF prf_to_user_key: {}", e))?;
    Ok(k.to_vec())
}

#[derive(Debug, Clone)]
pub struct PasskeyMeta {
    pub credential_id: String,
    pub prf_salt: String,
    pub public_key_x: Option<String>,
    pub public_key_y: Option<String>,
}

pub async fn fetch_passkey_meta(custodian: &str, vault: &str) -> Result<PasskeyMeta, String> {
    let passkeys = fetch_passkeys_json(custodian, vault).await?;
    let p = &passkeys[0];
    Ok(PasskeyMeta {
        credential_id: p["credential_id"]
            .as_str()
            .ok_or("no credential_id")?
            .to_string(),
        prf_salt: p["prf_salt"].as_str().ok_or("no prf_salt")?.to_string(),
        public_key_x: p["public_key_x"].as_str().map(|s| s.to_string()),
        public_key_y: p["public_key_y"].as_str().map(|s| s.to_string()),
    })
}

/// Fetch the raw passkeys array from GET /v/{vault}/passkeys.
pub async fn fetch_passkeys_json(custodian: &str, vault: &str) -> Result<Vec<Value>, String> {
    let client = http_client()?;
    let url = format!(
        "{}/v/{}/passkeys",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("passkeys: {}", e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        // Surface the daemon's human message (e.g. "vault_id has illegal
        // chars") instead of a bare status line.
        let msg = resp
            .text()
            .await
            .ok()
            .and_then(|b| serde_json::from_str::<Value>(&b).ok())
            .and_then(|v| v["message"].as_str().map(str::to_string))
            .unwrap_or_default();
        return Err(if msg.is_empty() {
            format!("passkeys HTTP {}", status)
        } else {
            format!("passkeys HTTP {}: {}", status, msg)
        });
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    let vault_exists = body
        .get("vault_exists")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !vault_exists {
        return Err("vault not found on this custodian — run `safeclaw vault create`".into());
    }
    let passkeys = body["passkeys"]
        .as_array()
        .ok_or("no passkeys array")?
        .clone();
    if passkeys.is_empty() {
        return Err("vault has no enrolled passkeys".into());
    }
    Ok(passkeys)
}

pub fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn random_hex(n: usize) -> String {
    random_bytes(n)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

struct CbState {
    tx: Mutex<Option<oneshot::Sender<GestureResult>>>,
}

async fn handle_done(
    State(state): State<Arc<CbState>>,
    Query(params): Query<GestureResult>,
) -> impl IntoResponse {
    if let Some(tx) = state.tx.lock().await.take() {
        let _ = tx.send(params);
    }
    (StatusCode::OK, "OK — you can close this tab.\n")
}

/// True if the shell looks like an SSH session — set by sshd in any
/// non-trivial Linux/macOS deployment. False positives (X11 forwarding,
/// remote browser plumbing) are harmless: we only print a hint, never block.
fn ssh_session_detected() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_CLIENT").is_some()
}

/// Default port to suggest in the SSH-tunnel hint. Clusters just above the
/// daemon's 23293/23294 pair (skipping the commonly-squatted 23295) so the
/// safeclaw ports stay together and the tunnel command stays compact.
const SUGGESTED_CB_PORT: u16 = 23296;

/// If `url` points at this machine, return the port. Used to decide
/// whether the SSH-tunnel hint needs to forward the daemon port too
/// (laptop browser → server daemon) on top of the callback port.
fn local_custodian_port(url: &str) -> Option<u16> {
    let after = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let host_port = after.split('/').next()?;
    let mut parts = host_port.splitn(2, ':');
    let host = parts.next()?;
    if !matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return None;
    }
    let port = parts.next().and_then(|p| p.parse().ok()).unwrap_or(80);
    Some(port)
}

fn print_ssh_tunnel_hint(custodian: &str, cb_port: Option<u16>) {
    let user = std::env::var("USER").unwrap_or_else(|_| "<user>".into());
    let daemon_port = local_custodian_port(custodian);

    match cb_port {
        Some(cb) => {
            // Port already configured — compact reminder in case the tunnel dropped.
            let tunnel_flags = match daemon_port {
                Some(dp) => format!("-L {cb}:localhost:{cb} -L {dp}:localhost:{dp}"),
                None => format!("-L {cb}:localhost:{cb}"),
            };
            eprintln!();
            eprintln!("note: SSH session detected. If your tunnel dropped, restart it:");
            eprintln!("       ssh -N {tunnel_flags} {user}@<your-host>");
            eprintln!();
        }
        None => {
            // First time: full two-step setup guide.
            let cb = SUGGESTED_CB_PORT;
            let tunnel_flags = match daemon_port {
                Some(dp) => format!("-L {cb}:localhost:{cb} -L {dp}:localhost:{dp}"),
                None => format!("-L {cb}:localhost:{cb}"),
            };
            eprintln!();
            eprintln!("note: looks like you're SSH'd in. The browser callback runs on this");
            eprintln!("      server but your browser lives on your laptop — you need a tunnel.");
            eprintln!();
            eprintln!("Do both, once:");
            eprintln!();
            eprintln!("  1. On your laptop, leave this running in another terminal");
            eprintln!("     (replace <your-host> with how you SSH to this server):");
            eprintln!("       ssh -N {tunnel_flags} {user}@<your-host>");
            eprintln!();
            eprintln!("  2. On this server, set the matching port (persists):");
            eprintln!("       safeclaw config set cb-port {cb}");
            eprintln!();
            eprintln!("Then re-run the command. (Continuing now with a random port; the URL");
            eprintln!("below probably won't open through SSH unless you've already tunneled.)");
            eprintln!();
        }
    }
}

fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    let candidates: &[&[&str]] = &[&["xdg-open"], &["wslview"], &["x-www-browser"]];
    #[cfg(target_os = "macos")]
    let candidates: &[&[&str]] = &[&["open"]];
    #[cfg(target_os = "windows")]
    let candidates: &[&[&str]] = &[&["cmd", "/C", "start", ""]];
    for cmd in candidates {
        let mut c = std::process::Command::new(cmd[0]);
        for arg in &cmd[1..] {
            c.arg(arg);
        }
        c.arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if c.spawn().is_ok() {
            return Ok(());
        }
    }
    Err("no browser opener".into())
}
