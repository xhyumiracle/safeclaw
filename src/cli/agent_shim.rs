//! The `sc`-transport shim — hop-A of the mutual-mTLS transport
//! (`design/agent-device-identity-mtls.md` §9.1), slice 3.
//!
//! `sc run` starts this tiny local forward proxy on loopback and points the
//! child's `*_PROXY` env at IT (not the daemon directly). The shim HOLDS the
//! agent's credentials (the AIK, and — during the dual-auth window — the api-key)
//! so the child's env carries NONE: that closes the injectable-env-bearer gap,
//! which is hop-A's core local value. Per connection it:
//!
//!   - **CONNECT `host:port`** (an https tunnel) → mints a FRESH per-CONNECT AIK
//!     proof-of-possession token ([`crate::agent_pop::AgentProxyPopSigner`]) and
//!     forwards the CONNECT to the daemon proxy with
//!     `Proxy-Authorization: Basic base64("<vid>:<token>")`, then relays bytes.
//!   - **origin-form** (`GET /v/{vid}/registry …`) → the daemon's api-face
//!     (registry / op-poll / health / ca), authed by `Authorization: Bearer`.
//!     The shim injects the api-key Bearer and forwards. (A later slice can move
//!     this channel to PoP too; for now the api-key just moves OUT of the child
//!     env into the shim, which already closes the env-bearer gap.)
//!
//! This module is the PURE wire logic (classification + head rewriting), unit-
//! tested here because that's where a subtle byte can break a tunnel. The async
//! accept-loop + relay and the `sc run` wiring are slice 3b; the relay itself is
//! a thin `tokio::io::copy_bidirectional` over the classified streams.
//!
//! ADDITIVE / dual-auth: `sc run` only routes through the shim when an AIK
//! identity file exists; with no AIK it falls back to today's direct
//! key-in-the-proxy-URL env, so nothing bricks.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::agent_pop::AgentProxyPopSigner;
use crate::util::now_unix;

/// What the child asked the shim to do, parsed from the first request line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimReq {
    /// `CONNECT host:port HTTP/1.1` — an https tunnel. The `authority` is the
    /// exact `host:port` the child named; the shim signs THIS verbatim so the
    /// daemon's PoP verify (which rebuilds the input from its own CONNECT
    /// authority) matches byte-for-byte.
    Connect { authority: String },
    /// Any other (origin-form) request — the daemon api-face. Inject the Bearer.
    Origin,
}

/// Classify the FIRST request line (`first_line` = the bytes before the first
/// CRLF, no trailing CRLF). `None` if it isn't a well-formed `METHOD TARGET
/// VERSION` request line.
pub fn classify_request_line(first_line: &str) -> Option<ShimReq> {
    let mut parts = first_line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let _version = parts.next()?;
    if target.is_empty() {
        return None;
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        Some(ShimReq::Connect {
            authority: target.to_string(),
        })
    } else {
        Some(ShimReq::Origin)
    }
}

/// The CONNECT request head the shim sends to the DAEMON proxy for an https
/// tunnel: the SAME `authority` the child asked for (so the daemon rebuilds the
/// PoP signing input verbatim) with a fresh PoP token spliced into
/// `Proxy-Authorization: Basic base64("<vid>:<pop_token>")`. Terminated by the
/// blank line so it can be written straight to the daemon socket.
pub fn daemon_connect_head(authority: &str, vid: &str, pop_token: &str) -> String {
    let cred = STANDARD.encode(format!("{}:{}", vid, pop_token).as_bytes());
    format!(
        "CONNECT {a} HTTP/1.1\r\nHost: {a}\r\nProxy-Authorization: Basic {c}\r\n\r\n",
        a = authority,
        c = cred
    )
}

/// Rewrite an origin-form request head so it carries the api-key as
/// `Authorization: Bearer <key>` (the daemon api-face channel) — moving the
/// credential OUT of the child env into the shim. Any `Authorization` /
/// `Proxy-Authorization` the child set is dropped (the shim owns auth), and
/// `Connection` is forced to `close`: the shim injects auth per CONNECTION, so
/// one api-face request per connection means a keep-alive follow-up can't slip
/// through the raw relay un-authed. Every other header is preserved verbatim,
/// including the terminating blank line. `head` is the full request head up to
/// and including the CRLFCRLF.
pub fn inject_bearer(head: &str, key: &str) -> String {
    let (req_line, rest) = head.split_once("\r\n").unwrap_or((head, ""));
    // `split_inclusive` keeps each line's trailing CRLF, so the tail (headers +
    // the empty line) reconstructs byte-for-byte minus the dropped lines.
    let preserved: String = rest
        .split_inclusive("\r\n")
        .filter(|line| {
            let l = line.to_ascii_lowercase();
            !(l.starts_with("authorization:")
                || l.starts_with("proxy-authorization:")
                || l.starts_with("connection:"))
        })
        .collect();
    format!("{req_line}\r\nAuthorization: Bearer {key}\r\nConnection: close\r\n{preserved}")
}

/// Index just PAST the first CRLFCRLF in `buf` (the end of the request head), or
/// `None` if the head isn't complete yet. Bytes at/after the returned index are
/// already-read body/leftover the caller must forward before relaying (a
/// blocking read can over-read past the head into a POST body). Pure/testable.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Cap on the request head we buffer before giving up (a malformed/hostile client
/// must not drive unbounded memory). Heads are tiny; 64 KiB is generous.
const MAX_HEAD: usize = 64 * 1024;

/// Everything the shim needs to authenticate one child's traffic. Built once by
/// `sc run` from the resolved vault + the loaded AIK + (dual-auth window) the
/// api-key, then shared across connections.
pub struct ShimConfig {
    /// Vault id — the proxy-auth username, and part of every PoP signature.
    pub vid: String,
    /// `host:port` of the real daemon proxy the shim forwards to.
    pub daemon_authority: String,
    /// Holds the AIK; mints a fresh PoP token per CONNECT.
    pub signer: AgentProxyPopSigner,
    /// The api-key injected as a Bearer on api-face (origin-form) requests during
    /// the dual-auth window, so it too stays OUT of the child env. `None` once the
    /// api-face moves to PoP / the key retires.
    pub api_key: Option<String>,
}

/// Read a request head (up to and including CRLFCRLF) from `s`, returning the
/// head text plus any already-read leftover bytes (a POST body prefix a blocking
/// read grabbed past the head; empty for a CONNECT, whose client waits for our
/// 200 before sending more).
async fn read_head(s: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(end) = head_end(&buf) {
            let leftover = buf[end..].to_vec();
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            return Ok((head, leftover));
        }
        if buf.len() > MAX_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof before request head",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Handle one child connection: classify, inject the right credential, forward to
/// the daemon proxy, and relay. Errors just close the connection (best-effort —
/// a broken tunnel must never take down the shim).
async fn handle_conn(mut child: TcpStream, cfg: Arc<ShimConfig>) -> std::io::Result<()> {
    let (head, leftover) = read_head(&mut child).await?;
    let first_line = head.split("\r\n").next().unwrap_or("");
    match classify_request_line(first_line) {
        Some(ShimReq::Connect { authority }) => {
            // Mint a fresh per-CONNECT PoP token, open the daemon tunnel with it.
            let token = cfg.signer.token(&cfg.vid, &authority, now_unix());
            let mut daemon = TcpStream::connect(&cfg.daemon_authority).await?;
            daemon
                .write_all(daemon_connect_head(&authority, &cfg.vid, &token).as_bytes())
                .await?;
            // Read the daemon's CONNECT response head and hand it back to the child
            // verbatim (a 200 Connection established, or the daemon's error). Only
            // after a 200 does the child begin its TLS to the target.
            let (resp_head, resp_leftover) = read_head(&mut daemon).await?;
            child.write_all(resp_head.as_bytes()).await?;
            if !resp_leftover.is_empty() {
                child.write_all(&resp_leftover).await?;
            }
            // A well-behaved client sends nothing before the 200, so `leftover` is
            // normally empty; forward it if present rather than drop tunnel bytes.
            if !leftover.is_empty() {
                daemon.write_all(&leftover).await?;
            }
            tokio::io::copy_bidirectional(&mut child, &mut daemon).await?;
        }
        Some(ShimReq::Origin) => {
            // api-face: inject the api-key Bearer (+ force Connection: close) and
            // forward. Without a key there's nothing to auth with → close.
            let Some(key) = cfg.api_key.as_deref() else {
                return Ok(());
            };
            let mut daemon = TcpStream::connect(&cfg.daemon_authority).await?;
            daemon.write_all(inject_bearer(&head, key).as_bytes()).await?;
            if !leftover.is_empty() {
                daemon.write_all(&leftover).await?;
            }
            tokio::io::copy_bidirectional(&mut child, &mut daemon).await?;
        }
        None => { /* malformed request line → just close */ }
    }
    Ok(())
}

/// Bind the shim on an ephemeral loopback port and serve forever on a background
/// task. Returns `(port, handle)`: `sc run` points the child's `*_PROXY` at
/// `127.0.0.1:<port>` (with NO credentials) and aborts `handle` when the child
/// exits. Each accepted connection is handled on its own task, so one stuck
/// tunnel never blocks others.
pub async fn start(config: ShimConfig) -> std::io::Result<(u16, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let cfg = Arc::new(config);
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _)) => {
                    let cfg = cfg.clone();
                    tokio::spawn(async move {
                        let _ = handle_conn(sock, cfg).await;
                    });
                }
                // Transient accept error (fd pressure) — keep serving.
                Err(_) => continue,
            }
        }
    });
    Ok((port, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_end_finds_terminator_and_leftover_boundary() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), Some(27));
        // Incomplete head → None (keep reading).
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
        // Over-read: bytes past the terminator are the leftover the caller forwards.
        let buf = b"POST /x HTTP/1.1\r\n\r\nBODY";
        let end = head_end(buf).unwrap();
        assert_eq!(&buf[end..], b"BODY");
    }

    #[test]
    fn classifies_connect_vs_origin() {
        assert_eq!(
            classify_request_line("CONNECT api.openai.com:443 HTTP/1.1"),
            Some(ShimReq::Connect {
                authority: "api.openai.com:443".to_string()
            })
        );
        // Case-insensitive method.
        assert_eq!(
            classify_request_line("connect x:443 HTTP/1.1"),
            Some(ShimReq::Connect {
                authority: "x:443".to_string()
            })
        );
        assert_eq!(
            classify_request_line("GET /v/abc/registry HTTP/1.1"),
            Some(ShimReq::Origin)
        );
        // Malformed → None (caller closes the connection).
        assert_eq!(classify_request_line("CONNECT"), None);
        assert_eq!(classify_request_line(""), None);
    }

    #[test]
    fn daemon_connect_head_binds_authority_and_carries_pop() {
        let head = daemon_connect_head("api.x:443", "vault-7", "scpop1.aaa.1.bbb");
        // Same authority the child asked for (daemon rebuilds the PoP input from it).
        assert!(head.starts_with("CONNECT api.x:443 HTTP/1.1\r\n"));
        assert!(head.contains("Host: api.x:443\r\n"));
        // Proxy-Authorization = Basic base64("vid:token"); decodes back exactly.
        let b64 = head
            .lines()
            .find_map(|l| l.strip_prefix("Proxy-Authorization: Basic "))
            .expect("has proxy-auth");
        let decoded = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();
        assert_eq!(decoded, "vault-7:scpop1.aaa.1.bbb");
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn inject_bearer_replaces_auth_preserves_rest() {
        let head = "GET /v/abc/registry HTTP/1.1\r\nHost: 127.0.0.1:23294\r\nAccept: */*\r\n\r\n";
        let out = inject_bearer(head, "sc_agent_k9");
        assert_eq!(
            out,
            "GET /v/abc/registry HTTP/1.1\r\nAuthorization: Bearer sc_agent_k9\r\nConnection: close\r\nHost: 127.0.0.1:23294\r\nAccept: */*\r\n\r\n"
        );
    }

    #[test]
    fn inject_bearer_drops_any_client_auth_and_connection() {
        // A child that set its own (stale/empty) auth must not leak it through —
        // the shim owns the credential — and its Connection is forced to close so
        // a keep-alive follow-up can't slip past the raw relay un-authed.
        let head = "GET /x HTTP/1.1\r\nAuthorization: Bearer stale\r\nProxy-Authorization: Basic zzz\r\nConnection: keep-alive\r\nHost: h\r\n\r\n";
        let out = inject_bearer(head, "real");
        assert!(out.contains("Authorization: Bearer real\r\n"));
        assert!(out.contains("Connection: close\r\n"));
        assert!(!out.contains("stale"));
        assert!(!out.contains("keep-alive"));
        assert!(!out.contains("Proxy-Authorization"));
        assert!(out.contains("Host: h\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }
}
