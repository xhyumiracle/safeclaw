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

use base64::{engine::general_purpose::STANDARD, Engine};

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
/// `Proxy-Authorization` the child set is dropped (the shim owns auth); every
/// other header is preserved verbatim, including the terminating blank line.
/// `head` is the full request head up to and including the CRLFCRLF.
pub fn inject_bearer(head: &str, key: &str) -> String {
    let (req_line, rest) = head.split_once("\r\n").unwrap_or((head, ""));
    // `split_inclusive` keeps each line's trailing CRLF, so the tail (headers +
    // the empty line) reconstructs byte-for-byte minus the dropped auth lines.
    let preserved: String = rest
        .split_inclusive("\r\n")
        .filter(|line| {
            let l = line.to_ascii_lowercase();
            !(l.starts_with("authorization:") || l.starts_with("proxy-authorization:"))
        })
        .collect();
    format!("{req_line}\r\nAuthorization: Bearer {key}\r\n{preserved}")
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "GET /v/abc/registry HTTP/1.1\r\nAuthorization: Bearer sc_agent_k9\r\nHost: 127.0.0.1:23294\r\nAccept: */*\r\n\r\n"
        );
    }

    #[test]
    fn inject_bearer_drops_any_client_auth() {
        // A child that set its own (stale/empty) auth must not leak it through —
        // the shim owns the credential.
        let head = "GET /x HTTP/1.1\r\nAuthorization: Bearer stale\r\nProxy-Authorization: Basic zzz\r\nHost: h\r\n\r\n";
        let out = inject_bearer(head, "real");
        assert!(out.contains("Authorization: Bearer real\r\n"));
        assert!(!out.contains("stale"));
        assert!(!out.contains("Proxy-Authorization"));
        assert!(out.contains("Host: h\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }
}
