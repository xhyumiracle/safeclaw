//! Agent proxy-connect proof-of-possession (hop-A of the mutual-mTLS transport,
//! `design/agent-device-identity-mtls.md` §9.1).
//!
//! An agent reaches the daemon through a STANDARD forward proxy (`HTTP_PROXY`).
//! A standard client can't present a client cert to a forward proxy — its only
//! client-auth channel is the `Proxy-Authorization` header on each `CONNECT`. So
//! hop-A (like hop-B under Railway) carries the AIK identity as an application-
//! layer proof-of-possession (PoP): a fresh signed credential in the standard
//! auth header. This is a well-trodden pattern — its closest named standard is
//! OAuth **DPoP (RFC 9449, "Demonstrating Proof of Possession")**, which likewise
//! puts a per-request key-signed token in an HTTP header; cf. also RFC 9421 (HTTP
//! Message Signatures) and AWS SigV4. mTLS is the *transport-layer* PoP; this is
//! the *application-layer* one, chosen because a forward proxy exposes no
//! client-cert channel (see the module CONNECT note below). We use a compact
//! bespoke token rather than a DPoP JWT only to reuse hop-B's signing primitive
//! and save bytes; the shape is DPoP-style.
//!
//! The `sc` transport (which holds the AIK, keeping it OUT of the agent's env)
//! signs one token per CONNECT with [`AgentProxyPopSigner`]; the daemon parses +
//! verifies it with [`verify_agent_proxy_pop`] and then checks the resolved
//! `ag_id` against the vault's authorized-agents table. ADDITIVE / dual-auth: a
//! non-PoP password falls back to the legacy api-key hash-set, so nothing bricks.
//!
//! Wire format of the `Proxy-Authorization` password slot:
//! ```text
//! scpop1.<b64url(aik_pubkey[32])>.<unix_ts>.<b64url(sig[64])>
//! ```
//! `.`-separated (b64url has no `.`), and the prefix `scpop1.` is unambiguous vs.
//! an `sc_…` api-key. The pubkey is carried so the token is self-verifying (the
//! daemon derives `ag_id` from it); `vault_id`/`target` are NOT carried — they
//! come from the CONNECT context and the daemon rebuilds the signing input, so a
//! token can't be lifted to a different vault or destination.

use crate::identity::{agent_proxy_pop_input, derive_id, verify, IdKind, SigningIdentity};
use data_encoding::BASE64URL_NOPAD;

/// Token scheme tag — the first `.`-segment. Distinguishes a PoP token from a
/// legacy `sc_…` api-key in the same password slot (dual-auth).
pub const TOKEN_PREFIX: &str = "scpop1";

/// Default freshness window (± seconds) the daemon accepts a token's timestamp
/// within. Generous enough for agent/daemon clock skew, tight enough that a
/// captured token goes stale fast (it's also bound to one vault+target).
pub const DEFAULT_MAX_SKEW_SECS: u64 = 300;

/// Signs one proxy-connect PoP token per CONNECT. Holds the agent's AIK and its
/// `ag_…` self-id. Lives in the `sc` transport, never in the agent's env.
pub struct AgentProxyPopSigner {
    identity: SigningIdentity,
    agent_id: String,
}

impl AgentProxyPopSigner {
    pub fn new(identity: SigningIdentity, agent_id: String) -> Self {
        Self { identity, agent_id }
    }

    /// This signer's `ag_…` id.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Produce the `Proxy-Authorization` password token for a CONNECT to `target`
    /// (`host:port`) on `vault_id`, stamped `timestamp` (unix seconds; pass the
    /// real clock at the call site — this stays clock-free for deterministic
    /// tests).
    pub fn token(&self, vault_id: &str, target: &str, timestamp: u64) -> String {
        let input = agent_proxy_pop_input(vault_id, target, timestamp, &self.agent_id);
        let sig = self.identity.sign(&input);
        format!(
            "{}.{}.{}.{}",
            TOKEN_PREFIX,
            BASE64URL_NOPAD.encode(&self.identity.public_bytes()),
            timestamp,
            BASE64URL_NOPAD.encode(&sig),
        )
    }
}

/// Parse + verify a proxy-auth PoP token against the CONNECT context. Returns the
/// resolved `ag_…` id iff the token is well-formed, its signature verifies under
/// the carried pubkey over the rebuilt input (`vault_id`+`target`+`ts`+`ag_id`),
/// and it is fresh (`|now - ts| <= max_skew`). Returns `None` for anything that
/// isn't a valid, fresh PoP token — a legacy api-key, a malformed token, a bad
/// signature, or a stale one — so the caller falls back to the api-key hash-set
/// (dual-auth). Never panics. Does NOT check authorization: the caller must still
/// confirm the returned `ag_id` is in the vault's authorized-agents table.
pub fn verify_agent_proxy_pop(
    token: &str,
    vault_id: &str,
    target: &str,
    now: u64,
    max_skew: u64,
) -> Option<String> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?.strip_prefix('.')?;
    let mut parts = rest.split('.');
    let pub_b64 = parts.next()?;
    let ts_str = parts.next()?;
    let sig_b64 = parts.next()?;
    if parts.next().is_some() {
        return None; // extra segments → malformed
    }

    let pub_vec = BASE64URL_NOPAD.decode(pub_b64.as_bytes()).ok()?;
    let pubkey: [u8; 32] = pub_vec.as_slice().try_into().ok()?;
    let sig_vec = BASE64URL_NOPAD.decode(sig_b64.as_bytes()).ok()?;
    let sig: [u8; 64] = sig_vec.as_slice().try_into().ok()?;
    let ts: u64 = ts_str.parse().ok()?;

    // Freshness (symmetric window, saturating so a clock blip never panics).
    let skew = now.max(ts) - now.min(ts);
    if skew > max_skew {
        return None;
    }

    let agent_id = derive_id(IdKind::Agent, &pubkey);
    let input = agent_proxy_pop_input(vault_id, target, ts, &agent_id);
    if verify(&pubkey, &input, &sig) {
        Some(agent_id)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> AgentProxyPopSigner {
        let seed = [9u8; 32];
        let id = SigningIdentity::from_seed(&seed);
        let ag = derive_id(IdKind::Agent, &id.public_bytes());
        AgentProxyPopSigner::new(id, ag)
    }

    #[test]
    fn token_roundtrips_and_resolves_agent_id() {
        let s = signer();
        let tok = s.token("vault-x", "api.openai.com:443", 1_700_000_000);
        assert!(tok.starts_with("scpop1."));
        let got = verify_agent_proxy_pop(&tok, "vault-x", "api.openai.com:443", 1_700_000_000, 300);
        assert_eq!(got.as_deref(), Some(s.agent_id()));
    }

    #[test]
    fn wrong_vault_or_target_fails() {
        let s = signer();
        let tok = s.token("vault-x", "api.openai.com:443", 1_700_000_000);
        assert!(verify_agent_proxy_pop(&tok, "vault-y", "api.openai.com:443", 1_700_000_000, 300).is_none());
        assert!(verify_agent_proxy_pop(&tok, "vault-x", "evil.example:443", 1_700_000_000, 300).is_none());
    }

    #[test]
    fn stale_token_rejected() {
        let s = signer();
        let tok = s.token("vault-x", "api.openai.com:443", 1_700_000_000);
        // 301s in the future → outside the 300s window.
        assert!(verify_agent_proxy_pop(&tok, "vault-x", "api.openai.com:443", 1_700_000_301, 300).is_none());
        // within window (299s) → ok.
        assert!(verify_agent_proxy_pop(&tok, "vault-x", "api.openai.com:443", 1_700_000_299, 300).is_some());
    }

    #[test]
    fn legacy_api_key_is_not_a_pop_token() {
        // A non-PoP password (an api-key) → None, so the caller falls back to the
        // api-key hash-set (dual-auth, nothing bricks).
        assert!(verify_agent_proxy_pop("sc_agent_alice", "vault-x", "api.x:443", 1_700_000_000, 300).is_none());
        assert!(verify_agent_proxy_pop("scpop1.garbage", "vault-x", "api.x:443", 1_700_000_000, 300).is_none());
    }
}
