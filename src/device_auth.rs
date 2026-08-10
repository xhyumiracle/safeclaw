//! Device-request proof-of-possession (hop-B of the mutual-mTLS transport,
//! `design/agent-device-identity-mtls.md` §9.1).
//!
//! Railway terminates TLS before the Node backend ever sees the connection, so
//! hop-B can't be a real client-cert handshake. Instead the daemon signs every
//! cloud request with its DIK (device identity keypair) and the backend verifies
//! the signature against the device's registered `dev_` pubkey. This module owns
//! the daemon (signing) side; the backend mirrors the verify in
//! `keyset-roles.mjs::verifyDeviceRequestSig`.
//!
//! ADDITIVE / dual-auth: the daemon keeps sending its bearer device-key on every
//! request too (see `sync.rs`), so this is purely a second, stronger proof that a
//! not-yet-upgraded or not-yet-migrated backend simply ignores. Nothing bricks in
//! any upgrade order. This module is dormant until `sync.rs` attaches the headers.

use crate::identity::{device_request_signature_input, IdKind, SigningIdentity};
use data_encoding::BASE64;
use std::time::{SystemTime, UNIX_EPOCH};

/// The `dev_…` self-id of the signing device (tells the backend which registered
/// pubkey to check).
pub const HDR_DEVICE_ID: &str = "x-sc-device-id";
/// Unix-seconds timestamp the signature was produced at (freshness / replay
/// window; the backend bounds how far it may drift).
pub const HDR_DEVICE_TS: &str = "x-sc-device-ts";
/// Base64 (standard, padded) of the raw-64 Ed25519 signature over
/// [`device_request_signature_input`].
pub const HDR_DEVICE_SIG: &str = "x-sc-device-sig";

/// A device's request signer: its DIK plus its self-id. Cheap to hold; clone per
/// request or share behind the daemon state. Construct once from the loaded
/// device identity file ([`crate::identity_file::load`]).
pub struct DeviceRequestSigner {
    identity: SigningIdentity,
    device_id: String,
}

impl DeviceRequestSigner {
    /// Build from a device `SigningIdentity` and its `dev_…` id. The caller is
    /// responsible for passing the id that matches the identity (the identity
    /// file's `load` recomputes+validates it, so use `LoadedIdentity.id`).
    pub fn new(identity: SigningIdentity, device_id: String) -> Self {
        Self {
            identity,
            device_id,
        }
    }

    /// The signing device's `dev_…` id.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Produce the three PoP header (name, value) pairs for one request. `path`
    /// MUST be the on-wire path including any query string, byte-for-byte as it
    /// will reach the backend; `body` is the raw request body (`&[]` for a
    /// bodyless GET); `timestamp` is unix seconds (pass the real clock at the
    /// call site — this module stays clock-free so it's deterministically
    /// testable). Apply the pairs to the reqwest builder ALONGSIDE the existing
    /// `.bearer_auth(device_key)` — never in place of it (dual-auth).
    pub fn headers(
        &self,
        method: &str,
        path: &str,
        timestamp: u64,
        body: &[u8],
    ) -> [(&'static str, String); 3] {
        let input = device_request_signature_input(method, path, timestamp, body, &self.device_id);
        let sig = self.identity.sign(&input);
        [
            (HDR_DEVICE_ID, self.device_id.clone()),
            (HDR_DEVICE_TS, timestamp.to_string()),
            (HDR_DEVICE_SIG, BASE64.encode(&sig)),
        ]
    }
}

/// Load the device's DIK signer from its on-disk identity file, mirroring
/// [`crate::sync::device_key`] (per-call, best-effort, no cache). `None` when the
/// DIK hasn't been minted yet (a device paired before P2, or an fmt1 box) — the
/// caller then signs with the bearer only (dual-auth). Per-call load matches how
/// the daemon already reads the device-key; the DIK can also appear AFTER the
/// daemon started (a later `sc login`), so caching would risk a stale `None`.
pub fn device_signer() -> Option<DeviceRequestSigner> {
    let path = crate::identity_file::device_identity_path().ok()?;
    let loaded = crate::identity_file::load(&path).ok()?;
    if loaded.kind != IdKind::Device {
        return None;
    }
    Some(DeviceRequestSigner::new(loaded.identity, loaded.id))
}

/// Current unix-seconds wall clock for the request timestamp. Saturates to 0 if
/// the clock is before the epoch (never in practice).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The on-wire path+query of a full URL — exactly what the Node backend sees as
/// `req.url` (path, `?`, query; no scheme/host). Both sides sign THIS so the PoP
/// verifies. `None` if the URL doesn't parse (caller then skips signing rather
/// than sign bytes the backend can't reproduce).
fn path_and_query(full_url: &str) -> Option<String> {
    let u = reqwest::Url::parse(full_url).ok()?;
    Some(match u.query() {
        Some(q) => format!("{}?{}", u.path(), q),
        None => u.path().to_string(),
    })
}

/// Attach the DIK proof-of-possession headers to a daemon→cloud request,
/// ALONGSIDE the `.bearer_auth(device_key)` already set — never in place of it
/// (dual-auth: hop-B is additive, the bearer stays the live auth). A no-op when
/// no DIK exists or the URL doesn't parse, so it can never break an existing
/// request; it only ever adds three headers a pre-hop-B backend ignores.
pub trait DikRequestExt {
    /// `method` = the uppercase HTTP method; `full_url` = the request URL (its
    /// path+query is extracted for the signature); `body` = the EXACT bytes the
    /// request will send (`&[]` for a bodyless GET/DELETE; for a `.json(&v)` body
    /// pass `&serde_json::to_vec(&v)` — reqwest serializes with the same
    /// `serde_json::to_vec`, so the bytes match).
    fn dik_pop(self, method: &str, full_url: &str, body: &[u8]) -> Self;
}

impl DikRequestExt for reqwest::RequestBuilder {
    fn dik_pop(self, method: &str, full_url: &str, body: &[u8]) -> Self {
        let Some(signer) = device_signer() else {
            return self;
        };
        let Some(path) = path_and_query(full_url) else {
            return self;
        };
        let mut rb = self;
        for (k, v) in signer.headers(method, &path, now_unix(), body) {
            rb = rb.header(k, v);
        }
        rb
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{derive_id, verify, IdKind};

    fn signer() -> DeviceRequestSigner {
        let seed = [7u8; 32];
        let id = SigningIdentity::from_seed(&seed);
        let dev_id = derive_id(IdKind::Device, &id.public_bytes());
        DeviceRequestSigner::new(id, dev_id)
    }

    #[test]
    fn headers_verify_over_the_rebuilt_input() {
        let s = signer();
        let seed = [7u8; 32];
        let pub_bytes = SigningIdentity::from_seed(&seed).public_bytes();
        let hdrs = s.headers("PUT", "/v/vault-x/membership", 1_700_000_000, b"{}");
        // Header names + order are stable.
        assert_eq!(hdrs[0].0, HDR_DEVICE_ID);
        assert_eq!(hdrs[1].0, HDR_DEVICE_TS);
        assert_eq!(hdrs[2].0, HDR_DEVICE_SIG);
        assert_eq!(hdrs[0].1, s.device_id());
        assert_eq!(hdrs[1].1, "1700000000");
        // The signature the backend will check verifies over the input it rebuilds
        // from method/path/ts/body/device_id.
        let sig: [u8; 64] = BASE64.decode(hdrs[2].1.as_bytes()).unwrap().try_into().unwrap();
        let input = device_request_signature_input(
            "PUT",
            "/v/vault-x/membership",
            1_700_000_000,
            b"{}",
            s.device_id(),
        );
        assert!(verify(&pub_bytes, &input, &sig), "PoP verifies");
    }

    #[test]
    fn path_and_query_matches_backend_req_url() {
        // Node's http `req.url` = path (+ ?query), never scheme/host — sign that.
        assert_eq!(
            path_and_query("https://api.example.com/v/abc/blob?since=5").as_deref(),
            Some("/v/abc/blob?since=5")
        );
        assert_eq!(
            path_and_query("https://api.example.com/api/vault/agents/hashes").as_deref(),
            Some("/api/vault/agents/hashes")
        );
        assert_eq!(path_and_query("not a url"), None);
    }

    #[test]
    fn a_replayed_signature_fails_on_a_different_request() {
        let s = signer();
        let pub_bytes = SigningIdentity::from_seed(&[7u8; 32]).public_bytes();
        let hdrs = s.headers("GET", "/a", 1, b"");
        let sig: [u8; 64] = BASE64.decode(hdrs[2].1.as_bytes()).unwrap().try_into().unwrap();
        // Same signature, different path → the rebuilt input differs → reject.
        let other = device_request_signature_input("GET", "/b", 1, b"", s.device_id());
        assert!(!verify(&pub_bytes, &other, &sig));
    }
}
