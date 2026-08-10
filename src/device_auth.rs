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

use crate::identity::{device_request_signature_input, SigningIdentity};
use data_encoding::BASE64;

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
