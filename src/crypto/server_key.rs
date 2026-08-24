//! Pinned SafeClaw server signing key + verification of the server-signed sync
//! envelope and contact token (team §9 — "谁是权威谁签名", the server-authority
//! half).
//!
//! The server signs the OPERATIONAL facts it pushes to daemons — sharedness
//! `kind`, format, membership epoch, and a fresh "last real contact" token. The
//! daemon PINS the server's Ed25519 public key and verifies before trusting its
//! locally-cached copy, so a local user (or a fake `/blob` server the daemon is
//! pointed at) cannot flip a shared vault to private (to kill its offline lease)
//! nor fake a recent contact (to hold the lease open offline) without the server
//! private key. This defends the daemon's cache against LOCAL tampering, NOT
//! against a compromised server (which is the authority here); the hard
//! revocation is always upstream-key rotation. See
//! design/team-shared-vault-security-model.md §9.
//!
//! The signed byte layout is built by [`crate::identity`] (`server_envelope_input`
//! / `contact_token_input`) and the backend mirrors it byte-for-byte in
//! `safeclaw-pro-backend/src/server-signing.mjs` (guarded by a shared golden
//! vector). The pinned key below is the DEV server key; a prod build or a test
//! overrides it via `SAFECLAW_SERVER_PUBKEY` (64-hex).

use crate::identity;

/// The pinned DEV SafeClaw server signing public key (Ed25519, 32-byte hex). The
/// matching private key lives server-side only (Supabase `server_signing_key`
/// row, or the `SAFECLAW_SERVER_SIGNING_KEY` env in prod). Overridable at runtime
/// via `SAFECLAW_SERVER_PUBKEY`.
const PINNED_SERVER_PUBKEY_HEX: &str =
    "898c205d7b5da4f448404811b57d2093d21259423d6ee50c754f411fc1c55054";

/// Resolve the server public key to verify against: the `SAFECLAW_SERVER_PUBKEY`
/// override (64-hex) if valid, else the pinned constant. Returns `None` only if
/// the pinned constant is malformed (a build error — never at runtime).
pub fn server_pubkey() -> Option<[u8; 32]> {
    if let Ok(hex) = std::env::var("SAFECLAW_SERVER_PUBKEY") {
        let hex = hex.trim();
        if !hex.is_empty() {
            if let Some(k) = parse_hex32(hex) {
                return Some(k);
            }
            tracing::warn!(
                "SAFECLAW_SERVER_PUBKEY is not 32-byte hex; falling back to the pinned key"
            );
        }
    }
    parse_hex32(PINNED_SERVER_PUBKEY_HEX)
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Verify a server envelope signature against an explicit public key (pure).
#[allow(clippy::too_many_arguments)]
pub fn verify_envelope_with(
    pubkey: &[u8; 32],
    vault_id: &str,
    kind: &str,
    format: u64,
    membership_epoch: u64,
    issued_at: u64,
    nonce: &[u8],
    sig: &[u8; 64],
) -> bool {
    identity::verify(
        pubkey,
        &identity::server_envelope_input(
            vault_id,
            kind,
            format,
            membership_epoch,
            issued_at,
            nonce,
        ),
        sig,
    )
}

/// Verify a server envelope signature against the pinned server key. Fail-closed:
/// a malformed pinned key (impossible at runtime) verifies as false.
#[allow(clippy::too_many_arguments)]
pub fn verify_envelope(
    vault_id: &str,
    kind: &str,
    format: u64,
    membership_epoch: u64,
    issued_at: u64,
    nonce: &[u8],
    sig: &[u8; 64],
) -> bool {
    match server_pubkey() {
        Some(pk) => verify_envelope_with(
            &pk,
            vault_id,
            kind,
            format,
            membership_epoch,
            issued_at,
            nonce,
            sig,
        ),
        None => false,
    }
}

/// Verify a contact-token signature against an explicit public key (pure).
pub fn verify_contact_token_with(
    pubkey: &[u8; 32],
    vault_id: &str,
    account_id: &str,
    issued_at: u64,
    nonce: &[u8],
    sig: &[u8; 64],
) -> bool {
    identity::verify(
        pubkey,
        &identity::contact_token_input(vault_id, account_id, issued_at, nonce),
        sig,
    )
}

/// Verify a contact-token signature against the pinned server key.
pub fn verify_contact_token(
    vault_id: &str,
    account_id: &str,
    issued_at: u64,
    nonce: &[u8],
    sig: &[u8; 64],
) -> bool {
    match server_pubkey() {
        Some(pk) => verify_contact_token_with(&pk, vault_id, account_id, issued_at, nonce, sig),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SigningIdentity;

    #[test]
    fn pinned_pubkey_parses() {
        assert!(
            server_pubkey().is_some(),
            "pinned server pubkey must be valid 32-byte hex"
        );
    }

    #[test]
    fn envelope_verify_roundtrip_and_tamper() {
        // Sign with an in-test key (never the real private key) and verify with
        // the explicit-key variant — proves the verify logic without embedding a
        // private key in the repo.
        let signer = SigningIdentity::from_seed(&[0x55; 32]);
        let pk = signer.public_bytes();
        let nonce = [0xAAu8; 12];
        let sig = signer.sign(&identity::server_envelope_input(
            "v1", "shared", 2, 1, 1000, &nonce,
        ));
        assert!(verify_envelope_with(
            &pk, "v1", "shared", 2, 1, 1000, &nonce, &sig
        ));
        // Any tampered field flips verification.
        assert!(!verify_envelope_with(
            &pk, "v1", "private", 2, 1, 1000, &nonce, &sig
        )); // kind
        assert!(!verify_envelope_with(
            &pk, "v1", "shared", 3, 1, 1000, &nonce, &sig
        )); // format
        assert!(!verify_envelope_with(
            &pk, "v1", "shared", 2, 2, 1000, &nonce, &sig
        )); // epoch
        assert!(!verify_envelope_with(
            &pk, "v2", "shared", 2, 1, 1000, &nonce, &sig
        )); // vault
            // Wrong key fails.
        let other = SigningIdentity::from_seed(&[0x56; 32]).public_bytes();
        assert!(!verify_envelope_with(
            &other, "v1", "shared", 2, 1, 1000, &nonce, &sig
        ));
    }

    #[test]
    fn contact_token_verify_roundtrip_and_tamper() {
        let signer = SigningIdentity::from_seed(&[0x77; 32]);
        let pk = signer.public_bytes();
        let nonce = [0xBBu8; 12];
        let sig = signer.sign(&identity::contact_token_input("v1", "acc-1", 1000, &nonce));
        assert!(verify_contact_token_with(
            &pk, "v1", "acc-1", 1000, &nonce, &sig
        ));
        assert!(!verify_contact_token_with(
            &pk, "v1", "acc-1", 1001, &nonce, &sig
        )); // issued_at
        assert!(!verify_contact_token_with(
            &pk, "v1", "acc-2", 1000, &nonce, &sig
        )); // account
    }
}
