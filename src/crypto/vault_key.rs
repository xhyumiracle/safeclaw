//! `custody → UIK → K` key layering (team-shared-vault-security-model.md §5,
//! sudp-identity-signing-revision.md §B3) — the vault-key half of the UIK model.
//!
//! ## Status: ISOLATED + golden-vector tested; NOT yet wired into the live
//! unlock / ceremony / keyset paths.
//!
//! This module is built and tested on its own first (spec §B6: "先隔离可测,再
//! 接线") because flipping the live unlock graph is the highest-risk change in
//! the codebase — it must land atomically across core + browser + backend and
//! never leave a half-migrated unlock. Here we prove the crypto round-trips; the
//! wiring is a separate, deliberate cutover.
//!
//! ## The model
//!
//! A person has ONE **UIK root** (32 bytes). Custody (the passkey PRF's `W_c`,
//! or a password KDF) wraps the ROOT — not `K`. From the root we derive, by
//! domain-separated HKDF:
//!   - an **Ed25519 signing identity** ([`crate::identity::SigningIdentity`]) —
//!     signs config / state; `user_id = derive_id(User, ·)`;
//!   - an **X25519 encryption keypair** — the recipient for the vault key `K`.
//!
//! `K` is HPKE-sealed to the UIK's X25519 **public** key (per member, stable
//! across that member's devices). Adding a device = one more `W_c`-wrap of the
//! SAME root; it never touches `K`'s per-member seal. Re-key / member-join =
//! (re-)sealing `K` to each member's PUBLIC encryption key, which the owner can
//! do without any member's secret — the property the old per-credential `W_c`→K
//! wrap could not provide.
//!
//! **Iron rule (§5):** UIK private material lives only in personal custody; it
//! is NEVER placed under a shared vault's `K` (a member holding `K` must not be
//! able to recover another member's — or the owner's — UIK and forge signatures).

use hpke::{Deserializable, Kem};
use zeroize::Zeroizing;

use crate::crypto::envelope::{seal_to, ScKeyPair, SuiteKem};
use crate::crypto::kdf::WRAP_VERSION;
use crate::error::{AppError, Result};
use crate::identity::SigningIdentity;
use sudp::primitives::{Kdf, PrimitiveSuite, StdPrimitives};

/// HKDF `info` deriving the UIK Ed25519 signing seed from the root.
const UIK_IDENTITY_INFO: &[u8] = b"safeclaw/v1/uik-identity";
/// HKDF `info` deriving the UIK X25519 encryption scalar from the root.
const UIK_ENCRYPTION_INFO: &[u8] = b"safeclaw/v1/uik-encryption";
/// HPKE `info` prefix binding a K-seal to its vault (mirrors `grant_seal_info`).
const K_SEAL_INFO_PREFIX: &[u8] = b"safeclaw/v1/uik-kseal";

fn hkdf(root: &[u8; 32], info: &[u8]) -> [u8; 32] {
    <StdPrimitives as PrimitiveSuite>::Kdf::derive_32(root, &[], info)
        .expect("HKDF-SHA256 derive_32 is infallible for a 32-byte root")
}

/// Build the HPKE `info` for sealing `K` to a UIK, bound to `vault_id` so a seal
/// captured from one vault cannot be replayed into another. Seal and open MUST
/// use byte-identical `info`.
fn k_seal_info(vault_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(K_SEAL_INFO_PREFIX.len() + 1 + vault_id.len());
    v.extend_from_slice(K_SEAL_INFO_PREFIX);
    v.push(0x1f);
    v.extend_from_slice(vault_id.as_bytes());
    v
}

/// A person's UIK root secret — the single seed all their UIK material derives
/// from. Held only in personal custody (never under a shared `K`).
pub struct UikRoot {
    root: Zeroizing<[u8; 32]>,
}

impl UikRoot {
    /// Adopt an existing 32-byte root (e.g. custody-unwrapped at unlock).
    pub fn from_root(root: [u8; 32]) -> Self {
        Self {
            root: Zeroizing::new(root),
        }
    }

    /// Mint a fresh UIK root from the OS CSPRNG (onboarding ceremony).
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut root = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut root);
        Self::from_root(root)
    }

    /// The Ed25519 signing identity (config / state signatures, no gesture).
    pub fn signing(&self) -> SigningIdentity {
        let seed = Zeroizing::new(hkdf(&self.root, UIK_IDENTITY_INFO));
        SigningIdentity::from_seed(&seed)
    }

    /// The account primary key `us_…` (self-certifying from the signing pubkey).
    pub fn user_id(&self) -> String {
        self.signing().user_id()
    }

    /// The UIK's X25519 encryption keypair (HPKE recipient for `K`).
    fn encryption_keypair(&self) -> Result<ScKeyPair> {
        let scalar = Zeroizing::new(hkdf(&self.root, UIK_ENCRYPTION_INFO));
        let sk = <SuiteKem as Kem>::PrivateKey::from_bytes(&scalar[..])
            .map_err(|e| AppError::Internal(format!("uik x25519 sk from bytes: {}", e)))?;
        let pk = <SuiteKem as Kem>::sk_to_pk(&sk);
        Ok(ScKeyPair { sk, pk })
    }

    /// The UIK's X25519 encryption PUBLIC key (raw 32 bytes) — what `K` is sealed
    /// to. Published in the keyset (cloud-visible); a member seals `K` here.
    pub fn encryption_public(&self) -> Result<Vec<u8>> {
        Ok(self.encryption_keypair()?.pk_bytes())
    }

    /// Open a `K` HPKE-sealed to this UIK ([`seal_k_to_uik`]).
    pub fn open_k(&self, vault_id: &str, encapped: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let kp = self.encryption_keypair()?;
        let opened = kp.open(encapped, ct, &k_seal_info(vault_id), b"")?;
        Ok(Zeroizing::new(opened))
    }
}

/// Seal the vault key `K` to a UIK's X25519 encryption public key (owner-driven
/// member-join / re-key). Returns `(encapped_key, ciphertext)`. The owner needs
/// only the recipient's PUBLIC key — no member secret — which is what makes
/// owner-driven re-key possible.
pub fn seal_k_to_uik(uik_enc_pub: &[u8], vault_id: &str, k: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    seal_to(uik_enc_pub, k, &k_seal_info(vault_id), b"")
}

/// Wrap a UIK root under a custody wrapping key `W_c` — the exact same sudp
/// `KeyWrap` + `WrapBinding{credential_id, version}` the keyset already uses for
/// `K̂_c`, so the browser wrap helper changes only its plaintext (K → root),
/// never its mechanism/AAD. One `W_c`-wrap of the root per credential (device).
pub fn wrap_uik_root(w_c: &[u8], credential_id: &[u8], root: &[u8]) -> Result<Vec<u8>> {
    use sudp::primitives::{KeyWrap as _, WrapBinding};
    type Wrap = <StdPrimitives as PrimitiveSuite>::Wrap;
    let binding = WrapBinding {
        credential_id,
        version: WRAP_VERSION,
    };
    Wrap::wrap(w_c, root, &binding).map_err(|e| AppError::Internal(format!("uik root wrap: {}", e)))
}

/// Unwrap a UIK root at unlock: `W_c` (from the passkey PRF) + the wrapped root.
pub fn unwrap_uik_root(
    w_c: &[u8],
    credential_id: &[u8],
    wrapped: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    use sudp::primitives::{KeyWrap as _, WrapBinding};
    type Wrap = <StdPrimitives as PrimitiveSuite>::Wrap;
    let binding = WrapBinding {
        credential_id,
        version: WRAP_VERSION,
    };
    let bytes = Wrap::unwrap(w_c, wrapped, &binding)
        .map_err(|_| AppError::Unauthorized("uik root unwrap failed".into()))?;
    if bytes.len() != 32 {
        return Err(AppError::Unauthorized(
            "unwrapped uik root wrong length".into(),
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// The full daemon-side v2 unlock, composed from the verified primitives: the
/// custody wrapping key `W_c` (from the passkey PRF) unwraps the member's UIK
/// root; the root's UIK opens the vault key `K` (HPKE-sealed to the member's UIK
/// encryption key). This is the single call the unlock path makes for a v2
/// credential (the `custody → UIK → K` analogue of v1's `W_c`-unwrap of `K̂_c`).
/// `k_encapped` / `k_ct` come from the member's keyset row (the K seal); the
/// returned root is discarded here — a caller that also needs the UIK signing key
/// (to sign config no-gesture) should call `unwrap_uik_root` + `UikRoot` directly.
pub fn unlock_k_v2(
    w_c: &[u8],
    credential_id: &[u8],
    wrapped_uik: &[u8],
    vault_id: &str,
    k_encapped: &[u8],
    k_ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let root = unwrap_uik_root(w_c, credential_id, wrapped_uik)?;
    UikRoot::from_root(*root).open_k(vault_id, k_encapped, k_ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    const ROOT: [u8; 32] = [0x33; 32];

    #[test]
    fn pinned_uik_derivation() {
        // Fixed root → stable signing pubkey / user_id / encryption pubkey. The
        // browser ceremony (once wired) pins the same values. Do NOT edit an
        // expected value to make this pass — find why the derivations diverged.
        let uik = UikRoot::from_root(ROOT);
        assert_eq!(
            hex(&uik.signing().public_bytes()),
            "1838406bdd286c1fe706cd570707d50dc4bd0d6e29d8e8e3beaec9ce0bd56285"
        );
        assert_eq!(uik.user_id(), "us_mzg6tb63typxzojujnvinkldck7jax6k");
        assert_eq!(
            hex(&uik.encryption_public().unwrap()),
            "9163381fc5434e03de47ffef26026b599c5a42882e1b2711ecfae861b338235a"
        );
    }

    #[test]
    fn k_seal_roundtrip() {
        let uik = UikRoot::from_root(ROOT);
        let enc_pub = uik.encryption_public().unwrap();
        let k = [0x9a_u8; 32];
        let (encapped, ct) = seal_k_to_uik(&enc_pub, "vault-7", &k).unwrap();
        let opened = uik.open_k("vault-7", &encapped, &ct).unwrap();
        assert_eq!(&opened[..], &k[..]);
    }

    #[test]
    fn k_seal_wrong_vault_info_fails() {
        // The seal is bound to its vault id via HPKE `info`; opening under a
        // different vault must fail (anti cross-vault replay).
        let uik = UikRoot::from_root(ROOT);
        let enc_pub = uik.encryption_public().unwrap();
        let (encapped, ct) = seal_k_to_uik(&enc_pub, "vault-A", &[1u8; 32]).unwrap();
        assert!(uik.open_k("vault-B", &encapped, &ct).is_err());
    }

    #[test]
    fn k_seal_wrong_recipient_fails() {
        let owner = UikRoot::from_root(ROOT);
        let stranger = UikRoot::from_root([0x44; 32]);
        let (encapped, ct) =
            seal_k_to_uik(&owner.encryption_public().unwrap(), "v", &[7u8; 32]).unwrap();
        assert!(stranger.open_k("v", &encapped, &ct).is_err());
    }

    #[test]
    fn root_wrap_roundtrip() {
        let w_c = [0x55u8; 32];
        let cid = b"credential-abc";
        let wrapped = wrap_uik_root(&w_c, cid, &ROOT).unwrap();
        let root = unwrap_uik_root(&w_c, cid, &wrapped).unwrap();
        assert_eq!(&root[..], &ROOT[..]);
    }

    #[test]
    fn root_wrap_wrong_cid_or_wc_fails() {
        let w_c = [0x55u8; 32];
        let wrapped = wrap_uik_root(&w_c, b"cid-A", &ROOT).unwrap();
        // Wrong credential id (AAD binding) fails.
        assert!(unwrap_uik_root(&w_c, b"cid-B", &wrapped).is_err());
        // Wrong W_c fails.
        assert!(unwrap_uik_root(&[0x66u8; 32], b"cid-A", &wrapped).is_err());
    }

    #[test]
    fn v2_full_unlock_roundtrip() {
        // Simulate a v2 keyset credential: W_c-wrap the member's UIK root, and
        // seal K to that member's UIK. `unlock_k_v2` must recover K from those.
        let uik = UikRoot::from_root(ROOT);
        let w_c = [0x55u8; 32];
        let cid = b"cred-1";
        let wrapped_uik = wrap_uik_root(&w_c, cid, &ROOT).unwrap();
        let k = [0x9au8; 32];
        let (encapped, ct) =
            seal_k_to_uik(&uik.encryption_public().unwrap(), "vault-9", &k).unwrap();
        let recovered = unlock_k_v2(&w_c, cid, &wrapped_uik, "vault-9", &encapped, &ct).unwrap();
        assert_eq!(&recovered[..], &k[..]);
        // Wrong W_c (wrong custody) can't unwrap the root → unlock fails.
        assert!(unlock_k_v2(&[0x66u8; 32], cid, &wrapped_uik, "vault-9", &encapped, &ct).is_err());
    }
}
