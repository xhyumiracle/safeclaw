//! SafeClaw cryptographic primitives.

pub mod aead;
pub mod binding;
pub mod canonical;
pub mod envelope;
pub mod kdf;
pub mod keys;
pub mod server_key;
pub mod vault_key;
pub mod zeroize;

pub use aead::{
    decrypt as aead_decrypt, encrypt as aead_encrypt, open as aead_open, seal as aead_seal,
};
pub use binding::{
    binding_for_op, binding_for_request, compute_binding, compute_request_hash, constant_time_eq,
    DOMAIN_SETUP, DOMAIN_STANDARD,
};
pub use canonical::{canonicalize, canonicalize_body};
pub use kdf::{derive_user_key, derive_wrapping_key, WRAP_VERSION};

use rand::{rngs::OsRng, RngCore};

/// Generate a random 32-byte DEK.
pub fn generate_dek() -> [u8; 32] {
    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);
    dek
}

/// Generate a random 32-byte prf_salt.
pub fn fresh_prf_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}
