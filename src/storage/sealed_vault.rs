//! Sealed-vault on-disk format = [`sudp::state::SealedState`].
//!
//! As of Phase 3b.M (2026-05-21), safeclaw uses sudp's canonical state shape
//! for vault.dat: `{ version, registry, credentials, ciphertext }` where
//! - `registry` keys credential_id → opaque public-key JSON (WebAuthn x/y/
//!   device_name)
//! - `credentials[i]` carries `cid, prf_salt, wrapped_key` (= `K̂_c` =
//!   AEAD-wrap of K under W_c with AAD `DS_WRAP ‖ cid ‖ ver_be`)
//! - `ciphertext` = AEAD-seal of canonical(ProtectedState) under K with AAD
//!   `DS_SEAL ‖ ver_be`
//!
//! The client does the sealing — safeclaw daemon never sees `K` (the state
//! key) or `M` (ProtectedState) in plaintext at setup time. The client sends
//! the already-sealed bytes; the daemon just rehouses them into a SealedState
//! file. At grant redemption (export / use / write) the client transmits `W_c`
//! over the confidential TLS leg; the daemon momentarily unwraps and acts on
//! `M`, then drops `K` and any decrypted target bytes.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sudp::passkey::WebAuthn;
use sudp::primitives::PrimitiveSuite;
use sudp::state::{Registry, SealedCredential, SealedState, Version, CURRENT_VERSION};

use crate::error::{AppError, Result};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::decode_credential_id;
use crate::storage::item::{
    item_id, item_id_bytes, seal_item, unseal_item, ItemCtx, ItemNs, ItemPayload, VaultKeys,
};

/// On-disk vault is exactly the sudp sealed-state JSON.
pub type SealedVault = SealedState;

// (F-18) TMP_EXT removed — temp path is now generated with a random suffix per call.

/// Read the vault file. Returns `None` if it doesn't exist.
pub fn read(path: &Path) -> Result<Option<SealedVault>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let v: SealedVault = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("vault.dat parse: {}", e)))?;
    if v.version != CURRENT_VERSION {
        return Err(AppError::Internal(format!(
            "vault.dat version mismatch: {} (expected {})",
            v.version, CURRENT_VERSION
        )));
    }
    Ok(Some(v))
}

/// Atomically write vault.dat.
///
/// F-18: The temp file gets a random 32-bit hex suffix so that two
/// concurrent calls (which the per-vault async mutex in approve.rs should
/// prevent, but we defend in-depth) cannot collide on the same tmp path.
/// On success the tmp file is renamed over the final path. On any error
/// the tmp file is unlinked so stale temps don't accumulate.
pub fn write_atomic(path: &Path, vault: &SealedVault) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(vault)?;
    let tmp = path.with_extension(format!("dat.tmp.{:08x}", rand::random::<u32>()));
    if let Err(e) = std::fs::write(&tmp, &bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Look up a credential's WebAuthn public key from the registry.
///
/// Returns a safeclaw-side [`PasskeyEntry`] so existing call sites that fetch
/// `(x, y, device_name)` for binding verification don't need to know the
/// sudp Registry shape.
pub fn find_pubkey(vault: &SealedVault, credential_id_b64: &str) -> Option<PasskeyEntry> {
    find_pubkey_in_registry(&vault.registry, credential_id_b64)
}

/// Same as [`find_pubkey`] but against a bare [`Registry`] — used by callers
/// that hold a per-item [`Keyset`] (which carries its own `registry`) rather
/// than a whole [`SealedVault`].
pub fn find_pubkey_in_registry(
    registry: &Registry,
    credential_id_b64: &str,
) -> Option<PasskeyEntry> {
    let cid_bytes = decode_credential_id(credential_id_b64).ok()?;
    let pk = registry.get::<WebAuthn>(&cid_bytes).ok().flatten()?;
    Some(PasskeyEntry {
        x: pk.x,
        y: pk.y,
        device_name: pk.device_name,
        created_at: 0, // sudp Registry doesn't track this; lossy.
    })
}

/// Find a credential entry by base64 id. Returns None if absent.
pub fn find_credential<'a>(
    vault: &'a SealedVault,
    credential_id_b64: &str,
) -> Option<&'a SealedCredential> {
    let cid_bytes = decode_credential_id(credential_id_b64).ok()?;
    vault.find_credential(&cid_bytes)
}

/// Build a fresh single-credential vault for first-time setup.
///
/// All sealing is performed by the client; the daemon receives the already-
/// sealed bytes (`wrapped_key`, `ciphertext`) and just assembles the file.
pub fn build_initial(
    credential_id: Vec<u8>,
    public_key_x_b64: String,
    public_key_y_b64: String,
    device_name: String,
    prf_salt: Vec<u8>,
    wrapped_key: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<SealedVault> {
    let mut registry = Registry::new();
    let pk = sudp::passkey::WebAuthnPublicKey {
        x: public_key_x_b64,
        y: public_key_y_b64,
        device_name,
    };
    registry
        .insert::<WebAuthn>(&credential_id, &pk)
        .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;
    let sealed_cred = SealedCredential {
        credential_id,
        prf_salt,
        wrapped_key,
        // The client seals everything; the KCV (if any) arrives via /keys sync
        // or the unlock backfill, not this assembly helper.
        wc_check: None,
    };
    Ok(SealedState {
        version: CURRENT_VERSION,
        registry,
        credentials: vec![sealed_cred],
        ciphertext,
    })
}

/// Rotate the acting credential's `(prf_salt, wrapped_key)` after a Write and
/// replace the body ciphertext. Used by the write handler.
pub fn replace_after_write(
    vault: &mut SealedVault,
    credential_id_b64: &str,
    new_prf_salt: Vec<u8>,
    new_wrapped_key: Vec<u8>,
    new_ciphertext: Vec<u8>,
) -> Result<()> {
    let cid_bytes = decode_credential_id(credential_id_b64)?;
    let cred = vault
        .credentials
        .iter_mut()
        .find(|c| c.credential_id == cid_bytes)
        .ok_or_else(|| AppError::Unauthorized("unknown credential for write".into()))?;
    cred.prf_salt = new_prf_salt;
    cred.wrapped_key = new_wrapped_key;
    vault.ciphertext = new_ciphertext;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// PER-ITEM LOCAL STORE  (PER_ITEM_SYNC.md §11.B step 1 / build contract §4)
//
// The whole-blob `SealedVault` = `SealedState` path ABOVE is still the live
// on-disk format wired into sync/connect/approve/metadata. The types below are
// the ADDITIVE landing target for the per-item rework: the daemon's on-disk
// vault becomes `{ keyset, items }` —
//   - `keyset` = the passkey-wrap layer (registry + credentials + format
//     version) — the SAME small CAS blob as today (§7), NOT sealed under K;
//   - `items`  = `item_id (base64url) → { version, ct }`, each `ct` a
//     `sudp::seal_record` of one `ItemPayload` under K (contract §2).
//
// Single-writer (the daemon), so one JSON file is fine. NOTHING here is wired
// into the live handlers yet — cutting sync/connect/approve/metadata over to it
// is priorities 3–5; until then the whole-blob path above stays authoritative.
// ─────────────────────────────────────────────────────────────────────────

/// serde (de)serialization of `Vec<u8>` as **base64url-nopad** — the ONE
/// binary-in-JSON encoding across the entire per-item stack (contract §1).
/// NEVER std-base64 (the recurring bug); Rust and TS both use exactly this.
mod b64url_bytes {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Serde helper: encode bytes as STANDARD base64 (matching the frontend `toBase64`)
/// and decode LENIENTLY (accept standard OR url-safe, padded or not) — the same
/// mixed-encoding tolerance as [`decode_keys_data_field`]. Used for the delegation
/// log / root-succession signature + pubkey byte fields so a keyset's `/keys` wire
/// shape (what the browser writes) round-trips byte-for-byte through the daemon AND
/// equals the on-disk `vault.dat` representation — ONE SSOT encoding for both, so
/// `serde_json::to_value(&uik.delegation_log)` yields exactly the wire the frontend
/// and backend agree on (no separate hand-rolled converter).
mod b64_std {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let norm: String = s
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                other => other,
            })
            .collect();
        let norm = norm.trim_end_matches('=');
        let pad = norm.len() % 4;
        let padded = if pad == 0 {
            norm.to_string()
        } else {
            let mut t = norm.to_string();
            t.push_str(&"=".repeat(4 - pad));
            t
        };
        STANDARD
            .decode(padded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// LENIENT base64 decode for a `/keys` row `data` field, mirroring the
/// frontend's `fromBase64` (lib/safeclaw-crypto.ts): the frontend writes these
/// fields with MIXED encodings — `x`/`y`/`prf_salt`/`wrapped_key` are STANDARD
/// base64 (`toBase64`, has `+`/`/`/`=`) while `x25519_pub` is base64url — and its
/// reader accepts BOTH. So the daemon must NOT use a strict base64url decoder
/// (it would reject `+`/`/`/`=` and fail to unwrap `K`). Normalize url→std
/// (`-`→`+`, `_`→`/`), re-pad to a multiple of 4, then STANDARD-decode.
/// This is EXCLUSIVELY for `/keys` data fields; the `cid` row PK stays strict
/// base64url-nopad (`decode_credential_id`), and content item `ct`/id bytes stay
/// strict base64url-nopad (the per-item stack, `b64url_bytes`).
pub fn decode_keys_data_field(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let std: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let std = std.trim_end_matches('=');
    let pad = std.len() % 4;
    let padded = if pad == 0 {
        std.to_string()
    } else {
        let mut t = std.to_string();
        t.push_str(&"=".repeat(4 - pad));
        t
    };
    STANDARD
        .decode(padded.as_bytes())
        .map_err(|e| AppError::BadRequest(format!("keys data field not base64: {}", e)))
}

/// One sealed content item at rest: the writer-assigned CAS `version` (plaintext,
/// also AAD-bound inside `ct` so it can't lie) + the sudp sealed-record bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredItem {
    /// Monotonic per-id CAS version (contract §6). Mirrors the cloud row's
    /// `vault_items.version` for the same `item_id`.
    pub version: u64,
    /// `sudp::seal_record` output (`suite ‖ nonce ‖ ct ‖ tag`), base64url-nopad
    /// in JSON.
    #[serde(with = "b64url_bytes")]
    pub ct: Vec<u8>,
    /// The highest `version` of this id KNOWN to be on the cloud —
    /// `version > synced_version` means the row is DIRTY (needs a push);
    /// equal means clean, and the push loop skips it. Without this every sync
    /// re-offered every already-synced row and burned one 409 round-trip per
    /// row. Local bookkeeping only (not AAD-bound, never sent): set by the
    /// pull/adopt path and by a successful push; `0` (the serde default, and
    /// what an existing on-disk store loads as) = "never confirmed on cloud",
    /// which safely re-offers the row once.
    #[serde(default)]
    pub synced_version: u64,
    /// True when this row's sealed body is a tombstone (`status:"deleted"`).
    /// Local metadata only (not AAD-bound, never sent) — it lets the push loop
    /// order writes BEFORE deletes so a syncing observer never sees a dangling
    /// reference. Concretely: a completed connect writes 3 rows at once (the
    /// refresh-token secret, the `connection` record, and a tombstone for the
    /// old `connecting` row); if the tombstone lands on the cloud first, the
    /// console briefly sees the connect withdrawn with no connection yet and
    /// renders "not configured". Serde-defaulted to false (an adopted or
    /// pre-upgrade row reads as live — harmless, it only affects push order).
    #[serde(default)]
    pub tombstone: bool,
    /// The per-record Ed25519 signature (A1.2, `record_signature_input` over the
    /// CIPHERTEXT), base64url-nopad — `None` for a legacy unsigned record (pre-team
    /// fmt1 personal / NoUik, honored additively). Carried on the wire
    /// (`vault_items.sig`) so a blind server can gate + every reader can verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// The signing principal's self-id (`us_`/`dev_`) — a UIK for human writes, the
    /// DIK for automatic (daemon/OAuth) writes (A2). `None` iff unsigned. Wire:
    /// `vault_items.signer`. The reader maps it to a pubkey (keyset UIK / authorized
    /// devices) to verify + to a role for the role×type gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// The v2 (UIK) material carried alongside one credential (device) row — the
/// per-row half of `custody → UIK → K`. `K` is HPKE-sealed to the member's UIK
/// X25519 **encryption public key** (team-shared-vault-security-model.md §1/§2:
/// "K 用该成员的 UIK 公钥封装成一份"). Logically the seal is per-MEMBER (one
/// `enc_pub` per person), but it is stored per-credential-ROW so the keyset sync
/// carries it losslessly: `/keys` rows are cid-keyed, and a daemon re-pushes an
/// adopted row verbatim without needing to map the credential back to its member
/// (it cannot — that needs the member's root). The copies across one member's
/// devices are identical and tiny; the "no duplication" rule (§2) targets ITEM
/// storage explosion, not these keyset seals. Cloud-visible by design.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UikCred {
    /// The account primary key `us_…` of the member this credential belongs to.
    /// Carried so offboarding can drop every credential of a departed member.
    pub user_id: String,
    /// The member's UIK Ed25519 **signing** public key (raw 32 bytes). Published
    /// so any reader can verify this member's config / role signatures (§9):
    /// `user_id = derive_id(sig_pub)` is one-way, so the pubkey itself must be
    /// carried. The creator's `sig_pub` is the vault's config-integrity trust
    /// anchor (only owner-signed config is honored; a malicious server can't
    /// forge it). Same across a member's devices (per-person, like `enc_pub`).
    #[serde(default)]
    pub sig_pub: Vec<u8>,
    /// The member's UIK X25519 encryption public key (raw 32 bytes). The owner
    /// seals `K` here on join / re-key (needs only this PUBLIC key); the member
    /// derives the same key from its unwrapped root and opens the seal.
    pub enc_pub: Vec<u8>,
    /// HPKE encapsulated key for the K-seal.
    pub k_encapped: Vec<u8>,
    /// HPKE ciphertext = `Seal(K)` to `enc_pub`, `info = uik-kseal ‖ vault_id`
    /// ([`crate::crypto::vault_key::seal_k_to_uik`]).
    pub k_ct: Vec<u8>,
    /// This member's role in the vault — an owner-signed attribute riding on the
    /// SAME record as membership (SSOT: the keyset cred is SM §1's single home
    /// for "who is a member"; role rides it, so there is one representation, no
    /// in-vault membership to drift). Verified via `role_sig`. `#[serde(default)]` =
    /// `Member` (least privilege) for legacy rows that predate this field, so a
    /// missing role never confers owner powers.
    #[serde(default)]
    pub role: crate::storage::plaintext::MemberRole,
    /// The vault CREATOR's Ed25519 signature over
    /// [`crate::identity::role_grant_input`]`(vault_id, user_id, role, generation)`
    /// (raw 64 bytes), signed at the keyset's `generation`. The daemon derives the
    /// owner-set by verifying this against the TOFU-pinned `creator_sig_pub`
    /// ([`KeysetUik::creator_sig_pub`]) at the CURRENT `generation`: a cred is
    /// honored at its `role` iff its `role_sig` verifies under the pinned creator AT
    /// that generation. This roots role in genesis (closing finding #1 — a member
    /// can no longer self-sign `{me: owner}`) and binds the grant to the role epoch
    /// (F3-b — a re-key generation bump invalidates a stale grant, so a
    /// demoted/offboarded person's replayed grant fails verification). May be empty
    /// for a legacy cred (then the cred is NOT an owner: an empty/invalid `role_sig`
    /// fails verification).
    #[serde(default)]
    pub role_sig: Vec<u8>,
}

/// The v2 (UIK) layer of a keyset — the `custody → UIK → K` layering
/// (team-shared-vault-security-model.md §5, sudp-identity-signing-revision.md
/// §B3). Present (`Some`) iff the keyset is v2. In v2, each
/// `SealedCredential.wrapped_key` holds `Wrap_{W_c}(UIK root)` (the classic
/// custody slot, re-purposed from wrapping `K` to wrapping the identity root),
/// and `K` is recovered from that credential's per-row seal in `creds`. A v1
/// keyset has `uik = None` and its `wrapped_key` is the classic `Wrap_{W_c}(K)`.
/// An owner-signed DP-S1 re-key event (team-shared-vault-security-model.md §3.2 /
/// sudp-identity-signing-revision.md A1.7). Proves a `generation` bump + content-
/// key rotation was authorized by an owner — so a malicious backend can neither
/// storm fake generations (unlock DoS) nor swap in a content key it chose (the
/// commitment binds the signature to the actual new content key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyProof {
    /// The generation this event authorizes (must equal `KeysetUik::generation`).
    pub generation: u64,
    /// A one-way commitment to the new content key ([`rekey_commitment`]), so the
    /// signature is bound to the specific rotated key (anti content-swap).
    pub k_commitment: Vec<u8>,
    /// The owner's Ed25519 signature over [`crate::identity::rekey_sig_input`].
    pub sig: Vec<u8>,
    /// The signing owner's `us_…` (must be an owner in the verified membership).
    pub signer_id: String,
    /// Membership anti-rollback (owner-signed): the number of delegation events at the
    /// current role-epoch captured at re-key time. `0` = empty prefix.
    #[serde(default)]
    pub membership_len: u64,
    /// [`crate::identity::membership_commitment`] over that prefix's event signatures, in
    /// `(seq, sig)` order. The fold refuses a keyset whose delegation-log prefix does
    /// not hash to this (a server serving the current generation with a rolled-back
    /// log — e.g. an omitted `remove` — fails the check).
    #[serde(default, with = "b64_std")]
    pub membership_hash: Vec<u8>,
}

/// An owner-signed delegation event — the any-owner, issuance-time-authority half
/// of the owner-set fold (design/identity-uik-aik.md §4.3,
/// delegation-log-impl-spec.md §1.2). Appended to [`KeysetUik::delegation_log`]
/// between root-signed checkpoints so ANY current owner (not just the root/creator)
/// can add / promote / demote / remove without a re-key. The fold honors an event
/// iff its `granter_id` is an Owner in the owner-set folded up to this event's `seq`
/// — so a member can't grant, and the fact "granter WAS an owner when they signed"
/// survives the granter's own later removal (NON-CASCADE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEvent {
    /// `"set"` (insert `subject_id → role`: add / promote / demote) or `"remove"`
    /// (drop `subject_id`; touches ONLY the subject — non-cascade).
    pub op: String,
    /// The `us_…` whose role this event changes.
    pub subject_id: String,
    /// The role for a `"set"` (ignored for `"remove"`). `#[serde(default)]` = Member.
    #[serde(default)]
    pub role: crate::storage::plaintext::MemberRole,
    /// The signing owner's `us_…`. Must be an Owner in the fold up to `seq`.
    pub granter_id: String,
    /// The granter's Ed25519 signing pubkey (raw 32 bytes), carried INLINE and
    /// SELF-CERTIFYING: the fold requires `derive_id(granter_sig_pub) == granter_id`,
    /// then verifies `sig` under it. Carrying it in the event (rather than resolving it
    /// from the granter's cred row) is load-bearing: it makes verification immune to a
    /// spoofed cred row that lies about `(user_id, sig_pub)`, AND keeps the event
    /// verifiable AFTER the granter's own cred row is deleted at offboard — so removing
    /// a granter never drops whom they added (NON-CASCADE survives eviction).
    #[serde(default, with = "b64_std")]
    pub granter_sig_pub: Vec<u8>,
    /// Monotone ordering within `role_epoch` (rollback / reorder guard).
    pub seq: u64,
    /// The checkpoint epoch this event rides on. An event whose `role_epoch` differs
    /// from the keyset's current (succession-derived) `role_epoch` is a pre-compaction
    /// replay → ignored by the fold.
    pub role_epoch: u64,
    /// `granter`'s Ed25519 over [`crate::identity::delegation_event_input`] (64 bytes).
    #[serde(with = "b64_std")]
    pub sig: Vec<u8>,
}

/// A root-succession certificate — the CURRENT root signs the NEXT root's id +
/// signing pubkey, letting the daemon follow a short chain from the TOFU-pinned
/// GENESIS root to the current root (creator transfer / offboard;
/// design/identity-uik-aik.md §4.3). A succession is always paired with a
/// checkpoint re-cut at `role_epoch` by the NEW root (the new root re-signs every
/// surviving grant, so the fold verifies checkpoint grants under the new root).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootSuccession {
    /// The retiring root's `us_…` (must equal `derive_id(current root)` when applied).
    pub old_root_id: String,
    /// The incoming root's `us_…` (must equal `derive_id(new_root_sig_pub)`).
    pub new_root_id: String,
    /// The incoming root's UIK Ed25519 signing pubkey (raw 32 bytes), bound in the
    /// signature so a colluding server can't swap in a root key of its choosing. For a
    /// pure COMPACTION (no ownership change) this equals the current root's pubkey and
    /// `old_root_id == new_root_id` — a self-succession that only advances `role_epoch`.
    #[serde(with = "b64_std")]
    pub new_root_sig_pub: Vec<u8>,
    /// The checkpoint epoch at which the transfer / compaction takes effect (strictly
    /// increasing along the chain — rollback guard, and the SOLE source of the current
    /// `role_epoch`, which is DERIVED from this chain rather than stored as a
    /// separately-forgeable scalar).
    pub role_epoch: u64,
    /// `old_root`'s Ed25519 over [`crate::identity::root_succession_input`] (64 bytes).
    #[serde(with = "b64_std")]
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeysetUik {
    /// `cid_b64 → per-credential UIK material` (same cid key as the credential /
    /// `/keys` row). Membership = holding one of these seals (SM §1).
    #[serde(default)]
    pub creds: BTreeMap<String, UikCred>,
    /// DP-S1 re-key epoch (team-shared-vault-security-model.md §3.2). `0` = never
    /// re-keyed (the K-seals carry a bundle whose content half is the original
    /// content key). An offboard/compromise re-key rotates the content key and
    /// bumps this, gated by an owner-signed re-key event
    /// ([`crate::identity::rekey_sig_input`]). A daemon that sees a higher, signed
    /// generation drops its old content key and re-unlocks under the new one.
    #[serde(default)]
    pub generation: u64,
    /// The owner-signed proof for the CURRENT `generation` (present iff
    /// `generation > 0`). A daemon refuses to fold a re-keyed vault whose proof is
    /// missing/invalid — so a backend can't forge a re-key.
    #[serde(default)]
    pub rekey_proof: Option<RekeyProof>,
    /// The vault's ROOT owner — the CREATOR's UIK Ed25519 signing pubkey (raw
    /// 32 bytes). This is the genesis anchor for role authority (design/
    /// identity-uik-aik.md §4.3 RESOLVED): the owner-set is derived by verifying
    /// each cred's `role_sig` against THIS key ([`Self`]'s creds →
    /// `resolve_membership_trust`). TOFU-pinned SET-ONCE by the daemon (first-seen
    /// wins; a non-empty pin is NEVER overwritten), so a colluding backend can't
    /// swap the anchor to forge an owner-set. On a v2 keyset that carries creds,
    /// empty here (serde default) means the anchor was never pinned — a colluding
    /// backend can STRIP it, so that state FAILS CLOSED ([`MembershipTrust::Untrusted`]:
    /// ALL owner-config is dropped, NOT downgraded to integrity-only). Only a
    /// legacy v1 keyset (`uik == None`) reads config integrity-only.
    #[serde(default)]
    pub creator_sig_pub: Vec<u8>,
    /// Append-only owner-signed delegation events since the last checkpoint — the
    /// any-owner half of the owner-set fold ([`DelegationEvent`]). Empty right after
    /// a compaction. A fresh daemon folds `checkpoint(role_epoch) ∘ delegation_log`.
    #[serde(default)]
    pub delegation_log: Vec<DelegationEvent>,
    /// Root-succession + compaction chain from the GENESIS `creator_sig_pub` to the
    /// current root ([`RootSuccession`]). Empty = creator is still root at genesis
    /// epoch 0. The daemon walks it to resolve BOTH the current root AND the current
    /// `role_epoch` (the role-checkpoint epoch, ORTHOGONAL to the K-rotation
    /// `generation` — memory "generation ⊥ chain 正交"). `role_epoch` is DERIVED from
    /// this root-signed chain, not stored as a separate scalar: a pure compaction is a
    /// SELF-succession (`old_root == new_root`) that only advances the epoch, so the
    /// epoch can never be forged upward without a valid root signature (closing the
    /// generation-brick class of DoS by construction — [`resolve_current_root`]).
    #[serde(default)]
    pub root_succession: Vec<RootSuccession>,
}

/// A one-way commitment to a content key for a re-key event: `SHA-256(domain ‖
/// content_key)`. Byte-identical to the browser's `rekeyCommitment`
/// (lib/uik-crypto.ts). Binds a signed `generation` to the specific content key.
pub fn rekey_commitment(content_key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"safeclaw/v1/rekey-kc");
    h.update(content_key);
    h.finalize().into()
}

/// The lowercase serde token for a role (`"owner"` / `"member"`) — the EXACT
/// bytes the creator signs in [`crate::identity::role_grant_input`]. Kept in one
/// place so the signing input and the enum's serde spelling can never drift.
pub(crate) fn role_str(role: crate::storage::plaintext::MemberRole) -> &'static str {
    match role {
        crate::storage::plaintext::MemberRole::Owner => "owner",
        crate::storage::plaintext::MemberRole::Member => "member",
    }
}

/// The passkey-wrap layer — §7's small CAS blob, unchanged in substance from
/// today's `SealedState` minus its `ciphertext`. This is what *gives* you `K`,
/// so it can never be a K-sealed item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keyset {
    /// Format version of the keyset blob (= `SealedState::version` today).
    pub version: Version,
    pub registry: Registry,
    pub credentials: Vec<SealedCredential>,
    /// Whole-blob CAS cursor for the keyset (mirrors `vault_blobs.version`).
    /// Bumped on add/remove-passkey / K-rewrap. `0` before the first cloud push.
    #[serde(default)]
    pub keyset_version: u64,
    /// The v2 (UIK) layer — `Some` iff this keyset uses `custody → UIK → K`
    /// (team edition). `None` = a classic v1 keyset (`wrapped_key` = `Wrap(K)`).
    /// Serde-default `None` so existing on-disk v1 keysets load untouched.
    #[serde(default)]
    pub uik: Option<KeysetUik>,
}

/// C.3 — verify + unwrap a signed **owner-config** item body (team-shared-vault-
/// security-model.md §9: owner-authored config is integrity-protected by a UIK
/// signature; the reader/daemon verifying it is "the real wall" against a
/// malicious/compromised server rewriting policy).
///
/// A signed body is `{ data, uik_sig, uik_sign_pub }`; the signature covers
/// [`crate::identity::config_sig_input`]`(vault, config_name, version,
/// JCS(data), derive_id(sign_pub))`. Returns:
///   - `Some(data)` — honor this config: EITHER a valid signed wrapper, OR a
///     legacy/v1 raw body (no `uik_sig`) — additive, so pre-signing vaults are
///     untouched.
///   - `None` — DROP it: a signed wrapper that FAILED (bad sig, malformed, or a
///     signer whose pubkey is NOT a published member key — the anti-forgery
///     anchor from C.1). Dropping falls the field to its safe default (A1.6:
///     isolate the bad record, never crash, safe-default security-relevant config).
///
/// `config_name` is the addressing-independent logical name (`policy`, `stores`,
/// …) so the same signature verifies whether the item rode legacy `aux:<name>`
/// or the unified ns. The browser signer is `lib/uik-crypto.ts` (JCS parity via
/// `crate::crypto::canonical`, byte-identical to the browser `canonicalize`).
/// Integrity-verify an owner-config body (the C.3 half — no role authorization).
/// Returns:
///   - `None` — a signed wrapper that FAILED (bad/malformed sig, or a signer
///     whose pubkey is NOT a published member key = the C.1 anti-forgery anchor).
///   - `Some((data, None))` — a legacy/v1 raw body (no `uik_sig`): honored, no
///     signer (additive — pre-signing vaults untouched).
///   - `Some((data, Some(signer_id)))` — a valid signature; `signer_id` = the
///     signing member's `us_…` (for D's role authorization by the caller).
fn verify_config_sig(
    body: serde_json::Value,
    keyset: &Keyset,
    vault_id: &str,
    config_name: &str,
    version: u64,
) -> Option<(serde_json::Value, Option<String>)> {
    // Not a signed wrapper → legacy raw body, honored unchanged (no signer).
    let obj = match &body {
        serde_json::Value::Object(o) if o.contains_key("uik_sig") => o,
        _ => return Some((body, None)),
    };
    // A malformed signed wrapper is a DROP (fail-closed), not a legacy pass —
    // a present-but-broken `uik_sig` must never silently fall through unsigned.
    let sig_b64 = obj.get("uik_sig").and_then(|v| v.as_str())?;
    let sign_pub_b64 = obj.get("uik_sign_pub").and_then(|v| v.as_str())?;
    let data = obj.get("data")?.clone();
    let sig_vec = decode_keys_data_field(sig_b64).ok()?;
    let sign_pub_vec = decode_keys_data_field(sign_pub_b64).ok()?;
    let sig: [u8; 64] = sig_vec.as_slice().try_into().ok()?;
    let sign_pub: [u8; 32] = sign_pub_vec.as_slice().try_into().ok()?;
    // Anti-server-forgery: the signer's pubkey MUST be a published member key
    // (the C.1 keyset anchor). A wrapper self-signed with a server-minted key is
    // rejected — the server can't add its key to the keyset with a valid K-seal.
    let known = keyset
        .uik
        .as_ref()
        .is_some_and(|u| u.creds.values().any(|c| c.sig_pub == sign_pub_vec));
    if !known {
        return None;
    }
    let signer_id = crate::identity::derive_id(crate::identity::IdKind::User, &sign_pub);
    let canonical = crate::crypto::canonical::canonicalize(&data);
    let input = crate::identity::config_sig_input(
        vault_id,
        config_name,
        version,
        Some(&canonical),
        &signer_id,
    );
    if crate::identity::verify(&sign_pub, &input, &sig) {
        Some((data, Some(signer_id)))
    } else {
        None
    }
}

/// A1.2/A1.5 — verify a per-record **sidecar** signature (`StoredItem.sig`/`signer`)
/// over the record's CIPHERTEXT, by a keyset MEMBER (a UIK — `us_…`). This is the
/// daemon-side (trust wall) verification of the new signed-record scheme: unlike
/// [`verify_config_sig`] (the sig lives INSIDE the sealed body and covers the
/// plaintext), here the sig is a plaintext sidecar covering `record_signature_input`
/// over the ciphertext — so the same signature a blind server verified at write is
/// re-verified here. Returns the signer's `us_…` iff the signature verifies AND the
/// signer's pubkey is a published keyset cred (the anti-server-forgery anchor); else
/// `None` (drop). `item_id_raw` = the 32-byte blinded id; `status_live` = live vs
/// tombstone. DIK (`dev_…`) signers are NOT resolved here (device pubkeys aren't in
/// the keyset) — that path is served separately; this covers the UIK-signed
/// owner-config + authorized-agents records.
fn verify_record_sidecar_sig(
    ct: &[u8],
    keyset: &Keyset,
    vault_id: &str,
    item_id_raw: &[u8],
    record_type: &str,
    version: u64,
    status_live: bool,
    sig_b64: &str,
    signer_id: &str,
) -> Option<String> {
    let sig_vec = decode_keys_data_field(sig_b64).ok()?;
    let sig: [u8; 64] = sig_vec.as_slice().try_into().ok()?;
    // Resolve the signer's pubkey from the published keyset creds and bind it to the
    // claimed `signer_id` (self-certifying: id = fold of pubkey). A server-minted
    // key isn't in the keyset (it can't add one with a valid K-seal) → rejected.
    let uik = keyset.uik.as_ref()?;
    let sign_pub_vec = uik.creds.values().map(|c| &c.sig_pub).find(|pk| {
        <[u8; 32]>::try_from(pk.as_slice())
            .map(|k| crate::identity::derive_id(crate::identity::IdKind::User, &k) == signer_id)
            .unwrap_or(false)
    })?;
    let sign_pub: [u8; 32] = sign_pub_vec.as_slice().try_into().ok()?;
    let input = crate::identity::record_signature_input(
        record_type,
        item_id_raw,
        version,
        vault_id,
        ct,
        status_live,
        signer_id,
    );
    if crate::identity::verify(&sign_pub, &input, &sig) {
        Some(signer_id.to_string())
    } else {
        None
    }
}

/// Fold one authorized-agents row, PREFERRING the new sidecar item-sig (A1.2) and
/// falling back to the legacy in-body config-sig during the migration batch. The
/// sidecar path verifies `record_signature_input` (type `"agent"`, the blinded
/// `item_id` disambiguating WHICH agent) over the ciphertext, then applies the §11
/// authz (signer is the row's `owner` OR any owner). Returns `(data, was_signed)`
/// to honor, or `None` to drop. `body` is the raw row for the sidecar path (no
/// wrapper) or the `{data,uik_sig}` wrapper for the config-sig fallback.
#[allow(clippy::too_many_arguments)]
fn fold_agent_record(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    keyset: &Keyset,
    vault_id: &str,
    item_id_raw: &[u8],
    config_name: &str,
    version: u64,
    body: serde_json::Value,
    trust: &MembershipTrust,
) -> Option<(serde_json::Value, bool)> {
    let Some(sig) = stored_sig else {
        // No sidecar → legacy in-body config-sig path (unchanged).
        return unwrap_verified_agent_grant(body, keyset, vault_id, config_name, version, trust);
    };
    let signer = stored_signer?;
    let sid = verify_record_sidecar_sig(
        ct, keyset, vault_id, item_id_raw, "agent", version, true, sig, signer,
    )?;
    match trust {
        MembershipTrust::Untrusted => None,
        // Legacy v1 keyset: integrity-only (the sig already verified above).
        MembershipTrust::NoUik => Some((body, true)),
        MembershipTrust::Verified(membership) => {
            let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or_default();
            let is_owner = membership.get(&sid)
                == Some(&crate::storage::plaintext::MemberRole::Owner);
            if is_owner || sid == owner {
                Some((body, true))
            } else {
                None
            }
        }
    }
}

/// Fold one owner-config singleton, PREFERRING the sidecar item-sig (A1.2) and
/// falling back to the in-body config-sig during migration. `config_name` doubles
/// as the plaintext record type for the sidecar (owner-config ns == its name:
/// `policy`/`stores`/…). Owner-only: the sidecar signer must be an owner. Returns
/// the raw `data` to honor (the daemon then parses it) or `None` to drop.
#[allow(clippy::too_many_arguments)]
fn fold_owner_config_record(
    stored_sig: Option<&str>,
    stored_signer: Option<&str>,
    ct: &[u8],
    keyset: &Keyset,
    vault_id: &str,
    item_id_raw: &[u8],
    config_name: &str,
    version: u64,
    body: serde_json::Value,
    trust: &MembershipTrust,
) -> Option<serde_json::Value> {
    let Some(sig) = stored_sig else {
        return unwrap_verified_config(body, keyset, vault_id, config_name, version, trust);
    };
    let signer = stored_signer?;
    let sid = verify_record_sidecar_sig(
        ct, keyset, vault_id, item_id_raw, config_name, version, true, sig, signer,
    )?;
    match trust {
        MembershipTrust::Untrusted => None,
        MembershipTrust::NoUik => Some(body),
        MembershipTrust::Verified(membership) => {
            if membership.get(&sid) == Some(&crate::storage::plaintext::MemberRole::Owner) {
                Some(body)
            } else {
                None
            }
        }
    }
}

/// The three-state trust an owner-config reader derives from the KEYSET's UIK
/// anchor (design/identity-uik-aik.md §4.3, team-shared-vault-security-model.md
/// §9). This REPLACES the old `Option<BTreeMap<..>>` membership signal, which
/// conflated two very different "no owner-set" cases into `None` and so
/// FAIL-OPENED: a v2 keyset whose `creator_sig_pub` a colluding server had
/// STRIPPED looked identical to a legacy v1 vault and silently downgraded to
/// integrity-only, letting a colluding member's signed owner-config be honored.
/// The three states keep those cases distinct:
enum MembershipTrust {
    /// Legacy v1 keyset (`keyset.uik == None`) — no UIK layer, never re-keyable.
    /// Owner-config is honored on integrity alone (additive; pre-signing vaults).
    NoUik,
    /// A v2 keyset with a valid 32-byte pinned creator anchor. Owner-config is
    /// gated by this derived owner-set (`user_id → role`); an empty map is fine
    /// (it just means every SIGNED owner-config item drops).
    Verified(BTreeMap<String, crate::storage::plaintext::MemberRole>),
    /// A v2 keyset that carries credentials but has NO valid creator anchor
    /// (`creator_sig_pub` empty / not 32 bytes). This is the server-strippable
    /// state (`adopt_creator_pin` only pins a non-empty value), so it FAILS
    /// CLOSED: ALL owner-config (signed OR legacy-raw) is dropped → the fields
    /// fall to their safe defaults. Never downgrade this to integrity-only.
    Untrusted,
}

/// C.3 + D — verify AND authorize an owner-config item body (team-shared-vault-
/// security-model.md §9 + §附 role×type: owner-authored config is honored only
/// when signed by an **owner**; the reader/daemon verifying it is "the real
/// wall"). Composes [`verify_config_sig`] (integrity) with role authorization,
/// keyed on the [`MembershipTrust`] state:
///   - [`MembershipTrust::NoUik`] (legacy v1) ⇒ integrity-only: a valid or unsigned
///     body is honored (additive — pre-signing vaults);
///   - [`MembershipTrust::Verified`] (v2, anchor pinned) ⇒ owner-gated: legacy-raw
///     (unsigned) honored; a valid signature honored only if the signer is an
///     **owner** in the derived owner-set, else DROPPED (a non-owner member, an
///     unknown signer, or a bad/forged signature all drop);
///   - [`MembershipTrust::Untrusted`] (v2, anchor stripped) ⇒ FAIL CLOSED: EVERYTHING
///     the owner-config path would otherwise honor is dropped, signed or not, so
///     a colluding member's config is never honored via integrity-only.
/// Dropping falls the field to its safe default (A1.6).
fn unwrap_verified_config(
    body: serde_json::Value,
    keyset: &Keyset,
    vault_id: &str,
    config_name: &str,
    version: u64,
    trust: &MembershipTrust,
) -> Option<serde_json::Value> {
    match verify_config_sig(body, keyset, vault_id, config_name, version) {
        None => None,
        Some((data, signer)) => match trust {
            // Anchor stripped: drop everything the owner-config path would honor.
            MembershipTrust::Untrusted => None,
            // Legacy v1: integrity-only (additive) — signed or unsigned honored.
            MembershipTrust::NoUik => Some(data),
            // Verified v2: legacy-raw honored; a signed item is honored only from
            // an OWNER in the derived owner-set, else dropped.
            MembershipTrust::Verified(membership) => match signer {
                Some(signer_id)
                    if membership.get(&signer_id)
                        != Some(&crate::storage::plaintext::MemberRole::Owner) =>
                {
                    None
                }
                _ => Some(data),
            },
        },
    }
}

/// §11.1 — verify AND authorize an **authorized-agents table** row body
/// (design/agent-device-identity-mtls.md §11.1). Composes [`verify_config_sig`]
/// (integrity + anti-server-forgery: the signer's pubkey MUST be a published
/// keyset cred, i.e. a real member) with the agent-specific authorization rule: a
/// signed row is honored iff the signer is EITHER the row's declared `owner` (a
/// member authorizing their OWN agent) OR any owner (owner override). This REUSES
/// the owner-config signing machinery — same crypto, one extra authz predicate,
/// no new fragility.
///
/// Returns `Some((data, was_signed))`:
///   - `was_signed == true` — a valid, authorized signature; the caller retains
///     the original signed wrapper for lossless re-emit (the daemon holds only
///     public keys and cannot re-sign).
///   - `was_signed == false` — a legacy raw (unsigned) row, honored additively
///     (pre-AIK vaults / NoUik keysets), no signer.
/// Returns `None` — DROP the row: a bad/forged/unknown-signer signature, an
/// [`MembershipTrust::Untrusted`] keyset, or a signer who is neither the row's
/// `owner` nor an owner. A dropped row simply means that `ag_id` is not in the
/// table (= not authorized), never a crash (A1.6 fault isolation).
fn unwrap_verified_agent_grant(
    body: serde_json::Value,
    keyset: &Keyset,
    vault_id: &str,
    config_name: &str,
    version: u64,
    trust: &MembershipTrust,
) -> Option<(serde_json::Value, bool)> {
    match verify_config_sig(body, keyset, vault_id, config_name, version) {
        None => None,
        Some((data, signer)) => match trust {
            // Anchor stripped: drop everything (fail-closed).
            MembershipTrust::Untrusted => None,
            // Legacy v1 keyset: integrity-only (additive; pre-AIK vaults).
            MembershipTrust::NoUik => Some((data, signer.is_some())),
            MembershipTrust::Verified(membership) => match signer {
                // Legacy raw (unsigned) honored additively.
                None => Some((data, false)),
                Some(signer_id) => {
                    let owner = data.get("owner").and_then(|v| v.as_str()).unwrap_or_default();
                    let is_owner_override = membership.get(&signer_id)
                        == Some(&crate::storage::plaintext::MemberRole::Owner);
                    // self-service: the signer admits their OWN agent (the signer is
                    // a real member — verify_config_sig pinned its pubkey to a keyset
                    // cred); owner-override: any owner may admit/modify/revoke any.
                    if is_owner_override || signer_id == owner {
                        Some((data, true))
                    } else {
                        None
                    }
                }
            },
        },
    }
}

/// Resolve the CURRENT root's Ed25519 signing pubkey AND the current `role_epoch` by
/// walking the [`KeysetUik::root_succession`] chain from the TOFU-pinned GENESIS root
/// (`creator_sig_pub`) (design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md
/// §1.2). The `role_epoch` is DERIVED here (not stored): a pure COMPACTION is a
/// SELF-succession (`old_root == new_root`, same pubkey) that only advances the
/// epoch, so the epoch can never be forged upward without a valid root signature.
///
/// A hop from the current `(root, epoch)` is VALID iff: `old_root_id ==
/// derive_id(current root)` (chains from the current root, so the server can't fork
/// it onto a key it controls), `role_epoch` STRICTLY increases (rollback guard),
/// `new_root_id == derive_id(new_root_sig_pub)` (id/pubkey bound), and the `sig`
/// verifies under the CURRENT root over [`crate::identity::root_succession_input`].
///
/// The walk is ORDER-ROBUST: at each step it SEARCHES the whole chain for a valid
/// extending hop (rather than reading in slice order), so a colluding server cannot
/// block a legitimate successor by reordering / prepending a bogus cert. Among
/// multiple valid extensions of the same root (a root that equivocated), the
/// lowest-`role_epoch` (ties broken by `new_root_id`) is taken for determinism; the
/// loop terminates because each step strictly increases the epoch. An unverifiable
/// succession never advances the root (fail-closed forward), so a forged succession
/// can't install a server-chosen root. Returns `None` iff the genesis anchor itself
/// is absent / not 32 bytes (the server-strippable state → callers fail closed).
fn resolve_current_root(uik: &KeysetUik, vault_id: &str) -> Option<([u8; 32], u64)> {
    let mut cur = <[u8; 32]>::try_from(uik.creator_sig_pub.as_slice()).ok()?;
    let mut cur_epoch: u64 = 0;
    loop {
        let cur_id = crate::identity::derive_id(crate::identity::IdKind::User, &cur);
        // Find the lowest-epoch valid hop extending the current root (order-robust +
        // deterministic under equivocation).
        let mut best: Option<(&RootSuccession, [u8; 32])> = None;
        for s in &uik.root_succession {
            if s.old_root_id != cur_id || s.role_epoch <= cur_epoch {
                continue;
            }
            let Ok(new_pub) = <[u8; 32]>::try_from(s.new_root_sig_pub.as_slice()) else {
                continue;
            };
            if s.new_root_id != crate::identity::derive_id(crate::identity::IdKind::User, &new_pub)
            {
                continue; // id/pubkey mismatch
            }
            let Ok(sig) = <[u8; 64]>::try_from(s.sig.as_slice()) else {
                continue;
            };
            let input = crate::identity::root_succession_input(
                vault_id,
                &s.old_root_id,
                &s.new_root_id,
                &new_pub,
                s.role_epoch,
            );
            if !crate::identity::verify(&cur, &input, &sig) {
                continue; // signature by anyone but the current root
            }
            // Prefer the lowest epoch; break ties on new_root_id for determinism.
            let better = match &best {
                None => true,
                Some((b, _)) => {
                    s.role_epoch < b.role_epoch
                        || (s.role_epoch == b.role_epoch && s.new_root_id < b.new_root_id)
                }
            };
            if better {
                best = Some((s, new_pub));
            }
        }
        match best {
            Some((s, new_pub)) => {
                cur = new_pub;
                cur_epoch = s.role_epoch;
            }
            None => return Some((cur, cur_epoch)),
        }
    }
}

/// Verify a keyset's DP-S1 re-key state (team-shared-vault-security-model.md
/// §3.2). A gen-0 keyset (or a v1 vault) is trivially valid. A re-keyed keyset
/// (`generation > 0`) is trusted only if it carries an owner-signed
/// [`RekeyProof`] that: matches the generation; commits to the ACTUAL content
/// key in use (anti content-swap by a backend); is signed by a key that is a
/// published keyset member (C.1 anchor) AND an OWNER in the verified owner-set
/// (D); with a valid signature over [`crate::identity::rekey_sig_input`]. A
/// missing or invalid proof on a re-keyed vault ⇒ `false` (the daemon refuses to
/// fold it), which is what stops a backend forging a generation bump (unlock
/// DoS). An [`MembershipTrust::Untrusted`] keyset (v2 anchor stripped) has no
/// confirmable owner, so a re-keyed (`generation > 0`) keyset is likewise refused
/// — a DoS a colluding server can already cause by stripping the anchor, NOT a
/// privilege escalation.
fn verify_rekey_proof(
    keyset: &Keyset,
    trust: &MembershipTrust,
    vault_id: &str,
    content_key: &[u8],
) -> bool {
    let Some(uik) = keyset.uik.as_ref() else {
        return true; // v1 / no UIK layer — not re-keyable
    };
    if uik.generation == 0 {
        return true; // never re-keyed
    }
    // A re-key must be authorized by an OWNER, so a confirmed owner-set is
    // required. `uik` is present here, so `trust` is Verified or Untrusted;
    // Untrusted (anchor stripped) ⇒ no confirmable owner ⇒ refuse the bump.
    let MembershipTrust::Verified(membership) = trust else {
        return false;
    };
    let Some(proof) = uik.rekey_proof.as_ref() else {
        return false; // gen > 0 with no proof = a forged bump
    };
    if proof.generation != uik.generation {
        return false;
    }
    // The signature must commit to the content key actually delivered (a backend
    // can't pair a valid signed generation with a content key it chose).
    if proof.k_commitment.as_slice() != rekey_commitment(content_key).as_slice() {
        return false;
    }
    let Ok(sig) = <[u8; 64]>::try_from(proof.sig.as_slice()) else {
        return false;
    };
    // The signer must be a PUBLISHED member key whose id matches the claimed
    // signer (C.1 anchor) — a backend-minted key isn't in the keyset.
    let signer_pub: Option<[u8; 32]> = uik.creds.values().find_map(|c| {
        let a = <[u8; 32]>::try_from(c.sig_pub.as_slice()).ok()?;
        (crate::identity::derive_id(crate::identity::IdKind::User, &a) == proof.signer_id)
            .then_some(a)
    });
    let Some(signer_pub) = signer_pub else {
        return false;
    };
    // The signer must be an OWNER in the verified owner-set (D).
    let owner = matches!(
        membership.get(&proof.signer_id),
        Some(crate::storage::plaintext::MemberRole::Owner)
    );
    if !owner {
        return false;
    }
    let input = crate::identity::rekey_sig_input(
        vault_id,
        proof.generation,
        &proof.k_commitment,
        &proof.signer_id,
        proof.membership_len,
        &proof.membership_hash,
    );
    crate::identity::verify(&signer_pub, &input, &sig)
}

/// Membership anti-rollback check (delegation-log-review-findings.md C2): the current
/// re-key proof committed a delegation-log PREFIX (`membership_len` events at the current
/// role-epoch, in `(seq, sig)` order, hashed to `membership_hash`). Recompute that
/// commitment over the SERVED log's prefix and compare — a mismatch means the server
/// rolled the log back (e.g. omitted a `remove`) or altered it, so the owner-set
/// can't be trusted. A proof with `membership_len == 0` (empty prefix) commits nothing
/// beyond "the log was empty at re-key". Returns `true` (no rollback detected) when
/// there is no proof. Because the daemon ratchets `generation` (won't adopt a lower
/// one) and this binds the log to that generation, a server can't serve the CURRENT
/// generation with a rolled-back log.
fn membership_prefix_ok(uik: &KeysetUik, vault_id: &str) -> bool {
    let Some(proof) = uik.rekey_proof.as_ref() else {
        return true; // no re-key → nothing committed to roll back
    };
    if proof.generation == 0 {
        return true;
    }
    let role_epoch = resolve_current_root(uik, vault_id)
        .map(|(_, e)| e)
        .unwrap_or(0);
    let mut events: Vec<&DelegationEvent> = uik
        .delegation_log
        .iter()
        .filter(|e| e.role_epoch == role_epoch)
        .collect();
    events.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));
    let n = proof.membership_len as usize;
    if events.len() < n {
        return false; // the server dropped committed events
    }
    let prefix_sigs: Vec<&[u8]> = events.iter().take(n).map(|e| e.sig.as_slice()).collect();
    crate::identity::membership_commitment(&prefix_sigs).as_slice() == proof.membership_hash.as_slice()
}

/// The daemon's per-item on-disk vault: keyset blob + N sealed item records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerItemVault {
    pub keyset: Keyset,
    /// `item_id (base64url) → StoredItem`. Disjoint items live in disjoint
    /// entries → two writers touching different items never collide.
    #[serde(default)]
    pub items: BTreeMap<String, StoredItem>,
    /// Last cloud `vault_items.seq` this local store has pulled (the incremental
    /// pull cursor — replaces the whole-blob `.blob_version`). `0` = full-resync.
    #[serde(default)]
    pub items_seq: u64,
    /// Last cloud `vault_keys.seq` this local store has pulled (the incremental
    /// keyset pull cursor — the `/keys` analogue of `items_seq`). The keyset now
    /// syncs via `/keys` (one `vault_keys` row per credential), NOT the whole-blob
    /// `/blob` path. `0` = full keyset resync. Pre-launch: serde-default'd so an
    /// existing on-disk `vault.per-item.json` loads without migration.
    #[serde(default)]
    pub keyset_seq: u64,
}

impl PerItemVault {
    /// Fresh per-item vault for first-time setup: a keyset with one credential
    /// and no items.
    pub fn build_initial(
        credential_id: Vec<u8>,
        public_key_x_b64: String,
        public_key_y_b64: String,
        device_name: String,
        prf_salt: Vec<u8>,
        wrapped_key: Vec<u8>,
    ) -> Result<Self> {
        let mut registry = Registry::new();
        let pk = sudp::passkey::WebAuthnPublicKey {
            x: public_key_x_b64,
            y: public_key_y_b64,
            device_name,
        };
        registry
            .insert::<WebAuthn>(&credential_id, &pk)
            .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;
        Ok(Self {
            keyset: Keyset {
                version: CURRENT_VERSION,
                registry,
                credentials: vec![SealedCredential {
                    credential_id,
                    prf_salt,
                    wrapped_key,
                    // KCV arrives via /keys sync or the unlock backfill.
                    wc_check: None,
                }],
                keyset_version: 0,
                uik: None,
            },
            items: BTreeMap::new(),
            items_seq: 0,
            keyset_seq: 0,
        })
    }

    /// Borrow a stored item by its base64url id.
    pub fn get_item(&self, item_id_b64: &str) -> Option<&StoredItem> {
        self.items.get(item_id_b64)
    }

    /// Insert or replace a raw sealed item (used by the pull/adopt path — the ct
    /// is already sealed by whoever wrote the cloud row, so by construction the
    /// cloud has this exact version: the row lands clean). `tombstone` stays
    /// false: an adopted row is clean and never re-pushed, so its push-order
    /// flag is never consulted (and we hold no K here to open the ct anyway).
    pub fn put_raw(&mut self, item_id_b64: String, version: u64, ct: Vec<u8>) {
        self.put_raw_signed(item_id_b64, version, ct, None, None)
    }

    /// Like [`Self::put_raw`] but carrying the per-record signature fields pulled
    /// from the cloud row (`vault_items.sig`/`signer`, A1.2). Legacy rows pass
    /// `None`/`None` (unsigned; honored additively on NoUik).
    pub fn put_raw_signed(
        &mut self,
        item_id_b64: String,
        version: u64,
        ct: Vec<u8>,
        sig: Option<String>,
        signer: Option<String>,
    ) {
        self.items.insert(
            item_id_b64,
            StoredItem {
                version,
                ct,
                synced_version: version,
                tombstone: false,
                sig,
                signer,
            },
        );
    }

    /// Drop a stored item outright (local GC of a fully-propagated tombstone).
    pub fn remove_item(&mut self, item_id_b64: &str) -> Option<StoredItem> {
        self.items.remove(item_id_b64)
    }

    /// Adopt one pulled `/keys` row into the keyset: upsert the credential's
    /// WebAuthn registry entry (`x`/`y`/`device_name` — sudp's `WebAuthnPublicKey`
    /// stores `x`/`y` as verbatim strings, exactly what the frontend sent) and the
    /// `SealedCredential` (`credential_id` = decoded `cid`, `prf_salt`/`wrapped_key`
    /// = lenient-decoded data fields, contract §7). `cid_b64` is the row PK
    /// (base64url-nopad WebAuthn credential id). Returns `true` iff the keyset
    /// changed. `x25519_pub` is intentionally NOT stored — sudp's
    /// `WebAuthnPublicKey` has no field for it, and the daemon needs only
    /// `x`/`y` (assertion verify) + `prf_salt`/`wrapped_key` (unwrap `K`).
    ///
    /// Byte-compatibility: `x`/`y` are kept as the exact strings the frontend
    /// wrote (std-base64), and `prf_salt`/`wrapped_key` decode leniently
    /// ([`decode_keys_data_field`]) so a std-base64 field round-trips through
    /// sudp's own STANDARD `wire::b64bytes` codec on write.
    pub fn upsert_key_row(
        &mut self,
        cid_b64: &str,
        x_b64: &str,
        y_b64: &str,
        device_name: &str,
        prf_salt_b64: &str,
        wrapped_key_b64: &str,
        wc_check_b64: Option<&str>,
    ) -> Result<bool> {
        let cid_bytes = decode_credential_id(cid_b64)?;
        let prf_salt = decode_keys_data_field(prf_salt_b64)?;
        let wrapped_key = decode_keys_data_field(wrapped_key_b64)?;
        // Optional KCV (`wc_check`) — carried verbatim from the cloud row so a
        // pull preserves a value another device (or an earlier backfill) wrote.
        let wc_check = wc_check_b64
            .filter(|s| !s.is_empty())
            .map(decode_keys_data_field)
            .transpose()?;

        // Registry pubkey (x/y verbatim strings — sudp keeps them as-is).
        let pk = sudp::passkey::WebAuthnPublicKey {
            x: x_b64.to_string(),
            y: y_b64.to_string(),
            device_name: device_name.to_string(),
        };
        // `insert` overwrites an existing entry — idempotent.
        self.keyset
            .registry
            .insert::<WebAuthn>(&cid_bytes, &pk)
            .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;

        // SealedCredential (upsert by credential_id).
        if let Some(cred) = self
            .keyset
            .credentials
            .iter_mut()
            .find(|c| c.credential_id == cid_bytes)
        {
            cred.prf_salt = prf_salt;
            cred.wrapped_key = wrapped_key;
            // Only adopt a cloud-provided KCV; never clear a locally-backfilled
            // one just because an older row omitted it.
            if wc_check.is_some() {
                cred.wc_check = wc_check;
            }
        } else {
            self.keyset.credentials.push(SealedCredential {
                credential_id: cid_bytes,
                prf_salt,
                wrapped_key,
                wc_check,
            });
        }
        Ok(true)
    }

    /// Whether this vault's keyset is v2 (`custody → UIK → K`). In a v2 keyset,
    /// `SealedCredential.wrapped_key` wraps the UIK root (not `K`), and `K` is
    /// recovered from a per-credential seal ([`Self::uik_cred`]).
    pub fn is_uik(&self) -> bool {
        self.keyset.uik.is_some()
    }

    /// Borrow the v2 UIK material for credential `cid_b64` (v2 keysets). `None`
    /// if this is a v1 keyset or the credential carries no seal.
    pub fn uik_cred(&self, cid_b64: &str) -> Option<&UikCred> {
        self.keyset.uik.as_ref()?.creds.get(cid_b64)
    }

    /// Upsert a credential's v2 UIK material, promoting the keyset to v2 if it
    /// was v1 (owner-driven join / re-key sealed `K` to `enc_pub` via
    /// [`crate::crypto::vault_key::seal_k_to_uik`]). Idempotent by `cid_b64`.
    #[allow(clippy::too_many_arguments)]
    pub fn set_uik_cred(
        &mut self,
        cid_b64: String,
        user_id: String,
        sig_pub: Vec<u8>,
        enc_pub: Vec<u8>,
        k_encapped: Vec<u8>,
        k_ct: Vec<u8>,
        role: crate::storage::plaintext::MemberRole,
        role_sig: Vec<u8>,
    ) {
        self.keyset
            .uik
            .get_or_insert_with(KeysetUik::default)
            .creds
            .insert(
                cid_b64,
                UikCred {
                    user_id,
                    sig_pub,
                    enc_pub,
                    k_encapped,
                    k_ct,
                    role,
                    role_sig,
                },
            );
    }

    /// Adopt a pulled `/keys` row's v2 UIK fields (base64, lenient-decoded like
    /// the other keyset data fields). Mirrors [`Self::upsert_key_row`]'s b64-in
    /// contract so the sync layer never handles raw key bytes. Promotes the
    /// keyset to v2.
    #[allow(clippy::too_many_arguments)]
    pub fn set_uik_cred_b64(
        &mut self,
        cid_b64: &str,
        user_id: &str,
        sig_pub_b64: &str,
        enc_pub_b64: &str,
        k_encapped_b64: &str,
        k_ct_b64: &str,
        role: crate::storage::plaintext::MemberRole,
        role_sig_b64: &str,
    ) -> Result<()> {
        let sig_pub = decode_keys_data_field(sig_pub_b64)?;
        let enc_pub = decode_keys_data_field(enc_pub_b64)?;
        let k_encapped = decode_keys_data_field(k_encapped_b64)?;
        let k_ct = decode_keys_data_field(k_ct_b64)?;
        // Role signature is base64 (raw 64-byte Ed25519); an empty string = a
        // legacy row with no grant (decodes to an empty vec → not an owner).
        let role_sig = if role_sig_b64.is_empty() {
            Vec::new()
        } else {
            decode_keys_data_field(role_sig_b64)?
        };
        self.set_uik_cred(
            cid_b64.to_string(),
            user_id.to_string(),
            sig_pub,
            enc_pub,
            k_encapped,
            k_ct,
            role,
            role_sig,
        );
        Ok(())
    }

    /// Drop every credential seal belonging to member `user_id` (offboarding /
    /// re-key removes the departed member's access; SM §3.2). No-op on a v1
    /// keyset. Returns the number of credential seals removed.
    pub fn remove_uik_member(&mut self, user_id: &str) -> usize {
        let Some(uik) = self.keyset.uik.as_mut() else {
            return 0;
        };
        let before = uik.creds.len();
        uik.creds.retain(|_, c| c.user_id != user_id);
        before - uik.creds.len()
    }

    /// The current keyset row version for `cid_b64` — the analogue of
    /// [`item_version`] for the keyset (there is no per-row version stored today,
    /// so this is a placeholder used only by tests / future CAS). The keyset row
    /// version lives cloud-side (`vault_keys.version`); the daemon adopts a row
    /// whenever its pulled version exceeds what it last saw for that cid, tracked
    /// by the caller (see `sync::pull_keys`), not on-disk.
    pub fn has_credential(&self, cid_b64: &str) -> bool {
        let Ok(cid_bytes) = decode_credential_id(cid_b64) else {
            return false;
        };
        self.keyset
            .credentials
            .iter()
            .any(|c| c.credential_id == cid_bytes)
    }

    /// The current CAS version of item `(ns, name)`, or `0` if absent — i.e.
    /// the `base_version` a new write should CAS against (contract §6).
    pub fn item_version<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        ns: ItemNs,
        name: &str,
    ) -> Result<u64> {
        let id = item_id::<S>(keys.id_seed, ns.as_str(), name)?;
        Ok(self.items.get(&id).map(|s| s.version).unwrap_or(0))
    }

    /// Seal `payload` for `(ns, name)` at the NEXT version (current + 1) under
    /// `K` and upsert it — the monotonic-bump write the connect / write paths
    /// use so an offline peer's CAS sees a strictly higher version (contract
    /// §6). Returns `(item_id_b64, new_version)`.
    pub fn seal_and_bump<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        payload: &ItemPayload,
    ) -> Result<(String, u64)> {
        let next = self.item_version::<S>(keys, ns, name)? + 1;
        let id = self.seal_and_upsert::<S>(keys, vault_id, ns, name, next, payload)?;
        Ok((id, next))
    }

    /// Seal `payload` for `(ns, name)` at `version` under `K` and upsert it,
    /// returning the base64url item id. Bridges the item.rs primitives
    /// (contract §1/§2) into the local store.
    pub fn seal_and_upsert<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        version: u64,
        payload: &ItemPayload,
    ) -> Result<String> {
        let ctx = ItemCtx::for_item::<S>(keys.id_seed, vault_id, ns, name, version)?;
        let ct = seal_item::<S>(keys.content, &ctx, payload)?;
        let id = ctx.item_id_b64();
        // A local write leaves `synced_version` where it was (the new version
        // is by definition not on the cloud yet) — the row is dirty until pushed.
        let synced_version = self.items.get(&id).map(|s| s.synced_version).unwrap_or(0);
        let tombstone = payload.is_tombstone();
        // B2a: seal-level writers land UNSIGNED (sig/signer None) — signing is done
        // by the write ORCHESTRATION (B2b), which knows the principal (the DIK for
        // the daemon's automatic writes). A `None` here is honored additively on a
        // NoUik (fmt1 personal) vault and is the pre-cutover state for team writes.
        self.items.insert(
            id.clone(),
            StoredItem {
                version,
                ct,
                synced_version,
                tombstone,
                sig: None,
                signer: None,
            },
        );
        Ok(id)
    }

    /// Unseal one stored item addressed by `(ns, name)` under `K`. `Ok(None)` if
    /// no such item is stored. The stored `version` is fed into the `SealCtx`,
    /// so a tampered version would fail the AEAD (contract §6).
    pub fn open_item<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
        ns: ItemNs,
        name: &str,
    ) -> Result<Option<ItemPayload>> {
        // DP-S1: address by the STABLE id-seed, unseal with the CURRENT content
        // key (they're the same at gen 0; distinct after a re-key).
        let id = item_id::<S>(keys.id_seed, ns.as_str(), name)?;
        let Some(stored) = self.items.get(&id) else {
            return Ok(None);
        };
        let raw = item_id_bytes::<S>(keys.id_seed, ns.as_str(), name)?;
        let ctx = ItemCtx::new(vault_id, raw, stored.version);
        Ok(Some(unseal_item::<S>(keys.content, &ctx, &stored.ct)?))
    }

    /// Seed / re-seed this vault's item rows from a decrypted
    /// [`VaultPlaintextView`] (contract §2 `ns` split). Used by the per-item
    /// cut-over of the whole-blob paths (enroll, write): the browser still
    /// hands the daemon ONE sealed `ProtectedState` ciphertext, which the
    /// daemon opens into a view and then re-shards into N sealed item records
    /// under the SAME `K`.
    ///
    /// Each item's CAS `version` starts at `bump_from + 1` for a freshly-sealed
    /// row, so re-seeding after a write monotonically advances the version an
    /// offline peer will CAS against (the enroll case passes `0`). Aux subtrees
    /// with their default/empty value are NOT sealed (they'd only add tombstone-
    /// like noise); only `stores`, `store_order`, `policy`,
    /// `audit_retention_days`, plus every connection/connecting entry and every
    /// native secret, become their own item.
    pub fn seed_items_from_view<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        view: &crate::storage::plaintext::VaultPlaintextView,
    ) -> Result<()> {
        // native secrets → one `secret` item each.
        for (name, bytes) in &view.native_secrets {
            let value = String::from_utf8(bytes.clone())
                .map_err(|_| AppError::Internal(format!("secret '{}' not utf8", name)))?;
            let payload = ItemPayload::secret_live(name.clone(), &value);
            self.seal_and_upsert::<S>(keys, vault_id, ItemNs::Secret, name, 1, &payload)?;
        }
        // established connections → one `connection` item each.
        for (conn_id, conn) in &view.aux.connections {
            let body = serde_json::to_value(conn).map_err(AppError::from)?;
            let payload = ItemPayload::live(ItemNs::Connection, conn_id.clone(), body);
            self.seal_and_upsert::<S>(keys, vault_id, ItemNs::Connection, conn_id, 1, &payload)?;
        }
        // in-flight connects → one `connecting` item each.
        for (conn_id, c) in &view.aux.connecting {
            let body = serde_json::to_value(c).map_err(AppError::from)?;
            let payload = ItemPayload::live(ItemNs::Connecting, conn_id.clone(), body);
            self.seal_and_upsert::<S>(keys, vault_id, ItemNs::Connecting, conn_id, 1, &payload)?;
        }
        // aux subtrees → one `aux:<name>` item each. Config singletons are
        // single blobs; AGENTS are PER-ITEM `aux:agent/<id>`
        // (one item per agent) — independent CAS so two members editing their
        // own agents never clobber, and a distinct item id per agent for the
        // future per-author write gate (team §8.1). The `aux:` prefix is
        // retained (the cosmetic drop → `agent:<id>` is the pre-launch
        // console-coordinated cutover); the PER-ITEM SPLIT is here now.
        for (name, body) in Self::aux_blob_bodies(&view.aux)? {
            self.seal_and_upsert::<S>(
                keys,
                vault_id,
                ItemNs::Aux,
                &name,
                1,
                &ItemPayload::live(ItemNs::Aux, name.clone(), body),
            )?;
        }
        Ok(())
    }

    /// The aux items a view wants materialised, as `(aux_name, body)` pairs
    /// under `aux:<name>` addressing. Shared by seed + reconcile so the two
    /// write paths can never disagree. Config singletons are whole
    /// blobs; each agent mask is its OWN item `aux:agent/<id>` (per-item CAS).
    /// Default/empty subtrees are skipped (no tombstone-like noise).
    fn aux_blob_bodies(
        aux: &crate::storage::plaintext::VaultAux,
    ) -> Result<Vec<(String, serde_json::Value)>> {
        let mut out: Vec<(String, serde_json::Value)> = Vec::new();
        out.push((
            "stores".into(),
            serde_json::to_value(&aux.stores).map_err(AppError::from)?,
        ));
        out.push((
            "store_order".into(),
            serde_json::to_value(&aux.store_order).map_err(AppError::from)?,
        ));
        if let Some(policy) = &aux.policy {
            out.push((
                "policy".into(),
                serde_json::to_value(policy).map_err(AppError::from)?,
            ));
        }
        if let Some(days) = aux.audit_retention_days {
            out.push(("audit_retention_days".into(), serde_json::json!(days)));
        }
        if !aux.services.is_empty() {
            out.push((
                "services".into(),
                serde_json::to_value(&aux.services).map_err(AppError::from)?,
            ));
        }
        // PER-AGENT items — one `aux:agent/<ag_id>` each (§11.1 authorized-agents
        // table). A row folded from a UIK-signed wrapper is re-emitted VERBATIM
        // (the daemon holds only public keys, so it cannot re-sign it); a legacy
        // raw row serializes its fields directly.
        for (id, entry) in &aux.agents {
            let body = match &entry.signed_body {
                Some(signed) => signed.clone(),
                None => serde_json::to_value(entry).map_err(AppError::from)?,
            };
            out.push((format!("agent/{}", id), body));
        }
        Ok(out)
    }

    /// Reconcile the item rows toward a freshly-decrypted [`VaultPlaintextView`]
    /// (the post-connect / post-write state), applying ONLY the changes with a
    /// monotonic version bump so the sync layer's per-item CAS sees a strictly
    /// higher version (contract §4/§6). Unlike [`seed_items_from_view`] (which
    /// resets every version to 1), this:
    ///   - upserts a `secret`/`connection`/`connecting`/`aux` item whose sealed
    ///     value changed, at `current + 1`;
    ///   - writes a `tombstone` (also bumped) for a `secret`/`connection`/
    ///     `connecting` item that the view no longer has (e.g. a completed
    ///     connect MOVEs its `connecting` entry away → tombstone the old row).
    ///
    /// This is the daemon-side, single-writer equivalent of "PUT the changed
    /// items" (contract §5 `writeVault` diff). Returns the ids that changed.
    pub fn reconcile_from_view<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
        view: &crate::storage::plaintext::VaultPlaintextView,
    ) -> Result<Vec<String>> {
        let mut changed: Vec<String> = Vec::new();

        // Build the desired (ns, name) → body set from the view.
        let mut desired: BTreeMap<(ItemNs, String), serde_json::Value> = BTreeMap::new();
        for (name, bytes) in &view.native_secrets {
            let value = String::from_utf8(bytes.clone())
                .map_err(|_| AppError::Internal(format!("secret '{}' not utf8", name)))?;
            desired.insert(
                (ItemNs::Secret, name.clone()),
                serde_json::Value::String(value),
            );
        }
        for (id, conn) in &view.aux.connections {
            desired.insert(
                (ItemNs::Connection, id.clone()),
                serde_json::to_value(conn).map_err(AppError::from)?,
            );
        }
        for (id, c) in &view.aux.connecting {
            desired.insert(
                (ItemNs::Connecting, id.clone()),
                serde_json::to_value(c).map_err(AppError::from)?,
            );
        }
        // aux subtrees (config + agents + members) at legacy `aux:<name>`.
        for (name, body) in Self::aux_blob_bodies(&view.aux)? {
            desired.insert((ItemNs::Aux, name.to_string()), body);
        }

        // Upsert every desired item whose sealed body differs from what we hold.
        for ((ns, name), body) in &desired {
            // `open_item` is unconverted (single-key); id_seed == content here so
            // the read is byte-identical either way.
            let existing = self.open_item::<S>(keys, vault_id, *ns, name)?;
            let same = existing
                .as_ref()
                .map(|p| !p.is_tombstone() && &p.body == body)
                .unwrap_or(false);
            if same {
                continue;
            }
            let payload = ItemPayload::live(*ns, name.clone(), body.clone());
            let (id, _v) = self.seal_and_bump::<S>(keys, vault_id, *ns, name, &payload)?;
            changed.push(id);
        }

        // Tombstone secret/connection/connecting rows the view dropped. Our own
        // folded view gives the currently-live (ns, name) set; tombstone any not
        // in `desired` (a completed connect MOVEs its `connecting` entry, so the
        // old connecting row must become a tombstone).
        let mine = self.fold_view::<S>(keys, vault_id)?;
        for name in mine.native_secrets.keys() {
            if !desired.contains_key(&(ItemNs::Secret, name.clone())) {
                let (id, _v) = self.seal_and_bump::<S>(
                    keys,
                    vault_id,
                    ItemNs::Secret,
                    name,
                    &ItemPayload::tombstone(ItemNs::Secret, name.clone()),
                )?;
                changed.push(id);
            }
        }
        for id in mine.aux.connections.keys() {
            if !desired.contains_key(&(ItemNs::Connection, id.clone())) {
                let (iid, _v) = self.seal_and_bump::<S>(
                    keys,
                    vault_id,
                    ItemNs::Connection,
                    id,
                    &ItemPayload::tombstone(ItemNs::Connection, id.clone()),
                )?;
                changed.push(iid);
            }
        }
        for id in mine.aux.connecting.keys() {
            if !desired.contains_key(&(ItemNs::Connecting, id.clone())) {
                let (iid, _v) = self.seal_and_bump::<S>(
                    keys,
                    vault_id,
                    ItemNs::Connecting,
                    id,
                    &ItemPayload::tombstone(ItemNs::Connecting, id.clone()),
                )?;
                changed.push(iid);
            }
        }
        // A dropped agent mask (offboarding sweep, or a member deleting their
        // own agent) → tombstone its per-item `aux:agent/<id>` row.
        for id in mine.aux.agents.keys() {
            let name = format!("agent/{}", id);
            if !desired.contains_key(&(ItemNs::Aux, name.clone())) {
                let (iid, _v) = self.seal_and_bump::<S>(
                    keys,
                    vault_id,
                    ItemNs::Aux,
                    &name,
                    &ItemPayload::tombstone(ItemNs::Aux, name.clone()),
                )?;
                changed.push(iid);
            }
        }
        Ok(changed)
    }

    /// Resolve the KEYSET's [`MembershipTrust`] — the owner-authority anchor state
    /// (design/identity-uik-aik.md §4.3 RESOLVED). This REPLACES the old in-vault
    /// `resolve_verified_membership`, which trusted a membership by single-version
    /// self-consistency and so let any member self-sign `{me: owner}` and
    /// self-promote (finding #1). Role is now rooted at genesis, and the return
    /// distinguishes the three trust states so a missing anchor can NEVER
    /// fail-open to integrity-only on a v2 keyset:
    ///
    /// - `keyset.uik == None` ⇒ [`MembershipTrust::NoUik`] (legacy v1 — integrity-only,
    ///   additive; pre-signing vaults are untouched).
    /// - `uik` present but `creator_sig_pub` is NOT a valid 32-byte key AND the
    ///   keyset already carries credentials ⇒ [`MembershipTrust::Untrusted`]. This is
    ///   the server-strippable state (`adopt_creator_pin` only pins non-empty), so
    ///   it FAILS CLOSED — callers drop ALL owner-config, not just unsigned.
    /// - `uik` present with a valid 32-byte `creator_pub` ⇒ [`MembershipTrust::Verified`]:
    ///   for each keyset cred, verify its `role_sig` over
    ///   [`crate::identity::role_grant_input`]`(vault_id, user_id, role, generation)`
    ///   under `creator_pub` at the CURRENT `uik.generation` (F3-b generation-
    ///   binding: the grant is bound to the owner-signed DP-S1 role epoch, so a
    ///   stale grant signed at an OLD generation fails here after a re-key bump and
    ///   the cred drops from the owner-set — a colluding server can't replay a
    ///   demoted/offboarded person's grant). A cred that verifies is inserted at its
    ///   `role`; one that fails (empty/forged sig, a role the creator never signed,
    ///   or a grant signed at a different generation) is dropped — it is NOT an
    ///   owner. The creator's OWN cred is included by the SAME rule
    ///   (its role=Owner, self-signed under `creator_pub`); no special case. An
    ///   empty owner-set is a valid `Verified` result (all signed owner-config
    ///   drops). A `uik` with no anchor AND no creds yet is a fresh bootstrap with
    ///   nothing to authorize — `Verified(∅)` (only legacy-raw config is additive).
    fn resolve_membership_trust(&self, vault_id: &str) -> MembershipTrust {
        let Some(uik) = self.keyset.uik.as_ref() else {
            return MembershipTrust::NoUik; // legacy v1 — integrity-only (additive)
        };
        // Resolve the CURRENT root by walking the succession chain from the pinned
        // GENESIS anchor. `None` = the genesis anchor is absent / not 32 bytes: a v2
        // keyset that already carries creds but has NO resolvable root is the
        // server-strippable state → FAIL CLOSED (`Untrusted`); an anchor-less keyset
        // with NO creds is a fresh bootstrap: nothing to authorize → empty Verified
        // set (legacy-raw stays additive, every signed item drops).
        if resolve_current_root(uik, vault_id).is_none() {
            return if uik.creds.is_empty() {
                MembershipTrust::Verified(BTreeMap::new())
            } else {
                MembershipTrust::Untrusted
            };
        }
        // Membership anti-rollback (C2): the current re-key proof committed the
        // delegation-log prefix — if the SERVED log doesn't match it, the server
        // rolled the membership back (e.g. omitted a `remove`); the owner-set can't be
        // trusted → FAIL CLOSED. (Owner-signed + generation-ratcheted, so the server
        // can't forge a fresh commitment or serve the current generation with a
        // tampered log.)
        if !membership_prefix_ok(uik, vault_id) {
            return MembershipTrust::Untrusted;
        }
        MembershipTrust::Verified(self.fold_owner_set(vault_id))
    }

    /// §15 leg-B: is `us_id` a VERIFIED member of this vault right now? Answers the
    /// "did the owner offboard me?" question SAFELY, so a caller can drop a lost vault:
    /// - `Some(true)`  = the owner-verified fold seats this id (owner or member).
    /// - `Some(false)` = the fold is TRUSTED (`Verified`) + non-empty and does NOT seat
    ///   this id → an owner-signed removal (or never-granted). The caller MAY drop.
    /// - `None`        = can't decide safely: legacy/`NoUik`, no resolvable root, or a
    ///   rolled-back/`Untrusted` log (a dropped-grant rollback fails `membership_prefix_ok`
    ///   → `Untrusted` here, so it can never masquerade as a removal). The caller PARKS.
    /// Trust comes from [`resolve_membership_trust`], which fails closed — so this never
    /// reports a false removal from a tampered or partial triple.
    pub(crate) fn verified_membership(&self, vault_id: &str, us_id: &str) -> Option<bool> {
        match self.resolve_membership_trust(vault_id) {
            MembershipTrust::Verified(map) if !map.is_empty() => Some(map.contains_key(us_id)),
            _ => None, // NoUik / Untrusted / empty bootstrap → park, never wipe
        }
    }

    /// Compute the current derived OWNER-SET (`user_id → role`) = the FOLD of the
    /// root-signed CHECKPOINT (each cred's `role_sig` @ the current `role_epoch`)
    /// followed by the append-only `delegation_log` (design/identity-uik-aik.md
    /// §4.3, delegation-log-impl-spec.md §0). The checkpoint is verified under the
    /// SUCCESSION-RESOLVED current root (not the raw genesis anchor); each log event
    /// is honored iff its `granter_id` is an Owner in the fold SO FAR (issuance-time
    /// authority) with a valid signature, and a `remove` drops ONLY its subject
    /// (NON-CASCADE). A last-owner removal/demote is ignored (defense in depth; also
    /// gated at write time). Returns an EMPTY map when there is no UIK layer or no
    /// resolvable root (no confirmable owner → callers fail closed).
    pub(crate) fn fold_owner_set(
        &self,
        vault_id: &str,
    ) -> BTreeMap<String, crate::storage::plaintext::MemberRole> {
        use crate::storage::plaintext::MemberRole;
        let mut map: BTreeMap<String, MemberRole> = BTreeMap::new();
        let Some(uik) = self.keyset.uik.as_ref() else {
            return map;
        };
        let Some((root_pub, role_epoch)) = resolve_current_root(uik, vault_id) else {
            return map; // no resolvable root → no confirmable owner
        };
        let root_id = crate::identity::derive_id(crate::identity::IdKind::User, &root_pub);
        // Genesis: the current root is an owner (TOFU-pinned anchor + succession).
        map.insert(root_id.clone(), MemberRole::Owner);
        // Checkpoint: root-signed grants @ the current (succession-derived) role_epoch
        // (depth-1 → a fresh daemon verifies with no history).
        for cred in uik.creds.values() {
            // The root's ownership is the genesis pin — a checkpoint grant must NEVER
            // overwrite/demote it (defense in depth for "the owner-set always contains
            // the root as Owner").
            if cred.user_id == root_id {
                continue;
            }
            // Self-certifying: the cred's `user_id` label MUST derive from its
            // `sig_pub`, so a spoofed `(user_id, sig_pub)` pair can't seat a phantom
            // owner keyed on a label the server chose.
            let Ok(cred_pub) = <[u8; 32]>::try_from(cred.sig_pub.as_slice()) else {
                continue;
            };
            if crate::identity::derive_id(crate::identity::IdKind::User, &cred_pub) != cred.user_id
            {
                continue;
            }
            let Ok(sig) = <[u8; 64]>::try_from(cred.role_sig.as_slice()) else {
                continue; // no / malformed grant → not in the checkpoint
            };
            let input = crate::identity::role_grant_input(
                vault_id,
                &cred.user_id,
                role_str(cred.role),
                role_epoch,
            );
            if crate::identity::verify(&root_pub, &input, &sig) {
                map.insert(cred.user_id.clone(), cred.role);
            }
        }
        // Delegation log: apply in a DETERMINISTIC total order; only events on the
        // current role_epoch (a pre-compaction replay carries an older epoch → ignored).
        let mut events: Vec<&DelegationEvent> = uik
            .delegation_log
            .iter()
            .filter(|e| e.role_epoch == role_epoch)
            .collect();
        // Sort by (seq, sig) — NOT seq alone: a stable sort by seq leaves same-seq
        // order at the mercy of storage/Vec order, which the server controls, so the
        // three implementations (daemon / backend / browser) could pick different
        // same-seq winners. Breaking the tie on the signature bytes makes the winner
        // deterministic and server-independent.
        events.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));
        let mut last_seq: Option<u64> = None;
        for e in events {
            if matches!(last_seq, Some(ls) if e.seq <= ls) {
                continue; // a seq already CONSUMED by a validated event
            }
            // Issuance-time authority: the granter must be an Owner in the fold SO FAR.
            // A junk / non-owner event must NOT consume the seq slot (else it could
            // suppress a legitimate same-seq event — the dup guard would then drop the
            // real one), so `last_seq` advances ONLY AFTER full validation below.
            if map.get(&e.granter_id) != Some(&MemberRole::Owner) {
                continue;
            }
            // The granter's verifying key rides INLINE and is SELF-CERTIFYING: it must
            // derive to `granter_id`. This makes the event immune to a poisoned cred row
            // (which lies about `sig_pub`) AND keeps it verifiable after the granter's
            // own cred row is deleted at offboard (so NON-CASCADE survives eviction).
            let Ok(granter_pub) = <[u8; 32]>::try_from(e.granter_sig_pub.as_slice()) else {
                continue;
            };
            if crate::identity::derive_id(crate::identity::IdKind::User, &granter_pub)
                != e.granter_id
            {
                continue;
            }
            let role_tok = if e.op == "remove" {
                ""
            } else {
                role_str(e.role)
            };
            let input = crate::identity::delegation_event_input(
                vault_id,
                &e.op,
                &e.subject_id,
                role_tok,
                &e.granter_id,
                e.seq,
                e.role_epoch,
            );
            let Ok(sig) = <[u8; 64]>::try_from(e.sig.as_slice()) else {
                continue;
            };
            if !crate::identity::verify(&granter_pub, &input, &sig) {
                continue;
            }
            // VALIDATED (owner + self-certifying key + signature): now consume the seq
            // slot, so a later same-seq event is a dup (equivocation) and is dropped.
            last_seq = Some(e.seq);
            // The creator (root) is seated at the base for ISSUANCE-TIME authority (so
            // grants they signed verify), but is a NORMAL owner in the FINAL set: any
            // owner (incl. the creator themselves) can be removed/demoted via the log
            // (creator-offboard is just a `remove`). The ONLY invariant is the
            // owner-set is never EMPTIED — a remove/demote that would drop the LAST
            // owner is ignored (last-owner guard; also enforced at write time in the
            // console). This replaces the old "root is permanently immune" rule.
            let owner_count = |m: &BTreeMap<String, MemberRole>| {
                m.values().filter(|r| **r == MemberRole::Owner).count()
            };
            match e.op.as_str() {
                "remove" => {
                    if map.get(&e.subject_id) == Some(&MemberRole::Owner) && owner_count(&map) <= 1
                    {
                        continue; // last-owner guard: never empty the owner-set
                    }
                    map.remove(&e.subject_id); // NON-CASCADE: only the subject
                }
                "set" => {
                    // A demote (owner → member) of the last owner would empty it → skip.
                    if e.role != MemberRole::Owner
                        && map.get(&e.subject_id) == Some(&MemberRole::Owner)
                        && owner_count(&map) <= 1
                    {
                        continue;
                    }
                    map.insert(e.subject_id.clone(), e.role);
                }
                _ => {} // unknown op → ignore
            }
        }
        map
    }

    /// Fold all **live** items into a [`VaultPlaintextView`] — the per-item
    /// equivalent of today's whole-blob decrypt (`metadata.rs`
    /// `decrypt_vault_view*`, priority 3). Unseals every stored record under
    /// `K`, drops tombstones, and rebuilds the in-memory view by grouping on
    /// `ns` (contract §2). The item id is an HMAC so `(ns, name)` is unknown
    /// from the key alone — the sealed payload carries them; we rebuild the
    /// `SealCtx` from the id bytes (decoded from the base64url row key) + the
    /// stored `version`, so a tampered `version` fails the AEAD.
    ///
    /// This is the LIVE per-item read path: `metadata.rs`'s
    /// `decrypt_vault_view_peritem*` helpers call it, and `open_view_for_grant`
    /// routes any vault with a `vault.per-item.json` through here. The whole-blob
    /// `ciphertext` open is now the FALLBACK for vaults not yet cut over
    /// (daemon-side Enroll/Write that only re-sealed `vault.dat`).
    pub fn fold_view<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
    ) -> Result<crate::storage::plaintext::VaultPlaintextView> {
        use crate::storage::plaintext::{VaultAux, VaultPlaintextView};
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        // Start from the fresh-vault defaults; config items OVERRIDE their
        // subtree, secret/connection/connecting/agent items fill their maps.
        //
        // Unified addressing (team §8.2): config singletons live at their own
        // ns with the empty name. Legacy `aux:<name>` items are still parsed
        // (read-compat for not-yet-migrated vaults) but NEW addresses win when
        // both spellings exist mid-migration — precedence is tracked with
        // `seen_new`, not item order (the id map iterates in hash order).
        let mut aux = VaultAux::initial();
        let mut native_secrets: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        #[derive(Default)]
        struct SeenNew {
            stores: bool,
            store_order: bool,
            policy: bool,
            retention: bool,
            services: bool,
        }
        let mut seen_new = SeenNew::default();
        // Legacy values parked until the loop ends (applied only where no new-
        // address item set the field).
        let mut legacy_stores: Option<serde_json::Value> = None;
        let mut legacy_store_order: Option<serde_json::Value> = None;
        let mut legacy_policy: Option<serde_json::Value> = None;
        let mut legacy_retention: Option<serde_json::Value> = None;
        let mut legacy_services: Option<serde_json::Value> = None;
        let mut legacy_addressing = false;

        // D: the verified OWNER-SET authorizes owner-config (owner-only). It is
        // now derived from the KEYSET (creator-rooted role grants), NOT from an
        // in-vault membership — that in-vault path (finding #1) is removed.
        // The three-state [`MembershipTrust`] keeps "legacy v1" (integrity-only,
        // additive) distinct from "v2 anchor stripped" (fail closed) so a missing
        // anchor on a v2 keyset can never fail-open to integrity-only.
        let trust = self.resolve_membership_trust(vault_id);

        // DP-S1: a re-keyed vault (generation > 0) is trusted only if the bump is
        // owner-signed and bound to THIS content key — else refuse to fold it (a
        // backend can't forge a re-key to force an unlock storm / swap content).
        if !verify_rekey_proof(&self.keyset, &trust, vault_id, keys.content) {
            return Err(AppError::Unauthorized(
                "vault re-key generation is unverified (missing/invalid owner signature)".into(),
            ));
        }

        for (id_b64, stored) in &self.items {
            // Fold each item independently: a single unreadable/unparseable item
            // (seal-parity mismatch, a body shape from a newer client, a rotated
            // K) must NOT hide EVERY other secret. Skip + log it; keep the rest.
            let one: crate::error::Result<()> = (|| {
                let raw_vec = URL_SAFE_NO_PAD
                    .decode(id_b64.as_bytes())
                    .map_err(|e| AppError::Internal(format!("item id base64url decode: {}", e)))?;
                let raw: [u8; 32] = raw_vec
                    .as_slice()
                    .try_into()
                    .map_err(|_| AppError::Internal("item id is not 32 bytes".into()))?;
                let ctx = ItemCtx::new(vault_id, raw, stored.version);
                let payload = unseal_item::<S>(keys.content, &ctx, &stored.ct)?;
                if payload.is_tombstone() {
                    return Ok(());
                }
                let name = payload.name;
                match payload.ns {
                    ItemNs::Secret => {
                        let s = payload.body.as_str().ok_or_else(|| {
                            AppError::Internal(format!(
                                "secret item '{}' body is not a string",
                                name
                            ))
                        })?;
                        native_secrets.insert(name, s.as_bytes().to_vec());
                    }
                    ItemNs::Connection => {
                        let conn = serde_json::from_value(payload.body).map_err(|e| {
                            AppError::Internal(format!("connection '{}' parse: {}", name, e))
                        })?;
                        aux.connections.insert(name, conn);
                    }
                    ItemNs::Connecting => {
                        let c = serde_json::from_value(payload.body).map_err(|e| {
                            AppError::Internal(format!("connecting '{}' parse: {}", name, e))
                        })?;
                        aux.connecting.insert(name, c);
                    }
                    ItemNs::Agent => {
                        let raw_body = payload.body.clone();
                        let cfg = format!("agent/{}", name);
                        let Some((data, was_signed)) = fold_agent_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            &self.keyset,
                            vault_id,
                            &raw,
                            &cfg,
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, agent = %name, "fold: dropping agent grant — unauthorized/invalid signature");
                            return Ok(());
                        };
                        let mut entry: crate::storage::plaintext::AgentEntry =
                            serde_json::from_value(data).map_err(|e| {
                                AppError::Internal(format!("agent '{}' parse: {}", name, e))
                            })?;
                        entry.signed_body = was_signed.then_some(raw_body);
                        aux.agents.insert(name, entry);
                    }
                    ItemNs::Policy => {
                        let Some(data) = fold_owner_config_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            &self.keyset,
                            vault_id,
                            &raw,
                            "policy",
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, "fold: dropping policy — unauthorized/invalid owner signature");
                            return Ok(());
                        };
                        aux.policy = Some(
                            serde_json::from_value(data)
                                .map_err(|e| AppError::Internal(format!("policy parse: {}", e)))?,
                        );
                        seen_new.policy = true;
                    }
                    ItemNs::Stores => {
                        let Some(data) = fold_owner_config_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            &self.keyset,
                            vault_id,
                            &raw,
                            "stores",
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, "fold: dropping stores — unauthorized/invalid owner signature");
                            return Ok(());
                        };
                        aux.stores = serde_json::from_value(data)
                            .map_err(|e| AppError::Internal(format!("stores parse: {}", e)))?;
                        seen_new.stores = true;
                    }
                    ItemNs::StoreOrder => {
                        let Some(data) = fold_owner_config_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            &self.keyset,
                            vault_id,
                            &raw,
                            "store_order",
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, "fold: dropping store_order — unauthorized/invalid owner signature");
                            return Ok(());
                        };
                        aux.store_order = serde_json::from_value(data)
                            .map_err(|e| AppError::Internal(format!("store_order parse: {}", e)))?;
                        seen_new.store_order = true;
                    }
                    ItemNs::AuditRetentionDays => {
                        let Some(data) = fold_owner_config_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            &self.keyset,
                            vault_id,
                            &raw,
                            "audit_retention_days",
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, "fold: dropping audit_retention_days — unauthorized/invalid owner signature");
                            return Ok(());
                        };
                        aux.audit_retention_days = serde_json::from_value(data).map_err(|e| {
                            AppError::Internal(format!("audit_retention_days parse: {}", e))
                        })?;
                        seen_new.retention = true;
                    }
                    ItemNs::Services => {
                        let Some(data) = fold_owner_config_record(
                            stored.sig.as_deref(),
                            stored.signer.as_deref(),
                            &stored.ct,
                            &self.keyset,
                            vault_id,
                            &raw,
                            "services",
                            stored.version,
                            payload.body,
                            &trust,
                        ) else {
                            tracing::warn!(vault = %vault_id, "fold: dropping services — unauthorized/invalid owner signature");
                            return Ok(());
                        };
                        aux.services = serde_json::from_value(data)
                            .map_err(|e| AppError::Internal(format!("services parse: {}", e)))?;
                        seen_new.services = true;
                    }
                    ItemNs::Members => {
                        // The in-vault membership is RETIRED (finding #1):
                        // role now rides the keyset cred (owner-authority anchor,
                        // §4.3), derived by `resolve_membership_trust`. Any
                        // legacy `members:` item is ignored — never trusted for
                        // roles, never folded back into the view.
                    }
                    ItemNs::Aux => {
                        // Config singletons ride `aux:<name>` blobs (parked +
                        // applied after the loop if no unified-ns item set the
                        // field — the cosmetic `aux:` drop is deferred). AGENTS
                        // are per-item `aux:agent/<id>` — one mask each,
                        // independent CAS (team §8.1).
                        legacy_addressing = true;
                        // C.3: owner-config carries a UIK signature (or is legacy
                        // raw). Verify+unwrap here; a bad signature parks `None`
                        // (→ safe default). `config_name` is addressing-independent.
                        // A legacy `aux:members` blob is ignored (membership retired).
                        match name.as_str() {
                            "stores" => {
                                legacy_stores = fold_owner_config_record(
                                    stored.sig.as_deref(),
                                    stored.signer.as_deref(),
                                    &stored.ct,
                                    &self.keyset,
                                    vault_id,
                                    &raw,
                                    "stores",
                                    stored.version,
                                    payload.body,
                                    &trust,
                                )
                            }
                            "store_order" => {
                                legacy_store_order = fold_owner_config_record(
                                    stored.sig.as_deref(),
                                    stored.signer.as_deref(),
                                    &stored.ct,
                                    &self.keyset,
                                    vault_id,
                                    &raw,
                                    "store_order",
                                    stored.version,
                                    payload.body,
                                    &trust,
                                )
                            }
                            "policy" => {
                                legacy_policy = fold_owner_config_record(
                                    stored.sig.as_deref(),
                                    stored.signer.as_deref(),
                                    &stored.ct,
                                    &self.keyset,
                                    vault_id,
                                    &raw,
                                    "policy",
                                    stored.version,
                                    payload.body,
                                    &trust,
                                )
                            }
                            "audit_retention_days" => {
                                legacy_retention = fold_owner_config_record(
                                    stored.sig.as_deref(),
                                    stored.signer.as_deref(),
                                    &stored.ct,
                                    &self.keyset,
                                    vault_id,
                                    &raw,
                                    "audit_retention_days",
                                    stored.version,
                                    payload.body,
                                    &trust,
                                )
                            }
                            "services" => {
                                legacy_services = fold_owner_config_record(
                                    stored.sig.as_deref(),
                                    stored.signer.as_deref(),
                                    &stored.ct,
                                    &self.keyset,
                                    vault_id,
                                    &raw,
                                    "services",
                                    stored.version,
                                    payload.body,
                                    &trust,
                                )
                            }
                            n => {
                                if let Some(agent_id) = n.strip_prefix("agent/") {
                                    // §11.1 authorized-agents table row — sidecar
                                    // item-sig (A1.2) preferred, in-body config-sig
                                    // fallback. Verify + authorize; a bad /
                                    // unauthorized row drops (that ag_id is simply
                                    // not in the table). The verified signed body is
                                    // retained for lossless re-emit.
                                    let raw_body = payload.body.clone();
                                    let Some((data, was_signed)) = fold_agent_record(
                                        stored.sig.as_deref(),
                                        stored.signer.as_deref(),
                                        &stored.ct,
                                        &self.keyset,
                                        vault_id,
                                        &raw,
                                        n,
                                        stored.version,
                                        payload.body,
                                        &trust,
                                    ) else {
                                        tracing::warn!(vault = %vault_id, agent = %agent_id, "fold: dropping agent grant — unauthorized/invalid signature");
                                        return Ok(());
                                    };
                                    let mut entry: crate::storage::plaintext::AgentEntry =
                                        serde_json::from_value(data).map_err(|e| {
                                            AppError::Internal(format!(
                                                "agent '{}' parse: {}",
                                                agent_id, e
                                            ))
                                        })?;
                                    entry.signed_body = was_signed.then_some(raw_body);
                                    // Per-item row is authoritative for its id;
                                    // it overrides anything a legacy blob carried.
                                    aux.agents.insert(agent_id.to_string(), entry);
                                }
                                // other unknown aux names: ignored (forward-compat).
                            }
                        }
                    }
                }
                Ok(())
            })();
            if let Err(e) = one {
                tracing::warn!(item = %id_b64, "fold: skipping unreadable item: {}", e);
            }
        }

        // Apply parked legacy values where no new-address item set the field.
        if !seen_new.stores {
            if let Some(v) = legacy_stores {
                aux.stores = serde_json::from_value(v)
                    .map_err(|e| AppError::Internal(format!("aux.stores parse: {}", e)))?;
            }
        }
        if !seen_new.store_order {
            if let Some(v) = legacy_store_order {
                aux.store_order = serde_json::from_value(v)
                    .map_err(|e| AppError::Internal(format!("aux.store_order parse: {}", e)))?;
            }
        }
        if !seen_new.policy {
            if let Some(v) = legacy_policy {
                aux.policy = Some(
                    serde_json::from_value(v)
                        .map_err(|e| AppError::Internal(format!("aux.policy parse: {}", e)))?,
                );
            }
        }
        if !seen_new.retention {
            if let Some(v) = legacy_retention {
                aux.audit_retention_days = serde_json::from_value(v).map_err(|e| {
                    AppError::Internal(format!("aux.audit_retention_days parse: {}", e))
                })?;
            }
        }
        if !seen_new.services {
            if let Some(v) = legacy_services {
                aux.services = serde_json::from_value(v)
                    .map_err(|e| AppError::Internal(format!("aux.services parse: {}", e)))?;
            }
        }
        // No `members` legacy blob to merge: the in-vault membership is retired
        // (finding #1); role lives on the keyset cred (owner-authority anchor).

        Ok(VaultPlaintextView {
            aux,
            native_secrets,
            legacy_addressing,
        })
    }

    /// One-shot migration to the unified addressing (team §8.3 "升级即切换").
    /// If the vault still holds live legacy `aux:*` items: fold, re-write every
    /// config singleton at its new address, and tombstone the legacy rows —
    /// all version-bumped so sync pushes them as normal item changes. Idempotent
    /// (second call folds to `legacy_addressing == false` and does nothing).
    /// Returns the changed item ids (empty = already migrated). The caller is
    /// responsible for (a) writing a plaintext snapshot BEFORE calling this and
    /// (b) marking the vault `format=2` server-side AFTER the push succeeds.
    pub fn migrate_addressing<S: PrimitiveSuite>(
        &mut self,
        keys: VaultKeys,
        vault_id: &str,
    ) -> Result<Vec<String>> {
        let view = self.fold_view::<S>(keys, vault_id)?;
        if !view.legacy_addressing {
            return Ok(Vec::new());
        }
        // Reconcile writes every config singleton at its NEW address (the
        // mapping lives in `singleton_bodies`, shared with seed).
        let mut changed = self.reconcile_from_view::<S>(keys, vault_id, &view)?;
        // Tombstone every live legacy aux row (known + unknown names alike —
        // the namespace is retired wholesale).
        let legacy: Vec<String> = self
            .live_names_in_ns::<S>(keys, vault_id, ItemNs::Aux)?
            .into_iter()
            .collect();
        for name in legacy {
            let (id, _v) = self.seal_and_bump::<S>(
                keys,
                vault_id,
                ItemNs::Aux,
                &name,
                &ItemPayload::tombstone(ItemNs::Aux, name.clone()),
            )?;
            changed.push(id);
        }
        Ok(changed)
    }

    /// Names of live (non-tombstone) items in one namespace. Unreadable items
    /// are skipped with a warning (same fault isolation as the fold).
    fn live_names_in_ns<S: PrimitiveSuite>(
        &self,
        keys: VaultKeys,
        vault_id: &str,
        want: ItemNs,
    ) -> Result<Vec<String>> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let mut out = Vec::new();
        for (id_b64, stored) in &self.items {
            let one: crate::error::Result<()> = (|| {
                let raw_vec = URL_SAFE_NO_PAD
                    .decode(id_b64.as_bytes())
                    .map_err(|e| AppError::Internal(format!("item id decode: {}", e)))?;
                let raw: [u8; 32] = raw_vec
                    .as_slice()
                    .try_into()
                    .map_err(|_| AppError::Internal("item id is not 32 bytes".into()))?;
                let ctx = ItemCtx::new(vault_id, raw, stored.version);
                let payload = unseal_item::<S>(keys.content, &ctx, &stored.ct)?;
                if payload.ns == want && !payload.is_tombstone() {
                    out.push(payload.name);
                }
                Ok(())
            })();
            if let Err(e) = one {
                tracing::warn!(item = %id_b64, "live_names_in_ns: skipping unreadable item: {}", e);
            }
        }
        Ok(out)
    }
}

/// Read the per-item vault file. `None` if it doesn't exist. (New per-item
/// format; NOT interchangeable with [`read`]'s whole-blob `SealedState`.)
pub fn read_per_item(path: &Path) -> Result<Option<PerItemVault>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let v: PerItemVault = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Internal(format!("per-item vault parse: {}", e)))?;
    Ok(Some(v))
}

/// Atomically write the per-item vault file (same F-18 random-suffix temp +
/// rename discipline as [`write_atomic`]).
pub fn write_per_item_atomic(path: &Path, vault: &PerItemVault) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(vault)?;
    let tmp = path.with_extension(format!("dat.tmp.{:08x}", rand::random::<u32>()));
    if let Err(e) = std::fs::write(&tmp, &bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test fixture encodes credential_id with base64url-no-pad to match
    // `decode_credential_id`'s wire format (the WebAuthn convention).
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    use tempfile::tempdir;

    #[test]
    fn vault_write_read_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let v = build_initial(
            b"cred-bytes".to_vec(),
            "x_b64".into(),
            "y_b64".into(),
            "Test Device".into(),
            vec![0u8; 32],
            vec![0u8; 48],
            vec![0u8; 64],
        )
        .unwrap();
        write_atomic(&path, &v).unwrap();
        let loaded = read(&path).unwrap().unwrap();
        assert_eq!(loaded.version, CURRENT_VERSION);
        assert_eq!(loaded.credentials.len(), 1);
        assert_eq!(loaded.credentials[0].credential_id, b"cred-bytes");
        let pk = find_pubkey(&v, &URL_SAFE_NO_PAD.encode(b"cred-bytes")).unwrap();
        assert_eq!(pk.x, "x_b64");
        assert_eq!(pk.device_name, "Test Device");
    }

    #[test]
    fn decode_keys_data_field_accepts_std_and_url() {
        // The lenient decoder mirrors the frontend's `fromBase64`: accept both
        // STANDARD base64 (frontend `toBase64` for x/y/prf_salt/wrapped_key) and
        // base64url (x25519_pub), padded or not. All four spellings of the same
        // bytes must decode identically.
        let raw: Vec<u8> = vec![
            0xFB, 0xFF, 0xBF, 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8B,
        ];
        let std_pad = STANDARD.encode(&raw); // has +, /, and = padding
        assert!(std_pad.contains('+') || std_pad.contains('/'));
        let std_nopad = std_pad.trim_end_matches('=').to_string();
        let url_pad = std_pad.replace('+', "-").replace('/', "_");
        let url_nopad = url_pad.trim_end_matches('=').to_string();
        for s in [&std_pad, &std_nopad, &url_pad, &url_nopad] {
            assert_eq!(decode_keys_data_field(s).unwrap(), raw, "decode {}", s);
        }
    }

    #[test]
    fn per_item_vault_seal_write_read_open_roundtrip() {
        use sudp::primitives::StdPrimitives;
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.per-item.json");
        let k = [0x42u8; 32];
        let vid = "vault-xyz";

        let mut pv = PerItemVault::build_initial(
            b"cred-bytes".to_vec(),
            "x_b64".into(),
            "y_b64".into(),
            "Test Device".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // Seal a secret item into the store, then a tombstone for another.
        let id = pv
            .seal_and_upsert::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Secret,
                "GMAIL_REFRESH_TOKEN",
                1,
                &ItemPayload::secret_live("GMAIL_REFRESH_TOKEN", "ya29.value"),
            )
            .unwrap();
        // The stored key is exactly the contract's base64url item id.
        assert_eq!(
            id,
            item_id::<StdPrimitives>(&k, "secret", "GMAIL_REFRESH_TOKEN").unwrap()
        );
        assert_eq!(pv.get_item(&id).unwrap().version, 1);

        // Persist and reload → the sealed ct survives the base64url JSON codec.
        write_per_item_atomic(&path, &pv).unwrap();
        let loaded = read_per_item(&path).unwrap().unwrap();
        assert_eq!(loaded.keyset.credentials.len(), 1);
        assert_eq!(loaded.items.len(), 1);

        // Open it back through K — the fold the metadata layer will do per row.
        let payload = loaded
            .open_item::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Secret,
                "GMAIL_REFRESH_TOKEN",
            )
            .unwrap()
            .unwrap();
        assert_eq!(payload.body, serde_json::Value::String("ya29.value".into()));
        assert!(!payload.is_tombstone());

        // A wrong vault id must NOT open (AAD binds the vault).
        assert!(loaded
            .open_item::<StdPrimitives>(
                VaultKeys::single(&k),
                "other-vault",
                ItemNs::Secret,
                "GMAIL_REFRESH_TOKEN"
            )
            .is_err());

        // Absent item → Ok(None), not an error.
        assert!(loaded
            .open_item::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Secret, "NOPE")
            .unwrap()
            .is_none());
    }

    #[test]
    fn synced_version_tracks_dirty_vs_clean() {
        use sudp::primitives::StdPrimitives;
        let k = [0x21u8; 32];
        let vid = "vault-dirty";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // A fresh local write is DIRTY (never confirmed on cloud).
        let id = pv
            .seal_and_upsert::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Secret,
                "T",
                1,
                &ItemPayload::secret_live("T", "v1"),
            )
            .unwrap();
        assert_eq!(
            pv.get_item(&id).unwrap().synced_version,
            0,
            "local write starts dirty"
        );

        // Pull/adopt lands CLEAN — the cloud has this exact version by construction.
        let ct = pv.get_item(&id).unwrap().ct.clone();
        pv.put_raw(id.clone(), 1, ct);
        assert_eq!(
            pv.get_item(&id).unwrap().synced_version,
            1,
            "adopted row is clean"
        );

        // A subsequent local bump goes dirty again, KEEPING the confirmed floor.
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Secret,
            "T",
            2,
            &ItemPayload::secret_live("T", "v2"),
        )
        .unwrap();
        let s = pv.get_item(&id).unwrap();
        assert_eq!(
            (s.version, s.synced_version),
            (2, 1),
            "bumped row is dirty above its synced floor"
        );
    }

    #[test]
    fn tombstone_flag_tracks_payload_status() {
        use sudp::primitives::StdPrimitives;
        let k = [0x33u8; 32];
        let vid = "vault-tomb";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // A live write is NOT a tombstone; a deleting write IS one — so the push
        // loop can order writes before deletes.
        let live = pv
            .seal_and_bump::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Connection,
                "gcp",
                &ItemPayload::live(
                    ItemNs::Connection,
                    "gcp",
                    serde_json::json!({"service": "gcp"}),
                ),
            )
            .unwrap()
            .0;
        assert!(
            !pv.get_item(&live).unwrap().tombstone,
            "live row is not a tombstone"
        );

        let dead = pv
            .seal_and_bump::<StdPrimitives>(
                VaultKeys::single(&k),
                vid,
                ItemNs::Connecting,
                "gcp",
                &ItemPayload::tombstone(ItemNs::Connecting, "gcp"),
            )
            .unwrap()
            .0;
        assert!(
            pv.get_item(&dead).unwrap().tombstone,
            "deleting row is a tombstone"
        );

        // Survives the JSON codec (serde-defaulted, so an old store loads false).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.per-item.json");
        write_per_item_atomic(&path, &pv).unwrap();
        let loaded = read_per_item(&path).unwrap().unwrap();
        assert!(!loaded.get_item(&live).unwrap().tombstone);
        assert!(loaded.get_item(&dead).unwrap().tombstone);
    }

    #[test]
    fn agent_mask_serde_all_and_blocked() {
        use crate::storage::plaintext::{AgentEntry, AgentMask};
        // Untagged serde distinguishes the two variants purely by JSON shape:
        // string "all" → All, object { "deny": [...] } → Blocked.

        // Default / "all" round-trips as the bare string; allows everything.
        let all: AgentEntry = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(all.connections.allows("anything"));
        assert!(matches!(all.connections, AgentMask::All(_)), "default = All");
        assert_eq!(
            serde_json::to_value(&AgentEntry::default()).unwrap(),
            serde_json::json!({ "connections": "all" })
        );

        // Blacklist: an object `{ "deny": [...] }` → Blocked; allows everything
        // EXCEPT the denied ids (fail-open — later/unknown ids stay reachable).
        let blk: AgentEntry =
            serde_json::from_value(serde_json::json!({ "connections": { "deny": ["stripe-live"] } }))
                .unwrap();
        assert!(matches!(blk.connections, AgentMask::Blocked { .. }), "object → Blocked");
        assert!(!blk.connections.allows("stripe-live"), "denied conn refused");
        assert!(blk.connections.allows("github-work"), "non-listed conn allowed");
        assert!(
            blk.connections.allows("added-later-conn"),
            "unknown/new conn allowed (fail-open)"
        );
        let back = serde_json::to_value(&blk).unwrap();
        assert_eq!(back, serde_json::json!({ "connections": { "deny": ["stripe-live"] } }));

        // Direct allows() matrix, independent of AgentEntry wrapping.
        assert!(AgentMask::default().allows("x"), "default = All");
        assert!(AgentMask::Blocked { deny: vec!["a".into()] }.allows("b"));
        assert!(!AgentMask::Blocked { deny: vec!["a".into()] }.allows("a"));
        assert!(
            AgentMask::Blocked { deny: vec![] }.allows("anything"),
            "empty deny = allow all"
        );
    }

    // T1 addressing: config singletons ride single `aux:<name>` blobs
    // (console-compatible; the cosmetic `aux:` drop is the deferred cutover).
    // AGENTS are PER-ITEM `aux:agent/<id>` — one item each, so two members
    // editing their own agents never clobber (independent CAS). This asserts the
    // seed → fold round-trip, per-item agent addressing, and that a dropped agent
    // tombstones only its own row. (The in-vault `members` membership is retired —
    // finding #1 — so it is no longer part of the fold round-trip.)
    #[test]
    fn t1_agents_are_per_item_config_and_members_are_blobs() {
        use crate::storage::plaintext::{AgentEntry, AgentMask, VaultAux};
        use sudp::primitives::StdPrimitives;
        let k = [0x55u8; 32];
        let vid = "vault-t1";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // Seed from a view with policy + TWO agents.
        let mut aux = VaultAux::initial();
        aux.policy = Some(serde_json::from_value(serde_json::json!({ "timeout": 222 })).unwrap());
        aux.agents.insert(
            "ag_alice".into(),
            AgentEntry {
                connections: AgentMask::Blocked {
                    deny: vec!["stripe".into()],
                },
                ..Default::default()
            },
        ); // blacklist
        aux.agents.insert("ag_bob".into(), AgentEntry::default()); // "all"
        let view = crate::storage::plaintext::VaultPlaintextView {
            aux,
            native_secrets: std::collections::BTreeMap::new(),
            legacy_addressing: false,
        };
        pv.seed_items_from_view::<StdPrimitives>(VaultKeys::single(&k), vid, &view)
            .unwrap();

        let folded = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vid)
            .unwrap();
        assert_eq!(folded.aux.policy.as_ref().unwrap().timeout, Some(222));
        // Blacklist survives the seed → fold round-trip: denied conn refused,
        // everything else (incl. ids never listed) allowed (fail-open).
        assert!(matches!(
            folded.aux.agents["ag_alice"].connections,
            AgentMask::Blocked { .. }
        ));
        assert!(
            !folded.aux.agents["ag_alice"].connections.allows("stripe"),
            "blacklist denies"
        );
        assert!(
            folded.aux.agents["ag_alice"].connections.allows("gmail"),
            "blacklist allows non-denied"
        );
        assert!(
            folded.aux.agents["ag_alice"]
                .connections
                .allows("added-later-conn"),
            "blacklist allows unknown/new (fail-open)"
        );
        assert!(
            folded.aux.agents["ag_bob"].connections.allows("anything"),
            "all"
        );

        // Per-item: each agent is its OWN `aux:agent/<id>` item (independent
        // CAS), NOT a shared blob and NOT a new-ns row.
        let aux_names = pv
            .live_names_in_ns::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Aux)
            .unwrap();
        assert!(aux_names.contains(&"agent/ag_alice".to_string()));
        assert!(aux_names.contains(&"agent/ag_bob".to_string()));
        assert!(
            !aux_names.contains(&"agents".to_string()),
            "no shared agents blob"
        );
        assert!(
            pv.live_names_in_ns::<StdPrimitives>(VaultKeys::single(&k), vid, ItemNs::Agent)
                .unwrap()
                .is_empty(),
            "T1 keeps agents under aux:, not the deferred agent: ns"
        );

        // Drop ag_bob (offboard/delete) — reconcile tombstones ONLY its row;
        // ag_alice's item is untouched (the anti-clobber property).
        let mut view2 = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vid)
            .unwrap();
        view2.aux.agents.remove("ag_bob");
        pv.reconcile_from_view::<StdPrimitives>(VaultKeys::single(&k), vid, &view2)
            .unwrap();
        let after = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vid)
            .unwrap();
        assert!(
            after.aux.agents.contains_key("ag_alice"),
            "other agent survives"
        );
        assert!(
            !after.aux.agents.contains_key("ag_bob"),
            "dropped agent tombstoned"
        );
    }

    #[test]
    fn fold_view_rebuilds_secrets_connections_and_aux() {
        use sudp::primitives::StdPrimitives;
        let k = [0x42u8; 32];
        let vid = "vault-fold";
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // A live secret, a tombstoned secret (must be dropped), a connection,
        // and an aux store_order override.
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Secret,
            "OPENAI_KEY",
            1,
            &ItemPayload::secret_live("OPENAI_KEY", "sk-live"),
        )
        .unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Secret,
            "GONE",
            2,
            &ItemPayload::tombstone(ItemNs::Secret, "GONE"),
        )
        .unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Connection,
            "gmail",
            1,
            &ItemPayload::live(
                ItemNs::Connection,
                "gmail",
                serde_json::json!({ "service": "gmail" }),
            ),
        )
        .unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            VaultKeys::single(&k),
            vid,
            ItemNs::Aux,
            "store_order",
            1,
            &ItemPayload::live(
                ItemNs::Aux,
                "store_order",
                serde_json::json!(["native-secrets", "gcp-1"]),
            ),
        )
        .unwrap();

        let view = pv
            .fold_view::<StdPrimitives>(VaultKeys::single(&k), vid)
            .unwrap();
        assert_eq!(
            view.resolve_value_native("OPENAI_KEY"),
            Some(&b"sk-live"[..])
        );
        assert_eq!(
            view.native_secrets.get("GONE"),
            None,
            "tombstone must be dropped"
        );
        assert_eq!(
            view.aux
                .connections
                .get("gmail")
                .and_then(|c| c.service.as_deref()),
            Some("gmail")
        );
        assert_eq!(view.aux.store_order, vec!["native-secrets", "gcp-1"]);
        assert_eq!(view.aux.version, 4);
    }

    #[test]
    fn v1_keyset_has_no_uik_layer() {
        // A classic keyset built by `build_initial` is v1: `uik` is `None`, so
        // `is_uik()` is false and `wrapped_key` is the plain `Wrap(K)`.
        let pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        assert!(!pv.is_uik());
        assert!(pv.keyset.uik.is_none());
    }

    #[test]
    fn v2_keyset_store_unlock_roundtrip() {
        // Build a v2 (`custody → UIK → K`) keyset through the storage accessors,
        // persist it (serde round-trip), then reproduce the browser's unlock:
        // custody-unwrap the UIK root from `wrapped_key`, derive the member's
        // `user_id`, look up its K-seal, and open `K`. This is the storage-layer
        // proof that the v2 fields survive disk and compose back into `K`.
        use crate::crypto::vault_key::{seal_k_to_uik, unwrap_uik_root, wrap_uik_root, UikRoot};

        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.per-item.json");
        let vid = "vault-v2";

        // Owner mints (here: fixed) a UIK root; custody `W_c` from the passkey PRF.
        let root = [0x33u8; 32];
        let uik = UikRoot::from_root(root);
        let w_c = [0x55u8; 32];
        let cid: Vec<u8> = b"cred-v2".to_vec();

        // v2 keyset: `wrapped_key` = Wrap_{W_c}(UIK root), NOT Wrap(K).
        let wrapped_root = wrap_uik_root(&w_c, &cid, &root).unwrap();
        let mut pv = PerItemVault::build_initial(
            cid.clone(),
            "x".into(),
            "y".into(),
            "Owner Device".into(),
            vec![0u8; 32],
            wrapped_root,
        )
        .unwrap();

        // K sealed to the owner's UIK enc pubkey → this credential's seal.
        let k = [0x9au8; 32];
        let enc_pub = uik.encryption_public().unwrap();
        let (encapped, ct) = seal_k_to_uik(&enc_pub, vid, &k).unwrap();
        let cid_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cid);
        let sig_pub = uik.signing().public_bytes().to_vec();
        pv.set_uik_cred(
            cid_b64.clone(),
            uik.user_id(),
            sig_pub.clone(),
            enc_pub.clone(),
            encapped,
            ct,
            crate::storage::plaintext::MemberRole::Owner,
            Vec::new(),
        );
        assert!(pv.is_uik(), "seal promotes the keyset to v2");

        write_per_item_atomic(&path, &pv).unwrap();
        let loaded = read_per_item(&path).unwrap().unwrap();
        assert!(loaded.is_uik());

        // Unlock (browser's role): recover the root from custody, then open K
        // from the acting credential's own seal.
        let recovered_root =
            unwrap_uik_root(&w_c, &cid, &loaded.keyset.credentials[0].wrapped_key).unwrap();
        let ruik = UikRoot::from_root(*recovered_root);
        assert_eq!(ruik.user_id(), uik.user_id());
        let entry = loaded
            .uik_cred(&cid_b64)
            .expect("acting credential carries its own seal");
        assert_eq!(entry.user_id, uik.user_id());
        assert_eq!(entry.sig_pub, sig_pub, "signing pubkey survives disk");
        let opened = ruik.open_k(vid, &entry.k_encapped, &entry.k_ct).unwrap();
        assert_eq!(&opened[..], &k[..]);

        // An unknown credential has no seal; offboarding drops the member's rows.
        assert!(loaded.uik_cred("unknown-cid").is_none());
        let mut pv2 = loaded;
        assert_eq!(pv2.remove_uik_member(&uik.user_id()), 1);
        assert!(pv2.uik_cred(&cid_b64).is_none());
    }

    #[test]
    fn config_signature_verify_accept_reject() {
        // C.3: owner-config integrity. A valid UIK signature from a PUBLISHED
        // member key is honored; a tampered version/name, a forged signer, or a
        // malformed wrapper is dropped; an unsigned (legacy) body passes through.
        use crate::crypto::vault_key::UikRoot;
        use base64::engine::general_purpose::STANDARD;

        let vault = "vault-cfg";
        let uik = UikRoot::from_root([0x33u8; 32]);
        let sign_pub = uik.signing().public_bytes();

        // Keyset that KNOWS this member's sig_pub (the C.1 anchor).
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        pv.set_uik_cred(
            "cid1".into(),
            uik.user_id(),
            sign_pub.to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            crate::storage::plaintext::MemberRole::Member,
            Vec::new(),
        );

        let data = serde_json::json!({ "timeout": 30, "default": { "read": "ask" } });
        let version = 7u64;
        let canonical = crate::crypto::canonical::canonicalize(&data);
        let signer_id = crate::identity::derive_id(crate::identity::IdKind::User, &sign_pub);
        let input = crate::identity::config_sig_input(
            vault,
            "policy",
            version,
            Some(&canonical),
            &signer_id,
        );
        let sig = uik.signing().sign(&input);
        let signed = |d: &serde_json::Value, s: &[u8; 64], pk: &[u8; 32]| {
            serde_json::json!({
                "data": d,
                "uik_sig": STANDARD.encode(s),
                "uik_sign_pub": STANDARD.encode(pk),
            })
        };
        let wrapper = signed(&data, &sig, &sign_pub);

        // --- C (integrity-only, MembershipTrust::NoUik = legacy v1) ---
        // Valid → honored (returns inner data).
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::NoUik
            ),
            Some(data.clone()),
        );
        // Wrong version → sig no longer matches → DROP.
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version + 1,
                &MembershipTrust::NoUik
            ),
            None,
        );
        // Wrong config name → DROP.
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "stores",
                version,
                &MembershipTrust::NoUik
            ),
            None,
        );
        // Unsigned (legacy raw) → honored unchanged (additive).
        assert_eq!(
            unwrap_verified_config(
                data.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::NoUik
            ),
            Some(data.clone()),
        );
        // Malformed wrapper (uik_sig present but not base64) → DROP (fail-closed).
        let bad = serde_json::json!({ "data": data, "uik_sig": "!!!", "uik_sign_pub": "!!!" });
        assert_eq!(
            unwrap_verified_config(
                bad,
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::NoUik
            ),
            None
        );
        // Forged: a real signature from a key NOT in the keyset → DROP.
        let stranger = UikRoot::from_root([0x44u8; 32]);
        let s_pub = stranger.signing().public_bytes();
        let s_id = crate::identity::derive_id(crate::identity::IdKind::User, &s_pub);
        let s_input =
            crate::identity::config_sig_input(vault, "policy", version, Some(&canonical), &s_id);
        let s_sig = stranger.signing().sign(&s_input);
        assert_eq!(
            unwrap_verified_config(
                signed(&data, &s_sig, &s_pub),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::NoUik
            ),
            None,
        );

        // --- D (role authorization, MembershipTrust::Verified owner-set) ---
        use crate::storage::plaintext::MemberRole;
        let uid = uik.user_id();
        // Signer is an OWNER in the owner-set → honored.
        let owner_set: std::collections::BTreeMap<String, MemberRole> =
            [(uid.clone(), MemberRole::Owner)].into_iter().collect();
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Verified(owner_set)
            ),
            Some(data.clone()),
        );
        // Signer is only a MEMBER (not owner) → DROP (can't rewrite owner config).
        let member_set: std::collections::BTreeMap<String, MemberRole> =
            [(uid.clone(), MemberRole::Member)].into_iter().collect();
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Verified(member_set)
            ),
            None,
        );
        // Signer absent from the owner-set entirely → DROP.
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Verified(std::collections::BTreeMap::new())
            ),
            None,
        );

        // --- E (MembershipTrust::Untrusted = v2 anchor stripped) fails CLOSED ---
        // Even a VALID owner-signed wrapper is dropped when the keyset carries no
        // valid creator anchor (a colluding server could have stripped it), and so
        // is legacy-raw config — everything falls to safe defaults.
        assert_eq!(
            unwrap_verified_config(
                wrapper.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Untrusted
            ),
            None,
            "Untrusted drops even a valid owner signature",
        );
        assert_eq!(
            unwrap_verified_config(
                data.clone(),
                &pv.keyset,
                vault,
                "policy",
                version,
                &MembershipTrust::Untrusted
            ),
            None,
            "Untrusted drops legacy-raw config too (no integrity-only downgrade)",
        );
    }

    #[test]
    fn dps1_content_rotation_preserves_ids_and_forward_secrecy() {
        // DP-S1 (team-shared-vault-security-model.md §3.2): a re-key rotates the
        // CONTENT key while the ID-SEED stays fixed. Item ids therefore survive
        // the re-key (sync sees content updates, not delete-all+add-all), and a
        // departed member holding only the OLD content key cannot open the
        // re-sealed bodies (forward secrecy).
        use crate::storage::item::{vault_key_bundle, VaultKeys};
        use sudp::primitives::StdPrimitives;

        let vid = "vault-rekey";
        let seed = [0x11u8; 32]; // stable id-seed (never rotates)
        let c_old = [0x22u8; 32]; // pre-re-key content key (a departed member's)
        let c_new = [0x33u8; 32]; // post-re-key content key

        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();

        // Seal a secret at the stable id-seed, under the NEW content key (the
        // post-re-key state).
        let vk_new = VaultKeys {
            id_seed: &seed,
            content: &c_new,
        };
        pv.seal_and_upsert::<StdPrimitives>(
            vk_new,
            vid,
            ItemNs::Secret,
            "TOKEN",
            1,
            &ItemPayload::secret_live("TOKEN", "sk-new"),
        )
        .unwrap();

        // The row lands at the id-seed-derived id — INDEPENDENT of the content
        // key (so a re-key that changes only content leaves the id fixed).
        let id_from_seed =
            item_id::<StdPrimitives>(&seed, ItemNs::Secret.as_str(), "TOKEN").unwrap();
        assert!(
            pv.items.contains_key(&id_from_seed),
            "id derives from id-seed"
        );

        // A current member (new content key) reads it.
        let got = pv
            .open_item::<StdPrimitives>(vk_new, vid, ItemNs::Secret, "TOKEN")
            .unwrap()
            .unwrap();
        assert_eq!(got.body, serde_json::Value::String("sk-new".into()));

        // A departed member with the OLD content key: SAME id-seed → the id
        // resolves (row found), but the old content key CANNOT unseal the body
        // sealed under the new content key → forward secrecy.
        let vk_old = VaultKeys {
            id_seed: &seed,
            content: &c_old,
        };
        assert!(
            pv.open_item::<StdPrimitives>(vk_old, vid, ItemNs::Secret, "TOKEN")
                .is_err(),
            "old content key must not open a re-sealed body"
        );

        // The 64-byte bundle `id_seed ‖ content` splits back via `from_material`
        // (the daemon's acquire → fold path).
        let bundle = vault_key_bundle(&seed, &c_new);
        let vk = VaultKeys::from_material(&bundle);
        assert_eq!(vk.id_seed, &seed[..]);
        assert_eq!(vk.content, &c_new[..]);
        let got2 = pv
            .open_item::<StdPrimitives>(vk, vid, ItemNs::Secret, "TOKEN")
            .unwrap()
            .unwrap();
        assert_eq!(got2.body, serde_json::Value::String("sk-new".into()));
    }

    #[test]
    fn rekey_proof_verify_accept_reject() {
        // E.3d: a re-keyed keyset (generation > 0) is trusted only with a valid
        // owner-signed proof bound to the actual content key.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;

        let vault = "vault-rk";
        let owner = UikRoot::from_root([0x55u8; 32]);
        let owner_sig_pub = owner.signing().public_bytes().to_vec();
        let owner_id = owner.user_id();
        let content = [0xABu8; 32];
        let gen = 1u64;
        let commit = rekey_commitment(&content).to_vec();
        // Empty delegation log at re-key → membership commitment over 0 events.
        let membership = crate::identity::membership_commitment(&[]).to_vec();
        let input = crate::identity::rekey_sig_input(vault, gen, &commit, &owner_id, 0, &membership);
        let sig = owner.signing().sign(&input).to_vec();

        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        pv.set_uik_cred(
            "cid1".into(),
            owner_id.clone(),
            owner_sig_pub.clone(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            Vec::new(),
        );
        {
            let uik = pv.keyset.uik.as_mut().unwrap();
            uik.generation = gen;
            uik.rekey_proof = Some(RekeyProof {
                generation: gen,
                k_commitment: commit.clone(),
                sig: sig.clone(),
                signer_id: owner_id.clone(),
                membership_len: 0,
                membership_hash: membership.clone(),
            });
        }
        let owner_trust = MembershipTrust::Verified(
            [(owner_id.clone(), MemberRole::Owner)]
                .into_iter()
                .collect(),
        );

        // Valid owner-signed proof, correct content → accept.
        assert!(verify_rekey_proof(
            &pv.keyset,
            &owner_trust,
            vault,
            &content
        ));
        // Wrong content key → commitment mismatch → reject (anti content-swap).
        assert!(!verify_rekey_proof(
            &pv.keyset,
            &owner_trust,
            vault,
            &[0x00u8; 32]
        ));
        // Signer is only a member (not owner) → reject.
        let member_trust = MembershipTrust::Verified(
            [(owner_id.clone(), MemberRole::Member)]
                .into_iter()
                .collect(),
        );
        assert!(!verify_rekey_proof(
            &pv.keyset,
            &member_trust,
            vault,
            &content
        ));
        // Untrusted (v2 anchor stripped) → can't confirm owner → reject.
        assert!(!verify_rekey_proof(
            &pv.keyset,
            &MembershipTrust::Untrusted,
            vault,
            &content
        ));
        // generation mismatch (proof says 1, keyset says 2) → reject.
        pv.keyset.uik.as_mut().unwrap().generation = 2;
        assert!(!verify_rekey_proof(
            &pv.keyset,
            &owner_trust,
            vault,
            &content
        ));
        pv.keyset.uik.as_mut().unwrap().generation = gen;
        // Missing proof on a re-keyed keyset → reject (forged bump).
        pv.keyset.uik.as_mut().unwrap().rekey_proof = None;
        assert!(!verify_rekey_proof(
            &pv.keyset,
            &owner_trust,
            vault,
            &content
        ));
        // gen 0 (never re-keyed) → trivially accepted.
        pv.keyset.uik.as_mut().unwrap().generation = 0;
        assert!(verify_rekey_proof(
            &pv.keyset,
            &owner_trust,
            vault,
            &content
        ));
    }

    /// Shared setup for the role-on-keyset fixtures: a v2 keyset pinned to a
    /// creator, a creator cred (Owner, self-signed) and a member cred. Returns the
    /// vault, keyset holder, both roots, and their ids.
    #[cfg(test)]
    fn role_fixture_creator_cred() -> (
        &'static str,
        crate::crypto::vault_key::UikRoot,
        crate::crypto::vault_key::UikRoot,
        String,
        String,
        PerItemVault,
    ) {
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let vault = "vault-role";
        let creator = UikRoot::from_root([0x11u8; 32]);
        let member = UikRoot::from_root([0x22u8; 32]);
        let creator_id = creator.user_id();
        let member_id = member.user_id();
        let mut pv = PerItemVault::build_initial(
            b"c".to_vec(),
            "x".into(),
            "y".into(),
            "Dev".into(),
            vec![0u8; 32],
            vec![0u8; 48],
        )
        .unwrap();
        // Creator cred: role=Owner, self-signed under the creator key (the root),
        // at the keyset's generation (0 for this gen-0 fixture — F3-b).
        let creator_grant = creator.signing().sign(&crate::identity::role_grant_input(
            vault,
            &creator_id,
            "owner",
            0,
        ));
        pv.set_uik_cred(
            "cid-creator".into(),
            creator_id.clone(),
            creator.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            creator_grant.to_vec(),
        );
        // Pin the root anchor = the creator's signing pubkey.
        pv.keyset.uik.as_mut().unwrap().creator_sig_pub = creator.signing().public_bytes().to_vec();
        (vault, creator, member, creator_id, member_id, pv)
    }

    #[test]
    fn role_on_keyset_owner_config_accept_reject() {
        // Owner-authority (design/identity-uik-aik.md §4.3): role is a
        // CREATOR-signed attribute on the keyset cred. The owner-set is derived
        // from the keyset (each cred's role_sig verified against the pinned creator
        // pubkey); config signed by an owner is honored, config signed by a mere
        // member is dropped.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::STANDARD;

        let (vault, creator, member, creator_id, member_id, mut pv) = role_fixture_creator_cred();

        // A member cred: role=Member, CREATOR-signed at the keyset generation (0).
        let member_grant = creator.signing().sign(&crate::identity::role_grant_input(
            vault, &member_id, "member", 0,
        ));
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Member,
            member_grant.to_vec(),
        );

        // Owner-set from the keyset: Verified {creator→Owner, member→Member}.
        let MembershipTrust::Verified(owner_set) = pv.resolve_membership_trust(vault) else {
            panic!("pinned creator ⇒ MembershipTrust::Verified");
        };
        assert_eq!(owner_set.get(&creator_id), Some(&MemberRole::Owner));
        assert_eq!(owner_set.get(&member_id), Some(&MemberRole::Member));
        let trust = MembershipTrust::Verified(owner_set);

        // Config signed by an owner (creator) honored; by a member dropped.
        let data = serde_json::json!({ "timeout": 30 });
        let version = 4u64;
        let canonical = crate::crypto::canonical::canonicalize(&data);
        let signed = |signer: &UikRoot| -> serde_json::Value {
            let sid = signer.user_id();
            let input =
                crate::identity::config_sig_input(vault, "policy", version, Some(&canonical), &sid);
            let sig = signer.signing().sign(&input);
            serde_json::json!({
                "data": data,
                "uik_sig": STANDARD.encode(sig),
                "uik_sign_pub": STANDARD.encode(signer.signing().public_bytes()),
            })
        };
        assert_eq!(
            unwrap_verified_config(
                signed(&creator),
                &pv.keyset,
                vault,
                "policy",
                version,
                &trust
            ),
            Some(data.clone()),
            "owner-signed config honored",
        );
        assert_eq!(
            unwrap_verified_config(
                signed(&member),
                &pv.keyset,
                vault,
                "policy",
                version,
                &trust
            ),
            None,
            "member-signed owner-config dropped (not an owner)",
        );
    }

    #[test]
    fn agent_grant_authz_self_owner_and_forged() {
        // §11.1 authorized-agents table authorization: a row is honored iff its
        // signer is the row's declared `owner` (a member admitting their OWN
        // agent) OR any owner (override). A member admitting SOMEONE ELSE'S agent,
        // an unknown signer, or a bad signature all drop; legacy raw (unsigned) is
        // honored additively.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::STANDARD;

        let (vault, creator, member, creator_id, member_id, mut pv) = role_fixture_creator_cred();
        // Add a member cred (role=Member, creator-signed at gen 0).
        let member_grant = creator.signing().sign(&crate::identity::role_grant_input(
            vault, &member_id, "member", 0,
        ));
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Member,
            member_grant.to_vec(),
        );
        let MembershipTrust::Verified(owner_set) = pv.resolve_membership_trust(vault) else {
            panic!("pinned creator ⇒ Verified");
        };
        let trust = MembershipTrust::Verified(owner_set);
        let outsider = UikRoot::from_root([0x99u8; 32]); // never published to the keyset

        let cfg = "agent/ag_testagent";
        let version = 3u64;
        let grant_body = |owner_id: &str| -> serde_json::Value {
            serde_json::json!({ "agent_pubkey": "cGs", "owner": owner_id, "connections": "all" })
        };
        let sign = |signer: &UikRoot, data: &serde_json::Value| -> serde_json::Value {
            let sid = signer.user_id();
            let canonical = crate::crypto::canonical::canonicalize(data);
            let input =
                crate::identity::config_sig_input(vault, cfg, version, Some(&canonical), &sid);
            let sig = signer.signing().sign(&input);
            serde_json::json!({
                "data": data,
                "uik_sig": STANDARD.encode(sig),
                "uik_sign_pub": STANDARD.encode(signer.signing().public_bytes()),
            })
        };

        // self-service: member admits their OWN agent → honored, signed.
        let own = grant_body(&member_id);
        assert_eq!(
            unwrap_verified_agent_grant(sign(&member, &own), &pv.keyset, vault, cfg, version, &trust),
            Some((own.clone(), true)),
            "member admits own agent",
        );
        // owner override: creator admits the member's agent → honored, signed.
        assert_eq!(
            unwrap_verified_agent_grant(
                sign(&creator, &own),
                &pv.keyset,
                vault,
                cfg,
                version,
                &trust
            ),
            Some((own.clone(), true)),
            "any owner may admit any agent",
        );
        // forged: member admits an agent it declares OWNED BY the creator (neither
        // self nor an owner) → drop.
        let other = grant_body(&creator_id);
        assert_eq!(
            unwrap_verified_agent_grant(
                sign(&member, &other),
                &pv.keyset,
                vault,
                cfg,
                version,
                &trust
            ),
            None,
            "member cannot admit an agent owned by someone else",
        );
        // unknown signer (outsider, not a keyset cred) → drop.
        assert_eq!(
            unwrap_verified_agent_grant(
                sign(&outsider, &own),
                &pv.keyset,
                vault,
                cfg,
                version,
                &trust
            ),
            None,
            "outsider signature dropped",
        );
        // legacy raw (unsigned) → honored additively, unsigned.
        assert_eq!(
            unwrap_verified_agent_grant(own.clone(), &pv.keyset, vault, cfg, version, &trust),
            Some((own.clone(), false)),
            "legacy raw honored, was_signed=false",
        );
    }

    #[test]
    fn verify_record_sidecar_sig_accept_and_reject() {
        // A1.2 sidecar verify: a keyset member signs record_signature_input over the
        // record's ciphertext; the daemon re-verifies from the wire sig+signer.
        use crate::crypto::vault_key::UikRoot;
        use base64::engine::general_purpose::STANDARD;
        let (vault, creator, _member, creator_id, _member_id, pv) = role_fixture_creator_cred();
        let outsider = UikRoot::from_root([0x77u8; 32]); // not a keyset cred
        let ct = b"pretend-sealed-ciphertext-bytes";
        let id_raw = [0x09u8; 32];
        let sign = |signer: &UikRoot, ty: &str, body: &[u8]| -> String {
            let input = crate::identity::record_signature_input(
                ty, &id_raw, 4, vault, body, true, &signer.user_id());
            STANDARD.encode(signer.signing().sign(&input))
        };
        // Valid: creator (a keyset member) signs "policy" over ct → signer id back.
        let good = sign(&creator, "policy", ct);
        assert_eq!(
            verify_record_sidecar_sig(ct, &pv.keyset, vault, &id_raw, "policy", 4, true, &good, &creator_id),
            Some(creator_id.clone()),
        );
        // Tampered type: signed "policy", verified as "secret" → reject.
        assert_eq!(
            verify_record_sidecar_sig(ct, &pv.keyset, vault, &id_raw, "secret", 4, true, &good, &creator_id),
            None, "record_type is bound",
        );
        // Tampered ct: signature was over `ct`, verify over a different body → reject.
        assert_eq!(
            verify_record_sidecar_sig(b"other-ct", &pv.keyset, vault, &id_raw, "policy", 4, true, &good, &creator_id),
            None, "ciphertext is bound",
        );
        // Outsider (not a keyset cred) → reject even with a valid self-signature.
        let bad = sign(&outsider, "policy", ct);
        assert_eq!(
            verify_record_sidecar_sig(ct, &pv.keyset, vault, &id_raw, "policy", 4, true, &bad, &outsider.user_id()),
            None, "non-member signer rejected",
        );
    }

    #[test]
    fn role_self_promote_blocked() {
        // THE finding-#1 regression test. A member's cred claims role=Owner with a
        // role_sig it signed ITSELF (not the creator). Under the creator-rooted
        // owner-set, that grant fails verification against the pinned creator
        // pubkey — the member is NOT an owner and its owner-config is dropped. This
        // FAILS under the old single-version self-consistent membership (which trusted
        // `{me: owner}` self-signed) and PASSES under owner-authority.
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::STANDARD;

        let (vault, _creator, member, creator_id, member_id, mut pv) = role_fixture_creator_cred();

        // ATTACK: the member cred claims role=Owner, role_sig = the MEMBER
        // self-signing the owner grant (NOT creator-signed).
        let self_grant = member.signing().sign(&crate::identity::role_grant_input(
            vault, &member_id, "owner", 0,
        ));
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            self_grant.to_vec(),
        );

        // The self-promoting member is NOT in the owner-set (grant fails under the
        // pinned creator pubkey); the creator still is.
        let MembershipTrust::Verified(owner_set) = pv.resolve_membership_trust(vault) else {
            panic!("pinned creator ⇒ MembershipTrust::Verified");
        };
        assert_eq!(
            owner_set.get(&creator_id),
            Some(&MemberRole::Owner),
            "creator remains owner"
        );
        assert!(
            !owner_set.contains_key(&member_id),
            "self-signed owner grant rejected (finding #1)"
        );
        let trust = MembershipTrust::Verified(owner_set);

        // A config item signed by the self-promoting member is DROPPED.
        let data = serde_json::json!({ "timeout": 99 });
        let version = 2u64;
        let canonical = crate::crypto::canonical::canonicalize(&data);
        let sid = member.user_id();
        let input =
            crate::identity::config_sig_input(vault, "policy", version, Some(&canonical), &sid);
        let sig = member.signing().sign(&input);
        let wrapper = serde_json::json!({
            "data": data,
            "uik_sig": STANDARD.encode(sig),
            "uik_sign_pub": STANDARD.encode(member.signing().public_bytes()),
        });
        assert_eq!(
            unwrap_verified_config(wrapper, &pv.keyset, vault, "policy", version, &trust),
            None,
            "self-promoted member cannot rewrite owner config",
        );
    }

    #[test]
    fn untrusted_v2_no_anchor_drops_member_config() {
        // HIGH-severity fail-open regression: a v2 keyset (UIK layer present, ≥1
        // cred) whose `creator_sig_pub` a colluding server STRIPPED must FAIL
        // CLOSED — `resolve_membership_trust` returns `Untrusted`, and even a VALID
        // member-signed owner-config item is dropped (never downgraded to
        // integrity-only, which is what honored it before this fix).
        use crate::storage::plaintext::MemberRole;
        use base64::engine::general_purpose::STANDARD;

        let (vault, _creator, member, _creator_id, member_id, mut pv) = role_fixture_creator_cred();

        // A member cred is present (so the keyset is a real v2 keyset with creds).
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Member,
            Vec::new(),
        );
        // ATTACK: the server stripped the genesis anchor from every /keys row, so
        // it was never pinned — `creator_sig_pub` is empty.
        pv.keyset.uik.as_mut().unwrap().creator_sig_pub = Vec::new();

        // v2 keyset with creds but no anchor ⇒ Untrusted (fail closed). We thread
        // the trust RESOLVED from the keyset (not a hardcoded state) so this test
        // exercises the exact vulnerable path: pre-fix, `resolve_*` returned the
        // `None` membership and `unwrap_verified_config` honored the member config.
        let trust = pv.resolve_membership_trust(vault);
        assert!(
            matches!(&trust, MembershipTrust::Untrusted),
            "stripped anchor on a v2 keyset with creds ⇒ Untrusted",
        );

        // A member signs owner-config with a VALID signature (member IS a keyset
        // cred, so the integrity/known check passes) — under the old code this fell
        // through the empty-membership branch and was HONORED. It MUST now be dropped.
        let data = serde_json::json!({ "timeout": 1 });
        let version = 3u64;
        let canonical = crate::crypto::canonical::canonicalize(&data);
        let sid = member.user_id();
        let input =
            crate::identity::config_sig_input(vault, "policy", version, Some(&canonical), &sid);
        let sig = member.signing().sign(&input);
        let wrapper = serde_json::json!({
            "data": data,
            "uik_sig": STANDARD.encode(sig),
            "uik_sign_pub": STANDARD.encode(member.signing().public_bytes()),
        });
        assert_eq!(
            unwrap_verified_config(wrapper, &pv.keyset, vault, "policy", version, &trust),
            None,
            "no-anchor v2: member-signed owner-config dropped (fail closed)",
        );
    }

    #[test]
    fn role_grant_role_epoch_bound() {
        // Two-counter model (delegation-log-impl-spec.md §0): a root-signed
        // checkpoint grant binds `role_epoch` (the role-checkpoint epoch), ORTHOGONAL
        // to `generation` (the K-rotation epoch). Proven here on a NON-ROOT member
        // (the creator is always an owner via the genesis pin, so demotion-by-replay
        // is only meaningful for a granted member):
        //   (1) a `generation` (K-eviction) bump ALONE leaves the owner-set intact —
        //       role authority is decoupled from content-key rotation;
        //   (2) a `role_epoch` bump (compaction) WITHOUT a re-signed grant DROPS the
        //       stale checkpoint grant — a colluding server replaying a demoted/
        //       removed person's pre-compaction grant cannot keep them in;
        //   (3) re-signing at the new `role_epoch` (what compaction does for a
        //       survivor) restores them.
        use crate::storage::plaintext::MemberRole;

        let (vault, creator, member, creator_id, member_id, mut pv) = role_fixture_creator_cred();

        // Grant the MEMBER an OWNER role at role_epoch 0 (creator/root-signed).
        let grant0 = creator.signing().sign(&crate::identity::role_grant_input(
            vault, &member_id, "owner", 0,
        ));
        pv.set_uik_cred(
            "cid-member".into(),
            member_id.clone(),
            member.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            grant0.to_vec(),
        );

        let owners = |pv: &PerItemVault| match pv.resolve_membership_trust(vault) {
            MembershipTrust::Verified(m) => m,
            _ => panic!("pinned creator ⇒ MembershipTrust::Verified"),
        };

        // Baseline: both the root creator and the granted member are owners @epoch 0.
        let os = owners(&pv);
        assert_eq!(os.get(&creator_id), Some(&MemberRole::Owner));
        assert_eq!(
            os.get(&member_id),
            Some(&MemberRole::Owner),
            "member granted owner @role_epoch 0 is an owner",
        );

        // (1) A K-rotation bumps `generation` but NOT `role_epoch`: owner-set intact.
        pv.keyset.uik.as_mut().unwrap().generation = 5;
        let os = owners(&pv);
        assert_eq!(
            os.get(&member_id),
            Some(&MemberRole::Owner),
            "a generation (K-eviction) bump alone leaves the owner-set intact (⊥)",
        );

        // (2) A compaction (root-signed SELF-succession to epoch 1) advances the
        // derived `role_epoch` WITHOUT re-signing the member's grant — the exact
        // stale-grant replay a colluding server attempts. The member's grant drops;
        // the root creator stays (genesis pin, not a checkpoint grant).
        push_compaction(&mut pv, vault, &creator, 1);
        let os = owners(&pv);
        assert!(
            !os.contains_key(&member_id),
            "stale grant (signed @role_epoch 0) is DROPPED @role_epoch 1 — replay defeated",
        );
        assert_eq!(
            os.get(&creator_id),
            Some(&MemberRole::Owner),
            "the root creator is an owner by the genesis pin, immune to grant replay",
        );

        // (3) Re-sign the member's grant @role_epoch 1 (what compaction does for a
        // survivor) → restored.
        let grant1 = creator.signing().sign(&crate::identity::role_grant_input(
            vault, &member_id, "owner", 1,
        ));
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .creds
            .get_mut("cid-member")
            .expect("fixture member cred")
            .role_sig = grant1.to_vec();
        assert_eq!(
            owners(&pv).get(&member_id),
            Some(&MemberRole::Owner),
            "re-signing the grant @role_epoch 1 restores the owner",
        );
    }

    /// Append a signed delegation event to the keyset log (test helper).
    fn push_event(
        pv: &mut PerItemVault,
        vault: &str,
        signer: &crate::crypto::vault_key::UikRoot,
        op: &str,
        subject_id: &str,
        role: crate::storage::plaintext::MemberRole,
        seq: u64,
        role_epoch: u64,
    ) {
        let granter_id = signer.user_id();
        let granter_sig_pub = signer.signing().public_bytes().to_vec();
        let role_tok = if op == "remove" { "" } else { role_str(role) };
        let sig = signer
            .signing()
            .sign(&crate::identity::delegation_event_input(
                vault,
                op,
                subject_id,
                role_tok,
                &granter_id,
                seq,
                role_epoch,
            ));
        pv.keyset
            .uik
            .as_mut()
            .expect("v2 keyset")
            .delegation_log
            .push(DelegationEvent {
                op: op.into(),
                subject_id: subject_id.into(),
                role,
                granter_id,
                granter_sig_pub,
                seq,
                role_epoch,
                sig: sig.to_vec(),
            });
    }

    /// Push a root-signed SELF-succession (a pure COMPACTION): advances the derived
    /// `role_epoch` to `epoch` without changing the root. `root` must be the CURRENT
    /// root. This is how a compaction is expressed — the role-checkpoint epoch is
    /// derived from the root-signed succession chain, never a forgeable scalar.
    fn push_compaction(
        pv: &mut PerItemVault,
        vault: &str,
        root: &crate::crypto::vault_key::UikRoot,
        epoch: u64,
    ) {
        let root_id = root.user_id();
        let root_pub = root.signing().public_bytes();
        let sig = root.signing().sign(&crate::identity::root_succession_input(
            vault, &root_id, &root_id, &root_pub, epoch,
        ));
        pv.keyset
            .uik
            .as_mut()
            .expect("v2 keyset")
            .root_succession
            .push(RootSuccession {
                old_root_id: root_id.clone(),
                new_root_id: root_id,
                new_root_sig_pub: root_pub.to_vec(),
                role_epoch: epoch,
                sig: sig.to_vec(),
            });
    }

    /// Give a principal a keyset cred with sig_pub published but NO checkpoint grant
    /// (empty role_sig) — so its authority can come ONLY from delegation events.
    fn cred_no_grant(
        pv: &mut PerItemVault,
        cid: &str,
        who: &crate::crypto::vault_key::UikRoot,
        id: &str,
    ) {
        use crate::storage::plaintext::MemberRole;
        pv.set_uik_cred(
            cid.into(),
            id.into(),
            who.signing().public_bytes().to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Member,
            Vec::new(),
        );
    }

    fn owner_set(
        pv: &PerItemVault,
        vault: &str,
    ) -> BTreeMap<String, crate::storage::plaintext::MemberRole> {
        match pv.resolve_membership_trust(vault) {
            MembershipTrust::Verified(m) => m,
            other => panic!(
                "expected Verified, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn delegation_event_grant_and_non_cascade() {
        // The core of the full delegation model (design/identity-uik-aik.md §4.3):
        //   - ANY owner (not just the root) can grant via a signed event (SPKI
        //     delegation bit): the root adds A, then A adds B.
        //   - Removing A is NON-CASCADE: B (whom A added) stays an owner, because the
        //     fact "A WAS an owner when A signed" survives A's later removal.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, _creator_id, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let b = UikRoot::from_root([0x44u8; 32]);
        let (a_id, b_id) = (a.user_id(), b.user_id());
        cred_no_grant(&mut pv, "cid-a", &a, &a_id);
        cred_no_grant(&mut pv, "cid-b", &b, &b_id);

        // A/B have no checkpoint grant → not owners yet.
        assert!(!owner_set(&pv, vault).contains_key(&a_id));

        // seq 1: root sets A → owner.
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &a_id,
            MemberRole::Owner,
            1,
            0,
        );
        assert_eq!(
            owner_set(&pv, vault).get(&a_id),
            Some(&MemberRole::Owner),
            "root grants A via event",
        );
        // seq 2: A (a NON-root owner) sets B → owner (egalitarian delegation).
        push_event(&mut pv, vault, &a, "set", &b_id, MemberRole::Owner, 2, 0);
        assert_eq!(
            owner_set(&pv, vault).get(&b_id),
            Some(&MemberRole::Owner),
            "a non-root owner can grant (delegation bit)",
        );
        // seq 3: root removes A → A dropped, B STAYS (non-cascade).
        push_event(
            &mut pv,
            vault,
            &creator,
            "remove",
            &a_id,
            MemberRole::Member,
            3,
            0,
        );
        let os = owner_set(&pv, vault);
        assert!(!os.contains_key(&a_id), "A removed");
        assert_eq!(
            os.get(&b_id),
            Some(&MemberRole::Owner),
            "NON-CASCADE: removing A does not drop B (whom A added)",
        );
    }

    #[test]
    fn delegation_event_by_non_owner_rejected() {
        // A member (not an owner) signs `set self owner` — the fold ignores it
        // (granter is not an owner-so-far), so self-promotion via the log is blocked.
        use crate::storage::plaintext::MemberRole;
        let (vault, _creator, member, _cid, member_id, mut pv) = role_fixture_creator_cred();
        cred_no_grant(&mut pv, "cid-member", &member, &member_id);
        push_event(
            &mut pv,
            vault,
            &member,
            "set",
            &member_id,
            MemberRole::Owner,
            1,
            0,
        );
        assert!(
            !owner_set(&pv, vault).contains_key(&member_id),
            "a non-owner's delegation event is ignored (no self-promote via the log)",
        );
    }

    #[test]
    fn delegation_log_dup_seq_replay_rejected() {
        // Two events sharing a `seq` (a reorder/replay attempt): only the first (by
        // sort order) applies; the second is dropped by the monotone-seq guard.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, _cid, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let b = UikRoot::from_root([0x44u8; 32]);
        let (a_id, b_id) = (a.user_id(), b.user_id());
        cred_no_grant(&mut pv, "cid-a", &a, &a_id);
        cred_no_grant(&mut pv, "cid-b", &b, &b_id);
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &a_id,
            MemberRole::Owner,
            1,
            0,
        );
        // Second event REUSES seq 1 → rejected.
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &b_id,
            MemberRole::Owner,
            1,
            0,
        );
        let os = owner_set(&pv, vault);
        // The deterministic (seq, sig) tiebreak keeps EXACTLY ONE seq-1 event; for
        // these fixed keys A's grant signature sorts first, so A applies and B is
        // dropped (the winner is server-independent — same on every implementation).
        assert_eq!(
            os.get(&a_id),
            Some(&MemberRole::Owner),
            "the (seq,sig)-first seq-1 event applies"
        );
        assert!(
            !os.contains_key(&b_id),
            "a duplicate seq is dropped (replay / equivocation guard)"
        );
    }

    #[test]
    fn junk_same_seq_event_does_not_suppress_legit() {
        // Re-audit C1 fix: `last_seq` advances ONLY after an event passes the owner +
        // signature checks, so a well-formed-but-INVALID event that shares a legit
        // event's `seq` (and sorts first — sig = all-zeros) cannot consume the slot and
        // make the dup guard drop the real one. Without the fix a colluding server (no
        // key) could void a `remove` this way and resurrect a removed owner.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, _cid, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let a_id = a.user_id();
        cred_no_grant(&mut pv, "cid-a", &a, &a_id);
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &a_id,
            MemberRole::Owner,
            1,
            0,
        );
        assert_eq!(
            owner_set(&pv, vault).get(&a_id),
            Some(&MemberRole::Owner),
            "A granted @seq1",
        );
        // Junk @seq2: valid owner granter + self-certifying pubkey, but a ZERO signature
        // (sorts FIRST among seq-2 events). It must fail the sig check WITHOUT consuming
        // seq 2.
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .delegation_log
            .push(DelegationEvent {
                op: "set".into(),
                subject_id: "us_ghost".into(),
                role: MemberRole::Owner,
                granter_id: creator.user_id(),
                granter_sig_pub: creator.signing().public_bytes().to_vec(),
                seq: 2,
                role_epoch: 0,
                sig: vec![0u8; 64],
            });
        // The root's REAL `remove A` also at seq 2.
        push_event(
            &mut pv,
            vault,
            &creator,
            "remove",
            &a_id,
            MemberRole::Member,
            2,
            0,
        );
        let os = owner_set(&pv, vault);
        assert!(
            !os.contains_key(&a_id),
            "the junk seq-2 event did NOT suppress the real remove — A is removed",
        );
        assert!(
            !os.contains_key("us_ghost"),
            "the junk event itself never applied",
        );
    }

    #[test]
    fn event_verifies_via_inline_key_without_cred_row() {
        // Re-audit X2 fix (NON-CASCADE survives offboard): a delegation event carries
        // the granter's signing pubkey INLINE (self-certifying), so it stays verifiable
        // even when the granter has NO cred row in the keyset (their row was deleted at
        // offboard). Here A is an owner ONLY via a log event (no cred at all), and A's
        // grant of B still verifies — so removing A (deleting A's row) would not drop B.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, _cid, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let b = UikRoot::from_root([0x44u8; 32]);
        let (a_id, b_id) = (a.user_id(), b.user_id());
        cred_no_grant(&mut pv, "cid-b", &b, &b_id); // B has a cred; A has NONE
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &a_id,
            MemberRole::Owner,
            1,
            0,
        );
        push_event(&mut pv, vault, &a, "set", &b_id, MemberRole::Owner, 2, 0);
        let os = owner_set(&pv, vault);
        assert_eq!(
            os.get(&a_id),
            Some(&MemberRole::Owner),
            "A is an owner via the log with no cred row",
        );
        assert_eq!(
            os.get(&b_id),
            Some(&MemberRole::Owner),
            "A's grant of B verifies via A's INLINE key — non-cascade survives A having no cred row",
        );
    }

    #[test]
    fn root_succession_transfers_root_and_offboards_creator() {
        // A root transfer (creator offboard): the current root signs a succession to
        // a NEW root, which re-cuts the checkpoint @role_epoch 1. Afterwards the new
        // root is the owner authority and the old creator (not re-granted) is gone.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, creator_id, _mid, mut pv) = role_fixture_creator_cred();
        let newroot = UikRoot::from_root([0x55u8; 32]);
        let newroot_id = newroot.user_id();
        let nr_pub = newroot.signing().public_bytes();
        // Current (genesis) root signs the succession → newroot @role_epoch 1.
        let succ_sig = creator
            .signing()
            .sign(&crate::identity::root_succession_input(
                vault,
                &creator_id,
                &newroot_id,
                &nr_pub,
                1,
            ));
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .root_succession
            .push(RootSuccession {
                old_root_id: creator_id.clone(),
                new_root_id: newroot_id.clone(),
                new_root_sig_pub: nr_pub.to_vec(),
                role_epoch: 1,
                sig: succ_sig.to_vec(),
            });
        // The succession cert ALREADY derives role_epoch 1 (no separate stored
        // scalar). The NEW root re-cuts the checkpoint @epoch 1 (its own owner grant +
        // a cred); the creator's @epoch-0 grant is now stale.
        let nr_grant = newroot.signing().sign(&crate::identity::role_grant_input(
            vault,
            &newroot_id,
            "owner",
            1,
        ));
        pv.set_uik_cred(
            "cid-newroot".into(),
            newroot_id.clone(),
            nr_pub.to_vec(),
            vec![9u8; 32],
            vec![1u8; 40],
            vec![2u8; 40],
            MemberRole::Owner,
            nr_grant.to_vec(),
        );
        let os = owner_set(&pv, vault);
        assert_eq!(
            os.get(&newroot_id),
            Some(&MemberRole::Owner),
            "succession installs the new root as the owner authority",
        );
        assert!(
            !os.contains_key(&creator_id),
            "the offboarded creator is no longer an owner after transfer",
        );
    }

    #[test]
    fn forged_succession_does_not_advance_root() {
        // A succession NOT signed by the current root (here: signed by a member) does
        // NOT advance the root — the creator stays root, the attacker's key isn't
        // installed. Fail-closed forward.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, _creator, member, creator_id, _mid, mut pv) = role_fixture_creator_cred();
        let evil = UikRoot::from_root([0x66u8; 32]);
        let evil_id = evil.user_id();
        let evil_pub = evil.signing().public_bytes();
        // `member` (NOT the root) signs the succession → verify under the root fails.
        let bad_sig = member
            .signing()
            .sign(&crate::identity::root_succession_input(
                vault,
                &creator_id,
                &evil_id,
                &evil_pub,
                1,
            ));
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .root_succession
            .push(RootSuccession {
                old_root_id: creator_id.clone(),
                new_root_id: evil_id.clone(),
                new_root_sig_pub: evil_pub.to_vec(),
                role_epoch: 1,
                sig: bad_sig.to_vec(),
            });
        let os = owner_set(&pv, vault);
        assert_eq!(
            os.get(&creator_id),
            Some(&MemberRole::Owner),
            "a forged succession is ignored; the creator stays root",
        );
        assert!(
            !os.contains_key(&evil_id),
            "the attacker's key is not installed as root"
        );
    }

    #[test]
    fn last_owner_cannot_be_removed() {
        // The owner-set can never be EMPTIED (last-owner guard, replacing the old
        // "root is permanently immune" rule). Here the creator is the ONLY owner, so a
        // `remove` or a demote targeting them is ignored — they stay.
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, creator_id, _mid, mut pv) = role_fixture_creator_cred();
        push_event(
            &mut pv,
            vault,
            &creator,
            "remove",
            &creator_id,
            MemberRole::Member,
            1,
            0,
        );
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &creator_id,
            MemberRole::Member,
            2,
            0,
        );
        assert_eq!(
            owner_set(&pv, vault).get(&creator_id),
            Some(&MemberRole::Owner),
            "the last owner (here the creator) can't be removed or demoted away",
        );
    }

    #[test]
    fn creator_removable_when_another_owner_exists() {
        // Creator-offboard is just a `remove` (no two-party dance): once there is
        // ANOTHER owner, the creator can be removed via the log like anyone. Their
        // historical grants survive (they were seated at the base for issuance-time
        // authority), so whoever they added stays — the creator just leaves.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, creator_id, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let a_id = a.user_id();
        push_event(
            &mut pv,
            vault,
            &creator,
            "set",
            &a_id,
            MemberRole::Owner,
            1,
            0,
        );
        push_event(
            &mut pv,
            vault,
            &creator,
            "remove",
            &creator_id,
            MemberRole::Member,
            2,
            0,
        );
        let os = owner_set(&pv, vault);
        assert!(
            !os.contains_key(&creator_id),
            "the creator can leave (be removed) once another owner exists",
        );
        assert_eq!(
            os.get(&a_id),
            Some(&MemberRole::Owner),
            "the successor owner (added by the creator) stays after the creator leaves",
        );
    }

    #[test]
    fn membership_rollback_is_rejected() {
        // Part 2 (anti-rollback): the current re-key proof commits the delegation-log
        // PREFIX (owner-signed). If a colluding server serves the current generation
        // but a ROLLED-BACK log (an event omitted), the prefix no longer hashes to the
        // committed value → the whole owner-set is distrusted (fail closed), so the
        // server can't un-remove someone by serving an old log at the current gen.
        use crate::crypto::vault_key::UikRoot;
        use crate::storage::plaintext::MemberRole;
        let (vault, creator, _m, creator_id, _mid, mut pv) = role_fixture_creator_cred();
        let a = UikRoot::from_root([0x33u8; 32]);
        let a_id = a.user_id();
        // creator adds A via a delegation event (seq 1).
        let gsig = creator
            .signing()
            .sign(&crate::identity::delegation_event_input(
                vault,
                "set",
                &a_id,
                "owner",
                &creator_id,
                1,
                0,
            ));
        pv.keyset
            .uik
            .as_mut()
            .unwrap()
            .delegation_log
            .push(DelegationEvent {
                op: "set".into(),
                subject_id: a_id.clone(),
                role: MemberRole::Owner,
                granter_id: creator_id.clone(),
                granter_sig_pub: creator.signing().public_bytes().to_vec(),
                seq: 1,
                role_epoch: 0,
                sig: gsig.to_vec(),
            });
        // A re-key (gen 1) commits the membership prefix = [that event's sig].
        let membership = crate::identity::membership_commitment(&[gsig.as_slice()]);
        let commit = rekey_commitment(&[0x01u8; 32]).to_vec();
        let rk_sig = creator
            .signing()
            .sign(&crate::identity::rekey_sig_input(
                vault,
                1,
                &commit,
                &creator_id,
                1,
                &membership,
            ))
            .to_vec();
        {
            let uik = pv.keyset.uik.as_mut().unwrap();
            uik.generation = 1;
            uik.rekey_proof = Some(RekeyProof {
                generation: 1,
                k_commitment: commit,
                sig: rk_sig,
                signer_id: creator_id.clone(),
                membership_len: 1,
                membership_hash: membership.to_vec(),
            });
        }
        // Happy path: the committed log is present → Verified, A is an owner.
        assert!(
            matches!(pv.resolve_membership_trust(vault), MembershipTrust::Verified(_)),
            "matching log prefix → Verified",
        );
        assert_eq!(owner_set(&pv, vault).get(&a_id), Some(&MemberRole::Owner));
        // Rollback: the server drops the committed event → prefix mismatch → Untrusted
        // (the owner-set is NOT silently recomputed without it).
        pv.keyset.uik.as_mut().unwrap().delegation_log.clear();
        assert!(
            matches!(pv.resolve_membership_trust(vault), MembershipTrust::Untrusted),
            "a rolled-back log (committed event omitted) is rejected → Untrusted",
        );
    }
}
