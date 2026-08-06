//! SafeClaw identity & signing layer — Ed25519 principals (UIK / AIK),
//! self-certifying ids, and the canonical signing-input builders that config
//! signatures, re-key events, lineage succession, and the server-signed sync
//! envelope are all computed over.
//!
//! ## Boundary — why this lives here and NOT in the `sudp` crate
//!
//! sudp core stays a pure symmetric seal / wrap / grant codec: it knows nothing
//! of UIK, roles, or state signatures (design/sudp-identity-signing-revision.md
//! §0 — "SUDP core 只知道 K + 一把包 K 的 wrapping key + 抽象 authenticator +
//! grant/redeem"). Everything in this module is the SafeClaw-level extension
//! built *on top* of sudp. We reuse sudp's HKDF (so there is exactly one KDF
//! across the system — see [`storage::item`](crate::storage::item)) but keep our
//! own `safeclaw/v1/*` domain labels, pairwise-disjoint from sudp's `sudp/v1/*`
//! set and from the WebAuthn ECDSA-P256 β verification.
//!
//! ## Layering (design/team-shared-vault-security-model.md §5)
//!
//! `custody (passkey PRF / password KDF / HSM) → UIK → K`.
//!
//! - **UIK** = the human principal: signs config / state (no gesture, one per
//!   account, `user_id = derive_id(User, uik_pub)` = the account's cryptographic
//!   primary key). Custody wraps the UIK *private* key; the vault key `K` is
//!   HPKE-sealed to the UIK *public* key. Adding a device = adding one more
//!   custody wrap of the same UIK — it never touches `K`.
//! - **AIK** = an agent principal: one per agent, derived from a single root
//!   seed. The private key is resident in the daemon/`sc` component and NEVER
//!   enters the agent's environment or crosses a machine. `agent_id =
//!   derive_id(Agent, aik_pub)`; the wire bearer is a separate HKDF output so
//!   bearer rotation (epoch bump) is decoupled from identity continuity.
//!
//! This module is the identity half only: keypairs, ids, and the byte-exact
//! signing inputs. The custody→UIK→K wrap graph lives in the vault key layer;
//! the fold/verify *policy* (which pubkeys are owners, when to accept a signed
//! record) lives in the sync/members layer. Those consume the primitives here.
//!
//! ## Cross-language parity
//!
//! Config records are signed in the browser (TS `@sudp-protocol/authorizer` +
//! `lib/vault-grant.ts`) and verified by the daemon (Rust), so [`config_sig_input`]
//! and [`derive_id`] MUST be byte-identical across Rust and TS. The pinned
//! vectors at the bottom of this file are the contract; the TS side pins the
//! same values. Change one side, change both — and never edit an expected value
//! just to make a test pass; find why the two diverged.

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use sudp::primitives::{Kdf, PrimitiveSuite, StdPrimitives};
use zeroize::Zeroizing;

// ── Domain-separation labels (SafeClaw namespace; disjoint from sudp/v1/*) ──

/// Owner UIK signature over a config singleton (policy / stores / store_order /
/// audit_retention_days / services / members). See [`config_sig_input`].
pub const DS_CONFIG_SIG: &[u8] = b"safeclaw/v1/config-sig";

/// Owner-signed re-key event (a `generation` bump). See [`rekey_sig_input`].
pub const DS_REKEY: &[u8] = b"safeclaw/v1/rekey";

/// Creator-signed role grant on a keyset cred (the owner-authority anchor for
/// "who is an owner") — the root-signed CHECKPOINT base of the delegation fold.
/// See [`role_grant_input`].
pub const DS_ROLE_GRANT: &[u8] = b"safeclaw/v1/role-grant";

/// An owner-signed delegation event (add/promote/demote/remove) appended to the
/// keyset's delegation log — the any-owner, issuance-time-authority half of the
/// owner-set fold (design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md
/// §1.1). See [`delegation_event_input`].
pub const DS_DELEGATION: &[u8] = b"safeclaw/v1/delegation-event";

/// A root-succession certificate: the CURRENT root signs the NEXT root's id +
/// pubkey, so the daemon can follow a short chain from the TOFU-pinned genesis
/// root to the current root (creator transfer / offboard). See
/// [`root_succession_input`].
pub const DS_ROOT_SUCCESSION: &[u8] = b"safeclaw/v1/root-succession";

/// UIK lineage succession certificate (old UIK signs the new UIK). See
/// [`succession_input`].
pub const DS_SUCCESSION: &[u8] = b"safeclaw/v1/uik-succession";

/// Server-key signature over the whole sync envelope. See [`server_envelope_input`].
pub const DS_SERVER_ENVELOPE: &[u8] = b"safeclaw/v1/server-envelope";

/// Server-key signature over a fresh "last real contact" token. See
/// [`contact_token_input`].
pub const DS_CONTACT_TOKEN: &[u8] = b"safeclaw/v1/contact-token";

/// HKDF `info` deriving an agent's Ed25519 identity seed from its root seed.
const AIK_IDENTITY_INFO: &[u8] = b"safeclaw/v1/agent-identity";

/// HKDF `info` (prefix, before the big-endian epoch) deriving an agent's wire
/// bearer from its root seed. Pinned label (memory: single-root keyring).
const AIK_BEARER_INFO: &[u8] = b"sc/agent-bearer";

/// Append a length-prefixed field: `u32_be(len) ‖ bytes`. Identical to
/// [`storage::item`](crate::storage::item)'s `push_lp` and sudp's `record_aad`
/// so all length-prefixed constructions agree byte-for-byte. Length-prefixing
/// removes splicing ambiguity between adjacent variable-length fields.
fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// ── Self-certifying ids ────────────────────────────────────────────────────

/// Which principal an id names. The prefix makes ids self-describing and keeps
/// user and agent id spaces disjoint even at equal hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdKind {
    /// A human principal (UIK). Prints as `us_…`.
    User,
    /// An agent principal (AIK). Prints as `ag_…`.
    Agent,
}

impl IdKind {
    fn prefix(self) -> &'static str {
        match self {
            IdKind::User => "us",
            IdKind::Agent => "ag",
        }
    }
}

/// Derive the self-certifying id of a principal from its Ed25519 public key:
/// `"{us|ag}_" ‖ base32_lower_nopad(SHA-256(pubkey)[..20])`.
///
/// The id IS a commitment to the pubkey (ETH-address / SSH-fingerprint style),
/// so a colluding server cannot swap the key behind an id. 20 bytes → 32 base32
/// chars; lower-cased for a friendly, case-insensitive, URL/DNS-safe token.
pub fn derive_id(kind: IdKind, pubkey: &[u8; 32]) -> String {
    let digest = sha256(pubkey);
    let body = BASE32_NOPAD.encode(&digest[..20]).to_lowercase();
    format!("{}_{}", kind.prefix(), body)
}

// ── Signing principal (UIK, or a resolved AIK) ─────────────────────────────

/// An Ed25519 signing principal: holds the private key, can sign and expose its
/// public key / id. Used for a UIK (from custody-unwrapped bytes) and for a
/// resolved AIK (see [`AgentRoot::identity`]).
pub struct SigningIdentity {
    key: SigningKey,
}

impl SigningIdentity {
    /// Build from a 32-byte Ed25519 seed (the secret key). Deterministic:
    /// identical seed ⇒ identical public key and identical signatures.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Mint a fresh principal from the OS CSPRNG. (Foundation convenience; the
    /// production UIK is minted in the onboarding ceremony, an AIK from its root.)
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *seed);
        Self::from_seed(&seed)
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Sign a message, returning the 64-byte detached signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }

    /// This principal's self-certifying id under `kind`.
    pub fn id(&self, kind: IdKind) -> String {
        derive_id(kind, &self.public_bytes())
    }

    /// Convenience: the account primary key `us_…` for a UIK.
    pub fn user_id(&self) -> String {
        self.id(IdKind::User)
    }
}

/// Verify a detached Ed25519 signature over `msg` by `pubkey`. Uses
/// `verify_strict` (rejects the small-order / malleable edge cases), and treats
/// a malformed public key as a failed verification (never a panic). This is the
/// reader-side wall: every daemon calls it before applying a signed record.
pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature).is_ok()
}

// ── Agent root (AIK single-root derivation) ────────────────────────────────

/// An agent's single root seed. Everything about the agent derives from this one
/// secret: its Ed25519 identity keypair (⇒ `agent_id`) and its per-epoch wire
/// bearer. Storing one root per agent (memory: keyring `{seed, epoch, name}`)
/// keeps identity and bearer rotation independent while sharing no second secret.
pub struct AgentRoot {
    root: Zeroizing<[u8; 32]>,
}

impl AgentRoot {
    /// Adopt an existing 32-byte root seed.
    pub fn from_seed(root: [u8; 32]) -> Self {
        Self {
            root: Zeroizing::new(root),
        }
    }

    /// Mint a fresh agent root from the OS CSPRNG.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut root = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut root);
        Self::from_seed(root)
    }

    fn hkdf(&self, info: &[u8]) -> [u8; 32] {
        <StdPrimitives as PrimitiveSuite>::Kdf::derive_32(&self.root[..], &[], info)
            .expect("HKDF-SHA256 derive_32 is infallible for a 32-byte root")
    }

    /// The agent's Ed25519 identity, derived from the root (domain-separated
    /// from the bearer). The private key stays in this process.
    pub fn identity(&self) -> SigningIdentity {
        let seed = Zeroizing::new(self.hkdf(AIK_IDENTITY_INFO));
        SigningIdentity::from_seed(&seed)
    }

    /// The wire bearer for `epoch`: `HKDF(root, "sc/agent-bearer" ‖ u32_be(epoch))`.
    /// Rotating the bearer = bumping the epoch; the identity (and thus `agent_id`)
    /// is unchanged.
    pub fn bearer(&self, epoch: u32) -> [u8; 32] {
        let mut info = Vec::with_capacity(AIK_BEARER_INFO.len() + 4);
        info.extend_from_slice(AIK_BEARER_INFO);
        info.extend_from_slice(&epoch.to_be_bytes());
        self.hkdf(&info)
    }

    /// The agent's self-certifying id `ag_…`.
    pub fn agent_id(&self) -> String {
        self.identity().id(IdKind::Agent)
    }
}

// ── Canonical signing inputs (length-prefixed, domain-separated) ────────────
//
// Fixed-width scalars (version / generation / format / epoch / issued_at) are
// appended as big-endian bytes directly (unambiguous at fixed width); every
// variable-length field is `push_lp`'d.

/// Signing input for a config singleton (UIK-signed; reader-verified).
///
/// ```text
/// lp(DS_CONFIG_SIG) ‖ lp(vault_id) ‖ lp(item_ns) ‖ u64_be(version)
///   ‖ status(1) ‖ lp(SHA-256(body_or_empty)) ‖ lp(signer_id)
/// ```
///
/// `body = Some(canonical_bytes)` for a live record, `None` for a tombstone;
/// `status` = `1` live / `0` tombstone, so a live signature can never be
/// replayed as a tombstone (and vice versa). Hashing the (already-canonical)
/// body keeps the input bounded. `signer_id` (the owner's `us_…`) binds the
/// signature to a specific principal. The caller canonicalizes the body (JCS)
/// before hashing — see the config-signing layer for the body parity vector.
pub fn config_sig_input(
    vault_id: &str,
    item_ns: &str,
    version: u64,
    body: Option<&[u8]>,
    signer_id: &str,
) -> Vec<u8> {
    let status: u8 = if body.is_some() { 1 } else { 0 };
    let body_hash = sha256(body.unwrap_or(&[]));
    let mut out = Vec::new();
    push_lp(&mut out, DS_CONFIG_SIG);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, item_ns.as_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.push(status);
    push_lp(&mut out, &body_hash);
    push_lp(&mut out, signer_id.as_bytes());
    out
}

/// Signing input for an owner-signed re-key event (DP-S1 `generation` bump).
///
/// ```text
/// lp(DS_REKEY) ‖ lp(vault_id) ‖ u64_be(generation) ‖ lp(k_commitment) ‖ lp(signer_id)
///   ‖ u64_be(membership_len) ‖ lp(membership_hash)
/// ```
///
/// `k_commitment` = a one-way commitment to the new content key `K'` (e.g. a
/// KCV) so a signed generation is bound to the specific new key and an old
/// signed event can't be replayed to force a different key. The signature is
/// what makes a `generation` bump trustworthy: an unsigned bump is ignored, so a
/// malicious backend cannot storm fake generations to DoS unlock (SM §3.2 ⚠).
///
/// **Membership anti-rollback (delegation-log-review-findings.md C2, owner-signed).**
/// `membership_len` + `membership_hash` = [`membership_commitment`] over the delegation-log
/// PREFIX current at re-key time (all events at the current role-epoch, sorted).
/// Because a re-key is owner-signed and the daemon RATCHETS `generation` (refuses a
/// lower one), binding the membership head here lets a device REFUSE a keyset that serves
/// the current generation but a rolled-back log (e.g. an omitted `remove`): the
/// prefix would not hash to `membership_hash`. Low-frequency by construction (only on
/// re-key / offboard, not on every add), and the server can't forge it (no owner
/// key). A truly-fresh device against a permanent consistent OLD snapshot is still
/// inherent to cloud-blind — but that bubble is fragile (new content is under the
/// new K it can't open).
pub fn rekey_sig_input(
    vault_id: &str,
    generation: u64,
    k_commitment: &[u8],
    signer_id: &str,
    membership_len: u64,
    membership_hash: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_REKEY);
    push_lp(&mut out, vault_id.as_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    push_lp(&mut out, k_commitment);
    push_lp(&mut out, signer_id.as_bytes());
    out.extend_from_slice(&membership_len.to_be_bytes());
    push_lp(&mut out, membership_hash);
    out
}

/// A one-way commitment to the delegation-log PREFIX for the membership anti-rollback
/// binding in [`rekey_sig_input`]. `sigs` = the Ed25519 signatures of the first
/// `membership_len` delegation events at the current role-epoch, in the SAME
/// deterministic `(seq, sig)` order the fold applies them (each `sig` is a
/// commitment to its event's full content). Byte-identical across daemon / backend /
/// browser:
///
/// ```text
/// SHA-256( "safeclaw/v1/membership-commit" ‖ u64_be(membership_len) ‖ sig_1 ‖ … ‖ sig_N )
/// ```
pub fn membership_commitment(sigs: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"safeclaw/v1/membership-commit");
    buf.extend_from_slice(&(sigs.len() as u64).to_be_bytes());
    for s in sigs {
        buf.extend_from_slice(s);
    }
    sha256(&buf)
}

/// Signing input for a creator-signed role grant on a keyset cred — the
/// owner-authority anchor (design/identity-uik-aik.md §4.3 RESOLVED). Role is an
/// attribute ON the keyset cred, signed by the vault's ROOT owner (the creator);
/// a daemon derives the owner-set by verifying each cred's `role_sig` against the
/// TOFU-pinned `creator_sig_pub`. This roots role in genesis, closing finding #1
/// (single-version self-consistency let any member self-sign `{me: owner}`).
///
/// ```text
/// lp(DS_ROLE_GRANT) ‖ lp(vault_id) ‖ lp(user_id) ‖ lp(role) ‖ u64_be(role_epoch)
/// ```
///
/// `role` is the lowercase serde token of [`crate::storage::plaintext::MemberRole`]
/// (`"owner"` / `"member"`). The variable-length fields are length-prefixed (so a
/// `(vault, user, role)` triple can't be spliced into another); the trailing epoch
/// is appended as a fixed-width big-endian `u64`, EXACTLY as [`rekey_sig_input`]
/// appends `generation`.
///
/// **Role-epoch binding (delegation-log-impl-spec.md §0, design/identity-uik-aik.md
/// §4.3).** This grant is the root-signed CHECKPOINT of the owner-set. It is bound
/// to `role_epoch` — the role-checkpoint epoch, ORTHOGONAL to the K-rotation
/// `generation` (memory: "generation ⊥ chain 正交"). A checkpoint grant signed at
/// `role_epoch = E` is honored only while the keyset's DERIVED epoch is `E` — the
/// epoch is derived from the root-signed succession/compaction chain
/// (`resolve_current_root`), never a stored scalar. Compaction (root-only) is a
/// SELF-succession that advances the epoch to `E+1`, re-signing every surviving owner
/// and dropping demoted/removed ones — so a colluding server that replays a stale
/// grant fails verification at the new epoch (and can't forge the epoch upward
/// without a root signature).
/// Between checkpoints, any-owner add/remove rides the delegation log
/// ([`delegation_event_input`]), not this checkpoint. K-eviction bumps `generation`
/// independently and does NOT invalidate checkpoint grants (they bind `role_epoch`).
pub fn role_grant_input(vault_id: &str, user_id: &str, role: &str, role_epoch: u64) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_ROLE_GRANT);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, user_id.as_bytes());
    push_lp(&mut out, role.as_bytes());
    out.extend_from_slice(&role_epoch.to_be_bytes());
    out
}

/// Signing input for an owner-signed delegation event — the any-owner,
/// issuance-time-authority half of the owner-set fold (design/identity-uik-aik.md
/// §4.3, delegation-log-impl-spec.md §1.1).
///
/// ```text
/// lp(DS_DELEGATION) ‖ lp(vault_id) ‖ lp(op) ‖ lp(subject_id) ‖ lp(role)
///   ‖ lp(granter_id) ‖ u64_be(seq) ‖ u64_be(role_epoch)
/// ```
///
/// `op` ∈ {`"set"`, `"remove"`}: `set` inserts `subject_id → role` (add / promote /
/// demote); `remove` drops `subject_id` (NON-CASCADE — touches only the subject).
/// `role` is the lowercase [`crate::storage::plaintext::MemberRole`] token for `set`,
/// empty for `remove`. `granter_id` is the signing owner's `us_…`; the event is
/// honored by the fold iff `granter_id` is an OWNER in the owner-set folded up to
/// this event (so a member can't grant, and issuance-time authority survives the
/// granter's later removal). `seq` is monotone within `role_epoch` (rollback guard);
/// `role_epoch` binds the event to the current checkpoint so a compaction that folds
/// the log invalidates replays of pre-compaction events at the new epoch.
pub fn delegation_event_input(
    vault_id: &str,
    op: &str,
    subject_id: &str,
    role: &str,
    granter_id: &str,
    seq: u64,
    role_epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_DELEGATION);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, op.as_bytes());
    push_lp(&mut out, subject_id.as_bytes());
    push_lp(&mut out, role.as_bytes());
    push_lp(&mut out, granter_id.as_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&role_epoch.to_be_bytes());
    out
}

/// Signing input for a root-succession certificate — the CURRENT root signs the
/// NEXT root's id + signing pubkey, so a daemon follows a short chain from the
/// TOFU-pinned genesis root to the current root (creator transfer / offboard;
/// design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md §1.2).
///
/// ```text
/// lp(DS_ROOT_SUCCESSION) ‖ lp(vault_id) ‖ lp(old_root_id) ‖ lp(new_root_id)
///   ‖ lp(new_root_sig_pub) ‖ u64_be(role_epoch)
/// ```
///
/// The `new_root_sig_pub` (raw 32 bytes) is bound in the signature so the server
/// cannot swap in a root pubkey of its choosing; `old_root_id` must equal
/// `derive_id(current root)` at verification; `role_epoch` must strictly increase
/// along the chain (rollback guard). This differs from [`succession_input`], which
/// is a PERSON's key rotation preserving one id — here the root's id CHANGES
/// (ownership moves to a different principal).
pub fn root_succession_input(
    vault_id: &str,
    old_root_id: &str,
    new_root_id: &str,
    new_root_sig_pub: &[u8; 32],
    role_epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_ROOT_SUCCESSION);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, old_root_id.as_bytes());
    push_lp(&mut out, new_root_id.as_bytes());
    push_lp(&mut out, new_root_sig_pub);
    out.extend_from_slice(&role_epoch.to_be_bytes());
    out
}

/// Signing input for a UIK lineage succession certificate: the *old* UIK signs
/// the new UIK's id + public key so verifiers accept the new key under the old
/// identity (id continuity across rotation).
///
/// ```text
/// lp(DS_SUCCESSION) ‖ lp(old_id) ‖ lp(new_id) ‖ lp(new_pubkey)
/// ```
pub fn succession_input(old_id: &str, new_id: &str, new_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_SUCCESSION);
    push_lp(&mut out, old_id.as_bytes());
    push_lp(&mut out, new_id.as_bytes());
    push_lp(&mut out, new_pubkey);
    out
}

/// Signing input for the server-signed sync envelope (server key signs; daemon
/// verifies against a pinned server public key).
///
/// ```text
/// lp(DS_SERVER_ENVELOPE) ‖ lp(vault_id) ‖ lp(kind) ‖ u64_be(format)
///   ‖ u64_be(membership_epoch) ‖ u64_be(issued_at) ‖ lp(nonce)
/// ```
///
/// Signs the server-authoritative operational facts (SM §9): sharedness `kind`,
/// format version, membership epoch, freshness. Defends the daemon's local cache
/// against local tampering (flip a bool / forge a value) — NOT against a
/// malicious server (which is the authority here).
pub fn server_envelope_input(
    vault_id: &str,
    kind: &str,
    format: u64,
    membership_epoch: u64,
    issued_at: u64,
    nonce: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_SERVER_ENVELOPE);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, kind.as_bytes());
    out.extend_from_slice(&format.to_be_bytes());
    out.extend_from_slice(&membership_epoch.to_be_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    push_lp(&mut out, nonce);
    out
}

/// Signing input for a fresh "last real contact" token (server key signs). The
/// offline lease computes staleness from the newest VALID token, so a daemon
/// that forges its local `last_contact` clock cannot extend the lease — it can't
/// mint a token without the server key (SM §9 "真正的防绕点是联系时间戳").
///
/// ```text
/// lp(DS_CONTACT_TOKEN) ‖ lp(vault_id) ‖ lp(account_id) ‖ u64_be(issued_at) ‖ lp(nonce)
/// ```
pub fn contact_token_input(
    vault_id: &str,
    account_id: &str,
    issued_at: u64,
    nonce: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_CONTACT_TOKEN);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, account_id.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    push_lp(&mut out, nonce);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    // ── Correctness (no magic values) ──────────────────────────────────────

    #[test]
    fn id_format_and_stability() {
        let uik = SigningIdentity::from_seed(&[0x42; 32]);
        let id = uik.user_id();
        assert!(id.starts_with("us_"), "user id prefix: {id}");
        assert_eq!(id.len(), 3 + 32, "us_ + 32 base32 chars");
        assert_eq!(id, uik.user_id(), "id is deterministic");
        // Agent and user id spaces are prefix-disjoint for the same key.
        assert_ne!(uik.id(IdKind::User), uik.id(IdKind::Agent));
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let uik = SigningIdentity::from_seed(&[7; 32]);
        let pk = uik.public_bytes();
        let msg = b"the owner signs the policy";
        let sig = uik.sign(msg);
        assert!(verify(&pk, msg, &sig));
        // Tampered message fails.
        assert!(!verify(&pk, b"the owner signs the polici", &sig));
        // Wrong key fails.
        let other = SigningIdentity::from_seed(&[8; 32]).public_bytes();
        assert!(!verify(&other, msg, &sig));
        // Tampered signature fails.
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!verify(&pk, msg, &bad));
    }

    #[test]
    fn signatures_are_deterministic() {
        // Ed25519 is deterministic (RFC 8032): same key + msg ⇒ same signature.
        let uik = SigningIdentity::from_seed(&[0x42; 32]);
        let m = b"deterministic?";
        assert_eq!(uik.sign(m), uik.sign(m));
    }

    #[test]
    fn generate_is_random() {
        assert_ne!(
            SigningIdentity::generate().public_bytes(),
            SigningIdentity::generate().public_bytes()
        );
    }

    #[test]
    fn aik_bearer_rotates_identity_stable() {
        let root = AgentRoot::from_seed([0x11; 32]);
        let id0 = root.agent_id();
        assert!(id0.starts_with("ag_"));
        // Identity (hence id) is stable across bearer epochs.
        assert_eq!(id0, root.agent_id());
        // Distinct epochs give distinct bearers; identity unchanged.
        assert_ne!(root.bearer(0), root.bearer(1));
        assert_eq!(root.bearer(3), AgentRoot::from_seed([0x11; 32]).bearer(3));
        // Bearer is domain-separated from the identity seed (no accidental reuse).
        assert_ne!(
            root.bearer(0).to_vec(),
            root.identity().public_bytes().to_vec()
        );
    }

    #[test]
    fn config_sig_input_live_vs_tombstone_differ() {
        let live = config_sig_input("v1", "policy", 3, Some(b"{\"a\":1}"), "us_owner");
        let tomb = config_sig_input("v1", "policy", 3, None, "us_owner");
        assert_ne!(live, tomb, "status byte + body hash separate the two");
    }

    #[test]
    fn config_sig_input_lp_ambiguity_resolved() {
        // Without length prefixes ("ab","c") and ("a","bc") for (vault, ns)
        // would collide; with them the inputs differ.
        let a = config_sig_input("ab", "c", 1, Some(b"x"), "s");
        let b = config_sig_input("a", "bc", 1, Some(b"x"), "s");
        assert_ne!(a, b);
    }

    // ── Pinned cross-language vectors ───────────────────────────────────────
    // Established first-party here; the TS `@sudp-protocol/authorizer` mirror
    // pins the same values when config-signing lands there. Do NOT edit an
    // expected value to make a test pass — find why Rust ↔ TS diverged.
    // (Filled from the first `cargo test identity` run.)

    const UIK_SEED: [u8; 32] = [0x42; 32];
    const AIK_ROOT: [u8; 32] = [0x11; 32];

    #[test]
    fn pinned_uik_pubkey_and_id() {
        let uik = SigningIdentity::from_seed(&UIK_SEED);
        assert_eq!(
            hex(&uik.public_bytes()),
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
        );
        assert_eq!(uik.user_id(), "us_gcl6fxxcznfdjnjyidg3obno24igpq3p");
    }

    #[test]
    fn pinned_config_sig_input() {
        // K-vector: vault "vault-7", ns "policy", version 5, body {"k":"v"},
        // signer "us_owner".
        let input = config_sig_input("vault-7", "policy", 5, Some(b"{\"k\":\"v\"}"), "us_owner");
        assert_eq!(hex(&input), "0000001673616665636c61772f76312f636f6e6669672d736967000000077661756c742d3700000006706f6c69637900000000000000050100000020666c1aa02e8068c6d5cc1d3295009432c16790bec28ec8ce119d0d1a18d613190000000875735f6f776e6572");
    }

    #[test]
    fn pinned_config_signature() {
        let uik = SigningIdentity::from_seed(&UIK_SEED);
        let input = config_sig_input("vault-7", "policy", 5, Some(b"{\"k\":\"v\"}"), "us_owner");
        let sig = uik.sign(&input);
        assert_eq!(hex(&sig), "b6dcc1bd43082cfb16789191d73c65c9213093e2f827ca7e35084cd699668b668b798f97d47c8bb1ca584811f339f3f40430259a192d8c9bcef94a4f4d304304");
        assert!(verify(&uik.public_bytes(), &input, &sig));
    }

    #[test]
    fn pinned_aik_identity_and_bearer() {
        let root = AgentRoot::from_seed(AIK_ROOT);
        assert_eq!(
            hex(&root.identity().public_bytes()),
            "2a25e722dc68abfe33f7d78adc91904ed0c9b7f74b17c52e8338968c87e2357b"
        );
        assert_eq!(root.agent_id(), "ag_n7smudy334mfsttpye6oedc3fqp7pjrf");
        assert_eq!(
            hex(&root.bearer(0)),
            "48922af2f82a4ba05581440fec31d0ef06f22571f0c5f59117d06b656ab6e4b3"
        );
    }

    #[test]
    fn pinned_server_envelope_input() {
        // K-vector: vault "vault-7", kind "shared", format 2, membership_epoch 1,
        // issued_at 1000, nonce = 0xAA*12. The server key signs this exact
        // layout; the Node backend mirror pins the same hex.
        let input = server_envelope_input("vault-7", "shared", 2, 1, 1000, &[0xAA; 12]);
        assert_eq!(hex(&input), "0000001b73616665636c61772f76312f7365727665722d656e76656c6f7065000000077661756c742d37000000067368617265640000000000000002000000000000000100000000000003e80000000caaaaaaaaaaaaaaaaaaaaaaaa");
    }

    #[test]
    fn pinned_contact_token_input() {
        // K-vector: vault "vault-7", account "acc-1", issued_at 1000,
        // nonce = 0xBB*12. Mirrored by the Node backend.
        let input = contact_token_input("vault-7", "acc-1", 1000, &[0xBB; 12]);
        assert_eq!(hex(&input), "0000001973616665636c61772f76312f636f6e746163742d746f6b656e000000077661756c742d37000000056163632d3100000000000003e80000000cbbbbbbbbbbbbbbbbbbbbbbbb");
    }

    #[test]
    fn pinned_rekey_vectors() {
        // DP-S1 re-key golden vectors (Part 2). FIXED inputs:
        //   vault "vault-7", generation 5, content = 0x9a*32, signer "us_owner",
        //   k_commitment = rekey_commitment(content).
        // The browser mirror (lib/uik-crypto.ts) pins the SAME hex in
        // scripts/verify-uik-crypto.mts. Do NOT edit an expected value to make a
        // test pass — find why Rust ↔ TS diverged.
        let content = [0x9au8; 32];
        let commit = crate::storage::sealed_vault::rekey_commitment(&content);
        assert_eq!(
            hex(&commit),
            "9f3fe20e9995e64c9403e734e2a3dce8fd7a8659cc05d9995cbd277c27d6f499"
        );
        // Membership anti-rollback commitment over an EMPTY log prefix (membership_len 0).
        let membership = membership_commitment(&[]);
        assert_eq!(
            hex(&membership),
            "2f12a37c5a33eff8fca2c3623090a825c377cd051cf786dddfc5dd3286d631af"
        );
        // Non-empty prefix (two sigs) — exercises the sig-concat path cross-language.
        let sig_a = [0xAAu8; 64];
        let sig_b = [0xBBu8; 64];
        assert_eq!(
            hex(&membership_commitment(&[&sig_a, &sig_b])),
            "b70c763903e84f63d918943fccb98554f1f384e4a42e0d59c44d54eae0feb3ca"
        );
        let input = rekey_sig_input("vault-7", 5, &commit, "us_owner", 0, &membership);
        assert_eq!(
            hex(&input),
            "0000001173616665636c61772f76312f72656b6579000000077661756c742d370000000000000005000000209f3fe20e9995e64c9403e734e2a3dce8fd7a8659cc05d9995cbd277c27d6f4990000000875735f6f776e65720000000000000000000000202f12a37c5a33eff8fca2c3623090a825c377cd051cf786dddfc5dd3286d631af"
        );
    }

    #[test]
    fn pinned_role_grant_input() {
        // Owner-authority role-grant golden vector (design/identity-uik-aik.md
        // §4.3). FIXED inputs: vault "vault-7", user "us_alice", role "member",
        // generation 3. The browser mirror pins the SAME hex when role-grant
        // signing lands there. Do NOT edit an expected value to make a test pass
        // — find why Rust ↔ TS diverged.
        let input = role_grant_input("vault-7", "us_alice", "member", 3);
        assert_eq!(
            hex(&input),
            "0000001673616665636c61772f76312f726f6c652d6772616e74000000077661756c742d370000000875735f616c696365000000066d656d6265720000000000000003"
        );
        // Role is bound: the same (vault, user, generation) under a different role differs.
        let owner = role_grant_input("vault-7", "us_alice", "owner", 3);
        assert_ne!(input, owner, "role token is part of the signed input");
        // F3-b generation-binding: the SAME (vault, user, role) at a different
        // generation differs, so a stale grant can't be replayed after a re-key.
        let next_gen = role_grant_input("vault-7", "us_alice", "member", 4);
        assert_ne!(input, next_gen, "generation is part of the signed input");
    }

    #[test]
    fn pinned_derive_id() {
        // Cross-language derive_id vector (base32-lower of SHA-256(pubkey)[..20]). The
        // backend + browser mirrors pin the SAME strings so the succession-chain id
        // binding (`new_root_id == derive_id(new_pub)`) agrees byte-for-byte.
        assert_eq!(
            derive_id(IdKind::User, &[0x11u8; 32]),
            "us_alketiy7xmthzdzvf2mwrj46hzp4sxa3"
        );
        assert_eq!(
            derive_id(IdKind::User, &[0x22u8; 32]),
            "us_t5zoudhusu3ohrtmpb7xaumg36neg6ai"
        );
    }

    #[test]
    fn pinned_delegation_event_input() {
        // Delegation-event golden vector (delegation-log-impl-spec.md §1.1). FIXED
        // inputs: vault "vault-7", op "set", subject "us_bob", role "owner", granter
        // "us_alice", seq 5, role_epoch 2. The browser + backend mirrors pin the SAME
        // hex. Do NOT edit an expected value to make a test pass — find why the
        // implementations diverged.
        let input = delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 2);
        assert_eq!(
            hex(&input),
            "0000001c73616665636c61772f76312f64656c65676174696f6e2d6576656e74000000077661756c742d37000000037365740000000675735f626f62000000056f776e65720000000875735f616c69636500000000000000050000000000000002"
        );
        // A `remove` carries an EMPTY role token (so the same subject can't be spliced
        // between a set and a remove), and the seq / role_epoch are fixed-width tails.
        let remove = delegation_event_input("vault-7", "remove", "us_bob", "", "us_alice", 6, 2);
        assert_eq!(
            hex(&remove),
            "0000001c73616665636c61772f76312f64656c65676174696f6e2d6576656e74000000077661756c742d370000000672656d6f76650000000675735f626f62000000000000000875735f616c69636500000000000000060000000000000002"
        );
        // seq and role_epoch are both part of the signed input (reorder / replay guard).
        assert_ne!(
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 2),
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 6, 2),
            "seq is bound"
        );
        assert_ne!(
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 2),
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 3),
            "role_epoch is bound"
        );
    }

    #[test]
    fn pinned_root_succession_input() {
        // Root-succession golden vector (delegation-log-impl-spec.md §1.2). FIXED
        // inputs: vault "vault-7", old_root "us_alice", new_root "us_bob",
        // new_root_sig_pub = 32×0x11, role_epoch 4. Mirrors pin the SAME hex.
        let pub_key = [0x11u8; 32];
        let input = root_succession_input("vault-7", "us_alice", "us_bob", &pub_key, 4);
        assert_eq!(
            hex(&input),
            "0000001b73616665636c61772f76312f726f6f742d73756363657373696f6e000000077661756c742d370000000875735f616c6963650000000675735f626f620000002011111111111111111111111111111111111111111111111111111111111111110000000000000004"
        );
        // The new root's pubkey is bound (a colluding server can't swap in a key it
        // controls) and the epoch is a fixed-width tail (rollback guard).
        assert_ne!(
            input,
            root_succession_input("vault-7", "us_alice", "us_bob", &[0x22u8; 32], 4),
            "new_root_sig_pub is bound"
        );
        assert_ne!(
            input,
            root_succession_input("vault-7", "us_alice", "us_bob", &pub_key, 5),
            "role_epoch is bound"
        );
    }
}
