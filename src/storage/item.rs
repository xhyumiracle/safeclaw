//! Per-item vault records — the SafeClaw-owned layer over sudp's generic
//! per-record seal/unseal primitive ([`sudp::state`] `record`).
//!
//! Division of labour (see `wt-merge-spec/docs/PER_ITEM_SYNC.md` + the build
//! contract §1–§2):
//!
//! - **sudp** does the AEAD only: [`seal_record`] / [`unseal_record`], binding
//!   `AAD = domain ‖ vault ‖ id ‖ version`. It never derives the id, compares
//!   versions, merges, or GCs.
//! - **SafeClaw (this module)** owns everything else: the opaque **item id**
//!   (HMAC of `ns ‖ name` under a K-derived subkey), the [`SealCtx`] build, the
//!   JSON payload shape `{ns,name,status,body}`, and the conflict-copy id. The
//!   version comparison / merge / tombstone / GC policy lives in `sync.rs`.
//!
//! ## Cross-language parity (the recurring bug)
//!
//! The item id and the sealed payload are produced in the browser (TS
//! `@sudp-protocol/authorizer` + `lib/vault-grant.ts`) **and** here, so the
//! derivations MUST be byte-identical. In particular **all binary-in-JSON is
//! base64url-**no-pad**, never std-base64** — one helper ([`URL_SAFE_NO_PAD`]),
//! used everywhere. The [`tests::pinned_item_id_parity_vector`] test pins the
//! fixed contract vector; the TS side pins the same string.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sudp::primitives::{Kdf, PrimitiveSuite};
use sudp::state::{seal_record, unseal_record, SealCtx};

use crate::error::{AppError, Result};

/// HKDF `info` label for the item-id subkey. Byte-identical to the TS side.
const ITEM_ID_INFO: &[u8] = b"safeclaw/item-id/v1";

/// Discriminator folded into a conflict-copy id so it never collides with the
/// canonical item's id (contract §4/§5).
const CONFLICT_LABEL: &[u8] = b"conflict";

/// `SealCtx.domain` for a **content** item — distinct from the future
/// `"keyset"` domain (cross-domain confusion is caught by sudp's AAD binding).
pub const ITEM_DOMAIN: &str = "item";

type HmacSha256 = Hmac<Sha256>;

/// Append a length-prefixed field: `u32_be(len) ‖ bytes` (contract §1 `lp(x)`).
/// Length-prefixing removes splicing ambiguity between adjacent variable
/// fields (`ns="ab",name="c"` vs `ns="a",name="bc"`).
fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// Derive the item-id subkey
/// `K_id = HKDF-SHA256(ikm = K, salt = "", info = "safeclaw/item-id/v1")`.
///
/// Uses the SAME `Kdf` the daemon's suite already uses for sealing
/// ([`PrimitiveSuite::Kdf`] = HKDF-SHA-256 under `StdPrimitives`), so there is
/// exactly one HKDF on both sides. Domain-separated from sudp's internal
/// `K_aead` (info `"sudp/v1/item"`) so the id subkey never shares raw bytes
/// with the AEAD key.
pub fn derive_item_id_key<S: PrimitiveSuite>(k: &[u8]) -> Result<[u8; 32]> {
    S::Kdf::derive_32(k, &[], ITEM_ID_INFO)
        .map_err(|e| AppError::Internal(format!("item-id key derive: {}", e)))
}

/// Raw 32-byte item id:
/// `HMAC-SHA256(K_id, lp(utf8(ns)) ‖ lp(utf8(name)))` (contract §1).
///
/// One-way (cloud never learns the name) and deterministic (two writers naming
/// the same logical key land on the same row → concurrency is *detectable*).
pub fn item_id_bytes<S: PrimitiveSuite>(k: &[u8], ns: &str, name: &str) -> Result<[u8; 32]> {
    let k_id = derive_item_id_key::<S>(k)?;
    let mut msg = Vec::with_capacity(8 + ns.len() + name.len());
    push_lp(&mut msg, ns.as_bytes());
    push_lp(&mut msg, name.as_bytes());
    Ok(hmac32(&k_id, &msg))
}

/// Wire / row-PK / URL form of an item id: `base64url_nopad(item_id_bytes)`.
pub fn item_id<S: PrimitiveSuite>(k: &[u8], ns: &str, name: &str) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(item_id_bytes::<S>(k, ns, name)?))
}

// ── Cleartext agent-authz item ids (T2 / aux→agent cutover) ──────────────────
// An authorized-agents item is addressed by its CLEARTEXT `ag_id` (not a blinded
// HMAC), so the backend can read the ag_id off the wire id and gate the write by
// ownership — see design/agent-authz-cleartext-cutover.md. The seal/sig AAD is
// STILL the HMAC `item_id_bytes(k,"agent",ag_id)` (unchanged 32 bytes); only the
// WIRE string (row PK / URL) differs. Recognition is collision-proof by LENGTH:
// `ag_id` = `"ag_"` + 32 base32 chars = 35 (identity::derive_id); every blinded
// item id is 43-char base64url. Disjoint sets — no prefix guessing can misfire.

/// Length of a cleartext agent wire id: `"ag_"` (3) + 32 base32 chars.
pub const AGENT_WIRE_ID_LEN: usize = 35;

/// True iff `wire_id` is a cleartext agent-authz item id (`ag_…`, 35 chars).
pub fn is_agent_wire_id(wire_id: &str) -> bool {
    wire_id.len() == AGENT_WIRE_ID_LEN && wire_id.starts_with("ag_")
}

/// The WIRE id (row PK / URL) for `(ns, name)`. `agent` ns ⇒ the cleartext ag_id
/// (`== name`); every other ns ⇒ the blinded base64url HMAC.
pub fn wire_id_for<S: PrimitiveSuite>(k: &[u8], ns: ItemNs, name: &str) -> Result<String> {
    if ns == ItemNs::Agent {
        Ok(name.to_string())
    } else {
        item_id::<S>(k, ns.as_str(), name)
    }
}

/// Reconstruct the 32-byte seal/sig AAD id from a stored WIRE id. Blinded ids are
/// base64url of the 32 AAD bytes (decode). A cleartext agent wire id IS the ag_id,
/// so recompute its HMAC `item_id_bytes(k,"agent",ag_id)` — the SAME bytes the
/// writer sealed under. Mirrors the FE read path (`unsealItem`).
pub fn aad_id_from_wire<S: PrimitiveSuite>(k: &[u8], wire_id: &str) -> Result<[u8; 32]> {
    if is_agent_wire_id(wire_id) {
        item_id_bytes::<S>(k, ItemNs::Agent.as_str(), wire_id)
    } else {
        let raw = URL_SAFE_NO_PAD
            .decode(wire_id.as_bytes())
            .map_err(|e| AppError::Internal(format!("item id base64url decode: {}", e)))?;
        <[u8; 32]>::try_from(raw.as_slice())
            .map_err(|_| AppError::Internal("item id is not 32 bytes".into()))
    }
}

/// Deterministic **conflict-copy** id (contract §4/§5): the same HMAC
/// construction as [`item_id_bytes`] with an extra `"conflict"` label and the
/// loser's version folded in, so a retry of the same conflict is idempotent
/// (can't spawn a second copy) yet never collides with the canonical id.
pub fn conflict_copy_id_bytes<S: PrimitiveSuite>(
    k: &[u8],
    ns: &str,
    name: &str,
    loser_version: u64,
) -> Result<[u8; 32]> {
    let k_id = derive_item_id_key::<S>(k)?;
    let mut msg = Vec::new();
    push_lp(&mut msg, ns.as_bytes());
    push_lp(&mut msg, name.as_bytes());
    push_lp(&mut msg, CONFLICT_LABEL);
    push_lp(&mut msg, &loser_version.to_be_bytes());
    Ok(hmac32(&k_id, &msg))
}

/// `base64url_nopad` of a [`conflict_copy_id_bytes`].
pub fn conflict_copy_id<S: PrimitiveSuite>(
    k: &[u8],
    ns: &str,
    name: &str,
    loser_version: u64,
) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(conflict_copy_id_bytes::<S>(k, ns, name, loser_version)?))
}

/// `HMAC-SHA256(key, msg)` → 32 bytes.
fn hmac32(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// The two per-vault keys the item layer needs, split for DP-S1 re-key
/// (team-shared-vault-security-model.md §3.2). `id_seed` derives the **stable**
/// item-id key (`derive_item_id_key`) so item ids survive a re-key; `content` is
/// the AEAD key for item bodies, which **rotates** on re-key. A gen-0 vault
/// (never re-keyed) has `id_seed == content == K`, so [`VaultKeys::single`] keeps
/// every pre-re-key call site a one-line wrap and byte-identical in behavior.
#[derive(Clone, Copy)]
pub struct VaultKeys<'a> {
    /// Stable across re-key → item ids never change (sync sees content updates,
    /// not delete-all + add-all).
    pub id_seed: &'a [u8],
    /// The current generation's content-encryption key (rotates on re-key).
    pub content: &'a [u8],
}

impl<'a> VaultKeys<'a> {
    /// A gen-0 (never-re-keyed) vault: id-seed and content are the same key `K`.
    pub fn single(k: &'a [u8]) -> Self {
        Self { id_seed: k, content: k }
    }

    /// Interpret acquired key material into the split view:
    ///   - **64 bytes** = a v2 DP-S1 bundle `id_seed(32) ‖ content_key(32)` →
    ///     the two halves (id_seed stable, content rotates on re-key);
    ///   - **any other length** (32 = v1 single `K`) → `single` (id == content).
    /// The daemon retains the acquired material and rebuilds this on each fold.
    pub fn from_material(material: &'a [u8]) -> Self {
        if material.len() == 64 {
            Self { id_seed: &material[..32], content: &material[32..] }
        } else {
            Self::single(material)
        }
    }
}

/// Concatenate a DP-S1 key bundle: `id_seed(32) ‖ content_key(32)` = 64 bytes,
/// the plaintext a v2 keyset seals to a member's UIK. Mirror on the browser side
/// (lib/uik-crypto.ts). `VaultKeys::from_material` is the inverse.
pub fn vault_key_bundle(id_seed: &[u8], content_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(id_seed.len() + content_key.len());
    out.extend_from_slice(id_seed);
    out.extend_from_slice(content_key);
    out
}

/// Owns the byte buffers a [`SealCtx`] borrows, so callers can build a sealing
/// context for one item + version without lifetime juggling.
///
/// `vault` = the vault id's UTF-8 bytes; `id` = the **32 raw** HMAC bytes (NOT
/// the base64url string); `version` = `u64` big-endian.
pub struct ItemCtx {
    vault: Vec<u8>,
    id: [u8; 32],
    version: [u8; 8],
}

impl ItemCtx {
    /// Build from an already-derived raw id.
    pub fn new(vault_id: &str, id_bytes: [u8; 32], version: u64) -> Self {
        Self {
            vault: vault_id.as_bytes().to_vec(),
            id: id_bytes,
            version: version.to_be_bytes(),
        }
    }

    /// Build for an item addressed by `(ns, name)`, deriving its id from `K`.
    pub fn for_item<S: PrimitiveSuite>(
        k: &[u8],
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        version: u64,
    ) -> Result<Self> {
        Ok(Self::new(
            vault_id,
            item_id_bytes::<S>(k, ns.as_str(), name)?,
            version,
        ))
    }

    /// The borrowed sudp [`SealCtx`] for this item at this version.
    pub fn seal_ctx(&self) -> SealCtx<'_> {
        SealCtx {
            domain: ITEM_DOMAIN,
            vault: &self.vault,
            id: &self.id,
            version: &self.version,
        }
    }

    /// The raw 32-byte id.
    pub fn id_bytes(&self) -> &[u8; 32] {
        &self.id
    }

    /// The base64url-nopad wire id (row PK / URL) for this item.
    pub fn item_id_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.id)
    }
}

/// Namespace of a content item — selects how `body` is interpreted (contract §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemNs {
    /// `body` = the secret string.
    Secret,
    /// `body` = `{ service, config }`.
    Connection,
    /// `body` = `{ service, config, code, verifier }`.
    Connecting,
    /// LEGACY (pre-unification): `ns = "aux"`, `name ∈ {policy, stores, …}`.
    /// Read-compat only — the fold still parses it, nothing writes it. Team
    /// §8.2: one rule now addresses everything (`ns` = the `VaultAux` field,
    /// `name` = the map key, singletons use the empty name), so each former
    /// aux subtree has its own ns below. Removable once the version census
    /// says the fleet is migrated.
    Aux,
    /// `body` = [`AgentEntry`] (reach mask); `name` = agent id. Team §8.1.
    Agent,
    /// Singleton (`name = ""`): `body` = the [`Policy`] tree.
    Policy,
    /// Singleton: `body` = the stores map.
    Stores,
    /// Singleton: `body` = the store-order list.
    #[serde(rename = "store_order")]
    StoreOrder,
    /// Singleton: `body` = retention days (integer).
    #[serde(rename = "audit_retention_days")]
    AuditRetentionDays,
    /// Singleton: `body` = custom-service source map.
    Services,
    /// Singleton: `body` = `{ user_id → role }` (team membership record —
    /// the signed owner-list anchor once UIK config signatures land).
    Members,
}

/// The authority a record's SIGNER carries, for the §A1.4/A2 role×type write
/// policy. A principal that authors a record is EITHER a human (UIK — an owner or
/// a plain member) OR the device (DIK) making an automatic, no-human-present write
/// (OAuth refresh / connect). Agents (AIK) never author records — they USE the
/// vault through the broker — so there is no agent writer role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterRole {
    /// A human UIK that is an OWNER of the vault.
    Owner,
    /// A human UIK that is a non-owner MEMBER.
    Member,
    /// The DIK — the daemon's automatic writes on behalf of its account. Bounded
    /// to data records (an owner-config or agent-authz change is a deliberate
    /// human act, never an automatic one).
    Device,
}

impl ItemNs {
    /// The lowercase wire string (matches the serde rename and the TS side).
    pub fn as_str(self) -> &'static str {
        match self {
            ItemNs::Secret => "secret",
            ItemNs::Connection => "connection",
            ItemNs::Connecting => "connecting",
            ItemNs::Aux => "aux",
            ItemNs::Agent => "agent",
            ItemNs::Policy => "policy",
            ItemNs::Stores => "stores",
            ItemNs::StoreOrder => "store_order",
            ItemNs::AuditRetentionDays => "audit_retention_days",
            ItemNs::Services => "services",
            ItemNs::Members => "members",
        }
    }

    /// §A1.4/A2 role×type write authorization: may a principal with `role` write
    /// (or tombstone) this record type? `is_own_agent` applies ONLY to `Agent` —
    /// it means the signer is the authorized agent's declared owner (self-service).
    /// The server uses this on the plaintext type as a clean-state write-gate, and
    /// every reader re-applies it after verifying the record signature (A1.5, the
    /// trust wall). Fail-CLOSED: retired (`Members`), legacy (`Aux`), and any type
    /// not enumerated deny (A1.4 "未知 type → 默认拒").
    pub fn write_allowed(self, role: WriterRole, is_own_agent: bool) -> bool {
        use ItemNs::*;
        match self {
            // Data records: any member principal, incl. the device's automatic writes.
            Secret | Connection | Connecting => true,
            // Owner-config singletons: a human OWNER only.
            Policy | Stores | StoreOrder | AuditRetentionDays | Services => {
                role == WriterRole::Owner
            }
            // Authorized-agents table (§11.1): any owner, or the agent's own member.
            Agent => role == WriterRole::Owner || (role == WriterRole::Member && is_own_agent),
            // Retired in-vault membership + legacy aux ns + anything else: fail-closed.
            Members | Aux => false,
        }
    }

    /// Singleton namespaces address exactly one item and use the empty name.
    pub fn is_singleton(self) -> bool {
        matches!(
            self,
            ItemNs::Policy
                | ItemNs::Stores
                | ItemNs::StoreOrder
                | ItemNs::AuditRetentionDays
                | ItemNs::Services
                | ItemNs::Members
        )
    }
}

/// Item lifecycle status. A tombstone carries `body: null` (contract §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemStatus {
    Live,
    Tombstone,
}

/// The sealed JSON payload of a content item (contract §2). This is exactly the
/// plaintext handed to [`seal_record`]; the cloud never sees it (it can't even
/// tell a tombstone from a live item — `status` is inside the ct).
///
/// `body` is the ns-specific value, or JSON `null` for a tombstone. We keep it
/// as an untyped [`serde_json::Value`] because the shape varies by `ns` and we
/// never byte-compare cts (random nonce per seal) — plain serde is fine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemPayload {
    pub ns: ItemNs,
    pub name: String,
    pub status: ItemStatus,
    /// The value (`secret` string / `connection` object / aux subtree) or
    /// `null` for a tombstone. Always serialized (including `null`).
    #[serde(default)]
    pub body: serde_json::Value,
}

impl ItemPayload {
    /// A live payload with an arbitrary JSON body.
    pub fn live(ns: ItemNs, name: impl Into<String>, body: serde_json::Value) -> Self {
        Self {
            ns,
            name: name.into(),
            status: ItemStatus::Live,
            body,
        }
    }

    /// A live `secret` payload (`body` = the string value).
    pub fn secret_live(name: impl Into<String>, value: &str) -> Self {
        Self::live(
            ItemNs::Secret,
            name,
            serde_json::Value::String(value.to_string()),
        )
    }

    /// A tombstone for `(ns, name)` — `status = tombstone`, `body = null`.
    pub fn tombstone(ns: ItemNs, name: impl Into<String>) -> Self {
        Self {
            ns,
            name: name.into(),
            status: ItemStatus::Tombstone,
            body: serde_json::Value::Null,
        }
    }

    /// True iff this payload is a tombstone (the sync layer drops the local item).
    pub fn is_tombstone(&self) -> bool {
        matches!(self.status, ItemStatus::Tombstone)
    }

    /// Serialize to the sealed-plaintext JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(AppError::from)
    }

    /// Parse from sealed-plaintext JSON bytes.
    pub fn from_json_bytes(b: &[u8]) -> Result<Self> {
        serde_json::from_slice(b).map_err(AppError::from)
    }
}

/// Seal an [`ItemPayload`] for `(vault, id, version)` under `K` using the
/// daemon's primitive suite. Output is sudp's per-record layout
/// `suite(1) ‖ nonce(24) ‖ ct ‖ tag(16)`.
pub fn seal_item<S: PrimitiveSuite>(
    k: &[u8],
    ctx: &ItemCtx,
    payload: &ItemPayload,
) -> Result<Vec<u8>> {
    let pt = payload.to_json_bytes()?;
    seal_record::<S>(k, &ctx.seal_ctx(), &pt)
        .map_err(|e| AppError::Internal(format!("seal item: {}", e)))
}

/// Unseal a sealed item ct back to its [`ItemPayload`]. The `version` bound in
/// `ctx` MUST equal the one the ct was sealed under (sudp's AAD binding), so a
/// tampered plaintext `version` sidecar can't lie — a mismatch is an
/// `Unauthorized` here.
pub fn unseal_item<S: PrimitiveSuite>(
    k: &[u8],
    ctx: &ItemCtx,
    sealed: &[u8],
) -> Result<ItemPayload> {
    let pt = unseal_record::<S>(k, &ctx.seal_ctx(), sealed)
        .map_err(|e| AppError::Unauthorized(format!("unseal item: {}", e)))?;
    ItemPayload::from_json_bytes(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sudp::primitives::StdPrimitives;

    #[test]
    fn write_allowed_role_x_type() {
        use ItemNs::*;
        use WriterRole::*;
        // Data records: every writer principal (owner / member / device auto-write).
        for ns in [Secret, Connection, Connecting] {
            for role in [Owner, Member, Device] {
                assert!(ns.write_allowed(role, false), "{ns:?} writable by {role:?}");
            }
        }
        // Owner-config: OWNER only; member + device denied.
        for ns in [Policy, Stores, StoreOrder, AuditRetentionDays, Services] {
            assert!(ns.write_allowed(Owner, false), "{ns:?} owner ok");
            assert!(!ns.write_allowed(Member, false), "{ns:?} member denied");
            assert!(!ns.write_allowed(Device, false), "{ns:?} device denied");
        }
        // Authorized-agents table: any owner; the agent's OWN member; not others.
        assert!(Agent.write_allowed(Owner, false), "any owner may authorize any agent");
        assert!(Agent.write_allowed(Member, true), "member authorizes their OWN agent");
        assert!(!Agent.write_allowed(Member, false), "member cannot authorize someone else's agent");
        assert!(!Agent.write_allowed(Device, true), "device never authorizes agents");
        // Retired / legacy / (implicitly) unknown: fail-closed.
        assert!(!Members.write_allowed(Owner, false), "in-vault membership retired");
        assert!(!Aux.write_allowed(Owner, false), "legacy aux ns not writable");
    }

    /// THE pinned cross-language parity vector (build contract §1).
    ///
    /// `K = 0x42 * 32 ; ns = "secret" ; name = "GMAIL_REFRESH_TOKEN"`.
    /// The frontend TS `item_id` MUST produce this exact base64url-nopad string.
    /// If this ever changes, the derivation drifted — do NOT edit the expected
    /// value to make it pass; find why Rust ↔ TS diverged.
    #[test]
    fn pinned_item_id_parity_vector() {
        let k = [0x42u8; 32];
        let id = item_id::<StdPrimitives>(&k, "secret", "GMAIL_REFRESH_TOKEN").unwrap();
        assert_eq!(id, "25fAyYNRxgkF3WqLCKweefkv-JCd5UECrQP7LCgApiQ");
    }

    /// The cleartext agent wire-id scheme (design/agent-authz-cleartext-cutover):
    /// the wire id IS the ag_id, but its seal/sig AAD is the SAME HMAC the blinded
    /// scheme derives for (ns=agent, name=ag_id). Blinded ids stay 43-char base64url
    /// and are decoded; the two id spaces are disjoint by length (35 vs 43). The FE
    /// mirror (lib/vault-items.ts) must agree byte-for-byte.
    #[test]
    fn agent_cleartext_wire_id_scheme() {
        let k = [0x42u8; 32];
        // ag_id = "ag_" + 32 lowercase base32 chars = 35 chars.
        let ag = "ag_abcdefghijklmnopqrstuvwxyz234567";
        assert_eq!(ag.len(), AGENT_WIRE_ID_LEN);
        assert!(is_agent_wire_id(ag));
        // wire id for an agent item is the ag_id verbatim.
        assert_eq!(wire_id_for::<StdPrimitives>(&k, ItemNs::Agent, ag).unwrap(), ag);
        // its AAD reconstructs to the SAME HMAC the writer sealed under.
        assert_eq!(
            aad_id_from_wire::<StdPrimitives>(&k, ag).unwrap(),
            item_id_bytes::<StdPrimitives>(&k, "agent", ag).unwrap(),
        );
        // a blinded secret id is 43 chars, NOT an agent id, and round-trips by decode.
        let blinded = item_id::<StdPrimitives>(&k, "secret", "X").unwrap();
        assert_eq!(blinded.len(), 43);
        assert!(!is_agent_wire_id(&blinded));
        assert_eq!(
            aad_id_from_wire::<StdPrimitives>(&k, &blinded).unwrap(),
            item_id_bytes::<StdPrimitives>(&k, "secret", "X").unwrap(),
        );
        // wire id for a non-agent ns is the blinded base64url.
        assert_eq!(wire_id_for::<StdPrimitives>(&k, ItemNs::Secret, "X").unwrap(), blinded);
    }

    /// Pin `K_id` too (cross-checked against an independent Python HKDF that
    /// also reproduces sudp's own `sudp/v1/item` conformance vector).
    #[test]
    fn pinned_item_id_subkey() {
        let k = [0x42u8; 32];
        let k_id = derive_item_id_key::<StdPrimitives>(&k).unwrap();
        let hex: String = k_id.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "5f1809d9cc658a4aa4f4dd5a2b5974fff833eacfabfd30f13ae8c5b1ed070c15"
        );
    }

    #[test]
    fn seal_unseal_item_roundtrip() {
        let k = [0x42u8; 32];
        let id = item_id_bytes::<StdPrimitives>(&k, "secret", "GMAIL_REFRESH_TOKEN").unwrap();
        let ctx = ItemCtx::new("vault-1", id, 1);
        let payload = ItemPayload::secret_live("GMAIL_REFRESH_TOKEN", "ya29.secret-value");
        let sealed = seal_item::<StdPrimitives>(&k, &ctx, &payload).unwrap();
        assert_eq!(sealed[0], 0x01, "sudp record suite tag");
        let opened = unseal_item::<StdPrimitives>(&k, &ctx, &sealed).unwrap();
        assert_eq!(opened.ns, ItemNs::Secret);
        assert_eq!(opened.name, "GMAIL_REFRESH_TOKEN");
        assert_eq!(
            opened.body,
            serde_json::Value::String("ya29.secret-value".into())
        );
        assert!(!opened.is_tombstone());
    }

    #[test]
    fn tombstone_roundtrips_with_null_body() {
        let k = [0x42u8; 32];
        let id = item_id_bytes::<StdPrimitives>(&k, "secret", "OLD").unwrap();
        let ctx = ItemCtx::new("v", id, 5);
        let tomb = ItemPayload::tombstone(ItemNs::Secret, "OLD");
        let sealed = seal_item::<StdPrimitives>(&k, &ctx, &tomb).unwrap();
        let opened = unseal_item::<StdPrimitives>(&k, &ctx, &sealed).unwrap();
        assert!(opened.is_tombstone());
        assert_eq!(opened.body, serde_json::Value::Null);
    }

    /// The AAD binds `version`; opening under a different version fails. This is
    /// what makes the plaintext CAS `version` un-forgeable relative to `ct`.
    #[test]
    fn wrong_version_ctx_fails_unseal() {
        let k = [0x42u8; 32];
        let id = item_id_bytes::<StdPrimitives>(&k, "secret", "X").unwrap();
        let sealed = seal_item::<StdPrimitives>(
            &k,
            &ItemCtx::new("v", id, 1),
            &ItemPayload::secret_live("X", "y"),
        )
        .unwrap();
        assert!(unseal_item::<StdPrimitives>(&k, &ItemCtx::new("v", id, 2), &sealed).is_err());
    }

    /// THE pinned cross-language conflict-copy-id vector (build contract §7 /
    /// §1 CANONICAL). `K = 0x42*32 ; ns = "secret" ; name = "GMAIL_REFRESH_TOKEN"
    /// ; loser_version = 2`. Layout:
    /// `base64url_nopad(HMAC-SHA256(K_id, lp(ns)‖lp(name)‖lp("conflict")‖lp(u64_be(2))))`.
    /// The frontend TS conflict-copy id MUST produce this exact string; if it
    /// ever drifts, do NOT edit the expected value — find why Rust ↔ TS diverged.
    #[test]
    fn pinned_conflict_copy_id_parity_vector() {
        let k = [0x42u8; 32];
        let id = conflict_copy_id::<StdPrimitives>(&k, "secret", "GMAIL_REFRESH_TOKEN", 2).unwrap();
        assert_eq!(id, "hBVW1yFYQ9aIxjcB-PeisTpr_EYtjQFXysiLCq7bN6k");
    }

    /// A conflict-copy id is deterministic (idempotent retry) and distinct from
    /// both the canonical id and any other loser version.
    #[test]
    fn conflict_copy_id_is_deterministic_and_distinct() {
        let k = [0x42u8; 32];
        let canonical = item_id::<StdPrimitives>(&k, "secret", "T").unwrap();
        let c1 = conflict_copy_id::<StdPrimitives>(&k, "secret", "T", 3).unwrap();
        let c1_again = conflict_copy_id::<StdPrimitives>(&k, "secret", "T", 3).unwrap();
        let c2 = conflict_copy_id::<StdPrimitives>(&k, "secret", "T", 4).unwrap();
        assert_eq!(c1, c1_again, "same inputs → same id (idempotent)");
        assert_ne!(c1, canonical, "conflict copy never collides with canonical");
        assert_ne!(c1, c2, "different loser version → different id");
    }

    #[test]
    fn ns_str_matches_serde() {
        // as_str() must equal the serde-serialized tag (both feed the id HMAC
        // / the wire on the two sides).
        for ns in [
            ItemNs::Secret,
            ItemNs::Connection,
            ItemNs::Connecting,
            ItemNs::Aux,
        ] {
            let json = serde_json::to_value(ns).unwrap();
            assert_eq!(json, serde_json::Value::String(ns.as_str().to_string()));
        }
    }
}
