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
    item_id, item_id_bytes, seal_item, unseal_item, ItemCtx, ItemNs, ItemPayload,
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
        self.items.insert(
            item_id_b64,
            StoredItem {
                version,
                ct,
                synced_version: version,
                tombstone: false,
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
    pub fn item_version<S: PrimitiveSuite>(&self, k: &[u8], ns: ItemNs, name: &str) -> Result<u64> {
        let id = item_id::<S>(k, ns.as_str(), name)?;
        Ok(self.items.get(&id).map(|s| s.version).unwrap_or(0))
    }

    /// Seal `payload` for `(ns, name)` at the NEXT version (current + 1) under
    /// `K` and upsert it — the monotonic-bump write the connect / write paths
    /// use so an offline peer's CAS sees a strictly higher version (contract
    /// §6). Returns `(item_id_b64, new_version)`.
    pub fn seal_and_bump<S: PrimitiveSuite>(
        &mut self,
        k: &[u8],
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        payload: &ItemPayload,
    ) -> Result<(String, u64)> {
        let next = self.item_version::<S>(k, ns, name)? + 1;
        let id = self.seal_and_upsert::<S>(k, vault_id, ns, name, next, payload)?;
        Ok((id, next))
    }

    /// Seal `payload` for `(ns, name)` at `version` under `K` and upsert it,
    /// returning the base64url item id. Bridges the item.rs primitives
    /// (contract §1/§2) into the local store.
    pub fn seal_and_upsert<S: PrimitiveSuite>(
        &mut self,
        k: &[u8],
        vault_id: &str,
        ns: ItemNs,
        name: &str,
        version: u64,
        payload: &ItemPayload,
    ) -> Result<String> {
        let ctx = ItemCtx::for_item::<S>(k, vault_id, ns, name, version)?;
        let ct = seal_item::<S>(k, &ctx, payload)?;
        let id = ctx.item_id_b64();
        // A local write leaves `synced_version` where it was (the new version
        // is by definition not on the cloud yet) — the row is dirty until pushed.
        let synced_version = self.items.get(&id).map(|s| s.synced_version).unwrap_or(0);
        let tombstone = payload.is_tombstone();
        self.items.insert(
            id.clone(),
            StoredItem {
                version,
                ct,
                synced_version,
                tombstone,
            },
        );
        Ok(id)
    }

    /// Unseal one stored item addressed by `(ns, name)` under `K`. `Ok(None)` if
    /// no such item is stored. The stored `version` is fed into the `SealCtx`,
    /// so a tampered version would fail the AEAD (contract §6).
    pub fn open_item<S: PrimitiveSuite>(
        &self,
        k: &[u8],
        vault_id: &str,
        ns: ItemNs,
        name: &str,
    ) -> Result<Option<ItemPayload>> {
        let id = item_id::<S>(k, ns.as_str(), name)?;
        let Some(stored) = self.items.get(&id) else {
            return Ok(None);
        };
        let raw = item_id_bytes::<S>(k, ns.as_str(), name)?;
        let ctx = ItemCtx::new(vault_id, raw, stored.version);
        Ok(Some(unseal_item::<S>(k, &ctx, &stored.ct)?))
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
        k: &[u8],
        vault_id: &str,
        view: &crate::storage::plaintext::VaultPlaintextView,
    ) -> Result<()> {
        // native secrets → one `secret` item each.
        for (name, bytes) in &view.native_secrets {
            let value = String::from_utf8(bytes.clone())
                .map_err(|_| AppError::Internal(format!("secret '{}' not utf8", name)))?;
            let payload = ItemPayload::secret_live(name.clone(), &value);
            self.seal_and_upsert::<S>(k, vault_id, ItemNs::Secret, name, 1, &payload)?;
        }
        // established connections → one `connection` item each.
        for (conn_id, conn) in &view.aux.connections {
            let body = serde_json::to_value(conn).map_err(AppError::from)?;
            let payload = ItemPayload::live(ItemNs::Connection, conn_id.clone(), body);
            self.seal_and_upsert::<S>(k, vault_id, ItemNs::Connection, conn_id, 1, &payload)?;
        }
        // in-flight connects → one `connecting` item each.
        for (conn_id, c) in &view.aux.connecting {
            let body = serde_json::to_value(c).map_err(AppError::from)?;
            let payload = ItemPayload::live(ItemNs::Connecting, conn_id.clone(), body);
            self.seal_and_upsert::<S>(k, vault_id, ItemNs::Connecting, conn_id, 1, &payload)?;
        }
        // aux subtrees → one `aux:<name>` item each (LEGACY addressing —
        // team T1 stays here so the console, which still reads/writes
        // `aux:*`, keeps working. `agents`/`members` are blobs too. The
        // unified per-ns addressing (§8.2) + its ItemNs variants are folded
        // dual-read for a LATER coordinated core+console cutover; nothing
        // WRITES it yet.)
        for (name, body) in Self::aux_blob_bodies(&view.aux)? {
            self.seal_and_upsert::<S>(
                k,
                vault_id,
                ItemNs::Aux,
                name,
                1,
                &ItemPayload::live(ItemNs::Aux, name, body),
            )?;
        }
        Ok(())
    }

    /// The aux subtrees a view wants materialised, as `(aux_name, body)` pairs
    /// under LEGACY `aux:<name>` addressing. Shared by seed + reconcile so the
    /// two write paths can never disagree. Default/empty subtrees are skipped
    /// (no tombstone-like noise). `agents`/`members` ride here as whole blobs
    /// (team T1 — console reads them as `aux:agents`/`aux:members`).
    fn aux_blob_bodies(
        aux: &crate::storage::plaintext::VaultAux,
    ) -> Result<Vec<(&'static str, serde_json::Value)>> {
        let mut out = Vec::new();
        out.push((
            "stores",
            serde_json::to_value(&aux.stores).map_err(AppError::from)?,
        ));
        out.push((
            "store_order",
            serde_json::to_value(&aux.store_order).map_err(AppError::from)?,
        ));
        if let Some(policy) = &aux.policy {
            out.push(("policy", serde_json::to_value(policy).map_err(AppError::from)?));
        }
        if let Some(days) = aux.audit_retention_days {
            out.push(("audit_retention_days", serde_json::json!(days)));
        }
        if !aux.services.is_empty() {
            out.push((
                "services",
                serde_json::to_value(&aux.services).map_err(AppError::from)?,
            ));
        }
        if !aux.agents.is_empty() {
            out.push((
                "agents",
                serde_json::to_value(&aux.agents).map_err(AppError::from)?,
            ));
        }
        if !aux.members.is_empty() {
            out.push((
                "members",
                serde_json::to_value(&aux.members).map_err(AppError::from)?,
            ));
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
        k: &[u8],
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
            let existing = self.open_item::<S>(k, vault_id, *ns, name)?;
            let same = existing
                .as_ref()
                .map(|p| !p.is_tombstone() && &p.body == body)
                .unwrap_or(false);
            if same {
                continue;
            }
            let payload = ItemPayload::live(*ns, name.clone(), body.clone());
            let (id, _v) = self.seal_and_bump::<S>(k, vault_id, *ns, name, &payload)?;
            changed.push(id);
        }

        // Tombstone secret/connection/connecting rows the view dropped. Our own
        // folded view gives the currently-live (ns, name) set; tombstone any not
        // in `desired` (a completed connect MOVEs its `connecting` entry, so the
        // old connecting row must become a tombstone).
        let mine = self.fold_view::<S>(k, vault_id)?;
        for name in mine.native_secrets.keys() {
            if !desired.contains_key(&(ItemNs::Secret, name.clone())) {
                let (id, _v) = self.seal_and_bump::<S>(
                    k,
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
                    k,
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
                    k,
                    vault_id,
                    ItemNs::Connecting,
                    id,
                    &ItemPayload::tombstone(ItemNs::Connecting, id.clone()),
                )?;
                changed.push(iid);
            }
        }
        Ok(changed)
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
    /// NOTE: not yet called by the live handlers — `metadata.rs` still opens the
    /// whole-blob `ciphertext`. This is the ready target for that cut-over.
    pub fn fold_view<S: PrimitiveSuite>(
        &self,
        k: &[u8],
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
            members: bool,
        }
        let mut seen_new = SeenNew::default();
        // Legacy values parked until the loop ends (applied only where no new-
        // address item set the field).
        let mut legacy_stores: Option<serde_json::Value> = None;
        let mut legacy_store_order: Option<serde_json::Value> = None;
        let mut legacy_policy: Option<serde_json::Value> = None;
        let mut legacy_retention: Option<serde_json::Value> = None;
        let mut legacy_services: Option<serde_json::Value> = None;
        let mut legacy_agents: Option<serde_json::Value> = None;
        let mut legacy_members: Option<serde_json::Value> = None;
        let mut legacy_addressing = false;

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
                let payload = unseal_item::<S>(k, &ctx, &stored.ct)?;
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
                        let entry = serde_json::from_value(payload.body).map_err(|e| {
                            AppError::Internal(format!("agent '{}' parse: {}", name, e))
                        })?;
                        aux.agents.insert(name, entry);
                    }
                    ItemNs::Policy => {
                        aux.policy = Some(serde_json::from_value(payload.body).map_err(|e| {
                            AppError::Internal(format!("policy parse: {}", e))
                        })?);
                        seen_new.policy = true;
                    }
                    ItemNs::Stores => {
                        aux.stores = serde_json::from_value(payload.body).map_err(|e| {
                            AppError::Internal(format!("stores parse: {}", e))
                        })?;
                        seen_new.stores = true;
                    }
                    ItemNs::StoreOrder => {
                        aux.store_order = serde_json::from_value(payload.body).map_err(|e| {
                            AppError::Internal(format!("store_order parse: {}", e))
                        })?;
                        seen_new.store_order = true;
                    }
                    ItemNs::AuditRetentionDays => {
                        aux.audit_retention_days = serde_json::from_value(payload.body)
                            .map_err(|e| {
                                AppError::Internal(format!("audit_retention_days parse: {}", e))
                            })?;
                        seen_new.retention = true;
                    }
                    ItemNs::Services => {
                        aux.services = serde_json::from_value(payload.body).map_err(|e| {
                            AppError::Internal(format!("services parse: {}", e))
                        })?;
                        seen_new.services = true;
                    }
                    ItemNs::Members => {
                        aux.members = serde_json::from_value(payload.body).map_err(|e| {
                            AppError::Internal(format!("members parse: {}", e))
                        })?;
                        seen_new.members = true;
                    }
                    ItemNs::Aux => {
                        // LEGACY addressing (pre-unification). Park the value;
                        // applied after the loop only if no new-address item
                        // set the same field. Unknown names ignored (forward-
                        // compat, unchanged).
                        legacy_addressing = true;
                        match name.as_str() {
                            "stores" => legacy_stores = Some(payload.body),
                            "store_order" => legacy_store_order = Some(payload.body),
                            "policy" => legacy_policy = Some(payload.body),
                            "audit_retention_days" => legacy_retention = Some(payload.body),
                            "services" => legacy_services = Some(payload.body),
                            // The console still seals aux subtrees as whole
                            // blobs (legacy addressing). `agents`/`members`
                            // arrive that way until the frontend seal layer
                            // moves to per-item; parse them here (a blob wins
                            // over nothing, and the migration splits `agents`
                            // into per-agent items + promotes `members` to its
                            // singleton). Only applied if no new-address item
                            // set the same field.
                            // Park; applied after the loop with per-key merge so
                            // any future per-item `agent:`/`members:` row wins
                            // per key, order-independent (never the coarse
                            // all-or-nothing drop).
                            "agents" => legacy_agents = Some(payload.body),
                            "members" => legacy_members = Some(payload.body),
                            _ => {}
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
        // agents / members legacy blobs: per-key merge, per-item row wins.
        if let Some(v) = legacy_agents {
            if let Ok(m) = serde_json::from_value::<
                std::collections::BTreeMap<String, crate::storage::plaintext::AgentEntry>,
            >(v) {
                for (id, entry) in m {
                    aux.agents.entry(id).or_insert(entry);
                }
            }
        }
        if !seen_new.members {
            if let Some(v) = legacy_members {
                if let Ok(m) = serde_json::from_value::<
                    std::collections::BTreeMap<String, crate::storage::plaintext::MemberRole>,
                >(v) {
                    for (id, role) in m {
                        aux.members.entry(id).or_insert(role);
                    }
                }
            }
        }

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
        k: &[u8],
        vault_id: &str,
    ) -> Result<Vec<String>> {
        let view = self.fold_view::<S>(k, vault_id)?;
        if !view.legacy_addressing {
            return Ok(Vec::new());
        }
        // Reconcile writes every config singleton at its NEW address (the
        // mapping lives in `singleton_bodies`, shared with seed).
        let mut changed = self.reconcile_from_view::<S>(k, vault_id, &view)?;
        // Tombstone every live legacy aux row (known + unknown names alike —
        // the namespace is retired wholesale).
        let legacy: Vec<String> = self
            .live_names_in_ns::<S>(k, vault_id, ItemNs::Aux)?
            .into_iter()
            .collect();
        for name in legacy {
            let (id, _v) = self.seal_and_bump::<S>(
                k,
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
        k: &[u8],
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
                let payload = unseal_item::<S>(k, &ctx, &stored.ct)?;
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
                &k,
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
            .open_item::<StdPrimitives>(&k, vid, ItemNs::Secret, "GMAIL_REFRESH_TOKEN")
            .unwrap()
            .unwrap();
        assert_eq!(payload.body, serde_json::Value::String("ya29.value".into()));
        assert!(!payload.is_tombstone());

        // A wrong vault id must NOT open (AAD binds the vault).
        assert!(loaded
            .open_item::<StdPrimitives>(&k, "other-vault", ItemNs::Secret, "GMAIL_REFRESH_TOKEN")
            .is_err());

        // Absent item → Ok(None), not an error.
        assert!(loaded
            .open_item::<StdPrimitives>(&k, vid, ItemNs::Secret, "NOPE")
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
                &k,
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
            &k,
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
                &k,
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
                &k,
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
    fn agent_mask_serde_all_and_selected() {
        use crate::storage::plaintext::{AgentEntry, AgentMask};
        // "all" round-trips as the bare string; a list stays a list.
        let all: AgentEntry = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(all.connections.allows("anything"));
        assert_eq!(
            serde_json::to_value(&AgentEntry::default()).unwrap(),
            serde_json::json!({ "connections": "all" })
        );
        let sel: AgentEntry =
            serde_json::from_value(serde_json::json!({ "connections": ["github-work"] })).unwrap();
        assert!(sel.connections.allows("github-work"));
        assert!(!sel.connections.allows("stripe-live"), "fail-closed");
        let back = serde_json::to_value(&sel).unwrap();
        assert_eq!(back, serde_json::json!({ "connections": ["github-work"] }));
    }

    // T1 addressing: everything (config + agents + members) rides LEGACY
    // `aux:<name>` blobs so the console (still on aux addressing) keeps working.
    // The unified per-ns variants + fold dual-read exist for a LATER cutover but
    // nothing writes them yet. This asserts the seed → fold round-trip and the
    // agents/members per-key merge the reviewer flagged.
    #[test]
    fn t1_aux_blob_addressing_roundtrips_including_agents_and_members() {
        use crate::storage::plaintext::{AgentEntry, AgentMask, MemberRole, VaultAux};
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

        // Seed from a view carrying policy + an agent mask + members.
        let mut aux = VaultAux::initial();
        aux.policy = Some(serde_json::from_value(serde_json::json!({ "timeout": 222 })).unwrap());
        aux.agents.insert(
            "ag_test".into(),
            AgentEntry { connections: AgentMask::Selected(vec!["gmail".into()]) },
        );
        aux.members.insert("u_alice".into(), MemberRole::Owner);
        let view = crate::storage::plaintext::VaultPlaintextView {
            aux,
            native_secrets: std::collections::BTreeMap::new(),
            legacy_addressing: false,
        };
        pv.seed_items_from_view::<StdPrimitives>(&k, vid, &view).unwrap();

        // Every subtree comes back through the legacy `aux:*` blobs.
        let folded = pv.fold_view::<StdPrimitives>(&k, vid).unwrap();
        assert_eq!(folded.aux.policy.as_ref().unwrap().timeout, Some(222));
        assert!(folded.aux.agents["ag_test"].connections.allows("gmail"));
        assert!(!folded.aux.agents["ag_test"].connections.allows("stripe"), "fail-closed");
        assert_eq!(folded.aux.members.get("u_alice"), Some(&MemberRole::Owner));
        // No per-ns unified items were written (T1 stays on legacy addressing).
        assert!(
            pv.live_names_in_ns::<StdPrimitives>(&k, vid, ItemNs::Agent).unwrap().is_empty(),
            "T1 must not write per-item agent rows"
        );

        // A per-item agent row (future addressing) wins per-key over the blob;
        // an agent only in the blob still survives (per-key merge, not drop).
        pv.seal_and_upsert::<StdPrimitives>(
            &k,
            vid,
            ItemNs::Agent,
            "ag_new",
            1,
            &ItemPayload::live(ItemNs::Agent, "ag_new", serde_json::json!({ "connections": "all" })),
        )
        .unwrap();
        let merged = pv.fold_view::<StdPrimitives>(&k, vid).unwrap();
        assert!(merged.aux.agents.contains_key("ag_test"), "blob agent survives");
        assert!(merged.aux.agents.contains_key("ag_new"), "per-item agent present");
        assert!(merged.aux.agents["ag_new"].connections.allows("anything"));
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
            &k,
            vid,
            ItemNs::Secret,
            "OPENAI_KEY",
            1,
            &ItemPayload::secret_live("OPENAI_KEY", "sk-live"),
        )
        .unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            &k,
            vid,
            ItemNs::Secret,
            "GONE",
            2,
            &ItemPayload::tombstone(ItemNs::Secret, "GONE"),
        )
        .unwrap();
        pv.seal_and_upsert::<StdPrimitives>(
            &k,
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
            &k,
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

        let view = pv.fold_view::<StdPrimitives>(&k, vid).unwrap();
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
}
