//! Vault-scoped and custodian-level read-only endpoints.
//!
//! - `GET /v/{vid}/passkeys` — list this vault's enrolled credentials (public metadata only)
//! - `GET /pubkey`           — custodian's HPKE public key (bootstrap for outer envelope)
//!
//! Listing actual target names still requires a passkey-signed Export op via
//! `POST /v/{vid}/op` + `POST /op/{op_id}/approve`.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::Serialize;
use serde_json::{json, Value};
use sudp::grant::{GrantOpt, RedeemedGrant, WrappingKey};
use sudp::passkey::WebAuthn;
use sudp::primitives::StdPrimitives;

use crate::error::{AppError, Result};
use crate::protocol::Operation;
use crate::server::handlers::op::validate_vault_id;
use crate::state::AppState;
use crate::storage::plaintext::VaultPlaintextView;
use crate::storage::sealed_vault::find_pubkey_in_registry;

#[derive(Debug, Serialize)]
pub struct PasskeyMeta {
    pub credential_id: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    /// Base64 of the credential's prf_salt — needed by the client for PRF eval.
    pub prf_salt: String,
    /// P-256 public key X coordinate (base64). Used by --reuse to skip create().
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_x: Option<String>,
    /// P-256 public key Y coordinate (base64). Used by --reuse to skip create().
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_y: Option<String>,
    /// Optional key-check value (KCV, STANDARD base64). Lets the browser confirm
    /// a re-derived `W_c` before depositing a grant, without unwrapping `K`.
    /// Absent for credentials enrolled before the KCV existed (until backfilled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wc_check: Option<String>,
}

pub async fn passkeys(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    validate_vault_id(&vault_id)?;
    // Per-item vault (vault.per-item.json) is the current keyset home; fall back
    // to the legacy vault.dat for vaults predating the per-item rework. This
    // handler used to read ONLY vault.dat, so a per-item-enrolled vault (keyset
    // synced into vault.per-item.json via pull_keys, with no vault.dat) reported
    // vault_exists:false — surfacing as `sc status` "not found" for a real,
    // enrolled vault that simply had no secrets yet.
    let per_item_path = state.vaults.per_item_path(&vault_id)?;
    let vault_path = state.vaults.vault_path(&vault_id)?;
    let (registry, credentials) =
        if let Some(pv) = crate::storage::sealed_vault::read_per_item(&per_item_path)? {
            (pv.keyset.registry, pv.keyset.credentials)
        } else if let Some(v) = crate::storage::sealed_vault::read(&vault_path)? {
            (v.registry, v.credentials)
        } else {
            return Ok(Json(json!({ "vault_exists": false, "passkeys": [] })));
        };
    // F-24: prf_salt exposure mitigation.
    //
    // Protocol constraint: prf_salt IS required by the client to run WebAuthn
    // PRF and derive W_c for the vault-unlock ceremony — the ceremony begins
    // from the Locked state. Suppressing prf_salt universally when locked
    // would therefore break unlock. The correct long-term fix is a session-
    // token gate on this endpoint so only the authenticated vault owner can
    // retrieve the salt.
    //
    // For now we add a tracing event when the vault is locked so operators can
    // see unauthenticated probes in their logs, and include a TODO so this is
    // not forgotten.
    //
    // TODO: Add a lightweight session-token requirement to this endpoint so
    // prf_salt is only returned to the authenticated vault owner (F-24).
    if state.is_vault_locked(&vault_id) {
        tracing::debug!(vault = %vault_id, "GET /passkeys while vault locked — prf_salt returned; TODO: gate on session token (F-24)");
    }
    let metas: Vec<PasskeyMeta> = credentials
        .iter()
        .map(|c| {
            // Emit credential_id as base64url-no-pad. credentialId is the one
            // sudp field that crosses the WebAuthn boundary (W3C spec specifies
            // base64url here) and that appears in URL paths on the pro-backend.
            // Everything else (prf_salt, wrapped_key, ciphertext, signatures…)
            // stays strict-STANDARD — those don't have the same cross-system
            // / URL-safety pressure.
            let cid_b64 = URL_SAFE_NO_PAD.encode(&c.credential_id);
            let pk = find_pubkey_in_registry(&registry, &cid_b64);
            PasskeyMeta {
                credential_id: cid_b64,
                device_name: pk
                    .as_ref()
                    .map(|p| p.device_name.clone())
                    .unwrap_or_default(),
                created_at: 0, // sudp Registry doesn't track this; future: aux side-store.
                prf_salt: STANDARD.encode(&c.prf_salt),
                public_key_x: pk.as_ref().map(|p| p.x.clone()),
                public_key_y: pk.as_ref().map(|p| p.y.clone()),
                wc_check: c.wc_check.as_ref().map(|v| STANDARD.encode(v)),
            }
        })
        .collect();
    // Pending-passkey deposits (Stage 1 done, awaiting Stage 2 Enroll).
    // list() opportunistically GC-sweeps expired files — that's the only
    // place we know the daemon is actively serving this vault. Failure to
    // list isn't fatal: pending list just renders empty.
    let pending: Vec<Value> = crate::storage::pending_passkey::list(&state.vaults, &vault_id)
        .unwrap_or_default()
        .into_iter()
        .map(|p| p.public_metadata())
        .collect();
    Ok(Json(json!({
        "vault_exists": true,
        "passkeys": metas,
        "pending_passkeys": pending,
    })))
}

/// `GET /pubkey` — daemon HPKE outer-envelope public key (PROTOCOL.md §4.2.1 M1).
///
/// Returns the daemon's static `sc_pk` plus the suite identifier so clients
/// can pick the matching HPKE implementation. Currently used by the
/// pending-passkey deposit flow (cross-device add-passkey); future use:
/// `[HPKE: MUST]` grant submissions.
///
/// `sc_pk_fingerprint` lets remote clients OOB-verify the key on first pin
/// (per PROTOCOL.md §4.2.2 trust establishment).
pub async fn pubkey(State(state): State<Arc<AppState>>) -> Json<Value> {
    use base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine,
    };
    use sha2::{Digest, Sha256};
    let pk_bytes = state.sc.pk_bytes();
    let fp = Sha256::digest(&pk_bytes);
    Json(json!({
        "hpke_supported": true,
        "kem": "x25519-hkdf-sha256",
        "kdf": "hkdf-sha256",
        "aead": "chacha20-poly1305",
        "sc_pk": URL_SAFE_NO_PAD.encode(&pk_bytes),
        "sc_pk_fingerprint": STANDARD.encode(fp),
    }))
}

/// `POST /v/{vid}/sync` — on-demand cloud pull + complete-pending-connect
/// (backs `sc sync`). No passkey: it only advances already-sealed state (the
/// pull is device-key-authed; the connect re-seal uses the retained K and
/// no-ops if the vault is locked). The vault id is validated; the rest is
/// handled inside `sync::sync_vault_now`.
pub async fn sync_now(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Json<Value> {
    if let Err(e) = validate_vault_id(&vault_id) {
        return Json(json!({ "ok": false, "error": e.to_string() }));
    }
    match crate::sync::sync_vault_now(&state, &vault_id).await {
        Ok(out) => {
            let c = &out.connects;
            Json(json!({
                "ok": true,
                "pulled": out.pulled,
                "connects": {
                    "completed": c.completed,
                    "failed": c.failed.iter()
                        .map(|(conn, reason)| json!({ "conn": conn, "reason": reason }))
                        .collect::<Vec<_>>(),
                    "unreached": c.unreached.iter()
                        .map(|(conn, host)| json!({ "conn": conn, "host": host }))
                        .collect::<Vec<_>>(),
                },
            }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

/// Decrypt vault and return a parsed v3 view of the plaintext. Used by
/// `approve.rs` for Export/Use act dispatch and by the unlock-bootstrap
/// path. Hard-fails on `version != 3` (callers should treat this as
/// "user must re-enroll under the new binary").
pub fn decrypt_vault_view(
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &crate::storage::SealedVault,
) -> Result<VaultPlaintextView> {
    let redeemed = RedeemedGrant {
        o: op.clone(),
        credential_id: credential_id_bytes.to_vec(),
        wrapping_key: WrappingKey::from_bytes(wrapping_key.to_vec()),
        opt: GrantOpt::default(),
    };
    let opened = sudp::phases::consumption::open::<StdPrimitives>(&redeemed, vault)
        .map_err(|e| AppError::Unauthorized(format!("vault open: {}", e)))?;
    let view = VaultPlaintextView::from_protected_state(&opened.m)?;
    let _ = redeemed_zeroize_marker();
    Ok(view)
}

/// Like [`decrypt_vault_view`] but also returns the unwrapped state key `K`
/// (zeroized on drop) so the caller can RETAIN it for the unlocked session.
/// Used by the unlock + write paths so a later cloud-sync pull can refresh the
/// cache with `K` instead of forcing another passkey ([`decrypt_vault_view_with_key`]).
pub fn decrypt_vault_view_keep_key(
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &crate::storage::SealedVault,
) -> Result<(VaultPlaintextView, zeroize::Zeroizing<Vec<u8>>)> {
    let redeemed = RedeemedGrant {
        o: op.clone(),
        credential_id: credential_id_bytes.to_vec(),
        wrapping_key: WrappingKey::from_bytes(wrapping_key.to_vec()),
        opt: GrantOpt::default(),
    };
    let opened = sudp::phases::consumption::open::<StdPrimitives>(&redeemed, vault)
        .map_err(|e| AppError::Unauthorized(format!("vault open: {}", e)))?;
    let view = VaultPlaintextView::from_protected_state(&opened.m)?;
    let _ = redeemed_zeroize_marker();
    Ok((view, opened.k))
}

/// Decrypt the vault's body ciphertext with a RETAINED state key `K` — no
/// grant, no passkey. The body is sealed under `K` with AAD `DS_SEAL ‖ ver`,
/// independent of any credential, so a held `K` opens it directly. Returns
/// `Unauthorized` if `K` can't open it (e.g. the writer rotated `K`), which
/// callers treat as graceful "lock+unlock to see new state". Used by the
/// cloud-sync refresh after a runtime pull. Reconstructs `seal_ad` from sudp's
/// public `DS_SEAL` (sudp's own `seal_ad` is crate-private).
pub fn decrypt_vault_view_with_key(
    k: &[u8],
    vault: &crate::storage::SealedVault,
) -> Result<VaultPlaintextView> {
    use sudp::primitives::domain::DS_SEAL;
    use sudp::primitives::{Aead, ChaCha20Poly1305};
    use sudp::state::ProtectedState;

    let mut ad = Vec::with_capacity(DS_SEAL.len() + 2);
    ad.extend_from_slice(DS_SEAL);
    ad.extend_from_slice(&vault.version.to_be_bytes());

    let m_bytes = ChaCha20Poly1305::open(k, &vault.ciphertext, &ad)
        .map_err(|e| AppError::Unauthorized(format!("vault open (retained key): {}", e)))?;
    let m = ProtectedState::from_canonical(&m_bytes)
        .map_err(|e| AppError::Internal(format!("protected-state parse: {}", e)))?;
    VaultPlaintextView::from_protected_state(&m)
}

fn redeemed_zeroize_marker() -> std::marker::PhantomData<WebAuthn> {
    std::marker::PhantomData
}

// ─────────────────────────────────────────────────────────────────────────
// PER-ITEM READ PATH  (PER_ITEM_SYNC.md §11.B step 2 / build contract §4)
//
// In the per-item world the KEYSET (registry + credentials + wrapped_key)
// still hands you `K` via a grant's W_c — exactly the first half of sudp's
// `open()` — but there is no whole-blob `ciphertext` to open; the content is
// N sealed item rows instead. So the read path splits into two steps:
//   1. `unwrap_k_from_keyset` — the credential-unwrap half of sudp's `open`
//      (lines 34-51 of sudp `phases::consumption::open`), reproduced here so
//      we get `K` WITHOUT needing a body ciphertext.
//   2. `PerItemVault::fold_view(K)` — unseal every item row → the same
//      `VaultPlaintextView` the whole-blob path produced, so every downstream
//      consumer (bootstrap_cache_from_view, resolve_value_async, Export map)
//      is byte-for-byte unchanged.
// ─────────────────────────────────────────────────────────────────────────

/// Unwrap the vault state key `K` from a keyset credential using a grant's
/// `W_c` — the credential-unwrap half of sudp's [`open`](sudp::phases::consumption::open),
/// with no body ciphertext required. `wrapping_key` = the 32-byte `W_c` the
/// grant carries (already HPKE-opened by the caller for the web/op-relay path).
///
/// Returns `K` in a [`zeroize::Zeroizing`] so it wipes on drop. `Unauthorized`
/// if the credential isn't in the keyset or `W_c` doesn't unwrap it.
pub fn unwrap_k_from_keyset(
    keyset: &crate::storage::sealed_vault::Keyset,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use sudp::primitives::{Aead, ChaCha20Poly1305, KeyWrap as _KeyWrap, WrapBinding};
    type Wrap = <StdPrimitives as sudp::primitives::PrimitiveSuite>::Wrap;

    let entry = keyset
        .credentials
        .iter()
        .find(|c| c.credential_id == credential_id_bytes)
        .ok_or_else(|| AppError::Unauthorized("unknown credential for keyset unwrap".into()))?;
    let binding = WrapBinding {
        credential_id: credential_id_bytes,
        version: keyset.version,
    };
    let k_bytes = Wrap::unwrap(wrapping_key, &entry.wrapped_key, &binding)
        .map_err(|_| AppError::Unauthorized("keyset K unwrap failed".into()))?;
    if k_bytes.len() != ChaCha20Poly1305::KEY_LEN {
        return Err(AppError::Unauthorized("unwrapped K wrong length".into()));
    }
    Ok(zeroize::Zeroizing::new(k_bytes))
}

/// Blinded item ids of the owner-only config aux items under this vault's `K`
/// — the owner lock list the backend write-gates (team §5.15). `aux:*`
/// addressing. Non-secret by design (the aux-id registration decision):
/// naming WHICH ids are config reveals category, never content. Includes
/// `members` (owner-managed: only owners approve joins / change roles), so a
/// member can't rewrite the roster. `agents` is NOT here — each agent mask is
/// its own `aux:agent/<id>` item, member-edited (edit tier); its per-author
/// gate is a T2 concern (needs the agent-id→member registration).
fn config_aux_item_ids(k: &[u8], vault_id: &str) -> Result<Vec<String>> {
    use crate::storage::item::ItemNs;
    let _ = vault_id;
    ["policy", "stores", "store_order", "audit_retention_days", "services", "members"]
        .into_iter()
        .map(|name| crate::storage::item::item_id::<StdPrimitives>(k, ItemNs::Aux.as_str(), name))
        .collect()
}

/// Per-item analogue of [`decrypt_vault_view`]: unwrap `K` from the keyset via
/// the grant, then fold all live item rows into a [`VaultPlaintextView`]. Used
/// by the per-item Export path. Discards `K` after the fold (read-only).
pub fn decrypt_vault_view_peritem(
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &crate::storage::sealed_vault::PerItemVault,
    vault_id: &str,
) -> Result<VaultPlaintextView> {
    let k = unwrap_k_from_keyset(&vault.keyset, wrapping_key, credential_id_bytes)?;
    vault.fold_view::<StdPrimitives>(&k, vault_id)
}

/// Per-item analogue of [`decrypt_vault_view_keep_key`]: like
/// [`decrypt_vault_view_peritem`] but RETAINS `K` (zeroized on drop) so the
/// caller can hold it for the unlocked session (cache refresh, later per-item
/// writes) without a second passkey. Used by the per-item unlock / write /
/// enroll auto-unlock paths.
pub fn decrypt_vault_view_peritem_keep_key(
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: &crate::storage::sealed_vault::PerItemVault,
    vault_id: &str,
) -> Result<(VaultPlaintextView, zeroize::Zeroizing<Vec<u8>>)> {
    let k = unwrap_k_from_keyset(&vault.keyset, wrapping_key, credential_id_bytes)?;
    let view = vault.fold_view::<StdPrimitives>(&k, vault_id)?;
    Ok((view, k))
}

/// Fold a per-item vault into a [`VaultPlaintextView`] with a RETAINED `K`
/// (no grant, no passkey) — the per-item analogue of
/// [`decrypt_vault_view_with_key`], used by the cloud-sync post-pull refresh.
/// `Err` if `K` can't unseal a row (rotated `K`), which callers treat as the
/// graceful "lock+unlock to see new state".
pub fn decrypt_vault_view_peritem_with_key(
    k: &[u8],
    vault: &crate::storage::sealed_vault::PerItemVault,
    vault_id: &str,
) -> Result<VaultPlaintextView> {
    vault.fold_view::<StdPrimitives>(k, vault_id)
}

/// THE per-item read seam for the live grant paths (Export / Use / unlock).
///
/// Prefer the per-item store: if `vaults/{vid}/vault.per-item.json` exists,
/// unwrap `K` from its keyset via the grant and [`fold_view`] the item rows.
/// Otherwise fall back to the whole-blob open (the paths not yet cut over —
/// notably a browser Write that only re-sealed `vault.dat`; stubbed[]).
///
/// One call site for every read so the two formats can't diverge in what a
/// grant resolves. Returns the `VaultPlaintextView` the whole downstream
/// (resolve_value_async, Export map, bootstrap_cache) already consumes.
pub fn open_view_for_grant(
    state: &AppState,
    vault_id: &str,
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: Option<&crate::storage::SealedVault>,
) -> Result<VaultPlaintextView> {
    if let Ok(path) = state.vaults.per_item_path(vault_id) {
        if let Ok(Some(pv)) = crate::storage::sealed_vault::read_per_item(&path) {
            return decrypt_vault_view_peritem(wrapping_key, credential_id_bytes, &pv, vault_id);
        }
    }
    // Whole-blob fallback — only vaults that still have a vault.dat (daemon-side
    // Enroll/Write) reach here; a web-enrolled per-item vault is served above.
    let vault = vault.ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
    decrypt_vault_view(op, wrapping_key, credential_id_bytes, vault)
}

/// Like [`open_view_for_grant`] but RETAINS `K` for the unlocked session — the
/// per-item seam for the unlock ceremony (which caches under the retained key).
pub fn open_view_for_grant_keep_key(
    state: &AppState,
    vault_id: &str,
    op: &Operation,
    wrapping_key: &[u8],
    credential_id_bytes: &[u8],
    vault: Option<&crate::storage::SealedVault>,
) -> Result<(VaultPlaintextView, zeroize::Zeroizing<Vec<u8>>)> {
    if let Ok(path) = state.vaults.per_item_path(vault_id) {
        if let Ok(Some(mut pv)) = crate::storage::sealed_vault::read_per_item(&path) {
            let (view, k) = decrypt_vault_view_peritem_keep_key(
                wrapping_key,
                credential_id_bytes,
                &pv,
                vault_id,
            )?;
            // Shared vault: queue the owner lock-list registration — the
            // blinded ids of the config aux items the backend write-gates as
            // owner-only (team §5.15). The sync loop delivers it once. NOTE:
            // T1 keeps config at LEGACY `aux:<name>` addressing (the console
            // still reads/writes it), so the gated ids are the `aux:*` ids,
            // NOT the not-yet-active unified per-ns ids. The unified-addressing
            // cutover (§8.3) is a LATER coordinated core+console release; the
            // ItemNs variants + fold dual-read are in place for it but nothing
            // writes them or runs the migration yet.
            if !view.aux.members.is_empty() {
                if let Ok(ids) = config_aux_item_ids(&k, vault_id) {
                    state
                        .pending_config_ids
                        .lock()
                        .unwrap()
                        .insert(vault_id.to_string(), ids);
                }
            }
            return Ok((view, k));
        }
    }
    // Whole-blob fallback — see open_view_for_grant.
    let vault = vault.ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
    decrypt_vault_view_keep_key(op, wrapping_key, credential_id_bytes, vault)
}

/// Open the vault body to the RAW [`sudp::state::ProtectedState`] with a
/// RETAINED state key `K` — no grant, no passkey. Unlike
/// [`decrypt_vault_view_with_key`] (which projects to a read-only
/// `VaultPlaintextView`), this returns the full mutable `ProtectedState` so a
/// caller can edit `targets` and re-seal it with [`reseal_body_with_key`]
/// while preserving `peers`/`aux` byte-for-byte. Used by the OAuth-connect
/// processor (CONNECTIONS_AND_AUTH.md §4a), which writes
/// `<conn>_refresh_token` into the open vault and deletes the pending item —
/// the daemon's own connect-completion, no approval op (it holds `K` while
/// unlocked; an agent can't forge a Google login + a passkey-sealed code).
pub fn open_protected_state_with_key(
    k: &[u8],
    vault: &crate::storage::SealedVault,
) -> Result<sudp::state::ProtectedState> {
    use sudp::primitives::domain::DS_SEAL;
    use sudp::primitives::{Aead, ChaCha20Poly1305};
    use sudp::state::ProtectedState;

    let mut ad = Vec::with_capacity(DS_SEAL.len() + 2);
    ad.extend_from_slice(DS_SEAL);
    ad.extend_from_slice(&vault.version.to_be_bytes());

    let m_bytes = ChaCha20Poly1305::open(k, &vault.ciphertext, &ad)
        .map_err(|e| AppError::Unauthorized(format!("vault open (retained key): {}", e)))?;
    ProtectedState::from_canonical(&m_bytes)
        .map_err(|e| AppError::Internal(format!("protected-state parse: {}", e)))
}

/// Re-seal a (possibly mutated) [`sudp::state::ProtectedState`] under the same
/// retained `K` and write the new body ciphertext into `vault.ciphertext`,
/// leaving `registry`/`credentials`/`wrapped_key` untouched (the body is
/// sealed under `K` with AAD `DS_SEAL ‖ ver`, independent of any credential —
/// see [`decrypt_vault_view_with_key`]). The caller persists the updated
/// `vault` via `write_atomic`. Companion to [`open_protected_state_with_key`].
pub fn reseal_body_with_key(
    k: &[u8],
    vault: &mut crate::storage::SealedVault,
    m: &sudp::state::ProtectedState,
) -> Result<()> {
    use sudp::primitives::domain::DS_SEAL;
    use sudp::primitives::{Aead, ChaCha20Poly1305};

    let mut ad = Vec::with_capacity(DS_SEAL.len() + 2);
    ad.extend_from_slice(DS_SEAL);
    ad.extend_from_slice(&vault.version.to_be_bytes());

    let canonical = m
        .to_canonical()
        .map_err(|e| AppError::Internal(format!("protected-state canonicalize: {}", e)))?;
    let ciphertext = ChaCha20Poly1305::seal(k, &canonical[..], &ad)
        .map_err(|e| AppError::Internal(format!("vault re-seal: {}", e)))?;
    vault.ciphertext = ciphertext;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::plaintext::VaultAux;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use sudp::primitives::domain::DS_SEAL;
    use sudp::primitives::{Aead, ChaCha20Poly1305};
    use sudp::state::{ProtectedState, CURRENT_VERSION};

    /// The retained-K refresh path: a vault's body is K-sealed with AAD
    /// `DS_SEAL ‖ ver`, independent of any credential, so a held `K` opens it
    /// with NO grant/passkey. This builds a real v3 ProtectedState, seals it
    /// under K exactly as the vault does, and asserts `decrypt_vault_view_with_key`
    /// recovers the target with the right K and rejects a wrong K (the graceful
    /// "rotated K → lock+unlock" path). Guards the seal_ad reconstruction.
    #[test]
    fn retained_key_opens_body_without_credential() {
        let k = vec![9u8; 32];
        let version: u16 = CURRENT_VERSION;

        let mut ps = ProtectedState::new();
        ps.aux = serde_json::to_value(VaultAux::initial()).unwrap();
        ps.put_secret("openai_key", b"sk-test-123".to_vec());
        let canonical = ps.to_canonical().unwrap();

        let mut ad = Vec::new();
        ad.extend_from_slice(DS_SEAL);
        ad.extend_from_slice(&version.to_be_bytes());
        let ciphertext = ChaCha20Poly1305::seal(&k, &canonical[..], &ad).unwrap();

        // Empty registry/credentials — the body opens independent of any cred.
        let vault: crate::storage::SealedVault = serde_json::from_value(serde_json::json!({
            "version": version,
            "registry": {},
            "credentials": [],
            "ciphertext": STANDARD.encode(&ciphertext),
        }))
        .unwrap();

        let view = decrypt_vault_view_with_key(&k, &vault).expect("retained-K open");
        assert_eq!(
            view.native_secrets.get("openai_key").map(|v| v.as_slice()),
            Some(b"sk-test-123".as_ref())
        );

        // Wrong K (the rotated-K case) → AEAD open fails → Err (graceful).
        assert!(decrypt_vault_view_with_key(&vec![1u8; 32], &vault).is_err());
    }
}
