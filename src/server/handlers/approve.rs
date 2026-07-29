//! `/op/{op_id}` family — op lifecycle (poll, approve, reject).
//!
//! - `GET  /op/{op_id}`            — poll: status + cached value + render(o)
//! - `POST /op/{op_id}/approve`    — U submits grant G; T validates, dispatches act
//! - `POST /op/{op_id}/reject`     — U denies
//!
//! All act kinds (Enroll, Write, Export, Use) flow through `approve_op`; the
//! act-specific dispatch is inlined per the SUDP protocol.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroize as _;

use axum::{
    extract::{Path, State},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};

/// HPKE `info` prefix for the pending-passkey deposit seal. The full info
/// string is `PENDING_PASSKEY_INFO_PREFIX ‖ vault_id ‖ 0x1F ‖ cid_new` —
/// binding the seal to (vault, cid) so a deposit prepared for one pairing
/// can't be opened against another. Frontend builds the same string in
/// `lib/passkey-vault-primitive.ts`.
const PENDING_PASSKEY_INFO_PREFIX: &[u8] = b"safeclaw/v1/pending-passkey";
use serde_json::{json, Value};

use crate::approval::ApprovalStatus;
use crate::audit::{STATUS_APPROVED, STATUS_REJECTED};
use crate::error::{AppError, Result};
use crate::passkey::PasskeyEntry;
use crate::protocol::operation::{
    as_enroll_credential, as_export_path, as_write_patch, decode_credential_id, discriminator,
    ActType,
};
use crate::protocol::{render_operation, validate_grant, Grant};
use crate::server::handlers::metadata::decrypt_vault_view_keep_key;
use crate::state::{AppState, ApprovalEvent, SecretsCache};
use crate::storage::plaintext::{Category, VaultPlaintextView};
use crate::storage::sealed_vault::{
    build_initial, find_pubkey, find_pubkey_in_registry, read as read_vault, read_per_item,
    replace_after_write, write_atomic,
};

/// `GET /op/{op_id}` — JSON poll: status + cached value + render(o).
///
/// The agent (and the CLI's browser-callback flow) polls this for the op's
/// state. There is no HTML branch: the human approves on safeclaw.pro (the
/// op-relay carries the sealed grant back to the daemon), so the daemon serves
/// no approval page of its own (2026-06-23 zero-inbound pivot).
pub async fn get_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match get_op_json(state, op_id).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

async fn get_op_json(state: Arc<AppState>, op_id: String) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;
    let body = op_poll_value(&state, &op_id)?;
    let pending = body.get("status").and_then(|s| s.as_str()) == Some("pending");
    let mut resp = Json(body).into_response();
    // Pending → advertise the poll pacing (Retry-After, matching the 202's
    // `approval.interval`) so agents keep a standard cadence.
    if pending {
        if let Ok(v) = axum::http::HeaderValue::from_str(
            &crate::approval::store::POLL_INTERVAL_HINT_SECS.to_string(),
        ) {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, v);
        }
    }
    Ok(resp)
}

/// The `/op/{id}` poll body as a plain `Value`. Shared by the axum handler
/// (above) and the 23294 API face (`proxy::api_face`), so the agent's poll loop
/// sees identical JSON whether it hit the control plane or the proxy port. Pure
/// read — briefly locks `approvals`, no I/O.
pub fn op_poll_value(state: &AppState, op_id: &str) -> Result<Value> {
    let mut store = state.approvals.lock().unwrap();
    let rec = store.get(op_id).ok_or(AppError::NotFound)?;
    // Consumed ops: the approve window is closed. Return a minimal tombstone
    // — no op content — to limit the exposure window for the agent request
    // body and upstream URL that live in op.act.scope. The op_id's 122-bit
    // entropy is the access-control mechanism for in-flight ops; once the
    // op is consumed, that window should close.
    if matches!(rec.status, ApprovalStatus::Consumed) {
        return Ok(json!({
            "op_id": rec.id,
            "status": "consumed",
        }));
    }

    let act_kind = discriminator(&rec.op.act);
    let display = render_operation(&rec.op);
    let path = match &rec.op.act.kind {
        ActType::Export => Some(rec.op.act.target.clone()),
        _ => None,
    };
    let op_json = serde_json::to_value(&rec.op)?;
    // Whether this op reveals a raw secret (Export). Its plaintext must be
    // SINGLE-USE: handed to the one poll that delivers it, then tombstoned —
    // `sc secret get`'s remote arm reads `value` from exactly this poll, and the
    // op was minted `multiplicity: one`. Leaving it re-readable let a co-resident
    // process re-fetch the secret for the op's whole TTL.
    let is_export = matches!(rec.op.act.kind, ActType::Export);
    let id = rec.id.clone();
    let r = rec.r.clone();
    let expires_at_unix = rec.expires_at_unix;
    let (status, value) = match &rec.status {
        ApprovalStatus::Pending => ("pending", None),
        // "ok" is the skill-documented terminal (done — result in `value`). The
        // internal enum stays `Approved`; only the wire status is normalized so
        // the agent's poll loop (`ok`/`pending`/`rejected`) recognizes completion.
        //
        // `value` shape by act: a Use caches the upstream envelope as a JSON
        // string — emit it as the OBJECT the skill documents ({status, headers,
        // body}), matching the allow fast-path, instead of a double-encoded
        // string agents must re-parse. Export stays a raw string (the plaintext
        // secret is opaque — never parse it, even when it happens to be JSON).
        ApprovalStatus::Approved => {
            let v = rec.cached_value.clone().map(|s| match &rec.op.act.kind {
                ActType::Use => serde_json::from_str::<Value>(&s).unwrap_or(Value::String(s)),
                _ => Value::String(s),
            });
            ("ok", v)
        }
        ApprovalStatus::Rejected { .. } => ("rejected", None),
        ApprovalStatus::Consumed => unreachable!("handled above"),
    };
    // A rejected op's reason distinguishes a USER rejection from a mechanical
    // withdrawal ("superseded by a newer request") — the waiter renders them
    // differently, so a superseded `sc up`/`sc lock` never reads as "the user
    // said no" (it confused exactly that way before this field existed).
    let reason = match &rec.status {
        ApprovalStatus::Rejected { reason } if !reason.is_empty() => Some(reason.clone()),
        _ => None,
    };
    // Consume an Export's plaintext on delivery (single-use). Only Export —
    // a Use result is the agent's own upstream reply, which its poll loop may
    // legitimately re-read; consuming it would break an interrupted retry. The
    // `rec` borrow ends above (everything below is owned), so the &mut is clean.
    if is_export && value.is_some() {
        store.consume(&id);
    }
    Ok(json!({
        "op_id": id,
        "r": r,
        "status": status,
        "reason": reason,
        "act": act_kind,
        "path": path,
        "display": display,
        "op": op_json,
        "value": value,
        "expires_at": expires_at_unix,
    }))
}

/// Best-effort: if the acting credential's stored keyset row carries no KCV yet,
/// compute it from the `W_c` that just unlocked the vault and persist it (then
/// push the keyset row cloud-side so it survives pulls and reaches other
/// devices). Idempotent — a credential that already has a KCV is untouched.
/// Never fatal to the unlock; failures are logged and swallowed. Targets the
/// per-item keyset (the current home); a legacy `vault.dat`-only vault simply
/// skips — the browser falls back to its no-precheck path for KCV-less creds.
fn maybe_backfill_wc_check(state: &Arc<AppState>, vault_id: &str, cid: &[u8], w_c: &[u8]) {
    let Ok(per_item_path) = state.vaults.per_item_path(vault_id) else {
        return;
    };
    let mut pv = match crate::storage::sealed_vault::read_per_item(&per_item_path) {
        Ok(Some(pv)) => pv,
        _ => return, // no per-item keyset (legacy or unreadable) — skip
    };
    let Some(cred) = pv
        .keyset
        .credentials
        .iter_mut()
        .find(|c| c.credential_id == cid)
    else {
        return;
    };
    if cred.wc_check.is_some() {
        return; // already present (freshly enrolled with a KCV, or backfilled)
    }
    let wc = match sudp::primitives::wc_check_value::<sudp::primitives::HkdfSha256>(
        w_c,
        &cred.prf_salt,
        cid,
    ) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(vault = %vault_id, "wc_check backfill KDF failed: {}", e);
            return;
        }
    };
    cred.wc_check = Some(wc.to_vec());
    if let Err(e) = crate::storage::sealed_vault::write_per_item_atomic(&per_item_path, &pv) {
        tracing::warn!(vault = %vault_id, "wc_check backfill write failed: {}", e);
        return;
    }
    tracing::info!(vault = %vault_id, "backfilled wc_check for the acting credential");
    let state = state.clone();
    let vid = vault_id.to_string();
    tokio::spawn(async move {
        crate::sync::push_keys_best_effort(&state, &vid).await;
    });
}

/// Every custom act the dispatch below handles. Keep in lockstep with the
/// `ActType::Custom` match arms — `consent::tests::dispatch_and_table_agree`
/// fails when this list and acts.toml drift in either direction, so an act
/// can't ship without approval copy (and dead copy can't linger).
pub(crate) const DISPATCHED_CUSTOM_ACTS: &[&str] = &[
    "vault-unlock",
    "vault-lock",
    "vault-delete",
    "rename-passkey",
    "widen-host",
    "service-ls",
    "service-rm",
    "service-add",
    "secret-rm",
    "connection-rm",
    "connection-add",
    "secret-set",
];

/// `POST /op/{op_id}/approve` — U submits the signed grant. T validates and
/// dispatches the act (Enroll / Write / Export / Use).
pub async fn approve_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
    Json(mut grant): Json<Grant>,
) -> Result<Json<Value>> {
    // 1. Look up the pending op.
    let (vault_id, approval_op) = {
        let store = state.approvals.lock().unwrap();
        let rec = store.get(&op_id).ok_or(AppError::NotFound)?;
        if !matches!(rec.status, ApprovalStatus::Pending) {
            return Err(AppError::Conflict("op not pending".into()));
        }
        if rec.fail_count >= crate::approval::store::MAX_APPROVE_ATTEMPTS {
            return Err(AppError::TooManyRequests);
        }
        (rec.vault_id.clone(), rec.op.clone())
    };

    // 2. grant.o must equal the stored op (canonical equality).
    let canonical_grant_op = serde_json::to_value(&grant.o)?;
    let canonical_stored_op = serde_json::to_value(&approval_op)?;
    if canonical_grant_op != canonical_stored_op {
        return Err(AppError::BadRequest(
            "grant.o does not match the stored op".into(),
        ));
    }

    // 3. Serialize vault reads/writes per vault (F-17).
    // Two concurrent approve calls on the same vault both read the same
    // on-disk state and race to write_atomic — the second rename wins
    // silently. This per-vault async mutex ensures the full read-validate-
    // write cycle is atomic per vault without blocking unrelated vaults.
    let vault_write_lock = {
        let mut locks = state.vault_write_locks.lock().unwrap();
        Arc::clone(
            locks
                .entry(vault_id.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    };
    let _vault_write_guard = vault_write_lock.lock().await;

    // 3b. Resolve credential pubkey lookup.
    //
    // For Enroll, the credential is brand-new (not in vault yet) — pubkey is
    // taken from the op's scope. For Write/Export/Use, the credential must be
    // already enrolled — look it up in the existing vault.
    let vault_path = state.vaults.vault_path(&vault_id)?;
    let existing_vault = read_vault(&vault_path)?;
    // A web-enrolled vault synced down as per-item rows (vault.per-item.json)
    // has NO vault.dat — its keyset (credential pubkeys) lives in the per-item
    // store. Read it once so credential lookup + the read grants (Unlock / Use /
    // Export) below work for those vaults too.
    let existing_per_item = state
        .vaults
        .per_item_path(&vault_id)
        .ok()
        .and_then(|p| read_per_item(&p).ok().flatten());
    let lookup_credential = |cred_id_b64: &str| -> Option<PasskeyEntry> {
        existing_vault
            .as_ref()
            .and_then(|v| find_pubkey(v, cred_id_b64))
            .or_else(|| {
                existing_per_item
                    .as_ref()
                    .and_then(|pv| find_pubkey_in_registry(&pv.keyset.registry, cred_id_b64))
            })
    };
    // 3c. HPKE-unseal W_c if the grant carries a sealed wrapping key (the web /
    // op-relay path). The browser sealed W* to our `sc_pk` with
    // `info = grant_seal_info(op_id)` so any cloud intermediary carrying the
    // grant never saw W*. Populate `grant.wrapping_key` with the opened bytes
    // so the rest of validation is identical to the legacy plaintext path.
    // (Legacy local op-page ships plaintext `wrapping_key` and skips this.)
    if grant.wk_enc.is_some() || grant.wk_ct.is_some() {
        let enc_b64 = grant.wk_enc.as_deref().ok_or_else(|| {
            AppError::BadRequest(
                "sealed wrapping key needs both wk_enc and wk_ct (wk_enc missing)".into(),
            )
        })?;
        let ct_b64 = grant.wk_ct.as_deref().ok_or_else(|| {
            AppError::BadRequest(
                "sealed wrapping key needs both wk_enc and wk_ct (wk_ct missing)".into(),
            )
        })?;
        let enc = URL_SAFE_NO_PAD
            .decode(enc_b64)
            .map_err(|_| AppError::BadRequest("wk_enc not base64url".into()))?;
        let ct = URL_SAFE_NO_PAD
            .decode(ct_b64)
            .map_err(|_| AppError::BadRequest("wk_ct not base64url".into()))?;
        let info = crate::crypto::envelope::grant_seal_info(&op_id);
        let wk = state.sc.open(&enc, &ct, &info, b"")?;
        if wk.len() != 32 {
            return Err(AppError::BadRequest(
                "sealed wrapping_key must be 32 bytes".into(),
            ));
        }
        grant.wrapping_key = Some(STANDARD.encode(&wk));
    }

    let mut validated = {
        let result = {
            let mut chs = state.challenges.lock().unwrap();
            validate_grant(
                &grant,
                &mut chs,
                &state.config.origin,
                &state.config.rp_id,
                lookup_credential,
            )
        };
        match result {
            Ok(v) => v,
            Err(e) => {
                // Track failure; auto-reject op if limit reached.
                let auto_rejected = state.approvals.lock().unwrap().record_failure(&op_id);
                if auto_rejected {
                    tracing::warn!(op = %op_id, "op auto-rejected after too many failed approve attempts");
                }
                return Err(e);
            }
        }
    };

    // 3b. Verify bind.redeemer matches the vault this op was created for.
    // SUDP §4 binds an op to a specific custodian/vault via bind.redeemer;
    // failing to check this would let a grant authorized for vault A be
    // submitted against vault B's approve endpoint.
    if validated.op.bind.redeemer != vault_id {
        return Err(AppError::Unauthorized(
            "grant.o.bind.redeemer does not match vault".into(),
        ));
    }

    // 4. Act dispatch — same logic that previously lived in grant.rs.
    // Captured here for the audit row finalize at the bottom (Use's upstream
    // status code; None for all other act kinds).
    let audit_upstream_status: Option<i64> = None;
    let (response, cached_value) = match &validated.op.act.kind {
        ActType::Enroll if validated.op.act.target == "passkeys" => {
            // Add-passkey-to-existing-vault path. PROTOCOL.md §3.4 maps
            // `target = "passkeys"` to "register a new credential against
            // the already-enrolled vault". K stays the same (no state-key
            // rotation), but a new SealedCredential entry gets appended
            // with K wrapped under the new credential's W_c.
            //
            // Same- and cross-device add-passkey both go through the
            // pending-passkey deposit (`storage::pending_passkey`):
            //   - Stage 1 (any device with the new credential): POST
            //     /v/{vid}/pending-passkeys with HPKE-sealed user_key_initial.
            //   - Stage 2 (any device with an existing vault-enrolled
            //     credential, possibly the same device): this op, with
            //     `scope.new = { credential_id }` referring to the pending.
            //
            // grant.opt is NOT consulted — the new credential's W_c lives
            // exclusively in the daemon-stored pending-passkey blob.
            let vault = existing_vault.clone().ok_or_else(|| {
                AppError::Conflict("vault not initialized — first-time enroll required".into())
            })?;
            // scope.new should just carry { credential_id } — that's the
            // pointer to the pending-passkey file. No public-key / W_c
            // material inline.
            let new_cid_str = validated
                .op
                .act
                .scope
                .get("new")
                .and_then(|n| n.get("credential_id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AppError::BadRequest("add-passkey: scope.new.credential_id required".into())
                })?
                .to_string();
            // Pop the pending file (single-use, deleted on read).
            let pending = crate::storage::pending_passkey::load_and_consume(
                &state.vaults,
                &vault_id,
                &new_cid_str,
            )
            .map_err(|_| AppError::NotFound)?;
            // HPKE-open the sealed user_key_initial with daemon's sc_sk.
            // info binds the seal to (vault_id, cid) — the Stage 1 device
            // committed to those at seal time, so a deposit prepared for
            // (vault_A, cidA) can't be replayed against a different vault
            // or cid.
            let enc = URL_SAFE_NO_PAD
                .decode(&pending.enc)
                .map_err(|_| AppError::BadRequest("pending.enc not base64url".into()))?;
            let ct = URL_SAFE_NO_PAD
                .decode(&pending.ct)
                .map_err(|_| AppError::BadRequest("pending.ct not base64url".into()))?;
            let mut info: Vec<u8> = Vec::with_capacity(
                PENDING_PASSKEY_INFO_PREFIX.len() + vault_id.len() + new_cid_str.len() + 2,
            );
            info.extend_from_slice(PENDING_PASSKEY_INFO_PREFIX);
            info.extend_from_slice(vault_id.as_bytes());
            info.push(0x1f); // unit separator
            info.extend_from_slice(new_cid_str.as_bytes());
            let new_w_c = state.sc.open(&enc, &ct, &info, b"")?;
            if new_w_c.len() != 32 {
                return Err(AppError::BadRequest(
                    "sealed user_key_initial must be 32 bytes after open".into(),
                ));
            }
            // Open the vault to recover K. We deliberately don't reuse
            // decrypt_vault_view here because we need K itself, not the
            // ProtectedState view.
            // F-05: move W_c bytes into RedeemedGrant instead of cloning so
            // there is only one copy of the key on the heap at a time.
            let redeemed = sudp::grant::RedeemedGrant {
                o: validated.op.clone(),
                credential_id: validated.credential_id_bytes.clone(),
                wrapping_key: sudp::grant::WrappingKey::from_bytes(std::mem::take(
                    &mut validated.wrapping_key,
                )),
                opt: sudp::grant::GrantOpt::default(),
            };
            let opened = sudp::phases::consumption::open::<sudp::primitives::StdPrimitives>(
                &redeemed, &vault,
            )
            .map_err(|e| AppError::Unauthorized(format!("vault open: {}", e)))?;
            // Wrap K under the new W_c with sudp's canonical wrap primitive.
            use sudp::primitives::{KeyWrap as _KeyWrap, WrapBinding};
            type Wrap = <sudp::primitives::StdPrimitives as sudp::primitives::PrimitiveSuite>::Wrap;
            let new_cid_bytes = decode_credential_id(&new_cid_str)?;
            if vault.find_credential(&new_cid_bytes).is_some() {
                return Err(AppError::Conflict(
                    "credential already enrolled on this vault".into(),
                ));
            }
            let binding = WrapBinding {
                credential_id: &new_cid_bytes,
                version: vault.version,
            };
            let wrapped_for_new = Wrap::wrap(&new_w_c, &opened.k[..], &binding)
                .map_err(|e| AppError::Internal(format!("wrap K under new W_c: {}", e)))?;
            let new_prf_salt = STANDARD
                .decode(&pending.prf_salt)
                .map_err(|_| AppError::BadRequest("prf_salt not base64".into()))?;
            // Key-check value for the new credential, computed while W_c is still
            // live: it lets a browser confirm a re-derived W_c before depositing
            // a grant, WITHOUT unwrapping K. Then W_c is done — zeroize it.
            let new_wc_check = sudp::primitives::wc_check_value::<sudp::primitives::HkdfSha256>(
                &new_w_c,
                &new_prf_salt,
                &new_cid_bytes,
            )
            .map_err(|e| AppError::Internal(format!("wc_check: {}", e)))?;
            let mut new_w_c = new_w_c;
            new_w_c.zeroize();
            // Append to credentials + registry, using the (x, y, prf_salt,
            // device_name) we just popped from the pending file.
            let mut updated = vault.clone();
            updated.credentials.push(sudp::state::SealedCredential {
                credential_id: new_cid_bytes.clone(),
                prf_salt: new_prf_salt,
                wrapped_key: wrapped_for_new,
                wc_check: Some(new_wc_check.to_vec()),
            });
            let pk = sudp::passkey::WebAuthnPublicKey {
                x: pending.x,
                y: pending.y,
                device_name: pending.device_name,
            };
            updated
                .registry
                .insert::<sudp::passkey::WebAuthn>(&new_cid_bytes, &pk)
                .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;
            write_atomic(&vault_path, &updated)?;
            tracing::info!(
                vault = %vault_id,
                cred_count = updated.credentials.len(),
                "vault add-passkey applied (pending-passkey consumed)"
            );
            (
                json!({ "ok": true, "act": "enroll", "target": "passkeys" }),
                None,
            )
        }
        ActType::Enroll => {
            let credential = as_enroll_credential(&validated.op)?;
            if existing_vault.is_some() {
                return Err(AppError::Conflict(
                    "vault already initialized for this vault_id".into(),
                ));
            }
            let payload = grant
                .setup_payload
                .as_ref()
                .ok_or_else(|| AppError::BadRequest("enroll grant missing setup_payload".into()))?;
            let cid_bytes = decode_credential_id(&credential.credential_id)?;
            let prf_salt = STANDARD
                .decode(&credential.prf_salt)
                .map_err(|_| AppError::BadRequest("prf_salt not base64".into()))?;
            let wrapped_key = STANDARD
                .decode(&payload.wrapped_key)
                .map_err(|_| AppError::BadRequest("wrapped_key not base64".into()))?;
            let ciphertext = STANDARD
                .decode(&payload.ciphertext)
                .map_err(|_| AppError::BadRequest("ciphertext not base64".into()))?;
            let vault = build_initial(
                cid_bytes,
                credential.public_key_x,
                credential.public_key_y,
                credential.device_name,
                prf_salt,
                wrapped_key,
                ciphertext,
            )?;
            state.vaults.ensure_dir(&vault_id)?;
            write_atomic(&vault_path, &vault)?;
            tracing::info!(vault = %vault_id, "vault enroll complete");
            // Auto-unlock after Enroll: the user just proved their passkey,
            // and we already hold W_c. Bootstrapping the cache inline here
            // saves /try (and any first-time-setup flow) a second passkey
            // ceremony before the agent's first /use call. Best-effort — a
            // bootstrap failure leaves the vault Locked (user can manually
            // unlock later) rather than failing the enroll.
            if let Ok((view, k)) = decrypt_vault_view_keep_key(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                &vault,
            ) {
                // PER-ITEM: seed the local per-item store from the just-enrolled
                // ProtectedState. The browser still hands ONE sealed ciphertext
                // at enroll; the daemon re-shards it into N `seal_record` item
                // rows under the SAME K, so the per-item read path (Use/Export/
                // unlock) can serve from items. Best-effort: a failure leaves
                // only the whole-blob vault.dat, which the read paths still fall
                // back to (stubbed[]).
                seed_per_item_store(&state, &vault_id, &vault, &view, &k);
                let cache = bootstrap_cache_from_view(&view, &state);
                tracing::info!(
                    vault = %vault_id,
                    cached_services = cache.entries.len(),
                    "vault auto-unlocked after enroll"
                );
                state.unlock_vault(vault_id.clone(), cache, k);
            }
            (
                json!({ "ok": true, "vault_id": vault_id, "act": "enroll" }),
                None,
            )
        }
        ActType::Write => {
            let patch = as_write_patch(&validated.op)?;
            let mut vault = existing_vault
                .clone()
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            let new_prf_salt = STANDARD
                .decode(&patch.prf_salt_next)
                .map_err(|_| AppError::BadRequest("prf_salt_next not base64".into()))?;
            let new_wrapped_key = STANDARD
                .decode(&patch.wrapped_key)
                .map_err(|_| AppError::BadRequest("wrapped_key not base64".into()))?;
            let new_ciphertext = STANDARD
                .decode(&patch.ciphertext)
                .map_err(|_| AppError::BadRequest("ciphertext not base64".into()))?;
            replace_after_write(
                &mut vault,
                &grant.credential_id,
                new_prf_salt,
                new_wrapped_key,
                new_ciphertext,
            )?;
            write_atomic(&vault_path, &vault)?;
            tracing::info!(vault = %vault_id, "vault write applied");
            // Auto-refresh cache from the new ciphertext using the same
            // wrapping_key the grant carries (Write doesn't rotate W_c
            // unless paired with a passkey op). Without this, the
            // daemon's `entries` / `native_keys` / `external_stores`
            // snapshots stay stuck on the pre-Write state until the
            // user manually locks + unlocks — most visible symptom is
            // a freshly-Connected GCP store whose `list()` keys never
            // surface in /v/{vid}/secret-keys. Best-effort: a rotation-
            // case decrypt failure leaves the cache stale but doesn't
            // fail the Write.
            if state.is_vault_locked(&vault_id) {
                // Vault was Locked when this Write arrived. Don't
                // auto-unlock from a Write — the user expects unlock
                // to be a deliberate ceremony.
            } else if let Ok((view, k)) = decrypt_vault_view_keep_key(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                &vault,
            ) {
                // PER-ITEM: re-shard the post-write ProtectedState into the local
                // per-item store (same K). A browser Write still ships one sealed
                // ciphertext; re-seeding keeps the item rows in step so a later
                // per-item push/pull carries the change. Best-effort. NOTE: this
                // re-derives EVERY item at version 1 rather than diffing to the
                // changed item(s) + bumping only those — a proper per-item PUT
                // diff (contract §3) is stubbed[] pending the browser cut-over.
                seed_per_item_store(&state, &vault_id, &vault, &view, &k);
                let cache = bootstrap_cache_from_view(&view, &state);
                tracing::info!(
                    vault = %vault_id,
                    cached_services = cache.entries.len(),
                    external_stores = cache.external_stores.len(),
                    "vault cache re-bootstrapped after write"
                );
                state.unlock_vault(vault_id.clone(), cache, k);
            } else {
                tracing::warn!(
                    vault = %vault_id,
                    "post-write cache refresh skipped — decrypt failed (rotation?); user must lock+unlock to see new state",
                );
            }
            // A Write may have sealed a `<conn>_oauth_pending` from a browser
            // "Connect" — complete the OAuth code→token exchange NOW instead of
            // waiting for the next unlock or cloud-sync pull (the symptom this
            // fixes: the web UI sticks on "Connecting…" after paste because the
            // Write path never kicked the exchange). CONNECTIONS_AND_AUTH.md §4a.
            // Detached + best-effort: process_vault_connects acquires the
            // per-vault write lock itself (not reentrant, so it must run AFTER
            // this handler's guard drops) and no-ops if the vault is locked.
            {
                let state = state.clone();
                let vid = vault_id.clone();
                tokio::spawn(async move {
                    // A daemon-side Write rotated the acting credential's
                    // prf_salt/wrapped_key (replace_after_write) and re-sharded
                    // the content. Propagate BOTH ahead of the cloud so OTHER
                    // devices can still unwrap K and see the new content: the
                    // keyset rides `/keys`, the content rides `/items`. Both are
                    // best-effort + never clobber (409 → adopt cloud, stop).
                    crate::sync::push_keys_best_effort(&state, &vid).await;
                    crate::sync::push_items_best_effort(&state, &vid).await;
                    crate::auth::connect::process_vault_connects(&state, &vid, None).await;
                });
            }
            (json!({ "ok": true, "act": "write" }), None)
        }
        ActType::Revoke => {
            // Remove-passkey. `target = "passkeys.<cid_b64>"`. K stays
            // the same — we only drop the named credential's SealedCredential
            // entry and Registry record. At-least-one safeguard prevents
            // locking the user out of their own vault.
            //
            // Acting credential CAN revoke itself (matches per-VM and 1P
            // behavior — user might want to remove a compromised device).
            // The at-least-one safeguard still catches "revoking the only
            // remaining credential".
            let target = validated.op.act.target.as_str();
            let cid_b64 = target.strip_prefix("passkeys.").ok_or_else(|| {
                AppError::BadRequest("revoke target must be 'passkeys.<credential_id>'".into())
            })?;
            let mut vault = existing_vault
                .clone()
                .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
            if vault.credentials.len() <= 1 {
                return Err(AppError::BadRequest(
                    "cannot remove the last passkey — add another one first".into(),
                ));
            }
            let cid_bytes = decode_credential_id(cid_b64)?;
            if vault.find_credential(&cid_bytes).is_none() {
                return Err(AppError::BadRequest(
                    "target credential not enrolled on this vault".into(),
                ));
            }
            vault.credentials.retain(|c| c.credential_id != cid_bytes);
            vault.registry.remove(&cid_bytes);
            write_atomic(&vault_path, &vault)?;
            tracing::info!(
                vault = %vault_id,
                cred_count = vault.credentials.len(),
                "vault revoke-passkey applied"
            );
            (
                json!({ "ok": true, "act": "revoke", "target": target }),
                None,
            )
        }
        ActType::Export => {
            // F-15: reject KEM-sealed Export until it is implemented.
            // If a client submits a grant with bind.recipient set, the raw-reveal
            // path would silently ignore it and return the secret in plain TLS.
            // Block this until a proper HPKE-sealed Export path is available.
            if validated.op.bind.recipient.is_some() {
                return Err(AppError::BadRequest(
                    "KEM-sealed Export not yet implemented; omit bind.recipient".into(),
                ));
            }
            let path = as_export_path(&validated.op)?;
            // Read seam: per-item store first, whole-blob vault.dat as fallback
            // (Option — a web-enrolled per-item vault has no vault.dat).
            let view = crate::server::handlers::metadata::open_view_for_grant(
                &state,
                &vault_id,
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                existing_vault.as_ref(),
            )?;

            // RETIRED: whole-vault reveal-all (`target = "env"` / "").
            // An Export must name ONE secret so its plaintext egress stays
            // scope-constrained (and single-use). The console editor no longer
            // uses a daemon reveal-all — it derives its `{kv, aux}` view
            // client-side (`revealAllVault = unlockVault`), and `sc secret get`
            // always names a specific key. Refuse the unbounded form outright so
            // no path can dump the whole vault's plaintext through one op.
            if path == "env" || path.is_empty() {
                return Err(AppError::BadRequest(
                    "reveal-all export is retired — export a specific secret by name".into(),
                ));
            }
            {
                let raw = view
                    .resolve_value_async(path)
                    .await?
                    .ok_or(AppError::NotFound)?;
                let value = String::from_utf8(raw)
                    .map_err(|_| AppError::Internal("resolved item not utf8".into()))?;
                (
                    json!({ "ok": true, "act": "export", "path": path, "value": value.clone() }),
                    Some(value),
                )
            }
        }
        ActType::Use => {
            // Read seam (per-item first, whole-blob Option fallback) lives inside
            // the broker resolve call — so a web-enrolled per-item vault
            // (no vault.dat) resolves without the old "vault not initialized" bail.
            // Phantom-only: an approved Use op is ALWAYS authorize_only — the
            // resident proxy serves live traffic and retries the real request
            // after approval. Resolve the connection's primary secret with the
            // verified grant and stash it so the retry fast-paths; never forward
            // here (there is no buffered request on the op plane).
            let s_o = crate::server::broker::resolve_use_primary(
                &validated.op,
                &validated.wrapping_key,
                &validated.credential_id_bytes,
                existing_vault.as_ref(),
                &state,
                &vault_id,
            )
            .await?;
            let scope = &validated.op.act.scope;
            let conn = scope
                .get("connection_id")
                .or_else(|| scope.get("service"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let (pc, grant_agent) = {
                let store = state.approvals.lock().unwrap();
                let rec = store.get(&op_id);
                (
                    rec.and_then(|r| r.policy_context.clone()),
                    rec.and_then(|r| r.agent_prefix.clone()).unwrap_or_default(),
                )
            };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let level = pc.as_ref().map(|p| p.level);
            // Phase 2: fold the bound `[requests]` scope-field values the proxy
            // stamped into `scope.scope_vars` (and the passkey signed) into the
            // grant identity. Rebuild the SAME sorted pairs the redeem path
            // re-extracts from the live request, so an approval for `amount=80`
            // can't be spent by `amount=180`. Empty (no requests shape) ⇒ `""`.
            let bound: Vec<(String, String)> = scope
                .get("scope_vars")
                .and_then(|v| v.as_object())
                .map(|m| {
                    let mut pairs: Vec<(String, String)> = m
                        .iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect();
                    pairs.sort_by(|a, b| a.0.cmp(&b.0));
                    pairs
                })
                .unwrap_or_default();
            let scope_digest = crate::service::scope_digest(&bound);
            let is_ask_always = level == Some(crate::core::policy::AccessLevel::AskAlways);
            let scoped_ask =
                level == Some(crate::core::policy::AccessLevel::Ask) && !scope_digest.is_empty();
            if is_ask_always || scoped_ask {
                // Request-BOUND grant (`op_grants`), keyed by the exact request
                // the user saw — (connection, method, host, path, scope_digest)
                // off the op scope. Never the conn-keyed `entries`: a conn-global
                // value would let a DIFFERENT request on this connection silently
                // ride the approval. ask-always is single-use; a scoped ask is
                // reusable for the SAME bound action within its window. If the
                // binding tuple is missing (malformed scope), store NOTHING — the
                // replay re-prompts, the safe failure.
                let method = scope.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let path = scope.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let host = pc
                    .as_ref()
                    .and_then(|p| p.host.clone())
                    .or_else(|| scope.get("host").and_then(|v| v.as_str()).map(String::from))
                    .unwrap_or_default();
                let window = if is_ask_always {
                    crate::state::ASK_ALWAYS_REPLAY_WINDOW_SECS
                } else {
                    pc.as_ref().map(|p| p.ttl_seconds).unwrap_or(300)
                };
                if !conn.is_empty() && !method.is_empty() && !host.is_empty() && !path.is_empty() {
                    state.op_grant_insert(
                        &vault_id,
                        &grant_agent,
                        &conn,
                        method,
                        &host,
                        path,
                        &scope_digest,
                        s_o,
                        now + window,
                    );
                } else {
                    tracing::warn!(
                        vault = %vault_id, op = %op_id,
                        "bound approve without a full request binding — grant not stored (replay will re-prompt)"
                    );
                }
            } else if !conn.is_empty() {
                // Unscoped ask (and legacy no-context ops): conn-keyed value with
                // the grant-window TTL, read by the downgraded-to-Allow retry.
                let ttl = pc.as_ref().map(|p| p.ttl_seconds).unwrap_or(300);
                state.cache_insert(
                    &vault_id,
                    &conn,
                    s_o,
                    Some(now + ttl),
                    Some(grant_agent.clone()),
                );
            }
            (
                json!({ "ok": true, "act": "use", "authorized": true, "stream": true }),
                None,
            )
        }
        ActType::Custom(name) => match name.as_str() {
            // Lifecycle op (H3 / PROTOCOL.md §6.3): decrypt vault, bootstrap
            // secrets_cache for allow-policy services, transition to Unlocked,
            // and return all target plaintexts to the requester (the same
            // shape Export-with-target="env" returned, so /try's editor
            // doesn't need a separate reveal call).
            "vault-unlock" => {
                // Read seam: per-item store first (a web-enrolled vault has only
                // vault.per-item.json, no vault.dat), whole-blob as Option fallback.
                let (view, unlock_key) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        &validated.wrapping_key,
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                // vault-unlock is a pure STATE TRANSITION: it uses the grant's
                // W_c to open the vault, bootstrap the daemon's in-memory
                // secrets cache, and flip the vault unlocked. It deliberately
                // returns NO secret material. The console editor derives its
                // `{kv, aux}` view entirely client-side (it pulls the sealed
                // per-item rows and unseals them under its own passkey PRF —
                // `unlockVault` in the frontend), the CLI reads only the ok
                // status, and the grant page discards the response body. A
                // cached plaintext here served no consumer and was readable via
                // the (capability-gated) op-poll — so a routine unlock left the
                // whole vault's plaintext retrievable. Plaintext leaves the
                // daemon ONLY through a scope-constrained, single-use `Export`
                // op (the passkey-gated `sc secret get` / reveal path), never
                // here. Bootstrap the cache from `view` (every allow-policy
                // service's auth value via the v3 store_order; native-only at
                // unlock — external adapters fetch lazily at /use); never
                // materialize kv.
                let cache = bootstrap_cache_from_view(&view, &state);
                tracing::info!(
                    vault = %vault_id,
                    cached_services = cache.entries.len(),
                    "vault unlocked"
                );
                state.unlock_vault(vault_id.clone(), cache, unlock_key);
                // Backfill the acting credential's key-check value if the stored
                // keyset predates it (best-effort; we hold the write guard). This
                // lets a later cross-device approval fail FAST in the browser
                // (the KCV won't match a divergent W_c) instead of silently
                // hanging on an unseal the daemon can't complete.
                maybe_backfill_wc_check(
                    &state,
                    &vault_id,
                    &validated.credential_id_bytes,
                    &validated.wrapping_key,
                );
                // On unlock, complete any pending OAuth connect: a
                // browser "Connect" may have sealed `<conn>_oauth_pending`
                // into the vault while it was locked (or before this device
                // synced). Run it detached — it acquires the per-vault write
                // lock itself, so it must start AFTER this handler's
                // `_vault_write_guard` drops (the lock is not reentrant).
                // Best-effort + never fatal (CONNECTIONS_AND_AUTH.md §4a).
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::auth::connect::process_vault_connects(&state, &vid, None).await;
                    });
                }
                let resp = json!({ "ok": true, "act": "vault-unlock" });
                // No cached value: unlock returns no secret, so nothing is
                // stashed for the op-poll to hand back.
                (resp, None)
            }
            // Lifecycle op: drop the cache and flip Locked. No vault read
            // needed — pure state transition. Requires a fresh grant so an
            // attacker with the user's session token can't DOS-lock without
            // a passkey gesture.
            "vault-lock" => {
                state.lock_vault(&vault_id);
                tracing::info!(vault = %vault_id, "vault locked");
                (json!({ "ok": true, "act": "vault-lock" }), None)
            }
            // Lifecycle op: wipe the vault's on-disk state (vault.dat +
            // any sibling blob files) and clear the in-memory locked/
            // unlocked entry. Passkey-gated through the standard grant
            // machinery so a stolen session token can't destroy data. Once
            // approved, this is irreversible — the user must re-enroll to
            // get a new vault.
            "vault-delete" => {
                if existing_vault.is_none() {
                    return Err(AppError::Conflict("vault not initialized".into()));
                }
                // Close the cached AuditStore SQLite handle BEFORE removing
                // the directory. On Linux, unlinking a file that still has
                // an open fd leaves the inode alive: any subsequent
                // `state.audits.for_vault(vid)` call returns the cached
                // Arc<AuditStore> and reads/writes against the now-orphan
                // inode. Recreating the same vault_id (deterministic from
                // user_id, so very common after delete) then sees the old
                // approvals "from 50 minutes ago" instead of an empty log.
                // Matches the admin DELETE path's ordering (admin.rs).
                state.audits.forget(&vault_id);
                state
                    .vaults
                    .remove(&vault_id)
                    .map_err(|e| AppError::Internal(format!("vault dir remove: {}", e)))?;
                {
                    let mut states = state.vault_states.lock().unwrap();
                    states.remove(&vault_id);
                }
                state.last_host_unions.lock().unwrap().remove(&vault_id);
                tracing::info!(vault = %vault_id, "vault deleted");
                (json!({ "ok": true, "act": "vault-delete" }), None)
            }
            // Rename a passkey's `device_name`. Pure registry update — K,
            // M, and credentials list stay untouched. Modeled as Custom
            // (not Write/Rotate) because it doesn't mutate the protected
            // state, just an opaque public-info field.
            //
            // Wire shape: `target = "passkeys.<cid_b64>"`,
            // `scope = { device_name: "<new name>" }`.
            // Acting credential authenticates via the standard grant
            // pipeline. Self-rename allowed (matches per-VM UX).
            "rename-passkey" => {
                let target = validated.op.act.target.as_str();
                let cid_b64 = target.strip_prefix("passkeys.").ok_or_else(|| {
                    AppError::BadRequest(
                        "rename-passkey target must be 'passkeys.<credential_id>'".into(),
                    )
                })?;
                let new_name = validated
                    .op
                    .act
                    .scope
                    .get("device_name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AppError::BadRequest("rename-passkey scope.device_name required".into())
                    })?
                    .trim()
                    .to_string();
                if new_name.is_empty() {
                    return Err(AppError::BadRequest("device_name cannot be empty".into()));
                }
                if new_name.len() > 120 {
                    return Err(AppError::BadRequest(
                        "device_name too long (max 120 chars)".into(),
                    ));
                }
                let mut vault = existing_vault
                    .clone()
                    .ok_or_else(|| AppError::Conflict("vault not initialized".into()))?;
                let cid_bytes = decode_credential_id(cid_b64)?;
                let mut pk = vault
                    .registry
                    .get::<sudp::passkey::WebAuthn>(&cid_bytes)
                    .map_err(|e| AppError::Internal(format!("registry get: {}", e)))?
                    .ok_or_else(|| {
                        AppError::BadRequest("target credential not enrolled on this vault".into())
                    })?;
                pk.device_name = new_name.clone();
                vault
                    .registry
                    .insert::<sudp::passkey::WebAuthn>(&cid_bytes, &pk)
                    .map_err(|e| AppError::Internal(format!("registry insert: {}", e)))?;
                write_atomic(&vault_path, &vault)?;
                tracing::info!(
                    vault = %vault_id,
                    cred = %cid_b64,
                    "passkey rename applied"
                );
                (
                    json!({ "ok": true, "act": "rename-passkey", "target": target, "device_name": new_name }),
                    None,
                )
            }
            // Component C — one-tap host widen. The agent hit a destination the
            // connection doesn't anchor; the user approves adding that exact
            // FQDN as a permanent grant. Session-level today (the in-memory
            // routing snapshot is widened so the agent's retry passes the
            // anchor); durable persistence into `aux.connections[conn].hosts`
            // is the documented follow-up (see BUILD_NOTES: widen durable write).
            "widen-host" => {
                let conn = validated
                    .op
                    .act
                    .scope
                    .get("connection_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let host = validated
                    .op
                    .act
                    .scope
                    .get("host")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if conn.is_empty() || host.is_empty() {
                    return Err(AppError::BadRequest(
                        "widen-host scope needs connection_id + host".into(),
                    ));
                }
                state.widen_connection_host(&vault_id, &conn, &host);
                tracing::info!(vault = %vault_id, conn = %conn, host = %host, "host widened (session)");
                (
                    json!({ "ok": true, "act": "widen-host", "connection_id": conn, "host": host }),
                    None,
                )
            }
            // List the vault's custom service definitions (`aux.services`) with
            // each one's validation status + referencing connections. Read-only
            // (opens the view under the grant's W_c, never writes). This is the
            // only surface that shows an INVALID definition — the daemon skips
            // those at unlock and the console only renders a def through its
            // connections, so a broken/orphaned def is otherwise invisible.
            "service-ls" => {
                let (view, _k) = crate::server::handlers::metadata::open_view_for_grant_keep_key(
                    &state,
                    &vault_id,
                    &validated.op,
                    &validated.wrapping_key,
                    &validated.credential_id_bytes,
                    existing_vault.as_ref(),
                )?;
                let mut services = Vec::new();
                for (id, toml_src) in &view.aux.services {
                    let problems = crate::service::validate::validate_service(toml_src)
                        .err()
                        .unwrap_or_default();
                    services.push(json!({
                        "id": id,
                        "valid": problems.is_empty(),
                        "problems": problems,
                        "connections": service_refs(&view, id),
                    }));
                }
                let resp = json!({ "ok": true, "act": "service-ls", "services": services });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Delete a custom service definition. Connections referencing it are
            // kept (their stored secrets stay resolvable) but reported so the CLI
            // can warn. Daemon-side reseal + reconcile + push — the CLI needs no
            // PRF key, so this works over SSH via the grant link.
            "service-rm" => {
                let id = validated.op.act.target.trim().to_string();
                if id.is_empty() {
                    return Err(AppError::BadRequest(
                        "service-rm target (service id) required".into(),
                    ));
                }
                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        &validated.wrapping_key,
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                let refs = service_refs(&view, &id);
                if view.aux.services.remove(&id).is_none() {
                    return Err(AppError::BadRequest(format!(
                        "no custom service '{}' in this vault",
                        id
                    )));
                }
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &view, &k)
                    .map_err(AppError::Internal)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, service = %id, "custom service removed");
                let resp = json!({
                    "ok": true, "act": "service-rm",
                    "removed": id, "referencing_connections": refs,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Store a validated custom service definition (`aux.services`). The
            // toml rides `scope.toml`; the daemon re-validates (same gate as the
            // unlock-time check) and refuses to shadow a built-in id. Daemon-side
            // reseal + reconcile + push, like service-rm.
            "service-add" => {
                let toml_src = validated
                    .op
                    .act
                    .scope
                    .get("toml")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::BadRequest("service-add scope.toml required".into()))?
                    .to_string();
                if let Err(problems) = crate::service::validate::validate_service(&toml_src) {
                    return Err(AppError::BadRequest(format!(
                        "invalid service definition: {}",
                        problems.join("; ")
                    )));
                }
                let def: crate::service::ServiceDef = toml::from_str(&toml_src)
                    .map_err(|e| AppError::BadRequest(format!("parse: {}", e)))?;
                let id = def.service.id.clone();
                if state.services.get(&id).is_some() {
                    return Err(AppError::BadRequest(format!(
                        "'{}' shadows a built-in service id",
                        id
                    )));
                }
                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        &validated.wrapping_key,
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                view.aux.services.insert(id.clone(), toml_src);
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &view, &k)
                    .map_err(AppError::Internal)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, service = %id, "custom service added");
                let resp = json!({ "ok": true, "act": "service-add", "id": id });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Delete a native secret KEY. Shared-pool semantics
            // (CONNECTION_SCHEMA.md §3): never cascades into a connection — the
            // referencing connections just turn unconfigured until the key is
            // re-added. Returns who referenced it so the CLI can say so. The
            // KEY name is public (rides the op), the value never does.
            "secret-rm" => {
                let key = validated.op.act.target.trim().to_ascii_uppercase();
                if key.is_empty() {
                    return Err(AppError::BadRequest(
                        "secret-rm target (key) required".into(),
                    ));
                }
                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        &validated.wrapping_key,
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                if !view.native_secrets.contains_key(&key) {
                    // One flat namespace, two authorities: SafeClaw OWNS
                    // native items but only READS external stores — so an
                    // external-hosted key gets a precise refusal, not a
                    // misleading "not found".
                    if view.resolve_value_async(&key).await?.is_some() {
                        return Err(AppError::BadRequest(format!(
                            "key '{}' is hosted by an external store — SafeClaw reads it pass-through and cannot delete it; remove it in the provider's console",
                            key
                        )));
                    }
                    return Err(AppError::BadRequest(format!(
                        "key '{}' not found in vault",
                        key
                    )));
                }
                let referenced_by = view
                    .aux
                    .connection_claims(&state.services, "")
                    .remove(&key)
                    .unwrap_or_default();
                view.native_secrets.remove(&key);
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &view, &k)
                    .map_err(AppError::Internal)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, key = %key, "secret removed");
                let resp = json!({
                    "ok": true, "act": "secret-rm",
                    "removed": key, "referenced_by": referenced_by,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Delete a connection record. Unless `scope.keep_secrets`, also
            // deletes the secret(s) ONLY this connection references (shared-pool
            // guard: a key another connection still claims is kept). Returns the
            // removed + kept secret lists so the CLI can report them.
            "connection-rm" => {
                let id = validated.op.act.target.trim().to_string();
                if id.is_empty() {
                    return Err(AppError::BadRequest(
                        "connection-rm target (connection id) required".into(),
                    ));
                }
                let keep_secrets = validated
                    .op
                    .act
                    .scope
                    .get("keep_secrets")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        &validated.wrapping_key,
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                let rec = view.aux.connections.get(&id).cloned().ok_or_else(|| {
                    AppError::BadRequest(format!("no connection '{}' in this vault", id))
                })?;
                let mut removed_secrets: Vec<String> = Vec::new();
                let mut kept_secrets: Vec<(String, Vec<String>)> = Vec::new();
                if !keep_secrets {
                    let claims = view.aux.connection_claims(&state.services, &id);
                    for addr in rec.secret_addresses(&state.services) {
                        if let Some(by) = claims.get(&addr) {
                            if view.native_secrets.contains_key(&addr) {
                                kept_secrets.push((addr, by.clone()));
                            }
                            continue;
                        }
                        if view.native_secrets.remove(&addr).is_some() {
                            removed_secrets.push(addr);
                        }
                    }
                }
                view.aux.connections.remove(&id);
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &view, &k)
                    .map_err(AppError::Internal)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, connection = %id, "connection removed");
                let resp = json!({
                    "ok": true, "act": "connection-rm",
                    "removed": id,
                    "removed_secrets": removed_secrets,
                    "kept_secrets": kept_secrets,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Create (or replace) a connection — the CLI's `sc connect`, ONE
            // approval. `scope` carries the public shape only: hosts / service /
            // referenced KEY names / an optional `values_digest` committing to
            // the new secret VALUES the CLI deposited at `/v/{vid}/op-payload`
            // (the full op rides to the cloud relay, so plaintext never can —
            // see `AppState::op_payloads`). Daemon-side reseal + push, so this
            // works over SSH via the grant link like the other write acts.
            "connection-add" => {
                let id = validated.op.act.target.trim().to_string();
                if !crate::cli::conn::valid_conn_id(&id) {
                    return Err(AppError::BadRequest(format!(
                        "'{}' is not a valid connection id",
                        id
                    )));
                }
                let scope = &validated.op.act.scope;
                let service = scope
                    .get("service")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let hosts: Option<Vec<String>> =
                    scope.get("hosts").and_then(|v| v.as_array()).map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    });
                let referenced: Vec<String> = scope
                    .get("secrets")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                // Referenced keys may name EXTERNAL-store secrets, whose
                // casing/hyphens are not ours to fold — the relaxed
                // phantom-safe charset applies here. NEW keys (deposited
                // values) keep the strict uppercase gate below: they write
                // into native-secrets, whose canonical form is UPPERCASE.
                for k in &referenced {
                    if !crate::cli::conn::valid_secret_ref(k) {
                        return Err(AppError::BadRequest(format!(
                            "'{}' is not a valid secret key reference",
                            k
                        )));
                    }
                }
                let keys: Option<std::collections::BTreeMap<String, String>> =
                    scope.get("keys").and_then(|v| v.as_object()).map(|m| {
                        m.iter()
                            .filter_map(|(r, k)| k.as_str().map(|k| (r.clone(), k.to_string())))
                            .collect()
                    });
                // The committed value deposit (absent = no new values, e.g. a
                // pure `--use-existing` connection). Single-use; expiry or a
                // daemon restart between create and approve fails closed.
                let values = match scope.get("values_digest").and_then(|v| v.as_str()) {
                    Some(d) => Some(state.op_payload_take(d).ok_or_else(|| {
                        AppError::BadRequest(
                            "deposited values not found or expired — re-run the command".into(),
                        )
                    })?),
                    None => None,
                };
                if let Some(vals) = &values {
                    for k in vals.keys() {
                        if !referenced.contains(k) {
                            return Err(AppError::BadRequest(format!(
                                "deposited key '{}' is not in the approved scope.secrets",
                                k
                            )));
                        }
                        // Deposits WRITE into native-secrets — enforce the
                        // native canonical form (strict uppercase role).
                        if !crate::cli::conn::valid_role(k) || k.to_ascii_uppercase() != *k {
                            return Err(AppError::BadRequest(format!(
                                "'{}' is not a valid UPPERCASE secret key",
                                k
                            )));
                        }
                    }
                }

                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        &validated.wrapping_key,
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;

                let record = match &service {
                    // RAW: anchors its own exact FQDNs; explicit `secrets` list.
                    None => {
                        let hosts = hosts.filter(|h| !h.is_empty()).ok_or_else(|| {
                            AppError::BadRequest("a raw connection needs at least one host".into())
                        })?;
                        for h in &hosts {
                            crate::cli::conn::validate_raw_host(h).map_err(AppError::BadRequest)?;
                        }
                        if referenced.is_empty() {
                            return Err(AppError::BadRequest(
                                "a raw connection needs at least one secret key".into(),
                            ));
                        }
                        // `--use-existing` keys (referenced but not deposited)
                        // must already be in the vault. The vault is ONE flat
                        // namespace across every store — a key hosted in an
                        // external store (GCP etc.) binds exactly like a
                        // native one, so walk the full store_order, not just
                        // native-secrets. Canonicalisation: native keys are
                        // canonically UPPERCASE (a lowercase-typed reference
                        // rewrites to the stored casing); external keys are
                        // accepted exactly as named (external naming is not
                        // ours to fold). The external probe is a network
                        // call, but this is a ceremony (approve) path; a
                        // store outage surfaces as the approve failing
                        // loudly, never as a silent "no such secret".
                        let mut canonical: Vec<String> = Vec::with_capacity(referenced.len());
                        for key in &referenced {
                            let deposited = values
                                .as_ref()
                                .map(|v| v.contains_key(key))
                                .unwrap_or(false);
                            if deposited || view.native_secrets.contains_key(key) {
                                canonical.push(key.clone());
                                continue;
                            }
                            if let Some((native, _)) = view
                                .native_secrets
                                .iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                            {
                                canonical.push(native.clone());
                                continue;
                            }
                            if view.resolve_value_async(key).await?.is_some() {
                                canonical.push(key.clone());
                                continue;
                            }
                            return Err(AppError::BadRequest(format!(
                                "no such secret '{}' in the vault (checked native + external stores)",
                                key
                            )));
                        }
                        // Exact dedup only: native case-folding already
                        // collapsed duplicates; two external keys differing
                        // by case are DISTINCT secrets (GCP is case-
                        // sensitive) and must both survive.
                        let mut seen = std::collections::HashSet::new();
                        canonical.retain(|k| seen.insert(k.clone()));
                        crate::storage::plaintext::Connection {
                            name: None,
                            service: None,
                            hosts: Some(hosts),
                            secrets: Some(canonical),
                            keys: None,
                        }
                    }
                    // SERVICE-backed: hosts derive from the service; `hosts`
                    // here only PINS exact FQDNs inside its `*.suffix`
                    // wildcards. Custom-first resolution (per-vault def wins).
                    Some(svc) => {
                        let service_hosts: Vec<String> = match view.aux.services.get(svc) {
                            Some(toml_src) => {
                                toml::from_str::<crate::service::ServiceDef>(toml_src)
                                    .map(|d| d.service.hosts)
                                    .map_err(|e| {
                                        AppError::BadRequest(format!(
                                            "custom service '{}': {}",
                                            svc, e
                                        ))
                                    })?
                            }
                            None => state
                                .services
                                .get(svc)
                                .ok_or_else(|| {
                                    AppError::BadRequest(format!("unknown service '{}'", svc))
                                })?
                                .service
                                .hosts
                                .clone(),
                        };
                        let pins = hosts.filter(|h| !h.is_empty());
                        if let Some(pins) = &pins {
                            for h in pins {
                                crate::cli::conn::validate_raw_host(h)
                                    .map_err(AppError::BadRequest)?;
                                let ok = service_hosts
                                    .iter()
                                    .any(|e| crate::core::host::wildcard_matches(e, h));
                                if !ok {
                                    return Err(AppError::BadRequest(format!(
                                        "pinned host '{}' is not within service '{}' hosts",
                                        h, svc
                                    )));
                                }
                            }
                        }
                        crate::storage::plaintext::Connection {
                            name: None,
                            service: Some(svc.clone()),
                            hosts: pins,
                            secrets: None,
                            keys: keys.clone().filter(|m| !m.is_empty()),
                        }
                    }
                };

                let written: Vec<String> = values
                    .as_ref()
                    .map(|v| v.keys().cloned().collect())
                    .unwrap_or_default();
                if let Some(vals) = values {
                    for (key, val) in vals {
                        view.native_secrets.insert(key, val.into_bytes());
                    }
                }
                view.aux.connections.insert(id.clone(), record);
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &view, &k)
                    .map_err(AppError::Internal)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, connection = %id, "connection added");
                let resp = json!({
                    "ok": true, "act": "connection-add",
                    "id": id, "service": service,
                    "written": written, "referenced": referenced,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            // Store one native secret — the CLI's `sc set`, ONE approval. The
            // value rides the local `op-payload` deposit (committed by
            // `scope.values_digest`); `scope.hosts` optionally anchors a raw
            // single-secret connection at the lowercased KEY (the `sc set
            // --host` sugar), `scope.no_broker` explicitly un-brokers instead.
            "secret-set" => {
                let key = validated.op.act.target.trim().to_ascii_uppercase();
                if !crate::cli::conn::valid_role(&key) {
                    return Err(AppError::BadRequest(format!(
                        "'{}' is not a valid secret key",
                        key
                    )));
                }
                let scope = &validated.op.act.scope;
                let no_broker = scope
                    .get("no_broker")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let hosts: Vec<String> = scope
                    .get("hosts")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if no_broker && !hosts.is_empty() {
                    return Err(AppError::BadRequest(
                        "secret-set: no_broker and hosts are mutually exclusive".into(),
                    ));
                }
                let conn = key.to_ascii_lowercase();
                if !hosts.is_empty() {
                    if !crate::cli::conn::valid_conn_id(&conn) {
                        return Err(AppError::BadRequest(format!(
                            "can't derive a connection id from '{}'",
                            key
                        )));
                    }
                    for h in &hosts {
                        crate::cli::conn::validate_raw_host(h).map_err(AppError::BadRequest)?;
                    }
                }
                let digest = scope
                    .get("values_digest")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AppError::BadRequest("secret-set: scope.values_digest required".into())
                    })?;
                let mut values = state.op_payload_take(digest).ok_or_else(|| {
                    AppError::BadRequest(
                        "deposited value not found or expired — re-run the command".into(),
                    )
                })?;
                let value = values.remove(&key).ok_or_else(|| {
                    AppError::BadRequest("deposited values don't match the op's key".into())
                })?;
                if !values.is_empty() {
                    return Err(AppError::BadRequest(
                        "secret-set deposit must carry exactly the op's key".into(),
                    ));
                }

                let (mut view, k) =
                    crate::server::handlers::metadata::open_view_for_grant_keep_key(
                        &state,
                        &vault_id,
                        &validated.op,
                        &validated.wrapping_key,
                        &validated.credential_id_bytes,
                        existing_vault.as_ref(),
                    )?;
                view.native_secrets.insert(key.clone(), value.into_bytes());
                let mut removed_prior_anchor = false;
                if no_broker {
                    // Opting out must actually un-broker: drop the raw
                    // connection a prior `sc set <key> --host …` created.
                    removed_prior_anchor = view.aux.connections.remove(&conn).is_some();
                } else if !hosts.is_empty() {
                    view.aux.connections.insert(
                        conn.clone(),
                        crate::storage::plaintext::Connection {
                            name: None,
                            service: None,
                            hosts: Some(hosts.clone()),
                            secrets: Some(vec![key.clone()]),
                            keys: None,
                        },
                    );
                }
                crate::auth::connect::persist_mutated_view(&state, &vault_id, &view, &k)
                    .map_err(AppError::Internal)?;
                {
                    let state = state.clone();
                    let vid = vault_id.clone();
                    tokio::spawn(async move {
                        crate::sync::push_keys_best_effort(&state, &vid).await;
                        crate::sync::push_items_best_effort(&state, &vid).await;
                    });
                }
                tracing::info!(vault = %vault_id, key = %key, "secret set");
                let resp = json!({
                    "ok": true, "act": "secret-set", "key": key,
                    "conn": if hosts.is_empty() { Value::Null } else { json!(conn) },
                    "hosts": hosts,
                    "removed_prior_anchor": removed_prior_anchor,
                });
                let cached = Some(resp.to_string());
                (resp, cached)
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "unsupported Custom act: {}",
                    other
                )));
            }
        },
        other => {
            return Err(AppError::BadRequest(format!(
                "unsupported act kind: {:?}",
                other
            )));
        }
    };

    // 5. Mark approved + emit event. We also pull the policy_context off
    // the record before mutation so we can write into the rule-approvals
    // cache below — without this, an `ask`-with-TTL approval would never
    // short-circuit the next matching request.
    let (rec_id, rec_vault_id, response_preview, policy_ctx_for_cache, rec_agent_prefix) = {
        let mut store = state.approvals.lock().unwrap();
        let rec = store
            .approve(&op_id, cached_value.clone())
            .ok_or_else(|| AppError::Conflict("op no longer pending after validation".into()))?;
        let preview = match &validated.op.act.kind {
            ActType::Use => cached_value
                .as_deref()
                .and_then(|s| serde_json::from_str::<Value>(s).ok()),
            _ => None,
        };
        // Only Use ops carry a policy_context (other op kinds bypass the
        // policy gate). Cache writes are gated by Ask level — AskAlways is
        // explicitly excluded at op-create time so it'll be None here.
        let pc = if matches!(validated.op.act.kind, ActType::Use) {
            rec.policy_context.clone()
        } else {
            None
        };
        (
            rec.id.clone(),
            rec.vault_id.clone(),
            preview,
            pc,
            rec.agent_prefix.clone().unwrap_or_default(),
        )
    };

    // Cache write: an Ask-level approval scopes a TTL'd "next matching
    // request fast-paths" effect. Service id pulled off the op's scope
    // (which the broker resolve path populates verbatim). No-op when:
    //   - The op wasn't a Use (policy_ctx_for_cache is None)
    //   - The level was Allow / AskAlways / Deny (not stored)
    //   - The vault relocked between approve and now (record_ask_approval
    //     is a no-op then)
    // A SCOPED ask does NOT use this conn-keyed downgrade window — it was bound
    // into `op_grants` above (redeemed by peek), so writing a rule_approvals
    // entry here would let `evaluate` downgrade it to Allow and fast-path a
    // DIFFERENT bound value on the connection. Only a genuinely UNSCOPED ask
    // (no `[requests]` shape on the path) takes the window. We key off the
    // proxy-stamped `scoped` marker, NOT the presence of resolved values — an
    // empty-body ask on a scoped path is still scoped and must not open a
    // value-blind window (the "approve a blank purchase, then spend anything"
    // bypass).
    let is_scoped_path = validated
        .op
        .act
        .scope
        .get("scoped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if let Some(pc) = policy_ctx_for_cache {
        if pc.level == crate::core::policy::AccessLevel::Ask && !is_scoped_path {
            // The grant is scoped to the **connection** (CONNECTION_SCHEMA.md §6):
            // approving account A's request never fast-paths account B. Falls back
            // to `service` for the default connection (conn == service).
            let conn = validated
                .op
                .act
                .scope
                .get("connection_id")
                .or_else(|| validated.op.act.scope.get("service"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Method scopes the grant (a read-approval can't fast-path a
            // later write). Pulled off the op's scope, same as `connection_id`.
            let req_method = validated
                .op
                .act
                .scope
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Host-scoped grant: read the resolved host the proxy stamped onto
            // the policy context (falls back to the op scope for robustness).
            let host = pc
                .host
                .clone()
                .or_else(|| {
                    validated
                        .op
                        .act
                        .scope
                        .get("host")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default();
            if !conn.is_empty() && !req_method.is_empty() {
                state.record_ask_approval(
                    &rec_vault_id,
                    &rec_agent_prefix,
                    &conn,
                    pc.rule_id,
                    &req_method,
                    &host,
                    pc.ttl_seconds,
                );
            }
        }
    }

    // Audit: pending → approved. Best-effort; daemon UX must not depend on
    // audit being healthy.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(store) = state.audits.for_vault(&rec_vault_id) {
        if let Err(e) = store.finalize(
            &op_id,
            STATUS_APPROVED,
            now,
            Some(&grant.credential_id),
            None,
            audit_upstream_status,
        ) {
            tracing::warn!(vault = %rec_vault_id, op = %op_id, "audit finalize approved failed: {}", e);
        }
    }

    state.emit_event(ApprovalEvent {
        vault_id: rec_vault_id,
        approval_id: rec_id,
        kind: "approved".into(),
        op_summary: None,
        response_preview,
        reason: None,
    });

    Ok(Json(response))
}

/// Connection ids (established `aux.connections` + in-flight `aux.connecting`)
/// whose `service` references `service_id` — for the `service-ls`/`service-rm`
/// "still referenced by …" report.
fn service_refs(
    view: &crate::storage::plaintext::VaultPlaintextView,
    service_id: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    for (cid, c) in &view.aux.connections {
        if c.service.as_deref() == Some(service_id) {
            out.push(cid.clone());
        }
    }
    for (cid, c) in &view.aux.connecting {
        if c.service == service_id && !out.contains(cid) {
            out.push(cid.clone());
        }
    }
    out
}

pub async fn reject_op(
    State(state): State<Arc<AppState>>,
    Path(op_id): Path<String>,
) -> Result<Json<Value>> {
    let (rec_id, rec_vault_id) = {
        let mut store = state.approvals.lock().unwrap();
        let rec = store
            .reject(&op_id, "user denied")
            .ok_or(AppError::NotFound)?;
        (rec.id.clone(), rec.vault_id.clone())
    };

    // Audit: pending → rejected.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Ok(store) = state.audits.for_vault(&rec_vault_id) {
        if let Err(e) = store.finalize(
            &op_id,
            STATUS_REJECTED,
            now,
            None,
            Some("user denied"),
            None,
        ) {
            tracing::warn!(vault = %rec_vault_id, op = %op_id, "audit finalize rejected failed: {}", e);
        }
    }

    state.emit_event(ApprovalEvent {
        vault_id: rec_vault_id,
        approval_id: rec_id.clone(),
        kind: "rejected".into(),
        op_summary: None,
        response_preview: None,
        reason: Some("user denied".into()),
    });

    Ok(Json(
        json!({ "ok": true, "op_id": rec_id, "status": "rejected" }),
    ))
}

/// Build the per-service `secrets_cache` from a decrypted v3 view. The cache
/// carries three things per session:
///   1. `entries` — resolved auth bytes for every service whose required
///      item is currently available (any store). Per-rule evaluation at /use
///      time decides whether to USE them (Allow), prompt (Ask / AskAlways),
///      or block (Deny) — so we don't pre-filter to allow-default services
///      anymore: a rule-level Allow on a service whose default was Ask still
///      needs the bytes ready for fast-path forwarding.
///   2. `policy` — the effective policy tree (`aux.policy` overlaid on
///      compiled defaults). Holds default floors, per-tag, and
///      per-connection user policy. Built-in per-service rules are read
///      live from the service at eval, not cached here.
/// Build + persist the local per-item store (`vault.per-item.json`) from a
/// just-decrypted whole-blob vault + its view. The keyset (registry +
/// credentials + wrapped_key) is copied verbatim from the whole-blob
/// `SealedVault` (it's what gives you `K`); the content is re-sharded from
/// `view` into N `seal_record` item rows under the same `K` (contract §2/§4).
///
/// Best-effort by design: a failure logs and leaves only `vault.dat`, which the
/// per-item read path falls back to. This is the ADDITIVE landing seam — enroll
/// and write call it so the daemon holds items alongside the whole blob until
/// the browser cut-over retires the blob (stubbed[]).
fn seed_per_item_store(
    state: &AppState,
    vault_id: &str,
    vault: &crate::storage::SealedVault,
    view: &VaultPlaintextView,
    k: &[u8],
) {
    use crate::storage::sealed_vault::{Keyset, PerItemVault};
    let Ok(per_item_path) = state.vaults.per_item_path(vault_id) else {
        return;
    };
    // Carry the keyset cursor forward if a per-item file already exists, so a
    // re-seed after a write doesn't reset the CAS cursors the sync layer tracks.
    let (keyset_version, items_seq, keyset_seq) =
        crate::storage::sealed_vault::read_per_item(&per_item_path)
            .ok()
            .flatten()
            .map(|pv| (pv.keyset.keyset_version, pv.items_seq, pv.keyset_seq))
            .unwrap_or((0, 0, 0));
    let mut pv = PerItemVault {
        keyset: Keyset {
            version: vault.version,
            registry: vault.registry.clone(),
            credentials: vault.credentials.clone(),
            keyset_version,
        },
        items: std::collections::BTreeMap::new(),
        items_seq,
        keyset_seq,
    };
    if let Err(e) = pv.seed_items_from_view::<sudp::primitives::StdPrimitives>(k, vault_id, view) {
        tracing::warn!(vault = %vault_id, "per-item seed from view failed: {}", e);
        return;
    }
    if let Err(e) = crate::storage::sealed_vault::write_per_item_atomic(&per_item_path, &pv) {
        tracing::warn!(vault = %vault_id, "per-item store write failed: {}", e);
        return;
    }
    tracing::info!(
        vault = %vault_id,
        items = pv.items.len(),
        "per-item store seeded"
    );
}

/// The role KEYs cached for a service's connections: the declared `secrets`
/// plus any oauth `[auth].exposes` roles (derived at connect, stored UPPERCASED —
/// the phantom's lowercase segment matches case-insensitively at resolve).
fn cacheable_roles(svc: &crate::service::ServiceDef) -> Vec<String> {
    let mut roles: Vec<String> = svc.service.secrets.clone();
    if let Some(o) = svc.oauth2() {
        roles.extend(o.exposes.iter().map(|r| r.to_ascii_uppercase()));
    }
    roles
}

pub(crate) fn bootstrap_cache_from_view(
    view: &VaultPlaintextView,
    state: &AppState,
) -> SecretsCache {
    let mut cache = SecretsCache::default();
    // Effective policy = the vault's sparse `aux.policy` overlaid on compiled
    // defaults. Rebuilt here on every unlock/refresh, so a per-connection edit
    // is live on the next request (PROTOCOL.md §6.2/§6.4).
    let effective_policy = crate::core::policy::Policy::effective(view.aux.policy.as_ref());
    cache.policy = effective_policy.clone();
    cache.audit_retention_days = view.aux.audit_retention_days;
    // Residency mirrors the DECISION floor (`AppState::evaluate_request_policy`):
    // a connection's credential is pre-loaded at unlock iff its effective READ
    // floor resolves to `allow` — recipe `[default]` ⊕ the user's `aux.policy`
    // connection override, then tag, then the global `allow` floor. This
    // replaces the old `default_read_level(service) == Allow` gate, whose
    // no-`[policy]` fallback was `ask-always` (contradicting the decision layer's
    // global-`allow` floor, so the first use of a policy-less recipe always
    // prompted) and which never consulted `aux.policy` (a user tightening a
    // service to ask-always still got it resident — PROTOCOL.md §6.2). Reusing
    // `evaluate` with a GET and no rules resolves exactly that read floor, so
    // residency can't drift from the decision. `service = None` ⇒ raw connection.
    let read_floor_allows = |service: Option<&str>, conn: &str| -> bool {
        residency_read_floor_allows(&effective_policy, &state.services, service, conn)
    };
    // Routing snapshot (CONNECTION_SCHEMA.md §6): `connection_id → {service,
    // config}`. The per-service loop below bootstraps every *default* connection
    // (conn == service); a second pass after it covers *named* connections.
    cache.connections = view
        .aux
        .connections
        .iter()
        .map(|(c, conn)| (c.clone(), conn.clone()))
        .collect();
    cache.agents = view.aux.agents.clone();
    // Snapshot native-store item names (names only, never values). Surface
    // for GET /v/{vid}/secret-keys so the frontend can compute "which
    // services are reachable" without re-walking the kv map.
    for name in view.native_secrets.keys() {
        cache.native_keys.insert(name.clone());
    }
    // Snapshot external stores' adapter inputs so GET /v/{vid}/secret-keys
    // can list() them later without re-decrypting the vault. Only kinds
    // we have an adapter for today — others are skipped (they live in
    // store_order but never resolve).
    for (store_id, store) in view.aux.stores.iter() {
        if store.kind != "gcp-secret-manager" {
            continue;
        }
        // ONE adapter instance per store for the whole unlocked session:
        // this is what makes the adapter's OAuth-token cache effective
        // (F-19: the adapter zeroizes the SA private key on drop, i.e. on
        // lock). A store that fails to materialise is skipped, same as the
        // old missing-credential cases — its keys just aren't resident and
        // `secret-keys` won't list it.
        match crate::store::build_adapter(store_id, store, view) {
            Ok(adapter) => {
                cache.external_stores.insert(
                    store_id.clone(),
                    (store.clone(), std::sync::Arc::new(adapter)),
                );
            }
            Err(e) => {
                // F-20: full error in the log only; the cache carries a
                // sanitised reason for `secret-keys` to surface.
                tracing::warn!(store = %store_id, "unlock: external store adapter init failed: {}", e);
                cache.external_store_errors.push((
                    store_id.clone(),
                    format!("store '{}' unavailable", store_id),
                ));
            }
        }
    }
    // Resolution order for the lazy fill — aux.store_order restricted to the
    // adapters that actually materialised, so first-match-wins agrees with
    // `resolve_value_async`.
    cache.external_store_order = view
        .aux
        .store_order
        .iter()
        .filter(|id| {
            cache
                .external_stores
                .get(*id)
                .is_some_and(|(s, _)| s.category == Category::Value)
        })
        .cloned()
        .collect();
    for (service_id, _) in state.services.iter_sorted() {
        // PROTOCOL.md §6.2: only connections whose effective READ floor is
        // `allow` get their auth value loaded at unlock. ask / ask-always
        // connections don't sit in cache pre-approval — they're filled lazily
        // by `approve_op` after the user passkey gesture (ask) or never
        // (ask-always — fresh-decrypted-per-request via the grant's W_c and
        // immediately zeroized). Marked `from_bootstrap` so a per-path
        // ask/ask-always RULE on this (read-allow) connection still forces a
        // fresh passkey instead of riding this residency.
        if read_floor_allows(Some(service_id), service_id) {
            // The default connection's record (usually absent) may rebind a role
            // to an existing key (`keys` map); identity otherwise. Cache maps
            // stay ROLE-keyed — only the storage lookup goes through the record.
            let rec = view.aux.connections.get(service_id);
            if let Some(role) = state.services.service_env_key(service_id) {
                let key = crate::storage::plaintext::secret_key_for(rec, &role);
                if let Some(val) = view.resolve_value_native(&key) {
                    cache.entries.insert(
                        service_id.to_string(),
                        crate::state::CacheEntry {
                            value: val.to_vec(),
                            expires_at: None, // allow = lives whole unlocked session
                            from_bootstrap: true,
                            agent_prefix: None,
                        },
                    );
                }
            }

            // v4 multi-secret: resolve each declared `secrets` role so the
            // allow fast-path can inject multi-secret services without a vault
            // view. oauth services declare no injectable direct secret here
            // (their access token is minted from the refresh_token at forward),
            // but their `exposes` roles — derived at connect and stored
            // UPPERCASED — ARE injectable, so they load alongside.
            if let Some(svc) = state.services.get(service_id) {
                let mut map: std::collections::HashMap<String, Vec<u8>> =
                    std::collections::HashMap::new();
                for name in cacheable_roles(svc) {
                    let key = crate::storage::plaintext::secret_key_for(rec, &name);
                    if let Some(val) = view.resolve_value_native(&key) {
                        map.insert(name, val.to_vec());
                    }
                }
                if !map.is_empty() {
                    cache.allow_secrets.insert(service_id.to_string(), map);
                }
            }
        }

        // Built-in policy rules are NOT cached: they're read live from the
        // service registry at eval and merged with the connection's user rules
        // (`aux.policy.connections.<id>.rules`). See
        // `AppState::evaluate_request_policy`.
    }

    // Named connections (`conn_id != service_id`) bind each ROLE to its own
    // BARE key via the record's `keys` map (CONNECTION_SCHEMA.md §3; identity
    // when unmapped). The per-service loop above already covered every default
    // connection; here we add the named ones, keyed by connection_id, resolving
    // each role through its binding but storing the multi-secret map under the
    // ROLE name so the proxy's phantom resolution finds each role's bytes.
    // (Allow-level only — ask-level connections resolve lazily from the op's
    // bound `target` key.)
    for (conn, c) in view.aux.connections.iter() {
        // Raw connections (service: None) have no service to bootstrap from; their
        // bytes resolve lazily at approve. Only service-backed named connections
        // are pre-bootstrapped here.
        let Some(service) = c.service.as_deref() else {
            continue;
        };
        if conn == service {
            continue; // default — already bootstrapped above
        }
        if !read_floor_allows(Some(service), conn) {
            continue;
        }
        if let Some(role) = state.services.service_env_key(service) {
            let key = crate::storage::plaintext::secret_key_for(Some(c), &role);
            if let Some(val) = view.resolve_value_native(&key) {
                cache.entries.insert(
                    conn.clone(),
                    crate::state::CacheEntry {
                        value: val.to_vec(),
                        expires_at: None,
                        from_bootstrap: true,
                        agent_prefix: None,
                    },
                );
            }
        }
        if let Some(svc) = state.services.get(service) {
            let mut map: std::collections::HashMap<String, Vec<u8>> =
                std::collections::HashMap::new();
            for name in cacheable_roles(svc) {
                let key = crate::storage::plaintext::secret_key_for(Some(c), &name);
                if let Some(val) = view.resolve_value_native(&key) {
                    map.insert(name, val.to_vec());
                }
            }
            if !map.is_empty() {
                cache.allow_secrets.insert(conn.clone(), map);
            }
        }
    }

    // Raw connections (`service: None`, created by `sc set K --host h` or
    // `sc connect`) have no service definition, so the per-service loops above
    // skip them. Their policy floor is the global default (`allow`), and the
    // resident proxy resolves an allow request straight from the session cache
    // (no grant to open the vault), so their secret bytes MUST be resident. §2:
    // read the connection's EXPLICIT `secrets` (uppercase KEY names, stored bare)
    // — no reverse-index-by-casing. Each KEY is resolved case-insensitively
    // (canonical uppercase storage, but a legacy key may differ).
    for (conn, c) in view.aux.connections.iter() {
        if c.service.is_some() {
            continue; // service-backed — handled above
        }
        let Some(keys) = &c.secrets else { continue };
        // Same read-floor gate as service connections: a raw connection the user
        // tightened to ask/ask-always must NOT be resident (PROTOCOL.md §6.2); an
        // untouched raw connection floors to the global `allow` and stays resident.
        if !read_floor_allows(None, conn) {
            continue;
        }
        let mut map: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        for key in keys {
            if let Some((_, bytes)) = view
                .native_secrets
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
            {
                map.insert(key.clone(), bytes.clone());
            }
        }
        // Sole secret → also the short-phantom `primary`; a multi-secret raw
        // connection resolves each role from the map (role phantoms).
        if map.len() == 1 {
            let primary = map.values().next().cloned().unwrap();
            cache.entries.insert(
                conn.clone(),
                crate::state::CacheEntry {
                    value: primary,
                    expires_at: None,
                    from_bootstrap: true,
                    agent_prefix: None,
                },
            );
        }
        if !map.is_empty() {
            cache.allow_secrets.insert(conn.clone(), map);
        }
    }

    // Custom (per-vault `aux.services`) definitions: validate before they can
    // broker (defense in depth — never trust the stored blob), never shadow a
    // built-in id, load only if valid. Wiped on lock with the rest of the cache.
    for (service_id, toml_src) in view.aux.services.iter() {
        if state.services.get(service_id).is_some() {
            tracing::warn!(service = %service_id, "custom service shadows a built-in id — skipped");
            continue;
        }
        if let Err(e) = crate::service::validate::validate_service(toml_src) {
            tracing::warn!(service = %service_id, "custom service failed validation: {:?} — skipped", e);
            continue;
        }
        match toml::from_str::<crate::service::ServiceDef>(toml_src) {
            Ok(def) => {
                cache.custom_services.insert(service_id.clone(), def);
            }
            Err(e) => {
                tracing::warn!(service = %service_id, "custom service parse failed: {} — skipped", e)
            }
        }
    }
    cache
}

/// Residency gate shared by the unlock bootstrap and the allow-path lazy
/// fill: a connection's bytes may sit in the session cache iff its effective
/// READ floor resolves to `allow` (PROTOCOL.md §6.2 — residency mirrors the
/// decision layer, see the block comment in `bootstrap_cache_from_view`).
/// `service = None` ⇒ raw connection.
pub(crate) fn residency_read_floor_allows(
    effective_policy: &crate::core::policy::Policy,
    services: &crate::service::ServiceRegistry,
    service: Option<&str>,
    conn: &str,
) -> bool {
    let recipe = service.and_then(|s| services.default_policy_levels(s));
    let user = effective_policy
        .connections
        .get(conn)
        .and_then(|c| c.default.as_ref());
    let conn_levels = crate::core::policy::merge_levels(user, recipe.as_ref());
    let tags = service.map(|s| services.service_tags(s)).unwrap_or(&[]);
    crate::core::policy::evaluate(
        "GET",
        "/",
        None,
        &crate::core::policy::VarMap::new(),
        None,
        conn_levels.as_ref(),
        effective_policy,
        tags,
    ) == crate::core::policy::AccessLevel::Allow
}

/// Allow-path lazy residency for EXTERNAL stores (the store-agnostic half of
/// the unlock bootstrap above). The secret model is one abstraction: a
/// connection binds KEYS and policy gates CONNECTIONS — neither knows which
/// store hosts the bytes. native-secrets values are resident from unlock
/// because they're already in hand; external values are network I/O we
/// refuse to put on the unlock path, so they load on FIRST TOUCH instead:
/// same read-floor gate, same `from_bootstrap` marking, same
/// whole-session lifetime — only the load moment differs.
///
/// Returns:
///   - `Ok(true)`  — the cache now holds bytes for `conn`; retry the lookup.
///   - `Ok(false)` — nothing external to load (no stores, floor not allow,
///     or no store has the keys); fall through to the portal as before.
///   - `Err(store_id)` — a CONFIGURED store failed (auth/network). Fail
///     loudly (P2): the caller surfaces an explicit error, never a portal
///     that would misread an outage as "needs approval".
pub(crate) async fn lazy_fill_external(
    state: &AppState,
    vault_id: &str,
    conn: &str,
) -> std::result::Result<bool, String> {
    // Single-flight: a burst of first requests fills once. Waiters re-check
    // the cache under the lock and ride the winner's insert.
    let _fill = state.external_fill_lock.lock().await;

    let (policy, rec, adapters) = {
        let states = state.vault_states.lock().unwrap();
        let Some(crate::state::VaultState::Unlocked { cache, .. }) = states.get(vault_id) else {
            return Ok(false);
        };
        if cache.entries.contains_key(conn) || cache.allow_secrets.contains_key(conn) {
            return Ok(true); // another request filled while we waited
        }
        if cache.external_store_order.is_empty() {
            return Ok(false);
        }
        let adapters: Vec<(String, Arc<crate::store::Adapter>)> = cache
            .external_store_order
            .iter()
            .filter_map(|id| {
                cache
                    .external_stores
                    .get(id)
                    .map(|(_, a)| (id.clone(), a.clone()))
            })
            .collect();
        (
            cache.policy.clone(),
            cache.connections.get(conn).cloned(),
            adapters,
        )
    };

    // Service resolution: explicit record binding, else the connection id
    // names a REGISTRY service (default connection), else raw. Custom
    // (per-vault) services deliberately follow the bootstrap's behavior —
    // registry-blind residency, first use goes through the portal — so the
    // two residency paths can never disagree.
    let service = rec
        .as_ref()
        .and_then(|c| c.service.clone())
        .or_else(|| state.services.get(conn).map(|_| conn.to_string()));

    if !residency_read_floor_allows(&policy, &state.services, service.as_deref(), conn) {
        return Ok(false);
    }

    // Walk stores in vault order for one key; external keys resolve EXACT
    // (external naming is accepted as-is — no case folding). `Err(store_id)`
    // aborts the whole fill: a configured store outage must surface, not
    // degrade into "not found".
    let resolve_key = |key: String| {
        let adapters = &adapters;
        let conn = conn.to_string();
        async move {
            for (store_id, adapter) in adapters {
                match adapter.resolve(&key).await {
                    Ok(Some(bytes)) => return Ok(Some(bytes)),
                    Ok(None) => continue,
                    Err(e) => {
                        // F-20: full error server-side only; the caller
                        // returns a sanitised message.
                        tracing::warn!(store = %store_id, conn = %conn, "lazy external fill failed: {}", e);
                        return Err(store_id.clone());
                    }
                }
            }
            Ok(None)
        }
    };

    // Same shapes as the bootstrap's passes: `entries` primary from the
    // service's env-key role; `allow_secrets` map from `cacheable_roles`
    // (NOT the primary role — an oauth refresh token is resident for the
    // mint path only, never in the injectable role map); raw connections
    // map their explicit keys, sole key doubling as primary.
    let mut primary: Option<Vec<u8>> = None;
    let mut map: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    // Names that actually resolved from an external store — fed back into
    // the cache's external_keys slot so registry/entries surfaces learn
    // them even when the store's SA can't list().
    let mut fetched_keys: Vec<String> = Vec::new();
    match service.as_deref() {
        Some(svc_id) => {
            if let Some(role) = state.services.service_env_key(svc_id) {
                let key = crate::storage::plaintext::secret_key_for(rec.as_ref(), &role);
                primary = resolve_key(key.clone()).await?;
                if primary.is_some() {
                    fetched_keys.push(key);
                }
            }
            if let Some(svc) = state.services.get(svc_id) {
                for name in cacheable_roles(svc) {
                    let key = crate::storage::plaintext::secret_key_for(rec.as_ref(), &name);
                    if let Some(bytes) = resolve_key(key.clone()).await? {
                        map.insert(name, bytes);
                        fetched_keys.push(key);
                    }
                }
            }
        }
        None => {
            let Some(keys) = rec.as_ref().and_then(|c| c.secrets.clone()) else {
                return Ok(false); // raw connection with no explicit keys
            };
            for key in keys {
                if let Some(bytes) = resolve_key(key.clone()).await? {
                    map.insert(key.clone(), bytes);
                    fetched_keys.push(key);
                }
            }
            if map.len() == 1 {
                primary = map.values().next().cloned();
            }
        }
    }
    if primary.is_none() && map.is_empty() {
        return Ok(false);
    }
    {
        let mut states = state.vault_states.lock().unwrap();
        let Some(crate::state::VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id)
        else {
            return Ok(false); // locked while we were fetching — drop the bytes
        };
        if let Some(val) = primary {
            cache
                .entries
                .entry(conn.to_string())
                .or_insert(crate::state::CacheEntry {
                    value: val,
                    expires_at: None,
                    from_bootstrap: true,
                    agent_prefix: None,
                });
        }
        if !map.is_empty() {
            cache.allow_secrets.entry(conn.to_string()).or_insert(map);
        }
        cache
            .external_keys
            .lock()
            .unwrap()
            .extend(fetched_keys.iter().cloned());
    }
    tracing::info!(conn = %conn, "external store secrets resident after lazy fill");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::plaintext::{Store, VaultAux};
    use std::collections::BTreeMap;

    fn test_state() -> AppState {
        let cfg = crate::config::Config {
            state_dir: std::path::PathBuf::from(format!(
                "/tmp/safeclaw-test-approve-{}",
                std::process::id()
            )),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            rp_id: "localhost".into(),
            admin_key: None,
            relay_url: None,
            body_cap: crate::config::DEFAULT_BODY_CAP,
        };
        AppState::new(cfg)
    }

    fn gcp_store(creds_item: &str) -> Store {
        let mut extra = serde_json::Map::new();
        extra.insert(
            "project_id".into(),
            serde_json::Value::String("proj".into()),
        );
        extra.insert(
            "credentials_item".into(),
            serde_json::Value::String(creds_item.into()),
        );
        Store {
            kind: "gcp-secret-manager".into(),
            category: Category::Value,
            items: BTreeMap::new(),
            extra,
        }
    }

    /// The unlock bootstrap materialises ONE shared adapter per external
    /// store (a store whose credential is missing is skipped, not fatal)
    /// and snapshots store_order restricted to what materialised — the
    /// exact walk order `lazy_fill_external` uses.
    #[test]
    fn bootstrap_snapshots_external_adapters_and_order() {
        let state = test_state();
        let mut aux = VaultAux::initial();
        aux.stores.insert("gcpa".into(), gcp_store("GCPA_SA_JSON"));
        aux.stores.insert("gcpb".into(), gcp_store("MISSING_ITEM"));
        aux.store_order = vec!["native-secrets".into(), "gcpa".into(), "gcpb".into()];
        let mut native_secrets = BTreeMap::new();
        native_secrets.insert(
            "GCPA_SA_JSON".to_string(),
            br#"{"client_email":"sa@proj.iam.gserviceaccount.com","private_key":"not-a-real-pem"}"#
                .to_vec(),
        );
        let view = VaultPlaintextView {
            aux,
            native_secrets,
            legacy_addressing: false,
        };

        let cache = bootstrap_cache_from_view(&view, &state);

        assert!(cache.external_stores.contains_key("gcpa"));
        assert!(
            !cache.external_stores.contains_key("gcpb"),
            "store with a missing credential item must be skipped"
        );
        assert_eq!(cache.external_store_order, vec!["gcpa".to_string()]);
        let (store, adapter) = &cache.external_stores["gcpa"];
        assert_eq!(store.kind, "gcp-secret-manager");
        assert_eq!(adapter.kind(), "gcp-secret-manager");
    }

    fn export_op(target: &str) -> crate::protocol::operation::Operation {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        Operation {
            act: Act {
                kind: ActType::Export,
                target: target.into(),
                scope: serde_json::Value::Null,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        }
    }

    // An Export reveals a raw secret; its plaintext must be handed to exactly
    // ONE poll and then tombstoned, so a co-resident process can't re-fetch it
    // for the op's remaining TTL.
    #[test]
    fn export_plaintext_is_single_use_via_poll() {
        let state = test_state();
        let op_id = {
            let mut s = state.approvals.lock().unwrap();
            let id = s.create("v1".into(), export_op("GITHUB_TOKEN"), "r".into());
            s.approve(&id, Some("ghp_SECRET".into()));
            id
        };

        let first = op_poll_value(&state, &op_id).unwrap();
        assert_eq!(first["status"], "ok");
        assert_eq!(first["value"], "ghp_SECRET");

        // Second read: consumed tombstone, the plaintext is gone.
        let second = op_poll_value(&state, &op_id).unwrap();
        assert_eq!(second["status"], "consumed");
        assert!(second.get("value").and_then(|v| v.as_str()).is_none());
    }

    // A Use result is the agent's own upstream reply, which its poll loop may
    // legitimately re-read after an interrupted retry — it must NOT be consumed.
    #[test]
    fn use_result_survives_repeat_poll() {
        use crate::protocol::operation::{Act, ActType, Bind, Operation, Valid};
        let state = test_state();
        let op = Operation {
            act: Act {
                kind: ActType::Use,
                target: "github".into(),
                scope: serde_json::Value::Null,
            },
            bind: Bind {
                redeemer: "v1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        };
        let op_id = {
            let mut s = state.approvals.lock().unwrap();
            let id = s.create("v1".into(), op, "r".into());
            s.approve(&id, Some("{\"status\":200}".into()));
            id
        };

        for _ in 0..2 {
            let body = op_poll_value(&state, &op_id).unwrap();
            assert_eq!(body["status"], "ok");
            assert_eq!(body["value"]["status"], 200);
        }
    }
}
