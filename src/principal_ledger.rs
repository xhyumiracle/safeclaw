//! §15 account principal ledger — daemon-side sync + verify + enforce.
//!
//! The cloud serves an append-only, owner-UIK-signed log of device/agent ADMIT +
//! REVOKE events at `GET /api/vault/principals`. This module pulls it, verifies
//! every event against the ACCOUNT ANCHOR (the owner UIK, self-certifying:
//! `derive_id(User, uik_pub) == anchor_uik`), folds by monotone `seq`, and — behind
//! a flag, DEFAULT OFF until the P6 cutover — ENFORCES a verified revoke of THIS
//! device by locking + wiping every local vault + logging out.
//!
//! Invariants (design §15):
//! - Destructive action fires ONLY on a daemon-VERIFIED owner signature, NEVER on a
//!   bare 401 (that class caused the transient-403 mass-outage incident; a fetch
//!   failure just parks and keeps the prior decision).
//! - The `anchor_uik`, trusted-on-pairing (TOFU), IS the anchor: a swapped anchor
//!   pubkey fails the self-cert check and the whole pull is rejected. No separate
//!   pin file is needed (the per-vault genesis-anchor trick, lifted to account scope).
//! - Rollback-resistant: a verified self-revoke LATCHES to disk (`principal_floor.json`),
//!   and a later pull whose max `seq` regresses below the recorded floor is ignored, so
//!   a malicious server dropping the revoke event cannot un-revoke a device.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::device_auth::DikRequestExt;
use crate::identity::{self, IdKind};
use crate::state::AppState;

// ── Wire shapes (GET /api/vault/principals) ─────────────────────────────────

#[derive(Debug, Deserialize)]
struct AnchorJson {
    #[allow(dead_code)]
    uik_id: String,
    /// base64 raw 32-byte Ed25519 owner-UIK signing pubkey (public — `derive_id`
    /// is one-way, so serving it leaks nothing).
    uik_pub: String,
}

#[derive(Debug, Deserialize)]
struct PrincipalEventJson {
    seq: u64,
    op: String,           // "admit" | "revoke"
    principal_id: String, // dev_… / ag_…
    #[serde(default)]
    #[allow(dead_code)]
    principal_kind: String,
    #[serde(default)]
    anchor_uik: String,
    owner_id: String,
    sig: String, // base64 raw 64-byte Ed25519
    #[serde(default)]
    #[allow(dead_code)]
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct LedgerJson {
    #[serde(default)]
    events: Vec<PrincipalEventJson>,
    #[serde(default)]
    anchor: Option<AnchorJson>,
    #[serde(default)]
    #[allow(dead_code)]
    cursor: u64,
}

/// The folded outcome of a verified ledger.
#[derive(Debug, Default)]
struct Folded {
    /// principal ids whose FINAL folded state is revoked.
    revoked: HashSet<String>,
    /// highest `seq` among applied (verified) events.
    max_seq: u64,
}

/// Persisted, rollback-resistant decision floor (`<state_dir>/principal_floor.json`).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct LedgerFloor {
    #[serde(default)]
    seq: u64,
    /// Latched once THIS device's own revoke is verified; a later regressed pull
    /// (server dropped the event) can never clear it.
    #[serde(default)]
    self_revoked: bool,
}

// ── Flag ────────────────────────────────────────────────────────────────────

/// Enforcement flag — DEFAULT OFF until the P6 cutover. A NEW destructive behavior
/// opts IN (the inverse of the `sync_stream` kill switch, which opts out).
/// `SAFECLAW_PRINCIPAL_ENFORCE` wins over the `principal_enforce` config key (the env
/// var survives an old binary's config save, so it is the robust lever either way).
pub fn principal_enforce_enabled() -> bool {
    let v = std::env::var("SAFECLAW_PRINCIPAL_ENFORCE")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            crate::cli::active::load()
                .ok()
                .and_then(|c| c.principal_enforce)
                .map(|s| s.trim().to_ascii_lowercase())
        });
    matches!(v.as_deref(), Some("on" | "1" | "true" | "yes" | "enabled"))
}

/// §15 leg-A require-signed-tombstone flag — DEFAULT OFF (an unsigned `status:"deleted"`
/// still drops local state, the legacy behavior). `SAFECLAW_REQUIRE_SIGNED_TOMBSTONE`
/// wins over `CliConfig.require_signed_tombstone`. Flipped on at the P6 cutover so a
/// server can no longer force a local wipe by flipping `status` without a valid
/// owner-signed tombstone (verified against the vault's fold-owner set).
pub fn require_signed_tombstone() -> bool {
    let v = std::env::var("SAFECLAW_REQUIRE_SIGNED_TOMBSTONE")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            crate::cli::active::load()
                .ok()
                .and_then(|c| c.require_signed_tombstone)
                .map(|s| s.trim().to_ascii_lowercase())
        });
    matches!(v.as_deref(), Some("on" | "1" | "true" | "yes" | "enabled"))
}

// ── base64 → fixed arrays ────────────────────────────────────────────────────

fn decode_pub32(b64: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(STANDARD.decode(b64).ok()?.as_slice()).ok()
}

fn decode_sig64(b64: &str) -> Option<[u8; 64]> {
    <[u8; 64]>::try_from(STANDARD.decode(b64).ok()?.as_slice()).ok()
}

// ── Pull ──────────────────────────────────────────────────────────────────

/// GET the account principal ledger with device-key bearer + DIK PoP (same auth
/// shape as vault discovery). Best-effort: any failure returns `None` and the
/// caller PARKS (keeps the prior decision) — a fetch failure is never a revoke.
async fn fetch_ledger(cloud: &str, dk: &str) -> Option<LedgerJson> {
    let cloud = cloud.trim_end_matches('/');
    let url = format!("{}/api/vault/principals", cloud);
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15)).ok()?;
    let resp = client
        .get(&url)
        .bearer_auth(dk)
        .dik_pop("GET", &url, &[])
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        // 404 = a backend that predates the ledger; anything else transient. Park.
        tracing::debug!(status = %resp.status(), "principal ledger: non-success (old backend / transient)");
        return None;
    }
    resp.json().await.ok()
}

// ── Verify + fold ────────────────────────────────────────────────────────────

/// Verify every event against the account anchor and fold admit/revoke by monotone
/// `seq`. Returns `None` (fail closed → park) iff the anchor is missing or does NOT
/// self-certify against `anchor_uik` (a swapped anchor = untrusted source). An
/// individually invalid event (bad sig, foreign owner, unknown op) is SKIPPED, not
/// fatal — mirrors the per-vault `fold_owner_set`.
fn fold_verified(ledger: &LedgerJson, anchor_uik: &str) -> Option<Folded> {
    let anchor = ledger.anchor.as_ref()?;
    let anchor_pub = decode_pub32(&anchor.uik_pub)?;
    // Self-cert: the anchor pubkey MUST derive to the anchor_uik we pinned at pairing.
    if identity::derive_id(IdKind::User, &anchor_pub) != anchor_uik {
        tracing::warn!("principal ledger: anchor pubkey does not self-certify against anchor_uik; rejecting pull");
        return None;
    }

    // Deterministic total order; strictly-increasing seq (consumed-seq dup guard).
    let mut events: Vec<&PrincipalEventJson> = ledger.events.iter().collect();
    events.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.sig.cmp(&b.sig)));

    let mut present: HashMap<String, bool> = HashMap::new();
    let mut last_seq: Option<u64> = None;
    let mut max_seq: u64 = 0;
    for e in events {
        if matches!(last_seq, Some(ls) if e.seq <= ls) {
            continue; // duplicate/backwards seq at the same position — keep the first
        }
        // The signer must be the account owner (owner_id == the anchor id), and the
        // event's own anchor_uik (when carried) must match too.
        if e.owner_id != anchor_uik {
            tracing::warn!(seq = e.seq, "principal ledger: event owner_id != account anchor; skipping");
            continue;
        }
        if !e.anchor_uik.is_empty() && e.anchor_uik != anchor_uik {
            tracing::warn!(seq = e.seq, "principal ledger: event anchor_uik mismatch; skipping");
            continue;
        }
        let Some(sig) = decode_sig64(&e.sig) else {
            tracing::warn!(seq = e.seq, "principal ledger: undecodable signature; skipping");
            continue;
        };
        // anchor_uik is the first signed field (== anchor for a personal account).
        let input = identity::principal_event_input(anchor_uik, &e.op, &e.principal_id, e.seq, &e.owner_id);
        if !identity::verify(&anchor_pub, &input, &sig) {
            tracing::warn!(seq = e.seq, "principal ledger: signature does not verify; skipping");
            continue;
        }
        last_seq = Some(e.seq);
        max_seq = max_seq.max(e.seq);
        match e.op.as_str() {
            "admit" => {
                present.insert(e.principal_id.clone(), true);
            }
            "revoke" => {
                present.insert(e.principal_id.clone(), false);
            }
            other => tracing::warn!(op = %other, "principal ledger: unknown op; skipping"),
        }
    }
    let revoked = present
        .into_iter()
        .filter(|(_, live)| !*live)
        .map(|(id, _)| id)
        .collect();
    Some(Folded { revoked, max_seq })
}

// ── Floor persistence (rollback resistance) ─────────────────────────────────

fn floor_path(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("principal_floor.json")
}

fn load_floor(state_dir: &Path) -> LedgerFloor {
    std::fs::read_to_string(floor_path(state_dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn store_floor(state_dir: &Path, floor: &LedgerFloor) {
    if let Ok(json) = serde_json::to_string(floor) {
        if let Err(e) = std::fs::write(floor_path(state_dir), json) {
            tracing::warn!("principal ledger: failed to persist floor: {}", e);
        }
    }
}

// ── Enforcement ──────────────────────────────────────────────────────────────

/// Self-revoke enforcement: the owner revoked THIS device. Lock + wipe every local
/// vault (evict retained K + delete sealed blobs, in-process — no CLI), delete the
/// device-key, clear the pairing config, then EXIT. "A revoked device can't use
/// secrets" (design §15). Does not return.
async fn self_wipe_and_logout(state: &Arc<AppState>) -> ! {
    tracing::warn!(
        "principal ledger: THIS DEVICE was revoked by the account owner (VERIFIED signature) — \
         locking + wiping all local vaults and logging out"
    );
    // 1. Lock + wipe every synced vault, in-process (zeroize retained K + remove the
    //    sealed blob), through the same locked drop the tombstone path uses.
    let vaults: Vec<String> = crate::cli::active::known_vaults()
        .into_iter()
        .map(|kv| kv.vault)
        .filter(|v| !v.is_empty())
        .collect();
    for vid in vaults {
        crate::sync::drop_local_vault_locked(state, &vid).await;
    }
    // 2. Delete the device-key (this host's cloud credential): once gone, the bearer
    //    can never be matched again.
    if let Some(home) = dirs::home_dir() {
        let _ = std::fs::remove_file(home.join(".safeclaw").join("device-key"));
    }
    // 3. Clear the pairing from config + known-vaults (mirrors `sc logout`).
    if let Err(e) = crate::cli::active::clear_pairing() {
        tracing::warn!("principal ledger: failed to clear pairing config on self-revoke: {}", e);
    }
    // 4. Stop serving. With K evicted, blobs wiped, and the pairing gone, the daemon
    //    must not keep running; process exit is the in-process equivalent of the CLI
    //    `sc logout` stopping it.
    tracing::warn!("principal ledger: local state wiped; daemon exiting (re-pair with `sc login`)");
    std::process::exit(0);
}

// ── Loop ──────────────────────────────────────────────────────────────────

/// Periodic principal-ledger poll: pull → verify + fold → (flag-gated) enforce a
/// verified self-revoke. Spawned once per paired daemon (like the vault-discovery
/// reconcile loop). `anchor_uik` is the account's owner-UIK id (`us_…`) pinned at
/// pairing — the self-certifying ledger anchor (NOT the Supabase account UUID).
pub async fn principal_ledger_loop(state: Arc<AppState>, cloud: String, dk: String, anchor_uik: String) {
    /// Poll cadence. A revoke propagates within one interval of the owner tapping
    /// (or instantly on the next daemon start via the latched floor).
    const INTERVAL: Duration = Duration::from_secs(120);
    let state_dir = state.config.state_dir.clone();

    // Honor a latch that survived a restart FIRST: if this device was already
    // verified-revoked and enforcement is on, wipe immediately on start.
    let mut floor = load_floor(&state_dir);
    if floor.self_revoked && principal_enforce_enabled() {
        self_wipe_and_logout(&state).await;
    }

    loop {
        // Work first (immediate check on start), then wait — a fresh revoke enforces
        // within one poll of daemon start rather than after a full INTERVAL.
        if let Some(ledger) = fetch_ledger(&cloud, &dk).await {
            if let Some(folded) = fold_verified(&ledger, &anchor_uik) {
                if folded.max_seq < floor.seq {
                    // Rollback: the server dropped a higher-seq event we already saw.
                    // Ignore this pull and keep the prior (latched) decision.
                    tracing::warn!(
                        max = folded.max_seq,
                        floor = floor.seq,
                        "principal ledger: pull regressed below the known seq (rollback?); ignoring, keeping prior decision"
                    );
                } else {
                    let my_dev = crate::device_auth::device_signer()
                        .map(|s| s.device_id().to_string());
                    let self_revoked = my_dev
                        .as_deref()
                        .map(|d| folded.revoked.contains(d))
                        .unwrap_or(false);
                    // Adopt this (non-regressed) fold's decision; latch is monotone in
                    // seq, so a real re-admit at a higher seq can clear it but a rollback
                    // cannot.
                    if folded.max_seq > floor.seq || self_revoked != floor.self_revoked {
                        floor = LedgerFloor { seq: folded.max_seq.max(floor.seq), self_revoked };
                        store_floor(&state_dir, &floor);
                    }
                    if self_revoked {
                        if principal_enforce_enabled() {
                            self_wipe_and_logout(&state).await;
                        } else {
                            tracing::warn!(
                                device = ?my_dev,
                                "principal ledger: THIS device is revoked (VERIFIED) but enforcement is OFF \
                                 (SAFECLAW_PRINCIPAL_ENFORCE); NOT wiping — the P6 cutover flips the default"
                            );
                        }
                    }
                    // Agent revokes need no separate action in P4: the existing
                    // /agents/hashes sync already stops serving a revoked agent's key
                    // (the backend drops it). The ledger is the account-level record +
                    // the daemon-verifiable authority the P6 cutover enforces directly.
                }
            }
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SigningIdentity;

    // Deterministic owner UIK for the vectors below.
    const OWNER_SEED: [u8; 32] = [7u8; 32];

    fn owner() -> SigningIdentity {
        SigningIdentity::from_seed(&OWNER_SEED)
    }

    fn signed_event(owner: &SigningIdentity, anchor_uik: &str, op: &str, principal: &str, seq: u64) -> PrincipalEventJson {
        let input = identity::principal_event_input(anchor_uik, op, principal, seq, anchor_uik);
        let sig = owner.sign(&input);
        PrincipalEventJson {
            seq,
            op: op.to_string(),
            principal_id: principal.to_string(),
            principal_kind: if principal.starts_with("dev_") { "device" } else { "agent" }.to_string(),
            anchor_uik: anchor_uik.to_string(),
            owner_id: anchor_uik.to_string(),
            sig: STANDARD.encode(sig),
            created_at: String::new(),
        }
    }

    fn ledger(owner: &SigningIdentity, events: Vec<PrincipalEventJson>) -> LedgerJson {
        LedgerJson {
            events,
            anchor: Some(AnchorJson {
                uik_id: owner.user_id(),
                uik_pub: STANDARD.encode(owner.public_bytes()),
            }),
            cursor: 0,
        }
    }

    #[test]
    fn admit_then_revoke_folds_to_revoked() {
        let o = owner();
        let acct = o.user_id();
        let l = ledger(&o, vec![
            signed_event(&o, &acct, "admit", "dev_box", 1),
            signed_event(&o, &acct, "revoke", "dev_box", 2),
        ]);
        let folded = fold_verified(&l, &acct).expect("trusted anchor folds");
        assert!(folded.revoked.contains("dev_box"), "final state is revoked");
        assert_eq!(folded.max_seq, 2);
    }

    #[test]
    fn revoke_then_readmit_clears() {
        let o = owner();
        let acct = o.user_id();
        let l = ledger(&o, vec![
            signed_event(&o, &acct, "admit", "dev_box", 1),
            signed_event(&o, &acct, "revoke", "dev_box", 2),
            signed_event(&o, &acct, "admit", "dev_box", 3),
        ]);
        let folded = fold_verified(&l, &acct).unwrap();
        assert!(!folded.revoked.contains("dev_box"), "a higher-seq re-admit un-revokes");
        assert_eq!(folded.max_seq, 3);
    }

    #[test]
    fn wrong_anchor_rejects_whole_pull() {
        let o = owner();
        let acct = o.user_id();
        let mut l = ledger(&o, vec![signed_event(&o, &acct, "revoke", "dev_box", 1)]);
        // Swap the anchor pubkey to a different key: self-cert (derive_id == anchor_uik) fails.
        let imposter = SigningIdentity::from_seed(&[9u8; 32]);
        l.anchor = Some(AnchorJson { uik_id: imposter.user_id(), uik_pub: STANDARD.encode(imposter.public_bytes()) });
        assert!(fold_verified(&l, &acct).is_none(), "a swapped anchor is untrusted → park");
    }

    #[test]
    fn forged_signature_event_is_skipped_not_fatal() {
        let o = owner();
        let acct = o.user_id();
        let mut forged = signed_event(&o, &acct, "revoke", "dev_box", 2);
        // Corrupt the signature: this event must be skipped, the valid admit still applies.
        forged.sig = STANDARD.encode([0u8; 64]);
        let l = ledger(&o, vec![signed_event(&o, &acct, "admit", "ag_bot", 1), forged]);
        let folded = fold_verified(&l, &acct).expect("valid anchor");
        assert!(!folded.revoked.contains("dev_box"), "forged revoke is skipped");
        assert!(!folded.revoked.contains("ag_bot"), "ag_bot was admitted, not revoked");
        assert_eq!(folded.max_seq, 1, "only the verified admit counts");
    }

    #[test]
    fn foreign_owner_event_is_skipped() {
        let o = owner();
        let acct = o.user_id();
        // An event whose owner_id is someone else, but signed by our owner (a confused
        // or malicious re-attribution): owner_id != account anchor → skipped.
        let mut ev = signed_event(&o, &acct, "revoke", "dev_box", 1);
        ev.owner_id = "us_someone_else".to_string();
        let l = ledger(&o, vec![ev]);
        let folded = fold_verified(&l, &acct).unwrap();
        assert!(folded.revoked.is_empty(), "foreign-owner event does not revoke");
    }
}
