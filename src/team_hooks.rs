//! Team-edition extension hooks (team-edition §9 open/closed split).
//!
//! Team-EXCLUSIVE client policy — the shared-vault offline lease, invite
//! redemption, member handling — is closed-source and lives in the private
//! `safeclaw-ee` overlay crate, NEVER in this open repo. Core exposes only these
//! neutral extension points; the open-source build wires [`NoopHooks`] (no team
//! behavior at all, so a personal vault is never gated), while the official
//! binary's `safeclaw-ee` crate provides real implementations and injects them
//! via [`crate::state::AppState::with_team_hooks`].
//!
//! What stays in open core is neutral per-vault bookkeeping the hooks READ
//! (`vault_is_shared`, `cloud_contact_age_secs`); what a hook DECIDES with it
//! (deny service, redeem an invite, offboard a member) is the closed policy.

use crate::error::ScCode;
use crate::state::AppState;

/// A serve-time refusal: the structured code + human message the proxy turns
/// into its usual RFC9457 error response.
pub struct GateDenial {
    pub code: ScCode,
    pub message: String,
}

/// Extension points the closed `safeclaw-ee` overlay implements. Every method
/// has a no-op default, so the open-source build (which wires [`NoopHooks`])
/// carries zero team policy.
pub trait TeamHooks: Send + Sync {
    /// Called on every brokered request after the vault is resolved + unlocked
    /// and before a credential is served. Return `Some(GateDenial)` to REFUSE
    /// (e.g. the shared-vault offline lease has expired); `None` to allow.
    /// Default: allow (a personal build never gates).
    fn serve_gate(&self, _state: &AppState, _vault_id: &str) -> Option<GateDenial> {
        None
    }

    /// Called on the serve path right after a vault is unlocked (K in hand). The
    /// overlay uses it to register serve-time team policy that depends on the
    /// unlocked key, e.g. the SHARED-vault owner lock-list (the blinded ids of the
    /// owner-only config the backend write-gates so a non-owner member can't
    /// overwrite it). The gated set is team POLICY and lives in the closed overlay;
    /// core exposes only the neutral id primitive ([`crate::storage::item::aux_item_id`]).
    /// Default: no-op (a personal / open-source build registers nothing).
    fn on_vault_unlocked(&self, _state: &AppState, _vault_id: &str, _k: &[u8]) {}
}

/// The open-source build's hooks: no team behavior whatsoever. A personal vault
/// is never leased or gated.
pub struct NoopHooks;

impl TeamHooks for NoopHooks {}
