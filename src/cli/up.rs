//! `sc up` — bring SafeClaw to a ready state: ensure the local daemon is
//! running, then make sure the vault is unlocked.
//!
//! Unlock is invisible by design. `ensure_unlocked` below is the ONLY place
//! `run_unlock` is invoked — `sc up` and `sc login` both route through it, and
//! everything else (an `sc upgrade` restart, the agent's lazy-start `sc up`)
//! goes through `sc up`. So the user never runs a separate "unlock" command and
//! never confuses the local vault state with the web console's unlock — they
//! just tap their passkey when SafeClaw asks.

use std::time::Duration;

use crate::cli::active::{resolve_active, settings_cb_port};
use crate::cli::status::{fetch_status, VaultState};
use crate::cli::{service, unlock};
use crate::config::UnlockArgs;

/// `sc up`: get SafeClaw ready — install the daemon service on first run (so
/// there's no separate setup step), make sure it's running, then unlock.
pub async fn run() -> Result<(), String> {
    if service::unit_installed() {
        // Migrate a unit installed by an older build (ExecStart=… custodian run)
        // to `serve` before starting it — `custodian` no longer exists.
        let _ = service::reconcile_unit_execstart();
        service::run_ensure_running()?;
    } else {
        // First `sc up` on this host: install + enable + start the user service.
        service::run_start_systemd(false).await?;
    }
    ensure_unlocked().await
}

/// `sc restart`: force a fresh daemon process, then converge back to ready.
///
/// A process bounce wipes the in-memory vault keys, so a bare `systemctl
/// restart` would leave the vault Locked — a *different* end-state than `sc up`.
/// To keep the verb taxonomy honest (every "make it run" verb lands you ready),
/// `restart` reconciles a stale unit first (like `up`), bounces, then routes
/// through the same `ensure_unlocked` chokepoint. `sc upgrade` (and, going
/// forward, `sc login`) reuse this so they can't silently leave you locked
/// onto a freshly-started daemon either.
pub async fn restart() -> Result<(), String> {
    let _ = service::reconcile_unit_execstart();
    service::run_restart()?;
    ensure_unlocked().await
}

/// The single unlock chokepoint. If the active vault is Locked, run the passkey
/// unlock; otherwise no-op (already unlocked, or no vault selected). Waits
/// briefly for the daemon to finish pulling the vault on a fresh start.
/// Best-effort: an unreachable daemon just isn't unlocked here.
pub async fn ensure_unlocked() -> Result<(), String> {
    // Pairing is DEVICE state — an env pin alone (a stale agent .env after
    // `sc logout`) must not send us into the reachability wait below. Before
    // the default-daemon change, cfg.daemon=None made resolve_active err here;
    // same instant no-op, now stated explicitly.
    let cfg = crate::cli::active::load().unwrap_or_default();
    if cfg.vault.is_none()
        && cfg.cloud_backend.is_none()
        && crate::cli::active::known_vaults().is_empty()
    {
        return Ok(()); // nothing paired yet — nothing to unlock
    }
    let (custodian, vault) = match resolve_active(None) {
        Ok(v) => v,
        Err(_) => return Ok(()), // nothing paired yet — nothing to unlock
    };

    // The daemon pulls the sealed vault on start; give it a moment to serve.
    let mut status = fetch_status(&custodian, &vault).await;
    for _ in 0..15 {
        if !matches!(status.state, VaultState::Unreachable | VaultState::NotFound) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        status = fetch_status(&custodian, &vault).await;
    }

    if should_attempt_unlock(&status.state) {
        let args = UnlockArgs {
            no_browser: false,
            cb_port: settings_cb_port(),
            timeout: 120,
        };
        unlock::run_unlock(args).await?;
    }
    Ok(())
}

/// Whether `ensure_unlocked` should attempt a passkey unlock for this state.
/// Only a Locked vault needs it: Unlocked is a no-op, and Unreachable/NotFound
/// mean there's nothing here to unlock (the caller already waited for the
/// daemon to come up). Pulled out so the convergence decision is unit-testable
/// — the regression we guard is that `up`/`restart`/`upgrade` all still
/// re-unlock after a bounce instead of leaving the vault silently Locked.
fn should_attempt_unlock(state: &VaultState) -> bool {
    matches!(state, VaultState::Locked { .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_only_when_locked() {
        assert!(should_attempt_unlock(&VaultState::Locked { passkeys: 1 }));
        assert!(!should_attempt_unlock(&VaultState::Unlocked {
            passkeys: 1,
            secrets: 3
        }));
        assert!(!should_attempt_unlock(&VaultState::Unreachable));
        assert!(!should_attempt_unlock(&VaultState::NotFound));
    }
}
