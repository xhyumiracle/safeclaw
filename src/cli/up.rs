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
    ensure_unlocked().await?;
    warn_if_stale_after_restart().await;
    Ok(())
}

/// After a bounce, confirm the daemon that came back up is actually THIS
/// binary's version — the guarantee behind `sc upgrade` (you end up running the
/// new version, not silently the old one). The common install (unit ExecStart
/// path == the binary `sc upgrade` just overwrote) relaunches the new binary by
/// construction. This catches the rare exceptions: the service unit points at a
/// *different* `sc` (path drift), or the bounce didn't take. We can't force the
/// service from here, so we make it LOUD and actionable instead of leaving a
/// silent stale daemon. Best-effort: an unreachable or version-less daemon is
/// left alone (nothing to assert).
async fn warn_if_stale_after_restart() {
    let Ok((custodian, _vault)) = resolve_active(None) else {
        return; // nothing paired — no daemon state to verify
    };
    let want = crate::build_version();
    let want = want.trim().trim_start_matches("safeclaw ").trim();
    // ensure_unlocked already waited for the daemon; a couple of cheap retries
    // cover a still-settling health endpoint.
    for _ in 0..5 {
        let d = crate::cli::status::probe_local_daemon(&custodian).await;
        if d.up {
            match d.version.as_deref().map(|v| v.trim().trim_start_matches("safeclaw ").trim()) {
                Some(v) if v == want => return, // ✓ the new binary is serving
                Some(v) => {
                    eprintln!(
                        "⚠ The running daemon is still {v}, but this build is {want}. The upgrade\n  \
                         did not take: the service is launching a different `sc`. Fix it with:\n    \
                         sc down && sc up"
                    );
                    return;
                }
                None => return, // pre-version daemon — can't compare, don't cry wolf
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
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
