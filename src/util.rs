//! Small cross-cutting helpers with no better home.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time in unix seconds, saturating to 0 before the epoch
/// (never in practice). One shared definition for the identity-wave call sites
/// (`device_auth`, `agent_pop`/`agent_shim`, the proxy handler) that each used to
/// carry their own copy of this idiom.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
