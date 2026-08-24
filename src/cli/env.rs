//! `safeclaw env` — print shell `export` lines for the DEVICE/human's shell.
//!
//! Output is meant to be evaluated by the user's shell:
//!
//! ```bash
//! eval "$(safeclaw env)"
//! ```
//!
//! `sc env` is the DEVICE/human's tool (CREDENTIAL_BROKER.md §14) — it emits
//! ONE routing var, never a key:
//!
//! - `SAFECLAW_BROKER_URL` — the resident daemon's API face
//!   (`http://127.0.0.1:<PROXY_PORT>`), for reference / manual `/health` / `/ca`.
//!
//! Deliberately NOT emitted: `SAFECLAW_VAULT_ID`. A durable pin in a human
//! shell shadows `sc vault use` forever (design/vault-addressing.md) — vault
//! follows the device default; per-call override is the global `--vault`.
//! The pin's one legitimate minter is `sc run`, which injects it into the
//! child it launches.
//!
//! The AGENT's config (routing var PLUS its per-agent identity path
//! `SAFECLAW_AGENT_IDENTITY`) is minted whole by `sc agent add`, not here: each
//! agent holds its own AIK identity file, so `sc env` (device scope) must never
//! emit an agent identity — that would collapse every agent on the device to one.
//! See [[project_vault_agent_architecture_2026_06_25]] / CREDENTIAL_BROKER.md §14.

use crate::cli::active::{device_daemon_host, load as load_config};
use crate::config::PROXY_PORT;

pub fn run() -> Result<(), String> {
    // Device atoms only — never the process env (`sc env` MINTS output; a
    // re-eval that read its own prior output would freeze stale values).
    let cfg = load_config()?;
    let broker_url = format!("{}:{}", device_daemon_host(&cfg), PROXY_PORT);
    println!("export SAFECLAW_BROKER_URL={}", shell_quote(&broker_url));
    Ok(())
}

/// POSIX-safe single-quote escaping. Wraps the value in `'...'` and
/// turns inner `'` into the canonical `'\''` close-escape-reopen
/// sequence. Empty strings stay as `''`. Single-quoting also makes git's
/// `!sc git-credential` helper marker literal (no history expansion). Shared
/// with `sc run --export-env`.
pub(crate) fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("abc"), "'abc'");
        assert_eq!(shell_quote("ab c"), "'ab c'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }
}
