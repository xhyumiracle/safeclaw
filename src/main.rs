//! Thin binary wrapper. The entire CLI + daemon lives in
//! [`safeclaw::entry::run_cli`] so the open-source `safeclaw`/`sc` bins and the
//! closed `safeclaw-ee` overlay's bin share it verbatim, differing ONLY in which
//! [`safeclaw::team_hooks::TeamHooks`] implementation they inject. The open
//! build wires `NoopHooks` (no team policy whatsoever); the official binary's
//! `safeclaw-ee` crate injects the real team hooks. See team-edition §9.

use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    safeclaw::entry::run_cli(Arc::new(safeclaw::team_hooks::NoopHooks)).await
}
