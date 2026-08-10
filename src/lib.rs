/// The version string every user-facing surface prints (`sc version`,
/// `/health`, doctor, upgrade). Release CI stamps the git tag into the build
/// via `.build-tag` (see build.rs), so pre-release binaries self-report
/// "0.9.48-rc.6" instead of the bare Cargo version — Cargo.toml stays bare by
/// the release-channel convention (tags carry the rc suffix, the manifest
/// never does). Local/dev builds have no tag file and fall back to the Cargo
/// version. Display-only: nothing compares this string (upgrade's up-to-date
/// check is binary-hash equality).
pub fn build_version() -> &'static str {
    match option_env!("SC_BUILD_TAG") {
        Some(tag) if !tag.trim().is_empty() => tag.trim().trim_start_matches('v'),
        _ => env!("CARGO_PKG_VERSION"),
    }
}

pub mod agent_pop;
pub mod api_key;
pub mod approval;
pub mod audit;
pub mod auth;
pub mod cli;
pub mod config;
pub mod core;
pub mod crypto;
pub mod device_auth;
pub mod entry;
pub mod error;
mod generated_services;
pub mod identity;
pub mod identity_file;
pub mod passkey;
pub mod protocol;
pub mod proxy;
pub mod relay;
pub mod server;
pub mod service;
pub mod state;
pub mod storage;
pub mod store;
pub mod sync;
pub mod sync_stream;
pub mod team_hooks;
