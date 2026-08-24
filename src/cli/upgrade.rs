//! `sc upgrade` — built-in self-update.
//!
//! Mirrors `install.sh`: downloads the prebuilt binary for this platform from
//! the project's LATEST GitHub Release, verifies its sha256 against the
//! release's published `SHA256SUMS`, and atomically replaces the running
//! binary. This is the ONLY supported way to change which cloud the daemon
//! pairs with (the cloud URL is baked, not config) — a domain move ships as a
//! new release. See [[project_vault_agent_architecture_2026_06_25]].
//!
//! Version-scheme-agnostic: rather than parse tags, it compares the verified
//! download's hash to the running binary's hash and is a no-op when they match
//! ("already up to date"). `--force` rewrites anyway.
//!
//! Channels are DERIVED from the cloud this host is paired to, not from a flag:
//! a `dev.*` login is a dogfood box and tracks PRE-RELEASES (the newest
//! `vX.Y.Z-rc.N`, resolved via the releases API); prod / self-host / unpaired
//! track the STABLE line (GitHub's `releases/latest`, which excludes
//! pre-releases). So a dogfood box needs no flag — plain `sc upgrade` already
//! follows rc, and can't be silently downgraded back to stable by a forgotten
//! flag; and rc builds still can't reach a prod-paired user, who derives stable.
//! This mirrors the backend's registry channel, which likewise keys off the
//! `dev.` frontend host rather than a parallel indicator (see
//! [[project_release_channels]]). `--prerelease` / `--stable` force a channel for the
//! rare cross-grain case (pull an rc while on prod, or drop a dev box to stable).

use std::time::Duration;

use crate::cli::active::frontend_origin;
use crate::config::UpgradeArgs;

const REPO: &str = "SafeClaw-OSS/safeclaw";
/// Stable channel: GitHub's `latest` pointer, which by definition skips
/// pre-releases and drafts — the asset base every ordinary `sc upgrade` uses.
const LATEST_BASE: &str = "https://github.com/SafeClaw-OSS/safeclaw/releases/latest/download";

/// Map the build target to the release asset name (matches install.sh + CI).
fn asset_name() -> Result<&'static str, String> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "safeclaw-linux-x86_64",
        ("linux", "aarch64") => "safeclaw-linux-aarch64",
        ("macos", "x86_64") => "safeclaw-macos-x86_64",
        ("macos", "aarch64") => "safeclaw-macos-aarch64",
        (os, arch) => return Err(format!("unsupported platform {}/{}", os, arch)),
    })
}

/// Decide the release channel and WHY, before any network call. Explicit flags
/// win (`--stable` > derivation, `--prerelease` > derivation; the two can't co-occur,
/// clap `conflicts_with`). Otherwise it's derived from the paired cloud's
/// frontend host: a `dev.` prefix (e.g. `dev.safeclaw.pro`) is a dogfood box and
/// tracks pre-releases; prod, self-host, and an unpaired daemon all track stable
/// — the conservative default. The `dev.` test is the SAME signal the backend's
/// registry channel uses, so the two never disagree about what "dev" means.
/// Returns `(want_prerelease, reason)`; `reason` is surfaced so the user can see
/// which channel ran and why it was chosen.
fn resolve_channel(args: &UpgradeArgs) -> (bool, String) {
    if args.stable {
        return (false, "stable (--stable)".to_string());
    }
    if args.prerelease {
        return (true, "pre-release (--prerelease)".to_string());
    }
    match frontend_origin() {
        Some(origin) if origin_host(&origin).starts_with("dev.") => (
            true,
            format!("pre-release (paired to {})", origin_host(&origin)),
        ),
        Some(origin) => (
            false,
            format!("stable (paired to {})", origin_host(&origin)),
        ),
        None => (false, "stable (not paired)".to_string()),
    }
}

/// `https://dev.safeclaw.pro/foo` → `dev.safeclaw.pro`. Scheme and any path are
/// dropped; a bare host (no scheme) is returned unchanged.
fn origin_host(origin: &str) -> &str {
    origin
        .split_once("://")
        .map_or(origin, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or(origin)
}

/// Resolve the asset base URL for the chosen channel, plus a short label for
/// user messaging. Stable → GitHub's `latest/download` (no API call).
/// Pre-release → query the releases API for the newest release (index 0,
/// newest-first, INCLUDING pre-releases) and point at its
/// `releases/download/<tag>` assets.
async fn resolve_base(client: &reqwest::Client, pre: bool) -> Result<(String, String), String> {
    if !pre {
        return Ok((LATEST_BASE.to_string(), "latest stable".to_string()));
    }
    // GitHub requires a User-Agent; the API returns releases newest-first and,
    // unauthenticated, includes pre-releases but not drafts (CI never drafts).
    let url = format!("https://api.github.com/repos/{}/releases?per_page=1", REPO);
    let resp = client
        .get(&url)
        .header("User-Agent", "safeclaw-upgrade")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("query releases: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("query releases: HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parse releases: {}", e))?;
    let tag = body
        .as_array()
        .and_then(|a| a.first())
        .and_then(|r| r.get("tag_name"))
        .and_then(|t| t.as_str())
        .ok_or("no releases found (including pre-releases)")?;
    let base = format!("https://github.com/{}/releases/download/{}", REPO, tag);
    Ok((base, format!("pre-release {}", tag)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Pull the expected hash for `asset` out of a `SHA256SUMS` file body
/// (`<hex>␠␠<name>` or `<hex>␠<name>` lines, as produced by sha256sum/shasum).
fn expected_hash(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hex = parts.next()?;
        let name = parts.next()?;
        (name == asset).then(|| hex.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pre: bool, stable: bool) -> UpgradeArgs {
        UpgradeArgs {
            force: false,
            prerelease: pre,
            stable,
        }
    }

    #[test]
    fn origin_host_strips_scheme_and_path() {
        assert_eq!(
            origin_host("https://dev.safeclaw.pro/grant/x"),
            "dev.safeclaw.pro"
        );
        assert_eq!(origin_host("https://safeclaw.pro"), "safeclaw.pro");
        assert_eq!(origin_host("bare.host.example"), "bare.host.example");
    }

    #[test]
    fn explicit_flags_override_derivation() {
        // Flags don't read config — they short-circuit before derivation, so
        // these hold regardless of how this host is paired.
        let (pre, why) = resolve_channel(&args(false, true));
        assert!(!pre, "--stable forces stable");
        assert!(why.contains("--stable"));

        let (pre, why) = resolve_channel(&args(true, false));
        assert!(pre, "--prerelease forces pre-release");
        assert!(why.contains("--prerelease"));
    }
}

pub async fn run(args: UpgradeArgs) -> Result<(), String> {
    let asset = asset_name()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;

    // 0. Resolve which release to pull from. The channel is derived from the
    //    paired cloud (dev → pre-release, prod/self-host/unpaired → stable),
    //    unless `--prerelease`/`--stable` force it. Stable = GitHub's `latest` pointer
    //    (skips pre-releases); pre-release = the newest release incl.
    //    pre-releases, resolved by tag → the exact `releases/download/<tag>` base.
    let (want_pre, reason) = resolve_channel(&args);
    let (base, channel) = resolve_base(&client, want_pre).await?;
    eprintln!("Channel: {} — {}.", channel, reason);

    // 1. Fetch the published checksums first — refuse to install anything we
    //    can't verify (unlike install.sh, which warns-and-continues; a
    //    self-replacing binary is higher-stakes, so we hard-fail).
    let sums_url = format!("{}/SHA256SUMS", base);
    let sums = client
        .get(&sums_url)
        .send()
        .await
        .map_err(|e| format!("fetch SHA256SUMS: {}", e))?;
    if !sums.status().is_success() {
        return Err(format!("fetch SHA256SUMS: HTTP {}", sums.status()));
    }
    let sums = sums
        .text()
        .await
        .map_err(|e| format!("read SHA256SUMS: {}", e))?;
    let expected = expected_hash(&sums, asset)
        .ok_or_else(|| format!("no checksum for {} in the latest release", asset))?;

    // 2. Download the asset.
    let asset_url = format!("{}/{}", base, asset);
    eprintln!("Fetching {} ({})…", asset, channel);
    let resp = client
        .get(&asset_url)
        .send()
        .await
        .map_err(|e| format!("download {}: {}", asset, e))?;
    if !resp.status().is_success() {
        return Err(format!("download {}: HTTP {}", asset, resp.status()));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("read {}: {}", asset, e))?;

    // 3. Verify integrity before it touches disk.
    let actual = sha256_hex(&bytes);
    if actual != expected {
        return Err(format!(
            "checksum mismatch — refusing to install.\n  expected {}\n  got      {}",
            expected, actual
        ));
    }

    // 4. No-op when the verified download equals the running binary.
    let current = std::env::current_exe().map_err(|e| format!("locate current binary: {}", e))?;
    let current_hash = std::fs::read(&current).ok().map(|b| sha256_hex(&b));
    if current_hash.as_deref() == Some(actual.as_str()) && !args.force {
        eprintln!(
            "Already up to date — safeclaw {} ({}).",
            crate::build_version(),
            &actual[..12]
        );
        return Ok(());
    }

    // 5. Atomically replace the running binary: write a sibling temp file (same
    //    dir ⇒ same filesystem ⇒ atomic rename), chmod +x, then rename over the
    //    current path. On Unix the running process keeps the old inode open, so
    //    replacing the path mid-run is safe; the next launch is the new build.
    let dir = current
        .parent()
        .ok_or_else(|| "current binary has no parent dir".to_string())?;
    let tmp = dir.join(format!(".sc-upgrade-{}.tmp", std::process::id()));
    std::fs::write(&tmp, &bytes).map_err(|e| {
        format!(
            "write {} (need write access to {}): {}",
            tmp.display(),
            dir.display(),
            e
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("chmod {}: {}", tmp.display(), e));
        }
    }
    if let Err(e) = std::fs::rename(&tmp, &current) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "replace {}: {} — if it's in a system dir, re-run install.sh with the right permissions",
            current.display(),
            e
        ));
    }

    // Report the version we just installed. The running process is still the OLD
    // build (its compiled-in CARGO_PKG_VERSION is stale), so ask the freshly
    // written binary for its own version rather than parse the release tag.
    let new_version = std::process::Command::new(&current)
        .arg("version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    match &new_version {
        Some(v) => eprintln!(
            "Upgraded safeclaw {} → {} ({}).",
            crate::build_version(),
            v.strip_prefix("safeclaw ").unwrap_or(v),
            &actual[..12]
        ),
        None => eprintln!("Upgraded {} ({}).", current.display(), &actual[..12]),
    }
    // Take effect now: restart the daemon onto the new binary and re-unlock.
    // Hand the whole convergence to the NEW binary via exec — this process is
    // still the old build, and driving a new daemon from an old client is a
    // guaranteed version skew once per upgrade: one wire or unit-convention
    // change and the convergence hangs or mis-reconciles (v1.0.40→42: the old
    // poll loop didn't know the "ok" status and sat out its full timeout on an
    // already-unlocked vault). `restart` reconciles a stale ExecStart, bounces,
    // then unlocks — same chokepoint as `sc up`, now version-matched to the
    // daemon by construction. The version probe above already proved the new
    // binary executes; on success exec never returns.
    if crate::cli::service::unit_installed() {
        if new_version.is_some() {
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new(&current).arg("restart").exec();
                eprintln!("  couldn't hand off to the new binary ({err}); run `sc up`.");
            }
            #[cfg(not(unix))]
            eprintln!("  Restart it with `sc up`.");
        } else {
            eprintln!("  couldn't probe the new binary; restart it with `sc up`.");
        }
    } else {
        eprintln!("  Start it with `sc up`.");
    }
    Ok(())
}
