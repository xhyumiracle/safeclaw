//! On-disk identity files for the **AIK** (agent) and **DIK** (device) — the
//! possession-proven keypair identities that replace the two BEARER credentials
//! (the agent api-key and the device pair token). Symmetric by design
//! (`design/agent-device-identity-mtls.md` §5): same JSON shape, same 0600
//! discipline, same "the seed is the secret, the id is the derived handle"
//! contract. This is the identity-wave's Phase 2 foundation — minting + on-disk
//! custody — consumed by the app-layer PoP transport (Phase 3) and by `sc agent add` /
//! `sc login`.
//!
//! Paths (§5):
//!   - AIK: `~/.safeclaw/agents/<name>/identity` — selected per wrapped child via
//!     the env var `SAFECLAW_AGENT_IDENTITY` (a PATH, not a secret).
//!   - DIK: `~/.safeclaw/device/identity` — daemon-local, one per machine, no env
//!     (migrated from the legacy `~/.safeclaw/device-key` bearer file).
//!
//! File = 0600 JSON `{ "v":1, "kind":"agent"|"device", "id":"ag_…|dev_…",
//! "seed":"<base64-32>" }`. The `seed` is the 32-byte secret; `id` is stored for
//! human readability but is RECOMPUTED from the seed on load (the seed is
//! authoritative — a mismatch means corruption).
//!
//! Derivation asymmetry (deliberate, hidden behind [`resolve`]): an AGENT seed is
//! an [`AgentRoot`] root — its Ed25519 identity is derived via HKDF
//! (`AIK_IDENTITY_INFO`), preserving the canonical `ag_` derivation + golden
//! vectors and keeping bearer rotation decoupled; a DEVICE seed IS the Ed25519
//! signing seed directly (no wire bearer to decouple). Either way [`resolve`]
//! returns the [`SigningIdentity`] whose public key the id commits to.

use crate::identity::{AgentRoot, IdKind, SigningIdentity};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Current on-disk identity-file schema version.
pub const IDENTITY_FILE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct OnDisk {
    v: u32,
    kind: String,
    id: String,
    seed: String,
}

fn kind_str(kind: IdKind) -> &'static str {
    match kind {
        IdKind::Agent => "agent",
        IdKind::Device => "device",
        IdKind::User => "user",
    }
}

fn kind_from_str(s: &str) -> Result<IdKind, String> {
    match s {
        "agent" => Ok(IdKind::Agent),
        "device" => Ok(IdKind::Device),
        "user" => Ok(IdKind::User),
        other => Err(format!("unknown identity kind {other:?}")),
    }
}

/// The identity file path for an agent named `name` (§5). `<home>/.safeclaw/
/// agents/<name>/identity`.
pub fn agent_identity_path(name: &str) -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "cannot locate home dir".to_string())?;
    Ok(home.join(".safeclaw").join("agents").join(name).join("identity"))
}

/// The daemon-local device identity file path (§5). `<home>/.safeclaw/device/
/// identity`.
pub fn device_identity_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "cannot locate home dir".to_string())?;
    Ok(home.join(".safeclaw").join("device").join("identity"))
}

/// Resolve a stored `seed` (under `kind`) to its signing identity + self-
/// certifying id. The seed is authoritative; see the module note for the
/// agent-vs-device derivation asymmetry.
pub fn resolve(kind: IdKind, seed: &[u8; 32]) -> (SigningIdentity, String) {
    let si = match kind {
        IdKind::Agent => AgentRoot::from_seed(*seed).identity(),
        _ => SigningIdentity::from_seed(seed),
    };
    let id = si.id(kind);
    (si, id)
}

/// Mint a fresh identity of `kind` from the OS CSPRNG. Returns the (zeroizing)
/// seed + its derived id. Nothing is written — the caller persists via [`write`].
pub fn mint(kind: IdKind) -> (Zeroizing<[u8; 32]>, String) {
    use rand::RngCore;
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *seed);
    let (_, id) = resolve(kind, &seed);
    (seed, id)
}

/// Persist an identity file at `path` (0600), overwriting any existing one.
/// Returns the derived id. `kind` selects the derivation + the on-disk `kind`
/// tag; `seed` is the 32-byte secret.
pub fn write(path: &Path, kind: IdKind, seed: &[u8; 32]) -> Result<String, String> {
    let (_, id) = resolve(kind, seed);
    let rec = OnDisk {
        v: IDENTITY_FILE_VERSION,
        kind: kind_str(kind).to_string(),
        id: id.clone(),
        seed: BASE64.encode(seed),
    };
    let json =
        serde_json::to_vec_pretty(&rec).map_err(|e| format!("serialize identity: {e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }
    std::fs::write(path, &json).map_err(|e| format!("write {}: {}", path.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort chmod — never fail the mint over an exotic filesystem.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(id)
}

/// A loaded identity: its kind, its (zeroizing) seed, its signing identity, and
/// the id recomputed from the seed (authoritative).
pub struct LoadedIdentity {
    pub kind: IdKind,
    pub seed: Zeroizing<[u8; 32]>,
    pub identity: SigningIdentity,
    pub id: String,
}

/// Load + validate an identity file. The id is recomputed from the seed (the
/// stored `id` is display-only); a stored-vs-recomputed mismatch is an error
/// (corruption / tampering).
pub fn load(path: &Path) -> Result<LoadedIdentity, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let rec: OnDisk =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {}", path.display(), e))?;
    if rec.v != IDENTITY_FILE_VERSION {
        return Err(format!(
            "identity {} has unsupported version {} (expected {})",
            path.display(),
            rec.v,
            IDENTITY_FILE_VERSION
        ));
    }
    let kind = kind_from_str(&rec.kind)?;
    let raw = BASE64
        .decode(rec.seed.as_bytes())
        .map_err(|e| format!("decode seed in {}: {}", path.display(), e))?;
    let seed_arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("seed in {} is not 32 bytes", path.display()))?;
    let seed = Zeroizing::new(seed_arr);
    let (identity, id) = resolve(kind, &seed);
    if id != rec.id {
        return Err(format!(
            "identity {} is corrupt: stored id {} != derived {}",
            path.display(),
            rec.id,
            id
        ));
    }
    Ok(LoadedIdentity {
        kind,
        seed,
        identity,
        id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_matches_agent_root() {
        // A minted agent identity's id must equal AgentRoot::agent_id() over the
        // same seed (canonical `ag_` derivation, golden-vector-compatible).
        let (seed, id) = mint(IdKind::Agent);
        assert!(id.starts_with("ag_"));
        assert_eq!(id, AgentRoot::from_seed(*seed).agent_id());
    }

    #[test]
    fn device_id_is_direct_ed25519() {
        let (seed, id) = mint(IdKind::Device);
        assert!(id.starts_with("dev_"));
        let (si, id2) = resolve(IdKind::Device, &seed);
        assert_eq!(id, id2);
        assert_eq!(id, si.id(IdKind::Device));
    }

    #[test]
    fn write_then_load_roundtrips() {
        let dir = std::env::temp_dir().join(format!("scid-test-{}", std::process::id()));
        let path = dir.join("identity");
        let (seed, id) = mint(IdKind::Agent);
        let written = write(&path, IdKind::Agent, &seed).unwrap();
        assert_eq!(written, id);
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.id, id);
        assert_eq!(loaded.kind, IdKind::Agent);
        assert_eq!(*loaded.seed, *seed);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
