//! `safeclaw vault ...` — vault lifecycle ops.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::json;
use std::io::{self, Write as _};

use crate::cli::active::{
    forget as forget_vault, join_vault_url, known_vaults, load as load_config, put_active,
    resolve_active, split_vault_url,
};
use crate::cli::status::{fetch_status, print_status, VaultState};
use crate::cli::webauthn::*;
use crate::config::{
    VaultCreateArgs, VaultDeleteArgs, VaultForgetArgs, VaultSubcommand, VaultUseArgs,
};

// Port must equal `config::CONTROL_PORT` (the daemon's control/API plane).
const LOCAL_CUSTODIAN: &str = "http://localhost:23293";
const LOCAL_VAULT_ID: &str = "default";

/// True if the custodian URL points at this machine. Used to specialize
/// "daemon down" hints — a remote daemon being unreachable is a network
/// problem; a local one almost always means `safeclaw c start` isn't running.
fn is_localhost(custodian: &str) -> bool {
    let after_scheme = custodian
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = after_scheme.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub async fn run(sub: VaultSubcommand) -> Result<(), String> {
    match sub {
        VaultSubcommand::Status(a) => crate::cli::status::run(a).await,
        VaultSubcommand::Ls(a) => run_ls(a).await,
        VaultSubcommand::Use(a) => run_use(a).await,
        VaultSubcommand::Forget(a) => run_forget(a).await,
        VaultSubcommand::Create(a) => run_create(a).await,
        VaultSubcommand::Delete(a) => run_delete(a).await,
        VaultSubcommand::Unlock(a) => crate::cli::unlock::run_unlock(a).await,
        VaultSubcommand::Lock(a) => crate::cli::unlock::run_lock(a).await,
    }
}

async fn run_ls(args: crate::config::VaultLsArgs) -> Result<(), String> {
    let cfg = load_config()?;
    let known = known_vaults();
    let active = (cfg.daemon.as_deref(), cfg.vault.as_deref());
    if args.json {
        let rows: Vec<serde_json::Value> = known
            .iter()
            .map(|kv| {
                json!({
                    "url": join_vault_url(&kv.daemon, &kv.vault),
                    "daemon": kv.daemon,
                    "vault": kv.vault,
                    "label": kv.label,
                    "kind": kv.kind,
                    "default": active == (Some(kv.daemon.as_str()), Some(kv.vault.as_str())),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_default()
        );
        return Ok(());
    }
    if known.is_empty() {
        println!("(no vaults yet — `safeclaw vault create` or `safeclaw vault use`)");
        return Ok(());
    }
    for (i, kv) in known.iter().enumerate() {
        let marker = if active == (Some(&kv.daemon), Some(&kv.vault)) {
            "*"
        } else {
            " "
        };
        // Lead with the human name + kind so an agent told "the team vault" can
        // pick the right one; the id trails as the canonical, copyable handle.
        let name = kv.label.as_deref().unwrap_or("(unnamed)");
        let kind = kv.kind.as_deref().unwrap_or("?");
        println!("  {} {}) {} ({})  {}", marker, i + 1, name, kind, kv.vault);
    }
    Ok(())
}

/// Parse a `url_or_idx` arg into (custodian, vault). Accepts:
/// - SAFECLAW_VAULT_URL (`<custodian>/v/<id>`)
/// - numeric index (1-based) into the known_vaults list
fn resolve_url_or_idx(arg: &str) -> Result<(String, String), String> {
    if let Ok(idx) = arg.parse::<usize>() {
        let known = known_vaults();
        if idx < 1 || idx > known.len() {
            return Err(format!("index {} out of range [1-{}]", idx, known.len()));
        }
        let kv = &known[idx - 1];
        return Ok((kv.daemon.clone(), kv.vault.clone()));
    }
    if let Some(pair) = split_vault_url(arg) {
        return Ok(pair);
    }
    // Otherwise resolve it as a vault TOKEN — id, unique id-prefix, or exact name
    // (case-insensitive) — via the same git/docker/kubectl resolver `--vault`
    // uses, so `sc vault use` and `sc run --vault` accept identical handles
    // (including a quoted name). Ambiguity fails loud with candidates; a name
    // with spaces just needs quoting.
    let cfg = load_config().unwrap_or_default();
    crate::cli::active::resolve_vault_token(arg, &cfg)
}

async fn run_use(args: VaultUseArgs) -> Result<(), String> {
    let (custodian, vault) = if args.local {
        (LOCAL_CUSTODIAN.to_string(), LOCAL_VAULT_ID.to_string())
    } else if let Some(arg) = args.url_or_idx {
        resolve_url_or_idx(&arg)?
    } else {
        let url = interactive_pick(OnEmpty::UseLocalDefault)?
            .expect("UseLocalDefault never returns None");
        split_vault_url(&url).ok_or_else(|| format!("not a valid SAFECLAW_VAULT_URL: {}", url))?
    };

    // Probe before saving. If the vault doesn't exist on the custodian,
    // refuse — bad active state would silently confuse later commands.
    // (Daemon unreachable is OK — accept and warn; user might be offline.)
    let s = fetch_status(&custodian, &vault).await;
    match s.state {
        VaultState::NotFound => {
            return Err(format!(
                "vault not found on custodian: {}\n  run `safeclaw vault create` to make a new one, or pick a different URL",
                join_vault_url(&custodian, &vault)
            ));
        }
        VaultState::Unreachable => {
            if is_localhost(&custodian) {
                eprintln!(
                    "warning: no local daemon at {} — start one with `safeclaw c start`",
                    custodian
                );
                eprintln!(
                    "  (saving anyway; `safeclaw status` will recheck once the daemon is up)"
                );
            } else {
                eprintln!("warning: couldn't reach custodian; saving anyway");
            }
        }
        _ => {}
    }
    put_active(&custodian, &vault).map_err(|e| format!("save config: {}", e))?;
    print_status(&s);
    // Pin-aware (design/vault-addressing.md): a shell that carries a launch pin
    // keeps targeting it — say so here, at the moment of the switch, instead of
    // letting the very next `sc ls` contradict the header above.
    if let Ok(pin) = std::env::var("SAFECLAW_VAULT_ID") {
        if !pin.is_empty() && pin != vault {
            eprintln!(
                "note: this shell is pinned to {} via $SAFECLAW_VAULT_ID, so `sc` here still targets it;",
                pin
            );
            eprintln!(
                "      the new default applies everywhere else — `unset SAFECLAW_VAULT_ID` to follow it here"
            );
        }
    }
    Ok(())
}

async fn run_forget(args: VaultForgetArgs) -> Result<(), String> {
    let (custodian, vault) = if let Some(arg) = args.url_or_idx {
        resolve_url_or_idx(&arg)?
    } else {
        if known_vaults().is_empty() {
            return Err("no vaults in known list — nothing to forget".into());
        }
        let url = interactive_pick(OnEmpty::Abort)?.ok_or("cancelled")?;
        split_vault_url(&url).ok_or_else(|| format!("not a valid SAFECLAW_VAULT_URL: {}", url))?
    };
    let removed = forget_vault(&custodian, &vault)?;
    if !removed {
        return Err(format!(
            "vault not in known list: {}",
            join_vault_url(&custodian, &vault)
        ));
    }
    println!("forgot: {}", join_vault_url(&custodian, &vault));
    Ok(())
}

/// What `interactive_pick` does when the user just hits Enter.
enum OnEmpty {
    /// Return the local-default URL (`use` semantics).
    UseLocalDefault,
    /// Return `Ok(None)` so the caller can treat it as a cancel
    /// (`forget` semantics).
    Abort,
}

fn interactive_pick(on_empty: OnEmpty) -> Result<Option<String>, String> {
    let cfg = load_config().unwrap_or_default();
    let known = known_vaults();
    let active = (cfg.daemon.as_deref(), cfg.vault.as_deref());
    let has_known = !known.is_empty();
    if has_known {
        eprintln!("Known vaults:");
        for (i, kv) in known.iter().enumerate() {
            let marker = if active == (Some(&kv.daemon), Some(&kv.vault)) {
                " (active)"
            } else {
                ""
            };
            eprintln!(
                "  {}) {}{}",
                i + 1,
                join_vault_url(&kv.daemon, &kv.vault),
                marker
            );
        }
        eprintln!();
    }
    // Prompt shape depends on what input is actually meaningful here:
    // - has_known controls whether "index" is offered
    // - on_empty controls what Enter does
    let prompt = match (has_known, &on_empty) {
        (true, OnEmpty::UseLocalDefault) => {
            "Pick: index, SAFECLAW_VAULT_URL, or Enter for local default: "
        }
        (true, OnEmpty::Abort) => "Pick: index or SAFECLAW_VAULT_URL (Enter to cancel): ",
        (false, OnEmpty::UseLocalDefault) => {
            "Paste a SAFECLAW_VAULT_URL, or press Enter for local default: "
        }
        (false, OnEmpty::Abort) => "Paste a SAFECLAW_VAULT_URL (Enter to cancel): ",
    };
    eprint!("{}", prompt);
    io::stderr().flush().ok();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        return match on_empty {
            OnEmpty::UseLocalDefault => Ok(Some(join_vault_url(LOCAL_CUSTODIAN, LOCAL_VAULT_ID))),
            OnEmpty::Abort => Ok(None),
        };
    }
    if let Ok(idx) = trimmed.parse::<usize>() {
        if idx < 1 || idx > known.len() {
            return Err(format!("index {} out of range [1-{}]", idx, known.len()));
        }
        let kv = &known[idx - 1];
        return Ok(Some(join_vault_url(&kv.daemon, &kv.vault)));
    }
    Ok(Some(trimmed.to_string()))
}

async fn run_create(args: VaultCreateArgs) -> Result<(), String> {
    use crate::crypto::kdf::WRAP_VERSION;

    let (custodian, vault_id) = match args.remote.as_deref() {
        Some(remote) => (
            remote.trim_end_matches('/').to_string(),
            uuid::Uuid::new_v4().to_string(),
        ),
        None => (LOCAL_CUSTODIAN.to_string(), LOCAL_VAULT_ID.to_string()),
    };
    eprintln!(
        "safeclaw vault create — new vault at {}",
        join_vault_url(&custodian, &vault_id)
    );

    let prf_eval_salt_js = b"safeclaw-prf-v1";

    // ── Obtain cred_id, pub_x/y, and prf_first ───────────────────────
    // --reuse: pick an existing passkey from another vault on this custodian,
    //   skip the create() ceremony, do a single get() with PRF instead.
    // default: register a new passkey (create()), fall back to get() if PRF
    //   wasn't available on create.
    let (cred_id, pub_x, pub_y, prf_first_b64) = if args.reuse_passkey {
        let meta = pick_reuse_passkey(&custodian, &vault_id).await?;
        let cred_id = meta.credential_id;
        let pub_x = meta
            .public_key_x
            .ok_or("passkeys endpoint didn't return public_key_x — upgrade daemon and retry")?;
        let pub_y = meta
            .public_key_y
            .ok_or("passkeys endpoint didn't return public_key_y — upgrade daemon and retry")?;
        eprintln!("  step 1/2: touch passkey to confirm reuse (PRF)…");
        let dummy_beta = [0u8; 32];
        let get_result = do_browser_gesture(
            &custodian,
            &vault_id,
            &dummy_beta,
            Some(prf_eval_salt_js),
            &cred_id,
            "Reuse passkey (PRF)",
            args.no_browser,
            args.timeout,
            false,
            args.cb_port,
        )
        .await?;
        let prf = get_result.prf_first.ok_or(
            "PRF unavailable on this authenticator — use `sc vault create` without --reuse",
        )?;
        (cred_id, pub_x, pub_y, prf)
    } else {
        // ── Step 1: register passkey (WebAuthn create()) ─────────────────
        eprintln!("  step 1/3: register a passkey in your browser…");
        let create_result = do_browser_gesture(
            &custodian,
            &vault_id,
            &[0u8; 32],
            Some(prf_eval_salt_js),
            "",
            "Create vault (register passkey)",
            args.no_browser,
            args.timeout,
            true,
            args.cb_port,
        )
        .await?;
        let cred_id = create_result
            .credential_id
            .clone()
            .ok_or("browser didn't return credential_id")?;
        let pub_x = create_result
            .public_key_x
            .clone()
            .ok_or("browser didn't return public_key_x")?;
        let pub_y = create_result
            .public_key_y
            .clone()
            .ok_or("browser didn't return public_key_y")?;
        // ── Step 2: get PRF output ────────────────────────────────────
        let prf = if let Some(ref pf) = create_result.prf_first {
            pf.clone()
        } else {
            eprintln!("  step 2/3: PRF not available on create — doing a second passkey gesture…");
            let dummy_beta = [0u8; 32];
            let get_result = do_browser_gesture(
                &custodian,
                &vault_id,
                &dummy_beta,
                Some(prf_eval_salt_js),
                &cred_id,
                "Vault setup (PRF)",
                args.no_browser,
                args.timeout,
                false,
                args.cb_port,
            )
            .await?;
            get_result
                .prf_first
                .ok_or("PRF still unavailable — authenticator may not support PRF extension")?
        };
        (cred_id, pub_x, pub_y, prf)
    };
    let prf_first_bytes = URL_SAFE_NO_PAD
        .decode(&prf_first_b64)
        .map_err(|e| format!("decode prf_first: {}", e))?;
    let user_key = prf_to_user_key(&prf_first_bytes)?;
    let cred_id_raw = URL_SAFE_NO_PAD
        .decode(&cred_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;

    // ── Seal initial vault state ──────────────────────────────────────
    let seal_step = if args.reuse_passkey {
        "step 2/2"
    } else {
        "step 3/3"
    };
    eprintln!("  {}: sealing initial vault state…", seal_step);
    let prf_salt = random_bytes(32);
    let state_key = random_bytes(32); // K
    let wrapping_key =
        crate::crypto::kdf::derive_wrapping_key(&user_key, &prf_salt, &cred_id_raw, WRAP_VERSION)
            .map_err(|e| format!("derive wrapping key: {}", e))?;

    let binding = sudp::primitives::WrapBinding {
        credential_id: &cred_id_raw,
        version: WRAP_VERSION,
    };
    let wrapped_key = <sudp::primitives::AeadWrap<sudp::primitives::ChaCha20Poly1305>
        as sudp::primitives::KeyWrap>::wrap(&wrapping_key, &state_key, &binding)
        .map_err(|e| format!("wrap K: {}", e))?;

    let aux = serde_json::to_value(crate::storage::plaintext::VaultAux::initial())
        .map_err(|e| format!("serialize aux: {}", e))?;
    let empty_state = json!({
        "targets": {},
        "peers": { &cred_id: STANDARD.encode(&wrapping_key) },
        "aux": aux,
    });
    let canonical_m = sudp::canonical::canonicalize_strict(&empty_state)
        .map_err(|e| format!("canonicalize: {}", e))?;
    let seal_ad = {
        let mut ad = Vec::with_capacity(b"sudp/v1/seal".len() + 2);
        ad.extend_from_slice(b"sudp/v1/seal");
        ad.extend_from_slice(&WRAP_VERSION.to_be_bytes());
        ad
    };
    let ciphertext = <sudp::primitives::ChaCha20Poly1305 as sudp::primitives::Aead>::seal(
        &state_key,
        &canonical_m,
        &seal_ad,
    )
    .map_err(|e| format!("seal M: {}", e))?;

    // ── Build Enroll op + create on daemon ────────────────────────────
    let enroll_op = json!({
        "act": {
            "type": "enroll",
            "target": cred_id,
            "scope": {
                "public_key_x": pub_x,
                "public_key_y": pub_y,
                "prf_salt": STANDARD.encode(&prf_salt),
                "device_name": "CLI",
            }
        },
        "bind": { "redeemer": vault_id },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let (op_id, r) = create_op(&custodian, &vault_id, &enroll_op).await?;
    let r_bytes = STANDARD
        .decode(&r)
        .map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta_setup(&r_bytes, &enroll_op)?;

    // ── Assertion gesture (sign β) ────────────────────────────────────
    eprintln!("  signing enrollment grant — touch passkey again…");
    let assert_result = do_browser_gesture(
        &custodian,
        &op_id,
        &beta,
        None,
        &cred_id,
        "Confirm vault creation",
        args.no_browser,
        args.timeout,
        false,
        args.cb_port,
    )
    .await?;

    // ── Submit Enroll grant ───────────────────────────────────────────
    let grant = json!({
        "o": enroll_op,
        "r": r,
        "credential_id": cred_id,
        "wrapping_key": STANDARD.encode(&wrapping_key),
        "assertion": assertion_json(
            &assert_result.credential_id,
            &assert_result.authenticator_data,
            &assert_result.client_data_json,
            &assert_result.signature,
        ),
        "setup_payload": {
            "wrapped_key": STANDARD.encode(&wrapped_key),
            "ciphertext": STANDARD.encode(&ciphertext),
        }
    });
    let client = http_client()?;
    let resp = client
        .post(format!(
            "{}/op/{}/approve",
            custodian.trim_end_matches('/'),
            urlencoding::encode(&op_id)
        ))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "approve HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }

    put_active(&custodian, &vault_id).map_err(|e| format!("save config: {}", e))?;
    let url = join_vault_url(&custodian, &vault_id);
    eprintln!("safeclaw vault create — done");
    eprintln!("  active vault: {}", url);
    Ok(())
}

async fn run_delete(args: VaultDeleteArgs) -> Result<(), String> {
    if !args.yes_i_mean_it {
        return Err("destructive — pass --yes-i-mean-it to confirm vault deletion".into());
    }
    let (custodian, _) = resolve_active(Some(args.vault.as_str()))?;
    let vault = args.vault.trim().to_string();
    if vault.is_empty() {
        return Err("vault id cannot be empty".into());
    }

    if atty_isatty_stdin() {
        eprint!("Type vault id `{}` to confirm permanent deletion: ", vault);
        io::stderr().flush().ok();
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
        if buf.trim() != vault {
            return Err("confirmation mismatch — aborted".into());
        }
    }

    // Delete is approval-only (the daemon wipes the vault from the grant's
    // W_c) — same shape as unlock/lock, so it goes through the ONE shared
    // approval path: cloud /grant link when paired, local ceremony for
    // self-host. No bespoke gesture here.
    let op = json!({
        "act": { "type": { "custom": "vault-delete" }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = crate::cli::approve::ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    crate::cli::approve::approve_op(
        &custodian,
        &vault,
        &op,
        "Delete vault (irreversible)",
        &opts,
    )
    .await?;
    eprintln!("safeclaw vault delete — ok (vault {} wiped)", vault);
    Ok(())
}

/// For `--reuse`: pick a passkey from an existing vault on the same custodian.
///
/// If only one other vault exists → use it automatically.
/// If multiple → prompt the user to pick.
/// Returns the first enrolled passkey's meta (cred_id + pub_x/y).
async fn pick_reuse_passkey(
    new_custodian: &str,
    new_vault_id: &str,
) -> Result<crate::cli::webauthn::PasskeyMeta, String> {
    let known = known_vaults();
    let candidates: Vec<_> = known
        .iter()
        .filter(|kv| {
            kv.daemon.trim_end_matches('/') == new_custodian.trim_end_matches('/')
                && kv.vault != new_vault_id
        })
        .collect();
    if candidates.is_empty() {
        return Err(format!(
            "no other vaults on {} to reuse a passkey from\n  run `sc vault create` (without --reuse) first",
            new_custodian
        ));
    }
    let source_vault = if candidates.len() == 1 {
        eprintln!(
            "  reusing passkey from: {}",
            join_vault_url(&candidates[0].daemon, &candidates[0].vault)
        );
        &candidates[0].vault
    } else {
        eprintln!("Pick a vault to reuse a passkey from:");
        for (i, kv) in candidates.iter().enumerate() {
            eprintln!("  {}) {}", i + 1, join_vault_url(&kv.daemon, &kv.vault));
        }
        eprint!("Enter index: ");
        io::stderr().flush().ok();
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
        let idx: usize = buf.trim().parse().map_err(|_| "invalid index")?;
        if idx < 1 || idx > candidates.len() {
            return Err(format!(
                "index {} out of range [1-{}]",
                idx,
                candidates.len()
            ));
        }
        &candidates[idx - 1].vault
    };
    crate::cli::webauthn::fetch_passkey_meta(new_custodian, source_vault).await
}

fn atty_isatty_stdin() -> bool {
    unsafe { libc_isatty(0) != 0 }
}

#[link(name = "c")]
extern "C" {
    #[link_name = "isatty"]
    fn libc_isatty(fd: i32) -> i32;
}
