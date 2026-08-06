//! `sc service validate <path>` — run the static service-definition safety
//! validator offline (no daemon). Mirrors exactly what the console's custom-TOML
//! upload editor will enforce, so authors can check a service.toml before
//! submitting it.

use serde_json::json;

use crate::cli::active::resolve_active;
use crate::cli::approve::{act_result, approve_op, ApproveOpts};
use crate::cli::webauthn::now_unix;
use crate::config::{ServiceAddArgs, ServiceLsArgs, ServiceRmArgs, ServiceValidateArgs};
use crate::service::validate::validate_recipe;
use crate::service::ServiceDef;

pub async fn run_validate(args: ServiceValidateArgs) -> Result<(), String> {
    let path = &args.path;
    let toml_str = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;

    match validate_recipe(&toml_str, args.first_party) {
        Ok(()) => {
            let mode = if args.first_party {
                " (first-party: exec allowed)"
            } else {
                ""
            };
            println!("✓ {} — valid{}", path.display(), mode);
            Ok(())
        }
        Err(problems) => {
            eprintln!(
                "✗ {} — {} problem{}:",
                path.display(),
                problems.len(),
                if problems.len() == 1 { "" } else { "s" }
            );
            for p in &problems {
                eprintln!("  • {}", p);
            }
            // Non-zero exit via the Err path (main prints + boxes it).
            Err(format!("{}: service validation failed", path.display()))
        }
    }
}

/// `sc service add <file.toml>` — validate a v4 definition, then store it in the
/// active vault's `aux.services` (keyed by the service id) via a daemon-side
/// grant op. One passkey gesture; over SSH it surfaces the cloud grant link (no
/// browser tunnel, no local WebAuthn ceremony). The daemon re-validates + seals.
pub async fn run_add(args: ServiceAddArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let toml_str = std::fs::read_to_string(&args.path)
        .map_err(|e| format!("cannot read {}: {}", args.path.display(), e))?;

    // Offline fast-fail: the same validator the daemon re-runs on the grant.
    if let Err(problems) = validate_recipe(&toml_str, false) {
        eprintln!(
            "✗ {} — {} problem{}:",
            args.path.display(),
            problems.len(),
            if problems.len() == 1 { "" } else { "s" }
        );
        for p in &problems {
            eprintln!("  • {}", p);
        }
        return Err(format!(
            "{}: service validation failed",
            args.path.display()
        ));
    }
    let def: ServiceDef = toml::from_str(&toml_str).map_err(|e| format!("parse: {}", e))?;
    let id = def.service.id.clone();

    let op = json!({
        "act": { "type": { "custom": "service-add" }, "target": "", "scope": { "toml": toml_str } },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    approve_op(
        &custodian,
        &vault,
        &op,
        &format!("Add service {}", id),
        &opts,
    )
    .await?;
    println!("service '{}' stored", id);
    Ok(())
}

/// `sc service ls` — list `aux.services` with each definition's validation
/// status + referencing connections. The daemon silently SKIPS an invalid
/// definition at unlock (its connections stay stuck "connecting"), and the
/// console only shows a definition through its connections — so a broken or
/// orphaned def is invisible everywhere but here. One passkey gesture (over SSH:
/// the cloud grant link).
pub async fn run_ls(args: ServiceLsArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let op = json!({
        "act": { "type": { "custom": "service-ls" }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    let body = approve_op(&custodian, &vault, &op, "List services", &opts).await?;

    let services = act_result(&body)
        .get("services")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if services.is_empty() {
        println!("(no custom service definitions in this vault)");
        return Ok(());
    }
    for s in &services {
        let id = s.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let valid = s.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        let conns = s
            .get("connections")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let used = if conns.is_empty() {
            "no connections".to_string()
        } else {
            format!("connections: {}", conns)
        };
        if valid {
            println!("✓ {} — valid ({})", id, used);
        } else {
            println!("✗ {} — INVALID, the daemon skips it ({})", id, used);
            if let Some(problems) = s.get("problems").and_then(|v| v.as_array()) {
                for p in problems {
                    let Some(p) = p.as_str() else { continue };
                    // A parse error spans lines; indent them under the bullet.
                    let mut lines = p.lines();
                    if let Some(first) = lines.next() {
                        println!("    • {}", first);
                    }
                    for l in lines {
                        println!("      {}", l);
                    }
                }
            }
        }
    }
    Ok(())
}

/// `sc service rm <id>` — delete a custom service definition from
/// `aux.services` via a daemon-side grant op. Connections referencing it are
/// kept (their stored secrets stay resolvable; only the service backing goes
/// away) and reported so we can warn. One passkey gesture (over SSH: the cloud
/// grant link).
pub async fn run_rm(args: ServiceRmArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let op = json!({
        "act": { "type": { "custom": "service-rm" }, "target": args.id, "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    let body = approve_op(
        &custodian,
        &vault,
        &op,
        &format!("Remove service {}", args.id),
        &opts,
    )
    .await?;

    let refs: Vec<String> = act_result(&body)
        .get("referencing_connections")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !refs.is_empty() {
        eprintln!(
            "note: connection{} still reference{} it: {} — stored secrets keep working, the service backing is gone",
            if refs.len() == 1 { "" } else { "s" },
            if refs.len() == 1 { "s" } else { "" },
            refs.join(", ")
        );
    }
    println!("service '{}' removed", args.id);
    Ok(())
}
