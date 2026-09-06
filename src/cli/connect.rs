//! `sc connect <name>` — create a connection in one unlock+write cycle. The CLI
//! superset of `sc set --host` (which is the raw single-secret shorthand).
//!
//! Two shapes (§9):
//!   - RAW (default): `--host <domain>` (repeatable) + `--secret KEY[=VALUE]`
//!     (repeatable) and/or `--use-existing KEY`. Anchors its own hosts and stores
//!     each secret at its BARE uppercase KEY (the vault is a flat env namespace).
//!     Reachable via `__sc__<name>__` (sole) or `__sc__<name>__<role>__` (several).
//!   - SERVICE-backed: `--service <id>` binds a catalog service — its hosts and
//!     declared secrets. `--host` is then optional and only PINS an exact FQDN
//!     inside the service's `*.suffix` wildcards (each pin ⊆ the service hosts).
//!     Secret values are provided with `--secret KEY=VALUE`; keys must be a
//!     subset of the service's declared secrets. Every value is stored at a
//!     BARE uppercase key (§3): the role's own name for the default connection,
//!     the suggested `<ROLE>_<QUALIFIER>` for a named one — recorded in the
//!     connection's `keys` map (the binding is stored data, never recomputed).
//!
//! Secret KEYs are canonical UPPERCASE (§1); a lowercase `--secret key=…` is
//! auto-converted. Connection ids are lowercase.

use std::io::IsTerminal;
use std::io::Write as _;

use serde_json::{json, Value};

use crate::cli::active::resolve_active;
use crate::cli::approve::{act_result, approve_op, deposit_values, ApproveOpts};
use crate::cli::conn::{slugify_conn_id, valid_role, validate_raw_host};
use crate::cli::webauthn::now_unix;
use crate::config::{ConnectArgs, ConnectionAddHostArgs, ConnectionRmArgs};
use crate::service::ServiceRegistry;
use crate::storage::plaintext::suggested_secret_key;

pub async fn run(mut args: ConnectArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;

    // Resolve the connection id: slugify a provided handle, or (no id given) run
    // the TTY wizard — which prompts the id and may also pick a `--service`.
    let name = resolve_conn_id(&mut args)?;

    match args.service.clone() {
        Some(service) => run_service_backed(&custodian, &vault, &name, &service, &args).await,
        None => run_raw(&custodian, &vault, &name, &args).await,
    }
}

/// Turn the optional `<id>` arg into a concrete, phantom-safe connection id.
/// Provided handle → slugified (echoing the result when it changed). Omitted →
/// wizard on a terminal (prompt the id, then optionally a catalog service);
/// hard error off a terminal.
fn resolve_conn_id(args: &mut ConnectArgs) -> Result<String, String> {
    if let Some(raw) = args.name.clone() {
        let id = slugify_conn_id(&raw);
        if id.is_empty() {
            return Err(format!(
                "'{}' has no usable id characters — choose a handle with letters or digits",
                raw
            ));
        }
        if id != raw {
            eprintln!("safeclaw connect — using id '{}' (from '{}')", id, raw);
        }
        return Ok(id);
    }

    if !std::io::stdin().is_terminal() {
        return Err(
            "provide a connection id: `sc connection add <id> --host <domain> --secret KEY=VALUE` (or `--service <id>`)".into(),
        );
    }

    // Wizard step 1 — the id.
    let id = loop {
        let raw = prompt_line("Connection id (a short handle you choose, e.g. work_gmail): ")?;
        let raw = raw.trim();
        if raw.is_empty() {
            eprintln!("  an id is required");
            continue;
        }
        let id = slugify_conn_id(raw);
        if id.is_empty() {
            eprintln!(
                "  '{}' has no usable id characters; use letters/digits",
                raw
            );
            continue;
        }
        if id != raw {
            eprintln!("  → id '{}'", id);
        }
        break id;
    };

    // Wizard step 2 — optionally back it with a catalog service (skip if the
    // caller already passed `--service`). Blank = a raw connection.
    if args.service.is_none() {
        let svc = prompt_line(
            "Back with a catalog service? id from `sc registry`, or blank for a raw connection: ",
        )?;
        let svc = svc.trim();
        if !svc.is_empty() {
            args.service = Some(svc.to_string());
        }
    }
    Ok(id)
}

// ── ls ───────────────────────────────────────────────────────────────────────

/// `sc connection ls` — the agent-usable connection projection (the same rows
/// `sc status` prints), optionally as JSON.
pub async fn run_ls(json: bool) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let conns = crate::cli::discovery::connections(&custodian, &vault).await?;

    if json {
        let arr: Vec<Value> = conns
            .iter()
            .map(|c| serde_json::json!({ "id": c.name, "hosts": c.hosts, "phantoms": c.phantoms, "setup": c.setup }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&Value::Array(arr)).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }

    if conns.is_empty() {
        println!(
            "no connections — add one with `sc connection add <id> --host <domain> --secret KEY=VALUE`"
        );
        return Ok(());
    }
    for c in &conns {
        println!("{}", c.name);
        if !c.hosts.is_empty() {
            println!("  hosts:    {}", c.hosts.join(", "));
        }
        for ph in &c.phantoms {
            println!("  phantom:  {}", ph);
        }
    }
    Ok(())
}

// ── rm ───────────────────────────────────────────────────────────────────────

/// `sc connection rm <id>` — drop a connection record and the secret(s) ONLY
/// it references, the inverse of `add` and the CLI twin of the console's
/// removal. Shared-pool semantics (CONNECTION_SCHEMA.md §3): a key another
/// connection still references is always kept (printed with its claimants);
/// `--keep-secrets` keeps everything (unreference only). Two passkey gestures
/// (unlock + write); confirms first unless `--yes`.
/// `sc connection add-host <id> <host>` — the SELF-SERVICE host widen: an agent
/// (or a human) proposes adding a host to an existing connection's anchor, the
/// vault owner approves with a passkey, and the host is added DURABLY. Mints the
/// SAME `widen-host` op the proxy's one-tap widen uses (approve.rs dispatch), so
/// reactive and proactive widening share one code path + one consent card. The
/// host may be an exact FQDN or a leftmost `*.domain` wildcard.
pub async fn run_add_host(args: ConnectionAddHostArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let id = slugify_conn_id(&args.id);
    if id.is_empty() {
        return Err(format!("'{}' is not a valid connection id", args.id));
    }
    let host = args.host.trim().to_string();
    validate_raw_host(&host)?;

    let op = json!({
        "act": {
            "type": { "custom": "widen-host" },
            "target": "",
            "scope": { "connection_id": id, "host": host }
        },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
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
        &format!("Add host {} to connection {}", host, id),
        &opts,
    )
    .await?;
    let _ = act_result(&body);
    println!("host '{}' added to connection '{}'", host, id);
    Ok(())
}

pub async fn run_rm(args: ConnectionRmArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let id = slugify_conn_id(&args.id);
    if id.is_empty() {
        return Err(format!("'{}' is not a valid connection id", args.id));
    }

    // Anti-fat-finger confirm BEFORE the gesture (the grant page also names the
    // op). The cascade detail — which secrets get deleted — is reported AFTER,
    // computed daemon-side under the open vault. The connection id rides the op
    // (public); no secret value ever does. Off a terminal, require `--yes`.
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            return Err(format!(
                "refusing to remove connection '{}' without confirmation — pass `--yes` (non-interactive)",
                id
            ));
        }
        let ans = prompt_line(&format!(
            "Remove connection '{}'{}? [y/N]: ",
            id,
            if args.keep_secrets {
                " (keeping its secrets)"
            } else {
                " and the secret(s) only it references"
            },
        ))?;
        if !matches!(ans.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("aborted");
            return Ok(());
        }
    }

    let op = json!({
        "act": { "type": { "custom": "connection-rm" }, "target": id, "scope": { "keep_secrets": args.keep_secrets } },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
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
        &format!("Remove connection {}", id),
        &opts,
    )
    .await?;

    let result = act_result(&body);
    let removed_secrets: Vec<String> = result
        .get("removed_secrets")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if removed_secrets.is_empty() {
        println!("connection '{}' removed", id);
    } else {
        println!(
            "connection '{}' removed (+{} secret(s): {})",
            id,
            removed_secrets.len(),
            removed_secrets.join(", ")
        );
    }
    if args.keep_secrets {
        eprintln!("  secrets kept (record removed only)");
    }
    // kept_secrets: [[key, [referencing_conn, …]], …]
    if let Some(kept) = result.get("kept_secrets").and_then(|v| v.as_array()) {
        for entry in kept {
            let Some(pair) = entry.as_array() else {
                continue;
            };
            let key = pair.first().and_then(|v| v.as_str()).unwrap_or("?");
            let by = pair
                .get(1)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            eprintln!("  kept: {} (still referenced by {})", key, by);
        }
    }
    Ok(())
}

// ── raw connection ───────────────────────────────────────────────────────────

async fn run_raw(
    custodian: &str,
    vault: &str,
    name: &str,
    args: &ConnectArgs,
) -> Result<(), String> {
    // Hosts: anchor our own exact FQDNs.
    let hosts = if !args.host.is_empty() {
        args.host.clone()
    } else if std::io::stdin().is_terminal() {
        prompt_hosts(name)?
    } else {
        return Err(
            "a raw connection needs at least one host — pass `--host <domain>` (repeatable), or `--service <id>` to bind a catalog service".into(),
        );
    };
    for h in &hosts {
        validate_raw_host(h)?;
    }

    // Secrets: gather + uppercase the KEYs (§1).
    let gathered = gather_secrets(name, &args.secret, &args.use_existing)?;
    if gathered.new_values.is_empty() && gathered.existing.is_empty() {
        return Err(
            "a connection needs at least one secret — `--secret KEY=VALUE` or `--use-existing KEY`"
                .into(),
        );
    }

    // Raw secrets are stored at their BARE uppercase KEY (§2 — the vault is a
    // flat env namespace; two connections referencing the same KEY share it).
    // `secret_keys` = every KEY the connection references (new + existing);
    // the daemon verifies each `--use-existing` KEY actually exists.
    let mut secret_keys: Vec<String> = gathered
        .new_values
        .iter()
        .map(|(role, _)| role.clone())
        .collect();
    secret_keys.extend(gathered.existing.iter().cloned());
    dedup_upper(&mut secret_keys);

    // New VALUES go to the local daemon deposit; the op carries only the
    // salted digest (the op JSON travels to the cloud grant page — §values).
    let mut scope = json!({ "hosts": hosts, "secrets": secret_keys });
    if !gathered.new_values.is_empty() {
        let values: std::collections::BTreeMap<String, String> =
            gathered.new_values.iter().cloned().collect();
        scope["values_digest"] = json!(deposit_values(custodian, vault, &values).await?);
    }
    let op = json!({
        "act": { "type": { "custom": "connection-add" }, "target": name, "scope": scope },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    approve_op(
        custodian,
        vault,
        &op,
        &format!("Add connection {}", name),
        &opts,
    )
    .await?;

    report_phantoms(name, &hosts, &secret_keys);
    Ok(())
}

// ── service-backed connection ────────────────────────────────────────────────

async fn run_service_backed(
    custodian: &str,
    vault: &str,
    name: &str,
    service: &str,
    args: &ConnectArgs,
) -> Result<(), String> {
    // Resolve the service from the compiled catalog (built-ins). A per-vault
    // custom service (aux.services) is connected via the console, not here.
    let reg = ServiceRegistry::load();
    let def = reg.get(service).ok_or_else(|| {
        format!(
            "unknown service '{}' — see `sc registry`; per-vault custom services are connected in the console",
            service
        )
    })?;
    let service_hosts = def.service.hosts.clone();
    let service_secrets = def.service.secrets.clone();
    // Auxiliary pointer to where the token is minted (display-only).
    if let Some(url) = def.service.secret_url.as_deref() {
        eprintln!("  Get a token: {}", url);
    }

    // `--host` on a service-backed connect only PINS a host inside the service's
    // declared set: each pin must match an exact host or fall within a `*.suffix`
    // wildcard. `None` (no pin) derives the service's exact hosts at runtime.
    let pins: Option<Vec<String>> = if args.host.is_empty() {
        None
    } else {
        for h in &args.host {
            validate_raw_host(h)?;
            let ok = service_hosts
                .iter()
                .any(|e| crate::core::host::wildcard_matches(e, h));
            if !ok {
                return Err(format!(
                    "host '{}' is not within service '{}' hosts ({}) — a --service pin must be ⊆ the service's hosts",
                    h,
                    service,
                    service_hosts.join(", ")
                ));
            }
        }
        Some(args.host.clone())
    };

    // Secret values: keys must be a subset of the service's declared secrets.
    let gathered = gather_secrets(name, &args.secret, &[])?;
    if !args.use_existing.is_empty() {
        return Err("--use-existing is not supported with --service (provide values with `--secret KEY=VALUE`)".into());
    }
    for (role, _) in &gathered.new_values {
        let declared = service_secrets.iter().any(|s| s.eq_ignore_ascii_case(role));
        if !declared {
            return Err(format!(
                "secret '{}' is not declared by service '{}' (its secrets: {})",
                role,
                service,
                if service_secrets.is_empty() {
                    "none".into()
                } else {
                    service_secrets.join(", ")
                }
            ));
        }
    }

    // Every secret is stored at a BARE uppercase KEY (§3): the role's own
    // mainstream name for the default connection (`name == service`), or the
    // suggested `<ROLE>_<QUALIFIER>` for a named one — recorded in the
    // connection's `keys` map so readers resolve the same slot.
    let keys: Option<Vec<(String, String)>> = if name == service {
        None
    } else {
        Some(
            gathered
                .new_values
                .iter()
                .map(|(role, _)| (role.clone(), suggested_secret_key(name, service, role)))
                .collect(),
        )
    };
    let mut values = std::collections::BTreeMap::new();
    for (role, val) in &gathered.new_values {
        let key = keys
            .as_ref()
            .and_then(|m| m.iter().find(|(r, _)| r == role).map(|(_, k)| k.clone()))
            .unwrap_or_else(|| role.clone());
        values.insert(key, val.clone());
    }

    // New VALUES go to the local daemon deposit; the op carries only the
    // salted digest plus the public shape (service, pins, key bindings).
    let written_keys: Vec<String> = values.keys().cloned().collect();
    let mut scope = json!({ "service": service, "secrets": written_keys });
    if let Some(p) = &pins {
        scope["hosts"] = json!(p);
    }
    if let Some(k) = keys.as_ref().filter(|k| !k.is_empty()) {
        let map: serde_json::Map<String, Value> = k
            .iter()
            .map(|(role, key)| (role.clone(), Value::String(key.clone())))
            .collect();
        scope["keys"] = Value::Object(map);
    }
    if !values.is_empty() {
        scope["values_digest"] = json!(deposit_values(custodian, vault, &values).await?);
    }
    let op = json!({
        "act": { "type": { "custom": "connection-add" }, "target": name, "scope": scope },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    approve_op(
        custodian,
        vault,
        &op,
        &format!("Add connection {}", name),
        &opts,
    )
    .await?;

    // The service def is the SSoT for the advertised phantoms.
    let phantoms: Vec<String> = crate::core::host::phantoms_for(name, def)
        .into_values()
        .collect();
    let host_line = pins
        .as_ref()
        .map(|p| p.join(", "))
        .unwrap_or_else(|| service_hosts.join(", "));
    eprintln!(
        "safeclaw connect — '{}' → {} ({})",
        name, service, host_line
    );
    for ph in &phantoms {
        eprintln!("  phantom: {}", ph);
    }
    if phantoms.is_empty() {
        eprintln!("  (no injectable phantom yet — provide the service's secret with `--secret KEY=VALUE`)");
    }
    Ok(())
}

// ── shared secret gathering ──────────────────────────────────────────────────

struct Gathered {
    /// New secrets to write: `(UPPERCASE_ROLE, value)`.
    new_values: Vec<(String, String)>,
    /// Existing BARE secret KEYs to reference (uppercased).
    existing: Vec<String>,
}

/// Parse `--secret KEY[=VALUE]` (and `--use-existing KEY`), uppercasing every KEY
/// to the canonical form (§1). A bare `--secret KEY` prompts for a hidden value
/// on a TTY. Fully-interactive (no flags) loops prompting KEY + value.
fn gather_secrets(
    name: &str,
    secret_flags: &[String],
    use_existing: &[String],
) -> Result<Gathered, String> {
    let mut new_values: Vec<(String, String)> = Vec::new();
    // `--use-existing` keys pass through AS TYPED: an external store's key
    // (GCP allows lowercase/hyphens) must reach the daemon exactly as named.
    // The daemon canonicalises — a native key typed in the wrong case is
    // folded to its stored (uppercase) form at approve.
    let existing: Vec<String> = use_existing.iter().map(|k| k.trim().to_string()).collect();
    for k in &existing {
        if !crate::cli::conn::valid_secret_ref(k) {
            return Err(format!(
                "--use-existing '{}': not a valid secret key (ASCII letters/digits/_/-, no '__')",
                k
            ));
        }
    }

    if !secret_flags.is_empty() {
        for s in secret_flags {
            if let Some((k, v)) = s.split_once('=') {
                let role = k.trim().to_ascii_uppercase();
                if !valid_role(&role) {
                    return Err(format!(
                        "secret KEY '{}' isn't a valid env key ([A-Z0-9_])",
                        k.trim()
                    ));
                }
                new_values.push((role, v.to_string()));
            } else if std::io::stdin().is_terminal() {
                let role = s.trim().to_ascii_uppercase();
                if !valid_role(&role) {
                    return Err(format!(
                        "secret KEY '{}' isn't a valid env key ([A-Z0-9_])",
                        s.trim()
                    ));
                }
                let val = rpassword::prompt_password(format!("Value for {} (hidden): ", role))
                    .map_err(|e| format!("read value: {}", e))?;
                if val.is_empty() {
                    return Err(format!("value for '{}' cannot be empty", role));
                }
                new_values.push((role, val));
            } else {
                return Err(format!(
                    "--secret {}: provide a value as `--secret {}=<value>` (non-interactive)",
                    s, s
                ));
            }
        }
    } else if existing.is_empty() {
        // Fully interactive: loop prompting KEY names + hidden values.
        if !std::io::stdin().is_terminal() {
            return Err(
                "no secrets given — `--secret KEY=VALUE` (repeatable) or `--use-existing KEY`"
                    .into(),
            );
        }
        loop {
            let role = prompt_line(&format!("secret KEY for '{}' (blank to finish): ", name))?;
            let role = role.trim().to_ascii_uppercase();
            if role.is_empty() {
                break;
            }
            if !valid_role(&role) {
                eprintln!("  '{}' isn't a valid env key ([A-Z0-9_]); try again", role);
                continue;
            }
            let val = rpassword::prompt_password(format!("Value for {} (hidden): ", role))
                .map_err(|e| format!("read value: {}", e))?;
            if val.is_empty() {
                eprintln!("  value cannot be empty; try again");
                continue;
            }
            new_values.push((role, val));
        }
    }

    // Duplicate KEY guard (already uppercase — case-insensitive by construction).
    let mut seen = std::collections::HashSet::new();
    for (role, _) in &new_values {
        if !seen.insert(role.clone()) {
            return Err(format!("duplicate secret KEY '{}'", role));
        }
    }
    Ok(Gathered {
        new_values,
        existing,
    })
}

fn dedup_upper(keys: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    keys.retain(|k| seen.insert(k.clone()));
}

fn prompt_hosts(name: &str) -> Result<Vec<String>, String> {
    eprintln!(
        "Connection '{}' needs at least one egress host (the API's exact domain).",
        name
    );
    let mut hosts = Vec::new();
    loop {
        let prompt = if hosts.is_empty() {
            "Host (e.g. api.example.com): ".to_string()
        } else {
            "Another host (blank to finish): ".to_string()
        };
        let h = prompt_line(&prompt)?;
        let h = h.trim();
        if h.is_empty() {
            if hosts.is_empty() {
                eprintln!("  at least one host is required");
                continue;
            }
            break;
        }
        hosts.push(h.to_string());
    }
    Ok(hosts)
}

pub(crate) fn prompt_line(prompt: &str) -> Result<String, String> {
    eprint!("{}", prompt);
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read input: {}", e))?;
    Ok(line)
}

/// Report the advertised phantom(s) for a raw connection: sole → short form,
/// several → role-qualified (matches the resolver's form-A grammar).
fn report_phantoms(name: &str, hosts: &[String], secret_keys: &[String]) {
    eprintln!("safeclaw connect — '{}' → {}", name, hosts.join(", "));
    let phantoms = crate::core::host::phantoms_for_raw(name, secret_keys);
    for ph in phantoms.values() {
        eprintln!("  phantom: {}", ph);
    }
}
