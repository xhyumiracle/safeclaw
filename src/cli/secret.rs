//! `safeclaw set <KEY> <VALUE>` / `safeclaw get <KEY>` / `safeclaw rm <KEY>`
//!
//! Every verb drives ONE op through the shared approval path
//! (`cli::approve::approve_op`): paired → the cloud `/grant/{op_id}` link,
//! self-host → the local on-box ceremony. For `set`, the VALUE is deposited
//! with the local daemon first (`deposit_values`) and the op carries only its
//! salted digest — plaintext never rides the op (which travels to the cloud
//! grant page), and one passkey approval covers the whole write.

use std::collections::BTreeMap;
use std::io::IsTerminal;

use serde_json::json;

use crate::cli::active::resolve_active;
use crate::cli::approve::{act_result, approve_op, deposit_values, ApproveOpts};
use crate::cli::conn::{valid_conn_id, valid_role, validate_raw_host};
use crate::cli::webauthn::*;
use crate::config::{GetArgs, RmArgs, SetArgs};

/// What `sc set` does with the item's broker binding.
enum BrokerIntent {
    /// Store the value with no host — human-only, invisible to the agent.
    NoBroker,
    /// Create a raw connection anchored to these exact FQDNs.
    Host(Vec<String>),
}

pub async fn run_set(args: SetArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    // §1: secret KEYs are ALWAYS uppercase. Force-uppercase on input (a lowercase
    // key is auto-converted, never stored lowercase) so there is one canonical
    // form. Reject anything that isn't a valid env KEY even after uppercasing.
    let key = args.key.trim().to_ascii_uppercase();
    if !valid_role(&key) {
        return Err(format!(
            "'{}' is not a valid secret key — use UPPERCASE letters, digits and '_' (e.g. STRIPE_KEY)",
            args.key.trim()
        ));
    }

    // Value: explicit arg, else hidden TTY prompt, else (non-TTY) an error.
    let value = match args.value.clone() {
        Some(v) => v,
        None => prompt_secret_value(&key)?,
    };

    // Broker intent: --no-broker | --host <h..> | (TTY) prompt | (non-TTY) error.
    let intent = resolve_broker_intent(&key, &args.host, args.no_broker)?;

    // The single-secret sugar: the connection id is the lowercased key — a plain
    // handle (safe now that `secrets` is stored explicitly, no reverse-index
    // coupling — §9). Validate the id + anchor hosts BEFORE spending a passkey
    // gesture — an invalid --host must not cost the user an unlock touch.
    let conn = key.to_ascii_lowercase();
    if let BrokerIntent::Host(hosts) = &intent {
        if !valid_conn_id(&conn) {
            return Err(format!(
                "can't derive a connection id from '{}' — use `sc connect <name> --host {} --secret {}=<value>` instead",
                key,
                hosts.first().map(String::as_str).unwrap_or("<domain>"),
                key
            ));
        }
        for h in hosts {
            validate_raw_host(h)?;
        }
    }

    // Deposit the value with the LOCAL daemon; only its salted digest rides the
    // op (the op JSON travels to the cloud grant page — the value must not).
    let mut values = BTreeMap::new();
    values.insert(key.clone(), value);
    let digest = deposit_values(&custodian, &vault, &values).await?;

    let mut scope = json!({ "values_digest": digest });
    match &intent {
        BrokerIntent::NoBroker => scope["no_broker"] = json!(true),
        BrokerIntent::Host(hosts) => scope["hosts"] = json!(hosts),
    }
    let op = json!({
        "act": { "type": { "custom": "secret-set" }, "target": key, "scope": scope },
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
        &format!("Store secret {}", key),
        &opts,
    )
    .await?;

    let result = act_result(&body);
    match intent {
        BrokerIntent::NoBroker => {
            // The daemon dropped any raw connection a prior `sc set <key>
            // --host …` created (opting out must actually un-broker).
            if result
                .get("removed_prior_anchor")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                eprintln!("  removed the prior host anchor for '{}'", conn);
            }
            eprintln!("  stored · no host anchored — agent cannot use this item (`sc secret get` reveals it for a human)");
        }
        BrokerIntent::Host(hosts) => {
            eprintln!(
                "  connection '{}' → {} · phantom __sc__{}__",
                conn,
                hosts.join(", "),
                conn
            );
        }
    }
    eprintln!("safeclaw set — {} written", key);
    Ok(())
}

/// Decide the broker binding for `sc set`. Host is a REQUIRED answer (spec §11):
/// `--no-broker` / `--host none` opt out explicitly; otherwise `--host` anchors;
/// missing on a TTY → prompt; missing off a TTY → a clear error naming both
/// fixes (never hang, never silently store an unusable item).
fn resolve_broker_intent(
    key: &str,
    host: &[String],
    no_broker: bool,
) -> Result<BrokerIntent, String> {
    if no_broker {
        return Ok(BrokerIntent::NoBroker);
    }
    // `--host none` is the explicit opt-out sentinel.
    if host.len() == 1 && host[0].eq_ignore_ascii_case("none") {
        eprintln!("  --host none → stored without a host · agent cannot use this item");
        return Ok(BrokerIntent::NoBroker);
    }
    if !host.is_empty() {
        return Ok(BrokerIntent::Host(host.to_vec()));
    }
    if std::io::stdin().is_terminal() {
        let entered = prompt_host(key)?;
        if entered.eq_ignore_ascii_case("none") {
            eprintln!("  stored without a host · agent cannot use this item");
            return Ok(BrokerIntent::NoBroker);
        }
        Ok(BrokerIntent::Host(vec![entered]))
    } else {
        Err(format!(
            "'{}' needs a host so the agent can use it — pass `--host <domain>` (the API's domain, e.g. api.stripe.com), or `--no-broker` to store it for humans only",
            key
        ))
    }
}

/// Hidden value prompt (TTY only — keeps the secret out of shell history / `ps`).
fn prompt_secret_value(key: &str) -> Result<String, String> {
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "no value given for '{}' — pass it as an argument (non-interactive input isn't a terminal)",
            key
        ));
    }
    let v = rpassword::prompt_password(format!("Value for {} (hidden): ", key))
        .map_err(|e| format!("read value: {}", e))?;
    if v.is_empty() {
        return Err("value cannot be empty".into());
    }
    Ok(v)
}

/// Required host prompt. Echoes the intent so an arg-order slip is visible.
fn prompt_host(key: &str) -> Result<String, String> {
    use std::io::Write as _;
    eprintln!("'{}' needs an egress host so the agent can use it.", key);
    eprint!("Host (the API's exact domain, e.g. api.stripe.com; 'none' = store for humans only): ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read host: {}", e))?;
    let h = line.trim().to_string();
    if h.is_empty() {
        return Err(
            "a host is required (or `none` / `--no-broker` to store for humans only)".into(),
        );
    }
    Ok(h)
}

pub async fn run_rm(args: RmArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    // §1: secret KEYs are canonical uppercase — normalize on input so `sc rm
    // github_token` finds the stored `GITHUB_TOKEN`.
    let key = args.key.trim().to_ascii_uppercase();
    if key.is_empty() {
        return Err("key required".into());
    }
    // Anti-fat-finger confirm BEFORE the gesture (the grant page also names the
    // op). The referenced-by detail is reported AFTER — the daemon computes it
    // while it holds the open vault. The KEY name rides the op (public); the
    // value never leaves the vault.
    if !args.force && std::io::stdin().is_terminal() {
        let ans = crate::cli::connect::prompt_line(&format!("Remove key '{}'? [y/N]: ", key))?;
        if !matches!(ans.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("aborted");
            return Ok(());
        }
    }
    let op = json!({
        "act": { "type": { "custom": "secret-rm" }, "target": key, "scope": null },
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
        &format!("Remove key {}", key),
        &opts,
    )
    .await?;

    let refs: Vec<String> = act_result(&body)
        .get("referenced_by")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !refs.is_empty() {
        eprintln!(
            "note: {} is referenced by connection(s): {} — they turn unconfigured until the key is re-added",
            key,
            refs.join(", ")
        );
    }
    println!("key '{}' removed", key);
    Ok(())
}

pub async fn run_get(args: GetArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    // Case-SENSITIVE exact match — the mainstream convention for env vars and
    // secret managers (GCP/AWS/Vault). `get` reads across ALL stores: native
    // keys are canonical UPPERCASE, but external stores (GCP Secret Manager)
    // preserve their own casing, so a lowercase name like `xh-gcp-test` is only
    // reachable verbatim. We do NOT uppercase here (that would make external
    // lowercase secrets unreadable); `sc get github_token` must be typed as the
    // stored `GITHUB_TOKEN`.
    let key = args.key.trim().to_string();
    if key.is_empty() {
        return Err("key cannot be empty".into());
    }

    let op = json!({
        "act": { "type": "export", "target": key, "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    let body = approve_op(&custodian, &vault, &op, &format!("Reveal {}", key), &opts).await?;
    let value = body
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or("no value in response — op may have been consumed")?;
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    out.write_all(value.as_bytes())
        .map_err(|e| format!("stdout: {}", e))?;
    out.write_all(b"\n").ok();
    Ok(())
}
