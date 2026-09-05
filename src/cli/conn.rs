//! Shared creation of connections for `sc set --host` (raw single-secret) and
//! `sc connect` (raw multi-secret, or service-backed via `--service`), plus the
//! `aux.services` write for `sc service add`. One place enforces the id + host +
//! role rules so the verbs can't drift, and one place mutates the sealed `aux`
//! value in a way that preserves every other key. Raw connections carry explicit
//! `secrets` (§2); service-backed connections omit them (derived from the service).

use serde_json::{json, Value};

use crate::service::validate::host_egress_allowed;

/// A connection id / phantom `<conn>` segment: `[a-z0-9_]`, starts
/// alphanumeric, no `__` (the phantom delimiter). Same rule the resolver and
/// service-id validator use.
pub fn valid_conn_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 || s.contains("__") {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Turn a free-typed handle ("My Work Gmail") into a safe connection id
/// ("my_work_gmail"): lowercase, collapse every non-`[a-z0-9]` run into a single
/// `_`, trim leading/trailing `_`, cap at 64. Mirrors the console's
/// `slugifyHandle` so the CLI and web mint the same id from the same input (the
/// one divergence: no NFKD fold — a non-ASCII char becomes a separator rather
/// than its ASCII base, e.g. `café` → `caf`). The result always satisfies
/// [`valid_conn_id`] or is empty (caller re-prompts / errors).
pub fn slugify_conn_id(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_sep = true; // treat start as a separator so leading runs drop
    for c in input.chars().flat_map(|c| c.to_lowercase()) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
            prev_sep = false;
        } else if !prev_sep {
            out.push('_');
            prev_sep = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.len() > 64 {
        out.truncate(64);
        while out.ends_with('_') {
            out.pop();
        }
    }
    out
}

/// A secret role KEY on a connection: env-style `[A-Za-z0-9_]` starting with a
/// letter. Because its lowercase becomes a phantom role segment
/// (`__sc__<conn>__<role>__`), it may carry no `__` (the delimiter) and no
/// trailing `_` (which would fuse into the delimiter as `___`, making the
/// advertised phantom unparseable).
pub fn valid_role(s: &str) -> bool {
    if s.is_empty() || s.contains("__") || s.ends_with('_') {
        return false;
    }
    let first_ok = s
        .chars()
        .next()
        .map(|c| c.is_ascii_alphabetic())
        .unwrap_or(false);
    first_ok && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A REFERENCED (already-existing) secret key — native canonical form or an
/// external store's name. External naming is not ours to fold (GCP allows
/// lowercase and hyphens), but the key still rides consent cards, connection
/// records, and phantom-adjacent strings, so keep it printable and
/// phantom-safe: ASCII alnum / `_` / `-`, starts alphanumeric, no `__`, no
/// trailing `_`, ≤255 chars. NEW keys (deposits) stay on the strict
/// uppercase `valid_role` — this relaxation is for referencing only.
pub fn valid_secret_ref(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 || s.contains("__") || s.ends_with('_') {
        return false;
    }
    let first_ok = s
        .chars()
        .next()
        .map(|c| c.is_ascii_alphanumeric())
        .unwrap_or(false);
    first_ok
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Validate a raw connection's anchor host: a bare FQDN (no scheme / path /
/// port) that is not a private / metadata / loopback target. A leftmost
/// `*.suffix` wildcard IS allowed — it anchors the whole domain (matched at
/// runtime by `host_anchor_matches`), so a user who doesn't know the exact API
/// host can pin `*.example.com`; the suffix must have >=2 labels so a whole TLD
/// can never be anchored.
pub fn validate_raw_host(h: &str) -> Result<(), String> {
    let h = h.trim();
    if h.is_empty() {
        return Err("host cannot be empty".into());
    }
    if h.contains("://") || h.contains('/') || h.contains("{{") {
        return Err(format!(
            "host '{}' must be a bare domain (no scheme/path)",
            h
        ));
    }
    if h.contains(':') {
        return Err(format!("host '{}' must not carry a port", h));
    }
    // A leftmost `*.suffix` wildcard is allowed (anchors the whole domain).
    // Strip it and validate the suffix as the bare domain; require >=2 labels
    // so a whole TLD (`*.com`) can never be anchored.
    let bare = match h.strip_prefix("*.") {
        Some(suffix) => {
            if !suffix.contains('.') {
                return Err(format!(
                    "host '{}' is too broad — a wildcard needs a domain like *.example.com",
                    h
                ));
            }
            suffix
        }
        None => h,
    };
    if bare.contains('*') {
        return Err(format!(
            "host '{}' — only a single leftmost '*.' wildcard is allowed",
            h
        ));
    }
    if !host_egress_allowed(bare) {
        return Err(format!(
            "host '{}' is loopback / private / metadata — not a valid egress target",
            h
        ));
    }
    Ok(())
}

/// Insert (or replace) a RAW connection into the vault `aux` value, preserving
/// every other aux key. `hosts` are the anchored exact FQDNs; `secrets` are the
/// UPPERCASE secret KEY names this connection uses (stored explicitly so
/// discovery/bootstrap never reverse-index by casing — §2). The written shape
/// (`{ "hosts": [...], "secrets": [...] }`, `service` omitted) deserializes to
/// `Connection { service: None, hosts: Some(..), secrets: Some(..) }`.
pub fn insert_raw_connection(aux: &mut Value, conn_id: &str, hosts: &[String], secrets: &[String]) {
    ensure_object(aux);
    let obj = aux.as_object_mut().unwrap();
    let conns = obj.entry("connections").or_insert_with(|| json!({}));
    if !conns.is_object() {
        *conns = json!({});
    }
    conns.as_object_mut().unwrap().insert(
        conn_id.to_string(),
        json!({ "hosts": hosts, "secrets": secrets }),
    );
}

/// Insert (or replace) a SERVICE-backed connection into the vault `aux` value,
/// preserving every other aux key. `hosts` is `Some(pins)` only when the user
/// pinned exact FQDNs inside a service's `*.suffix` wildcard (else `None`, hosts
/// derive from the service). `secrets` is omitted — a service-backed connection's
/// secrets derive from the service's declared `secrets` (§2). `keys` is the
/// role→KEY binding of a NAMED connection (§3; omitted = identity bindings, the
/// default connection's shape). The written shape deserializes to
/// `Connection { service: Some(..), hosts, secrets: None, keys }`.
pub fn insert_service_connection(
    aux: &mut Value,
    conn_id: &str,
    service: &str,
    hosts: Option<&[String]>,
    keys: Option<&[(String, String)]>,
) {
    ensure_object(aux);
    let obj = aux.as_object_mut().unwrap();
    let conns = obj.entry("connections").or_insert_with(|| json!({}));
    if !conns.is_object() {
        *conns = json!({});
    }
    let mut rec = serde_json::Map::new();
    rec.insert("service".to_string(), Value::String(service.to_string()));
    if let Some(h) = hosts {
        rec.insert("hosts".to_string(), json!(h));
    }
    if let Some(k) = keys.filter(|k| !k.is_empty()) {
        let map: serde_json::Map<String, Value> = k
            .iter()
            .map(|(role, key)| (role.clone(), Value::String(key.clone())))
            .collect();
        rec.insert("keys".to_string(), Value::Object(map));
    }
    conns
        .as_object_mut()
        .unwrap()
        .insert(conn_id.to_string(), Value::Object(rec));
}

/// Store a custom service definition (verbatim v4 toml source) under
/// `aux.services[<id>]`, preserving every other aux key.
pub fn insert_custom_service(aux: &mut Value, id: &str, toml_source: &str) {
    ensure_object(aux);
    let obj = aux.as_object_mut().unwrap();
    let svcs = obj.entry("services").or_insert_with(|| json!({}));
    if !svcs.is_object() {
        *svcs = json!({});
    }
    svcs.as_object_mut()
        .unwrap()
        .insert(id.to_string(), Value::String(toml_source.to_string()));
}

/// Remove a connection from `aux.connections`, preserving every other aux key.
/// Returns true if an entry was present. Used by `sc set --no-broker` and
/// `sc rm` to un-broker / clean up the connection tied to a key.
pub fn remove_connection(aux: &mut Value, conn_id: &str) -> bool {
    let Some(obj) = aux.as_object_mut() else {
        return false;
    };
    let Some(conns) = obj.get_mut("connections").and_then(|c| c.as_object_mut()) else {
        return false;
    };
    conns.remove(conn_id).is_some()
}

fn ensure_object(aux: &mut Value) {
    if !aux.is_object() {
        *aux = json!({});
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_id_rules() {
        assert!(valid_conn_id("github"));
        assert!(valid_conn_id("github_work"));
        assert!(valid_conn_id("s3"));
        assert!(!valid_conn_id("GitHub")); // uppercase
        assert!(!valid_conn_id("git__hub")); // double underscore
        assert!(!valid_conn_id("git-hub")); // hyphen
        assert!(!valid_conn_id("_x")); // must start alphanumeric
        assert!(!valid_conn_id(""));
    }

    #[test]
    fn slugify_matches_console_and_yields_valid_id() {
        assert_eq!(slugify_conn_id("My Work Gmail"), "my_work_gmail");
        assert_eq!(slugify_conn_id("github"), "github");
        assert_eq!(slugify_conn_id("  spaced  out  "), "spaced_out");
        assert_eq!(slugify_conn_id("a--b__c"), "a_b_c"); // any non-alnum run → one '_'
        assert_eq!(slugify_conn_id("café"), "caf"); // non-ASCII becomes a separator
        assert_eq!(slugify_conn_id("___"), ""); // nothing usable → empty (caller re-prompts)
                                                // Whatever it emits (non-empty) is a legal connection id.
        for s in ["My Work", "s3 bucket", "GitHub-Work"] {
            let id = slugify_conn_id(s);
            assert!(
                !id.is_empty() && valid_conn_id(&id),
                "slug {:?} → {:?}",
                s,
                id
            );
        }
    }

    #[test]
    fn role_rules() {
        assert!(valid_role("GITHUB_TOKEN"));
        assert!(valid_role("api_token"));
        assert!(!valid_role("1TOKEN")); // starts with digit
        assert!(!valid_role("A__B")); // double underscore
        assert!(!valid_role("A B")); // space
        assert!(!valid_role("_X")); // leading underscore
        assert!(!valid_role("X_")); // trailing underscore fuses the delimiter
    }

    #[test]
    fn secret_ref_rules() {
        // Native canonical + external naming both pass.
        assert!(valid_secret_ref("GITHUB_TOKEN"));
        assert!(valid_secret_ref("xh-gcp-test")); // lowercase + hyphens (GCP)
        assert!(valid_secret_ref("1password-item")); // digit start is fine for a reference
                                                     // Phantom safety + shape still enforced.
        assert!(!valid_secret_ref("")); // empty
        assert!(!valid_secret_ref("a__b")); // double underscore (phantom delimiter)
        assert!(!valid_secret_ref("key_")); // trailing underscore fuses the delimiter
        assert!(!valid_secret_ref("-key")); // must start alphanumeric
        assert!(!valid_secret_ref("a b")); // space
        assert!(!valid_secret_ref("a/b")); // path-ish
        assert!(!valid_secret_ref(&"x".repeat(256))); // length cap
    }

    #[test]
    fn remove_connection_drops_entry_and_reports() {
        let mut aux = json!({ "connections": { "stripe_key": { "hosts": ["api.stripe.com"] }, "keep": { "hosts": ["x.com"] } } });
        assert!(remove_connection(&mut aux, "stripe_key"));
        assert!(aux["connections"].get("stripe_key").is_none());
        assert!(aux["connections"]["keep"].is_object());
        // Idempotent: removing a missing conn reports false, leaves aux intact.
        assert!(!remove_connection(&mut aux, "stripe_key"));
    }

    #[test]
    fn raw_host_rejects_unsafe() {
        assert!(validate_raw_host("api.stripe.com").is_ok());
        assert!(validate_raw_host("https://api.stripe.com").is_err());
        assert!(validate_raw_host("api.stripe.com/x").is_err());
        assert!(validate_raw_host("api.stripe.com:443").is_err());
        assert!(validate_raw_host("*.stripe.com").is_ok()); // wildcard domain allowed
        assert!(validate_raw_host("*.com").is_err()); // whole TLD too broad
        assert!(validate_raw_host("a.*.stripe.com").is_err()); // only a leftmost wildcard
        assert!(validate_raw_host("localhost").is_err());
        assert!(validate_raw_host("169.254.169.254").is_err());
        assert!(validate_raw_host("10.0.0.5").is_err());
    }

    #[test]
    fn insert_raw_preserves_other_aux_keys() {
        let mut aux = json!({ "version": 4, "stores": { "native-secrets": {} } });
        insert_raw_connection(
            &mut aux,
            "stripe_key",
            &["api.stripe.com".to_string()],
            &["STRIPE_KEY".to_string()],
        );
        assert_eq!(aux["version"], 4);
        assert!(aux["stores"].is_object());
        assert_eq!(
            aux["connections"]["stripe_key"]["hosts"][0],
            "api.stripe.com"
        );
        // Explicit secrets (§2), uppercase KEY.
        assert_eq!(aux["connections"]["stripe_key"]["secrets"][0], "STRIPE_KEY");
        // No `service` key (None ⇒ raw).
        assert!(aux["connections"]["stripe_key"].get("service").is_none());
    }

    #[test]
    fn insert_service_connection_omits_secrets_and_optional_hosts() {
        let mut aux = json!({ "version": 4 });
        // Default connection, hosts derived (None).
        insert_service_connection(&mut aux, "gmail", "gmail", None, None);
        assert_eq!(aux["connections"]["gmail"]["service"], "gmail");
        assert!(aux["connections"]["gmail"].get("hosts").is_none());
        assert!(aux["connections"]["gmail"].get("secrets").is_none());
        // Named connection with a pinned wildcard host.
        insert_service_connection(
            &mut aux,
            "acme_t1",
            "acme",
            Some(&["t1.acme.dev".to_string()]),
            Some(&[("ACME_TOKEN".to_string(), "ACME_TOKEN_T1".to_string())]),
        );
        assert_eq!(aux["connections"]["acme_t1"]["service"], "acme");
        assert_eq!(aux["connections"]["acme_t1"]["hosts"][0], "t1.acme.dev");
        assert_eq!(
            aux["connections"]["acme_t1"]["keys"]["ACME_TOKEN"],
            "ACME_TOKEN_T1"
        );
    }

    #[test]
    fn insert_custom_service_preserves_aux() {
        let mut aux = json!({ "version": 4, "connections": { "a": { "hosts": ["x.com"] } } });
        insert_custom_service(&mut aux, "myapi", "[service]\nid=\"myapi\"\n");
        assert_eq!(aux["services"]["myapi"], "[service]\nid=\"myapi\"\n");
        assert!(aux["connections"]["a"].is_object());
    }
}
