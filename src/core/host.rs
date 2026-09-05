//! Host anchor + phantom string derivation (phantom-only broker).
//!
//! `resolved_hosts` is the SSoT for "where may this connection's credential
//! egress" — service-declared exact hosts plus any exact FQDNs the instance
//! pinned within a service's `*.suffix` wildcards, or a raw connection's own
//! anchored hosts. Runtime enforcement is always exact FQDN, case-insensitive,
//! port-aware; wildcards never reach it (they only constrain what an instance
//! may pin, checked at connect time via `wildcard_matches`).
//!
//! The phantom builders are the single source for the `__sc__<conn>__[<role>__]`
//! strings the discovery surfaces hand agents, so the format lives in exactly
//! one place.

use std::collections::{BTreeMap, HashSet};

use crate::service::{ServiceDef, ServiceRegistry};
use crate::storage::plaintext::Connection;

/// The exact FQDNs a connection's credential may egress to (spec §4):
///   service set → the service's exact host entries ∪ the instance's pinned
///                 exact FQDNs (each ⊆ a `*.suffix` entry, validated at connect);
///   raw (`service: None`) → the connection's own `hosts`.
/// `def` is the already-resolved service definition (compiled or custom); pass
/// `None` for a raw connection or an unresolvable service.
pub fn resolved_hosts(conn: &Connection, def: Option<&ServiceDef>) -> Vec<String> {
    match (&conn.service, def) {
        (Some(_), Some(def)) => {
            let mut out: Vec<String> = def
                .service
                .hosts
                .iter()
                .filter(|h| !h.starts_with("*."))
                .cloned()
                .collect();
            if let Some(pinned) = &conn.hosts {
                for h in pinned {
                    if !out.iter().any(|e| e.eq_ignore_ascii_case(h)) {
                        out.push(h.clone());
                    }
                }
            }
            out
        }
        // A named service we couldn't resolve → only whatever the instance pinned.
        (Some(_), None) => conn.hosts.clone().unwrap_or_default(),
        // Raw connection.
        (None, _) => conn.hosts.clone().unwrap_or_default(),
    }
}

/// Convenience: resolve a connection's service through the compiled registry
/// then compute `resolved_hosts`. (S2 substitutes a custom-def lookup for
/// `aux.services`-backed connections.)
pub fn resolved_hosts_via_registry(conn: &Connection, services: &ServiceRegistry) -> Vec<String> {
    let def = conn.service.as_deref().and_then(|s| services.get(s));
    resolved_hosts(conn, def)
}

/// Strip a `:port` (or `]:port` for a bracketed IPv6) from an authority.
fn strip_port(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        // [ipv6]:port → the bracketed host
        return rest.split(']').next().unwrap_or(rest);
    }
    authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority)
}

/// Exact-FQDN match for runtime enforcement: case-insensitive, port-aware.
pub fn host_matches_exact(dest_authority: &str, allowed_fqdn: &str) -> bool {
    strip_port(dest_authority).eq_ignore_ascii_case(strip_port(allowed_fqdn))
}

/// Match a destination authority against ONE anchor entry, honoring a leftmost
/// `*.suffix` wildcard at RUNTIME. Unlike the connect-time single-label
/// [`wildcard_matches`] (TLS-cert rule), a raw-connection wildcard anchor covers
/// a subdomain at ANY depth so a user who doesn't know the exact API host can
/// anchor the whole domain: `*.bitquery.io` matches `api.bitquery.io` and
/// `a.b.bitquery.io`, but NEVER the bare apex `bitquery.io` nor a label-boundary
/// fake like `notbitquery.io`. A non-wildcard entry is the exact, port-aware,
/// case-insensitive compare.
pub fn host_anchor_matches(dest_authority: &str, anchor: &str) -> bool {
    if let Some(suffix) = anchor.strip_prefix("*.") {
        let dest = strip_port(dest_authority).to_ascii_lowercase();
        let suffix = suffix.to_ascii_lowercase();
        dest.strip_suffix(&suffix)
            .and_then(|pre| pre.strip_suffix('.'))
            .map(|pre| !pre.is_empty())
            .unwrap_or(false)
    } else {
        host_matches_exact(dest_authority, anchor)
    }
}

/// True if `dest_authority` matches any of the `resolved` anchor entries — an
/// exact FQDN or a `*.suffix` wildcard (see [`host_anchor_matches`]).
pub fn host_allowed(dest_authority: &str, resolved: &[String]) -> bool {
    resolved
        .iter()
        .any(|h| host_anchor_matches(dest_authority, h))
}

/// Single-label leftmost wildcard match (TLS-cert rule): `*.suffix` matches
/// exactly one label in front of `suffix`. An exact pattern falls back to a
/// case-insensitive compare. Used at connect-time pin validation, never at
/// runtime enforcement.
pub fn wildcard_matches(pattern: &str, fqdn: &str) -> bool {
    let fqdn = fqdn.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        match fqdn.strip_suffix(&format!(".{}", suffix)) {
            Some(label) => !label.is_empty() && !label.contains('.'),
            None => false,
        }
    } else {
        pattern == fqdn
    }
}

/// The union of `resolved_hosts` (lowercased) over a set of connections, using
/// the compiled registry. S2 uses this (extended with custom defs) to decide
/// which CONNECT authorities to MITM vs blind-tunnel.
pub fn host_union<'a>(
    conns: impl Iterator<Item = &'a Connection>,
    services: &ServiceRegistry,
) -> HashSet<String> {
    let mut set = HashSet::new();
    for c in conns {
        for h in resolved_hosts_via_registry(c, services) {
            set.insert(h.to_ascii_lowercase());
        }
    }
    set
}

// ── phantom strings ──────────────────────────────────────────────────────────

/// The default shorthand phantom — the connection's sole injectable secret (or
/// an oauth2 connection's minted access token).
pub fn short_phantom(conn_id: &str) -> String {
    format!("__sc__{}__", conn_id)
}

/// A role-qualified phantom — one of several injectable secrets, or an oauth2
/// `exposes` value. The role segment is the role lowercased.
pub fn role_phantom(conn_id: &str, role: &str) -> String {
    format!("__sc__{}__{}__", conn_id, role.to_ascii_lowercase())
}

fn insert_direct(map: &mut BTreeMap<String, String>, conn_id: &str, roles: &[String]) {
    match roles {
        [] => {}
        [only] => {
            map.insert(only.clone(), short_phantom(conn_id));
        }
        many => {
            for role in many {
                map.insert(role.clone(), role_phantom(conn_id, role));
            }
        }
    }
}

/// The discovery `phantoms` map (injectable role → ready-made phantom string)
/// for a service-backed connection. A minted mechanism (`[auth]`) → an
/// `ACCESS` short-form phantom (the minted token) plus, for oauth2, one
/// role-qualified phantom per `exposes` entry; the mint's input secret is
/// NEVER in the map. Static → the service's `secrets` (sole → short form,
/// several → role-qualified).
pub fn phantoms_for(conn_id: &str, def: &ServiceDef) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    match &def.auth {
        Some(crate::service::AuthDef::Oauth2(o)) => {
            map.insert("ACCESS".to_string(), short_phantom(conn_id));
            for role in &o.exposes {
                map.insert(role.to_ascii_uppercase(), role_phantom(conn_id, role));
            }
        }
        // Any other minted mechanism (snaplii): the sole injectable is the
        // minted token behind the default phantom; the input key never appears.
        Some(_) => {
            map.insert("ACCESS".to_string(), short_phantom(conn_id));
        }
        None => insert_direct(&mut map, conn_id, &def.service.secrets),
    }
    map
}

/// The `phantoms` map for a raw connection (`service: None`): its injectable
/// secret keys are the record's explicit `secrets` list (bare KEYs), passed in
/// by the caller.
pub fn phantoms_for_raw(conn_id: &str, secret_keys: &[String]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    insert_direct(&mut map, conn_id, secret_keys);
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct(id: &str, hosts: &[&str], secrets: &[&str]) -> ServiceDef {
        let hosts = hosts
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", ");
        let secrets = secrets
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", ");
        let toml = format!(
            "[service]\nid = \"{}\"\nname = \"X\"\nhosts = [{}]\nsecrets = [{}]\n",
            id, hosts, secrets
        );
        toml::from_str(&toml).unwrap()
    }

    #[test]
    fn exact_match_case_insensitive_and_port_aware() {
        let resolved = vec!["api.github.com".to_string()];
        assert!(host_allowed("API.GitHub.com", &resolved));
        assert!(host_allowed("api.github.com:443", &resolved));
        assert!(!host_allowed("evil.com", &resolved));
        assert!(!host_allowed("api.github.com.evil.com", &resolved));
    }

    #[test]
    fn wildcard_anchor_covers_subdomains_not_apex_or_lookalikes() {
        let resolved = vec!["*.bitquery.io".to_string()];
        // any-depth subdomain matches (case-insensitive, port-aware).
        assert!(host_allowed("api.bitquery.io", &resolved));
        assert!(host_allowed("streaming.bitquery.io:443", &resolved));
        assert!(host_allowed("a.b.bitquery.io", &resolved));
        assert!(host_allowed("API.BitQuery.io", &resolved));
        // the bare apex is NOT covered by a `*.` wildcard.
        assert!(!host_allowed("bitquery.io", &resolved));
        // label-boundary: a lookalike suffix never matches.
        assert!(!host_allowed("notbitquery.io", &resolved));
        assert!(!host_allowed("bitquery.io.evil.com", &resolved));
        assert!(!host_allowed("evil.com", &resolved));
        // exact entries stay exact even alongside the wildcard support.
        let exact = vec!["api.bitquery.io".to_string()];
        assert!(host_allowed("api.bitquery.io", &exact));
        assert!(!host_allowed("streaming.bitquery.io", &exact));
    }

    #[test]
    fn wildcard_single_label_only() {
        assert!(wildcard_matches(
            "*.openai.azure.com",
            "foo.openai.azure.com"
        ));
        assert!(wildcard_matches(
            "*.openai.azure.com",
            "FOO.OPENAI.AZURE.COM"
        ));
        // two labels rejected (single-label leftmost).
        assert!(!wildcard_matches(
            "*.openai.azure.com",
            "a.b.openai.azure.com"
        ));
        // zero labels rejected.
        assert!(!wildcard_matches("*.openai.azure.com", "openai.azure.com"));
        // exact pattern is a plain compare.
        assert!(wildcard_matches("api.github.com", "API.github.com"));
        assert!(!wildcard_matches("api.github.com", "x.api.github.com"));
    }

    #[test]
    fn resolved_hosts_service_excludes_wildcards_includes_pins() {
        let mut def = direct("acme", &["api.acme.com"], &["ACME_TOKEN"]);
        def.service.hosts.push("*.acme.dev".to_string());
        let conn = Connection {
            name: None,
            service: Some("acme".to_string()),
            hosts: Some(vec!["tenant1.acme.dev".to_string()]),
            secrets: None,
            keys: None,
        };
        let hosts = resolved_hosts(&conn, Some(&def));
        assert!(hosts.contains(&"api.acme.com".to_string()));
        assert!(hosts.contains(&"tenant1.acme.dev".to_string()));
        assert!(!hosts.iter().any(|h| h.contains('*')));
    }

    #[test]
    fn resolved_hosts_raw_uses_own_hosts() {
        let conn = Connection {
            name: None,
            service: None,
            hosts: Some(vec!["api.stripe.com".to_string()]),
            secrets: Some(vec!["STRIPE_KEY".to_string()]),
            keys: None,
        };
        assert_eq!(
            resolved_hosts(&conn, None),
            vec!["api.stripe.com".to_string()]
        );
    }

    #[test]
    fn phantoms_direct_sole_and_multi() {
        let sole = direct("github", &["api.github.com"], &["GITHUB_TOKEN"]);
        let m = phantoms_for("github", &sole);
        assert_eq!(
            m.get("GITHUB_TOKEN").map(String::as_str),
            Some("__sc__github__")
        );

        let multi = direct("bb", &["api.bitbucket.org"], &["USERNAME", "API_TOKEN"]);
        let m = phantoms_for("bb", &multi);
        assert_eq!(
            m.get("USERNAME").map(String::as_str),
            Some("__sc__bb__username__")
        );
        assert_eq!(
            m.get("API_TOKEN").map(String::as_str),
            Some("__sc__bb__api_token__")
        );
    }

    #[test]
    fn phantoms_oauth2_access_plus_exposes_never_refresh() {
        let toml = r#"
[service]
id = "gmail"
name = "Gmail"
hosts = ["gmail.googleapis.com"]
[auth]
type = "oauth2"
provider = "google"
refresh_token = "GMAIL_REFRESH_TOKEN"
exposes = ["account_id"]
"#;
        let def: ServiceDef = toml::from_str(toml).unwrap();
        let m = phantoms_for("gmail", &def);
        assert_eq!(m.get("ACCESS").map(String::as_str), Some("__sc__gmail__"));
        assert_eq!(
            m.get("ACCOUNT_ID").map(String::as_str),
            Some("__sc__gmail__account_id__")
        );
        // The refresh secret is never surfaced as an injectable phantom.
        assert!(!m.contains_key("GMAIL_REFRESH_TOKEN"));
    }
}
