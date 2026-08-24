//! Grouped top-level `sc --help`.
//!
//! clap has no builtin way to group subcommands under section headings — it
//! renders one flat "Commands:" list. gh, docker and kubectl all show grouped
//! help; they get it from Cobra (Go), which has a curated one-line `Short` per
//! command and command groups. We do the same by hand: a short summary + section
//! per command below, rendered as the top-level help. The full description of
//! each command still lives on the command itself (`sc <command> --help`).
//!
//! A command that isn't listed here is NOT dropped — it falls under "Other" with
//! its own (clap-derived) description, so the help can never silently hide a
//! command someone forgot to slot in.

use clap::CommandFactory;

use crate::config::Cli;

/// Sections in display order; each row is `(command, one-line summary)`. The
/// command name must match the clap name of the `Command` variant.
const SECTIONS: &[(&str, &[(&str, &str)])] = &[
    (
        "Setup",
        &[
            ("login", "Pair this host to your vault"),
            ("logout", "Unpair this host"),
            ("up", "Start the daemon and unlock the vault"),
            ("down", "Stop the daemon"),
            ("restart", "Restart the daemon and re-unlock"),
            ("status", "Show daemon and active-vault status"),
        ],
    ),
    (
        "Secrets",
        &[
            ("secret", "Manage vault secrets: set / get / rm / ls"),
            ("get", "Read a secret to stdout"),
            ("set", "Write a secret"),
            ("ls", "List secret names"),
            ("rm", "Delete a secret"),
        ],
    ),
    (
        "Connections",
        &[
            ("connection", "Manage connections: add / ls / rm"),
            ("run", "Run a command through the credential proxy"),
            ("registry", "Show the service catalog"),
            ("store", "Manage connected external stores"),
        ],
    ),
    (
        "Account",
        &[
            ("agent", "Manage agents (API keys)"),
            ("device", "Manage this device's pairing"),
            ("passkey", "Manage enrolled passkeys"),
            ("vault", "Per-vault lifecycle (e.g. rm)"),
        ],
    ),
    (
        "Maintenance",
        &[
            ("sync", "Pull vault state from the cloud now"),
            ("unlock", "Unlock the active vault"),
            ("lock", "Lock the active vault"),
            ("log", "Tail the daemon's logs"),
            ("doctor", "Run health and reachability checks"),
            ("upgrade", "Self-update to the latest release"),
            ("env", "Print shell exports for your shell"),
            ("config", "Read/write CLI preferences"),
            ("proxy", "Set the daemon's upstream egress proxy"),
            ("service", "Work with service.toml definitions"),
            ("op", "Approval ops (e.g. op wait)"),
        ],
    ),
];

/// The derived top-level command with our grouped help installed. `main` parses
/// through this instead of `Cli::parse()` so bare `sc` and `sc --help` print the
/// grouped layout; per-command help (`sc secret --help`) stays clap's default.
pub fn command() -> clap::Command {
    let base = Cli::command();
    let help = render(&base);
    base.arg_required_else_help(true)
        .override_help(help)
        // Global `-v/-vv/-vvv` (curl-style): available on every subcommand. Read
        // in `main` from the matches (not the derived `Cli`) to init logging.
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::Count)
                .global(true)
                .help("Increase logging to stderr (-v info, -vv debug, -vvv trace)"),
        )
}

/// Collapse a (possibly multi-line) clap `about` to a single trimmed sentence,
/// hard-capped so "Other" rows line up with the curated ones.
fn short_from_about(about: &str, max: usize) -> String {
    let flat = about.split_whitespace().collect::<Vec<_>>().join(" ");
    let sentence = flat
        .split_inclusive('.')
        .next()
        .unwrap_or(&flat)
        .trim()
        .trim_end_matches('.')
        .to_string();
    let s = if sentence.is_empty() { flat } else { sentence };
    if s.chars().count() <= max {
        return s;
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    if let Some(i) = t.rfind(' ') {
        t.truncate(i);
    }
    format!("{}…", t.trim_end())
}

fn render(cmd: &clap::Command) -> String {
    // Visible (non-hidden) subcommand names, and their clap descriptions for the
    // "Other" fallback.
    let mut visible: Vec<String> = Vec::new();
    let mut about: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for s in cmd.get_subcommands() {
        if s.is_hide_set() || s.get_name() == "help" {
            continue;
        }
        let name = s.get_name().to_string();
        about.insert(
            name.clone(),
            short_from_about(
                &s.get_about().map(|a| a.to_string()).unwrap_or_default(),
                52,
            ),
        );
        visible.push(name);
    }

    let curated: std::collections::HashSet<&str> = SECTIONS
        .iter()
        .flat_map(|(_, rows)| rows.iter().map(|(n, _)| *n))
        .collect();
    // One column for every row, wide enough for the longest command name AND the
    // longest option label below, so descriptions line up throughout.
    let pad = visible
        .iter()
        .map(String::len)
        .chain(std::iter::once("-V, --version".len()))
        .max()
        .unwrap_or(4)
        .max(4)
        + 2;

    let mut out = String::new();
    out.push_str("SafeClaw — passkey-gated credential broker\n\n");
    out.push_str("Usage: sc <command> [options]\n");

    for (heading, rows) in SECTIONS {
        let present: Vec<&(&str, &str)> = rows
            .iter()
            .filter(|(n, _)| visible.iter().any(|v| v == n))
            .collect();
        if present.is_empty() {
            continue;
        }
        out.push('\n');
        out.push_str(heading);
        out.push('\n');
        for (name, summary) in present {
            out.push_str(&format!("  {name:<pad$}{summary}\n"));
        }
    }

    let others: Vec<&String> = visible
        .iter()
        .filter(|v| !curated.contains(v.as_str()))
        .collect();
    if !others.is_empty() {
        out.push_str("\nOther\n");
        for name in others {
            let summary = about.get(name).map(String::as_str).unwrap_or("");
            out.push_str(&format!("  {name:<pad$}{summary}\n"));
        }
    }

    out.push_str("\nOptions:\n");
    out.push_str(&format!(
        "  {:<pad$}Print help (and `sc <command> --help` per command)\n",
        "-h, --help"
    ));
    out.push_str(&format!("  {:<pad$}Print version\n", "-V, --version"));
    out.push_str(&format!(
        "  {:<pad$}More logging to stderr (-v info, -vv debug, -vvv trace)\n",
        "-v, --verbose"
    ));
    out.push_str(&format!(
        "  {:<pad$}Emit machine-readable JSON where supported\n",
        "--json"
    ));
    out
}
