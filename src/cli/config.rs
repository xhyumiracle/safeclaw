//! `sc config set/get/unset/ls` — persistent CLI preferences in
//! `~/.safeclaw/config.toml` `[settings]`.
//!
//! Resolution chain for any setting:
//!   1. CLI flag (per-invocation)
//!   2. SAFECLAW_* env var (per-shell)
//!   3. this config file (persistent)
//!   4. clap default (built-in)
//!
//! Keys are kebab-case on the CLI (matches the flag names),
//! snake_case in the TOML file (Rust convention).

use crate::cli::active::{load, save};
use crate::config::ConfigSubcommand;

pub fn run(sub: ConfigSubcommand) -> Result<(), String> {
    match sub {
        ConfigSubcommand::Set { key, value } => run_set(&key, &value),
        ConfigSubcommand::Get { key } => run_get(&key),
        ConfigSubcommand::Unset { key } => run_unset(&key),
        ConfigSubcommand::Ls => run_ls(),
    }
}

fn run_set(key: &str, value: &str) -> Result<(), String> {
    let mut cfg = load().unwrap_or_default();
    match canonical_key(key)? {
        Key::CbPort => {
            let n: u16 = value
                .parse()
                .map_err(|_| format!("cb-port must be a 1..=65535 integer, got {:?}", value))?;
            cfg.settings.cb_port = Some(n);
        }
    }
    let path = save(&cfg)?;
    println!("set {} = {}  ({})", key, value, path.display());
    Ok(())
}

fn run_get(key: &str) -> Result<(), String> {
    let cfg = load().unwrap_or_default();
    match canonical_key(key)? {
        Key::CbPort => match cfg.settings.cb_port {
            Some(n) => {
                println!("{}", n);
                Ok(())
            }
            None => Err(format!("{} is not set", key)),
        },
    }
}

fn run_unset(key: &str) -> Result<(), String> {
    let mut cfg = load().unwrap_or_default();
    let was = match canonical_key(key)? {
        Key::CbPort => cfg.settings.cb_port.take().map(|v| v.to_string()),
    };
    save(&cfg)?;
    match was {
        Some(prev) => println!("unset {} (was {})", key, prev),
        None => println!("{} was already unset", key),
    }
    Ok(())
}

fn run_ls() -> Result<(), String> {
    let cfg = load().unwrap_or_default();
    let mut any = false;
    if let Some(n) = cfg.settings.cb_port {
        println!("cb-port = {}", n);
        any = true;
    }
    if !any {
        println!("(no settings yet — try `sc config set cb-port 23394`)");
    }
    Ok(())
}

enum Key {
    CbPort,
}

fn canonical_key(key: &str) -> Result<Key, String> {
    match key.replace('_', "-").to_ascii_lowercase().as_str() {
        "cb-port" => Ok(Key::CbPort),
        other => Err(format!("unknown setting: {:?}. Known keys: cb-port", other)),
    }
}
