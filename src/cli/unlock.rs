//! `safeclaw unlock` / `safeclaw lock` — build the lifecycle op and hand it to
//! the shared approval driver (`cli::approve`), which picks the remote (cloud
//! web-approval) or local (on-box ceremony) arm. No bespoke passkey logic here
//! — every approval flows through the one code path.

use serde_json::json;

use crate::cli::active::resolve_active;
use crate::cli::approve::{approve_op, ApproveOpts};
use crate::cli::webauthn::now_unix;
use crate::config::UnlockArgs;

pub async fn run_unlock(args: UnlockArgs) -> Result<(), String> {
    drive("vault-unlock", "Unlock vault", args).await
}
pub async fn run_lock(args: UnlockArgs) -> Result<(), String> {
    drive("vault-lock", "Lock vault", args).await
}

async fn drive(custom_op: &str, label: &str, args: UnlockArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;

    let op = json!({
        "act": { "type": { "custom": custom_op }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });

    let opts = ApproveOpts {
        no_browser: args.no_browser,
        cb_port: args.cb_port,
        timeout: args.timeout,
    };
    approve_op(&custodian, &vault, &op, label, &opts).await?;

    eprintln!("safeclaw {} — ok", label.to_lowercase());
    Ok(())
}
