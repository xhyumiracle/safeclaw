//! Short-lived CLI commands that talk to a `safeclaw start` daemon over HTTP.
//!
//! Each subcommand is a small async fn — kept here (not in `handlers/`)
//! because handlers are the daemon's HTTP request side; this is the
//! client side. Same binary, different mode.

pub mod active;
pub mod agent;
pub mod agent_shim;
pub mod apierr;
pub mod approve;
pub mod config;
pub mod conn;
pub mod connect;
pub mod custodian;
pub mod discovery;
pub mod doctor;
pub mod egress_proxy;
pub mod env;
pub mod git_credential;
pub mod help;
pub mod logging;
pub mod login;
pub mod logout;
pub mod ls;
pub mod neterr;
pub mod op;
pub mod passkey;
pub mod proxy;
pub mod proxy_env;
pub mod run;
pub mod secret;
pub mod service;
pub mod service_def;
pub mod status;
pub mod store;
pub mod sync;
pub mod unlock;
pub mod up;
pub mod upgrade;
pub mod vault;
pub mod webauthn;
