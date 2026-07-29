//! In-memory approval state.
//!
//! When a brokered request through the credential proxy needs human approval,
//! an `ApprovalRecord` is created. The user approves it via the passkey-gated
//! op ceremony, which validates a passkey-signed grant and caches the
//! authorization. The agent's retry then resolves against that cached grant
//! and the record is consumed.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use uuid::Uuid;

use crate::protocol::operation::Operation;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected { reason: String },
    Consumed,
}

#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    pub id: String,
    pub vault_id: String,
    pub op: Operation,
    /// Challenge `r` issued by the custodian when this op was created. Returned
    /// to U via `GET /op/{op_id}` so U can compute β = H(domain ‖ r ‖ H(o))
    /// for the grant. Validated against the challenge store on
    /// `POST /op/{op_id}/approve`.
    pub r: String,
    pub status: ApprovalStatus,
    /// Cached plaintext result (e.g. for reveal). Available once status=Approved.
    pub cached_value: Option<String>,
    pub created_at: Instant,
    /// Wall-clock unix seconds when this op expires. Exposed verbatim in
    /// `GET /op/{op_id}` responses so the UI can render a countdown.
    pub expires_at_unix: u64,
    pub ttl: Duration,
    /// Number of failed `POST /op/{id}/approve` attempts (passkey verify
    /// failed, wrong grant, etc.). Auto-rejects the op at MAX_APPROVE_ATTEMPTS
    /// to prevent brute-force on expensive crypto operations.
    pub fail_count: u32,
    /// Policy decision context captured when the op was created. Used by
    /// approve.rs to write into the rule-approvals cache after a
    /// successful Use op — so the `ask`-with-TTL semantic kicks in on the
    /// next matching request. Daemon-internal: never appears on the wire,
    /// never signed into the grant.
    pub policy_context: Option<PolicyContext>,
    /// Prefix of the agent api-key that TRIGGERED this op (op-agent binding,
    /// team §C1) — the daemon-side enforcement handle. Every agent-facing
    /// consumption surface (proxy op poll, op_grants redeem, ask-cache
    /// write/read) compares the acting key against this. The same value rides
    /// in `o.act.scope.agent` so the human's signature covers it; this copy
    /// exists so enforcement never re-parses the signed op. `None` = op not
    /// created by an agent request (ceremonies) — no agent gate applies.
    pub agent_prefix: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// The decision level when this op was created. `Ask` is the only
    /// value that drives cache writes; we keep the others for audit /
    /// debug. `AskAlways` is explicitly excluded — that's the whole
    /// point of the level.
    pub level: crate::core::policy::AccessLevel,
    /// Matched rule id from `evaluate_with_match`. `None` =
    /// tag / global default fired — which is **not** cached (a grant
    /// needs a rule's path scope to bound it; see `record_ask_approval`).
    pub rule_id: Option<String>,
    /// TTL in seconds the approval should remain cached. Threaded from
    /// the matched rule's `ttl`, the service / tag default's
    /// `ask_ttl`, or `Policy.timeout` as last resort.
    pub ttl_seconds: u64,
    /// Resolved destination host of the request that created this op. The
    /// approval-cache key is host-scoped (an approval for host A must not
    /// authorize host B in the TTL), so the approve handler reads this when it
    /// writes `record_ask_approval`. Stamped by the proxy at op-create.
    pub host: Option<String>,
}

impl ApprovalRecord {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }
}

/// Default TTL for a pending approval — how long the user has to walk over and
/// tap their passkey before it expires. 30 minutes.
pub const DEFAULT_TTL: Duration = Duration::from_secs(1800);

/// Absolute ceiling on a record's lifetime, however generous the op's own
/// window: bounds zombie waiters if a caller mints a huge exp. User-tuned
/// approval windows (aux.policy.timeout) pass through untouched below this
/// — the old cap at DEFAULT_TTL silently clipped them, advertising a grant
/// window the record couldn't honor.
pub const MAX_TTL: Duration = Duration::from_secs(86_400);

/// Suggested agent poll pacing for a pending op, surfaced as `Retry-After` and
/// `approval.interval` (the RFC 8628 / async-request-reply convention) so
/// agents don't invent their own loop cadence.
pub const POLL_INTERVAL_HINT_SECS: u64 = 3;

/// Maximum consecutive failed approve attempts before the op is auto-rejected.
/// Generous enough that a legitimate user never hits it, but blocks brute-force
/// on the computationally-expensive ECDSA verify + AEAD decrypt path.
pub const MAX_APPROVE_ATTEMPTS: u32 = 10;

#[derive(Default)]
pub struct ApprovalStore {
    inner: HashMap<String, ApprovalRecord>,
}

impl ApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new pending approval. Returns the new approval id.
    pub fn create(&mut self, vault_id: String, op: Operation, r: String) -> String {
        self.create_bound(vault_id, op, r, None, None)
    }

    /// Same as [`create`] but stashes the policy-decision context that led
    /// to this op being created.
    pub fn create_with_policy(
        &mut self,
        vault_id: String,
        op: Operation,
        r: String,
        policy_context: Option<PolicyContext>,
    ) -> String {
        self.create_bound(vault_id, op, r, policy_context, None)
    }

    /// Full-fat create: policy context + the triggering agent's key prefix
    /// (op-agent binding). Used by the broker paths; ceremonies (export,
    /// write, lifecycle) have no agent and pass `None`.
    pub fn create_bound(
        &mut self,
        vault_id: String,
        op: Operation,
        r: String,
        policy_context: Option<PolicyContext>,
        agent_prefix: Option<String>,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // The record's lifetime tracks the op's own Valid window (capped by
        // MAX_TTL): a pending record that outlives its op advertises an
        // `expires_at` no passkey tap can meet — a waiter would spin on a
        // zombie. Ops without an exp keep the default ceiling.
        let ttl_secs = op
            .valid
            .exp
            .map(|e| e.saturating_sub(now_unix))
            .filter(|&s| s > 0)
            .map(|s| s.min(MAX_TTL.as_secs()))
            .unwrap_or(DEFAULT_TTL.as_secs());
        let rec = ApprovalRecord {
            id: id.clone(),
            vault_id,
            op,
            r,
            status: ApprovalStatus::Pending,
            cached_value: None,
            created_at: Instant::now(),
            expires_at_unix: now_unix + ttl_secs,
            ttl: Duration::from_secs(ttl_secs),
            policy_context,
            agent_prefix,
            fail_count: 0,
        };
        self.inner.insert(id.clone(), rec);
        id
    }

    pub fn get(&self, id: &str) -> Option<&ApprovalRecord> {
        self.inner.get(id).filter(|r| !r.is_expired())
    }

    pub fn approve(&mut self, id: &str, value: Option<String>) -> Option<&ApprovalRecord> {
        if let Some(rec) = self.inner.get_mut(id) {
            if !matches!(rec.status, ApprovalStatus::Pending) || rec.is_expired() {
                return None;
            }
            rec.status = ApprovalStatus::Approved;
            rec.cached_value = value;
        }
        self.inner.get(id)
    }

    pub fn reject(&mut self, id: &str, reason: impl Into<String>) -> Option<&ApprovalRecord> {
        if let Some(rec) = self.inner.get_mut(id) {
            if !matches!(rec.status, ApprovalStatus::Pending) || rec.is_expired() {
                return None;
            }
            rec.status = ApprovalStatus::Rejected {
                reason: reason.into(),
            };
        }
        self.inner.get(id)
    }

    /// Consume an approved record. Returns the cached value if available.
    pub fn consume(&mut self, id: &str) -> Option<String> {
        let rec = self.inner.get_mut(id)?;
        if rec.is_expired() {
            return None;
        }
        if !matches!(rec.status, ApprovalStatus::Approved) {
            return None;
        }
        let v = rec.cached_value.take();
        rec.status = ApprovalStatus::Consumed;
        v
    }

    /// Increment the failure counter for `id`. If the counter reaches
    /// `MAX_APPROVE_ATTEMPTS`, auto-rejects the op and returns `true` so
    /// the caller can emit an audit event / SSE notification.
    pub fn record_failure(&mut self, id: &str) -> bool {
        if let Some(rec) = self.inner.get_mut(id) {
            rec.fail_count += 1;
            if rec.fail_count >= MAX_APPROVE_ATTEMPTS {
                rec.status = ApprovalStatus::Rejected {
                    reason: "too many failed approve attempts".into(),
                };
                return true;
            }
        }
        false
    }

    /// Drop expired and consumed records.
    pub fn cleanup(&mut self) {
        self.inner
            .retain(|_, r| !r.is_expired() && !matches!(r.status, ApprovalStatus::Consumed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::operation::{Act, ActType, Bind, Valid};

    fn fake_op() -> Operation {
        Operation {
            act: Act {
                kind: ActType::Export,
                target: "env.x".into(),
                scope: serde_json::Value::Null,
            },
            bind: Bind {
                redeemer: "vault1".into(),
                recipient: None,
            },
            valid: Valid::single_use(0, None),
        }
    }

    // Keep test fixture consistent with the new ApprovalRecord shape.
    // (no behaviour change; just satisfies the struct literal in create_approve_consume.)

    #[test]
    fn create_approve_consume() {
        let mut s = ApprovalStore::new();
        let id = s.create("vault1".into(), fake_op(), "fake_r".into());
        assert!(matches!(
            s.get(&id).unwrap().status,
            ApprovalStatus::Pending
        ));
        s.approve(&id, Some("secret".into()));
        assert!(matches!(
            s.get(&id).unwrap().status,
            ApprovalStatus::Approved
        ));
        let v = s.consume(&id);
        assert_eq!(v.as_deref(), Some("secret"));
        assert!(matches!(
            s.get(&id).unwrap().status,
            ApprovalStatus::Consumed
        ));
        // Second consume returns None (already consumed).
        assert!(s.consume(&id).is_none());
    }

    #[test]
    fn reject_blocks_consume() {
        let mut s = ApprovalStore::new();
        let id = s.create("vault1".into(), fake_op(), "fake_r".into());
        s.reject(&id, "user denied");
        assert!(s.consume(&id).is_none());
    }

    #[test]
    fn record_ttl_follows_op_valid_window() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // A bounded op: the record expires with the op, not at the default.
        let mut op = fake_op();
        op.valid = Valid::single_use(now, Some(now + 120));
        let mut s = ApprovalStore::new();
        let id = s.create("vault1".into(), op, "r".into());
        let rec = s.get(&id).unwrap();
        assert!(rec.ttl <= Duration::from_secs(120));
        assert!(rec.ttl >= Duration::from_secs(118)); // clock-tick slack
        assert!(rec.expires_at_unix <= now + 121);

        // No exp (fake_op default) keeps the default ceiling.
        let id2 = s.create("vault1".into(), fake_op(), "r".into());
        assert_eq!(s.get(&id2).unwrap().ttl, DEFAULT_TTL);

        // A user-widened window (aux.policy.timeout > default) passes
        // through — only the MAX_TTL ceiling clips. (Was: silently clipped
        // to DEFAULT_TTL — the grant page then promised a window the record
        // wouldn't honor.)
        let mut wide = fake_op();
        wide.valid = Valid::single_use(now, Some(now + 7200));
        let id3 = s.create("vault1".into(), wide, "r".into());
        let rec3 = s.get(&id3).unwrap();
        assert!(rec3.ttl > Duration::from_secs(7100));
        assert!(rec3.ttl <= Duration::from_secs(7200));
    }
}
