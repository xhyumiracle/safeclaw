# Account principal ledger + universal revocation-drop — BUILD LOG

Execution log for design **§15** (SSOT: `design/agent-device-identity-mtls.md` §15).
Branch: `feat/account-principal-ledger` (core). Backend/frontend branches added per phase.

## Goal (one line)
Owner-signed ADMIT + REVOKE of account principals (device/agent), enforced locally
while online: a revoked device/agent loses the ability to use secrets. Universal
(personal + team), not a team privilege.

## Invariants (non-negotiable)
- **Additive / dual-path / flag-gated.** Current §14 session-admission + the shipping
  launch flow never brick during the build. Enforcement flips are last + gated.
- **Destructive only on VERIFIED owner signature.** "Lock + wipe local" fires ONLY on a
  daemon-verified owner-signed removal, NEVER on a bare 401 (that class caused the
  transient-403 mass-outage incident; 401 keeps PARKING).
- **Delivery-before-hard-kill.** Publish the signed `revoke` (target still syncs it) →
  target verifies + self-drops → THEN hard-kill its device-key.
- Build on the feature branch; merge additive phases to `dev` + release rc only when green.

## Two layers (both owner-signed)
| Layer | Channel | Signer/anchor | Revoke → daemon |
|---|---|---|---|
| Account admission (device/agent) | NEW account principal ledger | owner **UIK**; anchor = the account's own UIK (self-certified: `derive_id(User,uik_pub)==account_id`) | device `−` → LOCK+WIPE all vaults + logout; agent `−` → global reject |
| Per-vault access | authorized-agents / passkey-membership (existing) | **K** per-vault | remove → drop that ONE vault |

## Phases
- **P1 core crypto foundation** — DONE (this branch). `identity.rs`: `DS_PRINCIPAL_EVENT`
  = `safeclaw/v1/principal-event`; `principal_event_input(account_id, op, principal_id,
  seq, owner_id)` (account-scoped analog of `delegation_event_input`); field-binding +
  lp-ambiguity + roundtrip + pinned golden-vector tests. 33 identity tests green.
  Anchor needs NO new primitive: `account_id == derive_id(User, owner_uik_pub)` already
  self-certifies the owner UIK (same trick as per-vault genesis anchor).
- **P2 backend** — account principal ledger: append-only owner-signed events
  (`admit`/`revoke`, monotone `seq`). New table (e.g. `account_principals` /
  `principal_ledger`) + write endpoint (verify UIK sig vs account anchor = write-gate) +
  serve endpoint (daemon pulls). Dual-path with the current session-admission + api_keys
  roster. Node mirror of `principal_event_input` (parity vs the pinned hex).
- **P3 frontend** — admission + revoke become UIK-signed ceremonies. /pair approval signs
  `admit` (passkey tap); revoke UI signs `revoke`. Bootstrap: pin/learn the account owner
  UIK at first pair. Pin the same golden hex as P1.
- **P4 core/daemon** — sync the ledger, verify vs account anchor, fold the current
  principal set. On self (device) `revoke` verified → LOCK + WIPE all local vaults +
  logout. Behind a flag until verified. Delivery-before-hard-kill.
- **P5 per-vault drop hardening** — sign the vault-delete tombstone (currently unsigned
  server cleartext); upgrade daemon membership-loss from "stop serving" to "actively
  LOCK+WIPE"; extend to personal. ("team removes member" ≡ "user deletes own vault" =
  one verified vault-owner-signed "vault access gone" → daemon drops that vault.)
- **P6 cutover** — flip enforcement (require signed admission; wipe-on-revoke on) + retire
  session-admission + adversarial review + e2e. Gated/census'd.

## Already shipped (rc.9, the small clear pieces, on dev)
`sc logout` stops the daemon on macOS too + wipes local `<state_dir>/vaults/` (commit 6efb795).

## Resume pointer
Next: **P2 backend** — add the account principal ledger table + write/serve endpoints +
the Node `principalEventInput` mirror (parity with `identity.rs` pinned hex
`0000001b…75735f61636374`). Keep dual-path with §14 session-admission.
