# Pending-accept invitations (owner pre-seals, invitee accepts)

Status: LOCKED 2026-08-17. SSOT for the team-invite flow. Supersedes the
`#68 invite=seal` behaviour on the REGISTERED path (owner-invites-immediately-
seats-a-live-member). Read alongside `unified-identity-schema.md` (triple shape)
and `team-edition.md` §0/§0.7 (current-truth overview). The cross-device
add-passkey deposit/approve flow (`pending_passkeys`) is UNRELATED and untouched.

## Why

`#68` made an invited registered user a LIVE member the instant the owner hit
invite: no consent, and undoing it (decline/expire) needed a re-key because the
sealed K was already in the live roster. We want a real accept step:

- The invitee CONSENTS before being bound (nothing accessible until they accept).
- Declining/expiring is a cheap DELETE (never entered the live roster → no re-key).
- The owner still touches it ONCE (seals at invite; never comes back to finish).
- Billing is UNCHANGED in timing — the seat is the owner's provisioning act, so it
  is counted at INVITE (see Billing).

## The cache: `invitations.sealed_grant`

Adding `members[us_id]` to the live triple (`vault_membership`) requires an
OWNER-SIGNED delegation event in `proof.delegation_log` (the fold verifies it
chains to an owner). A non-owner cannot write themselves in. So the owner
pre-signs the whole grant at invite time and we PARK it on the invitation row —
NOT in the daemon-synced triple (else the invitee's daemon pulls K before accept,
and decline needs a re-key).

`invitations.sealed_grant jsonb` =
```
{
  us_id:        <invitee UIK id, from /directory at invite>,
  role:         'member' | 'owner',
  member_entry: { role, k_encapped, k_ct },   // exactly the triple's members[us_id]
  delegation_log: [ <owner-signed `set` event granting role to us_id> ],
  generation:   <K generation the member_entry was sealed at>  // staleness check
}
```
The fold loads the invitee's `sig_pub` from `identities` (registered path), so
the grant carries no pubkeys.

### Grant properties (all enforced)
- **Expires**: rides `invitations.expires_at` (7d). `getInvitationByToken` flips
  `sent→expired` past it; accept refuses a non-`sent` row.
- **One-time**: accept CASes `status sent→accepted` then `→consumed`; a replay
  hits a non-`sent` row and is refused. Promotion is idempotent on the triple.
- **Bound to user**: accept verifies the accepting account's UIK `us_id` ==
  `sealed_grant.us_id` (strictly stronger than the email bind; and K is sealed to
  that identity's `enc_pub`, so no other account can even unseal it).
- **Bound to role**: the role lives in the owner-signed delegation event
  (cryptographically bound), not a mutable column.

## Flow

1. **Invite** (owner, `POST /v/{vid}/invitations`): resolve invitee via
   `/directory` → seal K to their `enc_pub`, build the `member_entry` + an
   owner-signed `set` delegation event → store as `sealed_grant`, `status=sent`.
   Reconcile billing (seat now counted). One owner touchpoint; done.
2. **Accept** (invitee, `POST /api/invitations/{token}/accept`): verify
   email+us_id bind → MERGE the grant into the CURRENT triple
   (`members[us_id]=member_entry`; `proof.delegation_log = dedup(cur ∪ grant)`)
   → re-fold to verify the merged triple still seats an owner AND the new grant
   chains to an owner → CAS-write `vault_membership` seq+1 → seat the
   `memberships` row → `status=consumed`. Billing reconcile (no-op; already
   counted).
3. **Decline / revoke / expire**: DELETE/mark the invitation. The grant dies with
   it. No re-key (never in the live roster). Billing reconcile (seat released).

## Staleness = clear pending on re-key (simple, no refresh)

A re-key rotates K→K', so every parked `member_entry` now seals the OLD key.
Rather than refresh the parked grants, we CLEAR them (2026-08-17 decision — the
user rejected the re-seal/re-sign refresh as over-built):

- **Invariant (load-bearing, server-side):** `handleMembershipPut` clears ALL
  pending invitations for the vault whenever the triple's `proof.generation`
  bumps (= a re-key). This holds no matter which path drove the re-key, so no
  stale grant ever survives to be accepted on a rotated key. The freed pending
  seats are reconciled.
- **UI confirm:** the only console op that re-keys is offboarding a member
  (`changeMemberRole` is a pure delegation-log append — no K rotation, so it does
  NOT touch pending grants). The offboard confirm warns "N pending invites will be
  cancelled; you'll need to re-invite" before proceeding.
- **Belt (accept):** accept still checks `grant.generation === current` and
  re-folds the merged triple, so even if a grant somehow outlived a re-key it
  fails closed with `grant_stale` rather than seating a member on a rotated key.
  (In practice the invariant already flipped it to `revoked`, so accept returns
  `invitation_revoked`.)

Result: after any re-key the invitee simply gets re-invited. No re-seal, no
re-sign, no `role_epoch`/succession special-casing.

## Billing (Q2: bill at invite)

Adding a seat is the owner's proactive provisioning act, so it is counted at
INVITE, not accept:

- `billableSeatsForAccount` = DISTINCT people over (live `memberships` ∪ pending
  `invitations` with status ∈ {sent, accepted}), deduped by email.
- Reconcile on invite-create and on revoke/decline/expire (宽进严出: increase
  charges immediately; decrease lapses at renewal via `syncSeats` proration-none).
- Accept does NOT change the count (already counted) — its reconcile is a no-op.

## Surfaces

- Owner Members tab: pending invitations already listed (`handleInvitationList`).
  Offboarding warns that pending invites will be cancelled (they're cleared on the
  re-key) and to re-invite after.
- Invitee inbox: `GET /api/invitations/mine` lists invitations addressed to the
  logged-in account's email with status=sent; a console card offers Accept / Decline.

## Not touched
- `pending_passkeys` (cross-device add-passkey deposit/approve) — different table,
  different orientation (joiner stages pubkey, approver seals later). Its stale
  name (predates the passkeys→credentials rename; `credentials` is the base table,
  `passkeys` is a compat VIEW) is a separate cleanup, out of scope here.
- Core/daemon: the triple it syncs is a normal triple; a member simply appears in
  it at accept. No Rust change.
