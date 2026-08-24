# Notifications & the account inbox

Status: DESIGN (2026-08-18). Centers on a **coherent, uniform API route scheme** for everything
that is "addressed to me" across vaults, plus a notifications inbox. Supersedes the ad-hoc
`/api/invitations/*` shape (see pending-accept-invitations.md for the invite mechanism itself).

## Problem

Everything that "needs me" is scattered across inconsistent surfaces AND inconsistent routes:

- **Approvals** (an agent is waiting): `op_relay` pipeline — `/op/{id}`, `/op/{id}/approve|reject`,
  history `GET /v/{vid}/approvals`; a real-time doorbell.
- **Vault invites**: owner side `/v/{vid}/invitations` (vault-scoped, clear); invitee side
  `/api/invitations/{mine, <token>, <id>/accept, <id>/decline}` — a NEW `/api/` namespace opened
  OUTSIDE `/v/`, with three smells: (1) generic name (reads like an account/org invite, not a
  vault invite), (2) token and id share the same path slot (`/{token}` vs `/{id}/accept`, and
  `mine` collides with the token regex — only "works" by check ordering), (3) it 404'd in prod
  because relay's hand-maintained delegate-prefix list didn't include `/api/invitations/`.
- **Future** (daemon-update nudge, cross-device passkey deposits, trial/billing, security digests):
  no home at all.

There is no notifications inbox and no coherent account-level "what needs me" axis.

## Model: two interaction classes, ONE surface

- **Synchronous gates** (approvals): live, blocking, expire in minutes, an agent is stalled, need a
  passkey gesture. They KEEP their own real-time pipeline (op_relay + SSE + `/grant`). They are NOT
  dissolved into a generic notifications table: a time-critical gate must never be buried among
  async messages (missed approval → stalled agent).
- **Async messages** (notifications): durable, act-whenever — vault invite, "invite accepted",
  daemon-update, trial ending, security digest. These get a `notifications` inbox.
- **Unify the SURFACE, not the mechanism.** The top-right shows both: approvals as the loud
  real-time doorbell, notifications as the quiet inbox (one bell, two sections, or two adjacent
  bells). This is the GitHub / Linear / Slack pattern (a notifications inbox distinct from
  high-stakes synchronous gates, co-located in the top bar).

## Coherent API route scheme (the point)

Two axes, and every route picks exactly one:

- `/v/{vid}/…`  = act ON a specific vault (owner/member managing that vault).
- `/api/me/…` = act on MY account, spanning vaults (my inbox, my plan, my things).

The rule that was violated: anything "addressed to me across vaults" belongs under
`/api/me/…`, never a fresh top-level `/api/<noun>/…`.

**Why `me`, not `my` or `account`** (researched 2026-08-18, primary API docs): the modern
convention for the current authenticated principal's resources is `/me/…` — Microsoft Graph
(`GET /me`, `/me/messages`), Spotify (`GET /me`, `/me/tracks`), Google (`users/me`), X
(`/2/users/me`), Atlassian (`/myself`). GitHub's variant is `/user` (singular). NO major API uses
`/my/`. `account/` is reserved for the account ENTITY (billing/settings), not the personal inbox.
Since a SafeClaw account is 1:1 with a person, `/api/me/*` is the single current-user namespace and
the existing `/api/account/*` routes (billing/daemon-status/trial) migrate onto it.

### Account-level "what needs me" — all under `/api/me/*`, symmetric

| Resource | Route | Notes |
|---|---|---|
| Notifications inbox | `GET /api/me/notifications?unread=1&cursor=…` | paged; async messages |
| Mark read | `POST /api/me/notifications/read` `{ ids?, all? }` | bulk |
| Pending approvals (all vaults) | `GET /api/me/approvals` | DERIVED from op_relay; read-only count+list; each links to `/op/{id}` / `/grant` |
| My vault invites (inbox) | `GET /api/me/vault-invites` | pending invites to JOIN a shared vault, addressed to my email |
| Open an emailed vault invite | `GET /api/me/vault-invites/by-token/{token}` | token EXPLICIT — no id/mine collision |
| Accept | `POST /api/me/vault-invites/{id}/accept` | |
| Decline | `POST /api/me/vault-invites/{id}/decline` | |

The bell aggregates the three `/api/me/{notifications,approvals,vault-invites}` reads.
approvals & vault-invites are distinct RESOURCES (different actions); notifications is the generic
message stream. Same mechanism-separation, uniform routes.

### Naming: self-explaining by what you're invited TO

`invitations` alone is ambiguous — a mature product carries several kinds: account/referral
invites (invite a friend to SIGN UP), shared-vault member invites, org/workspace invites. So name
the invitee-side resource by WHAT the invite is TO, and the path self-explains + future kinds never
collide:

- shared-vault member invite (now): `/api/me/vault-invites/*`
- account signup / referral (future): a DISTINCT noun, e.g. `/api/me/referrals` — never
  overloaded onto `vault-invites`.

Under `/v/{vid}/…` the vault context already disambiguates, so the owner side stays clear as
`/v/{vid}/invitations` (= invitations to THIS vault); align it to `/v/{vid}/invites` only if we
want noun-for-noun symmetry with `vault-invites` — cosmetic, not required.

### Vault-level (owner managing their vault) — under `/v/{vid}/…`, unchanged

| `POST /v/{vid}/invitations` | create an invite |
| `GET  /v/{vid}/invitations` | list this vault's invites |
| `DELETE /v/{vid}/invitations/{id}` | revoke |
| `GET  /v/{vid}/approvals` | this vault's approval history (existing) |

### Retire the ad-hoc `/api/invitations/*`

Move `/api/invitations/{mine, <token>, <id>/accept, <id>/decline}` → `/api/me/vault-invites/*`
per the table (`mine` → the bare `GET /api/me/vault-invites`; token → `…/by-token/{token}`).
Dev-only, no external consumers → clean rename, no compat shim.

### Structural: kill the relay-prefix trap

relay delegates only a hand-maintained prefix list to `tryHandleVaultRoute`; a new `/api/`
subpath missing from that list 404s (exactly the invite bug — the same class the inline `blob`
note already warns about). Fix: relay delegates ALL otherwise-unmatched `/api/*` to
`tryHandleVaultRoute` as a FALLBACK — after relay's own inline routes, before the final 404.
`tryHandleVaultRoute` already returns false for unknown subpaths, so the fallthrough is safe, and
vault-routes' dispatch becomes the single source of truth for the `/api` subpaths it owns:
adding a route is ONE edit, never two.

## Data model

`notifications (account_id, id, type, payload jsonb, created_at, read_at, action_url?)`.
Types: `vault_invite`, `invite_accepted`, `daemon_update`, `trial_ending`, `security_digest`, …
A `vault_invite` row's payload references the invitation id — the accept/decline still act on the
INVITATION resource (the notification is only a pointer). Invitations and op_relay keep their own
tables; the inbox READS/derives from them for `/api/me/{invitations,approvals}`, while
`notifications` holds only the generic async messages + their read/unread state.

## UI

- Top-right: the existing approvals doorbell (real-time, loud) + a notifications bell (unread
  count). Or a single bell with two sections: "Needs your approval" (`/api/me/approvals`,
  real-time) and "Inbox" (`/api/me/notifications`).
- A vault invite gets a distinct, prominent accept CARD (who invited / which vault / which role /
  accept · decline) — the current `pending-invites` + `/invite/[token]` are the seed. Never a
  one-line bell entry only.

## Phasing

1. **Routes coherence (small, do first):** (a) rename invite routes → `/api/me/vault-invites/*`
   (+ `by-token/{token}`); (b) migrate the existing `/api/account/*` (billing / daemon-status /
   trial) → `/api/me/*` so there is ONE current-user namespace; (c) add relay's `/api/*` fallback
   delegation. All FE+BE, dev-only, no external consumers. Retires the 404 trap + the ad-hoc/split
   namespaces, no new features.
2. **Inbox v1:** `notifications` table + `GET/POST /api/me/notifications` + the bell/inbox
   with `vault_invite` as the first type; emit `invite_accepted` on accept.
3. **Account-wide approvals + more types:** `GET /api/me/approvals` (cross-vault pending) so
   the doorbell reads one account-level source; add `daemon_update`, `trial_ending`, etc.

## Non-goals

- NOT merging approvals into the notifications table — they stay a real-time gate.
- NOT a full activity feed / read receipts everywhere. Scope is "what needs me / what happened to
  me," nothing more.
