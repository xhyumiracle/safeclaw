# Cross-device enroll integrity + daemon-pubkey pinning

Two security debts, both **confirmed present** and both **known/deferred by prior
design notes** (not regressions). Surfaced while investigating a `PrfUnavailable`
report (2026-07-22); the fix for that was copy-only and unrelated. This doc is a
**design proposal for review**, not an implemented change. Nothing here touches
the security model until approved.

Ground truth for the invariants is the retired `DE_DAEMON.md` (archived at
`safeclaw-pro-backend/docs/core-archive/DE_DAEMON.md`), [credential-broker.md](credential-broker.md),
and [protocol.md](protocol.md). The stale `safeclaw-protocol` V1 handoff
(peer_keks / 23294 dual-port) does **not** describe the current de-daemon world;
ignore it.

## Invariants at stake (restated so this doc stands alone)

- **I1 — cloud is blind; only K-holders can write a vault.** The cloud stores
  ciphertext it can neither read nor write; "who can change a vault" = exactly the
  devices holding `K`. A compromised cloud cannot inject content into a vault.
  (DE_DAEMON §1.)
- **I2 — a new device is never wrapped in without human approval.** An existing
  unlocked device must never auto-wrap a cross-device deposit without the user
  OK-ing the new device, else a silent takeover. (DE_DAEMON §5; the gate lives in
  `src/server/handlers/approve.rs` for the daemon path, and client-side in the
  console's `approvePendingPasskeyInstall`.)
- **I3 — a compromised agent cannot escalate.** The agent never holds a raw
  secret and cannot approve its own requests. (credential-broker.md;
  [broker principles P1–P5].)
- **I4 — the grant's `W_c` is confidential end-to-end.** It is HPKE-sealed so a
  cloud relay carrying the grant never sees it. (protocol.md; `src/protocol/grant.rs`,
  `src/crypto/envelope.rs`.)

I2 and I3 are the ones the debts below bear on.

---

## Debt A — cross-device enroll/approve path has no server-side integrity

### What is true today (verified)

The console cross-device add is: **new device deposits** a pending passkey
(`POST /v/{vid}/pending-passkeys`, HPKE-sealing its `W_c` to an existing device's
X25519 pubkey), then an **existing unlocked device approves** (unwraps `K`,
re-wraps under the deposited `W_c`, writes a new keyset row via
`PUT /v/{vid}/keys/{cid}`, deletes the pending row).

1. **`self_assertion` is stored and never verified.** The depositor signs the
   payload with its passkey, but the backend writes it to the row and ignores it
   (`safeclaw-pro-backend/src/vault-routes.mjs:2363`, `self_assertion: body.self_assertion ?? null`;
   it is not even in the required-field list). The console comment marks this a
   "v2 hardening" deferral.
2. **The endpoints authorize on account-ownership only, any api-key tier.**
   `resolveAuth` + `isOwnedVaultId` accept a browser session **or any** `sc_`
   api-key tier — demo/agent/device — that owns the vault
   (`vault-routes.mjs:2063-2067`, `:2343-2346`, `:2376-2378`). There is **no**
   cryptographic binding check on the body: no verification that `new_credential_id`
   / `x` / `y` correspond to a passkey the account actually registered.
3. **The approve action leaves no audit record.** It is a bare `PUT keys` +
   `DELETE pending`; no `audit_events` write, no DB trigger, no op-relay row. And
   the browser **structurally cannot** write `audit_events` (ingest is device-key
   gated, `vault-routes.mjs:2422`). The shipped "ceremony audit" only covers
   daemon-sourced enroll/write ceremonies, not this browser-driven path.

### Threat

An attacker with **account-level access** — a stolen web session, **or a leaked
agent `sc_` key** (exactly the credential I3 assumes may be exposed) — can deposit
a pending passkey with attacker-controlled `new_credential_id` / `x` / `y` / `enc`
/ `ct` and an attacker-chosen `device_name` (e.g. "iPhone"). If the user then
approves it on their unlocked device, the console unwraps `K` and re-wraps it
under the **attacker's** `W_c` → the attacker's fabricated credential now unlocks
the vault. Full compromise, **with no audit trail**.

Severity is bounded by I2: the human approval gate still holds — this is a
**social-engineering-gated** takeover, not silent. But (a) a compromised agent
key being able to *stage* it undercuts I3, and (b) the absence of any audit record
means even a caught attempt is invisible. Note I1 is **not** broken: injecting a
lone keyset row without a valid `wrapped_key` (attacker has no `K`) yields only a
garbage row that fails `aeadOpen` on unlock — a nuisance, not access. The real
exposure is strictly the deposit→approve confused-deputy.

### Why this is not a one-line fix

The tempting fix — "restrict these endpoints to browser sessions only" — is
**wrong and would break sync**: the daemon legitimately `PUT`s `/v/{vid}/keys/{cid}`
with its **device key** during per-item sync (`safeclaw/src/sync.rs:2502-2520`,
`.bearer_auth(device_key)`). So tier alone cannot be the gate. The integrity has
to come from a **cryptographic binding on the body**, not from who is calling.

### Options

- **A1 — verify `self_assertion` at deposit (server-side).** Backend verifies the
  stored assertion signs the canonical deposit payload under a public key the
  account has registered for `new_credential_id`. Closes "deposit a credential you
  don't control." **Gap:** an attacker fabricating *their own* credential signs
  with their own key, so A1 alone does not stop the confused-deputy — it only
  stops forging deposits for *someone else's* credential id. Necessary, not
  sufficient.
- **A2 — bind `new_credential_id`/`x`/`y` to the account's registered `passkeys`
  table at deposit.** Reject deposits whose credential is not already an
  account-registered passkey (registration itself is attestation-gated). This is
  the load-bearing one: it forces a new device to first register a passkey through
  the attested `POST /api/auth/passkeys` flow before it can be deposited, so an
  attacker cannot inject an arbitrary fabricated recipient. Combined with A1 this
  closes the confused-deputy at the server.
- **A3 — make the approve UI show attested provenance, not attacker copy.** The
  approve screen currently trusts `device_name` (attacker-controlled). Show
  registration time / a fingerprint the user can compare, so a smuggled "iPhone"
  is not indistinguishable from a real one. Defense-in-depth on I2's human gate.
- **A4 — audit the approve action.** Two sub-options, pick one:
  - **A4a** open a **session-authored** audit path (a narrow `POST /v/{vid}/audit`
    variant accepting a browser session for a fixed allow-list of `act_kind` =
    `enroll-approve` / `enroll-deposit`), or
  - **A4b** route the enrol-approve through the **daemon** so the existing
    device-key ingest emits the ceremony row. A4b keeps one audit author (device
    key) but drags the daemon into a today-daemon-free flow — heavier, and it
    breaks the "any unlocked device approves" property for browser-only users.
    **Recommend A4a.**

### Recommendation for Debt A

**A2 + A1 + A4a**, with A3 as a fast-follow. A2 is the structural fix (bind to a
registered, attested credential); A1 hardens it against id-spoofing; A4a restores
a trail. All three are backend-only (no core, no protocol wire change — the
deposit body already carries `self_assertion`). Est. medium; needs a dedicated e2e
for cross-device add across the tightened path.

---

## Debt B — daemon HPKE pubkey is unpinned (DE_DAEMON §6.2)

### What is true today (verified)

Half of the original §6.2/§8 TODO is **already fixed**: the grant's `W_c` is no
longer plaintext-over-TLS — it is HPKE-sealed (`wk_enc`/`wk_ct`) to the daemon's
`sc_pk`, `info`-bound to the `op_id` (commit `67dd090`; `src/protocol/grant.rs:28-43`,
`src/crypto/envelope.rs`, opened in `src/server/handlers/approve.rs:308-339`). So
a **passive** relay never sees `W_c` — I4 holds against eavesdropping.

The **unfixed** half: the `daemon_pubkey` the browser seals to is published
**fresh per op** via the op-relay register payload and delivered to the browser
**by the cloud** (`src/relay/client.rs:182-196`). There is **no pinning anywhere**
— no TOFU store, no account-binding at pair/login, no key-change detection (greps
for `pinned_pubkey`/`account.?bind`/`register_device` are empty; `pk_bytes()` call
sites only emit, never compare). The code owns this: `src/relay/mod.rs:11-14` —
"daemon-pubkey-pinned auth is a later tier."

### Threat

An **active / compromised cloud** substitutes its own pubkey in what it hands the
browser. The browser (which trusts whatever key it is given, `grant.rs:36-38`)
HPKE-seals `W_c` to the attacker's key → attacker opens the seal → recovers `W_c`
→ with the sealed blob, recovers `K`. This is a full confidentiality break of I1's
premise against an **active** cloud adversary. It directly undercuts the HPKE fix
(a seal is only as strong as the key it targets), which is exactly the
"intersects grant.rs:29" note in §6.2.

This is the **more severe** of the two debts (no human gate, breaks confidentiality
outright), but also the larger change and an explicitly accepted "later tier"
deferral.

### Options

- **B1 — TOFU pin in the browser.** On first sight of a vault's `daemon_pubkey`,
  the console pins it (fingerprint in account-scoped storage); a later change
  raises a hard interstitial. Cheap, no core change, but first-contact is
  trust-on-first-use and pinned state is per-browser.
- **B2 — account-bind at pair/login (recommend).** The daemon registers `sc_pk`
  **account-bound at `sc login`/pair time**, over the device-key-authenticated
  channel, into a server record the browser reads out-of-band from the op-relay
  path. The per-op register then must match the bound key or the backend rejects
  it. Moves the pin to a trusted moment (pairing) instead of first-op. Needs a new
  registration step in `src/cli/login.rs` / `src/sync.rs` (today `sc_pk` never
  touches those) + a backend record + browser verification. This is a protocol
  change.
- **B3 — OOB fingerprint verify.** `GET /pubkey` already returns `sc_pk_fingerprint`
  for OOB comparison (`src/server/handlers/metadata.rs:143-159`); expose it in the
  console + CLI so a user can manually verify. Weakest (manual), but a fast
  interim mitigation and composes with B1.

### Recommendation for Debt B

**B2 as the real fix**, with **B3 shipped first** as a cheap interim (manual
verify) and **B1** as the zero-core stopgap if B2 is not scheduled soon. B2 is a
protocol/core change and should be its own slice with its own review — do **not**
fold it into Debt A.

---

## Sequencing & non-goals

1. **Debt A (A2+A1+A4a)** first — backend-only, closes the in-threat-model
   (compromised agent key) staging path, restores audit.
2. **Debt B3** (OOB fingerprint) as a cheap interim any time.
3. **Debt B2** (account-bound pin) as a separate core slice.

**Non-goals / explicitly out:** the NGC/TPM PRF-less fallback (evaluated and
shelved, see memory `prf-fallback-decision`); re-adding the daemon to the browser
enroll path except as the audited A4b alternative we rejected; any change to the
`PrfUnavailable` copy work (already shipped separately).
