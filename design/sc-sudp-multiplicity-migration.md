# SC ↔ sudp multiplicity — decision & migration (DONE)

sudp `v0.3.0` generalized `Multiplicity` to an execution budget. This records what
SC adopted (and, more importantly, what it deliberately did NOT) and why.

## Outcome: keep `multiplicity = 1`; reuse stays a SafeClaw cache layer

We do NOT model ask-once reuse as a sudp `unbounded` grant. We bumped the dep and
fixed the wire, nothing more.

### The decisive fact

On reuse, the resident proxy serves **cached credential bytes**: it holds **no
grant** and does **not open the vault** (`src/proxy/handler.rs:599-657` — "the
proxy has no grant to open the vault"; ask/ask-always/allow all read from the
session cache). sudp is touched exactly **once**, at the approval ceremony (open
`K`, extract `s_o`, cache it). Every subsequent in-window use is a plaintext cache
read with **zero sudp executions and zero vault opens**.

sudp's `multiplicity` is defined as *executions under one redeemed grant*. SC
performs exactly one. So `multiplicity = 1` is the **truthful** value; declaring
`unbounded` would overclaim what the sudp op authorizes. The ask-once reuse is a
SafeClaw residency feature that sits **above** sudp and is orthogonal to
multiplicity — it is not a sudp budget and should not masquerade as one.

This is consistent with the standing no-hold-`W_c` rule: the very reason SC cannot
re-execute a grant (that would mean holding `W_c` = a standing capability to
re-open `K` without fresh UV) is exactly why reuse is not a sudp execution.

### Rejected: Option B (declare `unbounded` + `authorize_use`)

Declaring `unbounded` would match the paper's "standing grant reused within a
window" *intent*, but SC's reuse window (`grant_ttl`) and approval hold
(`hold_secs`) are deliberately separate clocks (`src/proxy/handler.rs:918-924`),
and neither is the signed `op.valid.exp` cleanly. It would force a residency-side
`Valid` for `authorize_use` distinct from the signed one, and count cache reads as
"executions." More moving parts, and it stretches sudp's execution model for no
security or honesty gain. Not done.

## What changed (0.3.0 wire cutover)

sudp 0.3.0's `Multiplicity` wire is a positive integer (`1`) or `"unbounded"`; the
deserializer **rejects the old string `"one"`**. So:

- `Cargo.toml:37` — `sudp` `0.2.1` → `0.3.0`.
- 12 hand-written `"multiplicity": "one"` literals → `"multiplicity": 1`
  (`src/cli/{unlock,vault,connect,secret,service_def}.rs`). All are true single-use
  ceremonies, so `1` is correct.
- Struct-built ops (`Valid::single_use(...)`) auto-serialize to `1` under 0.3.0 —
  no source change needed.

Verified: `cargo check` clean; 405 lib tests pass.

### Frontend (type-hygiene only)

β is computed frontend-side and `multiplicity` feeds the signed bytes, BUT the
authorizer canonicalizer (`@sudp-protocol/authorizer`) is a field-agnostic JCS
encoder that already serializes integers, and nothing in the FE reads/branches on
`multiplicity`. So there is no runtime change and no authorizer bump — only two
type declarations widened from `'one' | 'unbounded'` to `number | 'unbounded'`:
`lib/vault-api.ts:245`, `app/grant/[id]/page.tsx:146`.
