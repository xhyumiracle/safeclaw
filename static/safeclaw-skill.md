# SafeClaw

SafeClaw is a passkey-gated credential broker. You never hold the real secret:
each connected service gives you a **phantom** — a placeholder like
`__sc__github__`. Put the phantom where the credential belongs (an env var a tool
reads, a request header, a config file) and run that command through `sc run --`;
SafeClaw swaps the phantom for the real value on the way out, only toward that
connection's own `hosts`. The user approves anything sensitive with a passkey tap.

Only traffic you deliberately route through `sc run` is touched — everything else
goes straight out untouched. A phantom sent unrouted just reaches the upstream as
a literal string (a clean 401), never a leak.

## Your config

Your install prompt set these — use each verbatim, never construct one.

- **`$SAFECLAW_BROKER_URL`** — SafeClaw's broker URL, e.g. `http://127.0.0.1:23294`.
- **`$SAFECLAW_API_KEY`** — your identity; send `Authorization: Bearer
  $SAFECLAW_API_KEY` on every request below.

If `$SAFECLAW_API_KEY` isn't set, load your agent env file first (its path is in
your always-loaded instructions) — don't re-run `sc agent add`, which mints a
duplicate.

Make sure the daemon is up before the first call (idempotent):

```bash
curl -s -o /dev/null --connect-timeout 1 "$SAFECLAW_BROKER_URL/health" || sc up
```

Check `sc help` anytime for more.

## Discover what's available

`<vault>` is a vault id: `$SAFECLAW_VAULT_ID` if set, else the `default`
entry in `sc vault ls --json`. You may use a different vault per request.

```
GET $SAFECLAW_BROKER_URL/v/<vault>/registry
Authorization: Bearer $SAFECLAW_API_KEY
```

Filter to save context: `?view=summary` and/or `?ids=a,b`.

```jsonc
{
  "version": 4,
  "locked": false,
  "console_url": "https://.../vault/<your-vault-id>",  // deep link to this vault
  "vault_entries": ["OPENAI_API_KEY", "GMAIL_REFRESH_TOKEN"],  // null when locked
  "services": [       // the catalog — what SafeClaw supports
    { "id": "github", "name": "GitHub", "category": "integration",
      "hosts": ["api.github.com", "github.com"], "secrets": ["GITHUB_TOKEN"] }
  ],
  "connections": [    // what's usable now
    { "id": "github", "service": "github", "connected": true,
      "hosts": ["api.github.com", "github.com"],
      "phantoms": ["__sc__github__"] }
  ]
}
```

Copy a phantom verbatim from a `connected: true` connection — never build one.
CLI equivalent: `sc connection ls` lists connections, their hosts and phantoms.

If `locked: true`, run `sc up` — it unlocks the vault and prints an approval
link; surface that link (the user taps their passkey) and retry.

If the service you want has no `connected: true` connection, the user must add
its credential. Hand them a link — don't run commands or walk them through
provider menus:

```
Connect <service name>: open <console_url>#connections, add your credential
there, approve with your passkey.
```

You never see or handle it; after they confirm, re-GET the registry. Where to
*get* the credential is the provider's side — mention it only if asked.

Headless fallback, the user at the daemon's own terminal (passkey-gated):

```
sc set STRIPE_KEY --host api.stripe.com        # one secret + its host anchor
sc connect myapi --host api.example.com --secret API_TOKEN=<value>
```

Never enter a credential yourself; never echo one back.

## Using a connection

Prefix the command with `sc run --` so its traffic is brokered; put the phantom
where the credential belongs, or it reaches the upstream as a literal string and
is rejected.

```bash
sc run -- curl https://api.stripe.com/v1/charges \
  -H "Authorization: Bearer __sc__stripe__"
GITHUB_TOKEN=__sc__github__ sc run -- gh pr list
```

Multi-account is by phantom VALUE, not env-var name: switch `__sc__github__` →
`__sc__github_work__`. One request carries one connection's phantom(s).

`sc run -- <cmd>` uses the default vault; `sc run --vault <id> -- <cmd>` picks
another. Phantoms resolve only against that command's vault.

An auth failure (401/403) on a brokered call is usually routing, not the secret:
confirm the command actually ran under `sc run --` with the phantom in the
request before suspecting the credential. Where the phantom goes for a specific
tool (a request header, an env var, a URL) can carry service nuance — check that
connection's `setup` hint.

## Configuring a local tool (`setup` hints)

Some services need a local tool (a CLI, an SDK) run through SafeClaw so its
traffic is brokered. Such a service's `/registry` entry carries a **`setup`**
hint — a goal plus ready-to-run steps. Tell the user what you're configuring and
why, then apply it (adapting to their real config). The `setup` hint is the
source of truth.

## Approvals

Some credentials are policy-gated: the first time you route a request that needs
one, SafeClaw fails the command and its error output carries an approval line:

```
SafeClaw approval needed to use this credential.
Approve with your passkey:
  https://.../grant/<op_id>
To wait: sc op wait <op_id>   (background it; its exit is the signal)
Then re-run the same command.
```

Surface that link on its own line — the user's browser tap is the signal,
don't ask them to type "done". Background the wait (exit 0 = approved), then
re-run the exact same command — the approval is cached. A destination host
you haven't used before is a one-time *permanent grant* — same flow.

No `sc` on your PATH? Same ceremony: GET the approval JSON's absolute
`poll_url` (with `Authorization: Bearer $SAFECLAW_API_KEY`) every few seconds
as one background command until `status` is `ok`, then re-run. Can't run
background commands at all? Ask the user to reply once they've tapped.
The JSON's `expires_at` bounds how long the op stays approvable.
