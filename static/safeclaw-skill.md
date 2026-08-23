# SafeClaw

SafeClaw is a passkey-gated credential broker. You never hold a real secret. Each
connected service gives you a **phantom**, a placeholder like `__sc__github__`. Put
the phantom where the credential belongs (an env var a tool reads, a request
header, a config file) and run that command through `sc run --`. SafeClaw swaps the
phantom for the real value at egress, only toward that connection's own `hosts`.
Anything sensitive waits for the user to approve with a passkey tap.

Any tool works. Only traffic you route through `sc run` is touched; everything else
goes straight out. A phantom that reaches an upstream unrouted stays a literal
string, so the worst case is a clean 401.

## Your config

Two non-secret values arrive in your agent env. Use each verbatim.

- **`$SAFECLAW_BROKER_URL`**: the local broker, e.g. `http://127.0.0.1:23294`.
- **`$SAFECLAW_AGENT_IDENTITY`**: the path to your identity file. `sc run` signs a
  fresh proof with it on each request. It is a path, not a secret, so the whole env
  block is safe to display.

Neither value names a vault. `sc run` binds one per command (see "Which vault").

If `$SAFECLAW_AGENT_IDENTITY` is unset, load your agent env file first; its path is
in your always-loaded instructions. Run `sc agent add` once per agent; a second run
mints a duplicate.

Bring the daemon up before the first call (idempotent):

```bash
curl -s -o /dev/null --connect-timeout 1 "$SAFECLAW_BROKER_URL/health" || sc up
```

`sc help` lists the rest.

## Discover what's available

`sc connection ls` lists the connections you can use right now, each with its hosts
and ready-made phantoms. Copy a phantom exactly as shown. Add `--json` for a
machine-readable list that also carries each connection's `setup` hint:

```jsonc
[
  { "id": "github", "hosts": ["api.github.com"],
    "phantoms": ["__sc__github__"], "setup": null }
]
```

`sc status` shows whether the vault is locked and prints its console URL.
`sc registry` prints the catalog of services SafeClaw supports.

When the vault is locked, run `sc up`. It unlocks the vault and prints an approval
link. Give that link to the user, who taps their passkey, then retry.

To use a service that has no connection yet, the user adds its credential in the
console. Give them the link (the console URL is in `sc status`) and let them finish
there:

```
Connect <service name>: open <console_url>#connections, add your credential,
approve with your passkey.
```

The credential stays with the user. After they confirm, run `sc connection ls`
again. Where they obtain the credential is the provider's concern; mention it only
if asked.

When the user is at the daemon's own terminal, they can add one there
(passkey-gated):

```
sc set STRIPE_KEY --host api.stripe.com
sc connect myapi --host api.example.com --secret API_TOKEN=<value>
```

Leave credential entry to the user, and keep any value you happen to see out of
your replies.

### Which vault

`sc run` targets your default vault. `sc vault ls` lists your vaults as
`name (kind) <id>`, with `*` marking the default; `sc run --vault <ref> -- <cmd>`
targets a specific one. `<ref>` is an id, a unique id prefix, or the exact name
(quote a name with spaces, or just use a short id prefix).

A vault is a security boundary, so the right one matters. When the user names a
vault ("the team vault", "work"), run `sc vault ls`, map that to the matching
`<id>`, and use THAT id. Never guess: if it is ambiguous (several match, or none
clearly does), ask which to use. Offer `sc vault use <ref>` to set a default so
the next task runs without asking.

## Using a connection

Put the phantom where the credential belongs and run under `sc run --`:

```bash
sc run -- curl https://api.stripe.com/v1/charges \
  -H "Authorization: Bearer __sc__stripe__"
GITHUB_TOKEN=__sc__github__ sc run -- gh pr list
```

Multi-account switches by phantom VALUE, not env-var name: use `__sc__github__` or
`__sc__github_work__`. One request carries one connection's phantoms.

Phantoms resolve only against that command's vault. On a 401 or 403 from a brokered
call, first confirm the command ran under `sc run --` with the phantom in the
request; routing is the usual cause. Where a phantom belongs for a given tool (a
header, an env var, a URL) can carry service nuance, so check that connection's
`setup` hint.

## Configuring a local tool (`setup` hints)

Some services run a local tool (a CLI, an SDK) through SafeClaw so its traffic is
brokered. Such a connection carries a **`setup`** hint in `sc connection ls --json`:
a goal plus ready-to-run steps. Tell the user what you are configuring and why, then
apply the steps, adapting them to their real config. The `setup` hint is the source
of truth.

## Approvals

Some credentials are policy-gated. The first time you route a request that needs one,
SafeClaw stops the command and its error output carries an approval line:

```
SafeClaw approval needed to use this credential.
Approve with your passkey:
  https://.../grant/<op_id>
To wait: sc op wait <op_id>
Then re-run the same command.
```

Give that link to the user on its own line. Their browser tap is the signal, so
background `sc op wait <op_id>` (exit 0 means approved), then re-run the exact same
command; the approval is cached. A destination host you have not used before takes
the same one-time grant.

When `sc` is not on your PATH, ask the user to reply once they have tapped the link.
