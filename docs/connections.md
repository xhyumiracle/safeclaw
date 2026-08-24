# Connections: how a secret becomes a phantom

A secret in the vault is just a value. A **connection** is what makes it
spendable: the binding of secret(s) to a service's hosts, addressed by a
phantom.

```
secret  HF_TOKEN = hf_xxx…                      inert storage
   +
anchor  huggingface.co                          where it may be spent
   =
connection "hf_token"  →  phantom __sc__hf_token__
```

Three rules keep this unambiguous:

- **A secret belongs to at most one connection.** So a phantom resolves to
  exactly one value, no guessing.
- **Hosts come from one source.** A catalog service declares its hosts; a
  custom connection anchors its own. Either way the agent can't move them.
- **Host is a constraint, never a selector.** The broker validates the
  destination against the anchor; it never picks a credential *because* of
  where traffic is going.

## The catalog

Services ship as declarative definitions (`services/*/service.toml`): hosts,
secret shapes, OAuth wiring, and human-labeled policy rules. GitHub, OpenAI,
Anthropic, Gemini, Gmail, Google Drive, GCP, Supabase, Railway, GitLab, npm,
crates.io, Telegram and more are built in; agents discover what's connected
with `sc connection ls`.
Adding a service is a TOML file, not a plugin: [SERVICES.md](reference/services.md).

## Ways to connect

- **OAuth services**: connect from the console; SafeClaw runs the flow and
  manages token refresh. The agent's phantom stays stable across refreshes.
- **Paste a key in the console**: encrypted in your browser before upload.
- **At the terminal**: `sc set HF_TOKEN --host huggingface.co` prompts for
  the value, takes one passkey approval, and the value never leaves your
  machine.
- **Any other HTTPS API**: a custom connection with your own host anchor.
  The catalog is a convenience, not a boundary.
- **External stores**: keep values in your own secret manager (e.g. GCP
  Secret Manager); SafeClaw fetches at use, and the value still never
  reaches the agent.

## Multiple accounts

Accounts differ by phantom *value*, not env-var name: `__sc__github__` and
`__sc__github_work__` are two connections behind the same `GITHUB_TOKEN`
variable. See [`sc run` and phantoms](sc-run.md).
