# SafeClaw Docs

A systematic tour of SafeClaw, one module per page. Concepts explain how the
product thinks; guides get a task done; security answers the questions that
decide trust. `reference/` holds the lookup layer; contributor design docs
live outside this tree in [`design/`](https://github.com/SafeClaw-OSS/safeclaw/tree/main/design).
Pages are deliberately short and will deepen over time.

New here? Read [Overview](overview.md), then do the
[Quickstart](quickstart.md).

## Concepts

| Page | The module |
|---|---|
| [Overview](overview.md) | The whole model on one page: phantoms, the broker, passkey approvals |
| [Vault](vault.md) | Where credentials live: sealed under your passkey, synced blind |
| [Connections](connections.md) | The catalog, host anchors, and how a secret becomes a phantom |
| [Broker](broker.md) | `sc run`: one local egress point that swaps phantoms for values |
| [Approvals & policy](approvals.md) | Who decides what runs: levels, rules, single-use grants |
| [Agents](agents.md) | Agent identities: attribution without possession |

## Guides

| Page | The task |
|---|---|
| [Quickstart](quickstart.md) | Zero to first brokered call in five minutes |
| [`sc run` and phantoms](sc-run.md) | The patterns, and the `sc get` anti-pattern |
| [For your agent](for-your-agent.md) | Handing SafeClaw to an agent: skill file, paste-ready prompt |

## Security

| Page | The question |
|---|---|
| [Design principles](design-principles.md) | The rules the whole system is built on |
| [Security model](security-model.md) | Where keys live, what the cloud sees, what compromise costs |

## Reference

For users and service authors, in [`reference/`](reference/):
[services.md](reference/services.md) (writing a `service.toml`),
[policy.md](reference/policy.md) (per-action decisions),
[diagnostics.md](reference/diagnostics.md) (every error code, with fixes),
[passkey-support.md](reference/passkey-support.md) (which devices can encrypt a vault),
[platform-support.md](reference/platform-support.md) (which OSes run the `sc` binary),
[consent-templates.md](reference/consent-templates.md) (approval-copy grammar).

## Design docs

For contributors reading the source, outside this tree in
[`design/`](https://github.com/SafeClaw-OSS/safeclaw/tree/main/design):
[protocol.md](https://github.com/SafeClaw-OSS/safeclaw/blob/main/design/protocol.md) (SUDP cryptographic profile),
[credential-broker.md](https://github.com/SafeClaw-OSS/safeclaw/blob/main/design/credential-broker.md) (the broker architecture),
[connection-schema.md](https://github.com/SafeClaw-OSS/safeclaw/blob/main/design/connection-schema.md) (vault data shapes),
[sync.md](https://github.com/SafeClaw-OSS/safeclaw/blob/main/design/sync.md) / [sse-sync.md](https://github.com/SafeClaw-OSS/safeclaw/blob/main/design/sse-sync.md) (cloud sync),
[request-scope.md](https://github.com/SafeClaw-OSS/safeclaw/blob/main/design/request-scope.md) (approval scope binding),
[stores-and-items.md](https://github.com/SafeClaw-OSS/safeclaw/blob/main/design/stores-and-items.md) (stores and vault content model).
