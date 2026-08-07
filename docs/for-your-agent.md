# For your agent

Agents learn SafeClaw from one file:
[`safeclaw-skill.md`](https://github.com/SafeClaw-OSS/safeclaw/blob/main/static/safeclaw-skill.md). It is the single
source of truth for agent behavior: discovery, phantom placement, `sc run`,
approvals. This page is only about handing it over.

## The easy way

The console's "Connect a new agent" install prompt already pairs the
machine, mints the agent's env, and delivers the skill. If you went through
[Quickstart](quickstart.md) step 3, you are done; this page is for doing it by
hand.

## Paste-ready prompt

Machine already paired, agent env already minted (`sc agent add` ran)? Send
your agent this:

```text
Fetch https://raw.githubusercontent.com/SafeClaw-OSS/safeclaw/main/static/safeclaw-skill.md
and save it where you keep always-loaded skills. Follow it whenever a task
needs an external credential: use the phantom placeholders it describes and
route those commands through `sc run --`. Never ask me to paste a key and
never try to read one; if a service isn't connected yet, give me the console
link as the skill instructs.
```

Agents with filesystem access can equally copy the file from a checkout of
this repo into their skills directory.

## What the agent's env means

`sc agent add <name>` mints one env block per agent:

| Var | Meaning |
|---|---|
| `SAFECLAW_BROKER_URL` | The local broker, e.g. `http://127.0.0.1:23294` |
| `SAFECLAW_API_KEY` | The agent's bearer identity |

The vault is not part of the env: each request names one in its URL
(`/v/<vault>/…`), and `sc run` binds one per launched command
(`sc run --vault <id> -- <cmd>` to pick). `sc vault ls` lists ids (`*` = default).

One identity per agent keeps the audit trail attributable; don't share a key
across agents, and don't re-run `sc agent add` when the env already exists (it
mints a duplicate).

These vars steer the *agent's* requests only. Your own `sc` commands read the
active vault from `~/.safeclaw/config.toml` (set by `sc login` / `sc vault
use`), so a stale agent env can never hijack what you do at the terminal.
