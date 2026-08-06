# Vault addressing: vault is an argument, not an identity

Status: LOCKED 2026-08-07. Supersedes the mint-time vault pin (`sc agent add`
emitting `SAFECLAW_VAULT_ID`) and the 3-var agent env contract.

## Principle

A vault names *what this call acts on*. Identity (the api-key) is durable;
vault is per-call. Anything that freezes a vault into durable state —
a minted env file, a config projection — recreates the bug where the
ergonomic switch (`sc vault use`) writes a value something else shadows.

The wire already treats vault as per-call: the explicit face carries it in
the URL (`/v/<vid>/…`), the transparent face carries it in each CONNECT's
`Proxy-Authorization` userinfo (`<vid>:<key>`). Only the layers above the
wire collapsed it into a scalar. This design removes those collapses.

## Resolution order (the single chain, `resolve_active`)

```
--vault flag (global)  >  $SAFECLAW_VAULT_ID  >  config default  >  single-vault auto-select
```

Unchanged in shape; what changes is the *sources* of each level:

- `--vault` becomes one **global** clap arg (works on every subcommand,
  any position), replacing the 15 scattered per-subcommand copies.
- `$SAFECLAW_VAULT_ID` has exactly ONE legitimate source: **launch
  injection by `sc run`** (child env, so the child's shelled `sc` and its
  proxy target the same vault). No durable file mints it anymore.
- config default is what `sc vault use` writes. With no durable pin,
  human shells follow it directly — `vault use` then `ls` just works.

## Decisions

1. **`sc agent add` mints 2 lines, not 3**: `SAFECLAW_BROKER_URL` +
   `SAFECLAW_API_KEY`. The vault line is gone — it was a mint-time
   snapshot of the device default, i.e. a second, shadowing device
   default that `vault use` could never beat.
2. **`sc env` emits only `SAFECLAW_BROKER_URL`.** It was the last path
   that pinned a *human* shell durably. With both minters gone, a set
   `$SAFECLAW_VAULT_ID` always means "inside a launched session".
3. **`--vault` is global** (`#[arg(global = true)]` on the top-level CLI);
   the per-subcommand fields are deleted. Existing invocations like
   `sc get KEY --vault X` keep parsing (global args are accepted in
   subcommand position).
4. **`sc run` is unchanged in behavior**: resolves at launch
   (flag > env > default), embeds the vid in the child's proxy URL, and
   injects `SAFECLAW_VAULT_ID` into the child. Mid-session switching on
   the transparent face = wrap the command: `sc run --vault B -- <cmd>`
   (nested runs work because flag > env).
5. **Agents may address any vault per request** on the explicit face
   (`/v/<vid>/…`). The skill stops calling `$SAFECLAW_VAULT_ID` config;
   vault ids come from `sc vault ls` (`--json` added for machines; `*`
   marks the device default).
6. **`sc vault use` is pin-aware**: when the shell carries a pin that
   differs from the new default, say so (the default was saved; this
   shell keeps its pin; `unset SAFECLAW_VAULT_ID` to follow) instead of
   printing an "active vault" header that the next command contradicts.
7. **`sc status`** honors the global `--vault`; its pin-vs-default note
   drops the `eval "$(sc env)"` remedy (sc env no longer re-pins) and
   keeps `unset SAFECLAW_VAULT_ID`.

## Compatibility

- Old agent env files that still export `SAFECLAW_VAULT_ID` keep working
  (the env level still resolves); they just keep the old frozen-pin
  behavior until the line is deleted. Migration is: delete the line.
- `$SAFECLAW_BROKER_URL` / `$SAFECLAW_API_KEY` semantics unchanged.
- Daemon/protocol untouched — this is CLI-surface + contract only.

## Non-goals (recorded so they stay decided)

- **No broker `GET /vaults` endpoint.** `sc vault ls --json` covers
  discovery; the protocol surface stays closed until a real need.
- **No phantom format change.** Phantoms stay `__sc__<conn>__`; the
  transparent face's vault carrier is proxy-auth, per launch. A single
  command mixing two vaults' phantoms stays unsupported (wrap each
  command instead).
- **No cross-vault phantom fallback in the proxy.** A phantom not found
  in the bound vault passes through literally (existing behavior);
  silently resolving it from another vault would be a misroute
  (wrong secrets, wrong approvers, wrong audit trail).
- **No precedence flip.** Config beating env would yank vaults out from
  under running sessions on every `vault use`.
