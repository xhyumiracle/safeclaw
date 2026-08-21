# Quickstart

Zero to an agent making authenticated API calls with a key it never saw.
Takes about five minutes.

## 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/SafeClaw-OSS/safeclaw/main/install.sh | sh
```

Puts the `sc` binary in `~/.local/bin` after verifying its `SHA256SUMS`. No
sudo, no system changes. `sc --version` to confirm. Supported platforms and how
to verify the download: [Platform support](reference/platform-support.md).

## 2. Create your vault

Sign in at [safeclaw.pro](https://safeclaw.pro) and register a passkey when
prompted. The passkey is the root of everything: your vault's contents are
sealed under it, and it is what you tap to approve sensitive actions later.
There is no password.

## 3. Pair this machine and your agent

In the console, "Connect a new agent" mints a one-time pair token and an
install prompt. Paste the prompt to your agent and it does the rest. What it
runs:

```bash
sc login                      # pair this machine; brings the daemon up and
                              # prints a passkey-approval link you open once
sc agent add my-agent         # mint the agent's env file:
                              # SAFECLAW_BROKER_URL / SAFECLAW_AGENT_IDENTITY
```

The approval is a passkey tap in your browser. After this, `sc status` shows
the daemon up and the vault unlocked.

## 4. Add a credential

Two doors, same result: a **connection** with hosts and a **phantom**.

**Console** (recommended for OAuth services like GitHub or Gmail): open your
vault's Connections tab, pick the service, sign in or paste the key. Values
you type there are encrypted in your browser before upload.

**Terminal**, for any bare API key:

```bash
sc set HF_TOKEN --host huggingface.co
```

Prompts for the value, asks for one passkey approval, and mints the phantom
`__sc__hf_token__` anchored to `huggingface.co`. Entered this way the value
never leaves your machine.

## 5. First brokered call

Put the phantom where the credential belongs and route the command through
`sc run --`:

```bash
HF_TOKEN=__sc__hf_token__ sc run -- huggingface-cli whoami
GITHUB_TOKEN=__sc__github__ sc run -- gh pr list
```

The proxy swaps the phantom for the real value on the way out, only toward
that connection's own hosts. The command gets the API response; the
environment, the shell history, and the agent hold only the phantom.

## 6. When an approval is needed

Policy-gated uses don't fail silently: the command's error output carries an
approval link. Open it, tap your passkey, re-run the same command. Agents can
block on `sc op wait <op_id>` instead of asking you to say "done". Approvals
are cached per policy, so routine calls don't nag.

## 7. Daily rhythm

```bash
sc up      # start of day: daemon up + vault unlocked, one passkey tap
sc lock    # done for the day: wipe keys from the daemon's memory
sc doctor  # something's off: health + reachability checks
```

Next: teach the agent the full patterns in
[`sc run` and phantoms](sc-run.md), or hand it the skill directly via
[For your agent](for-your-agent.md).
