# Platform support

Which operating systems and CPU architectures the `sc` binary and its daemon
install and run on. Passkey/browser support is a separate axis, covered in
[Passkey support](passkey-support.md).

**Legend** — ✅ available · 🚧 in progress · ❌ not supported

| Platform | Architecture | Status | Binary |
|---|---|:--:|---|
| macOS | Apple Silicon (arm64) | ✅ | `safeclaw-macos-aarch64` |
| macOS | Intel (x86_64) | ✅ | `safeclaw-macos-x86_64` |
| Linux | x86_64 | ✅ | `safeclaw-linux-x86_64` (static, musl) |
| Linux | aarch64 | ✅ | `safeclaw-linux-aarch64` (static, musl) |
| Windows | x86_64 | 🚧 | see [Windows](#windows) |
| Windows | 32-bit / Arm | ❌ | not planned |
| Any other OS / arch | — | ❌ | the installer exits with "Unsupported platform" |

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/SafeClaw-OSS/safeclaw/main/install.sh | sh
```

Puts the `sc` binary in `~/.local/bin` (override with `$SAFECLAW_BIN_DIR`). No
sudo, no system changes, no telemetry. `sc --version` to confirm. Linux binaries
are statically linked (musl), so there is no glibc or runtime-dependency
requirement.

## Verifying the download

Every release publishes a `SHA256SUMS` file, which the installer checks (and
warns if it can't fetch it), plus a sigstore build-provenance attestation. To
verify a binary yourself:

```bash
gh attestation verify ~/.local/bin/sc --repo SafeClaw-OSS/safeclaw
```

## macOS

The binary is not yet Apple-notarized. The `curl | sh` install above runs
without a Gatekeeper prompt; a binary downloaded through a browser would be
quarantined and blocked as "unidentified developer" instead. Verify provenance
with the attestation command above if you obtained it another way.

`sc up` installs a launchd LaunchAgent (`pro.safeclaw.daemon`) that starts the
daemon at login and restarts it on crash; `sc down` removes it. Logs at
`~/.safeclaw/daemon.log`.

## Linux

A single static binary, no runtime dependencies. `sc up` installs a per-user
systemd unit (`~/.config/systemd/user/safeclaw.service`, `systemctl --user`)
that starts the daemon and restarts it on failure; `sc log` reads its journal.
Running it as a system-wide service is possible by hand-writing your own unit.

## Windows

Native Windows support (a per-user Scheduled Task daemon that needs no admin) is
built and working on a feature branch, but **not yet merged or published** — the
standard install channel does not carry a Windows build today, so the install
command and release asset for Windows will not resolve until it ships. What
remains before release is code signing (an unsigned `.exe` triggers SmartScreen).

On Windows the binary is named `safeclaw.exe`, not `sc.exe` — `sc` is Windows'
own Service Control Manager and would shadow ours.

## Runtime

The daemon (`sc serve`, started by `sc up`) listens on `127.0.0.1:23293`
(control) and `127.0.0.1:23294` (the proxy `sc run` routes agent traffic
through). Both are localhost-only and overridable via `$SAFECLAW_PORT`. Unlock
uses your platform passkey — see [Passkey support](passkey-support.md).

Related: [Quickstart](../quickstart.md) · [Security model](../security-model.md)
