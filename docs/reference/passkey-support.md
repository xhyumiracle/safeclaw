# Passkey support

SafeClaw seals every vault under a passkey, using the WebAuthn **PRF extension**
to derive the encryption key on your device. Most modern setups support it; a
few do not yet, notably Windows 10 and cross-device QR approval. This page is the
lookup for what works, and what to do when yours doesn't.

> PRF is how the browser reaches the hardware-held secret that encrypts your
> vault. This is **not** a browser-version problem: modern browsers support PRF.
> What varies is whether the passkey's **store** (the authenticator) and the
> **transport** carry it. See [Security model](../security-model.md) for why the
> key never leaves your device.

**Legend** — ✅ works · ⚠️ conditional, see note · ❌ no PRF

Support is expanding fast; the tables below are current as of 2026. When in
doubt, open [passkeyprf.com](https://www.passkeyprf.com/) on the device: one tap
tells you whether that passkey can do PRF.

## Quick check

1. **Who stores your passkey?** The provider decides — see the first table.
2. **Your OS and browser** — the second table.
3. **This device, or a QR from another?** Cross-device is the weak leg — the
   third table.

## By passkey provider

Your passkey lives in one of these. This is the table that usually settles it.

| Provider | PRF | Where it works | Notes |
|---|:--:|---|---|
| Google Password Manager | ✅ | Android, Windows 11 25H2+, macOS, iOS/iPadOS | Every GPM passkey includes PRF. On desktop, GPM has to be offered as a save target: if your Google account is used only on Apple devices, Chrome on macOS may not let you *create* a GPM passkey (you can still use ones synced from Android). |
| iCloud Keychain / Apple Passwords | ✅ | macOS 15.4+, iOS/iPadOS 18.4+ | Platform only; no security keys on macOS. Earlier 15.x / 18.x do not carry PRF, even though the passkey still works for login. |
| Chrome profile (local, unsynced) | ❌ | Chrome desktop | Chrome's own local store, distinct from Google Password Manager. Does not carry PRF. When you save to Chrome, make sure it lands in Google Password Manager, not "Your Chrome profile". |
| 1Password | ✅ | macOS, Windows, Linux, iOS, Android | Via app or extension; independent of the OS |
| Bitwarden | ✅ | Chromium browsers, via extension | |
| Dashlane | ✅ | Supported platforms | |
| Windows Hello | ⚠️ | Windows 11 25H2+ only | Needs the Feb-2026 update (KB5077181). **Windows 10: never.** |
| Hardware security keys | ⚠️ | FIDO2 keys with hmac-secret | Newer keys work; older ones need PRF enabled when the passkey is first created |

The fastest fix for any ❌ or ⚠️ below is to store your passkey in a provider
that is ✅ here. **1Password** is the most reliable across platforms and works
even on macOS 14 and earlier. Google Password Manager also carries PRF, but on
desktop macOS Chrome may not offer it as a *create* target for Apple-only Google
accounts (see the provider note above).

## By OS and browser

| OS | Chrome / Edge | Safari | Firefox |
|---|:--:|:--:|:--:|
| macOS 15.4+ | ✅ 132+ | ✅ 18.4+ | ✅ 139+ |
| macOS 14 and earlier | ❌ built-in | ❌ built-in | ❌ built-in |
| Windows 11 25H2+ | ✅ 147+ | — | ✅ 148+ |
| Windows 11 (pre-25H2) / Windows 10 | ❌ | — | ❌ |
| iOS / iPadOS 18.4+ | ✅ | ✅ | ❌ |
| Android | ✅ | — | ❌ |
| Linux | ⚠️ | — | ⚠️ |

This table is the **built-in / platform** path (iCloud Keychain through Safari,
or the OS authenticator). A cross-platform provider adds PRF on top, independent
of these OS versions: **1Password** works on macOS 14 and earlier where the
built-in path does not. Firefox has no PRF on iOS or Android. Linux has no
built-in authenticator with PRF: use a provider (1Password) or a hardware key.

## By transport

| How you verify | PRF | Notes |
|---|:--:|---|
| This device (built-in / platform) | ✅ | The normal path; fully supported wherever the provider above is ✅ |
| Cross-device QR (hybrid) | ⚠️ | PRF over the QR/hybrid transport is still being standardized. iOS 18.0–18.3 dropped it; fixed in 18.4+. Prefer approving on the device running SafeClaw. |

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| "This passkey can't produce the vault's encryption key on this device" (creating or unlocking) | The passkey's store has no PRF: e.g. iCloud Keychain on macOS before 15.4, a local "Chrome profile" passkey, or Windows Hello before 25H2. Your browser is fine. | Use a passkey from a provider that carries PRF: **1Password** (any recent OS, including macOS 14), a synced Google Password Manager passkey, or a hardware security key. On macOS, upgrading to 15.4+ enables the built-in iCloud path. On Windows 11, update to 25H2. |
| "Your browser does not support the required passkey extensions" | The browser itself lacks WebAuthn PRF. Rare, and means a genuinely old browser. | Update to a current Chrome, Safari, or Firefox. |
| Fails only when you scan a QR to approve from another device | PRF didn't survive the cross-device (hybrid) transport. | Approve on the device running SafeClaw, or enroll that device's own passkey, then retry. |

Related: [Security model](../security-model.md) · [Diagnostics](diagnostics.md)
