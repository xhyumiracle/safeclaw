# SafeClaw Credential Broker — one proxy, one phantom (design, LOCKED 2026-07-03)

> **Status: LOCKED — phantom-only proxy model.** This supersedes the earlier
> two-stage `/use`+`/proxy` design (see §Superseded). Pre-launch, 0 users,
> wipe+re-enroll: build the whole model at once, no back-compat, no staged
> cutover.
> **Mechanism-only** — positioning/market strategy lives in the PRIVATE
> `safeclaw-pro-backend/docs/STRATEGY.md`, never here.
> Grounded in: [connection-schema.md](connection-schema.md),
> [services.md](../docs/reference/services.md), [protocol.md](protocol.md) §6.

---

## 1. TL;DR

Give an agent the **use** of a credential without letting it **hold** the
credential. There is **one surface**: a **local HTTPS proxy** on the user's
machine. The agent writes a **phantom placeholder** (`__sc__<conn>__`) wherever the
credential belongs — an env var its tool reads, a request header it sends. The
proxy is the only thing that ever sees the real value: it resolves the phantom →
connection → secret, checks the destination host against the connection's
anchor, substitutes at egress, forwards. The agent never receives the real value
back.

**One mental model, one sentence:** *"SafeClaw is a local proxy. Put the phantom
where the credential goes; send your traffic through the proxy."*

**No `/use`, no `/proxy` JSON endpoint, no base-URL rewriting.** Those are all
special cases of "route the request through the proxy with a phantom in it."

---

## 2. The three questions (the whole model)

A brokered request answers exactly three questions, each with **one** owner:

| Question | Owner | Carrier |
|---|---|---|
| **Where does the credential go?** (injection site) | the **agent** | the phantom's position in the request (header / query / body — anywhere) |
| **What value, produced how?** | the **vault** | phantom name → connection → secret (direct value, or the OAuth-minted token) |
| **Is it allowed?** | the **vault** | the connection's **host anchor** + policy tree + approval |

**The SSOT rule chain (memorize this — it is the entire design):**

> a secret is **single-owned** by a connection (the address *is* the ownership)
> → the **phantom is the only intent carrier** (traffic with no phantom is
> forwarded untouched, never injected)
> → a connection's **hosts have one source** (service-declared if a service is
> referenced — instance may only pin within its wildcards — else the connection's
> own user-anchored `hosts`; never overridable)
> → **host is a constraint, never a selector** (we validate the destination
> against the anchor; we never pick a connection *by* host).

Everything below is a consequence of this chain.

## 3. Single-ownership invariant (verified)

**A secret belongs to at most one connection.** This is already enforced by
storage: a secret's address is `[<conn>:]<ROLE>` — ownership is encoded in the
name, so `secret → connection` is a total function today. Checked against the
apparent counter-cases:

- *One PAT for both REST and git* → that's **one connection, multiple hosts**
  (the service declares them), not two connections.
- *One key shared by two services* → vanishingly rare; copy it. Not worth
  breaking single-ownership.

Because ownership is single-valued, a phantom carrying the secret's name
resolves to a unique connection — no host-based guessing, no ambiguity.

## 4. The hierarchy — secret / connection / service (settled once)

**Secret is a 2-tuple.** Hosts are a property of the *relationship to a
destination*, not of the value (a multi-secret connection would otherwise
duplicate/conflict hosts across its secrets); the flat pool matches the
env-is-vault architecture; no-broker is the natural unwrapped state.

```
secret      = <key, value>                            flat pool; unclaimed by any connection ⟺ no-broker
connection  = <secret key(s), hosts> + service ref    the INSTANCE
service     = <secret keys, hosts>  (+ oauth, hints)  the TYPE — optional, per-target knowledge
raw conn    = a connection with NO service ref        (service is optional; no "trivial service" entity)
```

**The instance struct** (`config` is deleted — it existed to feed the retired
template layer; `host` is promoted because it is the anchor, the single most
security-relevant field, and the settled tuple already makes it first-class):

```jsonc
// STORED — aux.connections[<conn_id>].  conn_id is the map key (not repeated in the value).
// Minimal by construction: everything else is derived or lives elsewhere.
{
  "name":    "GitHub · Work Laptop", // string — FULL display name (see below)
  "service": "github",           // string | null   (null = raw)
  "hosts":   ["api.github.com"], // string[] | null  (see the SSOT invariant)
  "secrets": ["GITHUB_TOKEN"]    // string[] | null  — the UPPERCASE keys this conn uses
}
// secrets: REQUIRED for a RAW connection (service = null) — it answers "which
//          secrets" DIRECTLY, so discovery / cache-bootstrap read it instead of
//          reverse-indexing the flat pool by casing. OMITTED (null) for a
//          service-backed connection: its keys derive from the service's declared
//          `secrets` (incl. the oauth2 refresh key). Values live in the flat
//          pool at BARE env-valid keys; the record's sparse `keys` map binds
//          role → KEY (identity when unmapped — connection-schema.md §3), so a
//          named connection stores at distinct suggested keys
//          (GMAIL_REFRESH_TOKEN_WORK) and may bind to an existing key to share.
// policy:  NOT here — aux.policy.connections.<conn_id>.
// phantom: NEVER stored — it is a DERIVED composite of (conn_id + a secret key);
//          storing it would be redundant and ambiguous for multi-secret conns.
// name:    the FULL display string shown in lists, stored verbatim as composed
//          at creation. Same field name + contract as a service's `name`: every
//          creation path writes it (required at creation); wire-optional only
//          for legacy rows (pre-name / CLI-created / written under the old
//          `label` key — read via serde alias) ⇒ absent = render the id.
//          Display ONLY: the id stays the technical handle for
//          phantoms/policy/audit. Also on aux.connecting; the daemon carries it
//          through the connecting→connections move.
//          NAMING (2026-07-06/07, service-backed): the user types only a
//          QUALIFIER; creation composes name = "<Service> · <qualifier>" and
//          conn_id = <service>_<slug(qualifier)> ("GitHub · Work Laptop" ⇒
//          github_work_laptop). No qualifier ⇒ the default connection:
//          name = the service's display name, conn_id == service_id. The
//          service half of the identity is structural, never retyped. RAW
//          connections keep free naming (name = typed verbatim, id = slug).

// hosts has ONE source (SSOT):
//   service = null             ⇒ hosts required (raw; normally a single host)
//   service, exact hosts only  ⇒ hosts null (derived from the service; no stored copy)
//   service with *.wildcards   ⇒ hosts required: exact FQDNs pinned ⊆ the wildcards
```

**Phantom belongs to the DISCOVERY view, not the stored record.** The registry
(`GET /v/{vid}/registry`, mirrored by `sc status`) projects into the agent-facing
shape as **two arrays**: `services[]` — the browse catalog, 1:1 with the service
tomls, carrying NO connection state — and `connections[]` — 1:1 with
`aux.connections`, each row a DERIVED `connected` flag plus a ready-made
`phantoms` **list**. A phantom names a CONNECTION, so it lives only on the
connection row. `phantoms` is a **list** of ready-made strings the agent copies
verbatim (form A: sole injectable → the short `__sc__<conn>__`; several →
role-qualified `__sc__<conn>__<role>__` — one form per role, never both):

```jsonc
// GET /v/{vid}/registry  (agent-facing projection — derived, not stored)
{ "version": 4,
  "locked": false,                              // PER-VAULT (this vault, not the daemon)
  "services":    [ /* browse catalog — no connected/phantoms */ ],
  "connections": [
    { "id": "github", "service": "github",
      "hosts": ["api.github.com", "github.com"],
      "connected": true, "phantoms": ["__sc__github__"] },        // sole → short form
    { "id": "stripe_key",                                          // RAW: no service…
      "hosts": ["api.stripe.com"], "secrets": ["STRIPE_KEY"],     // …carries explicit secrets
      "connected": true, "phantoms": ["__sc__stripe_key__"] }
  ] }
// multi-secret:  "phantoms": ["__sc__bb__username__", "__sc__bb__api_token__"]
// oauth2:        "phantoms": ["__sc__gmail__", "__sc__gmail__account_id__"]  // ACCESS + exposes
```

(There is NO routing preflight anywhere — the broker is opt-in, §14: the agent
routes every credential request explicitly, so "am I routed?" has no meaning.)

**The service toml schema.** `[[upstream]]` is retired (it was `/use`-era
routing; its essence was the host set). A service declares exactly what a
minimum connection has — `secrets` + `hosts` — plus the one non-direct
production (`[oauth2]`) and optional helper overrides:

```toml
[service]
id = "github"
name = "GitHub"                              # cosmetic

hosts = ["api.github.com", "github.com"]     # exact FQDNs, or "*.suffix" wildcards
secrets = ["GITHUB_TOKEN"]                   # stored keys; phantom resolves to the value as-is

setup = """…"""                              # cosmetic (agent-facing prose)
# NO auth section: Basic needs none — the scheme names itself in the header;
# the proxy decodes it natively and substitutes the phantom inside.
```

**Host matching = the mainstream domain rule** (TLS-certificate wildcard
semantics), no variable system:
- a service `hosts` entry is an **exact FQDN** or **`*.suffix`** (`*` leftmost
  only, matches exactly ONE label: `*.openai.azure.com` matches
  `foo.openai.azure.com`, not `a.b.openai.azure.com`); bare `*` forbidden.
- `conn.hosts` entries are **always exact FQDNs**, each required to fall inside
  some service entry (⊆). Exact service entries anchor automatically; **a
  wildcard entry never reaches runtime enforcement** — it only constrains what
  the instance may PIN (human-confirmed at connect). Pinning is mandatory
  because on `*.openai.azure.com` an attacker can stand up their own tenant —
  without a pinned exact host the secret could egress to it (invalid there, but
  leaked).
- **No full override** of service hosts by the connection: curated hosts are the
  audited anti-SSRF promise. Fully self-hosted instances (own GitLab) = **just a
  raw connection** — insertion-auth self-hosting needs no service definition;
  self-hosted+OAuth is deferred until a real case appears.

**Named sections are auth MECHANISMS, never tools.** OAuth2 lives in an `[oauth2]`
table (`oauth2` not `oauth` — precise, self-documents the parse semantics) whose
token slots carry RFC 6749 response field names:

```toml
[service]
id = "gmail"
name = "Gmail"

hosts = ["gmail.googleapis.com"]
secrets = ["GMAIL_REFRESH_TOKEN"]            # uniform `secrets` — lists the refresh key too

[oauth2]
provider = "google"                          # display label only; wiring is inline
scopes   = ["https://www.googleapis.com/auth/gmail.send", …]
refresh_token = "GMAIL_REFRESH_TOKEN"        # RFC 6749 field → the vault secret KEY the
                                             # durable refresh token is stored under
# id_token = "GMAIL_ID_TOKEN"                # only if the provider returns a stored id token
# exposes = ["account_id"]                   # optional extra minted/derived values →
                                             # __sc__<conn>__account_id__ (openai-codex case)
# __sc__<conn>__ resolves to the MINTED access token; the refresh key is durable
# storage for the mint ⇒ internal by construction, never an injectable phantom.
```

*(`[[api]]` is deleted along with `[[upstream]]` — it was the `/use` routing
table; with real URLs the route is in the traffic, and policy matches
`(host, path, method)` directly.)*

**Three classes of service content:**
1. **First-class:** `hosts` + `secrets` — the same two words as the connection
   tuple. Direct insertion is the default and needs no declaration.
2. **Auth-mechanism sections** — the ONLY named sections, one per mechanism,
   each with self-evident parse semantics:
   - **`[oauth2]`** — the phantom resolves to a minted access token.
   - **There is NO `[basic]` section** (killed by its own existence trial):
     the scheme names itself in the header (`Authorization: Basic …`), so the
     proxy decodes it natively, finds the phantom, substitutes, re-encodes —
     zero declared information needed. Constructing a pair is just another
     phantom PLACEMENT, which is the agent's job: git → URL userinfo
     (`https://x:__sc__github__@github.com/…`; a validated username — Bitbucket,
     case-sensitive — is instance data the agent types there); docker →
     `docker login -u <user> -p __sc__dockerhub__` (the phantom lands in
     docker's config.json and rides every registry call). `sc git-credential`
     survives only as an OPTIONAL zero-schema convenience with one documented
     global rule: for the asked host's connection emit
     `("x", <phantom of the sole injectable secret>)`; multiple/none → decline.
     It reads no service data — a placement automation, like `sc run`'s env
     pasting; not load-bearing.
   - future `[sigv4]` etc. when real. **Tool-named sections (`[git]`,
     `[docker]`) are forbidden.**
3. **Cosmetic:** `name`, `setup`, UI placeholders — deletable without affecting
   any parse or security behaviour; considered last, never allowed to shape the
   structure.

```
resolved_hosts(conn) = conn.service ? exact_entries(service.hosts) ∪ pinned(conn.hosts ⊆ wildcard entries)
                                    : conn.hosts                            // raw
enforce:  destination host ∈ resolved_hosts(conn)   (always EXACT FQDN, case-insensitive, port-aware)
```

## 5. Phantom syntax

The phantom is always a **value** (an env var's value, or an inline header/URL
token) — never an env var *name*. The binding constraint is **round-trip
safety**: it must survive env values, URL path/query, JSON, headers, and base64
(the proxy decodes Basic auth before matching). ⇒ charset locked to
**`[A-Za-z0-9_]`** (`:` and `.` are out — they break Basic-auth / URL / env-name
round-tripping).

```
__sc__<conn>__<role>__          // <conn>,<role> ∈ [a-z0-9_], no double-underscore inside (__ is the delimiter)
__sc__<conn>__                   // DEFAULT shorthand — the connection's sole injectable secret
```

- Most connections expose exactly **one** injectable secret (OAuth-refresh is
  internal/hidden), so `__sc__<conn>__` is the everyday form; the `__<role>__`
  suffix appears only when a connection genuinely exposes several.
- `<conn>` is the id the user gave at connect time and sees in the UI
  (`github`, `gmail_work`) — nothing new to learn. Connect enforces env-safe ids.
- Storage keys are ALL bare env-valid names; the connection record's `keys`
  map binds role → KEY (connection-schema.md §3). The phantom stays the only
  SafeClaw-invented string on any surface.
- The `__sc__…__` shell is a **leak breadcrumb**: an un-substituted phantom is
  recognizable in logs/upstream errors.
- Multi-account is disambiguated by **conn name** (`__sc__gmail__` vs
  `__sc__gmail_work__`), never by host.
- Parse: strip the `__sc__` prefix and trailing `__`, split the remainder on
  `__` → 1 or 2 segments; unambiguous because ids may not contain `__`.
- No industry standard for phantom tokens exists; `__X__` is the folk
  placeholder idiom (scaffolding/templating), and vendor prefixes are the modern
  secret-string convention (`ghp_`, `sk_live_`, secret-scanning). `__sc__…__`
  carries both signals: *"I am a placeholder"* + *"SafeClaw substitutes me."*

**Multi-profile is selected by phantom VALUE — never by env var name.** The env
var *name* is the consuming tool's contract (`gh` reads only
`GITHUB_TOKEN`/`GH_TOKEN`; nothing reads an invented `GITHUB_WORK__GITHUB_TOKEN`),
so the selector must live in the value — which matches how the ecosystem already
does profiles (`AWS_PROFILE`, kubectl contexts, per-project `.env`/direnv):

- persistent: per-project `.env` (`GITHUB_TOKEN=__sc__github_work__` in the work
  repo; recorded in the manifest);
- ad-hoc: per-command prefix (`GITHUB_TOKEN=__sc__github_work__ gh pr list`);
- git (no env var): **the phantom itself goes in the URL username slot** —
  `git clone https://__sc__github_work__@github.com/owner/repo` → git sends it as
  the Basic username → the proxy substitutes. Same one concept, zero extra rules.
  The credential helper covers only the default case (the host's default
  connection). What the user puts in a URL username otherwise is their own
  business — no coupling between URL usernames and connection ids is designed or
  documented.

**Storage keys never reach the agent, and there is no address syntax at all.**
The agent surface is exactly two things: the tool's env var name (its contract)
and the phantom value (ours). Vault keys are plain env names — which connection
uses which key is data in the connection RECORD (`keys` map / raw `secrets`
list), not something parsed out of the key. *Storage-only vs connection secret*
is decided by **whether any connection claims the key**, not by key syntax.
(The pre-2026-07-08 `[<conn>:]<ROLE>` colon namespacing is retired.)

## 6. Transport: the local HTTPS proxy + the env bundle

The proxy is a **local HTTPS MITM** (HTTP CONNECT). A process is brought under it
by a bundle of environment variables — the only per-process, permission-free way
to (a) route traffic to the proxy and (b) trust the proxy's CA (§7 has the
first-principles reason). The **CA and proxy are resident** (generated once at
install, private key `chmod 600`, never leaves the machine — no system-trust
install, no GUI prompt). The bundle just points a child process at them:

```
HTTPS_PROXY / HTTP_PROXY = http://<vid>:<agent-key>@127.0.0.1:23294
                                      # vid routes to a vault; the key is the
                                      # agent's identity, verified BEFORE any
                                      # substitution (§14 auth)
NO_PROXY = localhost,127.0.0.1
NODE_USE_ENV_PROXY = 1                # Node 24+ fetch honours proxy only with this
SSL_CERT_FILE / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / NODE_EXTRA_CA_CERTS /
GIT_SSL_CAINFO / DENO_CERT = <resident CA path>
```

**Selective MITM (by SNI).** The proxy decrypts + substitutes **only** for
connections whose SNI ∈ the union of all connections' hosts; everything else is a
**blind tunnel** (not decrypted). Wins: privacy ("we only see brokered
traffic" — matters for the trust phase), performance, and unrelated
cert-pinned tools are untouched. The union covers unlocked vaults live, plus
each locked vault's last-known anchors (in-memory, remembered across Lock) —
so a phantom sent while locked meets an explicit `vault_locked` instead of
tunneling to the upstream literally (docs/../docs/reference/diagnostics.md).

**Scopes** — same bundle, three reaches (the only real degree of freedom):

| Scope | Who | How |
|---|---|---|
| one command | agent, zero human | `sc run -- git push` — the only self-service form for an already-running agent; the default |
| whole session | human, once | `eval "$(sc run --export-env)"` — covers the shell |
| whole agent / service | human, once | launch the agent under `sc run`, or write the bundle into its systemd `Environment=` / docker env |

`sc run` is a **thin env-paster** over the resident CA/proxy — it does not spin up
a per-process CA or proxy. Its ancestor "export all secrets to env vars as
plaintext then exec" is **dropped** (§Decided-NOT).

## 7. Why env vars are the mechanism (first principles)

Bringing one process's traffic under our CA needs two independent things:
**(a)** the traffic reaches our proxy, and **(b)** the process trusts our root.
The OS gives **no per-process trust switch** — TLS trust is decided inside each
process's own TLS stack, and the one global switch (system trust store) is behind
a GUI-authorization prompt on macOS (Apple removed silent CLI trust in Big Sur;
only MDM profiles bypass it). So the only permission-free, per-process path is the
env-var interface each stack *chooses* to honour. These are decades-old
documented interfaces (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, …) — stable, but
per-stack conventions, not an OS guarantee. Hence coverage is a **matrix**, and
the gaps are handled by adaptors (§8), not by forcing it.

Verified holes (route these via adaptor, not MITM):

| Hole | Fact |
|---|---|
| **Go on macOS** | `root_unix.go` build-excludes darwin; forced through Security.framework → `SSL_CERT_FILE` ignored. **gh / terraform / supabase on Mac miss env-CA** (fine on Linux). |
| Node built-in fetch (proxy side) | ignores `HTTPS_PROXY` pre-24; needs `NODE_USE_ENV_PROXY=1`. |
| Java | reads neither; escape `JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=…` (prints a stderr line). |
| rustls / Electron static roots | not overridable. |

## 8. MITM + adaptor = deliberate hybrid

MITM covers **as many cases as it cleanly can**, not all — that is *why* the
model is a hybrid. A process the env-CA can't reach (§7 matrix, cert-pinning)
falls back to an **adaptor**: a per-command explicit route the tool already
supports (`git`'s credential path, `npm --registry`, `pip -i`). The adaptor still
carries a phantom and still resolves through the same connection/host machinery —
it is a different *transport onto the same core*, never a second model.

**git — the worked case (no hard blocker):**

| Scenario | Route | Outcome |
|---|---|---|
| under the proxy (session/agent-scope `sc run`) | CONNECT → SNI hits the connection's host → helper emits phantom → proxy Basic-decodes, substitutes, re-encodes; streaming relays natively | transparent |
| not under the proxy, agent shells git | **`sc run -- git push` — the per-command prefix IS git's adaptor** (same bundle, command scope) | task completes |
| no routing possible at all | opt-in discipline (§14): don't send the phantom — say so to the user | explicit, not a mystery 401 |
| SSH remote (`git@…`) | not HTTP — outside the broker; setup hints "use the HTTPS remote for brokered flows" | honest boundary |

Helper registration is residue-free: `sc run` injects
`GIT_CONFIG_COUNT/KEY_0=credential.helper/VALUE_0="!sc git-credential"` (git's
native per-process config env) — nothing written to any gitconfig.

**A further simplification the git case exposes: service auth-header templates die
entirely.** `Authorization = "Bearer {{secret.X}}"` was a `/use`-era artifact
(daemon built the header). Phantom-only: the **tool builds its own header with
the phantom inline** (gh pulls it from env and writes `Bearer <phantom>`; git
base64s it itself) and the proxy only substitutes. The helper shape (GitHub:
username ignored; Bitbucket: real username) needs NO declaration — pair
construction is phantom placement (URL userinfo), with `sc git-credential` as an
optional zero-schema convenience (§4).

## 9. What the phantom resolves to

- **Default: the stored secret's value, as-is** (bearer / api-key / query / URL /
  Basic — position is the agent's, via the phantom; no declaration needed). The
  vault always stores the **semantic** value, never a pre-encoded form.
- **`[oauth2]`: the minted access token** (refresh→access in the daemon, [built]).
  The mint is cached **in memory keyed by `sha256(refresh_token)`** (never
  persisted; wiped on lock): a hit reuses the unexpired access token and never
  sends the refresh upstream. Keying on the refresh VALUE (not `(vault, conn)`)
  auto-invalidates on reconnect / refresh-token rotation — a new refresh is a
  natural cache miss → fresh mint — and never collides across accounts. The one
  non-direct case; a future request-signer (SigV4/HMAC) would be another named
  section when it becomes real.
- The old `{{secret.X | b64|basic}}` egress filters are **cut** (they served the
  retired daemon-built-header path; no known pre-encoded-slot use case — YAGNI,
  revisit on a real one).

## 10. Security

**Sound because:** the phantom is the only injection trigger (no host-based
auto-inject); host is anchored per connection and validated exact-FQDN;
`{{secret.*}}` can't appear in a service-declared authority (`upstream_host_has_unsafe_template`);
private/metadata/localhost floor (`host_egress_allowed`) sits under the anchor;
replace-all-matching strips agent-supplied auth so the agent can't shadow the
injected credential; `/export` off the agent surface removes the raw-reveal path;
OAuth is curated-only.

**Approval-cache key includes the resolved host** — an approval for host A must
not authorize host B within the TTL (host is request-data in this model). Key =
`(conn_id, rule_id, method, host)`; for single-host connections behaviour is
unchanged.

**New-destination confirmation = higher-friction, exact-FQDN.** First unmatched
host → a captive-portal one-tap-**widen** that writes an **exact FQDN** as a
permanent grant (distinct, higher-friction UX; show host + eTLD+1; never
auto-widen to a bare suffix). Ships in warn/log mode first, then deny.

**Honest posture:** even fully built, the human anchor is
**habituation-defeatable** (true of all human-approval security). The claim is
"agent never holds the key + host-anchored egress + human confirms new
destinations" = **strictly better than status quo** (agent holds the raw key,
sends it anywhere), not "unbreakable." Defense = keep widen prompts rare +
salient (default to curated/correct hosts).

*Optional hardening, not a gate:* DNS-pin on the resolved IP (anti-rebinding) —
value is reaching internal/metadata IPs behind a name block, a hosted/shared-
daemon concern; the local daemon can reach LAN anyway. Low priority.

## 11. `sc set` — host required, skip must be explicit

Interactive and non-interactive, modern-CLI standard. **Host is a required
answer**, not a default-skip (a set-without-host that the agent later can't use is
the reverse-intuitive trap):

- **Interactive** (TTY): missing value → hidden prompt (keeps the secret out of
  shell history / `ps`); missing host → prompt, **required**; no-broker must be
  chosen explicitly (`--no-broker` or typing `none`, echoing the consequence
  "agent cannot use this item"). Every prompt echoes the intent of what was
  already passed (defends arg-order mistakes; host is `--host`, never a 3rd
  positional).
- **Non-interactive** (script / agent pipe): missing host → error listing the two
  fixes (`--host <h>` / `--no-broker`). Never hangs.

`sc set KEY [VALUE] --host H` **creates the raw connection** — id `= lower(KEY)`,
`service: None`, `hosts: [H]`, and explicit `secrets: [KEY]` (KEY force-uppercased
to the one canonical form; the value is stored bare in the flat pool). Hostless
`--no-broker` (or `--host none`) writes a no-broker item invisible to the broker,
and drops any raw connection a prior `sc set … --host` created for the key.

`sc set --host` is the single-secret **shorthand of `sc connection add`** (`add ⊃
set`; `sc connect` is the hidden back-compat alias): `sc connection add <id> --host
H… --secret KEY=VALUE…` builds a multi-secret raw connection, and `--service SVC` a
service-backed one — where `--host` then only PINS an exact FQDN ⊆ the service's
`*.suffix` hosts, and each `--secret KEY` must be a subset of the service's declared
secrets. `<id>` is a handle you choose (free text is slugified). Siblings:
`sc connection ls` / `sc connection rm <id>`.

## 12. Storage-only items (the "no upstream" family)

`host` is **required, but a host of `*` is never allowed.** Two distinct "no host"
meanings:

- **"any host"** (wildcard egress) — **no legitimate need**; it is exactly
  "silently exfiltratable." Forbidden.
- **"no upstream at all"** — real: values consumed by **local computation**, never
  sent to a third party over HTTP (`JWT_SECRET`, session/encryption keys, DB
  passwords over non-HTTP `postgres://`, wallet seeds, license keys). These have
  no host to anchor; phantom substitution doesn't apply. ⇒ **pure storage**,
  retrieved by a human with passkey (`sc secret get`); **invisible to the agent
  surface.** This absorbs the "files / pure storage" family into the same list —
  a no-broker item just shows *"stored · agent cannot use · add a host to
  broker."*

## 13. `/export` — a reveal, not an injection (out of scope for phantom)

`/export` gives the agent the **raw value** — the opposite shape of the broker
(inject-toward-upstream). It has **no upstream**, so it does not fit the phantom
model, and forcing it back in would reopen the raw-exfil hole. **Decision: keep it
out.** Current handling is final for this wave — and needs nothing new built: the
human path is the **op-plane Export ceremony** (`sc secret get` → `POST /v/{vid}/op`
`act.type=export` → browser passkey "Reveal <key>" → approve redemption;
cli/secret.rs). What's 403'd is only the **proxy-plane sugar route**
`/v/{vid}/export/<key>` (the agent door). Two doors; only the agent one is shut.

**Forward concept (record, don't build now): the `system` category.** A *virtual
connection whose upstream is the daemon itself*, driven through the same
proxy+phantom surface, lets agents perform meta-ops (e.g. **propose a vault
policy**, propose a service definition) under one unified mechanism. Export does **not** fit
(it's give-agent-plaintext, anti-broker), but agent→daemon *data-submitting*
ops do (upstream = self). This is why a `system` category exists in the vault. Out
of scope now; noted so the mechanism composes later.

## 14. Agent surface — opt-in, three planes, dual-face port, atomic env (LOCKED 2026-07-06)

(Absorbs `docs/AGENT_SURFACE_REDESIGN.md`, built + shipped on `feat/broker-phantom`;
that file is deleted. Supersedes this section's old "routing discipline".)

**Opt-in, NOT a mandatory proxy.** Normal traffic goes direct and untouched.
Only credential traffic — a request the agent DELIBERATELY writes a phantom
into — is routed (`sc run --`).
A dead daemon degrades only vault features, never all egress; a phantom sent
unrouted reaches the upstream as a literal string → clean 401, never a leak.
Consequence: **all routing-detection is deleted** (probe host, `is_routed`,
the `sc status` routing block) — the agent routes every vault request
explicitly, so "am I routed?" has no meaning. If no routing is possible, the
agent doesn't send the phantom and says so.

**Three planes, and WHO is the client:**

| plane | port | the CLIENT is | auth | for |
|---|---|---|---|---|
| **data (proxy)** | :23294 | the **agent's runtime** (its HTTP client + `sc run` children) | agent-key | discovery reads + brokered credential traffic |
| **control** | :23295 | the **`sc` CLI** (human, or agent via a shelled `sc up`) | passkey / localhost | unlock, connect, approve, status |
| **account** | cloud :443 | the **`sc` CLI** (`login`/`logout` ≡ `sc device *`, `sc agent *`) | device-key (pair-token bootstraps it) | pair devices, mint agent keys, hash registry, blob sync, op-relay |

The agent's own traffic touches ONLY :23294. `sc` is a control/account tool —
never a client of the proxy port; `sc run` doesn't *use* the proxy, it
*launches a child* onto it. Two ports stay (data-plane/control-plane
separation: independent exposure requires independent listeners); the proxy
DEFAULTS to loopback as a safe default, not a law — remote exposure is a
future capability gated on TLS + a network-grade key + user-owned infra.

**Dual-face :23294** (RFC 7230 §5.3 request-line dispatch): CONNECT /
absolute-form → the MITM proxy face; **origin-form → a read-only API face**
(`/health`, `/ca` unauthenticated; `/v/{vid}/registry`, `/op/{id}` Bearer
agent-key), self-answered from the SAME projection functions the control
plane serves so the two ports can't drift. Self-authority absolute-form =
loop guard. Writes/ceremony never appear here. Discovery is a plain direct
GET — never through the proxy. Captive-portal 401s carry an ABSOLUTE
`poll_url` at this face.

**Waiting is a process, not a held connection**: every pending-approval body
on a paired daemon also names `sc op wait <op_id>` — a waiter that polls
`/op/{id}` until the op resolves, then exits with the outcome (0 approved /
5 rejected / 3 expired / 4 timeout; 2 stays clap's usage-error code). An
agent backgrounds it and treats process-exit as its wake-up — the `sc up`
unlock experience generalized to every approval. Polling never consumes the
grant (a retry reads the approval cache; only `ask-always` burns it
single-use), so waiting and re-running can't race. The record's
`expires_at` tracks the op's own Valid window, so the waiter 404s
exactly when the op stops being approvable. Sandboxed agent without `sc` →
the JSON `poll_url` is the same contract by hand; the reject-and-re-run
floor is unchanged.

**An `ask-always` approval is a one-shot bound to the request the user saw**
(v0.9.28): approving mints a grant keyed by the op's `(connection, method,
host, path)` in `op_grants`, consumed single-use by the replay
(`op_grant_take`). A replay whose method/host/path differ — the
approve-$80-then-send-$180 shape rides only as far as the path identity;
a different endpoint or verb re-prompts — misses WITHOUT consuming, so the
legitimate replay still works. The ask-always resolve path never reads the
conn-keyed `entries`, so an unconsumed approval can no longer be spent by an
unrelated later request on the same connection, and it can't ride allow
residency or a plain-ask leftover. The redeem window is generous
(`ASK_ALWAYS_REPLAY_WINDOW_SECS`, 30 min — an agent that replays only when
its user next prompts it may take minutes); single-use + exact binding is
the guard, not time. Known boundary (settled 2026-07-09): the request BODY
is not part of the binding — same method+host+path with a different body
redeems. Body-field binding is the Phase-2 `[requests]`/vars/scope design.

**The agent's env = its SSOT — two dotenv vars, minted as ONE block:**

```
SAFECLAW_BROKER_URL=http://127.0.0.1:23294               # broker/API face
SAFECLAW_API_KEY=<key>                                   # identity — Bearer (API face) + proxy password
```

No vault var (design/vault-addressing.md): vault is per-call — the discovery
path param and proxy username carry it, and `sc run` injects
`$SAFECLAW_VAULT_ID` into the child it launches. Nothing durable mints the
pin; a mint-time vault froze the device default of mint day into a shadow
default `sc vault use` could never beat.

**`sc agent add <name>` IS the single minter**: it prints this whole block to
stdout (key shown once; stderr guidance carries no secret) — a mint-time
projection of the DEVICE atoms — and the agent appends it unseen to its own
`.env`. The key stays out of the install prompt AND the transcript (settled:
the cloud also can't know a device's real atoms, so a console-baked env would
freeze assumptions). `sc env` stays the HUMAN-shell projection (`BROKER_URL`
only — never a key, which would collapse per-agent revocation, and never a
vault pin, which would shadow `sc vault use`). Install chain: prompt = install + pair-token login + `sc agent
add >> .env` + a CLAUDE.md reminder.

**Atoms are truth, `_url`s are derived** — `src/cli/active.rs` is the single
derivation point. Device atoms: config `daemon` host + the port constants +
the default vault; vault history lives in `~/.safeclaw/known_vaults.toml`
(known_hosts-style). THE invariant: **proxy and control always derive from
the same daemon host** — when `$SAFECLAW_BROKER_URL` is set, its HOST feeds
`control_root` and every derived proxy URL, so an agent's shelled `sc` and
its own HTTP cannot target different daemons; worst case is a uniformly
stale snapshot, never a split. Vault precedence at the one choke point
(`resolve_active`): `--vault > $SAFECLAW_VAULT_ID (env pin) > config >
single-known auto-select`. Mint-time projections (`sc env`, `sc agent add`)
read DEVICE atoms only — never the env pins (a re-eval must not freeze its
own prior output). Remote is config, not code: hand-edit the daemon atom,
copy the PUBLIC `ca.pem` (`$SAFECLAW_CA_PATH`); `ca.key` never leaves.

**Auth:** the api-key is the AGENT's identity (agent ≡ api-key,
account-level) and the proxy verifies it **before any substitution** —
Proxy-Auth password on the proxy face, Bearer on the API face — against the
cloud-synced hash-set (in-memory, blob-external → works while locked).
Absent Proxy-Auth = blind tunnel (non-participating); present-but-wrong =
407. An auth miss with a key present triggers ONE debounced hash refresh (a
just-minted `sc agent add` key must not 407 for the 30s sync loop).

Discovery shape: `GET $BROKER_URL/v/$VAULT_ID/registry` → `{ services[],
connections:[{ id, hosts, connected, phantoms }] }` — **discovery returns the
ready-made phantom strings**; the agent copies, never constructs. The phantom
FORMAT lives in the skill's one-concept sentence; per-connection INSTANCES
live here; toml `setup` never carries phantom mechanics. Egress floor =
mainstream SSRF hygiene only (private/loopback/link-local IP literals +
`localhost` names; no `.internal` name blocks — a credential only reaches a
human-anchored host anyway). Skill stays generic; the shipped
`static/safeclaw-skill.md` is the canonical agent-facing text.

## 15. Superseded / Decided NOT to do (1–2 lines each; don't re-litigate)

- **Routing preflight / `phantom ⟺ routed` discipline — RETIRED (2026-07-06).**
  Probe host, `is_routed`, `sc status` routing block all deleted: opt-in means
  the agent routes explicitly, so the unrouted-phantom state isn't a detection
  problem (it's a clean upstream 401 by design).
- **Key-in-the-install-prompt (console pre-baked env) — REJECTED.** Puts a
  long-lived credential in the transcript AND bakes cloud-side assumptions
  about device atoms. The device-side minter (`sc agent add` → full dotenv
  block on stdout) achieves single-minter without either cost.
- **`sc env` emitting the agent key / a key-bearing PROXY_URL — REJECTED.**
  Device-scope tool; one device-level key would collapse per-agent
  revocation/audit.
- **`/use/<conn>/<path>` endpoint — RETIRED.** Two injection triggers (URL-conn +
  phantom) create conflict/precedence/缺省 combinatorics; phantom-only is one
  trigger. Raw connections are single-host, so a real upstream URL + phantom fully
  determines the call — `/use` adds nothing. (Shipped in v1; replaced wholesale,
  0 users.)
- **`/proxy` JSON endpoint — NOT built.** Redundant once the request goes through
  the actual HTTPS proxy with a phantom inline.
- **`/stream` (git) as a separate endpoint — RETIRED.** Streaming passes through
  the CONNECT proxy natively; git needs only the Basic-decode + credential-helper
  specials (§8), not its own route.
- **The 2×2 Fill×Transport matrix — GONE.** Collapsed to one surface + one
  trigger; the only remaining degree of freedom is env-bundle scope (§6).
- **Host-based auto-injection — FORBIDDEN.** Ambiguous under multi-account (two
  Gmails → googleapis.com) and violates transparent-cooperation ("inject only what
  the agent asked for, by phantom").
- **Old `sc run` = export-all-to-env-plaintext — DROPPED.** Dangerous, low-value;
  MITM + phantom serves the real need (tools reading a token from env) without
  plaintext in the process.
- **`<agent-key>@proxy` userinfo binding — DROPPED.** Over-design; a custom
  convention on top of phantoms. Localhost + session association already binds
  identity; the agent only needs "phantom is in my env."
- **No `allowed_hosts` side-table, no per-item bytes/sudp change** — ONE host
  concept: `Connection.hosts` (raw) / service-fixed (curated); `resolved_hosts()`
  abstracts it.
- **`Connection.config` — DELETED; `host` promoted to `Connection.hosts`.**
  (Reverses the earlier "don't promote": that decision's rationale — config as
  the uniform template-render source — died with the template layer; the anchor
  deserves typed write-time validation.)
- **No "trivial service" entity for raw** — raw = a connection with `service:
  None`; a service is *optional per-target type knowledge*, nothing more.
- **No `[consume.env]` / env-var-name hints in service tomls** — the env var *name* is
  the consuming tool's contract, which the agent knows natively; the vault
  maintaining tool conventions is the wrong layer (and `sc run` does NOT pre-set
  phantom env vars — the agent writes them).
- **No production taxonomy (`material`/direct|derived|minted)** — direct is the
  undeclared default; `[oauth2]` is the one named exception; `{{secret.X | b64|
  basic}}` egress filters are cut (served the retired header templates; YAGNI).
- **No eTLD+1 host matching — runtime enforcement is always exact FQDN.**
  `*.suffix` (mainstream single-label rule) exists ONLY in service `hosts` as a
  pinning constraint; instances pin exact hosts.
- **No host variable system (`{{host}}`/`{{resource}}`)** — exact | `*.suffix`
  only. Fully self-hosted = a raw connection (no service definition needed);
  self-hosted+OAuth deferred until a real case.
- **No conn-side full override of service hosts** — curated hosts are the
  audited anti-SSRF promise; override would degrade curated to raw-with-a-label.
- **No tool-named sections (`[git]`/`[docker]`)** — sections are auth
  mechanisms only.
- **`[basic]` DELETED too (its own existence trial)** — the scheme
  self-describes in the header; proxy decodes natively; pair construction =
  phantom placement (URL userinfo / `docker login -p`); the helper is optional,
  zero-schema, one documented global rule. Auth sections today = `[oauth2]`
  alone; future = the SIGNING family only (`[sigv4]`, `[web3sign]` — EIP-191/712
  semantics, Web3Signer-style remote signing) because signatures are computed
  FROM the request and can never be a textual substitution.
- **toml carries NO routing/transport information** — routing = the env bundle
  at some scope, or a tool's native per-command URL switch (setup prose only,
  e.g. npm `--registry`). cargo's local-git-index hack is deleted because cargo
  natively honours proxy+CA env ⇒ the bundle IS its adaptor on every path — not
  "because MITM exists".
- **No `broker.rs`/`approve.rs` rewrite** — additive over the existing 2-RTT flow.
- **No pre-storing encoded credential forms** — the vault stores the semantic value.
- **No baked "common host" hint list** — service-declared / agent deep-link / TOFU.
- **No provider-template layer** (retired 2026-07-08) — every `[oauth2]` is
  inline-complete (endpoints, client; a literal client_secret is a public
  client's by convention, review-enforced — the client_type assertion field is
  retired too). OAuth **connections** are self-serve via a **custom service
  toml** (per-vault `aux.services`, validated) → then added like any catalog
  service — NEVER an OAuth option inside
  the add-connection form (it would force an `oauth` field onto the 2-field
  connection record). Custom-toml authoring is a separate low-frequency
  surface: the v4 schema is what it accepts, nothing else.
- **No early sudo system-trust CA. No auto-covering an already-running process**
  (env can't retro-inject a live process → `sc run` or explicit).
- **No wildcard host (`*`)** — "any host" = silently exfiltratable; forbidden.
- **`/export` not forced into phantom** — it's a reveal, no upstream; kept as the
  human passkey act, agent surface 403.

## 16. Vision — agent-as-integrator (post-core)

User tells the agent *"put service X's API in my vault"*; the agent researches it,
proposes a connection **+ its host** via a deep-link, the human **anchors with one
passkey**; the agent never holds the raw secret. Everything is a connection
(degenerate or curated); the human-passkey gate on a secret→host binding **is** the
trust anchor. Foundation: the `feat/per-vault-custom-recipes` branch — absorb its useful parts (storage renamed `aux.services`, validator), then DELETE the branch + its worktrees. Gap: the agent-facing author path (deposit → passkey approve),
scoped to insertion-auth. The `system` category (§13) is the same idea turned
inward (agent proposes policy/service definitions to the daemon).
