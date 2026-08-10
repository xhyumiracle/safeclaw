//! SSE sync push — the daemon (Core) side of design/sse-sync.md.
//!
//! ONE `text/event-stream` connection per daemon replaces the per-vault PAIR
//! of ~25s long-polls as the wake TRANSPORT. Long-poll stays intact as the
//! per-vault fallback (stream down, vid not in hello, old backend, or
//! `sync_stream = "off"`). Events are hints, not data: nothing in this module
//! pulls or persists vault state — the dispatcher merges wake hints into
//! per-vault [`WakeCell`]s, and the vault watch tasks (`sync::watch_loop`)
//! react by running their existing cursor-gated pull paths, so a duplicated,
//! stale, or echoed event is a no-op by construction.
//!
//! Wire (backend `handleSyncStream`):
//!   `GET {cloud}/api/vault/sync/stream?vids=a,b,c` (Bearer device key) →
//!   `event: hello` with `{"vaults":{vid:{version,status}}}`, then `vault` /
//!   `items` / `keys` hint frames, `:ka` comment heartbeats every 20s.
//!   Pre-stream failures are plain JSON with 401/400/429/503. Railway
//!   hard-caps any request at ~15 min: stream EOF after a healthy run is
//!   ROTATION, not failure — see the state machine in [`dispatcher`].
//!
//! v1.1 adds two ACCOUNT-scoped event kinds on the same stream —
//! `agent_hashes` (api_keys changed) and `op` (an op_relay grant flipped) —
//! which have no vault cell to land in and route to the daemon-global
//! signals below instead. Same hints-not-data rule: the signals carry
//! nothing; the consumers re-run their existing fetch/poll paths, which stay
//! the source of truth.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use tokio::sync::{watch, Notify};

use crate::device_auth::DikRequestExt;

// ── Tunables (each one traces to a rule in design/sse-sync.md) ─────────

/// Backend `SSE_MAX_VIDS`. The route 400s the WHOLE request on any excess or
/// shape-violating vid, so the dispatcher filters here — an excluded vault
/// simply stays on its long-poll instead of poisoning the stream for all.
const MAX_STREAM_VIDS: usize = 32;
/// Budget from dial to response HEADERS on a normal connect.
const CONNECT_HEADERS_BUDGET: Duration = Duration::from_secs(10);
/// hello must land this soon after headers (the backend writes it right
/// behind them; anything slower is a middlebox sitting on the stream).
const HELLO_BUDGET: Duration = Duration::from_secs(5);
/// ★★ A rotation re-dial gets ONE attempt with this TOTAL budget (dial +
/// hello) before health flips Down (design doc: rotation-not-failure). Sized
/// to the full first-connect budget (10s headers + 5s hello): on a slow
/// corporate-proxy link where the TLS dial alone takes >5s, a tighter budget
/// would fail EVERY ~15-min rotation and churn all vault tasks through the
/// fallback shape — the exact churn the rotation rule exists to avoid. The
/// cost of the wider window is nil: vault tasks are parked on their cells
/// either way, and any write landing in the gap is covered by the next
/// hello's reconcile.
const ROTATION_REDIAL_BUDGET: Duration = Duration::from_secs(15);
/// No-bytes liveness: heartbeats arrive every 20s, so 45s of silence (two
/// missed heartbeats + slack) means the stream is dead even if the socket
/// hasn't noticed (laptop suspend, NAT table drop).
const LIVENESS: Duration = Duration::from_secs(45);
/// ★ A stream is only "proven" after this long healthy (post-hello). Backoff
/// reset and rotation treatment both key off it — NOT off hello — or a
/// middlebox that kills streams right after hello would hot-loop
/// hello+reconcile forever instead of decaying to slow retries.
const PROVEN_HEALTHY: Duration = Duration::from_secs(60);
const BACKOFF_MIN: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// 404 = backend without the route (version skew; the backend ships first).
const PARK_OLD_BACKEND: Duration = Duration::from_secs(600);
/// 401/403 — THE long-poll watcher's AUTH_RETRY, shared by construction so
/// the two shapes can never recover from an auth blip at different speeds:
/// park, never die; a transient blip (deploy, migration) must not end SSE
/// for the daemon's lifetime.
const PARK_AUTH: Duration = crate::sync::AUTH_RETRY;
/// 429 — the backend's per-account/global stream cap.
const PARK_CAP: Duration = Duration::from_secs(300);
/// ★★ Never-healthy escalation: after this many consecutive attempts none of
/// which reached PROVEN_HEALTHY, park PARK_NEVER_HEALTHY between tries — a
/// path that always kills the stream must cost ~144 attempts/day, not 1440
/// (each failed attempt also burns two backend snapshot queries).
const NEVER_HEALTHY_ESCALATION: u32 = 5;
const PARK_NEVER_HEALTHY: Duration = Duration::from_secs(600);
/// With `sync_stream = "off"` the dispatcher parks and re-reads the switch on
/// this tick, so flipping BACK to auto doesn't need a restart either.
const OFF_RECHECK: Duration = Duration::from_secs(60);

// ── Config switch ────────────────────────────────────────────────────────────

/// The `sync_stream` switch: `"off"` disables the stream (pure long-poll);
/// anything else — including the key being absent — is auto. Read by the
/// dispatcher at EVERY (re)connect (★★ design doc: flipping to "off" bites at
/// the next reconnect, ≤15 min under the Railway cap; restart for immediate
/// effect). `SAFECLAW_SYNC_STREAM` wins over config.toml because the env var
/// survives an old binary's config save (which drops unknown keys) — it is
/// the robust rollback lever.
pub fn sync_stream_enabled() -> bool {
    let v = std::env::var("SAFECLAW_SYNC_STREAM")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            crate::cli::active::load()
                .ok()
                .and_then(|c| c.sync_stream)
                .map(|s| s.trim().to_ascii_lowercase())
        });
    match v.as_deref() {
        None | Some("auto" | "on") => true,
        // A rollback lever that only accepts one spelling silently fails the
        // operator who reaches for "false"/"0" mid-incident — take the usual
        // synonyms.
        Some("off" | "0" | "false" | "no" | "disabled") => false,
        Some(other) => {
            // Unrecognized value: stay in the default (auto/on), but say so
            // ONCE — a misspelled kill switch must fail loudly, not silently.
            static WARNED: std::sync::Once = std::sync::Once::new();
            let other = other.to_string();
            WARNED.call_once(|| {
                tracing::warn!(
                    value = %other,
                    "sync_stream: unrecognized value (expected auto|off); treating as auto"
                );
            });
            true
        }
    }
}

// ── Per-vault merged pending-wake cell ───────────────────────────────────────

/// Which select! shape a vault's watch task runs this round. Set ONLY by the
/// dispatcher: `Sse` for vids confirmed by the current stream's hello,
/// `Fallback` (the default) otherwise. The task re-reads it at every loop top.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Sse,
    Fallback,
}

/// Cleartext lifecycle carried by a vault event / hello row — the projection
/// of the blob envelope's `status` field. `Deleted` is the tombstone, and in
/// Sse mode the EVENT is the lifecycle authority (same trust as the long-poll
/// body: authenticated TLS to our own backend).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStatus {
    Live,
    Deleted,
}

/// Global stream health, broadcast to every vault task. Fallback-mode tasks
/// keep a `changed()` arm in their long-poll select so recovery is noticed
/// within a hold instead of a full ~25s turnover; Sse-mode tasks use it to
/// fall back promptly when the stream dies. The dispatcher flips it with
/// `send_if_modified`, so an UNCHANGED value never wakes the tasks — that is
/// load-bearing for the rotation rule (health must not blip every ~15 min).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamHealth {
    Up,
    Down,
}

// ── Daemon-global signals (v1.1 — op_relay + agent-hash eventing) ───────────

/// Wakes `sync::sync_agent_keys_loop`. Fired on an `agent_hashes` stream
/// event and after EVERY reconnect hello (resync-on-reconnect, see
/// `run_stream`). A static, not AppState plumbing: the producers
/// (`dispatch_record` / `run_stream`) are free functions with no AppState
/// handle, and the sole consumer is spawned in main.rs BEFORE
/// `spawn_watchers` builds any stream state.
static AGENT_HASH_EVENTS: Notify = Notify::const_new();

/// Arm a wake on the agent-hash signal. `notify_one` semantics: a fire with
/// no waiter parks a permit, so an event landing while the consumer is
/// mid-fetch completes its NEXT wait instantly instead of being lost.
pub fn agent_hashes_notified() -> tokio::sync::futures::Notified<'static> {
    AGENT_HASH_EVENTS.notified()
}

fn notify_agent_hashes() {
    AGENT_HASH_EVENTS.notify_one();
}

/// Live op-relay pollers, keyed by op_id. A relay client registers before
/// its poll loop and deregisters via [`OpWaitGuard`]'s Drop — the guard IS
/// the registration, so no exit path (early error returns included) can
/// leak an entry into this daemon-lifetime map. The dispatcher notifies on
/// a matching `op` event; unknown op_ids are ignored (forward compatible:
/// another device's ceremony, an event racing a poller's exit, or an op
/// kind this build doesn't poll).
pub struct OpRegistry {
    // std Mutex, locked only inside these sync methods — never held across
    // an await (the module invariant shared with WakeCell).
    map: Mutex<HashMap<String, Arc<Notify>>>,
}

impl OpRegistry {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Register interest in `op_id`. Dropping the returned guard
    /// deregisters.
    pub fn register(&self, op_id: &str) -> OpWaitGuard<'_> {
        let notify = Arc::new(Notify::new());
        self.map
            .lock()
            .unwrap()
            .insert(op_id.to_string(), Arc::clone(&notify));
        OpWaitGuard {
            registry: self,
            op_id: op_id.to_string(),
            notify,
        }
    }

    /// Wake the poller registered for `op_id`, if any; says whether one was
    /// (the caller's log cue). Unknown ids are a silent no-op by design.
    fn notify(&self, op_id: &str) -> bool {
        let notify = self.map.lock().unwrap().get(op_id).map(Arc::clone);
        // Lock already dropped — signal outside it.
        match notify {
            Some(n) => {
                n.notify_one();
                true
            }
            None => false,
        }
    }
}

/// A live [`OpRegistry`] registration (guard pattern — Drop deregisters).
pub struct OpWaitGuard<'a> {
    registry: &'a OpRegistry,
    op_id: String,
    notify: Arc<Notify>,
}

impl OpWaitGuard<'_> {
    /// Arm a wake for this op's next stream event. `notify_one` parks a
    /// permit, so an event that fires between waits (while the poll response
    /// is in flight) completes the next wait instantly.
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }
}

impl Drop for OpWaitGuard<'_> {
    fn drop(&mut self) {
        let mut map = self.registry.map.lock().unwrap();
        // Remove only OUR registration: if the same op_id was re-registered
        // (shouldn't happen — one poll task per op — but cheap to be exact),
        // the newer entry must survive this older guard's drop.
        if map
            .get(&self.op_id)
            .is_some_and(|n| Arc::ptr_eq(n, &self.notify))
        {
            map.remove(&self.op_id);
        }
    }
}

/// The daemon-global op-event registry (relay pollers ↔ dispatcher).
pub fn op_events() -> &'static OpRegistry {
    static OP_EVENTS: LazyLock<OpRegistry> = LazyLock::new(OpRegistry::new);
    &OP_EVENTS
}

/// The dispatcher's health watch, re-exposed daemon-wide. Set once by
/// `sync::spawn_watchers` — the only place that knows whether streaming
/// exists for this daemon at all — and read through [`stream_healthy`] by
/// the consumers OUTSIDE the vault tasks (the agent-hash loop's cadence,
/// the relay pollers' interval). A OnceLock set by spawn_watchers rather
/// than a channel built at AppState construction because (a) main.rs spawns
/// `sync_agent_keys_loop` BEFORE `spawn_watchers`, and relay pollers spawn
/// at arbitrary times, so consumers can never assume the channel exists;
/// (b) an UNSET cell already reads as Down, which is the right answer in
/// every no-stream world (local-only daemon, unpaired device, watchers not
/// yet started) — AppState would have to fabricate a dead channel to say
/// the same thing, and thread sync_stream types through state.rs for it.
static STREAM_HEALTH: OnceLock<watch::Receiver<StreamHealth>> = OnceLock::new();

/// Called by `sync::spawn_watchers` right after it creates the health
/// channel. First caller wins (spawn_watchers runs once per process).
pub fn publish_stream_health(rx: watch::Receiver<StreamHealth>) {
    let _ = STREAM_HEALTH.set(rx);
}

/// Cheap point-read: is the stream currently proven up? Consumers use it to
/// pick a CADENCE, never as a data channel — a race with a health flip
/// costs one mis-sized sleep at worst, inside the bounds both cadences
/// already promise.
pub fn stream_healthy() -> bool {
    STREAM_HEALTH
        .get()
        .map(|rx| *rx.borrow() == StreamHealth::Up)
        .unwrap_or(false)
}

/// Await the NEXT health flip (either direction); pends forever when no
/// stream world exists. For consumers whose armed sleeps are mode-sized
/// (the agent-hash loop): a 600s streamed sleep must not ride across an
/// Up→Down flip — the 30s Down-mode promise is per-mode, not per-cycle.
pub async fn stream_health_edge() {
    let Some(rx) = STREAM_HEALTH.get() else {
        return std::future::pending::<()>().await;
    };
    let mut rx = rx.clone();
    // A fresh clone can carry an UNSEEN historical version — mark the
    // current value seen so this awaits the NEXT flip, not an old one
    // (else the caller's select would fire instantly, forever).
    let _ = rx.borrow_and_update();
    if rx.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// What the CURRENT stream actually delivers: the hello-confirmed vid set
/// plus the backend's declared optional event capabilities (`caps` in
/// hello). Consumers gate their RELAXED cadences on this, never on bare
/// health — "stream healthy" is strictly weaker than "the event I'm
/// waiting for can reach me": a v1-stream backend emits no `op` events at
/// all (version skew / rollback), and `op` events are delivered per-vid,
/// so a vault outside the streamed set (born after daemon start, over the
/// 32-vid cap, hello-rejected) never hears them either. Cleared on every
/// go_down; kept across a rotation (the gap is one re-dial budget, inside
/// the poll floors).
#[derive(Default)]
struct StreamCaps {
    vids: std::collections::HashSet<String>,
    op_events: bool,
    agent_hash_events: bool,
}

static STREAM_CAPS: LazyLock<Mutex<StreamCaps>> =
    LazyLock::new(|| Mutex::new(StreamCaps::default()));

/// Can THIS vault's `op` events actually reach this daemon right now?
/// Gates the relay poller's relaxed 15s cadence; anything short of proof
/// keeps the legacy 2s poll.
pub fn op_events_for(vid: &str) -> bool {
    let c = STREAM_CAPS.lock().unwrap();
    c.op_events && c.vids.contains(vid)
}

/// Does the connected backend emit `agent_hashes` events? Gates the
/// agent-hash loop's relaxed 600s cadence.
pub fn agent_hash_events_live() -> bool {
    STREAM_CAPS.lock().unwrap().agent_hash_events
}

fn set_stream_caps(vids: std::collections::HashSet<String>, caps: Option<&serde_json::Value>) {
    let list: Vec<&str> = caps
        .and_then(|c| c.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let mut s = STREAM_CAPS.lock().unwrap();
    s.op_events = list.contains(&"op");
    s.agent_hash_events = list.contains(&"agent_hashes");
    s.vids = vids;
}

fn clear_stream_caps() {
    *STREAM_CAPS.lock().unwrap() = StreamCaps::default();
}

/// The drained portion of a cell — what one watch-task round processes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Work {
    pub vault: Option<(u64, VaultStatus)>,
    pub items: bool,
    pub keys: bool,
}

impl Work {
    pub fn is_empty(&self) -> bool {
        self.vault.is_none() && !self.items && !self.keys
    }
}

#[derive(Debug)]
struct Pending {
    vault: Option<(u64, VaultStatus)>,
    items: bool,
    keys: bool,
    mode: Mode,
    /// ★★ "deleted" is STICKY for the cell's LIFETIME (survives `take_work`):
    /// backend emits from concurrent write handlers aren't serialized with
    /// commit order, and a stale hello can arrive after a fresher pre-hello
    /// event — latest-wins could resurrect a tombstone across the take
    /// boundary. A bit that only ever sets makes every interleaving harmless
    /// (the same shape as cursors-only-advance).
    deleted_sticky: bool,
}

/// Per-vault merged pending-wake cell + its wake signal. ★ A CELL, not a
/// queue (design doc): burst coalescing is free, there is no bounded-queue
/// head-of-line blocking, and a tombstone payload cannot be dropped. The
/// dispatcher merges, the owning vault task drains — take-then-process with
/// the standard missed-wakeup pattern (arm `notified()` BEFORE re-checking;
/// `notify_one`'s stored permit covers the race).
pub struct WakeCell {
    pending: Mutex<Pending>,
    notify: Notify,
}

impl Default for WakeCell {
    fn default() -> Self {
        Self::new()
    }
}

impl WakeCell {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(Pending {
                vault: None,
                items: false,
                keys: false,
                mode: Mode::Fallback,
                deleted_sticky: false,
            }),
            notify: Notify::new(),
        }
    }

    /// Arm a wake. Create this future BEFORE checking [`has_work`] — a merge
    /// landing in between is captured as a stored permit and completes the
    /// wait instantly.
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }

    pub fn mode(&self) -> Mode {
        self.pending.lock().unwrap().mode
    }

    /// Dispatcher-only. Notifies on an actual change so the owning task
    /// re-picks its select shape without waiting out a park.
    pub fn set_mode(&self, mode: Mode) {
        let changed = {
            let mut p = self.pending.lock().unwrap();
            if p.mode == mode {
                false
            } else {
                p.mode = mode;
                true
            }
        };
        if changed {
            self.notify.notify_one();
        }
    }

    /// ★★ MONOTONE merge of the vault slot: keep the HIGHER version, and
    /// "deleted" wins over "live" forever (see `deleted_sticky`). hello rows
    /// go through here exactly like live events — hello is only the
    /// connect-budget sentinel and mode-setter, never a gate on event
    /// processing or a fresher-than-events truth.
    pub fn merge_vault(&self, version: u64, status: VaultStatus) {
        {
            let mut p = self.pending.lock().unwrap();
            merge_vault_locked(&mut p, version, status);
        }
        self.notify.notify_one();
    }

    pub fn set_items(&self) {
        self.pending.lock().unwrap().items = true;
        self.notify.notify_one();
    }

    pub fn set_keys(&self) {
        self.pending.lock().unwrap().keys = true;
        self.notify.notify_one();
    }

    pub fn has_work(&self) -> bool {
        let p = self.pending.lock().unwrap();
        p.vault.is_some() || p.items || p.keys
    }

    /// Drain the pending work (mode and the deleted-sticky bit stay).
    pub fn take_work(&self) -> Work {
        let mut p = self.pending.lock().unwrap();
        Work {
            vault: p.vault.take(),
            items: std::mem::take(&mut p.items),
            keys: std::mem::take(&mut p.keys),
        }
    }

    /// Put drained-but-unprocessed work back (the Sse shape's bounded retry:
    /// ★ SSE delivers an event ONCE — unlike long-poll, where an unadvanced
    /// cursor makes the server re-answer the re-armed hold instantly — so a
    /// failed pull must not lose the hint). MERGES, so a fresher event that
    /// landed since the take wins. Deliberately no notify: the owner retries
    /// on its own backoff.
    pub fn reinject(&self, w: Work) {
        if w.is_empty() {
            return;
        }
        let mut p = self.pending.lock().unwrap();
        if let Some((version, status)) = w.vault {
            merge_vault_locked(&mut p, version, status);
        }
        p.items |= w.items;
        p.keys |= w.keys;
    }
}

fn merge_vault_locked(p: &mut Pending, version: u64, status: VaultStatus) {
    if status == VaultStatus::Deleted {
        p.deleted_sticky = true;
    }
    let v = p.vault.map(|(v, _)| v.max(version)).unwrap_or(version);
    let s = if p.deleted_sticky {
        VaultStatus::Deleted
    } else {
        VaultStatus::Live
    };
    p.vault = Some((v, s));
}

// ── SSE wire parser ──────────────────────────────────────────────────────────

/// One parsed event-stream record. `event` defaults to "message" (spec) when
/// the field is absent — our protocol always names it.
#[derive(Debug, PartialEq, Eq)]
pub struct SseRecord {
    pub event: String,
    pub data: String,
}

/// Upper bound on buffered unparsed bytes. Hint frames are ~100 bytes; only a
/// broken/hostile peer produces more. On overflow the buffer and half-built
/// record are dropped — the parser resyncs at the next record boundary, and a
/// lost hint is recovered by the reconcile floor (hints are best-effort).
const PARSER_BUF_CAP: usize = 256 * 1024;

/// Hand-rolled `text/event-stream` parser over a BYTE buffer. Chunk-boundary
/// safe by construction: bytes accumulate until a COMPLETE line exists, so a
/// record — or a multi-byte UTF-8 sequence — split across chunks reassembles
/// before any decoding happens (line terminators are single-byte ASCII, and
/// UTF-8 continuation bytes can never equal `\r`/`\n`, so a complete line
/// always holds whole sequences). Handles `\n`, `\r\n` and lone `\r`
/// terminators, `:` comment lines (the `:ka` heartbeat), multi-line `data:`
/// (joined with `\n` per spec), and ignores unknown fields (`id:`/`retry:`).
pub struct SseParser {
    buf: Vec<u8>,
    event: Option<String>,
    data: Option<String>,
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SseParser {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            event: None,
            data: None,
        }
    }

    /// Feed one network chunk; returns every record COMPLETED by it.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseRecord> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut pos = 0;
        while let Some((end, term)) = find_line(&self.buf[pos..]) {
            let line = self.buf[pos..pos + end].to_vec();
            pos += end + term;
            self.consume_line(&line, &mut out);
        }
        self.buf.drain(..pos);
        // The cap must count the HALF-BUILT RECORD too, not just unparsed
        // bytes: endless well-terminated `data:` lines with no blank-line
        // record boundary drain `buf` on every push while `data` grows
        // without bound (a garbling middlebox or a peer bug — the daemon
        // must not OOM on either).
        let pending = self.buf.len() + self.data.as_ref().map_or(0, |d| d.len());
        if pending > PARSER_BUF_CAP {
            // Pathological input — drop it (see cap note); the parser
            // resyncs at the next record boundary.
            self.buf.clear();
            self.event = None;
            self.data = None;
        }
        out
    }

    fn consume_line(&mut self, line: &[u8], out: &mut Vec<SseRecord>) {
        if line.is_empty() {
            // Blank line = record boundary. Per spec: dispatch only if data
            // accumulated; either way both field buffers reset.
            if let Some(data) = self.data.take() {
                out.push(SseRecord {
                    event: self.event.take().unwrap_or_else(|| "message".to_string()),
                    data,
                });
            } else {
                self.event = None;
            }
            return;
        }
        if line[0] == b':' {
            return; // comment — the `:ka` heartbeat lands here
        }
        let (name, value) = match line.iter().position(|&b| b == b':') {
            Some(i) => {
                let v = &line[i + 1..];
                // Exactly one leading space after the colon is field syntax.
                let v = if v.first() == Some(&b' ') { &v[1..] } else { v };
                (&line[..i], v)
            }
            None => (line, &line[..0]), // field name with empty value (spec)
        };
        // A complete line is the UTF-8 reassembly unit (see the type doc);
        // lossy conversion only fires on genuinely invalid bytes, and a hint
        // stream must never die on those (wide-boundary discipline).
        let value = String::from_utf8_lossy(value);
        match name {
            b"event" => self.event = Some(value.into_owned()),
            b"data" => match &mut self.data {
                Some(d) => {
                    d.push('\n');
                    d.push_str(&value);
                }
                None => self.data = Some(value.into_owned()),
            },
            _ => {}
        }
    }
}

/// First complete line in `buf`: `(content_len, terminator_len)`. A `\r` as
/// the LAST byte returns None — its `\n` may be in the next chunk, and one
/// terminator must never be read as two.
fn find_line(buf: &[u8]) -> Option<(usize, usize)> {
    for (i, &b) in buf.iter().enumerate() {
        match b {
            b'\n' => return Some((i, 1)),
            b'\r' => {
                if i + 1 == buf.len() {
                    return None;
                }
                return Some((i, if buf[i + 1] == b'\n' { 2 } else { 1 }));
            }
            _ => {}
        }
    }
    None
}

// ── Dispatcher — the connection owner ────────────────────────────────────────

/// How one stream attempt ended.
enum StreamEnd {
    /// hello was reached; the stream then lived `healthy_for` before dying.
    Died { healthy_for: Duration, why: String },
    /// Never reached hello.
    Failed(ConnectFail),
}

enum ConnectFail {
    /// 404 — backend without the route (version skew).
    OldBackend,
    /// 401 | 403.
    Auth(u16),
    /// 429 — stream cap.
    Cap,
    /// Network/timeout/unexpected status — the backoff path.
    Transient(String),
}

/// The SSE connection owner, spawned once by `sync::spawn_watchers` next to
/// the per-vault watch tasks. Holds only WEAK cell refs: a vault task that
/// exits (tombstone) drops the sole strong ref, and the failed upgrade at the
/// next (re)connect is how the vid leaves `?vids` — no back-channel needed.
///
/// State machine (design/sse-sync.md, backoff/flap discipline):
///  - connect budget 10s-to-headers + 5s-to-hello; 45s no-bytes liveness.
///  - ★★ death after ≥60s healthy = ROTATION (Railway's ~15-min cap):
///    immediate re-dial, no backoff, health STAYS Up; Down only if that one
///    re-dial misses hello in ~5s. The hello reconcile covers the gap.
///  - failures: backoff 2s→60s ±20% jitter, reset only after healthy ≥60s;
///    ★★ 5 consecutive never-healthy attempts → 600s parks. 404 → 600s,
///    401/403 → 600s, 429 → 300s.
pub async fn dispatcher(
    cloud: String,
    dk: String,
    cells: Vec<(String, Weak<WakeCell>)>,
    health: watch::Sender<StreamHealth>,
) {
    let cloud = cloud.trim_end_matches('/').to_string();
    let mut backoff = BACKOFF_MIN;
    let mut never_healthy: u32 = 0;
    let mut rotating = false;
    let mut announced_old_backend = false;
    let mut announced_off = false;
    tracing::debug!(vaults = cells.len(), "sync stream: dispatcher started");
    loop {
        // Prune: a tombstoned vault's task exited and dropped its cell.
        let live: Vec<(String, Arc<WakeCell>)> = cells
            .iter()
            .filter_map(|(vid, w)| w.upgrade().map(|c| (vid.clone(), c)))
            .collect();
        if live.is_empty() {
            clear_stream_caps();
            let _ = health.send(StreamHealth::Down);
            tracing::debug!("sync stream: no vaults left to stream; dispatcher exiting");
            return;
        }

        // ★★ The switch is read at EVERY (re)connect.
        if !sync_stream_enabled() {
            // Announced on ENTERING the off state, not keyed on the health
            // edge — at boot health is already Down and go_down() reports no
            // flip, which would leave the operator's rollback flip with zero
            // acknowledgment in the logs.
            go_down(&health, live.iter().map(|(_, c)| c));
            if !announced_off {
                announced_off = true;
                tracing::info!("sync stream: disabled (sync_stream=off); long-poll only");
            }
            rotating = false;
            tokio::time::sleep(OFF_RECHECK).await;
            continue;
        }
        announced_off = false; // re-entering off later announces again

        // This attempt's vid set (see MAX_STREAM_VIDS for why we filter).
        let mut stream_cells: HashMap<String, Arc<WakeCell>> = HashMap::new();
        for (vid, cell) in &live {
            if stream_cells.len() >= MAX_STREAM_VIDS {
                tracing::debug!(vault = %vid, "sync stream: over the {}-vid route cap; vault stays on long-poll", MAX_STREAM_VIDS);
                continue;
            }
            if vid_shape_ok(vid) {
                stream_cells.insert(vid.clone(), Arc::clone(cell));
            } else {
                tracing::debug!(vault = %vid, "sync stream: vid fails the route shape; vault stays on long-poll");
            }
        }
        if stream_cells.is_empty() {
            go_down(&health, live.iter().map(|(_, c)| c));
            tokio::time::sleep(OFF_RECHECK).await;
            continue;
        }
        let mut vids: Vec<&str> = stream_cells.keys().map(|s| s.as_str()).collect();
        vids.sort_unstable(); // stable param across reconnects
        let vids_param = vids.join(",");

        match run_stream(&cloud, &dk, &stream_cells, &vids_param, &health, rotating).await {
            StreamEnd::Died { healthy_for, why } => {
                announced_old_backend = false; // hello proved the route exists
                if healthy_for >= PROVEN_HEALTHY {
                    // ★★ ROTATION, not failure: Railway caps any request at
                    // ~15 min, so a proven-healthy stream ending is ROUTINE.
                    // Re-dial immediately and keep health Up — vault tasks
                    // must not churn select shapes or fire fallback
                    // long-polls every 15 min. The new hello's unconditional
                    // reconcile covers writes landing in the gap; debug-level
                    // for the same reason (overnight-soak logs stay clean).
                    backoff = BACKOFF_MIN;
                    never_healthy = 0;
                    rotating = true;
                    tracing::debug!(
                        healthy_secs = healthy_for.as_secs(),
                        why = %why,
                        "sync stream: rotation — re-dialing immediately"
                    );
                    // Sub-second jittered spread, not a backoff: a deploy
                    // drain closes the WHOLE fleet's streams in the same
                    // instant, and every healthy daemon classifies that as
                    // rotation — without jitter they re-dial in lockstep
                    // against the instance that is mid-drain or just booting.
                    tokio::time::sleep(jittered(Duration::from_millis(750))).await;
                    continue;
                }
                // Died young (post-hello, < PROVEN_HEALTHY): something on the
                // path tolerates the connect but kills held streams. Real
                // failure — decay, and escalate if it never stops.
                never_healthy = never_healthy.saturating_add(1);
                rotating = false;
                let flipped = go_down(&health, stream_cells.values());
                let delay = park_or_backoff(&mut backoff, never_healthy);
                // First death of the streak only: every died-young attempt
                // reached hello and flipped health Up, so `flipped` is true
                // EVERY cycle here — gating the warn on it alone would spam
                // one warn per attempt against a stream-killing middlebox.
                if flipped && never_healthy == 1 {
                    tracing::warn!(
                        healthy_secs = healthy_for.as_secs(),
                        why = %why,
                        retry_secs = delay.as_secs(),
                        "sync stream: died before proven healthy; vaults fall back to long-poll"
                    );
                } else {
                    tracing::debug!(
                        healthy_secs = healthy_for.as_secs(),
                        why = %why,
                        retry_secs = delay.as_secs(),
                        "sync stream: died young again"
                    );
                }
                tokio::time::sleep(delay).await;
            }
            StreamEnd::Failed(fail) => {
                rotating = false;
                let flipped = go_down(&health, stream_cells.values());
                match fail {
                    ConnectFail::OldBackend => {
                        if !announced_old_backend {
                            tracing::info!(
                                retry_secs = PARK_OLD_BACKEND.as_secs(),
                                "sync stream: backend has no stream route (404); long-poll only for now"
                            );
                            announced_old_backend = true;
                        }
                        tokio::time::sleep(PARK_OLD_BACKEND).await;
                    }
                    ConnectFail::Auth(code) => {
                        // Park, don't die — the long-poll AUTH_RETRY rule.
                        tracing::warn!(
                            retry_secs = PARK_AUTH.as_secs(),
                            "sync stream: auth rejected (HTTP {}); retrying",
                            code
                        );
                        tokio::time::sleep(PARK_AUTH).await;
                    }
                    ConnectFail::Cap => {
                        tracing::info!(
                            retry_secs = PARK_CAP.as_secs(),
                            "sync stream: server stream cap hit (429); retrying"
                        );
                        tokio::time::sleep(PARK_CAP).await;
                    }
                    ConnectFail::Transient(e) => {
                        never_healthy = never_healthy.saturating_add(1);
                        let delay = park_or_backoff(&mut backoff, never_healthy);
                        // Event-driven logging: one warn on the Up→Down edge,
                        // debug while already down (no per-cycle spam).
                        if flipped {
                            tracing::warn!(
                                retry_secs = delay.as_secs(),
                                "sync stream: connect failed ({}); vaults fall back to long-poll",
                                e
                            );
                        } else {
                            tracing::debug!(
                                retry_secs = delay.as_secs(),
                                "sync stream: connect failed ({})",
                                e
                            );
                        }
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    }
}

/// One dial → hello → pump cycle. Returns how it ended (never panics the
/// dispatcher loop). `rotating` selects the tighter one-shot budget and the
/// debug-level reconnect log.
async fn run_stream(
    cloud: &str,
    dk: &str,
    cells: &HashMap<String, Arc<WakeCell>>,
    vids_param: &str,
    health: &watch::Sender<StreamHealth>,
    rotating: bool,
) -> StreamEnd {
    use futures_util::StreamExt;
    // ★ Fresh client on EVERY (re)connect — proxy config applied at build
    // time, so a runtime `sc proxy set` reaches the stream at its next dial
    // (the hot-reload contract). Connect budget only: a total `.timeout()`
    // would fire mid-body and kill a healthy held-open stream.
    let client = match crate::cli::egress_proxy::client_streaming(CONNECT_HEADERS_BUDGET) {
        Ok(c) => c,
        Err(e) => return StreamEnd::Failed(ConnectFail::Transient(format!("client init: {}", e))),
    };
    let url = format!("{}/api/vault/sync/stream?vids={}", cloud, vids_param);
    let started = Instant::now();
    let headers_budget = if rotating {
        ROTATION_REDIAL_BUDGET
    } else {
        CONNECT_HEADERS_BUDGET
    };
    let resp = match tokio::time::timeout(
        headers_budget,
        client
            .get(&url)
            .bearer_auth(dk)
            .dik_pop("GET", &url, &[])
            .send(),
    )
    .await
    {
        Err(_) => {
            return StreamEnd::Failed(ConnectFail::Transient(
                "no response headers within budget".into(),
            ))
        }
        Ok(Err(e)) => return StreamEnd::Failed(ConnectFail::Transient(format!("connect: {}", e))),
        Ok(Ok(r)) => r,
    };
    match resp.status().as_u16() {
        200 => {}
        404 => return StreamEnd::Failed(ConnectFail::OldBackend),
        code @ (401 | 403) => return StreamEnd::Failed(ConnectFail::Auth(code)),
        429 => return StreamEnd::Failed(ConnectFail::Cap),
        other => return StreamEnd::Failed(ConnectFail::Transient(format!("HTTP {}", other))),
    }

    let mut stream = resp.bytes_stream();
    let mut parser = SseParser::new();
    // A rotation re-dial spends ONE total budget across dial + hello.
    let hello_wait = if rotating {
        ROTATION_REDIAL_BUDGET.saturating_sub(started.elapsed())
    } else {
        HELLO_BUDGET
    };
    let hello = match tokio::time::timeout(
        hello_wait,
        read_until_hello(&mut stream, &mut parser, cells),
    )
    .await
    {
        Err(_) => {
            return StreamEnd::Failed(ConnectFail::Transient("no hello within budget".into()))
        }
        Ok(Err(e)) => return StreamEnd::Failed(ConnectFail::Transient(e)),
        Ok(Ok(h)) => h,
    };

    // Modes + merges FIRST, the health edge second: a fallback task woken by
    // the Up edge re-reads its mode at the loop top and must see the final
    // value, never a stale Fallback.
    let n = apply_hello(cells, &hello);
    // ★ Resync-on-reconnect (v1.1): the dominant way to LOSE an
    // `agent_hashes` event is a stream disconnect — and the reconnect the
    // loss forces is exactly where we stand now, so firing the notify here
    // turns the failure mode into the recovery. With Railway rotating every
    // stream ≤15 min, the platform itself becomes the revocation backstop: a
    // revoke whose event fell into a gap goes unseen for at most one
    // rotation before this resync picks it up.
    notify_agent_hashes();
    health.send_if_modified(|h| {
        if *h == StreamHealth::Up {
            false
        } else {
            *h = StreamHealth::Up;
            true
        }
    });
    if rotating {
        tracing::debug!(vaults = n, "sync stream: reconnected (rotation)");
    } else {
        tracing::info!(
            vaults = n,
            requested = cells.len(),
            "sync stream: connected"
        );
    }

    let hello_at = Instant::now();
    loop {
        match tokio::time::timeout(LIVENESS, stream.next()).await {
            // 45s with no bytes (heartbeats come every 20s): the stream is
            // dead even if the socket hasn't noticed.
            Err(_) => {
                return StreamEnd::Died {
                    healthy_for: hello_at.elapsed(),
                    why: "no bytes for 45s".into(),
                }
            }
            // Clean EOF — the normal Railway ~15-min rotation.
            Ok(None) => {
                return StreamEnd::Died {
                    healthy_for: hello_at.elapsed(),
                    why: "eof".into(),
                }
            }
            Ok(Some(Err(e))) => {
                return StreamEnd::Died {
                    healthy_for: hello_at.elapsed(),
                    why: e.to_string(),
                }
            }
            Ok(Some(Ok(chunk))) => {
                for rec in parser.push(chunk.as_ref()) {
                    dispatch_record(cells, &rec);
                }
            }
        }
    }
}

/// Read records until the hello frame shows up, returning its parsed data.
/// ★★ Events received BEFORE hello merge into cells exactly like any other
/// event — hello is only the connect-budget sentinel, the mode-setter and the
/// per-vault reconcile trigger, never a gate: the backend registers vids
/// BEFORE its snapshot query, so an event can legitimately hit the wire
/// first. (Records parsed from the same chunk AFTER hello dispatch too —
/// their pre-apply_hello ordering is harmless because merges are monotone.)
async fn read_until_hello<S, B>(
    stream: &mut S,
    parser: &mut SseParser,
    cells: &HashMap<String, Arc<WakeCell>>,
) -> Result<serde_json::Value, String>
where
    S: futures_util::Stream<Item = Result<B, reqwest::Error>> + Unpin,
    B: AsRef<[u8]>,
{
    use futures_util::StreamExt;
    loop {
        let chunk = match stream.next().await {
            None => return Err("stream ended before hello".into()),
            Some(Err(e)) => return Err(format!("read before hello: {}", e)),
            Some(Ok(c)) => c,
        };
        let mut hello = None;
        for rec in parser.push(chunk.as_ref()) {
            if rec.event == "hello" && hello.is_none() {
                hello = Some(
                    serde_json::from_str::<serde_json::Value>(&rec.data)
                        .map_err(|e| format!("undecodable hello: {}", e))?,
                );
            } else {
                dispatch_record(cells, &rec);
            }
        }
        if let Some(h) = hello {
            return Ok(h);
        }
    }
}

/// Fold a hello snapshot into the cells: rows merge EXACTLY like live vault
/// events (monotone — a stale hello racing a fresher pre-hello event cannot
/// regress a cell), plus items/keys flags, so every streamed vault runs one
/// cursor-gated reconcile round. (Re)connect ≡ reconcile — this is what makes
/// the zero-churn rotation window safe. Requested vids MISSING from hello are
/// not owned by this account (or hard-deleted): the backend did not register
/// them, so long-poll keeps owning those vaults (mode → Fallback). Returns
/// how many vids hello confirmed.
fn apply_hello(cells: &HashMap<String, Arc<WakeCell>>, hello: &serde_json::Value) -> usize {
    let vaults = hello.get("vaults").and_then(|v| v.as_object());
    let mut n = 0usize;
    let mut confirmed = std::collections::HashSet::new();
    for (vid, cell) in cells {
        match vaults.and_then(|m| m.get(vid)) {
            Some(row) => {
                n += 1;
                confirmed.insert(vid.clone());
                let (version, status) = parse_vault_hint(row);
                cell.merge_vault(version, status);
                cell.set_items();
                cell.set_keys();
                cell.set_mode(Mode::Sse);
            }
            None => cell.set_mode(Mode::Fallback),
        }
    }
    // Publish what this stream can actually deliver (confirmed vids + the
    // backend's declared caps) BEFORE health flips Up — a consumer woken by
    // the Up edge must never read stale reach.
    set_stream_caps(confirmed, hello.get("caps"));
    n
}

/// Route one parsed record into its vault's cell, or (v1.1) an
/// account-scoped event into its daemon-global signal. Unknown event kinds,
/// unknown vids and unknown op_ids are ignored (forward compatibility —
/// hints are best-effort by design). `items.seq` is deliberately unused: the
/// hint means "just pull"; the pull's own cursor decides what is new. Same
/// rule for the v1.1 payloads: nothing beyond ROUTING is trusted — the
/// consumers re-fetch/re-poll and their responses are the truth.
fn dispatch_record(cells: &HashMap<String, Arc<WakeCell>>, rec: &SseRecord) {
    // Account-scoped, payload-free: `data` is `{}` today and deliberately
    // not parsed (the consumer re-fetches the WHOLE hash-set regardless), so
    // this routes before the JSON gate — a garbled body must still wake it.
    if rec.event == "agent_hashes" {
        notify_agent_hashes();
        return;
    }
    let Ok(data) = serde_json::from_str::<serde_json::Value>(&rec.data) else {
        tracing::debug!(event = %rec.event, "sync stream: undecodable event data; ignoring");
        return;
    };
    if rec.event == "hello" {
        // Not expected mid-stream, but folding it like a fresh snapshot is
        // strictly harmless (merges are monotone) — and it counts as a
        // resync point, so fire the agent-hash notify exactly like the
        // connect-time hello does (design: after EVERY apply_hello).
        apply_hello(cells, &data);
        notify_agent_hashes();
        return;
    }
    if rec.event == "op" {
        // {"vid","op_id","status"} — op_id routes; status is log color only
        // (the poller's next poll response is the real status either way).
        if let Some(op_id) = data.get("op_id").and_then(|v| v.as_str()) {
            if op_events().notify(op_id) {
                // Event-driven by construction: one line per grant flip.
                tracing::debug!(
                    op = %op_id,
                    status = data.get("status").and_then(|s| s.as_str()).unwrap_or("?"),
                    "sync stream: op event; waking relay poller"
                );
            }
        }
        return;
    }
    let Some(cell) = data
        .get("vid")
        .and_then(|v| v.as_str())
        .and_then(|vid| cells.get(vid))
    else {
        return;
    };
    match rec.event.as_str() {
        "vault" => {
            let (version, status) = parse_vault_hint(&data);
            cell.merge_vault(version, status);
        }
        "items" => cell.set_items(),
        "keys" => cell.set_keys(),
        _ => {}
    }
}

/// The ONE decode of a wire vault row/event `{version, status}` — hello rows
/// and live `vault` events are the same wire object and MUST classify
/// identically (a decode edited in one place only would make hello and events
/// disagree on a vault's lifecycle, and the monotone merge would quietly mask
/// the divergence). Absent/odd version → 0 (merges as no-op); anything but an
/// explicit "deleted" is Live — only an explicit tombstone ever destroys.
fn parse_vault_hint(v: &serde_json::Value) -> (u64, VaultStatus) {
    let version = v.get("version").and_then(|x| x.as_u64()).unwrap_or(0);
    let status = if v.get("status").and_then(|x| x.as_str()) == Some("deleted") {
        VaultStatus::Deleted
    } else {
        VaultStatus::Live
    };
    (version, status)
}

/// Demote every given cell to Fallback FIRST, then flip health — a task woken
/// by the health edge re-reads its mode and must observe the final value.
/// Returns whether health actually changed: the caller's warn-vs-debug cue
/// (event-driven logs, no per-cycle spam).
fn go_down<'a>(
    health: &watch::Sender<StreamHealth>,
    cells: impl Iterator<Item = &'a Arc<WakeCell>>,
) -> bool {
    // Reach first: consumers must stop trusting the stream's event delivery
    // before (or at worst, at the same wake as) they see the health edge.
    clear_stream_caps();
    for c in cells {
        c.set_mode(Mode::Fallback);
    }
    health.send_if_modified(|h| {
        if *h == StreamHealth::Down {
            false
        } else {
            *h = StreamHealth::Down;
            true
        }
    })
}

/// Backoff/park arithmetic shared by young-death and transient-connect
/// failures: doubling 2s→60s with ±20% jitter, escalating to a 600s park
/// after NEVER_HEALTHY_ESCALATION consecutive never-proven attempts.
fn park_or_backoff(backoff: &mut Duration, never_healthy: u32) -> Duration {
    let delay = if never_healthy >= NEVER_HEALTHY_ESCALATION {
        PARK_NEVER_HEALTHY
    } else {
        jittered(*backoff)
    };
    *backoff = (*backoff * 2).min(BACKOFF_MAX);
    delay
}

/// ±20% jitter so a fleet of daemons whose streams die together (deploy
/// drain, a Railway rotation burst) doesn't reconnect in lockstep.
fn jittered(d: Duration) -> Duration {
    use rand::Rng;
    d.mul_f64(rand::thread_rng().gen_range(0.8..=1.2))
}

/// Backend route shape `^[0-9a-f-]{1,64}$` — mirrored so one odd vid can't
/// 400 the whole connect for every vault.
fn vid_shape_ok(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: this is the ONLY test that touches the process-global
    // STREAM_CAPS (parallel test threads would race a second one).
    #[test]
    fn stream_caps_gate_relaxed_cadences() {
        clear_stream_caps();
        assert!(!op_events_for("aaaa"));
        assert!(!agent_hash_events_live());
        let vids: std::collections::HashSet<String> = ["aaaa".to_string()].into_iter().collect();
        set_stream_caps(vids, Some(&serde_json::json!(["op", "agent_hashes"])));
        assert!(op_events_for("aaaa"));
        assert!(!op_events_for("bbbb")); // vid not on the stream → no proof
        assert!(agent_hash_events_live());
        // v1 backend: hello carries no caps → confirmed vids alone must NOT
        // relax any cadence (the version-skew case this mechanism exists for).
        let vids: std::collections::HashSet<String> = ["aaaa".to_string()].into_iter().collect();
        set_stream_caps(vids, None);
        assert!(!op_events_for("aaaa"));
        assert!(!agent_hash_events_live());
        clear_stream_caps();
    }

    // ── SSE parser ──

    #[test]
    fn parser_caps_unbounded_data_accumulation() {
        // Endless well-terminated `data:` lines with no blank-line record
        // boundary drain `buf` every push — the cap must count the half-built
        // record's `data` too, or a garbling middlebox OOMs the daemon.
        let mut p = SseParser::new();
        let line = format!("data: {}\n", "x".repeat(1024));
        for _ in 0..(PARSER_BUF_CAP / 1024 + 8) {
            assert!(p.push(line.as_bytes()).is_empty());
            // THE property: retained memory stays bounded near the cap at
            // every point, no matter how long the hostile stream runs.
            let held = p.buf.len() + p.data.as_ref().map_or(0, |d| d.len());
            assert!(held <= PARSER_BUF_CAP + 2 * 1024, "held {} bytes", held);
        }
        // Resync: a record after the next boundary still parses; any residue
        // accumulated since the cap-drop dispatches first, far below the cap.
        let recs = p.push(b"\nevent: items\ndata: {\"vid\":\"a\"}\n\n");
        let last = recs.last().expect("fresh record parses after resync");
        assert_eq!(last.event, "items");
        assert!(recs.iter().all(|r| r.data.len() < PARSER_BUF_CAP / 2));
    }

    #[test]
    fn parser_multiple_records_and_comments_one_chunk() {
        let mut p = SseParser::new();
        let recs = p.push(
            b"event: vault\ndata: {\"vid\":\"a\"}\n\n:ka\n\nevent: items\ndata: {\"vid\":\"b\"}\n\n",
        );
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].event, "vault");
        assert_eq!(recs[0].data, "{\"vid\":\"a\"}");
        assert_eq!(recs[1].event, "items");
        assert_eq!(recs[1].data, "{\"vid\":\"b\"}");
    }

    /// Every possible split point — including inside the multi-byte UTF-8
    /// sequences — must reassemble losslessly (bytes buffer until a complete
    /// line exists).
    #[test]
    fn parser_reassembles_record_split_mid_utf8() {
        let mut p = SseParser::new();
        let frame = "event: vault\ndata: {\"vid\":\"héllo→世\"}\n\n".as_bytes();
        let mut recs = Vec::new();
        for b in frame {
            recs.extend(p.push(std::slice::from_ref(b)));
        }
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].event, "vault");
        assert_eq!(recs[0].data, "{\"vid\":\"héllo→世\"}");
    }

    /// CRLF terminators, a `\r\n` split ACROSS chunks (the trailing `\r` must
    /// wait for its possible `\n`), and lone-`\r` terminators.
    #[test]
    fn parser_tolerates_crlf_split_crlf_and_lone_cr() {
        let mut p = SseParser::new();
        let mut recs = p.push(b"event: keys\r\ndata: {\"vid\":\"c\"}\r\n\r");
        assert!(recs.is_empty(), "trailing \\r must wait for the next byte");
        recs.extend(p.push(b"\n"));
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].event, "keys");
        assert_eq!(recs[0].data, "{\"vid\":\"c\"}");

        // Lone \r as terminator (spec-legal).
        let recs = p.push(b"data: y\r\rdata: z\n\n");
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].data, "y");
        assert_eq!(recs[1].data, "z");
    }

    #[test]
    fn parser_joins_multiline_data_and_ignores_unknown_fields() {
        let mut p = SseParser::new();
        let recs = p.push(b"id: 7\nevent: hello\ndata: line1\ndata: line2\nretry: 100\n\n");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].event, "hello");
        assert_eq!(recs[0].data, "line1\nline2");
    }

    #[test]
    fn parser_default_event_and_no_space_after_colon() {
        let mut p = SseParser::new();
        let recs = p.push(b"data:x\n\n");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].event, "message");
        assert_eq!(recs[0].data, "x");
    }

    /// A record whose head arrived in one chunk and tail in another (split
    /// mid-field-name) is one record, not garbage.
    #[test]
    fn parser_record_split_mid_field_across_chunks() {
        let mut p = SseParser::new();
        let mut recs = p.push(b"eve");
        recs.extend(p.push(b"nt: vault\nda"));
        recs.extend(p.push(b"ta: {}\n"));
        assert!(recs.is_empty(), "record not complete until the blank line");
        recs.extend(p.push(b"\n"));
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].event, "vault");
        assert_eq!(recs[0].data, "{}");
    }

    // ── Monotone cell merge ──

    /// The stale-hello-after-fresher-event race: higher version wins no
    /// matter the arrival order.
    #[test]
    fn cell_merge_is_monotone_across_stale_hello() {
        let c = WakeCell::new();
        c.merge_vault(7, VaultStatus::Live); // pre-hello event
        c.merge_vault(5, VaultStatus::Live); // stale hello row
        let w = c.take_work();
        assert_eq!(w.vault, Some((7, VaultStatus::Live)));
        assert!(!c.has_work());
    }

    /// "deleted" is sticky for the CELL's lifetime — a later (even
    /// higher-versioned) "live" cannot resurrect the tombstone, including
    /// after a take.
    #[test]
    fn cell_deleted_is_sticky_for_cell_lifetime() {
        let c = WakeCell::new();
        c.merge_vault(4, VaultStatus::Deleted);
        c.merge_vault(9, VaultStatus::Live);
        assert_eq!(c.take_work().vault, Some((9, VaultStatus::Deleted)));
        c.merge_vault(10, VaultStatus::Live);
        assert_eq!(c.take_work().vault, Some((10, VaultStatus::Deleted)));
    }

    #[test]
    fn cell_take_clears_work_keeps_mode() {
        let c = WakeCell::new();
        assert_eq!(c.mode(), Mode::Fallback);
        c.set_mode(Mode::Sse);
        c.set_items();
        c.set_keys();
        let w = c.take_work();
        assert!(w.items && w.keys && w.vault.is_none());
        assert!(!c.has_work());
        assert_eq!(c.mode(), Mode::Sse);
    }

    /// The Sse shape's bounded retry re-injects taken work; a merge, so a
    /// fresher event landing in between wins.
    #[test]
    fn cell_reinject_restores_unprocessed_work() {
        let c = WakeCell::new();
        c.merge_vault(3, VaultStatus::Live);
        c.set_items();
        let w = c.take_work();
        assert!(!c.has_work());
        c.merge_vault(8, VaultStatus::Live); // fresher event raced the retry
        c.reinject(w);
        let again = c.take_work();
        assert_eq!(again.vault, Some((8, VaultStatus::Live)));
        assert!(again.items && !again.keys);
    }

    // ── Daemon-global signals (v1.1) ──
    // `now_or_never` polls once with a noop waker: Some(()) ⇔ a notify_one
    // permit was parked — exactly the between-waits semantics the consumers
    // rely on (no runtime needed; Notify is pure synchronization).

    use futures_util::FutureExt;

    #[test]
    fn op_registry_register_notify_deregister_on_drop() {
        let reg = OpRegistry::new();
        let guard = reg.register("op-a");
        assert!(reg.notify("op-a"), "registered id must be known");
        // The fire above had no waiter armed: the permit must carry over.
        assert!(guard.notified().now_or_never().is_some());
        assert!(
            guard.notified().now_or_never().is_none(),
            "permit is one-shot"
        );
        assert!(!reg.notify("op-unknown"), "unknown op_id is a no-op");
        drop(guard);
        assert!(!reg.notify("op-a"), "drop must deregister");
    }

    /// A stale guard's drop must not evict a fresher registration for the
    /// same op_id (the Arc::ptr_eq check in Drop).
    #[test]
    fn op_registry_stale_guard_drop_keeps_fresh_entry() {
        let reg = OpRegistry::new();
        let stale = reg.register("op-a");
        let fresh = reg.register("op-a");
        drop(stale);
        assert!(reg.notify("op-a"), "fresh registration survives stale drop");
        assert!(fresh.notified().now_or_never().is_some());
    }

    /// `agent_hashes` routes to the daemon-global notify — even with an
    /// undecodable payload (it is payload-free by design; the consumer
    /// re-fetches the whole set regardless). This is the only test touching
    /// the global notify, so parallel test runs can't race the permit.
    #[test]
    fn dispatch_routes_agent_hashes_to_global_notify() {
        let cells = HashMap::new();
        dispatch_record(
            &cells,
            &SseRecord {
                event: "agent_hashes".into(),
                data: "not json".into(),
            },
        );
        assert!(agent_hashes_notified().now_or_never().is_some());
        assert!(
            agent_hashes_notified().now_or_never().is_none(),
            "permit consumed"
        );
    }

    /// `op` events route by op_id to the registered poller; unknown or
    /// missing op_ids are ignored without effect (forward compatible).
    #[test]
    fn dispatch_routes_op_event_to_registered_poller() {
        let cells = HashMap::new();
        // Globally-unique id: the registry is the process-wide static.
        let guard = op_events().register("test-dispatch-op-8c11");
        dispatch_record(
            &cells,
            &SseRecord {
                event: "op".into(),
                data: r#"{"vid":"v1","op_id":"test-dispatch-op-8c11","status":"approved"}"#.into(),
            },
        );
        assert!(guard.notified().now_or_never().is_some());
        // Unknown op_id and missing op_id: no panic, no wake.
        dispatch_record(
            &cells,
            &SseRecord {
                event: "op".into(),
                data: r#"{"vid":"v1","op_id":"test-dispatch-op-nobody","status":"rejected"}"#
                    .into(),
            },
        );
        dispatch_record(
            &cells,
            &SseRecord {
                event: "op".into(),
                data: "{}".into(),
            },
        );
        assert!(guard.notified().now_or_never().is_none());
    }

    /// Health read defaults to NOT-healthy while unset — the correct answer
    /// for every no-stream world (local-only, unpaired, watchers not yet
    /// started). The set-path is exercised in-process by the daemon itself;
    /// setting the global here would poison parallel tests.
    #[test]
    fn stream_health_unset_reads_down() {
        assert!(!stream_healthy());
    }
}
