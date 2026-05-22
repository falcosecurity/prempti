use std::io::Write;
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Cross-platform stream type for interceptor connections.
/// Uses Unix domain sockets on all platforms (Windows 10+ supports AF_UNIX).
#[cfg(unix)]
pub type BrokerStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type BrokerStream = uds_windows::UnixStream;

use dashmap::DashMap;

use crate::verdict::Verdict;

/// TTL for pending requests. Entries older than this are reaped.
/// Set well above the interceptor's timeout (default 5s) to avoid false reaping
/// during normal operation. This catches entries whose seen alert was lost.
const PENDING_TTL_SECS: u64 = 30;

/// How often the reaper thread scans for stale entries.
const REAPER_INTERVAL_SECS: u64 = 10;

/// How often the reaper thread wakes to check the shutdown flag. Keeping this
/// much smaller than `REAPER_INTERVAL_SECS` ensures `Drop` (which joins the
/// reaper) returns quickly on `ctl stop` — otherwise the whole plugin
/// teardown would stall up to `REAPER_INTERVAL_SECS`. 100ms is a good balance:
/// negligible CPU overhead, sub-second shutdown latency.
const REAPER_SHUTDOWN_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// Process-wide monotonic counter for correlation IDs.
///
/// In the current design, `Plugin::new()` runs exactly once per Falco process
/// (config-driven hot-reload is disabled — see `configs/falco.yaml`), so a
/// per-`Broker` counter would also be sufficient. The counter is process-wide
/// as a defensive measure: if a future change ever introduces a path where a
/// `Broker` is recreated mid-process, alerts already queued for the previous
/// `Broker` won't collide with newly-issued IDs from the next one.
static NEXT_CORRELATION_ID: AtomicU64 = AtomicU64::new(1);

/// Tracks pending requests from interceptors, waiting for verdict resolution.
pub struct Broker {
    /// Maps correlation ID → pending request.
    pending: DashMap<u64, PendingRequest>,
    /// When true, all verdicts resolve as allow (monitor mode).
    monitor_mode: AtomicBool,
    /// When true, resolve all requests as allow immediately on register.
    passthrough: AtomicBool,
    /// Shutdown signal for background threads.
    shutdown: AtomicBool,
}

/// A pending request from an interceptor, awaiting a verdict.
struct PendingRequest {
    /// The connection back to the interceptor (Unix domain socket).
    stream: Mutex<BrokerStream>,
    /// The wire protocol request ID (to include in the response).
    wire_id: String,
    /// The current best verdict (escalated as alerts arrive).
    current_verdict: Mutex<Option<Verdict>>,
    /// When this request was registered.
    created_at: Instant,
    /// Number of "seen" alerts still expected before resolving. Set at
    /// register time: 1 for single-event flows (every hook except codex's
    /// multi-file apply_patch), N for synthetic multi-event flows where the
    /// broker emitted N Falco events from one wire request. `apply_seen`
    /// decrements; only the last seen triggers resolve.
    remaining_seens: AtomicU64,
}

impl Broker {
    pub fn new() -> Self {
        Broker {
            pending: DashMap::new(),
            monitor_mode: AtomicBool::new(false),
            passthrough: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
        }
    }

    /// Signal all background threads to stop.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Returns true if shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Generate a unique correlation ID for an event.
    ///
    /// Uses a process-wide counter (see `NEXT_CORRELATION_ID`) so IDs remain
    /// unique even if a `Broker` is ever reconstructed within the same Falco
    /// process.
    pub fn next_correlation_id(&self) -> u64 {
        NEXT_CORRELATION_ID.fetch_add(1, Ordering::Relaxed)
    }

    /// Set monitor mode. When enabled, all verdicts resolve as allow after
    /// the synchronous rule-eval wait. Independent of passthrough mode.
    pub fn set_monitor_mode(&self, enabled: bool) {
        self.monitor_mode.store(enabled, Ordering::Relaxed);
        log::info!(
            "broker monitor: {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    /// Set passthrough mode. When enabled, all interceptor requests are resolved
    /// as "allow" immediately upon registration, without waiting for rule evaluation.
    /// Events are still enqueued for the Falco engine to process.
    pub fn set_passthrough(&self, enabled: bool) {
        self.passthrough.store(enabled, Ordering::Relaxed);
        log::info!(
            "broker passthrough: {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    /// Returns true if passthrough mode is active.
    pub fn is_passthrough(&self) -> bool {
        self.passthrough.load(Ordering::Relaxed)
    }

    /// Returns true if monitor mode is active.
    fn is_monitor(&self) -> bool {
        self.monitor_mode.load(Ordering::Relaxed)
    }

    /// Register a new pending request. `correlation_id` is the broker-assigned ID
    /// used for Falco alert correlation. `wire_id` is the interceptor's request ID
    /// used in the verdict response. `expected_events` is the number of "seen"
    /// alerts the broker should wait for before resolving — 1 for ordinary
    /// hooks, N for codex apply_patch multi-file multiplex. Values below 1 are
    /// clamped to 1 so misuse can't deadlock the interceptor.
    ///
    /// In passthrough mode, the request is resolved as "allow" immediately without
    /// being added to the pending map.
    pub fn register(
        &self,
        correlation_id: u64,
        wire_id: String,
        stream: BrokerStream,
        expected_events: u64,
    ) {
        if self.is_passthrough() {
            let response = Verdict::Allow.to_response_json(&wire_id);
            let mut s = stream;
            let _ = write!(s, "{}\n", response);
            let _ = s.flush();
            let _ = s.shutdown(Shutdown::Both);
            return;
        }
        self.pending.insert(
            correlation_id,
            PendingRequest {
                stream: Mutex::new(stream),
                wire_id,
                current_verdict: Mutex::new(None),
                created_at: Instant::now(),
                remaining_seens: AtomicU64::new(expected_events.max(1)),
            },
        );
    }

    /// Apply a deny verdict. Deny wins immediately — resolve and respond.
    pub fn apply_deny(&self, correlation_id: u64, reason: String) {
        if self.is_monitor() {
            // In monitor mode, log the deny but don't resolve yet — wait for seen.
            log::info!("monitor: would deny {} ({})", correlation_id, reason);
            return;
        }
        self.resolve(correlation_id, Verdict::Deny(reason));
    }

    /// Apply an ask verdict. Escalate: only upgrade if not already deny.
    pub fn apply_ask(&self, correlation_id: u64, reason: String) {
        if self.is_monitor() {
            // In monitor mode, log the ask but don't resolve yet — wait for seen.
            log::info!("monitor: would ask {} ({})", correlation_id, reason);
            return;
        }
        if let Some(pending) = self.pending.get(&correlation_id) {
            let mut current = pending
                .current_verdict
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let new_verdict = Verdict::Ask(reason);
            *current = Some(match current.take() {
                Some(existing) => existing.escalate(new_verdict),
                None => new_verdict,
            });
        }
        // Don't resolve yet — wait for the seen signal.
    }

    /// Signal that rule evaluation is complete for one Falco event with this
    /// correlation ID. For single-event flows the broker resolves immediately;
    /// for multi-event flows (codex apply_patch multiplex) the broker waits
    /// for `expected_events` seen alerts before resolving with the escalated
    /// verdict (deny > ask > allow). In monitor mode the verdict is always
    /// downgraded to allow.
    ///
    /// `apply_deny` may short-circuit and `resolve` away the entry before all
    /// seens arrive; subsequent calls hit an empty pending map and become
    /// no-ops, which is the intended behavior.
    pub fn apply_seen(&self, correlation_id: u64) {
        // Decrement the seen counter under the DashMap shard lock. Returns
        // `Some(true)` if we just brought the counter to 0 (= ready to
        // resolve), `Some(false)` if more seens are still expected, and
        // `None` if the entry is already gone (e.g. apply_deny resolved
        // early). Holding the shard lock for the duration of this check is
        // fine — fetch_sub is a single atomic op, the lock is just to keep
        // the entry alive while we touch the counter.
        let should_resolve = self
            .pending
            .get(&correlation_id)
            .map(|p| p.remaining_seens.fetch_sub(1, Ordering::AcqRel) == 1);
        match should_resolve {
            Some(true) => {}
            Some(false) | None => return,
        }

        if self.is_monitor() {
            self.resolve(correlation_id, Verdict::Allow);
            return;
        }
        if let Some((_, pending)) = self.pending.remove(&correlation_id) {
            let verdict = pending
                .current_verdict
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .unwrap_or(Verdict::Allow);
            let response = verdict.to_response_json(&pending.wire_id);
            let mut stream = pending.stream.lock().unwrap_or_else(|e| e.into_inner());
            let _ = write!(stream, "{}\n", response);
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// Resolve a pending request: send the verdict response to the interceptor
    /// and remove the request from the pending map. The response uses the wire_id
    /// (the interceptor's original request ID), not the broker's correlation ID.
    fn resolve(&self, correlation_id: u64, verdict: Verdict) {
        if let Some((_, pending)) = self.pending.remove(&correlation_id) {
            let response = verdict.to_response_json(&pending.wire_id);
            let mut stream = pending.stream.lock().unwrap_or_else(|e| e.into_inner());
            let _ = write!(stream, "{}\n", response);
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// Remove pending requests older than `ttl`.
    /// Returns the number of reaped entries.
    pub fn reap_stale(&self, ttl: std::time::Duration) -> usize {
        let now = Instant::now();
        let mut reaped = 0;

        // Collect stale IDs first to avoid holding DashMap iterators during removal.
        let stale_ids: Vec<u64> = self
            .pending
            .iter()
            .filter(|entry| now.duration_since(entry.value().created_at) > ttl)
            .map(|entry| *entry.key())
            .collect();

        for id in stale_ids {
            if let Some((_, pending)) = self.pending.remove(&id) {
                log::warn!(
                    "reaping stale pending request {} (age {:?})",
                    id,
                    now.duration_since(pending.created_at)
                );
                // Send deny to unblock the interceptor if it's somehow still waiting.
                let response = Verdict::Deny("request expired".to_string())
                    .to_response_json(&pending.wire_id);
                let mut stream = pending.stream.lock().unwrap_or_else(|e| e.into_inner());
                let _ = write!(stream, "{}\n", response);
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Both);
                reaped += 1;
            }
        }

        reaped
    }

    /// Number of currently pending requests.
    #[allow(dead_code)]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Start a background thread that periodically reaps stale pending requests.
    ///
    /// The thread polls the shutdown flag every `REAPER_SHUTDOWN_POLL` so it
    /// can exit quickly on `Drop`, and performs a reap pass whenever
    /// `REAPER_INTERVAL_SECS` has elapsed since the last one.
    pub fn start_reaper(broker: Arc<Broker>) -> std::thread::JoinHandle<()> {
        let reap_interval = std::time::Duration::from_secs(REAPER_INTERVAL_SECS);
        let ttl = std::time::Duration::from_secs(PENDING_TTL_SECS);
        std::thread::Builder::new()
            .name("prempti-reaper".to_string())
            .spawn(move || {
                let mut last_reap = Instant::now();
                while !broker.is_shutdown() {
                    std::thread::sleep(REAPER_SHUTDOWN_POLL);
                    if last_reap.elapsed() >= reap_interval {
                        let reaped = broker.reap_stale(ttl);
                        if reaped > 0 {
                            log::info!("reaper: removed {} stale pending request(s)", reaped);
                        }
                        last_reap = Instant::now();
                    }
                }
                log::info!("reaper thread exiting");
            })
            .expect("failed to spawn reaper thread")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn read_response_json(peer: &UnixStream) -> serde_json::Value {
        let mut reader = BufReader::new(peer);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("read_line on peer stream");
        serde_json::from_str(line.trim()).expect("parse response JSON")
    }

    fn expect_no_response(peer: &UnixStream) {
        peer.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut buf = [0u8; 1];
        let err = (&mut &*peer)
            .read(&mut buf)
            .expect_err("peer should not have received data");
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        peer.set_read_timeout(None).unwrap();
    }

    fn register_with(broker: &Broker, id: u64, wire_id: &str) -> UnixStream {
        register_with_count(broker, id, wire_id, 1)
    }

    fn register_with_count(
        broker: &Broker,
        id: u64,
        wire_id: &str,
        expected_events: u64,
    ) -> UnixStream {
        let (broker_side, peer) = UnixStream::pair().expect("UnixStream::pair");
        broker.register(id, wire_id.to_string(), broker_side, expected_events);
        peer
    }

    #[test]
    fn seen_with_no_verdict_resolves_as_allow() {
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "allow");
        assert_eq!(resp["id"], "wire-1");
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn deny_resolves_immediately_and_clears_pending() {
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_deny(1, "blocked".to_string());
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        assert_eq!(resp["reason"], "blocked");
        assert_eq!(broker.pending_count(), 0);
        // Subsequent seen is a no-op (entry already removed).
        broker.apply_seen(1);
    }

    #[test]
    fn ask_defers_until_seen() {
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_ask(1, "needs confirm".to_string());
        expect_no_response(&peer);
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "ask");
        assert_eq!(resp["reason"], "needs confirm");
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn deny_beats_ask_when_ask_arrives_first() {
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_ask(1, "confirm".to_string());
        broker.apply_deny(1, "blocked".to_string());
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        assert_eq!(resp["reason"], "blocked");
        // Seen after deny is a no-op.
        broker.apply_seen(1);
    }

    #[test]
    fn deny_beats_ask_when_ask_arrives_after() {
        // apply_ask after deny should be a no-op (entry already removed by resolve).
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_deny(1, "blocked".to_string());
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        // The ask after deny hits an empty pending map → no panic, no double-write.
        broker.apply_ask(1, "confirm".to_string());
        broker.apply_seen(1);
    }

    #[test]
    fn monitor_mode_suppresses_deny() {
        let broker = Broker::new();
        broker.set_monitor_mode(true);
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_deny(1, "would-block".to_string());
        expect_no_response(&peer);
        // Seen then drives the allow verdict.
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "allow");
    }

    #[test]
    fn monitor_mode_suppresses_ask() {
        let broker = Broker::new();
        broker.set_monitor_mode(true);
        let peer = register_with(&broker, 1, "wire-1");
        broker.apply_ask(1, "would-ask".to_string());
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "allow");
    }

    #[test]
    fn unknown_correlation_id_is_noop() {
        let broker = Broker::new();
        // None of these should panic.
        broker.apply_deny(42, "r".to_string());
        broker.apply_ask(42, "r".to_string());
        broker.apply_seen(42);
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn correlation_ids_are_monotonic_and_positive() {
        let broker = Broker::new();
        let a = broker.next_correlation_id();
        let b = broker.next_correlation_id();
        let c = broker.next_correlation_id();
        assert!(a > 0 && b > a && c > b);
    }

    #[test]
    fn concurrent_requests_resolved_independently() {
        let broker = Broker::new();
        let peer1 = register_with(&broker, 1, "wire-1");
        let peer2 = register_with(&broker, 2, "wire-2");
        // Mix: peer1 gets deny, peer2 gets allow.
        broker.apply_deny(1, "one".to_string());
        broker.apply_seen(2);
        let r1 = read_response_json(&peer1);
        let r2 = read_response_json(&peer2);
        assert_eq!(r1["id"], "wire-1");
        assert_eq!(r1["decision"], "deny");
        assert_eq!(r2["id"], "wire-2");
        assert_eq!(r2["decision"], "allow");
    }

    #[test]
    fn reap_stale_removes_and_denies() {
        let broker = Broker::new();
        let peer = register_with(&broker, 1, "wire-1");
        assert_eq!(broker.pending_count(), 1);
        std::thread::sleep(Duration::from_millis(20));
        let n = broker.reap_stale(Duration::from_millis(10));
        assert_eq!(n, 1);
        assert_eq!(broker.pending_count(), 0);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        assert!(resp["reason"]
            .as_str()
            .unwrap()
            .contains("expired"));
    }

    #[test]
    fn reap_stale_preserves_fresh_entries() {
        let broker = Broker::new();
        let _peer = register_with(&broker, 1, "wire-1");
        let n = broker.reap_stale(Duration::from_secs(60));
        assert_eq!(n, 0);
        assert_eq!(broker.pending_count(), 1);
    }

    #[test]
    fn passthrough_allows_immediately_and_skips_pending() {
        let broker = Broker::new();
        broker.set_passthrough(true);
        let peer = register_with(&broker, 1, "wire-1");
        // Allow JSON is on the wire right away — no apply_* call needed.
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "allow");
        assert_eq!(resp["id"], "wire-1");
        // Pending map must stay empty: passthrough short-circuits before insert.
        assert_eq!(broker.pending_count(), 0);
    }

    // ------------------------------------------------------------------
    // Multi-event seen counting (apply_patch multiplex)
    //
    // These tests pin the broker's expected_events behavior: a single wire
    // request can correspond to N Falco events sharing the same correlation
    // id, and the broker must wait for N seen alerts before resolving.
    // Deny still short-circuits.
    // ------------------------------------------------------------------

    #[test]
    fn multi_event_seen_counts_down_before_resolving_allow() {
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 3);

        // First two seens do nothing on the wire — broker waits for all three.
        broker.apply_seen(1);
        expect_no_response(&peer);
        broker.apply_seen(1);
        expect_no_response(&peer);

        // Third seen resolves as allow (no deny/ask was applied).
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "allow");
        assert_eq!(resp["id"], "wire-1");
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn multi_event_deny_short_circuits_pending_seens() {
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 5);

        // Deny resolves immediately regardless of how many seens remain.
        broker.apply_deny(1, "blocked on path 2 of 5".to_string());
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "deny");
        assert_eq!(resp["reason"], "blocked on path 2 of 5");
        assert_eq!(broker.pending_count(), 0);

        // Remaining seen alerts for that correlation id are silent no-ops.
        broker.apply_seen(1);
        broker.apply_seen(1);
        broker.apply_seen(1);
        broker.apply_seen(1);
        // Pending stays empty; no double-write to the stream.
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn multi_event_ask_resolves_only_at_last_seen() {
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 2);

        // Ask alert lands first; broker stages the verdict and waits.
        broker.apply_ask(1, "needs confirm".to_string());
        expect_no_response(&peer);

        // First of two seens still doesn't resolve.
        broker.apply_seen(1);
        expect_no_response(&peer);

        // Second seen resolves with the staged ask.
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "ask");
        assert_eq!(resp["reason"], "needs confirm");
    }

    #[test]
    fn multi_event_monitor_mode_resolves_at_last_seen_as_allow() {
        let broker = Broker::new();
        broker.set_monitor_mode(true);
        let peer = register_with_count(&broker, 1, "wire-1", 2);

        // Monitor mode also has to wait for the full seen count — otherwise
        // a single-event observer would race ahead and resolve before the
        // rest of a multi-file apply_patch finishes evaluating.
        broker.apply_deny(1, "would-deny on first path".to_string());
        expect_no_response(&peer);
        broker.apply_seen(1);
        expect_no_response(&peer);
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "allow");
    }

    #[test]
    fn register_with_zero_expected_events_clamps_to_one() {
        // Defensive: a caller bug passing 0 must not deadlock the broker by
        // requiring an impossible-to-reach seen count. Clamp to 1.
        let broker = Broker::new();
        let peer = register_with_count(&broker, 1, "wire-1", 0);
        broker.apply_seen(1);
        let resp = read_response_json(&peer);
        assert_eq!(resp["decision"], "allow");
        assert_eq!(broker.pending_count(), 0);
    }

    #[test]
    fn passthrough_disabled_keeps_default_register_behavior() {
        // Default (passthrough=false): entry inserted, stream stays open until
        // a verdict is applied.
        let broker = Broker::new();
        assert!(!broker.is_passthrough());
        let peer = register_with(&broker, 1, "wire-1");
        assert_eq!(broker.pending_count(), 1);
        expect_no_response(&peer);
        // Resolve so the stream/peer drop cleanly.
        broker.apply_deny(1, "cleanup".to_string());
        let _ = read_response_json(&peer);
        assert_eq!(broker.pending_count(), 0);
    }
}
