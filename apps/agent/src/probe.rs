//! SEL-001 candidate-endpoint probe runtime: a dedicated thread sends light ICMP probes
//! to every candidate endpoint of each peer at `interval_secs` (default 5s),
//! maintaining sliding windows of RTT / loss / jitter. Why a dedicated thread instead
//! of riding the agent main loop: the main loop ticks at `poll_interval_secs` (default
//! 30s) while the probe period (spec default 5s) is denser; and a probe round spawns a
//! `ping` subprocess (up to 1s each), which must never slow the data-plane loop. Zero
//! control-plane load (per spec): the candidate set reuses the list fetched by the 30s
//! direct reconciliation (heartbeat-synced data); the probe thread never talks to the
//! server. The cache is refreshed by [`reconcile`](crate::agent::Agent); after a peer
//! goes offline, probing stops within at most one reconciliation cycle. Statistics feed
//! SEL-002 (scoring / hysteresis switching) and SEL-004 (console display); during the
//! SEL-001 phase they appear as debug logs (one per 5s, invisible at default log
//! level).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use meshlet_config::ProbeConfig;
use meshlet_domain::{EndpointCandidate, PeerEndpoints};
use meshlet_network::probe::{
    default_transport, is_degraded, probe_round, ProbeSample, ProbeTarget, ProbeTracker,
    ProbeWindow, SwitchDecision, SwitchGate, LAST_LOST_TOLERANCE,
};

/// Probe runtime: one background thread + a candidate cache (written by
/// reconcile / read by the probe thread) + a statistics tracker (written by
/// the probe thread / read by the agent as snapshots).
///
/// `Drop` only sets the stop flag, no `join`: the thread exits by itself
/// after at most one period (default 5s), holding `Arc` clones — memory safe; joining
/// would make agent shutdown (and test construction / drops) wait a full period for
/// nothing.
pub struct ProbeRuntime {
    cache: Arc<Mutex<Vec<PeerEndpoints>>>,
    tracker: Arc<Mutex<ProbeTracker>>,
    /// SEL-002 hysteresis gate: the agent main loop only reads evaluation
    /// results; state advances in place via `evaluate_switch` (short critical
    /// sections, untouched by the probe thread).
    gate: Arc<Mutex<SwitchGate>>,
    /// SEL-003 latency degradation threshold (ms,
    /// `ProbeConfig::degrade_rtt_ms`): window RTT median ≥ this means
    /// degraded (the config entry for the latency dimension of is_degraded).
    degrade_rtt_ms: u64,
    /// SEL-003 loss-spike threshold (`ProbeConfig::loss_spike`): window loss
    /// rate ≥ this means degraded (the config entry for the loss dimension of
    /// is_degraded; default 0.2, see its docs).
    loss_spike: f64,
    /// SEL-003 young-window exemption floor
    /// (`ProbeConfig::degrade_min_samples`, Plan 1): fewer window samples than
    /// this is never judged degraded.
    degrade_min_samples: usize,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProbeRuntime {
    /// Start the probe thread; `enabled = false` means a cold start (no
    /// thread, zero overhead; cache and snapshot interfaces still work).
    pub fn start(config: &ProbeConfig) -> Self {
        let cache = Arc::new(Mutex::new(Vec::new()));
        let tracker = Arc::new(Mutex::new(ProbeTracker::new(config.window)));
        let gate = Arc::new(Mutex::new(SwitchGate::new(
            config.switch_required,
            config.switch_margin,
            config.switch_cooldown_secs.saturating_mul(1000),
        )));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = if config.enabled {
            let cache = Arc::clone(&cache);
            let tracker = Arc::clone(&tracker);
            let stop = Arc::clone(&stop);
            let interval = Duration::from_secs(config.interval_secs.max(1));
            Some(
                std::thread::Builder::new()
                    .name("meshlet-probe".into())
                    .spawn(move || loop {
                        std::thread::sleep(interval);
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        let peers = lock(&cache).clone();
                        if peers.is_empty() {
                            // No candidates (direct off / no peers): no-op
                            // this round, windows untouched.
                            continue;
                        }
                        let mut tracker = lock(&tracker);
                        let round = probe_round(&mut tracker, &peers, default_transport);
                        tracing::debug!(
                            peers = peers.len(),
                            issued = round.issued,
                            lost = round.lost,
                            "candidate probe round finished"
                        );
                    })
                    .expect("spawn the candidate probe thread"),
            )
        } else {
            None
        };
        Self {
            cache,
            tracker,
            gate,
            degrade_rtt_ms: config.degrade_rtt_ms,
            loss_spike: config.loss_spike,
            degrade_min_samples: config.degrade_min_samples,
            stop,
            handle,
        }
    }

    /// Refresh the candidate set (called by `reconcile_direct` every 30s; an
    /// empty list clears the cache and the probe thread no-ops from the next
    /// round on).
    pub fn update_candidates(&self, peers: &[PeerEndpoints]) {
        *lock(&self.cache) = peers.to_vec();
    }

    /// Snapshot of windows for all current targets (consumed by SEL-002 /
    /// SEL-004; clones a small map — target count = peers × candidates).
    pub fn snapshot(&self) -> BTreeMap<ProbeTarget, ProbeWindow> {
        lock(&self.tracker).windows().clone()
    }
    /// /// SEL-002: evaluate whether a peer should switch its direct endpoint to /// a better
    /// candidate.
    ///
    /// Reads the window snapshot and advances the hysteresis gate
    /// ([`SwitchGate::evaluate`]). `current` = the direct candidate currently
    /// issued; `None` = no direct path yet (initial selection is not this
    /// gate's job). Returns the switch decision (with reason); the caller
    /// issues `wg set endpoint` and records the event. Switch grace (Plan 1)
    /// is decided inside the gate: always `None` within the grace period.
    pub fn evaluate_switch(
        &self,
        peer: &str,
        current: Option<EndpointCandidate>,
    ) -> Option<SwitchDecision> {
        self.evaluate_switch_at(peer, current, now_ms())
    }

    /// Clock-injected variant of [`Self::evaluate_switch`] (virtual time for
    /// tests).
    fn evaluate_switch_at(
        &self,
        peer: &str,
        current: Option<EndpointCandidate>,
        now_ms: u64,
    ) -> Option<SwitchDecision> {
        let snapshot = self.snapshot();
        lock(&self.gate).evaluate(peer, current, &snapshot, now_ms)
    }

    /// SEL-003: derive from the window snapshot whether each peer's **current
    /// direct path** is degraded (loss spike / timeout / deeply degraded RTT).
    /// Public key → degraded bool.
    ///
    /// /// Only the window of the active endpoint given by `current` (the direct /// candidate actually issued to `wg`) is evaluated: other candidates in
    /// the candidate list (public NAT / off-subnet LAN, often permanently
    /// ICMP-unreachable) are irrelevant to the active path — the 2026-11-13
    /// true-death re-verification proved that "any candidate degraded → whole
    /// peer degraded" would permanently and wrongly demote a healthy direct
    /// link. Probing off / no window → empty map (never blanket-fall back to
    /// relay).
    pub fn degraded_map(
        &self,
        current: &BTreeMap<String, EndpointCandidate>,
    ) -> BTreeMap<String, bool> {
        self.degraded_map_at(current, now_ms())
    }

    /// Clock-injected variant of [`Self::degraded_map`] (virtual time for
    /// tests).
    ///
    /// Switch grace (Plan 1): a peer inside its grace period skips the
    /// degradation check (the current path must not be judged degraded — a
    /// freshly switched path's window hasn't filled; within grace the gate
    /// shields it, and true death is caught by handshake classify).
    fn degraded_map_at(
        &self,
        current: &BTreeMap<String, EndpointCandidate>,
        now_ms: u64,
    ) -> BTreeMap<String, bool> {
        let snapshot = self.snapshot();
        let gate = lock(&self.gate);
        let mut map = BTreeMap::new();
        for (public_key, candidate) in current {
            if gate.in_cooldown(public_key, now_ms) {
                continue;
            }
            let Some(window) = snapshot.get(&(public_key.clone(), *candidate)) else {
                continue;
            };
            if is_degraded(
                window,
                self.degrade_rtt_ms,
                self.loss_spike,
                self.degrade_min_samples,
            ) {
                map.insert(public_key.clone(), true);
            }
        }
        map
    }

    /// Promote prefers healthy faces (2026-11-14 inspection sheet
    /// nov14-1410): the set of (public_key, candidate) faces currently
    /// degraded per the probe window, for pre-filtering promotion path
    /// selection (re-promoting on a degraded face just degrades again
    /// immediately — the demote → memory-face fallback → degrade flip loop
    /// recorded in the 930f137 decision log).
    ///
    /// Same criterion as [`Self::degraded_map`] (the same is_degraded
    /// verdict): no baseline (all Lost / no samples) is not judged — never
    /// blanket-blacklist a face that has not been probed; probing off → empty
    /// set (the filter is inert, matching legacy behavior).
    pub fn degraded_faces(&self) -> BTreeSet<(String, EndpointCandidate)> {
        let snapshot = self.snapshot();
        let mut set = BTreeSet::new();
        for ((public_key, candidate), window) in snapshot {
            if is_degraded(
                &window,
                self.degrade_rtt_ms,
                self.loss_spike,
                self.degrade_min_samples,
            ) {
                set.insert((public_key, candidate));
            }
        }
        set
    }

    /// Plan 8: one-shot rollback to the pre-switch endpoint while inside the
    /// switch grace. Trigger evidence = the current path (the face the last
    /// switch landed on) "went dark for good after being good" — the window
    /// has an RTT baseline (the face must have produced successful readings
    /// to be selected at switch time) and the last [`LAST_LOST_TOLERANCE`]
    /// samples are all `Lost`; permission and bookkeeping live in
    /// [`SwitchGate::rollback`] (within grace + one shot + the rollback also
    /// passes the grace). No baseline (all Lost — common behind Windows
    /// firewalls) does not trigger: that is not evidence of "broken", and such
    /// a face would never have become a switch target. Returns the old
    /// endpoint; the caller issues `wg set` and records the event.
    pub fn switch_rollback(
        &self,
        peer: &str,
        current: EndpointCandidate,
    ) -> Option<EndpointCandidate> {
        self.switch_rollback_at(peer, current, now_ms())
    }

    /// Clock-injected variant of [`Self::switch_rollback`] (virtual time for
    /// tests).
    fn switch_rollback_at(
        &self,
        peer: &str,
        current: EndpointCandidate,
        now_ms: u64,
    ) -> Option<EndpointCandidate> {
        let dead = self
            .snapshot()
            .get(&(peer.to_string(), current))
            .is_some_and(|w| {
                w.samples().iter().any(|s| matches!(s, ProbeSample::Rtt(_)))
                    && w.samples()
                        .iter()
                        .rev()
                        .take(LAST_LOST_TOLERANCE)
                        .all(|s| matches!(s, ProbeSample::Lost))
            });
        if !dead {
            return None;
        }
        lock(&self.gate).rollback(peer, current, now_ms)
    }

    /// FLIP-001: whether a (public key, candidate) face has
    /// "probe-verified healthy" evidence — the evidence input for the
    /// recovery-gate bypass (a healthy face in the candidate table → no
    /// hold_relay wait for the gate; promote that face directly).
    ///
    /// Criterion: a non-empty window with **at least one successful RTT
    /// /// sample** (positive evidence — an all-Lost long window enjoys the /// no-baseline exemption and is not judged degraded, but that is not
    /// "healthy", just "unknown", and never passed off as healthy), and not
    /// degraded (the same [`is_degraded`] verdict). No window / no successful
    /// sample → `false`.
    pub fn face_healthy(&self, public_key: &str, candidate: EndpointCandidate) -> bool {
        let snapshot = self.snapshot();
        snapshot
            .get(&(public_key.to_string(), candidate))
            .is_some_and(|w| {
                window_is_healthy(
                    w,
                    self.degrade_rtt_ms,
                    self.loss_spike,
                    self.degrade_min_samples,
                )
            })
    }

    /// FLIP-001: the set of all currently "probe-verified healthy" faces
    /// (batch verdict on a single snapshot — the candidate-table probe
    /// evidence refresh and the recovery-gate bypass share one round of
    /// readings, avoiding repeated per-face snapshot clones). Same criterion
    /// as [`Self::face_healthy`].
    pub fn healthy_faces(&self) -> BTreeSet<(String, EndpointCandidate)> {
        let snapshot = self.snapshot();
        snapshot
            .into_iter()
            .filter(|(_, w)| {
                window_is_healthy(
                    w,
                    self.degrade_rtt_ms,
                    self.loss_spike,
                    self.degrade_min_samples,
                )
            })
            .map(|(target, _)| target)
            .collect()
    }

    /// Evidence input for the decision log: a probe-window summary for one
    /// peer's candidate (e.g. `23,31,L,L loss=50% med=27ms`; `L` = lost
    /// sample). Probing off / no window → `None` (the field is absent from
    /// the decision event, never passed off as "probed and healthy").
    pub fn window_summary(&self, public_key: &str, candidate: EndpointCandidate) -> Option<String> {
        let snapshot = self.snapshot();
        let window = snapshot.get(&(public_key.to_string(), candidate))?;
        let samples = window
            .samples()
            .iter()
            .map(|s| match s {
                ProbeSample::Rtt(v) => v.to_string(),
                ProbeSample::Lost => "L".into(),
            })
            .collect::<Vec<_>>()
            .join(",");
        Some(format!(
            "{samples} loss={:.0}% med={:?}ms",
            window.loss_rate() * 100.0,
            window.rtt_ms()
        ))
    }

    /// SEL-004: details for all of a peer's candidate endpoints
    /// (endpoint/RTT/loss/selected and reason).
    ///
    /// `current_endpoint` = the direct endpoint currently issued (`ip:port`;
    /// empty = nothing selected). One entry per candidate, sorted by (ip,
    /// port) (deterministic); `selected` marks the candidate matching the
    /// active path. Probing off / no window → empty list (the console shows
    /// "no candidate readings").
    pub fn candidate_statuses(
        &self,
        peer: &str,
        current_endpoint: &str,
    ) -> Vec<meshlet_domain::DirectCandidateStatus> {
        let snapshot = self.snapshot();
        let mut out: Vec<meshlet_domain::DirectCandidateStatus> = snapshot
            .iter()
            .filter(|((p, _), _)| p == peer)
            .map(|((_, c), w)| {
                let endpoint = format!("{}:{}", c.ip, c.port);
                let selected = endpoint == current_endpoint;
                meshlet_domain::DirectCandidateStatus {
                    endpoint: endpoint.clone(),
                    kind: c.kind.as_str().to_string(),
                    rtt_ms: w.rtt_ms(),
                    loss_rate: w.loss_rate(),
                    selected,
                    reason: if selected {
                        "current".into()
                    } else {
                        "backup".into()
                    },
                }
            })
            .collect();
        out.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));
        out
    }

    /// Whether the probe thread is running (config switch; off = cold start,
    /// zero overhead).
    pub fn is_enabled(&self) -> bool {
        self.handle.is_some()
    }
}

impl Drop for ProbeRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Dropping the JoinHandle = detaching the thread: see the struct docs
        // (why we don't join).
        drop(self.handle.take());
    }
}

/// Current Unix milliseconds (no chrono dependency; a backwards clock falls
/// back to 0 — grace decisions prefer letting go over deadlocking).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Lock and recover from poisoning: a probe-thread panic must not take the
/// agent main loop down with it (cache / tracker are short critical sections;
/// poisoning can only mean the probe thread already crashed — recover the
/// data and keep going).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The "probe-verified healthy" window criterion (FLIP-001): at least one
/// successful RTT sample (positive evidence; an all-Lost no-baseline window
/// is "unknown", not "healthy") and not degraded (the same [`is_degraded`]
/// verdict). Empty window → `false`.
fn window_is_healthy(
    window: &ProbeWindow,
    degrade_rtt_ms: u64,
    loss_spike: f64,
    min_samples: usize,
) -> bool {
    window
        .samples()
        .iter()
        .any(|s| matches!(s, ProbeSample::Rtt(_)))
        && !is_degraded(window, degrade_rtt_ms, loss_spike, min_samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ProbeConfig {
        ProbeConfig {
            enabled: false,
            interval_secs: 5,
            window: 8,
            switch_required: 3,
            switch_margin: 0.30,
            recovery_required: 3,
            degrade_rtt_ms: 800,
            loss_spike: 0.20,
            switch_cooldown_secs: 30,
            degrade_min_samples: 4,
        }
    }

    #[test]
    fn evaluate_switch_requires_gate_and_reports_decision() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        // Probe thread off (enabled=false): record 3 rounds of windows by
        // hand to verify the hysteresis gate.
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..3 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(100));
                tracker.record("dev-b", c2, ProbeSample::Rtt(60));
            }
        }
        // Rounds 1 and 2 don't switch, round 3 does (3 consecutive rounds).
        assert!(rt.evaluate_switch("dev-b", Some(c1)).is_none());
        assert!(rt.evaluate_switch("dev-b", Some(c1)).is_none());
        let decision = rt.evaluate_switch("dev-b", Some(c1)).expect("switch");
        assert_eq!(decision.to, c2);
        assert!(decision.reason.contains("3 consecutive"));
        // After switching to c2: the current path is best → no further
        // switch.
        assert!(rt.evaluate_switch("dev-b", Some(c2)).is_none());
    }

    #[test]
    fn evaluate_switch_none_without_current_path() {
        let rt = ProbeRuntime::start(&config());
        // No current path (initial selection is DirectManager's job) → the
        // gate does not switch.
        assert!(rt.evaluate_switch("dev-b", None).is_none());
    }

    #[test]
    fn degraded_map_marks_peers_with_loss_spike_or_timeout() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        {
            let mut tracker = lock(&rt.tracker);
            // dev-b: healthy (all RTT). dev-c: last 3 samples all timed out
            // (degraded; after last-Lost softening, a single transient sample
            // no longer trips it).
            for _ in 0..3 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(10));
            }
            for _ in 0..4 {
                tracker.record("dev-c", c2, ProbeSample::Rtt(10));
            }
            for _ in 0..3 {
                tracker.record("dev-c", c2, ProbeSample::Lost);
            }
        }
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c1);
        current.insert("dev-c".to_string(), c2);
        let degraded = rt.degraded_map(&current);
        assert!(
            !degraded.get("dev-b").copied().unwrap_or(false),
            "dev-b healthy"
        );
        assert!(
            degraded.get("dev-c").copied().unwrap_or(false),
            "dev-c degraded"
        );
        // Empty windows → empty map.
        let empty = ProbeRuntime::start(&config());
        assert!(empty.degraded_map(&current).is_empty());
    }

    /// Latency dimension (2026-11-13 residual follow-up): probes all
    /// succeed but RTT stays deeply degraded (a live-machine log showed
    /// 1715ms probe_ok pinning the direct link) → degraded_map marks it
    /// degraded.
    #[test]
    fn degraded_map_marks_sustained_high_rtt_without_loss() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        {
            let mut tracker = lock(&rt.tracker);
            // dev-b: sustained ~1715ms (0% loss) → latency degraded.
            for v in [1715u64, 1600, 1800, 1715] {
                tracker.record("dev-b", c1, ProbeSample::Rtt(v));
            }
            // dev-d: healthy low RTT → not degraded.
            for _ in 0..4 {
                tracker.record("dev-d", c1, ProbeSample::Rtt(9));
            }
        }
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c1);
        current.insert("dev-d".to_string(), c1);
        let degraded = rt.degraded_map(&current);
        assert!(
            degraded.get("dev-b").copied().unwrap_or(false),
            "sustained 1715ms without loss must degrade"
        );
        assert!(
            !degraded.get("dev-d").copied().unwrap_or(false),
            "dev-d healthy"
        );
    }

    /// Active-path scope + no-baseline exemption (2026-11-13 SEL-002
    /// true-death re-verification): only the current endpoint's window
    /// participates — backup candidates that never answer ICMP (public NAT /
    /// off-subnet LAN) no longer drag the whole peer down; an active path
    /// that is all Lost has no baseline and is not judged degraded either
    /// (the peer's firewall blocks ICMP, the tunnel may be healthy, and true
    /// death is caught by handshake classify).
    #[test]
    fn degraded_map_scopes_to_current_path_and_requires_baseline() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        let c3 = EndpointCandidate::lan("192.168.1.70".parse().unwrap(), 51821);
        {
            let mut tracker = lock(&rt.tracker);
            // c1: active and healthy (all RTT). c2: backup, all Lost (NAT
            // won't answer ICMP). c3: went bad after being good (50% spike).
            for _ in 0..4 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(10));
                tracker.record("dev-b", c2, ProbeSample::Lost);
            }
            tracker.record("dev-b", c3, ProbeSample::Rtt(10));
            tracker.record("dev-b", c3, ProbeSample::Rtt(10));
            tracker.record("dev-b", c3, ProbeSample::Lost);
            tracker.record("dev-b", c3, ProbeSample::Lost);
        }
        let mut current = BTreeMap::new();
        // Active = c1: the backup c2/c3 windows are irrelevant to the active
        // path → not degraded.
        current.insert("dev-b".to_string(), c1);
        assert!(
            !rt.degraded_map(&current)
                .get("dev-b")
                .copied()
                .unwrap_or(false),
            "healthy current path; backup candidates are irrelevant"
        );
        // Active = c3 (went bad after being good) → degraded.
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c3);
        assert!(
            rt.degraded_map(&current)
                .get("dev-b")
                .copied()
                .unwrap_or(false),
            "current path degraded by loss spike with baseline"
        );
        // Active = c2 (all Lost, no baseline) → not degraded.
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c2);
        assert!(
            !rt.degraded_map(&current)
                .get("dev-b")
                .copied()
                .unwrap_or(false),
            "never-answered path has no baseline; handshake classify owns true death"
        );
        // Active with no window (just switched paths) → not degraded.
        let mut current = BTreeMap::new();
        current.insert("dev-x".to_string(), c1);
        assert!(
            !rt.degraded_map(&current)
                .get("dev-x")
                .copied()
                .unwrap_or(false),
            "no window yet; do not degrade"
        );
    }

    #[test]
    fn candidate_statuses_reports_all_candidates_with_selection() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        {
            let mut tracker = lock(&rt.tracker);
            tracker.record("dev-b", c1, ProbeSample::Rtt(10));
            tracker.record("dev-b", c1, ProbeSample::Rtt(12));
            tracker.record("dev-b", c2, ProbeSample::Rtt(40));
            tracker.record("dev-b", c2, ProbeSample::Lost);
        }
        // c1 currently selected: both candidates listed, c1 marked selected.
        let statuses = rt.candidate_statuses("dev-b", "192.168.1.50:51821");
        assert_eq!(statuses.len(), 2);
        let c1s = statuses
            .iter()
            .find(|c| c.endpoint == "192.168.1.50:51821")
            .unwrap();
        assert!(c1s.selected);
        assert_eq!(c1s.reason, "current");
        assert_eq!(c1s.rtt_ms, Some(11));
        assert_eq!(c1s.loss_rate, 0.0);
        let c2s = statuses
            .iter()
            .find(|c| c.endpoint == "192.168.1.60:51821")
            .unwrap();
        assert!(!c2s.selected);
        assert_eq!(c2s.reason, "backup");
        assert_eq!(c2s.rtt_ms, Some(40));
        assert_eq!(c2s.loss_rate, 0.5);
        // Other peers' candidates don't interfere.
        assert!(rt.candidate_statuses("dev-x", "").is_empty());
    }

    /// Decision-log evidence input (2026-11-14 inspection sheet): the window
    /// summary string carries per-sample readings plus loss/med aggregates; no
    /// window (probing off / no samples) → None, never passed off as
    /// "probed".
    #[test]
    fn window_summary_reports_samples_and_aggregates_or_none() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        assert!(rt.window_summary("dev-b", c1).is_none(), "no window yet");
        {
            let mut tracker = lock(&rt.tracker);
            tracker.record("dev-b", c1, ProbeSample::Rtt(23));
            tracker.record("dev-b", c1, ProbeSample::Rtt(31));
            tracker.record("dev-b", c1, ProbeSample::Lost);
            tracker.record("dev-b", c1, ProbeSample::Lost);
        }
        let summary = rt.window_summary("dev-b", c1).expect("summary");
        assert!(summary.starts_with("23,31,L,L"), "summary={summary}");
        assert!(summary.contains("loss=50%"), "summary={summary}");
        assert!(summary.contains("med=Some(27)"), "summary={summary}");
        // Other peers have no window.
        assert!(rt.window_summary("dev-x", c1).is_none());
    }

    /// The degraded-face set behind "promote prefers healthy faces": only
    /// faces with a baseline that then degraded are collected; healthy faces
    /// aren't, all-Lost no-baseline faces aren't (never blanket-blacklist),
    /// and probing off (no samples) yields an empty set.
    #[test]
    fn degraded_faces_marks_baseline_degraded_faces_only() {
        let rt = ProbeRuntime::start(&config());
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        let c3 = EndpointCandidate::lan("192.168.1.70".parse().unwrap(), 51821);
        {
            let mut tracker = lock(&rt.tracker);
            // dev-b@c1 healthy; dev-b@c2 went bad after being good (last 3
            // samples Lost); dev-b@c3 all Lost (no baseline, true death is
            // caught by handshake classify).
            for _ in 0..4 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(10));
                tracker.record("dev-b", c2, ProbeSample::Rtt(10));
                tracker.record("dev-b", c3, ProbeSample::Lost);
            }
            for _ in 0..3 {
                tracker.record("dev-b", c2, ProbeSample::Lost);
            }
        }
        let faces = rt.degraded_faces();
        assert!(
            !faces.contains(&("dev-b".into(), c1)),
            "healthy face not marked"
        );
        assert!(
            faces.contains(&("dev-b".into(), c2)),
            "baseline + tail Lost run marked"
        );
        assert!(
            !faces.contains(&("dev-b".into(), c3)),
            "no-baseline face not marked"
        );
        // Probing off / no samples → empty set (the filter is inert = legacy
        // behavior).
        assert!(ProbeRuntime::start(&config()).degraded_faces().is_empty());
    }

    /// Pin for the loss-spike threshold tightening (2026-11-17 user decision,
    /// 50% → 20%, on the recovery-gate face): under the old threshold a 49%
    /// loss face counted as "probe-verified healthy" and could serve as
    /// FLIP-001 bypass evidence to open the recovery gate and pull the direct
    /// link back onto a degraded face — no longer judged healthy now;
    /// <20% (19%) stays healthy.
    #[test]
    fn face_healthy_rejects_49_percent_loss_but_accepts_19_percent() {
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        // Exact boundaries need a 100-sample window (the default test window
        // of 8 cannot hold 49/100): window=100.
        let mut cfg = config();
        cfg.window = 100;
        let rt = ProbeRuntime::start(&cfg);
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..49 {
                tracker.record("dev-b", c1, ProbeSample::Lost);
            }
            for _ in 0..51 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(10));
            }
            for _ in 0..19 {
                tracker.record("dev-b", c2, ProbeSample::Lost);
            }
            for _ in 0..81 {
                tracker.record("dev-b", c2, ProbeSample::Rtt(10));
            }
        }
        assert!(
            !rt.face_healthy("dev-b", c1),
            "49% loss must not count as probe-healthy (no recovery bypass)"
        );
        assert!(
            rt.face_healthy("dev-b", c2),
            "19% loss stays probe-healthy under the 20% threshold"
        );
        // Same verdict source: the degraded map also marks the 49% face
        // degraded (consistent with the demote gate).
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c1);
        assert!(rt
            .degraded_map(&current)
            .get("dev-b")
            .copied()
            .unwrap_or(false));
    }

    /// Switch-grace pin (Plan 1, 2026-11-17): within the grace period after a
    /// switch (default interval×required×2 = 30s) ① no re-switch ② no
    /// degraded verdict on the current path; once grace passes, both resume
    /// normal judgment. The "momentary gap at switch" the user measured as
    /// ping jumping between three states is exactly this vacuum period
    /// amplified by the gate/degradation verdicts.
    #[test]
    fn switch_grace_blocks_reswitch_and_degrade_marking() {
        let c1 = EndpointCandidate::lan("192.168.1.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.1.60".parse().unwrap(), 51821);
        let c3 = EndpointCandidate::lan("192.168.1.70".parse().unwrap(), 51821);
        let rt = ProbeRuntime::start(&config());
        // Accumulate 3 consecutive samples with c2 better than c1 → trigger
        // the c1→c2 switch at t0=1_000.
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..3 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(100));
                tracker.record("dev-b", c2, ProbeSample::Rtt(60));
            }
        }
        assert!(rt.evaluate_switch_at("dev-b", Some(c1), 900).is_none());
        assert!(rt.evaluate_switch_at("dev-b", Some(c1), 950).is_none());
        let decision = rt
            .evaluate_switch_at("dev-b", Some(c1), 1_000)
            .expect("switch at t0");
        assert_eq!(decision.to, c2);
        // After the switch, the c2 window collapses (last 3 samples Lost,
        // filling a 7-sample window) and c3 is far better than c2 — within
        // grace both must be blocked.
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..3 {
                tracker.record("dev-b", c2, ProbeSample::Lost);
                tracker.record("dev-b", c3, ProbeSample::Rtt(10));
            }
        }
        let mut current = BTreeMap::new();
        current.insert("dev-b".to_string(), c2);
        // Within grace (t0+5s): no degraded verdict, no re-switch.
        let map = rt.degraded_map_at(&current, 1_000 + 5_000);
        assert!(
            !map.get("dev-b").copied().unwrap_or(false),
            "degrade marking suppressed within grace"
        );
        assert!(
            rt.evaluate_switch_at("dev-b", Some(c2), 1_000 + 5_000)
                .is_none(),
            "re-switch blocked within grace"
        );
        // Grace over (t0+31.5s; grace includes its endpoint boundary, so
        // 31_000 is still within grace — the rollback check must land in the
        // next reconciliation round after the switch): the same readings
        // resume acting — degradation hits; the gate must refill its
        // consecutive count (evaluation is frozen within grace, the streak
        // restarts from 0) and only switches on round 3.
        let map = rt.degraded_map_at(&current, 1_000 + 31_500);
        assert!(
            map.get("dev-b").copied().unwrap_or(false),
            "degrade acts after grace"
        );
        assert!(
            rt.evaluate_switch_at("dev-b", Some(c2), 1_000 + 31_500)
                .is_none(),
            "streak restarts after grace"
        );
        assert!(
            rt.evaluate_switch_at("dev-b", Some(c2), 1_000 + 31_501)
                .is_none(),
            "streak restarts after grace (2/3)"
        );
        assert!(
            rt.evaluate_switch_at("dev-b", Some(c2), 1_000 + 31_502)
                .is_some(),
            "gate acts after streak refills"
        );
    }

    /// Plan-8 rollback pin (2026-11-18): death evidence = the current path's
    /// window has an RTT baseline and its last [`LAST_LOST_TOLERANCE`]
    /// samples are all Lost; permission = within grace + one shot + target
    /// face match (the gate-level grace-extension semantics are pinned on the
    /// network side).
    #[test]
    fn switch_rollback_needs_death_evidence_and_is_one_shot() {
        let c1 = EndpointCandidate::lan("192.168.2.50".parse().unwrap(), 51821);
        let c2 = EndpointCandidate::lan("192.168.2.60".parse().unwrap(), 51821);
        let rt = ProbeRuntime::start(&config());
        // Accumulate 3 consecutive samples with c2 better than c1 → trigger
        // the c1→c2 switch at t0=1_000.
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..3 {
                tracker.record("dev-b", c1, ProbeSample::Rtt(100));
                tracker.record("dev-b", c2, ProbeSample::Rtt(60));
            }
        }
        assert!(rt.evaluate_switch_at("dev-b", Some(c1), 900).is_none());
        assert!(rt.evaluate_switch_at("dev-b", Some(c1), 950).is_none());
        let decision = rt
            .evaluate_switch_at("dev-b", Some(c1), 1_000)
            .expect("switch at t0");
        assert_eq!(decision.to, c2);

        // No death evidence (window full of good readings): None even within
        // grace.
        assert!(
            rt.switch_rollback_at("dev-b", c2, 1_000 + 5_000).is_none(),
            "healthy window is not rollback evidence"
        );
        // Target face mismatch (current is not where the last switch landed):
        // no rollback.
        assert!(
            rt.switch_rollback_at("dev-b", c1, 1_000 + 5_000).is_none(),
            "rollback only applies to the face the switch landed on"
        );

        // Window went bad after being good: [R,R,R] + [L,L,L] → death
        // evidence complete; within grace, roll back to Some(c1).
        {
            let mut tracker = lock(&rt.tracker);
            for _ in 0..3 {
                tracker.record("dev-b", c2, ProbeSample::Lost);
            }
        }
        assert_eq!(
            rt.switch_rollback_at("dev-b", c2, 1_000 + 5_000),
            Some(c1),
            "dead target face rolls back to the pre-switch face"
        );

        // One shot: evidence still present within the same grace, but the
        // rollback happens only once.
        assert!(
            rt.switch_rollback_at("dev-b", c2, 1_000 + 6_000).is_none(),
            "rollback is one shot"
        );
        // Grace over (rollback happened at 5_000 + 30_000): no more
        // rollback.
        assert!(
            rt.switch_rollback_at("dev-b", c2, 35_001).is_none(),
            "no rollback outside grace"
        );
    }
}
