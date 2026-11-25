//! SEL-001 candidate-endpoint probing layer: send a lightweight probe to every candidate endpoint
//! of every peer and collect RTT / loss / jitter sliding windows ([todo.md](../../../todo.md) SEL-001).
//!
//! Design points (one-to-one with the task sheet):
//! - **Candidate input** is [`meshlet_domain::PeerEndpoints`] (the public / LAN candidates pushed
//!   by the hub); the probing layer only consumes it and never assembles one itself;
//! - **Window statistics** ([`ProbeWindow`]) are pure logic: keep the most recent `capacity` probes,
//!   evicting the oldest when over capacity, and `rtt_ms` (median) / `loss_rate` / `jitter_ms` are all
//!   derived from the window; SEL-002's scoring and hysteresis switching consume them directly;
//! - **Injectable transport** (the `transport` closure of [`probe_round`]): production uses the
//!   platform default [`default_transport`] (Linux sends an ICMP echo via `ping`, adding no control
//!   plane load), while the netns integration tests inject a "ping inside a given namespace" transport
//!   to measure both paths' RTT for real;
//! - **Zero control-plane load**: the probe cycle is independent of the heartbeat / dispatch and only
//!   reuses the peer candidate sets (data synced on the 30s heartbeat); probing never triggers an
//!   extra request to the server.
//!
//! Platform differences converge in [`default_transport`]: real ICMP probing on Linux (`ping -c 1
//! -W 1`); the same-caliber ICMP on Windows (`ping -n 1 -w 1000`, [`crate::windows_probe`], wired in
//! 2026-11-13); all other platforms return `None` (recorded as a loss).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;

use meshlet_domain::{EndpointCandidate, PeerEndpoints};

// ---------------------------------------------------------------------------
// Window statistics
// ---------------------------------------------------------------------------

/// The outcome of one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeSample {
    /// Round-trip time (milliseconds).
    Rtt(u64),
    /// The probe timed out without a response (a loss).
    Lost,
}

/// A bounded sliding window: keeps the most recent `capacity` probes and evicts the oldest when over.
///
/// A pure statistics structure with no IO; every reading (RTT / loss rate / jitter) is derived from
/// the samples in the window, no external state is kept, and SEL-002 can consume it directly.
#[derive(Debug, Clone)]
pub struct ProbeWindow {
    capacity: usize,
    samples: VecDeque<ProbeSample>,
}

impl ProbeWindow {
    /// Create a window. `capacity` is floored at 1 (an empty window is meaningless).
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            samples: VecDeque::new(),
        }
    }

    /// Record one probe; evict the oldest sample once the window is full.
    pub fn record(&mut self, sample: ProbeSample) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    /// The number of samples in the window.
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The window capacity (the sample ceiling for this probe round).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// All samples in the window (oldest → newest, a read-only view).
    pub fn samples(&self) -> &VecDeque<ProbeSample> {
        &self.samples
    }

    /// The median of the RTT samples in the window (milliseconds). A robust measure of central tendency:
    /// a single spike / a single loss does not skew the reading, and SEL-002's scoring relies on it
    /// primarily. No RTT samples -> `None`.
    pub fn rtt_ms(&self) -> Option<u64> {
        let mut rtts: Vec<u64> = self
            .samples
            .iter()
            .filter_map(|s| match s {
                ProbeSample::Rtt(v) => Some(*v),
                ProbeSample::Lost => None,
            })
            .collect();
        rtts.sort_unstable();
        let n = rtts.len();
        match n {
            0 => None,
            _ if n % 2 == 1 => Some(rtts[n / 2]),
            _ => Some((rtts[n / 2 - 1] + rtts[n / 2]) / 2),
        }
    }

    /// The loss rate (0.0..=1.0): Lost samples in the window / total samples. An empty window -> 0.0.
    pub fn loss_rate(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let lost = self
            .samples
            .iter()
            .filter(|s| **s == ProbeSample::Lost)
            .count();
        lost as f64 / self.samples.len() as f64
    }

    /// The jitter (milliseconds): the mean of the absolute differences between adjacent RTT samples (a
    /// simple RFC 3550-style jitter). Requires >= 2 RTT samples, otherwise `None`.
    pub fn jitter_ms(&self) -> Option<f64> {
        let rtts: Vec<u64> = self
            .samples
            .iter()
            .filter_map(|s| match s {
                ProbeSample::Rtt(v) => Some(*v),
                ProbeSample::Lost => None,
            })
            .collect();
        if rtts.len() < 2 {
            return None;
        }
        let sum: u64 = rtts.windows(2).map(|w| w[0].abs_diff(w[1])).sum();
        Some(sum as f64 / (rtts.len() - 1) as f64)
    }
}

// ---------------------------------------------------------------------------
// Per-target tracker
// ---------------------------------------------------------------------------

/// A probe target identifier: the peer's wg public key + the candidate endpoint.
///
/// The public key is the unified key for every consumer: the SEL-003 degradation map /
/// [`RecoveryGate`], the SEL-002 [`SwitchGate`], and the SEL-004 candidate details all look windows
/// up by `PeerEndpoints::public_key` (confirmed by the 2026-11-13 SEL-002 real-death re-verification:
/// keying by device_id mismatched all three consumers, blinding degradation / switching / candidate
/// details in production).
pub type ProbeTarget = (String, EndpointCandidate);

/// A tracker holding one sliding window per `(peer, candidate)`.
///
/// The candidate sets come from the peer list synced on the 30s heartbeat; this tracker only adds
/// and removes targets and performs no network operation of its own (the transport is injected by
/// [`probe_round`]).
#[derive(Debug, Clone)]
pub struct ProbeTracker {
    capacity: usize,
    windows: BTreeMap<ProbeTarget, ProbeWindow>,
}

impl ProbeTracker {
    /// Create a tracker; every target's window capacity is `capacity` (floored at 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            windows: BTreeMap::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record one probe against the target `(peer public key, candidate)`.
    pub fn record(&mut self, public_key: &str, candidate: EndpointCandidate, sample: ProbeSample) {
        self.windows
            .entry((public_key.to_string(), candidate))
            .or_insert_with(|| ProbeWindow::new(self.capacity))
            .record(sample);
    }

    /// Read the target's current window (no record -> `None`).
    pub fn window(&self, public_key: &str, candidate: EndpointCandidate) -> Option<&ProbeWindow> {
        self.windows.get(&(public_key.to_string(), candidate))
    }

    /// The number of targets currently tracked (including historical targets that have lost their
    /// candidates; after [`retain_peers`](Self::retain_peers) only live targets remain).
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// Every target -> window (a read-only view).
    pub fn windows(&self) -> &BTreeMap<ProbeTarget, ProbeWindow> {
        &self.windows
    }

    /// Forget targets that are no longer in the current peer set: a peer going offline / a candidate
    /// disappearing reclaims the statistics, so dead targets do not drag stale windows around and
    /// hold memory (SEL-002 scoring for peers outside the candidate set is meaningless anyway).
    pub fn retain_peers(&mut self, peers: &[PeerEndpoints]) {
        let live: BTreeSet<ProbeTarget> = peers
            .iter()
            .flat_map(|p| p.endpoints.iter().map(|c| (p.public_key.clone(), *c)))
            .collect();
        self.windows.retain(|k, _| live.contains(k));
    }
}

// ---------------------------------------------------------------------------
// One probe round orchestration
// ---------------------------------------------------------------------------

/// The summary of one probe round (for logging / test assertions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRound {
    /// The number of probes issued this round (peers × each one's candidate count).
    pub issued: usize,
    /// How many of them were recorded as losses (the transport returned `None`).
    pub lost: usize,
}

/// Send one probe to each candidate endpoint of each peer and record them into [`ProbeTracker`].
///
/// `transport(ip) -> Option<u128>` measures the RTT (milliseconds): `Some(ms)` is recorded as
/// [`ProbeSample::Rtt`] and `None` (timeout / unreachable / platform unsupported) as
/// [`ProbeSample::Lost`]. The ICMP echo targets the candidate IP (a port is meaningless for ICMP, but
/// it is kept in the target identifier so that later UDP / WG transports can distinguish different
/// candidates of the same IP).
///
/// [`ProbeTracker::retain_peers`] runs before probing: stale targets outside this round's peer set are
/// reclaimed immediately.
pub fn probe_round<F: Fn(Ipv4Addr) -> Option<u128>>(
    tracker: &mut ProbeTracker,
    peers: &[PeerEndpoints],
    transport: F,
) -> ProbeRound {
    tracker.retain_peers(peers);
    let mut issued = 0usize;
    let mut lost = 0usize;
    for peer in peers {
        for candidate in &peer.endpoints {
            let sample = match transport(candidate.ip) {
                Some(ms) => ProbeSample::Rtt(ms.min(u64::MAX as u128) as u64),
                None => {
                    lost += 1;
                    ProbeSample::Lost
                }
            };
            tracker.record(&peer.public_key, *candidate, sample);
            issued += 1;
        }
    }
    ProbeRound { issued, lost }
}

/// Platform default probe transport: on Linux, measure the RTT by sending an ICMP echo via
/// `ping -c 1 -W 1` (both the unprivileged `ping_group_range` and root work, the same source as
/// [`crate::linux::run_ping_rtt`]).
///
/// Windows measures with the same caliber via `ping -n 1 -w 1000` ([`crate::windows_probe`], P0
/// wiring on 2026-11-13: before that, every non-Linux platform returned `None` and was recorded as
/// a loss, leaving probing blind on the primary platform).
/// Other platforms return `None` — `probe_round` records a loss and never pretends an RTT was probed.
#[cfg(target_os = "linux")]
pub fn default_transport(ip: Ipv4Addr) -> Option<u128> {
    crate::linux::run_ping_rtt(ip)
}

/// Platform default probe transport (Windows): see the docs of the Linux variant above.
#[cfg(target_os = "windows")]
pub fn default_transport(ip: Ipv4Addr) -> Option<u128> {
    crate::windows_probe::run_ping_rtt(ip)
}

/// Platform default probe transport (all other platforms): there is no probe implementation, so it
/// records a loss (see the docs above).
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn default_transport(_ip: Ipv4Addr) -> Option<u128> {
    None
}

// ---------------------------------------------------------------------------
// SEL-002 path scoring and hysteresis switching (pure logic, no IO)
// ---------------------------------------------------------------------------

/// The loss penalty factor: `score = rtt_ms * (1 + LOSS_PENALTY * loss_rate)`.
/// RTT is the dominant term (milliseconds serve directly as the base) and the loss rate multiplies
/// it upward — 10% loss doubles the score, and an all-lost window with no RTT samples scores +∞
/// (the worst). The heavy loss penalty ensures a degraded path suffering a "loss spike" is not
/// misjudged as good just because its median RTT is still low.
pub const LOSS_PENALTY: f64 = 10.0;

/// Path score (the SEL-002 scoring): `rtt_ms * (1 + LOSS_PENALTY * loss_rate)`.
///
/// - an empty window -> `None` (no readings yet, it does not take part in comparisons);
/// - a window with no RTT samples (all lost) -> `Some(+∞)` (the worst; any path with an RTT is better);
/// - otherwise -> `Some(rtt median * (1 + LOSS_PENALTY * loss rate))`.
///
/// Lower is better. SEL-002's hysteresis switching makes its "the new path beats the current one by
/// >= 30%" decision directly on this.
pub fn score(window: &ProbeWindow) -> Option<f64> {
    if window.is_empty() {
        return None;
    }
    match window.rtt_ms() {
        None => Some(f64::INFINITY),
        Some(rtt) => Some(rtt as f64 * (1.0 + LOSS_PENALTY * window.loss_rate())),
    }
}

/// One hysteresis switch decision (SEL-002): the target candidate + a human-readable reason (for event records).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchDecision {
    /// The candidate endpoint being switched to.
    pub to: EndpointCandidate,
    /// The switch reason (e.g. "score 60.0 beats 100.0 by >=30% for 3 consecutive samples").
    pub reason: String,
}

/// The bookkeeping of one switch (the carrier of the plan-1 cooldown): the switch instant, the old
/// endpoint before the switch (the rollback target), the current endpoint after the switch, and
/// whether the one-shot rollback has been used during the cooldown (plan 8).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SwitchRecord {
    at_ms: u64,
    from: EndpointCandidate,
    to: EndpointCandidate,
    rolled_back: bool,
}

/// The hysteresis gate (SEL-002): a new path must score better than the current one
/// by at least `margin` (default 30%) for **`required` consecutive** samples before
/// switching — debounce. A pure state machine, no IO.
///
/// State records the consecutive-better count per `(peer, candidate)`: a candidate getting worse,
/// the current path re-taking the lead, or the switch target changing each reset the relevant
/// count; a single jitter blip never flips the gate.
///
/// **Switch cooldown** (plan 1, 2026-11-17): for `cooldown_ms` after each switch (default
/// interval×required×2 = 30s, capped at 60s), no further switch is allowed and the current path may
/// not be judged degraded (consumers query [`Self::in_cooldown`] and exempt themselves, e.g. `degraded_map`).
/// This addresses the "switch blackout band" in the user's measured three-state ping flapping
/// (100% timeout ↔ 1.7-3.3s huge latency ↔ 12ms full speed) — right after a switch the new path's
/// handshake / probe window has not stood up yet, and the hysteresis gate and the degradation gate
/// acting immediately on the reading-less new current path are exactly the amplifier of the flapping;
/// the cooldown shields that vacuum period. Too long a cooldown would delay switching on real
/// failures, so the configuration side clamps it to <= 60s.
#[derive(Debug, Clone)]
pub struct SwitchGate {
    required: usize,
    margin: f64,
    /// The switch cooldown (milliseconds). 0 = cooldown off (re-evaluation is possible immediately
    /// after a switch).
    cooldown_ms: u64,
    /// `(peer, candidate)` -> the number of samples that consecutively met "better than the current path by >= margin".
    streaks: BTreeMap<ProbeTarget, usize>,
    /// Peer public key -> the most recent switch bookkeeping (the carrier of the cooldown and rollback).
    last_switch: BTreeMap<String, SwitchRecord>,
}

impl SwitchGate {
    /// Create a hysteresis gate. `required` is floored at 1; `margin` is clamped into `(0.0, 1.0]`;
    /// `cooldown_ms` = the switch cooldown (0 disables it).
    pub fn new(required: usize, margin: f64, cooldown_ms: u64) -> Self {
        Self {
            required: required.max(1),
            margin: margin.clamp(f64::EPSILON, 1.0),
            cooldown_ms,
            streaks: BTreeMap::new(),
            last_switch: BTreeMap::new(),
        }
    }

    pub fn required(&self) -> usize {
        self.required
    }

    pub fn margin(&self) -> f64 {
        self.margin
    }

    /// Whether this peer is inside the switch cooldown (within `cooldown_ms` after the most recent
    /// switch, endpoint inclusive). Cooldown semantics: no further switch (intercepted up front
    /// inside [`Self::evaluate`]) + no degradation verdict against the current path (the degradation
    /// consumer calls this method and exempts itself).
    ///
    /// Endpoint inclusive (`now <= at + cooldown`): the reconciliation cycle and the probe cycle
    /// differ by one poll interval (default 30s = the default cooldown), and only an inclusive
    /// endpoint keeps the reconciliation round right after a switch (the plan-8 rollback check)
    /// inside the cooldown.
    pub fn in_cooldown(&self, peer: &str, now_ms: u64) -> bool {
        self.last_switch
            .get(peer)
            .is_some_and(|rec| now_ms <= rec.at_ms.saturating_add(self.cooldown_ms))
    }

    /// The one-shot rollback to the old endpoint within the switch cooldown (plan 8): when inside the
    /// cooldown, the rollback has not been used yet, and the current path is still the target face
    /// of the last switch -> return the old endpoint and book it (a rollback also passes through
    /// the cooldown: the cooldown start resets to this round's `now_ms` and the one-shot marker is
    /// set — at most one rollback per switch, never ping-pong). Outside the cooldown / already rolled
    /// back / the current path has been moved by roaming or a later action -> `None`. The caller
    /// decides the evidence for "when does the new path count as bad"; this gate only handles
    /// permission and bookkeeping (kept unified inside SwitchGate, proposal (d)).
    pub fn rollback(
        &mut self,
        peer: &str,
        current: EndpointCandidate,
        now_ms: u64,
    ) -> Option<EndpointCandidate> {
        if !self.in_cooldown(peer, now_ms) {
            return None;
        }
        let rec = self.last_switch.get_mut(peer)?;
        if rec.rolled_back || rec.to != current {
            return None;
        }
        rec.rolled_back = true;
        rec.at_ms = now_ms;
        Some(rec.from)
    }

    /// Evaluate one round: given the current path and all candidate windows, decide whether to switch.
    ///
    /// - `current`: the currently selected candidate (`None` = no direct path yet; the initial
    ///   selection is the DirectManager's job, this gate only does **switching between established
    ///   paths**);
    /// - `windows`: this peer's candidate -> window snapshot (the view of
    ///   [`ProbeTracker::windows`] filtered by the peer's public key);
    /// - `now_ms`: the current Unix milliseconds (for the cooldown; a pure state machine never
    ///   reads the system clock, and tests can inject a virtual clock).
    ///
    /// Returns `Some(SwitchDecision)` if and only if: not inside the cooldown, and there exists a
    /// candidate whose score is strictly lower than the current path's and `score <= current score *
    /// (1 - margin)`, and that candidate has met this condition for `required` consecutive rounds.
    /// Once the threshold is reached the candidate's count is reset (one switch, one count) and the
    /// switch bookkeeping is recorded (the cooldown start = this round's `now_ms`).
    pub fn evaluate(
        &mut self,
        peer: &str,
        current: Option<EndpointCandidate>,
        windows: &BTreeMap<ProbeTarget, ProbeWindow>,
        now_ms: u64,
    ) -> Option<SwitchDecision> {
        // Evaluation freezes during the cooldown: the streak does not advance (after the cooldown ends the
        // consecutive count must be rebuilt from scratch — spending required×interval extra seconds
        // in exchange for "never flips during the post-switch vacuum period").
        if self.in_cooldown(peer, now_ms) {
            return None;
        }
        let current = current?;
        if windows.is_empty() {
            return None;
        }
        // The current path has no window (e.g. WG has roamed onto a face outside the candidate table,
        // confirmed on a real machine on 2026-11-13: a stable 192.168.5.0/24 roaming face is not in
        // the candidate table -> no reading) -> **do not switch**. The "no RTT reading = ∞" semantics
        // of `score` should only be used to compare candidates (an all-lost candidate really is the
        // worst); a current path with "no reading" must not be treated as the worst — that would
        // actively kick a working stable path over to a candidate that is visible in the candidate
        // table (but not necessarily better for the WG session), triggering session rebuilds and even
        // a classify-240 degradation limit cycle. With no evidence, do not touch the current path;
        // path death is owned by the handshake-age classify and the SEL-003 degradation gate.
        let current_score = windows.get(&(peer.to_string(), current)).and_then(score)?;

        // The best candidate = the lowest score (deterministic: on a tie, the smallest address wins).
        let mut best_candidate: Option<EndpointCandidate> = None;
        let mut best_score = f64::INFINITY;
        for ((p, c), w) in windows {
            if p != peer {
                continue;
            }
            let s = score(w).unwrap_or(f64::INFINITY);
            let better = match best_candidate {
                None => true,
                Some(bc) => s < best_score || (s == best_score && *c < bc),
            };
            if better {
                best_candidate = Some(*c);
                best_score = s;
            }
        }
        let best_candidate = best_candidate?;

        if best_candidate == current {
            // The current path is still the best: every candidate's win streak is cleared (the consecutive condition broke).
            self.streaks.clear();
            return None;
        }

        // The new path must be **strictly** better and beat the current path by >= margin (debounce).
        let improved =
            best_score < current_score && best_score <= current_score * (1.0 - self.margin);
        if !improved {
            self.streaks.remove(&(peer.to_string(), best_candidate));
            return None;
        }

        let key = (peer.to_string(), best_candidate);
        let streak = self.streaks.entry(key.clone()).or_insert(0);
        *streak += 1;
        if *streak >= self.required {
            // The plan-8 target pre-check made explicit: the switch target's window must be non-empty and
            // have at least one successful RTT beat — an "all Lost / no reading" face has no
            // availability evidence and must never become a switch target. Score's ∞ ordering already
            // blocks such targets on the normal path (all lost = worst, and strictly-better requires a
            // finite score); this turns the implicit premise into an explicit contract: on a failed
            // pre-check, prefer staying on the current path and re-gathering evidence next cycle.
            let target_live = windows.get(&key).is_some_and(|w| {
                !w.is_empty() && w.samples().iter().any(|s| matches!(s, ProbeSample::Rtt(_)))
            });
            if !target_live {
                self.streaks.remove(&key);
                return None;
            }
            let reason = format!(
                "score {best_score:.1} beats current {current_score:.1} by >= {:.0}% for {} consecutive samples",
                self.margin * 100.0,
                *streak
            );
            self.streaks.remove(&key);
            // Switch bookkeeping: the cooldown start + the old endpoint (the plan-8 rollback target).
            self.last_switch.insert(
                peer.to_string(),
                SwitchRecord {
                    at_ms: now_ms,
                    from: current,
                    to: best_candidate,
                    rolled_back: false,
                },
            );
            Some(SwitchDecision {
                to: best_candidate,
                reason,
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// SEL-003 hub backstop: direct degradation detection and recovery gate (pure logic, no IO)
// ---------------------------------------------------------------------------

/// The default "loss spike" threshold (SEL-003): a window loss rate >= this
/// value counts as a "loss spike" and sends us straight back to the relay. Narrowed from 0.5 to 0.2 on
/// 2026-11-17 (user decision): under the old threshold a face with 49% loss was still "below the spike"
/// and healthy enough to serve as FLIP-001 recovery-gate bypass evidence and drag the direct connect back
/// up — and that is exactly where the degraded-face release in the measured ping three-state flapping
/// (100% timeout ↔ 1.7-3.3s huge latency ↔ 12ms full speed) came from. It is now pushed down by the agent
/// configuration `ProbeConfig::loss_spike` (default 0.2); this constant is only the configuration default
/// and a test baseline.
pub const LOSS_SPIKE_THRESHOLD: f64 = 0.2;

/// The last-beats timeout tolerance (SEL-003): the window's tail must hold this
/// many consecutive `Lost` beats before the path counts as degraded. With a 20-beat window (~100s of
/// evidence), 3 beats ≈ 15s of sustained loss is required for a true verdict — a single transient beat
/// triggers nothing (on a real machine recorded on 2026-11-14: an ICMP single-beat transient on the ZT
/// face once triggered a demote by itself while the handshake age was fresh at 56–120s and classify was
/// innocent — the JMrE/FSaf ~2min direct↔hub limit cycle).
pub const LAST_LOST_TOLERANCE: usize = 3;

/// The direct-path degradation verdict (SEL-003):
/// - an empty window -> `false` (no readings yet, no abrupt fallback to the relay);
/// - a window shorter than [`LAST_LOST_TOLERANCE`] beats that is all `Lost` -> `true` (short-window
///   low-traffic endpoints get no exemption, see below);
/// - a window >= [`LAST_LOST_TOLERANCE`] beats with no RTT samples at all (all `Lost`) -> `false` (the
///   no-baseline exemption applies, see below);
/// - a window loss rate >= `loss_spike` (a loss spike, default [`LOSS_SPIKE_THRESHOLD`], pushed by the
///   agent configuration `ProbeConfig::loss_spike`) -> `true`;
/// - [`LAST_LOST_TOLERANCE`] consecutive `Lost` beats at the window tail (a sustained timeout) -> `true`;
///   a single transient beat triggers nothing;
/// - a window RTT median >= `degrade_rtt_ms` (latency degradation) -> `true`;
/// - anything else -> `false`.
///
/// Any hit means "fall back to the relay immediately": the degraded direct path no longer carries traffic,
/// and the hub peer's whole route section takes over automatically (with the /32 direct peer removed, the
/// longest-prefix match falls back to the hub). Recovery must go through the [`RecoveryGate`] hysteresis
/// switch-back.
///
/// **The latency dimension** (2026-11-13, SEL-002 two-machine acceptance follow-up): there were only two
/// rules, loss/timeout — a path that probes successfully throughout but has a deeply degraded RTT (recorded
/// at 1715ms `probe_ok` on a real machine) never degraded, and the direct connect was pinned by the
/// "the link is alive" evidence. Median-based verdicts are naturally equivalent to "N consecutive beats over
/// the threshold": a single peak / a few peaks cannot move the median (debounce), only sustained deep
/// degradation hits. The threshold is pushed by the agent configuration `ProbeConfig::degrade_rtt_ms`
/// (default 800ms, rationale in its doc).
///
/// **The no-baseline exemption** (2026-11-13 SEL-002 imac/openclaw real-death re-verification): when the
/// peer's firewall blocks ICMP (Windows blocks echo by default) the probes are all `Lost`, but the WG
/// tunnel may be perfectly healthy (kernel handshake kept renewing, 7–8ms measured) — the same philosophy
/// as the promotion bar "an ICMP probe failure does not block promotion" (the Windows grid firewall drops
/// 100% of packets to the wg interface): with no "went from good to bad" window evidence, do not call it
/// degraded. Real death is owned by the handshake-age classify (past the healthy window -> Demote), not by
/// probing.
///
/// **Last-beat continuity** (2026-11-14 SEL-003 last-Lost softening): the old "one `Lost` beat at the tail
/// is degradation" was over-sensitive to ZT-face single-beat transients — a real machine recorded a demote
/// with a fresh 56–120s handshake age (classify innocent), and such transients were the trigger, feeding the
/// JMrE/FSaf direct↔hub limit cycle. Now only a run of [`LAST_LOST_TOLERANCE`] consecutive beats at the tail
/// acts. The loss-spike / median branches are naturally multi-beat and stay unchanged.
///
/// **The young-window exemption** (plan 1, 2026-11-17): window samples < `min_samples` (default 4, pushed
/// by the agent configuration `ProbeConfig::degrade_min_samples`) -> always `false`. Same semantics as the
/// no-baseline exemption: what is exempted is "insufficient readings", not "bad readings" — a just-switched
/// path or a newly observed face's window has not stood up yet, and aggregate statistics over a few beats
/// (loss rate / median) have enormous variance, so judging degradation from them is exactly the amplifier
/// of the measured ping three-state flapping. The cost: the old 11-14 rule "a short window of all `Lost` is
/// directly judged degraded (low-traffic endpoints get no exemption)" is replaced by this exemption under
/// the default `min_samples` >= 3 — windows with insufficient readings never act, and real death is still
/// owned by the handshake-age classify (this function's standing philosophy). With `min_samples` set to 1-2
/// the short-window branch stays reachable (all `Lost` is directly judged degraded).
pub fn is_degraded(
    window: &ProbeWindow,
    degrade_rtt_ms: u64,
    loss_spike: f64,
    min_samples: usize,
) -> bool {
    let samples = window.samples();
    // Young-window exemption: insufficient readings means no degradation verdict (an empty window also
    // hits 0 < min_samples).
    if samples.len() < min_samples.max(1) {
        return false;
    }
    let median_rtt = window.rtt_ms();
    if samples.len() < LAST_LOST_TOLERANCE {
        // Short window (< 3 beats, reachable only when min_samples <= 2): tail continuity is off the
        // table, judge straight on the existing samples — all Lost is degradation (the no-baseline
        // exemption does not apply to short windows).
        if samples.iter().all(|s| matches!(s, ProbeSample::Lost)) {
            return true;
        }
    } else if median_rtt.is_none() {
        // No-baseline exemption: no successful sample in the window -> there is no baseline to compare
        // against, so "loss spike / timeout" is out of the question; real death is owned by the
        // handshake-age classify.
        return false;
    }
    if window.loss_rate() >= loss_spike {
        return true;
    }
    // Last-beat continuity: only a run of LAST_LOST_TOLERANCE consecutive Lost beats at the tail is a true
    // degradation (a single transient beat triggers nothing, see doc).
    if samples
        .iter()
        .rev()
        .take(LAST_LOST_TOLERANCE)
        .all(|s| matches!(s, ProbeSample::Lost))
    {
        return true;
    }
    median_rtt.is_some_and(|m| m >= degrade_rtt_ms)
}

/// The recovery gate (SEL-003): after a direct degradation falls back to the relay, the peer must be
/// healthy for `required` consecutive rounds before the hysteresis gate allows switching back. A pure
/// state machine, no IO.
#[derive(Debug, Clone)]
pub struct RecoveryGate {
    required: usize,
    /// Peer public key -> the count of consecutive healthy rounds.
    streaks: BTreeMap<String, usize>,
}

impl RecoveryGate {
    /// Create a recovery gate. `required` is floored at 1.
    pub fn new(required: usize) -> Self {
        Self {
            required: required.max(1),
            streaks: BTreeMap::new(),
        }
    }

    pub fn required(&self) -> usize {
        self.required
    }

    /// Record one round's probe outcome. `healthy` = this peer's direct path was healthy (not degraded)
    /// this round. Returns `true` if and only if the peer has now been healthy for `required` consecutive
    /// rounds (switch-back allowed); an unhealthy round clears the count (the consecutive condition broke).
    pub fn record(&mut self, peer: &str, healthy: bool) -> bool {
        if !healthy {
            self.streaks.remove(peer);
            return false;
        }
        let streak = self.streaks.entry(peer.to_string()).or_insert(0);
        *streak += 1;
        *streak >= self.required
    }

    /// Whether the peer has currently recovered (`required` consecutive healthy rounds).
    pub fn is_ready(&self, peer: &str) -> bool {
        self.streaks.get(peer).is_some_and(|s| *s >= self.required)
    }

    /// Forget peers that are no longer in the current peer set (their counters are reclaimed after
    /// going offline or being revoked).
    pub fn retain(&mut self, peers: &[String]) {
        let live: BTreeSet<&str> = peers.iter().map(|s| s.as_str()).collect();
        self.streaks.retain(|k, _| live.contains(k.as_str()));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Test baseline for the young-window exemption floor (same value as the
    /// ProbeConfig::degrade_min_samples default of 4).
    const MIN_SAMPLES: usize = 4;

    fn lan(ip: &str, port: u16) -> EndpointCandidate {
        EndpointCandidate::lan(ip.parse().unwrap(), port)
    }

    fn peer(key: &str, vip: &str, endpoints: &[EndpointCandidate]) -> PeerEndpoints {
        PeerEndpoints {
            device_id: meshlet_domain::DeviceId(key.into()),
            public_key: key.into(),
            virtual_ipv4: vip.parse().unwrap(),
            name: format!("{key}-name"),
            endpoints: endpoints.to_vec(),
        }
    }

    // -- ProbeWindow ---------------------------------------------------------

    #[test]
    fn window_clamps_capacity_to_one() {
        let w = ProbeWindow::new(0);
        assert_eq!(w.capacity(), 1);
    }

    #[test]
    fn window_records_and_evicts_oldest() {
        let mut w = ProbeWindow::new(3);
        w.record(ProbeSample::Rtt(10));
        w.record(ProbeSample::Rtt(20));
        w.record(ProbeSample::Rtt(30));
        assert_eq!(w.len(), 3);
        // The 4th record evicts the oldest (10).
        w.record(ProbeSample::Rtt(40));
        assert_eq!(w.len(), 3);
        assert_eq!(
            w.samples().iter().copied().collect::<Vec<_>>(),
            vec![
                ProbeSample::Rtt(20),
                ProbeSample::Rtt(30),
                ProbeSample::Rtt(40)
            ]
        );
    }

    #[test]
    fn rtt_median_handles_odd_and_even_counts() {
        let mut w = ProbeWindow::new(8);
        for v in [30, 10, 20] {
            w.record(ProbeSample::Rtt(v));
        }
        // Odd: sorted 10,20,30 -> median 20.
        assert_eq!(w.rtt_ms(), Some(20));
        w.record(ProbeSample::Rtt(40));
        // Even: 10,20,30,40 -> mean (20+30)/2 = 25.
        assert_eq!(w.rtt_ms(), Some(25));
    }

    #[test]
    fn rtt_median_ignores_lost_samples() {
        let mut w = ProbeWindow::new(8);
        w.record(ProbeSample::Lost);
        w.record(ProbeSample::Rtt(50));
        w.record(ProbeSample::Lost);
        w.record(ProbeSample::Rtt(70));
        // Only 50,70 -> median 60.
        assert_eq!(w.rtt_ms(), Some(60));
    }

    #[test]
    fn rtt_none_when_no_rtt_samples() {
        let mut w = ProbeWindow::new(4);
        w.record(ProbeSample::Lost);
        assert_eq!(w.rtt_ms(), None);
        assert!(ProbeWindow::new(4).rtt_ms().is_none());
    }

    #[test]
    fn loss_rate_counts_lost_over_total() {
        let mut w = ProbeWindow::new(5);
        w.record(ProbeSample::Rtt(10));
        w.record(ProbeSample::Lost);
        w.record(ProbeSample::Rtt(20));
        w.record(ProbeSample::Lost);
        assert_eq!(w.loss_rate(), 0.5);
        // All lost.
        let mut all = ProbeWindow::new(2);
        all.record(ProbeSample::Lost);
        all.record(ProbeSample::Lost);
        assert_eq!(all.loss_rate(), 1.0);
        // An empty window -> 0.
        assert_eq!(ProbeWindow::new(2).loss_rate(), 0.0);
    }

    #[test]
    fn jitter_is_mean_abs_diff_of_consecutive_rtts() {
        let mut w = ProbeWindow::new(8);
        for v in [10, 20, 25] {
            w.record(ProbeSample::Rtt(v));
        }
        // Adjacent differences |10-20|=10, |20-25|=5 -> mean 7.5.
        assert_eq!(w.jitter_ms(), Some(7.5));
    }

    #[test]
    fn jitter_none_with_fewer_than_two_rtts() {
        let mut w = ProbeWindow::new(4);
        w.record(ProbeSample::Rtt(10));
        assert_eq!(w.jitter_ms(), None);
        w.record(ProbeSample::Lost);
        assert_eq!(w.jitter_ms(), None);
    }

    // -- ProbeTracker --------------------------------------------------------

    #[test]
    fn tracker_records_per_target_independently() {
        let mut t = ProbeTracker::new(4);
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        t.record("dev-b", c1, ProbeSample::Rtt(11));
        t.record("dev-b", c2, ProbeSample::Lost);
        t.record("dev-b", c1, ProbeSample::Rtt(13));
        assert_eq!(t.len(), 2);
        assert_eq!(t.window("dev-b", c1).unwrap().rtt_ms(), Some(12));
        assert_eq!(t.window("dev-b", c2).unwrap().loss_rate(), 1.0);
        assert!(t.window("dev-x", c1).is_none());
    }

    #[test]
    fn retain_peers_drops_targets_of_removed_peers() {
        let mut t = ProbeTracker::new(4);
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        t.record("dev-b", c1, ProbeSample::Rtt(11));
        t.record("dev-c", c2, ProbeSample::Rtt(12));
        // Only dev-b left: dev-c's target is reclaimed.
        t.retain_peers(&[peer("dev-b", "10.240.0.3", &[c1])]);
        assert_eq!(t.len(), 1);
        assert!(t.window("dev-c", c2).is_none());
        assert!(t.window("dev-b", c1).is_some());
    }

    // -- probe_round ---------------------------------------------------------

    #[test]
    fn probe_round_records_rtt_and_lost_via_transport() {
        let mut t = ProbeTracker::new(4);
        let peers = vec![
            peer(
                "dev-b",
                "10.240.0.3",
                &[lan("192.168.1.50", 51821), lan("192.168.1.60", 51821)],
            ),
            peer("dev-c", "10.240.0.4", &[lan("10.0.0.7", 51821)]),
        ];
        // Transport: .50 is reachable (7ms), .60 and 10.0.0.7 time out.
        let round = probe_round(&mut t, &peers, |ip| match ip.octets()[3] {
            50 => Some(7),
            _ => None,
        });
        assert_eq!(round.issued, 3);
        assert_eq!(round.lost, 2);
        assert_eq!(
            t.window("dev-b", lan("192.168.1.50", 51821))
                .unwrap()
                .rtt_ms(),
            Some(7)
        );
        assert_eq!(
            t.window("dev-b", lan("192.168.1.60", 51821))
                .unwrap()
                .loss_rate(),
            1.0
        );
        assert_eq!(
            t.window("dev-c", lan("10.0.0.7", 51821))
                .unwrap()
                .loss_rate(),
            1.0
        );
    }

    #[test]
    fn probe_round_retains_only_live_peers() {
        let mut t = ProbeTracker::new(4);
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let first = vec![peer("dev-b", "10.240.0.3", &[c1, c2])];
        probe_round(&mut t, &first, |_| Some(5));
        assert_eq!(t.len(), 2);
        // Round 2 leaves only c1 for dev-b: c2's target is reclaimed.
        let second = vec![peer("dev-b", "10.240.0.3", &[c1])];
        probe_round(&mut t, &second, |_| Some(6));
        assert_eq!(t.len(), 1);
        assert!(t.window("dev-b", c2).is_none());
        assert_eq!(t.window("dev-b", c1).unwrap().rtt_ms(), Some(5));
    }

    /// Probe windows must be keyed under `public_key` (in production device_id != public_key is the norm):
    /// the degradation map / the hysteresis gate / the candidate details all look windows up by public
    /// key (the 2026-11-13 SEL-002 real-death recheck pinned down that keying on device_id made all
    /// three consumers mismatch, leaving production completely blind).
    #[test]
    fn probe_round_keys_windows_by_public_key() {
        let mut t = ProbeTracker::new(4);
        let c1 = lan("192.168.1.50", 51821);
        let mut p = peer("dev-reg-5", "10.240.0.3", &[c1]);
        p.public_key = "JMrE4SZy-pub".into();
        probe_round(&mut t, &[p], |_| Some(9));
        assert!(t.window("JMrE4SZy-pub", c1).is_some());
        assert!(t.window("dev-reg-5", c1).is_none());
    }

    // -- score ----------------------------------------------------------------

    #[test]
    fn score_uses_rtt_with_loss_penalty_and_penalizes_full_loss() {
        // No loss: score = rtt.
        let mut w = ProbeWindow::new(4);
        w.record(ProbeSample::Rtt(100));
        assert_eq!(score(&w), Some(100.0));
        // 50% loss: score = 100 * (1 + 10*0.5) = 600.
        let mut half = ProbeWindow::new(4);
        half.record(ProbeSample::Rtt(100));
        half.record(ProbeSample::Lost);
        assert_eq!(score(&half), Some(600.0));
        // All lost: no RTT samples -> +inf (worst).
        let mut all = ProbeWindow::new(4);
        all.record(ProbeSample::Lost);
        assert_eq!(score(&all), Some(f64::INFINITY));
        // An empty window -> None (no reading yet).
        assert_eq!(score(&ProbeWindow::new(4)), None);
    }

    // -- SwitchGate -----------------------------------------------------------

    #[test]
    fn switch_gate_switches_after_required_consecutive_better_samples() {
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(3, 0.30, 0);
        let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();

        // The first 2 rounds: c2 scores 60 against c1's 100, which clears >=30% but has not lasted 3 rounds in a row.
        for _ in 0..2 {
            windows.clear();
            let mut w1 = ProbeWindow::new(8);
            w1.record(ProbeSample::Rtt(100));
            let mut w2 = ProbeWindow::new(8);
            w2.record(ProbeSample::Rtt(60));
            windows.insert(("dev-b".into(), c1), w1);
            windows.insert(("dev-b".into(), c2), w2);
            assert!(gate.evaluate("dev-b", Some(c1), &windows, 0).is_none());
        }
        // Round 3: 3 consecutive rounds -> switch.
        windows.clear();
        let mut w1 = ProbeWindow::new(8);
        w1.record(ProbeSample::Rtt(100));
        let mut w2 = ProbeWindow::new(8);
        w2.record(ProbeSample::Rtt(60));
        windows.insert(("dev-b".into(), c1), w1);
        windows.insert(("dev-b".into(), c2), w2);
        let decision = gate
            .evaluate("dev-b", Some(c1), &windows, 0)
            .expect("switch");
        assert_eq!(decision.to, c2);
        assert!(decision.reason.contains("3 consecutive"));
    }

    #[test]
    fn switch_gate_jitter_does_not_flip() {
        // Jitter scenario: c1 and c2 alternate in the lead with a gap under 30% -> never switch.
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(3, 0.30, 0);
        for round in 0..20u64 {
            let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
            // Alternating leads but the gap is only 10% (below the 30% hysteresis).
            let (a, b) = if round % 2 == 0 { (100, 90) } else { (90, 100) };
            let mut w1 = ProbeWindow::new(8);
            w1.record(ProbeSample::Rtt(a));
            let mut w2 = ProbeWindow::new(8);
            w2.record(ProbeSample::Rtt(b));
            windows.insert(("dev-b".into(), c1), w1);
            windows.insert(("dev-b".into(), c2), w2);
            assert!(
                gate.evaluate("dev-b", Some(c1), &windows, 0).is_none(),
                "jitter must not flip the path (round {round})"
            );
        }
    }

    #[test]
    fn switch_gate_resets_streak_when_current_is_best_again() {
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(3, 0.30, 0);
        let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();

        // 2 rounds where c2 is better (consecutive count = 2).
        for _ in 0..2 {
            windows.clear();
            let mut w1 = ProbeWindow::new(8);
            w1.record(ProbeSample::Rtt(100));
            let mut w2 = ProbeWindow::new(8);
            w2.record(ProbeSample::Rtt(60));
            windows.insert(("dev-b".into(), c1), w1);
            windows.insert(("dev-b".into(), c2), w2);
            assert!(gate.evaluate("dev-b", Some(c1), &windows, 0).is_none());
        }
        // Round 3: c1 is best again -> the count resets and nothing switches.
        windows.clear();
        let mut w1 = ProbeWindow::new(8);
        w1.record(ProbeSample::Rtt(50));
        let mut w2 = ProbeWindow::new(8);
        w2.record(ProbeSample::Rtt(100));
        windows.insert(("dev-b".into(), c1), w1);
        windows.insert(("dev-b".into(), c2), w2);
        assert!(gate.evaluate("dev-b", Some(c1), &windows, 0).is_none());
        // 3 more rounds where c2 is better: the count restarts from 0, so a full 3 rounds are needed.
        for _ in 0..2 {
            windows.clear();
            let mut w1 = ProbeWindow::new(8);
            w1.record(ProbeSample::Rtt(100));
            let mut w2 = ProbeWindow::new(8);
            w2.record(ProbeSample::Rtt(60));
            windows.insert(("dev-b".into(), c1), w1);
            windows.insert(("dev-b".into(), c2), w2);
            assert!(gate.evaluate("dev-b", Some(c1), &windows, 0).is_none());
        }
        windows.clear();
        let mut w1 = ProbeWindow::new(8);
        w1.record(ProbeSample::Rtt(100));
        let mut w2 = ProbeWindow::new(8);
        w2.record(ProbeSample::Rtt(60));
        windows.insert(("dev-b".into(), c1), w1);
        windows.insert(("dev-b".into(), c2), w2);
        assert!(gate.evaluate("dev-b", Some(c1), &windows, 0).is_some());
    }

    /// The current path has no window (the roaming plane outside the candidate table, pinned down on a
    /// real machine on 2026-11-13: the stable 192.168.5.0/24 roaming plane is not in the candidate
    /// table -> no reading -> the old logic scored it as +inf and kicked it off line, triggering
    /// session rebuilds and even a classify-240 degradation limit loop) -> do not switch.
    #[test]
    fn switch_gate_spares_current_path_without_window() {
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(1, 0.30, 0);
        // Only c2 has a reading (48ms); the current path c1 has no window at all.
        let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
        let mut w = ProbeWindow::new(8);
        w.record(ProbeSample::Rtt(48));
        windows.insert(("dev-b".into(), c2), w);
        for _ in 0..5 {
            assert!(
                gate.evaluate("dev-b", Some(c1), &windows, 0).is_none(),
                "no evidence about the current path must not switch"
            );
        }
    }

    #[test]
    fn switch_gate_requires_strict_margin_improvement() {
        // A 20% gap (<30%): no switch even across several consecutive rounds.
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(3, 0.30, 0);
        for _ in 0..5 {
            let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
            let mut w1 = ProbeWindow::new(8);
            w1.record(ProbeSample::Rtt(100));
            let mut w2 = ProbeWindow::new(8);
            w2.record(ProbeSample::Rtt(80));
            windows.insert(("dev-b".into(), c1), w1);
            windows.insert(("dev-b".into(), c2), w2);
            assert!(gate.evaluate("dev-b", Some(c1), &windows, 0).is_none());
        }
    }

    #[test]
    fn switch_gate_full_loss_makes_that_path_worst() {
        // The current path is fully lost (score = +inf) and the other path has an RTT -> switch on the first round (required = 1).
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(1, 0.30, 0);
        let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
        let mut w1 = ProbeWindow::new(8);
        w1.record(ProbeSample::Lost);
        let mut w2 = ProbeWindow::new(8);
        w2.record(ProbeSample::Rtt(40));
        windows.insert(("dev-b".into(), c1), w1);
        windows.insert(("dev-b".into(), c2), w2);
        let decision = gate
            .evaluate("dev-b", Some(c1), &windows, 0)
            .expect("switch");
        assert_eq!(decision.to, c2);
    }

    /// Switch-grace (plan 1, 2026-11-17) nail: after a switch, re-switching is blocked within the cooldown
    /// even when another candidate stays consistently far better than the current path; once the grace
    /// elapses, the ordinary hysteresis gate acts. During the grace the streak does not advance (the
    /// evaluation is frozen), and after it the consecutive count must be gathered again from zero.
    #[test]
    fn switch_gate_cooldown_blocks_re_switch_within_grace() {
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let c3 = lan("192.168.1.70", 51821);
        let mut gate = SwitchGate::new(1, 0.30, 30_000);
        let windows = |entries: [(EndpointCandidate, u64); 3]| {
            let mut w: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
            for (c, rtt) in entries {
                let mut pw = ProbeWindow::new(8);
                pw.record(ProbeSample::Rtt(rtt));
                w.insert(("dev-b".to_string(), c), pw);
            }
            w
        };
        // t=1000: c2 scores 60 against c1's 100, >=30% -> switch (grace start).
        let w = windows([(c1, 100), (c2, 60), (c3, 300)]);
        let decision = gate
            .evaluate("dev-b", Some(c1), &w, 1000)
            .expect("initial switch fires");
        assert_eq!(decision.to, c2);
        assert!(gate.in_cooldown("dev-b", 2000), "within grace");
        assert!(!gate.in_cooldown("dev-b", 31_001), "grace elapsed");
        // t=2000 (within grace): c3 scores 30, far better than the current path c2's 60 -> re-switch still blocked.
        let w = windows([(c1, 100), (c2, 60), (c3, 30)]);
        assert!(
            gate.evaluate("dev-b", Some(c2), &w, 2000).is_none(),
            "re-switch blocked within grace"
        );
        // t=31001 (just past grace): the same better candidate -> the ordinary gate acts.
        let decision = gate
            .evaluate("dev-b", Some(c2), &w, 31_001)
            .expect("switch after grace");
        assert_eq!(decision.to, c3);
    }

    /// Plan-8 target pre-check nail: an all-lost target candidate never switches -- when any RTT-bearing
    /// face is present, the score ordering rules out all-lost faces by itself (inf is worst); when the
    /// current path and the candidate are both all-lost, "strictly better" cannot be met either. The
    /// two together pin the contract: a face without any availability evidence never becomes a switch
    /// target (the explicit pre-check inside evaluate is defense in depth).
    #[test]
    fn switch_gate_never_targets_all_lost_candidate() {
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let c3 = lan("192.168.1.70", 51821);
        let mut gate = SwitchGate::new(1, 0.30, 0);
        // The current path is healthy (100), the only other candidate is all-lost -> no switch.
        let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
        let mut w1 = ProbeWindow::new(8);
        w1.record(ProbeSample::Rtt(100));
        let mut w2 = ProbeWindow::new(8);
        w2.record(ProbeSample::Lost);
        windows.insert(("dev-b".into(), c1), w1);
        windows.insert(("dev-b".into(), c2), w2);
        for round in 0..5u64 {
            assert!(
                gate.evaluate("dev-b", Some(c1), &windows, round).is_none(),
                "all-lost candidate must never be a switch target"
            );
        }
        // The current path and the candidate are both all-lost (neither has availability evidence) -> no
        // switch; a third candidate with an RTT is present -> switch to it.
        let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
        let mut dead1 = ProbeWindow::new(8);
        let mut dead2 = ProbeWindow::new(8);
        for _ in 0..4 {
            dead1.record(ProbeSample::Lost);
            dead2.record(ProbeSample::Lost);
        }
        let mut live = ProbeWindow::new(8);
        live.record(ProbeSample::Rtt(40));
        windows.insert(("dev-b".into(), c1), dead1);
        windows.insert(("dev-b".into(), c2), dead2);
        windows.insert(("dev-b".into(), c3), live);
        let decision = gate
            .evaluate("dev-b", Some(c1), &windows, 10)
            .expect("switch to the live face");
        assert_eq!(
            decision.to, c3,
            "switch goes to the live face, not the all-lost one"
        );
    }

    /// Plan-8 rollback nail: within the grace, a one-shot rollback to the old endpoint; the rollback also
    /// passes the grace (the grace start resets to this round's instant); one-shot -- at most one
    /// rollback per switch; outside the grace, or when the current path is no longer the last switch's
    /// target (moved away by a roam) -> no rollback.
    #[test]
    fn rollback_is_one_shot_within_grace_and_extends_it() {
        let c1 = lan("192.168.1.50", 51821);
        let c2 = lan("192.168.1.60", 51821);
        let mut gate = SwitchGate::new(1, 0.30, 30_000);
        let mut windows: BTreeMap<ProbeTarget, ProbeWindow> = BTreeMap::new();
        let mut w1 = ProbeWindow::new(8);
        w1.record(ProbeSample::Rtt(100));
        let mut w2 = ProbeWindow::new(8);
        w2.record(ProbeSample::Rtt(60));
        windows.insert(("dev-b".into(), c1), w1);
        windows.insert(("dev-b".into(), c2), w2);
        gate.evaluate("dev-b", Some(c1), &windows, 1000)
            .expect("switch c1->c2");
        // Roll back c2->c1 within the grace.
        assert_eq!(gate.rollback("dev-b", c2, 2000), Some(c1));
        // One-shot: a second request within the same grace -> None.
        assert_eq!(gate.rollback("dev-b", c2, 3000), None);
        // The rollback also passes the grace: the grace start resets to 2000, so 31_000 is still within the reset grace.
        assert!(
            gate.in_cooldown("dev-b", 31_000),
            "grace restarts at rollback"
        );
        assert!(
            !gate.in_cooldown("dev-b", 32_001),
            "and expires from the rollback instant"
        );
        // Outside the grace: no rollback.
        assert_eq!(gate.rollback("dev-b", c1, 32_001), None);
        // The current path is not the last switch's target -> no rollback (a request naming the wrong target after one more switch).
        gate.evaluate("dev-b", Some(c1), &windows, 32_001)
            .expect("re-switch c1->c2 after grace");
        assert_eq!(
            gate.rollback("dev-b", c1, 32_100),
            None,
            "rollback target must match the last switch"
        );
        assert_eq!(gate.rollback("dev-b", c2, 32_100), Some(c1));
    }

    // -- SEL-003: is_degraded / RecoveryGate ----------------------------------

    #[test]
    fn degraded_detects_loss_spike_and_timeout() {
        const DEGRADE_RTT_MS: u64 = 800;
        // A loss spike (>= the default 20% loss) -> degraded.
        let mut w = ProbeWindow::new(4);
        w.record(ProbeSample::Rtt(10));
        w.record(ProbeSample::Rtt(10));
        w.record(ProbeSample::Lost);
        w.record(ProbeSample::Lost);
        assert!(
            is_degraded(&w, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "50% loss is a spike"
        );
        // A single tail timeout (loss 1/6 ~= 16.7%, under the 20% spike threshold) -> a
        // one-beat transient triggers nothing (the 2026-11-14 last-Lost softening: the tail must
        // be Lost for LAST_LOST_TOLERANCE consecutive beats; at the 20% threshold a small window
        // needs at least 6 beats to absorb a single-beat transient).
        let mut t = ProbeWindow::new(6);
        for _ in 0..5 {
            t.record(ProbeSample::Rtt(10));
        }
        t.record(ProbeSample::Lost);
        assert!(
            !is_degraded(&t, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "single tail lost tolerated"
        );
        // Healthy: all RTT, low loss, last beat an Rtt -> not degraded.
        let mut ok = ProbeWindow::new(4);
        ok.record(ProbeSample::Rtt(10));
        ok.record(ProbeSample::Rtt(12));
        assert!(!is_degraded(
            &ok,
            DEGRADE_RTT_MS,
            LOSS_SPIKE_THRESHOLD,
            MIN_SAMPLES
        ));
        // An empty window (no reading yet) -> do not rashly fall back to the relay.
        assert!(!is_degraded(
            &ProbeWindow::new(4),
            DEGRADE_RTT_MS,
            LOSS_SPIKE_THRESHOLD,
            MIN_SAMPLES
        ));
    }

    /// Nail for the narrowed loss-spike threshold (the user fixed 50% -> 20% on 2026-11-17): under the
    /// old threshold, 49% loss was a "below spike" healthy face and could serve as FLIP-001 recovery-gate
    /// bypass evidence, dragging direct connect back onto a degraded face (admitting a degraded face
    /// that hops among ping's three states in practice); 49% must read as degraded, while below 20%
    /// (19%) stays healthy.
    #[test]
    fn loss_spike_threshold_boundary_49_and_19_percent() {
        const DEGRADE_RTT_MS: u64 = 800;
        // 49% loss (49/100, the last beat an Rtt so the tail rule does not fire) -> a spike degradation.
        let mut w = ProbeWindow::new(100);
        for _ in 0..48 {
            w.record(ProbeSample::Lost);
        }
        w.record(ProbeSample::Lost);
        for _ in 0..51 {
            w.record(ProbeSample::Rtt(10));
        }
        assert!(
            is_degraded(&w, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "49% loss must degrade under the 20% threshold"
        );
        // Under the old 50% threshold the same window would not degrade (the contrast assertion behind the narrowing).
        assert!(
            !is_degraded(&w, DEGRADE_RTT_MS, 0.5, MIN_SAMPLES),
            "49% loss was healthy under the old 50% threshold"
        );
        // 19% loss (19/100) -> still healthy.
        let mut ok = ProbeWindow::new(100);
        for _ in 0..19 {
            ok.record(ProbeSample::Lost);
        }
        for _ in 0..81 {
            ok.record(ProbeSample::Rtt(10));
        }
        assert!(
            !is_degraded(&ok, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "19% loss stays healthy under the 20% threshold"
        );
    }

    /// last-Lost softening (the 2026-11-14 patrol sheet): the window tail must be Lost for
    /// [`LAST_LOST_TOLERANCE`] consecutive beats before it degrades -- a one-beat ICMP transient on the
    /// ZT face (recorded on a real machine: at demotion time the handshake age was 56-120s, fresh, and
    /// classify was innocent, the trigger being that one-beat transient) no longer acts; a short window
    /// (< 3 beats) that is all `Lost` does not get the exemption.
    #[test]
    fn last_lost_requires_consecutive_tail_loss() {
        const DEGRADE_RTT_MS: u64 = 800;
        // Exactly 1 tail beat Lost -> not degraded.
        let mut one = ProbeWindow::new(8);
        for _ in 0..7 {
            one.record(ProbeSample::Rtt(10));
        }
        one.record(ProbeSample::Lost);
        assert!(
            !is_degraded(&one, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "single tail lost tolerated"
        );
        // Exactly 2 tail beats Lost -> not degraded (loss 2/12 ~= 16.7% < the 20% spike threshold;
        // at the 20% threshold a small window needs at least 12 beats to absorb a two-beat transient).
        let mut two = ProbeWindow::new(12);
        for _ in 0..10 {
            two.record(ProbeSample::Rtt(10));
        }
        two.record(ProbeSample::Lost);
        two.record(ProbeSample::Lost);
        assert!(
            !is_degraded(&two, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "two tail losts tolerated"
        );
        // 3 consecutive tail beats Lost -> degraded (loss 3/16 ~= 18.75% < the 20% spike threshold,
        // hit purely by the tail rule).
        let mut three = ProbeWindow::new(16);
        for _ in 0..13 {
            three.record(ProbeSample::Rtt(10));
        }
        for _ in 0..3 {
            three.record(ProbeSample::Lost);
        }
        assert!(
            is_degraded(&three, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "three consecutive tail losts degrade"
        );
        // 3 Lost beats but 2 RTT beats interleaved (the tail run is broken) -> not degraded (loss
        // 3/16 ~= 18.75% < the 20% spike threshold; a purely tail-continuity verdict).
        let mut broken = ProbeWindow::new(16);
        for _ in 0..5 {
            broken.record(ProbeSample::Rtt(10));
        }
        broken.record(ProbeSample::Lost);
        broken.record(ProbeSample::Rtt(10));
        broken.record(ProbeSample::Lost);
        broken.record(ProbeSample::Rtt(10));
        broken.record(ProbeSample::Lost);
        for _ in 0..6 {
            broken.record(ProbeSample::Rtt(10));
        }
        assert_eq!(broken.len(), 16);
        assert!(
            !is_degraded(&broken, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "interleaved rtt breaks the tail run"
        );
        // The young-window exemption (plan 1, 2026-11-17) replaces the 11-14 "a short all-Lost window
        // degrades outright" rule: 2 all-Lost beats are an insufficient reading at the default
        // min_samples=4 -> not judged degraded (a real death is caught by the handshake-age classify).
        let mut short = ProbeWindow::new(2);
        short.record(ProbeSample::Lost);
        short.record(ProbeSample::Lost);
        assert!(
            !is_degraded(&short, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "young all-lost window exempt"
        );
        // The same short window still degrades outright under a min_samples <= 2 configuration (the branch stays reachable).
        assert!(
            is_degraded(&short, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, 2),
            "short all-lost window degrades when min_samples = 2"
        );
    }

    /// Nail for the young-window exemption (plan 1, 2026-11-17): fewer samples than min_samples (default 4)
    /// never degrades -- the aggregate statistics of the few beats right after a path switch / a newly
    /// observed face have enormous variance, and judging on them is exactly the amplifier of the ping
    /// three-state hopping seen in practice; once the window accumulates 4 beats, evidence under the same
    /// criterion acts.
    #[test]
    fn young_window_below_min_samples_is_exempt() {
        const DEGRADE_RTT_MS: u64 = 800;
        // 3 beats [Rtt, L, L]: loss 2/3 >= 20% and 2 consecutive tail beats Lost -- both conditions
        // "ought to hit", but 3 < 4 -> the young-window exemption.
        let mut young = ProbeWindow::new(8);
        young.record(ProbeSample::Rtt(10));
        young.record(ProbeSample::Lost);
        young.record(ProbeSample::Lost);
        assert!(
            !is_degraded(&young, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "3-sample window is young and exempt"
        );
        // The 4th beat, a Lost, lands: the window is full -> 3 consecutive tail beats Lost -> degraded.
        young.record(ProbeSample::Lost);
        assert!(
            is_degraded(&young, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "4th sample fills the window; tail run acts"
        );
        // An empty window is exempt the same way (0 < 4).
        assert!(!is_degraded(
            &ProbeWindow::new(8),
            DEGRADE_RTT_MS,
            LOSS_SPIKE_THRESHOLD,
            MIN_SAMPLES
        ));
    }

    /// No-baseline exemption (pinned down by the 2026-11-13 real-death recheck): the firewalls on
    /// openclaw-win / windows-desktop block ICMP, so the candidate window is Lost throughout, while the WG
    /// tunnel is healthy (the handshake keeps renewing) -- an all-Lost window carries no "went from good to
    /// bad" evidence, so it is not judged degraded; a true death is caught by the handshake-age classify.
    #[test]
    fn degraded_without_rtt_baseline_stays_healthy() {
        const DEGRADE_RTT_MS: u64 = 800;
        let mut w = ProbeWindow::new(8);
        for _ in 0..8 {
            w.record(ProbeSample::Lost);
        }
        assert!(
            !is_degraded(&w, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "never-answered path has no baseline; handshake classify owns true death"
        );
    }

    /// The latency dimension (the 2026-11-13 residual follow-up): probing succeeding throughout while the RTT
    /// stays deeply degraded (recorded on a real machine, 1715ms of `probe_ok` pinning direct connect)
    /// must also read as degraded. The median verdict is equivalent to "N consecutive beats over the
    /// threshold" -- a minority of spikes cannot drag the median (debounce).
    #[test]
    fn degraded_when_median_rtt_is_sustained_over_threshold() {
        const DEGRADE_RTT_MS: u64 = 800;
        // Sustained deep degradation: every sample >= the threshold -> the median 900/1715 hits.
        let mut bad = ProbeWindow::new(8);
        for v in [900, 1715, 950, 880] {
            bad.record(ProbeSample::Rtt(v));
        }
        assert!(
            is_degraded(&bad, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "sustained 900ms degrades"
        );
        // The boundary: the median exactly equals the threshold -> it hits (>= semantics, consistent with the
        // loss spike). 4 beats fill the young-window floor (min_samples=4), so the exemption no longer applies.
        let mut edge = ProbeWindow::new(4);
        for _ in 0..4 {
            edge.record(ProbeSample::Rtt(800));
        }
        assert!(
            is_degraded(&edge, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "median == threshold hits"
        );
        // A minority of spikes cannot drag the median: 2 beats of 1500ms out of 8, the median still ~10ms -> not degraded.
        let mut spiky = ProbeWindow::new(8);
        for _ in 0..6 {
            spiky.record(ProbeSample::Rtt(10));
        }
        spiky.record(ProbeSample::Rtt(1500));
        spiky.record(ProbeSample::Rtt(1500));
        assert!(
            !is_degraded(&spiky, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "minority spikes must not degrade"
        );
        // A majority of beats over the threshold: [10,900,900,1500] -> median 900 >= 800 -> sustained degradation hits.
        let mut half = ProbeWindow::new(4);
        half.record(ProbeSample::Rtt(10));
        half.record(ProbeSample::Rtt(900));
        half.record(ProbeSample::Rtt(900));
        half.record(ProbeSample::Rtt(1500));
        assert!(
            is_degraded(&half, DEGRADE_RTT_MS, LOSS_SPIKE_THRESHOLD, MIN_SAMPLES),
            "majority sustained degrades"
        );
    }

    #[test]
    fn recovery_gate_requires_consecutive_healthy_rounds() {
        let mut gate = RecoveryGate::new(3);
        // Unhealthy -> the count clears, never ready.
        assert!(!gate.record("peer-a", false));
        assert!(!gate.is_ready("peer-a"));
        // 3 consecutive healthy rounds -> ready on the 3rd.
        assert!(!gate.record("peer-a", true));
        assert!(!gate.record("peer-a", true));
        assert!(gate.record("peer-a", true));
        assert!(gate.is_ready("peer-a"));
        // One unhealthy round -> the count clears, no longer ready.
        assert!(!gate.record("peer-a", false));
        assert!(!gate.is_ready("peer-a"));
        // 2 more healthy rounds and still not 3.
        assert!(!gate.record("peer-a", true));
        assert!(!gate.record("peer-a", true));
        assert!(!gate.is_ready("peer-a"));
    }

    #[test]
    fn recovery_gate_retains_only_live_peers() {
        let mut gate = RecoveryGate::new(2);
        gate.record("peer-a", true);
        gate.record("peer-b", true);
        gate.record("peer-a", true);
        gate.record("peer-b", true);
        assert!(gate.is_ready("peer-a"));
        assert!(gate.is_ready("peer-b"));
        gate.retain(&["peer-a".to_string()]);
        assert!(gate.is_ready("peer-a"));
        assert!(
            !gate.is_ready("peer-b"),
            "removed peer's streak is reclaimed"
        );
    }
}
