//! Demote backoff (the FLIP-002 floor): after consecutive demotes, apply exponential backoff
//! cooldown on the promote side - the Nth consecutive demote's promote cooldown = `base x 2^(N-1)`, capped at `cap`;
//! sustained link health (M consecutive rounds with probe health-surface evidence, M = `recovery_confirmations`)
//! clears the counter.
//!
//! Why: the SEL-003 degrade gate + recovery gate debounce "single-beat transients", but when the degrade
//! source persists (e.g. the JMrE 24h window's 262 promote->demote flips, median 1.48min), the old path
//! flips again on the same surface the moment the recovery gate lets it through - backoff stretches the retry
//! interval exponentially (30s -> 1min -> 2min -> ... -> cap 15min), so useless retries on the degraded surface
//! decay from a "minute-scale loop" to single-digit attempts, converging naturally once FLIP-001's candidate
//! table provides a healthy surface.
//!
//! Boundary (task charter): backoff **only acts on the promote side** - SEL-003's degrade detection and
//! demote action are entirely unaffected (probes still report degradation as they should, with no loss of
//! sensitivity); the domain layer consults the suppression table after hold_relay, keeping the relay during
//! suppression and recording a defer decision.
//!
//! Pure logic, no IO: time is passed in by the caller (milliseconds), and tests may inject any clock.

use std::collections::BTreeMap;

/// Backoff state for one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackoffState {
    /// Number of consecutive demotes (within the current cooldown chain; the whole entry is deleted when health clears it).
    demotes: u32,
    /// Consecutive healthy rounds (driven by note_health; reset to zero on any unhealthy round).
    health_streak: u32,
    /// Suppression deadline (Unix milliseconds).
    suppress_until_ms: u64,
}

/// Demote backoff state machine: peer public key -> backoff state.
#[derive(Debug)]
pub struct DemoteBackoff {
    base_ms: u64,
    cap_ms: u64,
    confirmations: u32,
    state: BTreeMap<String, BackoffState>,
}

impl DemoteBackoff {
    /// Create a backoff tracker. `base_ms` has a floor of 1; `cap_ms` a floor of `base_ms`;
    /// `confirmations` a floor of 1 (clamped, so invalid configuration does not panic).
    pub fn new(base_ms: u64, cap_ms: u64, confirmations: u32) -> Self {
        let base_ms = base_ms.max(1);
        Self {
            base_ms,
            cap_ms: cap_ms.max(base_ms),
            confirmations: confirmations.max(1),
            state: BTreeMap::new(),
        }
    }

    /// Cooldown duration in milliseconds for the Nth consecutive demote: `base x 2^(N-1)`, capped at `cap`.
    /// `base > cap >> exp` means `base << exp` would reach/exceed the cap (including u64 high-bit
    /// wraparound - `checked_shl` only checks the shift amount, not value overflow) -> take the cap directly.
    fn delay_ms(&self, demotes: u32) -> u64 {
        let exponent = demotes.saturating_sub(1).min(62);
        if exponent > 0 && self.base_ms > self.cap_ms >> exponent {
            self.cap_ms
        } else {
            self.base_ms << exponent
        }
    }

    /// Record one demote: increment the consecutive counter, reset healthy rounds, and set the suppression deadline = now + cooldown.
    pub fn on_demote(&mut self, public_key: &str, now_ms: u64) {
        let demotes = {
            let entry = self
                .state
                .entry(public_key.to_string())
                .or_insert(BackoffState {
                    demotes: 0,
                    health_streak: 0,
                    suppress_until_ms: 0,
                });
            entry.demotes = entry.demotes.saturating_add(1);
            entry.health_streak = 0;
            entry.demotes
        };
        let delay = self.delay_ms(demotes);
        let entry = self
            .state
            .get_mut(public_key)
            .expect("entry just inserted above");
        entry.suppress_until_ms = now_ms.saturating_add(delay);
    }

    /// Record one round of health evidence: `healthy` = this peer's round hit the probe health surface
    /// (any member of the FLIP-001 health-surface set). `confirmations` consecutive healthy rounds ->
    /// clear the whole backoff entry (the next demote restarts from base); one unhealthy round ->
    /// reset the healthy-round streak (continuity broken) while the demote counter and current
    /// suppression hold. A no-op when no backoff state exists.
    pub fn note_health(&mut self, public_key: &str, healthy: bool, _now_ms: u64) {
        let Some(state) = self.state.get_mut(public_key) else {
            return;
        };
        if healthy {
            state.health_streak = state.health_streak.saturating_add(1);
            if state.health_streak >= self.confirmations {
                self.state.remove(public_key);
            }
        } else {
            state.health_streak = 0;
        }
    }

    /// Whether this peer is currently suppressed (if so, returns a reason string for the defer decision record).
    pub fn suppress_reason(&self, public_key: &str, now_ms: u64) -> Option<String> {
        let state = self.state.get(public_key)?;
        if now_ms >= state.suppress_until_ms {
            return None;
        }
        let cooling_secs = (state.suppress_until_ms - now_ms).div_ceil(1000);
        Some(format!(
            "promote deferred: demote backoff ({} consecutive demote(s), cooling {}s more; FLIP-002)",
            state.demotes, cooling_secs
        ))
    }

    /// All currently suppressed peers -> reason (the input to the domain layer's `suppress_promote` argument;
    /// built as a single snapshot to avoid rescanning peer by peer).
    pub fn suppress_map(&self, now_ms: u64) -> BTreeMap<String, String> {
        self.state
            .iter()
            .filter(|(_, state)| now_ms < state.suppress_until_ms)
            .map(|(key, state)| {
                let cooling_secs = (state.suppress_until_ms - now_ms).div_ceil(1000);
                (
                    key.clone(),
                    format!(
                        "promote deferred: demote backoff ({} consecutive demote(s), cooling {}s more; FLIP-002)",
                        state.demotes, cooling_secs
                    ),
                )
            })
            .collect()
    }

    /// Reclaim peers not in the candidate set (state cleanup after revocation / going offline).
    pub fn retain(&mut self, keys: &[String]) {
        let live: std::collections::BTreeSet<&str> = keys.iter().map(String::as_str).collect();
        self.state.retain(|key, _| live.contains(key.as_str()));
    }

    /// Whether any backoff state exists (diagnostics / testing).
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // base 30s / cap 15min / health cleared after 3 rounds - an accelerated equivalent of the all-defaults test scale.
    fn backoff() -> DemoteBackoff {
        DemoteBackoff::new(30_000, 900_000, 3)
    }

    #[test]
    fn delay_grows_exponentially_then_caps() {
        let b = backoff();
        assert_eq!(b.delay_ms(1), 30_000, "1st demote: base");
        assert_eq!(b.delay_ms(2), 60_000, "2nd: base × 2");
        assert_eq!(b.delay_ms(3), 120_000, "3rd: base × 4");
        assert_eq!(b.delay_ms(4), 240_000, "4th: base × 8");
        // Capped: base x 32 = 960_000ms exceeds 15min, pressed down to 900_000ms.
        assert_eq!(b.delay_ms(6), 900_000, "capped below base × 32");
        assert_eq!(b.delay_ms(7), 900_000, "cap reached");
        assert_eq!(b.delay_ms(100), 900_000, "far beyond cap");
    }

    #[test]
    fn on_demote_suppresses_for_the_backoff_window() {
        let mut b = backoff();
        b.on_demote("pk", 1_000);
        assert!(b.suppress_reason("pk", 1_000).is_some(), "suppressed now");
        assert!(
            b.suppress_reason("pk", 30_999).is_some(),
            "still within 30s"
        );
        assert!(
            b.suppress_reason("pk", 31_000).is_none(),
            "cooldown expired at base × 1"
        );
    }

    #[test]
    fn consecutive_demotes_stretch_and_restart_window() {
        let mut b = backoff();
        b.on_demote("pk", 0);
        b.on_demote("pk", 5_000); // demote again within the cooldown (promote suppressed, but the degrade side proceeds as usual)
        assert!(
            b.suppress_reason("pk", 5_000)
                .unwrap()
                .contains("2 consecutive"),
            "reason counts consecutive demotes"
        );
        assert!(b.suppress_reason("pk", 5_000 + 60_000 - 1).is_some());
        assert!(
            b.suppress_reason("pk", 5_000 + 60_000).is_none(),
            "2nd window = 60s"
        );
    }

    #[test]
    fn health_confirmations_clear_backoff_fully() {
        let mut b = backoff();
        b.on_demote("pk", 0);
        b.on_demote("pk", 1_000); // demotes=2, cooldown 60s
                                  // 2 healthy rounds (< confirmations=3) -> still suppressed.
        b.note_health("pk", true, 2_000);
        b.note_health("pk", true, 3_000);
        assert!(b.suppress_reason("pk", 2_000).is_some(), "not yet cleared");
        // The 3rd healthy round -> the whole entry cleared: suppression ends immediately, and the next demote restarts from base.
        b.note_health("pk", true, 4_000);
        assert!(
            b.suppress_reason("pk", 4_000).is_none(),
            "cleared by 3 healthy rounds"
        );
        assert!(b.is_empty(), "state fully removed");
        b.on_demote("pk", 5_000);
        assert!(b.suppress_reason("pk", 5_000 + 29_999).is_some());
        assert!(
            b.suppress_reason("pk", 5_000 + 30_000).is_none(),
            "restarts at base, not at the old 2nd-demote level"
        );
    }

    #[test]
    fn unhealthy_round_breaks_health_streak_but_keeps_suppression() {
        let mut b = backoff();
        b.on_demote("pk", 0);
        b.note_health("pk", true, 1_000);
        b.note_health("pk", true, 2_000);
        b.note_health("pk", false, 3_000); // continuity broken
        b.note_health("pk", true, 4_000);
        b.note_health("pk", true, 5_000);
        assert!(
            b.suppress_reason("pk", 5_000).is_some(),
            "2+1 healthy rounds < 3 confirmations; suppression holds"
        );
    }

    #[test]
    fn note_health_without_state_is_noop() {
        let mut b = backoff();
        b.note_health("pk", true, 0);
        b.note_health("pk", false, 1_000);
        assert!(b.is_empty(), "no backoff state was created");
    }

    #[test]
    fn retain_drops_departed_peers() {
        let mut b = backoff();
        b.on_demote("pk-a", 0);
        b.on_demote("pk-b", 0);
        b.retain(&["pk-a".to_string()]);
        assert!(b.suppress_reason("pk-a", 0).is_some());
        assert!(
            b.suppress_reason("pk-b", 0).is_none(),
            "departed peer reclaimed"
        );
    }

    #[test]
    fn constructor_clamps_invalid_values() {
        let b = DemoteBackoff::new(0, 0, 0);
        assert_eq!(b.delay_ms(1), 1, "base clamped to 1ms");
        let b = DemoteBackoff::new(60_000, 30_000, 0);
        assert_eq!(b.delay_ms(1), 60_000, "cap raised to base");
        assert_eq!(b.delay_ms(2), 60_000, "cap == base means constant delay");
    }
}
