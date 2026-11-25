//! Device disconnect observability (P1, 2026-11-12 user directive: fix
//! stability first).
//!
//! Confirmed background (dev VPS): the imac was genuinely disconnected (0
//! ESTABLISHED connections), yet the server logs held 0 disconnect records
//! over the preceding 24h -- presence is a **computed-at-read** pure function
//! (`meshlet_domain::presence`), so a disconnect is only visible when someone
//! refreshes the console; when nobody is looking, the disconnect does not
//! **exist** in the server log.
//!
//! What this module adds is the timeline: in the background it periodically
//! recomputes presence for every active device and explicitly logs on
//! **state transitions** -- heartbeat-timeout disconnect (Online -> non-Online)
//! at WARN, back online at INFO, total loss of evidence (TunnelOnly -> Offline:
//! the handshake timed out too) at INFO. From the log you can directly tell
//! "device X disconnected at, and recovered at", with wording aligned to the
//! existing diagnostics readings of "stale handshake / no handshake ever
//! observed".
//!
//! The verdict fully reuses [`crate::service::evaluate_presence`] (the same
//! criterion as the console/gauges); no second judgement path is introduced.
//! It does not depend on `dataplane.enabled` -- a pure control-plane
//! deployment must still be able to see each device's disconnect timeline.
//!
//! Known boundary (recorded as is): the recomputation period
//! [`WATCH_INTERVAL_SECS`] bounds detection latency (roughly one period +
//! `agent_window`); after a process restart the first round only builds a
//! baseline and does not retroactively report disconnects (nothing in the log
//! can claim continuity for what happened before the restart).

use std::collections::HashMap;
use std::time::Duration;

use meshlet_domain::presence::PresenceState;
use PresenceState::{Offline, Online, TunnelOnly};

use crate::auth::SharedAppState;

/// Recomputation period (seconds): same tier as hub recovery / task reclaim
/// (30s).
const WATCH_INTERVAL_SECS: u64 = 30;

/// A state transition worth a log line (pure classification; unit tests cover
/// the full matrix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEvent {
    /// Disconnected: the agent report went past the window
    /// (Online → TunnelOnly / Offline).
    Disconnected,
    /// Back online (TunnelOnly / Offline → Online).
    BackOnline,
    /// All evidence lost: the handshake also went past the window
    /// (TunnelOnly → Offline).
    EvidenceLost,
}

/// Classify a transition: `None` = no transition, or a change the criterion
/// does not log.
///
/// - Same state (including a mere change of evidence source) -> `None`;
/// - `Offline -> TunnelOnly` (handshake back first, agent report still
///   pending) -> `None`: a partial recovery is not announced; wait until the
///   agent report holds and then log `BackOnline`;
/// - all other cross-state transitions are logged per the table above.
pub fn classify(from: PresenceState, to: PresenceState) -> Option<WatchEvent> {
    match (from, to) {
        (Online, Online)
        | (TunnelOnly, TunnelOnly)
        | (Offline, Offline)
        | (Offline, TunnelOnly) => None,
        (Online, TunnelOnly) | (Online, Offline) => Some(WatchEvent::Disconnected),
        (TunnelOnly, Online) | (Offline, Online) => Some(WatchEvent::BackOnline),
        (TunnelOnly, Offline) => Some(WatchEvent::EvidenceLost),
    }
}

/// Presence recomputation snapshot for one device (collected while holding
/// the lock; transition verdicts and logging happen outside the lock).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DevicePresence {
    id: String,
    name: String,
    state: PresenceState,
    last_report_at: Option<String>,
    last_handshake_at: Option<String>,
}

/// Decide this round's transition for one device (pure function, unit
/// tested): `seen` records the previous state and is updated to this round's
/// state; the first round only builds a baseline (`None`, no transition
/// alert -- after a restart we must not flood a screen full of "disconnected"
/// for devices that were already long offline), and afterwards returns
/// transitions worth logging per the [`classify`] criterion.
fn transition(
    seen: &mut HashMap<String, PresenceState>,
    device: &DevicePresence,
) -> Option<(WatchEvent, PresenceState)> {
    let previous = seen.insert(device.id.clone(), device.state)?;
    let event = classify(previous, device.state)?;
    Some((event, previous))
}

/// Start the disconnect watcher: periodically recompute presence for every
/// active device and log on state transitions.
/// Runs until the process exits; failures are only logged and never affect
/// the request path.
pub fn start(state: SharedAppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(WATCH_INTERVAL_SECS));
        let mut seen: HashMap<String, PresenceState> = HashMap::new();
        loop {
            ticker.tick().await;
            // Hold the mesh lock only for recomputation and snapshotting; logging
            // happens outside the lock.
            let snapshot: Vec<DevicePresence> = {
                let mesh = state.mesh.lock().unwrap();
                let now = crate::service::now();
                mesh.registry
                    .devices()
                    .iter()
                    .filter(|d| d.is_active())
                    .map(|d| DevicePresence {
                        state: crate::service::evaluate_presence(
                            d,
                            &now,
                            &mesh.presence_thresholds,
                        )
                        .state,
                        id: d.id.0.clone(),
                        name: d.name.clone(),
                        last_report_at: d.last_report_at.clone(),
                        last_handshake_at: d.last_handshake_at.clone(),
                    })
                    .collect()
            };
            for device in &snapshot {
                let Some((event, previous)) = transition(&mut seen, device) else {
                    continue;
                };
                match event {
                    WatchEvent::Disconnected => tracing::warn!(
                        device_id = %device.id,
                        device = %device.name,
                        from = previous.as_str(),
                        to = device.state.as_str(),
                        last_report_at = device.last_report_at.as_deref().unwrap_or("never"),
                        last_handshake_at = device.last_handshake_at.as_deref().unwrap_or("never"),
                        "device disconnected: agent report timed out"
                    ),
                    WatchEvent::BackOnline => tracing::info!(
                        device_id = %device.id,
                        device = %device.name,
                        from = previous.as_str(),
                        "device back online: fresh agent report observed"
                    ),
                    WatchEvent::EvidenceLost => tracing::info!(
                        device_id = %device.id,
                        device = %device.name,
                        last_handshake_at = device.last_handshake_at.as_deref().unwrap_or("never"),
                        "device evidence lost: handshake also timed out"
                    ),
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, state: PresenceState) -> DevicePresence {
        DevicePresence {
            id: id.into(),
            name: format!("{id}-name"),
            state,
            last_report_at: Some("2026-11-12T00:00:00Z".into()),
            last_handshake_at: None,
        }
    }

    /// Full transition matrix: the classification of every (from, to) pair must
    /// match the documented criterion -- one each for disconnect / recovery /
    /// total loss of evidence, and nothing logged for same-state or partial
    /// recovery.
    #[test]
    fn classify_covers_the_full_transition_matrix() {
        use PresenceState::*;
        let all = [Online, TunnelOnly, Offline];
        for from in all {
            for to in all {
                let event = classify(from, to);
                match (from, to) {
                    (Online, Online) | (TunnelOnly, TunnelOnly) | (Offline, Offline) => {
                        assert_eq!(event, None, "same state must not log ({from:?}→{to:?})");
                    }
                    (Online, TunnelOnly) | (Online, Offline) => {
                        assert_eq!(event, Some(WatchEvent::Disconnected));
                    }
                    (TunnelOnly, Online) | (Offline, Online) => {
                        assert_eq!(event, Some(WatchEvent::BackOnline));
                    }
                    (TunnelOnly, Offline) => {
                        assert_eq!(event, Some(WatchEvent::EvidenceLost));
                    }
                    (Offline, TunnelOnly) => {
                        assert_eq!(
                            event, None,
                            "partial recovery must wait for the agent report"
                        );
                    }
                }
            }
        }
    }

    /// Timeline criterion: the first round builds a baseline without alerting
    /// (no screen flooding after a restart); same state does not alert; a
    /// cross-state change alerts once; the recorded state is updated right
    /// after alerting, so recovery alerts again -- in the log each device has
    /// a complete disconnect/recovery timeline.
    #[test]
    fn transition_builds_a_per_device_timeline() {
        let mut seen: HashMap<String, PresenceState> = HashMap::new();
        // First-round baseline: the device is already online (possibly since before
        // the restart) -- no alert.
        assert_eq!(transition(&mut seen, &device("d1", Online)), None);
        // Heartbeat past the window: disconnected -- alert, from=Online.
        assert_eq!(
            transition(&mut seen, &device("d1", Offline)),
            Some((WatchEvent::Disconnected, Online))
        );
        // Still offline: same state, no repeated alert.
        assert_eq!(transition(&mut seen, &device("d1", Offline)), None);
        // Handshake back first (partial recovery): wait for the agent report,
        // no alert.
        assert_eq!(transition(&mut seen, &device("d1", TunnelOnly)), None);
        // Agent report is back: recovery online -- alert, from=TunnelOnly.
        assert_eq!(
            transition(&mut seen, &device("d1", Online)),
            Some((WatchEvent::BackOnline, TunnelOnly))
        );
        // Devices do not interfere: d2's first-round baseline also does not
        // alert.
        assert_eq!(transition(&mut seen, &device("d2", Offline)), None);
        assert_eq!(transition(&mut seen, &device("d1", Online)), None);
    }
}
