//! Device online-status determination ([archive §12.2/§12.4](../../docs/review/chatgpt-2026-10-13.md)).
//!
//! The decision inputs are timestamps of three kinds of "evidence":
//! - **agent heartbeat / status report** (the agent reports periodically over the HTTPS control channel, §14.1)
//!   — the strongest signal, proving the agent process and the device's network functions work;
//! - **tunnel handshake** (WireGuard latest-handshake, read locally via `wg show` and reported)
//!   — proves only tunnel connectivity, **not** that all device functions are healthy (§12.4);
//! - **enrollment record** — the device appeared at least once, but without later signals it cannot be claimed online.
//!
//! The verdict must state **the data source and its update time** (§12.2): the console must not show a
//! green "online" icon without saying which evidence, at what moment, supports the conclusion.
//!
//! Pure function, no I/O: timestamps are ISO-8601 strings (as in [crate::entities]);
//! the decision instant `now` and the thresholds are injectable, keeping unit tests deterministic.

use crate::entities::Timestamp;
use std::time::Duration;

/// Evidence source (i.e. "where the online status comes from"), ordered by strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PresenceSource {
    /// Agent heartbeat / status report (strongest: agent process and control channel healthy).
    AgentReport,
    /// Tunnel handshake (proves only tunnel connectivity).
    Handshake,
    /// Enrollment record only (no handshake/heartbeat).
    Enrollment,
    /// No evidence at all.
    None,
}

impl PresenceSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PresenceSource::AgentReport => "agent_report",
            PresenceSource::Handshake => "handshake",
            PresenceSource::Enrollment => "enrollment",
            PresenceSource::None => "none",
        }
    }
}

/// Online status. **A fresh handshake is not "online"** (§12.4):
/// only an agent report proves the device's functions are healthy; on handshake evidence alone
/// the state is labelled `TunnelOnly`, shown by the console in a style distinct from "online".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceState {
    /// An agent report is inside the window: online.
    Online,
    /// Only the handshake is inside the window: tunnel connected, but with no agent evidence the device cannot be called fully healthy.
    TunnelOnly,
    /// No fresh evidence at all.
    Offline,
}

impl PresenceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PresenceState::Online => "online",
            PresenceState::TunnelOnly => "tunnel_only",
            PresenceState::Offline => "offline",
        }
    }
}

/// Decision window thresholds (injectable; production defaults in [PresenceThresholds::default]).
#[derive(Debug, Clone, Copy)]
pub struct PresenceThresholds {
    /// Agent report freshness window: default 5 minutes (the agent reports roughly every minute, so a few losses are tolerated).
    pub agent_window: Duration,
    /// Handshake freshness window: default 2 minutes (with a 25 s keepalive the handshake keeps refreshing while the tunnel is active).
    pub handshake_window: Duration,
}

impl Default for PresenceThresholds {
    fn default() -> Self {
        Self {
            agent_window: Duration::from_secs(5 * 60),
            handshake_window: Duration::from_secs(2 * 60),
        }
    }
}

/// Decision inputs: the timestamps of the three evidence kinds (`None` = never observed).
#[derive(Debug, Clone, Copy, Default)]
pub struct PresenceInput<'a> {
    pub last_handshake_at: Option<&'a str>,
    pub last_report_at: Option<&'a str>,
    pub enrolled_at: Option<&'a str>,
}

/// Decision result: status + data source (evidence strength label) + decision instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presence {
    pub state: PresenceState,
    /// Source of the evidence supporting the current status; for Offline, the source of the **most recent** evidence.
    pub source: PresenceSource,
    /// The decision instant (i.e. "when the status was computed").
    pub evaluated_at: Timestamp,
}

/// Freshness check: `now - ts <= window` is fresh (boundary inclusive; future
/// timestamps count as fresh, tolerating slight clock skew). Unparseable timestamps are treated as "absent".
pub fn fresh(ts: &str, now: &str, window: Duration) -> bool {
    match (parse(ts), parse(now)) {
        (Some(ts), Some(now)) => now
            .signed_duration_since(ts)
            .num_nanoseconds()
            .is_some_and(|delta| delta <= window.as_nanos() as i64),
        _ => false,
    }
}

/// Source and timestamp of the most recent evidence (maximum by parsed instant; unparseable evidence is ignored).
fn latest_evidence(
    handshake: Option<&str>,
    report: Option<&str>,
    enrolled: Option<&str>,
) -> Option<(PresenceSource, Timestamp)> {
    [
        handshake.map(|t| (PresenceSource::Handshake, t)),
        report.map(|t| (PresenceSource::AgentReport, t)),
        enrolled.map(|t| (PresenceSource::Enrollment, t)),
    ]
    .into_iter()
    .flatten()
    .filter_map(|(source, t)| parse(t).map(|dt| (source, dt, t.to_string())))
    .max_by_key(|(_, dt, _)| *dt)
    .map(|(source, _, t)| (source, t))
}

/// Determines device online status (the decision instant and thresholds are injected).
pub fn evaluate(input: PresenceInput<'_>, now: &str, thresholds: &PresenceThresholds) -> Presence {
    let report_fresh = input
        .last_report_at
        .is_some_and(|t| fresh(t, now, thresholds.agent_window));
    let handshake_fresh = input
        .last_handshake_at
        .is_some_and(|t| fresh(t, now, thresholds.handshake_window));

    if report_fresh {
        // An agent report is the strongest evidence: straight to online.
        return Presence {
            state: PresenceState::Online,
            source: PresenceSource::AgentReport,
            evaluated_at: now.to_string(),
        };
    }
    if handshake_fresh {
        // A fresh handshake only proves tunnel connectivity; without agent evidence device health cannot be claimed.
        return Presence {
            state: PresenceState::TunnelOnly,
            source: PresenceSource::Handshake,
            evaluated_at: now.to_string(),
        };
    }
    // Offline: label the source of the most recent evidence (traceable data source).
    let source = latest_evidence(
        input.last_handshake_at,
        input.last_report_at,
        input.enrolled_at,
    )
    .map(|(source, _)| source)
    .unwrap_or(PresenceSource::None);
    Presence {
        state: PresenceState::Offline,
        source,
        evaluated_at: now.to_string(),
    }
}

/// Decides with the default thresholds.
pub fn evaluate_with_defaults(input: PresenceInput<'_>, now: &str) -> Presence {
    evaluate(input, now, &PresenceThresholds::default())
}

fn parse(ts: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(ts).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-10-14T12:00:00Z";

    fn thresh(agent_secs: u64, handshake_secs: u64) -> PresenceThresholds {
        PresenceThresholds {
            agent_window: Duration::from_secs(agent_secs),
            handshake_window: Duration::from_secs(handshake_secs),
        }
    }

    #[test]
    fn fresh_agent_report_is_online() {
        let p = evaluate_with_defaults(
            PresenceInput {
                last_report_at: Some("2026-10-14T11:58:00Z"), // 2 minutes ago
                ..PresenceInput::default()
            },
            NOW,
        );
        assert_eq!(p.state, PresenceState::Online);
        assert_eq!(p.source, PresenceSource::AgentReport);
        assert_eq!(p.evaluated_at, NOW);
    }

    #[test]
    fn stale_report_with_fresh_handshake_is_tunnel_only() {
        // Report 10 minutes ago (outside the 5-minute window), handshake 1 minute ago (inside) → tunnel connected only.
        let p = evaluate_with_defaults(
            PresenceInput {
                last_report_at: Some("2026-10-14T11:50:00Z"),
                last_handshake_at: Some("2026-10-14T11:59:00Z"),
                ..PresenceInput::default()
            },
            NOW,
        );
        assert_eq!(p.state, PresenceState::TunnelOnly);
        assert_eq!(p.source, PresenceSource::Handshake);
    }

    #[test]
    fn handshake_fresh_alone_is_not_online() {
        // §12.4: a recent WireGuard handshake ≠ all networking on the device working.
        let p = evaluate_with_defaults(
            PresenceInput {
                last_handshake_at: Some("2026-10-14T11:59:30Z"),
                ..PresenceInput::default()
            },
            NOW,
        );
        assert_ne!(p.state, PresenceState::Online);
        assert_eq!(p.state, PresenceState::TunnelOnly);
    }

    #[test]
    fn both_fresh_report_wins() {
        let p = evaluate_with_defaults(
            PresenceInput {
                last_report_at: Some("2026-10-14T11:59:00Z"),
                last_handshake_at: Some("2026-10-14T11:59:50Z"),
                ..PresenceInput::default()
            },
            NOW,
        );
        assert_eq!(p.state, PresenceState::Online);
        assert_eq!(p.source, PresenceSource::AgentReport);
    }

    #[test]
    fn both_stale_is_offline_with_latest_evidence_source() {
        let p = evaluate_with_defaults(
            PresenceInput {
                last_report_at: Some("2026-10-14T10:00:00Z"),
                last_handshake_at: Some("2026-10-14T11:30:00Z"),
                ..PresenceInput::default()
            },
            NOW,
        );
        assert_eq!(p.state, PresenceState::Offline);
        assert_eq!(p.source, PresenceSource::Handshake); // latest evidence is the 11:30 handshake
    }

    #[test]
    fn stale_report_only_keeps_agent_source_when_offline() {
        let p = evaluate_with_defaults(
            PresenceInput {
                last_report_at: Some("2026-10-14T09:00:00Z"),
                ..PresenceInput::default()
            },
            NOW,
        );
        assert_eq!(p.state, PresenceState::Offline);
        assert_eq!(p.source, PresenceSource::AgentReport);
    }

    #[test]
    fn enrollment_only_is_offline_with_enrollment_source() {
        let p = evaluate_with_defaults(
            PresenceInput {
                enrolled_at: Some("2026-10-13T08:00:00Z"),
                ..PresenceInput::default()
            },
            NOW,
        );
        assert_eq!(p.state, PresenceState::Offline);
        assert_eq!(p.source, PresenceSource::Enrollment);
    }

    #[test]
    fn no_evidence_is_offline_with_none_source() {
        let p = evaluate_with_defaults(PresenceInput::default(), NOW);
        assert_eq!(p.state, PresenceState::Offline);
        assert_eq!(p.source, PresenceSource::None);
    }

    #[test]
    fn unparseable_timestamps_are_ignored_conservatively() {
        let p = evaluate_with_defaults(
            PresenceInput {
                last_report_at: Some("not-a-timestamp"),
                last_handshake_at: Some("2026-13-49T99:99:99Z"),
                enrolled_at: Some(NOW),
            },
            NOW,
        );
        assert_eq!(p.state, PresenceState::Offline);
        assert_eq!(p.source, PresenceSource::Enrollment); // the only parseable evidence
    }

    #[test]
    fn future_timestamp_counts_as_fresh() {
        // Tolerate slight clock skew: evidence stamped in the future counts as fresh.
        let p = evaluate_with_defaults(
            PresenceInput {
                last_handshake_at: Some("2026-10-14T12:00:05Z"),
                ..PresenceInput::default()
            },
            NOW,
        );
        assert_eq!(p.state, PresenceState::TunnelOnly);
    }

    #[test]
    fn window_boundary_is_fresh_one_second_past_is_stale() {
        let t = thresh(10, 10);
        // Exactly 10 seconds ago = boundary, fresh.
        let p = evaluate(
            PresenceInput {
                last_report_at: Some("2026-10-14T11:59:50Z"),
                ..PresenceInput::default()
            },
            NOW,
            &t,
        );
        assert_eq!(p.state, PresenceState::Online);
        // 11 seconds ago → stale.
        let p = evaluate(
            PresenceInput {
                last_report_at: Some("2026-10-14T11:59:49Z"),
                ..PresenceInput::default()
            },
            NOW,
            &t,
        );
        assert_eq!(p.state, PresenceState::Offline);
    }

    #[test]
    fn custom_thresholds_change_verdict() {
        // Default 5-minute window: a report 90 seconds ago is fresh → online.
        let p = evaluate_with_defaults(
            PresenceInput {
                last_report_at: Some("2026-10-14T11:58:30Z"),
                ..PresenceInput::default()
            },
            NOW,
        );
        assert_eq!(p.state, PresenceState::Online);
        // Threshold tightened to 1 minute: the same evidence is now stale → offline.
        let p = evaluate(
            PresenceInput {
                last_report_at: Some("2026-10-14T11:58:30Z"),
                ..PresenceInput::default()
            },
            NOW,
            &thresh(60, 60),
        );
        assert_eq!(p.state, PresenceState::Offline);
    }
}
