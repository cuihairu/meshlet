//! Peer link state machine (30s probe promote/demote) and probe classification: Relay / DirectPending / Direct
//! transitions once per probe cycle, idempotent and replayable; promotion accepts only WireGuard handshake
//! evidence, with the health window and promotion threshold forming a hysteresis policy (against promote/demote flapping).
//! Also holds the §12.3 link status report contract (DirectLinkStatus / DirectCandidateStatus).

use std::net::Ipv4Addr;

use crate::p2p::endpoint::DirectDecision;

/// Probe interval (seconds): spec says "probe the direct path every 30s".
pub const DIRECT_PROBE_INTERVAL_SECS: u64 = 30;
/// Max pending probe cycles tolerated while establishing a direct link (spec: "3 handshake cycles").
pub const MAX_PROMOTE_ATTEMPTS: u8 = 3;
/// Direct-link health window (seconds): a direct peer whose last handshake age exceeds this is unhealthy.
///
/// **It must not be shrunk to the keepalive cadence**: `latest-handshake` refreshes only on a
/// **completed re-handshake**; keepalives and data packets do not refresh it. WireGuard re-handshakes
/// an active session on the REKEY_AFTER_TIME cadence (initiator ~120s, responder ~180s), so a healthy
/// but idle direct link's handshake age periodically climbs to ~180s - if the window were below that
/// cadence (it was once 35s), a healthy link was judged Unhealthy -> demote -> promote, flapping every
/// ~90s (evidence from real machines, 2026-11-06, coding-vm<->cuihaitao). The window must exceed the
/// re-handshake cadence upper bound; a dead link (peer gone, re-handshake no longer succeeds) keeps
/// growing its handshake age past this window and is still caught.
pub const DIRECT_HEALTH_WINDOW_SECS: u64 = 240;
/// persistent-keepalive for a direct peer (seconds): makes wg send packets on its own - both the
/// "hole" of NAT punching and the heartbeat source of the health probe.
pub const DIRECT_PERSISTENT_KEEPALIVE_SECS: u32 = 15;
/// Direct promotion threshold (seconds): DirectPending -> Direct accepts only **WireGuard handshake evidence** -
/// the kernel's latest-handshake age at or below this value means the direct link is up.
///
/// Why not an ICMP probe: field evidence (Windows mesh, imac 2026-11-07) shows the firewall drops 100% of
/// ICMP echo to the wg interface / overlay VIP - the handshake is fresh but every ping is dead while the
/// link is fully alive. Probing is used only for RTT annotation and SEL-003 degradation judgement, and
/// **no longer blocks promotion**; otherwise direct connect stays stuck in `direct_pending` (dialing),
/// flapping promote/demote every ~90s. The threshold matches the hub keepalive / CLI `peer_mode` p2p_direct rule (<180s).
pub const DIRECT_PROMOTE_FRESH_SECS: u64 = 180;

/// Direct-link state of a single peer (transitions once per probe cycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLinkState {
    /// Going through the hub relay (current behaviour; direct not established or already fallen back).
    Relay,
    /// Direct endpoint handed out, waiting for handshake verification (`attempts` = cycles used so far).
    DirectPending { attempts: u8 },
    /// Direct link verified (last handshake inside the health window).
    Direct,
}

impl PeerLinkState {
    /// Status report contract field (`relay` / `direct_pending` / `direct`), used by the console to
    /// display P2P / relay. The pending attempt count is an internal counter and is not exposed.
    pub fn as_str(self) -> &'static str {
        match self {
            PeerLinkState::Relay => "relay",
            PeerLinkState::DirectPending { .. } => "direct_pending",
            PeerLinkState::Direct => "direct",
        }
    }
}

/// Outcome of one direct-link health probe (translated by the execution layer from the per-peer
/// handshake age; see [classify_probe]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// The direct path is healthy (last handshake inside the window).
    Healthy,
    /// The direct path is dead (handshake expired / no handshake anymore).
    Unhealthy,
    /// No readable reading yet (not yet handshaken while pending / reading failed).
    Unknown,
}

/// Peer configuration action produced by a state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLinkAction {
    /// No change needed (keep as is).
    Keep,
    /// Establish direct connect: hand out the direct peer per the decided path (endpoint + `/32` + keepalive).
    Promote(DirectDecision),
    /// Fall back to the hub: remove this peer's direct peer (the hub peer's whole-segment route takes over automatically).
    Demote,
}

/// Translate "a direct peer's last handshake age (seconds)" into a probe result:
/// - `None` (never handshaken / unreadable): pending counts as [ProbeResult::Unknown]
///   (still waiting), any other state as [ProbeResult::Unhealthy] (established but the reading is gone);
/// - `Some(age)`: `age <= health_window_secs` -> Healthy, otherwise Unhealthy.
pub fn classify_probe(
    state: PeerLinkState,
    handshake_age_secs: Option<u64>,
    health_window_secs: u64,
) -> ProbeResult {
    match handshake_age_secs {
        None if matches!(state, PeerLinkState::DirectPending { .. }) => ProbeResult::Unknown,
        None => ProbeResult::Unhealthy,
        Some(age) if age <= health_window_secs => ProbeResult::Healthy,
        Some(_) => ProbeResult::Unhealthy,
    }
}

/// Promotion probe for DirectPending (**handshake evidence first**, see [DIRECT_PROMOTE_FRESH_SECS]):
/// - last handshake age at or below `promote_fresh_secs` -> Healthy (direct verified, promote to Direct);
/// - beyond `health_window_secs` -> Unhealthy (there was a handshake but it is long dead, so time out and fall back);
/// - anything else (not yet handshaken / missing reading / age in the rekey gap between the two windows) ->
///   Unknown (keep waiting; fall back once attempts are used up).
pub fn classify_promote_probe(
    handshake_age_secs: Option<u64>,
    promote_fresh_secs: u64,
    health_window_secs: u64,
) -> ProbeResult {
    match handshake_age_secs {
        Some(age) if age <= promote_fresh_secs => ProbeResult::Healthy,
        Some(age) if age > health_window_secs => ProbeResult::Unhealthy,
        _ => ProbeResult::Unknown,
    }
}

/// State machine transition (once per probe cycle, pure function):
/// - Relay: only the decision matters. A viable direct path exists -> `DirectPending{1}` + Promote;
///   none -> stay on Relay. A probe is meaningless in this state (no direct endpoint to probe yet).
/// - DirectPending: Healthy -> Direct; unhealthy with `max_attempts` cycles already used up
///   -> Relay + Demote (hole punching failed, fall back to relay, no error); otherwise bump the cycle count by 1 and keep waiting.
/// - Direct: Unhealthy -> Relay + Demote (an automatic fall back when direct connect breaks);
///   Healthy / Unknown (a transient read failure must not kill it) -> keep.
pub fn on_probe(
    state: PeerLinkState,
    decision: DirectDecision,
    probe: ProbeResult,
    max_attempts: u8,
) -> (PeerLinkState, PeerLinkAction) {
    match state {
        PeerLinkState::Relay => match decision {
            DirectDecision::Relay => (PeerLinkState::Relay, PeerLinkAction::Keep),
            path => (
                PeerLinkState::DirectPending { attempts: 1 },
                PeerLinkAction::Promote(path),
            ),
        },
        PeerLinkState::DirectPending { attempts } => {
            if probe == ProbeResult::Healthy {
                return (PeerLinkState::Direct, PeerLinkAction::Keep);
            }
            if attempts >= max_attempts.max(1) {
                return (PeerLinkState::Relay, PeerLinkAction::Demote);
            }
            (
                PeerLinkState::DirectPending {
                    attempts: attempts + 1,
                },
                PeerLinkAction::Keep,
            )
        }
        PeerLinkState::Direct => match probe {
            ProbeResult::Unhealthy => (PeerLinkState::Relay, PeerLinkAction::Demote),
            _ => (PeerLinkState::Direct, PeerLinkAction::Keep),
        },
    }
}

/// Direct-link status report for a single peer (§12.3: carried in the agent heartbeat,
/// kept in memory only by the hub, used by the console to display "P2P / relay"). The peer public key is the primary key - the server / console map from it to the device.
fn default_connection_mode() -> String {
    "hub_relay".to_string()
}

/// SEL-004 details of a single direct candidate endpoint (shown in the console peer details).
///
/// The agent aggregates these from the probe window (SEL-001) and reports them via [DirectLinkStatus::candidates]:
/// endpoint / RTT / loss / whether it is currently selected / the selection reason. A pure data carrier, no IO.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DirectCandidateStatus {
    /// Candidate endpoint (`ip:port`).
    pub endpoint: String,
    /// Candidate classification (`lan` / `public`, [crate::p2p::EndpointKind::as_str]).
    pub kind: String,
    /// Median RTT inside the window (milliseconds); `None` = no RTT samples (all lost / not measured).
    pub rtt_ms: Option<u64>,
    /// Loss rate inside the window (0.0..=1.0).
    pub loss_rate: f64,
    /// Whether this is the currently selected direct endpoint.
    pub selected: bool,
    /// Selection reason (`current` = the live path; `backup` = not selected; degradation / switching reasons are recorded separately).
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DirectLinkStatus {
    /// Peer wg public key (the device's unique identity).
    pub public_key: String,
    /// Peer overlay address.
    pub virtual_ipv4: Ipv4Addr,
    /// `relay` / `direct_pending` / `direct` ([PeerLinkState::as_str]).
    pub link_state: String,
    /// Direct handshake age (seconds) read by the latest probe; `None` = no reading yet (pending /
    /// read failure). A link freshness signal, not an exact RTT - WireGuard does not expose a per-peer
    /// RTT, so handshake age is the activity proxy adopted by design (same rule as [classify_probe]).
    pub last_handshake_age_secs: Option<u64>,
    /// Peer name (read by the agent from the planned candidates; empty on older agents or when
    /// unavailable). Shown directly by the UI/CLI; the server still indexes by device identity, with the public key as the key.
    #[serde(default)]
    pub peer_name: String,
    /// Connection mode (`p2p_direct` / `direct_pending` / `hub_relay`; semantically the same as
    /// [link_state], but "relay" is no longer implied by the default).
    #[serde(default = "default_connection_mode")]
    pub connection_mode: String,
    /// Direct endpoint (`ip:port`; empty when relaying / when it could not be obtained).
    #[serde(default)]
    pub endpoint: String,
    /// Measured RTT of the direct path on the latest probe (milliseconds); `None` = not measured / probe failed.
    #[serde(default)]
    pub rtt_ms: Option<u64>,
    /// RTT reading source, labelled honestly (four states): `probe_ok` = the direct path was measured
    /// successfully (overlay or the fallback endpoint); `handshake_fresh` = unmeasurable but the last
    /// handshake is fresh (the activity evidence is the handshake, not ping - Windows mesh firewalls
    /// often do not answer ICMP); `probe_failed` = neither path responded and the handshake shows no
    /// fresh evidence either; `unprobed` = not its turn (probe in flight / no candidate);
    /// `None` = not measured / an older agent with no source label. The display layer uses this to label the RTT column's source; "last handshake" remains the primary evidence of link liveness.
    #[serde(default)]
    pub rtt_source: Option<String>,
    /// Unix timestamp (seconds) of the last handshake; 0 / `None` = no handshake yet.
    #[serde(default)]
    pub last_handshake_at: Option<u64>,
    /// Total received bytes (reading of the direct wg peer; 0 when relaying).
    #[serde(default)]
    pub rx_bytes: u64,
    /// Total sent bytes (reading of the direct wg peer; 0 when relaying).
    #[serde(default)]
    pub tx_bytes: u64,
    /// SEL-004 details for every candidate endpoint (endpoint / RTT / loss / current selection and reason).
    /// Empty = not reported or probing disabled; the console peer details render from this.
    #[serde(default)]
    pub candidates: Vec<DirectCandidateStatus>,
}

#[cfg(test)]
mod tests {
    use super::{
        classify_probe, classify_promote_probe, on_probe, DirectCandidateStatus, DirectLinkStatus,
        PeerLinkAction, PeerLinkState, ProbeResult, DIRECT_HEALTH_WINDOW_SECS,
        DIRECT_PROMOTE_FRESH_SECS, MAX_PROMOTE_ATTEMPTS,
    };
    use crate::p2p::endpoint::DirectDecision;
    use crate::p2p::test_support::{lan, public};

    // ----------------------------------------------------- state machine --------

    #[test]
    fn relay_promotes_when_a_path_exists() {
        let (next, action) = on_probe(
            PeerLinkState::Relay,
            DirectDecision::SameLan(lan("192.168.1.50", 51820)),
            ProbeResult::Unknown, // Relay has no direct path to probe; the probe is meaningless
            MAX_PROMOTE_ATTEMPTS,
        );
        assert_eq!(next, PeerLinkState::DirectPending { attempts: 1 });
        assert_eq!(
            action,
            PeerLinkAction::Promote(DirectDecision::SameLan(lan("192.168.1.50", 51820)))
        );
    }

    #[test]
    fn relay_without_path_stays_and_never_errors() {
        let (next, action) = on_probe(
            PeerLinkState::Relay,
            DirectDecision::Relay,
            ProbeResult::Unknown,
            MAX_PROMOTE_ATTEMPTS,
        );
        assert_eq!(next, PeerLinkState::Relay);
        assert_eq!(action, PeerLinkAction::Keep);
    }

    #[test]
    fn pending_converges_on_first_handshake() {
        let (next, action) = on_probe(
            PeerLinkState::DirectPending { attempts: 2 },
            DirectDecision::Relay, // the decision no longer matters while pending
            ProbeResult::Healthy,
            MAX_PROMOTE_ATTEMPTS,
        );
        assert_eq!(next, PeerLinkState::Direct);
        assert_eq!(action, PeerLinkAction::Keep);
    }

    #[test]
    fn pending_times_out_after_three_cycles_and_demotes() {
        let state = PeerLinkState::DirectPending {
            attempts: MAX_PROMOTE_ATTEMPTS,
        };
        let (next, action) = on_probe(
            state,
            DirectDecision::HolePunch(public("203.0.113.5", 51820)),
            ProbeResult::Unknown,
            MAX_PROMOTE_ATTEMPTS,
        );
        assert_eq!(next, PeerLinkState::Relay);
        assert_eq!(action, PeerLinkAction::Demote);

        // Cycles not used up: keep waiting, do not demote.
        let (next, action) = on_probe(
            PeerLinkState::DirectPending { attempts: 1 },
            DirectDecision::Relay,
            ProbeResult::Unknown,
            MAX_PROMOTE_ATTEMPTS,
        );
        assert_eq!(next, PeerLinkState::DirectPending { attempts: 2 });
        assert_eq!(action, PeerLinkAction::Keep);
    }

    #[test]
    fn direct_demotes_on_stale_handshake() {
        let (next, action) = on_probe(
            PeerLinkState::Direct,
            DirectDecision::SameLan(lan("192.168.1.50", 51820)),
            ProbeResult::Unhealthy,
            MAX_PROMOTE_ATTEMPTS,
        );
        assert_eq!(next, PeerLinkState::Relay);
        assert_eq!(action, PeerLinkAction::Demote);
    }

    #[test]
    fn direct_keeps_on_unreadable_probe_no_flapping() {
        let (next, action) = on_probe(
            PeerLinkState::Direct,
            DirectDecision::Relay,
            ProbeResult::Unknown,
            MAX_PROMOTE_ATTEMPTS,
        );
        assert_eq!(next, PeerLinkState::Direct);
        assert_eq!(action, PeerLinkAction::Keep);
    }

    #[test]
    fn demoted_peer_repromotes_on_recovery() {
        // After Demote we are back on Relay: the decision is still viable next cycle -> Promote again (auto re-promotion).
        let (next, action) = on_probe(
            PeerLinkState::Relay,
            DirectDecision::SameLan(lan("192.168.1.50", 51820)),
            ProbeResult::Unknown,
            MAX_PROMOTE_ATTEMPTS,
        );
        assert_eq!(next, PeerLinkState::DirectPending { attempts: 1 });
        assert!(matches!(action, PeerLinkAction::Promote(_)));
    }

    #[test]
    fn full_lifecycle_direct_to_relay_and_back() {
        let path = DirectDecision::SameLan(lan("192.168.1.50", 51820));
        let mut state = PeerLinkState::Relay;

        // ① Establish.
        let (s, a) = on_probe(state, path, ProbeResult::Unknown, MAX_PROMOTE_ATTEMPTS);
        assert!(matches!(a, PeerLinkAction::Promote(_)));
        state = s;

        // ② Handshake succeeds -> Direct.
        let (s, a) = on_probe(state, path, ProbeResult::Healthy, MAX_PROMOTE_ATTEMPTS);
        assert_eq!(a, PeerLinkAction::Keep);
        state = s;
        assert_eq!(state, PeerLinkState::Direct);

        // ③ Breaks -> fall back to the hub.
        let (s, a) = on_probe(state, path, ProbeResult::Unhealthy, MAX_PROMOTE_ATTEMPTS);
        assert_eq!(a, PeerLinkAction::Demote);
        state = s;
        assert_eq!(state, PeerLinkState::Relay);

        // ④ Recovers -> automatically promoted back to direct.
        let (_, a) = on_probe(state, path, ProbeResult::Unknown, MAX_PROMOTE_ATTEMPTS);
        assert!(matches!(a, PeerLinkAction::Promote(_)));
    }

    /// Promotion threshold (handshake evidence first): while pending, a last handshake age at or below the
    /// promotion threshold counts as Healthy - **probe failure / unavailability does not block promotion**
    /// (the Windows mesh firewall drops 100% of ICMP to the wg interface, imac 2026-11-07 evidence); the
    /// rekey gap (180, 240] keeps waiting; only beyond the health window counts as dead.
    #[test]
    fn classify_promote_probe_uses_handshake_evidence_not_icmp() {
        // Handshake fresh -> promote, whether or not the probe succeeds.
        assert_eq!(
            classify_promote_probe(
                Some(0),
                DIRECT_PROMOTE_FRESH_SECS,
                DIRECT_HEALTH_WINDOW_SECS
            ),
            ProbeResult::Healthy
        );
        assert_eq!(
            classify_promote_probe(
                Some(DIRECT_PROMOTE_FRESH_SECS),
                DIRECT_PROMOTE_FRESH_SECS,
                DIRECT_HEALTH_WINDOW_SECS
            ),
            ProbeResult::Healthy
        );
        // Just past the promotion threshold but inside the health window (rekey gap): keep waiting, neither promote nor declare dead.
        assert_eq!(
            classify_promote_probe(
                Some(DIRECT_PROMOTE_FRESH_SECS + 1),
                DIRECT_PROMOTE_FRESH_SECS,
                DIRECT_HEALTH_WINDOW_SECS
            ),
            ProbeResult::Unknown
        );
        // Not yet handshaken / missing reading: keep waiting (time out and fall back once attempts are used up).
        assert_eq!(
            classify_promote_probe(None, DIRECT_PROMOTE_FRESH_SECS, DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Unknown
        );
        // Beyond the health window: there was a handshake but it is long dead -> Unhealthy (the fallback path).
        assert_eq!(
            classify_promote_probe(
                Some(DIRECT_HEALTH_WINDOW_SECS + 1),
                DIRECT_PROMOTE_FRESH_SECS,
                DIRECT_HEALTH_WINDOW_SECS
            ),
            ProbeResult::Unhealthy
        );
    }

    /// Regression for a fix (user-reported: direct connect was always "dialing"): pending has handshaken
    /// (fresh handshake) but the ICMP probe never succeeds -> must **promote to Direct in that very
    /// cycle**, not wait out the attempts timeout. The same-rule regression over the full plan_updates
    /// path lives in the agent direct.rs test (`pending_with_fresh_handshake_promotes_via_plan_updates`).
    #[test]
    fn pending_with_fresh_handshake_promotes_even_when_probe_never_succeeds() {
        for age in [0u64, 30, DIRECT_PROMOTE_FRESH_SECS] {
            let (next, action) = on_probe(
                PeerLinkState::DirectPending {
                    attempts: MAX_PROMOTE_ATTEMPTS,
                },
                DirectDecision::Relay,
                classify_promote_probe(
                    Some(age),
                    DIRECT_PROMOTE_FRESH_SECS,
                    DIRECT_HEALTH_WINDOW_SECS,
                ),
                MAX_PROMOTE_ATTEMPTS,
            );
            assert_eq!(next, PeerLinkState::Direct, "age {age} must promote");
            assert_eq!(action, PeerLinkAction::Keep);
        }
    }

    /// Handshake expired (beyond the health window) -> pending is judged dead and falls back (the demotion
    /// rule is not loosened): Unhealthy falls back at once, no extra grace period.
    #[test]
    fn pending_with_stale_handshake_falls_back_to_relay() {
        let (next, action) = on_probe(
            PeerLinkState::DirectPending {
                attempts: MAX_PROMOTE_ATTEMPTS,
            },
            DirectDecision::Relay,
            classify_promote_probe(
                Some(DIRECT_HEALTH_WINDOW_SECS + 1),
                DIRECT_PROMOTE_FRESH_SECS,
                DIRECT_HEALTH_WINDOW_SECS,
            ),
            MAX_PROMOTE_ATTEMPTS,
        );
        assert_eq!(next, PeerLinkState::Relay);
        assert_eq!(action, PeerLinkAction::Demote);
    }

    #[test]
    fn classify_probe_by_state_and_window() {
        let pending = PeerLinkState::DirectPending { attempts: 1 };
        // No reading while pending = still waiting.
        assert_eq!(
            classify_probe(pending, None, DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Unknown
        );
        // No reading while Direct = dead.
        assert_eq!(
            classify_probe(PeerLinkState::Direct, None, DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Unhealthy
        );
        // Inside the window = healthy; outside = dead. The window must be larger than WireGuard's
        // re-handshake cadence (an active session re-handshakes every ~120-180s; keepalives do not
        // refresh latest-handshake) - a healthy idle link's handshake age legitimately climbs to ~180s.
        assert_eq!(
            classify_probe(PeerLinkState::Direct, Some(20), DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Healthy
        );
        assert_eq!(
            classify_probe(PeerLinkState::Direct, Some(180), DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Healthy
        );
        assert_eq!(
            classify_probe(PeerLinkState::Direct, Some(241), DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Unhealthy
        );
    }

    #[test]
    fn link_state_as_str_is_the_report_contract() {
        assert_eq!(PeerLinkState::Relay.as_str(), "relay");
        assert_eq!(
            PeerLinkState::DirectPending { attempts: 3 }.as_str(),
            "direct_pending"
        );
        assert_eq!(PeerLinkState::Direct.as_str(), "direct");
    }

    #[test]
    fn direct_link_status_round_trips_as_json() {
        let status = DirectLinkStatus {
            public_key: "pub-b".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            link_state: PeerLinkState::Direct.as_str().into(),
            last_handshake_age_secs: Some(12),
            peer_name: "edge-b".into(),
            connection_mode: "p2p_direct".into(),
            endpoint: "192.168.1.2:51821".into(),
            rtt_ms: Some(7),
            rtt_source: Some("overlay".into()),
            last_handshake_at: Some(1_700_000_000),
            rx_bytes: 1024,
            tx_bytes: 2048,
            candidates: vec![DirectCandidateStatus {
                endpoint: "192.168.1.2:51821".into(),
                kind: "lan".into(),
                rtt_ms: Some(7),
                loss_rate: 0.0,
                selected: true,
                reason: "current".into(),
            }],
        };
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(
            serde_json::from_str::<DirectLinkStatus>(&json).unwrap(),
            status
        );
        assert!(json.contains(r#""link_state":"direct""#));

        let pending = DirectLinkStatus {
            public_key: "pub-c".into(),
            virtual_ipv4: "10.240.0.4".parse().unwrap(),
            link_state: PeerLinkState::DirectPending { attempts: 1 }.as_str().into(),
            last_handshake_age_secs: None,
            peer_name: "edge-c".into(),
            connection_mode: "direct_pending".into(),
            endpoint: String::new(),
            rtt_ms: None,
            rtt_source: None,
            last_handshake_at: None,
            rx_bytes: 0,
            tx_bytes: 0,
            candidates: vec![],
        };
        assert_eq!(
            serde_json::from_str::<DirectLinkStatus>(&serde_json::to_string(&pending).unwrap())
                .unwrap(),
            pending
        );
    }
}
