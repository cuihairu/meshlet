//! Tray four-state machine: no new state names are invented - each of the four states maps
//! one-to-one onto an existing in-repo enum (see the mapping table in the "discipline one"
//! section of the [`crate::tray`] module header), and `derive` reasons from real agent-side
//! signals; every state carries a text equivalent (tooltip / accessible_name), never relying on
//! color. Rendering (outline geometry and palette) lives in [`crate::tray::icon`].

use crate::reconcile::Reason;

/// Tray state: each of the four states corresponds to a set of existing in-repo enums; no new state names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    /// "online direct" / "relaying" - **the same state in v1** (ADR-002 sends all traffic through the VPS central relay,
    /// and the repo has no direct-connect signal; P2P is deferred to v2). Maps to:
    /// [`PresenceState::Online`] + [`Reason::UpToDate`] + [`ApplyStatus::Applied`]
    /// + [`DeviceStatus::Active`].
    Online,
    /// The tunnel is connected but the control channel is down. Maps to [`PresenceState::TunnelOnly`]
    /// (the server-side notion of "only the handshake is fresh, the agent report is stale"); the agent-side
    /// counterpart: `wg show latest-handshakes` on this machine has a value, but heartbeat reporting fails.
    TunnelOnly,
    /// Tunnel fault: local kernel objects disagree with the server's expectation, or replay failed. Maps to
    /// [`Reason::KernelDrift`] + [`ApplyStatus::Failed`].
    TunnelDrift,
    /// Disconnected: no fresh evidence for either the control channel or the tunnel. Maps to [`PresenceState::Offline`].
    Offline,
}

impl TrayState {
    /// Derived from real agent-side signals (pure function, easy to unit test):
    ///
    /// - [`Reason::KernelDrift`] -> [`TrayState::TunnelDrift`] (kernel drift means "tunnel fault")
    /// - control channel down + a handshake is readable locally -> [`TrayState::TunnelOnly`]
    /// - control channel down + no handshake readable locally either -> [`TrayState::Offline`]
    /// - everything else (including `UpToDate` / `DesiredConfigChanged` / `NoLocalLedger`, all **expected**
    ///   configuration changes rather than faults) -> [`TrayState::Online`]
    pub fn derive(reason: Reason, control_ok: bool, tunnel_alive: bool) -> Self {
        if reason == Reason::KernelDrift {
            return TrayState::TunnelDrift;
        }
        if !control_ok {
            return if tunnel_alive {
                TrayState::TunnelOnly
            } else {
                TrayState::Offline
            };
        }
        TrayState::Online
    }

    /// Accessibility short name (the tray icon's accessible name; does not rely on color).
    pub fn accessible_name(self) -> &'static str {
        match self {
            TrayState::Online => "Meshlet online",
            TrayState::TunnelOnly => "Meshlet tunnel only",
            TrayState::TunnelDrift => "Meshlet tunnel drift",
            TrayState::Offline => "Meshlet offline",
        }
    }

    /// Tooltip body (a full sentence carrying the state's meaning; a redundant channel alongside the icon shape).
    pub fn tooltip(self) -> &'static str {
        match self {
            TrayState::Online => "在线：控制通道正常，数据面与服务端期望一致（流量经 VPS 中继）",
            TrayState::TunnelOnly => "隧道连通但控制通道失效：本机握手新鲜，agent 上报过期",
            TrayState::TunnelDrift => "隧道异常：本地内核对象与服务端期望不一致（正在重放）",
            TrayState::Offline => "已断开：无新鲜的控制通道或隧道证据",
        }
    }
}

/// All four states (for test iteration; `#[cfg(test)]` does not enter production builds).
#[cfg(test)]
pub(crate) fn all_states() -> [TrayState; 4] {
    [
        TrayState::Online,
        TrayState::TunnelOnly,
        TrayState::TunnelDrift,
        TrayState::Offline,
    ]
}

#[cfg(test)]
mod tests {
    use super::all_states;
    use super::*;
    use meshlet_domain::entities::{ApplyStatus, DeviceStatus};
    use meshlet_domain::presence::PresenceState;

    // -- Discipline one: states map onto existing in-repo enums ------------------------------

    #[test]
    fn kernel_drift_maps_to_tunnel_drift() {
        assert_eq!(
            TrayState::derive(Reason::KernelDrift, true, true),
            TrayState::TunnelDrift
        );
        // Drift takes priority over heartbeat state: TunnelDrift even when the control channel is down.
        assert_eq!(
            TrayState::derive(Reason::KernelDrift, false, false),
            TrayState::TunnelDrift
        );
    }

    #[test]
    fn control_channel_down_with_handshake_is_tunnel_only() {
        assert_eq!(
            TrayState::derive(Reason::UpToDate, false, true),
            TrayState::TunnelOnly
        );
    }

    #[test]
    fn control_channel_down_without_handshake_is_offline() {
        assert_eq!(
            TrayState::derive(Reason::UpToDate, false, false),
            TrayState::Offline
        );
    }

    #[test]
    fn expected_config_changes_stay_online() {
        // DesiredConfigChanged / NoLocalLedger are expected configuration changes, not faults.
        for reason in [
            Reason::UpToDate,
            Reason::DesiredConfigChanged,
            Reason::NoLocalLedger,
        ] {
            assert_eq!(
                TrayState::derive(reason, true, true),
                TrayState::Online,
                "{reason:?} must render as Online"
            );
        }
    }

    #[test]
    fn tooltips_are_pairwise_distinct() {
        let states = all_states();
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(
                    states[i].tooltip(),
                    states[j].tooltip(),
                    "{:?} and {:?} must not share a tooltip",
                    states[i],
                    states[j]
                );
                assert_ne!(states[i].accessible_name(), states[j].accessible_name());
            }
        }
    }

    /// Confirm at compile time that every mapping target is an existing in-repo enum (drift guard).
    #[test]
    fn mapped_enums_are_the_repos_own() {
        assert_eq!(PresenceState::Online.as_str(), "online");
        assert_eq!(PresenceState::TunnelOnly.as_str(), "tunnel_only");
        assert_eq!(PresenceState::Offline.as_str(), "offline");
        assert_eq!(Reason::KernelDrift.as_str(), "kernel_drift");
        // Another counterpart of the tunnel-fault state: application failure (a transition the ApplyStatus state machine permits).
        assert!(ApplyStatus::Applying.can_transition_to(ApplyStatus::Failed));
        assert_ne!(DeviceStatus::Active, DeviceStatus::Revoked);
    }
}
