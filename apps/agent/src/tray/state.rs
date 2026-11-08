//! 托盘四态状态机：不新造状态名——四态逐一对应仓内已有枚举（见模块 [`crate::tray`]
//! 头文档「纪律一」的映射表），derive 由 agent 侧真实信号推导；每态带文本等价物
//! （tooltip / accessible_name），不依赖颜色。渲染（轮廓几何与调色板）在
//! [`crate::tray::icon`]。

use crate::reconcile::Reason;

/// 托盘状态：四态各对应一组仓内已有枚举，不新造状态名。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    /// 「在线直连」/「中继中」——**v1 同态**（ADR-002 全部流量经 VPS 中心中继，
    /// 仓内无直连信号，P2P 留 v2）。对应：
    /// [`PresenceState::Online`] ＋ [`Reason::UpToDate`] ＋ [`ApplyStatus::Applied`]
    /// ＋ [`DeviceStatus::Active`]。
    Online,
    /// 隧道连通但控制通道失效。对应：[`PresenceState::TunnelOnly`]
    /// （服务端口径「仅握手新鲜、agent 上报过期」）；agent 侧对位：本机 `wg show
    /// latest-handshakes` 有值，但心跳上报失败。
    TunnelOnly,
    /// 隧道异常：本地内核对象与服务端期望不一致，或重放失败。对应：
    /// [`Reason::KernelDrift`] ＋ [`ApplyStatus::Failed`]。
    TunnelDrift,
    /// 已断开：控制通道与隧道均无新鲜证据。对应 [`PresenceState::Offline`]。
    Offline,
}

impl TrayState {
    /// 由 agent 侧真实信号推导（纯函数，便于单测）：
    ///
    /// - [`Reason::KernelDrift`] → [`TrayState::TunnelDrift`]（内核漂移即「隧道异常」）
    /// - 控制通道失效 ＋ 本地读得到握手 → [`TrayState::TunnelOnly`]
    /// - 控制通道失效 ＋ 本地也读不到握手 → [`TrayState::Offline`]
    /// - 其余（含 `UpToDate` / `DesiredConfigChanged` / `NoLocalLedger`，均为**预期内**
    ///   的配置变更而非异常）→ [`TrayState::Online`]
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

    /// 无障碍短名（tray 图标的可访问名称；不依赖颜色）。
    pub fn accessible_name(self) -> &'static str {
        match self {
            TrayState::Online => "Meshlet online",
            TrayState::TunnelOnly => "Meshlet tunnel only",
            TrayState::TunnelDrift => "Meshlet tunnel drift",
            TrayState::Offline => "Meshlet offline",
        }
    }

    /// tooltip 正文（整句，含状态含义；与图标形状互为冗余通道）。
    pub fn tooltip(self) -> &'static str {
        match self {
            TrayState::Online => "在线：控制通道正常，数据面与服务端期望一致（流量经 VPS 中继）",
            TrayState::TunnelOnly => "隧道连通但控制通道失效：本机握手新鲜，agent 上报过期",
            TrayState::TunnelDrift => "隧道异常：本地内核对象与服务端期望不一致（正在重放）",
            TrayState::Offline => "已断开：无新鲜的控制通道或隧道证据",
        }
    }
}

/// 全部四态（测试遍历用；`#[cfg(test)]` 不进生产构建）。
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

    // ── 纪律一：状态映射到仓内已有枚举 ───────────────────────────────────

    #[test]
    fn kernel_drift_maps_to_tunnel_drift() {
        assert_eq!(
            TrayState::derive(Reason::KernelDrift, true, true),
            TrayState::TunnelDrift
        );
        // 漂移优先于心跳状态：控制通道失效时也是 TunnelDrift。
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
        // DesiredConfigChanged / NoLocalLedger 是预期内的配置变更，不是异常。
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

    /// 编译期确认映射目标都是仓内已有枚举（防漂移）。
    #[test]
    fn mapped_enums_are_the_repos_own() {
        assert_eq!(PresenceState::Online.as_str(), "online");
        assert_eq!(PresenceState::TunnelOnly.as_str(), "tunnel_only");
        assert_eq!(PresenceState::Offline.as_str(), "offline");
        assert_eq!(Reason::KernelDrift.as_str(), "kernel_drift");
        // 隧道异常态的另一个对位：应用中失败（ApplyStatus 状态机允许的迁移）。
        assert!(ApplyStatus::Applying.can_transition_to(ApplyStatus::Failed));
        assert_ne!(DeviceStatus::Active, DeviceStatus::Revoked);
    }
}
