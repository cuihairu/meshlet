//! 设备掉线可观测（P1，2026-11-12 用户令：先修稳定性）。
//!
//! 背景实锤（dev VPS）：imac 掉线成事实（0 条 ESTABLISHED），server 近 24h
//! 日志却 0 条断连记录——presence 是**读时现算**的纯函数
//! （`meshlet_domain::presence`），只有控制台刷新才看得到掉线；没人看的
//! 时候，掉线在 server 日志里**不存在**。
//!
//! 本模块补的是时间线：后台周期复算每台活跃设备的 presence，**状态迁移**
//! 时显式落日志——心跳超时掉线（Online → 非 Online）WARN、恢复在线 INFO、
//! 证据全失（TunnelOnly → Offline：握手也超时）INFO。日志里能直接查出
//! 「设备 X 于何时掉线、何时恢复」，文案口径对齐 diagnostics 的
//! 「stale handshake / no handshake ever observed」既有判读。
//!
//! 判定完全复用 [`crate::service::evaluate_presence`]（与控制台/量规同一个
//! 口径），不引入第二套判定。不依赖 `dataplane.enabled`——纯控制面环境
//! 也须看得见每台设备的掉线时间线。
//!
//! 已知边界（如实记录）：复算周期 [`WATCH_INTERVAL_SECS`] 决定检出延迟
//! （≈ 周期 + `agent_window`）；进程重启后首轮只建基线、不补报掉线
//! （重启前的事日志里本就没有连续性可言）。

use std::collections::HashMap;
use std::time::Duration;

use meshlet_domain::presence::PresenceState;
use PresenceState::{Offline, Online, TunnelOnly};

use crate::auth::SharedAppState;

/// 复算周期（秒）：与 hub 恢复 / 任务回收同一档（30s）。
const WATCH_INTERVAL_SECS: u64 = 30;

/// 一条值得落日志的状态迁移（纯分类，单测覆盖全矩阵）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEvent {
    /// 掉线：agent 上报超窗（Online → TunnelOnly / Offline）。
    Disconnected,
    /// 恢复在线（TunnelOnly / Offline → Online）。
    BackOnline,
    /// 证据全失：握手也超窗（TunnelOnly → Offline）。
    EvidenceLost,
}

/// 迁移分类：`None` = 无迁移或按口径不落日志的变化。
///
/// - 同态（含仅证据来源变化）→ `None`；
/// - `Offline → TunnelOnly`（握手先回来、agent 还没报）→ `None`：部分恢复
///   不宣告，等 agent 上报成立再落 `BackOnline`；
/// - 其余跨态迁移按上表落日志。
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

/// 一台设备的 presence 复算快照（锁内采集；迁移判定与落日志在锁外做）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct DevicePresence {
    id: String,
    name: String,
    state: PresenceState,
    last_report_at: Option<String>,
    last_handshake_at: Option<String>,
}

/// 对一台设备判定本轮迁移（纯函数，单测覆盖）：`seen` 记上次状态并更新为
/// 本轮状态；首轮只建基线（`None`，不迁移告警——重启后对早已离线的设备
/// 不刷一屏「掉线」），其后按 [`classify`] 口径返回值得落日志的迁移。
fn transition(
    seen: &mut HashMap<String, PresenceState>,
    device: &DevicePresence,
) -> Option<(WatchEvent, PresenceState)> {
    let previous = seen.insert(device.id.clone(), device.state)?;
    let event = classify(previous, device.state)?;
    Some((event, previous))
}

/// 起掉线监视：周期复算每台活跃设备的 presence，状态迁移时落日志。
/// 常驻到进程退出；异常只记日志，绝不影响请求路径。
pub fn start(state: SharedAppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(WATCH_INTERVAL_SECS));
        let mut seen: HashMap<String, PresenceState> = HashMap::new();
        loop {
            ticker.tick().await;
            // 持 mesh 锁只做复算与快照；日志在锁外落。
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

    /// 全迁移矩阵：每对 (from, to) 的分类必须与文档口径一致——
    /// 掉线/恢复/证据全失各一条，同态与部分恢复不落日志。
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

    /// 时间线口径：首轮建基线不告警（重启后不刷屏）；同态不告警；跨态告警
    /// 一次；告警后状态即更新，恢复在线再告一次——日志里每台设备有完整的
    /// 掉线/恢复时间线。
    #[test]
    fn transition_builds_a_per_device_timeline() {
        let mut seen: HashMap<String, PresenceState> = HashMap::new();
        // 首轮基线：设备已在线（可能是重启前就在线）——不告警。
        assert_eq!(transition(&mut seen, &device("d1", Online)), None);
        // 心跳超窗：掉线——告警，from=Online。
        assert_eq!(
            transition(&mut seen, &device("d1", Offline)),
            Some((WatchEvent::Disconnected, Online))
        );
        // 仍离线：同态不重复告警。
        assert_eq!(transition(&mut seen, &device("d1", Offline)), None);
        // 握手先回来（部分恢复）：等 agent 上报，不告警。
        assert_eq!(transition(&mut seen, &device("d1", TunnelOnly)), None);
        // agent 上报回来：恢复在线——告警，from=TunnelOnly。
        assert_eq!(
            transition(&mut seen, &device("d1", Online)),
            Some((WatchEvent::BackOnline, TunnelOnly))
        );
        // 多设备互不干扰：d2 首轮基线同样不告警。
        assert_eq!(transition(&mut seen, &device("d2", Offline)), None);
        assert_eq!(transition(&mut seen, &device("d1", Online)), None);
    }
}
