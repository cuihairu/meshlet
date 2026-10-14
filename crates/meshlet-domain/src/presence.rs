//! 设备在线状态判定（[存档 §12.2/§12.4](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 判定输入是三类「证据」的时间戳：
//! - **Agent 心跳/状态上报**（agent 经 HTTPS 控制通道定期上报，§14.1）——最强信号，
//!   证明 agent 进程与设备网络功能在正常工作；
//! - **隧道握手**（WireGuard latest-handshake，agent 可从 `wg show` 本地读取后上报）——
//!   仅证明隧道连通，**不能**直接等同于设备全部功能正常（§12.4）；
//! - **加入记录**（enrollment）——设备至少出现过，但无后续信号时不可宣称在线。
//!
//! 判定结果必须标注**数据来源与更新时间**（§12.2）：控制台不允许只给一个
//! 绿色「在线」图标而不说明该结论由哪类证据、在什么时刻支撑。
//!
//! 纯函数、无 I/O：时间戳为 ISO-8601 字符串（与 [crate::entities] 一致），
//! 判定时刻 `now` 与阈值均可注入，便于确定性单测。

use crate::entities::Timestamp;
use std::time::Duration;

/// 证据来源（即「在线状态的数据来源」，按强度排序）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PresenceSource {
    /// Agent 心跳/状态上报（最强：agent 进程与控制通道正常）。
    AgentReport,
    /// 隧道握手（仅证明隧道连通）。
    Handshake,
    /// 仅加入记录（无握手/心跳）。
    Enrollment,
    /// 无任何证据。
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

/// 在线状态。**握手新鲜 ≠ 在线**（§12.4）：
/// 只有 agent 上报能证明设备功能正常；仅有握手证据时标注 `TunnelOnly`，
/// 由控制台以区别于「在线」的样式展示。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceState {
    /// Agent 上报在窗口内：在线。
    Online,
    /// 仅握手在窗口内：隧道连通，但缺 agent 证据，不能视为设备全部功能正常。
    TunnelOnly,
    /// 无任何新鲜证据。
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

/// 判定窗口阈值（可注入；生产默认见 [PresenceThresholds::default]）。
#[derive(Debug, Clone, Copy)]
pub struct PresenceThresholds {
    /// agent 上报新鲜窗口：默认 5 分钟（agent 约每分钟上报，容忍数次丢失）。
    pub agent_window: Duration,
    /// 握手新鲜窗口：默认 2 分钟（保活 25s 下隧道活跃时握手会持续刷新）。
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

/// 判定输入：三类证据的时间戳（`None` 表示从未观测到）。
#[derive(Debug, Clone, Copy, Default)]
pub struct PresenceInput<'a> {
    pub last_handshake_at: Option<&'a str>,
    pub last_report_at: Option<&'a str>,
    pub enrolled_at: Option<&'a str>,
}

/// 判定结果：状态 + 数据来源（证据强度标注）+ 判定时刻。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presence {
    pub state: PresenceState,
    /// 支撑当前状态的证据来源；Offline 时为**最新一条**证据的来源。
    pub source: PresenceSource,
    /// 判定时刻（即「状态于何时计算」）。
    pub evaluated_at: Timestamp,
}

/// 判定新鲜度：`now - ts <= window` 为新鲜（含边界；未来时间戳视为新鲜，
/// 容忍轻微的时钟偏移）。无法解析的时间戳按「不存在」保守处理。
pub fn fresh(ts: &str, now: &str, window: Duration) -> bool {
    match (parse(ts), parse(now)) {
        (Some(ts), Some(now)) => now
            .signed_duration_since(ts)
            .num_nanoseconds()
            .is_some_and(|delta| delta <= window.as_nanos() as i64),
        _ => false,
    }
}

/// 最新一条证据的来源与时间戳（按解析后的时刻取最大；无法解析的证据忽略）。
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

/// 判定设备在线状态（注入判定时刻与阈值）。
pub fn evaluate(input: PresenceInput<'_>, now: &str, thresholds: &PresenceThresholds) -> Presence {
    let report_fresh = input
        .last_report_at
        .is_some_and(|t| fresh(t, now, thresholds.agent_window));
    let handshake_fresh = input
        .last_handshake_at
        .is_some_and(|t| fresh(t, now, thresholds.handshake_window));

    if report_fresh {
        // agent 上报最强：直接在线。
        return Presence {
            state: PresenceState::Online,
            source: PresenceSource::AgentReport,
            evaluated_at: now.to_string(),
        };
    }
    if handshake_fresh {
        // 握手新鲜仅证明隧道连通，缺 agent 证据不能宣称设备功能全部正常。
        return Presence {
            state: PresenceState::TunnelOnly,
            source: PresenceSource::Handshake,
            evaluated_at: now.to_string(),
        };
    }
    // 离线：标注最新一条证据的来源（数据来源可追溯）。
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

/// 按默认阈值判定。
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
                last_report_at: Some("2026-10-14T11:58:00Z"), // 2 分钟前
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
        // 上报 10 分钟前（超出 5 分钟窗口），握手 1 分钟前（窗口内）→ 仅隧道连通。
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
        // §12.4：最近有 WireGuard 握手 ≠ 设备上所有网络功能都正常。
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
        assert_eq!(p.source, PresenceSource::Handshake); // 最新证据是 11:30 的握手
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
        assert_eq!(p.source, PresenceSource::Enrollment); // 唯一可解析的证据
    }

    #[test]
    fn future_timestamp_counts_as_fresh() {
        // 容忍轻微时钟偏移：证据时刻在未来视为新鲜。
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
        // 恰好 10 秒前 = 边界，新鲜。
        let p = evaluate(
            PresenceInput {
                last_report_at: Some("2026-10-14T11:59:50Z"),
                ..PresenceInput::default()
            },
            NOW,
            &t,
        );
        assert_eq!(p.state, PresenceState::Online);
        // 11 秒前 → 过期。
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
        // 默认 5 分钟窗口：90 秒前的上报新鲜 → 在线。
        let p = evaluate_with_defaults(
            PresenceInput {
                last_report_at: Some("2026-10-14T11:58:30Z"),
                ..PresenceInput::default()
            },
            NOW,
        );
        assert_eq!(p.state, PresenceState::Online);
        // 阈值收紧到 1 分钟：同一证据过期 → 离线。
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
