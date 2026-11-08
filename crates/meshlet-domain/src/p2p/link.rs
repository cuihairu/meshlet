//! 对端链路状态机（30s 探测升降级）与探测分类：Relay / DirectPending / Direct
//! 每探测周期跃迁一次，幂等可重放；晋升只认 WireGuard 握手证据，健康窗口与
//! 晋升门槛构成迟滞策略（防 promote/demote 抖动）。另含 §12.3 链路状态上报
//! 契约（DirectLinkStatus / DirectCandidateStatus）。

use std::net::Ipv4Addr;

use crate::p2p::endpoint::DirectDecision;

/// 探测周期（秒）：任务书「每 30s 探测直连路径」。
pub const DIRECT_PROBE_INTERVAL_SECS: u64 = 30;
/// 直连建立容忍的最大 pending 探测周期数（任务书「3 次握手周期」）。
pub const MAX_PROMOTE_ATTEMPTS: u8 = 3;
/// 直连健康窗口（秒）：直接 peer 最近握手年龄超过此值视为不健康。
///
/// **不能按 keepalive 周期取小值**：`latest-handshake` 只在**完成的重新
/// 握手**时刷新，keepalive/数据包不刷新它。WireGuard 对活跃会话按
/// REKEY_AFTER_TIME（发起方 ~120s，响应方 ~180s）节拍重新握手，健康但
/// 空闲的直连链路握手年龄会周期性涨到 ~180s——窗口若小于该节拍（曾取
/// 35s），健康链路被误判 Unhealthy → demote → promote 每 ~90s 抖动一次
/// （真机 2026-11-06 coding-vm↔cuihaitao 取证）。窗口须大于重新握手
/// 节拍上限；失效链路（对端死、重握手不再成功）的握手年龄会持续增长
/// 超过此窗口，仍能被兜住。
pub const DIRECT_HEALTH_WINDOW_SECS: u64 = 240;
/// 直连 peer 的 persistent-keepalive（秒）：让 wg 主动发包——既是 NAT
/// 打洞的「洞」，也是健康探测的心跳来源。
pub const DIRECT_PERSISTENT_KEEPALIVE_SECS: u32 = 15;
/// 直连晋升门槛（秒）：DirectPending → Direct 只认 **WireGuard 握手证据**——
/// 内核 latest-handshake 年龄 ≤ 此值即判定直连已建立。
///
/// 为什么不是 ICMP 探测：真机取证（Windows 网格，imac 2026-11-07）防火墙对
/// wg 接口 / overlay VIP 的 ICMP echo 100% 丢包——握手新鲜但 ping 全死，链路
/// 完全活着。探测只用于 RTT 标注与 SEL-003 劣化判定，**不再拦晋升**；否则
/// 直连永远卡在 `direct_pending`（拨号中），每 ~90s promote/demote 抖动。
/// 阈值对齐 hub keepalive 与 CLI `peer_mode` 的 p2p_direct 口径（<180s）。
pub const DIRECT_PROMOTE_FRESH_SECS: u64 = 180;

/// 单对端直连链路状态（每探测周期跃迁一次）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLinkState {
    /// 走 hub 中继（现状行为；直连未建立或已回退）。
    Relay,
    /// 直连 endpoint 已下发，等待握手验证（`attempts` 为已用周期数）。
    DirectPending { attempts: u8 },
    /// 直连已验证（最近握手在健康窗口内）。
    Direct,
}

impl PeerLinkState {
    /// 状态上报契约字段（`relay` / `direct_pending` / `direct`），供控制台
    /// 展示 P2P/中继。pending 的尝试次数是内部计数，不对外暴露。
    pub fn as_str(self) -> &'static str {
        match self {
            PeerLinkState::Relay => "relay",
            PeerLinkState::DirectPending { .. } => "direct_pending",
            PeerLinkState::Direct => "direct",
        }
    }
}

/// 一次直连健康探测的结果（由执行层从 per-peer 握手年龄翻译，见
/// [classify_probe]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// 直连路径健康（最近握手在窗口内）。
    Healthy,
    /// 直连路径失效（握手过期 / 再无握手）。
    Unhealthy,
    /// 尚无可判读的读数（pending 中尚未握上手 / 读数失败）。
    Unknown,
}

/// 状态跃迁产生的对端配置动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLinkAction {
    /// 无需变更（保持现状）。
    Keep,
    /// 建立直连：按决策路径下发直连 peer（endpoint + `/32` + keepalive）。
    Promote(DirectDecision),
    /// 回退 hub：移除该对端的直连 peer（hub peer 的整段路由自动接管）。
    Demote,
}

/// 把「直接 peer 最近握手年龄（秒）」翻译成探测结果：
/// - `None`（从未握手 / 无法读取）：pending 视为 [ProbeResult::Unknown]
///   （还在等），其余状态视为 [ProbeResult::Unhealthy]（已建立却没了读数）；
/// - `Some(age)`：`age <= health_window_secs` → Healthy，否则 Unhealthy。
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

/// DirectPending 的晋升探测（**握手证据优先**，见 [DIRECT_PROMOTE_FRESH_SECS]）：
/// - 最近握手年龄 ≤ `promote_fresh_secs` → Healthy（直连已验证，晋升 Direct）；
/// - 超过 `health_window_secs` → Unhealthy（有过握手但已死透，走超时回退）；
/// - 其余（尚未握手 / 读数缺失 / 年龄在两窗之间的 rekey 间隙）→ Unknown
///   （继续等，attempts 计满再回退）。
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

/// 状态机跃迁（每探测周期一次，纯函数）：
/// - Relay：只看决策。有可行直连路径 → `DirectPending{1}` + Promote；
///   无 → 保持 Relay。此状态的 probe 无意义（尚无直连 endpoint 可探测）。
/// - DirectPending：Healthy → Direct；非健康且已用满 `max_attempts` 个周期
///   → Relay + Demote（打洞失败回落中继，不报错）；否则周期数 +1 继续等。
/// - Direct：Unhealthy → Relay + Demote（直连断开自动回落）；Healthy /
///   Unknown（读数瞬时失败不误杀）→ 保持。
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

/// 单对端直连链路状态上报（§12.3：agent 心跳携带，hub 仅存内存，供控制台
/// 展示「P2P / 中继」）。以对端公钥为主键——服务端/控制台据此映射到设备。
fn default_connection_mode() -> String {
    "hub_relay".to_string()
}

/// SEL-004 单个直连候选端点的详情（console peer 详情展示）。
///
/// agent 从探测窗口（SEL-001）汇总，随 [DirectLinkStatus::candidates] 上报：
/// 端点 / RTT / 丢包 / 是否当前选中 / 选中理由。纯数据载体，无 IO。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DirectCandidateStatus {
    /// 候选端点（`ip:port`）。
    pub endpoint: String,
    /// 候选分类（`lan` / `public`，[crate::p2p::EndpointKind::as_str]）。
    pub kind: String,
    /// 窗口内 RTT 中位数（毫秒）；`None` = 无 RTT 样本（全丢/未测）。
    pub rtt_ms: Option<u64>,
    /// 窗口内丢包率（0.0..=1.0）。
    pub loss_rate: f64,
    /// 是否当前选中的直连 endpoint。
    pub selected: bool,
    /// 选中理由（`current` = 现路径；`backup` = 未选中；劣化/切换理由另记）。
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DirectLinkStatus {
    /// 对端 wg 公钥（设备唯一标识）。
    pub public_key: String,
    /// 对端 overlay 地址。
    pub virtual_ipv4: Ipv4Addr,
    /// `relay` / `direct_pending` / `direct`（[PeerLinkState::as_str]）。
    pub link_state: String,
    /// 最近一次探测读到的直连握手年龄（秒）；`None` = 尚无读数（pending 中 /
    /// 读数失败）。链路新鲜度信号，非精确 RTT——WireGuard 不暴露每 peer RTT，
    /// 握手年龄是设计采用的活度代理（[classify_probe] 同一口径）。
    pub last_handshake_age_secs: Option<u64>,
    /// 对端名称（agent 从计划候选中读到；旧 agent / 未取到为空）。UI/CLI
    /// 直接展示，服务端按设备身份索引时仍以公钥为准。
    #[serde(default)]
    pub peer_name: String,
    /// 连接模式（`p2p_direct` / `direct_pending` / `hub_relay`；与
    /// [link_state] 语义一致，但「中继」不再以缺省隐式表示）。
    #[serde(default = "default_connection_mode")]
    pub connection_mode: String,
    /// 直连 endpoint（`ip:port`；中继 / 未取到为空）。
    #[serde(default)]
    pub endpoint: String,
    /// 最近一次直连路径实测 RTT（毫秒）；`None` = 未测 / 探测失败。
    #[serde(default)]
    pub rtt_ms: Option<u64>,
    /// RTT 读数来源，如实标注（四态）：`probe_ok` = 直连路径实测成功（overlay
    /// 或回退 endpoint）；`handshake_fresh` = 不可测但最近握手新鲜（活性证据是
    /// 握手不是 ping——Windows 网格防火墙常不答 ICMP）；`probe_failed` = 两路
    /// 均无响应且握手也无新鲜证据；`unprobed` = 没轮到（探测在途 / 无候选）；
    /// `None` = 未测 / 旧 agent 无来源标注。展示层据此给 RTT 列标注来源，
    /// 「最近握手」仍是链路活性的主证据。
    #[serde(default)]
    pub rtt_source: Option<String>,
    /// 最近一次握手 Unix 时间戳（秒）；0 / `None` = 尚无握手。
    #[serde(default)]
    pub last_handshake_at: Option<u64>,
    /// 累计接收字节（直连 wg peer 读数；中继为 0）。
    #[serde(default)]
    pub rx_bytes: u64,
    /// 累计发送字节（直连 wg peer 读数；中继为 0）。
    #[serde(default)]
    pub tx_bytes: u64,
    /// SEL-004 全部候选端点详情（端点/RTT/丢包/当前选中与原因）。空 = 未上报
    /// 或探测未启用；console peer 详情据此渲染。
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

    // ----------------------------------------------------- 状态机 --------

    #[test]
    fn relay_promotes_when_a_path_exists() {
        let (next, action) = on_probe(
            PeerLinkState::Relay,
            DirectDecision::SameLan(lan("192.168.1.50", 51820)),
            ProbeResult::Unknown, // Relay 无直连可探测，probe 无意义
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
            DirectDecision::Relay, // pending 期不再依赖决策
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

        // 未用满周期：继续等，不 demote。
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
        // Demote 后回到 Relay：下一周期决策仍可行 → 再次 Promote（自动升回）。
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

        // ① 建立。
        let (s, a) = on_probe(state, path, ProbeResult::Unknown, MAX_PROMOTE_ATTEMPTS);
        assert!(matches!(a, PeerLinkAction::Promote(_)));
        state = s;

        // ② 握手成功 → Direct。
        let (s, a) = on_probe(state, path, ProbeResult::Healthy, MAX_PROMOTE_ATTEMPTS);
        assert_eq!(a, PeerLinkAction::Keep);
        state = s;
        assert_eq!(state, PeerLinkState::Direct);

        // ③ 断开 → 回落 hub。
        let (s, a) = on_probe(state, path, ProbeResult::Unhealthy, MAX_PROMOTE_ATTEMPTS);
        assert_eq!(a, PeerLinkAction::Demote);
        state = s;
        assert_eq!(state, PeerLinkState::Relay);

        // ④ 恢复 → 自动升回直连。
        let (_, a) = on_probe(state, path, ProbeResult::Unknown, MAX_PROMOTE_ATTEMPTS);
        assert!(matches!(a, PeerLinkAction::Promote(_)));
    }

    /// 晋升门槛（握手证据优先）：pending 期最近握手年龄 ≤ 晋升阈值即
    /// Healthy——**探测失败/不可用不拦晋升**（Windows 网格防火墙对 wg 接口
    /// ICMP 100% 丢包，imac 2026-11-07 取证）；rekey 间隙（180, 240] 继续等；
    /// 超过健康窗口才判失效。
    #[test]
    fn classify_promote_probe_uses_handshake_evidence_not_icmp() {
        // 握手新鲜 → 晋升，无论探测是否成功。
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
        // 刚过晋升阈值但在健康窗口内（rekey 间隙）：继续等，不晋升也不判死。
        assert_eq!(
            classify_promote_probe(
                Some(DIRECT_PROMOTE_FRESH_SECS + 1),
                DIRECT_PROMOTE_FRESH_SECS,
                DIRECT_HEALTH_WINDOW_SECS
            ),
            ProbeResult::Unknown
        );
        // 尚未握手 / 读数缺失：继续等（attempts 计满走超时回退）。
        assert_eq!(
            classify_promote_probe(None, DIRECT_PROMOTE_FRESH_SECS, DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Unknown
        );
        // 超过健康窗口：有过握手但已死透 → 失效（回退路径）。
        assert_eq!(
            classify_promote_probe(
                Some(DIRECT_HEALTH_WINDOW_SECS + 1),
                DIRECT_PROMOTE_FRESH_SECS,
                DIRECT_HEALTH_WINDOW_SECS
            ),
            ProbeResult::Unhealthy
        );
    }

    /// 修复回归（用户实测：直连每次都是「拨号中」）：pending 已握上手
    /// （握手新鲜）但 ICMP 探测永不成功 → 必须**当轮晋升 Direct**，
    /// 不再等满 attempts 超时回退。plan_updates 全路径的同口径回归在
    /// agent direct.rs 测试（`pending_with_fresh_handshake_promotes_via_plan_updates`）。
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

    /// 握手过期（超过健康窗口）→ pending 判失效回退（降级口径不放松）：
    /// Unhealthy 即回退，不等额外宽限。
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
        // pending 中无读数 = 还在等。
        assert_eq!(
            classify_probe(pending, None, DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Unknown
        );
        // Direct 无读数 = 已失效。
        assert_eq!(
            classify_probe(PeerLinkState::Direct, None, DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Unhealthy
        );
        // 窗口内 = 健康；窗口外 = 失效。窗口必须大于 WireGuard 重新握手
        // 节拍（活跃会话 ~120–180s 重新握手一次，keepalive 不刷新
        // latest-handshake）——健康空闲链路的握手年龄会合法涨到 ~180s。
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
