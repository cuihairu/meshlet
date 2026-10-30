//! P2P 节点直连（[ADR-015](../../docs/decisions/adr-015-p2p-direct-connect.md)）：
//! 类型、直连路径决策与对端链路状态机。
//!
//! 纯逻辑层，无 IO：候选 endpoint 分类（公网 / 局域网）、直连路径决策
//! （同 LAN 直连 / 公网打洞 / 保持 hub 中继）、对端直连 Peer 的 AllowedIPs
//! `/32` 拆分与冲突检查、30s 探测的升降级状态机。接口枚举、`wg` 命令与
//! 打洞发包属于 agent / meshlet-network 执行层，不在这里。
//!
//! 设计要点（与任务书一一对应）：
//! - hub 下发的候选 endpoint 是**建议**而非承诺：决策函数对不可达候选一律
//!   回落中继，绝不报错；
//! - 直连 Peer 的 AllowedIPs 只写对端 overlay `/32`——WireGuard 最长前缀
//!   匹配使 `/32` 天然优先于 hub peer 的整段路由，移除 `/32` 即自动回落
//!   hub，无需改动其他节点配置；
//! - 建立与回退是同一台 agent 本机的状态机（[PeerLinkState]），每探测周期
//!   跃迁一次，幂等可重放。

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::cidr::Ipv4Cidr;
use crate::entities::{Device, DeviceId};

// ---------------------------------------------------------------------------
// 候选 endpoint
// ---------------------------------------------------------------------------

/// 候选 endpoint 分类（任务书：公网 ip:port 与局域网 ip:port 两类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// RFC1918 内网地址（同网段直连用）。
    Lan,
    /// 公网地址（hub 观测到的 agent 源地址 + UDP 端口，打洞用）。
    Public,
}

impl EndpointKind {
    /// API 展示用小写蛇形标识（契约字段 `kind`）。
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointKind::Lan => "lan",
            EndpointKind::Public => "public",
        }
    }
}

/// 一个候选直连 endpoint（ip:port + 分类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct EndpointCandidate {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub kind: EndpointKind,
}

impl EndpointCandidate {
    pub fn lan(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip,
            port,
            kind: EndpointKind::Lan,
        }
    }

    pub fn public(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip,
            port,
            kind: EndpointKind::Public,
        }
    }

    /// 打洞 / `wg set peer endpoint` 用的 socket 地址。
    pub fn socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip, self.port)
    }
}

/// IP 是否为 RFC1918 私网地址（LAN 候选判定基准；链路本地 169.254/16
/// 不算——跨主机不可路由）。
pub fn is_private_ip(ip: Ipv4Addr) -> bool {
    match ip.octets() {
        [10, ..] => true,
        [172, b, ..] => (16..=31).contains(&b),
        [192, 168, ..] => true,
        _ => false,
    }
}

/// 对端候选是否落在本机任一局域网子网内（同网段判定）。
pub fn is_lan_reachable(my_lan_subnets: &[Ipv4Cidr], candidate: &EndpointCandidate) -> bool {
    candidate.kind == EndpointKind::Lan
        && my_lan_subnets.iter().any(|c| c.contains(candidate.ip))
}

/// 直连路径决策结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectDecision {
    /// 不可直连——保持 hub 中继（现状行为，不报错）。
    Relay,
    /// 同 LAN：直接用对端内网 endpoint（无 NAT，立即可握手）。
    SameLan(EndpointCandidate),
    /// 公网打洞：用对端公网 endpoint，双方各自发包开启 NAT 映射后握手。
    HolePunch(EndpointCandidate),
}

/// 决策直连路径（无 IO 纯函数）：
/// 1. 对端 LAN 候选落在本机子网内 → [DirectDecision::SameLan]（多个候选取
///    地址最小者，确定性）；
/// 2. 否则对端有公网候选 → [DirectDecision::HolePunch]（同样取最小者）；
/// 3. 都没有 → [DirectDecision::Relay]。
pub fn decide_direct_path(
    my_lan_subnets: &[Ipv4Cidr],
    peer_candidates: &[EndpointCandidate],
) -> DirectDecision {
    let mut lan: Vec<_> = peer_candidates
        .iter()
        .copied()
        .filter(|c| is_lan_reachable(my_lan_subnets, c))
        .collect();
    lan.sort_by_key(|c| (c.ip, c.port));
    if let Some(c) = lan.first() {
        return DirectDecision::SameLan(*c);
    }
    let mut public: Vec<_> = peer_candidates
        .iter()
        .copied()
        .filter(|c| c.kind == EndpointKind::Public)
        .collect();
    public.sort_by_key(|c| (c.ip, c.port));
    if let Some(c) = public.first() {
        return DirectDecision::HolePunch(*c);
    }
    DirectDecision::Relay
}

// ---------------------------------------------------------------------------
// 上报与分发（hub 侧聚合的纯逻辑）
// ---------------------------------------------------------------------------

/// agent 心跳携带的本地直连入口上报：本机 wg 的 UDP 监听端口 + RFC1918
/// 局域网地址列表。公网地址由 hub 观测 HTTP 源地址得出，agent 不自报
/// （NAT 后自报不可信）。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DirectEndpointReport {
    /// 本机 wg 接口的 UDP 监听端口（直连对端向它发包）。
    pub listen_port: u16,
    /// 本机各接口的 RFC1918 地址（不含端口；端口统一取 `listen_port`）。
    pub lan_addrs: Vec<Ipv4Addr>,
}

/// hub 记录的单设备直连状态：最近一次观测到的 agent 源地址 + 最近一次
/// 上报。二者任一缺失则该设备暂无可用候选。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceDirectState {
    /// 心跳 HTTP 请求的源地址（hub 观测；`None` = 尚未见过心跳）。
    pub observed_ip: Option<Ipv4Addr>,
    /// 最近一次 [DirectEndpointReport]（`None` = 该 agent 版本未上报）。
    pub report: Option<DirectEndpointReport>,
}

/// 把「hub 观测源地址 + agent 上报」合并成候选 endpoint 列表（纯函数）：
/// - LAN 候选 = 上报地址中 RFC1918 的每一个（端口统一 `listen_port`），
///   丢弃未指定 / 回环 / 非私网地址；
/// - 公网候选 = 观测源地址**非私网**时才构造（hub 与 agent 同内网时源
///   地址就是 LAN 地址，再标成 public 只会误导打洞）；
/// - 结果按 (ip, port) 确定性排序去重。
pub fn endpoint_candidates(
    observed_ip: Option<Ipv4Addr>,
    report: &DirectEndpointReport,
) -> Vec<EndpointCandidate> {
    let mut lan: Vec<_> = report
        .lan_addrs
        .iter()
        .copied()
        .filter(|ip| is_private_ip(*ip) && !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| EndpointCandidate::lan(ip, report.listen_port))
        .collect();
    lan.sort_by_key(|c| (c.ip, c.port));
    lan.dedup();
    let mut out = lan;
    if let Some(ip) = observed_ip {
        if !is_private_ip(ip) && !ip.is_loopback() && !ip.is_unspecified() {
            out.push(EndpointCandidate::public(ip, report.listen_port));
        }
    }
    out
}

/// hub 下发给 agent 的单节点直连信息（`GET .../peers/endpoints` 列表项）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerEndpoints {
    pub device_id: DeviceId,
    /// 对端 wg 公钥（agent 据此 `wg set peer`）。
    pub public_key: String,
    /// 对端 overlay 地址（AllowedIPs `/32` 的来源）。
    pub virtual_ipv4: Ipv4Addr,
    /// 候选 endpoint 列表（公网 + 局域网）。
    pub endpoints: Vec<EndpointCandidate>,
}

/// hub 侧聚合（纯函数）：为 `self_id` 视角汇总同网络内其他 Active 设备的
/// 直连候选。调用方传入已按网络过滤的设备列表；本函数只做：
/// - 排除非自身、非 Active、无上报、虚拟 IP 越出路由范围（scope）的设备；
/// - 无候选（未上报 / 观测缺失）的设备不进列表（不可能直连，避免死载荷）；
/// - 输出按 device_id 确定性排序。
///
/// `scope_cidr` = 该设备可路由的网段（单段网络为整个 overlay；分段网络为
/// 所属段前缀，与 peer AllowedIPs 推导同一口径）。
pub fn peer_endpoints_for(
    scope_cidr: Ipv4Cidr,
    self_id: &DeviceId,
    devices: &[Device],
    direct: &BTreeMap<DeviceId, DeviceDirectState>,
) -> Vec<PeerEndpoints> {
    let mut out = Vec::new();
    for device in devices {
        if &device.id == self_id || !device.is_active() {
            continue;
        }
        let Some(state) = direct.get(&device.id) else {
            continue;
        };
        let Some(report) = state.report.as_ref() else {
            continue;
        };
        if !scope_cidr.contains(device.virtual_ipv4) {
            continue;
        }
        let endpoints = endpoint_candidates(state.observed_ip, report);
        if endpoints.is_empty() {
            continue;
        }
        out.push(PeerEndpoints {
            device_id: device.id.clone(),
            public_key: device.public_key.clone(),
            virtual_ipv4: device.virtual_ipv4,
            endpoints,
        });
    }
    out.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    out
}

// ---------------------------------------------------------------------------
// 直连 Peer 冲突检查与 AllowedIPs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DirectPeerError {
    #[error("peer virtual IP {peer} outside routable scope {scope}")]
    PeerOutsideScope { peer: Ipv4Addr, scope: Ipv4Cidr },
    #[error("peer virtual IP {0} is this device's own address")]
    IsSelf(Ipv4Addr),
}

/// 直连 Peer 的 AllowedIPs：**只**写对端 overlay `/32`（任务书）。返回前
/// 复核两条冲突边界：对端虚拟 IP 必须在路由范围内、不得是自己。
pub fn direct_peer_allowed_ips(
    scope_cidr: Ipv4Cidr,
    self_virtual_ip: Ipv4Addr,
    peer_virtual_ip: Ipv4Addr,
) -> Result<Vec<Ipv4Cidr>, DirectPeerError> {
    if peer_virtual_ip == self_virtual_ip {
        return Err(DirectPeerError::IsSelf(peer_virtual_ip));
    }
    if !scope_cidr.contains(peer_virtual_ip) {
        return Err(DirectPeerError::PeerOutsideScope {
            peer: peer_virtual_ip,
            scope: scope_cidr,
        });
    }
    Ok(vec![Ipv4Cidr::new(peer_virtual_ip, 32).expect("valid /32")])
}

// ---------------------------------------------------------------------------
// 对端链路状态机（30s 探测升降级）
// ---------------------------------------------------------------------------

/// 探测周期（秒）：任务书「每 30s 探测直连路径」。
pub const DIRECT_PROBE_INTERVAL_SECS: u64 = 30;
/// 直连建立容忍的最大 pending 探测周期数（任务书「3 次握手周期」）。
pub const MAX_PROMOTE_ATTEMPTS: u8 = 3;
/// 直连健康窗口（秒）：直接 peer 最近握手年龄超过此值视为不健康
/// （keepalive 15s + 一个周期裕量）。
pub const DIRECT_HEALTH_WINDOW_SECS: u64 = 35;
/// 直连 peer 的 persistent-keepalive（秒）：让 wg 主动发包——既是 NAT
/// 打洞的「洞」，也是健康探测的心跳来源。
pub const DIRECT_PERSISTENT_KEEPALIVE_SECS: u32 = 15;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{DeviceStatus, NetworkId, Platform, SegmentId};

    const OVERLAY: &str = "10.240.0.0/16";
    const HOME: &str = "192.168.1.0/24";

    fn lan(ip: &str, port: u16) -> EndpointCandidate {
        EndpointCandidate::lan(ip.parse().unwrap(), port)
    }

    fn public(ip: &str, port: u16) -> EndpointCandidate {
        EndpointCandidate::public(ip.parse().unwrap(), port)
    }

    fn cidr(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
    }

    fn device(id: &str, ip: &str, status: DeviceStatus) -> Device {
        Device {
            id: DeviceId(id.into()),
            network_id: NetworkId("net-1".into()),
            name: id.into(),
            virtual_ipv4: ip.parse().unwrap(),
            public_key: format!("pub-{id}"),
            platform: Platform::Linux,
            status,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: "2026-10-31T00:00:00Z".into(),
            approved_at: None,
            revoked_at: None,
            segment_id: SegmentId("seg-net-1".into()),
        }
    }

    fn report(port: u16, addrs: &[&str]) -> DirectEndpointReport {
        DirectEndpointReport {
            listen_port: port,
            lan_addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    // ------------------------------------------------------- 路径决策 ----

    #[test]
    fn same_lan_wins_over_public() {
        let my = [cidr(HOME)];
        let cands = vec![public("203.0.113.5", 51820), lan("192.168.1.50", 51821)];
        assert_eq!(
            decide_direct_path(&my, &cands),
            DirectDecision::SameLan(lan("192.168.1.50", 51821))
        );
    }

    #[test]
    fn public_candidate_punches_when_lan_is_outside_my_subnets() {
        let my = [cidr(HOME)];
        let cands = vec![
            lan("10.0.0.9", 51820), // 对端内网但与我不同段
            public("203.0.113.5", 51820),
        ];
        assert_eq!(
            decide_direct_path(&my, &cands),
            DirectDecision::HolePunch(public("203.0.113.5", 51820))
        );
    }

    #[test]
    fn no_candidates_means_relay() {
        assert_eq!(decide_direct_path(&[cidr(HOME)], &[]), DirectDecision::Relay);
    }

    #[test]
    fn peer_lan_without_reach_and_without_public_stays_relay() {
        let my = [cidr(HOME)];
        let cands = vec![lan("10.0.0.9", 51820)];
        assert_eq!(decide_direct_path(&my, &cands), DirectDecision::Relay);
    }

    #[test]
    fn empty_lan_subnets_never_pick_peer_lan() {
        let cands = vec![lan("192.168.1.50", 51820)];
        assert_eq!(decide_direct_path(&[], &cands), DirectDecision::Relay);
    }

    #[test]
    fn multiple_lan_candidates_pick_lowest_ip_deterministically() {
        let my = [cidr("192.168.0.0/16")];
        let cands = vec![lan("192.168.1.9", 51820), lan("192.168.1.2", 51820)];
        assert_eq!(
            decide_direct_path(&my, &cands),
            DirectDecision::SameLan(lan("192.168.1.2", 51820))
        );
    }

    // ------------------------------------------------------- 私网判定 ----

    #[test]
    fn rfc1918_classification() {
        let p = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert!(is_private_ip(p("10.0.0.1")));
        assert!(is_private_ip(p("172.16.0.1")));
        assert!(is_private_ip(p("172.31.255.255")));
        assert!(is_private_ip(p("192.168.1.1")));
        assert!(!is_private_ip(p("172.32.0.1")));
        assert!(!is_private_ip(p("8.8.8.8")));
        assert!(!is_private_ip(p("169.254.1.1")));
        assert!(!is_private_ip(p("127.0.0.1")));
    }

    // ------------------------------------------------- 候选合并（hub）----

    #[test]
    fn candidates_merge_lan_report_and_public_observation() {
        let cands = endpoint_candidates(
            Some("203.0.113.7".parse().unwrap()),
            &report(51821, &["192.168.1.10", "10.8.0.5"]),
        );
        assert_eq!(
            cands,
            vec![
                lan("10.8.0.5", 51821),
                lan("192.168.1.10", 51821),
                public("203.0.113.7", 51821),
            ]
        );
    }

    #[test]
    fn same_lan_observation_yields_no_public_candidate() {
        // hub 与 agent 同内网：观测源地址是私网地址，不能标成 public。
        let cands = endpoint_candidates(
            Some("192.168.1.10".parse().unwrap()),
            &report(51821, &["192.168.1.10"]),
        );
        assert_eq!(cands, vec![lan("192.168.1.10", 51821)]);
    }

    #[test]
    fn candidates_drop_loopback_unspecified_and_non_private_lan_addrs() {
        let cands = endpoint_candidates(
            None,
            &report(51820, &["127.0.0.1", "0.0.0.0", "8.8.8.8", "192.168.1.10"]),
        );
        assert_eq!(cands, vec![lan("192.168.1.10", 51820)]);
    }

    #[test]
    fn candidates_dedup_and_sort_deterministically() {
        let cands = endpoint_candidates(
            None,
            &report(51820, &["192.168.1.20", "192.168.1.10", "192.168.1.20"]),
        );
        assert_eq!(
            cands,
            vec![lan("192.168.1.10", 51820), lan("192.168.1.20", 51820)]
        );
    }

    // --------------------------------------------- 分发聚合（hub）--------

    #[test]
    fn peer_endpoints_lists_active_peers_with_reports_sorted_by_id() {
        let devices = vec![
            device("dev-a", "10.240.0.2", DeviceStatus::Active),
            device("dev-b", "10.240.0.3", DeviceStatus::Active),
            device("dev-c", "10.240.0.4", DeviceStatus::Pending),
        ];
        let mut direct = BTreeMap::new();
        direct.insert(
            DeviceId("dev-a".into()),
            DeviceDirectState {
                observed_ip: Some("203.0.113.1".parse().unwrap()),
                report: Some(report(51820, &["192.168.1.2"])),
            },
        );
        direct.insert(
            DeviceId("dev-c".into()),
            DeviceDirectState {
                observed_ip: Some("203.0.113.3".parse().unwrap()),
                report: Some(report(51820, &[])),
            },
        );

        let list = peer_endpoints_for(cidr(OVERLAY), &DeviceId("dev-b".into()), &devices, &direct);

        // dev-a 在列（Active + 有上报）；dev-c 是 Pending 被排除；dev-b 是自己。
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].device_id, DeviceId("dev-a".into()));
        assert_eq!(list[0].public_key, "pub-dev-a");
        assert_eq!(
            list[0].virtual_ipv4,
            "10.240.0.2".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(list[0].endpoints.len(), 2);
    }

    #[test]
    fn peer_endpoints_excludes_self_out_of_scope_and_reportless() {
        let devices = vec![
            device("dev-a", "10.240.0.2", DeviceStatus::Active),
            device("dev-out", "10.250.0.9", DeviceStatus::Active), // 越出 scope
            device("dev-x", "10.240.0.5", DeviceStatus::Revoked),
        ];
        let mut direct = BTreeMap::new();
        direct.insert(
            DeviceId("dev-a".into()),
            DeviceDirectState {
                observed_ip: None,
                report: Some(report(51820, &["192.168.1.2"])),
            },
        );
        direct.insert(
            DeviceId("dev-out".into()),
            DeviceDirectState {
                observed_ip: None,
                report: Some(report(51820, &["192.168.1.9"])),
            },
        );

        // 自己（dev-a）被排除；越界与撤销的被排除。
        let list = peer_endpoints_for(cidr(OVERLAY), &DeviceId("dev-a".into()), &devices, &direct);
        assert!(list.is_empty());
    }

    #[test]
    fn peer_endpoints_skips_devices_without_usable_candidates() {
        let devices = vec![device("dev-a", "10.240.0.2", DeviceStatus::Active)];
        let mut direct = BTreeMap::new();
        // 观测缺失：LAN 候选仍在 → 在列。
        direct.insert(
            DeviceId("dev-a".into()),
            DeviceDirectState {
                observed_ip: None,
                report: Some(report(51820, &["192.168.1.2"])),
            },
        );
        let list = peer_endpoints_for(cidr(OVERLAY), &DeviceId("dev-b".into()), &devices, &direct);
        assert_eq!(list.len(), 1);

        // 完全无上报 → 不进列表。
        let mut direct = BTreeMap::new();
        direct.insert(
            DeviceId("dev-a".into()),
            DeviceDirectState::default(),
        );
        let list = peer_endpoints_for(cidr(OVERLAY), &DeviceId("dev-b".into()), &devices, &direct);
        assert!(list.is_empty());
    }

    // ------------------------------------------------- AllowedIPs /32 ----

    #[test]
    fn direct_peer_allowed_ips_is_only_the_peer_32() {
        let ips = direct_peer_allowed_ips(
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            "10.240.0.3".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(ips, vec!["10.240.0.3/32".parse().unwrap()]);
    }

    #[test]
    fn direct_peer_rejects_self() {
        let err = direct_peer_allowed_ips(
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            "10.240.0.2".parse().unwrap(),
        )
        .unwrap_err();
        assert_eq!(err, DirectPeerError::IsSelf("10.240.0.2".parse().unwrap()));
    }

    #[test]
    fn direct_peer_rejects_outside_scope() {
        let err = direct_peer_allowed_ips(
            cidr("10.240.1.0/24"),
            "10.240.1.2".parse().unwrap(),
            "10.240.9.9".parse().unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, DirectPeerError::PeerOutsideScope { .. }));
    }

    // ----------------------------------------------------- 状态机 --------

    #[test]
    fn relay_promotes_when_a_path_exists() {
        let (next, action) = on_probe(
            PeerLinkState::Relay,
            DirectDecision::SameLan(lan("192.168.1.50", 51820)),
            ProbeResult::Unknown, // Relay 无直连可探测，probe 无意义
            MAX_PROMOTE_ATTEMPTS,
        );
        assert_eq!(
            next,
            PeerLinkState::DirectPending { attempts: 1 }
        );
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
        // 窗口内 = 健康；窗口外 = 失效。
        assert_eq!(
            classify_probe(PeerLinkState::Direct, Some(20), DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Healthy
        );
        assert_eq!(
            classify_probe(PeerLinkState::Direct, Some(90), DIRECT_HEALTH_WINDOW_SECS),
            ProbeResult::Unhealthy
        );
    }

    #[test]
    fn peer_endpoints_round_trips_as_json() {
        let list = vec![PeerEndpoints {
            device_id: DeviceId("dev-a".into()),
            public_key: "pub-a".into(),
            virtual_ipv4: "10.240.0.2".parse().unwrap(),
            endpoints: vec![
                lan("192.168.1.2", 51821),
                public("203.0.113.1", 51821),
            ],
        }];
        let json = serde_json::to_string(&list).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<PeerEndpoints>>(&json).unwrap(),
            list
        );
        assert!(json.contains(r#""kind":"lan""#));
        assert!(json.contains(r#""kind":"public""#));
    }
}
