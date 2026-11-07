//! P2P 直连管理器（§12）：对每个可直连对端驱动域层状态机（[on_probe]），
//! 把跃迁动作翻译成 `wg set` 内核调用（经 `meshlet_network` 后端）。
//!
//! 纯逻辑（[plan_updates]、[DirectManager] 的状态持留）与 IO（fetch 端点、
//! `wg set`）分离：前者可无特权单测，后者在 [crate::agent::Agent] 里执行。
//!
//! 每个周期：
//! - 拉取服务端下发的可直连候选（建议而非承诺）；
//! - 对每个候选对端：`decide_direct_path`（同 LAN / 公网打洞 / 中继）→
//!   `classify_probe`（握手年龄）→ `on_probe`（状态跃迁）→ 动作；
//! - 不再在候选集里的对端（撤销/下线）：回退 hub 并移除；
//! - 动作是**本机**的 wg 配置增删（allowed-ips 只写对端 `/32`），不触碰
//!   其他节点、不触碰服务端计划（§12）。
//!
//! 重启恢复：直连对端持久化在本机 ledger（`{state_dir}/direct.json`，只存
//! keep set）——重启后按 ledger 恢复为「已建立」（Direct），下一周期由握手
//! 健康度收敛（过期即回退，健康即保持）。**不从内核猜**：内核里任何非 hub
//! peer 若被当作自有直连，外来 peer 的漂移检测就被废掉了（真机测试曾抓到
//! 这个回归）。

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;

use meshlet_domain::{
    classify_probe, decide_direct_path, direct_peer_allowed_ips, on_probe, DirectDecision,
    DirectLinkStatus, Ipv4Cidr, PeerEndpoints, PeerLinkAction, PeerLinkState,
    DIRECT_HEALTH_WINDOW_SECS, DIRECT_PERSISTENT_KEEPALIVE_SECS, MAX_PROMOTE_ATTEMPTS,
};

/// 单个对端的直连管理状态（域层状态机状态 + 对端 overlay 地址）。
#[derive(Debug, Clone, PartialEq)]
pub struct DirectPeer {
    /// 对端 overlay 地址（AllowedIPs `/32` 来源；域层已保证在路由范围内）。
    pub virtual_ipv4: Ipv4Addr,
    /// 当前直连链路状态。
    pub state: PeerLinkState,
    /// 最近一次探测读到的直连握手年龄（秒）。探测时快照（不是心跳时再读
    /// 内核——状态机的决策输入与上报信号同源）；`None` = pending 中或读数失败。
    pub last_handshake_age_secs: Option<u64>,
    /// 对端名称（R-DIAG-2 展示；候选里读到）。
    pub peer_name: String,
    /// 当前直连 endpoint（`ip:port`）；未建立 / 无候选为空。
    pub endpoint: String,
    /// 最近一次直连路径实测 RTT（毫秒）。
    pub rtt_ms: Option<u64>,
    /// RTT 读数来源（`overlay` / `endpoint` / `unreachable`；`None` = 未测）。
    pub rtt_source: Option<String>,
    /// 最近一次握手 Unix 时间戳（秒）。
    pub last_handshake_at: Option<u64>,
    /// 累计接收字节（wg 读数）。
    pub rx_bytes: u64,
    /// 累计发送字节（wg 读数）。
    pub tx_bytes: u64,
    /// SEL-004 候选端点详情（端点/RTT/丢包/当前选中与原因）；由 agent 探测
    /// 周期填充（[DirectManager::record_candidates]）。
    pub candidates: Vec<meshlet_domain::DirectCandidateStatus>,
}

/// 直连管理器：对端公钥 → 管理状态。跨周期持留（状态机要记住 pending 尝试次数）。
#[derive(Debug, Default)]
pub struct DirectManager {
    peers: BTreeMap<String, DirectPeer>,
}

/// 一个周期的直连动作（执行层据此下发 `wg set`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectUpdate {
    /// 建立直连：`allowed-ips` 只写对端 `/32` + 直连 endpoint + keepalive。
    Promote {
        public_key: String,
        allowed_ips: Vec<Ipv4Cidr>,
        endpoint: SocketAddrV4,
    },
    /// 回退 hub：移除该对端直连 peer（hub 整段路由自动接管）。
    Demote { public_key: String },
}

impl DirectManager {
    /// 重建一个空管理器（agent 启动时）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 计划重放时应保留的直连 peer 公钥集（非 Relay 状态 = 想让它在场）。
    pub fn keep_keys(&self) -> BTreeSet<String> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.state != PeerLinkState::Relay)
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// 本机是否还能直连某个对端（供 tray/诊断；当前仅按状态非 Relay）。
    pub fn is_direct(&self, public_key: &str) -> bool {
        self.peers
            .get(public_key)
            .is_some_and(|peer| peer.state == PeerLinkState::Direct)
    }

    /// 单个对端的当前管理状态（`peer dial` 结果判定用）。对端不在管返回
    /// `None`——不是候选（本周期候选集外），拨号结果按失败呈现。
    pub fn status_of(&self, public_key: &str) -> Option<&DirectPeer> {
        self.peers.get(public_key)
    }

    /// 一个周期：拉候选 → 域层状态机 → 就地更新 → 返回待下发动作。
    /// 见 [plan_updates]；执行层拿到动作后逐个 `wg set`（失败只记日志）。
    #[allow(clippy::too_many_arguments)]
    pub fn apply_plan(
        &mut self,
        wanted: &[PeerEndpoints],
        my_lan_subnets: &[Ipv4Cidr],
        scope: Ipv4Cidr,
        self_vip: Ipv4Addr,
        handshake_ages: &BTreeMap<String, u64>,
        degraded: &BTreeMap<String, bool>,
        hold_relay: &BTreeSet<String>,
    ) -> Vec<DirectUpdate> {
        plan_updates(
            wanted,
            my_lan_subnets,
            scope,
            self_vip,
            &mut self.peers,
            handshake_ages,
            degraded,
            hold_relay,
        )
    }

    /// 直连开关关闭：清空管理状态并回退所有已建立的直连（交还 hub）。
    /// 返回待下发动作（全部 [DirectUpdate::Demote]）。
    pub fn demote_all(&mut self) -> Vec<DirectUpdate> {
        let keys: Vec<String> = self.peers.keys().cloned().collect();
        self.peers.clear();
        keys.into_iter()
            .map(|public_key| DirectUpdate::Demote { public_key })
            .collect()
    }

    /// 持久化 keep set（`{state_dir}/direct.json`）：重启后据此恢复「已建立」。
    /// 只写非 Relay 对端；写失败只报错由调用方记日志（ledger 是加速器而非
    /// 真相源——丢了顶多多一个探测周期重建直连）。
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        #[derive(serde::Serialize)]
        struct Entry<'a> {
            public_key: &'a str,
            virtual_ipv4: Ipv4Addr,
        }
        let peers: Vec<Entry> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.state != PeerLinkState::Relay)
            .map(|(key, peer)| Entry {
                public_key: key,
                virtual_ipv4: peer.virtual_ipv4,
            })
            .collect();
        std::fs::write(path, serde_json::to_vec(&peers).unwrap_or_default())
    }

    /// 从 ledger 恢复（agent 启动时）：所有登记对端按「已建立」（Direct）
    /// 持有，下一周期由握手健康度收敛。文件缺失/损坏 → 空管理器（内核里
    /// 遗留的直连对端会被对账当漂移清掉，再由探测周期重建——自愈，不猜）。
    pub fn load(path: &Path) -> Self {
        #[derive(serde::Deserialize)]
        struct Entry {
            public_key: String,
            #[serde(default)]
            virtual_ipv4: Option<Ipv4Addr>,
        }
        let mut manager = Self::new();
        let Ok(raw) = std::fs::read(path) else {
            return manager;
        };
        let Ok(entries) = serde_json::from_slice::<Vec<Entry>>(&raw) else {
            return manager;
        };
        for entry in entries {
            manager.peers.insert(
                entry.public_key,
                DirectPeer {
                    virtual_ipv4: entry.virtual_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    state: PeerLinkState::Direct,
                    last_handshake_age_secs: None,
                    peer_name: String::new(),
                    endpoint: String::new(),
                    rtt_ms: None,
                    rtt_source: None,
                    last_handshake_at: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    candidates: vec![],
                },
            );
        }
        manager
    }

    /// §12.3 链路状态上报：每个在管对端一条（按公钥排序，确定性）。供心跳
    /// 携带给 hub（控制台展示 P2P/中继）。Relay 状态的对端不在此列——它们
    /// 没有直连链路，UI 按「中继」默认呈现。
    pub fn link_statuses(&self) -> Vec<DirectLinkStatus> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.state != PeerLinkState::Relay)
            .map(|(key, peer)| DirectLinkStatus {
                public_key: key.clone(),
                virtual_ipv4: peer.virtual_ipv4,
                link_state: peer.state.as_str().to_string(),
                last_handshake_age_secs: peer.last_handshake_age_secs,
                peer_name: peer.peer_name.clone(),
                connection_mode: match peer.state {
                    PeerLinkState::Direct => "p2p_direct".into(),
                    PeerLinkState::DirectPending { .. } => "direct_pending".into(),
                    PeerLinkState::Relay => "hub_relay".into(),
                },
                endpoint: peer.endpoint.clone(),
                rtt_ms: peer.rtt_ms,
                rtt_source: peer.rtt_source.clone(),
                last_handshake_at: peer.last_handshake_at,
                rx_bytes: peer.rx_bytes,
                tx_bytes: peer.tx_bytes,
                candidates: peer.candidates.clone(),
            })
            .collect()
    }

    /// SEL-004：填充某对端的候选端点详情（探测周期由执行侧调用）。对端不在管
    /// 或处于 Relay（无直连链路可展示）则 no-op。
    pub fn record_candidates(
        &mut self,
        public_key: &str,
        candidates: Vec<meshlet_domain::DirectCandidateStatus>,
    ) {
        if let Some(peer) = self.peers.get_mut(public_key) {
            if peer.state != PeerLinkState::Relay {
                peer.candidates = candidates;
            }
        }
    }

    /// 当前处于直连相关状态（非 Relay）的对端清单（公钥 + overlay 地址），
    /// 供探测周期做内核读数与直连路径延时实测（R-DIAG-2）。
    pub fn direct_candidates(&self) -> Vec<(String, Ipv4Addr)> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.state != PeerLinkState::Relay)
            .map(|(key, peer)| (key.clone(), peer.virtual_ipv4))
            .collect()
    }

    /// 记录已建立的直连 endpoint（Promote 成功后由执行侧调用；§12.3 状态
    /// 上报与控制台/CLI 展示）。对端不在管或处于 Relay（无直连链路）则 no-op。
    pub fn record_endpoint(&mut self, public_key: &str, endpoint: String) {
        if let Some(peer) = self.peers.get_mut(public_key) {
            if peer.state != PeerLinkState::Relay {
                peer.endpoint = endpoint;
            }
        }
    }

    /// 清空直连 endpoint 与 RTT（Demote 回退 hub 后由执行侧调用）。
    pub fn clear_endpoint(&mut self, public_key: &str) {
        if let Some(peer) = self.peers.get_mut(public_key) {
            peer.endpoint.clear();
            peer.rtt_ms = None;
            peer.rtt_source = None;
        }
    }

    /// 刷新直连状态读数（探测周期由执行侧调用）：直连路径实测 RTT（毫秒）+
    /// 来源（`overlay` / `endpoint` / `unreachable`，见
    /// [`crate::direct_rtt::RttProbe`]）、最近握手 Unix 秒、累计收发字节
    /// （wg 读数）。对端不在管或处于 Relay（无直连链路可测）则 no-op。
    pub fn record_peer_status(
        &mut self,
        public_key: &str,
        rtt_ms: Option<u64>,
        rtt_source: Option<&str>,
        last_handshake_at: Option<u64>,
        rx_bytes: u64,
        tx_bytes: u64,
    ) {
        if let Some(peer) = self.peers.get_mut(public_key) {
            if peer.state != PeerLinkState::Relay {
                peer.rtt_ms = rtt_ms;
                peer.rtt_source = rtt_source.map(str::to_string);
                peer.last_handshake_at = last_handshake_at;
                peer.rx_bytes = rx_bytes;
                peer.tx_bytes = tx_bytes;
            }
        }
    }
}

/// 一个周期内的状态跃迁计划（纯函数，无 IO；返回按公钥排序，确定性）。
///
/// - `wanted`：服务端下发的可直连候选（已按本设备路由范围过滤）；
/// - `my_lan_subnets`：本机局域网子网（同网段判定）；
/// - `scope` / `self_vip`：本设备可路由网段与自身 overlay 地址（AllowedIPs
///   `/32` 冲突检查用）；
/// - `current`：管理器当前状态（**就地更新**，跨周期持留）；
/// - `handshake_ages`：各对端最近握手距今秒（内核读数）。
///
/// 行为：
/// - 候选集之外的对端（撤销/下线/换段）→ 回退并移除；
/// - 候选集之内：`decide_direct_path` 无可行路径 → 保持中继（不报错）；
///   有路径 → `on_probe` 跃迁（Relay→Promote、Pending 超时→Demote、
///   Direct 断开→Demote、恢复→再 Promote）。
#[allow(clippy::too_many_arguments)]
pub fn plan_updates(
    wanted: &[PeerEndpoints],
    my_lan_subnets: &[Ipv4Cidr],
    scope: Ipv4Cidr,
    self_vip: Ipv4Addr,
    current: &mut BTreeMap<String, DirectPeer>,
    handshake_ages: &BTreeMap<String, u64>,
    degraded: &BTreeMap<String, bool>,
    hold_relay: &BTreeSet<String>,
) -> Vec<DirectUpdate> {
    let mut updates = Vec::new();

    // 候选集之外：回退并移除（先收集公钥，避免借用冲突）。
    let wanted_keys: BTreeMap<&str, ()> = wanted
        .iter()
        .map(|peer| (peer.public_key.as_str(), ()))
        .collect();
    let stale: Vec<String> = current
        .keys()
        .filter(|key| !wanted_keys.contains_key(key.as_str()))
        .cloned()
        .collect();
    for key in stale {
        current.remove(&key);
        updates.push(DirectUpdate::Demote { public_key: key });
    }

    for peer in wanted {
        let key = peer.public_key.clone();
        let decision = decide_direct_path(my_lan_subnets, &peer.endpoints);
        let state = current
            .get(&key)
            .map(|entry| entry.state)
            .unwrap_or(PeerLinkState::Relay);
        // SEL-003 恢复门：回中继后未连续健康 N 轮 → 保持中继（不立即切回，
        // 防抖）。健康已稳定（ready）后才允许状态机重新 Promote。
        if hold_relay.contains(&key) && matches!(state, PeerLinkState::Relay) {
            current.insert(
                key.clone(),
                DirectPeer {
                    virtual_ipv4: peer.virtual_ipv4,
                    state: PeerLinkState::Relay,
                    last_handshake_age_secs: None,
                    peer_name: peer.name.clone(),
                    endpoint: String::new(),
                    rtt_ms: None,
                    rtt_source: None,
                    last_handshake_at: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    candidates: vec![],
                },
            );
            continue;
        }
        // SEL-003：直连劣化（丢包尖峰/超时）→ 立即回中继，不等握手过期。
        if degraded.get(&key).copied().unwrap_or(false)
            && matches!(
                state,
                PeerLinkState::Direct | PeerLinkState::DirectPending { .. }
            )
        {
            current.insert(
                key.clone(),
                DirectPeer {
                    virtual_ipv4: peer.virtual_ipv4,
                    state: PeerLinkState::Relay,
                    last_handshake_age_secs: None,
                    peer_name: peer.name.clone(),
                    endpoint: String::new(),
                    rtt_ms: None,
                    rtt_source: None,
                    last_handshake_at: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    candidates: vec![],
                },
            );
            updates.push(DirectUpdate::Demote { public_key: key });
            continue;
        }
        let probe = classify_probe(
            state,
            handshake_ages.get(&key).copied(),
            DIRECT_HEALTH_WINDOW_SECS,
        );
        let (next_state, action) = on_probe(state, decision, probe, MAX_PROMOTE_ATTEMPTS);
        let handshake_age = handshake_ages.get(&key).copied();
        current.insert(
            key.clone(),
            DirectPeer {
                virtual_ipv4: peer.virtual_ipv4,
                state: next_state,
                last_handshake_age_secs: handshake_age,
                peer_name: peer.name.clone(),
                // endpoint 在 Promote 动作里给出；Relay/Demote 保留上次值，
                // 由动作执行侧在 Demote 时清空（见 agent.apply_direct_update）。
                endpoint: current
                    .get(&key)
                    .map(|e| e.endpoint.clone())
                    .unwrap_or_default(),
                rtt_ms: None,
                rtt_source: None,
                last_handshake_at: None,
                rx_bytes: 0,
                tx_bytes: 0,
                candidates: vec![],
            },
        );
        match action {
            PeerLinkAction::Keep => {}
            PeerLinkAction::Demote => updates.push(DirectUpdate::Demote { public_key: key }),
            PeerLinkAction::Promote(path) => {
                // 冲突边界（自己/越出路由范围）由域层复核；异常即放弃直连
                // （保持中继，绝不发越界 / 自指 peer）。
                let Ok(allowed_ips) = direct_peer_allowed_ips(scope, self_vip, peer.virtual_ipv4)
                else {
                    continue;
                };
                updates.push(DirectUpdate::Promote {
                    public_key: key,
                    allowed_ips,
                    endpoint: path_endpoint(path),
                });
            }
        }
    }
    updates
}

/// 决策路径的 endpoint（SameLan / HolePunch 都给出一个直连地址）。
fn path_endpoint(path: DirectDecision) -> SocketAddrV4 {
    match path {
        DirectDecision::SameLan(candidate) | DirectDecision::HolePunch(candidate) => {
            candidate.socket()
        }
        DirectDecision::Relay => {
            // `on_probe` 只在非 Relay 决策下发 Promote，这里不会走到。
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
        }
    }
}

/// keepalive 周期（域层常量，执行层据此下发）。
pub fn keepalive_secs() -> u32 {
    DIRECT_PERSISTENT_KEEPALIVE_SECS
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::EndpointCandidate;

    const OVERLAY: &str = "10.240.0.0/16";
    const HOME: &str = "192.168.1.0/24";

    fn cidr(s: &str) -> Ipv4Cidr {
        s.parse().unwrap()
    }

    fn direct_peer(key: &str, vip: &str, state: PeerLinkState) -> DirectPeer {
        DirectPeer {
            virtual_ipv4: vip.parse().unwrap(),
            state,
            last_handshake_age_secs: None,
            peer_name: format!("{key}-name"),
            endpoint: String::new(),
            rtt_ms: None,
            rtt_source: None,
            last_handshake_at: None,
            rx_bytes: 0,
            tx_bytes: 0,
            candidates: vec![],
        }
    }

    fn peer(key: &str, vip: &str, endpoints: &[EndpointCandidate]) -> PeerEndpoints {
        PeerEndpoints {
            device_id: meshlet_domain::DeviceId(key.into()),
            public_key: key.into(),
            virtual_ipv4: vip.parse().unwrap(),
            name: format!("{key}-name"),
            endpoints: endpoints.to_vec(),
        }
    }

    fn lan(ip: &str, port: u16) -> EndpointCandidate {
        EndpointCandidate::lan(ip.parse().unwrap(), port)
    }

    #[test]
    fn relay_promotes_a_lan_reachable_peer_with_a_32() {
        let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
        let mut current = BTreeMap::new();
        let updates = plan_updates(
            &wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &mut current,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert_eq!(updates.len(), 1);
        assert!(
            matches!(&updates[0], DirectUpdate::Promote { allowed_ips, .. }
            if allowed_ips == &vec![cidr("10.240.0.3/32")])
        );
        assert_eq!(
            current.get("dev-b").map(|p| p.state),
            Some(PeerLinkState::DirectPending { attempts: 1 })
        );
    }

    #[test]
    fn peer_without_any_path_stays_relay_and_emits_nothing() {
        let wanted = vec![peer("dev-b", "10.240.0.3", &[])];
        let mut current = BTreeMap::new();
        let updates = plan_updates(
            &wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &mut current,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(updates.is_empty());
        assert_eq!(
            current.get("dev-b").map(|p| p.state),
            Some(PeerLinkState::Relay)
        );
    }

    #[test]
    fn healthy_direct_peer_is_kept_without_repromoting() {
        let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
        let mut current = BTreeMap::new();
        current.insert(
            "dev-b".into(),
            direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
        );
        let mut ages = BTreeMap::new();
        ages.insert("dev-b".into(), 5u64);
        let updates = plan_updates(
            &wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &mut current,
            &ages,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(updates.is_empty(), "healthy direct peer: keep, no churn");
        assert_eq!(
            current.get("dev-b").map(|p| p.state),
            Some(PeerLinkState::Direct)
        );
    }

    #[test]
    fn stale_handshake_demotes_but_stale_peer_removed_from_wanted_demotes_too() {
        // 直连过期（握手年龄超过健康窗口）→ 回退。
        let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
        let mut current = BTreeMap::new();
        current.insert(
            "dev-b".into(),
            direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
        );
        let mut ages = BTreeMap::new();
        ages.insert("dev-b".into(), DIRECT_HEALTH_WINDOW_SECS.saturating_add(1));
        let updates = plan_updates(
            &wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &mut current,
            &ages,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(
            matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b")
        );
        assert_eq!(
            current.get("dev-b").map(|p| p.state),
            Some(PeerLinkState::Relay)
        );

        // 对端从候选集消失（撤销/下线）→ 即使健康也回退并移除。
        let mut current2 = BTreeMap::new();
        current2.insert(
            "dev-b".into(),
            direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
        );
        let updates = plan_updates(
            &[],
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &mut current2,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(
            matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b")
        );
        assert!(current2.is_empty());
    }

    #[test]
    fn degraded_direct_peer_immediately_falls_back_to_relay() {
        // SEL-003：直连路径劣化（丢包尖峰/超时）→ 立即 Demote 回中继。
        let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
        let mut current = BTreeMap::new();
        current.insert(
            "dev-b".into(),
            direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
        );
        let mut degraded = BTreeMap::new();
        degraded.insert("dev-b".into(), true);
        let updates = plan_updates(
            &wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &mut current,
            &BTreeMap::new(),
            &degraded,
            &BTreeSet::new(),
        );
        assert!(
            matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b")
        );
        assert_eq!(
            current.get("dev-b").map(|p| p.state),
            Some(PeerLinkState::Relay),
            "degraded direct peer must fall back to relay immediately"
        );
    }

    #[test]
    fn healthy_direct_peer_is_not_degraded() {
        // 未标劣化 → 不触发回退。
        let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
        let mut current = BTreeMap::new();
        current.insert(
            "dev-b".into(),
            direct_peer("dev-b", "10.240.0.3", PeerLinkState::Direct),
        );
        let mut ages = BTreeMap::new();
        ages.insert("dev-b".into(), 5u64);
        let updates = plan_updates(
            &wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &mut current,
            &ages,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(updates.is_empty(), "healthy direct peer: no demote");
        assert_eq!(
            current.get("dev-b").map(|p| p.state),
            Some(PeerLinkState::Direct)
        );
    }

    #[test]
    fn recovery_after_degradation_repromotes_via_state_machine() {
        // SEL-003 恢复：回中继后，下一周期健康 → 状态机重新 Promote（按迟滞
        // 闸切回）。这里验证 Relay→Promote 恢复路径（RecoveryGate 在 agent 侧
        // 门控「连续 N 轮健康」后才允许再次进入候选决策）。
        let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
        let mut current = BTreeMap::new();
        current.insert(
            "dev-b".into(),
            direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay),
        );
        let updates = plan_updates(
            &wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &mut current,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(
            matches!(&updates[0], DirectUpdate::Promote { .. }),
            "recovered peer is re-promoted: {updates:?}"
        );
        assert!(matches!(
            current.get("dev-b").map(|p| p.state),
            Some(PeerLinkState::DirectPending { .. })
        ));
    }

    #[test]
    fn recovery_hold_keeps_relay_until_gate_is_ready() {
        // SEL-003 恢复门：回中继后未连续健康 N 轮（hold_relay 含该对端）→
        // 即使有直连路径也保持中继，不立即切回（防抖）。
        let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
        let mut current = BTreeMap::new();
        current.insert(
            "dev-b".into(),
            direct_peer("dev-b", "10.240.0.3", PeerLinkState::Relay),
        );
        let mut hold = BTreeSet::new();
        hold.insert("dev-b".into());
        let updates = plan_updates(
            &wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &mut current,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &hold,
        );
        assert!(
            updates.is_empty(),
            "held peer must not be re-promoted yet: {updates:?}"
        );
        assert_eq!(
            current.get("dev-b").map(|p| p.state),
            Some(PeerLinkState::Relay),
            "held peer stays in relay"
        );
    }

    /// SEL-003 验收：可注入时钟的完整回退/恢复时序单测（任务书允许 netns 不可
    /// 用时的替代）。模拟一轮轮「探测周期」（degraded / 健康 是注入的时钟信号）：
    /// ① 健康直连 → 保持；② 直连劣化（丢包尖峰/超时）→ 立即回中继（Demote）；
    /// ③ 回中继后未连续健康 N(=3) 轮 → 保持中继（不切回）；④ 连续 3 轮健康 →
    /// 恢复门放行 → 状态机重新 Promote（切回）。
    #[test]
    fn sel003_fallback_and_recovery_timeline() {
        use meshlet_network::probe::RecoveryGate;
        let wanted = vec![peer("dev-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
        let mut current = BTreeMap::new();
        let mut recovery = RecoveryGate::new(3);

        // 每轮跑：degraded 注入 → 恢复门记录 → hold 集合 → 状态机。
        fn run_round(
            wanted: &[PeerEndpoints],
            current: &mut BTreeMap<String, DirectPeer>,
            recovery: &mut RecoveryGate,
            degraded: bool,
        ) -> Vec<DirectUpdate> {
            let mut degraded_map = BTreeMap::new();
            if degraded {
                degraded_map.insert("dev-b".to_string(), true);
            }
            let healthy = !degraded;
            let ready = recovery.record("dev-b", healthy);
            let mut hold = BTreeSet::new();
            let is_relay = current
                .get("dev-b")
                .map(|p| p.state == PeerLinkState::Relay)
                .unwrap_or(false);
            if !ready && is_relay {
                hold.insert("dev-b".to_string());
            }
            plan_updates(
                wanted,
                &[cidr(HOME)],
                cidr(OVERLAY),
                "10.240.0.2".parse().unwrap(),
                current,
                &BTreeMap::new(),
                &degraded_map,
                &hold,
            )
        }

        // ① 健康 → 首次 Promote（DirectPending）。
        let updates = run_round(&wanted, &mut current, &mut recovery, false);
        assert!(
            matches!(&updates[0], DirectUpdate::Promote { .. }),
            "initial promote"
        );
        // ② 劣化 → 立即 Demote 回中继。
        let updates = run_round(&wanted, &mut current, &mut recovery, true);
        assert!(
            matches!(&updates[0], DirectUpdate::Demote { public_key } if public_key == "dev-b"),
            "degraded immediately falls back: {updates:?}"
        );
        assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
        // ③ 回中继后第 1、2 轮健康：恢复门未满 3 轮 → 保持中继（不切回）。
        let u1 = run_round(&wanted, &mut current, &mut recovery, false);
        assert!(u1.is_empty(), "round 1 healthy after fallback: hold {u1:?}");
        let u2 = run_round(&wanted, &mut current, &mut recovery, false);
        assert!(u2.is_empty(), "round 2 healthy after fallback: hold {u2:?}");
        assert_eq!(current.get("dev-b").unwrap().state, PeerLinkState::Relay);
        // ④ 第 3 轮健康：恢复门放行 → 重新 Promote（切回）。
        let u3 = run_round(&wanted, &mut current, &mut recovery, false);
        assert!(
            matches!(&u3[0], DirectUpdate::Promote { .. }),
            "round 3 healthy after fallback: switch back {u3:?}"
        );
    }

    #[test]
    fn link_statuses_report_active_direct_links_only() {
        let mut manager = DirectManager::new();
        // 无在管对端 → 空上报（UI 默认按中继呈现）。
        assert!(manager.link_statuses().is_empty());

        // Pending（第 1 周期）：状态 direct_pending，无握手读数。
        let wanted = vec![peer("peer-b", "10.240.0.3", &[lan("192.168.1.50", 51821)])];
        manager.apply_plan(
            &wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert_eq!(
            manager.link_statuses(),
            vec![DirectLinkStatus {
                public_key: "peer-b".into(),
                virtual_ipv4: "10.240.0.3".parse().unwrap(),
                link_state: "direct_pending".into(),
                last_handshake_age_secs: None,
                peer_name: "peer-b-name".into(),
                connection_mode: "direct_pending".into(),
                endpoint: String::new(),
                rtt_ms: None,
                rtt_source: None,
                last_handshake_at: None,
                rx_bytes: 0,
                tx_bytes: 0,
                candidates: vec![],
            }]
        );

        // 握手健康 → Direct，并携带探测时的握手年龄快照。
        let mut ages = BTreeMap::new();
        ages.insert("peer-b".into(), 7u64);
        manager.apply_plan(
            &wanted,
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &ages,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert_eq!(
            manager.link_statuses(),
            vec![DirectLinkStatus {
                public_key: "peer-b".into(),
                virtual_ipv4: "10.240.0.3".parse().unwrap(),
                link_state: "direct".into(),
                last_handshake_age_secs: Some(7),
                peer_name: "peer-b-name".into(),
                connection_mode: "p2p_direct".into(),
                endpoint: String::new(),
                rtt_ms: None,
                rtt_source: None,
                last_handshake_at: None,
                rx_bytes: 0,
                tx_bytes: 0,
                candidates: vec![],
            }]
        );

        // 回退（候选撤销）→ 不再上报该对端。
        manager.apply_plan(
            &[],
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(manager.link_statuses().is_empty());
    }

    #[test]
    fn ledger_round_trips_the_keep_set_and_restores_as_direct() {
        let root =
            std::env::temp_dir().join(format!("meshlet-direct-ledger-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("direct.json");

        let mut manager = DirectManager::new();
        let _updates = manager.apply_plan(
            &[peer("peer-a", "10.240.0.3", &[lan("192.168.1.50", 51821)])],
            &[cidr(HOME)],
            cidr(OVERLAY),
            "10.240.0.2".parse().unwrap(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        manager.save(&path).expect("ledger write");

        // 从 ledger 恢复：keep set 原样、对端按「已建立」持有。
        let restored = DirectManager::load(&path);
        assert_eq!(restored.keep_keys(), manager.keep_keys());
        assert!(restored.is_direct("peer-a"));

        // 损坏/缺失文件 → 空管理器（自愈：探测周期重建，不猜）。
        assert_eq!(
            DirectManager::load(&root.join("missing.json"))
                .keep_keys()
                .len(),
            0
        );
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(DirectManager::load(&path).keep_keys().len(), 0);

        let _ = std::fs::remove_dir_all(root);
    }

    /// R-DIAG-2：record_*/clear_endpoint 只改命中对端，缺失对端 no-op；
    /// direct_candidates 只列非 Relay 对端。
    #[test]
    fn direct_peer_status_records_only_managed_non_relay() {
        let mut manager = DirectManager::new();
        manager.peers.insert(
            "peer-a".into(),
            direct_peer("peer-a", "10.240.0.3", PeerLinkState::Direct),
        );
        manager.peers.insert(
            "peer-b".into(),
            direct_peer("peer-b", "10.240.0.4", PeerLinkState::Relay),
        );

        // 富化：命中直连对端写入，Relay/缺失对端 no-op。
        manager.record_endpoint("peer-a", "192.168.1.50:51821".into());
        manager.record_peer_status(
            "peer-a",
            Some(42),
            Some("overlay"),
            Some(1_700_000_000),
            111,
            222,
        );
        manager.record_endpoint("peer-b", "192.168.1.60:51821".into());
        manager.record_peer_status("ghost", Some(1), Some("overlay"), Some(1), 1, 1);

        let a = &manager.peers["peer-a"];
        assert_eq!(a.endpoint, "192.168.1.50:51821");
        assert_eq!(a.rtt_ms, Some(42));
        assert_eq!(a.last_handshake_at, Some(1_700_000_000));
        assert_eq!((a.rx_bytes, a.tx_bytes), (111, 222));
        // Relay 对端不参与直连状态记录（无直连链路）。
        assert_eq!(manager.peers["peer-b"].endpoint, "");

        // direct_candidates 只列非 Relay。
        let candidates = manager.direct_candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "peer-a");
        assert_eq!(candidates[0].1, "10.240.0.3".parse::<Ipv4Addr>().unwrap());

        // 清空：endpoint 与 RTT 一并复位，其余读数保留。
        manager.clear_endpoint("peer-a");
        assert_eq!(manager.peers["peer-a"].endpoint, "");
        assert_eq!(manager.peers["peer-a"].rtt_ms, None);
        assert_eq!(
            manager.peers["peer-a"].last_handshake_at,
            Some(1_700_000_000)
        );
    }
}
