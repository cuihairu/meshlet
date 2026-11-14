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
    classify_probe, classify_promote_probe, decide_direct_path, direct_peer_allowed_ips, on_probe,
    DirectDecision, DirectLinkStatus, Ipv4Cidr, PeerEndpoints, PeerLinkAction, PeerLinkState,
    DIRECT_HEALTH_WINDOW_SECS, DIRECT_PERSISTENT_KEEPALIVE_SECS, DIRECT_PROMOTE_FRESH_SECS,
    MAX_PROMOTE_ATTEMPTS,
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
    /// 记忆面：上次直连实际在用的 endpoint（promote 时记下、内核读数随
    /// wg roaming 刷新）。回中继后的再晋升（re-promote）优先选回它——这类
    /// 面（尤其内核漫游出来的源面）常不在服务端候选表，是「无探测目标 →
    /// 永无 SEL-003 劣化误判」的最稳面；候选表按最低 IP 取 SameLan 会拿
    /// 10.x ZT 面压过它（2026-11-13 stranded 实锤）。pending 验证失败
    /// （3 拍无握手）即清除——死面不死锁。重启后清零（ledger 不存）。
    pub last_direct: Option<meshlet_domain::EndpointCandidate>,
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

    /// 一个周期：拉候选 → 域层状态机 → 就地更新 → 返回待下发动作与决策记录。
    /// 见 [plan_updates_logged]；执行层拿到动作后逐个 `wg set`（失败只记
    /// 日志），决策记录补全判据摘要后落盘（决策日志 + 模式翻转事件）。
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
    ) -> (Vec<DirectUpdate>, Vec<PeerDecisionRecord>) {
        plan_updates_logged(
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
                    last_direct: None,
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

    /// 记录已建立的直连 endpoint（Promote 成功后与内核读数刷新时由执行侧
    /// 调用；§12.3 状态上报与控制台/CLI 展示）。对端不在管或处于 Relay
    /// （无直连链路）则 no-op。记忆面跟随内核实况——wg roaming 后的真实
    /// 源面（常不在候选表）正是再晋升要能选回的对象。
    pub fn record_endpoint(&mut self, public_key: &str, endpoint: String) {
        if let Some(peer) = self.peers.get_mut(public_key) {
            if peer.state != PeerLinkState::Relay {
                peer.last_direct = crate::agent::endpoint::parse_endpoint_candidate(&endpoint);
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
    /// 来源（如实四态：`probe_ok` / `handshake_fresh` / `probe_failed` /
    /// `unprobed`，见 [`crate::direct_rtt::RttSource`]）、最近握手 Unix 秒、
    /// 累计收发字节（wg 读数）。对端不在管或处于 Relay（无直连链路可测）
    /// 则 no-op。
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

/// 一次对端决策的回放记录（[`plan_updates_logged`] 全分支产出；执行层落
/// `agent-decisions.jsonl` 决策日志，模式翻转换算成 switch-events 事件）。
/// 无控制台上下文（Windows 服务 / schtasks SYSTEM）也能事后回放判定原因
/// 与判据输入（2026-11-14 巡检单诊断缺口）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDecisionRecord {
    /// 对端 wg 公钥。
    pub public_key: String,
    /// 对端名称（候选里读到的展示名）。
    pub peer_name: String,
    /// 判定前模式（`p2p_direct` / `direct_pending` / `hub_relay`）。
    pub from_mode: &'static str,
    /// 判定后模式。
    pub to_mode: &'static str,
    /// 动作：`promote` / `demote` / `hold_relay` / `probe`。
    pub action: &'static str,
    /// 判定原因（人读）。
    pub reason: String,
    /// 判据输入：最近直连握手年龄（秒；内核读数快照）。
    pub handshake_age_secs: Option<u64>,
    /// 判据输入：SEL-003 探测窗口劣化判定。
    pub degraded: bool,
    /// 涉事 endpoint（promote 目标；demote 时的现役面；空 = 无）。
    pub endpoint: String,
}

/// [`PeerLinkState`] → 台账/上报模式字符串（决策记录与事件共用口径）。
fn mode_str(state: PeerLinkState) -> &'static str {
    match state {
        PeerLinkState::Direct => "p2p_direct",
        PeerLinkState::DirectPending { .. } => "direct_pending",
        PeerLinkState::Relay => "hub_relay",
    }
}

/// 一个周期内的状态跃迁计划（纯函数，无 IO；返回按公钥排序，确定性）。
/// 决策回放版见 [`plan_updates_logged`]。
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
pub fn plan_updates_logged(
    wanted: &[PeerEndpoints],
    my_lan_subnets: &[Ipv4Cidr],
    scope: Ipv4Cidr,
    self_vip: Ipv4Addr,
    current: &mut BTreeMap<String, DirectPeer>,
    handshake_ages: &BTreeMap<String, u64>,
    degraded: &BTreeMap<String, bool>,
    hold_relay: &BTreeSet<String>,
) -> (Vec<DirectUpdate>, Vec<PeerDecisionRecord>) {
    let mut updates = Vec::new();
    let mut records = Vec::new();

    // 候选集之外：回退并移除（先收集，避免借用冲突）。
    let wanted_keys: BTreeMap<&str, ()> = wanted
        .iter()
        .map(|peer| (peer.public_key.as_str(), ()))
        .collect();
    let stale: Vec<(String, PeerLinkState, String)> = current
        .iter()
        .filter(|(key, _)| !wanted_keys.contains_key(key.as_str()))
        .map(|(key, entry)| (key.clone(), entry.state, entry.peer_name.clone()))
        .collect();
    for (key, state, peer_name) in stale {
        let handshake_age_secs = handshake_ages.get(&key).copied();
        current.remove(&key);
        records.push(PeerDecisionRecord {
            public_key: key.clone(),
            peer_name,
            from_mode: mode_str(state),
            to_mode: "hub_relay",
            action: "demote",
            reason: "peer left the candidate set".into(),
            handshake_age_secs,
            degraded: false,
            endpoint: String::new(),
        });
        updates.push(DirectUpdate::Demote { public_key: key });
    }

    for peer in wanted {
        let key = peer.public_key.clone();
        let state = current
            .get(&key)
            .map(|entry| entry.state)
            .unwrap_or(PeerLinkState::Relay);
        // 决策直连路径。回中继后的再晋升（re-promote）优先选回记忆面：
        // 上次直连实际在用的 endpoint（含内核漫游出来的、不在服务端候选表
        // 的面）。候选表决策只在无记忆时兜底（首次晋升 / 记忆已因验证失败
        // 清除）。
        let mut used_memory_face = false;
        let decision = match state {
            PeerLinkState::Relay => match current.get(&key).and_then(|entry| entry.last_direct) {
                Some(c) => {
                    used_memory_face = true;
                    DirectDecision::SameLan(c)
                }
                None => decide_direct_path(my_lan_subnets, &peer.endpoints),
            },
            _ => decide_direct_path(my_lan_subnets, &peer.endpoints),
        };
        // SEL-003 恢复门：回中继后未连续健康 N 轮 → 保持中继（不立即切回，
        // 防抖）。健康已稳定（ready）后才允许状态机重新 Promote。记忆面
        // 穿透保持——门放行后的再晋升仍优先选回它。
        if hold_relay.contains(&key) && matches!(state, PeerLinkState::Relay) {
            let last_direct = current.get(&key).and_then(|entry| entry.last_direct);
            records.push(PeerDecisionRecord {
                public_key: key.clone(),
                peer_name: peer.name.clone(),
                from_mode: "hub_relay",
                to_mode: "hub_relay",
                action: "hold_relay",
                reason: "recovery gate: not yet N consecutive healthy rounds".into(),
                handshake_age_secs: handshake_ages.get(&key).copied(),
                degraded: degraded.get(&key).copied().unwrap_or(false),
                endpoint: String::new(),
            });
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
                    last_direct,
                },
            );
            continue;
        }
        // SEL-003：直连劣化（丢包尖峰/超时/RTT 深劣化）→ 立即回中继，不等
        // 握手过期。（劣化优先级最高：即使握手证据新鲜，劣化仍回退——降级
        // 口径不放松。这是「握手新鲜短路」的补口子：freshness 不能单方面判
        // Healthy，探测必须参与判定——2026-11-13 SEL-002 双机验收实锤的
        // hs 冻结 133–203s 钉直连，正是缺这条时延/探测否决路径。）
        if degraded.get(&key).copied().unwrap_or(false)
            && matches!(
                state,
                PeerLinkState::Direct | PeerLinkState::DirectPending { .. }
            )
        {
            // 劣化回退的记忆面：已建立的 Direct 保留（面大概率还在，真死了
            // 下次 promote 验证失败自然清除）；pending 被打断的 endpoint 尚未
            // 验证过握手，弃用。
            let mut last_direct = current.get(&key).and_then(|entry| entry.last_direct);
            if matches!(state, PeerLinkState::DirectPending { .. }) {
                last_direct = None;
            }
            let prev_endpoint = current
                .get(&key)
                .map(|e| e.endpoint.clone())
                .unwrap_or_default();
            records.push(PeerDecisionRecord {
                public_key: key.clone(),
                peer_name: peer.name.clone(),
                from_mode: mode_str(state),
                to_mode: "hub_relay",
                action: "demote",
                reason: "sel003 degraded: probe window (consecutive-lost / median-rtt gate)".into(),
                handshake_age_secs: handshake_ages.get(&key).copied(),
                degraded: true,
                endpoint: prev_endpoint,
            });
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
                    last_direct,
                },
            );
            updates.push(DirectUpdate::Demote { public_key: key });
            continue;
        }
        // 探测判读：pending 用**握手证据优先**的晋升门槛（最近握手新鲜即
        // 视为直连验证成功，ICMP 探测失败/不可用不拦晋升——Windows 网格
        // 防火墙对 wg 接口 100% 丢包，imac 2026-11-07 取证）；其余状态沿用
        // 健康窗口口径（Direct 断开回退等）。
        let handshake_age = handshake_ages.get(&key).copied();
        let probe = match state {
            PeerLinkState::DirectPending { .. } => classify_promote_probe(
                handshake_age,
                DIRECT_PROMOTE_FRESH_SECS,
                DIRECT_HEALTH_WINDOW_SECS,
            ),
            _ => classify_probe(state, handshake_age, DIRECT_HEALTH_WINDOW_SECS),
        };
        let (next_state, action) = on_probe(state, decision, probe, MAX_PROMOTE_ATTEMPTS);
        // 记忆面维护：promote 记下要拨的面；pending 验证失败的回退弃用记忆
        // （该 endpoint 未能建立握手，死面不锁死再晋升）；已建立直连的回退
        // 保留（面大概率还在，见劣化分支同款语义）。
        let mut last_direct = current.get(&key).and_then(|entry| entry.last_direct);
        match &action {
            PeerLinkAction::Promote(path) => {
                if let DirectDecision::SameLan(c) | DirectDecision::HolePunch(c) = *path {
                    last_direct = Some(c);
                }
            }
            PeerLinkAction::Demote => {
                if matches!(state, PeerLinkState::DirectPending { .. }) {
                    last_direct = None;
                }
            }
            PeerLinkAction::Keep => {}
        }
        let prev_endpoint = current
            .get(&key)
            .map(|e| e.endpoint.clone())
            .unwrap_or_default();
        current.insert(
            key.clone(),
            DirectPeer {
                virtual_ipv4: peer.virtual_ipv4,
                state: next_state,
                last_handshake_age_secs: handshake_age,
                peer_name: peer.name.clone(),
                // endpoint 在 Promote 动作里给出；Relay/Demote 保留上次值，
                // 由动作执行侧在 Demote 时清空（见 agent.apply_direct_update）。
                endpoint: prev_endpoint.clone(),
                rtt_ms: None,
                rtt_source: None,
                last_handshake_at: None,
                rx_bytes: 0,
                tx_bytes: 0,
                candidates: vec![],
                last_direct,
            },
        );
        // 决策入账：状态迁移或非 Keep 动作都记一条（探测窗口/握手年龄等判据
        // 输入由执行层补全后落盘，见 agent.reconcile_direct）。
        if next_state != state || !matches!(action, PeerLinkAction::Keep) {
            let (action_str, reason) = match &action {
                PeerLinkAction::Promote(_) => (
                    "promote",
                    if matches!(state, PeerLinkState::Relay) {
                        format!(
                            "promote attempt via {} (probe {probe:?})",
                            if used_memory_face {
                                "memory face (last_direct)"
                            } else {
                                "candidate table"
                            }
                        )
                    } else {
                        format!("pending verified: fresh handshake (probe {probe:?})")
                    },
                ),
                PeerLinkAction::Demote => (
                    "demote",
                    match state {
                        PeerLinkState::Direct => {
                            format!("handshake stale beyond health window (probe {probe:?})")
                        }
                        PeerLinkState::DirectPending { attempts } => {
                            format!("pending attempts exhausted after {attempts} rounds (probe {probe:?})")
                        }
                        PeerLinkState::Relay => "relay demoted".into(),
                    },
                ),
                PeerLinkAction::Keep => {
                    // Keep 且状态变化 = pending 门槛判定：验成（→Direct）或
                    // 继续等（attempts+1）。验成与 Promote 同性质（晋升）。
                    if matches!(next_state, PeerLinkState::Direct) {
                        (
                            "promote",
                            format!("pending verified: fresh handshake (probe {probe:?})"),
                        )
                    } else if let PeerLinkState::DirectPending { attempts } = next_state {
                        (
                            "probe",
                            format!("waiting for handshake (attempt {attempts})"),
                        )
                    } else {
                        ("probe", "state advanced (probe gate)".into())
                    }
                }
            };
            records.push(PeerDecisionRecord {
                public_key: key.clone(),
                peer_name: peer.name.clone(),
                from_mode: mode_str(state),
                to_mode: mode_str(next_state),
                action: action_str,
                reason,
                handshake_age_secs: handshake_age,
                degraded: degraded.get(&key).copied().unwrap_or(false),
                endpoint: match &action {
                    PeerLinkAction::Promote(path) => path_endpoint(*path).to_string(),
                    _ => prev_endpoint.clone(),
                },
            });
        }
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
    (updates, records)
}

/// 仅取动作序列的便捷封装（决策记录不需要时的旧签名入口）。
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
    plan_updates_logged(
        wanted,
        my_lan_subnets,
        scope,
        self_vip,
        current,
        handshake_ages,
        degraded,
        hold_relay,
    )
    .0
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

/// 握手读数兜底合并（纯函数）：`dedicated`（`wg show latest-handshakes` 专项
/// 读数）为空/缺某对端时，用诊断 dump（`wg show dump`，同一次内核读数的另一
/// 投影）推导的年龄补齐。Windows 隧道服务重装抖动期间 latest-handshakes 可能
/// 不可读（「Unable to access interface」，imac 2026-11-07 取证）——专项读数
/// 失败不该让握手证据整体丢失，否则晋升门槛拿不到输入，直连永卡「拨号中」。
pub fn merge_handshake_ages(
    dedicated: BTreeMap<String, u64>,
    dump: BTreeMap<String, u64>,
) -> BTreeMap<String, u64> {
    let mut merged = dedicated;
    for (key, age) in dump {
        merged.entry(key).or_insert(age);
    }
    merged
}

/// keepalive 周期（域层常量，执行层据此下发）。
pub fn keepalive_secs() -> u32 {
    DIRECT_PERSISTENT_KEEPALIVE_SECS
}

#[cfg(test)]
mod tests;
