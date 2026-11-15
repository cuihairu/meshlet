//! P2P direct connect orchestration.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Instant;

use meshlet_domain::PeerLinkState;
use meshlet_domain::DIRECT_PROBE_INTERVAL_SECS;
use meshlet_network::dial::{self, DirectDialRequest, DirectDialResult};
use meshlet_network::{DevicePlan, NetworkDiagnostics};

use crate::agent::endpoint::parse_endpoint_candidate;
use crate::agent::handshake::dump_handshake_ages;
use crate::agent::rtt_source::honest_rtt_source;
use crate::agent::scope::direct_scope;
use crate::agent::verdict::dial_verdict;
use crate::agent::views::direct_peer_views;
use crate::direct::{keepalive_secs, merge_handshake_ages, DirectUpdate, PeerDecisionRecord};
use crate::direct_rtt::{RttCandidate, RttProbe};
use crate::server;

impl super::Agent {
    /// §12 P2P 直连探测循环（30s 节流）：拉候选 → 域层状态机 → `wg set` 下发。
    ///
    /// 直连是**增益**：所有失败（拉候选失败 / LAN 枚举失败 / 握手读数失败 /
    /// `wg set` 失败）只记日志，绝不打断 hub 中继路径——对端仍按 hub 整段
    /// 路由可达，下一周期重试。开关关闭时清空已建立的直连（交还 hub，由
    /// 内核对账的漂移清理兜底）。
    ///
    /// `peer dial` 意图（[`dial::DirectDialRequest`]）：CLI 写在
    /// `{state_dir}/direct-dial.json`。有意图时**跳过 30s 节流**立刻探测一轮
    /// （拨号不等下个周期），把目标候选喂给状态机并经
    /// [`crate::agent::Agent::apply_direct_update`] 调 `wg set`（executor 经
    /// `meshlet-network` 发起直连拨号）；随后把结果写回
    /// `{state_dir}/direct-dial-result.json` 并清除意图。拨号失败/无路径/
    /// 非候选都如实写失败结果——绝不静默。
    ///
    /// 生产由 [`Agent::tick`] 在心跳之后调度（服务端先看到本机直连候选）；
    /// netns 集成测试可直接驱动一轮。
    pub fn reconcile_direct(&mut self, plan: &DevicePlan) {
        let request = dial::load_request(Path::new(&self.state_dir));
        if !self.dataplane.direct_connect.enabled {
            // 直连关 → 无候选可探：清空探测候选缓存与候选表（探测线程下一轮
            // no-op；roaming 面证据一并丢弃，开关重开后从服务端口径重建）。
            self.probe.update_candidates(&[]);
            self.candidates = crate::candidates::CandidateTable::new();
            let updates = self.direct.demote_all();
            if !updates.is_empty() {
                for update in &updates {
                    self.apply_direct_update(update);
                }
                self.save_direct_ledger();
            }
            self.last_direct_probe = Some(Instant::now());
            if let Some(req) = request {
                self.finish_dial(
                    &req,
                    false,
                    "hub_relay",
                    "direct connect is disabled (config)",
                );
            }
            return;
        }
        let due = self
            .last_direct_probe
            .map(|last| last.elapsed().as_secs() >= DIRECT_PROBE_INTERVAL_SECS)
            .unwrap_or(true);
        // 有拨号意图即强制本轮（不等节流）；无意图按正常节流。换网事件的
        // 「立即探测」由 run() 在网络事件唤醒处重置 last_direct_probe 实现。
        if !due && request.is_none() {
            return;
        }
        self.last_direct_probe = Some(Instant::now());
        let wanted = match server::fetch_peer_endpoints(&self.server_url, &self.token) {
            Ok(wanted) => wanted,
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: peer endpoints unavailable");
                if let Some(req) = request {
                    self.finish_dial(
                        &req,
                        false,
                        "hub_relay",
                        &format!("peer endpoints unavailable: {e}"),
                    );
                }
                return;
            }
        };
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // FLIP-001 候选表对账：config 面（服务端权威）插入/保鲜 → 回收出集
        // 对端与过期 roaming 面 → 合并成有效候选集（config 原序在前，表内
        // 新增面按地址排序追加）。SEL-001 自此探测**全部已知面**（含内核
        // roaming 面），不再只盯服务端单一 endpoint 等它劣化。
        self.candidates.sync_config(&wanted, now_secs);
        self.candidates.retain_peers(&wanted);
        self.candidates.expire(now_secs);
        let effective = self.candidates.merge_into(&wanted);
        // SEL-001：候选集刷新（探测线程复用，不额外请求 server——零控制面负载）。
        self.probe.update_candidates(&effective);
        let Some(scope) = direct_scope(plan) else {
            tracing::warn!("direct probe: no routable scope in the plan; keeping hub relay");
            if let Some(req) = request {
                self.finish_dial(&req, false, "hub_relay", "no routable scope in the plan");
            }
            return;
        };
        let my_lan_subnets = match self.backend.lan_subnets_sync() {
            Ok(subnets) => subnets,
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: lan subnets unavailable");
                Vec::new()
            }
        };
        let handshake_ages = match self.backend.handshake_ages_sync() {
            Ok(ages) => ages,
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: handshake ages unavailable");
                BTreeMap::new()
            }
        };
        // 诊断快照一次采集、多处复用（直连 enrich + 晋升门槛的握手兜底）：
        // `wg dump` 与 latest-handshakes 是同一次内核读数的两投影——Windows
        // 隧道抖动期 latest-handshakes 不可读时，dump 里的握手时间仍是晋升
        // 门槛的合法输入（缺失则 pending 拿不到握手证据，永卡「拨号中」）。
        let net = match self.backend.diagnostics_sync() {
            Ok(net) => Some(net),
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: diagnostics unavailable");
                None
            }
        };
        let handshake_ages =
            merge_handshake_ages(handshake_ages, dump_handshake_ages(net.as_ref(), now_secs));
        // FLIP-001 内核 roaming 观测：wg dump 里各在管对端的当前 endpoint
        // （内核收到新源面的合法认证包即漫游——对端换网 / 新 face 的最强
        // 证据，常不在服务端候选表）。灌入候选表（TTL 内有效）；新面出现即
        // 重合并 + 刷新探测缓存（探测线程一个周期内即采样新面）。hub peer
        // 与内核漂移 peer 不在候选集，不收。
        let wanted_keys: std::collections::BTreeSet<&str> =
            wanted.iter().map(|p| p.public_key.as_str()).collect();
        if let Some(net) = &net {
            for wg_peer in &net.wg {
                if !wanted_keys.contains(wg_peer.public_key.as_str()) {
                    continue;
                }
                let Some(candidate) = parse_endpoint_candidate(&wg_peer.endpoint) else {
                    continue;
                };
                if self
                    .candidates
                    .observe_roaming(&wg_peer.public_key, candidate, now_secs)
                {
                    tracing::info!(
                        public_key = %wg_peer.public_key,
                        endpoint = %wg_peer.endpoint,
                        "candidate table: new roaming face observed"
                    );
                }
            }
        }
        drop(wanted_keys);
        // 本轮统一用含 roaming 面的有效候选集（观测后重合并 + 刷新探测缓存）。
        let effective = self.candidates.merge_into(&wanted);
        self.probe.update_candidates(&effective);
        // SEL-003：从探测窗口推导各对端**当前直连路径**是否劣化（丢包尖峰/
        // 超时/RTT 深劣化——中位数 ≥ degrade_rtt_ms）。只看现役 endpoint 的
        // 窗口：候选列表里常年 ICMP 不达的备份候选（公网 NAT / 异网 LAN）
        // 与现役路径无关，任一候选劣化就整 peer 劣化会把健康直连误降级。
        let current_paths: BTreeMap<_, _> = self
            .direct
            .link_statuses()
            .into_iter()
            .filter(|s| s.link_state == "direct")
            .filter_map(|s| parse_endpoint_candidate(&s.endpoint).map(|c| (s.public_key, c)))
            .collect();
        let degraded = self.probe.degraded_map(&current_paths);
        // promote 偏好健康面：当前探测窗口劣化的面集合（晋升选路前置过滤，
        // 见 plan_updates_logged——劣化面上 re-promote 只会立刻再降级）。
        let unhealthy_faces = self.probe.degraded_faces();
        // FLIP-001 探测证据刷新：单快照批量取「探测证实健康」面集——候选表
        // 保鲜（roaming→discovered 升级、last_seen 前移）与恢复门 bypass
        // 共用同一轮读数。
        let healthy_faces = self.probe.healthy_faces();
        self.candidates
            .refresh_probe_evidence(&healthy_faces, now_secs);
        // FLIP-002 健康证据记账：对端本轮有任一探测健康面 → 健康轮 +1（连续
        // M 轮清零退避）；无健康面 → 健康轮清零（连续性打破，抑制保持）。
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        for peer in &effective {
            let peer_has_healthy_face = healthy_faces
                .iter()
                .any(|(public_key, _)| public_key == &peer.public_key);
            self.backoff
                .note_health(&peer.public_key, peer_has_healthy_face, now_ms);
        }
        // FLIP-002 抑制表：抑制中的对端本轮不 promote（域层 hold_relay 之后
        // 检查，保记忆面留中继）。
        let suppress_promote = self.backoff.suppress_map(now_ms);
        // SEL-003 恢复门：对处于直连状态的对端记录本轮健康度；回中继后连续
        // N 轮健康才放行切回。健康 = 未劣化且握手年龄在健康窗口内。
        // FLIP-001 bypass：候选表里存在探测健康面时不等门——换网后新面已
        // 可达即回直连，不经过「先 demote 再等恢复门」旧路径（门只兜底
        // 「没有任何健康面证据」的场景）。FLIP-002 抑制优先——退避期内
        // 即便有健康面也不 promote（拉开重试间隔）。
        let mut hold_relay = std::collections::BTreeSet::new();
        let mut gate_bypassed: Vec<(String, String)> = Vec::new();
        for peer in &effective {
            let healthy = !degraded.get(&peer.public_key).copied().unwrap_or(false)
                && handshake_ages
                    .get(&peer.public_key)
                    .is_none_or(|age| *age <= meshlet_domain::DIRECT_HEALTH_WINDOW_SECS);
            let ready = self.recovery.record(&peer.public_key, healthy);
            if !ready
                && self
                    .direct
                    .status_of(&peer.public_key)
                    .is_some_and(|p| p.state == PeerLinkState::Relay)
            {
                let faces = self.candidates.faces(&peer.public_key);
                let healthy_face = faces
                    .iter()
                    .find(|(c, _)| healthy_faces.contains(&(peer.public_key.clone(), *c)));
                match healthy_face {
                    Some((face, source)) if !suppress_promote.contains_key(&peer.public_key) => {
                        tracing::info!(
                            public_key = %peer.public_key,
                            face = %face.socket(),
                            source = source.as_str(),
                            "recovery gate bypassed: probe-healthy face in candidate table"
                        );
                        gate_bypassed.push((peer.public_key.clone(), face.socket().to_string()));
                    }
                    _ => {
                        // 已回中继且无健康面证据（或退避抑制中）：保持中继
                        // （防抖切回 / 拉开重试间隔）。
                        hold_relay.insert(peer.public_key.clone());
                    }
                }
            }
        }
        // 回收不在候选集里的恢复计数。
        let live_keys: Vec<String> = wanted.iter().map(|p| p.public_key.clone()).collect();
        self.recovery.retain(&live_keys);
        self.backoff.retain(&live_keys);
        let (updates, decisions) = self.direct.apply_plan(
            &effective,
            &my_lan_subnets,
            scope,
            plan.tunnel.address,
            &handshake_ages,
            &degraded,
            &unhealthy_faces,
            &hold_relay,
            &suppress_promote,
        );
        if !updates.is_empty() {
            for update in &updates {
                self.apply_direct_update(update);
                // FLIP-002：劣化/握手判定产生的 demote 计入退避（连续 demote
                // 指数拉开重试间隔）。候选集之外的逐出与开关关闭的清场不计
                // ——那是行政性移除，不是链路质量信号。
                if let DirectUpdate::Demote { public_key } = update {
                    if live_keys.contains(public_key) {
                        self.backoff.on_demote(public_key, now_ms);
                    }
                }
            }
            self.save_direct_ledger();
        }
        // 决策落盘（2026-11-14 巡检单观测性欠账）：classify / 切换闸判定逐条
        // 写决策日志，模式翻转另记 `mode_flip` 切换事件——无控制台上下文
        // （Windows 服务 / schtasks SYSTEM）也能事后回放降级/晋升原因。
        // 判据输入摘要（探测窗口）按**本轮**现役路径查窗口快照。
        self.record_decisions(&decisions, &current_paths);
        // FLIP-001 观测面：恢复门 bypass 逐条入决策日志（无控制台上下文也
        // 能回放「为什么没等门」）。
        self.record_bypass_events(&gate_bypassed, &handshake_ages);
        // R-DIAG-2：对处于直连状态的对端刷新读数（wg 端点/握手/流量）+ 实测
        // 直连路径 RTT——即使本周期无动作也要刷新，供心跳与控制台/CLI 展示。
        self.enrich_direct_peers(net.as_ref(), now_secs);
        // SEL-002：迟滞切换。已建立直连的对端，若其候选窗口中另有路径连续 N
        // 采样且优于现路径 ≥30%，则 `wg set endpoint` 漫游过去（零断线），
        // 并追加切换事件（事件可查）。探测未启用 / 无直连 / 无更优路径都
        // 是 no-op——绝不影响数据面循环。
        self.apply_switch_decisions();
        // 发布直连对端视图（`direct-peers.json`）：托盘「直连节点 / 连接节点…」
        // 子菜单与 CLI `peer dial` 解析 `<node>` 的数据源（含候选表 roaming 面）。
        self.publish_direct_peers(&effective);
        if let Some(req) = request {
            self.finish_dial_for_request(&req);
        }
    }

    /// 按拨号意图确定结果：状态机已跑完本轮，目标对端当前状态即判定依据。
    fn finish_dial_for_request(&self, req: &DirectDialRequest) {
        let (ok, mode, message) = dial_verdict(self.direct.status_of(&req.public_key));
        self.finish_dial(req, ok, mode, message);
    }

    /// 写拨号结果并清除意图。结果文件常驻（CLI 轮询它），下次拨号覆盖。
    fn finish_dial(&self, req: &DirectDialRequest, ok: bool, mode: &str, message: &str) {
        let result = DirectDialResult {
            request_id: req.request_id.clone(),
            ok,
            mode: mode.into(),
            message: message.into(),
            finished_at: dial::now_millis(),
        };
        if let Err(e) = dial::write_result(Path::new(&self.state_dir), &result) {
            tracing::warn!(error = %e, "direct dial result not written");
        }
        if let Err(e) = dial::clear_request(Path::new(&self.state_dir)) {
            tracing::warn!(error = %e, "direct dial request not cleared");
        }
    }

    /// 发布直连对端视图：服务端候选集 + 当前链路状态合并（`direct-peers.json`）。
    /// 候选已直连/待握手取链路状态；候选无路径（Relay）标 `hub_relay`（可拨号）。
    fn publish_direct_peers(&self, wanted: &[meshlet_domain::PeerEndpoints]) {
        let views = direct_peer_views(wanted, &self.direct.link_statuses());
        if let Err(e) = dial::write_direct_peers(Path::new(&self.state_dir), &views) {
            tracing::warn!(error = %e, "direct peers view not published");
        }
    }

    /// R-DIAG-2：从内核刷新各直连对端的实际状态（endpoint / 最近握手 /
    /// 累计流量），RTT 取**后台运行时**的最新实测值（绝不内联 `ping`）。
    ///
    /// 探测候选带对端 endpoint 的 underlay 地址：overlay VIP 不答 ICMP
    /// （WireGuard 接口 / 防火墙常弃包，链路可能完全活着）时，后台线程回退
    /// ping endpoint——两路都无响应才「实测失败」，rtt_source 随 RTT 如实记录
    /// （实测成功 probe_ok；不可测但握手新鲜 handshake_fresh；两路无响应且
    /// 握手也不新鲜 probe_failed；探测在途 unprobed），供面板/控制台标注。
    ///
    /// 读数失败只记日志——展示数据源是「最后已知态」，绝不让诊断采集干扰
    /// 数据面；对端已不在管（本周期被 Demote）则各 record_* no-op。
    fn enrich_direct_peers(&mut self, net: Option<&NetworkDiagnostics>, now_secs: u64) {
        let candidates = self.direct.direct_candidates();
        if candidates.is_empty() {
            // 无直连对端：清空 RTT 候选（后台线程下一轮 no-op）。
            self.direct_rtt.update_candidates(Vec::new());
            return;
        }
        // net 由调用方传入（reconcile 已采集一次，避免重复 `wg dump`）；None =
        // 读数失败则没有回退路径可用，仅按 overlay 探测（与旧行为一致）。
        let probed: Vec<RttCandidate> = candidates
            .into_iter()
            .map(|(public_key, vip)| {
                let endpoint_ip = net.as_ref().and_then(|net| {
                    net.wg
                        .iter()
                        .find(|p| p.public_key == public_key)
                        .map(|p| p.endpoint.clone())
                        .unwrap_or_default()
                        .rsplit_once(':')
                        .and_then(|(host, _)| host.parse::<Ipv4Addr>().ok())
                });
                (public_key, vip, endpoint_ip)
            })
            .collect();
        // 后台线程按最新候选集 ping；主循环只读快照，不等任何 ping。
        self.direct_rtt.update_candidates(probed.clone());
        let rtts = self.direct_rtt.snapshot();
        for (public_key, vip, _endpoint_ip) in probed {
            let wg_peer = net
                .as_ref()
                .and_then(|net| net.wg.iter().find(|p| p.public_key == public_key));
            let endpoint = wg_peer.map(|p| p.endpoint.clone()).unwrap_or_default();
            let last_handshake_at =
                wg_peer.and_then(|p| (p.last_handshake > 0).then_some(p.last_handshake));
            let (rx_bytes, tx_bytes) = wg_peer.map(|p| (p.rx_bytes, p.tx_bytes)).unwrap_or((0, 0));
            // 读快照：刚更新候选集的第一次读可能尚未有实测值（None=未知，
            // 与「读数失败」一致，展示数据源最后已知态）。`vip` 仅供记录日志。
            let probe = rtts
                .get(&public_key)
                .copied()
                .unwrap_or_else(RttProbe::unknown);
            let _ = vip;
            self.direct.record_peer_status(
                &public_key,
                probe.rtt_ms,
                honest_rtt_source(&probe, last_handshake_at, now_secs),
                last_handshake_at,
                rx_bytes,
                tx_bytes,
            );
            if !endpoint.is_empty() {
                self.direct.record_endpoint(&public_key, endpoint.clone());
            }
            // SEL-004：汇总候选端点详情（端点/RTT/丢包/当前选中与原因），
            // 供心跳上报 → console peer 详情渲染。
            let statuses = self.probe.candidate_statuses(&public_key, &endpoint);
            self.direct.record_candidates(&public_key, statuses);
        }
    }

    /// SEL-002：对每个已建立直连的对端评估迟滞闸，需要时漫游 endpoint。
    ///
    /// 只作用于 `direct` 状态的对端（`direct_pending` 尚未验证、`Relay` 无直连
    /// 链路，切换无意义）。`wg set endpoint` 失败只记日志——直连仍是增益，
    /// 保持当前 endpoint 下一周期再试；成功才记录切换事件（[`dial`] 追加）。
    fn apply_switch_decisions(&mut self) {
        if !self.dataplane.probe.enabled {
            return;
        }
        // 现路径候选（endpoint）解析 + 直连对端集合：只评估非 Relay。
        let statuses = self.direct.link_statuses();
        for status in statuses {
            if status.link_state != "direct" {
                continue;
            }
            let Some(current) = parse_endpoint_candidate(&status.endpoint) else {
                // 尚无已下发的直连 endpoint（异常态）：不切换。
                continue;
            };
            let Some(decision) = self
                .probe
                .evaluate_switch(&status.public_key, Some(current))
            else {
                continue;
            };
            if let Err(e) = self
                .backend
                .set_direct_endpoint_sync(&status.public_key, decision.to.socket())
            {
                tracing::warn!(
                    public_key = %status.public_key,
                    error = %e,
                    "direct endpoint switch failed; keeping current path"
                );
                continue;
            }
            let event = dial::SwitchEvent {
                public_key: status.public_key.clone(),
                from: status.endpoint.clone(),
                to: decision.to.socket().to_string(),
                reason: decision.reason.clone(),
                at_ms: dial::now_millis(),
                kind: None,
                detail: None,
                ts: Some(dial::rfc3339_now()),
            };
            if let Err(e) = dial::append_switch_event(Path::new(&self.state_dir), &event) {
                tracing::warn!(error = %e, "direct switch event not recorded");
            }
            tracing::info!(
                public_key = %status.public_key,
                from = %event.from,
                to = %event.to,
                reason = %event.reason,
                "direct endpoint switched (SEL-002)"
            );
            // 更新直连管理器记录的 endpoint（下一轮以此为现路径基准）。
            self.direct
                .record_endpoint(&status.public_key, event.to.clone());
        }
    }

    /// 决策落盘（2026-11-14 巡检单：无控制台上下文的事后回放）：状态机每条
    /// 判定追加决策日志（`{state_dir}/agent-decisions.jsonl`，超限滚动）；
    /// 模式翻转（`from_mode ≠ to_mode`）另记一条 `mode_flip` 切换事件到
    /// `direct-switch-events.json`（旧字段不动，向后兼容）。写失败只记日志
    /// ——观测是增益，绝不干扰数据面循环。
    fn record_decisions(
        &self,
        decisions: &[PeerDecisionRecord],
        current_paths: &BTreeMap<String, meshlet_domain::EndpointCandidate>,
    ) {
        let state_dir = Path::new(&self.state_dir);
        for d in decisions {
            let probe_window = current_paths
                .get(&d.public_key)
                .and_then(|c| self.probe.window_summary(&d.public_key, *c));
            let event = dial::DecisionEvent {
                ts: dial::rfc3339_now(),
                public_key: d.public_key.clone(),
                peer_name: d.peer_name.clone(),
                action: d.action.to_string(),
                from_mode: d.from_mode.to_string(),
                to_mode: d.to_mode.to_string(),
                reason: d.reason.clone(),
                handshake_age_secs: d.handshake_age_secs,
                degraded: d.degraded,
                endpoint: d.endpoint.clone(),
                probe_window,
            };
            if let Err(e) = dial::append_decision_event(state_dir, &event) {
                tracing::warn!(error = %e, "decision log not written");
            }
            if d.from_mode != d.to_mode {
                let flip = dial::SwitchEvent {
                    public_key: d.public_key.clone(),
                    from: d.from_mode.to_string(),
                    to: d.to_mode.to_string(),
                    reason: d.reason.clone(),
                    at_ms: dial::now_millis(),
                    kind: Some(dial::SWITCH_KIND_MODE_FLIP.into()),
                    detail: Some(format!(
                        "hs_age={:?} degraded={} ep={}",
                        d.handshake_age_secs, d.degraded, d.endpoint
                    )),
                    ts: Some(event.ts.clone()),
                };
                if let Err(e) = dial::append_switch_event(state_dir, &flip) {
                    tracing::warn!(error = %e, "mode flip event not recorded");
                }
                tracing::info!(
                    public_key = %d.public_key,
                    from = %d.from_mode,
                    to = %d.to_mode,
                    reason = %d.reason,
                    "direct mode flipped"
                );
            }
        }
    }

    /// FLIP-001：恢复门 bypass 逐条入决策日志（`agent-decisions.jsonl`，
    /// action=`probe`、reason 标注 FLIP-001，endpoint 即 bypass 凭据的健康面）。
    /// 写失败只记日志——观测是增益，绝不干扰数据面循环。
    fn record_bypass_events(
        &self,
        bypassed: &[(String, String)],
        handshake_ages: &BTreeMap<String, u64>,
    ) {
        let state_dir = Path::new(&self.state_dir);
        for (public_key, face) in bypassed {
            let probe_window = parse_endpoint_candidate(face)
                .and_then(|c| self.probe.window_summary(public_key, c));
            let event = dial::DecisionEvent {
                ts: dial::rfc3339_now(),
                public_key: public_key.clone(),
                peer_name: self
                    .direct
                    .status_of(public_key)
                    .map(|p| p.peer_name.clone())
                    .unwrap_or_default(),
                action: "probe".into(),
                from_mode: "hub_relay".into(),
                to_mode: "hub_relay".into(),
                reason: "recovery gate bypassed: face probe-healthy (FLIP-001)".into(),
                handshake_age_secs: handshake_ages.get(public_key).copied(),
                degraded: false,
                endpoint: face.clone(),
                probe_window,
            };
            if let Err(e) = dial::append_decision_event(state_dir, &event) {
                tracing::warn!(error = %e, "bypass decision log not written");
            }
        }
    }

    /// 持久化直连 keep set（§12 重启恢复）：失败只记日志——ledger 丢失顶多
    /// 多一个探测周期重建直连，绝不影响数据面循环。
    fn save_direct_ledger(&self) {
        if let Err(e) = self.direct.save(&self.direct_ledger) {
            tracing::warn!(
                error = %e,
                "direct ledger not written; keep set may be rebuilt on restart"
            );
        }
    }

    /// 应用单个直连动作（`wg set`）：失败只记日志——直连是增益，绝不回滚
    /// hub（对端仍按 hub 整段路由可达）。成功时记录/清空对端 endpoint
    /// （§12.3 状态上报与控制台/CLI 直连 peers 展示的数据源）。
    fn apply_direct_update(&mut self, update: &DirectUpdate) {
        match update {
            DirectUpdate::Promote {
                public_key,
                allowed_ips,
                endpoint,
            } => {
                if let Err(e) = self.backend.set_direct_peer_sync(
                    public_key,
                    allowed_ips,
                    *endpoint,
                    keepalive_secs(),
                ) {
                    tracing::warn!(
                        public_key = %public_key,
                        error = %e,
                        "direct promote failed; keeping hub relay"
                    );
                } else {
                    tracing::info!(
                        public_key = %public_key,
                        endpoint = %endpoint,
                        "direct link promoted"
                    );
                    self.direct
                        .record_endpoint(public_key, endpoint.to_string());
                }
            }
            DirectUpdate::Demote { public_key } => {
                if let Err(e) = self.backend.remove_peer_sync(public_key) {
                    tracing::warn!(
                        public_key = %public_key,
                        error = %e,
                        "direct demote failed; hub relay already covers this peer"
                    );
                } else {
                    tracing::info!(public_key = %public_key, "direct link demoted to hub relay");
                    self.direct.clear_endpoint(public_key);
                }
            }
        }
    }
}
