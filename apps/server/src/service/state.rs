//! In-memory MeshState aggregate and persistence-facing accessors.

use meshlet_domain::{
    AliasMapping, DesiredStateStatus, Device, DeviceDirectState, DeviceId, DeviceRegistration,
    DeviceRegistry, Invite, Ipam, LanRoute, Network, Segment, SegmentGrant,
};
use std::collections::{BTreeMap, HashMap};

use meshlet_network::NetworkDiagnostics;

use crate::service::error::ServiceError;

#[derive(Clone)]
pub struct MeshState {
    pub(crate) deployments: HashMap<String, crate::revision::Deployment>,
    pub(crate) networks: HashMap<String, Network>,
    /// 邀请按 Token 摘要索引（§11.3：兑换时以摘要定位，不暴露原始 Token）。
    pub(crate) invites: HashMap<String, Invite>,
    pub(crate) ipams: HashMap<String, Ipam>,
    /// 设备注册表（`pub(crate)`：agent 心跳需读设备网络归属）。
    pub(crate) registry: DeviceRegistry,
    /// LAN 路由（Phase 3 控制面：增删先落状态，应用待 backend，ADR-005）。
    pub(crate) lan_routes: HashMap<String, Vec<LanRoute>>,
    /// Alias 映射（Phase 4 控制面：等长前缀一对一，ADR-006；NAT 规则的
    /// 所有权归属——删除即整单元清理（alias + 绑定路由），内核规则由修订
    /// apply 交 backend 执行）。
    pub(crate) aliases: HashMap<String, Vec<AliasMapping>>,
    /// 服务发布对象（R-06：PortForward / HTTP 路由 / 探针 / DNS 记录，
    /// 按网络索引）。计划构建时按设备过滤（`crate::publish`），设备撤销
    /// 后不再生效。
    pub(crate) publishes: HashMap<String, crate::publish::PublishCatalog>,
    /// Segment trust groups (ADR-012), restored for startup validation and
    /// policy-plan work that follows.
    pub(crate) segments: HashMap<String, Vec<Segment>>,
    /// Directed segment grants (ADR-012), restored with segments.
    pub(crate) grants: HashMap<String, Vec<SegmentGrant>>,
    /// 路由 id 序列（全局单调，删除不复用）。
    pub(crate) route_seq: u64,
    /// 发布对象 id 序列（`pf-` / `hr-` / `pb-` / `dn-` 共用一条单调序列，
    /// 前缀不同故不冲突；持久化到 `mesh_meta.publish_seq`，已删 id 不复用）。
    publish_seq: u64,
    /// 在线判定窗口（§12.4；默认值见 [meshlet_domain::PresenceThresholds]）。
    /// `pub(crate)`：诊断 §12.7 第 4/8 项按同一窗口判握手/上报新鲜度。
    pub(crate) presence_thresholds: meshlet_domain::PresenceThresholds,
    /// 期望配置修订簿记（ADR-009 状态机，§10）。
    pub(crate) ledger: meshlet_domain::ConfigLedger,
    /// 自举码（按 Token 摘要索引；摘要索引纪律同邀请，§11.3）。
    pub(crate) bootstrap_tokens: std::collections::HashMap<String, meshlet_domain::BootstrapToken>,
    /// 自举码序列（`bt-N`，持久化到 `mesh_meta`，已删 id 不复用）。
    pub(crate) bootstrap_seq: u64,
    /// 注册申请序列（`dev-reg-N`，持久化到 `mesh_meta`，已删 id 不复用）。
    /// 前缀与 `bt-` 不冲突，故二者各自单调即可——不用共享计数器。
    /// 待审批申请本体在 `registry` 内（[DeviceRegistry]）。
    pub(crate) registration_seq: u64,
    /// §12 P2P 直连候选（**内存态**，临时性咨询数据）：每轮心跳重报，故不落
    /// 库——持久化只添陈旧风险（掉线后旧候选仍被对端当成有效）。观测源地址
    /// 由连接 socket 取（公网候选），LAN 地址由 agent 心跳上报。用 `BTreeMap`
    /// 与域层 `peer_endpoints_for` 一致（确定性排序）。
    pub(crate) direct_states: BTreeMap<DeviceId, DeviceDirectState>,
    /// 各节点真实主机名（**内存态**，同 `direct_states` 纪律）：agent 心跳
    /// 上报，SSH alias 分发的默认 alias 来源（主机名 > peer name）；不落库
    /// ——hub 重启后下一轮心跳即恢复。
    pub(crate) device_hostnames: BTreeMap<DeviceId, String>,
    /// R-DIAG 网络诊断三快照（**内存态**，同 `direct_states` 纪律）：每轮心跳
    /// 重报，不落库——持久化只添陈旧风险。`None` 上报（采集失败）即移除。
    pub(crate) diagnostics: BTreeMap<DeviceId, NetworkDiagnostics>,
    /// 任务（MT-002：派发→ack→运行→结果回执，id 为幂等键）。与配置修订同
    /// 纪律落库（重启恢复任务队列，断线补派不丢、不重复）。
    pub(crate) tasks: HashMap<String, crate::task::TaskRecord>,
    /// 任务 id 序列（`task-{seq}`，持久化到 `mesh_meta.task_seq`，已删 id
    /// 不复用；显式幂等 id 不占序列）。
    pub(crate) task_seq: u64,
}

impl MeshState {
    pub fn new(presence_thresholds: meshlet_domain::PresenceThresholds) -> Self {
        Self {
            deployments: HashMap::new(),
            networks: HashMap::new(),
            invites: HashMap::new(),
            ipams: HashMap::new(),
            registry: DeviceRegistry::new(),
            lan_routes: HashMap::new(),
            aliases: HashMap::new(),
            publishes: HashMap::new(),
            segments: HashMap::new(),
            grants: HashMap::new(),
            route_seq: 0,
            publish_seq: 0,
            presence_thresholds,
            ledger: meshlet_domain::ConfigLedger::new(),
            bootstrap_tokens: HashMap::new(),
            bootstrap_seq: 0,
            registration_seq: 0,
            direct_states: BTreeMap::new(),
            device_hostnames: BTreeMap::new(),
            diagnostics: BTreeMap::new(),
            tasks: HashMap::new(),
            task_seq: 0,
        }
    }

    pub(crate) fn network(&self, id: &str) -> Result<&Network, ServiceError> {
        self.networks
            .get(id)
            .ok_or_else(|| ServiceError::NetworkNotFound(id.to_string()))
    }

    // -- 持久化支撑（§17.3）---------------------------------------------------
    // 写路径：handler 在锁内完成状态变更后，经这些只读访问器取出需要落库的
    // 行（克隆），锁外写 SQLite。启动路径：`restore_*` 把 DB 行灌回状态。

    /// 网络行（持久化/重建共用；不存在返回 `None`）。
    pub(crate) fn network_row(&self, id: &str) -> Option<&Network> {
        self.networks.get(id)
    }

    /// 网络 hub 地址（IPAM 首地址；数据面接线用，不存在返回 `None`）。
    pub(crate) fn hub_address(&self, id: &str) -> Option<std::net::Ipv4Addr> {
        self.ipams.get(id).map(|ipam| ipam.hub_address())
    }

    /// 邀请行（按 Token 摘要定位；enroll 兑换后据此回写 `used_count`）。
    pub(crate) fn invite_by_hash(&self, token_hash: &str) -> Option<&Invite> {
        self.invites.get(token_hash)
    }

    /// 全部邀请（启动重建）。
    pub(crate) fn invites(&self) -> impl Iterator<Item = &Invite> {
        self.invites.values()
    }

    /// 当前路由 id 序列（持久化到 `mesh_meta`，重启不归零、不重号）。
    pub(crate) fn route_seq(&self) -> u64 {
        self.route_seq
    }

    /// 当前发布对象 id 序列（持久化到 `mesh_meta`，重启不归零、不重号）。
    pub(crate) fn publish_seq(&self) -> u64 {
        self.publish_seq
    }

    /// 当前任务 id 序列（持久化到 `mesh_meta.task_seq`，重启不归零、不重号）。
    pub(crate) fn task_seq(&self) -> u64 {
        self.task_seq
    }

    pub(crate) fn set_task_seq(&mut self, seq: u64) {
        self.task_seq = seq;
    }

    pub(crate) fn set_publish_seq(&mut self, seq: u64) {
        self.publish_seq = seq;
    }

    /// 当前自举码序列（持久化到 `mesh_meta`）。
    pub(crate) fn bootstrap_seq(&self) -> u64 {
        self.bootstrap_seq
    }

    pub(crate) fn set_bootstrap_seq(&mut self, seq: u64) {
        self.bootstrap_seq = seq;
    }

    /// 当前注册申请序列（持久化到 `mesh_meta`）。
    pub(crate) fn registration_seq(&self) -> u64 {
        self.registration_seq
    }

    pub(crate) fn set_registration_seq(&mut self, seq: u64) {
        self.registration_seq = seq;
    }

    pub(crate) fn registration_count(&self) -> usize {
        self.registry.registrations().len()
    }

    pub(crate) fn segment_count(&self) -> usize {
        self.segments.values().map(Vec::len).sum()
    }

    pub(crate) fn segments(&self, network_id: &str) -> &[Segment] {
        self.segments
            .get(network_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn segment_grants(&self, network_id: &str) -> &[SegmentGrant] {
        self.grants
            .get(network_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn segment_grant_count(&self) -> usize {
        self.grants.values().map(Vec::len).sum()
    }

    /// 启动重建：灌回一条待审批的注册申请（不进 IPAM、不进期望配置）。
    pub(crate) fn restore_registration(
        &mut self,
        r: DeviceRegistration,
    ) -> Result<(), ServiceError> {
        self.registry
            .add_registration(r)
            .map_err(ServiceError::from)
    }

    /// 启动重建（§17.3）：灌回一个网络与其 IPAM（hub 重算，地址逐一保留——
    /// 已撤销设备的虚拟 IP 同样占用，与运行期语义一致）。
    pub(crate) fn restore_network(&mut self, network: Network) -> Result<(), ServiceError> {
        let hub = network
            .overlay_cidr
            .iter_usable()
            .next()
            .expect("overlay has at least one usable address");
        let ipam = Ipam::new(network.overlay_cidr, hub)
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        let id = network.id.to_string();
        self.networks.insert(id.clone(), network);
        self.ipams.insert(id, ipam);
        Ok(())
    }

    /// 启动重建：灌回一台设备（IPAM 保留其虚拟 IP，注册表查重如常）。
    pub(crate) fn restore_device(&mut self, device: Device) -> Result<(), ServiceError> {
        let segments = self
            .segments
            .get(&device.network_id.to_string())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let network = self
            .networks
            .get(&device.network_id.to_string())
            .ok_or_else(|| ServiceError::Internal("network missing for device restore".into()))?;
        meshlet_domain::validate_device_segment(
            device.virtual_ipv4,
            &device.network_id,
            &device.segment_id,
            network.overlay_cidr,
            segments,
        )
        .map_err(|e| ServiceError::Internal(e.to_string()))?;
        let ipam = self
            .ipams
            .get_mut(&device.network_id.to_string())
            .ok_or_else(|| ServiceError::Internal("ipam missing for restore".to_string()))?;
        ipam.allocate_specific(device.virtual_ipv4)
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        self.registry.add(device).map_err(ServiceError::from)
    }

    /// 启动重建：灌回一条 LAN 路由。
    pub(crate) fn restore_route(&mut self, route: LanRoute) {
        self.lan_routes
            .entry(route.network_id.to_string())
            .or_default()
            .push(route);
    }

    /// 启动重建：灌回一条 Alias 映射。
    pub(crate) fn restore_alias(&mut self, alias: AliasMapping) {
        self.aliases
            .entry(alias.network_id.to_string())
            .or_default()
            .push(alias);
    }

    pub(crate) fn restore_segment(&mut self, segment: Segment) -> Result<(), ServiceError> {
        let network = self
            .networks
            .get(&segment.network_id.to_string())
            .ok_or_else(|| ServiceError::Internal("network missing for segment restore".into()))?;
        segment
            .validate_cidr(network.overlay_cidr)
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
        self.segments
            .entry(segment.network_id.to_string())
            .or_default()
            .push(segment);
        Ok(())
    }

    pub(crate) fn restore_segment_grant(
        &mut self,
        grant: SegmentGrant,
    ) -> Result<(), ServiceError> {
        let segments = self
            .segments
            .get(&grant.network_id.to_string())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if !segments
            .iter()
            .any(|segment| segment.id == grant.source_segment_id)
            || !segments
                .iter()
                .any(|segment| segment.id == grant.destination_segment_id)
        {
            return Err(ServiceError::Internal(
                "segment grant references an unknown segment".into(),
            ));
        }
        self.grants
            .entry(grant.network_id.to_string())
            .or_default()
            .push(grant);
        Ok(())
    }

    /// 启动重建：灌回一份邀请（摘要索引；撤销/耗尽状态如常保留）。
    pub(crate) fn restore_invite(&mut self, invite: Invite) {
        self.invites.insert(invite.token_hash.clone(), invite);
    }

    /// 启动重建：恢复路由 id 序列（删除过的 id 不复用）。
    pub(crate) fn set_route_seq(&mut self, seq: u64) {
        self.route_seq = seq;
    }

    // -- 启动摘要计数（BootState 日志/测试断言用） ----------------------------

    pub(crate) fn network_count(&self) -> usize {
        self.networks.len()
    }

    pub(crate) fn device_count(&self) -> usize {
        self.registry.devices().len()
    }

    pub(crate) fn route_count(&self) -> usize {
        self.lan_routes.values().map(Vec::len).sum()
    }

    pub(crate) fn alias_count(&self) -> usize {
        self.aliases.values().map(Vec::len).sum()
    }

    /// 启动重建用：全部在册路由 id（Alias 孤儿行判定）。
    pub(crate) fn bound_route_ids(&self) -> std::collections::HashSet<String> {
        self.lan_routes
            .values()
            .flat_map(|rs| rs.iter().map(|r| r.id.to_string()))
            .collect()
    }

    pub(crate) fn invite_count(&self) -> usize {
        self.invites.len()
    }

    pub(crate) fn revision_count(&self) -> usize {
        self.networks
            .keys()
            .map(|id| {
                self.ledger
                    .revisions(&meshlet_domain::NetworkId(id.clone()))
                    .len()
            })
            .sum()
    }
}

/// 网络存在性校验（供其他模块复用；网络不存在 → 404）。
pub fn require_network(state: &MeshState, network_id: &str) -> Result<(), ServiceError> {
    state.network(network_id).map(|_| ())
}

/// 期望项状态收敛结果：状态**发生变化**的路由/映射 id 与新状态（供落库）。
#[derive(Debug, Default, Clone)]
pub struct DesiredStateSettle {
    pub routes: Vec<(String, DesiredStateStatus)>,
    pub aliases: Vec<(String, DesiredStateStatus)>,
}

/// 把一次 apply / rollback 的结论收敛到每条期望项的 `status`
/// （§10.1「DB 写入 ≠ 显示生效」的路由/映射层镜像）。
///
/// - `applied = true`（backend 成功把配置下发到内核）：网关设备 Active 的路由
///   转 `Applied`，其绑定 Alias 同步转 `Applied`——此时这些前缀才真的可被
///   agent 数据面取用（[`meshlet_domain::peer_routes`] 只采纳 `Applied`）；
/// - 网关设备非 Active（无对端可发）或 apply 失败 / 已回滚：转 `Failed`——
///   失败可见，且 agent 计划随之撤下这些前缀，不会继续按未生效配置转发；
/// - 状态未变的不上报（幂等重放不产生无谓落库）。
pub fn settle_desired_state(
    state: &mut MeshState,
    network_id: &str,
    applied: bool,
) -> DesiredStateSettle {
    settle_desired_with_status(
        state,
        network_id,
        if applied {
            DesiredStateStatus::Applied
        } else {
            DesiredStateStatus::Failed
        },
    )
}

pub fn settle_desired_with_status(
    state: &mut MeshState,
    network_id: &str,
    status: DesiredStateStatus,
) -> DesiredStateSettle {
    let mut settle = DesiredStateSettle::default();
    // 先在不可变借用下算好每条路由的网关可用性与目标状态，再统一写回。
    let wanted: Vec<(String, bool, DesiredStateStatus)> = state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .map(|r| {
                    let gateway_ready = state
                        .registry
                        .find_by_id(&r.gateway_device_id)
                        .map(|d| d.is_active())
                        .unwrap_or(false);
                    let want = if gateway_ready {
                        status
                    } else {
                        DesiredStateStatus::Failed
                    };
                    (r.id.to_string(), r.status == want, want)
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(routes) = state.lan_routes.get_mut(network_id) {
        for (id, _, want) in &wanted {
            if let Some(route) = routes.iter_mut().find(|r| r.id.to_string() == *id) {
                if route.status != *want {
                    route.status = *want;
                    settle.routes.push((id.clone(), *want));
                }
            }
        }
    }
    // Alias 随其绑定路由：路由已生效则映射生效，否则映射 `Failed`（翻译未下发）。
    let route_status: HashMap<String, DesiredStateStatus> = state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .map(|r| (r.id.to_string(), r.status))
                .collect()
        })
        .unwrap_or_default();
    if let Some(aliases) = state.aliases.get_mut(network_id) {
        for alias in aliases.iter_mut() {
            let want = match route_status.get(&alias.lan_route_id.to_string()) {
                Some(status) => *status,
                _ => DesiredStateStatus::Failed,
            };
            if alias.status != want {
                alias.status = want;
                settle.aliases.push((alias.id.to_string(), want));
            }
        }
    }
    settle
}

impl Default for MeshState {
    fn default() -> Self {
        Self::new(meshlet_domain::PresenceThresholds::default())
    }
}
