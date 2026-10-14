//! 控制平面服务层（[存档 §11.2](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)）：
//! 网络/邀请/设备加入的内存实现 + HTTP DTO。
//!
//! 状态存于 `Mutex<MeshState>`（请求路径的唯一事实源）；每次变更由 handler
//! 同步镜像到 SQLite（[`crate::persist`]，§17.3），启动时从 DB 重建。邀请
//! 兑换等关键路径全程持锁，闭合 §11.3 的并发竞态。

use meshlet_api_types::ErrorResponse;
use meshlet_domain::{
    generate_token, DesiredStateStatus, Device, DeviceId, DeviceRegistry, Invite, Ipam, Ipv4Cidr,
    LanRoute, LanRouteId, Network, Platform, RegistryError, ReturnPathMode, RouteMode, Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

/// 当前 UTC 时间（ISO-8601 `Z`），与领域层 `Timestamp` 格式一致。
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// HTTP DTO
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct NetworkView {
    pub id: String,
    pub name: String,
    pub overlay_cidr: String,
    pub status: String,
    pub created_at: String,
    /// 当前期望修订号（ADR-009：配置修改类响应必须携带版本与应用状态）。
    pub revision_id: u64,
    /// 当前修订的应用状态：`pending`/`applying`/`applied`/`failed`/
    /// `rollback_pending`/`rolled_back`（ADR-009 状态机）。
    pub apply_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceView {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub virtual_ipv4: Ipv4Addr,
    pub public_key: String,
    pub fingerprint: String,
    pub status: String,
    pub created_at: String,
    /// 最后证据时间（加入/心跳/上报到达时刻）——控制台「最后在线时间」。
    pub last_seen_at: Option<String>,
    /// 在线状态判定：`online` / `tunnel_only` / `offline`（数据来源见下）。
    pub online_state: String,
    /// 状态的数据来源：`agent_report` / `handshake` / `enrollment` / `none`（§12.2）。
    pub presence_source: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateNetworkRequest {
    pub name: String,
    pub overlay_cidr: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateInviteRequest {
    /// ISO-8601 过期时刻；缺省表示永不过期。
    pub expires_at: Option<String>,
    /// 使用次数上限；缺省 1（一次性邀请，ADR-010）。
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateInviteResponse {
    pub invite_id: String,
    /// 原始 Token **仅此一次**返回；服务端只存 SHA-256 摘要（§11.3）。
    pub token: String,
    pub expires_at: Option<String>,
}

/// 加入请求：**不允许携带任何私钥字段**（`deny_unknown_fields` 强制，
/// 客户端尝试发送私钥会被 400 拒绝——私钥不出客户端，§11.2）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub invite_token: String,
    pub device_name: String,
    pub public_key: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollResponse {
    pub device_id: String,
    pub network_id: String,
    pub virtual_ipv4: Ipv4Addr,
    pub fingerprint: String,
    /// Agent API 凭证（Bearer）：**仅此一次**返回，服务端只存 SHA-256 摘要。
    pub agent_token: String,
    /// 本次变更生成的期望配置修订号（ADR-009）。
    pub revision_id: u64,
    /// 该修订的应用状态（新修订恒为 `pending`——DB 写入 ≠ 生效）。
    pub apply_status: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateRouteRequest {
    /// 网关设备（必须是本网络的 Active 设备，ADR-005）。
    pub gateway_device_id: String,
    pub destination_cidr: String,
    /// `direct`（缺省）或 `alias`。
    pub route_mode: Option<String>,
    /// `dual_route` 或 `controlled_snat`（必选，ADR-005）。
    pub return_path_mode: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteView {
    pub id: String,
    pub network_id: String,
    pub gateway_device_id: String,
    pub destination_cidr: String,
    pub route_mode: String,
    pub return_path_mode: String,
    /// `pending` / `applied` / `failed`（路由自身的期望态）。
    pub status: String,
    /// 本次变更生成的期望配置修订号（ADR-009）。
    pub revision_id: u64,
    pub apply_status: String,
}

/// 修订引用（撤销设备等操作返回；契约 `RevisionRef`）。
#[derive(Debug, Clone, Serialize)]
pub struct RevisionRef {
    pub revision_id: u64,
    pub apply_status: String,
}

// ---------------------------------------------------------------------------
// 服务错误 → API 错误码
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, thiserror::Error)]
pub enum ServiceError {
    #[error("network {0} not found")]
    NetworkNotFound(String),
    #[error("invite {0} not found")]
    InviteNotFound(String),
    #[error("device {0} not found")]
    DeviceNotFound(String),
    #[error("revision {0} not found")]
    RevisionNotFound(String),
    #[error("route {0} not found")]
    RouteNotFound(String),
    #[error("invalid invite token")]
    InvalidInviteToken,
    #[error("{0}")]
    InvalidCidr(String),
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    Conflict(String),
    /// 路由冲突（§17.2「路由冲突数」指标口径）：仅「目的网段与 overlay 或
    /// 既有 LAN 路由重叠」时使用——与设备未激活等其它 409 区分，保证指标
    /// 不把非冲突的拒绝计进来。
    #[error("{0}")]
    RouteConflict(String),
    #[error("{0}")]
    Internal(String),
}

impl ServiceError {
    /// 转为统一错误响应（结构见 docs/architecture/api-contract.md）。
    pub fn into_response(self) -> ErrorResponse {
        match self {
            ServiceError::NetworkNotFound(_)
            | ServiceError::InviteNotFound(_)
            | ServiceError::DeviceNotFound(_)
            | ServiceError::RouteNotFound(_)
            | ServiceError::RevisionNotFound(_) => {
                ErrorResponse::new(meshlet_api_types::ErrorCode::NotFound, self.to_string())
            }
            ServiceError::InvalidInviteToken => ErrorResponse::new(
                meshlet_api_types::ErrorCode::NotFound,
                "invite token is not valid",
            ),
            ServiceError::InvalidCidr(_) | ServiceError::InvalidInput(_) => ErrorResponse::new(
                meshlet_api_types::ErrorCode::ValidationFailed,
                self.to_string(),
            ),
            ServiceError::Conflict(_) | ServiceError::RouteConflict(_) => {
                ErrorResponse::new(meshlet_api_types::ErrorCode::Conflict, self.to_string())
            }
            ServiceError::Internal(_) => {
                ErrorResponse::new(meshlet_api_types::ErrorCode::Internal, self.to_string())
            }
        }
    }
}

impl From<RegistryError> for ServiceError {
    fn from(e: RegistryError) -> Self {
        match e {
            RegistryError::DuplicateVirtualIp(ip) => {
                ServiceError::Conflict(format!("virtual ip {ip} already in use"))
            }
            RegistryError::DuplicateName(name) => {
                ServiceError::Conflict(format!("device name {name:?} already in use"))
            }
        }
    }
}

impl ServiceError {
    /// 版本簿记错误 → API 错误（未知修订 404；非法跃迁与被取代的回滚 409，
    /// §10.4 乐观并发）。
    pub fn from_ledger(e: meshlet_domain::LedgerError) -> Self {
        match e {
            meshlet_domain::LedgerError::RevisionNotFound {
                network_id,
                revision,
            } => ServiceError::RevisionNotFound(format!("{revision} in network {network_id}")),
            meshlet_domain::LedgerError::IllegalTransition(err) => {
                ServiceError::Conflict(err.to_string())
            }
            meshlet_domain::LedgerError::SupersededRevision {
                network_id,
                revision,
                latest,
            } => ServiceError::Conflict(format!(
                "revision {revision} in network {network_id} is superseded by revision \
                 {latest}; roll back revision {latest} or record a new revision"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

pub struct MeshState {
    networks: HashMap<String, Network>,
    /// 邀请按 Token 摘要索引（§11.3：兑换时以摘要定位，不暴露原始 Token）。
    invites: HashMap<String, Invite>,
    ipams: HashMap<String, Ipam>,
    /// 设备注册表（`pub(crate)`：agent 心跳需读设备网络归属）。
    pub(crate) registry: DeviceRegistry,
    /// LAN 路由（Phase 3 控制面：增删先落状态，应用待 backend，ADR-005）。
    pub(crate) lan_routes: HashMap<String, Vec<LanRoute>>,
    /// 路由 id 序列（全局单调，删除不复用）。
    route_seq: u64,
    /// 在线判定窗口（§12.4；默认值见 [meshlet_domain::PresenceThresholds]）。
    presence_thresholds: meshlet_domain::PresenceThresholds,
    /// 期望配置修订簿记（ADR-009 状态机，§10）。
    pub(crate) ledger: meshlet_domain::ConfigLedger,
}

impl MeshState {
    pub fn new(presence_thresholds: meshlet_domain::PresenceThresholds) -> Self {
        Self {
            networks: HashMap::new(),
            invites: HashMap::new(),
            ipams: HashMap::new(),
            registry: DeviceRegistry::new(),
            lan_routes: HashMap::new(),
            route_seq: 0,
            presence_thresholds,
            ledger: meshlet_domain::ConfigLedger::new(),
        }
    }

    fn network(&self, id: &str) -> Result<&Network, ServiceError> {
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

/// 记录一次期望配置修订（§10.1/§10.4）：对当前网络配置取哈希并写入簿记，
/// 版本号网络内单调递增，初始状态 `Pending`——此时只完成了 DB 写入，
/// **尚未**应用到实际网络环境。
fn record_revision(state: &mut MeshState, network_id: &str) -> Result<u64, ServiceError> {
    let overlay = state.network(network_id)?.overlay_cidr;
    let ipam = state
        .ipams
        .get(network_id)
        .ok_or_else(|| ServiceError::Internal("ipam missing".to_string()))?;
    let devices: Vec<Device> = state
        .registry
        .devices()
        .iter()
        .filter(|d| d.network_id.to_string() == network_id)
        .cloned()
        .collect();
    let routes = state
        .lan_routes
        .get(network_id)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let hash = meshlet_domain::desired_config_hash(&overlay, ipam.hub_address(), &devices, routes);
    Ok(state.ledger.record(
        &meshlet_domain::NetworkId(network_id.to_string()),
        hash,
        now(),
    ))
}

impl Default for MeshState {
    fn default() -> Self {
        Self::new(meshlet_domain::PresenceThresholds::default())
    }
}

pub type SharedState = Arc<Mutex<MeshState>>;

// ---------------------------------------------------------------------------
// 操作
// ---------------------------------------------------------------------------

pub fn create_network(
    state: &mut MeshState,
    req: CreateNetworkRequest,
) -> Result<NetworkView, ServiceError> {
    let overlay: Ipv4Cidr = req
        .overlay_cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.overlay_cidr)))?;
    if req.name.trim().is_empty() {
        return Err(ServiceError::InvalidInput("name must not be empty".into()));
    }
    if state.networks.values().any(|n| n.overlay_cidr == overlay) {
        return Err(ServiceError::Conflict(format!(
            "overlay {overlay} already used by another network"
        )));
    }
    let id = format!("net-{}", state.networks.len() + 1);
    let ts = now();
    let network = Network::new(
        meshlet_domain::NetworkId(id.clone()),
        req.name.clone(),
        overlay,
        ts.clone(),
    );
    // IPAM：hub 取第一个可用地址（ADR-004），客户端从第二个起分配。
    let hub = overlay
        .iter_usable()
        .next()
        .expect("overlay has at least one usable address");
    let ipam = Ipam::new(overlay, hub).map_err(|e| ServiceError::Internal(e.to_string()))?;
    state.networks.insert(id.clone(), network);
    state.ipams.insert(id.clone(), ipam);
    // 记录初始期望配置修订（§10.1：DB 写入 ≠ 生效，初始修订为 Pending）。
    record_revision(state, &id)?;
    Ok(to_network_view(state, state.network(&id).unwrap()))
}

pub fn list_networks(state: &MeshState) -> Vec<NetworkView> {
    state
        .networks
        .values()
        .map(|n| to_network_view(state, n))
        .collect()
}

pub fn create_invite(
    state: &mut MeshState,
    network_id: &str,
    req: CreateInviteRequest,
) -> Result<CreateInviteResponse, ServiceError> {
    state.network(network_id)?; // 网络必须存在
    let max_uses = req.max_uses.unwrap_or(1);
    if max_uses == 0 {
        return Err(ServiceError::InvalidInput(
            "max_uses must be at least 1".into(),
        ));
    }
    let ts = now();
    let raw = generate_token();
    let invite = Invite::new(
        meshlet_domain::InviteId(format!("inv-{}", state.invites.len() + 1)),
        meshlet_domain::NetworkId(network_id.to_string()),
        &raw,
        req.expires_at.clone(),
        max_uses,
        ts.clone(),
    );
    let view = CreateInviteResponse {
        invite_id: invite.id.to_string(),
        token: raw,
        expires_at: req.expires_at,
    };
    // 只存摘要（§11.3）：索引键即 token_hash，原始 Token 不落地。
    state.invites.insert(invite.token_hash.clone(), invite);
    Ok(view)
}

pub fn revoke_invite(
    state: &mut MeshState,
    network_id: &str,
    invite_id: &str,
) -> Result<(), ServiceError> {
    state.network(network_id)?;
    let target = state
        .invites
        .values_mut()
        .find(|i| i.id.to_string() == invite_id)
        .ok_or_else(|| ServiceError::InviteNotFound(invite_id.to_string()))?;
    target
        .revoke(now())
        .map_err(|e| ServiceError::Conflict(e.to_string()))
}

/// 设备加入（§11.2 第 3-9 步的控制平面部分）。
/// 私钥不出客户端：本函数只接收公钥；服务端登记公钥 + 指纹、分配虚拟 IP。
pub fn enroll(state: &mut MeshState, req: EnrollRequest) -> Result<EnrollResponse, ServiceError> {
    let platform = match req.platform.as_str() {
        "linux" => Platform::Linux,
        "windows" => Platform::Windows,
        other => {
            return Err(ServiceError::InvalidInput(format!(
                "unsupported platform {other:?}"
            )));
        }
    };
    if req.device_name.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "device_name must not be empty".into(),
        ));
    }
    if req.public_key.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "public_key must not be empty".into(),
        ));
    }

    // 以摘要定位邀请并兑换（持锁原子完成，闭合并发竞态）。
    let invite = state
        .invites
        .get_mut(&meshlet_domain::token_hash(&req.invite_token))
        .ok_or(ServiceError::InvalidInviteToken)?;
    let network_id = invite.network_id.to_string();
    invite
        .redeem(&req.invite_token, now())
        .map_err(|e| match e {
            meshlet_domain::InviteError::InvalidToken => ServiceError::InvalidInviteToken,
            other => ServiceError::InvalidInput(other.to_string()),
        })?;

    let ipam = state
        .ipams
        .get_mut(&network_id)
        .ok_or_else(|| ServiceError::NetworkNotFound(network_id.clone()))?;
    let virtual_ip = ipam
        .allocate()
        .map_err(|e| ServiceError::Conflict(e.to_string()))?;

    let ts = now();
    let device = Device {
        id: meshlet_domain::DeviceId(format!("dev-{}", state.registry.devices().len() + 1)),
        network_id: meshlet_domain::NetworkId(network_id.clone()),
        name: req.device_name.clone(),
        virtual_ipv4: virtual_ip,
        public_key: req.public_key.clone(),
        platform,
        status: meshlet_domain::DeviceStatus::Active,
        last_seen_at: Some(ts.clone()),
        last_handshake_at: None,
        last_report_at: None,
        created_at: ts.clone(),
        revoked_at: None,
    };
    state.registry.add(device.clone())?;
    // 新设备改变期望配置：记录新修订（版本号网络内递增，§10.4）。
    let revision_id = record_revision(state, &network_id)?;

    // 指纹 = 公钥 SHA-256；服务端不存任何私钥侧材料。
    let fingerprint = fingerprint_of(&req.public_key);
    Ok(EnrollResponse {
        device_id: device.id.to_string(),
        network_id,
        virtual_ipv4: virtual_ip,
        fingerprint,
        agent_token: String::new(), // 由 handler 用 AgentTokenStore 签发后回填
        revision_id,
        apply_status: meshlet_domain::ApplyStatus::Pending.as_str().to_string(),
    })
}

/// 记录一次 agent 心跳/上报（§14.1）：定位设备、更新 `last_report_at`（到达
/// 时刻）、可选的 `last_handshake_at`（agent 本地 `wg show` 读数）与
/// `last_seen_at`，返回当前在线判定（状态 + 数据来源）。
pub fn record_agent_report(
    state: &mut MeshState,
    device_id: &DeviceId,
    last_handshake_at: Option<String>,
    now: Timestamp,
) -> Result<meshlet_domain::Presence, ServiceError> {
    let device = state
        .registry
        .find_by_id_mut(device_id)
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    apply_agent_report(device, last_handshake_at, &now);
    Ok(evaluate_presence(device, &now, &state.presence_thresholds))
}

/// 把一次上报写到设备记录（内部共享）。
fn apply_agent_report(device: &mut Device, last_handshake_at: Option<String>, now: &Timestamp) {
    if let Some(ts) = last_handshake_at {
        device.last_handshake_at = Some(ts);
    }
    device.last_report_at = Some(now.clone());
    device.last_seen_at = Some(now.clone());
}

/// 在线判定（域层纯函数；判定时刻 = 当前时间，阈值来自状态）。
pub fn evaluate_presence(
    device: &Device,
    now: &Timestamp,
    thresholds: &meshlet_domain::PresenceThresholds,
) -> meshlet_domain::Presence {
    meshlet_domain::evaluate(
        meshlet_domain::PresenceInput {
            last_handshake_at: device.last_handshake_at.as_deref(),
            last_report_at: device.last_report_at.as_deref(),
            enrolled_at: Some(device.created_at.as_str()),
        },
        now,
        thresholds,
    )
}

pub fn list_devices(state: &MeshState, network_id: &str) -> Result<Vec<DeviceView>, ServiceError> {
    state.network(network_id)?;
    let now: Timestamp = now();
    Ok(state
        .registry
        .devices()
        .iter()
        .filter(|d| d.network_id.to_string() == network_id)
        .map(|d| to_device_view(d, &now, &state.presence_thresholds))
        .collect())
}

/// 数据面证据量规快照（§17.2 指标 1/2/3/7 的数据源）：抓取时从 `MeshState`
/// **现算**，不存静态值。调用方持 mesh 锁；渲染（字符串拼接）在锁外做。
///
/// 「近期握手」= 握手落在 `handshake_window` 内（隧道证据，与「在线」的
/// agent 上报证据是两条独立来源——单看任一都会误判，见
/// `docs/architecture/observability.md` 组合判读）。
pub fn gauge_snapshot(state: &MeshState) -> crate::metrics::GaugeSnapshot {
    let now: Timestamp = now();
    let mut devices_online = 0u64;
    let mut devices_active = 0u64;
    let mut devices_with_recent_handshake = 0u64;
    let mut last_handshake_ts: i64 = 0;
    for device in state.registry.devices() {
        if device.is_active() {
            devices_active += 1;
        }
        let presence = evaluate_presence(device, &now, &state.presence_thresholds);
        if presence.state == meshlet_domain::presence::PresenceState::Online {
            devices_online += 1;
        }
        if let Some(ts) = device.last_handshake_at.as_deref() {
            if meshlet_domain::presence::fresh(ts, &now, state.presence_thresholds.handshake_window)
            {
                devices_with_recent_handshake += 1;
            }
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                last_handshake_ts = last_handshake_ts.max(dt.timestamp());
            }
        }
    }
    crate::metrics::GaugeSnapshot {
        devices_online,
        devices_active,
        devices_with_recent_handshake,
        last_handshake_timestamp_seconds: last_handshake_ts,
        // 接口状态（§17.2 第 7 项）：至少一台设备有近期握手证据即视为数据面
        // 接口在；主机侧接口读数待数据面 backend 落地后并入（agent 侧证据
        // 先到）。
        interface_up: u8::from(devices_with_recent_handshake > 0),
        // Alias 应用状态（§17.2 第 8 项）：Phase 4 未落地，无 Alias 映射可
        // 应用——恒 0 表示「无东西可应用」，**不是**「健康」。
        alias_apply_status: 0,
    }
}

/// 发布一条 LAN 路由（ADR-005）。路由属于期望配置：创建即记录新修订（§10.1）。
pub fn create_route(
    state: &mut MeshState,
    network_id: &str,
    req: CreateRouteRequest,
) -> Result<RouteView, ServiceError> {
    state.network(network_id)?;
    let destination: Ipv4Cidr = req
        .destination_cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.destination_cidr)))?;
    let route_mode = match req.route_mode.as_deref() {
        None | Some("direct") => RouteMode::Direct,
        Some("alias") => RouteMode::Alias,
        Some(other) => {
            return Err(ServiceError::InvalidInput(format!(
                "route_mode must be \"direct\" or \"alias\", got {other:?}"
            )));
        }
    };
    let return_path_mode = ReturnPathMode::parse(&req.return_path_mode).ok_or_else(|| {
        ServiceError::InvalidInput(format!(
            "return_path_mode must be \"dual_route\" or \"controlled_snat\", got {:?}",
            req.return_path_mode
        ))
    })?;

    // overlay 自身/其子网不是 LAN 目的（它们走 overlay 内部转发）。
    let overlay = state.network(network_id)?.overlay_cidr;
    if destination.overlaps(&overlay) {
        return Err(ServiceError::RouteConflict(format!(
            "destination {destination} overlaps overlay {overlay}"
        )));
    }
    // 同网络目的网段互斥（重叠即冲突，不做超集合并）。拒绝发生在任何状态
    // 变更之前：既有路由绝不被覆盖（§8.3 不静默）。错误消息点名冲突对端
    // （既有路由 id + 网段），控制台据此展示「跟哪条路由冲突」。
    if let Some(existing) = state
        .lan_routes
        .get(network_id)
        .and_then(|routes| {
            routes
                .iter()
                .find(|r| r.destination_cidr.overlaps(&destination))
        })
        .cloned()
    {
        return Err(ServiceError::RouteConflict(format!(
            "destination {destination} overlaps existing route {} ({}) in network {network_id}",
            existing.id, existing.destination_cidr
        )));
    }

    // 网关必须是本网络的 Active 设备。
    let gateway = DeviceId(req.gateway_device_id.clone());
    let device = state
        .registry
        .find_by_id(&gateway)
        .ok_or_else(|| ServiceError::DeviceNotFound(req.gateway_device_id.clone()))?;
    if device.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(req.gateway_device_id));
    }
    if !device.is_active() {
        return Err(ServiceError::Conflict(format!(
            "gateway device {} is not active",
            device.id
        )));
    }

    state.route_seq += 1;
    let route = LanRoute {
        id: LanRouteId(format!("rt-{}", state.route_seq)),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        gateway_device_id: gateway,
        destination_cidr: destination,
        route_mode,
        return_path_mode,
        status: DesiredStateStatus::Pending,
        created_at: now(),
    };
    state
        .lan_routes
        .entry(network_id.to_string())
        .or_default()
        .push(route.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_route_view(state, network_id, &route, revision_id))
}

pub fn list_routes(state: &MeshState, network_id: &str) -> Result<Vec<RouteView>, ServiceError> {
    state.network(network_id)?;
    let (revision_id, apply_status) = current_revision_ref(state, network_id);
    Ok(state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .map(|r| RouteView {
                    id: r.id.to_string(),
                    network_id: r.network_id.to_string(),
                    gateway_device_id: r.gateway_device_id.to_string(),
                    destination_cidr: r.destination_cidr.to_string(),
                    route_mode: r.route_mode.as_str().to_string(),
                    return_path_mode: r.return_path_mode.as_str().to_string(),
                    status: r.status.as_str().to_string(),
                    revision_id,
                    apply_status: apply_status.clone(),
                })
                .collect()
        })
        .unwrap_or_default())
}

pub fn get_route(
    state: &MeshState,
    network_id: &str,
    route_id: &str,
) -> Result<RouteView, ServiceError> {
    state.network(network_id)?;
    let route = state
        .lan_routes
        .get(network_id)
        .and_then(|routes| routes.iter().find(|r| r.id.to_string() == route_id))
        .ok_or_else(|| {
            ServiceError::RouteNotFound(format!("{route_id} in network {network_id}"))
        })?;
    let (revision_id, apply_status) = current_revision_ref(state, network_id);
    Ok(RouteView {
        id: route.id.to_string(),
        network_id: route.network_id.to_string(),
        gateway_device_id: route.gateway_device_id.to_string(),
        destination_cidr: route.destination_cidr.to_string(),
        route_mode: route.route_mode.as_str().to_string(),
        return_path_mode: route.return_path_mode.as_str().to_string(),
        status: route.status.as_str().to_string(),
        revision_id,
        apply_status,
    })
}

/// 删除一条 LAN 路由。删除也是期望配置变更：记录新修订。
pub fn delete_route(
    state: &mut MeshState,
    network_id: &str,
    route_id: &str,
) -> Result<(), ServiceError> {
    state.network(network_id)?;
    let routes = state.lan_routes.get_mut(network_id).ok_or_else(|| {
        ServiceError::RouteNotFound(format!("{route_id} in network {network_id}"))
    })?;
    let before = routes.len();
    routes.retain(|r| r.id.to_string() != route_id);
    if routes.len() == before {
        return Err(ServiceError::RouteNotFound(format!(
            "{route_id} in network {network_id}"
        )));
    }
    record_revision(state, network_id)?;
    Ok(())
}

/// 撤销设备（peer 撤销，§11.5 控制面部分）：状态转 `Revoked`（下线）并记录
/// 新修订——被撤销设备不入期望配置哈希。agent 凭证失效由 handler 在锁外完成。
pub fn revoke_device(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<RevisionRef, ServiceError> {
    state.network(network_id)?;
    let revoked_id = {
        let device = state
            .registry
            .find_by_id_mut(&DeviceId(device_id.to_string()))
            .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
        if device.network_id.to_string() != network_id {
            return Err(ServiceError::DeviceNotFound(device_id.to_string()));
        }
        device
            .revoke(now())
            .map_err(|e| ServiceError::Conflict(e.to_string()))?;
        device.id.clone()
    };
    // §11.5：撤销必须移除该设备发布的 LAN 路由，避免期望配置里留下指向
    // 已撤销 Peer 的路由（AllowedIPs 推导会把它当成远端网段继续下发）。
    if let Some(routes) = state.lan_routes.get_mut(network_id) {
        routes.retain(|r| r.gateway_device_id != revoked_id);
    }
    let revision_id = record_revision(state, network_id)?;
    Ok(RevisionRef {
        revision_id,
        apply_status: meshlet_domain::ApplyStatus::Pending.as_str().to_string(),
    })
}

/// 网络当前修订引用（网络视图语义复用：无修订时 0/`none`）。
fn current_revision_ref(state: &MeshState, network_id: &str) -> (u64, String) {
    state
        .ledger
        .current(&meshlet_domain::NetworkId(network_id.to_string()))
        .map(|r| (r.revision, r.apply_status.as_str().to_string()))
        .unwrap_or((0, "none".to_string()))
}

fn to_route_view(
    state: &MeshState,
    network_id: &str,
    route: &LanRoute,
    revision_id: u64,
) -> RouteView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    RouteView {
        id: route.id.to_string(),
        network_id: route.network_id.to_string(),
        gateway_device_id: route.gateway_device_id.to_string(),
        destination_cidr: route.destination_cidr.to_string(),
        route_mode: route.route_mode.as_str().to_string(),
        return_path_mode: route.return_path_mode.as_str().to_string(),
        status: route.status.as_str().to_string(),
        revision_id,
        apply_status,
    }
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

fn fingerprint_of(public_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn to_network_view(state: &MeshState, n: &Network) -> NetworkView {
    // 当前期望修订 = 最新一个未回滚的修订（ADR-009：显示以应用状态为准）。
    let current = state
        .ledger
        .current(&meshlet_domain::NetworkId(n.id.0.clone()));
    NetworkView {
        id: n.id.to_string(),
        name: n.name.clone(),
        overlay_cidr: n.overlay_cidr.to_string(),
        status: match n.status {
            meshlet_domain::NetworkStatus::Active => "active",
            meshlet_domain::NetworkStatus::Deleting => "deleting",
        }
        .to_string(),
        created_at: n.created_at.clone(),
        revision_id: current.map(|r| r.revision).unwrap_or(0),
        apply_status: current
            .map(|r| r.apply_status.as_str().to_string())
            .unwrap_or_else(|| "none".to_string()),
    }
}

fn to_device_view(
    d: &Device,
    now: &Timestamp,
    thresholds: &meshlet_domain::PresenceThresholds,
) -> DeviceView {
    let presence = evaluate_presence(d, now, thresholds);
    DeviceView {
        id: d.id.to_string(),
        network_id: d.network_id.to_string(),
        name: d.name.clone(),
        virtual_ipv4: d.virtual_ipv4,
        public_key: d.public_key.clone(),
        fingerprint: fingerprint_of(&d.public_key),
        status: match d.status {
            meshlet_domain::DeviceStatus::Pending => "pending",
            meshlet_domain::DeviceStatus::Active => "active",
            meshlet_domain::DeviceStatus::Revoked => "revoked",
        }
        .to_string(),
        created_at: d.created_at.clone(),
        last_seen_at: d.last_seen_at.clone(),
        online_state: presence.state.as_str().to_string(),
        presence_source: presence.source.as_str().to_string(),
    }
}
