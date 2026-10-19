//! 控制平面服务层（[存档 §11.2](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)）：
//! 网络/邀请/设备加入的内存实现 + HTTP DTO。
//!
//! 状态存于 `Mutex<MeshState>`（请求路径的唯一事实源）；每次变更由 handler
//! 同步镜像到 SQLite（[`crate::persist`]，§17.3），启动时从 DB 重建。邀请
//! 兑换等关键路径全程持锁，闭合 §11.3 的并发竞态。

use meshlet_api_types::ErrorResponse;
use meshlet_domain::{
    generate_token, token_hash, AliasError, AliasMapping, AliasMappingId, BootstrapToken,
    DataplaneEvidence, DesiredStateStatus, Device, DeviceId, DeviceRegistration, DeviceRegistry,
    Invite, Ipam, Ipv4Cidr, LanRoute, LanRouteId, Network, Platform, RegistryError, ReturnPathMode,
    RouteMode, Segment, SegmentGrant, Timestamp, TranslationMode,
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
    /// 批准时刻：自举注册路径 = 审批时刻（created_at 是申请时刻）；邀请入会
    /// 路径为 `None`（两时刻同值，无需重复展示）。控制台据此区分「刚批准」
    /// 与「已运行一段时间」。
    pub approved_at: Option<String>,
    /// 最后证据时间（加入/心跳/上报到达时刻）——控制台「最后在线时间」。
    pub last_seen_at: Option<String>,
    /// 在线状态判定：`online` / `tunnel_only` / `offline`（数据来源见下）。
    pub online_state: String,
    /// 状态的数据来源：`agent_report` / `handshake` / `enrollment` / `none`（§12.2）。
    pub presence_source: String,
    /// 最近一次心跳回传的数据面实测证据（§7.5）；`None` = 尚无上报。
    pub dataplane_evidence: Option<DataplaneEvidence>,
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

// ---------------------------------------------------------------------------
// 设备自举注册（ZeroTier 式：自举码注册 → Pending → 控制中心审批/拒绝）
// ---------------------------------------------------------------------------

/// 自举码（bootstrap token）：长期、可复用的注册入口凭据，区别于一次性邀请。
#[derive(Debug, Deserialize)]
pub struct CreateBootstrapTokenRequest {
    /// 使用次数上限；缺省不限次（自举码是长期入口，不是单次邀请）。
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateBootstrapTokenResponse {
    pub token_id: String,
    /// 原始自举码 **仅此一次**返回；服务端只存 SHA-256 摘要（§11.3）。
    pub token: String,
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapTokenView {
    pub id: String,
    pub network_id: String,
    pub max_uses: Option<u32>,
    pub used_count: u32,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

/// 设备自举注册请求（`POST /device-registrations`，公开端点）。
/// `deny_unknown_fields` 同 [EnrollRequest]：客户端尝试发送私钥即被 400 拒绝
/// （私钥不出客户端，§11.2）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterDeviceRequest {
    pub bootstrap_token: String,
    pub device_name: String,
    pub public_key: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterDeviceResponse {
    pub device_id: String,
    pub network_id: String,
    /// 恒为 `pending`（控制中心批准前不参与数据面）。
    pub status: String,
    /// Agent API 凭证（Bearer）：**仅此一次**返回。Pending 期可心跳上报
    /// （证明 agent 活着），但拉不到计划——批准前不进数据面。
    pub agent_token: String,
    pub requested_at: String,
}

/// 待审批申请视图（控制台设备页与设备列表共用；`status = "pending"`）。
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationView {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub platform: String,
    pub public_key: String,
    pub requested_at: String,
    pub last_report_at: Option<String>,
    /// agent 心跳回传的数据面证据（Pending 设备尚无 `devices` 行，证据只在这里）。
    pub dataplane_evidence: Option<DataplaneEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApproveRegistrationResponse {
    pub device_id: String,
    pub network_id: String,
    /// 批准时刻才分配的 overlay 地址（ADR-004 顺序分配）。
    pub virtual_ipv4: Ipv4Addr,
    /// 设备公钥指纹（SHA-256；服务端不存私钥侧材料）。
    pub fingerprint: String,
    /// **不含 agent 凭证**：注册时签发的凭证绑定设备 id（批准沿用同一 id），
    /// 设备端继续使用原凭证拉计划；轮换只会让无人能送达的新凭证作废设备。
    pub revision_id: u64,
    pub apply_status: String,
    pub approved_at: String,
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

#[derive(Debug, Deserialize)]
pub struct CreateAliasRequest {
    /// 绑定的 LAN Route（必须存在且 `route_mode = "alias"`，ADR-006 单元语义）。
    pub lan_route_id: String,
    pub alias_cidr: String,
    /// `dnat_snat`（缺省）或 `dnat_only`。
    pub translation_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateHostForwardRequest {
    /// 本网络 Active 网关设备：流量经它进入目标主机所在 LAN。
    pub gateway_device_id: String,
    /// LAN 内真实主机地址（不是 CIDR；Host Forward 会在服务端转成 /32）。
    pub target_ipv4: Ipv4Addr,
    /// 虚拟主机地址（必须是与 target 等长的 /32，且不落在 overlay）。
    pub alias_ipv4: Ipv4Addr,
    /// `dnat_snat`（缺省，兼容无返回路由的 LAN）或 `dnat_only`。
    pub translation_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostForwardView {
    pub id: String,
    pub network_id: String,
    pub gateway_device_id: String,
    pub target_ipv4: String,
    pub alias_ipv4: String,
    pub translation_mode: String,
    pub status: String,
    pub revision_id: u64,
    pub apply_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AliasView {
    pub id: String,
    pub network_id: String,
    pub lan_route_id: String,
    pub alias_cidr: String,
    /// 真实目标网段 = 绑定路由的目的网段（服务端推导，客户端不可指定）。
    pub target_cidr: String,
    pub translation_mode: String,
    /// `pending` / `applied` / `failed`（映射自身的期望态）。
    pub status: String,
    /// 本次变更生成的期望配置修订号（ADR-009）。
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
    #[error("alias {0} not found")]
    AliasNotFound(String),
    /// 诊断从未运行过（§12.7：GET 返回最近一次运行，没有就是没有，不现算
    /// 也不假称有）。消息点名 POST 触发方式。
    #[error("{0}")]
    DiagnosticsNotRun(String),
    #[error("invalid invite token")]
    InvalidInviteToken,
    /// 设备出示的自举码无效/已撤销/已耗尽（401：凭据问题，非资源缺失——
    /// 管理侧按 id 撤销时才走 `BootstrapTokenNotFound` 404）。
    #[error("invalid bootstrap token")]
    InvalidBootstrapToken,
    #[error("bootstrap token {0} not found")]
    BootstrapTokenNotFound(String),
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
            | ServiceError::BootstrapTokenNotFound(_)
            | ServiceError::DeviceNotFound(_)
            | ServiceError::RouteNotFound(_)
            | ServiceError::AliasNotFound(_)
            | ServiceError::RevisionNotFound(_)
            | ServiceError::DiagnosticsNotRun(_) => {
                ErrorResponse::new(meshlet_api_types::ErrorCode::NotFound, self.to_string())
            }
            ServiceError::InvalidInviteToken => ErrorResponse::new(
                meshlet_api_types::ErrorCode::NotFound,
                "invite token is not valid",
            ),
            ServiceError::InvalidBootstrapToken => ErrorResponse::new(
                meshlet_api_types::ErrorCode::Unauthorized,
                "bootstrap token is not valid",
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

#[derive(Clone)]
pub struct MeshState {
    pub(crate) deployments: HashMap<String, crate::revision::Deployment>,
    networks: HashMap<String, Network>,
    /// 邀请按 Token 摘要索引（§11.3：兑换时以摘要定位，不暴露原始 Token）。
    invites: HashMap<String, Invite>,
    ipams: HashMap<String, Ipam>,
    /// 设备注册表（`pub(crate)`：agent 心跳需读设备网络归属）。
    pub(crate) registry: DeviceRegistry,
    /// LAN 路由（Phase 3 控制面：增删先落状态，应用待 backend，ADR-005）。
    pub(crate) lan_routes: HashMap<String, Vec<LanRoute>>,
    /// Alias 映射（Phase 4 控制面：等长前缀一对一，ADR-006；NAT 规则的
    /// 所有权归属——删除即整单元清理（alias + 绑定路由），内核规则由修订
    /// apply 交 backend 执行）。
    pub(crate) aliases: HashMap<String, Vec<AliasMapping>>,
    /// Segment trust groups (ADR-012), restored for startup validation and
    /// policy-plan work that follows.
    segments: HashMap<String, Vec<Segment>>,
    /// Directed segment grants (ADR-012), restored with segments.
    grants: HashMap<String, Vec<SegmentGrant>>,
    /// 路由 id 序列（全局单调，删除不复用）。
    route_seq: u64,
    /// 在线判定窗口（§12.4；默认值见 [meshlet_domain::PresenceThresholds]）。
    /// `pub(crate)`：诊断 §12.7 第 4/8 项按同一窗口判握手/上报新鲜度。
    pub(crate) presence_thresholds: meshlet_domain::PresenceThresholds,
    /// 期望配置修订簿记（ADR-009 状态机，§10）。
    pub(crate) ledger: meshlet_domain::ConfigLedger,
    /// 自举码（按 Token 摘要索引；摘要索引纪律同邀请，§11.3）。
    pub(crate) bootstrap_tokens: std::collections::HashMap<String, meshlet_domain::BootstrapToken>,
    /// 自举码序列（`bt-N`，持久化到 `mesh_meta`，已删 id 不复用）。
    bootstrap_seq: u64,
    /// 注册申请序列（`dev-reg-N`，持久化到 `mesh_meta`，已删 id 不复用）。
    /// 前缀与 `bt-` 不冲突，故二者各自单调即可——不用共享计数器。
    /// 待审批申请本体在 `registry` 内（[DeviceRegistry]）。
    registration_seq: u64,
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
            segments: HashMap::new(),
            grants: HashMap::new(),
            route_seq: 0,
            presence_thresholds,
            ledger: meshlet_domain::ConfigLedger::new(),
            bootstrap_tokens: HashMap::new(),
            bootstrap_seq: 0,
            registration_seq: 0,
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

pub(crate) fn settle_desired_with_status(
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
    let aliases = state
        .aliases
        .get(network_id)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let hash = meshlet_domain::desired_config_hash(
        &overlay,
        ipam.hub_address(),
        &devices,
        routes,
        aliases,
        state.segment_grants(network_id),
    );
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

/// Reject ambiguous forwarding prefixes in the shared host routing domain.
pub(crate) fn check_forward_prefix(
    state: &MeshState,
    network_id: &str,
    prefix: Ipv4Cidr,
) -> Result<(), ServiceError> {
    if let Some(n) = state
        .networks
        .values()
        .find(|n| n.id.to_string() != network_id && n.overlay_cidr.overlaps(&prefix))
    {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps network {}",
            n.id
        )));
    }
    if state.lan_routes.iter().any(|(id, routes)| {
        id != network_id
            && routes
                .iter()
                .any(|r| r.route_mode == RouteMode::Direct && r.destination_cidr.overlaps(&prefix))
    }) || state.aliases.iter().any(|(id, aliases)| {
        id != network_id && aliases.iter().any(|a| a.alias_cidr.overlaps(&prefix))
    }) {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps another network's forwarding prefix"
        )));
    }
    Ok(())
}

/// Creation-time validation, including this network. Plan readback uses
/// check_forward_prefix instead so a resource does not conflict with itself.
fn check_new_forward_prefix(
    state: &MeshState,
    network_id: &str,
    prefix: Ipv4Cidr,
) -> Result<(), ServiceError> {
    check_forward_prefix(state, network_id, prefix)?;
    if prefix.overlaps(&state.network(network_id)?.overlay_cidr) {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps overlay"
        )));
    }
    if let Some(route) = state
        .lan_routes
        .get(network_id)
        .into_iter()
        .flatten()
        .find(|r| r.destination_cidr.overlaps(&prefix))
    {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps existing route {} ({})",
            route.id, route.destination_cidr
        )));
    }
    check_local_alias_prefix(state, network_id, prefix)
}

fn check_local_alias_prefix(
    state: &MeshState,
    network_id: &str,
    prefix: Ipv4Cidr,
) -> Result<(), ServiceError> {
    if let Some(alias) = state
        .aliases
        .get(network_id)
        .into_iter()
        .flatten()
        .find(|a| a.alias_cidr.overlaps(&prefix))
    {
        return Err(ServiceError::RouteConflict(format!(
            "prefix {prefix} overlaps existing alias {} ({})",
            alias.id, alias.alias_cidr
        )));
    }
    Ok(())
}

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
    if state
        .networks
        .values()
        .any(|n| n.overlay_cidr.overlaps(&overlay))
    {
        return Err(ServiceError::Conflict(format!(
            "overlay {overlay} already used by another network"
        )));
    }
    check_forward_prefix(state, "", overlay)?;
    let id = format!("net-{}", state.networks.len() + 1);
    let ts = now();
    let default_segment_ts = ts.clone();
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
    state.restore_segment(Segment {
        id: meshlet_domain::default_segment_id(&meshlet_domain::NetworkId(id.clone())),
        network_id: meshlet_domain::NetworkId(id.clone()),
        name: "default".into(),
        cidr: overlay,
        status: meshlet_domain::SegmentStatus::Active,
        created_at: default_segment_ts,
    })?;
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

// ---------------------------------------------------------------------------
// 设备自举注册（ZeroTier 式：自举码注册 → Pending → 控制中心审批/拒绝）
// ---------------------------------------------------------------------------

/// 创建自举码（控制中心侧）：长期、可复用的注册入口凭据。原始自举码
/// **仅此一次**返回，服务端只存 SHA-256 摘要（§11.3，同邀请）。
pub fn create_bootstrap_token(
    state: &mut MeshState,
    network_id: &str,
    req: CreateBootstrapTokenRequest,
) -> Result<CreateBootstrapTokenResponse, ServiceError> {
    state.network(network_id)?; // 网络必须存在
    if req.max_uses == Some(0) {
        return Err(ServiceError::InvalidInput(
            "max_uses must be at least 1, or unset for unlimited".into(),
        ));
    }
    // 自举码序列（`bootstrap_seq`，持久化到 mesh_meta）：重启不重号、不复用。
    let seq = state.bootstrap_seq() + 1;
    let raw = generate_token();
    let token = BootstrapToken {
        id: meshlet_domain::BootstrapTokenId(format!("bt-{seq}")),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        token_hash: token_hash(&raw),
        max_uses: req.max_uses,
        used_count: 0,
        created_at: now(),
        revoked_at: None,
    };
    let view = CreateBootstrapTokenResponse {
        token_id: token.id.to_string(),
        token: raw,
        max_uses: req.max_uses,
    };
    // 只存摘要（§11.3）：索引键即 token_hash，原始自举码不落地。
    state
        .bootstrap_tokens
        .insert(token.token_hash.clone(), token);
    state.set_bootstrap_seq(seq);
    Ok(view)
}

/// 撤销自举码：之后任何用它发起的注册都被拒绝（已落地的 Pending 申请不受
/// 影响——审批流程独立于入口凭据）。返回撤销时刻供 handler 落库。
pub fn revoke_bootstrap_token(
    state: &mut MeshState,
    network_id: &str,
    token_id: &str,
) -> Result<Timestamp, ServiceError> {
    state.network(network_id)?;
    let target = state
        .bootstrap_tokens
        .values_mut()
        .find(|t| t.id.to_string() == token_id)
        .ok_or_else(|| ServiceError::BootstrapTokenNotFound(token_id.to_string()))?;
    if target.revoked_at.is_some() {
        return Err(ServiceError::Conflict(
            "bootstrap token already revoked".into(),
        ));
    }
    let revoked_at = now();
    target.revoked_at = Some(revoked_at.clone());
    Ok(revoked_at)
}

/// 自举码列表（控制台展示用量；只含元数据，不含摘要以外的任何凭据材料）。
pub fn list_bootstrap_tokens(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<BootstrapTokenView>, ServiceError> {
    state.network(network_id)?;
    let mut views: Vec<BootstrapTokenView> = state
        .bootstrap_tokens
        .values()
        .filter(|t| t.network_id.to_string() == network_id)
        .map(|t| BootstrapTokenView {
            id: t.id.to_string(),
            network_id: t.network_id.to_string(),
            max_uses: t.max_uses,
            used_count: t.used_count,
            created_at: t.created_at.clone(),
            revoked_at: t.revoked_at.clone(),
        })
        .collect();
    // 稳定输出：按创建时刻排序（`bt-N` 文本序在位数不同时不等价于创建序）。
    views.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(views)
}

/// 设备自举注册（公开端点）：持自举码换取 agent 凭证，落 **Pending** 申请。
/// 批准前不分配虚拟 IP、不进期望配置（`device_plan` 只读 `devices`），
/// 数据面对 Pending 设备完全不可见（migration 008 头注释的三条理由）。
pub fn register_device(
    state: &mut MeshState,
    req: RegisterDeviceRequest,
) -> Result<RegisterDeviceResponse, ServiceError> {
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

    // 以摘要定位自举码并校验（持锁内原子完成，闭合并发竞态）。
    let token = state
        .bootstrap_tokens
        .get_mut(&token_hash(&req.bootstrap_token))
        .ok_or(ServiceError::InvalidBootstrapToken)?;
    if token.revoked_at.is_some() {
        return Err(ServiceError::InvalidBootstrapToken);
    }
    if let Some(max) = token.max_uses {
        if token.used_count >= max {
            return Err(ServiceError::InvalidBootstrapToken);
        }
    }
    token.used_count += 1;
    let network_id = token.network_id.to_string();

    let ts = now();
    let seq = state.registration_seq() + 1;
    let registration = DeviceRegistration {
        id: meshlet_domain::DeviceId(format!("dev-reg-{seq}")),
        network_id: meshlet_domain::NetworkId(network_id.clone()),
        name: req.device_name.clone(),
        public_key: req.public_key.clone(),
        platform,
        requested_at: ts.clone(),
        // 注册即首次上报（请求到达时刻）。
        last_report_at: Some(ts.clone()),
        dataplane_evidence: None,
    };
    // 名字唯一性跨 devices + registrations 两侧（域层 `add_registration`）。
    state.registry.add_registration(registration.clone())?;
    state.set_registration_seq(seq);

    Ok(RegisterDeviceResponse {
        device_id: registration.id.to_string(),
        network_id,
        status: "pending".to_string(),
        agent_token: String::new(), // 由 handler 用 AgentTokenStore 签发后回填
        requested_at: ts,
    })
}

/// 批准注册申请：**沿用注册时分配的设备 id** 转入 `devices`（`agent_tokens`
/// 等引用无需迁移），此刻才分配 overlay 地址（IPAM 顺序分配），并记录新
/// 修订——期望配置随之把新设备纳入数据面（§10.1/ADR-009）。
///
/// **凭证不轮换**：注册期签发的 agent 凭证原样沿用（设备 id 不变，批准
/// 动作对设备透明，审批者无需传递任何秘密）；拒绝路径才作废凭证。
pub fn approve_registration(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<(DeviceRegistration, Device, u64), ServiceError> {
    state.network(network_id)?;
    let registration = state
        .registry
        .find_registration(&meshlet_domain::DeviceId(device_id.to_string()))
        .filter(|r| r.network_id.to_string() == network_id)
        .cloned()
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;

    // 先摘除申请（名字唯一性检查跨两侧，摘除后同名转入 devices 才不撞自己）。
    let registration = state
        .registry
        .remove_registration(&registration.id)
        .expect("just found");

    let ipam = state
        .ipams
        .get_mut(network_id)
        .ok_or_else(|| ServiceError::NetworkNotFound(network_id.to_string()))?;
    let virtual_ip = match ipam.allocate() {
        Ok(ip) => ip,
        // IPAM 失败则把申请放回去：审批失败不得吞掉 Pending 申请。
        Err(e) => {
            state.registry.add_registration(registration.clone())?;
            return Err(ServiceError::Conflict(e.to_string()));
        }
    };

    let ts = now();
    let device = Device {
        id: registration.id.clone(),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        name: registration.name.clone(),
        virtual_ipv4: virtual_ip,
        public_key: registration.public_key.clone(),
        platform: registration.platform,
        status: meshlet_domain::DeviceStatus::Active,
        // Pending 期的心跳证据直接带入：批准后 agent 无缝续报。
        last_seen_at: registration.last_report_at.clone(),
        last_handshake_at: None,
        last_report_at: registration.last_report_at.clone(),
        dataplane_evidence: registration.dataplane_evidence.clone(),
        // created_at = 申请时刻（Pending 起始），approved_at = 审批时刻。
        created_at: registration.requested_at.clone(),
        approved_at: Some(ts.clone()),
        revoked_at: None,
        segment_id: meshlet_domain::default_segment_id(&meshlet_domain::NetworkId(
            network_id.into(),
        )),
    };
    if let Err(e) = state.registry.add(device.clone()) {
        // 登记失败（例如 IPAM 分配到重复地址）则回收地址并把申请放回去。
        if let Some(ipam) = state.ipams.get_mut(network_id) {
            ipam.release(virtual_ip);
        }
        state.registry.add_registration(registration.clone())?;
        return Err(e.into());
    }
    // 新设备改变期望配置：记录新修订（版本号网络内递增，§10.4）。
    let revision_id = record_revision(state, network_id)?;
    Ok((registration, device, revision_id))
}

/// 拒绝注册申请：摘除申请并返回（handler 据此清理 `device_registrations`
/// 行与 Pending 凭证）。**不记修订**（期望配置从未包含过 Pending 申请，
/// 拒绝是纯状态清理，§10.1「DB 写入 ≠ 生效」的反向：无生效即无修订）。
pub fn deny_registration(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<DeviceRegistration, ServiceError> {
    state.network(network_id)?;
    let registration = state
        .registry
        .find_registration(&meshlet_domain::DeviceId(device_id.to_string()))
        .filter(|r| r.network_id.to_string() == network_id)
        .cloned()
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    Ok(state
        .registry
        .remove_registration(&registration.id)
        .expect("just found"))
}

/// Pending 申请视图列表（控制台设备页「待审批」分区；`RegistrationView`
/// 不含虚拟 IP——批准前本就未分配，避免占位假值）。
pub fn list_registrations(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<RegistrationView>, ServiceError> {
    state.network(network_id)?;
    Ok(state
        .registry
        .registrations()
        .iter()
        .filter(|r| r.network_id.to_string() == network_id)
        .map(|r| RegistrationView {
            id: r.id.to_string(),
            network_id: r.network_id.to_string(),
            name: r.name.clone(),
            platform: match r.platform {
                Platform::Linux => "linux",
                Platform::Windows => "windows",
            }
            .to_string(),
            public_key: r.public_key.clone(),
            requested_at: r.requested_at.clone(),
            last_report_at: r.last_report_at.clone(),
            dataplane_evidence: r.dataplane_evidence.clone(),
        })
        .collect())
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
        dataplane_evidence: None,
        created_at: ts.clone(),
        approved_at: None,
        revoked_at: None,
        segment_id: meshlet_domain::default_segment_id(&meshlet_domain::NetworkId(
            network_id.clone(),
        )),
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
    dataplane: Option<DataplaneEvidence>,
    now: Timestamp,
) -> Result<meshlet_domain::Presence, ServiceError> {
    let device = state
        .registry
        .find_by_id_mut(device_id)
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    apply_agent_report(device, last_handshake_at, dataplane, &now);
    Ok(evaluate_presence(device, &now, &state.presence_thresholds))
}

/// Pending 申请的 agent 心跳（§7.5：证据不因 Pending 而丢弃）：只更新
/// `last_report_at` 与数据面证据。无隧道期握手读数无从谈起，`last_handshake_at`
/// 对 Pending 申请不采集（批准后从零开始，与 `devices.last_handshake_at` 一致）。
pub fn record_pending_agent_report(
    state: &mut MeshState,
    device_id: &DeviceId,
    dataplane: Option<DataplaneEvidence>,
    now: Timestamp,
) -> Result<(), ServiceError> {
    let registration = state
        .registry
        .find_registration_mut(device_id)
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    if let Some(evidence) = dataplane {
        registration.dataplane_evidence = Some(evidence);
    }
    registration.last_report_at = Some(now);
    Ok(())
}

/// 把一次上报写到设备记录（内部共享）。证据与握手时间同一纪律：请求未携带
/// 时保留上次读数（「最后已知读数」， staleness 由 last_report_at 承载）。
fn apply_agent_report(
    device: &mut Device,
    last_handshake_at: Option<String>,
    dataplane: Option<DataplaneEvidence>,
    now: &Timestamp,
) {
    if let Some(ts) = last_handshake_at {
        device.last_handshake_at = Some(ts);
    }
    if let Some(evidence) = dataplane {
        device.dataplane_evidence = Some(evidence);
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
    // 例外（ADR-006 旗舰场景）：新路由与既有路由**都是 Alias 模式**时允许
    // 真实前缀重叠——两个站点各有一个 192.168.1.0/24，经各自 Alias 前缀区分
    // 可达；对外可见的转发前缀是 Alias（唯一性由创建 Alias 时的
    // `alias_alias_overlap` 拒绝保证），真实前缀不进任何隧道 AllowedIPs。
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
        let both_alias = existing.route_mode == RouteMode::Alias && route_mode == RouteMode::Alias;
        if !both_alias {
            return Err(ServiceError::RouteConflict(format!(
                "destination {destination} overlaps existing route {} ({}) in network {network_id}",
                existing.id, existing.destination_cidr
            )));
        }
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

    if route_mode == RouteMode::Direct {
        check_new_forward_prefix(state, network_id, destination)?;
    } else {
        // Preserve Alias real-prefix overlap, but never route a real target
        // through an existing visible Alias on this gateway.
        check_local_alias_prefix(state, network_id, destination)?;
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
/// §12.6 所有权清理：绑定该路由的 Alias 一并移除（alias-路由是一对一单元，
/// 留下孤儿 Alias 会让 AllowedIPs 推导引用不存在的翻译）。
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
    if let Some(aliases) = state.aliases.get_mut(network_id) {
        aliases.retain(|a| a.lan_route_id.to_string() != route_id);
    }
    record_revision(state, network_id)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Alias 映射（ADR-006：等长前缀一对一；§12.6 所有权与清理）
// ---------------------------------------------------------------------------

/// 创建 Alias 映射（§9.2 转换前检查的控制面部分）：绑定路由必须是本网络
/// `alias` 模式路由、网关 Active、每路由一映射；前缀等长（域层校验）、
/// 与 overlay / 既有 Alias / 既有路由目的网段互不重叠（§8.3/§9.2 不静默——
/// 冲突消息点名对端）。target 由绑定路由推导，客户端不可指定。
/// 拒绝发生在任何状态变更之前。
pub fn create_alias(
    state: &mut MeshState,
    network_id: &str,
    req: CreateAliasRequest,
) -> Result<AliasView, ServiceError> {
    state.network(network_id)?;
    let alias_cidr: Ipv4Cidr = req
        .alias_cidr
        .parse()
        .map_err(|e| ServiceError::InvalidCidr(format!("{}: {e}", req.alias_cidr)))?;
    let translation_mode = match req.translation_mode.as_deref() {
        None | Some("dnat_snat") => TranslationMode::DnatSnat,
        Some("dnat_only") => TranslationMode::DnatOnly,
        Some(other) => {
            return Err(ServiceError::InvalidInput(format!(
                "translation_mode must be \"dnat_snat\" or \"dnat_only\", got {other:?}"
            )));
        }
    };

    // 绑定路由：本网络、alias 模式（§5：route_mode=alias 即「经虚拟前缀」，
    // alias-路由是一对一单元）；网关 Active（§9.2「网关有效」）；每路由一映射。
    let routes = state.lan_routes.get(network_id).ok_or_else(|| {
        ServiceError::RouteNotFound(format!("{} in network {network_id}", req.lan_route_id))
    })?;
    let route = routes
        .iter()
        .find(|r| r.id.to_string() == req.lan_route_id)
        .ok_or_else(|| {
            ServiceError::RouteNotFound(format!("{} in network {network_id}", req.lan_route_id))
        })?;
    if route.route_mode != RouteMode::Alias {
        return Err(ServiceError::InvalidInput(format!(
            "alias can only bind to a route with route_mode = \"alias\", but route {} has route_mode = \"{}\" (create the route in alias mode first, §5/ADR-006)",
            route.id,
            route.route_mode.as_str()
        )));
    }
    let target_cidr = route.destination_cidr;
    AliasMapping::new(
        AliasMappingId(format!("al-{}", state.route_seq + 1)),
        meshlet_domain::NetworkId(network_id.to_string()),
        route.id.clone(),
        alias_cidr,
        target_cidr,
        translation_mode,
    )
    .map_err(|e: AliasError| ServiceError::InvalidInput(e.to_string()))?;
    check_new_forward_prefix(state, network_id, alias_cidr)?;
    let gateway = state
        .registry
        .find_by_id(&route.gateway_device_id)
        .ok_or_else(|| ServiceError::DeviceNotFound(route.gateway_device_id.to_string()))?;
    if !gateway.is_active() {
        return Err(ServiceError::Conflict(format!(
            "gateway device {} of route {} is not active",
            gateway.id, route.id
        )));
    }
    if let Some(aliases) = state.aliases.get(network_id) {
        if let Some(existing) = aliases.iter().find(|a| a.lan_route_id == route.id) {
            return Err(ServiceError::Conflict(format!(
                "route {} already has alias {} bound (one mapping per route, §12.6)",
                route.id, existing.id
            )));
        }
    }

    let id = AliasMappingId(format!("al-{}", state.route_seq + 1));
    let alias = AliasMapping::new(
        id,
        meshlet_domain::NetworkId(network_id.to_string()),
        route.id.clone(),
        alias_cidr,
        target_cidr,
        translation_mode,
    )
    .map_err(|e: AliasError| ServiceError::InvalidInput(e.to_string()))?;

    state.route_seq += 1;
    state
        .aliases
        .entry(network_id.to_string())
        .or_default()
        .push(alias.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_alias_view(state, network_id, &alias, revision_id))
}

pub fn list_aliases(state: &MeshState, network_id: &str) -> Result<Vec<AliasView>, ServiceError> {
    state.network(network_id)?;
    let (revision_id, _) = current_revision_ref(state, network_id);
    Ok(state
        .aliases
        .get(network_id)
        .map(|aliases| {
            aliases
                .iter()
                .map(|a| to_alias_view(state, network_id, a, revision_id))
                .collect()
        })
        .unwrap_or_default())
}

pub fn get_alias(
    state: &MeshState,
    network_id: &str,
    alias_id: &str,
) -> Result<AliasView, ServiceError> {
    state.network(network_id)?;
    let alias = state
        .aliases
        .get(network_id)
        .and_then(|aliases| aliases.iter().find(|a| a.id.to_string() == alias_id))
        .ok_or_else(|| {
            ServiceError::AliasNotFound(format!("{alias_id} in network {network_id}"))
        })?;
    let (revision_id, _) = current_revision_ref(state, network_id);
    Ok(to_alias_view(state, network_id, alias, revision_id))
}

/// 删除 Alias = 整单元清理（§12.6「删除 Alias 同步清理其路由和 NAT 规则」
/// 的控制面部分）：移除映射与其绑定路由，记录**一个**修订。内核侧 NAT 规则
/// 的移除随该修订的 apply 交 backend 执行（未接线时确定性失败可见，§10.3）。
/// 返回 (alias_id, route_id) 供 handler 落库与审计。
pub fn delete_alias(
    state: &mut MeshState,
    network_id: &str,
    alias_id: &str,
) -> Result<(String, String), ServiceError> {
    state.network(network_id)?;
    let aliases = state.aliases.get_mut(network_id).ok_or_else(|| {
        ServiceError::AliasNotFound(format!("{alias_id} in network {network_id}"))
    })?;
    let before = aliases.len();
    let route_id = aliases
        .iter()
        .find(|a| a.id.to_string() == alias_id)
        .map(|a| a.lan_route_id.to_string())
        .ok_or_else(|| {
            ServiceError::AliasNotFound(format!("{alias_id} in network {network_id}"))
        })?;
    aliases.retain(|a| a.id.to_string() != alias_id);
    debug_assert_eq!(aliases.len(), before - 1);
    // 绑定路由同删（一对一单元；孤儿 alias 模式路由没有翻译语义）。
    if let Some(routes) = state.lan_routes.get_mut(network_id) {
        routes.retain(|r| r.id.to_string() != route_id);
    }
    record_revision(state, network_id)?;
    Ok((alias_id.to_string(), route_id))
}

/// 创建单主机全端口转发：把「alias /32 → target /32」作为一个原子单元写入。
///
/// Host Forward 不新增端口防火墙模型：`/32` 使 TCP/UDP/ICMP 的所有端口和
/// 协议都经既有 LAN Route + Alias NETMAP 路径转发，删除路由/alias 单元即全删。
pub fn create_host_forward(
    state: &mut MeshState,
    network_id: &str,
    req: CreateHostForwardRequest,
) -> Result<HostForwardView, ServiceError> {
    state.network(network_id)?;
    let target = Ipv4Cidr::new(req.target_ipv4, 32)
        .map_err(|e| ServiceError::InvalidCidr(format!("{}/32: {e}", req.target_ipv4)))?;
    let alias_cidr = Ipv4Cidr::new(req.alias_ipv4, 32)
        .map_err(|e| ServiceError::InvalidCidr(format!("{}/32: {e}", req.alias_ipv4)))?;
    check_new_forward_prefix(state, network_id, alias_cidr)?;
    check_local_alias_prefix(state, network_id, target)?;
    let translation_mode = match req.translation_mode.as_deref() {
        None | Some("dnat_snat") => TranslationMode::DnatSnat,
        Some("dnat_only") => TranslationMode::DnatOnly,
        Some(other) => {
            return Err(ServiceError::InvalidInput(format!(
                "translation_mode must be \"dnat_snat\" or \"dnat_only\", got {other:?}"
            )));
        }
    };
    let overlay = state.network(network_id)?.overlay_cidr;
    if target.overlaps(&overlay) || alias_cidr.overlaps(&overlay) {
        return Err(ServiceError::RouteConflict(format!(
            "host forward target {target} or alias {alias_cidr} overlaps overlay {overlay}"
        )));
    }
    for existing in state
        .lan_routes
        .get(network_id)
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        if existing.destination_cidr.overlaps(&target) {
            return Err(ServiceError::RouteConflict(format!(
                "host forward target {target} overlaps existing route {} ({})",
                existing.id, existing.destination_cidr
            )));
        }
    }

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

    let route = LanRoute {
        id: LanRouteId(format!("rt-{}", state.route_seq + 1)),
        network_id: meshlet_domain::NetworkId(network_id.to_string()),
        gateway_device_id: gateway,
        destination_cidr: target,
        route_mode: RouteMode::Alias,
        return_path_mode: ReturnPathMode::ControlledSnat,
        status: DesiredStateStatus::Pending,
        created_at: now(),
    };
    let alias = AliasMapping::new(
        AliasMappingId(format!("al-{}", state.route_seq + 2)),
        meshlet_domain::NetworkId(network_id.to_string()),
        route.id.clone(),
        alias_cidr,
        target,
        translation_mode,
    )
    .map_err(|e| ServiceError::InvalidInput(e.to_string()))?;

    state.route_seq += 2;

    state
        .lan_routes
        .entry(network_id.to_string())
        .or_default()
        .push(route);
    state
        .aliases
        .entry(network_id.to_string())
        .or_default()
        .push(alias.clone());
    let revision_id = record_revision(state, network_id)?;
    Ok(to_host_forward_view(state, network_id, &alias, revision_id))
}

/// Host Forward 列表 = 当前所有 /32 target 的 Alias 单元（真实 LAN 网段仍用
/// 原有 Alias 页面展示，避免把两种语义混在同一张表）。
pub fn list_host_forwards(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<HostForwardView>, ServiceError> {
    state.network(network_id)?;
    let routes: HashMap<String, &LanRoute> = state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .map(|route| (route.id.to_string(), route))
                .collect()
        })
        .unwrap_or_default();
    let mut views = state
        .aliases
        .get(network_id)
        .map(|aliases| {
            aliases
                .iter()
                .filter_map(|alias| {
                    let route = routes.get(&alias.lan_route_id.to_string())?;
                    if route.destination_cidr.prefix_len() != 32 {
                        return None;
                    }
                    let (_, apply_status) = current_revision_ref(state, network_id);
                    Some(HostForwardView {
                        id: alias.id.to_string(),
                        network_id: alias.network_id.to_string(),
                        gateway_device_id: route.gateway_device_id.to_string(),
                        target_ipv4: alias.target_cidr.network().to_string(),
                        alias_ipv4: alias.alias_cidr.network().to_string(),
                        translation_mode: alias.translation_mode.as_str().to_string(),
                        status: alias.status.as_str().to_string(),
                        revision_id: 0,
                        apply_status,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    views.sort_by_key(|view| view.alias_ipv4.clone());
    Ok(views)
}

/// 删除 Host Forward 的 alias id；绑定路由随既有 ownership 单元一并移除。
pub fn delete_host_forward(
    state: &mut MeshState,
    network_id: &str,
    alias_id: &str,
) -> Result<(String, String), ServiceError> {
    delete_alias(state, network_id, alias_id)
}

fn to_alias_view(
    state: &MeshState,
    network_id: &str,
    alias: &AliasMapping,
    revision_id: u64,
) -> AliasView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    AliasView {
        id: alias.id.to_string(),
        network_id: alias.network_id.to_string(),
        lan_route_id: alias.lan_route_id.to_string(),
        alias_cidr: alias.alias_cidr.to_string(),
        target_cidr: alias.target_cidr.to_string(),
        translation_mode: alias.translation_mode.as_str().to_string(),
        status: alias.status.as_str().to_string(),
        revision_id,
        apply_status,
    }
}

fn to_host_forward_view(
    state: &MeshState,
    network_id: &str,
    alias: &AliasMapping,
    revision_id: u64,
) -> HostForwardView {
    let (_, apply_status) = current_revision_ref(state, network_id);
    let target_ipv4 = alias.target_cidr.network().to_string();
    let alias_ipv4 = alias.alias_cidr.network().to_string();
    HostForwardView {
        id: alias.id.to_string(),
        network_id: alias.network_id.to_string(),
        gateway_device_id: state
            .lan_routes
            .get(network_id)
            .and_then(|routes| routes.iter().find(|route| route.id == alias.lan_route_id))
            .map(|route| route.gateway_device_id.to_string())
            .unwrap_or_default(),
        target_ipv4,
        alias_ipv4,
        translation_mode: alias.translation_mode.as_str().to_string(),
        status: alias.status.as_str().to_string(),
        revision_id,
        apply_status,
    }
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
    // §12.6 所有权清理：随之移除绑定这些路由的 Alias 映射（不留孤儿翻译）。
    let orphaned: Vec<String> = state
        .lan_routes
        .get(network_id)
        .map(|routes| {
            routes
                .iter()
                .filter(|r| r.gateway_device_id == revoked_id)
                .map(|r| r.id.to_string())
                .collect()
        })
        .unwrap_or_default();
    if let Some(routes) = state.lan_routes.get_mut(network_id) {
        routes.retain(|r| r.gateway_device_id != revoked_id);
    }
    if let Some(aliases) = state.aliases.get_mut(network_id) {
        aliases.retain(|a| !orphaned.contains(&a.lan_route_id.to_string()));
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

pub(crate) fn fingerprint_of(public_key: &str) -> String {
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
        approved_at: d.approved_at.clone(),
        last_seen_at: d.last_seen_at.clone(),
        online_state: presence.state.as_str().to_string(),
        presence_source: presence.source.as_str().to_string(),
        dataplane_evidence: d.dataplane_evidence.clone(),
    }
}

#[cfg(test)]
mod forwarding_tests {
    use super::*;
    use serde_json::{json, Value};

    fn network(state: &mut MeshState, overlay: &str) -> (String, String) {
        let id = create_network(
            state,
            CreateNetworkRequest {
                name: overlay.into(),
                overlay_cidr: overlay.into(),
            },
        )
        .unwrap()
        .id;
        let invite = create_invite(
            state,
            &id,
            CreateInviteRequest {
                expires_at: None,
                max_uses: None,
            },
        )
        .unwrap();
        let device = enroll(
            state,
            EnrollRequest {
                invite_token: invite.token,
                device_name: id.clone(),
                public_key: format!("key-{id}"),
                platform: "linux".into(),
            },
        )
        .unwrap();
        (id, device.device_id)
    }

    fn snapshot(state: &MeshState) -> Value {
        let revisions: std::collections::BTreeMap<_, _> = state
            .networks
            .keys()
            .map(|id| {
                (
                    id.clone(),
                    state
                        .ledger
                        .revisions(&meshlet_domain::NetworkId(id.clone()))
                        .iter()
                        .map(crate::revision::to_revision_view)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        json!({"routes": state.lan_routes, "aliases": state.aliases, "sequence": state.route_seq, "networks": state.networks.keys().collect::<std::collections::BTreeSet<_>>(), "revisions": revisions})
    }

    // Prepare an Alias route before the mutation snapshot: creating the mapping
    // must not consume a revision or id when its forwarding prefix conflicts.
    fn prepare(
        state: &mut MeshState,
        net: &str,
        gateway: &str,
        kind: &str,
        target: &str,
    ) -> Option<String> {
        (kind == "alias").then(|| {
            create_route(
                state,
                net,
                CreateRouteRequest {
                    gateway_device_id: gateway.into(),
                    destination_cidr: target.into(),
                    route_mode: Some("alias".into()),
                    return_path_mode: "controlled_snat".into(),
                },
            )
            .unwrap()
            .id
        })
    }

    fn publish(
        state: &mut MeshState,
        net: &str,
        gateway: &str,
        kind: &str,
        prefix: &str,
        target: &str,
        route: Option<String>,
    ) -> Result<(), ServiceError> {
        match kind {
            "direct" => create_route(
                state,
                net,
                CreateRouteRequest {
                    gateway_device_id: gateway.into(),
                    destination_cidr: prefix.into(),
                    route_mode: None,
                    return_path_mode: "dual_route".into(),
                },
            )
            .map(|_| ()),
            "alias" => create_alias(
                state,
                net,
                CreateAliasRequest {
                    lan_route_id: route.unwrap(),
                    alias_cidr: prefix.into(),
                    translation_mode: None,
                },
            )
            .map(|_| ()),
            "host" => create_host_forward(
                state,
                net,
                CreateHostForwardRequest {
                    gateway_device_id: gateway.into(),
                    target_ipv4: target.parse::<Ipv4Cidr>().unwrap().network(),
                    alias_ipv4: prefix.parse::<Ipv4Cidr>().unwrap().network(),
                    translation_mode: None,
                },
            )
            .map(|_| ()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn forwarding_prefix_entrypoints_reject_each_other_atomically() {
        let mut cases = 0;
        for first in ["direct", "alias", "host"] {
            for second in ["direct", "alias", "host"] {
                for cross_network in [false, true] {
                    for (first_len, second_len) in [(32, 32), (24, 32), (32, 24)] {
                        if (first == "host" && first_len != 32)
                            || (second == "host" && second_len != 32)
                        {
                            continue;
                        }
                        let mut state = MeshState::default();
                        let (n1, g1) = network(&mut state, "10.240.0.0/24");
                        let (n2, g2) = if cross_network {
                            network(&mut state, "10.242.0.0/24")
                        } else {
                            (n1.clone(), g1.clone())
                        };
                        let p1 = format!(
                            "10.250.0.{}/{first_len}",
                            if first_len == 32 { 5 } else { 0 }
                        );
                        let p2 = format!(
                            "10.250.0.{}/{second_len}",
                            if second_len == 32 { 5 } else { 0 }
                        );
                        let t1 = format!(
                            "192.168.60.{}/{first_len}",
                            if first_len == 32 { 5 } else { 0 }
                        );
                        let t2 = format!(
                            "192.168.61.{}/{second_len}",
                            if second_len == 32 { 5 } else { 0 }
                        );
                        let r1 = prepare(&mut state, &n1, &g1, first, &t1);
                        publish(&mut state, &n1, &g1, first, &p1, &t1, r1).unwrap();
                        let r2 = prepare(&mut state, &n2, &g2, second, &t2);
                        let before = snapshot(&state);
                        let err = publish(&mut state, &n2, &g2, second, &p2, &t2, r2).unwrap_err();
                        assert!(
                            matches!(err, ServiceError::RouteConflict(_)),
                            "{first} -> {second}: {err}"
                        );
                        assert_eq!(
                            snapshot(&state),
                            before,
                            "{first} -> {second}, cross={cross_network}, {p1}/{p2}"
                        );
                        cases += 1;
                    }
                }
            }
        }
        assert_eq!(cases, 42);
    }

    #[test]
    fn overlay_conflicts_reject_all_entries_and_creation_orders() {
        for kind in ["direct", "alias", "host"] {
            for cross in [false, true] {
                let mut state = MeshState::default();
                let (net, gw) = network(&mut state, "10.240.0.0/24");
                if cross {
                    network(&mut state, "10.242.0.0/24");
                }
                let target = "192.168.61.5/32";
                let route = prepare(&mut state, &net, &gw, kind, target);
                let before = snapshot(&state);
                let prefix = if cross {
                    "10.242.0.5/32"
                } else {
                    "10.240.0.5/32"
                };
                assert!(matches!(
                    publish(&mut state, &net, &gw, kind, prefix, target, route),
                    Err(ServiceError::RouteConflict(_))
                ));
                assert_eq!(snapshot(&state), before);
            }
            let mut state = MeshState::default();
            let (net, gw) = network(&mut state, "10.240.0.0/24");
            let route = prepare(&mut state, &net, &gw, kind, "192.168.61.5/32");
            publish(
                &mut state,
                &net,
                &gw,
                kind,
                "10.250.0.5/32",
                "192.168.61.5/32",
                route,
            )
            .unwrap();
            let before = snapshot(&state);
            assert!(matches!(
                create_network(
                    &mut state,
                    CreateNetworkRequest {
                        name: "blocked".into(),
                        overlay_cidr: "10.250.0.0/24".into()
                    }
                ),
                Err(ServiceError::RouteConflict(_))
            ));
            assert_eq!(snapshot(&state), before);
        }
    }

    #[test]
    fn invalid_host_unit_does_not_consume_ids_or_revisions() {
        let mut state = MeshState::default();
        let (net, gw) = network(&mut state, "10.240.0.0/24");
        let before = snapshot(&state);
        assert!(publish(
            &mut state,
            &net,
            &gw,
            "host",
            "192.168.61.5/32",
            "192.168.61.5/32",
            None
        )
        .is_err());
        assert_eq!(snapshot(&state), before);
    }
}
