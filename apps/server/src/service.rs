//! 控制平面服务层（[存档 §11.2](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)）：
//! 网络/邀请/设备加入的内存实现 + HTTP DTO。
//!
//! 持久化（SQLx migrations）落地前，状态存于 `Mutex<MeshState>`；
//! 邀请兑换等关键路径全程持锁，闭合 §11.3 的并发竞态。

use meshlet_api_types::ErrorResponse;
use meshlet_domain::{
    generate_token, Device, DeviceId, DeviceRegistry, Invite, Ipam, Ipv4Cidr, Network, Platform,
    RegistryError, Timestamp,
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
    #[error("invalid invite token")]
    InvalidInviteToken,
    #[error("{0}")]
    InvalidCidr(String),
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Internal(String),
}

impl ServiceError {
    /// 转为统一错误响应（结构见 docs/architecture/api-contract.md）。
    pub fn into_response(self) -> ErrorResponse {
        match self {
            ServiceError::NetworkNotFound(_)
            | ServiceError::InviteNotFound(_)
            | ServiceError::DeviceNotFound(_) => {
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
            ServiceError::Conflict(_) => {
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

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

pub struct MeshState {
    networks: HashMap<String, Network>,
    /// 邀请按 Token 摘要索引（§11.3：兑换时以摘要定位，不暴露原始 Token）。
    invites: HashMap<String, Invite>,
    ipams: HashMap<String, Ipam>,
    registry: DeviceRegistry,
    /// 在线判定窗口（§12.4；默认值见 [meshlet_domain::PresenceThresholds]）。
    presence_thresholds: meshlet_domain::PresenceThresholds,
}

impl MeshState {
    pub fn new(presence_thresholds: meshlet_domain::PresenceThresholds) -> Self {
        Self {
            networks: HashMap::new(),
            invites: HashMap::new(),
            ipams: HashMap::new(),
            registry: DeviceRegistry::new(),
            presence_thresholds,
        }
    }

    fn network(&self, id: &str) -> Result<&Network, ServiceError> {
        self.networks
            .get(id)
            .ok_or_else(|| ServiceError::NetworkNotFound(id.to_string()))
    }
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
    Ok(to_network_view(state.network(&id).unwrap()))
}

pub fn list_networks(state: &MeshState) -> Vec<NetworkView> {
    state.networks.values().map(to_network_view).collect()
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

    // 指纹 = 公钥 SHA-256；服务端不存任何私钥侧材料。
    let fingerprint = fingerprint_of(&req.public_key);
    Ok(EnrollResponse {
        device_id: device.id.to_string(),
        network_id,
        virtual_ipv4: virtual_ip,
        fingerprint,
        agent_token: String::new(), // 由 handler 用 AgentTokenStore 签发后回填
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

fn to_network_view(n: &Network) -> NetworkView {
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
