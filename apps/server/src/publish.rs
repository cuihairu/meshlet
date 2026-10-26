//! 服务发布控制面（R-06）：四类发布对象（PortForward / HTTP 路由 / 探针 /
//! DNS 记录）的 CRUD + agent 健康回报。
//!
//! - 写路径与 alias.rs 同构：`persist` 串行锁 → `mesh` 快照 staged 修改 →
//!   域层校验 → 同事务落库 + 审计（无审计不落地）→ 写回 `mesh`；
//! - 读视图**永不回显** `allowed_bearer_tokens`（入口允许清单是数据面比对
//!   密钥，ADR-010：不落审计、不落日志，只回条数）；
//! - 端口冲突按**设备**判定（每台设备是独立主机，不同设备绑同一端口合法）；
//! - 每设备至多一个 `(bind_address, internal_suffix)` DNS 套接字，计划聚合
//!   因此保持平凡；记录删除后 `(pf-|hr-|pb-|dn-)N` id 不复用（单一
//!   `publish_seq`，前缀不同不冲突）；
//! - 健康回报 `POST /api/v1/agent/publish-health` 用 `AuthorizedAgent`，且
//!   upsert 带 `device_id` 守卫——探针只能写归自己设备的报告。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::agent::{AgentApiError, AuthorizedAgent};
use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service::{MeshState, ServiceError};
use meshlet_publish::health::{HealthState, ProbeTarget};
use meshlet_publish::{
    AuthorizationPolicy, DnsPlan, ForwardProtocol, HttpRoute, HttpRouteSet, PortForwardConfig,
    ProbeSchedule, PublishPlan,
};

pub fn routes() -> Router<SharedAppState> {
    // 与 segments/aliases 同形：发布对象是网络范围内的期望配置。
    Router::new()
        .route(
            "/api/v1/networks/{network_id}/publish/forwards",
            post(create_forward_handler).get(list_forwards_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/forwards/{forward_id}",
            get(get_forward_handler).delete(delete_forward_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/http-routes",
            post(create_http_route_handler).get(list_http_routes_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/http-routes/{route_id}",
            get(get_http_route_handler).delete(delete_http_route_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/probes",
            post(create_probe_handler).get(list_probes_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/probes/{probe_id}",
            get(get_probe_handler).delete(delete_probe_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/dns-records",
            post(create_dns_record_handler).get(list_dns_records_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/dns-records/{record_id}",
            get(get_dns_record_handler).delete(delete_dns_record_handler),
        )
        .route("/api/v1/agent/publish-health", post(publish_health_handler))
}

// ---------------------------------------------------------------------------
// 领域记录（DB 行 ↔ 内存 ↔ 计划的三方一致形态）
// ---------------------------------------------------------------------------

/// L4 端口转发：`policy` 原样进计划（agent 侧 [`meshlet_publish`] 直接消费），
/// DB 里 CIDR 与 token 以 JSON 存放。
#[derive(Debug, Clone)]
pub struct PublishForward {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub protocol: ForwardProtocol,
    pub listener_address: std::net::SocketAddr,
    pub backend_address: std::net::SocketAddr,
    pub policy: AuthorizationPolicy,
    pub enabled: bool,
    pub created_at: String,
}

/// HTTP 路由：同网络内 `(hostname, path_prefix)` 唯一。
#[derive(Debug, Clone)]
pub struct PublishHttpRoute {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub hostname: String,
    pub path_prefix: String,
    pub backend_address: std::net::SocketAddr,
    pub listener_address: std::net::SocketAddr,
    pub policy: AuthorizationPolicy,
    pub tls_passthrough: bool,
    pub created_at: String,
}

/// 健康探针：平铺字段（DB 列一一对应），`target()` 时组装成
/// [`ProbeTarget`]；最近一次结果驻内存（`last_*`），agent 上报后更新。
#[derive(Debug, Clone)]
pub struct PublishProbe {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub target: ProbeTarget,
    pub interval_secs: u64,
    pub enabled: bool,
    pub created_at: String,
    pub last_state: Option<HealthState>,
    pub last_checked_at: Option<String>,
    pub last_detail: Option<String>,
}

impl PublishProbe {
    pub fn target(&self) -> ProbeTarget {
        self.target.clone()
    }
}

/// Split-horizon DNS 记录：`name` 必须落在设备套接字的 `internal_suffix` 内
/// （域层校验）；每设备一个 `(bind_address, internal_suffix)`。
#[derive(Debug, Clone)]
pub struct PublishDnsRecord {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub name: String,
    pub address: std::net::Ipv4Addr,
    pub ttl: u32,
    pub priority: u16,
    pub bind_address: std::net::SocketAddr,
    pub internal_suffix: String,
    pub created_at: String,
}

/// 一个网络的全部发布对象。启动时由 `persist::load` 灌回，计划构建时按
/// 设备过滤。
#[derive(Debug, Clone, Default)]
pub struct PublishCatalog {
    pub forwards: Vec<PublishForward>,
    pub http_routes: Vec<PublishHttpRoute>,
    pub probes: Vec<PublishProbe>,
    pub dns_records: Vec<PublishDnsRecord>,
}

impl MeshState {
    /// 启动重建：灌回一条发布对象（DB 已做外键约束，网络/设备必然存在）。
    pub(crate) fn restore_publish_forward(&mut self, forward: PublishForward) {
        self.publishes
            .entry(forward.network_id.clone())
            .or_default()
            .forwards
            .push(forward);
    }

    pub(crate) fn restore_publish_http_route(&mut self, route: PublishHttpRoute) {
        self.publishes
            .entry(route.network_id.clone())
            .or_default()
            .http_routes
            .push(route);
    }

    pub(crate) fn restore_publish_probe(&mut self, probe: PublishProbe) {
        self.publishes
            .entry(probe.network_id.clone())
            .or_default()
            .probes
            .push(probe);
    }

    pub(crate) fn restore_publish_dns_record(&mut self, record: PublishDnsRecord) {
        self.publishes
            .entry(record.network_id.clone())
            .or_default()
            .dns_records
            .push(record);
    }
}

/// 启动摘要用：发布对象总条数（四类之和）。
pub(crate) fn publish_object_count(state: &MeshState) -> usize {
    state
        .publishes
        .values()
        .map(|c| c.forwards.len() + c.http_routes.len() + c.probes.len() + c.dns_records.len())
        .sum()
}

// ---------------------------------------------------------------------------
// 视图与请求（读视图只回 token 条数，永不回显 token 本身）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct PublishForwardView {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub protocol: String,
    pub listener_address: String,
    pub backend_address: String,
    pub allowed_source_cidrs: Vec<String>,
    pub allowed_bearer_token_count: usize,
    pub enabled: bool,
    pub created_at: String,
    pub revision_id: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePublishForwardRequest {
    pub device_id: String,
    pub protocol: String,
    pub listener_address: String,
    pub backend_address: String,
    #[serde(default)]
    pub allowed_source_cidrs: Vec<String>,
    #[serde(default)]
    pub allowed_bearer_tokens: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PublishHttpRouteView {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub hostname: String,
    pub path_prefix: String,
    pub backend_address: String,
    pub listener_address: String,
    pub allowed_source_cidrs: Vec<String>,
    pub allowed_bearer_token_count: usize,
    pub tls_passthrough: bool,
    pub created_at: String,
    pub revision_id: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePublishHttpRouteRequest {
    pub device_id: String,
    pub hostname: String,
    pub path_prefix: String,
    pub backend_address: String,
    pub listener_address: String,
    #[serde(default)]
    pub allowed_source_cidrs: Vec<String>,
    #[serde(default)]
    pub allowed_bearer_tokens: Vec<String>,
    /// 旧名 `tls_termination` 仍被接受（M1 更名前的调用方不断）：它描述的
    /// 从来都是直通而非终结。响应一律输出新名。
    #[serde(default, alias = "tls_termination")]
    pub tls_passthrough: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PublishProbeView {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub target_kind: String,
    pub address: String,
    pub path: Option<String>,
    pub expected_status: Option<u16>,
    pub timeout_secs: f64,
    pub interval_secs: u64,
    pub enabled: bool,
    pub last_state: Option<String>,
    pub last_checked_at: Option<String>,
    pub last_detail: Option<String>,
    pub created_at: String,
    pub revision_id: u64,
}

/// 平铺请求体（不走 serde 外部标签枚举）：`target_kind` ∈ `tcp` / `http`，
/// http 探针必带 `path` + `expected_status`。
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePublishProbeRequest {
    pub device_id: String,
    pub target_kind: String,
    pub address: String,
    pub path: Option<String>,
    pub expected_status: Option<u16>,
    pub timeout_secs: f64,
    pub interval_secs: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PublishDnsRecordView {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    pub name: String,
    pub address: String,
    pub ttl: u32,
    pub priority: u16,
    pub bind_address: String,
    pub internal_suffix: String,
    pub created_at: String,
    pub revision_id: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePublishDnsRecordRequest {
    pub device_id: String,
    pub name: String,
    pub address: String,
    pub ttl: u32,
    #[serde(default = "default_dns_priority")]
    pub priority: u16,
    pub bind_address: String,
    pub internal_suffix: String,
}

// ---------------------------------------------------------------------------
// 视图转换
// ---------------------------------------------------------------------------

fn to_forward_view(
    state: &MeshState,
    network_id: &str,
    forward: &PublishForward,
) -> PublishForwardView {
    let (revision_id, _) = crate::service::current_revision_ref(state, network_id);
    PublishForwardView {
        id: forward.id.clone(),
        network_id: forward.network_id.clone(),
        device_id: forward.device_id.clone(),
        protocol: match forward.protocol {
            ForwardProtocol::Tcp => "tcp".into(),
            ForwardProtocol::Udp => "udp".into(),
        },
        listener_address: forward.listener_address.to_string(),
        backend_address: forward.backend_address.to_string(),
        allowed_source_cidrs: forward
            .policy
            .allowed_source_cidrs
            .iter()
            .map(|c| c.to_string())
            .collect(),
        allowed_bearer_token_count: forward.policy.allowed_bearer_tokens.len(),
        enabled: forward.enabled,
        created_at: forward.created_at.clone(),
        revision_id,
    }
}

fn to_http_route_view(
    state: &MeshState,
    network_id: &str,
    route: &PublishHttpRoute,
) -> PublishHttpRouteView {
    let (revision_id, _) = crate::service::current_revision_ref(state, network_id);
    PublishHttpRouteView {
        id: route.id.clone(),
        network_id: route.network_id.clone(),
        device_id: route.device_id.clone(),
        hostname: route.hostname.clone(),
        path_prefix: route.path_prefix.clone(),
        backend_address: route.backend_address.to_string(),
        listener_address: route.listener_address.to_string(),
        allowed_source_cidrs: route
            .policy
            .allowed_source_cidrs
            .iter()
            .map(|c| c.to_string())
            .collect(),
        allowed_bearer_token_count: route.policy.allowed_bearer_tokens.len(),
        tls_passthrough: route.tls_passthrough,
        created_at: route.created_at.clone(),
        revision_id,
    }
}

fn to_probe_view(state: &MeshState, network_id: &str, probe: &PublishProbe) -> PublishProbeView {
    let (revision_id, _) = crate::service::current_revision_ref(state, network_id);
    let (target_kind, address, path, expected_status) = match &probe.target {
        ProbeTarget::Tcp { address, .. } => ("tcp".to_string(), address.to_string(), None, None),
        ProbeTarget::Http {
            address,
            path,
            expected_status,
            ..
        } => (
            "http".to_string(),
            address.to_string(),
            Some(path.clone()),
            Some(*expected_status),
        ),
    };
    PublishProbeView {
        id: probe.id.clone(),
        network_id: probe.network_id.clone(),
        device_id: probe.device_id.clone(),
        target_kind,
        address,
        path,
        expected_status,
        timeout_secs: match &probe.target {
            ProbeTarget::Tcp { timeout, .. } | ProbeTarget::Http { timeout, .. } => {
                timeout.as_secs_f64()
            }
        },
        interval_secs: probe.interval_secs,
        enabled: probe.enabled,
        last_state: probe.last_state.map(|s| match s {
            HealthState::Healthy => "healthy".into(),
            HealthState::Unreachable => "unreachable".into(),
        }),
        last_checked_at: probe.last_checked_at.clone(),
        last_detail: probe.last_detail.clone(),
        created_at: probe.created_at.clone(),
        revision_id,
    }
}

fn to_dns_record_view(
    state: &MeshState,
    network_id: &str,
    record: &PublishDnsRecord,
) -> PublishDnsRecordView {
    let (revision_id, _) = crate::service::current_revision_ref(state, network_id);
    PublishDnsRecordView {
        id: record.id.clone(),
        network_id: record.network_id.clone(),
        device_id: record.device_id.clone(),
        name: record.name.clone(),
        address: record.address.to_string(),
        ttl: record.ttl,
        priority: record.priority,
        bind_address: record.bind_address.to_string(),
        internal_suffix: record.internal_suffix.clone(),
        created_at: record.created_at.clone(),
        revision_id,
    }
}

// ---------------------------------------------------------------------------
// 共享校验
// ---------------------------------------------------------------------------

/// 设备校验与 create_route 同口径：属于本网络且 Active。
fn device_in_network(
    state: &MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<meshlet_domain::Device, ServiceError> {
    let device = state
        .registry
        .find_by_id(&meshlet_domain::DeviceId(device_id.to_string()))
        .ok_or_else(|| ServiceError::DeviceNotFound(device_id.to_string()))?;
    if device.network_id.to_string() != network_id {
        return Err(ServiceError::DeviceNotFound(format!(
            "{device_id} is not in network {network_id}"
        )));
    }
    if !device.is_active() {
        return Err(ServiceError::Conflict(format!(
            "device {device_id} is not active"
        )));
    }
    Ok(device.clone())
}

fn parse_policy(
    allowed_source_cidrs: &[String],
    allowed_bearer_tokens: &[String],
) -> Result<AuthorizationPolicy, ServiceError> {
    if allowed_source_cidrs.is_empty() && allowed_bearer_tokens.is_empty() {
        return Err(ServiceError::InvalidInput(
            "publish object must allow at least one source cidr or one bearer token".into(),
        ));
    }
    let mut cidrs = Vec::new();
    for text in allowed_source_cidrs {
        let cidr: meshlet_domain::Ipv4Cidr = text
            .parse()
            .map_err(|e| ServiceError::InvalidCidr(format!("{text}: {e}")))?;
        cidrs.push(cidr);
    }
    let mut tokens = Vec::new();
    for token in allowed_bearer_tokens {
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(ServiceError::InvalidInput(
                "allowed_bearer_tokens must not contain empty entries".into(),
            ));
        }
        tokens.push(token);
    }
    Ok(AuthorizationPolicy {
        allowed_source_cidrs: cidrs,
        allowed_bearer_tokens: tokens,
    })
}

/// 计划对象校验入口：错误转 [`ServiceError`]（400）。
fn plan_error(e: meshlet_publish::PublishError) -> ServiceError {
    ServiceError::InvalidInput(e.to_string())
}

fn default_true() -> bool {
    true
}

fn default_dns_priority() -> u16 {
    100
}

// ---------------------------------------------------------------------------
// 端口转发的域函数
// ---------------------------------------------------------------------------

/// 端口冲突按设备判定：每台设备是独立主机，同设备上同 `(protocol,
/// listener 地址:端口)` 只能绑一次。
fn check_forward_port_free(
    state: &MeshState,
    network_id: &str,
    device_id: &str,
    protocol: ForwardProtocol,
    listener: std::net::SocketAddr,
) -> Result<(), ServiceError> {
    if let Some(catalog) = state.publishes.get(network_id) {
        if let Some(existing) = catalog.forwards.iter().find(|f| {
            f.device_id == device_id && f.protocol == protocol && f.listener_address == listener
        }) {
            return Err(ServiceError::Conflict(format!(
                "device {device_id} already binds {protocol:?} {} on forward {}",
                listener, existing.id
            )));
        }
    }
    Ok(())
}

pub fn create_forward(
    state: &mut MeshState,
    network_id: &str,
    req: CreatePublishForwardRequest,
) -> Result<PublishForwardView, ServiceError> {
    state.network(network_id)?;
    device_in_network(state, network_id, &req.device_id)?;
    let protocol = match req.protocol.as_str() {
        "tcp" => ForwardProtocol::Tcp,
        "udp" => ForwardProtocol::Udp,
        other => {
            return Err(ServiceError::InvalidInput(format!(
                "protocol must be \"tcp\" or \"udp\", got {other:?}"
            )));
        }
    };
    let listener_address: std::net::SocketAddr = req
        .listener_address
        .parse()
        .map_err(|e| ServiceError::InvalidInput(format!("listener_address: {e}")))?;
    let backend_address: std::net::SocketAddr = req
        .backend_address
        .parse()
        .map_err(|e| ServiceError::InvalidInput(format!("backend_address: {e}")))?;
    let policy = parse_policy(&req.allowed_source_cidrs, &req.allowed_bearer_tokens)?;
    let id = format!("pf-{}", state.publish_seq() + 1);
    PortForwardConfig {
        id: id.clone(),
        network_id: network_id.to_string(),
        protocol,
        listener_address,
        backend_address,
        policy: policy.clone(),
        enabled: req.enabled,
    }
    .validate()
    .map_err(plan_error)?;
    check_forward_port_free(
        state,
        network_id,
        &req.device_id,
        protocol,
        listener_address,
    )?;
    let forward = PublishForward {
        id,
        network_id: network_id.to_string(),
        device_id: req.device_id.clone(),
        protocol,
        listener_address,
        backend_address,
        policy,
        enabled: req.enabled,
        created_at: crate::service::now(),
    };
    state.set_publish_seq(state.publish_seq() + 1);
    let view = to_forward_view(state, network_id, &forward);
    state
        .publishes
        .entry(network_id.to_string())
        .or_default()
        .forwards
        .push(forward);
    crate::service::record_revision(state, network_id)?;
    Ok(view)
}

pub fn list_forwards(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<PublishForwardView>, ServiceError> {
    state.network(network_id)?;
    Ok(state
        .publishes
        .get(network_id)
        .map(|c| {
            c.forwards
                .iter()
                .map(|f| to_forward_view(state, network_id, f))
                .collect()
        })
        .unwrap_or_default())
}

pub fn get_forward(
    state: &MeshState,
    network_id: &str,
    forward_id: &str,
) -> Result<PublishForwardView, ServiceError> {
    state.network(network_id)?;
    let forward = state
        .publishes
        .get(network_id)
        .and_then(|c| c.forwards.iter().find(|f| f.id == forward_id))
        .ok_or_else(|| {
            ServiceError::PublishNotFound(format!("{forward_id} in network {network_id}"))
        })?;
    Ok(to_forward_view(state, network_id, forward))
}

/// 删除返回 `(forward_id)` 供落库与审计。
pub fn delete_forward(
    state: &mut MeshState,
    network_id: &str,
    forward_id: &str,
) -> Result<String, ServiceError> {
    state.network(network_id)?;
    let catalog = state.publishes.get_mut(network_id).ok_or_else(|| {
        ServiceError::PublishNotFound(format!("{forward_id} in network {network_id}"))
    })?;
    let before = catalog.forwards.len();
    catalog.forwards.retain(|f| f.id != forward_id);
    if catalog.forwards.len() == before {
        return Err(ServiceError::PublishNotFound(format!(
            "{forward_id} in network {network_id}"
        )));
    }
    crate::service::record_revision(state, network_id)?;
    Ok(forward_id.to_string())
}

// ---------------------------------------------------------------------------
// HTTP 路由的域函数
// ---------------------------------------------------------------------------

/// 同网络内 `(hostname, path_prefix)` 唯一（大小写不敏感），与计划层
/// `HttpRouteSet` 的查重口径一致。
fn check_http_route_free(
    state: &MeshState,
    network_id: &str,
    hostname: &str,
    path_prefix: &str,
) -> Result<(), ServiceError> {
    if let Some(catalog) = state.publishes.get(network_id) {
        if let Some(existing) = catalog
            .http_routes
            .iter()
            .find(|r| r.hostname.eq_ignore_ascii_case(hostname) && r.path_prefix == path_prefix)
        {
            return Err(ServiceError::Conflict(format!(
                "route {} already serves {}{}",
                existing.id, hostname, path_prefix
            )));
        }
    }
    Ok(())
}

/// 一台设备只绑定一个 HTTP 监听口、只用一种终止模式：计划里只有
/// `http_listener` 和 `tls_passthrough` 两个位置，其余值会被静默丢弃
/// （第二个监听口不绑定；混入 TLS 路由会让整台设备切成 SNI 嗅探）。
fn check_http_socket_consistent(
    state: &MeshState,
    network_id: &str,
    device_id: &str,
    listener_address: std::net::SocketAddr,
    tls_passthrough: bool,
) -> Result<(), ServiceError> {
    if let Some(existing) = state
        .publishes
        .get(network_id)
        .and_then(|c| c.http_routes.iter().find(|r| r.device_id == device_id))
    {
        if existing.listener_address != listener_address {
            return Err(ServiceError::Conflict(format!(
                "device {device_id} already listens for http on {listener} (route {id}); \
                 one http listener per device",
                listener = existing.listener_address,
                id = existing.id,
            )));
        }
        if existing.tls_passthrough != tls_passthrough {
            return Err(ServiceError::Conflict(format!(
                "device {device_id} already serves route {id} with tls_passthrough={tls}; \
                 one termination mode per device",
                id = existing.id,
                tls = existing.tls_passthrough,
            )));
        }
    }
    Ok(())
}

/// TLS passthrough 是 SNI 嗅探 + 原始字节直通：meshlet 没有证书、不解密。
/// 因此下面两项能力在该模式上根本不存在，静默忽略等于冒充，创建期一律 409
/// （与「混合终止模式 409」同口径扩展）：
/// - `allowed_bearer_tokens`：路由器看不到 HTTP 头（TLS 对它不透明），
///   token 永远不会被校验；
/// - `path_prefix` 非 `/`：嗅探只按 SNI 主机名选路（恒以 `/` 匹配），
///   路径前缀永不参与匹配。
///
/// 要这两项能力就用 plain HTTP 路由；真正的 TLS 终结当前不支持，
/// 直接拒绝而不是假装支持。
fn check_publish_mode_supported(
    tls_passthrough: bool,
    path_prefix: &str,
    allowed_bearer_tokens: &[String],
) -> Result<(), ServiceError> {
    if !tls_passthrough {
        return Ok(());
    }
    if !allowed_bearer_tokens.is_empty() {
        return Err(ServiceError::Conflict(
            "tls_passthrough forwards opaque TLS bytes: meshlet never terminates TLS \
             (no certificate, no decryption), so allowed_bearer_tokens cannot be enforced \
             on this route; use a plain http route to enforce bearer tokens"
                .into(),
        ));
    }
    if path_prefix != "/" {
        return Err(ServiceError::Conflict(
            "tls_passthrough selects by SNI host name only and never matches a path \
             prefix; use path_prefix \"/\" or a plain http route"
                .into(),
        ));
    }
    Ok(())
}

pub fn create_http_route(
    state: &mut MeshState,
    network_id: &str,
    req: CreatePublishHttpRouteRequest,
) -> Result<PublishHttpRouteView, ServiceError> {
    state.network(network_id)?;
    device_in_network(state, network_id, &req.device_id)?;
    if req.hostname.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "hostname must not be empty".into(),
        ));
    }
    let backend_address: std::net::SocketAddr = req
        .backend_address
        .parse()
        .map_err(|e| ServiceError::InvalidInput(format!("backend_address: {e}")))?;
    let listener_address: std::net::SocketAddr = req
        .listener_address
        .parse()
        .map_err(|e| ServiceError::InvalidInput(format!("listener_address: {e}")))?;
    if listener_address.port() == 0 {
        return Err(ServiceError::InvalidInput(
            "listener_address must not use port 0".into(),
        ));
    }
    let policy = parse_policy(&req.allowed_source_cidrs, &req.allowed_bearer_tokens)?;
    check_publish_mode_supported(
        req.tls_passthrough,
        &req.path_prefix,
        &req.allowed_bearer_tokens,
    )?;
    let id = format!("hr-{}", state.publish_seq() + 1);
    let hostname = req.hostname.trim().to_string();
    HttpRouteSet::new(vec![HttpRoute {
        id: id.clone(),
        network_id: network_id.to_string(),
        hostname: hostname.clone(),
        path_prefix: req.path_prefix.clone(),
        backend_address,
        policy: policy.clone(),
        tls_passthrough: req.tls_passthrough,
    }])
    .map_err(plan_error)?;
    check_http_route_free(state, network_id, &hostname, &req.path_prefix)?;
    check_http_socket_consistent(
        state,
        network_id,
        &req.device_id,
        listener_address,
        req.tls_passthrough,
    )?;
    let route = PublishHttpRoute {
        id,
        network_id: network_id.to_string(),
        device_id: req.device_id.clone(),
        hostname,
        path_prefix: req.path_prefix.clone(),
        backend_address,
        listener_address,
        policy,
        tls_passthrough: req.tls_passthrough,
        created_at: crate::service::now(),
    };
    state.set_publish_seq(state.publish_seq() + 1);
    let view = to_http_route_view(state, network_id, &route);
    state
        .publishes
        .entry(network_id.to_string())
        .or_default()
        .http_routes
        .push(route);
    crate::service::record_revision(state, network_id)?;
    Ok(view)
}

pub fn list_http_routes(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<PublishHttpRouteView>, ServiceError> {
    state.network(network_id)?;
    Ok(state
        .publishes
        .get(network_id)
        .map(|c| {
            c.http_routes
                .iter()
                .map(|r| to_http_route_view(state, network_id, r))
                .collect()
        })
        .unwrap_or_default())
}

pub fn get_http_route(
    state: &MeshState,
    network_id: &str,
    route_id: &str,
) -> Result<PublishHttpRouteView, ServiceError> {
    state.network(network_id)?;
    let route = state
        .publishes
        .get(network_id)
        .and_then(|c| c.http_routes.iter().find(|r| r.id == route_id))
        .ok_or_else(|| {
            ServiceError::PublishNotFound(format!("{route_id} in network {network_id}"))
        })?;
    Ok(to_http_route_view(state, network_id, route))
}

pub fn delete_http_route(
    state: &mut MeshState,
    network_id: &str,
    route_id: &str,
) -> Result<String, ServiceError> {
    state.network(network_id)?;
    let catalog = state.publishes.get_mut(network_id).ok_or_else(|| {
        ServiceError::PublishNotFound(format!("{route_id} in network {network_id}"))
    })?;
    let before = catalog.http_routes.len();
    catalog.http_routes.retain(|r| r.id != route_id);
    if catalog.http_routes.len() == before {
        return Err(ServiceError::PublishNotFound(format!(
            "{route_id} in network {network_id}"
        )));
    }
    crate::service::record_revision(state, network_id)?;
    Ok(route_id.to_string())
}

// ---------------------------------------------------------------------------
// 探针的域函数
// ---------------------------------------------------------------------------

fn probe_target_from_parts(
    target_kind: &str,
    address: &str,
    path: Option<&str>,
    expected_status: Option<u16>,
    timeout_secs: f64,
) -> Result<ProbeTarget, ServiceError> {
    let address: std::net::SocketAddr = address
        .parse()
        .map_err(|e| ServiceError::InvalidInput(format!("address: {e}")))?;
    if !(timeout_secs.is_finite() && timeout_secs > 0.0) {
        return Err(ServiceError::InvalidInput(
            "timeout_secs must be a positive finite number".into(),
        ));
    }
    let timeout = std::time::Duration::from_secs_f64(timeout_secs);
    match target_kind {
        "tcp" => Ok(ProbeTarget::Tcp { address, timeout }),
        "http" => {
            let path = path
                .map(str::to_string)
                .ok_or_else(|| ServiceError::InvalidInput("http probe needs path".into()))?;
            let expected_status = expected_status.ok_or_else(|| {
                ServiceError::InvalidInput("http probe needs expected_status".into())
            })?;
            Ok(ProbeTarget::Http {
                address,
                path,
                expected_status,
                timeout,
            })
        }
        other => Err(ServiceError::InvalidInput(format!(
            "target_kind must be \"tcp\" or \"http\", got {other:?}"
        ))),
    }
}

pub fn create_probe(
    state: &mut MeshState,
    network_id: &str,
    req: CreatePublishProbeRequest,
) -> Result<PublishProbeView, ServiceError> {
    state.network(network_id)?;
    device_in_network(state, network_id, &req.device_id)?;
    if req.interval_secs == 0 {
        return Err(ServiceError::InvalidInput(
            "interval_secs must not be zero".into(),
        ));
    }
    let target = probe_target_from_parts(
        &req.target_kind,
        &req.address,
        req.path.as_deref(),
        req.expected_status,
        req.timeout_secs,
    )?;
    let id = format!("pb-{}", state.publish_seq() + 1);
    ProbeSchedule {
        id: id.clone(),
        target: target.clone(),
        interval: std::time::Duration::from_secs(req.interval_secs),
    }
    .validate()
    .map_err(plan_error)?;
    let probe = PublishProbe {
        id,
        network_id: network_id.to_string(),
        device_id: req.device_id.clone(),
        target,
        interval_secs: req.interval_secs,
        enabled: true,
        created_at: crate::service::now(),
        last_state: None,
        last_checked_at: None,
        last_detail: None,
    };
    state.set_publish_seq(state.publish_seq() + 1);
    let view = to_probe_view(state, network_id, &probe);
    state
        .publishes
        .entry(network_id.to_string())
        .or_default()
        .probes
        .push(probe);
    crate::service::record_revision(state, network_id)?;
    Ok(view)
}

pub fn list_probes(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<PublishProbeView>, ServiceError> {
    state.network(network_id)?;
    Ok(state
        .publishes
        .get(network_id)
        .map(|c| {
            c.probes
                .iter()
                .map(|p| to_probe_view(state, network_id, p))
                .collect()
        })
        .unwrap_or_default())
}

pub fn get_probe(
    state: &MeshState,
    network_id: &str,
    probe_id: &str,
) -> Result<PublishProbeView, ServiceError> {
    state.network(network_id)?;
    let probe = state
        .publishes
        .get(network_id)
        .and_then(|c| c.probes.iter().find(|p| p.id == probe_id))
        .ok_or_else(|| {
            ServiceError::PublishNotFound(format!("{probe_id} in network {network_id}"))
        })?;
    Ok(to_probe_view(state, network_id, probe))
}

pub fn delete_probe(
    state: &mut MeshState,
    network_id: &str,
    probe_id: &str,
) -> Result<String, ServiceError> {
    state.network(network_id)?;
    let catalog = state.publishes.get_mut(network_id).ok_or_else(|| {
        ServiceError::PublishNotFound(format!("{probe_id} in network {network_id}"))
    })?;
    let before = catalog.probes.len();
    catalog.probes.retain(|p| p.id != probe_id);
    if catalog.probes.len() == before {
        return Err(ServiceError::PublishNotFound(format!(
            "{probe_id} in network {network_id}"
        )));
    }
    crate::service::record_revision(state, network_id)?;
    Ok(probe_id.to_string())
}

/// agent 健康回报（内存侧）：只更新归该设备的探针的 `last_*`。
pub fn record_probe_health(
    state: &mut MeshState,
    network_id: &str,
    device_id: &str,
    probe_id: &str,
    report: meshlet_publish::ProbeReport,
) -> Result<(), ServiceError> {
    let probe = state
        .publishes
        .get_mut(network_id)
        .and_then(|c| c.probes.iter_mut().find(|p| p.id == probe_id))
        .ok_or_else(|| {
            ServiceError::PublishNotFound(format!("{probe_id} in network {network_id}"))
        })?;
    if probe.device_id != device_id {
        return Err(ServiceError::Conflict(format!(
            "probe {probe_id} does not belong to device {device_id}"
        )));
    }
    probe.last_state = Some(report.state);
    probe.last_checked_at = Some(report.checked_at);
    probe.last_detail = report.detail;
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS 记录的域函数
// ---------------------------------------------------------------------------

/// 每设备至多一个 `(bind_address, internal_suffix)` 套接字：新记录必须与该
/// 设备既有记录的套接字一致——保证计划聚合时一台设备只产出 `Some(DnsPlan)`。
fn check_dns_socket_consistent(
    state: &MeshState,
    network_id: &str,
    device_id: &str,
    bind_address: std::net::SocketAddr,
    internal_suffix: &str,
) -> Result<(), ServiceError> {
    if bind_address.port() == 0 {
        return Err(ServiceError::InvalidInput(
            "dns bind_address must not use port 0".into(),
        ));
    }
    if internal_suffix.trim().is_empty() {
        return Err(ServiceError::InvalidInput(
            "internal_suffix must not be empty".into(),
        ));
    }
    if let Some(existing) = state
        .publishes
        .get(network_id)
        .and_then(|c| c.dns_records.iter().find(|r| r.device_id == device_id))
    {
        if existing.bind_address != bind_address || existing.internal_suffix != internal_suffix {
            return Err(ServiceError::Conflict(format!(
                "device {device_id} already answers dns on {} with suffix {:?} (record {}); \
                 one dns socket per device",
                existing.bind_address, existing.internal_suffix, existing.id
            )));
        }
    }
    Ok(())
}

pub fn create_dns_record(
    state: &mut MeshState,
    network_id: &str,
    req: CreatePublishDnsRecordRequest,
) -> Result<PublishDnsRecordView, ServiceError> {
    state.network(network_id)?;
    device_in_network(state, network_id, &req.device_id)?;
    let name = req.name.trim().to_lowercase();
    if name.is_empty() {
        return Err(ServiceError::InvalidInput("name must not be empty".into()));
    }
    let address: std::net::Ipv4Addr = req
        .address
        .parse()
        .map_err(|e| ServiceError::InvalidInput(format!("address: {e}")))?;
    let bind_address: std::net::SocketAddr = req
        .bind_address
        .parse()
        .map_err(|e| ServiceError::InvalidInput(format!("bind_address: {e}")))?;
    check_dns_socket_consistent(
        state,
        network_id,
        &req.device_id,
        bind_address,
        &req.internal_suffix,
    )?;
    if req.ttl == 0 {
        return Err(ServiceError::InvalidInput("ttl must not be zero".into()));
    }
    let id = format!("dn-{}", state.publish_seq() + 1);
    let record = PublishDnsRecord {
        id,
        network_id: network_id.to_string(),
        device_id: req.device_id.clone(),
        name,
        address,
        ttl: req.ttl,
        priority: req.priority,
        bind_address,
        internal_suffix: req.internal_suffix.trim().to_lowercase(),
        created_at: crate::service::now(),
    };
    state.set_publish_seq(state.publish_seq() + 1);
    let view = to_dns_record_view(state, network_id, &record);
    state
        .publishes
        .entry(network_id.to_string())
        .or_default()
        .dns_records
        .push(record);
    crate::service::record_revision(state, network_id)?;
    Ok(view)
}

pub fn list_dns_records(
    state: &MeshState,
    network_id: &str,
) -> Result<Vec<PublishDnsRecordView>, ServiceError> {
    state.network(network_id)?;
    Ok(state
        .publishes
        .get(network_id)
        .map(|c| {
            c.dns_records
                .iter()
                .map(|r| to_dns_record_view(state, network_id, r))
                .collect()
        })
        .unwrap_or_default())
}

pub fn get_dns_record(
    state: &MeshState,
    network_id: &str,
    record_id: &str,
) -> Result<PublishDnsRecordView, ServiceError> {
    state.network(network_id)?;
    let record = state
        .publishes
        .get(network_id)
        .and_then(|c| c.dns_records.iter().find(|r| r.id == record_id))
        .ok_or_else(|| {
            ServiceError::PublishNotFound(format!("{record_id} in network {network_id}"))
        })?;
    Ok(to_dns_record_view(state, network_id, record))
}

pub fn delete_dns_record(
    state: &mut MeshState,
    network_id: &str,
    record_id: &str,
) -> Result<String, ServiceError> {
    state.network(network_id)?;
    let catalog = state.publishes.get_mut(network_id).ok_or_else(|| {
        ServiceError::PublishNotFound(format!("{record_id} in network {network_id}"))
    })?;
    let before = catalog.dns_records.len();
    catalog.dns_records.retain(|r| r.id != record_id);
    if catalog.dns_records.len() == before {
        return Err(ServiceError::PublishNotFound(format!(
            "{record_id} in network {network_id}"
        )));
    }
    crate::service::record_revision(state, network_id)?;
    Ok(record_id.to_string())
}

// ---------------------------------------------------------------------------
// 计划构建：设备 → PublishPlan（build_device_plan 透传）
// ---------------------------------------------------------------------------

/// 指定设备的发布计划：过滤本设备对象 → 复用计划层校验 → DNS 聚合为
/// 至多一个 [`DnsPlan`]。`Err(String)` = 计划层校验拒绝（配置互相矛盾）。
pub fn device_publish_plan(
    mesh: &MeshState,
    network_id: &str,
    device_id: &str,
) -> Result<Option<PublishPlan>, String> {
    let Some(catalog) = mesh.publishes.get(network_id) else {
        return Ok(None);
    };
    let forwards: Vec<PortForwardConfig> = catalog
        .forwards
        .iter()
        .filter(|f| f.device_id == device_id && f.enabled)
        .map(|f| PortForwardConfig {
            id: f.id.clone(),
            network_id: f.network_id.clone(),
            protocol: f.protocol,
            listener_address: f.listener_address,
            backend_address: f.backend_address,
            policy: f.policy.clone(),
            enabled: f.enabled,
        })
        .collect();
    let routes: Vec<HttpRoute> = catalog
        .http_routes
        .iter()
        .filter(|r| r.device_id == device_id)
        .map(|r| HttpRoute {
            id: r.id.clone(),
            network_id: r.network_id.clone(),
            hostname: r.hostname.clone(),
            path_prefix: r.path_prefix.clone(),
            backend_address: r.backend_address,
            policy: r.policy.clone(),
            tls_passthrough: r.tls_passthrough,
        })
        .collect();
    let http_listener = catalog
        .http_routes
        .iter()
        .find(|r| r.device_id == device_id)
        .map(|r| r.listener_address);
    let probes: Vec<ProbeSchedule> = catalog
        .probes
        .iter()
        .filter(|p| p.device_id == device_id && p.enabled)
        .map(|p| ProbeSchedule {
            id: p.id.clone(),
            target: p.target(),
            interval: std::time::Duration::from_secs(p.interval_secs),
        })
        .collect();
    let dns = catalog
        .dns_records
        .iter()
        .find(|r| r.device_id == device_id)
        .map(|socket| DnsPlan {
            network_id: network_id.to_string(),
            internal_suffix: socket.internal_suffix.clone(),
            bind_address: socket.bind_address,
            records: catalog
                .dns_records
                .iter()
                .filter(|r| r.device_id == device_id)
                .map(|r| meshlet_publish::dns::DnsRecord {
                    service_id: r.id.clone(),
                    name: r.name.clone(),
                    address: r.address,
                    ttl: r.ttl,
                    priority: r.priority,
                })
                .collect(),
        });
    if forwards.is_empty()
        && http_listener.is_none()
        && routes.is_empty()
        && dns.is_none()
        && probes.is_empty()
    {
        return Ok(None);
    }
    let plan = PublishPlan {
        forwards,
        http_listener,
        http_routes: HttpRouteSet::new(routes).map_err(|e| e.to_string())?,
        dns,
        probes,
    };
    plan.validate().map_err(|e| e.to_string())?;
    Ok(Some(plan))
}

// ---------------------------------------------------------------------------
// agent 健康回报（证据，不是配置；upsert 带 device_id 守卫）
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishHealthRequest {
    pub reports: Vec<meshlet_publish::ProbeReport>,
}

#[derive(Debug, serde::Serialize)]
pub struct PublishHealthResponse {
    pub accepted: usize,
}

/// `POST /api/v1/agent/publish-health`：agent 批量上报探针结果。内存与 DB
/// 镜像同事务更新；`publish_probe_reports` 按 probe 主键 upsert（每探针一条
/// 最新证据），且只接受归本设备的探针。
pub async fn publish_health_handler(
    State(state): State<SharedAppState>,
    AuthorizedAgent(device_id): AuthorizedAgent,
    Json(req): Json<PublishHealthRequest>,
) -> Result<Json<PublishHealthResponse>, AgentApiError> {
    if req.reports.len() > 256 {
        return Err(AgentApiError::InvalidInput(format!(
            "too many reports in one batch: {} > 256",
            req.reports.len()
        )));
    }
    let _persist = state.persist.lock().await;
    let staged_reports = {
        let mut guard = state.mesh.lock().unwrap();
        let network_id = match guard.registry.find_by_id(&device_id) {
            Some(device) => device.network_id.to_string(),
            None => return Err(AgentApiError::NotFound(device_id.to_string())),
        };
        for report in &req.reports {
            if let Err(e) = crate::publish::record_probe_health(
                &mut guard,
                &network_id,
                &device_id.to_string(),
                &report.probe_id,
                report.clone(),
            ) {
                return Err(match e {
                    ServiceError::PublishNotFound(id) => AgentApiError::NotFound(id),
                    ServiceError::Conflict(m) => AgentApiError::InvalidInput(m),
                    other => AgentApiError::Internal(other.to_string()),
                });
            }
        }
        req.reports.clone()
    };
    crate::publish::persist::upsert_probe_reports(
        state.auth.pool(),
        &device_id.to_string(),
        &staged_reports,
    )
    .await
    .map_err(|e| AgentApiError::Internal(e.to_string()))?;
    Ok(Json(PublishHealthResponse {
        accepted: staged_reports.len(),
    }))
}

// ---------------------------------------------------------------------------
// HTTP handlers（与 alias.rs 同构）
// ---------------------------------------------------------------------------

async fn create_forward_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
    Json(req): Json<CreatePublishForwardRequest>,
) -> Result<(StatusCode, Json<PublishForwardView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, forward, revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match create_forward(&mut staged, &network_id, req) {
            Ok(view) => {
                let forward = staged
                    .publishes
                    .get(&network_id)
                    .and_then(|c| c.forwards.iter().find(|f| f.id == view.id))
                    .expect("just created")
                    .clone();
                let revision = staged
                    .ledger
                    .current(&meshlet_domain::NetworkId(network_id.clone()))
                    .expect("create_forward just recorded a revision")
                    .clone();
                let publish_seq = staged.publish_seq();
                (view, forward, revision, publish_seq, staged)
            }
            Err(e) => {
                crate::op_log!(
                    warn,
                    "publish",
                    "create_forward",
                    &network_id,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::ErrorCategory::from(&e).as_str(),
                    crate::telemetry::RESULT_ERROR
                );
                return Err(e);
            }
        }
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.forward_created",
        target_type: "publish_forward",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::publish::persist::commit_forward(
        state.auth.pool(),
        &forward,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "create_forward",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

async fn list_forwards_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<PublishForwardView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_forwards(&guard, &network_id)?))
}

async fn get_forward_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, forward_id)): Path<(String, String)>,
) -> Result<Json<PublishForwardView>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(get_forward(&guard, &network_id, &forward_id)?))
}

async fn delete_forward_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, forward_id)): Path<(String, String)>,
) -> Result<StatusCode, ServiceError> {
    let _persist = state.persist.lock().await;
    let (revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let _deleted = delete_forward(&mut staged, &network_id, &forward_id)?;
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_forward just recorded a revision")
            .clone();
        let publish_seq = staged.publish_seq();
        (revision, publish_seq, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.forward_deleted",
        target_type: "publish_forward",
        target_id: &forward_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::publish::persist::commit_delete(
        state.auth.pool(),
        "publish_forwards",
        &forward_id,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "delete_forward",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn create_http_route_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
    Json(req): Json<CreatePublishHttpRouteRequest>,
) -> Result<(StatusCode, Json<PublishHttpRouteView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, route, revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match create_http_route(&mut staged, &network_id, req) {
            Ok(view) => {
                let route = staged
                    .publishes
                    .get(&network_id)
                    .and_then(|c| c.http_routes.iter().find(|r| r.id == view.id))
                    .expect("just created")
                    .clone();
                let revision = staged
                    .ledger
                    .current(&meshlet_domain::NetworkId(network_id.clone()))
                    .expect("create_http_route just recorded a revision")
                    .clone();
                let publish_seq = staged.publish_seq();
                (view, route, revision, publish_seq, staged)
            }
            Err(e) => {
                crate::op_log!(
                    warn,
                    "publish",
                    "create_http_route",
                    &network_id,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::ErrorCategory::from(&e).as_str(),
                    crate::telemetry::RESULT_ERROR
                );
                return Err(e);
            }
        }
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.http_route_created",
        target_type: "publish_http_route",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::publish::persist::commit_http_route(
        state.auth.pool(),
        &route,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "create_http_route",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

async fn list_http_routes_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<PublishHttpRouteView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_http_routes(&guard, &network_id)?))
}

async fn get_http_route_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, route_id)): Path<(String, String)>,
) -> Result<Json<PublishHttpRouteView>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(get_http_route(&guard, &network_id, &route_id)?))
}

async fn delete_http_route_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, route_id)): Path<(String, String)>,
) -> Result<StatusCode, ServiceError> {
    let _persist = state.persist.lock().await;
    let (revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let _deleted = delete_http_route(&mut staged, &network_id, &route_id)?;
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_http_route just recorded a revision")
            .clone();
        let publish_seq = staged.publish_seq();
        (revision, publish_seq, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.http_route_deleted",
        target_type: "publish_http_route",
        target_id: &route_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::publish::persist::commit_delete(
        state.auth.pool(),
        "publish_http_routes",
        &route_id,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "delete_http_route",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn create_probe_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
    Json(req): Json<CreatePublishProbeRequest>,
) -> Result<(StatusCode, Json<PublishProbeView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, probe, revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match create_probe(&mut staged, &network_id, req) {
            Ok(view) => {
                let probe = staged
                    .publishes
                    .get(&network_id)
                    .and_then(|c| c.probes.iter().find(|p| p.id == view.id))
                    .expect("just created")
                    .clone();
                let revision = staged
                    .ledger
                    .current(&meshlet_domain::NetworkId(network_id.clone()))
                    .expect("create_probe just recorded a revision")
                    .clone();
                let publish_seq = staged.publish_seq();
                (view, probe, revision, publish_seq, staged)
            }
            Err(e) => {
                crate::op_log!(
                    warn,
                    "publish",
                    "create_probe",
                    &network_id,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::ErrorCategory::from(&e).as_str(),
                    crate::telemetry::RESULT_ERROR
                );
                return Err(e);
            }
        }
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.probe_created",
        target_type: "publish_probe",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::publish::persist::commit_probe(
        state.auth.pool(),
        &probe,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "create_probe",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

async fn list_probes_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<PublishProbeView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_probes(&guard, &network_id)?))
}

async fn get_probe_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, probe_id)): Path<(String, String)>,
) -> Result<Json<PublishProbeView>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(get_probe(&guard, &network_id, &probe_id)?))
}

async fn delete_probe_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, probe_id)): Path<(String, String)>,
) -> Result<StatusCode, ServiceError> {
    let _persist = state.persist.lock().await;
    let (revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let _deleted = delete_probe(&mut staged, &network_id, &probe_id)?;
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_probe just recorded a revision")
            .clone();
        let publish_seq = staged.publish_seq();
        (revision, publish_seq, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.probe_deleted",
        target_type: "publish_probe",
        target_id: &probe_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    // 探针删除连带清掉它的健康证据（证据不是配置，不悬挂）。
    crate::publish::persist::commit_probe_delete(
        state.auth.pool(),
        &probe_id,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "delete_probe",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn create_dns_record_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
    Json(req): Json<CreatePublishDnsRecordRequest>,
) -> Result<(StatusCode, Json<PublishDnsRecordView>), ServiceError> {
    let _persist = state.persist.lock().await;
    let (view, record, revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        match create_dns_record(&mut staged, &network_id, req) {
            Ok(view) => {
                let record = staged
                    .publishes
                    .get(&network_id)
                    .and_then(|c| c.dns_records.iter().find(|r| r.id == view.id))
                    .expect("just created")
                    .clone();
                let revision = staged
                    .ledger
                    .current(&meshlet_domain::NetworkId(network_id.clone()))
                    .expect("create_dns_record just recorded a revision")
                    .clone();
                let publish_seq = staged.publish_seq();
                (view, record, revision, publish_seq, staged)
            }
            Err(e) => {
                crate::op_log!(
                    warn,
                    "publish",
                    "create_dns_record",
                    &network_id,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::NOT_APPLICABLE,
                    crate::telemetry::ErrorCategory::from(&e).as_str(),
                    crate::telemetry::RESULT_ERROR
                );
                return Err(e);
            }
        }
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.dns_record_created",
        target_type: "publish_dns_record",
        target_id: &view.id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::publish::persist::commit_dns_record(
        state.auth.pool(),
        &record,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "create_dns_record",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        &view.revision_id.to_string(),
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok((StatusCode::CREATED, Json(view)))
}

async fn list_dns_records_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<PublishDnsRecordView>>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(list_dns_records(&guard, &network_id)?))
}

async fn get_dns_record_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path((network_id, record_id)): Path<(String, String)>,
) -> Result<Json<PublishDnsRecordView>, ServiceError> {
    let guard = state.mesh.lock().unwrap();
    Ok(Json(get_dns_record(&guard, &network_id, &record_id)?))
}

async fn delete_dns_record_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path((network_id, record_id)): Path<(String, String)>,
) -> Result<StatusCode, ServiceError> {
    let _persist = state.persist.lock().await;
    let (revision, publish_seq, staged) = {
        let guard = state.mesh.lock().unwrap();
        let mut staged = guard.clone();
        let _deleted = delete_dns_record(&mut staged, &network_id, &record_id)?;
        let revision = staged
            .ledger
            .current(&meshlet_domain::NetworkId(network_id.clone()))
            .expect("delete_dns_record just recorded a revision")
            .clone();
        let publish_seq = staged.publish_seq();
        (revision, publish_seq, staged)
    };
    let audit = crate::persist::AuditDraft {
        actor_id: Some(&user_id.0),
        action: "publish.dns_record_deleted",
        target_type: "publish_dns_record",
        target_id: &record_id,
        detail: Some(serde_json::json!({ "network_id": network_id })),
    };
    crate::publish::persist::commit_delete(
        state.auth.pool(),
        "publish_dns_records",
        &record_id,
        publish_seq,
        &revision,
        &audit,
    )
    .await
    .map_err(crate::persist::internal)?;
    *state.mesh.lock().unwrap() = staged;
    crate::op_log!(
        info,
        "publish",
        "delete_dns_record",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// 持久化（同事务：对象行 + publish_seq + 修订 + 审计；无审计不落地）
// ---------------------------------------------------------------------------

/// publish 模块的 sqlx 落库层。SQL 与 persist.rs 同约定：编译期迁移建表
/// （migrations/012_publish.sql），删除不复用 id（`mesh_meta.publish_seq`）。
pub(crate) mod persist {
    use super::{PublishDnsRecord, PublishForward, PublishHttpRoute, PublishProbe};
    use crate::persist::{insert_audit_tx, insert_revision_tx, save_seq_tx};
    use crate::service::ServiceError;
    use meshlet_domain::ConfigRevision;
    use meshlet_publish::health::HealthState;
    use sqlx::SqlitePool;

    fn policy_cidrs_json(policy: &meshlet_publish::AuthorizationPolicy) -> String {
        serde_json::json!(policy
            .allowed_source_cidrs
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>())
        .to_string()
    }

    fn policy_tokens_json(policy: &meshlet_publish::AuthorizationPolicy) -> String {
        serde_json::json!(policy.allowed_bearer_tokens).to_string()
    }

    fn policy_from_json(
        cidrs_json: &str,
        tokens_json: &str,
    ) -> Result<meshlet_publish::AuthorizationPolicy, ServiceError> {
        let cidrs: Vec<String> = serde_json::from_str(cidrs_json)
            .map_err(|e| ServiceError::Internal(format!("publish cidrs json: {e}")))?;
        let tokens: Vec<String> = serde_json::from_str(tokens_json)
            .map_err(|e| ServiceError::Internal(format!("publish tokens json: {e}")))?;
        let mut parsed = Vec::new();
        for text in &cidrs {
            let cidr: meshlet_domain::Ipv4Cidr = text
                .parse()
                .map_err(|e| ServiceError::Internal(format!("publish cidr {text}: {e}")))?;
            parsed.push(cidr);
        }
        Ok(meshlet_publish::AuthorizationPolicy {
            allowed_source_cidrs: parsed,
            allowed_bearer_tokens: tokens,
        })
    }

    fn probe_target_columns(
        target: &meshlet_publish::health::ProbeTarget,
    ) -> (String, String, Option<String>, Option<u16>, f64) {
        match target {
            meshlet_publish::health::ProbeTarget::Tcp { address, timeout } => (
                "tcp".into(),
                address.to_string(),
                None,
                None,
                timeout.as_secs_f64(),
            ),
            meshlet_publish::health::ProbeTarget::Http {
                address,
                path,
                expected_status,
                timeout,
            } => (
                "http".into(),
                address.to_string(),
                Some(path.clone()),
                Some(*expected_status),
                timeout.as_secs_f64(),
            ),
        }
    }

    fn probe_target_from_columns(
        kind: &str,
        address: &str,
        path: Option<&str>,
        expected_status: Option<u16>,
        timeout_secs: f64,
    ) -> Result<meshlet_publish::health::ProbeTarget, ServiceError> {
        let address: std::net::SocketAddr = address
            .parse()
            .map_err(|e| ServiceError::Internal(format!("probe address {address}: {e}")))?;
        let timeout = std::time::Duration::from_secs_f64(timeout_secs);
        Ok(match kind {
            "tcp" => meshlet_publish::health::ProbeTarget::Tcp { address, timeout },
            "http" => meshlet_publish::health::ProbeTarget::Http {
                address,
                path: path.unwrap_or_default().to_string(),
                expected_status: expected_status.unwrap_or(200),
                timeout,
            },
            other => {
                return Err(ServiceError::Internal(format!(
                    "unknown probe target_kind {other:?}"
                )));
            }
        })
    }

    pub async fn commit_forward(
        pool: &SqlitePool,
        forward: &PublishForward,
        publish_seq: u64,
        revision: &ConfigRevision,
        audit: &crate::persist::AuditDraft<'_>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;
        sqlx::query(
            "INSERT INTO publish_forwards
               (id, network_id, device_id, protocol, listener_address, backend_address,
                allowed_source_cidrs, allowed_bearer_tokens, enabled, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&forward.id)
        .bind(&forward.network_id)
        .bind(&forward.device_id)
        .bind(match forward.protocol {
            meshlet_publish::ForwardProtocol::Tcp => "tcp",
            meshlet_publish::ForwardProtocol::Udp => "udp",
        })
        .bind(forward.listener_address.to_string())
        .bind(forward.backend_address.to_string())
        .bind(policy_cidrs_json(&forward.policy))
        .bind(policy_tokens_json(&forward.policy))
        .bind(forward.enabled)
        .bind(&forward.created_at)
        .execute(&mut *tx)
        .await?;
        save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
        insert_revision_tx(&mut tx, revision).await?;
        insert_audit_tx(&mut tx, audit).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn commit_http_route(
        pool: &SqlitePool,
        route: &PublishHttpRoute,
        publish_seq: u64,
        revision: &ConfigRevision,
        audit: &crate::persist::AuditDraft<'_>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;
        sqlx::query(
            "INSERT INTO publish_http_routes
               (id, network_id, device_id, hostname, path_prefix, backend_address,
                listener_address, allowed_source_cidrs, allowed_bearer_tokens,
                tls_passthrough, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&route.id)
        .bind(&route.network_id)
        .bind(&route.device_id)
        .bind(&route.hostname)
        .bind(&route.path_prefix)
        .bind(route.backend_address.to_string())
        .bind(route.listener_address.to_string())
        .bind(policy_cidrs_json(&route.policy))
        .bind(policy_tokens_json(&route.policy))
        .bind(route.tls_passthrough)
        .bind(&route.created_at)
        .execute(&mut *tx)
        .await?;
        save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
        insert_revision_tx(&mut tx, revision).await?;
        insert_audit_tx(&mut tx, audit).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn commit_probe(
        pool: &SqlitePool,
        probe: &PublishProbe,
        publish_seq: u64,
        revision: &ConfigRevision,
        audit: &crate::persist::AuditDraft<'_>,
    ) -> Result<(), sqlx::Error> {
        let (kind, address, path, expected, timeout) = probe_target_columns(&probe.target);
        let mut tx = pool.begin().await?;
        sqlx::query(
            "INSERT INTO publish_probes
               (id, network_id, device_id, target_kind, address, path, expected_status,
                timeout_secs, interval_secs, enabled, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&probe.id)
        .bind(&probe.network_id)
        .bind(&probe.device_id)
        .bind(&kind)
        .bind(&address)
        .bind(&path)
        .bind(expected.map(i64::from))
        .bind(timeout)
        .bind(probe.interval_secs as i64)
        .bind(probe.enabled)
        .bind(&probe.created_at)
        .execute(&mut *tx)
        .await?;
        save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
        insert_revision_tx(&mut tx, revision).await?;
        insert_audit_tx(&mut tx, audit).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn commit_dns_record(
        pool: &SqlitePool,
        record: &PublishDnsRecord,
        publish_seq: u64,
        revision: &ConfigRevision,
        audit: &crate::persist::AuditDraft<'_>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;
        sqlx::query(
            "INSERT INTO publish_dns_records
               (id, network_id, device_id, name, address, ttl, priority, bind_address,
                internal_suffix, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.id)
        .bind(&record.network_id)
        .bind(&record.device_id)
        .bind(&record.name)
        .bind(record.address.to_string())
        .bind(record.ttl as i64)
        .bind(record.priority as i64)
        .bind(record.bind_address.to_string())
        .bind(&record.internal_suffix)
        .bind(&record.created_at)
        .execute(&mut *tx)
        .await?;
        save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
        insert_revision_tx(&mut tx, revision).await?;
        insert_audit_tx(&mut tx, audit).await?;
        tx.commit().await?;
        Ok(())
    }

    /// 通用删除：单表 + 序列 + 修订 + 审计（探针删除另有连带清证据的
    /// [`commit_probe_delete`]）。
    pub async fn commit_delete(
        pool: &SqlitePool,
        table: &str,
        id: &str,
        publish_seq: u64,
        revision: &ConfigRevision,
        audit: &crate::persist::AuditDraft<'_>,
    ) -> Result<(), sqlx::Error> {
        // 表名来自本模块调用点（白名单断言，杜绝拼接注入面）。
        assert!(
            matches!(
                table,
                "publish_forwards" | "publish_http_routes" | "publish_dns_records"
            ),
            "unexpected publish table {table}"
        );
        let mut tx = pool.begin().await?;
        sqlx::query(&format!("DELETE FROM {table} WHERE id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;
        save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
        insert_revision_tx(&mut tx, revision).await?;
        insert_audit_tx(&mut tx, audit).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn commit_probe_delete(
        pool: &SqlitePool,
        probe_id: &str,
        publish_seq: u64,
        revision: &ConfigRevision,
        audit: &crate::persist::AuditDraft<'_>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM publish_probe_reports WHERE probe_id = ?")
            .bind(probe_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM publish_probes WHERE id = ?")
            .bind(probe_id)
            .execute(&mut *tx)
            .await?;
        save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
        insert_revision_tx(&mut tx, revision).await?;
        insert_audit_tx(&mut tx, audit).await?;
        tx.commit().await?;
        Ok(())
    }

    /// 探针健康回报镜像：每探针一条最新证据（按主键 upsert），device_id
    /// 守卫保证 agent 只能写归自己设备的报告。
    pub async fn upsert_probe_reports(
        pool: &SqlitePool,
        device_id: &str,
        reports: &[meshlet_publish::ProbeReport],
    ) -> Result<(), sqlx::Error> {
        if reports.is_empty() {
            return Ok(());
        }
        let mut tx = pool.begin().await?;
        for report in reports {
            let state = match report.state {
                HealthState::Healthy => "healthy",
                HealthState::Unreachable => "unreachable",
            };
            sqlx::query(
                "INSERT INTO publish_probe_reports
                   (probe_id, network_id, device_id, state, checked_at, detail, updated_at)
                 SELECT p.id, p.network_id, p.device_id, ?, ?, ?, ?
                 FROM publish_probes p
                 WHERE p.id = ? AND p.device_id = ?
                 ON CONFLICT (probe_id) DO UPDATE SET
                   state = excluded.state,
                   checked_at = excluded.checked_at,
                   detail = excluded.detail,
                   updated_at = excluded.updated_at",
            )
            .bind(state)
            .bind(&report.checked_at)
            .bind(&report.detail)
            .bind(crate::service::now())
            .bind(&report.probe_id)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// 启动重建：灌回全部发布对象 + `mesh_meta.publish_seq`。行级错误以
    /// `corrupt` 语义上抛（与 persist::load 其余部分一致，由调用方包装）。
    pub async fn load(
        pool: &SqlitePool,
        state: &mut crate::service::MeshState,
    ) -> Result<(), sqlx::Error> {
        let seq: Option<String> =
            sqlx::query_scalar("SELECT value FROM mesh_meta WHERE key = 'publish_seq'")
                .fetch_optional(pool)
                .await?;
        if let Some(seq) = seq {
            let seq: u64 = seq
                .parse()
                .map_err(|e| sqlx::Error::Configuration(Box::new(e)))?;
            state.set_publish_seq(seq);
        }

        let forward_rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                bool,
                String,
            ),
        >(
            "SELECT id, network_id, device_id, protocol, listener_address, backend_address,
                    allowed_source_cidrs, allowed_bearer_tokens, enabled, created_at
             FROM publish_forwards ORDER BY id",
        )
        .fetch_all(pool)
        .await?;
        for (
            id,
            network_id,
            device_id,
            protocol,
            listener,
            backend,
            cidrs,
            tokens,
            enabled,
            created_at,
        ) in forward_rows
        {
            let policy = policy_from_json(&cidrs, &tokens).map_err(|e| {
                sqlx::Error::Configuration(format!("publish forward {id}: {e}").into())
            })?;
            let listener: std::net::SocketAddr = listener
                .parse()
                .map_err(|e| sqlx::Error::Configuration(format!("forward {id}: {e}").into()))?;
            let backend: std::net::SocketAddr = backend
                .parse()
                .map_err(|e| sqlx::Error::Configuration(format!("forward {id}: {e}").into()))?;
            let protocol = match protocol.as_str() {
                "tcp" => meshlet_publish::ForwardProtocol::Tcp,
                "udp" => meshlet_publish::ForwardProtocol::Udp,
                other => {
                    return Err(sqlx::Error::Configuration(
                        format!("forward {id}: unknown protocol {other:?}").into(),
                    ));
                }
            };
            state.restore_publish_forward(PublishForward {
                id,
                network_id,
                device_id,
                protocol,
                listener_address: listener,
                backend_address: backend,
                policy,
                enabled,
                created_at,
            });
        }

        let route_rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                bool,
                String,
            ),
        >(
            "SELECT id, network_id, device_id, hostname, path_prefix, backend_address,
                    listener_address, allowed_source_cidrs, allowed_bearer_tokens,
                    tls_passthrough, created_at
             FROM publish_http_routes ORDER BY id",
        )
        .fetch_all(pool)
        .await?;
        for (
            id,
            network_id,
            device_id,
            hostname,
            path_prefix,
            backend,
            listener,
            cidrs,
            tokens,
            tls,
            created_at,
        ) in route_rows
        {
            let policy = policy_from_json(&cidrs, &tokens).map_err(|e| {
                sqlx::Error::Configuration(format!("publish http route {id}: {e}").into())
            })?;
            let backend: std::net::SocketAddr = backend
                .parse()
                .map_err(|e| sqlx::Error::Configuration(format!("route {id}: {e}").into()))?;
            let listener: std::net::SocketAddr = listener
                .parse()
                .map_err(|e| sqlx::Error::Configuration(format!("route {id}: {e}").into()))?;
            state.restore_publish_http_route(PublishHttpRoute {
                id,
                network_id,
                device_id,
                hostname,
                path_prefix,
                backend_address: backend,
                listener_address: listener,
                policy,
                tls_passthrough: tls,
                created_at,
            });
        }

        let probe_rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<u16>,
                f64,
                i64,
                bool,
                String,
            ),
        >(
            "SELECT id, network_id, device_id, target_kind, address, path, expected_status,
                    timeout_secs, interval_secs, enabled, created_at
             FROM publish_probes ORDER BY id",
        )
        .fetch_all(pool)
        .await?;
        for (
            id,
            network_id,
            device_id,
            kind,
            address,
            path,
            expected,
            timeout,
            interval,
            enabled,
            created_at,
        ) in probe_rows
        {
            let target =
                probe_target_from_columns(&kind, &address, path.as_deref(), expected, timeout)
                    .map_err(|e| {
                        sqlx::Error::Configuration(format!("publish probe {id}: {e}").into())
                    })?;
            state.restore_publish_probe(PublishProbe {
                id,
                network_id,
                device_id,
                target,
                interval_secs: interval as u64,
                enabled,
                created_at,
                last_state: None,
                last_checked_at: None,
                last_detail: None,
            });
        }

        // 健康证据镜像回填（探针已删的孤儿证据不进内存）。
        let probe_ids: std::collections::HashSet<String> = state
            .publishes
            .values()
            .flat_map(|c| c.probes.iter().map(|p| p.id.clone()))
            .collect();
        let report_rows = sqlx::query_as::<_, (String, String, String, Option<String>, String)>(
            "SELECT probe_id, state, checked_at, detail, network_id
             FROM publish_probe_reports ORDER BY probe_id",
        )
        .fetch_all(pool)
        .await?;
        for (probe_id, state_text, checked_at, detail, _network_id) in report_rows {
            if !probe_ids.contains(&probe_id) {
                continue;
            }
            let health = match state_text.as_str() {
                "healthy" => HealthState::Healthy,
                "unreachable" => HealthState::Unreachable,
                other => {
                    return Err(sqlx::Error::Configuration(
                        format!("probe report {probe_id}: unknown state {other:?}").into(),
                    ));
                }
            };
            if let Some(catalog) = state
                .publishes
                .get_mut(&_network_id)
                .and_then(|c| c.probes.iter_mut().find(|p| p.id == probe_id))
            {
                catalog.last_state = Some(health);
                catalog.last_checked_at = Some(checked_at);
                catalog.last_detail = detail;
            }
        }

        let dns_rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                i64,
                i64,
                String,
                String,
                String,
            ),
        >(
            "SELECT id, network_id, device_id, name, address, ttl, priority, bind_address,
                    internal_suffix, created_at
             FROM publish_dns_records ORDER BY id",
        )
        .fetch_all(pool)
        .await?;
        for (id, network_id, device_id, name, address, ttl, priority, bind, suffix, created_at) in
            dns_rows
        {
            let address: std::net::Ipv4Addr = address
                .parse()
                .map_err(|e| sqlx::Error::Configuration(format!("dns {id}: {e}").into()))?;
            let bind: std::net::SocketAddr = bind
                .parse()
                .map_err(|e| sqlx::Error::Configuration(format!("dns {id}: {e}").into()))?;
            state.restore_publish_dns_record(PublishDnsRecord {
                id,
                network_id,
                device_id,
                name,
                address,
                ttl: ttl as u32,
                priority: priority as u16,
                bind_address: bind,
                internal_suffix: suffix,
                created_at,
            });
        }
        Ok(())
    }
}
