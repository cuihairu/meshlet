//! API 视图、请求体与内存记录转换；读视图只回 token 条数。

use super::models::{PublishDnsRecord, PublishForward, PublishHttpRoute, PublishProbe};
use crate::service::MeshState;
use meshlet_publish::health::{HealthState, ProbeTarget};
use meshlet_publish::ForwardProtocol;

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
    #[serde(default = "super::auth::default_true")]
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
    #[serde(default = "super::auth::default_dns_priority")]
    pub priority: u16,
    pub bind_address: String,
    pub internal_suffix: String,
}
pub(crate) fn to_forward_view(
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

pub(crate) fn to_http_route_view(
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

pub(crate) fn to_probe_view(
    state: &MeshState,
    network_id: &str,
    probe: &PublishProbe,
) -> PublishProbeView {
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

pub(crate) fn to_dns_record_view(
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
