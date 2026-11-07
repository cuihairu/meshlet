//! 发布对象内存记录（DB 行、内存与设备计划的共享形态）。

use crate::service::MeshState;
use meshlet_publish::health::{HealthState, ProbeTarget};
use meshlet_publish::{AuthorizationPolicy, ForwardProtocol};

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
